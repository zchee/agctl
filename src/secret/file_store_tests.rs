//! Tests for the credential file store (plan AC15, AC33, AC46, section 3.6).

use std::os::unix::fs::PermissionsExt;
use std::time::Instant;

use tempfile::TempDir;

use super::*;
use crate::config::paths::FILE_MODE;
use crate::provider::claude::credentials::Credentials;
use crate::runtime::coordinator::Cancel;

/// A store in a temporary directory, plus one namespace inside it.
struct Store {
    _dir: TempDir,
    paths: Paths,
    ns_dir: PathBuf,
}

fn store() -> Store {
    let dir = TempDir::new().expect("a temporary directory should be available");
    let paths = Paths::with_config_dir(dir.path().join("agentctl"));
    let ns_dir = paths.namespace_dir("acct", "org");
    Store { _dir: dir, paths, ns_dir }
}

fn ctx() -> PassCtx {
    PassCtx::standalone(Cancel::new(), Instant::now() + std::time::Duration::from_secs(30))
}

/// A minimal blob with the given tokens.
fn blob(access: &str, refresh: Option<&str>) -> String {
    let refresh = match refresh {
        Some(refresh) => format!(r#""refreshToken":"{refresh}","#),
        None => String::new(),
    };
    format!(
        r#"{{"claudeAiOauth":{{"accessToken":"{access}",{refresh}"expiresAt":9999999999999}}}}"#
    )
}

fn digests_of(json: &str) -> Digests {
    Credentials::parse_blob(json.as_bytes()).expect("the blob should parse").digests()
}

fn request<'a>(
    store: &'a Store,
    json: &'a str,
    prior: Option<&'a Digests>,
    fault: Fault,
) -> WriteRequest<'a> {
    WriteRequest {
        paths: &store.paths,
        ns_dir: &store.ns_dir,
        blob_json: json,
        prior,
        new_expires_at_ms: 9_999_999_999_999,
        fault,
    }
}

fn write(store: &Store, json: &str, prior: Option<&Digests>, fault: Fault) -> WriteOutcome {
    write_credentials(&request(store, json, prior, fault), &ctx())
        .unwrap_or_else(|err| panic!("the write should succeed: {err}"))
}

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path).expect("the path should exist").permissions().mode() & 0o777
}

#[test]
fn a_present_read_reports_the_file_s_identity_alongside_its_bytes() {
    // The snapshot is what the refresh path re-checks immediately before the
    // rename (plan section 3.3), so a read that did not carry it would leave
    // that check with nothing to compare against.
    let store = store();
    let json = blob("access-1", Some("refresh-1"));
    write(&store, &json, None, Fault::none());

    let ReadOutcome::Present { bytes, snap } =
        read_credentials(&store.ns_dir).expect("the file should be readable")
    else {
        panic!("the file was just written")
    };
    assert_eq!(bytes, json.as_bytes());

    let stat = snapshot(&store.ns_dir.join(CREDENTIALS_FILE))
        .expect("the file exists")
        .expect("the file exists");
    assert_eq!(snap, stat, "the read and a bare lstat agree about the file's identity");
    assert_eq!(snap.size, u64::try_from(json.len()).expect("a small file"));
    assert!(snap.ino > 0 && snap.dev > 0 && snap.mtime_ns > 0);
}

#[test]
fn reading_an_absent_namespace_is_absent_not_an_error() {
    let store = store();
    assert!(matches!(read_credentials(&store.ns_dir), Ok(ReadOutcome::Absent)));
}

#[test]
fn reading_through_a_component_that_is_a_file_is_absent() {
    // ENOTDIR, which fact F40 lists among the absent errnos.
    let store = store();
    std::fs::create_dir_all(store.ns_dir.parent().expect("the namespace has a parent"))
        .expect("directories should be creatable");
    std::fs::write(&store.ns_dir, b"not a directory").expect("the file should be creatable");
    assert!(matches!(read_credentials(&store.ns_dir), Ok(ReadOutcome::Absent)));
}

#[test]
fn a_directory_named_credentials_json_is_a_failure_not_an_absence() {
    // `EISDIR` is in fact F40's absent set, but macOS does not raise it:
    // `open(dir, O_RDONLY)` succeeds and only a write would fail. So the
    // regular-file check is what catches this, and it reports a failure —
    // which is the safer of the two answers, because "absent" would lead to
    // `needs login` and then a write the store would refuse anyway.
    let store = store();
    std::fs::create_dir_all(store.ns_dir.join(CREDENTIALS_FILE))
        .expect("directories should be creatable");

    let err = read_credentials(&store.ns_dir).expect_err("a directory is not credentials");
    assert!(matches!(err, FileStoreError::NotRegular(_)), "got {err:?}");
}

#[test]
fn a_symlinked_credentials_file_is_a_failure_not_an_absence() {
    // Plan AC46. "Absent" would lead to writing a new file over that path,
    // and the link points somewhere agentctl has not checked.
    let store = store();
    std::fs::create_dir_all(&store.ns_dir).expect("directories should be creatable");
    let target = store.ns_dir.join("elsewhere.json");
    std::fs::write(&target, blob("a", None)).expect("the target should be writable");
    std::os::unix::fs::symlink(&target, store.ns_dir.join(CREDENTIALS_FILE))
        .expect("the symlink should be creatable");

    let err = read_credentials(&store.ns_dir).expect_err("a symlink must not be read");
    assert!(matches!(err, FileStoreError::RefusedSymlink(_)), "got {err:?}");
}

#[test]
fn an_oversized_credentials_file_is_a_failure_not_an_absence() {
    let store = store();
    std::fs::create_dir_all(&store.ns_dir).expect("directories should be creatable");
    let big = vec![b'x'; usize::try_from(MAX_CREDENTIALS_BYTES).unwrap_or(usize::MAX) + 1];
    std::fs::write(store.ns_dir.join(CREDENTIALS_FILE), big).expect("the file should be writable");

    let err = read_credentials(&store.ns_dir).expect_err("an oversized file must not be read");
    assert!(matches!(err, FileStoreError::TooLarge { .. }), "got {err:?}");
}

#[test]
fn snapshot_reports_absence_refuses_links_and_changes_with_the_file() {
    let dir = TempDir::new().expect("a temporary directory");
    let path = dir.path().join("file");
    assert!(snapshot(&path).expect("an absent path is not an error").is_none());

    std::fs::write(&path, b"one").expect("the file should be writable");
    let first = snapshot(&path).expect("the file exists").expect("the file exists");
    assert_eq!(first.size, 3);
    assert!(first.ino > 0 && first.dev > 0);

    // A replacement changes the inode even when the size matches, which is
    // the case a size-and-mtime check would miss.
    std::fs::remove_file(&path).expect("the file should be removable");
    std::fs::write(&path, b"two").expect("the file should be writable");
    let second = snapshot(&path).expect("the file exists").expect("the file exists");
    assert_ne!(first, second);
    assert!(second.mtime_ns >= first.mtime_ns || second.ino != first.ino);

    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&path, &link).expect("the symlink should be creatable");
    assert!(snapshot(&link).is_err(), "a symlink must be refused, not followed");
}

#[test]
fn a_write_lands_at_0600_in_0700_directories_and_leaves_no_temporary() {
    let store = store();
    let json = blob("access-1", Some("refresh-1"));
    let outcome = write(&store, &json, None, Fault::none());
    let WriteOutcome::Written { snap } = outcome else { panic!("the rename should succeed") };

    let target = store.ns_dir.join(CREDENTIALS_FILE);
    assert_eq!(std::fs::read_to_string(&target).expect("the file should be readable"), json);
    assert_eq!(mode_of(&target), FILE_MODE);
    assert_eq!(snap.size, u64::try_from(json.len()).expect("a small file"));

    for dir in [store.paths.namespace_root(), store.ns_dir.clone()] {
        assert_eq!(mode_of(&dir), crate::config::paths::DIR_MODE, "{}", dir.display());
    }
    assert!(list_stray_tmp(&store.ns_dir).expect("the namespace should be listable").is_empty());
}

#[test]
fn a_second_write_replaces_the_file_with_a_new_inode() {
    let store = store();
    let first = blob("access-1", Some("refresh-1"));
    let WriteOutcome::Written { snap: before } = write(&store, &first, None, Fault::none()) else {
        panic!("the first write should land")
    };

    let second = blob("access-2", Some("refresh-2"));
    let prior = digests_of(&first);
    let WriteOutcome::Written { snap: after } = write(&store, &second, Some(&prior), Fault::none())
    else {
        panic!("the second write should land")
    };

    assert_ne!(before.ino, after.ino, "the replacement is atomic, not in-place");
    assert_eq!(
        std::fs::read_to_string(store.ns_dir.join(CREDENTIALS_FILE))
            .expect("the file should be readable"),
        second
    );
}

#[test]
fn a_write_outside_the_namespace_root_is_refused() {
    // Plan AC15, invariant I1.
    let store = store();
    let outside = store.paths.config_dir().to_path_buf();
    let escaping = store.paths.namespace_root().join("..").join("..").join("elsewhere");
    for ns_dir in [outside, escaping, PathBuf::from("/tmp/agentctl-should-never-be-written")] {
        let json = blob("a", None);
        let request = WriteRequest {
            paths: &store.paths,
            ns_dir: &ns_dir,
            blob_json: &json,
            prior: None,
            new_expires_at_ms: 0,
            fault: Fault::none(),
        };
        let err = write_credentials(&request, &ctx())
            .expect_err(&format!("`{}` must be refused", ns_dir.display()));
        assert!(matches!(err, FileStoreError::OutsideNamespaceRoot(_)), "got {err:?}");
        assert!(!ns_dir.join(CREDENTIALS_FILE).exists());
    }
}

#[test]
fn a_write_over_a_symlink_is_refused() {
    let store = store();
    std::fs::create_dir_all(&store.ns_dir).expect("directories should be creatable");
    let elsewhere = store.ns_dir.join("elsewhere.json");
    std::fs::write(&elsewhere, b"{}").expect("the target should be writable");
    std::os::unix::fs::symlink(&elsewhere, store.ns_dir.join(CREDENTIALS_FILE))
        .expect("the symlink should be creatable");

    let json = blob("a", None);
    let err = write_credentials(&request(&store, &json, None, Fault::none()), &ctx())
        .expect_err("a symlinked target must be refused");
    assert!(matches!(err, FileStoreError::RefusedSymlink(_)), "got {err:?}");
    assert_eq!(
        std::fs::read_to_string(&elsewhere).expect("readable"),
        "{}",
        "the link's target is untouched"
    );
}

#[test]
fn a_write_over_a_directory_is_refused() {
    let store = store();
    std::fs::create_dir_all(store.ns_dir.join(CREDENTIALS_FILE))
        .expect("directories should be creatable");
    let json = blob("a", None);
    let err = write_credentials(&request(&store, &json, None, Fault::none()), &ctx())
        .expect_err("a directory target must be refused");
    assert!(matches!(err, FileStoreError::NotRegular(_)), "got {err:?}");
}

#[test]
fn list_stray_tmp_finds_only_the_eight_hex_shape() {
    let store = store();
    std::fs::create_dir_all(&store.ns_dir).expect("directories should be creatable");
    let good = store.ns_dir.join(format!("{CREDENTIALS_FILE}.tmp.0123abcd"));
    let bad = [
        store.ns_dir.join(format!("{CREDENTIALS_FILE}.tmp.short")),
        store.ns_dir.join(format!("{CREDENTIALS_FILE}.tmp.0123abcde")),
        store.ns_dir.join(CREDENTIALS_FILE),
        store.ns_dir.join("unrelated"),
    ];
    for path in std::iter::once(&good).chain(bad.iter()) {
        std::fs::write(path, b"x").expect("the file should be writable");
    }

    let found = list_stray_tmp(&store.ns_dir).expect("the namespace should be listable");
    assert_eq!(found, vec![good]);
}

#[test]
fn remove_namespace_clears_the_files_and_the_directories() {
    let store = store();
    let json = blob("a", Some("r"));
    write(&store, &json, None, Fault::none());
    std::fs::write(store.ns_dir.join(PENDING_FILE), &json).expect("writable");
    std::fs::write(store.ns_dir.join(PENDING_META), b"{}").expect("writable");
    std::fs::write(store.ns_dir.join(format!("{CREDENTIALS_FILE}.tmp.deadbeef")), b"x")
        .expect("writable");

    // A lock file for the namespace, which must survive (plan section 3.5).
    let locks_dir = store.paths.locks_dir();
    std::fs::create_dir_all(&locks_dir).expect("directories should be creatable");
    let lock = store.paths.lock_path("acct", "org");
    std::fs::write(&lock, b"{}").expect("writable");

    remove_namespace(&store.paths, &store.ns_dir).expect("removal should succeed");

    assert!(!store.ns_dir.exists(), "the namespace directory is gone");
    assert!(lock.exists(), "the lock file is never unlinked");
    assert!(store.paths.namespace_root().exists(), "the root survives");
}

#[test]
fn remove_namespace_refuses_a_path_outside_the_root() {
    let store = store();
    let err = remove_namespace(&store.paths, store.paths.config_dir())
        .expect_err("the config directory is not a namespace");
    assert!(matches!(err, FileStoreError::OutsideNamespaceRoot(_)), "got {err:?}");
}

#[test]
fn resolve_pending_with_nothing_pending_does_nothing() {
    let store = store();
    std::fs::create_dir_all(&store.ns_dir).expect("directories should be creatable");
    assert_eq!(
        resolve_pending(&store.ns_dir, &ForeignActivity::None).expect("resolution should succeed"),
        PendingDecision::NoPending
    );
}

#[test]
fn resolve_pending_clears_a_meta_left_without_a_pending_file() {
    // The crash window: the metadata is written before the pending file, so
    // this state means the process died between the two and there is nothing
    // to replay.
    let store = store();
    std::fs::create_dir_all(&store.ns_dir).expect("directories should be creatable");
    let meta = store.ns_dir.join(PENDING_META);
    std::fs::write(&meta, b"{}").expect("writable");

    assert_eq!(
        resolve_pending(&store.ns_dir, &ForeignActivity::None).expect("resolution should succeed"),
        PendingDecision::NoPending
    );
    assert!(!meta.exists(), "the orphaned marker is cleared");
}

/// Sets up a namespace with a pending file, its metadata, and optionally a
/// current credentials file.
fn stage_pending(store: &Store, current: Option<&str>, meta: &PendingMeta, pending: &str) {
    std::fs::create_dir_all(&store.ns_dir).expect("directories should be creatable");
    if let Some(current) = current {
        std::fs::write(store.ns_dir.join(CREDENTIALS_FILE), current).expect("writable");
    }
    std::fs::write(
        store.ns_dir.join(PENDING_META),
        serde_json::to_string(meta).expect("the metadata should serialize"),
    )
    .expect("writable");
    std::fs::write(store.ns_dir.join(PENDING_FILE), pending).expect("writable");
}

fn meta_from(prior: Option<&Digests>) -> PendingMeta {
    PendingMeta {
        derived_from_access_sha256: prior.map(|d| d.access_sha256.clone()),
        derived_from_refresh_sha256: prior.and_then(|d| d.refresh_sha256.clone()),
        created_at: "2026-09-09T00:00:00Z".to_owned(),
        new_expires_at: 9_999_999_999_999,
    }
}

#[test]
fn pending_row_a_replays_when_the_file_is_unchanged() {
    let store = store();
    let current = blob("old-access", Some("old-refresh"));
    let pending = blob("new-access", Some("old-refresh"));
    stage_pending(&store, Some(&current), &meta_from(Some(&digests_of(&current))), &pending);

    let decision =
        resolve_pending(&store.ns_dir, &ForeignActivity::None).expect("resolution should succeed");
    assert_eq!(decision, PendingDecision::Replayed { first_write: false });
    assert_eq!(
        std::fs::read_to_string(store.ns_dir.join(CREDENTIALS_FILE)).expect("readable"),
        pending
    );
    assert!(!store.ns_dir.join(PENDING_FILE).exists());
    assert!(!store.ns_dir.join(PENDING_META).exists());
    assert_eq!(mode_of(&store.ns_dir.join(CREDENTIALS_FILE)), FILE_MODE);
}

#[test]
fn pending_row_b_discards_when_the_file_was_replaced() {
    let store = store();
    let derived_from = blob("old-access", Some("old-refresh"));
    let now_on_disk = blob("someone-elses-access", Some("someone-elses-refresh"));
    stage_pending(
        &store,
        Some(&now_on_disk),
        &meta_from(Some(&digests_of(&derived_from))),
        &blob("new-access", Some("old-refresh")),
    );

    let decision =
        resolve_pending(&store.ns_dir, &ForeignActivity::None).expect("resolution should succeed");
    assert_eq!(decision, PendingDecision::Discarded(PendingDiscardReason::FileChanged));
    assert_eq!(
        std::fs::read_to_string(store.ns_dir.join(CREDENTIALS_FILE)).expect("readable"),
        now_on_disk,
        "the file that was there wins"
    );
    assert!(!store.ns_dir.join(PENDING_FILE).exists());
}

#[test]
fn pending_row_c_replays_even_when_the_pending_token_has_itself_expired() {
    // The replay is decided by digests, not by `new_expires_at`: an expired
    // replayed token is simply refreshed on the next step.
    let store = store();
    let current = blob("old-access", Some("old-refresh"));
    let mut meta = meta_from(Some(&digests_of(&current)));
    meta.new_expires_at = 1;
    stage_pending(&store, Some(&current), &meta, &blob("new-access", Some("old-refresh")));

    assert_eq!(
        resolve_pending(&store.ns_dir, &ForeignActivity::None).expect("resolution should succeed"),
        PendingDecision::Replayed { first_write: false }
    );
}

#[test]
fn pending_row_d_discards_when_the_metadata_is_missing_or_corrupt() {
    for corrupt in [None, Some("not json"), Some("{}")] {
        let store = store();
        std::fs::create_dir_all(&store.ns_dir).expect("directories should be creatable");
        std::fs::write(store.ns_dir.join(PENDING_FILE), blob("new", None)).expect("writable");
        if let Some(text) = corrupt {
            std::fs::write(store.ns_dir.join(PENDING_META), text).expect("writable");
        }

        assert_eq!(
            resolve_pending(&store.ns_dir, &ForeignActivity::None)
                .expect("resolution should succeed"),
            PendingDecision::Discarded(PendingDiscardReason::Invalid),
            "metadata: {corrupt:?}"
        );
        assert!(!store.ns_dir.join(PENDING_FILE).exists());
    }
}

#[test]
fn pending_row_e_discards_a_symlinked_pending_file() {
    let store = store();
    std::fs::create_dir_all(&store.ns_dir).expect("directories should be creatable");
    let elsewhere = store.ns_dir.join("elsewhere.json");
    std::fs::write(&elsewhere, blob("smuggled", None)).expect("writable");
    std::os::unix::fs::symlink(&elsewhere, store.ns_dir.join(PENDING_FILE))
        .expect("the symlink should be creatable");
    std::fs::write(
        store.ns_dir.join(PENDING_META),
        serde_json::to_string(&meta_from(None)).expect("serializable"),
    )
    .expect("writable");

    assert_eq!(
        resolve_pending(&store.ns_dir, &ForeignActivity::None).expect("resolution should succeed"),
        PendingDecision::Discarded(PendingDiscardReason::Invalid)
    );
    assert!(!store.ns_dir.join(CREDENTIALS_FILE).exists(), "nothing was replayed through the link");
}

#[test]
fn pending_row_f_replays_a_first_write() {
    let store = store();
    let pending = blob("first-access", Some("first-refresh"));
    stage_pending(&store, None, &meta_from(None), &pending);

    assert_eq!(
        resolve_pending(&store.ns_dir, &ForeignActivity::None).expect("resolution should succeed"),
        PendingDecision::Replayed { first_write: true }
    );
    assert_eq!(
        std::fs::read_to_string(store.ns_dir.join(CREDENTIALS_FILE)).expect("readable"),
        pending
    );
}

#[test]
fn pending_row_g_discards_when_the_file_it_replaced_was_removed() {
    let store = store();
    let derived_from = blob("old-access", Some("old-refresh"));
    stage_pending(&store, None, &meta_from(Some(&digests_of(&derived_from))), &blob("new", None));

    assert_eq!(
        resolve_pending(&store.ns_dir, &ForeignActivity::None).expect("resolution should succeed"),
        PendingDecision::Discarded(PendingDiscardReason::FileRemoved)
    );
    assert!(!store.ns_dir.join(CREDENTIALS_FILE).exists());
}

#[test]
fn pending_row_h_discards_when_the_namespace_has_been_taken_over() {
    let store = store();
    let current = blob("old-access", Some("old-refresh"));
    let pending = blob("new-access", Some("old-refresh"));
    let foreign = [
        ForeignActivity::MigratedToKeychain {
            service: "Claude Code-credentials-5cdc535f".to_owned(),
        },
        ForeignActivity::ClaudeLock { name: ".oauth_refresh.lock".to_owned(), age_ms: 500 },
    ];
    for activity in foreign {
        stage_pending(&store, Some(&current), &meta_from(Some(&digests_of(&current))), &pending);
        assert_eq!(
            resolve_pending(&store.ns_dir, &activity).expect("resolution should succeed"),
            PendingDecision::Discarded(PendingDiscardReason::NamespaceTakenOver),
            "{activity:?}"
        );
        assert_eq!(
            std::fs::read_to_string(store.ns_dir.join(CREDENTIALS_FILE)).expect("readable"),
            current,
            "the namespace's own file is left alone"
        );
    }
}

#[test]
fn discard_reasons_have_the_plan_wording() {
    assert_eq!(PendingDiscardReason::Invalid.label(), "invalid");
    assert_eq!(PendingDiscardReason::NamespaceTakenOver.label(), "namespace taken over");
    assert_eq!(PendingDiscardReason::FileChanged.label(), "file changed");
    assert_eq!(PendingDiscardReason::FileRemoved.label(), "file removed");
}

#[test]
fn hex8_is_eight_lowercase_hex_digits() {
    for _ in 0..32 {
        let value = hex8();
        assert_eq!(value.len(), 8, "`{value}` should be eight characters");
        assert!(
            value.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "`{value}` should be lowercase hex"
        );
    }
}

#[cfg(feature = "testing")]
#[test]
fn a_failed_rename_parks_the_credentials_and_writes_the_metadata_first() {
    let store = store();
    let first = blob("old-access", Some("old-refresh"));
    write(&store, &first, None, Fault::none());

    let prior = digests_of(&first);
    let second = blob("new-access", Some("old-refresh"));
    let outcome = write(&store, &second, Some(&prior), Fault::from_list("rename_fail"));

    let WriteOutcome::SavedToPending { error } = outcome else {
        panic!("the injected rename failure should park the credentials")
    };
    assert!(!error.is_empty(), "the row explains why the write failed");

    assert_eq!(
        std::fs::read_to_string(store.ns_dir.join(CREDENTIALS_FILE)).expect("readable"),
        first,
        "the old credentials are still in place"
    );
    assert_eq!(std::fs::read_to_string(store.ns_dir.join(PENDING_FILE)).expect("readable"), second);
    assert!(
        list_stray_tmp(&store.ns_dir).expect("listable").is_empty(),
        "the temporary file became the pending file"
    );

    let meta: PendingMeta = serde_json::from_slice(
        &std::fs::read(store.ns_dir.join(PENDING_META)).expect("the metadata should exist"),
    )
    .expect("the metadata should parse");
    assert_eq!(meta.derived_from_access_sha256, Some(prior.access_sha256));
    assert_eq!(meta.derived_from_refresh_sha256, prior.refresh_sha256);
    assert_eq!(meta.new_expires_at, 9_999_999_999_999);
    assert!(!meta.created_at.is_empty());

    // And the round trip: the next run replays it, because nothing changed.
    assert_eq!(
        resolve_pending(&store.ns_dir, &ForeignActivity::None).expect("resolution should succeed"),
        PendingDecision::Replayed { first_write: false }
    );
    assert_eq!(
        std::fs::read_to_string(store.ns_dir.join(CREDENTIALS_FILE)).expect("readable"),
        second
    );
}

#[cfg(feature = "testing")]
#[test]
fn a_failed_first_rename_records_null_digests() {
    let store = store();
    let json = blob("first-access", Some("first-refresh"));
    let outcome = write(&store, &json, None, Fault::from_list("rename_fail"));
    assert!(matches!(outcome, WriteOutcome::SavedToPending { .. }));

    let meta: PendingMeta = serde_json::from_slice(
        &std::fs::read(store.ns_dir.join(PENDING_META)).expect("the metadata should exist"),
    )
    .expect("the metadata should parse");
    assert_eq!(meta.derived_from_access_sha256, None);
    assert_eq!(meta.derived_from_refresh_sha256, None);

    assert_eq!(
        resolve_pending(&store.ns_dir, &ForeignActivity::None).expect("resolution should succeed"),
        PendingDecision::Replayed { first_write: true }
    );
}

#[cfg(feature = "testing")]
#[test]
fn an_unarmed_pause_point_does_not_delay_a_write() {
    let store = store();
    let json = blob("a", None);
    let start = Instant::now();
    write(&store, &json, None, Fault::from_list("rename_fail_not_armed"));
    assert!(start.elapsed() < std::time::Duration::from_secs(5));
}

/// Plants `link` as a symbolic link to a directory that is not part of the
/// store, and puts one file inside it whose survival the caller asserts.
///
/// This is the shape of the escape the `O_NOFOLLOW` walk exists to close: the
/// path still *spells* something under the namespace root, so the lexical
/// check passes, and it resolves to a directory another program owns.
fn plant_directory_link(dir: &TempDir, link: &Path) -> PathBuf {
    let elsewhere = dir.path().join("someone-elses-store");
    std::fs::create_dir_all(&elsewhere).expect("directories should be creatable");
    std::fs::write(elsewhere.join(CREDENTIALS_FILE), b"not agentctl's").expect("writable");
    std::fs::create_dir_all(link.parent().expect("the link has a parent"))
        .expect("directories should be creatable");
    std::os::unix::fs::symlink(&elsewhere, link).expect("the symlink should be creatable");
    elsewhere
}

fn assert_untouched(elsewhere: &Path) {
    assert_eq!(
        std::fs::read_to_string(elsewhere.join(CREDENTIALS_FILE)).expect("readable"),
        "not agentctl's",
        "the link's target was written through"
    );
    let strays: Vec<_> = std::fs::read_dir(elsewhere)
        .expect("listable")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name != CREDENTIALS_FILE)
        .collect();
    assert!(strays.is_empty(), "the link's target gained files: {strays:?}");
}

#[test]
fn a_write_through_a_symlinked_account_component_is_refused() {
    // The lexical under-root check passes — `<root>/acct/org` spells a path
    // below the root — and the walk is what refuses.
    let store = store();
    let elsewhere = plant_directory_link(&store._dir, &store.paths.namespace_root().join("acct"));

    let json = blob("a", None);
    let err = write_credentials(&request(&store, &json, None, Fault::none()), &ctx())
        .expect_err("a symlinked account component must be refused");
    assert!(matches!(err, FileStoreError::RefusedSymlink(_)), "got {err:?}");
    assert_untouched(&elsewhere);
}

#[test]
fn a_write_through_a_symlinked_organization_component_is_refused() {
    let store = store();
    let elsewhere = plant_directory_link(&store._dir, &store.ns_dir);

    let json = blob("a", None);
    let err = write_credentials(&request(&store, &json, None, Fault::none()), &ctx())
        .expect_err("a symlinked organization component must be refused");
    assert!(matches!(err, FileStoreError::RefusedSymlink(_)), "got {err:?}");
    assert_untouched(&elsewhere);
}

#[test]
fn a_component_that_is_a_file_is_refused_rather_than_walked_through() {
    let store = store();
    std::fs::create_dir_all(store.paths.namespace_root()).expect("directories should be creatable");
    std::fs::write(store.paths.namespace_root().join("acct"), b"not a directory")
        .expect("writable");

    let json = blob("a", None);
    let err = write_credentials(&request(&store, &json, None, Fault::none()), &ctx())
        .expect_err("a component that is a file must be refused");
    assert!(matches!(err, FileStoreError::NotRegular(_)), "got {err:?}");
}

#[test]
fn remove_namespace_refuses_a_symlinked_component() {
    // Deleting through a link is the same escape as writing through one, and
    // a worse one to discover after the fact.
    let store = store();
    let elsewhere = plant_directory_link(&store._dir, &store.ns_dir);

    let err = remove_namespace(&store.paths, &store.ns_dir)
        .expect_err("a symlinked namespace must be refused");
    assert!(matches!(err, FileStoreError::RefusedSymlink(_)), "got {err:?}");
    assert_untouched(&elsewhere);
    assert!(store.ns_dir.exists(), "the link itself is left for the user to deal with");
}

#[test]
fn resolve_pending_refuses_a_symlinked_component() {
    let store = store();
    let elsewhere = plant_directory_link(&store._dir, &store.ns_dir);
    std::fs::write(elsewhere.join(PENDING_FILE), blob("smuggled", None)).expect("writable");
    std::fs::write(
        elsewhere.join(PENDING_META),
        serde_json::to_string(&meta_from(None)).expect("serializable"),
    )
    .expect("writable");

    let err = resolve_pending(&store.ns_dir, &ForeignActivity::None)
        .expect_err("a symlinked namespace must be refused");
    assert!(matches!(err, FileStoreError::RefusedSymlink(_)), "got {err:?}");
    assert_eq!(
        std::fs::read_to_string(elsewhere.join(CREDENTIALS_FILE)).expect("readable"),
        "not agentctl's",
        "nothing was replayed through the link"
    );
    assert!(elsewhere.join(PENDING_FILE).exists(), "and nothing was deleted through it either");
}

#[test]
fn a_cancelled_pass_unlinks_the_temporary_file_and_leaves_the_old_one() {
    // The window between `fsync` and `rename` is the last one in which
    // stopping costs nothing, so `Ctrl-C` there must cost nothing.
    let store = store();
    let first = blob("old-access", Some("old-refresh"));
    write(&store, &first, None, Fault::none());

    let cancel = Cancel::new();
    cancel.cancel();
    let ctx = PassCtx::standalone(cancel, Instant::now() + std::time::Duration::from_secs(30));

    let prior = digests_of(&first);
    let second = blob("new-access", Some("old-refresh"));
    let err = write_credentials(&request(&store, &second, Some(&prior), Fault::none()), &ctx)
        .expect_err("a cancelled pass must not replace the credentials");
    assert!(matches!(err, FileStoreError::Cancelled(_)), "got {err:?}");

    assert_eq!(
        std::fs::read_to_string(store.ns_dir.join(CREDENTIALS_FILE)).expect("readable"),
        first,
        "the old credentials are still in place"
    );
    assert!(
        list_stray_tmp(&store.ns_dir).expect("listable").is_empty(),
        "the staged replacement was unlinked, not left holding a token at rest"
    );
    assert!(!store.ns_dir.join(PENDING_FILE).exists(), "and it was not parked as pending either");
}

// ---------------------------------------------------------------------------
// remove_dir_under_root — the artefacts Claude Code actually leaves (AC73)
// ---------------------------------------------------------------------------

/// Creates one lock *directory* in the namespace, the way Claude Code does.
fn plant_lock_dir(store: &Store, name: &str) -> PathBuf {
    std::fs::create_dir_all(&store.ns_dir).expect("directories should be creatable");
    let path = store.ns_dir.join(name);
    std::fs::create_dir(&path).expect("the lock directory should be creatable");
    path
}

#[test]
fn remove_dir_under_root_removes_an_empty_lock_directory() {
    // Fact F45: acquire is `mkdir` and release is `rmdir`, so an empty
    // directory is the whole shape of a lapsed lock.
    let store = store();
    let lock = plant_lock_dir(&store, ".oauth_refresh.lock");

    remove_dir_under_root(&store.paths, &lock).expect("an empty lock directory is removable");

    assert!(!lock.exists(), "the lock directory is gone");
    assert!(store.ns_dir.exists(), "and the namespace around it survives");
}

#[test]
fn remove_dir_under_root_refuses_a_non_empty_directory() {
    // Never a recursive delete: a lock directory with something in it is not
    // a lapsed lock, so `ENOTEMPTY` is reported rather than worked around.
    let store = store();
    let lock = plant_lock_dir(&store, ".storage-write");
    std::fs::write(lock.join("holder.json"), b"{}").expect("writable");

    let err = remove_dir_under_root(&store.paths, &lock)
        .expect_err("a non-empty directory must be refused");

    assert!(matches!(err, FileStoreError::NotEmpty(_)), "got {err:?}");
    assert!(lock.join("holder.json").exists(), "and its contents are untouched");
}

#[test]
fn remove_dir_under_root_refuses_a_regular_file() {
    // `AT_REMOVEDIR` refuses anything that is not a directory, which is what
    // keeps the anomalous case — a regular file at an artefact's name — away
    // from the code that removes the real thing.
    let store = store();
    std::fs::create_dir_all(&store.ns_dir).expect("directories should be creatable");
    let file = store.ns_dir.join(".oauth_refresh.lock");
    std::fs::write(&file, b"{}").expect("writable");

    let err =
        remove_dir_under_root(&store.paths, &file).expect_err("a regular file must be refused");

    assert!(matches!(err, FileStoreError::NotRegular(_)), "got {err:?}");
    assert!(file.exists(), "the file is still there");
}

#[test]
fn remove_dir_under_root_refuses_a_symlink_at_the_artefact() {
    // A link is not a directory, so `AT_REMOVEDIR` will not unlink it — and,
    // more to the point, cannot delete what it points at.
    let store = store();
    let target = plant_lock_dir(&store, "target.lock");
    let link = store.ns_dir.join(".oauth_refresh.lock");
    std::os::unix::fs::symlink(&target, &link).expect("the symlink should be creatable");

    let err = remove_dir_under_root(&store.paths, &link).expect_err("a symlink must be refused");

    assert!(matches!(err, FileStoreError::NotRegular(_)), "got {err:?}");
    assert!(std::fs::symlink_metadata(&link).is_ok(), "the link is still there");
    assert!(target.exists(), "and so is what it pointed at");
}

#[test]
fn remove_dir_under_root_refuses_a_symlinked_component() {
    // The escape the walk exists to close: the path spells a location under
    // the root while `<org>` is a link into somebody else's store.
    let store = store();
    let elsewhere = plant_directory_link(&store._dir, &store.ns_dir);
    std::fs::create_dir(elsewhere.join(".oauth_refresh.lock"))
        .expect("the victim's lock directory should be creatable");

    let err = remove_dir_under_root(&store.paths, &store.ns_dir.join(".oauth_refresh.lock"))
        .expect_err("a symlinked component must be refused");

    assert!(matches!(err, FileStoreError::RefusedSymlink(_)), "got {err:?}");
    assert!(
        elsewhere.join(".oauth_refresh.lock").exists(),
        "the other store's lock directory is untouched"
    );
}

#[test]
fn remove_dir_under_root_refuses_a_path_outside_the_root() {
    let store = store();
    let outside = store._dir.path().join("elsewhere");
    std::fs::create_dir_all(&outside).expect("directories should be creatable");
    let lock = outside.join(".oauth_refresh.lock");
    std::fs::create_dir(&lock).expect("the lock directory should be creatable");

    let err = remove_dir_under_root(&store.paths, &lock)
        .expect_err("a path outside the namespace root must be refused");

    assert!(matches!(err, FileStoreError::OutsideNamespaceRoot(_)), "got {err:?}");
    assert!(lock.exists(), "nothing outside the root was removed");
}

#[test]
fn remove_dir_under_removes_below_the_anchor_it_is_given() {
    // The attested outside-root removal (plan section 3.9): the anchor is the
    // record's store directory's parent, and the store directory itself stays
    // a walked component — which is why a link there is still refused.
    let store = store();
    let home = store._dir.path().join("home");
    let live = home.join(".claude");
    std::fs::create_dir_all(&live).expect("directories should be creatable");
    let lock = live.join(".oauth_refresh.lock");
    std::fs::create_dir(&lock).expect("the lock directory should be creatable");

    remove_dir_under(&home, &lock).expect("a lock directory below the anchor is removable");
    assert!(!lock.exists(), "the leaked lock directory is gone");
    assert!(live.exists(), "and the store around it survives");

    // The legacy lock sits *beside* the store directory (fact F17), which is
    // why the anchor is the parent rather than the store itself.
    let legacy = home.join(".claude.lock");
    std::fs::create_dir(&legacy).expect("the legacy lock directory should be creatable");
    remove_dir_under(&home, &legacy).expect("the legacy lock is below the same anchor");
    assert!(!legacy.exists());
}

#[test]
fn remove_dir_under_refuses_a_symlinked_store_directory() {
    let store = store();
    let home = store._dir.path().join("home");
    std::fs::create_dir_all(&home).expect("directories should be creatable");
    let elsewhere = store._dir.path().join("someone-elses-claude");
    std::fs::create_dir_all(elsewhere.join(".oauth_refresh.lock"))
        .expect("directories should be creatable");
    std::os::unix::fs::symlink(&elsewhere, home.join(".claude"))
        .expect("the symlink should be creatable");

    let err = remove_dir_under(&home, &home.join(".claude").join(".oauth_refresh.lock"))
        .expect_err("a symlinked store directory must be refused");

    assert!(matches!(err, FileStoreError::RefusedSymlink(_)), "got {err:?}");
    assert!(elsewhere.join(".oauth_refresh.lock").exists(), "the target is untouched");
}

// ---------------------------------------------------------------------------
// `create_dir_under` (`agentctl-p2-held-locks-dir-through-symlink-1yj`)
// ---------------------------------------------------------------------------

/// The mode bits of a path, without following links.
fn lmode_of(path: &Path) -> u32 {
    fs::symlink_metadata(path).expect("the path should exist").permissions().mode() & 0o777
}

#[test]
fn create_dir_under_makes_a_missing_directory_at_0700_and_reopens_an_existing_one() {
    let store = store();
    let anchor = store.paths.namespace_root();
    fs::create_dir_all(&anchor).expect("the anchor should be creatable");
    let dir = anchor.join("held-locks");

    let fd = create_dir_under(&anchor, &dir).expect("a missing directory is created");
    assert!(dir.is_dir(), "it is there afterwards");
    assert_eq!(lmode_of(&dir), 0o700, "0700, set on the descriptor rather than left to the umask");
    // The descriptor addresses that directory, which is the whole point of
    // returning one: a file made through it lands there.
    create_new_file_at(fd.as_fd(), "probe", b"x").expect("the descriptor is writable");
    assert!(dir.join("probe").is_file());
    drop(fd);

    // A second call finds it and opens it rather than failing on `EEXIST`.
    let again = create_dir_under(&anchor, &dir).expect("an existing directory is reopened");
    create_new_file_at(again.as_fd(), "probe-2", b"x").expect("still the same directory");
    assert!(dir.join("probe-2").is_file());
}

#[test]
fn create_dir_under_refuses_a_symlink_at_the_directory_it_would_create() {
    // The finding this exists for: the old code asked `Path::is_dir`, which
    // follows links, and then created and wrote by path.
    let store = store();
    let anchor = store.paths.namespace_root();
    fs::create_dir_all(&anchor).expect("the anchor should be creatable");
    let elsewhere = store._dir.path().join("elsewhere");
    fs::create_dir(&elsewhere).expect("the decoy should be creatable");

    let dir = anchor.join("held-locks");
    std::os::unix::fs::symlink(&elsewhere, &dir).expect("the link should be plantable");
    assert!(dir.is_dir(), "`is_dir` follows the link and says yes, which was the bug");

    let err = create_dir_under(&anchor, &dir).expect_err("a link at the leaf is refused");
    assert!(matches!(err, FileStoreError::RefusedSymlink(_)), "got {err:?}");
    assert!(
        fs::read_dir(&elsewhere).expect("readable").next().is_none(),
        "nothing was created through the link"
    );
    assert!(
        fs::symlink_metadata(&dir).expect("still there").file_type().is_symlink(),
        "and the link itself was neither followed nor replaced"
    );
}

#[test]
fn create_dir_under_refuses_a_symlink_above_the_directory_and_a_missing_anchor() {
    let store = store();
    let anchor = store.paths.namespace_root();
    fs::create_dir_all(&anchor).expect("the anchor should be creatable");
    let elsewhere = store._dir.path().join("elsewhere");
    fs::create_dir(&elsewhere).expect("the decoy should be creatable");

    // A link one level up is refused too: the walk checks every component,
    // not only the last.
    let middle = anchor.join("middle");
    std::os::unix::fs::symlink(&elsewhere, &middle).expect("the link should be plantable");
    let err = create_dir_under(&anchor, &middle.join("held-locks"))
        .expect_err("a link above the leaf is refused");
    assert!(matches!(err, FileStoreError::RefusedSymlink(_)), "got {err:?}");
    assert!(fs::read_dir(&elsewhere).expect("readable").next().is_none(), "nothing was created");

    // A regular file where a directory belongs is not a link, and is refused
    // as what it is.
    let occupied = anchor.join("occupied");
    fs::write(&occupied, b"not a directory").expect("the file should be writable");
    let err = create_dir_under(&anchor, &occupied).expect_err("a file is not a directory");
    assert!(matches!(err, FileStoreError::NotRegular(_)), "got {err:?}");

    // The anchor is the caller's own root and is never created by this walk.
    let absent = store._dir.path().join("no-such-root");
    let err = create_dir_under(&absent, &absent.join("held-locks"))
        .expect_err("a missing anchor is a failure, not something to create");
    assert!(matches!(err, FileStoreError::Io { .. }), "got {err:?}");
    assert!(!absent.exists(), "and nothing was made on the way to finding out");
}

// ---------------------------------------------------------------------------
// The adopted copy, staged and committed (decision D-024, finding P1-1)
// ---------------------------------------------------------------------------

#[test]
fn staging_an_adoption_leaves_the_copy_holding_what_it_held() {
    // The whole point of the split. Until the commit, the name that matters
    // still holds whatever it held — which on a reversal is the only
    // remaining home of the credential being restored.
    let store = store();
    write_adopted(&store.paths, &store.ns_dir, &blob("first", Some("r1")), &ctx())
        .expect("the first adoption should land");

    let staged = stage_adopted(&store.paths, &store.ns_dir, &blob("second", Some("r2")), &ctx())
        .expect("the staging should succeed");
    let copy = store.ns_dir.join(ADOPTED_FILE);
    assert!(
        fs::read_to_string(&copy).expect("readable").contains("first"),
        "the copy is untouched while the adoption is only staged"
    );
    assert_eq!(
        list_stray_adopted_tmp(&store.ns_dir).expect("listable").len(),
        1,
        "and the staged credential is on disk under a temporary name"
    );

    commit_staged(&store.paths, staged).expect("the commit should succeed");
    assert!(
        fs::read_to_string(&copy).expect("readable").contains("second"),
        "the commit is what replaces it"
    );
    assert!(
        list_stray_adopted_tmp(&store.ns_dir).expect("listable").is_empty(),
        "and the temporary name is gone"
    );
}

#[test]
fn dropping_a_staged_adoption_removes_the_temporary() {
    // Every Phase C exit that does not write drops the staging rather than
    // remembering to clean it up, so a token cannot be left at rest under a
    // name nothing reports.
    let store = store();
    write_adopted(&store.paths, &store.ns_dir, &blob("kept", Some("r1")), &ctx())
        .expect("the first adoption should land");

    {
        let _staged =
            stage_adopted(&store.paths, &store.ns_dir, &blob("dropped", Some("r2")), &ctx())
                .expect("the staging should succeed");
        assert_eq!(list_stray_adopted_tmp(&store.ns_dir).expect("listable").len(), 1);
    }

    assert!(
        list_stray_adopted_tmp(&store.ns_dir).expect("listable").is_empty(),
        "the temporary is removed on drop"
    );
    let copy = store.ns_dir.join(ADOPTED_FILE);
    assert!(
        fs::read_to_string(&copy).expect("readable").contains("kept"),
        "and the copy still holds what it held"
    );
    assert!(!fs::read_to_string(&copy).expect("readable").contains("dropped"));
}

#[test]
fn a_staged_adoption_is_written_0600_and_the_mode_survives_the_commit() {
    // The mode is set on the temporary's inode and carried by the rename, so
    // there is no window in which the credential is readable by anyone else.
    let store = store();
    let staged = stage_adopted(&store.paths, &store.ns_dir, &blob("mode", Some("r1")), &ctx())
        .expect("the staging should succeed");
    let tmp = list_stray_adopted_tmp(&store.ns_dir).expect("listable").pop().expect("one staged");
    assert_eq!(
        fs::metadata(&tmp).expect("readable").permissions().mode() & 0o777,
        FILE_MODE,
        "the staged credential is 0600 before it is anything else"
    );

    commit_staged(&store.paths, staged).expect("the commit should succeed");
    let copy = store.ns_dir.join(ADOPTED_FILE);
    assert_eq!(
        fs::metadata(&copy).expect("readable").permissions().mode() & 0o777,
        FILE_MODE,
        "and the rename carries it"
    );
}

#[test]
fn a_symlink_at_the_adopted_name_refuses_before_anything_is_written() {
    // Somebody planted a link where the copy goes. Refusing at the staging is
    // what makes the refusal free: nothing has been created yet.
    let store = store();
    fs::create_dir_all(&store.ns_dir).expect("the namespace should be creatable");
    let target = store.ns_dir.join("elsewhere");
    fs::write(&target, "not a credential").expect("the decoy should be writable");
    std::os::unix::fs::symlink(&target, store.ns_dir.join(ADOPTED_FILE))
        .expect("the symlink should be plantable");

    let err = stage_adopted(&store.paths, &store.ns_dir, &blob("blocked", Some("r1")), &ctx())
        .expect_err("a symlink at the target must refuse");
    assert!(matches!(err, FileStoreError::RefusedSymlink(_)), "{err:?}");
    assert!(
        list_stray_adopted_tmp(&store.ns_dir).expect("listable").is_empty(),
        "and nothing was staged"
    );
    assert_eq!(
        fs::read_to_string(&target).expect("readable"),
        "not a credential",
        "the link's target is untouched"
    );
}
