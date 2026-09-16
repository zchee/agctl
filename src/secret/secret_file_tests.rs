//! Tests for the rooted credential-file primitive (plan AC97 unit half, ledger
//! #197/#231/#237).

use std::os::fd::AsFd;
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Instant;

use tempfile::TempDir;

use super::*;
use crate::config::paths::Paths;
use crate::runtime::coordinator::Cancel;
use crate::secret::file_store::create_dir_under;
use crate::secret::pending::Digests;

const AUTH: &str = "auth.json";
const AUTH_PENDING: &str = "auth.json.pending";
const AUTH_META: &str = "auth.pending.meta";

/// A store with one Codex namespace and one Claude namespace, both created
/// through the `O_NOFOLLOW` walk.
struct Store {
    _dir: TempDir,
    paths: Paths,
    codex_ns: PathBuf,
    codex_fd: OwnedFd,
    claude_ns: PathBuf,
    claude_fd: OwnedFd,
}

fn store() -> Store {
    let dir = TempDir::new().expect("a temporary directory should be available");
    let paths = Paths::with_config_dir(dir.path().join("agctl"));
    paths.ensure_codex_dirs().expect("the Codex tree should be creatable");
    paths.ensure_dirs().expect("the Claude tree should be creatable");
    let codex_ns = paths.codex_namespace_dir("user-abc", "acct-123").expect("valid ids");
    let codex_fd = create_dir_under(&paths.codex_root(), &codex_ns).expect("walkable");
    let claude_ns = paths.namespace_dir("acct", "org");
    let claude_fd = create_dir_under(&paths.namespace_root(), &claude_ns).expect("walkable");
    Store { _dir: dir, paths, codex_ns, codex_fd, claude_ns, claude_fd }
}

fn none() -> Fault {
    Fault::none()
}

fn codex_faults(fault: &Fault) -> WriteFaults<'_> {
    WriteFaults { fault, before_rename: "codex_before_rename", rename_fail: "codex_rename_fail" }
}

fn spec<'a>(prior: Option<&'a Digests>) -> PendingSpec<'a> {
    PendingSpec {
        target_name: AUTH,
        pending_name: AUTH_PENDING,
        meta_name: AUTH_META,
        prior,
        expires_at_ms: None,
    }
}

fn read_to_string(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("`{}` should be readable: {err}", path.display()))
}

fn stray_tmps(dir: &Path, name: &str) -> Vec<String> {
    let prefix = format!("{name}.tmp.");
    let mut found: Vec<String> = std::fs::read_dir(dir)
        .expect("the namespace should be listable")
        .map(|entry| entry.expect("a readable entry").file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(&prefix))
        .collect();
    found.sort();
    found
}

fn standalone_ctx(cancelled: bool) -> PassCtx {
    let cancel = Cancel::new();
    if cancelled {
        cancel.cancel();
    }
    PassCtx::standalone(cancel, Instant::now() + std::time::Duration::from_secs(30))
}

// ---------------------------------------------------------------------------
// The root requirement (AC97)
// ---------------------------------------------------------------------------

#[test]
fn a_codex_rooted_file_refuses_a_target_under_claude_and_the_reverse() {
    let store = store();
    let codex_root = store.paths.codex_root();
    let claude_root = store.paths.namespace_root();
    let claude_target = store.claude_ns.join(AUTH);
    let codex_target = store.codex_ns.join(".credentials.json");

    let cases = [
        ("codex root, claude target", &codex_root, store.claude_fd.as_fd(), AUTH, &claude_target),
        (
            "claude root, codex target",
            &claude_root,
            store.codex_fd.as_fd(),
            ".credentials.json",
            &codex_target,
        ),
    ];
    for (name, root, dir, file, shown) in cases {
        let secret = SecretFile::open(root, dir, file, shown);
        let fault = none();

        let err = secret
            .write(b"{}", None, StopPolicy::Complete, &codex_faults(&fault))
            .expect_err(&format!("{name}: the write must be refused"));
        assert!(matches!(err, FileStoreError::OutsideNamespaceRoot(_)), "{name}: got {err:?}");
        let err = secret.read(1024).expect_err(&format!("{name}: the read must be refused"));
        assert!(matches!(err, FileStoreError::OutsideNamespaceRoot(_)), "{name}: got {err:?}");
        let err = secret.remove().expect_err(&format!("{name}: the remove must be refused"));
        assert!(matches!(err, FileStoreError::OutsideNamespaceRoot(_)), "{name}: got {err:?}");
    }

    assert!(!claude_target.exists(), "nothing was written under claude/");
    assert!(!codex_target.exists(), "nothing was written under codex/");
    assert!(stray_tmps(&store.claude_ns, AUTH).is_empty(), "not even a temporary");
    assert!(stray_tmps(&store.codex_ns, ".credentials.json").is_empty(), "not even a temporary");
}

#[test]
fn a_name_or_displayed_path_that_is_not_one_plain_component_is_refused() {
    let store = store();
    let root = store.paths.codex_root();
    let dir = store.codex_fd.as_fd();
    let target = store.codex_ns.join(AUTH);
    let root_itself = root.clone();
    let escaping = store.codex_ns.join("..").join("..").join("..").join(AUTH);
    let nested = store.codex_ns.join("sub").join(AUTH);

    let cases: [(&str, &str, &Path); 6] = [
        ("a separator in the name", "sub/auth.json", &nested),
        ("a parent component as the name", "..", &target),
        ("a trailing slash on the name", "auth.json/", &target),
        ("a displayed path naming another file", AUTH, &nested.with_file_name("other.json")),
        ("the root itself", "codex", &root_itself),
        ("a displayed path that climbs out of the root", AUTH, &escaping),
    ];
    for (name, file, shown) in cases {
        let secret = SecretFile::open(&root, dir, file, shown);
        let fault = none();
        let err = secret
            .write(b"{}", None, StopPolicy::Complete, &codex_faults(&fault))
            .expect_err(&format!("{name}: must be refused"));
        assert!(matches!(err, FileStoreError::OutsideNamespaceRoot(_)), "{name}: got {err:?}");
    }
    assert!(!target.exists(), "nothing reached the namespace");
    assert!(!store.codex_ns.join("sub").exists(), "and no subdirectory was created");
}

#[test]
fn a_pending_spec_for_another_target_is_refused_before_anything_is_staged() {
    let store = store();
    let root = store.paths.codex_root();
    let target = store.codex_ns.join(AUTH);
    let secret = SecretFile::open(&root, store.codex_fd.as_fd(), AUTH, &target);
    let mut wrong = spec(None);
    wrong.target_name = "other.json";
    let fault = none();

    let err = secret
        .write(b"{}", Some(wrong), StopPolicy::Complete, &codex_faults(&fault))
        .expect_err("a spec naming another file must be refused");
    assert!(matches!(err, FileStoreError::OutsideNamespaceRoot(_)), "got {err:?}");
    assert!(stray_tmps(&store.codex_ns, AUTH).is_empty());
    assert!(!target.exists());
}

// ---------------------------------------------------------------------------
// The write itself
// ---------------------------------------------------------------------------

#[test]
fn a_write_lands_atomically_at_0600_and_reads_back() {
    let store = store();
    let root = store.paths.codex_root();
    let target = store.codex_ns.join(AUTH);
    let secret = SecretFile::open(&root, store.codex_fd.as_fd(), AUTH, &target);
    let fault = none();

    let WriteOutcome::Written { snap: first } = secret
        .write(br#"{"n":1}"#, Some(spec(None)), StopPolicy::Complete, &codex_faults(&fault))
        .expect("the first write should land")
    else {
        panic!("the first write should not park a pending file");
    };
    let WriteOutcome::Written { snap: second } = secret
        .write(br#"{"n":2}"#, Some(spec(None)), StopPolicy::Complete, &codex_faults(&fault))
        .expect("the second write should land")
    else {
        panic!("the second write should not park a pending file");
    };

    assert_ne!(first.ino, second.ino, "the replacement is a rename, not an in-place write");
    let mode = std::fs::metadata(&target).expect("present").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "the credential file is owner-only");
    match secret.read(1024).expect("readable") {
        ReadOutcome::Present { bytes, snap } => {
            assert_eq!(bytes, br#"{"n":2}"#);
            assert_eq!(snap, second, "the read sees the file the write reported");
        }
        ReadOutcome::Absent => panic!("the file was just written"),
    }
    assert!(stray_tmps(&store.codex_ns, AUTH).is_empty(), "no temporary is left behind");
    assert!(!store.codex_ns.join(AUTH_PENDING).exists());
    assert!(!store.codex_ns.join(AUTH_META).exists());
}

#[test]
fn a_symlink_or_a_directory_at_the_target_is_refused() {
    let store = store();
    let root = store.paths.codex_root();
    let target = store.codex_ns.join(AUTH);
    let elsewhere = store._dir.path().join("elsewhere.json");
    std::fs::write(&elsewhere, b"not agctl's").expect("writable");
    std::os::unix::fs::symlink(&elsewhere, &target).expect("the link should be creatable");
    let secret = SecretFile::open(&root, store.codex_fd.as_fd(), AUTH, &target);
    let fault = none();

    let err = secret
        .write(b"{}", None, StopPolicy::Complete, &codex_faults(&fault))
        .expect_err("a symlinked target must be refused");
    assert!(matches!(err, FileStoreError::RefusedSymlink(_)), "got {err:?}");
    let err = secret.read(1024).expect_err("and never followed on read");
    assert!(matches!(err, FileStoreError::RefusedSymlink(_)), "got {err:?}");
    assert_eq!(read_to_string(&elsewhere), "not agctl's", "the link's target is untouched");

    std::fs::remove_file(&target).expect("the link is removable");
    std::fs::create_dir(&target).expect("a directory is creatable");
    let err = secret
        .write(b"{}", None, StopPolicy::Complete, &codex_faults(&fault))
        .expect_err("a directory target must be refused");
    assert!(matches!(err, FileStoreError::NotRegular(_)), "got {err:?}");
    assert!(stray_tmps(&store.codex_ns, AUTH).is_empty());
}

#[test]
fn remove_reports_whether_a_file_was_there() {
    let store = store();
    let root = store.paths.codex_root();
    let target = store.codex_ns.join(AUTH);
    let secret = SecretFile::open(&root, store.codex_fd.as_fd(), AUTH, &target);
    let fault = none();
    secret.write(b"{}", None, StopPolicy::Complete, &codex_faults(&fault)).expect("lands");

    assert!(secret.remove().expect("removable"), "the file was there");
    assert!(!target.exists());
    assert!(!secret.remove().expect("an absent file is not an error"), "and now it is not");
    assert!(matches!(secret.read(1024).expect("readable"), ReadOutcome::Absent));
}

// ---------------------------------------------------------------------------
// Stop policies (ledger #197, #231)
// ---------------------------------------------------------------------------

#[test]
fn discard_staged_abandons_a_stopped_pass_and_complete_does_not() {
    let store = store();
    let root = store.paths.codex_root();
    let target = store.codex_ns.join(AUTH);
    let secret = SecretFile::open(&root, store.codex_fd.as_fd(), AUTH, &target);
    let fault = none();
    secret.write(b"old", None, StopPolicy::Complete, &codex_faults(&fault)).expect("lands");
    let stopped = standalone_ctx(true);

    let err = secret
        .write(b"new", Some(spec(None)), StopPolicy::DiscardStaged(&stopped), &codex_faults(&fault))
        .expect_err("a stopped DiscardStaged pass must not replace the file");
    assert!(matches!(err, FileStoreError::Cancelled(_)), "got {err:?}");
    assert_eq!(read_to_string(&target), "old", "the old file is still in place");
    assert!(stray_tmps(&store.codex_ns, AUTH).is_empty(), "the staged file was unlinked");

    // `Complete` carries no pass at all: the stop signal cannot reach it.
    let outcome = secret
        .write(b"new", Some(spec(None)), StopPolicy::Complete, &codex_faults(&fault))
        .expect("a Complete write lands whatever the pass says");
    assert!(matches!(outcome, WriteOutcome::Written { .. }), "got {outcome:?}");
    assert_eq!(read_to_string(&target), "new");
}

#[test]
#[cfg(feature = "testing")]
fn complete_leaves_its_staged_file_for_a_process_exit_and_discard_staged_does_not() {
    // Architect v5 M2: `cleanup::emergency` runs on `q` and on SIGINT/TERM/HUP
    // and unlinks every registered temporary. Under `Complete` the staged file
    // may be the only copy of a rotated grant, so it must not be registered.
    // Both writes pause between the fsync and the rename; the emergency
    // cleanup runs while they wait. Each test runs in its own process under
    // nextest, so the global registry is this test's alone.
    let complete = store();
    let discard = store();
    let fault = Fault::from_list("pause_codex_before_rename");

    std::thread::scope(|scope| {
        let complete_write = scope.spawn(|| {
            let root = complete.paths.codex_root();
            let target = complete.codex_ns.join(AUTH);
            SecretFile::open(&root, complete.codex_fd.as_fd(), AUTH, &target).write(
                b"rotated",
                Some(spec(None)),
                StopPolicy::Complete,
                &codex_faults(&fault),
            )
        });
        let discard_write = scope.spawn(|| {
            let ctx = standalone_ctx(false);
            let root = discard.paths.codex_root();
            let target = discard.codex_ns.join(AUTH);
            SecretFile::open(&root, discard.codex_fd.as_fd(), AUTH, &target).write(
                b"rotated",
                None,
                StopPolicy::DiscardStaged(&ctx),
                &codex_faults(&fault),
            )
        });

        let staged = Instant::now() + std::time::Duration::from_secs(5);
        while (stray_tmps(&complete.codex_ns, AUTH).is_empty()
            || stray_tmps(&discard.codex_ns, AUTH).is_empty())
            && Instant::now() < staged
        {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(stray_tmps(&complete.codex_ns, AUTH).len(), 1, "the Complete write staged");
        assert_eq!(stray_tmps(&discard.codex_ns, AUTH).len(), 1, "the DiscardStaged write staged");

        cleanup::emergency();

        assert_eq!(
            stray_tmps(&complete.codex_ns, AUTH).len(),
            1,
            "a process exit must leave the Complete write's staged grant on disk"
        );
        assert!(
            stray_tmps(&discard.codex_ns, AUTH).is_empty(),
            "the DiscardStaged write registered its temporary, as Claude's always has"
        );

        let complete_outcome = complete_write.join().expect("the Complete writer did not panic");
        assert!(
            matches!(complete_outcome, Ok(WriteOutcome::Written { .. })),
            "the staged grant still lands after the pause: {complete_outcome:?}"
        );
        let discard_outcome = discard_write.join().expect("the DiscardStaged writer did not panic");
        assert!(discard_outcome.is_err(), "its temporary is gone, so its rename fails");
    });
    assert_eq!(read_to_string(&complete.codex_ns.join(AUTH)), "rotated");
    assert!(!discard.codex_ns.join(AUTH).exists());
}

// ---------------------------------------------------------------------------
// Rename failure: pending or error (ledger #237)
// ---------------------------------------------------------------------------

#[test]
#[cfg(feature = "testing")]
fn a_failed_rename_with_a_spec_parks_the_bytes_as_pending_under_both_policies() {
    for complete in [true, false] {
        let store = store();
        let root = store.paths.codex_root();
        let target = store.codex_ns.join(AUTH);
        let secret = SecretFile::open(&root, store.codex_fd.as_fd(), AUTH, &target);
        let fault = none();
        secret.write(b"old", None, StopPolicy::Complete, &codex_faults(&fault)).expect("lands");

        let failing = Fault::from_list("codex_rename_fail");
        let prior = Digests { access_sha256: "a".repeat(64), refresh_sha256: Some("b".repeat(64)) };
        let ctx = standalone_ctx(false);
        let stop = if complete { StopPolicy::Complete } else { StopPolicy::DiscardStaged(&ctx) };
        let outcome = secret
            .write(b"rotated", Some(spec(Some(&prior))), stop, &codex_faults(&failing))
            .expect("a failed rename with a spec is not an error");

        let WriteOutcome::SavedToPending { error } = outcome else {
            panic!("complete={complete}: the bytes should be parked, got {outcome:?}");
        };
        assert!(error.contains("injected"), "complete={complete}: the cause is carried: {error}");
        assert_eq!(read_to_string(&target), "old", "complete={complete}: the old file survives");
        assert_eq!(read_to_string(&store.codex_ns.join(AUTH_PENDING)), "rotated");
        let meta: serde_json::Value =
            serde_json::from_str(&read_to_string(&store.codex_ns.join(AUTH_META)))
                .expect("the meta is JSON");
        assert_eq!(meta["derived_from_access_sha256"], "a".repeat(64));
        assert_eq!(meta["derived_from_refresh_sha256"], "b".repeat(64));
        assert!(
            meta.get("new_expires_at").is_none(),
            "no expiry is recorded when the spec has none: {meta}"
        );
        assert!(stray_tmps(&store.codex_ns, AUTH).is_empty(), "complete={complete}");
    }
}

#[test]
#[cfg(feature = "testing")]
fn a_failed_rename_without_a_spec_is_an_error_and_leaves_the_old_file() {
    // The install path (v5 L4): `pending: None` means no pending fallback, so
    // nothing a later `status` could replay over the surviving grant.
    let store = store();
    let root = store.paths.codex_root();
    let target = store.codex_ns.join(AUTH);
    let secret = SecretFile::open(&root, store.codex_fd.as_fd(), AUTH, &target);
    let fault = none();
    secret.write(b"old", None, StopPolicy::Complete, &codex_faults(&fault)).expect("lands");

    let failing = Fault::from_list("codex_install_rename_fail");
    let faults = WriteFaults {
        fault: &failing,
        before_rename: "codex_install_before_rename",
        rename_fail: "codex_install_rename_fail",
    };
    let err = secret
        .write(b"verified", None, StopPolicy::Complete, &faults)
        .expect_err("a failed rename without a spec is an error");
    assert!(matches!(err, FileStoreError::Io { .. }), "got {err:?}");
    assert_eq!(read_to_string(&target), "old", "the previous grant survives");
    assert!(!store.codex_ns.join(AUTH_PENDING).exists(), "no pending file was parked");
    assert!(!store.codex_ns.join(AUTH_META).exists());
    assert!(stray_tmps(&store.codex_ns, AUTH).is_empty(), "the caller still holds the bytes");

    // The fault is per writer: writer 1's name does not fail this write.
    let other = Fault::from_list("codex_rename_fail");
    let faults = WriteFaults { fault: &other, ..faults };
    secret.write(b"verified", None, StopPolicy::Complete, &faults).expect("lands");
    assert_eq!(read_to_string(&target), "verified");
}

#[test]
#[cfg(feature = "testing")]
fn a_failed_pending_save_keeps_the_staged_grant_only_under_complete() {
    // A directory at the pending name makes the park's rename fail after the
    // meta is written. `Complete` must not unlink the only copy of the grant.
    for complete in [true, false] {
        let store = store();
        let root = store.paths.codex_root();
        let target = store.codex_ns.join(AUTH);
        std::fs::create_dir(store.codex_ns.join(AUTH_PENDING)).expect("a directory");
        std::fs::write(store.codex_ns.join(AUTH_PENDING).join("occupant"), b"x").expect("a file");
        let secret = SecretFile::open(&root, store.codex_fd.as_fd(), AUTH, &target);

        let failing = Fault::from_list("codex_rename_fail");
        let ctx = standalone_ctx(false);
        let stop = if complete { StopPolicy::Complete } else { StopPolicy::DiscardStaged(&ctx) };
        let err = secret
            .write(b"rotated", Some(spec(None)), stop, &codex_faults(&failing))
            .expect_err("a pending save that cannot land is an error");
        assert!(matches!(err, FileStoreError::Io { .. }), "complete={complete}: got {err:?}");

        let strays = stray_tmps(&store.codex_ns, AUTH);
        if complete {
            assert_eq!(strays.len(), 1, "the staged grant is left for doctor to report");
            let stray = store.codex_ns.join(&strays[0]);
            assert_eq!(read_to_string(&stray), "rotated");
            assert!(
                err.to_string()
                    .contains(&format!("the staged credential was kept at `{}`", stray.display())),
                "the error names the kept temporary: {err}"
            );
        } else {
            assert!(strays.is_empty(), "Claude's rule removes the staged file: {strays:?}");
            assert!(!err.to_string().contains("kept"), "Claude's sentence is unchanged: {err}");
        }
        assert!(!store.codex_ns.join(AUTH_META).exists(), "a meta without a pending is removed");
        assert!(!target.exists());
    }
}

// ---------------------------------------------------------------------------
// Pending spec names are bound to the directory too (review F2)
// ---------------------------------------------------------------------------

#[test]
fn a_pending_spec_with_an_escaping_or_aliased_name_is_refused_before_anything_is_staged() {
    let store = store();
    let root = store.paths.codex_root();
    let target = store.codex_ns.join(AUTH);
    let secret = SecretFile::open(&root, store.codex_fd.as_fd(), AUTH, &target);
    let fault = none();
    secret.write(b"old", None, StopPolicy::Complete, &codex_faults(&fault)).expect("lands");
    // A Claude credential one tree over: what a `../` pending name would reach.
    let claude_file = store.claude_ns.join(".credentials.json");
    std::fs::write(&claude_file, b"claude's").expect("writable");

    let escape = "../../../../claude/acct/org/.credentials.json";
    let cases: [(&str, &str, &str, &str); 8] = [
        ("an escaping pending name", AUTH, escape, AUTH_META),
        ("an escaping meta name", AUTH, AUTH_PENDING, escape),
        ("a separator in the pending name", AUTH, "sub/auth.json.pending", AUTH_META),
        ("a parent component as the meta name", AUTH, AUTH_PENDING, ".."),
        ("an empty pending name", AUTH, "", AUTH_META),
        ("pending equal to the target", AUTH, AUTH, AUTH_META),
        ("meta equal to the target", AUTH, AUTH_PENDING, AUTH),
        ("meta equal to pending", AUTH, AUTH_PENDING, AUTH_PENDING),
    ];
    for (name, target_name, pending_name, meta_name) in cases {
        let spec =
            PendingSpec { target_name, pending_name, meta_name, prior: None, expires_at_ms: None };
        let err = secret
            .write(b"rotated", Some(spec), StopPolicy::Complete, &codex_faults(&fault))
            .expect_err(&format!("{name}: must be refused"));
        assert!(matches!(err, FileStoreError::OutsideNamespaceRoot(_)), "{name}: got {err:?}");
        assert!(stray_tmps(&store.codex_ns, AUTH).is_empty(), "{name}: nothing was staged");
        assert_eq!(read_to_string(&target), "old", "{name}: the live file is untouched");
    }
    assert_eq!(read_to_string(&claude_file), "claude's", "nothing crossed into claude/");
}

#[test]
#[cfg(feature = "testing")]
fn a_failed_meta_create_keeps_and_names_the_staged_grant_only_under_complete() {
    // Re-review N5: the other half of F5. A directory at the meta name makes
    // the `O_EXCL` meta create fail before the pending rename is attempted.
    for complete in [true, false] {
        let store = store();
        let root = store.paths.codex_root();
        let target = store.codex_ns.join(AUTH);
        std::fs::create_dir(store.codex_ns.join(AUTH_META)).expect("a directory");
        let secret = SecretFile::open(&root, store.codex_fd.as_fd(), AUTH, &target);

        let failing = Fault::from_list("codex_rename_fail");
        let ctx = standalone_ctx(false);
        let stop = if complete { StopPolicy::Complete } else { StopPolicy::DiscardStaged(&ctx) };
        let err = secret
            .write(b"rotated", Some(spec(None)), stop, &codex_faults(&failing))
            .expect_err("a meta that cannot be written is an error");
        assert!(matches!(err, FileStoreError::Io { .. }), "complete={complete}: got {err:?}");
        assert!(err.to_string().contains("auth.pending.meta"), "the meta is named: {err}");

        let strays = stray_tmps(&store.codex_ns, AUTH);
        if complete {
            assert_eq!(strays.len(), 1, "the staged grant is kept");
            let stray = store.codex_ns.join(&strays[0]);
            assert_eq!(read_to_string(&stray), "rotated");
            assert!(
                err.to_string()
                    .contains(&format!("the staged credential was kept at `{}`", stray.display())),
                "and named: {err}"
            );
        } else {
            assert!(strays.is_empty(), "Claude's rule removes it: {strays:?}");
            assert!(!err.to_string().contains("kept"), "Claude's sentence is unchanged: {err}");
        }
        assert!(!store.codex_ns.join(AUTH_PENDING).exists(), "nothing was parked");
        assert!(!target.exists());
    }
}
