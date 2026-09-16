//! Tests for the vendor-neutral pending table (plan AC113 unit half, ledger
//! #132).
//!
//! `Doc` stands in for Codex's `auth.json`: a JSON document whose token leaves
//! sit under `tokens`, with no expiry recorded in the meta. Claude's own blob
//! goes through `file_store::resolve_pending`, the thin caller, so the
//! regression cases below exercise exactly what `status` runs.

use std::os::fd::AsFd;
use std::os::fd::OwnedFd;
use std::path::PathBuf;

use sha2::Digest;
use sha2::Sha256;
use tempfile::TempDir;

use super::*;
use crate::config::paths::Paths;
use crate::runtime::fault::Fault;
use crate::secret::file_store::PENDING_FILE;
use crate::secret::file_store::PENDING_META;
use crate::secret::file_store::PendingMeta;
use crate::secret::file_store::create_dir_under;
use crate::secret::foreign_activity::ForeignActivity;
use crate::secret::secret_file::SecretFile;
use crate::secret::secret_file::StopPolicy;
use crate::secret::secret_file::WriteFaults;

const AUTH: &str = "auth.json";
const AUTH_PENDING: &str = "auth.json.pending";
const AUTH_META: &str = "auth.pending.meta";

/// A Codex-shaped credential: `{"tokens":{"access_token","refresh_token"}}`.
struct Doc;

fn hex_sha256(value: &str) -> String {
    Sha256::digest(value.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

impl PendingCredential for Doc {
    fn validate(bytes: &[u8]) -> bool {
        Self::digests(bytes).is_some()
    }

    fn digests(bytes: &[u8]) -> Option<Digests> {
        let doc: serde_json::Value = serde_json::from_slice(bytes).ok()?;
        let access = doc.get("tokens")?.get("access_token")?.as_str()?;
        let refresh = doc["tokens"].get("refresh_token").and_then(serde_json::Value::as_str);
        Some(Digests { access_sha256: hex_sha256(access), refresh_sha256: refresh.map(hex_sha256) })
    }
}

/// The same shape, but with Claude's rule that a meta must carry an expiry.
struct StrictDoc;

impl PendingCredential for StrictDoc {
    const META_REQUIRES_EXPIRY: bool = true;

    fn validate(bytes: &[u8]) -> bool {
        Doc::validate(bytes)
    }

    fn digests(bytes: &[u8]) -> Option<Digests> {
        Doc::digests(bytes)
    }
}

fn doc(access: &str, refresh: &str) -> String {
    format!(
        r#"{{"auth_mode":"chatgpt","tokens":{{"access_token":"{access}","refresh_token":"{refresh}","account_id":"acct-123"}},"last_refresh":"2026-09-16T00:00:00Z"}}"#
    )
}

struct Ns {
    _dir: TempDir,
    paths: Paths,
    path: PathBuf,
    fd: OwnedFd,
}

fn new_ns() -> Ns {
    let dir = TempDir::new().expect("a temporary directory should be available");
    let paths = Paths::with_config_dir(dir.path().join("agctl"));
    paths.ensure_codex_dirs().expect("the Codex tree should be creatable");
    let path = paths.codex_namespace_dir("user-abc", "acct-123").expect("valid ids");
    let fd = create_dir_under(&paths.codex_root(), &path).expect("walkable");
    Ns { _dir: dir, paths, path, fd }
}

fn spec(prior: Option<&Digests>) -> PendingSpec<'_> {
    PendingSpec {
        target_name: AUTH,
        pending_name: AUTH_PENDING,
        meta_name: AUTH_META,
        prior,
        expires_at_ms: None,
    }
}

fn put(ns: &Ns, name: &str, bytes: &str) {
    std::fs::write(ns.path.join(name), bytes)
        .unwrap_or_else(|err| panic!("`{name}` should be writable: {err}"));
}

fn meta(prior: Option<&Digests>) -> String {
    meta_json(&spec(prior)).expect("a meta serializes")
}

fn resolve<C: PendingCredential>(
    ns: &Ns,
    taken_over: bool,
) -> (PendingDecision, Option<PendingWrite>) {
    resolve_pending_with::<C>(ns.fd.as_fd(), &ns.path, &spec(None), taken_over)
        .expect("every case below is decidable")
}

fn read(ns: &Ns, name: &str) -> Option<String> {
    std::fs::read_to_string(ns.path.join(name)).ok()
}

fn digests(bytes: &str) -> Digests {
    Doc::digests(bytes.as_bytes()).expect("the document parses")
}

// ---------------------------------------------------------------------------
// The Codex pending table, AC113 (a)–(f)
// ---------------------------------------------------------------------------

#[test]
#[cfg(feature = "testing")]
fn a_unchanged_file_replays_and_the_rotated_refresh_token_is_never_lost() {
    // AC113 (a), with the pending file produced the way writer 1 produces it:
    // `codex_rename_fail` on a `Complete` write after a refresh answered.
    let ns = new_ns();
    let root = ns.paths.codex_root();
    let target = ns.path.join(AUTH);
    let secret = SecretFile::open(&root, ns.fd.as_fd(), AUTH, &target);
    let quiet = Fault::none();
    let faults = |fault| WriteFaults {
        fault,
        before_rename: "codex_before_rename",
        rename_fail: "codex_rename_fail",
    };
    let old = doc("at-old", "rt-old");
    secret.write(old.as_bytes(), None, StopPolicy::Complete, &faults(&quiet)).expect("lands");

    let rotated = doc("at-new", "rt-rotated");
    let prior = digests(&old);
    let failing = Fault::from_list("codex_rename_fail");
    let outcome = secret
        .write(
            rotated.as_bytes(),
            Some(spec(Some(&prior))),
            StopPolicy::Complete,
            &faults(&failing),
        )
        .expect("parked, not failed");
    assert!(
        matches!(outcome, crate::secret::file_store::WriteOutcome::SavedToPending { .. }),
        "got {outcome:?}"
    );
    assert_eq!(read(&ns, AUTH).as_deref(), Some(old.as_str()), "the old file is still live");

    let (decision, write) = resolve::<Doc>(&ns, false);
    assert_eq!(decision, PendingDecision::Replayed { first_write: false });
    assert_eq!(read(&ns, AUTH).as_deref(), Some(rotated.as_str()));
    assert_eq!(
        digests(&read(&ns, AUTH).expect("present")).refresh_sha256,
        Some(hex_sha256("rt-rotated")),
        "the replayed file carries the rotated refresh token the endpoint returned"
    );
    assert_eq!(
        write,
        Some(PendingWrite { before: Some(prior), pending: Some(digests(&rotated)) }),
        "the resolution reports what it replaced, for the audit line"
    );
    assert!(read(&ns, AUTH_PENDING).is_none() && read(&ns, AUTH_META).is_none());
}

#[test]
fn a_file_replaced_by_another_credential_discards_both_pending_files() {
    // AC113 (b).
    let ns = new_ns();
    let old = doc("at-old", "rt-old");
    let external = doc("at-external", "rt-external");
    put(&ns, AUTH, &external);
    put(&ns, AUTH_PENDING, &doc("at-new", "rt-new"));
    put(&ns, AUTH_META, &meta(Some(&digests(&old))));

    let (decision, write) = resolve::<Doc>(&ns, false);
    assert_eq!(decision, PendingDecision::Discarded(PendingDiscardReason::FileChanged));
    assert_eq!(PendingDiscardReason::FileChanged.label(), "file changed");
    assert_eq!(read(&ns, AUTH).as_deref(), Some(external.as_str()), "the newer grant is kept");
    assert!(read(&ns, AUTH_PENDING).is_none() && read(&ns, AUTH_META).is_none());
    assert_eq!(write.and_then(|w| w.before), Some(digests(&external)));
}

#[test]
fn a_missing_or_unparseable_meta_or_pending_is_invalid() {
    // AC113 (c), and the rest of the `invalid` row.
    let cases: [(&str, Option<String>, String); 4] = [
        ("meta missing", None, doc("at-new", "rt-new")),
        ("meta not JSON", Some("{not json".to_owned()), doc("at-new", "rt-new")),
        ("meta without created_at", Some("{}".to_owned()), doc("at-new", "rt-new")),
        ("pending not a credential", Some(meta(None)), r#"{"tokens":{}}"#.to_owned()),
    ];
    for (name, meta_text, pending) in cases {
        let ns = new_ns();
        put(&ns, AUTH, &doc("at-old", "rt-old"));
        put(&ns, AUTH_PENDING, &pending);
        if let Some(text) = &meta_text {
            put(&ns, AUTH_META, text);
        }

        let (decision, _) = resolve::<Doc>(&ns, false);
        assert_eq!(decision, PendingDecision::Discarded(PendingDiscardReason::Invalid), "{name}");
        assert_eq!(read(&ns, AUTH), Some(doc("at-old", "rt-old")), "{name}: file untouched");
        assert!(read(&ns, AUTH_PENDING).is_none(), "{name}: pending removed");
        assert!(read(&ns, AUTH_META).is_none(), "{name}: meta removed");
    }
}

#[test]
fn a_symlinked_pending_file_is_invalid_and_its_target_is_untouched() {
    // AC113 (d).
    let ns = new_ns();
    let elsewhere = ns._dir.path().join("elsewhere.json");
    let planted = doc("at-planted", "rt-planted");
    std::fs::write(&elsewhere, &planted).expect("writable");
    put(&ns, AUTH, &doc("at-old", "rt-old"));
    std::os::unix::fs::symlink(&elsewhere, ns.path.join(AUTH_PENDING)).expect("linkable");
    put(&ns, AUTH_META, &meta(Some(&digests(&doc("at-old", "rt-old")))));

    let (decision, _) = resolve::<Doc>(&ns, false);
    assert_eq!(decision, PendingDecision::Discarded(PendingDiscardReason::Invalid));
    assert_eq!(read(&ns, AUTH), Some(doc("at-old", "rt-old")), "nothing replayed through it");
    assert!(
        std::fs::symlink_metadata(ns.path.join(AUTH_PENDING)).is_err(),
        "the link itself is removed"
    );
    assert_eq!(std::fs::read_to_string(&elsewhere).expect("readable"), planted, "not its target");
}

#[test]
fn an_absent_file_replays_a_first_write_and_discards_a_derived_one() {
    // AC113 (e) and (f).
    let ns = new_ns();
    let first = doc("at-first", "rt-first");
    put(&ns, AUTH_PENDING, &first);
    put(&ns, AUTH_META, &meta(None));
    let (decision, write) = resolve::<Doc>(&ns, false);
    assert_eq!(decision, PendingDecision::Replayed { first_write: true }, "(e)");
    assert_eq!(read(&ns, AUTH).as_deref(), Some(first.as_str()));
    assert_eq!(write, Some(PendingWrite { before: None, pending: Some(digests(&first)) }));

    let ns = new_ns();
    put(&ns, AUTH_PENDING, &doc("at-new", "rt-new"));
    put(&ns, AUTH_META, &meta(Some(&digests(&doc("at-old", "rt-old")))));
    let (decision, _) = resolve::<Doc>(&ns, false);
    assert_eq!(decision, PendingDecision::Discarded(PendingDiscardReason::FileRemoved), "(f)");
    assert!(read(&ns, AUTH).is_none(), "(f) leaves `needs login`, not a guessed credential");
    assert!(read(&ns, AUTH_PENDING).is_none() && read(&ns, AUTH_META).is_none());
}

#[test]
fn nothing_pending_clears_a_lone_meta_and_reports_no_write() {
    let ns = new_ns();
    assert_eq!(resolve::<Doc>(&ns, false), (PendingDecision::NoPending, None));

    put(&ns, AUTH_META, &meta(None));
    assert_eq!(resolve::<Doc>(&ns, false), (PendingDecision::NoPending, None));
    assert!(read(&ns, AUTH_META).is_none(), "the crash-window meta is removed");
}

#[test]
fn a_taken_over_namespace_discards_after_validity_and_before_the_comparison() {
    let ns = new_ns();
    let old = doc("at-old", "rt-old");
    put(&ns, AUTH, &old);
    put(&ns, AUTH_PENDING, &doc("at-new", "rt-new"));
    put(&ns, AUTH_META, &meta(Some(&digests(&old))));
    let (decision, _) = resolve::<Doc>(&ns, true);
    assert_eq!(decision, PendingDecision::Discarded(PendingDiscardReason::NamespaceTakenOver));
    assert_eq!(read(&ns, AUTH).as_deref(), Some(old.as_str()));

    // Validity is decided first, exactly as phase 1 ordered it.
    let ns = new_ns();
    put(&ns, AUTH_PENDING, &doc("at-new", "rt-new"));
    let (decision, _) = resolve::<Doc>(&ns, true);
    assert_eq!(decision, PendingDecision::Discarded(PendingDiscardReason::Invalid));
}

#[test]
fn the_expiry_requirement_is_the_credential_s_choice() {
    // A meta without `new_expires_at` — what a Codex write parks — is valid for
    // a credential that records no expiry, and stays invalid for one that
    // always has (Claude's rule, `ClaudeBlob`).
    for (strict, expected) in [
        (false, PendingDecision::Replayed { first_write: true }),
        (true, PendingDecision::Discarded(PendingDiscardReason::Invalid)),
    ] {
        let ns = new_ns();
        put(&ns, AUTH_PENDING, &doc("at-first", "rt-first"));
        put(&ns, AUTH_META, &meta(None));
        let (decision, _) =
            if strict { resolve::<StrictDoc>(&ns, false) } else { resolve::<Doc>(&ns, false) };
        assert_eq!(decision, expected, "strict={strict}");
    }
}

#[test]
fn an_unreadable_target_is_an_error_not_a_decision() {
    // A directory or a symbolic link at the target is not something a replay
    // may overwrite, and it is not an absence either: the resolution stops with
    // an error and keeps the pending file for a later run.
    let old = doc("at-old", "rt-old");
    for (name, plant) in [("a directory", true), ("a symbolic link", false)] {
        let ns = new_ns();
        if plant {
            std::fs::create_dir(ns.path.join(AUTH)).expect("a directory is creatable");
        } else {
            let elsewhere = ns._dir.path().join("elsewhere.json");
            std::fs::write(&elsewhere, &old).expect("writable");
            std::os::unix::fs::symlink(&elsewhere, ns.path.join(AUTH)).expect("linkable");
        }
        put(&ns, AUTH_PENDING, &doc("at-new", "rt-new"));
        put(&ns, AUTH_META, &meta(Some(&digests(&old))));

        let err = resolve_pending_with::<Doc>(ns.fd.as_fd(), &ns.path, &spec(None), false)
            .expect_err(&format!("{name} at the target is never overwritten by a replay"));
        let expected = if plant {
            matches!(err, FileStoreError::NotRegular(_))
        } else {
            matches!(err, FileStoreError::RefusedSymlink(_))
        };
        assert!(expected, "{name}: got {err:?}");
        assert!(read(&ns, AUTH_PENDING).is_some(), "{name}: the pending file is kept");
        assert!(read(&ns, AUTH_META).is_some(), "{name}: and so is its meta");
    }
}

#[test]
fn a_spec_with_an_escaping_or_aliased_name_is_refused_before_anything_is_touched() {
    // Review F2: `renameat`/`unlinkat` resolve `..` inside a name, so an
    // unchecked spec name would carry the replay or the discard out of the
    // namespace the descriptor was walked to.
    let escape = "../../../outside.json";
    let cases: [(&str, &str, &str, &str); 6] = [
        ("an escaping target name", escape, AUTH_PENDING, AUTH_META),
        ("an escaping pending name", AUTH, escape, AUTH_META),
        ("a separator in the meta name", AUTH, AUTH_PENDING, "a/b"),
        ("pending equal to the target", AUTH, AUTH, AUTH_META),
        ("meta equal to the target", AUTH, AUTH_PENDING, AUTH),
        ("meta equal to pending", AUTH, AUTH_META, AUTH_META),
    ];
    for (name, target_name, pending_name, meta_name) in cases {
        let ns = new_ns();
        let outside = ns.paths.config_dir().join("outside.json");
        std::fs::write(&outside, "not agctl's").expect("writable");
        let old = doc("at-old", "rt-old");
        put(&ns, AUTH, &old);
        put(&ns, AUTH_PENDING, &doc("at-new", "rt-new"));
        put(&ns, AUTH_META, &meta(Some(&digests(&old))));

        let spec =
            PendingSpec { target_name, pending_name, meta_name, prior: None, expires_at_ms: None };
        let err = resolve_pending_with::<Doc>(ns.fd.as_fd(), &ns.path, &spec, false)
            .expect_err(&format!("{name}: must be refused"));
        assert!(matches!(err, FileStoreError::OutsideNamespaceRoot(_)), "{name}: got {err:?}");
        assert_eq!(read(&ns, AUTH).as_deref(), Some(old.as_str()), "{name}: target untouched");
        assert!(read(&ns, AUTH_PENDING).is_some(), "{name}: pending untouched");
        assert!(read(&ns, AUTH_META).is_some(), "{name}: meta untouched");
        assert_eq!(
            std::fs::read_to_string(&outside).expect("readable"),
            "not agctl's",
            "{name}: nothing outside the namespace was read over or removed"
        );
    }
}

// ---------------------------------------------------------------------------
// Claude, through the thin caller: byte-identical with <W1 base> (317722b)
// ---------------------------------------------------------------------------

fn claude_blob(access: &str, refresh: &str) -> String {
    format!(
        r#"{{"claudeAiOauth":{{"accessToken":"{access}","refreshToken":"{refresh}","expiresAt":9999999999999}}}}"#
    )
}

fn claude_ns() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("a temporary directory should be available");
    let paths = Paths::with_config_dir(dir.path().join("agctl"));
    let ns_dir = paths.namespace_dir("acct", "org");
    std::fs::create_dir_all(&ns_dir).expect("directories should be creatable");
    (dir, ns_dir)
}

fn claude_digests(blob: &str) -> Digests {
    crate::provider::claude::credentials::Credentials::parse_blob(blob.as_bytes())
        .expect("the blob parses")
        .digests()
}

#[test]
fn a_claude_pending_file_written_by_the_w1_base_binary_still_replays() {
    // The meta below is byte-for-byte what 317722b's `save_to_pending` wrote:
    // `serde_json::to_string(&PendingMeta { .. })`, members in declaration
    // order, `new_expires_at` a required integer.
    let (_dir, ns_dir) = claude_ns();
    let old = claude_blob("old-access", "old-refresh");
    let new = claude_blob("new-access", "new-refresh");
    let prior = claude_digests(&old);
    let base_meta = format!(
        r#"{{"derived_from_access_sha256":"{}","derived_from_refresh_sha256":"{}","created_at":"2026-09-16T12:00:00.123456Z","new_expires_at":9999999999999}}"#,
        prior.access_sha256,
        prior.refresh_sha256.as_deref().expect("the old blob has a refresh token"),
    );
    std::fs::write(ns_dir.join(".credentials.json"), &old).expect("writable");
    std::fs::write(ns_dir.join(PENDING_FILE), &new).expect("writable");
    std::fs::write(ns_dir.join(PENDING_META), &base_meta).expect("writable");

    let decision = crate::secret::file_store::resolve_pending(&ns_dir, &ForeignActivity::None)
        .expect("resolution succeeds");
    assert_eq!(decision, PendingDecision::Replayed { first_write: false });
    assert_eq!(std::fs::read_to_string(ns_dir.join(".credentials.json")).expect("present"), new);
    assert!(!ns_dir.join(PENDING_FILE).exists() && !ns_dir.join(PENDING_META).exists());
}

#[test]
fn a_claude_meta_without_new_expires_at_is_still_invalid() {
    // `PendingMeta.new_expires_at` stayed required on Claude's read path; a
    // `#[serde(default)]` there would have turned this discard into a replay.
    for member in [String::new(), r#","new_expires_at":null"#.to_owned()] {
        let (_dir, ns_dir) = claude_ns();
        let old = claude_blob("old-access", "old-refresh");
        let prior = claude_digests(&old);
        let base_meta = format!(
            r#"{{"derived_from_access_sha256":"{}","derived_from_refresh_sha256":"{}","created_at":"2026-09-16T12:00:00Z"{member}}}"#,
            prior.access_sha256,
            prior.refresh_sha256.as_deref().expect("present"),
        );
        std::fs::write(ns_dir.join(".credentials.json"), &old).expect("writable");
        std::fs::write(ns_dir.join(PENDING_FILE), claude_blob("n", "r")).expect("writable");
        std::fs::write(ns_dir.join(PENDING_META), &base_meta).expect("writable");

        let decision = crate::secret::file_store::resolve_pending(&ns_dir, &ForeignActivity::None)
            .expect("resolution succeeds");
        assert_eq!(
            decision,
            PendingDecision::Discarded(PendingDiscardReason::Invalid),
            "member {member:?}"
        );
    }
}

#[test]
fn claude_s_meta_bytes_are_the_w1_base_bytes() {
    // The writer moved from `file_store::save_to_pending` to this module; the
    // bytes it parks must not change. `PendingMeta` is the unchanged base type.
    let prior = claude_digests(&claude_blob("a", "r"));
    let claude_spec = PendingSpec {
        target_name: ".credentials.json",
        pending_name: PENDING_FILE,
        meta_name: PENDING_META,
        prior: Some(&prior),
        expires_at_ms: Some(1_234_567_890_123),
    };
    let written = meta_json(&claude_spec).expect("serializes");
    let created_at =
        serde_json::from_str::<serde_json::Value>(&written).expect("JSON")["created_at"]
            .as_str()
            .expect("a string")
            .to_owned();
    let base = serde_json::to_string(&PendingMeta {
        derived_from_access_sha256: Some(prior.access_sha256.clone()),
        derived_from_refresh_sha256: prior.refresh_sha256.clone(),
        created_at,
        new_expires_at: 1_234_567_890_123,
    })
    .expect("serializes");
    assert_eq!(written, base);

    let first = PendingSpec { prior: None, ..claude_spec };
    let written = meta_json(&first).expect("serializes");
    assert!(
        written.starts_with(r#"{"derived_from_access_sha256":null,"derived_from_refresh_sha256":null,"created_at":""#),
        "a first write records nulls, as before: {written}"
    );
}
