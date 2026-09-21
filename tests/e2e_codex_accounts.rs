#![cfg(feature = "testing")]

//! `agctl codex accounts list | show | remove | forget | unforget`, through the
//! real binary (plan AC107, AC115, AC125's `remove` clause).
//!
//! Every Codex home and every namespace here is inside the fixture's
//! temporary tree; `CodexFixture` removes the Codex home variable from every
//! spawn and refuses to let a test put it back (invariant I25).
//!
//! # What the removal tests are really watching
//!
//! `remove --delete-secret` is the only destructive command in the Codex
//! surface, so its two cases are proved by a **manifest** — every entry under
//! the namespace with its name, type, mode, size and SHA-256 — rather than by
//! spot checks. The refusal case asserts that manifest is identical before and
//! after, which is what "nothing was removed" has to mean if it is to mean
//! anything (plan AC115, decision M10).
//!
//! # Every launch goes through `checked`
//!
//! Which refuses a leaked needle and refuses a run whose binary dropped a
//! Codex write receipt before the audit log (S34 C2-a), and captures both
//! streams for `scripts/phase3-greps.sh --log`.

mod common;

#[path = "common/codex.rs"]
mod codex;

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Output;

use codex::CodexFixture;
use codex::Needle;
use codex::Stream;
use serde_json::Value;
use serde_json::json;

const USER: &str = "user-accounts-0001";
const ACCT: &str = "11111111-2222-4333-8444-555555555555";
const EMAIL: &str = "codex-owner@example.invalid";
/// The email a **Claude** row carries, to prove this command cannot see it.
const CLAUDE_EMAIL: &str = "claude-only@example.invalid";

const NEEDLES: [Needle; 6] = [
    ("an access token", "agctl-test-codex-at-"),
    ("a refresh token", "agctl-test-codex-rt-"),
    ("an API key", "agctl-test-codex-ak-"),
    ("a JWT", "agctl-test-codex-jwt-"),
    ("a Bearer header", "Bearer "),
    ("a bearer header", "bearer "),
];

fn checked(name: &str, output: Output) -> Output {
    codex::checked("e2e_codex_accounts", name, output, &NEEDLES, &[Stream::Stdout, Stream::Stderr])
}

/// Runs `agctl <args>` through [`checked`]. Every launch in this file is one
/// of these.
fn run(fixture: &CodexFixture, name: &str, args: &[&str]) -> Output {
    checked(name, fixture.cmd().args(args).output().expect("the binary runs"))
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// One Codex row, in the shape `config::codex` deserializes.
fn codex_row(user: &str, acct: &str, email: &str, kind: Value) -> Value {
    json!({
        "chatgpt_user_id": user,
        "chatgpt_account_id": acct,
        "email": email,
        "plan_type": "pro",
        "label": null,
        "kind": kind,
        "forgotten": false,
        "created_at": "2026-09-17T00:00:00Z",
    })
}

fn owned_kind() -> Value {
    json!({ "kind": "owned", "export_spelling": "/x", "refresh": "auto" })
}

/// Writes a registry holding `codex_accounts`, and optionally one Claude row.
fn registry(fixture: &CodexFixture, codex_rows: Vec<Value>, claude_rows: Vec<Value>) {
    fixture.inner().write_registry_document(&json!({
        "version": 2,
        "accounts": claude_rows,
        "forgotten_services": [],
        "codex_accounts": codex_rows,
    }));
}

/// The Codex write log, `<store>/codex/writes.jsonl` (`audit::LOG_FILE`).
fn audit_log(fixture: &CodexFixture) -> PathBuf {
    fixture.inner().config_dir().join("codex").join("writes.jsonl")
}

/// The namespace directory `<store>/codex/<user>/<acct>`.
fn namespace(fixture: &CodexFixture) -> PathBuf {
    fixture.inner().config_dir().join("codex").join(USER).join(ACCT)
}

fn write_0600(path: &Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
    fs::write(path, bytes).expect("write");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("chmod");
}

/// A namespace holding everything a login and a parked refresh leave behind.
fn seeded_namespace(fixture: &CodexFixture) -> PathBuf {
    let dir = namespace(fixture);
    write_0600(&dir.join("auth.json"), br#"{"auth_mode":"chatgpt"}"#);
    write_0600(&dir.join("auth.json.pending"), br#"{"auth_mode":"chatgpt"}"#);
    write_0600(&dir.join("auth.pending.meta"), b"{}");
    write_0600(&dir.join("auth.json.tmp.0badc0de"), b"{}");
    dir
}

/// `(name, is_dir, mode, size, sha256)` for every entry under `dir`, sorted.
fn manifest(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        for entry in fs::read_dir(&next).expect("listable").flatten() {
            let path = entry.path();
            let meta = fs::symlink_metadata(&path).expect("stat");
            let digest = if meta.is_file() {
                hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
                    fs::read(&path).expect("readable"),
                ))
            } else {
                String::new()
            };
            out.push(format!(
                "{} dir={} mode={:o} size={} mtime_ns={} sha256={digest}",
                path.strip_prefix(dir).expect("under dir").display(),
                meta.is_dir(),
                meta.permissions().mode() & 0o777,
                meta.len(),
                meta.mtime() * 1_000_000_000 + meta.mtime_nsec(),
            ));
            if meta.is_dir() {
                stack.push(path);
            }
        }
    }
    out.sort();
    out
}

fn codex_rows(fixture: &CodexFixture) -> Vec<Value> {
    let bytes = fs::read(fixture.inner().config_file()).expect("the registry");
    let document: Value = serde_json::from_slice(&bytes).expect("the registry is JSON");
    document["codex_accounts"].as_array().cloned().unwrap_or_default()
}

#[test]
fn ac107_list_and_show_report_the_codex_rows() {
    let fixture = CodexFixture::new();
    registry(&fixture, vec![codex_row(USER, ACCT, EMAIL, owned_kind())], Vec::new());

    let listed = run(&fixture, "list", &["codex", "accounts", "list"]);
    assert_eq!(listed.status.code(), Some(0), "{}", stderr(&listed));
    assert!(stdout(&listed).contains(&format!("{USER}/{ACCT}")), "{}", stdout(&listed));
    assert!(stdout(&listed).contains(EMAIL), "{}", stdout(&listed));

    let shown = run(&fixture, "show", &["codex", "accounts", "show", EMAIL]);
    assert_eq!(shown.status.code(), Some(0), "{}", stderr(&shown));
    let text = stdout(&shown);
    assert!(text.contains(USER) && text.contains(ACCT), "{text}");
    assert!(text.contains("owned"), "the kind is reported: {text}");
    assert!(text.contains("auto"), "the refresh policy is reported: {text}");
}

#[test]
fn ac107_show_resolves_within_codex_accounts_only() {
    // Invariant I28: one registry file, two lists that cannot see each other.
    // A Claude row's email must not resolve here, and the refusal must be the
    // ordinary "no account matches" rather than anything that admits it saw
    // something.
    let fixture = CodexFixture::new();
    let claude = fixture.inner().owned_record("acct-claude", "org-claude");
    let mut claude = claude;
    claude["email"] = json!(CLAUDE_EMAIL);
    registry(&fixture, vec![codex_row(USER, ACCT, EMAIL, owned_kind())], vec![claude]);

    let output = run(&fixture, "show-claude-email", &["codex", "accounts", "show", CLAUDE_EMAIL]);

    assert_ne!(output.status.code(), Some(0), "a Claude row resolved in the Codex command");
    assert!(stderr(&output).contains("no account matches"), "{}", stderr(&output));
    // And the Claude row is still there: a refusal reads, it does not write.
    let bytes = fs::read(fixture.inner().config_file()).expect("the registry");
    let document: Value = serde_json::from_slice(&bytes).expect("JSON");
    assert_eq!(document["accounts"].as_array().map(Vec::len), Some(1));
}

#[test]
fn ac107_forget_and_unforget_hide_a_row_without_touching_its_credential() {
    let fixture = CodexFixture::new();
    registry(&fixture, vec![codex_row(USER, ACCT, EMAIL, owned_kind())], Vec::new());
    let dir = seeded_namespace(&fixture);
    let before = manifest(&dir);

    let hidden = run(&fixture, "forget", &["codex", "accounts", "forget", EMAIL]);
    assert_eq!(hidden.status.code(), Some(0), "{}", stderr(&hidden));
    assert_eq!(codex_rows(&fixture)[0]["forgotten"], json!(true));

    let plain = run(&fixture, "list-after-forget", &["codex", "accounts", "list"]);
    assert!(!stdout(&plain).contains(ACCT), "a forgotten row was listed: {}", stdout(&plain));
    let all = run(&fixture, "list-all", &["codex", "accounts", "list", "--all"]);
    assert!(stdout(&all).contains(ACCT), "{}", stdout(&all));

    let shown = run(&fixture, "unforget", &["codex", "accounts", "unforget", EMAIL]);
    assert_eq!(shown.status.code(), Some(0), "{}", stderr(&shown));
    assert_eq!(codex_rows(&fixture)[0]["forgotten"], json!(false));

    assert_eq!(manifest(&dir), before, "forget or unforget touched the namespace");
}

#[test]
fn ac115_remove_delete_secret_unlinks_exactly_its_own_files() {
    // The namespace and its user directory go; the shared lock directory
    // stays; the removal is audited once as `delete`.
    let fixture = CodexFixture::new();
    registry(&fixture, vec![codex_row(USER, ACCT, EMAIL, owned_kind())], Vec::new());
    let dir = seeded_namespace(&fixture);
    let locks = fixture.inner().config_dir().join("codex").join(".locks");
    assert!(dir.is_dir(), "the fixture seeded a namespace");

    let output = run(
        &fixture,
        "remove-delete-secret",
        &["codex", "accounts", "remove", EMAIL, "--delete-secret", "--yes"],
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(!dir.exists(), "the namespace is still there");
    assert!(
        !fixture.inner().config_dir().join("codex").join(USER).exists(),
        "the user directory above it is still there"
    );
    assert!(locks.is_dir(), "the shared lock directory was removed with the namespace");
    assert!(codex_rows(&fixture).is_empty(), "the row is still recorded");

    let log = fs::read_to_string(audit_log(&fixture)).expect("the Codex audit log");
    assert!(log.contains("\"delete\""), "the removal was not audited: {log}");
}

#[test]
fn ac115_a_namespace_holding_foreign_entries_is_refused_and_nothing_is_removed() {
    // Decision M10 / risk PM25: someone pointed `CODEX_HOME` at an agctl
    // namespace and Codex wrote a session tree into it. The removal must
    // refuse, name what it found, and leave every byte — the refresh marker
    // included — where it was.
    let fixture = CodexFixture::new();
    registry(&fixture, vec![codex_row(USER, ACCT, EMAIL, owned_kind())], Vec::new());
    let dir = seeded_namespace(&fixture);
    fs::create_dir(dir.join("sessions")).expect("a Codex session directory");
    fs::write(dir.join("config.toml"), b"# theirs\n").expect("a config");
    let state = fixture.inner().config_dir().join("codex").join(".state");
    fs::create_dir_all(&state).expect("the marker directory");
    let marker = state.join(format!("{USER}+{ACCT}.refresh"));
    write_0600(&marker, b"{}");
    let before = manifest(&dir);
    let marker_before = fs::read(&marker).expect("the marker");

    let output = run(
        &fixture,
        "remove-refused",
        &["codex", "accounts", "remove", EMAIL, "--delete-secret", "--yes"],
    );

    assert_ne!(output.status.code(), Some(0), "a namespace with foreign entries was removed");
    let reason = stderr(&output);
    assert!(reason.contains("sessions"), "the refusal names what it found: {reason}");
    assert!(reason.contains("config.toml"), "{reason}");
    assert!(reason.contains("nothing was removed"), "{reason}");
    assert_eq!(manifest(&dir), before, "the namespace changed");
    assert_eq!(fs::read(&marker).expect("the marker"), marker_before, "the marker was removed");
    assert_eq!(codex_rows(&fixture).len(), 1, "the row was dropped despite the refusal");
}

#[test]
fn ac125_remove_of_a_record_without_a_credential_succeeds_and_creates_no_namespace() {
    // The "remove that writes" case: `OwnedNamespace::open` creates the
    // directory it opens, so a remove that opened one to delete it would
    // leave a namespace behind for a record that never had one.
    let fixture = CodexFixture::new();
    registry(&fixture, vec![codex_row(USER, ACCT, EMAIL, owned_kind())], Vec::new());
    let dir = namespace(&fixture);
    assert!(!dir.exists(), "the fixture starts with no namespace");

    let output = run(
        &fixture,
        "remove-without-a-file",
        &["codex", "accounts", "remove", EMAIL, "--delete-secret", "--yes"],
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stdout(&output).contains("no stored credential"), "{}", stdout(&output));
    assert!(!dir.exists(), "the removal created the namespace it then deleted");
    assert!(codex_rows(&fixture).is_empty(), "the row is still recorded");
    let audited = fs::read_to_string(audit_log(&fixture)).unwrap_or_default();
    assert!(!audited.contains("\"delete\""), "a delete was audited for a write that never was");
}

#[test]
fn delete_secret_is_refused_on_a_row_whose_home_agctl_did_not_create() {
    // Invariant I21. Both read-only kinds, and the foreign credential is
    // still there afterwards.
    let fixture = CodexFixture::new();
    let their_home = fixture.codex_home("theirs");
    write_0600(&their_home.join("auth.json"), br#"{"auth_mode":"chatgpt"}"#);
    registry(
        &fixture,
        vec![
            codex_row("user-live", "acct-live", "live@example.invalid", json!({ "kind": "live" })),
            codex_row(
                "user-imported",
                "acct-imported",
                "imported@example.invalid",
                json!({ "kind": "home_read_only", "dir": their_home.to_string_lossy() }),
            ),
        ],
        Vec::new(),
    );

    for (name, id) in [("live", "live@example.invalid"), ("imported", "imported@example.invalid")] {
        let output = run(
            &fixture,
            &format!("delete-secret-{name}"),
            &["codex", "accounts", "remove", id, "--delete-secret", "--yes"],
        );
        assert_ne!(output.status.code(), Some(0), "`{id}` was removed");
        let reason = stderr(&output);
        assert!(reason.contains("did not create"), "`{id}`: {reason}");
        assert!(reason.contains("accounts forget"), "it says what to do instead: {reason}");
    }

    assert_eq!(codex_rows(&fixture).len(), 2, "a refusal removed a row");
    assert!(their_home.join("auth.json").is_file(), "a refusal deleted a foreign credential");
}

#[test]
fn remove_without_delete_secret_keeps_the_credential() {
    // Decision D-007's other half: the flag is the whole difference between
    // forgetting the record and deleting the secret.
    let fixture = CodexFixture::new();
    registry(&fixture, vec![codex_row(USER, ACCT, EMAIL, owned_kind())], Vec::new());
    let dir = seeded_namespace(&fixture);
    let before = manifest(&dir);

    let output = run(&fixture, "remove-row-only", &["codex", "accounts", "remove", EMAIL]);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(codex_rows(&fixture).is_empty(), "the row is still recorded");
    assert_eq!(manifest(&dir), before, "the credential was touched without `--delete-secret`");
}

#[test]
fn an_unknown_id_is_refused_and_changes_nothing() {
    let fixture = CodexFixture::new();
    registry(&fixture, vec![codex_row(USER, ACCT, EMAIL, owned_kind())], Vec::new());

    for args in [
        &["codex", "accounts", "show", "nobody@example.invalid"][..],
        &["codex", "accounts", "remove", "nobody@example.invalid"][..],
        &["codex", "accounts", "forget", "nobody@example.invalid"][..],
    ] {
        let output = run(&fixture, &format!("unknown-{}", args[2]), args);
        assert_ne!(output.status.code(), Some(0), "`{}` succeeded", args.join(" "));
        assert!(stderr(&output).contains("no account matches"), "{}", stderr(&output));
    }
    assert_eq!(codex_rows(&fixture).len(), 1, "a refusal changed the registry");
}
