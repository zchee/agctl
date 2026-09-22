#![cfg(feature = "testing")]

//! `agctl codex login` over an account agctl already owns (plan AC107).
//!
//! A login that would replace a stored grant asks first. There is no `--yes`
//! on this command — plan section 3.2 gives it `--label` and `--no-refresh`
//! and nothing else — so a run with no terminal has no way to say yes, and it
//! must **refuse** rather than overwrite. Every run here is such a run: a
//! spawned process's standard input is a pipe.
//!
//! What that leaves to prove end to end is the cost of the refusal, which is
//! the part a person cares about: the grant agctl already holds is
//! byte-identical afterwards, down to the inode, and the fresh one the
//! vendor's CLI just wrote in the scratch home is gone. The answer's own
//! three exits — yes, no, and an answer that cannot be read — are proved in
//! `src/commands/codex/login_tests.rs`, where the terminal is a value.
//!
//! The AC105 crash window is the other half of this file: a namespace with no
//! record is **not** an account agctl owns, so the next login adopts it
//! without a question, exactly as it did before this confirmation existed.

mod common;

#[path = "common/codex.rs"]
mod codex;

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::Output;

use codex::CodexFixture;
use codex::Needle;
use codex::Stream;
use codex::audit_outcomes;
use codex::namespace;
use codex::stderr;
use serde_json::Value;
use serde_json::json;

/// A JWT signed with this file's own signature needle.
fn jwt(payload: &Value) -> String {
    codex::jwt(payload, JWT_SIGNATURE)
}

const USER: &str = "user-confirm-0001";
const ACCT: &str = "acct-confirm-0001";
const OTHER_USER: &str = "user-confirm-0002";
const OTHER_ACCT: &str = "acct-confirm-0002";
const EMAIL: &str = "codex-confirm@example.invalid";

const REFRESH_TOKEN: &str = "agctl-test-codex-confirm-rt-0001";
const JWT_SIGNATURE: &str = "agctl-test-codex-confirm-sig";

const NEEDLES: [Needle; 5] = [
    ("the refresh token", REFRESH_TOKEN),
    ("the JWT signature", JWT_SIGNATURE),
    ("a JWT header", "eyJ"),
    ("a Bearer header", "Bearer "),
    ("a bearer header", "bearer "),
];

/// The ChatGPT-mode `auth.json` the fake writes into its scratch home.
fn auth_doc(user: &str, acct: &str) -> Value {
    let exp = jiff::Timestamp::now().as_second() + 3600;
    json!({
        "auth_mode": "chatgpt",
        "OPENAI_API_KEY": null,
        "tokens": {
            "id_token": jwt(&json!({
                "email": EMAIL,
                "https://api.openai.com/auth": {
                    "chatgpt_user_id": user,
                    "chatgpt_account_id": acct,
                    "chatgpt_plan_type": "pro",
                },
                "exp": exp,
            })),
            "access_token": jwt(&json!({ "exp": exp, "jti": "j" })),
            "refresh_token": REFRESH_TOKEN,
            "account_id": acct,
        },
        "last_refresh": "2026-09-16T00:00:00Z",
    })
}

/// Writes `doc` where the fake will read it, and points the fake at it.
fn arm(fixture: &mut CodexFixture, name: &str, doc: &Value) {
    let path = fixture.root().join(name);
    fs::write(&path, serde_json::to_vec_pretty(doc).expect("serializes")).expect("writable");
    fixture.set("AGCTL_FAKE_CODEX_AUTH", &path.to_string_lossy());
}

/// A fixture whose fake `codex` logs its runs and writes `(USER, ACCT)`.
fn armed() -> CodexFixture {
    let mut fixture = CodexFixture::new();
    let log = fixture.codex_log_path();
    fixture.set("AGCTL_FAKE_CODEX_LOG", &log.to_string_lossy());
    arm(&mut fixture, "login-doc.json", &auth_doc(USER, ACCT));
    fixture
}

fn login(fixture: &CodexFixture, name: &str) -> Output {
    codex::checked(
        "e2e_codex_login_confirm",
        name,
        fixture.cmd().args(["codex", "login"]).output().expect("the binary runs"),
        &NEEDLES,
        &[Stream::Stdout, Stream::Stderr],
        Some(&fixture.security_log_path()),
    )
}

/// Every scratch home left behind.
fn scratch_leaves(fixture: &CodexFixture) -> Vec<PathBuf> {
    let root = fixture.inner().config_dir().join("codex").join(".scratch");
    let Ok(entries) = fs::read_dir(root) else { return Vec::new() };
    entries.flatten().map(|entry| entry.path()).collect()
}

fn registry(fixture: &CodexFixture) -> Value {
    let bytes = fs::read(fixture.inner().config_file()).expect("the registry is there");
    serde_json::from_slice(&bytes).expect("the registry is JSON")
}

/// How many Codex rows the registry holds.
fn codex_rows(fixture: &CodexFixture) -> usize {
    registry(fixture)["codex_accounts"].as_array().map_or(0, Vec::len)
}

#[test]
fn ac107_a_second_login_for_an_owned_account_is_refused_and_costs_the_stored_grant_nothing() {
    let fixture = armed();

    let first = login(&fixture, "first");
    assert!(first.status.success(), "{}", stderr(&first));
    let installed = namespace(&fixture, USER, ACCT).join("auth.json");
    let before = fs::read(&installed).expect("installed");
    let before_inode = fs::metadata(&installed).expect("metadata").ino();

    let second = login(&fixture, "second-no-terminal");

    assert!(!second.status.success(), "an overwrite nobody confirmed must not happen");
    let said = stderr(&second);
    assert!(
        said.contains(&format!("agctl codex accounts remove {USER}/{ACCT}")),
        "the refusal names the way a non-interactive run makes room:\n{said}"
    );
    assert!(
        !said.contains("--yes"),
        "`login` has no `--yes`, so naming one would be a lie:\n{said}"
    );

    // The cost of the refusal: the stored grant is untouched — the same
    // bytes in the same inode — and the one the child just wrote is gone.
    assert_eq!(fs::read(&installed).expect("still there"), before, "the grant is byte-identical");
    assert_eq!(fs::metadata(&installed).expect("metadata").ino(), before_inode, "same inode");
    assert!(
        scratch_leaves(&fixture).is_empty(),
        "the scratch home is removed: the new grant is gone"
    );
    assert_eq!(codex_rows(&fixture), 1, "and the registry still holds exactly one row");
    assert_eq!(audit_outcomes(&fixture), ["login_install"], "only the first login wrote");
}

#[test]
fn ac107_a_login_for_another_account_is_not_an_overwrite_and_is_not_asked_about() {
    let mut fixture = armed();

    let first = login(&fixture, "other-first");
    assert!(first.status.success(), "{}", stderr(&first));

    arm(&mut fixture, "other-doc.json", &auth_doc(OTHER_USER, OTHER_ACCT));
    let second = login(&fixture, "other-second");
    assert!(second.status.success(), "a different identity replaces nothing: {}", stderr(&second));

    assert!(namespace(&fixture, USER, ACCT).join("auth.json").exists());
    assert!(namespace(&fixture, OTHER_USER, OTHER_ACCT).join("auth.json").exists());
    assert_eq!(codex_rows(&fixture), 2);
}

#[test]
fn ac105_a_namespace_with_no_record_is_adopted_without_a_question() {
    // The crash window plan AC105 describes: the grant landed and the
    // registry update did not. The confirmation is registry-based precisely
    // so this keeps working — there is no account agctl owns to ask about,
    // and the next login adopts the namespace as it always did.
    let fixture = armed();

    let first = login(&fixture, "adopt-first");
    assert!(first.status.success(), "{}", stderr(&first));
    let installed = namespace(&fixture, USER, ACCT).join("auth.json");
    assert!(installed.exists());

    // Exactly the state that crash leaves: the namespace, no record.
    fixture.inner().write_registry_document(&json!({
        "version": 1,
        "accounts": [],
        "forgotten_services": [],
    }));

    let second = login(&fixture, "adopt-second");
    assert!(second.status.success(), "the orphan namespace is adopted: {}", stderr(&second));
    assert_eq!(codex_rows(&fixture), 1, "and the record is written again");
    assert_eq!(
        audit_outcomes(&fixture),
        ["login_install", "login_overwrite"],
        "the second install went over the grant that was there"
    );
}
