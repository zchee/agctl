#![cfg(feature = "testing")]

//! `agctl codex accounts set` and `agctl codex accounts refresh` through the
//! real binary (plan AC127).
//!
//! # What a test without a terminal can prove, and what it cannot
//!
//! A spawned process's standard input is a pipe, so every run here is a
//! non-interactive one. That is not a gap in the coverage — it is half of
//! AC127: `--yes` is **refused** when stdin is not a terminal, so what these
//! tests prove through the binary is that a scheduled re-send is impossible
//! and costs zero POSTs. The interactive half (a `yes` on a terminal sends
//! exactly once, with the marker's digest, and spends the marker's one
//! re-send) is proved in `src/commands/codex/accounts_refresh_tests.rs`,
//! where the terminal is a value and the endpoint is counted.
//!
//! Both Codex endpoint seams are always pointed at a mock, so no run here can
//! reach the vendor (invariant I25), and the token mock's call count is the
//! evidence for every "0 POSTs" claim.

mod common;

#[path = "common/codex.rs"]
mod codex;

use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Output;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use codex::CodexFixture;
use codex::Needle;
use codex::Stream;
use httpmock::Method::GET;
use httpmock::Method::POST;
use httpmock::MockServer;
use serde_json::Value;
use serde_json::json;

const USAGE_PATH: &str = "/backend-api/wham/usage";
const TOKEN_PATH: &str = "/oauth/token";

const USER: &str = "user-AbCdEf0123456789";
const ACCT: &str = "11111111-2222-4333-8444-555555555555";
const EMAIL: &str = "codex-owner@example.invalid";
const REFRESH_TOKEN: &str = "agctl-test-codex-rt-0001";

/// The needles no output may carry (plan section 9.4), by name.
const NEEDLES: [Needle; 6] = [
    ("an access token", "agctl-test-codex-at-"),
    ("a refresh token", "agctl-test-codex-rt-"),
    ("a JWT", "agctl-test-codex-jwt-"),
    ("a JWT header", "eyJ"),
    ("a Bearer header", "Bearer "),
    ("a bearer header", "bearer "),
];

fn now_s() -> i64 {
    jiff::Timestamp::now().as_second()
}

fn jwt(payload: &Value, signature: &str) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).expect("serializes"));
    format!("{header}.{body}.{signature}")
}

/// An `auth.json` whose access token expires at `exp`.
fn auth_doc(exp: i64) -> Value {
    json!({
        "auth_mode": "chatgpt",
        "OPENAI_API_KEY": null,
        "tokens": {
            "id_token": jwt(
                &json!({
                    "email": EMAIL,
                    "https://api.openai.com/auth": {
                        "chatgpt_user_id": USER,
                        "chatgpt_account_id": ACCT,
                        "chatgpt_plan_type": "pro",
                    },
                    "exp": exp,
                }),
                "agctl-test-codex-jwt-sig",
            ),
            "access_token": jwt(&json!({ "exp": exp, "jti": "j" }), "agctl-test-codex-at-sig"),
            "refresh_token": REFRESH_TOKEN,
            "account_id": ACCT,
        },
        "last_refresh": "2026-09-16T00:00:00Z",
    })
}

fn usage_body() -> Value {
    json!({
        "plan_type": "pro",
        "email": "agctl-test-codex-email-0001",
        "user_id": USER,
        "account_id": ACCT,
        "rate_limit": {
            "allowed": true,
            "limit_reached": false,
            "primary_window": { "used_percent": 42.0, "limit_window_seconds": 18_000, "reset_after_seconds": 3_600 },
            "secondary_window": { "used_percent": 7.0, "limit_window_seconds": 604_800, "reset_after_seconds": 86_400 },
        },
        "credits": { "has_credits": true, "unlimited": false, "balance": "0" },
    })
}

/// A token response in fact F80's shape.
fn grant_body() -> Value {
    json!({
        "access_token": jwt(&json!({ "exp": now_s() + 864_000, "jti": "j2" }), "agctl-test-codex-at-sig"),
        "token_type": "Bearer",
        "expires_in": 864_000,
        "refresh_token": "agctl-test-codex-rt-0002",
    })
}

fn write_0600(path: &Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
    fs::write(path, bytes).expect("write");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("chmod");
}

/// A Codex fixture with both endpoint seams pointed at `server`.
fn fixture(server: &MockServer) -> CodexFixture {
    let mut fixture = CodexFixture::new();
    fixture.set("AGCTL_CODEX_USAGE_URL", &server.base_url());
    fixture.set("AGCTL_CODEX_TOKEN_URL", &server.url(TOKEN_PATH));
    fixture
}

/// A registry with one owned account whose namespace holds `doc`.
fn owned(fixture: &CodexFixture, doc: &Value, refresh: &str) {
    fixture.inner().write_registry_document(&json!({
        "version": 2,
        "accounts": [],
        "forgotten_services": [],
        "codex_accounts": [{
            "chatgpt_user_id": USER,
            "chatgpt_account_id": ACCT,
            "email": EMAIL,
            "plan_type": "pro",
            "label": null,
            "kind": { "kind": "owned", "export_spelling": "/x", "refresh": refresh },
            "forgotten": false,
            "created_at": "2026-09-17T00:00:00Z",
        }],
    }));
    write_0600(&namespace(fixture).join("auth.json"), &pretty(doc));
}

fn pretty(doc: &Value) -> Vec<u8> {
    serde_json::to_vec_pretty(doc).expect("serializes")
}

fn namespace(fixture: &CodexFixture) -> PathBuf {
    fixture.inner().config_dir().join("codex").join(USER).join(ACCT)
}

fn marker_path(fixture: &CodexFixture) -> PathBuf {
    fixture.inner().config_dir().join("codex").join(".state").join(format!("{USER}+{ACCT}.refresh"))
}

/// A marker that says a grant was sent an hour and a minute ago and nothing
/// classified the answer.
///
/// The digest is a stand-in: every run here is refused by the consent, which
/// is taken **before** the namespace is opened, so no test below ever reaches
/// the compare that would read it.
fn write_unknown_marker(fixture: &CodexFixture, resent: bool) {
    let sent_at = jiff::Timestamp::from_second(now_s() - 61 * 60).expect("a valid time");
    write_0600(
        &marker_path(fixture),
        json!({
            "schema": 1,
            "inflight": { "sent_digest8": "0123abcd", "sent_at": sent_at.to_string() },
            "last_sent_at": sent_at.to_string(),
            "ambiguous_since": sent_at.to_string(),
            "class": "ambiguous",
            "resent": resent,
            "floor_min": 60,
            "did_not_help": 0,
        })
        .to_string()
        .as_bytes(),
    );
}

fn marker(fixture: &CodexFixture) -> Value {
    serde_json::from_slice(&fs::read(marker_path(fixture)).expect("the marker is there"))
        .expect("the marker is JSON")
}

fn registry_refresh(fixture: &CodexFixture) -> String {
    let bytes = fs::read(fixture.inner().config_file()).expect("the registry is there");
    let document: Value = serde_json::from_slice(&bytes).expect("the registry is JSON");
    document["codex_accounts"][0]["kind"]["refresh"]
        .as_str()
        .expect("an owned row carries its policy")
        .to_owned()
}

/// Runs `agctl <args>`, asserting neither stream carries a needle.
fn run(fixture: &CodexFixture, name: &str, args: &[&str]) -> Output {
    codex::checked(
        "e2e_codex_accounts_refresh",
        name,
        fixture.cmd().args(args).output().expect("the binary runs"),
        &NEEDLES,
        &[Stream::Stdout, Stream::Stderr],
    )
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

// ---------------------------------------------------------------------------
// `set --refresh auto|never`
// ---------------------------------------------------------------------------

#[test]
fn ac127_set_never_makes_the_next_pass_post_nothing_and_auto_restores_it() {
    let server = MockServer::start();
    let usage = server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(200).json_body(usage_body());
    });
    let token = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(200).json_body(grant_body());
    });
    let fixture = fixture(&server);
    // Expired an hour ago: with `auto` this row is exactly what the pre-pass
    // refreshes, so a pass that sends nothing can only be the policy's doing.
    owned(&fixture, &auth_doc(now_s() - 3_600), "auto");

    let set = run(&fixture, "set-never", &["codex", "accounts", "set", USER, "--refresh", "never"]);
    assert_eq!(set.status.code(), Some(0), "{}", stderr(&set));
    assert_eq!(registry_refresh(&fixture), "never", "the registry field is what changed");
    assert!(
        !marker_path(&fixture).exists(),
        "`set` wrote a refresh marker, so it opened the namespace"
    );

    let passed = run(&fixture, "status-never", &["codex", "status"]);
    token.assert_calls(0);
    let shown = stdout(&passed);
    assert!(shown.contains("expired"), "the row says what it is:\n{shown}");
    assert!(shown.contains("agctl codex login"), "and what fixes it:\n{shown}");

    // And `auto` gives the refresh back: the same pass now sends exactly once.
    let set = run(&fixture, "set-auto", &["codex", "accounts", "set", USER, "--refresh", "auto"]);
    assert_eq!(set.status.code(), Some(0), "{}", stderr(&set));
    assert_eq!(registry_refresh(&fixture), "auto");

    let _passed = run(&fixture, "status-auto", &["codex", "status"]);
    token.assert_calls(1);
    assert!(usage.calls() >= 1, "the pass still fetched usage");
}

#[test]
fn set_names_a_row_it_cannot_change() {
    let server = MockServer::start();
    let fixture = fixture(&server);
    owned(&fixture, &auth_doc(now_s() + 86_400), "auto");

    let output =
        run(&fixture, "set-unknown", &["codex", "accounts", "set", "nobody", "--refresh", "never"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("no account matches `nobody`"), "{}", stderr(&output));
    assert_eq!(registry_refresh(&fixture), "auto", "nothing was written");
}

// ---------------------------------------------------------------------------
// `refresh --resend` and `--reset-floor` without a terminal
// ---------------------------------------------------------------------------

#[test]
fn ac127_yes_without_a_terminal_refuses_the_re_send_and_posts_nothing() {
    let server = MockServer::start();
    let token = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(200).json_body(grant_body());
    });
    let fixture = fixture(&server);
    owned(&fixture, &auth_doc(now_s() + 9 * 86_400), "auto");
    write_unknown_marker(&fixture, false);
    let before = marker(&fixture);

    let output = run(
        &fixture,
        "resend-yes-no-tty",
        &["codex", "accounts", "refresh", USER, "--resend", "--yes"],
    );

    // The whole clause: refused, nothing sent, nothing spent. A re-send
    // cannot be scheduled, which is what `--yes` would otherwise be for.
    token.assert_calls(0);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("interactive terminal"), "{}", stderr(&output));
    assert_eq!(marker(&fixture), before, "the marker is byte-for-byte what it was");
}

#[test]
fn ac127_a_spent_marker_is_refused_before_a_terminal_is_even_asked_for() {
    // Ordering, not duplication: the consent is taken first, so a `--resend`
    // on a spent marker without a terminal is refused for the terminal — the
    // `already spent` refusal is the interactive path's, proved in the unit
    // tests. What matters here is that neither path sends.
    let server = MockServer::start();
    let token = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(200).json_body(grant_body());
    });
    let fixture = fixture(&server);
    owned(&fixture, &auth_doc(now_s() + 9 * 86_400), "auto");
    write_unknown_marker(&fixture, true);

    let output = run(&fixture, "resend-spent", &["codex", "accounts", "refresh", USER, "--resend"]);

    token.assert_calls(0);
    assert!(!output.status.success(), "{}", stdout(&output));
    assert!(marker(&fixture)["resent"].as_bool().expect("a flag"), "still spent");
}

#[test]
fn ac127_reset_floor_without_a_terminal_is_refused_and_lifts_nothing() {
    let server = MockServer::start();
    let token = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(200).json_body(grant_body());
    });
    let fixture = fixture(&server);
    owned(&fixture, &auth_doc(now_s() + 9 * 86_400), "auto");
    write_0600(
        &marker_path(&fixture),
        json!({ "schema": 1, "floor_min": 240, "did_not_help": 3 }).to_string().as_bytes(),
    );

    let output = run(
        &fixture,
        "reset-floor-no-tty",
        &["codex", "accounts", "refresh", USER, "--reset-floor", "--yes"],
    );

    token.assert_calls(0);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("interactive terminal"), "{}", stderr(&output));
    let marker = marker(&fixture);
    assert_eq!(marker["did_not_help"], 3, "the terminal state stands");
    assert_eq!(marker["floor_min"], 240, "and so does the floor");
}

#[test]
fn refresh_needs_one_of_the_two_actions_and_says_which() {
    let server = MockServer::start();
    let fixture = fixture(&server);
    owned(&fixture, &auth_doc(now_s() + 86_400), "auto");

    let output = run(&fixture, "refresh-bare", &["codex", "accounts", "refresh", USER]);
    assert_eq!(output.status.code(), Some(1), "a usage error is fatal");
    let said = stderr(&output);
    assert!(said.contains("--resend"), "{said}");
    assert!(said.contains("--reset-floor"), "{said}");
}

#[test]
fn a_row_agctl_stores_no_credential_for_has_no_refresh_state_to_act_on() {
    let server = MockServer::start();
    let fixture = fixture(&server);
    fixture.inner().write_registry_document(&json!({
        "version": 2,
        "accounts": [],
        "forgotten_services": [],
        "codex_accounts": [{
            "chatgpt_user_id": USER,
            "chatgpt_account_id": ACCT,
            "email": EMAIL,
            "plan_type": "pro",
            "label": null,
            "kind": { "kind": "live" },
            "forgotten": false,
            "created_at": "2026-09-17T00:00:00Z",
        }],
    }));

    let output =
        run(&fixture, "resend-live", &["codex", "accounts", "refresh", USER, "--resend", "--yes"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("stores no credential"), "{}", stderr(&output));
}
