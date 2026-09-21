#![cfg(feature = "testing")]

//! `agctl codex status` and `agctl codex watch`, driven through the real
//! binary against `httpmock` endpoints.
//!
//! Every Codex home here is inside the fixture's temporary tree: `HOME` points
//! into it, the Codex home variable is removed from every spawn, and both
//! Codex endpoint seams are always set — to a mock, or to a closed loopback
//! port — so no run can reach the vendor (invariant I25).
//!
//! # The trace capture (review S31 F5)
//!
//! Each test runs the binary with `RUST_LOG=agctl=trace` and asserts on the
//! bytes it wrote. When `AGCTL_E2E_TRACE_DIR` names a directory, the captured
//! standard error is also written there, so `scripts/phase3-greps.sh --log`
//! can count the leak needles in a binary's own trace rather than in nextest's
//! buffered output. The variable is read by this test file only; the binary
//! never sees it.

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
/// A second account id, so the live row does not share the owned row's
/// usage-cache key (review S33-C3a F1).
const LIVE_ACCT: &str = "66666666-7777-4888-8999-aaaaaaaaaaaa";
const EMAIL: &str = "codex-owner@example.invalid";

/// The needles no output of a pass may carry (plan section 9.4), by name.
const NEEDLES: [Needle; 8] = [
    ("an access token", "agctl-test-codex-at-"),
    ("a refresh token", "agctl-test-codex-rt-"),
    ("an API key", "agctl-test-codex-ak-"),
    ("a JWT", "agctl-test-codex-jwt-"),
    ("an email sentinel", "agctl-test-codex-email-"),
    ("a JWT header", "eyJ"),
    ("a Bearer header", "Bearer "),
    ("a bearer header", "bearer "),
];

/// The published version-2 schema.
const SCHEMA_V2: &str = include_str!("../schemas/status.v2.json");

fn now_s() -> i64 {
    jiff::Timestamp::now().as_second()
}

fn jwt(payload: &Value, signature: &str) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).expect("serializes"));
    format!("{header}.{body}.{signature}")
}

/// An `auth.json` for `user`/`acct` whose access token expires at `exp`.
fn auth_doc(user: &str, acct: &str, exp: i64, fedramp: bool, rt: &str) -> Value {
    let id_token = jwt(
        &json!({
            "email": EMAIL,
            "https://api.openai.com/auth": {
                "chatgpt_user_id": user,
                "chatgpt_account_id": acct,
                "chatgpt_plan_type": "pro",
                "chatgpt_account_is_fedramp": fedramp,
            },
            "exp": exp,
        }),
        "agctl-test-codex-jwt-sig",
    );
    let access_token = jwt(&json!({ "exp": exp, "jti": "j" }), "agctl-test-codex-at-sig");
    json!({
        "auth_mode": "chatgpt",
        "OPENAI_API_KEY": null,
        "tokens": {
            "id_token": id_token,
            "access_token": access_token,
            "refresh_token": rt,
            "account_id": acct,
        },
        "last_refresh": "2026-09-16T00:00:00Z",
    })
}

fn usage_body() -> Value {
    body_for(ACCT)
}

/// The usage body an account's own GET answers. The endpoint echoes the
/// account it was asked about, so a mock that answers one id for every row
/// misreports whichever row is not that one — visible in `--raw` and in v2's
/// `raw` member (review S33-C3a carry).
fn body_for(account: &str) -> Value {
    json!({
        "plan_type": "pro",
        "email": "agctl-test-codex-email-0001",
        "user_id": USER,
        "account_id": account,
        "rate_limit": {
            "allowed": true,
            "limit_reached": false,
            "primary_window": { "used_percent": 42.0, "limit_window_seconds": 18_000, "reset_after_seconds": 3_600 },
            "secondary_window": { "used_percent": 7.0, "limit_window_seconds": 604_800, "reset_after_seconds": 86_400 },
        },
        "credits": { "has_credits": true, "unlimited": false, "balance": "0" },
    })
}

fn write_0600(path: &Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
    fs::write(path, bytes).expect("write");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("chmod");
}

/// A Codex fixture with both endpoint seams pointed at `server` and tracing on.
fn fixture(server: &MockServer) -> CodexFixture {
    let mut fixture = CodexFixture::new();
    fixture.set("AGCTL_CODEX_USAGE_URL", &server.base_url());
    fixture.set("AGCTL_CODEX_TOKEN_URL", &server.url(TOKEN_PATH));
    fixture.set("RUST_LOG", "agctl=trace");
    fixture
}

/// The live home's `auth.json`: `$HOME/.codex`, inside the fixture.
fn live_auth(fixture: &CodexFixture) -> PathBuf {
    fixture.inner().home().join(".codex").join("auth.json")
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
    let ns = fixture.inner().config_dir().join("codex").join(USER).join(ACCT);
    write_0600(&ns.join("auth.json"), &serde_json::to_vec_pretty(doc).expect("serializes"));
}

/// Runs `agctl <args>`, asserts neither stream carries a needle, and hands
/// the captured standard error to the trace directory when one is named.
fn run(fixture: &CodexFixture, name: &str, args: &[&str]) -> Output {
    checked(name, fixture.cmd().args(args).output().expect("the binary runs"))
}

/// Asserts neither stream carries a needle and captures the standard error.
fn checked(name: &str, output: Output) -> Output {
    codex::checked("e2e_codex_status", name, output, &NEEDLES, &[Stream::Stderr])
}

#[test]
fn ac102_status_json_validates_against_v2_and_carries_no_needle() {
    let server = MockServer::start();
    // One mock per account, matched on the header the GET carries, so each row
    // is answered with its own `account_id` (review S33-C3a carry).
    let usage = server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH).header("chatgpt-account-id", ACCT);
        then.status(200).json_body(body_for(ACCT));
    });
    let usage_live = server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH).header("chatgpt-account-id", LIVE_ACCT);
        then.status(200).json_body(body_for(LIVE_ACCT));
    });
    let fixture = fixture(&server);
    // One user id across both rows, so D-039's qualification is still what is
    // being proved — but two *account* ids, because the usage cache is keyed by
    // identity (`pass::cache_path`). With one identity the rows share a cache
    // file, and whichever stores first lets the other serve from it, so
    // `usage.calls()` is 1 or 2 depending on the scheduler (review S33-C3a F1).
    let live = auth_doc(USER, LIVE_ACCT, now_s() + 86_400, false, "agctl-test-codex-rt-0001");
    let owned_doc = auth_doc(USER, ACCT, now_s() + 86_400, false, "agctl-test-codex-rt-0001");
    write_0600(&live_auth(&fixture), &serde_json::to_vec_pretty(&live).expect("serializes"));
    owned(&fixture, &owned_doc, "auto");

    let output = run(&fixture, "json", &["codex", "status", "--json"]);

    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));
    let document: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON");
    let schema: Value = serde_json::from_str(SCHEMA_V2).expect("the schema is JSON");
    let validator = jsonschema::validator_for(&schema).expect("the schema compiles");
    let errors: Vec<String> = validator.iter_errors(&document).map(|err| err.to_string()).collect();
    assert!(errors.is_empty(), "{errors:?}\n{document:#}");
    let rows = document["rows"].as_array().expect("rows");
    assert_eq!(
        rows.len(),
        2,
        "kinds seen: {:?}\n{document:#}",
        rows.iter().map(|row| (row["kind"].clone(), row["id"].clone())).collect::<Vec<_>>()
    );
    let mut accounts: Vec<String> = Vec::new();
    for row in rows {
        assert_eq!(row["provider"], "codex");
        assert_eq!(row["identity"]["user_id"], USER);
        assert_eq!(row["identity"]["plan_type"], "pro");
        assert_eq!(row["state"], "ok");
        let account = row["identity"]["account_id"].as_str().expect("an account id");
        assert_eq!(
            row["id"],
            format!("{USER}/{account}"),
            "two rows share the user id, so each is qualified by its account (D-039)"
        );
        accounts.push(account.to_owned());
    }
    accounts.sort();
    assert_eq!(accounts, [ACCT, LIVE_ACCT].map(str::to_owned), "{document:#}");
    // Exact, and deterministic now that the two rows key different cache files:
    // one GET each, each answered with its own account.
    assert_eq!((usage.calls(), usage_live.calls()), (1, 1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("codex_account"), "tracing is on, so the span is printed:\n{stderr}");
    assert!(stderr.contains(USER), "the display id is traced (review S31 F6):\n{stderr}");
    assert!(!stderr.contains(EMAIL), "an email is never traced:\n{stderr}");
}

#[test]
fn ac102_raw_bodies_carry_no_email_in_the_table_and_in_the_v2_document() {
    let server = MockServer::start();
    let _usage = server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(200).json_body(usage_body());
    });
    let fixture = fixture(&server);
    let doc = auth_doc(USER, ACCT, now_s() + 86_400, false, "agctl-test-codex-rt-0001");
    write_0600(&live_auth(&fixture), &serde_json::to_vec_pretty(&doc).expect("serializes"));

    let output = run(&fixture, "raw", &["codex", "status", "--raw"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--- raw: "), "{stdout}");
    assert!(stdout.contains("\"account_id\""), "raw keeps the ids (review S31 F7): {stdout}");

    let output = run(&fixture, "json-raw", &["codex", "status", "--json", "--raw"]);
    assert_eq!(output.status.code(), Some(0));
    let document: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON");
    let schema: Value = serde_json::from_str(SCHEMA_V2).expect("the schema is JSON");
    let validator = jsonschema::validator_for(&schema).expect("the schema compiles");
    assert!(validator.is_valid(&document), "{document:#}");
    let id = document["rows"][0]["id"].as_str().expect("an id");
    let body = &document["raw"][id];
    assert_eq!(body["account_id"], ACCT, "{document:#}");
    assert!(body.get("email").is_none(), "the raw body keeps no email: {document:#}");

    let plain = run(&fixture, "json-no-raw", &["codex", "status", "--json"]);
    let document: Value = serde_json::from_slice(&plain.stdout).expect("stdout is JSON");
    assert!(document.get("raw").is_none(), "`raw` is present only with --raw");
}

#[test]
fn ac103_no_usage_source_rows_alone_exit_0_and_a_degraded_row_exits_2() {
    let server = MockServer::start();
    let usage = server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(200).json_body(usage_body());
    });
    let fixture = fixture(&server);
    write_0600(&live_auth(&fixture), br#"{"OPENAI_API_KEY": "agctl-test-codex-ak-0001"}"#);

    let output = run(&fixture, "apikey", &["codex", "status"]);
    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));
    let table = String::from_utf8_lossy(&output.stdout);
    let heading = table.lines().next().expect("a heading");
    let headings: Vec<&str> = heading.split('|').map(str::trim).collect();
    assert_eq!(
        headings,
        ["Account", "Plan", "Kind", "5h", "Weekly", "Credits", "5h reset", "Weekly reset", "State"]
    );
    assert!(table.contains("no usage source (apikey)"), "{table}");

    // An owned account that may not be refreshed, and has expired.
    owned(&fixture, &auth_doc(USER, ACCT, 1_000, false, "agctl-test-codex-rt-0001"), "never");
    let output = run(&fixture, "never", &["codex", "status"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stdout).contains("expired (run agctl codex login)"));
    assert_eq!(usage.calls(), 0, "neither row is fetched");
}

#[test]
fn ac97_a_codex_only_run_creates_the_empty_claude_store_and_the_codex_roots() {
    let server = MockServer::start();
    let usage = usage_mock(&server, 200);
    let token = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(200).json_body(grant("agctl-test-codex-rt-0002"));
    });
    let fixture = fixture(&server);
    let config = fixture.inner().config_dir();
    assert!(!config.join("claude").exists());

    let output = run(&fixture, "empty", &["codex", "status"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Review S33-C2 B3: this fixture's `$HOME` has no `.codex`, so there is no
    // live row to fail on — a machine that has never run Codex reports nothing
    // rather than `needs login`. A home that exists without `auth.json` still
    // says so and exits 2 (deviation D18, pinned in `pass_tests.rs`).
    assert_eq!(
        output.status.code(),
        Some(0),
        "a machine that has never run Codex has no row to fail on: {stdout}"
    );
    assert!(
        !stdout.contains("needs login"),
        "a live row was reported for a home that does not exist: {stdout}"
    );
    for (dir, expected) in
        [("claude", vec![".locks"]), ("claude/.locks", vec![]), ("cache/claude", vec![])]
    {
        let path = config.join(dir);
        assert!(path.is_dir(), "{dir} was not created (accepted by AC97)");
        let entries: Vec<String> = fs::read_dir(&path)
            .expect("list")
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, expected, "{dir} holds more than `ensure_dirs` makes");
    }
    for dir in ["codex/.locks", "codex/.state", "codex/.scratch", "cache/codex"] {
        assert!(config.join(dir).is_dir(), "{dir} was not created");
    }

    // The other half of D30, through the binary (review S33-C3a F3): a Codex
    // home that *exists* without `auth.json` keeps its row, says why, and exits
    // 2 (deviation D18). Same fixture, so the only thing that differs between
    // the two runs is whether the directory is there.
    let home = fixture.inner().home().join(".codex");
    fs::create_dir_all(&home).expect("a Codex home with no credential");
    assert!(!home.join("auth.json").exists(), "the home must hold no credential");

    let output = run(&fixture, "empty-home", &["codex", "status"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(2), "an existing home with no credential: {stdout}");
    assert!(stdout.contains("needs login"), "{stdout}");
    assert!(stdout.contains("no credential in this Codex home"), "{stdout}");
    assert_eq!(usage.calls(), 0, "a home with no credential was fetched");
    assert_eq!(token.calls(), 0, "a home with no credential was refreshed");
}

#[test]
fn ac101_the_get_carries_the_documented_headers_and_fedramp_only_when_claimed() {
    for fedramp in [false, true] {
        let server = MockServer::start();
        let matched = server.mock(|when, then| {
            let when = when
                .method(GET)
                .path(USAGE_PATH)
                .header_exists("authorization")
                .header("chatgpt-account-id", ACCT)
                .header("accept", "application/json")
                .header_exists("user-agent");
            if fedramp {
                when.header("x-openai-fedramp", "true");
            } else {
                when.header_missing("x-openai-fedramp");
            }
            then.status(200).json_body(usage_body());
        });
        let fixture = fixture(&server);
        let doc = auth_doc(USER, ACCT, now_s() + 86_400, fedramp, "agctl-test-codex-rt-0001");
        write_0600(&live_auth(&fixture), &serde_json::to_vec_pretty(&doc).expect("serializes"));

        let output = run(&fixture, &format!("fedramp-{fedramp}"), &["codex", "status"]);

        assert_eq!(
            output.status.code(),
            Some(0),
            "fedramp {fedramp}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert_eq!(matched.calls(), 1, "fedramp {fedramp}");
    }
}

#[test]
fn ac101_a_403_is_an_error_and_never_a_refresh() {
    let server = MockServer::start();
    let forbidden = server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(403);
    });
    let token = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(200).json_body(json!({}));
    });
    let fixture = fixture(&server);
    owned(
        &fixture,
        &auth_doc(USER, ACCT, now_s() + 86_400, false, "agctl-test-codex-rt-0001"),
        "auto",
    );

    let output = run(&fixture, "403", &["codex", "status", "--account", USER]);

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stdout).contains("HTTP 403"));
    assert_eq!((forbidden.calls(), token.calls()), (1, 0));
}

#[test]
fn ac91b_default_flags_let_one_expired_owned_row_refresh_exactly_once() {
    let server = MockServer::start();
    let token = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(200).json_body(json!({
            "access_token": jwt(&json!({ "exp": now_s() + 864_000 }), "agctl-test-codex-at-new"),
            "refresh_token": "agctl-test-codex-rt-0002",
            "id_token": jwt(&json!({
                "https://api.openai.com/auth": { "chatgpt_user_id": USER, "chatgpt_account_id": ACCT }
            }), "agctl-test-codex-jwt-new"),
            "expires_in": 864_000,
        }));
    });
    let usage = server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(200).json_body(usage_body());
    });
    let fixture = fixture(&server);
    owned(&fixture, &auth_doc(USER, ACCT, 1_000, false, "agctl-test-codex-rt-0001"), "auto");

    let output = run(&fixture, "default-flags", &["codex", "status", "--account", USER]);

    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stdout));
    assert_eq!(token.calls(), 1, "exactly one POST with the default --timeout");
    assert_eq!(usage.calls(), 1);
    let ns = fixture.inner().config_dir().join("codex").join(USER).join(ACCT);
    let names: Vec<String> = fs::read_dir(&ns)
        .expect("the namespace")
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["auth.json"], "the namespace holds only auth.json");
}

#[test]
fn an_account_selector_that_matches_nothing_fails_naming_the_known_ones() {
    let server = MockServer::start();
    let fixture = fixture(&server);
    owned(
        &fixture,
        &auth_doc(USER, ACCT, now_s() + 86_400, false, "agctl-test-codex-rt-0001"),
        "auto",
    );

    let output = run(&fixture, "selector", &["codex", "status", "--account", "nobody"]);

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no Codex account matches `nobody`"), "{stderr}");
    assert!(stderr.contains(&format!("{USER}/{ACCT}")), "{stderr}");
}

#[test]
fn ac104_watch_rejects_an_interval_under_the_floor_naming_it() {
    let server = MockServer::start();
    let fixture = fixture(&server);

    let output = run(&fixture, "watch-floor", &["codex", "watch", "--interval", "30s"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("60s floor"));
}

// ---------------------------------------------------------------------------
// The refresh halves, through the binary (S33 C3a)
// ---------------------------------------------------------------------------

/// A token response in fact F80's shape.
fn grant(rt: &str) -> Value {
    json!({
        "access_token": jwt(&json!({ "exp": now_s() + 864_000 }), "agctl-test-codex-at-new"),
        "refresh_token": rt,
        "id_token": jwt(&json!({
            "https://api.openai.com/auth": { "chatgpt_user_id": USER, "chatgpt_account_id": ACCT }
        }), "agctl-test-codex-jwt-new"),
        "expires_in": 864_000,
    })
}

/// The owned namespace's directory inside a fixture.
fn namespace(fixture: &CodexFixture) -> PathBuf {
    fixture.inner().config_dir().join("codex").join(USER).join(ACCT)
}

/// The refresh marker for the owned account.
fn marker_path(fixture: &CodexFixture) -> PathBuf {
    fixture.inner().config_dir().join("codex").join(".state").join(format!("{USER}+{ACCT}.refresh"))
}

/// The marker, when one is on disk.
fn marker(fixture: &CodexFixture) -> Option<Value> {
    let bytes = fs::read(marker_path(fixture)).ok()?;
    Some(serde_json::from_slice(&bytes).expect("the marker parses"))
}

/// The Codex write log's lines.
fn audit_lines(fixture: &CodexFixture) -> Vec<Value> {
    let path = fixture.inner().config_dir().join("codex").join("writes.jsonl");
    let Ok(text) = fs::read_to_string(&path) else { return Vec::new() };
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("an audit line"))
        .collect()
}

/// A usage mock that always answers `status`.
fn usage_mock(server: &MockServer, status: u16) -> httpmock::Mock<'_> {
    server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        if status == 200 {
            then.status(200).json_body(usage_body());
        } else {
            then.status(status);
        }
    })
}

#[test]
fn ac92_a_permanent_class_needs_login_after_one_post_and_no_retry() {
    let server = MockServer::start();
    let token = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(400).json_body(json!({ "error": "invalid_grant" }));
    });
    let usage = usage_mock(&server, 200);
    let fixture = fixture(&server);
    let doc = auth_doc(USER, ACCT, 1_000, false, "agctl-test-codex-rt-0001");
    owned(&fixture, &doc, "auto");
    let before = fs::read(namespace(&fixture).join("auth.json")).expect("the credential");

    let output = run(&fixture, "ac92-permanent", &["codex", "status", "--account", USER]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(2), "{stdout}");
    assert!(stdout.contains("needs login"), "{stdout}");
    assert_eq!(token.calls(), 1, "a permanent class was retried");
    assert_eq!(usage.calls(), 0, "an expired row was fetched anyway");
    assert_eq!(
        fs::read(namespace(&fixture).join("auth.json")).expect("the credential"),
        before,
        "a permanent refusal rewrote the credential"
    );
    assert_eq!(marker(&fixture).and_then(|m| m["inflight"].as_object().cloned()), None);
}

#[test]
fn ac92_a_pre_send_failure_is_stale_and_the_next_pass_sends_exactly_once() {
    let server = MockServer::start();
    let token = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(200).json_body(grant("agctl-test-codex-rt-0002"));
    });
    let _usage = usage_mock(&server, 200);
    let mut fixture = fixture(&server);
    // A real closed loopback port: `Error::Io(ConnectionRefused)`, which the
    // driver classifies `PreSend` — proven never sent (plan AC92).
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        format!("http://127.0.0.1:{port}{TOKEN_PATH}")
    };
    fixture.set("AGCTL_CODEX_TOKEN_URL", &closed);
    owned(&fixture, &auth_doc(USER, ACCT, 1_000, false, "agctl-test-codex-rt-0001"), "auto");

    let first = run(&fixture, "ac92-presend-1", &["codex", "status", "--account", USER]);
    assert_eq!(first.status.code(), Some(2), "{}", String::from_utf8_lossy(&first.stdout));
    assert_eq!(token.calls(), 0, "the closed port reached the mock");
    assert_eq!(
        marker(&fixture).and_then(|m| m["inflight"].as_object().cloned()),
        None,
        "a proven pre-send failure left the marker behind"
    );

    fixture.set("AGCTL_CODEX_TOKEN_URL", &server.url(TOKEN_PATH));
    let second = run(&fixture, "ac92-presend-2", &["codex", "status", "--account", USER]);

    assert_eq!(second.status.code(), Some(0), "{}", String::from_utf8_lossy(&second.stdout));
    assert_eq!(token.calls(), 1, "the next pass did not send exactly once");
}

#[test]
fn ac117_a_refresh_appends_one_audited_line_that_names_no_identity() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(200).json_body(grant("agctl-test-codex-rt-0002"));
    });
    let _usage = usage_mock(&server, 200);
    let fixture = fixture(&server);
    owned(&fixture, &auth_doc(USER, ACCT, 1_000, false, "agctl-test-codex-rt-0001"), "auto");

    let output = run(&fixture, "ac117-audit", &["codex", "status", "--account", USER]);
    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stdout));

    let lines = audit_lines(&fixture);
    assert_eq!(lines.len(), 1, "one landed write, one audited line: {lines:?}");
    assert_eq!(lines[0]["provider"], "codex");
    let path = fixture.inner().config_dir().join("codex").join("writes.jsonl");
    let text = fs::read_to_string(&path).expect("the log");
    codex::assert_no_needle("ac117-audit", "the write log", text.as_bytes(), &NEEDLES);
    codex::assert_no_needle(
        "ac117-audit",
        "the write log",
        text.as_bytes(),
        &[("an address", "@")],
    );
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(&path).expect("the log").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "the write log is not 0600");
}

#[test]
fn ac117_an_audit_append_that_fails_leaves_the_write_and_says_so() {
    let server = MockServer::start();
    let _token = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(200).json_body(grant("agctl-test-codex-rt-0002"));
    });
    let _usage = usage_mock(&server, 200);
    let fixture = fixture(&server);
    owned(&fixture, &auth_doc(USER, ACCT, 1_000, false, "agctl-test-codex-rt-0001"), "auto");
    // A directory where the log belongs: every append fails, nothing else does.
    let log = fixture.inner().config_dir().join("codex").join("writes.jsonl");
    fs::create_dir_all(&log).expect("a directory in the log's place");

    let output = run(&fixture, "ac117-refused", &["codex", "status", "--account", USER]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("audit log refused"),
        "the row does not say the log refused:\n{stdout}"
    );
    let doc: Value = serde_json::from_slice(
        &run(&fixture, "ac117-refused-json", &["codex", "status", "--account", USER, "--json"])
            .stdout,
    )
    .expect("a v2 document");
    let rotated =
        fs::read_to_string(namespace(&fixture).join("auth.json")).expect("the credential");
    assert!(
        rotated.contains("agctl-test-codex-rt-0002"),
        "the refresh was rolled back when its audit line was refused"
    );
    assert!(doc["rows"].is_array(), "the report still rendered: {doc}");
}

#[test]
fn ac114_the_floor_blocks_the_second_pass_and_at_most_one_post_is_sent() {
    let server = MockServer::start();
    let token = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(200).json_body(grant("agctl-test-codex-rt-0002"));
    });
    let usage = usage_mock(&server, 401);
    let fixture = fixture(&server);
    // `exp` nine days out: the row is not expired, so the POST is reachable
    // only through the 401 post-pass (plan AC114, v6 note).
    owned(
        &fixture,
        &auth_doc(USER, ACCT, now_s() + 9 * 86_400, false, "agctl-test-codex-rt-0001"),
        "auto",
    );

    let first = run(&fixture, "ac114-pass-1", &["codex", "status", "--account", USER]);
    assert_eq!(first.status.code(), Some(2), "{}", String::from_utf8_lossy(&first.stdout));
    assert_eq!(token.calls(), 1, "the 401 post-pass did not send exactly once");
    assert_eq!(usage.calls(), 2, "the retried GET after a sent refresh is missing");
    let after_first = marker(&fixture).expect("a marker");
    assert_eq!(after_first["did_not_help"], 1, "{after_first}");
    assert_eq!(after_first["floor_min"], 120, "{after_first}");

    let second = run(&fixture, "ac114-pass-2", &["codex", "status", "--account", USER]);
    let stdout = String::from_utf8_lossy(&second.stdout);

    assert_eq!(second.status.code(), Some(2), "{stdout}");
    assert!(stdout.contains("refresh floor"), "the row does not name the floor:\n{stdout}");
    assert_eq!(token.calls(), 1, "two passes sent more than one refresh");
    let after_second = marker(&fixture).expect("a marker");
    assert_eq!(after_second["did_not_help"], 1, "a floor-blocked 401 was counted");
}

#[test]
fn ac123_a_server_error_is_an_unknown_outcome_and_the_next_pass_sends_nothing() {
    let server = MockServer::start();
    let token = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(503);
    });
    let _usage = usage_mock(&server, 401);
    let fixture = fixture(&server);
    owned(
        &fixture,
        &auth_doc(USER, ACCT, now_s() + 9 * 86_400, false, "agctl-test-codex-rt-0001"),
        "auto",
    );

    let first = run(&fixture, "ac123-pass-1", &["codex", "status", "--account", USER]);
    let stdout = String::from_utf8_lossy(&first.stdout);
    assert_eq!(first.status.code(), Some(2), "{stdout}");
    assert!(stdout.contains("refresh outcome unknown"), "{stdout}");
    assert_eq!(token.calls(), 1);
    let after = marker(&fixture).expect("a marker");
    assert!(after["inflight"].is_object(), "the send is not recorded: {after}");

    let second = run(&fixture, "ac123-pass-2", &["codex", "status", "--account", USER]);
    let stdout = String::from_utf8_lossy(&second.stdout);

    assert!(stdout.contains("refresh outcome unknown"), "{stdout}");
    assert_eq!(token.calls(), 1, "a grant whose fate is unknown was sent again");
}

#[test]
fn ac128_an_abort_after_the_marker_leaves_the_next_pass_with_no_post() {
    let server = MockServer::start();
    let token = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(200).json_body(grant("agctl-test-codex-rt-0002"));
    });
    let _usage = usage_mock(&server, 200);
    let mut fixture = fixture(&server);
    fixture.set("AGCTL_FAULT", "codex_abort_after_marker");
    owned(&fixture, &auth_doc(USER, ACCT, 1_000, false, "agctl-test-codex-rt-0001"), "auto");

    let aborted = checked(
        "ac128-abort",
        fixture.cmd().args(["codex", "status", "--account", USER]).output().expect("runs"),
    );
    assert_ne!(aborted.status.code(), Some(0), "the abort seam did not stop the process");
    assert_eq!(token.calls(), 0, "the POST went out after the abort point");
    assert!(marker(&fixture).expect("a marker")["inflight"].is_object());

    fixture.set("AGCTL_FAULT", "");
    let next = run(&fixture, "ac128-after-abort", &["codex", "status", "--account", USER]);
    let stdout = String::from_utf8_lossy(&next.stdout);

    assert!(stdout.contains("refresh outcome unknown"), "{stdout}");
    assert_eq!(token.calls(), 0, "a grant with an unknown fate was sent");
}

#[test]
fn ac128_an_unreadable_marker_is_state_unavailable_and_never_unknown() {
    use std::os::unix::fs::PermissionsExt;

    let server = MockServer::start();
    let token = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(200).json_body(grant("agctl-test-codex-rt-0002"));
    });
    let _usage = usage_mock(&server, 200);
    let fixture = fixture(&server);
    owned(&fixture, &auth_doc(USER, ACCT, 1_000, false, "agctl-test-codex-rt-0001"), "auto");
    let path = marker_path(&fixture);
    fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
    fs::write(&path, b"{}").expect("a marker");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).expect("chmod");

    let output = run(&fixture, "ac128-unreadable", &["codex", "status", "--account", USER]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(2), "{stdout}");
    assert!(stdout.contains("refresh state unavailable"), "{stdout}");
    assert!(
        !stdout.contains("refresh outcome unknown"),
        "unavailable was read as unknown:\n{stdout}"
    );
    assert_eq!(token.calls(), 0, "a refresh was sent with no readable marker");
}

#[test]
fn ac93_a_live_codex_daemon_stops_the_refresh_and_names_itself() {
    let server = MockServer::start();
    let token = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(200).json_body(grant("agctl-test-codex-rt-0002"));
    });
    let _usage = usage_mock(&server, 200);
    let fixture = fixture(&server);
    owned(&fixture, &auth_doc(USER, ACCT, 1_000, false, "agctl-test-codex-rt-0001"), "auto");
    // This test process is alive and started well before the record is
    // written, so the evidence is `pid alive` rather than `recycled`.
    let record = namespace(&fixture).join("app-server-daemon").join("app-server.pid");
    write_0600(&record, &serde_json::to_vec(&json!({ "pid": std::process::id() })).expect("bytes"));

    let output = run(&fixture, "ac93-daemon", &["codex", "status", "--account", USER]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(2), "{stdout}");
    assert!(stdout.contains("codex session detected"), "{stdout}");
    assert_eq!(token.calls(), 0, "a refresh was sent while a Codex daemon was alive");
}

/// Runs a pass that stops at `pause`, lets `during` interleave, and resumes.
///
/// The marker is fsynced immediately before the pause point, so its arrival on
/// disk is what says the child is waiting — no sleep decides anything.
fn run_paused(
    fixture: &CodexFixture,
    name: &str,
    args: &[&str],
    pause: &str,
    during: impl FnOnce() + Send,
) -> Output {
    let resume = fixture.inner().config_dir().join("resume");
    let marker = marker_path(fixture);
    let output = std::thread::scope(|scope| {
        scope.spawn(|| {
            let inflight = || {
                fs::read(&marker)
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                    .is_some_and(|state| state["inflight"].is_object())
            };
            let start = std::time::Instant::now();
            while !inflight() && start.elapsed() < std::time::Duration::from_secs(10) {
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            assert!(inflight(), "{name}: the pass never recorded a send");
            during();
            fs::write(&resume, b"go").expect("the resume file is writable");
        });
        fixture
            .cmd()
            .env("AGCTL_FAULT", format!("pause_{pause}"))
            .env("AGCTL_FAULT_RESUME", &resume)
            .args(args)
            .output()
            .expect("the binary runs")
    });
    checked(name, output)
}

/// An external writer rotating the namespace's grant in place, as Codex does.
fn rotate_in_place(fixture: &CodexFixture, exp: i64) {
    let doc = auth_doc(USER, ACCT, exp, false, "agctl-test-codex-rt-0009");
    write_0600(
        &namespace(fixture).join("auth.json"),
        &serde_json::to_vec_pretty(&doc).expect("serializes"),
    );
}

#[test]
fn ac124_a_a_race_at_the_post_snapshot_is_adopted_and_verified_with_one_get() {
    let server = MockServer::start();
    let token = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(400).json_body(json!({ "error": "invalid_grant" }));
    });
    let usage = usage_mock(&server, 200);
    let fixture = fixture(&server);
    owned(&fixture, &auth_doc(USER, ACCT, 1_000, false, "agctl-test-codex-rt-0001"), "auto");

    let output = run_paused(
        &fixture,
        "ac124-a",
        &["codex", "status", "--account", USER, "--json"],
        "codex_after_post_snapshot",
        || rotate_in_place(&fixture, now_s() + 9 * 86_400),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let doc: Value = serde_json::from_str(&stdout).expect("a v2 document");
    let row = &doc["rows"][0];

    assert_eq!(output.status.code(), Some(0), "a verified race is not a failure:\n{stdout}");
    assert_eq!(row["state"], "ok", "{row}");
    assert!(
        row["note"].as_str().is_some_and(|note| note.contains("refresh raced an external writer")),
        "{row}"
    );
    assert_eq!(token.calls(), 1);
    assert_eq!(usage.calls(), 1, "the adopted grant was verified with more than one GET");
    let rotated =
        fs::read_to_string(namespace(&fixture).join("auth.json")).expect("the credential");
    assert!(rotated.contains("agctl-test-codex-rt-0009"), "the external writer's grant was lost");
    assert_eq!(
        marker(&fixture).and_then(|m| m["inflight"].as_object().cloned()),
        None,
        "the marker outlived a definite outcome"
    );
    assert!(
        audit_lines(&fixture).iter().any(|line| line.to_string().contains("adopted_external")),
        "the adoption is not audited: {:?}",
        audit_lines(&fixture)
    );
}

#[test]
fn ac124_a_prime_an_adopted_grant_that_is_rejected_needs_login() {
    let server = MockServer::start();
    let token = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(400).json_body(json!({ "error": "invalid_grant" }));
    });
    let usage = usage_mock(&server, 401);
    let fixture = fixture(&server);
    owned(&fixture, &auth_doc(USER, ACCT, 1_000, false, "agctl-test-codex-rt-0001"), "auto");

    let output = run_paused(
        &fixture,
        "ac124-a-prime",
        &["codex", "status", "--account", USER, "--json"],
        "codex_after_post_snapshot",
        || rotate_in_place(&fixture, now_s() + 9 * 86_400),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let doc: Value = serde_json::from_str(&stdout).expect("a v2 document");

    assert_eq!(output.status.code(), Some(2), "{stdout}");
    assert_eq!(doc["rows"][0]["state"], "adopted_grant_dead", "{}", doc["rows"][0]);
    assert_eq!(token.calls(), 1, "a dead adopted grant was refreshed again");
    assert_eq!(usage.calls(), 1, "the verify GET ran more than once");
}

#[test]
fn f7_account_live_on_a_machine_without_codex_is_an_unmatched_selector() {
    // Deviation D30 drops the live row when the home is absent, so `--account
    // live` then matches nothing. Ruled acceptable for phase 3 (an unmatched
    // selector is the honest answer when there is no live row); this pins the
    // exact wording and exit code so it stays a decision rather than drifting
    // into an accident (review S33-C3a F7).
    let server = MockServer::start();
    let usage = usage_mock(&server, 200);
    let fixture = fixture(&server);
    owned(
        &fixture,
        &auth_doc(USER, ACCT, now_s() + 9 * 86_400, false, "agctl-test-codex-rt-0001"),
        "auto",
    );
    assert!(!fixture.inner().home().join(".codex").exists(), "this machine has no Codex home");

    let output = run(&fixture, "f7-live-absent", &["codex", "status", "--account", "live"]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(1), "a selector that matches nothing is fatal: {stderr}");
    assert!(
        stderr.contains("no Codex account matches `live`"),
        "the message does not name the selector:\n{stderr}"
    );
    assert!(
        stderr.contains(&format!("{USER}/{ACCT}")),
        "the message does not list what it could have matched:\n{stderr}"
    );
    assert_eq!(usage.calls(), 0, "a failed selector still fetched");

    // The same selector against a home that exists resolves to the live row.
    fs::create_dir_all(fixture.inner().home().join(".codex")).expect("a Codex home");
    let output = run(&fixture, "f7-live-present", &["codex", "status", "--account", "live"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(2), "{stdout}");
    assert!(stdout.contains("no credential in this Codex home"), "{stdout}");
}

#[test]
fn ac94_a_torn_credential_file_says_so_and_is_never_refreshed() {
    let server = MockServer::start();
    let usage = usage_mock(&server, 200);
    let token = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(200).json_body(grant("agctl-test-codex-rt-0002"));
    });
    let fixture = fixture(&server);
    // A file caught mid-rewrite: valid UTF-8, not valid JSON.
    write_0600(&live_auth(&fixture), b"{\"tokens\":{\"access_to");
    owned(&fixture, &auth_doc(USER, ACCT, 1_000, false, "agctl-test-codex-rt-0001"), "auto");
    write_0600(&namespace(&fixture).join("auth.json"), b"{\"tokens\":{\"access_to");

    let output = run(&fixture, "ac94-torn", &["codex", "status"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(2), "{stdout}");
    assert!(
        stdout.contains("auth.json was being rewritten"),
        "a torn file must say so, and name the file:\n{stdout}"
    );
    assert!(!stdout.contains("needs login"), "a torn file is never a missing one:\n{stdout}");
    assert_eq!(token.calls(), 0, "a torn file was refreshed");
    assert_eq!(usage.calls(), 0, "a torn file was fetched");
}

#[test]
fn ac95_the_live_home_is_read_from_the_environment_and_only_when_it_is_there() {
    // The `CODEX_HOME`-unset rule through the binary: the live home is
    // `$HOME/.codex`, read when it holds a credential and dropped when the
    // directory is absent (deviation D30). The two `CODEX_HOME`-*set* cases
    // cannot be driven through `codex status`: `--codex-home` exists only on
    // `codex import` (`cli.rs:842`), which is a stub until S34, and the
    // harness refuses to put the variable in a child's environment (AC109,
    // `tests/common/codex.rs:143-151`). Stated in the request.
    let server = MockServer::start();
    let usage = usage_mock(&server, 200);
    let fixture = fixture(&server);

    let absent = run(&fixture, "ac95-unset-absent", &["codex", "status"]);
    assert_eq!(absent.status.code(), Some(0), "no home, no row");
    assert_eq!(usage.calls(), 0);

    let doc = auth_doc(USER, ACCT, now_s() + 86_400, false, "agctl-test-codex-rt-0001");
    write_0600(&live_auth(&fixture), &serde_json::to_vec_pretty(&doc).expect("serializes"));
    assert_eq!(
        live_auth(&fixture).parent().expect("a home"),
        fixture.inner().home().join(".codex"),
        "the live home is `$HOME/.codex`, taken from the environment"
    );

    let present = run(&fixture, "ac95-unset-present", &["codex", "status"]);
    let stdout = String::from_utf8_lossy(&present.stdout);

    assert_eq!(present.status.code(), Some(0), "{stdout}");
    assert!(stdout.contains("live"), "the live row is named `live` when it has no registry id");
    assert_eq!(usage.calls(), 1, "the live home's credential was read and used");
}

#[test]
fn ac113_a_parked_grant_is_replayed_on_the_next_pass_without_a_second_post() {
    let server = MockServer::start();
    let usage = usage_mock(&server, 200);
    let token = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(200).json_body(grant("agctl-test-codex-rt-0002"));
    });
    let mut fixture = fixture(&server);
    owned(&fixture, &auth_doc(USER, ACCT, 1_000, false, "agctl-test-codex-rt-0001"), "auto");

    // The rename that installs the refreshed grant fails, so it is parked.
    fixture.set("AGCTL_FAULT", "codex_rename_fail");
    let parked = run(&fixture, "ac113-park", &["codex", "status", "--account", USER]);
    assert_eq!(token.calls(), 1, "{}", String::from_utf8_lossy(&parked.stdout));
    let ns = namespace(&fixture);
    assert!(ns.join("auth.json.pending").is_file(), "the grant was not parked");
    assert!(ns.join("auth.pending.meta").is_file(), "the pending metadata is missing");

    fixture.set("AGCTL_FAULT", "");
    let replayed = run(&fixture, "ac113-replay", &["codex", "status", "--account", USER]);
    let stdout = String::from_utf8_lossy(&replayed.stdout);

    assert!(
        stdout.contains("pending replayed"),
        "the row does not say the parked grant was replayed:\n{stdout}"
    );
    // Discriminating: the credential under the pending file is expired, so a
    // replay that failed to install would leave the row due and this pass
    // would POST a second time.
    assert_eq!(token.calls(), 1, "the replay sent a second refresh:\n{stdout}");
    assert!(usage.calls() >= 1, "the replayed grant was never used");
    let installed = fs::read_to_string(ns.join("auth.json")).expect("the credential");
    assert!(installed.contains("agctl-test-codex-rt-0002"), "the parked grant was not replayed");
    assert!(!ns.join("auth.json.pending").exists(), "the pending file outlived its replay");
    assert!(!ns.join("auth.pending.meta").exists(), "the pending metadata outlived its replay");
}

#[test]
fn ac113_a_pending_grant_with_no_metadata_is_discarded_and_the_row_stays_due() {
    let server = MockServer::start();
    let _usage = usage_mock(&server, 200);
    let token = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(200).json_body(grant("agctl-test-codex-rt-0003"));
    });
    let fixture = fixture(&server);
    // The credential on disk is **expired**, and the pending grant beside it is
    // not. That is what makes the POST count discriminating rather than free:
    // discarding the pending file leaves the row due, so exactly one refresh
    // goes out; applying it would leave the row fresh and send nothing. The
    // AC113 table's "0 POSTs" belongs to the replay case, which the test above
    // pins; here the honest discriminating claim is the opposite one
    // (review S33-C3b, second test assertion).
    owned(&fixture, &auth_doc(USER, ACCT, 1_000, false, "agctl-test-codex-rt-0001"), "auto");
    let ns = namespace(&fixture);
    write_0600(
        &ns.join("auth.json.pending"),
        &serde_json::to_vec_pretty(&auth_doc(
            USER,
            ACCT,
            now_s() + 9 * 86_400,
            false,
            "agctl-test-codex-rt-0009",
        ))
        .expect("serializes"),
    );

    let output = run(&fixture, "ac113-discard", &["codex", "status", "--account", USER]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("pending discarded"),
        "the row does not say the pending grant was discarded:\n{stdout}"
    );
    assert!(!ns.join("auth.json.pending").exists(), "an invalid pending file was kept:\n{stdout}");
    let installed = fs::read_to_string(ns.join("auth.json")).expect("the credential");
    assert!(
        !installed.contains("agctl-test-codex-rt-0009"),
        "a pending grant with no metadata was applied anyway:\n{installed}"
    );
    assert_eq!(
        token.calls(),
        1,
        "the row was due after the discard, so exactly one refresh should have gone out:\n{stdout}"
    );
    assert!(
        installed.contains("agctl-test-codex-rt-0003"),
        "the refresh that followed the discard did not install its grant:\n{installed}"
    );
}

// ---------------------------------------------------------------------------
// A process that dies mid-write (AC123, AC124 (h))
// ---------------------------------------------------------------------------

/// Spawns the binary with the fixture's own environment, so a test that needs
/// the child's pid keeps every isolation the fixture set up.
///
/// `assert_cmd::Command` does not expose `spawn`, and rebuilding the
/// environment by hand would be the one place a test could quietly reach a
/// real Codex home (AC109). Copying `get_program`/`get_args`/`get_envs` keeps
/// the removals too: `get_envs` yields `None` for a variable the fixture
/// deliberately unset.
fn spawn_with(fixture: &CodexFixture, args: &[&str], env: &[(&str, &str)]) -> std::process::Child {
    let template = fixture.cmd();
    let mut command = std::process::Command::new(template.get_program());
    command.args(template.get_args());
    for (key, value) in template.get_envs() {
        match value {
            Some(value) => command.env(key, value),
            None => command.env_remove(key),
        };
    }
    for (key, value) in env {
        command.env(key, value);
    }
    command
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the binary runs")
}

/// Waits for `marker` to exist, signals the child, and reaps it. Never leaves a child
/// behind: a signal that does not land is followed by a kill.
fn signal_when(
    child: &mut std::process::Child,
    signal: rustix::process::Signal,
    what: &str,
    marker: &Path,
) -> std::process::ExitStatus {
    let start = std::time::Instant::now();
    while !marker.exists() && start.elapsed() < std::time::Duration::from_secs(10) {
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    assert!(
        marker.exists(),
        "{what}: the pass never reached the point this test signals at ({} never appeared)",
        marker.display()
    );
    let pid =
        rustix::process::Pid::from_raw(i32::try_from(child.id()).expect("a pid fits in an i32"))
            .expect("a live pid");
    rustix::process::kill_process(pid, signal).expect("the signal is delivered");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match child.try_wait().expect("the child is waitable") {
            Some(status) => return status,
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{what}: the child ignored the signal");
            }
            None => std::thread::sleep(std::time::Duration::from_millis(5)),
        }
    }
}

/// N-1's twin: a wait that never sees its marker fails with a message that
/// names the marker path (10 s: the helper's only wait). The helper panics
/// before it signals, so the test reaps its own child.
#[test]
fn a_failed_wait_names_the_marker_it_waited_for() {
    let fixture = CodexFixture::new();
    let marker = fixture.root().join("never.reached");
    let mut child = std::process::Command::new("sleep").arg("30").spawn().expect("sleep runs");
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        signal_when(&mut child, rustix::process::Signal::TERM, "n1-twin", &marker);
    }));
    let _ = child.kill();
    let _ = child.wait();
    let report = failed.expect_err("a marker that never appears fails the wait");
    let text = report.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(text.contains(&marker.display().to_string()), "the failure names the marker: {text}");
}

/// The staged `<name>.tmp.<8hex>` files in the owned namespace.
fn staged_tmps(fixture: &CodexFixture) -> Vec<String> {
    let Ok(entries) = fs::read_dir(namespace(fixture)) else { return Vec::new() };
    let mut names: Vec<String> = entries
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains(".tmp."))
        .collect();
    names.sort();
    names
}

/// The fixture both signal tests share: an owned row that is due, a token
/// endpoint that answers, and a pass paused between the fsync and the rename.
fn interrupted_before_rename(
    fixture: &CodexFixture,
    signal: rustix::process::Signal,
    what: &str,
) -> std::process::ExitStatus {
    owned(fixture, &auth_doc(USER, ACCT, 1_000, false, "agctl-test-codex-rt-0001"), "auto");
    // The signal is sent once the pass is AT the pause point, which it
    // announces by creating `<resume>.reached` after the staged file has been
    // written and fsynced. Waiting for the staged file to merely EXIST would
    // race the write: the file is created first and filled after, and a
    // signal in between leaves it empty (bead agctl-u82l). The resume file is
    // never written, so the pass waits at the pause point until the signal.
    let resume = fixture.inner().config_dir().join("resume-before-rename");
    let mut reached = resume.clone().into_os_string();
    reached.push(".reached");
    let reached = PathBuf::from(reached);
    let resume_env = resume.to_string_lossy().into_owned();
    let mut child = spawn_with(
        fixture,
        &["codex", "status", "--account", USER],
        &[("AGCTL_FAULT", "pause_codex_before_rename"), ("AGCTL_FAULT_RESUME", &resume_env)],
    );
    signal_when(&mut child, signal, what, &reached)
}

#[test]
fn ac124_h_sigterm_before_the_rename_keeps_the_grant_and_the_marker() {
    let server = MockServer::start();
    let token = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(200).json_body(grant("agctl-test-codex-rt-0002"));
    });
    let _usage = usage_mock(&server, 200);
    let mut fixture = fixture(&server);

    let status =
        interrupted_before_rename(&fixture, rustix::process::Signal::TERM, "ac124-h-sigterm");

    assert!(!status.success(), "the signal did not end the run: {status:?}");
    assert_eq!(token.calls(), 1, "the refresh had not been sent when the signal arrived");
    // The rotated grant is recoverable: the staged file is NOT registered with
    // the emergency cleanup, so the signal handler leaves it alone (AC124 (h)).
    let staged = staged_tmps(&fixture);
    assert_eq!(staged.len(), 1, "the staged grant was unlinked on the way out: {staged:?}");
    let recovered = fs::read_to_string(namespace(&fixture).join(&staged[0])).expect("the tmp");
    assert!(recovered.contains("agctl-test-codex-rt-0002"), "the staged file lost the new grant");
    // …and the credential itself still holds the grant that was sent, so
    // nothing was half-installed.
    let installed = fs::read_to_string(namespace(&fixture).join("auth.json")).expect("auth.json");
    assert!(installed.contains("agctl-test-codex-rt-0001"), "the credential was rewritten anyway");
    assert!(
        marker(&fixture).expect("a marker")["inflight"].is_object(),
        "the marker was cleared by a process that never learned the outcome"
    );

    // The next pass classifies the interruption and sends nothing (AC123, R70).
    fixture.set("AGCTL_FAULT", "");
    let next = run(&fixture, "ac124-h-next", &["codex", "status", "--account", USER]);
    let stdout = String::from_utf8_lossy(&next.stdout);

    assert!(stdout.contains("refresh outcome unknown"), "{stdout}");
    assert_eq!(token.calls(), 1, "the next pass re-sent a grant whose fate is unknown");
}

#[test]
fn ac123_sigint_before_the_rename_leaves_an_interrupted_outcome() {
    let server = MockServer::start();
    let token = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(200).json_body(grant("agctl-test-codex-rt-0002"));
    });
    let _usage = usage_mock(&server, 200);
    let mut fixture = fixture(&server);

    let status = interrupted_before_rename(&fixture, rustix::process::Signal::INT, "ac123-sigint");

    assert!(!status.success(), "the signal did not end the run: {status:?}");
    assert_eq!(staged_tmps(&fixture).len(), 1, "Ctrl-C unlinked the only copy of the new grant");
    assert!(marker(&fixture).expect("a marker")["inflight"].is_object());

    fixture.set("AGCTL_FAULT", "");
    let next = run(&fixture, "ac123-sigint-next", &["codex", "status", "--account", USER]);
    let stdout = String::from_utf8_lossy(&next.stdout);

    // Nothing in-process classifies a send after a signal, so the *next* pass
    // is what calls it interrupted — and it must not send again.
    assert!(stdout.contains("refresh outcome unknown"), "{stdout}");
    assert_eq!(token.calls(), 1, "a grant whose fate is unknown was sent again");
}
