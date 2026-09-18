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

/// The needles no output of a pass may carry (plan section 9.4).
const NEEDLES: [&str; 8] = [
    "agctl-test-codex-at-",
    "agctl-test-codex-rt-",
    "agctl-test-codex-ak-",
    "agctl-test-codex-jwt-",
    "agctl-test-codex-email-",
    "eyJ",
    "Bearer ",
    "bearer ",
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
    let output = fixture.cmd().args(args).output().expect("the binary runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    for needle in NEEDLES {
        assert!(!stdout.contains(needle), "{name}: stdout carries `{needle}`:\n{stdout}");
        assert!(!stderr.contains(needle), "{name}: stderr carries `{needle}`:\n{stderr}");
    }
    if let Some(dir) = std::env::var_os("AGCTL_E2E_TRACE_DIR") {
        let path = PathBuf::from(dir).join(format!("e2e_codex_status-{name}.stderr"));
        fs::write(&path, &output.stderr).expect("the trace directory is writable");
    }
    output
}

#[test]
fn ac102_status_json_validates_against_v2_and_carries_no_needle() {
    let server = MockServer::start();
    let usage = server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(200).json_body(usage_body());
    });
    let fixture = fixture(&server);
    let doc = auth_doc(USER, ACCT, now_s() + 86_400, false, "agctl-test-codex-rt-0001");
    write_0600(&live_auth(&fixture), &serde_json::to_vec_pretty(&doc).expect("serializes"));
    owned(&fixture, &doc, "auto");

    let output = run(&fixture, "json", &["codex", "status", "--json"]);

    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));
    let document: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON");
    let schema: Value = serde_json::from_str(SCHEMA_V2).expect("the schema is JSON");
    let validator = jsonschema::validator_for(&schema).expect("the schema compiles");
    let errors: Vec<String> = validator.iter_errors(&document).map(|err| err.to_string()).collect();
    assert!(errors.is_empty(), "{errors:?}\n{document:#}");
    let rows = document["rows"].as_array().expect("rows");
    assert_eq!(rows.len(), 2, "{document:#}");
    for row in rows {
        assert_eq!(row["provider"], "codex");
        assert_eq!(row["identity"]["user_id"], USER);
        assert_eq!(row["identity"]["account_id"], ACCT);
        assert_eq!(row["identity"]["plan_type"], "pro");
        assert_eq!(row["state"], "ok");
        assert_eq!(row["id"], format!("{USER}/{ACCT}"), "two rows share the user id (D-039)");
    }
    assert_eq!(usage.calls(), 2);
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
    let fixture = fixture(&server);
    let config = fixture.inner().config_dir();
    assert!(!config.join("claude").exists());

    let output = run(&fixture, "empty", &["codex", "status"]);

    assert_eq!(
        output.status.code(),
        Some(2),
        "a machine without a Codex login shows the live row as `needs login`: {}",
        String::from_utf8_lossy(&output.stdout)
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
