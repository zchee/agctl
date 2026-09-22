//! The Codex watch session: its passes read, serve the cache on schedule, go
//! to the wire on `r`, and never reach the token endpoint.

use std::fs;
use std::time::Duration;

use httpmock::Method::GET;
use httpmock::Method::POST;
use httpmock::MockServer;
use jiff::Timestamp;
use serde_json::json;

use super::*;
use crate::commands::codex::pass;
use crate::provider::codex::account::CodexState;
use crate::provider::codex::testkit;

fn usage_body() -> serde_json::Value {
    json!({
        "plan_type": "pro",
        "rate_limit": {
            "primary_window": { "used_percent": 7.0, "limit_window_seconds": 18_000, "reset_after_seconds": 60 },
        },
    })
}

/// A store whose registry holds one owned account with `exp`, and a live home
/// (`$HOME/.codex` under the test's tree) with a fresh credential.
fn session(server: &MockServer, exp: i64) -> (tempfile::TempDir, Session) {
    let (dir, paths) = testkit::store();
    let record = testkit::owned_record(testkit::USER, testkit::ACCT);
    let ns = paths.codex_namespace_dir(testkit::USER, testkit::ACCT).expect("valid ids");
    testkit::write_0600(
        &ns.join("auth.json"),
        &testkit::pretty(&testkit::chatgpt_doc(Some(exp), None)),
    );
    let registry = json!({
        "version": 2,
        "accounts": [],
        "forgotten_services": [],
        "codex_accounts": [serde_json::to_value(&record).expect("a record serializes")],
    });
    fs::write(paths.config_file(), serde_json::to_vec(&registry).expect("serializes"))
        .expect("a registry");

    let home = dir.path().join("home");
    testkit::write_0600(&home.join(".codex").join("auth.json"), &testkit::fresh_auth_bytes());
    let base = server.base_url();
    let session = Session::new(
        Arc::new(paths),
        CodexEnv::new(None, Some(home)),
        Arc::new(move || UsageClient::new(&base, "agctl/test", Duration::from_secs(5))),
    );
    (dir, session)
}

#[test]
fn a_scheduled_pass_serves_the_cache_and_r_goes_to_the_wire() {
    let server = MockServer::start();
    let usage = server.mock(|when, then| {
        when.method(GET).path("/backend-api/wham/usage");
        then.status(200).json_body(usage_body());
    });
    let (_dir, session) = session(&server, Timestamp::now().as_second() + 86_400);
    let deadline = Instant::now() + Duration::from_secs(30);
    let cancel = Cancel::new();

    let first = session.run(false, &cancel, deadline).expect("rows");
    assert_eq!(first.len(), 2, "the live home and the owned namespace: {first:?}");
    assert!(first.iter().all(|row| row.state == CodexState::Ok), "{first:?}");
    // Both rows name the same account, so each display id carries the account.
    assert!(first.iter().all(|row| row.id.contains('/')), "{first:?}");
    assert_eq!(usage.calls(), 2);

    let scheduled = session.rows(&PassCtx::standalone(cancel.clone(), deadline)).expect("rows");
    assert_eq!(scheduled.len(), 2);
    assert_eq!(usage.calls(), 2, "a scheduled pass is served from the cache");

    session.run(true, &cancel, deadline).expect("rows");
    assert_eq!(usage.calls(), 4, "`r` bypasses the cache");
}

#[test]
fn u44_a_watch_pass_never_reaches_the_token_endpoint_for_a_due_owned_row() {
    let server = MockServer::start();
    let token = server.mock(|when, then| {
        when.method(POST);
        then.status(200).json_body(json!({}));
    });
    let _usage = server.mock(|when, then| {
        when.method(GET).path("/backend-api/wham/usage");
        then.status(200).json_body(usage_body());
    });
    let (_dir, session) = session(&server, 1_000);

    let rows =
        session.run(true, &Cancel::new(), Instant::now() + Duration::from_secs(30)).expect("rows");

    let owned = rows.iter().find(|row| row.kind.name() == "owned").expect("the owned row");
    assert_eq!(
        owned.state,
        CodexState::Expired { reason: pass::EXPIRED_IN_WATCH.to_owned() },
        "{owned:?}"
    );
    assert_eq!(token.calls(), 0, "watch sent a POST");
}

#[test]
fn an_unreadable_registry_keeps_the_numbers_on_screen() {
    let server = MockServer::start();
    let (_dir, session) = session(&server, Timestamp::now().as_second() + 86_400);
    fs::write(session.paths.config_file(), b"{ not json").expect("a corrupt registry");

    let rows = session.run(false, &Cancel::new(), Instant::now() + Duration::from_secs(5));

    assert!(rows.is_none(), "a registry that cannot be read says nothing about the accounts");
}
