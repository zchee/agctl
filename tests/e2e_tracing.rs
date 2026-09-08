#![cfg(feature = "testing")]

//! Plan section 9.4 and invariants I4 and P2: **no token material ever leaves
//! the process except to Anthropic.**
//!
//! The plan's own verification step is to run the suite under
//! `RUST_LOG=agentctl=trace` and grep the log for `sk-ant-`. Run that way from
//! the outside it proves less than it looks like it does: every command the
//! end-to-end harness starts has its standard error read through a pipe, so
//! the binary's trace stream never reaches the file being grepped.
//!
//! So the grep happens here instead, against the streams that actually carry
//! it. Each test drives a whole code path — discovery, a refresh POST, a usage
//! GET, a login exchange — with tracing turned all the way up, and asserts on
//! the bytes the process wrote to standard output and standard error. The
//! marker assertions are there so a subscriber that silently failed to install
//! cannot make this pass by printing nothing at all.

mod common;

use std::fs;
use std::process::Command as StdCommand;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use common::ACCT;
use common::EMAIL;
use common::Fixture;
use common::LIVE_SERVICE;
use common::ORG;
use common::USAGE_BODY;
use common::USAGE_PATH;
use httpmock::Method::GET;
use httpmock::Method::POST;
use httpmock::MockServer;
use serde_json::json;

/// The token prefixes and header shapes that must never be printed.
const FORBIDDEN: [&str; 4] =
    ["sk-ant-oat01-", "sk-ant-ort01-", "Authorization: Bearer", "authorization: bearer"];

/// Asserts that neither stream carries anything that looks like a credential.
#[track_caller]
fn assert_no_token_material(what: &str, stdout: &str, stderr: &str) {
    for needle in FORBIDDEN {
        assert!(
            !stdout.contains(needle),
            "{what}: `{needle}` reached standard output\n--- stdout ---\n{stdout}"
        );
        assert!(
            !stderr.contains(needle),
            "{what}: `{needle}` reached standard error\n--- stderr ---\n{stderr}"
        );
    }
}

#[test]
fn the_harness_drains_a_child_that_fills_its_standard_error_pipe() {
    // Turning the trace level up is what makes this file's other tests
    // interesting, and it is also what makes agentctl write far more to
    // standard error than a pipe holds — about 64 KiB. A harness that read the
    // two streams in turn would sit on standard output forever while the child
    // sat on a full standard error, so this pins the property `common::finish`
    // has to have, with a child that reproduces the shape exactly: fill
    // standard error first, write standard output only afterwards.
    let child = StdCommand::new("/bin/sh")
        .arg("-c")
        .arg("head -c 200000 /dev/zero | tr '\\0' 'e' >&2; echo done")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("`/bin/sh` should be runnable");

    // A regression here would deadlock rather than fail, and a hung test says
    // much less than a failed one. Killing the child unblocks both pipes, so
    // `finish` returns and the assertions below report what went wrong.
    let pid = child.id();
    let finished_in_time = Arc::new(AtomicBool::new(false));
    let watchdog = {
        let finished_in_time = Arc::clone(&finished_in_time);
        std::thread::spawn(move || {
            let start = Instant::now();
            while !finished_in_time.load(Ordering::SeqCst) {
                if start.elapsed() >= Duration::from_secs(10) {
                    let _ = StdCommand::new("/bin/kill").args(["-KILL", &pid.to_string()]).status();
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        })
    };

    let finished = common::finish(child);
    finished_in_time.store(true, Ordering::SeqCst);
    let _ = watchdog.join();

    assert_eq!(finished.code(), 0, "the child should have exited on its own, not been killed");
    assert_eq!(
        finished.stderr.len(),
        200_000,
        "the whole of standard error should be read back, not the first pipe-full"
    );
    assert_eq!(finished.stdout.trim(), "done", "and standard output should be complete too");
}

#[test]
fn section_9_4_a_traced_refresh_and_fetch_print_no_token_material() {
    // The path with the most opportunities to leak: a keychain read, a
    // credential parsed off disk, a refresh POST carrying a refresh token in
    // its body, and a usage GET carrying an access token in its header.
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(200).body(USAGE_BODY);
    });
    server.mock(|when, then| {
        when.method(POST).path(common::TOKEN_PATH);
        then.status(200).json_body(json!({
            "access_token": "sk-ant-oat01-rotated",
            "refresh_token": "sk-ant-ort01-rotated",
            "token_type": "Bearer",
            "expires_in": 28_800,
            "scope": "user:inference user:profile",
        }));
    });

    let mut fixture = Fixture::new();
    fixture.with_keychain().endpoints(&server.base_url());
    fixture.set("RUST_LOG", "agentctl=trace");
    fixture.dump(&[LIVE_SERVICE]);
    fixture.keychain_item(
        LIVE_SERVICE,
        &common::blob("sk-ant-oat01-live", "sk-ant-ort01-live", common::fresh_at()),
    );
    fixture.write_registry(vec![fixture.owned_record(ACCT, ORG)]);
    fixture.write_credentials(
        ACCT,
        ORG,
        &common::blob("sk-ant-oat01-stale", "sk-ant-ort01-stale", common::expired_at()),
    );

    let child = fixture
        .raw()
        .args(["claude", "status", "--refresh", "--all", "--json", "--raw"])
        .spawn()
        .expect("agentctl should start");
    let finished = common::finish(child);

    assert!(
        finished.stderr.contains("discovery finished"),
        "the trace subscriber should have been installed and talking:\n{}",
        finished.stderr
    );
    assert!(
        finished.stderr.contains("lock_state"),
        "and the per-account span should have been recorded:\n{}",
        finished.stderr
    );
    assert_no_token_material("status --refresh --json --raw", &finished.stdout, &finished.stderr);

    // The rotated token really did land on disk, so the assertion above is
    // about redaction rather than about a refresh that never happened.
    let stored = fs::read_to_string(fixture.credentials_path(ACCT, ORG)).expect("readable");
    assert!(stored.contains("sk-ant-oat01-rotated"), "the refresh did happen");
    fixture.assert_keychain_read_only();
}

#[test]
fn section_9_4_a_traced_login_prints_no_token_material() {
    // A login is the other place a token exists in memory: it arrives in an
    // exchange response and is written straight out. The authorize URL it
    // prints carries a PKCE challenge, which is a hash — but the verifier
    // behind it is a secret, and must not appear either.
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path(common::TOKEN_PATH);
        then.status(200).json_body(json!({
            "token_type": "Bearer",
            "access_token": "sk-ant-oat01-minted",
            "refresh_token": "sk-ant-ort01-minted",
            "expires_in": 28_800,
            "scope": "user:inference user:profile",
            "account": { "uuid": ACCT, "email_address": EMAIL },
            "organization": { "uuid": ORG, "name": "Acme" },
        }));
    });

    let mut fixture = Fixture::new();
    fixture.endpoints(&server.base_url());
    fixture.set("RUST_LOG", "agentctl=trace");

    let mut session = common::start_login(&fixture, &[], &[]);
    let state = session.state.clone();
    session.paste(&format!("minted-code#{state}"));
    let finished = session.finish();

    assert_eq!(finished.code(), 0, "stderr:\n{}", finished.stderr);
    assert_no_token_material("login --manual", &finished.stdout, &finished.stderr);
    assert!(
        !finished.stdout.contains("code_verifier") && !finished.stderr.contains("code_verifier"),
        "the PKCE verifier is a secret and never printed"
    );

    let stored =
        fs::read_to_string(fixture.ns_dir(ACCT, ORG).join(".credentials.json")).expect("readable");
    assert!(stored.contains("sk-ant-oat01-minted"), "the login did store a token");
}

#[test]
fn section_9_4_a_traced_failure_path_prints_no_token_material() {
    // Failure paths are where redaction usually goes wrong: an error carries
    // a body, a body carries a token, and the error is logged. Here the token
    // endpoint rejects the grant and the usage endpoint answers 401, so both
    // error renderings run.
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(401).body("{\"error\":\"unauthorized\"}");
    });
    server.mock(|when, then| {
        when.method(POST).path(common::TOKEN_PATH);
        then.status(400).json_body(json!({
            "error": "invalid_grant",
            "error_description": "refresh token sk-ant-ort01-echoed is not valid",
        }));
    });

    let mut fixture = Fixture::new();
    fixture.endpoints(&server.base_url());
    fixture.set("RUST_LOG", "agentctl=trace");
    fixture.write_registry(vec![fixture.owned_record(ACCT, ORG)]);
    fixture.write_credentials(
        ACCT,
        ORG,
        &common::blob("sk-ant-oat01-stale", "sk-ant-ort01-stale", common::expired_at()),
    );

    let child = fixture
        .raw()
        .args(["claude", "status", "--refresh", "--account", EMAIL])
        .spawn()
        .expect("agentctl should start");
    let finished = common::finish(child);

    assert_eq!(finished.code(), 2);
    assert!(finished.stdout.contains("needs login"), "stdout:\n{}", finished.stdout);
    // The server echoed a token-shaped string back in its error description.
    // Whatever the client does with that body, it must not print it.
    assert_no_token_material("a rejected refresh", &finished.stdout, &finished.stderr);
}
