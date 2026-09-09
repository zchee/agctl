#![cfg(feature = "testing")]

//! The refresh path through the real binary: the lock, the pending table, and
//! what a signal does to a namespace mid-write.
//!
//! These are the tests that need more than one process. Plan AC7 asks whether
//! two `agentctl` processes racing on one account make exactly one refresh
//! POST, and AC27 asks whether the lock a killed process held is available to
//! the next one — neither of which an in-process test can answer, because both
//! are questions about the kernel rather than about this program's data
//! structures. So the binary is started with `std::process::Command`, the test
//! interleaves with it while it runs, and the assertions are about hit counts
//! on a socket, `flock` from a genuinely different process, and directory
//! entries.

mod common;

use std::fs;
use std::path::PathBuf;
use std::process::Child;
use std::time::Duration;

use common::ACCT;
use common::EMAIL;
use common::Fixture;
use common::LIVE_SERVICE;
use common::ORG;
use common::USAGE_BODY;
use common::USAGE_PATH;
use httpmock::Method::GET;
use httpmock::Method::POST;
use httpmock::Mock;
use httpmock::MockServer;
use serde_json::Value;
use serde_json::json;

/// How long a test will wait for a child to reach an observable point before
/// deciding it never will.
const OBSERVE_BUDGET: Duration = Duration::from_secs(20);

fn usage_ok(server: &MockServer) -> Mock<'_> {
    server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(200).body(USAGE_BODY);
    })
}

/// The refresh mock, answering with a token that lasts `expires_in` seconds.
fn token_ok(server: &MockServer, expires_in: i64) -> Mock<'_> {
    server.mock(|when, then| {
        when.method(POST).path(common::TOKEN_PATH);
        then.status(200).json_body(json!({
            "access_token": "sk-ant-oat01-rotated",
            "refresh_token": "sk-ant-ort01-rotated",
            "token_type": "Bearer",
            "expires_in": expires_in,
            "refresh_token_expires_in": 2_377_445,
            "scope": "user:inference user:profile",
        }));
    })
}

/// A store holding one owned account whose access token has expired.
fn expired_owned(server: &MockServer) -> Fixture {
    let mut fixture = Fixture::new();
    fixture.endpoints(&server.base_url());
    fixture.write_registry(vec![fixture.owned_record(ACCT, ORG)]);
    fixture.write_credentials(
        ACCT,
        ORG,
        &common::blob("sk-ant-oat01-stale", "sk-ant-ort01-stale", common::expired_at()),
    );
    fixture
}

/// Kills a child and reaps it, for the process a test deliberately abandons.
fn kill(mut child: Child) {
    let _ = child.kill();
    let _ = common::finish(child);
}

/// The single row of a `status --json` document.
fn only_row(stdout: &str) -> Value {
    let document: Value = serde_json::from_str(stdout)
        .unwrap_or_else(|err| panic!("stdout should be one JSON document: {err}\n{stdout}"));
    document["rows"]
        .as_array()
        .and_then(|rows| rows.first())
        .cloned()
        .unwrap_or_else(|| panic!("the document should carry one row:\n{stdout}"))
}

/// The `owned` row of a `status --json` document.
///
/// A migrated namespace's keychain item is not a *claimed* service — only the
/// live item and an imported configuration directory's are — so discovery also
/// emits an `unclaimed` row for the same item, and `--account` matches it too
/// because the blob names the same address. The row under test is the one the
/// registry owns.
fn owned_row(stdout: &str) -> Value {
    let document: Value = serde_json::from_str(stdout)
        .unwrap_or_else(|err| panic!("stdout should be one JSON document: {err}\n{stdout}"));
    document["rows"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["kind"] == json!("owned")))
        .cloned()
        .unwrap_or_else(|| panic!("the document should carry an owned row:\n{stdout}"))
}

// ---------------------------------------------------------------------------
// AC7 — two processes, one refresh
// ---------------------------------------------------------------------------

#[test]
fn ac7_two_concurrent_refreshes_make_exactly_one_post() {
    // Plan AC7, invariant I3: the loser of the race waits, re-reads, and adopts
    // the winner's result rather than minting a second one. Two refreshes of
    // one chain is the failure mode the whole lock exists to prevent (risk R1).
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = server.mock(|when, then| {
        when.method(POST).path(common::TOKEN_PATH);
        then.status(200).delay(Duration::from_millis(1500)).json_body(json!({
            "access_token": "sk-ant-oat01-rotated",
            "refresh_token": "sk-ant-ort01-rotated",
            "token_type": "Bearer",
            "expires_in": 28_800,
            "scope": "user:inference user:profile",
        }));
    });

    let fixture = expired_owned(&server);
    let lock = fixture.lock_path(ACCT, ORG);

    let first = fixture
        .raw()
        .args(["claude", "status", "--refresh", "--account", EMAIL])
        .spawn()
        .expect("the first agentctl should start");
    assert!(
        common::wait_until(OBSERVE_BUDGET, || common::lock_is_held(&lock)),
        "the first process should have taken the namespace lock"
    );

    let second = fixture
        .raw()
        .args(["claude", "status", "--json", "--refresh", "--account", EMAIL])
        .spawn()
        .expect("the second agentctl should start");

    let first = common::finish(first);
    let second = common::finish(second);

    assert_eq!(first.code(), 0, "the winner refreshed and fetched\n{}", first.stderr);
    assert_eq!(second.code(), 0, "the loser adopted the winner's result\n{}", second.stderr);
    assert_eq!(token.calls(), 1, "exactly one refresh POST across both processes");
    assert_eq!(usage.calls(), 2, "both processes still answered the user's question");

    let row = only_row(&second.stdout);
    assert_eq!(row["lock_state"], json!("adopted"), "the loser says what it did: {row}");
    assert_eq!(row["state"], json!("ok"));
}

#[test]
fn ac7_a_lock_held_past_the_deadline_makes_the_second_process_busy() {
    // The other half of plan AC7. `hold_lock` keeps the first process on the
    // lock past the second's deadline, so the second cannot adopt anything —
    // and says `busy` rather than refreshing without the lock.
    let server = MockServer::start();
    let _usage = usage_ok(&server);
    let token = token_ok(&server, 28_800);

    let fixture = expired_owned(&server);
    let lock = fixture.lock_path(ACCT, ORG);

    let holder = fixture
        .raw()
        .args(["claude", "status", "--refresh", "--timeout", "30s", "--account", EMAIL])
        .env("AGENTCTL_FAULT", "hold_lock")
        .spawn()
        .expect("the holding agentctl should start");
    assert!(
        common::wait_until(OBSERVE_BUDGET, || common::lock_is_held(&lock)),
        "the first process should have taken the namespace lock"
    );

    let blocked = fixture
        .raw()
        .args(["claude", "status", "--json", "--refresh", "--timeout", "1s", "--account", EMAIL])
        .spawn()
        .expect("the blocked agentctl should start");
    let blocked = common::finish(blocked);

    assert_eq!(blocked.code(), 2, "a row that could not be read is a degraded row");
    let row = only_row(&blocked.stdout);
    assert_eq!(row["lock_state"], json!("busy"), "{row}");
    assert_eq!(row["state"], json!("busy"), "{row}");
    assert_eq!(token.calls(), 0, "the blocked process never refreshed without the lock");

    kill(holder);
}

// ---------------------------------------------------------------------------
// AC21 — a Claude Code session in the namespace
// ---------------------------------------------------------------------------

#[test]
fn ac21_a_claude_lock_in_the_namespace_refuses_the_refresh() {
    // Plan AC21, invariant I11: agentctl detects Claude Code's lock artefacts
    // and refuses. It never takes them, never removes them, and never writes
    // into a namespace that has one.
    for artefact in [".oauth_refresh.lock", ".storage-write"] {
        let server = MockServer::start();
        let usage = usage_ok(&server);
        let token = token_ok(&server, 28_800);

        let fixture = expired_owned(&server);
        let path = fixture.ns_dir(ACCT, ORG).join(artefact);
        fs::write(&path, "{}").expect("the artefact should be writable");
        let before = fs::read(fixture.credentials_path(ACCT, ORG)).expect("readable");

        let assert = fixture
            .cmd()
            .args(["claude", "status", "--refresh", "--account", EMAIL])
            .assert()
            .code(2);
        let stdout =
            String::from_utf8(assert.get_output().stdout.clone()).expect("stdout is UTF-8");
        assert!(
            stdout.contains("claude session detected"),
            "`{artefact}` should have been detected:\n{stdout}"
        );

        assert_eq!(token.calls(), 0, "`{artefact}`: no refresh");
        assert_eq!(
            usage.calls(),
            0,
            "`{artefact}`: an expired credential agentctl may not refresh is not spent on a \
             fetch either"
        );
        assert!(path.exists(), "`{artefact}`: agentctl never removes a foreign lock");
        assert_eq!(
            fs::read(fixture.credentials_path(ACCT, ORG)).expect("readable"),
            before,
            "`{artefact}`: the credential file was not touched"
        );
    }
}

#[test]
fn ac21_a_session_appearing_after_the_post_discards_the_refresh() {
    // Plan AC21's third clause, the one the fault switch exists for: the POST
    // has returned and the new credentials are in memory when a Claude Code
    // session takes the namespace over. The window is microseconds wide in
    // production; `pause_before_rename` holds it open so a test can step into
    // it. Nothing may be written, and no pending file may be left holding the
    // token that was discarded.
    let server = MockServer::start();
    let _usage = usage_ok(&server);
    let token = token_ok(&server, 28_800);

    let fixture = expired_owned(&server);
    let resume = fixture.scratch("resume");
    let path = fixture.credentials_path(ACCT, ORG);
    let before = fs::read(&path).expect("the credential file should be readable");

    let child = fixture
        .raw()
        .args(["claude", "status", "--refresh", "--account", EMAIL])
        .env("AGENTCTL_FAULT", "pause_before_rename")
        .env("AGENTCTL_FAULT_RESUME", &resume)
        .spawn()
        .expect("agentctl should start");

    assert!(
        common::wait_until(OBSERVE_BUDGET, || token.calls() == 1),
        "the refresh POST should have gone out before the pause"
    );
    // The session arrives while the new credentials are in flight.
    fs::write(fixture.ns_dir(ACCT, ORG).join(".oauth_refresh.lock"), "{}")
        .expect("the artefact should be writable");
    fs::write(&resume, "go").expect("the resume file should be writable");

    let finished = common::finish(child);
    assert_eq!(finished.code(), 2, "stderr:\n{}", finished.stderr);
    assert!(
        finished.stdout.contains("refresh discarded: namespace changed during refresh"),
        "stdout:\n{}",
        finished.stdout
    );

    assert_eq!(fs::read(&path).expect("readable"), before, "the credential file is untouched");
    let mut entries = fixture.namespace_entries(ACCT, ORG);
    entries.sort();
    assert_eq!(
        entries,
        vec![".credentials.json".to_owned(), ".oauth_refresh.lock".to_owned()],
        "no temporary file and no pending file were left behind"
    );
}

// ---------------------------------------------------------------------------
// AC27 — a signal during a held lock
// ---------------------------------------------------------------------------

#[test]
fn ac27_sigterm_during_a_held_refresh_exits_143_and_releases_the_lock() {
    // Plan AC27, design L3: the namespace lock is an `flock` on a file that is
    // never unlinked, so the kernel releases it when the holder dies. Nothing
    // has to be cleaned up for the next process to proceed — which is the
    // property that makes premortem PM6 ("stuck at `refresh skipped` forever")
    // unreachable.
    let server = MockServer::start();
    let _usage = usage_ok(&server);
    let _token = token_ok(&server, 28_800);

    let fixture = expired_owned(&server);
    let lock = fixture.lock_path(ACCT, ORG);

    let child = fixture
        .raw()
        .args(["claude", "status", "--refresh", "--timeout", "60s", "--account", EMAIL])
        .env("AGENTCTL_FAULT", "hold_lock")
        .spawn()
        .expect("agentctl should start");
    let pid = child.id();
    assert!(
        common::wait_until(OBSERVE_BUDGET, || common::lock_is_held(&lock)),
        "agentctl should have taken the namespace lock"
    );

    common::send_sigterm(pid);
    let finished = common::finish(child);

    assert_eq!(finished.code(), 143, "128 + SIGTERM, from the handler thread");
    assert!(
        common::wait_until(Duration::from_secs(2), || !common::lock_is_held(&lock)),
        "the kernel should have released the lock when the holder died"
    );
    let guard = common::hold_lock(&lock);
    drop(guard);
    assert_eq!(
        fixture.namespace_entries(ACCT, ORG),
        vec![".credentials.json".to_owned()],
        "nothing was staged, so nothing was left"
    );
}

// ---------------------------------------------------------------------------
// AC33 — the pending decision table
// ---------------------------------------------------------------------------

/// Runs one pass with a failing `rename`, leaving a pending write behind.
///
/// This is how plan section 3.6's failure path is reached from outside: the
/// POST succeeds, the file cannot be replaced, and the new credentials are
/// parked as `.credentials.json.pending` beside a `.pending.meta` recording
/// what they were derived from.
fn stage_pending(fixture: &Fixture) {
    fixture
        .cmd()
        .args(["claude", "status", "--refresh", "--account", EMAIL])
        .env("AGENTCTL_FAULT", "rename_fail")
        .assert()
        .code(2)
        .stdout(predicates::str::contains("refresh saved to pending"));
    let entries = fixture.namespace_entries(ACCT, ORG);
    assert!(
        entries.iter().any(|name| name == ".credentials.json.pending")
            && entries.iter().any(|name| name == ".pending.meta"),
        "the pending write should have been staged: {entries:?}"
    );
}

/// Writes a `.pending.meta` by hand, for the two vectors no command produces.
fn write_meta(fixture: &Fixture, derived_from: Option<(&str, &str)>, new_expires_at: i64) {
    let (access, refresh) = match derived_from {
        Some((access, refresh)) => (json!(access), json!(refresh)),
        None => (Value::Null, Value::Null),
    };
    let document = json!({
        "derived_from_access_sha256": access,
        "derived_from_refresh_sha256": refresh,
        "created_at": "2026-09-08T00:00:00Z",
        "new_expires_at": new_expires_at,
    });
    fs::write(fixture.ns_dir(ACCT, ORG).join(".pending.meta"), document.to_string())
        .expect("the pending metadata should be writable");
}

#[test]
fn ac33a_an_unchanged_file_replays_its_pending_without_a_post() {
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = token_ok(&server, 28_800);
    let fixture = expired_owned(&server);
    stage_pending(&fixture);
    assert_eq!(token.calls(), 1);

    fixture
        .cmd()
        .args(["claude", "status", "--refresh", "--account", EMAIL])
        .assert()
        .success()
        .stdout(predicates::str::contains("pending replayed"));

    assert_eq!(token.calls(), 1, "the replayed credentials were good; no second refresh");
    assert!(usage.calls() >= 2);
    assert_eq!(
        fixture.namespace_entries(ACCT, ORG),
        vec![".credentials.json".to_owned()],
        "the pending pair is gone"
    );
    let stored = fs::read_to_string(fixture.credentials_path(ACCT, ORG)).expect("readable");
    assert!(stored.contains("sk-ant-oat01-rotated"), "the replay moved the new token into place");
}

#[test]
fn ac33b_a_changed_file_discards_its_pending_and_refreshes_again() {
    let server = MockServer::start();
    let _usage = usage_ok(&server);
    let token = token_ok(&server, 28_800);
    let fixture = expired_owned(&server);
    stage_pending(&fixture);

    // Somebody else replaced the credential while the pending write waited.
    // Replaying over it would resurrect a token that account no longer uses.
    fixture.write_credentials(
        ACCT,
        ORG,
        &common::blob("sk-ant-oat01-other", "sk-ant-ort01-other", common::expired_at()),
    );

    fixture
        .cmd()
        .args(["claude", "status", "--refresh", "--account", EMAIL])
        .assert()
        .code(2)
        .stdout(predicates::str::contains("pending discarded: file changed"));

    assert_eq!(token.calls(), 2, "the file that is actually there was refreshed instead");
    assert_eq!(fixture.namespace_entries(ACCT, ORG), vec![".credentials.json".to_owned()]);
}

#[test]
fn ac33c_a_pending_past_its_expiry_is_replayed_and_then_refreshed() {
    // The decision table replays on digests alone, deliberately: an expired
    // replay is still the newest thing the account has, and the refresh path
    // immediately after is what makes it usable.
    let server = MockServer::start();
    let _usage = usage_ok(&server);
    let mut short = token_ok(&server, 1);
    let fixture = expired_owned(&server);
    stage_pending(&fixture);
    assert_eq!(short.calls(), 1);
    short.delete();

    let long = token_ok(&server, 28_800);
    fixture
        .cmd()
        .args(["claude", "status", "--refresh", "--account", EMAIL])
        .assert()
        .success()
        .stdout(predicates::str::contains("pending replayed"));

    assert_eq!(long.calls(), 1, "the replayed-but-expired credential was refreshed once");
    assert_eq!(fixture.namespace_entries(ACCT, ORG), vec![".credentials.json".to_owned()]);
}

#[test]
fn ac33d_a_pending_without_metadata_is_invalid() {
    let server = MockServer::start();
    let _usage = usage_ok(&server);
    let token = token_ok(&server, 28_800);
    let fixture = expired_owned(&server);
    stage_pending(&fixture);
    fs::remove_file(fixture.ns_dir(ACCT, ORG).join(".pending.meta"))
        .expect("the metadata should be removable");

    fixture
        .cmd()
        .args(["claude", "status", "--refresh", "--account", EMAIL])
        .assert()
        .code(2)
        .stdout(predicates::str::contains("pending discarded: invalid"));

    assert_eq!(token.calls(), 2, "the file on disk was refreshed normally afterwards");
    assert_eq!(fixture.namespace_entries(ACCT, ORG), vec![".credentials.json".to_owned()]);
}

#[test]
fn ac33e_a_symlinked_pending_is_invalid() {
    // A symlink at the pending path is somebody aiming a rename at a file of
    // their choosing. It is destroyed, not followed.
    let server = MockServer::start();
    let _usage = usage_ok(&server);
    let _token = token_ok(&server, 28_800);
    let fixture = expired_owned(&server);
    stage_pending(&fixture);

    let pending = fixture.ns_dir(ACCT, ORG).join(".credentials.json.pending");
    fs::remove_file(&pending).expect("the pending file should be removable");
    let target = fixture.scratch("elsewhere");
    fs::write(&target, "{}").expect("the decoy should be writable");
    std::os::unix::fs::symlink(&target, &pending).expect("the symlink should be plantable");

    fixture
        .cmd()
        .args(["claude", "status", "--refresh", "--account", EMAIL])
        .assert()
        .code(2)
        .stdout(predicates::str::contains("pending discarded: invalid"));

    assert!(!pending.exists(), "the symlink was removed");
    assert!(target.exists(), "and what it pointed at was left alone");
}

#[test]
fn ac33f_a_first_write_pending_replays_onto_an_empty_namespace() {
    // The row of the table a failed `login` produces: credentials parked
    // before any file existed, so the metadata records no prior digests.
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = token_ok(&server, 28_800);

    let mut fixture = Fixture::new();
    fixture.endpoints(&server.base_url());
    fixture.write_registry(vec![fixture.owned_record(ACCT, ORG)]);
    let ns_dir = fixture.ns_dir(ACCT, ORG);
    fs::create_dir_all(&ns_dir).expect("the namespace should be creatable");
    fs::write(
        ns_dir.join(".credentials.json.pending"),
        common::blob("sk-ant-oat01-first", "sk-ant-ort01-first", common::fresh_at()),
    )
    .expect("the pending file should be writable");
    write_meta(&fixture, None, common::fresh_at());

    fixture
        .cmd()
        .args(["claude", "status", "--refresh", "--account", EMAIL])
        .assert()
        .success()
        .stdout(predicates::str::contains("pending replayed"));

    assert_eq!(token.calls(), 0, "a fresh replay needs no refresh");
    assert_eq!(usage.calls(), 1);
    assert_eq!(fixture.namespace_entries(ACCT, ORG), vec![".credentials.json".to_owned()]);
    let stored = fs::read_to_string(fixture.credentials_path(ACCT, ORG)).expect("readable");
    assert!(stored.contains("sk-ant-oat01-first"));
}

#[test]
fn ac33g_a_pending_whose_file_was_removed_is_discarded() {
    // The account was deleted while the pending write waited. Replaying would
    // resurrect a credential the user got rid of, so it is destroyed and the
    // row says the only true thing left: log in again.
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = token_ok(&server, 28_800);

    let mut fixture = Fixture::new();
    fixture.endpoints(&server.base_url());
    fixture.write_registry(vec![fixture.owned_record(ACCT, ORG)]);
    let ns_dir = fixture.ns_dir(ACCT, ORG);
    fs::create_dir_all(&ns_dir).expect("the namespace should be creatable");
    fs::write(
        ns_dir.join(".credentials.json.pending"),
        common::blob("sk-ant-oat01-orphan", "sk-ant-ort01-orphan", common::fresh_at()),
    )
    .expect("the pending file should be writable");
    write_meta(&fixture, Some((&"a".repeat(64), &"b".repeat(64))), common::fresh_at());

    fixture
        .cmd()
        .args(["claude", "status", "--refresh", "--account", EMAIL])
        .assert()
        .code(2)
        .stdout(predicates::str::contains("needs login"));

    assert_eq!(token.calls(), 0);
    assert_eq!(usage.calls(), 0);
    assert!(fixture.namespace_entries(ACCT, ORG).is_empty(), "both files were destroyed");
}

#[test]
fn ac33h_a_migrated_namespace_discards_its_pending() {
    // A Claude Code session took the namespace over while the pending write
    // waited. Moving it into place now would hand that session a credential
    // agentctl chose (invariant I2).
    let server = MockServer::start();
    let _usage = usage_ok(&server);
    let token = token_ok(&server, 28_800);

    let mut fixture = expired_owned(&server);
    stage_pending(&fixture);

    fixture.with_keychain();
    let service = common::migration_service(&fixture.ns_dir(ACCT, ORG));
    fixture.dump(&[&service]);
    fixture.keychain_item(
        &service,
        &common::blob("sk-ant-oat01-migrated", "sk-ant-ort01-migrated", common::fresh_at()),
    );

    fixture
        .cmd()
        .args(["claude", "status", "--refresh", "--account", EMAIL])
        .assert()
        .code(2)
        .stdout(predicates::str::contains("pending discarded: namespace taken over"));

    assert_eq!(token.calls(), 1, "no refresh after the takeover");
    assert_eq!(
        fixture.namespace_entries(ACCT, ORG),
        vec![".credentials.json".to_owned()],
        "the pending pair was destroyed and the file left as it was"
    );
    fixture.assert_keychain_read_only();
}

// ---------------------------------------------------------------------------
// AC48 (c) — what the lock file records
// ---------------------------------------------------------------------------

#[test]
fn ac48_the_lock_body_names_the_process_holding_it() {
    // Plan AC48 (c): the body is what makes a wedged holder diagnosable. The
    // process id alone is not enough — ids are recycled — so the start time
    // goes in beside it, and `doctor` compares both before believing either.
    let server = MockServer::start();
    let _usage = usage_ok(&server);
    let _token = token_ok(&server, 28_800);

    let fixture = expired_owned(&server);
    let lock = fixture.lock_path(ACCT, ORG);

    let child = fixture
        .raw()
        .args(["claude", "status", "--refresh", "--timeout", "60s", "--account", EMAIL])
        .env("AGENTCTL_FAULT", "hold_lock")
        .spawn()
        .expect("agentctl should start");
    let pid = child.id();
    assert!(
        common::wait_until(OBSERVE_BUDGET, || common::lock_is_held(&lock)),
        "agentctl should have taken the namespace lock"
    );
    assert!(
        common::wait_until(OBSERVE_BUDGET, || fs::read_to_string(&lock)
            .is_ok_and(|body| body.contains("\"pid\""))),
        "and written its body under it"
    );

    let body: Value = serde_json::from_str(&fs::read_to_string(&lock).expect("readable"))
        .expect("the lock body should be JSON");
    assert_eq!(body["pid"], json!(pid), "the body names the holder: {body}");
    assert!(
        body["pid_start_time"].as_str().is_some_and(|value| !value.is_empty()),
        "and when it started, so a recycled id cannot be mistaken for it: {body}"
    );
    assert!(
        body["acquired_at"].as_str().is_some_and(|value| value.contains('T')),
        "and when the lock was taken: {body}"
    );

    kill(child);
}

// ---------------------------------------------------------------------------
// AC65, AC66 — a migrated namespace refreshes its own keychain item in place
// ---------------------------------------------------------------------------

/// A store whose one owned namespace a Claude Code session has migrated into
/// the keychain (fact F35, decision D-015).
///
/// The namespace *directory* is still there and `.credentials.json` is gone,
/// which is exactly what a session leaves behind: it writes the namespaced
/// item and deletes the file. The item is registered as a write target with
/// the stand-in, because a write it was not told about must not silently
/// succeed.
fn migrated_owned(server: &MockServer, expires_at_ms: i64) -> (Fixture, String) {
    let mut fixture = Fixture::new();
    fixture.with_keychain().endpoints(&server.base_url());
    fixture.write_registry(vec![fixture.owned_record(ACCT, ORG)]);
    fs::create_dir_all(fixture.ns_dir(ACCT, ORG)).expect("the namespace should be creatable");

    let service = common::migration_service(&fixture.ns_dir(ACCT, ORG));
    fixture.dump(&[&service]);
    fixture.keychain_item(
        &service,
        &common::blob("sk-ant-oat01-migrated", "sk-ant-ort01-migrated", expires_at_ms),
    );
    fixture.allow_write(&service);
    (fixture, service)
}

/// How many times the stand-in was asked to read one service's password.
fn finds_for(fixture: &Fixture, service: &str) -> usize {
    let suffix = format!("-s {service}");
    fixture
        .security_log()
        .iter()
        .filter(|line| line.starts_with("find-generic-password") && line.ends_with(&suffix))
        .count()
}

/// The account every read of `service` matched on.
///
/// Taken out of the argv log rather than assumed, because the point of the
/// assertion it feeds is that the write and the read agree about the account
/// — an assertion that would be worthless if both sides came from the same
/// constant in the test.
///
/// # Panics
///
/// Panics when the log holds no read of `service`, or when two reads of it
/// disagree about the account: either means the fixture is not modelling one
/// keychain item any more.
fn read_account(fixture: &Fixture, service: &str) -> String {
    let suffix = format!("-s {service}");
    let accounts: Vec<String> = fixture
        .security_log()
        .iter()
        .filter(|line| line.starts_with("find-generic-password") && line.ends_with(&suffix))
        .filter_map(|line| {
            let rest = line.split_once("-a ")?.1;
            Some(rest.split_once(' ')?.0.to_owned())
        })
        .collect();
    let first = accounts.first().unwrap_or_else(|| panic!("no read of `{service}` was logged"));
    assert!(
        accounts.iter().all(|account| account == first),
        "every read of `{service}` matched on one account: {accounts:?}"
    );
    first.clone()
}

/// Every write the stand-in recorded, redacted as it logs them.
fn writes(fixture: &Fixture) -> Vec<String> {
    fixture
        .security_log()
        .into_iter()
        .filter(|line| line.starts_with("add-generic-password"))
        .collect()
}

/// Runs one pass and hands back its stdout.
fn json_pass(fixture: &Fixture, extra: &[&str]) -> String {
    let mut command = fixture.cmd();
    command.args(["claude", "status", "--json", "--refresh", "--account", EMAIL]);
    command.args(extra);
    let assert = command.assert();
    let output = assert.get_output().clone();
    String::from_utf8(output.stdout).expect("stdout is UTF-8")
}

#[test]
fn ac65_a_migrated_namespace_refreshes_its_own_keychain_item_in_place() {
    // Plan AC65, decision D-015. One read of the item before the POST, one
    // POST, one write to *that* item under Claude Code's own lock protocol
    // against agentctl's own directory, the locks gone afterwards, the live
    // item untouched, and the plaintext file never resurrected.
    //
    // This test is named in `common::KEYCHAIN_WRITE_TESTS`, so it does not
    // record its calls into the suite-wide aggregate: AC61 replays one write
    // per name there and requires the count to match exactly.
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = token_ok(&server, 28_800);

    let (mut fixture, service) = migrated_owned(&server, common::expired_at());
    // The hold's own duration is only observable through the log line the
    // release writes, and invariant I17's number is worth asserting rather
    // than assuming.
    fixture.set("RUST_LOG", "agentctl=debug");
    let item = fixture.keychain_item_path(&service);
    let before = fs::read_to_string(&item).expect("the migrated item should be readable");
    // Absent *before* the pass as well as after: decision D-014 is that a
    // migrated namespace stays migrated, and a claim about what the pass did
    // not create is only worth making against a namespace that did not have
    // it to begin with.
    assert!(
        fixture.namespace_entries(ACCT, ORG).is_empty(),
        "the namespace starts with no plaintext store: {:?}",
        fixture.namespace_entries(ACCT, ORG)
    );

    let output = fixture
        .cmd()
        .args(["claude", "status", "--json", "--refresh", "--account", EMAIL])
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let stderr = common::strip_ansi(&String::from_utf8(output.stderr).expect("stderr is UTF-8"));

    // Invariant I17: the hold, from the first `mkdir` to the last `rmdir`,
    // stays inside the budget derived from fact F53's give-up floor.
    let released = stderr
        .lines()
        .find(|line| line.contains("released the credential-store hold"))
        .unwrap_or_else(|| panic!("the release should have been logged:\n{stderr}"));
    let field = released
        .split_once("hold_ms=")
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("the release line should carry `hold_ms`: {released}"));
    let hold_ms: u64 =
        field.parse().unwrap_or_else(|err| panic!("`hold_ms={field}` should be a number: {err}"));
    assert!(
        released.contains("budget_ms=3000"),
        "and the budget it is measured against: {released}"
    );
    assert!(hold_ms < 3000, "the hold was {hold_ms} ms, at or past its 3 000 ms budget");

    let row = owned_row(&stdout);
    assert_eq!(row["state"], json!("ok"), "the row reports the credential, not the migration");
    assert_eq!(
        row["lock_state"],
        json!("migrated_refreshed"),
        "and says the item itself was refreshed: {row}"
    );
    assert_eq!(row["source"], json!("keychain"), "{row}");

    assert_eq!(token.calls(), 1, "exactly one refresh POST");
    assert!(usage.calls() >= 1, "and the row still answered the user's question");

    // The item was updated in place, and it is the item that changed.
    let after = fs::read_to_string(&item).expect("the migrated item should still be readable");
    assert_ne!(after, before, "the namespaced item now holds the refreshed pair");
    assert!(after.contains("sk-ant-oat01-rotated"), "with the new access token: {after}");
    assert!(after.contains("sk-ant-ort01-rotated"), "and the rotated refresh token: {after}");

    // Exactly one write, naming that item, with the blob redacted.
    let write_lines = writes(&fixture);
    assert_eq!(write_lines.len(), 1, "exactly one keychain write: {write_lines:?}");
    let write = &write_lines[0];
    assert!(write.contains(&format!("-s \"{service}\"")), "it names the namespaced item: {write}");
    assert!(write.contains("-X <REDACTED:"), "and the stand-in redacted the blob: {write}");

    // Invariant I1′ over the *whole* matching key, not half of it. A generic
    // password is identified by its account and its service together, so a
    // write whose `-a` is not the `-a` the reads matched on would leave the
    // item that was read holding the pre-refresh pair and put the fresh one in
    // a sibling nobody reads — and, against a duplicate planted by another
    // process, hand that process a live credential across the ACL boundary.
    let account = read_account(&fixture, &service);
    assert!(
        write.contains(&format!("-a \"{account}\"")),
        "the write names the account the reads matched on (`{account}`): {write}"
    );
    assert_eq!(
        fixture.keychain_accounts(),
        vec![account.clone()],
        "and created no sibling item under any other account"
    );
    assert!(
        fixture.keychain_item_path_for(&account, &service).exists(),
        "the item that was read is the item that exists afterwards"
    );

    // The live item is never a target on this path (invariant I1′): no write
    // names it, and nothing ever created it.
    assert!(
        !write.contains(&format!("-s \"{LIVE_SERVICE}\"")),
        "the live item is not what was written: {write}"
    );
    assert!(
        !fixture.keychain_item_path(LIVE_SERVICE).exists(),
        "and the live item was never created at all"
    );

    // The exact number of reads of the item, and why each one exists:
    //   1. `foreign_activity::detect`, confirming the migration is real;
    //   2. discovery parsing what it found, for the owned row;
    //   3. discovery parsing it again, for the `unclaimed` row it also emits
    //      because a migrated namespace's service is not a *claimed* one;
    //   4. the check before the POST, holding nothing: a peer that refreshed
    //      between 1–3 and here has already minted what this pass would, and
    //      is adopted instead of racing (invariant I17 allows a read here and
    //      forbids the POST under the hold);
    //   5. the re-read under the three locks (invariant I2′);
    //   6. the verifying re-read after the release (section 3.4 step 12).
    // Only 4–6 belong to this step; 1–3 are discovery's, unchanged.
    assert_eq!(
        finds_for(&fixture, &service),
        6,
        "the item was read exactly six times: {:?}",
        fixture.security_log()
    );
    assert_eq!(
        finds_for(&fixture, LIVE_SERVICE),
        1,
        "and the live row read its own item exactly once: {:?}",
        fixture.security_log()
    );

    // And the whole of what `security` was asked to do, so a later change
    // cannot add an invocation without this failing: one preflight, one
    // listing, seven reads, and the write — which the stand-in logs twice,
    // once as the argv it was handed and once as the redacted line it parsed
    // off standard input.
    let calls = fixture.security_log();
    assert_eq!(calls.len(), 11, "the exact set of `security` invocations: {calls:?}");
    for (subcommand, expected) in
        [("show-keychain-info", 1), ("dump-keychain", 1), ("find-generic-password", 7)]
    {
        assert_eq!(
            calls.iter().filter(|line| line.starts_with(subcommand)).count(),
            expected,
            "`{subcommand}` was issued {expected} time(s): {calls:?}"
        );
    }
    assert_eq!(
        calls.iter().filter(|line| line.as_str() == "-i").count(),
        1,
        "and exactly one write transport was spawned: {calls:?}"
    );

    // The namespace is still migrated: no plaintext store, and no lock
    // artefact left behind (decision D-014, invariant I5′).
    assert!(
        fixture.namespace_entries(ACCT, ORG).is_empty(),
        "the namespace holds nothing at all: {:?}",
        fixture.namespace_entries(ACCT, ORG)
    );
    for artefact in fixture.hold_artefacts(ACCT, ORG) {
        assert!(
            fs::symlink_metadata(&artefact).is_err(),
            "`{}` should have been released",
            artefact.display()
        );
    }
    let records: Vec<PathBuf> = fs::read_dir(fixture.held_locks_dir())
        .expect("the held-locks directory should exist once a hold has happened")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    assert!(records.is_empty(), "the held-lock record was cleared: {records:?}");

    // The audit line, carrying digest prefixes and nothing else.
    let log = fs::read_to_string(fixture.audit_log_path()).expect("the audit log should exist");
    let entries: Vec<Value> = log
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("each audit line is one JSON object"))
        .collect();
    assert_eq!(entries.len(), 1, "one write, one entry: {log}");
    let entry = &entries[0];
    assert_eq!(entry["event"], json!("write"), "{entry}");
    assert_eq!(entry["outcome"], json!("applied"), "{entry}");
    let sha8 = service.rsplit('-').next().expect("the service name carries a suffix");
    assert_eq!(entry["target"], json!(format!("namespace:{sha8}")), "{entry}");
    for field in ["from_digest8", "to_digest8"] {
        let value = entry[field].as_str().unwrap_or_default();
        assert_eq!(value.len(), 8, "`{field}` is a digest prefix: {entry}");
        assert!(
            value.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "`{field}` is lowercase hex: {entry}"
        );
    }
    assert_ne!(entry["from_digest8"], entry["to_digest8"], "the write changed the item: {entry}");
    assert!(!log.contains("sk-ant-"), "and no line carries token material: {log}");
}

#[test]
fn ac65_a_peer_refresh_before_the_post_is_adopted_and_costs_no_grant() {
    // The window between discovery reading the item and this pass POSTing to
    // the token endpoint. The file path closes it under its namespace lock —
    // it re-reads and returns `adopted` without a POST — and invariant I17
    // forbids this path from holding anything across a network call, so it
    // asks the same question in Phase B, holding nothing.
    //
    // Without the check the pass POSTs with a refresh token the peer has just
    // spent: the server rotates ours away, our answer is discarded under the
    // locks, and the row lands on `needs login` for an item that is perfectly
    // healthy — advice decision D-014 forbids acting on for a migrated
    // namespace anyway.
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = token_ok(&server, 28_800);

    let (fixture, service) = migrated_owned(&server, common::expired_at());
    let resume = fixture.scratch("resume");
    let item = fixture.keychain_item_path(&service);

    let child = fixture
        .raw()
        .args(["claude", "status", "--json", "--refresh", "--timeout", "30s", "--account", EMAIL])
        .env("AGENTCTL_FAULT", "pause_before_migrated_reread")
        .env("AGENTCTL_FAULT_RESUME", &resume)
        .spawn()
        .expect("agentctl should start");

    // `discovery::discover` is single-threaded, so three logged reads mean the
    // first two — the migration probe and the owned row's own — have returned;
    // the third serves the `unclaimed` row and feeds nothing this test claims.
    // The pause then holds the next read until the resume file exists, so the
    // item written here is exactly what the pre-POST check will see.
    assert!(
        common::wait_until(OBSERVE_BUDGET, || finds_for(&fixture, &service) >= 3),
        "discovery should have read the item before the pause"
    );
    let peer = common::blob("sk-ant-oat01-peer", "sk-ant-ort01-peer", common::fresh_at());
    fs::write(&item, &peer).expect("the item should be writable");
    fs::write(&resume, "go").expect("the resume file should be writable");

    let finished = common::finish(child);
    let row = owned_row(&finished.stdout);
    assert_eq!(row["state"], json!("ok"), "the peer's credential answers the row: {row}");
    assert_eq!(row["lock_state"], json!("adopted"), "and says whose it is: {row}");
    assert_eq!(
        row["note"],
        json!("a Claude Code session refreshed this item"),
        "in words rather than by omission: {row}"
    );

    assert_eq!(token.calls(), 0, "no grant was spent: the peer had already minted one");
    assert!(usage.calls() >= 1, "and the row still answered the user's question");
    assert!(writes(&fixture).is_empty(), "nothing was written: {:?}", fixture.security_log());
    assert_eq!(
        fs::read_to_string(&item).expect("readable"),
        peer,
        "the peer's credential is exactly what is still there"
    );
    for artefact in fixture.hold_artefacts(ACCT, ORG) {
        assert!(
            fs::symlink_metadata(&artefact).is_err(),
            "`{}` was never created: the adoption precedes every lock",
            artefact.display()
        );
    }
    // One preflight, one listing, the live row's read, and four reads of the
    // item: discovery's three and the one before the POST. No hold, so no
    // re-read under it and no verifying read.
    assert_eq!(finds_for(&fixture, &service), 4, "{:?}", fixture.security_log());
    assert_eq!(
        fixture.security_log().len(),
        7,
        "the exact set of `security` invocations: {:?}",
        fixture.security_log()
    );
    // The audit log is for writes and breaks. Nothing was minted here, so
    // nothing was discarded, and the log has nothing to say.
    assert!(
        !fixture.audit_log_path().exists(),
        "a pass that made no POST records no discarded refresh"
    );
}

#[test]
fn ac65_an_invalid_grant_after_a_peer_refresh_adopts_rather_than_asking_for_a_login() {
    // The residual window the check above cannot close: the peer wrote while
    // this pass's POST was already in flight. The server answers
    // `invalid_grant`, because the peer's refresh consumed the grant — which
    // is a logout only if the refresh token is still the item's. It is not:
    // the item moved, so a Claude Code session holds the pair the server
    // minted, and the row takes theirs.
    //
    // The wrong answer here is `needs login`, which sends the user to
    // `agentctl claude login` — and decision D-014 forbids that from writing a
    // namespaced item, so the advice would be a dead end for a healthy row.
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = server.mock(|when, then| {
        when.method(POST).path(common::TOKEN_PATH);
        then.status(400).json_body(json!({
            "error": "invalid_grant",
            "error_description": "refresh token is not valid",
        }));
    });

    let (fixture, service) = migrated_owned(&server, common::expired_at());
    let resume = fixture.scratch("resume");
    let item = fixture.keychain_item_path(&service);

    let child = fixture
        .raw()
        .args(["claude", "status", "--json", "--refresh", "--timeout", "30s", "--account", EMAIL])
        .env("AGENTCTL_FAULT", "pause_before_invalid_grant_reread")
        .env("AGENTCTL_FAULT_RESUME", &resume)
        .spawn()
        .expect("agentctl should start");

    // The POST having been answered is the ordering point: the pre-POST check
    // has already run and agreed, so the item written here is invisible to it
    // and visible only to the recovery, which is paused waiting for the
    // resume file below.
    assert!(
        common::wait_until(OBSERVE_BUDGET, || token.calls() == 1),
        "the refresh POST should have been rejected before the pause"
    );
    let peer = common::blob("sk-ant-oat01-peer", "sk-ant-ort01-peer", common::fresh_at());
    fs::write(&item, &peer).expect("the item should be writable");
    fs::write(&resume, "go").expect("the resume file should be writable");

    let finished = common::finish(child);
    let row = owned_row(&finished.stdout);
    assert_eq!(row["state"], json!("ok"), "a healthy item is not a logout: {row}");
    assert_ne!(row["state"], json!("needs_login"), "{row}");
    assert_eq!(row["lock_state"], json!("adopted"), "{row}");
    assert_eq!(row["note"], json!("a Claude Code session refreshed this item"), "{row}");

    assert_eq!(token.calls(), 1, "the POST did go out; it is the answer that changed");
    assert!(usage.calls() >= 1, "and the row still answered the user's question");
    assert!(writes(&fixture).is_empty(), "nothing was written: {:?}", fixture.security_log());
    assert_eq!(
        fs::read_to_string(&item).expect("readable"),
        peer,
        "the peer's credential is untouched"
    );
    for artefact in fixture.hold_artefacts(ACCT, ORG) {
        assert!(
            fs::symlink_metadata(&artefact).is_err(),
            "`{}` was never created: the recovery precedes every lock",
            artefact.display()
        );
    }
    // Discovery's three, the one before the POST, and the recovery's one.
    assert_eq!(finds_for(&fixture, &service), 5, "{:?}", fixture.security_log());
    assert_eq!(
        fixture.security_log().len(),
        8,
        "the exact set of `security` invocations: {:?}",
        fixture.security_log()
    );
    // The POST failed, so nothing was minted and nothing was discarded.
    assert!(!fixture.audit_log_path().exists(), "a failed POST records no discarded refresh");
}

#[test]
fn ac65_a_refusal_after_the_post_records_the_discarded_refresh() {
    // Plan section 3.9's partial-state contract, for the row it did not have:
    // a refresh that was *performed* and never written. The item still holds
    // the pre-refresh refresh token, which the server has usually just rotated
    // away, so the next pass may report `needs login` for a situation this
    // pass created — and without an entry that is undiagnosable afterwards.
    //
    // `lock_contended` is the cheapest way to reach a post-POST refusal: the
    // acquire reports the store busy after the POST has already happened.
    let server = MockServer::start();
    let _usage = usage_ok(&server);
    let token = token_ok(&server, 28_800);

    let (mut fixture, service) = migrated_owned(&server, common::expired_at());
    fixture.fault("lock_contended");

    let stdout = json_pass(&fixture, &[]);
    let row = owned_row(&stdout);
    assert_eq!(row["state"], json!("busy"), "{row}");
    assert_eq!(token.calls(), 1, "the grant was spent");
    assert!(writes(&fixture).is_empty(), "and never written: {:?}", fixture.security_log());

    let log = fs::read_to_string(fixture.audit_log_path()).expect("the audit log should exist");
    let entries: Vec<Value> = log
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("each audit line is one JSON object"))
        .collect();
    let writes_logged: Vec<&Value> =
        entries.iter().filter(|entry| entry["event"] == json!("write")).collect();
    assert_eq!(writes_logged.len(), 1, "one refusal, one entry: {log}");
    let entry = writes_logged[0];
    assert_eq!(
        entry["outcome"],
        json!("discarded"),
        "the refresh was performed and thrown away: {entry}"
    );
    let sha8 = service.rsplit('-').next().expect("the service name carries a suffix");
    assert_eq!(entry["target"], json!(format!("namespace:{sha8}")), "{entry}");
    assert_ne!(
        entry["from_digest8"], entry["to_digest8"],
        "and it names both ends of what was lost: {entry}"
    );
    assert!(!log.contains("sk-ant-"), "with no token material: {log}");
}

#[test]
fn ac65_the_hold_creates_three_locks_and_a_changed_item_discards_the_refresh() {
    // Two claims in one run, because one fault produces both.
    //
    // `pause_before_migrated_write` holds open the window between the refresh
    // POST returning and the locks being taken — outside the hold, so nothing
    // Claude Code wants is held while the test interleaves (invariant I17).
    // The test rewrites the item in that window, which is what a live session
    // finishing its own refresh would do; the re-read under the locks then
    // disagrees with what the refresh was computed from, and the refreshed
    // credential is discarded rather than written over theirs (invariant I2′).
    //
    // `swap_lock_leak` makes the hold leave its directories and its record
    // behind exactly as a crashed hold would, which is what turns "the three
    // locks were taken, in the peer's own nesting" into an assertion rather
    // than an inference.
    let server = MockServer::start();
    let _usage = usage_ok(&server);
    let token = token_ok(&server, 28_800);

    let (fixture, service) = migrated_owned(&server, common::expired_at());
    let resume = fixture.scratch("resume");
    let item = fixture.keychain_item_path(&service);

    let child = fixture
        .raw()
        .args(["claude", "status", "--refresh", "--timeout", "30s", "--account", EMAIL])
        .env("AGENTCTL_FAULT", "pause_before_migrated_write,swap_lock_leak")
        .env("AGENTCTL_FAULT_RESUME", &resume)
        .spawn()
        .expect("agentctl should start");

    assert!(
        common::wait_until(OBSERVE_BUDGET, || token.calls() == 1),
        "the refresh POST should have gone out before the pause"
    );
    // A live session finishes its own refresh while ours is in flight.
    fs::write(&item, common::blob("sk-ant-oat01-peer", "sk-ant-ort01-peer", common::fresh_at()))
        .expect("the item should be writable");
    fs::write(&resume, "go").expect("the resume file should be writable");

    let finished = common::finish(child);
    assert_eq!(finished.code(), 2, "a discarded refresh is a degraded row\n{}", finished.stderr);
    assert!(
        finished.stdout.contains("refresh discarded: the item changed under us"),
        "stdout:\n{}",
        finished.stdout
    );

    assert_eq!(token.calls(), 1, "and no second POST was made");
    assert!(writes(&fixture).is_empty(), "nothing was written: {:?}", fixture.security_log());
    // One preflight, one listing, six reads — the five the positive case makes
    // before the write, plus the live row's own — and no write and no
    // verifying read, because the refusal ends the path.
    assert_eq!(
        fixture.security_log().len(),
        8,
        "the exact set of `security` invocations: {:?}",
        fixture.security_log()
    );
    let served = fs::read_to_string(&item).expect("readable");
    assert!(served.contains("sk-ant-oat01-peer"), "the peer's credential survived: {served}");

    // The leaked hold names all three directories, in the peer's nesting.
    let artefacts = fixture.hold_artefacts(ACCT, ORG);
    for artefact in &artefacts {
        let meta = fs::symlink_metadata(artefact)
            .unwrap_or_else(|err| panic!("`{}` should exist: {err}", artefact.display()));
        assert!(meta.is_dir(), "`{}` is a directory, as the peer makes them", artefact.display());
    }

    // And the record that brackets them, which is the only evidence a crashed
    // hold leaves (fact F45).
    let records: Vec<PathBuf> = fs::read_dir(fixture.held_locks_dir())
        .expect("the held-locks directory should exist")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    assert_eq!(records.len(), 1, "one leaked hold, one record: {records:?}");
    let body: Value =
        serde_json::from_str(&fs::read_to_string(&records[0]).expect("the record is readable"))
            .expect("the record is JSON");
    assert_eq!(body["tree"], json!("agentctl"), "the break stayed in agentctl's tree: {body}");
    assert_eq!(
        body["store_dir"].as_str().unwrap_or_default(),
        fixture.ns_dir(ACCT, ORG).to_string_lossy(),
        "and it names the namespace it locked: {body}"
    );
    let named: Vec<String> = body["paths"]
        .as_array()
        .expect("the record lists the directories it took")
        .iter()
        .map(|value| value.as_str().unwrap_or_default().to_owned())
        .collect();
    let expected: Vec<String> =
        artefacts.iter().map(|path| path.to_string_lossy().into_owned()).collect();
    assert_eq!(named, expected, "in the order the peer's own nesting takes them: {body}");
}

#[test]
fn ac66_a_fresh_migrated_namespace_is_no_longer_terminal() {
    // Plan AC66: `migrated to keychain` used to end the row. It no longer
    // does — a fresh item reads as `ok`, from the keychain, with no POST and
    // no write, and the note says which item the numbers came from.
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = token_ok(&server, 28_800);

    let (fixture, service) = migrated_owned(&server, common::fresh_at());

    let stdout = json_pass(&fixture, &[]);
    let row = owned_row(&stdout);
    assert_eq!(row["state"], json!("ok"), "a fresh migrated item is not a degraded row: {row}");
    assert_eq!(row["lock_state"], json!("none"), "no lock was taken at all: {row}");
    assert_eq!(row["source"], json!("keychain"), "{row}");
    assert_eq!(
        row["note"],
        json!(format!("keychain service `{service}`")),
        "and the row still says where the credential lives: {row}"
    );

    assert_eq!(token.calls(), 0, "a fresh credential is not refreshed");
    assert!(usage.calls() >= 1, "it is displayed, from the keychain");
    assert!(writes(&fixture).is_empty(), "and nothing was written: {:?}", fixture.security_log());
    assert!(fixture.namespace_entries(ACCT, ORG).is_empty(), "no plaintext store was created");
    // One preflight, one listing, four reads: the live item once and this one
    // three times, all of them discovery's.
    assert_eq!(
        fixture.security_log().len(),
        6,
        "the exact set of `security` invocations: {:?}",
        fixture.security_log()
    );
    fixture.assert_keychain_read_only();
}

#[test]
fn ac65_an_item_under_the_canonical_spelling_is_never_refreshed() {
    // Invariant I1′. Discovery looks for both spellings of a namespace
    // (plan AC20), but only the item whose name the registry *predicts* —
    // `WriteTarget::migrated`, from the record's own `export_sha8` — can be a
    // write target. An item under the canonical spelling's name belongs to
    // this directory just as plainly and is still refused, because agentctl
    // never created a namespace for that name.
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = token_ok(&server, 28_800);

    let mut fixture = Fixture::new();
    fixture.with_keychain().endpoints(&server.base_url());
    fixture.write_registry(vec![fixture.owned_record(ACCT, ORG)]);
    let ns_dir = fixture.ns_dir(ACCT, ORG);
    fs::create_dir_all(&ns_dir).expect("the namespace should be creatable");

    let canonical = common::canonical_migration_service(&ns_dir);
    assert_ne!(
        canonical,
        common::migration_service(&ns_dir),
        "the fixture needs the two spellings to differ, which under $TMPDIR they do"
    );
    fixture.dump(&[&canonical]);
    fixture.keychain_item(
        &canonical,
        &common::blob("sk-ant-oat01-canonical", "sk-ant-ort01-canonical", common::expired_at()),
    );
    fixture.allow_write(&canonical);

    let stdout = json_pass(&fixture, &[]);
    let row = owned_row(&stdout);
    assert_eq!(row["state"], json!("migrated_to_keychain"), "the row stays terminal: {row}");
    assert_eq!(row["lock_state"], json!("migrated"), "{row}");
    assert_eq!(
        row["note"],
        json!("item name does not match the recorded export spelling; refusing to refresh"),
        "and says why it will not be refreshed: {row}"
    );

    assert_eq!(token.calls(), 0, "no refresh was attempted");
    assert_eq!(usage.calls(), 0, "an expired credential agentctl may not refresh is not spent");
    assert!(writes(&fixture).is_empty(), "nothing was written: {:?}", fixture.security_log());
    for artefact in fixture.hold_artefacts(ACCT, ORG) {
        assert!(
            fs::symlink_metadata(&artefact).is_err(),
            "`{}` was never created: no lock is taken before the name is checked",
            artefact.display()
        );
    }
    assert_eq!(
        fixture.security_log().len(),
        6,
        "the exact set of `security` invocations: {:?}",
        fixture.security_log()
    );
    fixture.assert_keychain_read_only();
}

#[test]
fn ac65_a_contended_store_reports_busy_and_writes_nothing() {
    // Plan section 3.4's `busy`. `lock_contended` makes every attempt at the
    // primary lock come back `EEXIST`, which is what a live session holding it
    // looks like: the acquire releases what it took, restarts from the
    // lock-free probe, and after `MAX_RESTARTS` reports the store busy — never
    // waiting while holding anything (architect N-1).
    //
    // A lock artefact that is present *before* the pass starts is a stronger
    // refusal and a different one: discovery reports `claude session detected`
    // and no refresh is attempted at all (plan AC21). This is the arm that
    // only the acquire can reach.
    let server = MockServer::start();
    let _usage = usage_ok(&server);
    let token = token_ok(&server, 28_800);

    let (mut fixture, service) = migrated_owned(&server, common::expired_at());
    fixture.fault("lock_contended");
    let item = fixture.keychain_item_path(&service);
    let before = fs::read_to_string(&item).expect("readable");

    let stdout = json_pass(&fixture, &[]);
    let row = owned_row(&stdout);
    assert_eq!(row["state"], json!("busy"), "{row}");
    assert_eq!(row["lock_state"], json!("busy"), "{row}");
    assert_eq!(token.calls(), 1, "the POST had already happened; only the write was refused");
    assert!(writes(&fixture).is_empty(), "nothing was written: {:?}", fixture.security_log());
    assert_eq!(fs::read_to_string(&item).expect("readable"), before, "the item is untouched");

    // Every restart released what it had taken, and the last one left nothing.
    for artefact in fixture.hold_artefacts(ACCT, ORG) {
        assert!(
            fs::symlink_metadata(&artefact).is_err(),
            "`{}` was released on the way out",
            artefact.display()
        );
    }
    let records: Vec<PathBuf> = fs::read_dir(fixture.held_locks_dir())
        .expect("the held-locks directory should exist")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    assert!(records.is_empty(), "and cleared its record: {records:?}");
    // No re-read under the hold and no verifying read: the acquire never
    // handed back a hold. The read before the POST still happened.
    assert_eq!(
        fixture.security_log().len(),
        7,
        "the exact set of `security` invocations: {:?}",
        fixture.security_log()
    );
    fixture.assert_keychain_read_only();
}

#[test]
fn ac65_a_blob_over_the_stdin_limit_spawns_no_write() {
    // Refusal D, invariant I15. Fact F42's line is bounded at 4 032 bytes
    // *including* its newline, and Claude Code's own fallback for a longer one
    // is to put the hex in argv. agentctl has no such fallback: the line is
    // refused, and the refusal is decided before any lock is taken and before
    // any child exists.
    let server = MockServer::start();
    let _usage = usage_ok(&server);
    let token = server.mock(|when, then| {
        when.method(POST).path(common::TOKEN_PATH);
        then.status(200).json_body(json!({
            "access_token": "sk-ant-oat01-".to_owned() + &"a".repeat(2400),
            "refresh_token": "sk-ant-ort01-rotated",
            "token_type": "Bearer",
            "expires_in": 28_800,
            "scope": "user:inference user:profile",
        }));
    });

    let (fixture, service) = migrated_owned(&server, common::expired_at());
    let item = fixture.keychain_item_path(&service);
    let before = fs::read_to_string(&item).expect("readable");

    let stdout = json_pass(&fixture, &[]);
    let row = owned_row(&stdout);
    assert_eq!(row["state"], json!("error"), "{row}");
    assert_eq!(
        row["state_label"],
        json!("blob exceeds the keychain stdin limit"),
        "and names the limit rather than a syscall: {row}"
    );
    assert_eq!(token.calls(), 1);
    assert!(writes(&fixture).is_empty(), "no write was attempted: {:?}", fixture.security_log());
    assert_eq!(fs::read_to_string(&item).expect("readable"), before, "the item is untouched");
    for artefact in fixture.hold_artefacts(ACCT, ORG) {
        assert!(
            fs::symlink_metadata(&artefact).is_err(),
            "`{}` was never created: the refusal precedes the locks",
            artefact.display()
        );
    }
    assert_eq!(
        fixture.security_log().len(),
        7,
        "the exact set of `security` invocations: {:?}",
        fixture.security_log()
    );
    fixture.assert_keychain_read_only();
}
