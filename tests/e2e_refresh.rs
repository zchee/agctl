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
use std::process::Child;
use std::time::Duration;

use common::ACCT;
use common::EMAIL;
use common::Fixture;
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
