#![cfg(feature = "testing")]

//! `agentctl claude status`, driven through the real binary.
//!
//! Each test here re-proves an acceptance criterion the unit tests already
//! cover in-process, but from outside: a temporary store on disk, a scripted
//! `security(1)` on `PATH`'s stead, an `httpmock` server the binary really
//! talks to, and assertions on the exit status, the rendered text, the bytes
//! and inodes left on disk, and the keychain argv log.
//!
//! The negative claims are the point. "Zero requests for a row agentctl does
//! not own" and "the file was never opened" are not things an in-process test
//! can state as strongly as a hit count on a server the binary had to reach
//! over a socket.

mod common;

use std::fs;

use common::ACCT;
use common::EMAIL;
use common::Fixture;
use common::LIVE_SERVICE;
use common::OLD_BLOB;
use common::ORG;
use common::USAGE_BODY;
use common::USAGE_PATH;
use httpmock::Method::GET;
use httpmock::Method::POST;
use httpmock::Mock;
use httpmock::MockServer;
use predicates::str::contains;
use serde_json::json;

/// The mock that answers a usage GET with the captured body.
fn usage_ok(server: &MockServer) -> Mock<'_> {
    server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(200).body(USAGE_BODY);
    })
}

/// The mock that answers a refresh POST with a rotated token pair.
fn token_ok(server: &MockServer) -> Mock<'_> {
    server.mock(|when, then| {
        when.method(POST).path(common::TOKEN_PATH);
        then.status(200).json_body(json!({
            "access_token": "sk-ant-oat01-rotated",
            "refresh_token": "sk-ant-ort01-rotated",
            "token_type": "Bearer",
            "expires_in": 28_800,
            "refresh_token_expires_in": 2_377_445,
            "scope": "user:inference user:profile",
        }));
    })
}

#[test]
fn ac5_an_expired_live_credential_costs_no_request() {
    // Plan AC5, decision D-001: the live entry belongs to Claude Code, which
    // refreshes it. agentctl reports the expiry and spends nothing on it —
    // not even the usage GET, because the token it would send is the expired
    // one.
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = token_ok(&server);

    let mut fixture = Fixture::new();
    fixture.with_keychain().endpoints(&server.base_url());
    fixture.dump(&[LIVE_SERVICE]);
    fixture.keychain_item(
        LIVE_SERVICE,
        &common::blob("sk-ant-oat01-live", "sk-ant-ort01-live", common::expired_at()),
    );

    fixture
        .cmd()
        .args(["claude", "status"])
        .assert()
        .code(2)
        .stdout(contains("expired (read-only"));

    assert_eq!(usage.calls(), 0, "an expired read-only row is never fetched");
    assert_eq!(token.calls(), 0, "agentctl never refreshes the live credential");
    fixture.assert_keychain_read_only();
}

#[test]
fn ac6_an_expired_owned_credential_is_refreshed_and_replaced_atomically() {
    // Plan AC6: one POST, one GET, and a credential file replaced by a
    // rename — a new inode, still 0600, with no temporary or pending file
    // left beside it.
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = token_ok(&server);

    let mut fixture = Fixture::new();
    fixture.with_keychain().endpoints(&server.base_url());
    fixture.write_registry(vec![fixture.owned_record(ACCT, ORG)]);
    let path = fixture.write_credentials(
        ACCT,
        ORG,
        &common::blob("sk-ant-oat01-stale", "sk-ant-ort01-stale", common::expired_at()),
    );
    let before = common::inode_of(&path);

    fixture
        .cmd()
        .args(["claude", "status", "--refresh", "--account", EMAIL])
        .assert()
        .success()
        .stdout(contains("Fable (weekly)"));

    assert_eq!(token.calls(), 1, "exactly one refresh");
    assert_eq!(usage.calls(), 1, "exactly one usage fetch");
    assert_ne!(common::inode_of(&path), before, "the file was replaced, not rewritten in place");
    assert_eq!(common::mode_of(&path), 0o600, "the replacement is still 0600");
    assert_eq!(
        fixture.namespace_entries(ACCT, ORG),
        vec![".credentials.json".to_owned()],
        "no temporary or pending file survives a successful write"
    );
    let stored = fs::read_to_string(&path).expect("the credential file should be readable");
    assert!(stored.contains("sk-ant-oat01-rotated"), "the rotated token was stored");
    fixture.assert_keychain_read_only();
}

#[test]
fn ac8_a_rate_limit_is_honoured_past_the_end_of_the_process() {
    // Plan AC8, principle P4: a `retry-after` outlives the process that was
    // told about it. The third run must not call at all, and the second must
    // still show the numbers the first one cached.
    let server = MockServer::start();
    let mut ok = usage_ok(&server);

    let mut fixture = Fixture::new();
    fixture.with_keychain().endpoints(&server.base_url());
    fixture.write_registry(vec![fixture.owned_record(ACCT, ORG)]);
    fixture.write_credentials(
        ACCT,
        ORG,
        &common::blob("sk-ant-oat01-fresh", "sk-ant-ort01-fresh", common::fresh_at()),
    );

    // First run fills the cache.
    fixture.cmd().args(["claude", "status", "--account", EMAIL]).assert().success();
    assert_eq!(ok.calls(), 1);
    ok.delete();

    let limited = server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(429).header("retry-after", "30").body("{}");
    });

    // Second run meets the 429 and shows the cached figures beside it.
    fixture
        .cmd()
        .args(["claude", "status", "--no-cache", "--account", EMAIL])
        .assert()
        .code(2)
        .stdout(contains("rate-limited (retry in 30s)"))
        .stdout(contains("showing the cached value"))
        .stdout(contains("21"));
    assert_eq!(limited.calls(), 1);

    // Third run, inside the window, declines to call at all — even though
    // `--no-cache` asks for a fresh fetch.
    fixture
        .cmd()
        .args(["claude", "status", "--no-cache", "--account", EMAIL])
        .assert()
        .code(2)
        .stdout(contains("rate-limited"));
    assert_eq!(limited.calls(), 1, "the retry-after window survived the first process");
    fixture.assert_keychain_read_only();
}

#[test]
fn ac31_a_hanging_security_times_out_and_owned_rows_still_refresh() {
    // Plan AC31, invariant I12: `security(1)` is killed at its budget, the
    // keychain-backed row says so, and — invariant I10 — nothing falls back
    // to the live plaintext file. The owned row is unaffected and refreshes.
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = token_ok(&server);

    let mut fixture = Fixture::new();
    fixture.with_keychain().endpoints(&server.base_url());
    fixture.set("AGENTCTL_FAKE_SECURITY_SLEEP", "30");
    fixture.dump(&[LIVE_SERVICE]);
    fixture.write_registry(vec![fixture.owned_record(ACCT, ORG)]);
    fixture.write_credentials(
        ACCT,
        ORG,
        &common::blob("sk-ant-oat01-stale", "sk-ant-ort01-stale", common::expired_at()),
    );

    // The file a non-strict reader would fall through to. It must not be read
    // (plan section 3.3 step 1, invariant I10).
    let live_dir = fixture.live_store_dir();
    fs::create_dir_all(&live_dir).expect("the live store directory should be creatable");
    fs::write(
        live_dir.join(".credentials.json"),
        common::identified_blob(
            "sk-ant-oat01-plaintext",
            "sk-ant-ort01-plaintext",
            common::fresh_at(),
            "99999999-9999-9999-9999-999999999999",
            Some("88888888-8888-8888-8888-888888888888"),
        ),
    )
    .expect("the live plaintext store should be writable");

    let started = std::time::Instant::now();
    let assert = fixture
        .cmd()
        .args(["claude", "status", "--refresh"])
        .assert()
        .code(2)
        .stdout(contains("keychain timeout (transient)"))
        .stdout(contains("migration probe skipped"));
    let elapsed = started.elapsed();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).expect("stdout is UTF-8");
    assert!(
        !stdout.contains("99999999-9999-9999-9999-999999999999"),
        "a timed-out keychain must not fall through to the live plaintext file:\n{stdout}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(20),
        "the 30-second `security` child was waited on rather than killed at its budget \
         (took {elapsed:?})"
    );
    assert_eq!(token.calls(), 1, "the owned row refreshed regardless of the keychain");
    assert_eq!(usage.calls(), 1);
    fixture.assert_keychain_read_only();
}

#[test]
fn ac32_a_locked_keychain_stops_keychain_rows_and_not_owned_ones() {
    // Plan AC32, fact F34: preflight exit 36 means locked. The live row can
    // do nothing until the user unlocks; the owned row is on the filesystem
    // and carries on.
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = token_ok(&server);

    let mut fixture = Fixture::new();
    fixture.with_keychain().endpoints(&server.base_url());
    fixture.set("AGENTCTL_FAKE_SECURITY_PREFLIGHT_EXIT", "36");
    fixture.dump(&[LIVE_SERVICE]);
    fixture.write_registry(vec![fixture.owned_record(ACCT, ORG)]);
    fixture.write_credentials(
        ACCT,
        ORG,
        &common::blob("sk-ant-oat01-stale", "sk-ant-ort01-stale", common::expired_at()),
    );

    fixture
        .cmd()
        .args(["claude", "status", "--refresh"])
        .assert()
        .code(2)
        .stdout(contains("keychain locked"));

    assert_eq!(token.calls(), 1, "only the owned row refreshed");
    assert_eq!(usage.calls(), 1, "the locked row spent no request");
    let log = fixture.security_log();
    assert!(
        log.iter().all(|line| !line.starts_with("find-generic-password")),
        "a locked keychain is never asked for an item: {log:?}"
    );
    fixture.assert_keychain_read_only();
}

#[test]
fn ac34_a_migrated_namespace_is_read_from_the_keychain_and_never_written() {
    // Plan AC34, fact F35: a Claude Code session has moved this namespace's
    // credentials into the keychain. agentctl displays them from there and
    // stops writing the file entirely (invariant I2).
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = token_ok(&server);

    let mut fixture = Fixture::new();
    fixture.with_keychain().endpoints(&server.base_url());
    fixture.write_registry(vec![fixture.owned_record(ACCT, ORG)]);
    let path = fixture.write_credentials(
        ACCT,
        ORG,
        &common::blob("sk-ant-oat01-file", "sk-ant-ort01-file", common::expired_at()),
    );
    let before = fs::read(&path).expect("the credential file should be readable");
    let before_inode = common::inode_of(&path);

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
        .success()
        .stdout(contains("migrated to keychain"));

    assert_eq!(token.calls(), 0, "a migrated namespace is never refreshed");
    assert_eq!(usage.calls(), 1, "it is still displayed, from the keychain");
    assert_eq!(fs::read(&path).expect("readable"), before, "the file was left exactly as it was");
    assert_eq!(common::inode_of(&path), before_inode);
    assert_eq!(fixture.namespace_entries(ACCT, ORG), vec![".credentials.json".to_owned()]);
    assert!(
        fixture
            .security_log()
            .iter()
            .any(|line| line.starts_with("find-generic-password") && line.contains(&service)),
        "the migration probe read the item it found in the listing"
    );
    fixture.assert_keychain_read_only();
}

#[test]
fn ac34_a_locked_keychain_read_never_falls_back_to_the_file() {
    // Plan AC34's second clause and invariant I10: for a keychain-backed row
    // a read failure is transient, and the plaintext file beside it is not an
    // answer. Claude Code's own non-strict read would fall through; agentctl
    // deliberately does not, and this is where that divergence is pinned.
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = token_ok(&server);

    let mut fixture = Fixture::new();
    fixture.with_keychain().endpoints(&server.base_url());
    fixture.set("AGENTCTL_FAKE_SECURITY_FIND_EXIT", "36");
    fixture.dump(&[LIVE_SERVICE]);
    fixture.keychain_item(
        LIVE_SERVICE,
        &common::blob("sk-ant-oat01-live", "sk-ant-ort01-live", common::fresh_at()),
    );

    let live_dir = fixture.live_store_dir();
    fs::create_dir_all(&live_dir).expect("the live store directory should be creatable");
    fs::write(
        live_dir.join(".credentials.json"),
        common::identified_blob(
            "sk-ant-oat01-plaintext",
            "sk-ant-ort01-plaintext",
            common::fresh_at(),
            "99999999-9999-9999-9999-999999999999",
            Some("88888888-8888-8888-8888-888888888888"),
        ),
    )
    .expect("the live plaintext store should be writable");

    let assert = fixture
        .cmd()
        .args(["claude", "status"])
        .assert()
        .code(2)
        .stdout(contains("keychain locked"));
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).expect("stdout is UTF-8");
    assert!(
        !stdout.contains("99999999-9999-9999-9999-999999999999"),
        "the plaintext file was consulted after a locked keychain read:\n{stdout}"
    );
    assert_eq!(token.calls(), 0);
    assert_eq!(usage.calls(), 0, "a row with no readable credential spends no request");
    fixture.assert_keychain_read_only();
}

#[test]
fn ac39_a_config_dir_blob_without_an_identity_is_identity_unknown() {
    // Plan AC39, invariant I13: identity comes from the credential, never
    // from a path — and `.claude.json` is evidence for the live row alone.
    // An older blob in somebody else's configuration directory is therefore
    // `identity unknown`, and no request is spent on it.
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = token_ok(&server);

    let mut fixture = Fixture::new();
    fixture.with_keychain().endpoints(&server.base_url());
    let service = format!("{LIVE_SERVICE}-deadbeef");
    fixture.dump(&[&service]);
    fixture.keychain_item(&service, OLD_BLOB);
    fixture.write_registry(vec![fixture.config_dir_record(
        "44444444-4444-4444-4444-444444444444",
        "55555555-5555-5555-5555-555555555555",
        &service,
    )]);

    // `.claude.json` names an account. Borrowing it for this row would be
    // exactly the mistake invariant I13 forbids.
    fs::write(
        fixture.home().join(".claude.json"),
        json!({
            "oauthAccount": {
                "accountUuid": "99999999-9999-9999-9999-999999999999",
                "emailAddress": "borrowed@example.com",
                "organizationUuid": "88888888-8888-8888-8888-888888888888",
            }
        })
        .to_string(),
    )
    .expect("`.claude.json` should be writable");

    let assert = fixture
        .cmd()
        .args(["claude", "status"])
        .assert()
        .code(2)
        .stdout(contains("identity unknown"));

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).expect("stdout is UTF-8");
    // The live row *may* use `.claude.json` — that is fact F33. This row may
    // not, so the assertion is about this row's line rather than the table.
    let row = stdout
        .lines()
        .find(|line| line.contains(&service))
        .unwrap_or_else(|| panic!("the config-dir row should be rendered:\n{stdout}"));
    assert!(
        !row.contains("borrowed@example.com")
            && !row.contains("88888888-8888-8888-8888-888888888888"),
        "`.claude.json` was borrowed for a row that is not the live one:\n{row}"
    );
    assert_eq!(usage.calls(), 0, "a row with no identity is not fetched");
    assert_eq!(token.calls(), 0);
    fixture.assert_keychain_read_only();
}

#[test]
fn ac42_a_keychain_item_naming_the_live_directory_is_a_hidden_sibling() {
    // Plan AC42, facts F41 and F6: `~/.claude` is a symlink, and a keychain
    // item named after where it resolves holds *different* credentials. That
    // is one physical directory and two accounts, so folding by path would
    // show the wrong numbers. It folds by digest or not at all.
    let mut fixture = Fixture::new();
    fixture.with_keychain();

    let real = fixture.home().join("real-claude");
    fs::create_dir_all(&real).expect("the real store directory should be creatable");
    std::os::unix::fs::symlink(&real, fixture.live_store_dir())
        .expect("`~/.claude` should be linkable");
    let canonical = fs::canonicalize(&real).expect("the real directory resolves");
    let sibling = format!("{LIVE_SERVICE}-{}", common::sha8(&common::export_spelling(&canonical)));

    fixture.dump(&[LIVE_SERVICE, &sibling]);
    fixture.keychain_item(
        LIVE_SERVICE,
        &common::blob("sk-ant-oat01-live", "sk-ant-ort01-live", common::fresh_at()),
    );
    fixture.keychain_item(
        &sibling,
        &common::blob("sk-ant-oat01-older", "sk-ant-ort01-older", common::fresh_at()),
    );

    let assert = fixture.cmd().args(["claude", "status"]).assert();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).expect("stdout is UTF-8");
    assert!(
        !stdout.contains("stale sibling of live"),
        "the sibling is hidden without `--all`:\n{stdout}"
    );
    assert!(stdout.contains("1 entry hidden (--all)"), "and counted in the footer:\n{stdout}");

    fixture
        .cmd()
        .args(["claude", "status", "--all"])
        .assert()
        .stdout(contains("stale sibling of live"));
    fixture
        .cmd()
        .args(["claude", "accounts", "list", "--all"])
        .assert()
        .success()
        .stdout(contains("stale sibling of live"));
    fixture
        .cmd()
        .args(["claude", "doctor"])
        .assert()
        .success()
        .stdout(contains("stale sibling of live"));
    fixture.assert_keychain_read_only();
}

#[test]
fn ac42_an_identical_blob_under_a_second_name_folds_into_the_live_row() {
    // The other half of plan AC42: same directory, *same* credentials, so the
    // two names are one account and there is nothing to hide or to count.
    let mut fixture = Fixture::new();
    fixture.with_keychain();

    let real = fixture.home().join("real-claude");
    fs::create_dir_all(&real).expect("the real store directory should be creatable");
    std::os::unix::fs::symlink(&real, fixture.live_store_dir())
        .expect("`~/.claude` should be linkable");
    let canonical = fs::canonicalize(&real).expect("the real directory resolves");
    let sibling = format!("{LIVE_SERVICE}-{}", common::sha8(&common::export_spelling(&canonical)));

    let same = common::blob("sk-ant-oat01-live", "sk-ant-ort01-live", common::fresh_at());
    fixture.dump(&[LIVE_SERVICE, &sibling]);
    fixture.keychain_item(LIVE_SERVICE, &same);
    fixture.keychain_item(&sibling, &same);

    let assert = fixture.cmd().args(["claude", "status"]).assert();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).expect("stdout is UTF-8");
    assert!(!stdout.contains("hidden (--all)"), "nothing was hidden:\n{stdout}");
    assert!(!stdout.contains("stale sibling"), "and nothing is a sibling:\n{stdout}");
    fixture.assert_keychain_read_only();
}

#[test]
fn ac43_a_hanging_security_cannot_hold_the_pass_open() {
    // Plan AC43, design S1': every child is owned by the coordinator and
    // killed at its budget. The script sleeps for thirty seconds; the run
    // must not.
    let mut fixture = Fixture::new();
    fixture.with_keychain();
    fixture.set("AGENTCTL_FAKE_SECURITY_SLEEP", "30");
    fixture.dump(&[LIVE_SERVICE]);

    let started = std::time::Instant::now();
    fixture
        .cmd()
        .args(["claude", "status", "--timeout", "1s"])
        .assert()
        .code(2)
        .stdout(contains("keychain timeout"));
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "the pass waited on a hanging `security` child instead of killing it (took {elapsed:?})"
    );
    fixture.assert_keychain_read_only();
}

#[test]
fn ac48_a_symlink_at_the_lock_path_stops_the_refresh() {
    // Plan AC48 (a): the lock file is the one thing standing between two
    // writers, so anything unexpected at that path fails closed rather than
    // being followed to wherever it points.
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = token_ok(&server);

    let mut fixture = Fixture::new();
    fixture.endpoints(&server.base_url());
    fixture.write_registry(vec![fixture.owned_record(ACCT, ORG)]);
    fixture.write_credentials(
        ACCT,
        ORG,
        &common::blob("sk-ant-oat01-stale", "sk-ant-ort01-stale", common::expired_at()),
    );

    let lock = fixture.lock_path(ACCT, ORG);
    fs::create_dir_all(lock.parent().expect("the lock path has a parent"))
        .expect("the locks directory should be creatable");
    std::os::unix::fs::symlink(fixture.scratch("elsewhere"), &lock)
        .expect("the symlink should be plantable");

    fixture
        .cmd()
        .args(["claude", "status", "--refresh", "--account", EMAIL])
        .assert()
        .code(2)
        .stdout(contains("lock unavailable"));

    assert_eq!(token.calls(), 0, "a refusal costs no refresh");
    assert_eq!(usage.calls(), 0);
    assert!(!fixture.scratch("elsewhere").exists(), "the symlink target was never created");
}

#[test]
fn ac48_an_unavailable_flock_stops_the_refresh() {
    // Plan AC48 (b), invariant I12: a lock error that is not contention means
    // the single-writer guarantee is gone. Refreshing anyway could race a
    // second holder, so the row reports and stops.
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = token_ok(&server);

    let mut fixture = Fixture::new();
    fixture.endpoints(&server.base_url());
    fixture.fault("flock_enotsup");
    fixture.write_registry(vec![fixture.owned_record(ACCT, ORG)]);
    fixture.write_credentials(
        ACCT,
        ORG,
        &common::blob("sk-ant-oat01-stale", "sk-ant-ort01-stale", common::expired_at()),
    );

    fixture
        .cmd()
        .args(["claude", "status", "--refresh", "--account", EMAIL])
        .assert()
        .code(2)
        .stdout(contains("lock unavailable"));

    assert_eq!(token.calls(), 0);
    assert_eq!(usage.calls(), 0);
    assert_eq!(
        fixture.namespace_entries(ACCT, ORG),
        vec![".credentials.json".to_owned()],
        "nothing was staged"
    );
}
