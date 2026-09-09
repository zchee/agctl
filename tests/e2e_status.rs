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
use jiff::Timestamp;
use jiff::civil::Weekday;
use jiff::tz::TimeZone;
use predicates::str::contains;
use serde_json::Value;
use serde_json::json;

/// The mock that answers a usage GET with the captured body.
fn usage_ok(server: &MockServer) -> Mock<'_> {
    server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(200).body(USAGE_BODY);
    })
}

// ---------------------------------------------------------------------------
// The two reset columns (user request of 2026-09-09)
// ---------------------------------------------------------------------------
//
// The binary has no clock seam — `commands::status` stamps the report with
// `Timestamp::now()` — so these tests move the *fixture* instead: the captured
// body's `resets_at` values are rewritten relative to the moment the test
// starts. That makes both halves of the cell exactly assertable, the countdown
// because the offsets are chosen to floor to a constant and the clock time
// because it is derived from the same instant the fixture carries.

/// How far ahead the five-hour reset is placed, in milliseconds: 1h12m30s.
///
/// The thirty seconds are slack. `render_countdown` floors, so a reset exactly
/// 1h12m out would render `1h11m` as soon as the binary's clock read later
/// than the test's; half a minute of headroom keeps `1h12m` exact without
/// making the assertion depend on how fast the process starts.
const SESSION_AHEAD_MS: i64 = 3_600_000 + 12 * 60_000 + 30_000;

/// How far ahead the seven-day reset is placed: 2d6h30m, same slack.
const WEEKLY_AHEAD_MS: i64 = 2 * 86_400_000 + 6 * 3_600_000 + 30 * 60_000;

/// `Timestamp::now()`, truncated to a whole second.
///
/// Both halves of the cell are minute-resolution, and a whole second keeps the
/// RFC 3339 spellings this test compares readable in a failure message.
fn now_to_the_second() -> Timestamp {
    let now = Timestamp::now();
    Timestamp::from_second(now.as_second()).expect("a truncated `now` is still a timestamp")
}

/// `now` plus `millis`.
fn ahead(now: Timestamp, millis: i64) -> Timestamp {
    Timestamp::from_millisecond(now.as_millisecond() + millis)
        .expect("a few days from now is still a timestamp")
}

/// The captured usage body with its resets moved to `session_at` and
/// `weekly_at`.
///
/// The capture's own values are absolute instants from the day it was taken,
/// so a countdown asserted against them would read differently every day and
/// eventually just `now`. Only those fields move; every other byte is the real
/// response.
fn usage_body_resetting_at(session_at: Timestamp, weekly_at: Timestamp) -> String {
    let mut body: Value =
        serde_json::from_str(USAGE_BODY).expect("the captured usage body is valid JSON");
    body["five_hour"]["resets_at"] = json!(session_at.to_string());
    body["seven_day"]["resets_at"] = json!(weekly_at.to_string());
    for limit in body["limits"].as_array_mut().expect("the captured body carries `limits`") {
        let moved = if limit["kind"] == json!("session") { session_at } else { weekly_at };
        limit["resets_at"] = json!(moved.to_string());
    }
    body.to_string()
}

/// The cell a reset column should carry for `at`, seen from `tz`.
///
/// Derived from `Zoned`'s own components rather than through the `strftime`
/// format the renderer uses, so this is a second derivation of the answer and
/// not the implementation restated. The prefix rule is only half-applied: both
/// instants are inside a week of each other by construction, so the date form
/// cannot arise here (the unit tests in `src/render/reset_tests.rs` cover it).
fn expected_cell(now: Timestamp, at: Timestamp, tz: &TimeZone, countdown: &str) -> String {
    let now_local = now.to_zoned(tz.clone());
    let at_local = at.to_zoned(tz.clone());
    let hour = match at_local.hour() % 12 {
        0 => 12,
        hour => hour,
    };
    let meridiem = if at_local.hour() < 12 { "AM" } else { "PM" };
    let clock = format!("{hour}:{:02} {meridiem}", at_local.minute());
    if now_local.date() == at_local.date() {
        format!("{clock} ({countdown})")
    } else {
        format!("{} {clock} ({countdown})", weekday(at_local.weekday()))
    }
}

/// The abbreviation `%a` produces, spelled out rather than borrowed.
fn weekday(day: Weekday) -> &'static str {
    match day {
        Weekday::Monday => "Mon",
        Weekday::Tuesday => "Tue",
        Weekday::Wednesday => "Wed",
        Weekday::Thursday => "Thu",
        Weekday::Friday => "Fri",
        Weekday::Saturday => "Sat",
        Weekday::Sunday => "Sun",
    }
}

/// A fixture holding one fresh owned account, answering usage with `body`.
fn owned_fixture(server: &MockServer, body: String) -> Fixture {
    server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(200).body(body);
    });

    let mut fixture = Fixture::new();
    fixture.endpoints(&server.base_url());
    fixture.write_registry(vec![fixture.owned_record(ACCT, ORG)]);
    fixture.write_credentials(
        ACCT,
        ORG,
        &common::blob("sk-ant-oat01-fresh", "sk-ant-ort01-fresh", common::fresh_at()),
    );
    fixture
}

#[test]
fn the_reset_columns_are_printed_in_the_zone_tz_selects() {
    // The user's request of 2026-09-09: each reset column says *when* the
    // window rolls over, not only how long is left. "When" is a local time, so
    // the run has to honour `TZ` — and the same two instants must print
    // differently in Tokyo and in UTC, which is the assertion at the end.
    let now = now_to_the_second();
    let session_at = ahead(now, SESSION_AHEAD_MS);
    let weekly_at = ahead(now, WEEKLY_AHEAD_MS);

    let server = MockServer::start();
    let fixture = owned_fixture(&server, usage_body_resetting_at(session_at, weekly_at));

    let tokyo = TimeZone::get("Asia/Tokyo").expect("the platform tzdb should know Asia/Tokyo");
    let tokyo_session = expected_cell(now, session_at, &tokyo, "1h12m");
    let tokyo_weekly = expected_cell(now, weekly_at, &tokyo, "2d6h");
    let utc_session = expected_cell(now, session_at, &TimeZone::UTC, "1h12m");
    let utc_weekly = expected_cell(now, weekly_at, &TimeZone::UTC, "2d6h");
    assert_ne!(
        tokyo_session, utc_session,
        "+09:00 and UTC cannot spell the same clock time, so this test can tell them apart"
    );

    let assert = fixture
        .cmd()
        .env("TZ", "Asia/Tokyo")
        .args(["claude", "status", "--account", EMAIL])
        .assert()
        .success()
        .stdout(contains("5h reset"))
        .stdout(contains("Weekly reset"))
        .stdout(contains(tokyo_session.clone()))
        .stdout(contains(tokyo_weekly.clone()));

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).expect("stdout is UTF-8");
    assert!(!stdout.contains("Next reset"), "the countdown-only column is gone:\n{stdout}");
    assert!(
        !stdout.contains(&utc_session),
        "the `TZ=Asia/Tokyo` run printed a UTC clock time:\n{stdout}"
    );

    // The same fixture, the other zone. Nothing about the fetch changed, so
    // this run may well be served from the 300 s cache — which is the point:
    // the zone decides the rendering and nothing else.
    let assert = fixture
        .cmd()
        .env("TZ", "UTC")
        .args(["claude", "status", "--account", EMAIL])
        .assert()
        .success()
        .stdout(contains(utc_session))
        .stdout(contains(utc_weekly));

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).expect("stdout is UTF-8");
    assert!(!stdout.contains(&tokyo_session), "`TZ=UTC` was ignored:\n{stdout}");
    fixture.assert_keychain_read_only();
}

#[test]
fn the_json_report_carries_each_named_windows_own_reset() {
    // The document keeps every instant in UTC — the local rendering is the
    // table's business — and `next_reset` still means what it meant, which is
    // why the two new members sit beside it rather than replacing it.
    let now = now_to_the_second();
    let session_at = ahead(now, SESSION_AHEAD_MS);
    let weekly_at = ahead(now, WEEKLY_AHEAD_MS);

    let server = MockServer::start();
    let fixture = owned_fixture(&server, usage_body_resetting_at(session_at, weekly_at));

    let assert = fixture
        .cmd()
        .env("TZ", "Asia/Tokyo")
        .args(["claude", "status", "--json", "--account", EMAIL])
        .assert()
        .success();

    let document: Value = serde_json::from_slice(&assert.get_output().stdout)
        .expect("`--json` should print one JSON document and nothing else");
    let row = document["rows"]
        .as_array()
        .expect("`rows` is an array")
        .iter()
        .find(|row| row["email"] == json!(EMAIL))
        .unwrap_or_else(|| panic!("the owned account is in the document:\n{document}"));

    assert_eq!(row["session_reset"], json!(session_at.to_string()));
    assert_eq!(row["weekly_reset"], json!(weekly_at.to_string()));
    assert_eq!(
        row["next_reset"],
        json!(session_at.to_string()),
        "`next_reset` is still the soonest across every window"
    );
    fixture.assert_keychain_read_only();
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
    //
    // The row's *state* is no longer `migrated to keychain`: decision D-015
    // makes a migrated namespace refreshable in place, so an item the registry
    // predicts and that is fresh reads as `ok` with the service in its note
    // (plan AC66, `tests/e2e_refresh.rs`). What AC34 is about is unchanged and
    // is what the rest of this test asserts — the numbers come from the
    // keychain, and the plaintext file is not touched, not even its inode.
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
        .stdout(contains(&service));

    assert_eq!(token.calls(), 0, "a fresh migrated item needs no refresh");
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

// ---------------------------------------------------------------------------
// `same identity as live` (`agentctl-p3-login-live-identity-warning-b90`)
// ---------------------------------------------------------------------------

/// A second owned account, so "absent elsewhere" is a claim about a choice
/// and not about the only other row in the table.
const STRANGER_ACCT: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

/// Its organization.
const STRANGER_ORG: &str = "ffffffff-0000-4111-8222-333333333333";

/// A live keychain item and two owned namespaces: one the live account's
/// twin, one a stranger.
fn twin_fixture(server: &MockServer) -> Fixture {
    usage_ok(server);

    let mut fixture = Fixture::new();
    fixture.with_keychain().endpoints(&server.base_url());
    fixture.dump(&[LIVE_SERVICE]);
    // The live item and the owned file name one account and carry different
    // token pairs, which is what a second `login` leaves behind: two
    // independent sessions, one identity.
    fixture.keychain_item(
        LIVE_SERVICE,
        &common::blob("sk-ant-oat01-live", "sk-ant-ort01-live", common::fresh_at()),
    );
    fixture.write_registry(vec![
        fixture.owned_record(ACCT, ORG),
        fixture.owned_record(STRANGER_ACCT, STRANGER_ORG),
    ]);
    fixture.write_credentials(
        ACCT,
        ORG,
        &common::blob("sk-ant-oat01-owned", "sk-ant-ort01-owned", common::fresh_at()),
    );
    fixture.write_credentials(
        STRANGER_ACCT,
        STRANGER_ORG,
        &common::identified_blob(
            "sk-ant-oat01-stranger",
            "sk-ant-ort01-stranger",
            common::fresh_at(),
            STRANGER_ACCT,
            Some(STRANGER_ORG),
        ),
    );
    fixture
}

#[test]
fn b90_the_table_marks_only_the_owned_row_that_is_the_live_account() {
    // `agentctl-p3-login-live-identity-warning-b90` (status marks the Owned
    // row when its identity is the live one's), through the binary. The
    // symptom this answers is one email address appearing on two rows with no
    // explanation; the note is in the State column, next to the state it
    // qualifies, and it costs no extra keychain read — both identities were
    // already in the pass.
    let server = MockServer::start();
    let fixture = twin_fixture(&server);

    let assert = fixture.cmd().args(["claude", "status"]).assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).expect("stdout is UTF-8");

    assert_eq!(
        stdout.matches("same identity as live").count(),
        1,
        "exactly one row carries the note:\n{stdout}"
    );
    let marked = stdout
        .lines()
        .find(|line| line.contains("same identity as live"))
        .unwrap_or_else(|| panic!("the marked row should be rendered:\n{stdout}"));
    assert!(marked.contains(EMAIL), "it is the owned twin's row: {marked}");
    assert!(!marked.contains("sk-ant"), "no token material reaches the table: {marked}");
    fixture.assert_keychain_read_only();
}

#[test]
fn b90_the_json_report_names_the_live_twin_and_leaves_every_other_row_null() {
    let server = MockServer::start();
    let fixture = twin_fixture(&server);

    let assert = fixture.cmd().args(["claude", "status", "--json"]).assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).expect("stdout is UTF-8");
    let document: Value = serde_json::from_str(&stdout).expect("the report is JSON");
    let rows = document["rows"].as_array().expect("rows is an array");

    // One object per credential source, unchanged: the member says two rows
    // describe one account, it does not merge them.
    assert!(
        rows.iter().any(|row| row["kind"] == json!("live")),
        "the live row is still its own row:\n{stdout}"
    );

    let marked: Vec<&Value> =
        rows.iter().filter(|row| row["same_identity_as"] == json!("live")).collect();
    assert_eq!(marked.len(), 1, "one marked row:\n{stdout}");
    assert_eq!(marked[0]["kind"], json!("owned"));
    assert_eq!(marked[0]["account_uuid"], json!(ACCT));
    assert_eq!(marked[0]["organization_uuid"], json!(ORG));

    for row in rows
        .iter()
        .filter(|row| row["kind"] != json!("owned") || row["account_uuid"] != json!(ACCT))
    {
        assert_eq!(row["same_identity_as"], json!(null), "an unrelated row:\n{row:#}");
    }
    // Every row answers the question, so a consumer never has to tell an
    // absent member from a null one.
    for row in rows {
        assert!(
            row.as_object().expect("a row is an object").contains_key("same_identity_as"),
            "the member is present on every row:\n{row:#}"
        );
    }
    fixture.assert_keychain_read_only();
}

// ---------------------------------------------------------------------------
// `--by-identity` (`agentctl-xq8`)
// ---------------------------------------------------------------------------

/// The live keychain item and exactly one owned namespace, the same account.
///
/// One owned account rather than two, deliberately: `Fixture::owned_record`
/// gives every owned account the same email address (`agentctl-p95`), so a
/// second one could not be told from the first in rendered table text. With
/// one, the claim is a row *count* — two rows without the flag, one with it —
/// which needs no per-row identification at all.
fn one_identity_fixture(server: &MockServer) -> Fixture {
    usage_ok(server);

    let mut fixture = Fixture::new();
    fixture.with_keychain().endpoints(&server.base_url());
    fixture.dump(&[LIVE_SERVICE]);
    fixture.keychain_item(
        LIVE_SERVICE,
        &common::blob("sk-ant-oat01-live", "sk-ant-ort01-live", common::fresh_at()),
    );
    fixture.write_registry(vec![fixture.owned_record(ACCT, ORG)]);
    fixture.write_credentials(
        ACCT,
        ORG,
        &common::blob("sk-ant-oat01-owned", "sk-ant-ort01-owned", common::fresh_at()),
    );
    fixture
}

/// The rendered rows naming `EMAIL`, which under this fixture is every data
/// row and no heading or rule.
fn account_lines(stdout: &str) -> Vec<&str> {
    stdout.lines().filter(|line| line.contains(EMAIL)).collect()
}

#[test]
fn xq8_by_identity_renders_one_row_where_the_default_table_renders_two() {
    // `agentctl-xq8`: the symptom is one address on two rows. Without the
    // flag both are shown, which is the default this does not change; with
    // it, the live credential is folded into the row of the account that owns
    // it and the `Kind` column says `live+owned`.
    let server = MockServer::start();
    let fixture = one_identity_fixture(&server);

    let plain = fixture.cmd().args(["claude", "status"]).assert().success();
    let plain = String::from_utf8(plain.get_output().stdout.clone()).expect("stdout is UTF-8");
    assert_eq!(account_lines(&plain).len(), 2, "the live row and the owned row:\n{plain}");
    assert!(!plain.contains("| Kind"), "the default table has ten columns:\n{plain}");
    assert!(!plain.contains("live+owned"), "and no folded cell:\n{plain}");

    let folded = fixture.cmd().args(["claude", "status", "--by-identity"]).assert().success();
    let folded = String::from_utf8(folded.get_output().stdout.clone()).expect("stdout is UTF-8");
    assert_eq!(account_lines(&folded).len(), 1, "one row per identity:\n{folded}");
    assert!(folded.contains("Kind"), "the eleventh column is there:\n{folded}");
    let row = account_lines(&folded)[0];
    assert!(row.contains("live+owned"), "and the folded row says so: {row}");
    assert!(
        !row.contains("same identity as live"),
        "the note would only repeat the Kind cell: {row}"
    );
    assert!(!row.contains("sk-ant"), "no token material reaches the table: {row}");
    fixture.assert_keychain_read_only();
}

#[test]
fn xq8_the_flag_does_not_change_the_json_report_at_all() {
    // The document keeps one object per credential source under the flag as
    // without it — a consumer reads `same_identity_as` instead. Table and
    // JSON row counts therefore differ under the flag, which is the tradeoff
    // the bead records.
    let server = MockServer::start();
    let fixture = one_identity_fixture(&server);

    let plain = fixture.cmd().args(["claude", "status", "--json"]).assert().success();
    let plain: Value =
        serde_json::from_slice(&plain.get_output().stdout).expect("the report is JSON");

    let folded =
        fixture.cmd().args(["claude", "status", "--json", "--by-identity"]).assert().success();
    let mut folded: Value =
        serde_json::from_slice(&folded.get_output().stdout).expect("the report is JSON");

    assert_eq!(
        folded["rows"].as_array().expect("rows is an array").len(),
        2,
        "still one object per credential source:\n{folded:#}"
    );
    // Byte-for-byte the same document, once the two timestamps that cannot
    // agree between two runs are set aside.
    let mut plain = plain;
    for document in [&mut plain, &mut folded] {
        document["generated_at"] = json!("");
        for row in document["rows"].as_array_mut().expect("rows is an array") {
            row["next_reset"] = json!("");
            row["session_reset"] = json!("");
            row["weekly_reset"] = json!("");
        }
    }
    assert_eq!(plain, folded, "`--by-identity` is a table flag and nothing else");
}
