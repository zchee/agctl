#![cfg(feature = "testing")]

//! What the suite is allowed to do to a keychain, stated as assertions over
//! the fake `security(1)`'s own log.
//!
//! Phase 1's claim was the simple one — **nothing writes or deletes** (plan
//! AC25) — and the type system backed it up. Phase 2 adds exactly one write
//! transport, so the claim becomes three:
//!
//! 1. **No command writes.** `keychain_write::write_item` has no caller in the
//!    shipped binary in W2, which is the point of landing the dangerous module
//!    on its own, and [`Fixture::assert_keychain_read_only`] keeps every other
//!    end-to-end test honest about it.
//! 2. **The write path, when driven, does exactly one thing**: argv `-i`, one
//!    line on stdin, the hex redacted in the log, and nothing at all for a
//!    service the test did not register (plan AC59, AC60).
//! 3. **Nothing deletes, ever** — and the write count over the whole suite is
//!    exactly the number of tests that write, which is a positive number
//!    (plan AC61).

mod common;

use std::fs;

use common::Fixture;
use common::KEYCHAIN_WRITE_TESTS;
use common::LIVE_SERVICE;
use predicates::str::contains;

/// The only `security(1)` subcommands a *command* has any business issuing.
const READ_ONLY_SUBCOMMANDS: [&str; 3] =
    ["show-keychain-info", "find-generic-password", "dump-keychain"];

/// The tokens a line in the suite-wide log may start with.
///
/// The three reads, plus the two the write transport produces: `-i` is the
/// whole argv (fact F42 — the payload goes on stdin, never in argv) and
/// `add-generic-password` is the stand-in's own redacted record of the line it
/// was handed.
const AGGREGATE_TOKENS: [&str; 5] =
    ["show-keychain-info", "find-generic-password", "dump-keychain", "-i", "add-generic-password"];

/// Subcommands whose presence anywhere would mean the keychain was mutated in
/// a way agctl has no code path for.
///
/// `add-generic-password` is deliberately **not** here any more — phase 2 has
/// one write transport — but it is counted instead, exactly, below. A delete
/// is a non-goal with no implementation and no fallback (fact F43), so it
/// stays a flat prohibition.
const FORBIDDEN_SUBCOMMANDS: [&str; 4] =
    ["delete-generic-password", "set-generic-password-partition-list", "unlock-keychain", "import"];

/// A fixture with the fake keychain and one importable item registered as a
/// legitimate write target.
fn writable(service: &str) -> Fixture {
    let mut fixture = Fixture::new();
    fixture.with_keychain();
    fixture.dump(&[service]);
    fixture.allow_write(service);
    fixture
}

/// The lines the fake logged after the first `skip` of them.
fn logged_after(fixture: &Fixture, skip: usize) -> Vec<String> {
    fixture.security_log().into_iter().skip(skip).collect()
}

#[test]
fn ac25_no_command_in_the_suite_ever_mutates_the_keychain() {
    // Runs a keychain-heavy pass first, so this test contributes its own
    // entries rather than only reading other tests'. Nextest gives no ordering
    // guarantee across processes, so the aggregate is whatever has finished by
    // now — and every keychain-using test also asserts its own log, which is
    // what makes the invariant hold regardless of who ran when.
    let mut fixture = Fixture::new();
    fixture.with_keychain();
    let sibling = format!("{LIVE_SERVICE}-deadbeef");
    fixture.dump(&[LIVE_SERVICE, &sibling, "claude-switcher:someone@example.com"]);
    fixture.keychain_item(
        LIVE_SERVICE,
        &common::blob("sk-ant-oat01-live", "sk-ant-ort01-live", common::fresh_at()),
    );
    fixture.keychain_item(
        &sibling,
        &common::identified_blob(
            "sk-ant-oat01-other",
            "sk-ant-ort01-other",
            common::fresh_at(),
            "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa",
            Some("cccccccc-3333-4333-8333-cccccccccccc"),
        ),
    );

    let _ = fixture.cmd().args(["claude", "status", "--all"]).assert();
    fixture.cmd().args(["claude", "doctor"]).assert().success();
    fixture.cmd().args(["claude", "accounts", "list", "--all"]).assert().success();
    fixture.cmd().args(["claude", "import", "--from", "keychain", "--dry-run"]).assert().success();

    let own = fixture.security_log();
    assert!(!own.is_empty(), "this test should have driven the keychain at all");
    for subcommand in READ_ONLY_SUBCOMMANDS {
        assert!(
            own.iter().any(|line| line.starts_with(subcommand)),
            "all three read subcommands should have been exercised: {own:?}"
        );
    }
    // Appends this test's lines to the aggregate as well as checking them.
    fixture.assert_keychain_read_only();

    let aggregate = fs::read_to_string(common::aggregate_log_path()).unwrap_or_default();
    let lines: Vec<&str> = aggregate.lines().filter(|line| !line.trim().is_empty()).collect();
    assert!(
        !lines.is_empty(),
        "the suite-wide log at `{}` should have entries by now",
        common::aggregate_log_path().display()
    );

    for line in &lines {
        let token = line.split_whitespace().next().unwrap_or_default();
        assert!(
            AGGREGATE_TOKENS.contains(&token),
            "the suite issued `security {token}`, which agctl has no code path for \
             (plan invariant I1′, AC25); full argv: {line}"
        );
        for forbidden in FORBIDDEN_SUBCOMMANDS {
            assert!(!line.contains(forbidden), "the suite issued `security {forbidden}`: {line}");
        }
    }
}

#[test]
fn ac25_the_stand_in_refuses_the_argv_form_of_a_write() {
    // Invariant I15's other half, and the reason the transport is `-i` at all:
    // fact F42 says Claude Code falls back to putting the hex in **argv** for
    // an over-long line, and agctl has no such fallback. The stand-in
    // refuses that shape outright, so a regression that grew one could not
    // pass here by being silently tolerated. Asserted by running the script
    // directly — the one place in the suite where a mutating argv is
    // deliberately issued.
    let fixture = Fixture::new();
    let script = fixture.scratch("bin").join("security");
    fs::create_dir_all(script.parent().expect("a parent")).expect("creatable");
    fs::write(&script, common::FAKE_SECURITY).expect("the script should be writable");
    let mut permissions = fs::metadata(&script).expect("stat-able").permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
    fs::set_permissions(&script, permissions).expect("chmod");

    for argv in [
        vec!["add-generic-password", "-U", "-s", LIVE_SERVICE, "-X", "6162"],
        vec!["delete-generic-password", "-a", "example", "-s", LIVE_SERVICE],
    ] {
        let output = std::process::Command::new(&script)
            .args(&argv)
            .output()
            .expect("the stand-in should be runnable");
        assert_eq!(output.status.code(), Some(1), "`{argv:?}` must not be carried out");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.starts_with("security:"), "and it says so as security does: {stderr}");
    }
}

#[test]
fn ac59_the_write_transport_reads_one_line_from_stdin_and_redacts_the_hex() {
    // Plan AC59, from the far side of the pipe: the argv the stand-in sees is
    // exactly `-i`, the line arrives on stdin, the blob lands in the item, and
    // the log carries the hex's *length* rather than the hex.
    let blob = common::blob("sk-ant-oat01-written", "sk-ant-ort01-written", common::fresh_at());
    let fixture = writable(LIVE_SERVICE);
    let line = common::keychain_write_line("example", LIVE_SERVICE, &blob);

    let output = fixture.security_write(&line);
    assert_eq!(output.code(), 0, "stderr: {}", output.stderr);

    let stored = fs::read_to_string(fixture.keychain_item_path(LIVE_SERVICE))
        .expect("the write should have stored the item");
    assert_eq!(stored, blob, "the bytes on the pipe are the bytes in the item");

    let logged = fixture.security_log();
    assert_eq!(logged.first().map(String::as_str), Some("-i"), "argv is exactly `-i`: {logged:?}");
    let hex_len = blob.len() * 2;
    assert_eq!(
        logged.get(1).map(String::as_str),
        Some(
            format!(
                "add-generic-password -U -a \"example\" -s \"{LIVE_SERVICE}\" -X <REDACTED:{hex_len}>"
            )
            .as_str()
        ),
        "{logged:?}"
    );
    let whole = logged.join("\n");
    assert!(!whole.contains("sk-ant-"), "the log must not carry the payload: {whole}");
    assert!(!whole.contains(&hex::encode(&blob)), "nor its hex: {whole}");
}

#[test]
fn ac60_a_service_no_test_registered_is_refused_and_stores_nothing() {
    // The stand-in's allowlist: the one operation where "the test forgot to
    // say which item" must not silently succeed. The attempt is still logged,
    // which is what plan AC61 counts — an attempted write is a write for
    // accounting purposes.
    let blob = common::blob("sk-ant-oat01-refused", "sk-ant-ort01-refused", common::fresh_at());
    let mut fixture = Fixture::new();
    fixture.with_keychain();
    let line = common::keychain_write_line("example", LIVE_SERVICE, &blob);

    let output = fixture.security_write(&line);
    assert_eq!(output.code(), 1, "an unregistered service is refused");
    assert!(output.stderr.starts_with("security:"), "{}", output.stderr);
    assert!(output.stderr.contains("not registered with this stand-in"), "{}", output.stderr);
    assert!(!fixture.keychain_item_path(LIVE_SERVICE).exists(), "a refused write stores nothing");
    assert!(
        fixture.security_log().iter().any(|line| line.starts_with("add-generic-password")),
        "the attempt is on the record"
    );
}

#[test]
fn ac61_what_the_write_path_stores_is_what_the_binary_reads() {
    // The round trip, with the shipped binary on the reading end: an item this
    // suite created through the write transport is one `agctl` finds,
    // reads and parses. It is also the assertion that the *binary* issued no
    // write of its own — the write came from this test, and every line the
    // binary added afterwards is a read.
    const SERVICE: &str = "Claude Code-credentials-11112222";
    const ACCT: &str = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
    const ORG: &str = "cccccccc-3333-4333-8333-cccccccccccc";

    let fixture = writable(SERVICE);
    let blob = common::identified_blob(
        "sk-ant-oat01-round-trip",
        "sk-ant-ort01-round-trip",
        common::fresh_at(),
        ACCT,
        Some(ORG),
    );

    let output = fixture.security_write(&common::keychain_write_line("example", SERVICE, &blob));
    assert_eq!(output.code(), 0, "stderr: {}", output.stderr);
    let after_write = fixture.security_log().len();

    fixture
        .cmd()
        .args(["claude", "import", "--from", "keychain", "--dry-run"])
        .assert()
        .success()
        .stdout(contains(ACCT))
        .stdout(contains("imported 1"));

    for line in logged_after(&fixture, after_write) {
        let token = line.split_whitespace().next().unwrap_or_default();
        assert!(
            READ_ONLY_SUBCOMMANDS.contains(&token),
            "the binary itself issued `security {token}`; no command calls the write path in W2: \
             {line}"
        );
    }
}

#[test]
fn ac61_the_aggregate_log_holds_one_write_per_named_test_and_no_delete() {
    // Plan AC61. Two halves, and they are asserted differently on purpose.
    //
    // The **delete** half is genuinely suite-wide: every keychain-using test
    // appends its calls to one per-run log, so a delete anywhere in the run
    // shows up here.
    //
    // The **count** half is driven from this test rather than accumulated
    // across the named tests, because nextest gives no ordering guarantee
    // across processes: a count that waited for other test processes to finish
    // would be a flake, and one that tolerated their absence would not be a
    // count. So this test performs exactly one write per name in
    // `KEYCHAIN_WRITE_TESTS` and then requires the aggregate to hold exactly
    // that many — which still fails if any other test wrote, because that
    // write would push the count over. The named tests assert their own
    // behaviour against their own logs.
    let blob = common::blob("sk-ant-oat01-counted", "sk-ant-ort01-counted", common::fresh_at());
    let fixture = writable(LIVE_SERVICE);
    for name in KEYCHAIN_WRITE_TESTS {
        let output =
            fixture.security_write(&common::keychain_write_line(name, LIVE_SERVICE, &blob));
        assert_eq!(output.code(), 0, "`{name}`: {}", output.stderr);
    }
    common::record_keychain_calls(&fixture.security_log());

    let aggregate = fs::read_to_string(common::aggregate_log_path()).unwrap_or_default();
    let writes = aggregate.lines().filter(|line| line.starts_with("add-generic-password")).count();
    assert_eq!(
        writes,
        KEYCHAIN_WRITE_TESTS.len(),
        "one write per named test, and nothing else in the suite may write: {aggregate}"
    );
    assert!(writes > 0, "a count of zero would mean the write path did nothing at all");
    assert_eq!(
        aggregate.lines().filter(|line| line.contains("delete-generic-password")).count(),
        0,
        "agctl issues no delete anywhere (fact F43, invariant I1′): {aggregate}"
    );
    assert!(
        !aggregate.contains("sk-ant-"),
        "and no line in the whole run carries token material: {aggregate}"
    );
}
