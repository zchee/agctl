#![cfg(feature = "testing")]

//! Plan AC25, stated as one assertion: **phase 1 never writes or deletes a
//! keychain item.**
//!
//! Invariant I1 says there is no code path that could, and the type system
//! backs that up — `KeychainReader` has no write method, and adding one is a
//! phase-2 decision rather than an implementation detail. This file is the
//! empirical half of the same claim: the fake `security(1)` records every
//! invocation it receives, every keychain-using test in the suite contributes
//! its own log to a shared file, and what follows reads that file back.
//!
//! A subcommand outside the three read-only ones appearing here would mean a
//! write path exists and was taken, whatever the type system says.

mod common;

use std::fs;

use common::Fixture;
use common::LIVE_SERVICE;

/// The only `security(1)` subcommands phase 1 has any business issuing.
const READ_ONLY_SUBCOMMANDS: [&str; 3] =
    ["show-keychain-info", "find-generic-password", "dump-keychain"];

/// Subcommands whose presence would mean the keychain was mutated.
///
/// Listed explicitly as well as excluded by the allowlist, so a failure names
/// what happened rather than only that something did.
const MUTATING_SUBCOMMANDS: [&str; 5] = [
    "add-generic-password",
    "delete-generic-password",
    "set-generic-password-partition-list",
    "unlock-keychain",
    "import",
];

#[test]
fn ac25_no_test_in_the_suite_ever_mutates_the_keychain() {
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
        let subcommand = line.split_whitespace().next().unwrap_or_default();
        assert!(
            READ_ONLY_SUBCOMMANDS.contains(&subcommand),
            "the suite issued `security {subcommand}`, which phase 1 has no code path for \
             (plan invariant I1, AC25); full argv: {line}"
        );
        for mutating in MUTATING_SUBCOMMANDS {
            assert!(
                !line.contains(mutating),
                "the suite issued a mutating `security` call: {line}"
            );
        }
    }
}

#[test]
fn ac25_the_stand_in_refuses_a_write_subcommand_outright() {
    // The other side of the same claim: if agentctl ever did try to write, the
    // stand-in would fail rather than pretend, so a regression could not pass
    // by being silently tolerated. Asserted by running the script directly —
    // the one place in the suite where a mutating argv is deliberately issued.
    let fixture = Fixture::new();
    let script = fixture.scratch("bin").join("security");
    fs::create_dir_all(script.parent().expect("a parent")).expect("creatable");
    fs::write(&script, common::FAKE_SECURITY).expect("the script should be writable");
    let mut permissions = fs::metadata(&script).expect("stat-able").permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
    fs::set_permissions(&script, permissions).expect("chmod");

    let output = std::process::Command::new(&script)
        .args(["add-generic-password", "-U", "-s", "Claude Code-credentials"])
        .output()
        .expect("the stand-in should be runnable");

    assert_eq!(output.status.code(), Some(1), "a write subcommand is not implemented");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("read subcommands only"),
        "and it says so: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
