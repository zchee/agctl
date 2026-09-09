#![cfg(feature = "testing")]

//! `doctor`'s isolation section, driven through the real binary (plan AC58).
//!
//! Like `tests/e2e_isolate.rs`, these only exercise the session-directory
//! half of the store: no test here installs the fake `security(1)`, and every
//! session directory a test needs beyond what S15's `env` already creates is
//! built by hand with plain filesystem calls, so these run regardless of
//! whether S16's seeding has landed.

mod common;

use std::fs;
use std::os::unix::fs::symlink;

use common::ACCT;
use common::Fixture;
use common::ORG;
use serde_json::json;

/// An isolated store with one owned account, a live `.claude.json`, and the
/// session directory `env` creates: the directory, the D-019 `mcp.json`
/// symlink, and a seed carrying only the floor key, because the live file
/// here has no tier-1 entries and none of the seed keys.
fn store_with_session() -> Fixture {
    let fixture = Fixture::new();
    fixture.write_registry(vec![fixture.owned_record(ACCT, ORG)]);
    fs::write(fixture.home().join(".claude.json"), json!({"mcpServers": {}}).to_string())
        .expect("the live `.claude.json` fixture should be writable");
    fixture.cmd().args(["claude", "env", ACCT]).assert().success();
    fixture
}

#[test]
fn ac58_the_isolation_section_reports_a_minimal_session() {
    let fixture = store_with_session();

    let output =
        fixture.cmd().args(["claude", "doctor"]).output().expect("`claude doctor` should run");
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("isolation"), "{stdout}");
    assert!(stdout.contains(&format!("id={ACCT}")), "{stdout}");
    assert!(stdout.contains("sha8_match=true"), "{stdout}");
    assert!(stdout.contains("mcp.json"), "{stdout}");
    assert!(stdout.contains("linked"), "the D-019 symlink S15 placed is reported:\n{stdout}");
    assert!(
        stdout.contains("hasCompletedOnboarding"),
        "the seed carries only the floor key when the live file has none:\n{stdout}"
    );
    assert!(stdout.contains("leaked keys      none"), "{stdout}");
    assert!(stdout.contains("agentctl claude use --forget"), "{stdout}");
    assert!(stdout.contains("policySettings.disableSideloadFlags"), "{stdout}");
    assert!(stdout.contains("secure-storage backend"), "{stdout}");
}

#[test]
fn ac58_the_isolation_section_flags_a_hand_seeded_leak_and_an_occupied_path() {
    let fixture = store_with_session();
    let session_dir = fixture.session_dir(ACCT, ORG);

    // Hand-build a partially seeded state: one tier1 symlink placed
    // correctly, one occupied by something agentctl did not put there, and a
    // seed file carrying a key that must never be seeded (plan AC54's leak
    // vocabulary, also `doctor`'s).
    let live_settings = fixture.home().join(".claude").join("settings.json");
    fs::create_dir_all(live_settings.parent().expect("the live settings path has a parent"))
        .expect("the live config dir should be creatable");
    fs::write(&live_settings, "{}").expect("the live settings file should be writable");
    symlink(&live_settings, session_dir.join("settings.json"))
        .expect("the tier1 symlink should be creatable");
    fs::write(session_dir.join("CLAUDE.md"), "not agentctl's")
        .expect("the occupying file should be writable");

    fs::write(
        session_dir.join(".claude.json"),
        json!({"theme": "dark", "oauthAccount": {"uuid": "leaked"}}).to_string(),
    )
    .expect("the seed fixture should be writable");

    let output =
        fixture.cmd().args(["claude", "doctor"]).output().expect("`claude doctor` should run");
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("settings.json"), "{stdout}");
    assert!(stdout.contains("occupied"), "CLAUDE.md is not agentctl's symlink:\n{stdout}");
    assert!(stdout.contains("oauthAccount"), "the leaked key is named:\n{stdout}");
    assert!(stdout.contains("leaked keys"), "{stdout}");
    assert!(
        !stdout.contains("\"leaked\""),
        "no leaked value is printed, only the key name:\n{stdout}"
    );
}

#[test]
fn ac58_the_isolation_section_says_the_root_is_empty_with_no_sessions() {
    let fixture = Fixture::new();

    let output =
        fixture.cmd().args(["claude", "doctor"]).output().expect("`claude doctor` should run");
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("has no isolated sessions"), "{stdout}");
}
