#![cfg(feature = "testing")]

//! End-to-end smoke tests over the built binary.
//!
//! These run the real executable through `assert_cmd`, so they exercise
//! argument parsing, the exit-status mapping and stderr rendering exactly as a
//! user meets them. The suite is gated on the `testing` feature; see
//! `tests/feature_guard.rs` for why the guard lives in its own file.
//!
//! # Nothing here touches a real credential
//!
//! Most commands exercised fail at parse time or reach an unimplemented
//! dispatch arm. `status` does neither any more, so it is run through
//! [`isolated`], which points the binary at a throwaway store and a disabled
//! keychain backend. Running it bare would read the developer's own keychain
//! item and spend a request against their live account — which is exactly
//! what plan invariant I1 and the W1 verification checks exist to prevent.

use assert_cmd::Command;
use predicates::str::contains;
use tempfile::TempDir;

/// The binary under test.
fn agentctl() -> Command {
    Command::cargo_bin("agentctl").expect("the `agentctl` binary should be built")
}

/// The binary under test, cut off from every real credential store.
///
/// The returned [`TempDir`] must be kept alive for the duration of the run:
/// dropping it removes the store the command was pointed at.
fn isolated() -> (Command, TempDir) {
    let dir = TempDir::new().expect("a temporary directory should be creatable");
    let mut command = agentctl();
    command
        .args(["--config-dir", &dir.path().join("config").to_string_lossy()])
        // `none` selects the reader whose preflight is `Unavailable`, whose
        // listing is empty and whose every read is `Ok(None)`: no `security`
        // child is ever spawned.
        .env("AGENTCTL_KEYCHAIN_BACKEND", "none")
        // An unroutable base, so a regression that fetched anyway would fail
        // loudly here rather than quietly reaching Anthropic.
        .env("AGENTCTL_CLAUDE_USAGE_URL", "http://127.0.0.1:1")
        .env("HOME", dir.path())
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("CLAUDE_SECURESTORAGE_CONFIG_DIR")
        .env_remove("CLAUDE_CODE_OAUTH_TOKEN")
        .env_remove("AGENTCTL_CONFIG_DIR");
    (command, dir)
}

#[test]
fn help_exits_zero() {
    agentctl().arg("--help").assert().success();
}

#[test]
fn version_exits_zero() {
    agentctl().arg("--version").assert().success();
}

#[test]
fn watch_below_the_interval_floor_fails_and_names_sixty() {
    // AC13, seen from outside the process.
    agentctl()
        .args(["claude", "watch", "--interval", "30s"])
        .assert()
        .failure()
        .stderr(contains("60"));
}

#[test]
fn claude_help_lists_every_subcommand() {
    agentctl()
        .args(["claude", "--help"])
        .assert()
        .success()
        .stdout(contains("status"))
        .stdout(contains("watch"))
        .stdout(contains("login"))
        .stdout(contains("accounts"))
        .stdout(contains("import"))
        .stdout(contains("doctor"));
}

#[test]
fn an_unimplemented_command_exits_one_and_says_so() {
    // A command W2 has not built yet must fail loudly rather than exit 0
    // having done nothing at all.
    agentctl().args(["claude", "doctor"]).assert().code(1).stderr(contains("not implemented"));
}

#[test]
fn status_on_an_empty_store_renders_a_table_and_reports_the_degraded_row() {
    // An unreachable keychain is a degraded row, not a fatal error: the table
    // is still printed and the exit status says which rows are missing
    // (plan section 3.3 step 5).
    let (mut command, _dir) = isolated();
    command
        .args(["claude", "status"])
        .assert()
        .code(2)
        .stdout(contains("Account"))
        .stdout(contains("Fable (weekly)"))
        .stderr(contains("could not be read"));
}

#[test]
fn status_json_says_when_it_lands_rather_than_pretending() {
    let (mut command, _dir) = isolated();
    command.args(["claude", "status", "--json"]).assert().code(1).stderr(contains("S6"));
}

#[test]
fn status_rejects_an_account_selector_that_matches_nothing() {
    let (mut command, _dir) = isolated();
    command
        .args(["claude", "status", "--account", "nobody@example.com"])
        .assert()
        .code(1)
        .stderr(contains("nobody@example.com"));
}

#[test]
fn an_unknown_subcommand_is_rejected() {
    agentctl().args(["claude", "bogus"]).assert().failure();
}
