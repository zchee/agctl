#![cfg(feature = "testing")]

//! End-to-end smoke tests over the built binary.
//!
//! These run the real executable through `assert_cmd`, so they exercise
//! argument parsing, the exit-status mapping and stderr rendering exactly as a
//! user meets them. The suite is gated on the `testing` feature; see
//! `tests/feature_guard.rs` for why the guard lives in its own file.
//!
//! Nothing here touches the keychain, `~/.claude`, or any real credential:
//! every command exercised either fails at parse time or reaches an
//! unimplemented dispatch arm.

use assert_cmd::Command;
use predicates::str::contains;

/// The binary under test.
fn agentctl() -> Command {
    Command::cargo_bin("agentctl").expect("the `agentctl` binary should be built")
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
    // Until W1 lands, `status` must fail loudly rather than exit 0 having done
    // nothing at all.
    agentctl().args(["claude", "status"]).assert().code(1).stderr(contains("not implemented"));
}

#[test]
fn an_unknown_subcommand_is_rejected() {
    agentctl().args(["claude", "bogus"]).assert().failure();
}
