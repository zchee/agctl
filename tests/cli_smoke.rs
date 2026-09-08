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
///
/// `CARGO_BIN_EXE_agentctl` — the path cargo built for *this* test target —
/// rather than `assert_cmd`'s `cargo_bin`, which guesses
/// `<manifest>/target/debug/agentctl`. This project builds into a tmpfs target
/// directory (`~/.config/rust/config.dev.toml`), so that guess finds whatever
/// a bare `cargo build` happened to leave in the worktree: on this machine a
/// binary from an earlier build, of a different size, from different sources.
/// A smoke test asserting against a stale artifact is worse than no smoke test.
fn agentctl() -> Command {
    Command::new(env!("CARGO_BIN_EXE_agentctl"))
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
fn watch_refuses_an_interval_below_the_polling_floor() {
    // This was `an_unimplemented_command_exits_one_and_says_so`, which used
    // `watch` as the last command that had not been built. W3 built it, so the
    // assertion it replaces is no longer true of any command. What `watch` can
    // still be asked to do from outside a terminal is refuse: the polling floor
    // is enforced by the parser, before the process goes anywhere near raw mode
    // (plan AC13).
    agentctl()
        .args(["claude", "watch", "--interval", "30s"])
        .assert()
        .failure()
        .stderr(contains("60s floor"));
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
fn status_json_writes_only_the_document_to_stdout() {
    // Plan section 3.2: `--json` keeps the same exit codes as the table — this
    // store has one degraded row, so 2 — and stdout carries the document and
    // nothing else, which is what lets a caller pipe it straight into a
    // parser. The log line about the unreadable keychain is on stderr.
    let (mut command, _dir) = isolated();
    let assert = command.args(["claude", "status", "--json"]).assert().code(2);
    let stdout =
        String::from_utf8(assert.get_output().stdout.clone()).expect("the document is valid UTF-8");

    let document: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("stdout is one JSON document: {err}\n{stdout}"));
    assert_eq!(document["version"], serde_json::json!(1));
    assert!(document["rows"].is_array(), "{document}");
    assert!(document.get("raw").is_none(), "`raw` is absent without --raw");
    assert!(!stdout.contains("sk-ant-"), "no token material reaches stdout");
}

#[test]
fn doctor_reports_on_an_isolated_store() {
    // Plan AC45, from outside the process: the report runs against a store
    // with nothing in it and still says what it looked at.
    let (mut command, _dir) = isolated();
    command
        .args(["claude", "doctor"])
        .assert()
        .success()
        .stdout(contains("namespace root"))
        .stdout(contains("namespace locks"));
}

#[test]
fn accounts_list_renders_its_own_columns() {
    let (mut command, _dir) = isolated();
    command
        .args(["claude", "accounts", "list"])
        .assert()
        .success()
        .stdout(contains("Kind"))
        .stdout(contains("Source"))
        .stdout(contains("Location"));
}

#[test]
fn accounts_remove_refuses_an_id_it_does_not_know() {
    let (mut command, _dir) = isolated();
    command
        .args(["claude", "accounts", "remove", "nobody@example.com"])
        .assert()
        .code(1)
        .stderr(contains("nobody@example.com"));
}

#[test]
fn doctor_remove_stale_refuses_a_path_outside_the_store() {
    // Invariant I11, from outside the process: the live store's own lock is
    // the path a user is most likely to try, and it is exactly the one this
    // command must not touch. Exit 1, not 2: the run removed nothing and
    // rendered nothing, and 2 means a table was printed with a degraded row
    // in it.
    let (mut command, dir) = isolated();
    let outside = dir.path().join(".claude").join(".oauth_refresh.lock");
    std::fs::create_dir_all(dir.path().join(".claude")).expect("creatable");
    std::fs::write(&outside, "{}").expect("writable");
    command
        .args(["claude", "doctor", "--remove-stale", &outside.to_string_lossy(), "--yes"])
        .assert()
        .code(1)
        .stderr(contains("not inside"));
    assert!(outside.exists(), "the live store's lock is untouched");
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
