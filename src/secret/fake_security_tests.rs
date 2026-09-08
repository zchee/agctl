//! Tests for the `security(1)` stand-in itself.
//!
//! A test double that lies is worse than no double, and this one is shared by
//! three test layers, so its behaviour is pinned here rather than assumed by
//! each of them.

use std::process::Command;

use tempfile::TempDir;

use super::*;

fn script() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("a temporary directory should be available");
    let path = write_fake_security(dir.path()).expect("the script should be writable");
    (dir, path)
}

fn run(script: &Path, env: &[(&str, &str)], args: &[&str]) -> std::process::Output {
    let mut command = Command::new(script);
    command.args(args);
    for (name, value) in env {
        command.env(name, value);
    }
    command.output().unwrap_or_else(|err| panic!("the script should run: {err}"))
}

#[test]
fn the_script_is_executable() {
    use std::os::unix::fs::PermissionsExt;

    let (_dir, path) = script();
    let mode = std::fs::metadata(&path).expect("the script exists").permissions().mode();
    assert_eq!(mode & 0o111, 0o111, "mode {mode:o}");
}

#[test]
fn show_keychain_info_exits_zero_by_default_and_honours_an_override() {
    let (_dir, path) = script();
    assert_eq!(run(&path, &[], &["show-keychain-info"]).status.code(), Some(0));
    assert_eq!(
        run(&path, &[("AGENTCTL_FAKE_SECURITY_PREFLIGHT_EXIT", "36")], &["show-keychain-info"])
            .status
            .code(),
        Some(36)
    );
}

#[test]
fn a_missing_item_exits_44_with_the_real_tool_s_message() {
    let (_dir, path) = script();
    let output = run(&path, &[], &["find-generic-password", "-a", "u", "-w", "-s", "absent"]);
    assert_eq!(output.status.code(), Some(44));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(crate::secret::classify_stderr(&stderr), crate::secret::StderrClass::ItemNotFound);
}

#[test]
fn an_item_is_served_from_the_items_directory() {
    let (dir, path) = script();
    let items = dir.path().join("items");
    write_item(&items, "Claude Code-credentials", b"blob-bytes").expect("writable");

    let output = run(
        &path,
        &[("AGENTCTL_FAKE_SECURITY_ITEMS", &items.to_string_lossy())],
        &["find-generic-password", "-a", "u", "-w", "-s", "Claude Code-credentials"],
    );
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"blob-bytes");
}

#[test]
fn every_mutating_subcommand_is_refused() {
    // The whole point of the double: there is no code path, real or faked,
    // that changes a keychain (invariant I1). The script implements exactly
    // three read subcommands and refuses everything else, so a future writer
    // would fail loudly in the tests before it ever ran against a real
    // keychain.
    //
    // The two item-mutating subcommand names are deliberately not spelled
    // anywhere in `src/`: the gate greps for them, and that grep should stay
    // empty rather than needing a reader to work out that the match is only
    // a test.
    let (_dir, path) = script();
    for subcommand in ["set-keychain-password", "unlock-keychain", "import", "create-keychain"] {
        let output = run(&path, &[], &[subcommand, "-s", "anything"]);
        assert_eq!(output.status.code(), Some(1), "`{subcommand}` should be refused");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("read subcommands only"), "{stderr}");
    }
}

#[test]
fn the_argv_log_records_one_line_per_invocation() {
    let (dir, path) = script();
    let log = dir.path().join("argv.log");
    let env = [("AGENTCTL_FAKE_SECURITY_LOG", log.to_string_lossy().into_owned())];
    let env: Vec<(&str, &str)> = env.iter().map(|(n, v)| (*n, v.as_str())).collect();

    run(&path, &env, &["show-keychain-info"]);
    run(&path, &env, &["find-generic-password", "-a", "u", "-w", "-s", "svc"]);

    let logged = std::fs::read_to_string(&log).expect("the log should exist");
    assert_eq!(logged.lines().count(), 2);
    assert_eq!(logged.lines().next(), Some("show-keychain-info"));
    assert!(logged.lines().nth(1).is_some_and(|line| line.contains("-s svc")));
}

#[test]
fn the_item_file_name_fold_matches_the_shell_s() {
    // The Rust helper and the script's `tr` must agree, or a test writes an
    // item the script cannot find and silently exercises the absent path.
    let (dir, path) = script();
    let items = dir.path().join("items");
    for service in [
        "Claude Code-credentials",
        "claude-switcher:user@example.com",
        "Claude Code-credentials-5cdc535f",
    ] {
        write_item(&items, service, service.as_bytes()).expect("writable");
        let output = run(
            &path,
            &[("AGENTCTL_FAKE_SECURITY_ITEMS", &items.to_string_lossy())],
            &["find-generic-password", "-a", "u", "-w", "-s", service],
        );
        assert_eq!(output.status.code(), Some(0), "`{service}` should be found");
        assert_eq!(output.stdout, service.as_bytes());
    }
}

#[test]
fn item_file_name_folds_every_awkward_character() {
    assert_eq!(item_file_name("Claude Code-credentials"), "Claude_Code-credentials");
    assert_eq!(item_file_name("claude-switcher:a@b.com"), "claude-switcher_a_b.com");
    assert_eq!(item_file_name("../escape"), ".._escape");
}
