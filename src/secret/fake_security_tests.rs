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
fn every_mutating_subcommand_but_the_one_transport_is_refused() {
    // The double implements the three read subcommands and the one write
    // transport agentctl has — argv `-i`, payload on stdin (fact F42) — and
    // refuses everything else, so a code path that grew a second way to
    // change a keychain would fail loudly in the tests before it ever ran
    // against a real one.
    //
    // The item-mutating subcommand names are deliberately not spelled in
    // `src/` outside the write transport's own module: the gate greps for
    // them, and those greps should stay at their expected counts rather than
    // needing a reader to work out that a match is only a test.
    let (_dir, path) = script();
    for subcommand in ["set-keychain-password", "unlock-keychain", "import", "create-keychain"] {
        let output = run(&path, &[], &[subcommand, "-s", "anything"]);
        assert_eq!(output.status.code(), Some(1), "`{subcommand}` should be refused");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("read subcommands and -i only"), "{stderr}");
    }
}

/// Runs the script with `stdin` on its standard input.
fn run_with_stdin(
    script: &Path,
    env: &[(&str, &str)],
    args: &[&str],
    stdin: &str,
) -> std::process::Output {
    use std::io::Write;

    let mut command = Command::new(script);
    command.args(args);
    for (name, value) in env {
        command.env(name, value);
    }
    command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = command.spawn().expect("the script should start");
    {
        let pipe = child.stdin.as_mut().expect("stdin was piped");
        pipe.write_all(stdin.as_bytes()).expect("the line should be writable");
    }
    drop(child.stdin.take());
    child.wait_with_output().expect("the script should finish")
}

/// Fact F42's line for a blob, with the values quoted as the crate quotes
/// them.
fn write_line(account: &str, service: &str, blob: &[u8]) -> String {
    format!(
        "add-generic-password -U -a \"{account}\" -s \"{service}\" -X \"{}\"\n",
        hex::encode(blob)
    )
}

#[test]
fn the_write_path_stores_the_decoded_blob_and_redacts_the_log() {
    let (dir, path) = script();
    let items = dir.path().join("items");
    let log = dir.path().join("argv.log");
    allow_service(&items, "Claude Code-credentials").expect("registrable");
    let env = [
        ("AGENTCTL_FAKE_SECURITY_ITEMS", items.to_string_lossy().into_owned()),
        ("AGENTCTL_FAKE_SECURITY_LOG", log.to_string_lossy().into_owned()),
    ];
    let env: Vec<(&str, &str)> = env.iter().map(|(n, v)| (*n, v.as_str())).collect();

    let blob = br#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-x"}}"#;
    let output =
        run_with_stdin(&path, &env, &["-i"], &write_line("u", "Claude Code-credentials", blob));
    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));

    let stored = std::fs::read(items.join(item_file_name("Claude Code-credentials")))
        .expect("the item should have been stored");
    assert_eq!(stored, blob, "the hex round-trips to the bytes that were sent");

    let logged = std::fs::read_to_string(&log).expect("the log should exist");
    assert_eq!(logged.lines().next(), Some("-i"), "argv carries no payload: {logged}");
    assert_eq!(
        logged.lines().nth(1),
        Some(
            format!(
                "add-generic-password -U -a \"u\" -s \"Claude Code-credentials\" -X <REDACTED:{}>",
                blob.len() * 2
            )
            .as_str()
        )
    );
    assert!(!logged.contains("sk-ant-"), "redacted at the source: {logged}");
}

#[test]
fn the_write_path_refuses_anything_but_one_recognised_line() {
    let (dir, path) = script();
    let items = dir.path().join("items");
    allow_service(&items, "Claude Code-credentials").expect("registrable");
    let env = [("AGENTCTL_FAKE_SECURITY_ITEMS", items.to_string_lossy().into_owned())];
    let env: Vec<(&str, &str)> = env.iter().map(|(n, v)| (*n, v.as_str())).collect();
    let one = write_line("u", "Claude Code-credentials", b"{}");

    let cases = [
        ("nothing at all", String::new()),
        ("two lines", format!("{one}{one}")),
        ("a second command smuggled in", format!("{}\ndelete-generic-password -s x\n", one.trim())),
        ("an unquoted line", "add-generic-password -U -a u -s svc -X 7b7d\n".to_owned()),
        ("a different subcommand", "find-generic-password -s svc\n".to_owned()),
        (
            "odd hex",
            "add-generic-password -U -a \"u\" -s \"Claude Code-credentials\" -X \"7b7\"\n"
                .to_owned(),
        ),
        (
            "hex that is not hex",
            "add-generic-password -U -a \"u\" -s \"Claude Code-credentials\" -X \"zz\"\n"
                .to_owned(),
        ),
    ];

    for (name, stdin) in cases {
        let output = run_with_stdin(&path, &env, &["-i"], &stdin);
        assert_eq!(output.status.code(), Some(1), "`{name}` should be refused");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.starts_with("security:"), "`{name}`: {stderr}");
    }
    assert!(
        !items.join(item_file_name("Claude Code-credentials")).exists(),
        "a refused line stores nothing"
    );
}

#[test]
fn the_write_path_refuses_a_service_nobody_registered() {
    let (dir, path) = script();
    let items = dir.path().join("items");
    std::fs::create_dir_all(&items).expect("creatable");
    let env = [("AGENTCTL_FAKE_SECURITY_ITEMS", items.to_string_lossy().into_owned())];
    let env: Vec<(&str, &str)> = env.iter().map(|(n, v)| (*n, v.as_str())).collect();

    let output =
        run_with_stdin(&path, &env, &["-i"], &write_line("u", "Claude Code-credentials", b"{}"));
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(crate::secret::classify_stderr(&stderr), crate::secret::StderrClass::Other);
    assert!(stderr.contains("not registered with this stand-in"), "{stderr}");
}

#[test]
fn the_write_path_honours_the_forced_exit_knob() {
    let (dir, path) = script();
    let items = dir.path().join("items");
    allow_service(&items, "Claude Code-credentials").expect("registrable");
    let env = [
        ("AGENTCTL_FAKE_SECURITY_ITEMS", items.to_string_lossy().into_owned()),
        ("AGENTCTL_FAKE_SECURITY_WRITE_EXIT", "44".to_owned()),
        ("AGENTCTL_FAKE_SECURITY_STDERR", "security: forced".to_owned()),
    ];
    let env: Vec<(&str, &str)> = env.iter().map(|(n, v)| (*n, v.as_str())).collect();

    let output =
        run_with_stdin(&path, &env, &["-i"], &write_line("u", "Claude Code-credentials", b"{}"));
    assert_eq!(output.status.code(), Some(44));
    assert!(String::from_utf8_lossy(&output.stderr).contains("forced"));
    assert!(
        !items.join(item_file_name("Claude Code-credentials")).exists(),
        "a forced failure stores nothing"
    );
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
