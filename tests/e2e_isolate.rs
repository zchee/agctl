#![cfg(feature = "testing")]

//! `claude exec` and `claude env`, driven through the real binary (plan
//! AC50–AC52, and the `exec`/`env` halves of AC55).
//!
//! Every test here sets `HOME` to a temporary directory (through
//! [`Fixture::cmd`]) and never touches the real `~/.claude`. No keychain is
//! ever involved: `exec`/`env` read no credential and write none, so none of
//! these tests installs the fake `security(1)` at all.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;

use common::ACCT;
use common::Fixture;
use common::ORG;
use serde_json::json;

/// An isolated store with one owned account and a live `.claude.json` for
/// the D-019 symlink to target.
fn isolated_store() -> Fixture {
    let fixture = Fixture::new();
    fixture.write_registry(vec![fixture.owned_record(ACCT, ORG)]);
    fs::write(fixture.home().join(".claude.json"), "{}\n")
        .expect("the live `.claude.json` fixture should be writable");
    fixture
}

/// Writes a script recording its own argv, one entry per line, to
/// `out_file`, truncating it on each invocation.
fn write_argv_capture_script(dir: &Path, name: &str, out_file: &Path) -> PathBuf {
    let path = dir.join(name);
    let script = format!(
        "#!/bin/sh\n: > \"{o}\"\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> \"{o}\"; done\n",
        o = out_file.display()
    );
    fs::write(&path, script).expect("the argv-capturing script should be writable");
    let mut perms = fs::metadata(&path).expect("the script should exist").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).expect("the script should be made executable");
    path
}

// ---------------------------------------------------------------------------
// AC52 — exec's environment delta
// ---------------------------------------------------------------------------

#[test]
fn ac52_exec_delivers_exactly_the_expected_environment_delta() {
    let fixture = isolated_store();

    let output = fixture
        .cmd()
        .env("CLAUDE_CODE_OAUTH_TOKEN", "leaked-token-must-not-reach-the-child")
        .env("AGENTCTL_E2E_MARKER", "marker-value")
        .args(["claude", "exec", ACCT, "--", "/usr/bin/env"])
        .output()
        .expect("`claude exec` should run");

    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let vars: BTreeMap<String, String> = stdout
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect();

    let expected_securestorage = common::export_spelling(&fixture.ns_dir(ACCT, ORG));
    let expected_config_dir = fixture.session_dir(ACCT, ORG);

    assert_eq!(
        vars.get("CLAUDE_SECURESTORAGE_CONFIG_DIR"),
        Some(&expected_securestorage),
        "full delta: {vars:#?}"
    );
    assert_eq!(
        vars.get("CLAUDE_CONFIG_DIR"),
        Some(&expected_config_dir.to_string_lossy().into_owned()),
        "full delta: {vars:#?}"
    );
    assert!(
        !vars.contains_key("CLAUDE_CODE_OAUTH_TOKEN"),
        "the parent's token must not reach the child; full delta: {vars:#?}"
    );
    assert_eq!(
        vars.get("AGENTCTL_E2E_MARKER"),
        Some(&"marker-value".to_owned()),
        "an unrelated inherited variable must pass through unchanged"
    );
}

// ---------------------------------------------------------------------------
// AC51 — env's golden strings, one per shell
// ---------------------------------------------------------------------------

fn expected_zsh_bash_env(securestorage: &str, config_dir: &Path, mcp: &Path) -> String {
    format!(
        "export CLAUDE_SECURESTORAGE_CONFIG_DIR='{securestorage}'\n\
         export CLAUDE_CONFIG_DIR='{config}'\n\
         # CLAUDE_CODE_OAUTH_TOKEN would bypass this session's stored credential (fact F19)\n\
         unset CLAUDE_CODE_OAUTH_TOKEN\n\
         alias claude='claude --mcp-config \"{mcp}\"'\n\
         # an alias only reaches an interactive shell; a script started from one will not \
         inherit it\n",
        config = config_dir.display(),
        mcp = mcp.display(),
    )
}

fn expected_fish_env(securestorage: &str, config_dir: &Path, mcp: &Path) -> String {
    format!(
        "set -gx CLAUDE_SECURESTORAGE_CONFIG_DIR '{securestorage}'\n\
         set -gx CLAUDE_CONFIG_DIR '{config}'\n\
         # CLAUDE_CODE_OAUTH_TOKEN would bypass this session's stored credential (fact F19)\n\
         set -e CLAUDE_CODE_OAUTH_TOKEN\n\
         function claude\n    command claude --mcp-config \"{mcp}\" $argv\nend\n\
         # a fish function only reaches an interactive shell; a script started from one will \
         not inherit it\n",
        config = config_dir.display(),
        mcp = mcp.display(),
    )
}

#[test]
fn ac51_env_matches_the_golden_string_for_every_shell() {
    let fixture = isolated_store();
    let securestorage = common::export_spelling(&fixture.ns_dir(ACCT, ORG));
    let config_dir = fixture.session_dir(ACCT, ORG);
    let mcp = config_dir.join("mcp.json");

    let cases: [(&str, String); 3] = [
        ("zsh", expected_zsh_bash_env(&securestorage, &config_dir, &mcp)),
        ("bash", expected_zsh_bash_env(&securestorage, &config_dir, &mcp)),
        ("fish", expected_fish_env(&securestorage, &config_dir, &mcp)),
    ];

    for (shell, expected) in cases {
        let output = fixture
            .cmd()
            .args(["claude", "env", ACCT, "--shell", shell])
            .output()
            .unwrap_or_else(|err| panic!("`claude env --shell {shell}` should run: {err}"));
        assert!(
            output.status.success(),
            "--shell {shell} stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&output.stdout), expected, "--shell {shell}");
    }
}

#[test]
fn no_mcp_omits_the_symlink_the_flag_and_the_alias_together() {
    let fixture = isolated_store();

    let output = fixture
        .cmd()
        .args(["claude", "env", ACCT, "--no-mcp"])
        .output()
        .expect("`claude env --no-mcp` should run");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("alias"), "no alias line: {stdout}");
    assert!(!stdout.to_lowercase().contains("mcp"), "no mention of mcp at all: {stdout}");

    let bin_dir = fixture.scratch("fake-path-bin");
    fs::create_dir_all(&bin_dir).expect("the fake PATH directory should be creatable");
    let argv_log = fixture.scratch("argv.log");
    write_argv_capture_script(&bin_dir, "claude", &argv_log);

    fixture
        .cmd()
        .env("PATH", &bin_dir)
        .args(["claude", "exec", ACCT, "--no-mcp", "--", "claude"])
        .assert()
        .success();
    assert_eq!(
        fs::read_to_string(&argv_log).expect("the argv log should exist"),
        "",
        "--no-mcp must not append --mcp-config even for a command literally named `claude`"
    );

    assert!(
        !fixture.session_dir(ACCT, ORG).join("mcp.json").exists(),
        "--no-mcp must not create the symlink at all"
    );
}

// ---------------------------------------------------------------------------
// AC50 — the export refusal
// ---------------------------------------------------------------------------

#[test]
fn ac50_refuses_when_the_recorded_hash_disagrees_with_the_spelling() {
    let fixture = Fixture::new();
    let mut record = fixture.owned_record(ACCT, ORG);
    record["kind"]["export_sha8"] = json!("deadbeef");
    fixture.write_registry(vec![record]);
    fs::write(fixture.home().join(".claude.json"), "{}\n")
        .expect("the live file should be writable");

    fixture
        .cmd()
        .args(["claude", "env", ACCT])
        .assert()
        .failure()
        .code(1)
        .stderr(predicates::str::contains("deadbeef"));
}

// ---------------------------------------------------------------------------
// The `--mcp-config` argv rule
// ---------------------------------------------------------------------------

#[test]
fn mcp_config_is_appended_to_argv_only_when_the_command_is_named_claude() {
    let fixture = isolated_store();
    let bin_dir = fixture.scratch("fake-path-bin");
    fs::create_dir_all(&bin_dir).expect("the fake PATH directory should be creatable");
    let argv_log = fixture.scratch("argv.log");
    let mcp_path = fixture.session_dir(ACCT, ORG).join("mcp.json");

    write_argv_capture_script(&bin_dir, "claude", &argv_log);
    fixture
        .cmd()
        .env("PATH", &bin_dir)
        .args(["claude", "exec", ACCT, "--", "claude"])
        .assert()
        .success();
    assert_eq!(
        fs::read_to_string(&argv_log).expect("the argv log should exist"),
        format!("--mcp-config\n{}\n", mcp_path.display()),
        "a command literally named `claude` receives the flag"
    );

    write_argv_capture_script(&bin_dir, "notclaude", &argv_log);
    fixture
        .cmd()
        .env("PATH", &bin_dir)
        .args(["claude", "exec", ACCT, "--", "notclaude"])
        .assert()
        .success();
    assert_eq!(
        fs::read_to_string(&argv_log).expect("the argv log should exist"),
        "",
        "a command that is not named `claude` must not receive the flag"
    );
}

// ---------------------------------------------------------------------------
// AC55 (exec/env half) — the D-019 symlink, and nothing else
// ---------------------------------------------------------------------------

#[test]
fn ac55_the_symlink_target_is_exact_and_nothing_else_is_created() {
    let fixture = isolated_store();

    fixture.cmd().args(["claude", "exec", ACCT, "--", "/usr/bin/true"]).assert().success();

    let session_dir = fixture.session_dir(ACCT, ORG);
    let link = session_dir.join("mcp.json");
    let meta = fs::symlink_metadata(&link).expect("the symlink should exist");
    assert!(meta.file_type().is_symlink(), "mcp.json must be a symlink, not a copy");

    let target = fs::read_link(&link).expect("the symlink target should be readable");
    let expected = fs::canonicalize(fixture.home().join(".claude.json"))
        .expect("the live `.claude.json` fixture should canonicalize");
    assert_eq!(target, expected);

    let entries: Vec<String> = fs::read_dir(&session_dir)
        .expect("the session directory should exist")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        entries,
        vec!["mcp.json".to_owned()],
        "S15's skeleton creates nothing else under the session directory"
    );
}
