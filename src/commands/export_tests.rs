//! Tests for `spec_for`, `render_env` and `exec_command` (plan AC50–AC52).

use std::os::unix::fs::PermissionsExt;
use std::time::Instant;

use tempfile::TempDir;

use super::*;
use crate::commands::isolate::SessionDir;
use crate::config::AccountKind;

const ACCT: &str = "11111111-2222-3333-4444-555555555555";
const ORG: &str = "66666666-7777-8888-9999-000000000000";

fn owned(spelling: &str, sha8: &str) -> AccountRecord {
    crate::config::new_record(
        ACCT.to_owned(),
        ORG.to_owned(),
        AccountKind::Owned { export_spelling: spelling.to_owned(), export_sha8: sha8.to_owned() },
    )
    .expect("the fixture identifiers are valid")
}

fn session(path: &str, mcp: Option<&str>) -> SessionDir {
    SessionDir {
        path: PathBuf::from(path),
        mcp_config: mcp.map(PathBuf::from),
        linked: Vec::new(),
        missing: Vec::new(),
        already_linked: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// spec_for (AC50)
// ---------------------------------------------------------------------------

#[test]
fn spec_for_succeeds_when_the_hash_matches() {
    let spelling = "/home/example/.claude";
    let sha8 = namespace::sha8(spelling);
    let rec = owned(spelling, &sha8);
    let session = session("/session/dir", Some("/session/dir/mcp.json"));
    let paths = Paths::with_config_dir(PathBuf::from("/store"));

    let spec = spec_for(&paths, &rec, &session).expect("matching hash should succeed");
    assert_eq!(spec.securestorage_dir, spelling);
    assert_eq!(spec.config_dir, PathBuf::from("/session/dir"));
    assert_eq!(spec.mcp_config, Some(PathBuf::from("/session/dir/mcp.json")));
}

#[test]
fn spec_for_refuses_a_mismatched_hash() {
    let rec = owned("/home/example/.claude", "deadbeef");
    let session = session("/session/dir", None);
    let paths = Paths::with_config_dir(PathBuf::from("/store"));

    let err = spec_for(&paths, &rec, &session).expect_err("a wrong hash should be refused");
    assert!(matches!(err, AppError::Config(_)));
}

#[test]
fn spec_for_refuses_empty_spelling_or_hash() {
    let rec = owned("", "");
    let session = session("/session/dir", None);
    let paths = Paths::with_config_dir(PathBuf::from("/store"));

    let err = spec_for(&paths, &rec, &session).expect_err("empty fields should be refused");
    assert!(matches!(err, AppError::Config(_)));
}

#[test]
fn spec_for_refuses_non_owned_accounts() {
    let session = session("/session/dir", None);
    let paths = Paths::with_config_dir(PathBuf::from("/store"));

    for kind in [
        AccountKind::Live,
        AccountKind::ConfigDirReadOnly {
            dir: PathBuf::from("/other"),
            service: "Claude Code-credentials-aaaaaaaa".to_owned(),
            shares_live_dir: false,
        },
    ] {
        let rec = crate::config::new_record(ACCT.to_owned(), ORG.to_owned(), kind)
            .expect("the fixture identifiers are valid");
        let err = spec_for(&paths, &rec, &session).expect_err("a read-only kind has no export");
        assert!(matches!(err, AppError::Config(_)));
    }
}

// ---------------------------------------------------------------------------
// render_env (AC51)
// ---------------------------------------------------------------------------

fn spec_with_mcp() -> ExportSpec {
    ExportSpec {
        securestorage_dir: "/ns/spelling".to_owned(),
        config_dir: PathBuf::from("/session/dir"),
        mcp_config: Some(PathBuf::from("/session/dir/mcp.json")),
    }
}

fn spec_without_mcp() -> ExportSpec {
    ExportSpec {
        securestorage_dir: "/ns/spelling".to_owned(),
        config_dir: PathBuf::from("/session/dir"),
        mcp_config: None,
    }
}

#[test]
fn render_env_zsh_and_bash_match_the_golden_string() {
    let expected = "export CLAUDE_SECURESTORAGE_CONFIG_DIR='/ns/spelling'\n\
                     export CLAUDE_CONFIG_DIR='/session/dir'\n\
                     # CLAUDE_CODE_OAUTH_TOKEN would bypass this session's stored credential (fact F19)\n\
                     unset CLAUDE_CODE_OAUTH_TOKEN\n\
                     alias claude='claude --mcp-config '\\''/session/dir/mcp.json'\\'''\n\
                     # an alias only reaches an interactive shell; a script started from one \
                     will not inherit it";
    assert_eq!(render_env(&spec_with_mcp(), Shell::Zsh), expected);
    assert_eq!(render_env(&spec_with_mcp(), Shell::Bash), expected);
}

#[test]
fn render_env_fish_matches_the_golden_string() {
    let expected = "set -gx CLAUDE_SECURESTORAGE_CONFIG_DIR '/ns/spelling'\n\
                     set -gx CLAUDE_CONFIG_DIR '/session/dir'\n\
                     # CLAUDE_CODE_OAUTH_TOKEN would bypass this session's stored credential (fact F19)\n\
                     set -e CLAUDE_CODE_OAUTH_TOKEN\n\
                     function claude\n    command claude --mcp-config '/session/dir/mcp.json' $argv\nend\n\
                     # a fish function only reaches an interactive shell; a script started from \
                     one will not inherit it";
    assert_eq!(render_env(&spec_with_mcp(), Shell::Fish), expected);
}

#[test]
fn render_env_omits_the_alias_without_mcp() {
    let expected = "export CLAUDE_SECURESTORAGE_CONFIG_DIR='/ns/spelling'\n\
                     export CLAUDE_CONFIG_DIR='/session/dir'\n\
                     # CLAUDE_CODE_OAUTH_TOKEN would bypass this session's stored credential (fact F19)\n\
                     unset CLAUDE_CODE_OAUTH_TOKEN";
    assert_eq!(render_env(&spec_without_mcp(), Shell::Zsh), expected);
    assert!(!render_env(&spec_without_mcp(), Shell::Zsh).contains("alias"));
}

#[test]
fn render_env_single_quotes_survive_an_embedded_quote() {
    let spec = ExportSpec {
        securestorage_dir: "/it's/here".to_owned(),
        config_dir: PathBuf::from("/session/dir"),
        mcp_config: None,
    };
    assert_eq!(
        render_env(&spec, Shell::Zsh).lines().next().unwrap(),
        "export CLAUDE_SECURESTORAGE_CONFIG_DIR='/it'\\''s/here'"
    );
    assert_eq!(
        render_env(&spec, Shell::Fish).lines().next().unwrap(),
        "set -gx CLAUDE_SECURESTORAGE_CONFIG_DIR '/it\\'s/here'"
    );
}

/// P1-2: an `mcp.json` path carrying both a `'` and a `$(id)` must never let
/// a re-parse of the alias/function body execute anything. AC51's
/// "single-quoted" clause is proved two ways: an exact-string assertion on
/// the whole rendering (all three shells), and a real shell actually
/// expanding the alias and observing the literal path arrive at the child
/// — never the output of `id`.
#[test]
fn render_env_single_quotes_survive_an_embedded_quote_and_a_command_substitution() {
    let mcp_path = "/it's/$(id)/mcp.json";
    let spec = ExportSpec {
        securestorage_dir: "/ns/spelling".to_owned(),
        config_dir: PathBuf::from("/session/dir"),
        mcp_config: Some(PathBuf::from(mcp_path)),
    };

    let expected_inner = format!("claude --mcp-config {}", quote_posix(mcp_path));
    let expected_alias = format!("alias claude={}", quote_posix(&expected_inner));
    let zsh = render_env(&spec, Shell::Zsh);
    let alias_line =
        zsh.lines().find(|line| line.starts_with("alias claude=")).expect("alias present");
    assert_eq!(alias_line, expected_alias, "the whole alias body must be single-quoted");
    assert!(!alias_line.contains("\"$("), "no path segment may sit in re-parsable double quotes");
    assert_eq!(render_env(&spec, Shell::Bash), zsh, "zsh and bash share the same rendering");

    let fish = render_env(&spec, Shell::Fish);
    let expected_function_line =
        format!("    command claude --mcp-config {} $argv", quote_fish(mcp_path));
    assert!(
        fish.lines().any(|line| line == expected_function_line),
        "fish's function body must single-quote the path: {fish}"
    );

    // The real-shell proof: a fake `claude` on `PATH` records its own argv;
    // `bash` sources the rendered environment with alias expansion turned
    // on (as an interactive shell has it by default) and then types
    // `claude`, exactly as a user would.
    let dir = TempDir::new().expect("a temporary directory should be available");
    let argv_log = dir.path().join("argv.log");
    write_argv_capture_script(dir.path(), "claude", &argv_log);

    let script = format!("shopt -s expand_aliases\n{zsh}\nclaude\n");
    let output = std::process::Command::new("/bin/bash")
        .env(
            "PATH",
            format!("{}:{}", dir.path().display(), std::env::var("PATH").unwrap_or_default()),
        )
        .args(["-c", &script])
        .output()
        .expect("`/bin/bash` should be runnable");
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(
        std::fs::read_to_string(&argv_log).expect("the argv log should exist"),
        format!("--mcp-config\n{mcp_path}\n"),
        "the alias must expand to the literal path, never execute the embedded $(id)"
    );
}

// ---------------------------------------------------------------------------
// exec_command (AC52)
// ---------------------------------------------------------------------------

fn ctx() -> PassCtx {
    standalone_ctx(&Cancel::new())
}

#[test]
fn exec_command_sets_exactly_the_two_variables() {
    let dir = TempDir::new().expect("a temporary directory should be available");
    let out = dir.path().join("out.txt");
    let spec = ExportSpec {
        securestorage_dir: "/ns/spelling".to_owned(),
        config_dir: PathBuf::from("/session/dir"),
        mcp_config: None,
    };
    let argv = vec![
        OsString::from("/bin/sh"),
        OsString::from("-c"),
        OsString::from(format!(
            "printf '%s|%s' \"$CLAUDE_SECURESTORAGE_CONFIG_DIR\" \"$CLAUDE_CONFIG_DIR\" > {}",
            out.display()
        )),
    ];

    let cancel = Cancel::new();
    let status = exec_command(&spec, &argv, &ctx(), &cancel).expect("the child should run");
    assert!(status.success());
    let content = std::fs::read_to_string(&out).expect("the child should have written the file");
    assert_eq!(content, "/ns/spelling|/session/dir");
}

/// Writes a script that records its own argv, one entry per line, to
/// `out_file`, overwriting it on each invocation.
fn write_argv_capture_script(
    dir: &std::path::Path,
    name: &str,
    out_file: &std::path::Path,
) -> PathBuf {
    let path = dir.join(name);
    let script = format!(
        "#!/bin/sh\n: > \"{o}\"\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> \"{o}\"; done\n",
        o = out_file.display()
    );
    std::fs::write(&path, script).expect("the script should be writable");
    let mut perms = std::fs::metadata(&path).expect("the script should exist").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).expect("the script should be executable");
    path
}

#[test]
fn exec_command_appends_mcp_config_only_when_argv0_basename_is_claude() {
    let dir = TempDir::new().expect("a temporary directory should be available");
    let out = dir.path().join("argv.txt");
    let mcp = dir.path().join("mcp.json");

    let claude_script = write_argv_capture_script(dir.path(), "claude", &out);
    let spec = ExportSpec {
        securestorage_dir: "/ns".to_owned(),
        config_dir: PathBuf::from("/session"),
        mcp_config: Some(mcp.clone()),
    };
    let cancel = Cancel::new();
    exec_command(&spec, &[claude_script.into_os_string()], &ctx(), &cancel)
        .expect("the child should run");
    let recorded = std::fs::read_to_string(&out).expect("the argv file should exist");
    assert_eq!(recorded, format!("--mcp-config\n{}\n", mcp.display()));

    let other_script = write_argv_capture_script(dir.path(), "notclaude", &out);
    exec_command(&spec, &[other_script.into_os_string()], &ctx(), &cancel)
        .expect("the child should run");
    let recorded = std::fs::read_to_string(&out).expect("the argv file should exist");
    assert_eq!(recorded, "", "a command that is not `claude` must not receive the flag");
}

#[test]
fn exec_command_refuses_an_empty_argv() {
    let spec = spec_without_mcp();
    let cancel = Cancel::new();
    let err = exec_command(&spec, &[], &ctx(), &cancel).expect_err("an empty argv is refused");
    assert!(matches!(err, AppError::Config(_)));
}

#[test]
fn exec_command_refuses_when_already_cancelled() {
    let spec = spec_without_mcp();
    let cancel = Cancel::new();
    cancel.cancel();
    let err = exec_command(&spec, &[OsString::from("/bin/true")], &ctx(), &cancel)
        .expect_err("a cancelled run must not start the child");
    assert!(matches!(err, AppError::Refused { .. }));
}

#[test]
fn exit_code_of_returns_the_exact_exit_code() {
    let status = std::process::Command::new("/bin/sh")
        .args(["-c", "exit 7"])
        .status()
        .expect("`/bin/sh` should be runnable");
    assert_eq!(exit_code_of(status), 7);
}

#[test]
fn exit_code_of_maps_a_signal_death_to_128_plus_signal() {
    let mut child = std::process::Command::new("/bin/sh")
        .args(["-c", "kill -TERM $$; sleep 5"])
        .spawn()
        .expect("`/bin/sh` should be runnable");
    let status = child.wait().expect("the child should be waitable");
    assert_eq!(exit_code_of(status), 128 + 15);
}

#[test]
fn standalone_ctx_produces_a_usable_context() {
    let ctx = standalone_ctx(&Cancel::new());
    assert!(ctx.deadline() > Instant::now());
}
