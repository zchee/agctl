#![cfg(feature = "testing")]

//! `claude exec`/`env`/`use --forget`, driven through the real binary (plan
//! AC50–AC57, AC79, and the `exec`/`env` halves of AC55).
//!
//! Every test here sets `HOME` to a temporary directory (through
//! [`Fixture::cmd`]) and never touches the real `~/.claude`. No keychain is
//! ever involved: none of these commands read a credential or write one, so
//! none of these tests installs the fake `security(1)` at all.

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

/// Every regular file under `root`, with its bytes, symlinks skipped.
///
/// For the claims of the form "this pass created or rewrote nothing holding
/// token material": a path-set comparison alone is blind to a file that was
/// already there and got overwritten, so the contents come along. Symlinks
/// are skipped rather than followed — the session directory is mostly
/// symlinks into the live store, and following them would read the same live
/// files twice and call a link's target a file this pass wrote.
fn file_tree(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut found = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&path) else { continue };
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                stack.push(path);
            } else if let Ok(bytes) = fs::read(&path) {
                found.insert(path, bytes);
            }
        }
    }
    found
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
        .env("AGCTL_E2E_MARKER", "marker-value")
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
        vars.get("AGCTL_E2E_MARKER"),
        Some(&"marker-value".to_owned()),
        "an unrelated inherited variable must pass through unchanged"
    );
}

/// Arguments a shell would not leave alone, for the no-shell claim below.
///
/// One per mechanism `sh` would apply to them: word splitting, parameter
/// expansion, pathname expansion, the command separator, and command
/// substitution. The last two are the ones with a visible side effect, which
/// is what makes the claim checkable from outside rather than only by
/// comparing strings.
const SHELL_METACHARACTER_ARGS: [&str; 5] =
    ["a b", "$HOME", "*", "; touch semicolon-ran", "`touch backtick-ran`"];

#[test]
fn ac52_exec_runs_the_child_without_a_shell_and_writes_no_credential() {
    // The two AC52 clauses `ac52_exec_delivers_exactly_the_expected_environment_delta`
    // does not reach: that the child is started **directly** rather than
    // through `sh -c`, and that `exec` writes no credential of its own.
    //
    // "Without a shell" is asserted by consequence, not by inspection. Every
    // argument below is something `sh` would rewrite, and two of them would
    // leave a file behind if one had ever seen them — so a build that spawned
    // `sh -c "<command> <args>"` fails here twice over: the recorded argv
    // would differ, and the child's working directory would hold files
    // nothing asked for.
    let fixture = isolated_store();
    // A credential at rest before the pass, so "no new credential" is a claim
    // about a tree that had one to begin with rather than about an empty one.
    let at_rest = common::blob("access", "refresh", common::fresh_at());
    fixture.write_credentials(ACCT, ORG, &at_rest);

    let bin_dir = fixture.scratch("fake-path-bin");
    fs::create_dir_all(&bin_dir).expect("the fake PATH directory should be creatable");
    let argv_log = fixture.scratch("argv.log");
    let capture = write_argv_capture_script(&bin_dir, "capture", &argv_log);

    // The child inherits agctl's working directory, and agctl's is this
    // test process's — the crate root. A shell's side effects have to land
    // somewhere this test owns and can then assert is empty.
    let cwd = fixture.scratch("child-cwd");
    fs::create_dir_all(&cwd).expect("the child's working directory should be creatable");

    let before = [file_tree(&fixture.config_dir()), file_tree(&fixture.home())];

    let mut command = fixture.cmd();
    command.current_dir(&cwd);
    command.args(["claude", "exec", ACCT, "--"]);
    command.arg(&capture);
    command.args(SHELL_METACHARACTER_ARGS);
    let output = command.output().expect("`claude exec` should run");
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let expected: String = SHELL_METACHARACTER_ARGS.iter().map(|arg| format!("{arg}\n")).collect();
    assert_eq!(
        fs::read_to_string(&argv_log).expect("the argv log should exist"),
        expected,
        "every argument reached the child byte for byte; a shell would have split `a b`, \
         expanded `$HOME`, globbed `*`, and cut the list at the `;`"
    );

    let littered: Vec<String> = fs::read_dir(&cwd)
        .expect("the child's working directory should be readable")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        littered.is_empty(),
        "a shell ran the `;` or the backticks and left {littered:?} in `{}`",
        cwd.display()
    );

    // AC52's last clause: `exec` itself writes no credential. Asserted over
    // both trees rather than over the namespace alone, because a leak worth
    // catching is one that lands under a name the test did not think of.
    let after = [file_tree(&fixture.config_dir()), file_tree(&fixture.home())];
    for (was, now) in before.iter().zip(&after) {
        for (path, bytes) in now {
            if was.get(path) == Some(bytes) {
                continue;
            }
            assert!(
                !String::from_utf8_lossy(bytes).contains("sk-ant-"),
                "`{}` was created or rewritten by `exec` and holds token material",
                path.display()
            );
        }
    }
    assert_eq!(
        fs::read(fixture.credentials_path(ACCT, ORG)).expect("the credential at rest is readable"),
        at_rest.into_bytes(),
        "and the credential that was already there is byte-identical"
    );
}

// ---------------------------------------------------------------------------
// AC51 — env's golden strings, one per shell
// ---------------------------------------------------------------------------

/// A POSIX single-quoted encoding of `value`, mirroring the production
/// `quote_posix` in `src/commands/export.rs`. Duplicated here rather than
/// exposed from the binary — as `common::sha8`/`common::export_spelling`
/// already duplicate other production logic — so the golden strings are
/// computed independently of the code this e2e suite exercises.
fn quote_posix(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        if ch == '\'' { out.push_str("'\\''") } else { out.push(ch) }
    }
    out.push('\'');
    out
}

/// The `fish` equivalent of [`quote_posix`], mirroring `quote_fish`.
fn quote_fish(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        match ch {
            '\'' => out.push_str("\\'"),
            '\\' => out.push_str("\\\\"),
            _ => out.push(ch),
        }
    }
    out.push('\'');
    out
}

fn expected_zsh_bash_env(securestorage: &str, config_dir: &Path, mcp: &Path) -> String {
    let inner = format!("claude --mcp-config {}", quote_posix(&mcp.display().to_string()));
    format!(
        "export CLAUDE_SECURESTORAGE_CONFIG_DIR='{securestorage}'\n\
         export CLAUDE_CONFIG_DIR='{config}'\n\
         # CLAUDE_CODE_OAUTH_TOKEN would bypass this session's stored credential (fact F19)\n\
         unset CLAUDE_CODE_OAUTH_TOKEN\n\
         alias claude={alias}\n\
         # an alias only reaches an interactive shell; a script started from one will not \
         inherit it\n",
        config = config_dir.display(),
        alias = quote_posix(&inner),
    )
}

fn expected_fish_env(securestorage: &str, config_dir: &Path, mcp: &Path) -> String {
    format!(
        "set -gx CLAUDE_SECURESTORAGE_CONFIG_DIR '{securestorage}'\n\
         set -gx CLAUDE_CONFIG_DIR '{config}'\n\
         # CLAUDE_CODE_OAUTH_TOKEN would bypass this session's stored credential (fact F19)\n\
         set -e CLAUDE_CODE_OAUTH_TOKEN\n\
         function claude\n    command claude --mcp-config {mcp} $argv\nend\n\
         # a fish function only reaches an interactive shell; a script started from one will \
         not inherit it\n",
        config = config_dir.display(),
        mcp = quote_fish(&mcp.display().to_string()),
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
fn ac55_the_symlink_target_is_exact_and_nothing_unexpected_is_created() {
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

    let mut entries: Vec<String> = fs::read_dir(&session_dir)
        .expect("the session directory should exist")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    entries.sort();
    assert_eq!(
        entries,
        vec![".claude.json".to_owned(), "mcp.json".to_owned()],
        "the fixture's empty live config dir has no tier 1/tier 2 entries, so the D-019 \
         symlink and the AC54 seed are the only two things created under the session directory"
    );
}

// ---------------------------------------------------------------------------
// AC53 — tier 1/tier 2 symlinks, tier 3 absent, `--fresh-context`
// ---------------------------------------------------------------------------

/// Every tier 1/tier 2 name this module's tests populate, so the assertions
/// below do not have to repeat the allowlists by hand.
const TIER1_NAMES: [&str; 3] = ["settings.json", "CLAUDE.md", "skills"];
const TIER2_NAMES: [&str; 5] =
    ["projects", "shell-snapshots", "file-history", "sessions", "session-env"];

#[test]
fn ac53_symlinks_every_tier_1_and_tier_2_entry_and_leaves_tier_3_alone() {
    let fixture = isolated_store();
    let live_dir = fixture.live_store_dir();
    fs::create_dir_all(&live_dir).expect("the live config dir should be creatable");

    fs::write(live_dir.join("settings.json"), "{}").expect("writable");
    fs::write(live_dir.join("CLAUDE.md"), "# hi").expect("writable");
    fs::create_dir_all(live_dir.join("skills")).expect("writable");
    for name in TIER2_NAMES {
        fs::create_dir_all(live_dir.join(name)).expect("writable");
    }
    // Tier 3: present in the live dir, on neither list.
    fs::create_dir_all(live_dir.join("backups")).expect("writable");

    fixture.cmd().args(["claude", "exec", ACCT, "--", "/usr/bin/true"]).assert().success();

    let session_dir = fixture.session_dir(ACCT, ORG);
    let meta = fs::metadata(&session_dir).expect("the session directory should exist");
    assert_eq!(meta.permissions().mode() & 0o777, 0o700);
    assert!(
        !session_dir.starts_with(fixture.config_dir().join("claude")),
        "the session directory must be outside `namespace_root()`"
    );

    for name in TIER1_NAMES.into_iter().chain(TIER2_NAMES) {
        let link = session_dir.join(name);
        let link_meta = fs::symlink_metadata(&link)
            .unwrap_or_else(|err| panic!("`{name}` should be a symlink: {err}"));
        assert!(link_meta.file_type().is_symlink(), "`{name}` should be a symlink");
        let target = fs::read_link(&link).expect("readable");
        let expected = fs::canonicalize(live_dir.join(name)).expect("canonicalizable");
        assert_eq!(target, expected, "`{name}`'s target");
    }

    assert!(!session_dir.join("backups").exists(), "tier 3 is never exposed");
}

#[test]
fn ac53_fresh_context_omits_tier_2_but_keeps_tier_1() {
    let fixture = isolated_store();
    let live_dir = fixture.live_store_dir();
    fs::create_dir_all(&live_dir).expect("writable");
    fs::write(live_dir.join("settings.json"), "{}").expect("writable");
    fs::create_dir_all(live_dir.join("projects")).expect("writable");

    fixture
        .cmd()
        .args(["claude", "exec", ACCT, "--fresh-context", "--", "/usr/bin/true"])
        .assert()
        .success();

    let session_dir = fixture.session_dir(ACCT, ORG);
    assert!(
        fs::symlink_metadata(session_dir.join("settings.json")).is_ok(),
        "tier 1 still links under --fresh-context"
    );
    assert!(!session_dir.join("projects").exists(), "--fresh-context omits tier 2");
}

// ---------------------------------------------------------------------------
// AC54/AC55 — seeding: no regular file leaks `mcpServers`, the mcp.json
// symlink target is exact
// ---------------------------------------------------------------------------

#[test]
fn ac55_no_regular_file_under_the_session_directory_contains_mcp_servers_or_oauth_account() {
    let fixture = isolated_store();
    fs::write(
        fixture.home().join(".claude.json"),
        json!({
            "oauthAccount": {"uuid": "should-not-leak"},
            "mcpServers": {"server-a": {"command": "foo"}},
            "hasCompletedOnboarding": true,
            "theme": "dark",
        })
        .to_string(),
    )
    .expect("writable");

    fixture.cmd().args(["claude", "exec", ACCT, "--", "/usr/bin/true"]).assert().success();

    let session_dir = fixture.session_dir(ACCT, ORG);
    for entry in fs::read_dir(&session_dir).expect("readable") {
        let entry = entry.expect("readable");
        // `DirEntry::metadata` uses `lstat` on Unix: it does not follow a
        // symlink entry, which is exactly "walked without following
        // symlinks" (critic MAJOR 4 / AC55).
        let meta = entry.metadata().expect("lstat should succeed");
        if meta.file_type().is_symlink() {
            continue;
        }
        assert!(meta.is_file(), "unexpected non-file, non-symlink entry: {:?}", entry.path());
        let contents = fs::read_to_string(entry.path()).expect("readable");
        assert!(
            !contents.contains("mcpServers"),
            "`{}` is a regular file and must not contain `mcpServers`: {contents}",
            entry.path().display()
        );
        assert!(
            !contents.contains("should-not-leak"),
            "`{}` must not leak `oauthAccount`: {contents}",
            entry.path().display()
        );
    }

    let mcp_link = session_dir.join("mcp.json");
    let link_meta = fs::symlink_metadata(&mcp_link).expect("mcp.json should exist");
    assert!(link_meta.file_type().is_symlink());
    let target = fs::read_link(&mcp_link).expect("readable");
    let expected = fs::canonicalize(fixture.home().join(".claude.json")).expect("canonicalizable");
    assert_eq!(target, expected, "mcp.json's target must be the exact canonical live file");
}

// ---------------------------------------------------------------------------
// AC56 — I19 refusal names the path
// ---------------------------------------------------------------------------

#[test]
fn ac56_refuses_a_foreign_occupant_at_a_tier_1_path_naming_it() {
    let fixture = isolated_store();
    let live_dir = fixture.live_store_dir();
    fs::create_dir_all(&live_dir).expect("writable");
    fs::write(live_dir.join("settings.json"), "{}").expect("writable");

    let session_dir = fixture.session_dir(ACCT, ORG);
    fs::create_dir_all(&session_dir).expect("writable");
    fs::write(session_dir.join("settings.json"), "not a symlink").expect("writable");

    fixture
        .cmd()
        .args(["claude", "env", ACCT])
        .assert()
        .failure()
        .code(1)
        .stderr(predicates::str::contains("settings.json"));

    assert_eq!(
        fs::read_to_string(session_dir.join("settings.json")).expect("readable"),
        "not a symlink",
        "the foreign occupant is left untouched"
    );
}

#[test]
fn ac56_refuses_a_symlinked_session_directory_and_leaves_its_target_untouched() {
    // P1-1 scenario A: the session directory itself, not just what lives
    // under it, is a placed path invariant I19 must cover.
    let fixture = isolated_store();
    let live_elsewhere = fixture.scratch("live-elsewhere");
    fs::create_dir_all(&live_elsewhere).expect("the decoy live directory should be creatable");

    let session_dir = fixture.session_dir(ACCT, ORG);
    fs::create_dir_all(session_dir.parent().expect("the session dir has a parent"))
        .expect("the session directory's parent should be creatable");
    std::os::unix::fs::symlink(&live_elsewhere, &session_dir)
        .expect("the decoy symlink should be creatable");

    fixture
        .cmd()
        .args(["claude", "env", ACCT])
        .assert()
        .failure()
        .code(1)
        .stderr(predicates::str::contains(session_dir.to_string_lossy().into_owned()));

    assert_eq!(
        fs::read_dir(&live_elsewhere).expect("readable").count(),
        0,
        "nothing was created inside the symlink's target"
    );
}

// ---------------------------------------------------------------------------
// AC57 — never rewrites the seed after seeding it once
// ---------------------------------------------------------------------------

#[test]
fn ac57_never_rewrites_the_seed_once_claude_code_has_extended_it() {
    let fixture = isolated_store();
    fs::write(
        fixture.home().join(".claude.json"),
        json!({"hasCompletedOnboarding": true, "theme": "dark"}).to_string(),
    )
    .expect("writable");

    fixture.cmd().args(["claude", "exec", ACCT, "--", "/usr/bin/true"]).assert().success();

    let seed_path = fixture.session_dir(ACCT, ORG).join(".claude.json");
    let seeded: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&seed_path).expect("readable"))
            .expect("valid JSON");
    let seeded_keys: std::collections::BTreeSet<String> =
        seeded.as_object().expect("an object").keys().cloned().collect();
    assert!(seeded_keys.contains("hasCompletedOnboarding"));
    assert!(seeded_keys.contains("theme"));

    let seeded_mtime = fs::metadata(&seed_path).expect("readable").modified().expect("mtime");
    std::thread::sleep(std::time::Duration::from_millis(50));

    // Simulate Claude Code's own first run: it treats the session's
    // `.claude.json` as its own and extends it with a key agctl never
    // wrote.
    let mut extended = seeded.clone();
    extended["lastOnboardingVersion"] = json!("9.9.9");
    fs::write(&seed_path, serde_json::to_string_pretty(&extended).expect("serializable"))
        .expect("writable");
    let extended_mtime = fs::metadata(&seed_path).expect("readable").modified().expect("mtime");
    assert!(extended_mtime > seeded_mtime, "the simulated write should move the mtime");

    fixture.cmd().args(["claude", "exec", ACCT, "--", "/usr/bin/true"]).assert().success();

    let after_rerun_mtime = fs::metadata(&seed_path).expect("readable").modified().expect("mtime");
    assert_eq!(after_rerun_mtime, extended_mtime, "the re-run must not rewrite the seed");

    let after: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&seed_path).expect("readable"))
            .expect("valid JSON");
    let after_keys: std::collections::BTreeSet<String> =
        after.as_object().expect("an object").keys().cloned().collect();
    assert!(seeded_keys.is_subset(&after_keys), "the seeded key set must survive: {after_keys:?}");
    assert!(after_keys.contains("lastOnboardingVersion"), "the simulated addition must survive");
}

#[test]
fn ac57_the_audit_log_records_no_write_to_the_seeded_config() {
    // AC57's third clause. The first two — the seeded key set survives, and a
    // re-run does not move the mtime — are asserted by the test above; this is
    // the one that says the *other* durable record agrees with them.
    //
    // Seeding is the one thing `env` does that reads the live `.claude.json`
    // under the peer's configuration lock (rulings G12/Q5), and S24b taught
    // the audit log to carry a `config_write` line for every pass that writes
    // that file. So "the seed was taken, and nothing was written" has a
    // checkable second half: the log is byte-identical across both runs.
    //
    // Planted with a line already in it rather than left absent, because
    // "the file does not exist" is satisfied just as well by a build whose
    // audit writer is broken. A log that already holds a line and still holds
    // exactly that line is a claim about appending, not about existence.
    let (fixture, live_bytes) = linked_config_store();
    let planted = fixture.plant_audit_lines(&[json!({
        "ts": "2026-09-11T00:00:01Z",
        "monotonic_ms": 1,
        "agctl_pid": 1,
        "event": "write",
        "target": "live",
        "from_digest8": "0a0b0c0d",
        "to_digest8": "1a1b1c1d",
        "outcome": "applied",
        "direction": "forward",
        "incoming_identity": { "account_uuid": ACCT, "organization_uuid": ORG },
    })]);
    let before = fs::read(&planted).expect("the planted audit log is readable");

    fixture.cmd().args(["claude", "env", ACCT]).assert().success();

    // The seeding really happened, so the assertion below is about a run that
    // had something to record rather than about one that did nothing at all.
    let seed_path = fixture.session_dir(ACCT, ORG).join(".claude.json");
    assert!(seed_path.is_file(), "the first run should have seeded `{}`", seed_path.display());
    assert!(seed_keys(&fixture).contains("theme"), "and taken the live file's seed keys");

    // A second run, over a seed Claude Code has since extended: the path that
    // would have to decide whether to rewrite, and therefore the one that
    // would have something to audit if it ever did.
    let mut extended: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&seed_path).expect("readable")).expect("JSON");
    extended["lastOnboardingVersion"] = json!("9.9.9");
    fs::write(&seed_path, serde_json::to_string_pretty(&extended).expect("serializable"))
        .expect("writable");
    fixture.cmd().args(["claude", "env", ACCT]).assert().success();

    let after = fs::read(&planted).expect("the audit log is still readable");
    assert_eq!(
        String::from_utf8_lossy(&after),
        String::from_utf8_lossy(&before),
        "seeding appended nothing to `{}`: no write of the seed is an audited event, because \
         no write of the seed happens",
        planted.display()
    );
    assert_eq!(
        fs::read(fixture.home().join(".claude.json")).expect("readable"),
        live_bytes,
        "and the live file the seed was taken from is byte-identical"
    );
    assert!(!fixture.backups_dir().exists(), "nothing backed it up, because nothing rewrote it");
}

// ---------------------------------------------------------------------------
// AC79 — `use --forget`
// ---------------------------------------------------------------------------

#[test]
fn ac79_forget_removes_the_session_and_leaves_the_namespace_and_lock_untouched() {
    let fixture = isolated_store();
    fixture.cmd().args(["claude", "exec", ACCT, "--", "/usr/bin/true"]).assert().success();

    let session_dir = fixture.session_dir(ACCT, ORG);
    assert!(session_dir.exists(), "the fixture should have created a session first");

    fixture.write_credentials(ACCT, ORG, &common::blob("access", "refresh", common::fresh_at()));
    let lock_path = fixture.lock_path(ACCT, ORG);
    fs::create_dir_all(lock_path.parent().expect("has a parent")).expect("writable");
    fs::write(&lock_path, "{}").expect("writable");

    fixture.cmd().args(["claude", "use", "--forget", ACCT, "--yes"]).assert().success();

    assert!(!session_dir.exists(), "the session directory is gone");
    assert!(fixture.credentials_path(ACCT, ORG).exists(), "the namespace is untouched");
    assert!(lock_path.exists(), "the lock file is untouched");
}

#[test]
fn ac79_forget_without_yes_and_no_terminal_removes_nothing() {
    let fixture = isolated_store();
    fixture.cmd().args(["claude", "exec", ACCT, "--", "/usr/bin/true"]).assert().success();
    let session_dir = fixture.session_dir(ACCT, ORG);
    assert!(session_dir.exists());

    fixture
        .cmd()
        .args(["claude", "use", "--forget", ACCT])
        .assert()
        .failure()
        .stderr(predicates::str::contains("--yes"));

    assert!(session_dir.exists(), "nothing was removed without confirmation");
}

#[test]
fn ac79_forget_an_account_with_no_session_is_a_no_op() {
    let fixture = isolated_store();

    fixture
        .cmd()
        .args(["claude", "use", "--forget", ACCT, "--yes"])
        .assert()
        .success()
        .stdout(predicates::str::contains("nothing to forget"));
}

#[test]
fn ac79_forget_removes_a_symlinked_session_directory_without_removing_what_it_points_at() {
    // AC79's containment clause — "removes nothing outside
    // `claude-sessions/`" — at the only shape that can actually reach the
    // filesystem. `isolate::forget_session`'s own
    // `Paths::is_under_session_root` guard is unreachable through the CLI by
    // construction: `Paths::session_dir` always composes the path from
    // validated segments, so no argument makes it point elsewhere. What a
    // user *can* arrange is a session directory that is a symbolic link out
    // of the session root — planted by hand, or inherited from a tree somebody
    // moved — and then the containment question is about `remove_dir_all`
    // rather than about the guard.
    //
    // The answer this pins: the link is under the session root and is
    // removed; its target is not, and is left whole, contents and all.
    // `remove_dir_all` identifies the top-level entry's own type before
    // acting, so it unlinks the link rather than descending through it —
    // which is exactly what `forget_session`'s doc comment claims, and what a
    // switch to a "resolve then remove" implementation would silently break,
    // taking the user's real configuration with it.
    let fixture = isolated_store();

    let outside = fixture.scratch("outside-the-session-root");
    fs::create_dir_all(outside.join("nested")).expect("the decoy tree should be creatable");
    fs::write(outside.join("keepme"), "the user's own file").expect("writable");
    fs::write(outside.join("nested").join("keepme-too"), "and this one").expect("writable");

    let session_dir = fixture.session_dir(ACCT, ORG);
    assert!(
        !outside.starts_with(fixture.config_dir().join("claude-sessions")),
        "the decoy has to be outside the session root for this test to mean anything"
    );
    fs::create_dir_all(session_dir.parent().expect("the session dir has a parent"))
        .expect("the session directory's parent should be creatable");
    std::os::unix::fs::symlink(&outside, &session_dir)
        .expect("the decoy symlink should be creatable");

    fixture.cmd().args(["claude", "use", "--forget", ACCT, "--yes"]).assert().success();

    assert!(
        fs::symlink_metadata(&session_dir).is_err(),
        "the link itself is under the session root, so removing it is right"
    );
    assert!(outside.is_dir(), "but its target is not, and must still be there");
    assert_eq!(
        fs::read_to_string(outside.join("keepme")).expect("the user's file should still be there"),
        "the user's own file",
        "nothing was deleted through the link"
    );
    assert_eq!(
        fs::read_to_string(outside.join("nested").join("keepme-too"))
            .expect("the nested file should still be there"),
        "and this one",
        "and nothing was deleted through it recursively either"
    );
}

// ---------------------------------------------------------------------------
// M6 — the seed's read under the configuration lock (S24b-2)
// ---------------------------------------------------------------------------

/// An isolated store whose live `.claude.json` is a link into `.claude-real/`,
/// JS-shaped, carrying three seed keys among account state. Returns the fixture
/// and the planted bytes.
fn linked_config_store() -> (Fixture, Vec<u8>) {
    let fixture = Fixture::new();
    fixture.write_registry(vec![fixture.owned_record(ACCT, ORG)]);
    fixture.live_through_link();
    let link = fixture.live_claude_json_js(&json!({
        "numStartups": 3,
        "hasCompletedOnboarding": true,
        "theme": "dark",
        "editorMode": "vim",
        "oauthAccount": { "accountUuid": ACCT, "organizationUuid": ORG },
        "userID": "u-1",
    }));
    let bytes = fs::read(&link).expect("the planted file");
    (fixture, bytes)
}

/// The seeded session file's key set.
fn seed_keys(fixture: &Fixture) -> std::collections::BTreeSet<String> {
    let seed = fixture.session_dir(ACCT, ORG).join(".claude.json");
    let seeded: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&seed).expect("the seed exists")).expect("JSON");
    seeded.as_object().expect("an object").keys().cloned().collect()
}

#[test]
fn a_session_seed_is_read_under_the_config_lock_and_releases_it() {
    // Rulings G12 and Q5: a free lock is taken for the one read and given back;
    // the live file is read, never written, and the seed carries only its keys.
    let (fixture, bytes) = linked_config_store();

    fixture.cmd().args(["claude", "env", ACCT]).assert().success();

    assert_eq!(
        seed_keys(&fixture),
        ["editorMode", "hasCompletedOnboarding", "theme"].map(str::to_owned).into_iter().collect(),
        "exactly the three seed keys, the floor among them"
    );
    assert!(!fixture.config_lock_path().exists(), "`$HOME/.claude.json.lock` released");
    assert_eq!(fs::read(fixture.home().join(".claude.json")).expect("readable"), bytes);
    assert!(!fixture.backups_dir().exists(), "no `backups/`");
    let real = fixture.home().join(".claude-real");
    let beside_target: Vec<String> = fs::read_dir(&real)
        .expect("listable")
        .map(|entry| entry.expect("an entry").file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains(".lock") || name.contains(".tmp."))
        .collect();
    assert!(beside_target.is_empty(), "nothing beside the target: {beside_target:?}");

    // I18: once the seed exists the live file is not read at all — so a second
    // run succeeds even over a file no seed could be taken from, and the seed it
    // wrote stands. (This is what makes the early return load-bearing: without
    // it the lock would be taken and the parse attempted on every session.)
    let seeded = fs::read(fixture.session_dir(ACCT, ORG).join(".claude.json")).expect("the seed");
    fs::write(fixture.home().join(".claude-real").join(".claude.json"), "{not json")
        .expect("the live file is writable");
    fixture.cmd().args(["claude", "env", ACCT]).assert().success();
    assert_eq!(
        fs::read(fixture.session_dir(ACCT, ORG).join(".claude.json")).expect("the seed"),
        seeded,
        "the seed is what the first run wrote"
    );
    assert!(!fixture.config_lock_path().exists(), "and no lock was left behind");
}

#[test]
fn a_held_config_lock_never_blocks_seeding_and_is_left_alone() {
    // Rulings G5 and Q5: a lock a session holds — fresh, or past the peer's
    // staleness window — is never waited on and never broken; the seed reads
    // through today's twice-and-compare instead.
    for age in [std::time::Duration::ZERO, std::time::Duration::from_secs(60)] {
        let (fixture, bytes) = linked_config_store();
        let lock = fixture.plant_config_lock(age);
        let mtime = fs::metadata(&lock).and_then(|meta| meta.modified()).expect("stat");

        let started = std::time::Instant::now();
        fixture.cmd().args(["claude", "env", ACCT]).assert().success();
        assert!(started.elapsed() < std::time::Duration::from_secs(10), "{age:?}: no wait");

        assert!(seed_keys(&fixture).contains("theme"), "{age:?}: seeded through the fallback");
        assert!(lock.is_dir(), "{age:?}: the planted lock still exists");
        assert_eq!(
            fs::metadata(&lock).and_then(|meta| meta.modified()).expect("stat"),
            mtime,
            "{age:?}: with its mtime unchanged"
        );
        assert_eq!(
            fs::read(fixture.home().join(".claude.json")).expect("readable"),
            bytes,
            "{age:?}: the live file byte-identical"
        );
    }
}
