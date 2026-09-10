//! Tests for the command-line surface: parse vectors for every subcommand and
//! flag, the duration grammar, and the `watch` interval floor (AC13).

use std::path::PathBuf;
use std::time::Duration;

use clap::CommandFactory;
use clap::Parser;

use super::*;

/// Parses an argv, panicking with the clap error when it should have parsed.
fn parse(argv: &[&str]) -> Cli {
    match Cli::try_parse_from(argv) {
        Ok(cli) => cli,
        Err(err) => panic!("expected `{}` to parse, but clap said: {err}", argv.join(" ")),
    }
}

/// Returns the clap error rendered as a string, panicking if it parsed.
fn parse_err(argv: &[&str]) -> String {
    match Cli::try_parse_from(argv) {
        Ok(_) => panic!("expected `{}` to be rejected, but it parsed", argv.join(" ")),
        Err(err) => err.to_string(),
    }
}

/// Narrows a parsed `Cli` to its `claude` subcommand.
///
/// # Panics
///
/// Panics if `cli.command` is not [`Command::Claude`] — every call site
/// parses a `claude …` argv, so any other variant here is this test's own
/// bug, not something to route around.
fn claude_of(cli: &Cli) -> &ClaudeCommand {
    let Command::Claude { command } = &cli.command else {
        panic!("expected a `claude` subcommand, got {:?}", cli.command);
    };
    command
}

#[test]
fn clap_command_definition_is_internally_consistent() {
    // Catches long-option collisions and other build-time contradictions --
    // notably the global `--config-dir` against `import`'s directory flag,
    // which is why the latter is spelled `--claude-config-dir`.
    Cli::command().debug_assert();
}

#[test]
fn duration_parser_accepts_the_documented_spellings() {
    let tests = [
        ("success: bare seconds", "300", Duration::from_secs(300)),
        ("success: explicit seconds", "10s", Duration::from_secs(10)),
        ("success: minutes", "5m", Duration::from_secs(300)),
        ("success: hours", "2h", Duration::from_secs(7200)),
        ("success: zero", "0", Duration::ZERO),
        ("success: surrounding whitespace is trimmed", "  45s  ", Duration::from_secs(45)),
    ];

    for (name, input, expected) in tests {
        let got = parse_duration(input).unwrap_or_else(|err| panic!("{name}: {input:?} -> {err}"));
        assert_eq!(got, expected, "{name}: {input:?}");
    }
}

#[test]
fn duration_parser_rejects_bad_input_without_wrapping() {
    // The overflow cases matter more here than they would elsewhere: this
    // project compiles with `-C overflow-checks=off` in every profile, so a
    // parser relying on a panicking multiplication would silently return a
    // small, plausible duration instead of failing.
    let tests = [
        ("error: empty", "", DurationParseError::Empty),
        ("error: whitespace only", "   ", DurationParseError::Empty),
        ("error: no leading digits", "s", DurationParseError::NoDigits("s".to_owned())),
        ("error: unit only", "abc", DurationParseError::NoDigits("abc".to_owned())),
        (
            "error: value above u64::MAX",
            "99999999999999999999s",
            DurationParseError::Overflow("99999999999999999999s".to_owned()),
        ),
        (
            "error: minutes multiplication overflows",
            "999999999999999999m",
            DurationParseError::Overflow("999999999999999999m".to_owned()),
        ),
        (
            "error: hours multiplication overflows",
            "99999999999999999h",
            DurationParseError::Overflow("99999999999999999h".to_owned()),
        ),
        (
            "error: unknown unit",
            "10d",
            DurationParseError::UnknownUnit { unit: "d".to_owned(), input: "10d".to_owned() },
        ),
        (
            "error: fractional is not supported",
            "1.5s",
            DurationParseError::UnknownUnit { unit: ".5s".to_owned(), input: "1.5s".to_owned() },
        ),
        ("error: negative is not supported", "-5s", DurationParseError::NoDigits("-5s".to_owned())),
    ];

    for (name, input, expected) in tests {
        match parse_duration(input) {
            Ok(value) => panic!("{name}: {input:?} should have been rejected, got {value:?}"),
            Err(err) => assert_eq!(err, expected, "{name}: {input:?}"),
        }
    }
}

#[test]
fn duration_parser_overflow_returns_an_error_rather_than_a_wrapped_value() {
    // Stated separately from the table because it is the specific failure the
    // build configuration would otherwise hide: assert on the real value, not
    // through a `debug_assert!`, which is inert here.
    let err = parse_duration("999999999999999999m")
        .expect_err("a minutes value that overflows u64 seconds must be an error");
    assert!(
        matches!(err, DurationParseError::Overflow(_)),
        "expected an overflow error, got {err:?}"
    );
    assert!(err.to_string().contains("too large"), "message should say why: {err}");
}

#[test]
fn watch_interval_defaults_to_300_seconds() {
    let cli = parse(&["agctl", "claude", "watch"]);
    match claude_of(&cli) {
        ClaudeCommand::Watch(args) => {
            assert_eq!(args.interval, Duration::from_secs(300), "AC13: default interval");
        }
        other => panic!("expected `watch`, got {other:?}"),
    }
}

#[test]
fn watch_interval_below_the_floor_is_rejected_naming_the_floor() {
    // AC13: the message must tell the user what the limit is, not merely that
    // their value was refused.
    let message = parse_err(&["agctl", "claude", "watch", "--interval", "30s"]);
    assert!(message.contains("60"), "the error must name the 60s floor, got: {message}");

    for below in ["0", "1s", "59s", "59"] {
        let message = parse_err(&["agctl", "claude", "watch", "--interval", below]);
        assert!(message.contains("60"), "`{below}` must be refused naming 60: {message}");
    }
}

#[test]
fn watch_interval_at_or_above_the_floor_is_accepted() {
    let tests = [
        ("success: exactly the floor", "60s", Duration::from_secs(60)),
        ("success: bare seconds at the floor", "60", Duration::from_secs(60)),
        ("success: one minute spelled as minutes", "1m", Duration::from_secs(60)),
        ("success: well above the floor", "10m", Duration::from_secs(600)),
    ];

    for (name, input, expected) in tests {
        let cli = parse(&["agctl", "claude", "watch", "--interval", input]);
        match claude_of(&cli) {
            ClaudeCommand::Watch(args) => assert_eq!(args.interval, expected, "{name}"),
            other => panic!("{name}: expected `watch`, got {other:?}"),
        }
    }
}

#[test]
fn status_defaults_are_the_documented_ones() {
    let cli = parse(&["agctl", "claude", "status"]);
    match claude_of(&cli) {
        ClaudeCommand::Status(args) => {
            assert!(!args.json, "json defaults off");
            assert!(!args.raw, "raw defaults off");
            assert!(!args.refresh, "refresh defaults off");
            assert!(!args.no_cache, "no_cache defaults off");
            assert!(!args.all, "all defaults off");
            assert!(!args.by_identity, "by_identity defaults off");
            assert!(args.account.is_empty(), "account defaults empty");
            assert_eq!(args.timeout, Duration::from_secs(10), "timeout defaults to 10s");
        }
        other => panic!("expected `status`, got {other:?}"),
    }
}

#[test]
fn status_accepts_every_flag_and_repeats_account() {
    let cli = parse(&[
        "agctl",
        "claude",
        "status",
        "--json",
        "--raw",
        "--refresh",
        "--no-cache",
        "--all",
        "--by-identity",
        "--account",
        "acct-a",
        "--account",
        "acct-b/org-1",
        "--timeout",
        "5m",
    ]);
    match claude_of(&cli) {
        ClaudeCommand::Status(args) => {
            assert!(args.json && args.raw && args.refresh && args.no_cache && args.all);
            assert!(args.by_identity, "`--by-identity` is spelled with a hyphen");
            assert_eq!(args.account, vec!["acct-a".to_owned(), "acct-b/org-1".to_owned()]);
            assert_eq!(args.timeout, Duration::from_secs(300));
        }
        other => panic!("expected `status`, got {other:?}"),
    }
}

#[test]
fn status_rejects_an_unparseable_timeout() {
    let message = parse_err(&["agctl", "claude", "status", "--timeout", "10 fortnights"]);
    assert!(!message.is_empty(), "clap should explain the rejection");
}

#[test]
fn login_parses_both_flags() {
    let bare = parse(&["agctl", "claude", "login"]);
    match claude_of(&bare) {
        ClaudeCommand::Login(args) => {
            assert!(!args.manual);
            assert_eq!(args.label, None);
            assert!(!args.no_duplicate, "no_duplicate defaults off");
        }
        other => panic!("expected `login`, got {other:?}"),
    }

    let full =
        parse(&["agctl", "claude", "login", "--manual", "--label", "work", "--no-duplicate"]);
    match claude_of(&full) {
        ClaudeCommand::Login(args) => {
            assert!(args.manual);
            assert_eq!(args.label.as_deref(), Some("work"));
            assert!(args.no_duplicate, "`--no-duplicate` is spelled with a hyphen");
        }
        other => panic!("expected `login`, got {other:?}"),
    }
}

#[test]
fn accounts_subcommands_all_parse() {
    let list = parse(&["agctl", "claude", "accounts", "list", "--all"]);
    match claude_of(&list) {
        ClaudeCommand::Accounts { command: AccountsCommand::List { all } } => assert!(*all),
        other => panic!("expected `accounts list`, got {other:?}"),
    }

    let show = parse(&["agctl", "claude", "accounts", "show", "acct-1"]);
    match claude_of(&show) {
        ClaudeCommand::Accounts { command: AccountsCommand::Show { id } } => {
            assert_eq!(id, "acct-1");
        }
        other => panic!("expected `accounts show`, got {other:?}"),
    }

    let remove =
        parse(&["agctl", "claude", "accounts", "remove", "acct-1", "--delete-secret", "--yes"]);
    match claude_of(&remove) {
        ClaudeCommand::Accounts { command: AccountsCommand::Remove { id, delete_secret, yes } } => {
            assert_eq!(id, "acct-1");
            assert!(*delete_secret);
            assert!(*yes);
        }
        other => panic!("expected `accounts remove`, got {other:?}"),
    }

    let remove_bare = parse(&["agctl", "claude", "accounts", "remove", "acct-1"]);
    match claude_of(&remove_bare) {
        ClaudeCommand::Accounts { command: AccountsCommand::Remove { delete_secret, yes, .. } } => {
            assert!(!*delete_secret, "delete_secret must be opt-in");
            assert!(!*yes, "yes must be opt-in");
        }
        other => panic!("expected `accounts remove`, got {other:?}"),
    }

    let relocate = parse(&["agctl", "claude", "accounts", "relocate", "acct-1", "--yes"]);
    match claude_of(&relocate) {
        ClaudeCommand::Accounts { command: AccountsCommand::Relocate { id, yes } } => {
            assert_eq!(id, "acct-1");
            assert!(*yes);
        }
        other => panic!("expected `accounts relocate`, got {other:?}"),
    }

    let forget = parse(&["agctl", "claude", "accounts", "forget", "Claude Code-credentials"]);
    match claude_of(&forget) {
        ClaudeCommand::Accounts { command: AccountsCommand::Forget { service } } => {
            assert_eq!(service, "Claude Code-credentials");
        }
        other => panic!("expected `accounts forget`, got {other:?}"),
    }

    let unforget = parse(&["agctl", "claude", "accounts", "unforget", "Claude Code-credentials"]);
    match claude_of(&unforget) {
        ClaudeCommand::Accounts { command: AccountsCommand::Unforget { service } } => {
            assert_eq!(service, "Claude Code-credentials");
        }
        other => panic!("expected `accounts unforget`, got {other:?}"),
    }
}

#[test]
fn import_parses_its_source_and_repeats_config_dir() {
    let dry_run = parse(&["agctl", "claude", "import", "--from", "keychain", "--dry-run"]);
    match claude_of(&dry_run) {
        ClaudeCommand::Import(args) => {
            assert_eq!(args.from, ImportSource::Keychain);
            assert!(args.dry_run);
            assert!(args.claude_config_dir.is_empty());
        }
        other => panic!("expected `import`, got {other:?}"),
    }

    let keychain = parse(&[
        "agctl",
        "claude",
        "import",
        "--from",
        "keychain",
        "--claude-config-dir",
        "/one",
        "--claude-config-dir",
        "/two",
    ]);
    match claude_of(&keychain) {
        ClaudeCommand::Import(args) => {
            assert_eq!(args.from, ImportSource::Keychain);
            assert_eq!(args.claude_config_dir, vec![PathBuf::from("/one"), PathBuf::from("/two")]);
            assert!(!args.dry_run);
        }
        other => panic!("expected `import`, got {other:?}"),
    }
}

#[test]
fn import_requires_a_source() {
    let message = parse_err(&["agctl", "claude", "import"]);
    assert!(message.contains("--from"), "the error should name the missing flag: {message}");
}

#[test]
fn import_rejects_an_unknown_source() {
    let message = parse_err(&["agctl", "claude", "import", "--from", "sqlite"]);
    assert!(!message.is_empty(), "clap should explain the rejection");
}

#[test]
fn doctor_parses_its_flags() {
    let bare = parse(&["agctl", "claude", "doctor"]);
    match claude_of(&bare) {
        ClaudeCommand::Doctor(args) => {
            assert_eq!(args.remove_stale, None);
            assert!(!args.yes);
        }
        other => panic!("expected `doctor`, got {other:?}"),
    }

    let removing = parse(&[
        "agctl",
        "claude",
        "doctor",
        "--remove-stale",
        "/tmp/ns/.oauth_refresh.lock",
        "--yes",
    ]);
    match claude_of(&removing) {
        ClaudeCommand::Doctor(args) => {
            assert_eq!(args.remove_stale, Some(PathBuf::from("/tmp/ns/.oauth_refresh.lock")));
            assert!(args.yes);
        }
        other => panic!("expected `doctor`, got {other:?}"),
    }
}

#[test]
fn use_bare_id_parses_with_every_default_off() {
    let cli = parse(&["agctl", "claude", "use", "acct-1"]);
    match claude_of(&cli) {
        ClaudeCommand::Use(args) => {
            assert_eq!(args.id.as_deref(), Some("acct-1"));
            assert!(!args.live && !args.new_only && !args.undo && !args.yes && !args.json);
            assert_eq!(args.forget, None);
            assert_eq!(args.claude_config_dir, None);
            assert!(!args.fresh_context);
            assert!(!args.no_mcp);
        }
        other => panic!("expected `use`, got {other:?}"),
    }
}

#[test]
fn use_accepts_every_flag_together_with_an_id() {
    let cli = parse(&[
        "agctl",
        "claude",
        "use",
        "acct-1",
        "--claude-config-dir",
        "/tmp/session",
        "--fresh-context",
        "--no-mcp",
        "--yes",
        "--json",
    ]);
    match claude_of(&cli) {
        ClaudeCommand::Use(args) => {
            assert_eq!(args.id.as_deref(), Some("acct-1"));
            assert_eq!(args.claude_config_dir, Some(PathBuf::from("/tmp/session")));
            assert!(args.fresh_context && args.no_mcp && args.yes && args.json);
        }
        other => panic!("expected `use`, got {other:?}"),
    }
}

#[test]
fn use_undo_and_forget_parse_without_an_id() {
    let undo = parse(&["agctl", "claude", "use", "--undo", "--yes"]);
    match claude_of(&undo) {
        ClaudeCommand::Use(args) => {
            assert_eq!(args.id, None);
            assert!(args.undo);
            assert!(args.yes);
        }
        other => panic!("expected `use`, got {other:?}"),
    }

    let forget = parse(&["agctl", "claude", "use", "--forget", "acct-1"]);
    match claude_of(&forget) {
        ClaudeCommand::Use(args) => {
            assert_eq!(args.id, None);
            assert_eq!(args.forget.as_deref(), Some("acct-1"));
        }
        other => panic!("expected `use`, got {other:?}"),
    }
}

#[test]
fn use_live_conflicts_with_new_only_undo_and_forget() {
    for argv in [
        vec!["agctl", "claude", "use", "acct-1", "--live", "--new-only"],
        vec!["agctl", "claude", "use", "--live", "--undo"],
        vec!["agctl", "claude", "use", "--live", "--forget", "acct-1"],
    ] {
        let message = parse_err(&argv);
        assert!(!message.is_empty(), "`{}` should be rejected", argv.join(" "));
    }
}

#[test]
fn use_undo_and_forget_conflict_with_an_id_and_with_each_other() {
    for argv in [
        vec!["agctl", "claude", "use", "acct-1", "--undo"],
        vec!["agctl", "claude", "use", "acct-1", "--forget", "acct-1"],
        vec!["agctl", "claude", "use", "--undo", "--forget", "acct-1"],
    ] {
        let message = parse_err(&argv);
        assert!(!message.is_empty(), "`{}` should be rejected", argv.join(" "));
    }
}

#[test]
fn exec_requires_a_trailing_command() {
    let message = parse_err(&["agctl", "claude", "exec", "acct-1"]);
    assert!(!message.is_empty(), "a missing `-- <command>` should be rejected");
}

#[test]
fn exec_parses_the_id_and_the_trailing_command() {
    let cli = parse(&[
        "agctl",
        "claude",
        "exec",
        "acct-1",
        "--claude-config-dir",
        "/tmp/session",
        "--fresh-context",
        "--no-mcp",
        "--",
        "claude",
        "--resume",
    ]);
    match claude_of(&cli) {
        ClaudeCommand::Exec(args) => {
            assert_eq!(args.id, "acct-1");
            assert_eq!(args.claude_config_dir, Some(PathBuf::from("/tmp/session")));
            assert!(args.fresh_context && args.no_mcp);
            assert_eq!(
                args.command,
                vec![std::ffi::OsString::from("claude"), std::ffi::OsString::from("--resume")]
            );
        }
        other => panic!("expected `exec`, got {other:?}"),
    }
}

#[test]
fn env_defaults_to_zsh() {
    let cli = parse(&["agctl", "claude", "env", "acct-1"]);
    match claude_of(&cli) {
        ClaudeCommand::Env(args) => {
            assert_eq!(args.id, "acct-1");
            assert_eq!(args.shell, Shell::Zsh);
            assert!(!args.fresh_context && !args.no_mcp);
        }
        other => panic!("expected `env`, got {other:?}"),
    }
}

#[test]
fn env_accepts_every_documented_shell() {
    for (flag, expected) in [("zsh", Shell::Zsh), ("bash", Shell::Bash), ("fish", Shell::Fish)] {
        let cli = parse(&["agctl", "claude", "env", "acct-1", "--shell", flag]);
        match claude_of(&cli) {
            ClaudeCommand::Env(args) => assert_eq!(args.shell, expected, "--shell {flag}"),
            other => panic!("expected `env`, got {other:?}"),
        }
    }
}

#[test]
fn env_rejects_an_unknown_shell() {
    let message = parse_err(&["agctl", "claude", "env", "acct-1", "--shell", "powershell"]);
    assert!(!message.is_empty(), "clap should explain the rejection");
}

#[test]
fn top_level_config_dir_is_accepted_before_the_subcommand() {
    let cli = parse(&["agctl", "--config-dir", "/custom/store", "claude", "status"]);
    assert_eq!(cli.config_dir, Some(PathBuf::from("/custom/store")));
}

#[test]
fn config_dir_is_global_and_accepted_after_the_subcommand() {
    let cli = parse(&["agctl", "claude", "status", "--config-dir", "/custom/store"]);
    assert_eq!(cli.config_dir, Some(PathBuf::from("/custom/store")));

    let nested = parse(&["agctl", "claude", "accounts", "list", "--config-dir", "/custom/store"]);
    assert_eq!(nested.config_dir, Some(PathBuf::from("/custom/store")));
}

#[test]
fn top_level_config_dir_defaults_to_none() {
    // The environment variable is read by clap when set; the default with no
    // flag and no variable is `None`, which lets `config::paths` apply its own
    // precedence rules rather than having a default baked in here.
    let cli = parse(&["agctl", "claude", "doctor"]);
    let from_env = std::env::var_os("AGCTL_CONFIG_DIR");
    if from_env.is_none() {
        assert_eq!(cli.config_dir, None);
    }
}

#[test]
fn unknown_subcommands_are_rejected() {
    for argv in [
        vec!["agctl", "claude", "bogus"],
        vec!["agctl", "bogus"],
        vec!["agctl", "claude", "accounts", "bogus"],
    ] {
        let message = parse_err(&argv);
        assert!(!message.is_empty(), "`{}` should be rejected", argv.join(" "));
    }
}

#[test]
fn a_subcommand_is_required() {
    let message = parse_err(&["agctl"]);
    assert!(!message.is_empty(), "bare `agctl` should not parse as a runnable command");
}
