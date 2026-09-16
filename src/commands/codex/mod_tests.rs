//! Tests for the `agctl codex` skeleton.

use clap::Parser;

use super::*;

/// Parses a command line, or panics naming it.
fn parse(args: &[&str]) -> Cli {
    Cli::try_parse_from(args).unwrap_or_else(|err| panic!("`{}`: {err}", args.join(" ")))
}

/// The `codex` subcommand of a parsed line.
fn codex(args: &[&str]) -> CodexCommand {
    match parse(args).command {
        crate::cli::Command::Codex { command } => command,
        other => panic!("`{}` did not parse as a codex command: {other:?}", args.join(" ")),
    }
}

#[test]
fn every_subcommand_refuses_and_names_itself() {
    let lines: [(&[&str], &str); 8] = [
        (&["agctl", "codex", "status"], "agctl codex status"),
        (&["agctl", "codex", "watch"], "agctl codex watch"),
        (&["agctl", "codex", "login"], "agctl codex login"),
        (&["agctl", "codex", "import", "--from", "codex-home"], "agctl codex import"),
        (&["agctl", "codex", "doctor"], "agctl codex doctor"),
        (&["agctl", "codex", "accounts", "list"], "agctl codex accounts list"),
        (&["agctl", "codex", "accounts", "show", "x"], "agctl codex accounts show"),
        (
            &["agctl", "codex", "accounts", "refresh", "x", "--resend"],
            "agctl codex accounts refresh",
        ),
    ];

    for (args, expected) in lines {
        let cli = parse(args);
        let crate::cli::Command::Codex { command } = &cli.command else {
            panic!("`{}` is not a codex command", args.join(" "));
        };
        let err = run(&cli, command, &Cancel::new()).expect_err("no stub may report success");
        let message = err.to_string();
        assert!(message.contains(expected), "{message}");
        assert!(message.contains("not implemented"), "{message}");
        assert_eq!(err.exit_code(), crate::error::EXIT_FATAL, "a stub must not exit 0");
    }
}

#[test]
fn status_takes_the_phase_one_flags_and_the_same_default_timeout() {
    let CodexCommand::Status(args) = codex(&[
        "agctl",
        "codex",
        "status",
        "--json",
        "--raw",
        "--refresh",
        "--no-cache",
        "--all",
        "--account",
        "one",
        "--account",
        "two",
        "--timeout",
        "5m",
    ]) else {
        panic!("not a status command");
    };

    assert!(args.json && args.raw && args.refresh && args.no_cache && args.all);
    assert_eq!(args.account, vec!["one".to_owned(), "two".to_owned()]);
    assert_eq!(args.timeout, std::time::Duration::from_secs(300));

    let CodexCommand::Status(args) = codex(&["agctl", "codex", "status"]) else {
        panic!("not a status command");
    };
    assert_eq!(args.timeout, std::time::Duration::from_secs(10));
}

#[test]
fn watch_refuses_an_interval_under_the_floor_before_anything_runs() {
    // The same floor `agctl claude watch` enforces, and enforced by the
    // parser, so a stub that does nothing still cannot be asked to poll a
    // vendor's API every ten seconds.
    let err = Cli::try_parse_from(["agctl", "codex", "watch", "--interval", "30s"])
        .expect_err("an interval below the floor is refused");
    assert!(err.to_string().contains("60s floor"), "{err}");

    let CodexCommand::Watch(args) = codex(&["agctl", "codex", "watch"]) else {
        panic!("not a watch command");
    };
    assert_eq!(args.interval, std::time::Duration::from_secs(300));
}

#[test]
fn a_refresh_may_be_a_resend_or_a_floor_reset_but_not_both() {
    let CodexCommand::Accounts { command } =
        codex(&["agctl", "codex", "accounts", "refresh", "x", "--reset-floor", "--yes"])
    else {
        panic!("not an accounts command");
    };
    let CodexAccountsCommand::Refresh { id, resend, reset_floor, yes } = command else {
        panic!("not a refresh command");
    };
    assert_eq!(id, "x");
    assert!(!resend && reset_floor && yes);

    Cli::try_parse_from([
        "agctl",
        "codex",
        "accounts",
        "refresh",
        "x",
        "--resend",
        "--reset-floor",
    ])
    .expect_err("the two are exclusive: one sends a token, the other lifts a state");
}

#[test]
fn the_refresh_policy_flag_takes_the_two_words_the_registry_stores() {
    let CodexCommand::Accounts { command } =
        codex(&["agctl", "codex", "accounts", "set", "x", "--refresh", "never"])
    else {
        panic!("not an accounts command");
    };
    let CodexAccountsCommand::Set { id, refresh } = command else {
        panic!("not a set command");
    };
    assert_eq!(id, "x");
    assert_eq!(refresh, crate::cli::RefreshMode::Never);

    Cli::try_parse_from(["agctl", "codex", "accounts", "set", "x", "--refresh", "sometimes"])
        .expect_err("a mode the registry cannot store is not accepted");
}

#[test]
fn import_names_its_source_rather_than_assuming_one() {
    let CodexCommand::Import(args) = codex(&[
        "agctl",
        "codex",
        "import",
        "--from",
        "codex-home",
        "--codex-home",
        "/elsewhere/.codex",
        "--dry-run",
    ]) else {
        panic!("not an import command");
    };

    assert_eq!(args.from, crate::cli::CodexImportSource::CodexHome);
    assert_eq!(args.codex_home.as_deref(), Some(std::path::Path::new("/elsewhere/.codex")));
    assert!(args.dry_run);

    Cli::try_parse_from(["agctl", "codex", "import"])
        .expect_err("`--from` is required: a second source must not change what the first meant");
}

#[test]
fn the_help_text_does_not_spell_the_codex_home_variable() {
    // §9.3's grep allows that literal in exactly one file, and help text is
    // still a copy of it. The flag is `--codex-home`; the variable's name
    // belongs to `provider::codex::home`.
    let mut help = Vec::new();
    <Cli as clap::CommandFactory>::command()
        .find_subcommand_mut("codex")
        .expect("the codex subcommand exists")
        .write_long_help(&mut help)
        .expect("help renders");
    let help = String::from_utf8(help).expect("help is UTF-8");

    assert!(!help.contains("CODEX_HOME"), "{help}");
}
