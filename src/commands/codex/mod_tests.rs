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
    // `login` left this list at S34 C1, `import` at S34 C2-b, and
    // `accounts list/show/remove/forget/unforget` at S34 C3: each is
    // implemented, and its own refusals are proved in its `*_tests.rs` and its
    // `tests/e2e_codex_*.rs`. A command that lands must leave this list, or the
    // list stops meaning "still a stub" and starts meaning nothing.
    //
    // `accounts set` and `accounts refresh` stay: they change the refresh
    // policy and send POSTs, which is C4's capability, not C3's.
    let lines: [(&[&str], &str); 3] = [
        (&["agctl", "codex", "doctor"], "agctl codex doctor"),
        (
            &["agctl", "codex", "accounts", "set", "x", "--refresh", "never"],
            "agctl codex accounts set",
        ),
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

/// Plan ledger #230: the S30 shapes S33/S34 will call, spelled from outside
/// `provider::codex` with only what a command can reach.
///
/// Compiling this is the check — a `pub(super)` item or a private field in the
/// way would be E0624/E0451 here, the same wall the real callers would hit —
/// so neither function runs. The login tail is plan section 3.3's; the pass
/// shape stops before the refresh steps, which only `provider/codex/refresh.rs`
/// may take (plan AC122 clause 11).
mod provider_boundary {
    use crate::config::codex::CodexAccountRecord;
    use crate::config::paths::Paths;
    use crate::provider::codex::auth_store::InstallNamespace;
    use crate::provider::codex::auth_store::NamespaceRead;
    use crate::provider::codex::auth_store::OwnedNamespace;
    use crate::provider::codex::auth_store::RefreshStateRead;
    use crate::provider::codex::auth_store::WriteReceipt;
    use crate::provider::codex::credentials::CodexIdentity;
    use crate::provider::codex::lock;
    use crate::provider::codex::lock::LockBudget;
    use crate::provider::codex::proof;
    use crate::provider::codex::proof::VerifiedLogin;
    use crate::runtime::coordinator::Cancel;
    use crate::runtime::fault::Fault;
    use crate::secret::namespace_lock::COMMAND_LOCK_TIMEOUT;

    #[expect(dead_code, reason = "a compile check of the provider boundary; S34 writes the caller")]
    fn login_tail(
        paths: &Paths,
        login: VerifiedLogin,
        cancel: &Cancel,
        fault: &Fault,
    ) -> Result<(WriteReceipt, CodexIdentity), String> {
        let identity = login.identity();
        let guard = lock::acquire_codex_for_install(
            paths,
            &login,
            LockBudget::Command(COMMAND_LOCK_TIMEOUT),
            cancel,
            fault,
        )
        .map_err(|err| err.to_string())?;
        let install = InstallNamespace::open_for_install(paths, login, &guard)
            .map_err(|err| err.to_string())?;
        let (receipt, installed) = install.install(fault).map_err(|err| err.to_string())?;
        if installed != identity {
            return Err("the installed identity is not the verified one".to_owned());
        }
        Ok((receipt, installed))
    }

    #[expect(dead_code, reason = "a compile check of the provider boundary; S33 writes the caller")]
    fn owned_pass(
        paths: &Paths,
        record: &CodexAccountRecord,
        cancel: &Cancel,
        fault: &Fault,
    ) -> Result<Option<WriteReceipt>, String> {
        let owned = proof::owned(record).ok_or("not an owned record")?;
        let guard = lock::acquire_codex(
            paths,
            owned,
            LockBudget::Pass(COMMAND_LOCK_TIMEOUT),
            cancel,
            fault,
        )
        .map_err(|err| err.to_string())?;
        let ns = OwnedNamespace::open(paths, owned, &guard).map_err(|err| err.to_string())?;
        let (_decision, receipt, _evidence) =
            ns.resolve_pending(cancel).map_err(|err| err.to_string())?;
        if let RefreshStateRead::Unavailable(reason) = ns.refresh_state().load() {
            return Err(reason);
        }
        match ns.read().map_err(|err| err.to_string())? {
            NamespaceRead::Credentials(credentials) => {
                let _snapshot = ns.snapshot_for_post().map_err(|err| err.to_string())?;
                let _expired = credentials
                    .credentials()
                    .access_expired(jiff::Timestamp::now(), std::time::Duration::ZERO);
            }
            NamespaceRead::Absent | NamespaceRead::Torn => {}
        }
        Ok(receipt)
    }
}
