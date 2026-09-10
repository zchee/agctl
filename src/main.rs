//! `agctl` — a CLI for managing AI coding agents.
//!
//! This binary is deliberately thin. It parses the command line, brings up
//! logging and signal handling, dispatches, and turns the result into a
//! process exit status. Everything else lives in the modules below.
//!
//! The exit-status contract is stated once, in [`error`]: 0 for a clean run,
//! 1 for a fatal failure, 2 for a run that produced output in which at least
//! one shown row is degraded.

mod cli;
mod commands;
mod config;
mod error;
mod provider;
mod render;
mod runtime;
mod secret;
mod tui;
mod usage;

use std::process;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::cli::ClaudeCommand;
use crate::cli::Cli;
use crate::cli::Command;
use crate::commands::status;
use crate::error::AppError;
use crate::error::EXIT_OK;
use crate::runtime::coordinator::Cancel;
use crate::runtime::log_writer::TerminalAwareWriter;
use crate::runtime::signals;

fn main() {
    let cli = Cli::parse();
    init_tracing();

    let cancel = Cancel::new();
    if let Err(err) = signals::install(cancel.clone()) {
        // Without signal handling a Ctrl-C could strand a temporary file
        // holding token material, so this is fatal rather than a warning.
        eprintln!("agctl: could not install signal handling: {err}");
        process::exit(error::EXIT_FATAL);
    }

    match dispatch(&cli, &cancel) {
        Ok(code) => process::exit(code),
        Err(err) => {
            eprintln!("agctl: {err}");
            process::exit(err.exit_code());
        }
    }
}

/// Brings up tracing on stderr, filtered by `RUST_LOG`.
///
/// stderr, not stdout: `status --json` writes a machine-readable document to
/// stdout and log lines interleaved into it would corrupt it.
///
/// The writer is [`TerminalAwareWriter`] rather than [`std::io::stderr`]
/// directly, so that a line raised while `watch` owns the terminal is held
/// back and delivered once the terminal has been given up, instead of being
/// painted into the alternate screen and lost with it.
///
/// An unset or unparseable `RUST_LOG` falls back to `warn`, and a subscriber
/// that is already installed is left alone, so this is safe to call more than
/// once.
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(TerminalAwareWriter)
        .try_init();
}

/// Routes a parsed command line to its implementation, returning the process
/// exit code.
///
/// [`Command::Claude`] fans out through [`dispatch_claude`]; every other
/// top-level command is handled here directly, since `completions` is the
/// only one so far and has no state of its own to share with the rest of the
/// dispatch table.
fn dispatch(cli: &Cli, cancel: &Cancel) -> Result<i32, AppError> {
    match &cli.command {
        Command::Claude { command } => dispatch_claude(cli, command, cancel),
        Command::Completions(args) => {
            let mut stdout = std::io::stdout().lock();
            commands::completions::run(args, &mut stdout).map(|()| EXIT_OK)
        }
    }
}

/// Routes a parsed `agctl claude` subcommand.
///
/// Every arm is one line. Most commands follow agctl's own 0/1/2 contract
/// ([`error`]), so they are mapped to [`EXIT_OK`] on success; `use` and
/// `exec` instead launch a child the user is meant to interact with, so
/// their success value is that child's own exit code (plan AC52) rather than
/// a fixed one. The constructor stays for the next command that is parsed
/// before it is implemented, so such an arm fails loudly with exit status 1
/// rather than exiting 0 having done nothing.
fn dispatch_claude(cli: &Cli, command: &ClaudeCommand, cancel: &Cancel) -> Result<i32, AppError> {
    match command {
        ClaudeCommand::Status(args) => status::run(cli, args, cancel).map(|()| EXIT_OK),
        ClaudeCommand::Watch(args) => commands::watch::run(cli, args, cancel).map(|()| EXIT_OK),
        ClaudeCommand::Login(args) => {
            commands::login::run(cli.config_dir.as_deref(), args, cancel).map(|()| EXIT_OK)
        }
        ClaudeCommand::Import(args) => {
            commands::import::run(cli.config_dir.as_deref(), args, cancel).map(|()| EXIT_OK)
        }
        ClaudeCommand::Doctor(args) => {
            commands::doctor::run(cli.config_dir.as_deref(), args, cancel).map(|()| EXIT_OK)
        }
        ClaudeCommand::Accounts { command } => {
            commands::accounts::run(cli.config_dir.as_deref(), command, cancel).map(|()| EXIT_OK)
        }
        ClaudeCommand::Use(args) => commands::r#use::run(cli.config_dir.as_deref(), args, cancel),
        ClaudeCommand::Exec(args) => {
            commands::export::run_exec(cli.config_dir.as_deref(), args, cancel)
        }
        ClaudeCommand::Env(args) => {
            commands::export::run_env(cli.config_dir.as_deref(), args, cancel).map(|()| EXIT_OK)
        }
    }
}
