//! `agentctl` — a CLI for managing AI coding agents.
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
mod runtime;
mod secret;

use std::process;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::cli::AccountsCommand;
use crate::cli::ClaudeCommand;
use crate::cli::Cli;
use crate::cli::Command;
use crate::error::AppError;
use crate::error::EXIT_OK;
use crate::runtime::coordinator::Cancel;
use crate::runtime::signals;

fn main() {
    let cli = Cli::parse();
    init_tracing();

    let cancel = Cancel::new();
    if let Err(err) = signals::install(cancel.clone()) {
        // Without signal handling a Ctrl-C could strand a temporary file
        // holding token material, so this is fatal rather than a warning.
        eprintln!("agentctl: could not install signal handling: {err}");
        process::exit(error::EXIT_FATAL);
    }

    match dispatch(&cli, &cancel) {
        Ok(()) => process::exit(EXIT_OK),
        Err(err) => {
            eprintln!("agentctl: {err}");
            process::exit(err.exit_code());
        }
    }
}

/// Brings up tracing on stderr, filtered by `RUST_LOG`.
///
/// stderr, not stdout: `status --json` writes a machine-readable document to
/// stdout and log lines interleaved into it would corrupt it.
///
/// An unset or unparseable `RUST_LOG` falls back to `warn`, and a subscriber
/// that is already installed is left alone, so this is safe to call more than
/// once.
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ =
        tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).try_init();
}

/// Routes a parsed command line to its implementation.
///
/// Every arm that is not yet built returns [`AppError::not_implemented`], so
/// an unbuilt command fails loudly with exit status 1 instead of exiting 0
/// having done nothing. W1 to W3 replace these arms.
fn dispatch(cli: &Cli, cancel: &Cancel) -> Result<(), AppError> {
    let Command::Claude { command } = &cli.command;
    match command {
        ClaudeCommand::Status(_) => Err(AppError::not_implemented("agentctl claude status")),
        ClaudeCommand::Watch(_) => Err(AppError::not_implemented("agentctl claude watch")),
        ClaudeCommand::Login(args) => commands::login::run(cli.config_dir.as_deref(), args, cancel),
        ClaudeCommand::Import(_) => Err(AppError::not_implemented("agentctl claude import")),
        ClaudeCommand::Doctor(_) => Err(AppError::not_implemented("agentctl claude doctor")),
        ClaudeCommand::Accounts { command } => match command {
            AccountsCommand::List { .. } => {
                Err(AppError::not_implemented("agentctl claude accounts list"))
            }
            AccountsCommand::Show { .. } => {
                Err(AppError::not_implemented("agentctl claude accounts show"))
            }
            AccountsCommand::Remove { .. } => {
                Err(AppError::not_implemented("agentctl claude accounts remove"))
            }
            AccountsCommand::Relocate { .. } => {
                Err(AppError::not_implemented("agentctl claude accounts relocate"))
            }
            AccountsCommand::Forget { .. } => {
                Err(AppError::not_implemented("agentctl claude accounts forget"))
            }
            AccountsCommand::Unforget { .. } => {
                Err(AppError::not_implemented("agentctl claude accounts unforget"))
            }
        },
    }
}
