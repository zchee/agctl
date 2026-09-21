//! `agctl codex` — the dispatch table, the stubs behind it, and the one
//! constructor that reads the Codex home from the process.
//!
//! The command line for the whole Codex surface is parsed from S29b
//! (`cli::CodexCommand`), and the commands behind it land wave by wave: the
//! usage pass ([`status`], [`watch`]) at S33, login, import and accounts at
//! S34, doctor at S35. Every arm of this table now runs; the two `accounts`
//! subcommands that send a POST — `set` and `refresh` — are the last stubs,
//! and they refuse inside [`accounts`] rather than here.
//!
//! # Why the flags exist before the commands do
//!
//! Every flag lives in `cli.rs` (plan principle P4). Parsing the real surface
//! now is what makes shell completions, `--help` and the acceptance criteria
//! reviewable as one command line rather than as six separate additions, and
//! what lets a user discover what is coming. The cost is that
//! `agctl codex status` exists and refuses, which is the honest state of this
//! build.
//!
//! # What a stub must not do
//!
//! Nothing. No file is opened, no directory is created, no request is made —
//! in particular `ensure_codex_dirs` is **not** called here, so a build that
//! only ever ran the stubs leaves no `codex/` tree behind, and a Claude-only
//! user's store is exactly what it was (plan AC97). A stub that "prepared"
//! anything would be a write nobody asked for, on a path the reviewer of the
//! real command has not seen yet.

pub mod accounts;
pub mod accounts_refresh;
pub mod doctor;
pub mod import;
pub mod login;
pub mod pass;
pub mod status;
pub mod watch;

use std::path::PathBuf;

use crate::cli::Cli;
use crate::cli::CodexCommand;
use crate::error::AppError;
use crate::provider::codex::home;
use crate::provider::codex::home::CodexEnv;
use crate::runtime::coordinator::Cancel;

/// Routes a parsed `agctl codex` subcommand.
///
/// Every arm runs. The refusals that are left belong to `accounts set` and
/// `accounts refresh`, and are made inside [`accounts`].
///
/// # Errors
///
/// Whatever the command returns.
pub fn run(cli: &Cli, command: &CodexCommand, cancel: &Cancel) -> Result<i32, AppError> {
    match command {
        CodexCommand::Status(args) => status::run(cli, args, cancel).map(|()| 0),
        CodexCommand::Watch(args) => watch::run(cli, args, cancel).map(|()| 0),
        CodexCommand::Login(args) => login::run(cli, args, cancel).map(|()| 0),
        CodexCommand::Import(args) => import::run(cli, args, cancel).map(|()| 0),
        CodexCommand::Accounts { command } => accounts::run(cli, command, cancel).map(|()| 0),
        CodexCommand::Doctor(args) => doctor::run(cli, args, cancel).map(|()| 0),
    }
}

/// The Codex home inputs, read from this process (plan section 3.1,
/// invariant I25).
///
/// The one constructor that reads the process environment for a
/// [`CodexEnv`]: `provider::codex::home` never names the environment module,
/// so every resolution rule there is tested with values a test chose. Called
/// only by command code, never by a test.
pub fn codex_env_from_process() -> CodexEnv {
    CodexEnv::new(
        std::env::var_os(home::CODEX_HOME_ENV),
        std::env::var_os("HOME").map(PathBuf::from),
    )
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
