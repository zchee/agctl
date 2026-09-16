//! `agctl codex` — the dispatch table, and the stubs behind it.
//!
//! The command line for the whole Codex surface is parsed from S29b
//! (`cli::CodexCommand`), and the commands behind it land wave by wave: the
//! usage pass at S33, login, import and accounts at S34, doctor at S35. Until
//! each one exists its arm is a stub, and a stub does exactly one thing —
//! it says so and exits non-zero.
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

use crate::cli::Cli;
use crate::cli::CodexAccountsCommand;
use crate::cli::CodexCommand;
use crate::error::AppError;
use crate::runtime::coordinator::Cancel;

/// Routes a parsed `agctl codex` subcommand.
///
/// `cancel` and the store are untouched for now: every arm below refuses
/// before it could use either.
///
/// # Errors
///
/// Returns [`AppError::Config`] naming the command, for every subcommand
/// until its wave lands.
pub fn run(_cli: &Cli, command: &CodexCommand, _cancel: &Cancel) -> Result<i32, AppError> {
    Err(AppError::not_implemented(&name(command)))
}

/// What to call one subcommand in the refusal.
///
/// The user's own spelling, so the message names the thing they typed rather
/// than an internal variant.
fn name(command: &CodexCommand) -> String {
    let tail = match command {
        CodexCommand::Status(_) => "status".to_owned(),
        CodexCommand::Watch(_) => "watch".to_owned(),
        CodexCommand::Login(_) => "login".to_owned(),
        CodexCommand::Import(_) => "import".to_owned(),
        CodexCommand::Doctor(_) => "doctor".to_owned(),
        CodexCommand::Accounts { command } => format!("accounts {}", accounts_name(command)),
    };
    format!("agctl codex {tail}")
}

/// The `accounts` subcommand's own name.
fn accounts_name(command: &CodexAccountsCommand) -> &'static str {
    match command {
        CodexAccountsCommand::List { .. } => "list",
        CodexAccountsCommand::Show { .. } => "show",
        CodexAccountsCommand::Remove { .. } => "remove",
        CodexAccountsCommand::Forget { .. } => "forget",
        CodexAccountsCommand::Unforget { .. } => "unforget",
        CodexAccountsCommand::Set { .. } => "set",
        CodexAccountsCommand::Refresh { .. } => "refresh",
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
