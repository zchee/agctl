//! The subcommand implementations.
//!
//! One module per command, each exposing a `run` that `main`'s dispatch calls
//! with the parsed arguments and the process-wide cancellation flag. Keeping
//! them here rather than in `main.rs` is what lets the dispatch stay a table
//! of one-line arms, and what lets each command's real work be exercised by a
//! unit test that never spawns a process.

pub mod accounts;
pub mod doctor;
pub mod export;
pub mod import;
pub mod isolate;
pub mod login;
pub mod status;
pub mod r#use;
pub mod watch;

use std::io::IsTerminal;
use std::io::Write;

use crate::error::AppError;

/// The one thing `accounts` and `doctor` need a human for.
///
/// Both commands have a destructive path — removing a namespace, removing a
/// lock artefact — that plan section 3.2 gates behind a confirmation, and both
/// print what they are about to do first. Routing that through a trait rather
/// than straight to `std::io` is what lets a unit test drive the whole
/// decision, scripted answer and all, and then assert on the filesystem;
/// through a subprocess it could only ever be tested with `--yes`.
///
/// `login` has its own [`LoginIo`](login::LoginIo) because it needs more —
/// a browser and a pasted line — and because its refusal message names
/// `login`.
pub trait Prompt {
    /// Writes a line the user is meant to read.
    fn tell(&mut self, message: &str);

    /// Asks a yes/no question that must be answered by a person.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Refused`] when there is no terminal to ask at. A
    /// non-interactive run that meant it says `--yes`; one that did not must
    /// not have a namespace removed out from under it because nobody was
    /// there to say no.
    fn confirm(&mut self, question: &str) -> Result<bool, AppError>;
}

/// The real terminal.
pub struct Tty;

impl Prompt for Tty {
    fn tell(&mut self, message: &str) {
        println!("{message}");
    }

    fn confirm(&mut self, question: &str) -> Result<bool, AppError> {
        if !std::io::stdin().is_terminal() {
            return Err(AppError::Refused {
                reason: format!(
                    "{question} — standard input is not a terminal, so there is nobody to ask; \
                     pass `--yes` to say so up front"
                ),
            });
        }
        print!("{question} [y/N] ");
        std::io::stdout().flush().map_err(|err| AppError::Io {
            context: "could not write the confirmation prompt".to_owned(),
            source: err,
        })?;

        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer).map_err(|err| AppError::Io {
            context: "could not read the confirmation".to_owned(),
            source: err,
        })?;
        Ok(matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
    }
}
