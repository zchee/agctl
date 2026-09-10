//! `agctl completions` — a shell completion script generated straight
//! from the same `clap` definition the binary parses, so it can never drift
//! from the real flag set the way a hand-written completion script would.

use std::io::ErrorKind;
use std::io::Write;

use clap::CommandFactory;

use crate::cli::Cli;
use crate::cli::CompletionsArgs;
use crate::error::AppError;

/// Writes a shell completion script for `agctl` to `out`.
///
/// The command is rebuilt from [`Cli`] through [`clap::CommandFactory`] on
/// every call, so the script always matches the flags this binary actually
/// parses. The binary name passed to the generator is read back from the
/// built command with [`clap::Command::get_name`] rather than written a
/// second time as a literal, so it cannot drift from the
/// `#[command(name = "agctl")]` on [`Cli`].
///
/// The script is rendered into an in-memory buffer first and copied to `out`
/// in one `write_all` call. `clap_complete`'s generators write directly with
/// `write!(...).unwrap()` and offer no fallible entry point, so generating
/// straight into `out` would panic — and, under this crate's
/// `panic = "abort"` profile, abort the whole process — the moment a reader
/// closes its end early, which is an ordinary way to consume a completion
/// script (`agctl completions zsh | head -1`). Buffering first means the
/// only fallible write is the one this function controls, so that case can
/// be recognised as [`std::io::ErrorKind::BrokenPipe`] and treated as a
/// normal, silent end of output rather than a failure.
///
/// # Errors
///
/// Returns [`AppError::Io`] when `out` could not be written to, for any
/// reason other than the reader having closed its end of the pipe.
pub fn run(args: &CompletionsArgs, out: &mut impl Write) -> Result<(), AppError> {
    let mut cmd = Cli::command();
    let bin_name = cmd.get_name().to_owned();

    let mut script = Vec::new();
    clap_complete::generate(args.shell, &mut cmd, bin_name, &mut script);

    match out.write_all(&script) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::BrokenPipe => Ok(()),
        Err(err) => Err(AppError::Io {
            context: "could not write the completion script".to_owned(),
            source: err,
        }),
    }
}

#[cfg(test)]
#[path = "completions_tests.rs"]
mod tests;
