//! The subcommand implementations.
//!
//! One module per command, each exposing a `run` that `main`'s dispatch calls
//! with the parsed arguments and the process-wide cancellation flag. Keeping
//! them here rather than in `main.rs` is what lets the dispatch stay a table
//! of one-line arms, and what lets each command's real work be exercised by a
//! unit test that never spawns a process.

pub mod accounts;
pub mod codex;
pub mod completions;
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
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::time::Instant;

use crate::error::AppError;
use crate::runtime::coordinator::Cancel;

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

    /// Whether a person can be asked, for question details restricted to a terminal.
    fn can_ask(&self) -> bool {
        true
    }

    /// Asks a yes/no question that must be answered by a person.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Refused`] when there is no terminal to ask at. A
    /// non-interactive run that meant it says `--yes`; one that did not must
    /// not have a namespace removed out from under it because nobody was
    /// there to say no.
    fn confirm(&mut self, question: &str) -> Result<bool, AppError>;

    /// Obtains fresh, bounded per-input-group consent. Other prompt adapters cannot authorize it.
    fn attest(&mut self, _question: &str, _deadline: Instant, _cancel: &Cancel) -> Attestation {
        Attestation::NotObtained
    }
}

/// A complete answer is distinct from EOF, cancellation, or a partial line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), expect(dead_code, reason = "S11 selects the real attestation adapter"))]
pub enum Attestation {
    /// Exactly `y` followed by a terminal line terminator.
    Yes,
    /// A complete line other than `y`.
    Declined,
    /// No complete answer was obtained before the deadline.
    NotObtained,
}

/// Remote Control's human channel: all prose and questions go to stderr's TTY.
#[cfg_attr(not(test), expect(dead_code, reason = "S11 selects this adapter for the new flag"))]
pub struct AttestedTty;

impl Prompt for AttestedTty {
    fn tell(&mut self, message: &str) {
        eprintln!("{message}");
    }

    fn can_ask(&self) -> bool {
        std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
    }

    fn confirm(&mut self, question: &str) -> Result<bool, AppError> {
        if !self.can_ask() {
            return Ok(false);
        }
        eprint!("{question} [y/N] ");
        std::io::stderr().flush().map_err(|source| AppError::Io {
            context: "could not write the confirmation prompt".to_owned(),
            source,
        })?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer).map_err(|source| AppError::Io {
            context: "could not read the confirmation".to_owned(),
            source,
        })?;
        Ok(matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
    }

    fn attest(&mut self, question: &str, deadline: Instant, cancel: &Cancel) -> Attestation {
        attest_terminal(&std::io::stdin(), &mut std::io::stderr(), question, deadline, cancel)
    }
}

#[cfg_attr(not(test), expect(dead_code, reason = "S11 selects the real attestation adapter"))]
fn attest_terminal(
    input: &impl AsFd,
    output: &mut (impl AsFd + Write),
    question: &str,
    deadline: Instant,
    cancel: &Cancel,
) -> Attestation {
    use rustix::event::PollFd;
    use rustix::event::PollFlags;
    use rustix::termios::QueueSelector;
    let end = Instant::now()
        .checked_add(crate::provider::claude::remote_control::RC_ATTEST_TIMEOUT)
        .map_or(deadline, |end| end.min(deadline));
    if cancel.is_cancelled()
        || Instant::now() >= end
        || !rustix::termios::isatty(input)
        || !rustix::termios::isatty(&*output)
        || rustix::termios::tcflush(input, QueueSelector::IFlush).is_err()
        || write!(output, "{question} ").and_then(|()| output.flush()).is_err()
    {
        return Attestation::NotObtained;
    }
    let mut answer = Vec::with_capacity(2);
    let mut too_long = false;
    let mut select_fallback = false;
    loop {
        let now = Instant::now();
        if cancel.is_cancelled() || now >= end {
            return Attestation::NotObtained;
        }
        let wait = end
            .saturating_duration_since(now)
            .min(crate::provider::claude::remote_control::RC_POLL);
        let timeout =
            rustix::event::Timespec::try_from(wait).expect("a subsecond poll bound fits Timespec");
        let mut fds = [PollFd::new(input, PollFlags::IN)];
        let polled =
            if select_fallback { Ok(1) } else { rustix::event::poll(&mut fds, Some(&timeout)) };
        let ready = match polled {
            Ok(0) => false,
            Ok(_) if select_fallback || fds[0].revents().contains(PollFlags::NVAL) => {
                select_fallback = true;
                if cancel.is_cancelled() || Instant::now() >= end {
                    return Attestation::NotObtained;
                }
                // The failing poll may itself have waited. Do not give its
                // fallback another full interval before observing cancellation.
                let remaining = wait.saturating_sub(now.elapsed());
                if remaining.is_zero() {
                    continue;
                }
                let timeout = rustix::event::Timespec::try_from(remaining)
                    .expect("the remaining poll interval fits Timespec");
                let raw = input.as_fd().as_raw_fd();
                let Some(nfds) = raw.checked_add(1) else { return Attestation::NotObtained };
                let mut readfds = vec![
                    rustix::event::FdSetElement::default();
                    rustix::event::fd_set_num_elements(1, nfds)
                ];
                rustix::event::fd_set_insert(&mut readfds, raw);
                // SAFETY: input owns the sole inserted open descriptor throughout
                // select; the set is sized by rustix for this exact highest fd.
                match unsafe {
                    rustix::event::select(nfds, Some(&mut readfds), None, None, Some(&timeout))
                } {
                    Ok(count) => count > 0,
                    Err(rustix::io::Errno::INTR) => false,
                    Err(_) => return Attestation::NotObtained,
                }
            }
            Ok(_) => fds[0].revents().intersects(PollFlags::IN | PollFlags::HUP),
            Err(rustix::io::Errno::INTR) => false,
            Err(_) => return Attestation::NotObtained,
        };
        if cancel.is_cancelled() || Instant::now() >= end {
            return Attestation::NotObtained;
        }
        if !ready {
            continue;
        }
        let mut byte = [0_u8; 1];
        match rustix::io::read(input, &mut byte) {
            Ok(0) => return Attestation::NotObtained,
            Ok(_) => {
                if cancel.is_cancelled() || Instant::now() >= end {
                    return Attestation::NotObtained;
                }
                if byte[0] == b'\n' {
                    return if !too_long && (answer == b"y" || answer == b"y\r") {
                        Attestation::Yes
                    } else {
                        Attestation::Declined
                    };
                }
                if answer.len() < 2 {
                    answer.push(byte[0]);
                } else {
                    too_long = true;
                }
            }
            Err(rustix::io::Errno::INTR | rustix::io::Errno::AGAIN) => continue,
            Err(_) => return Attestation::NotObtained,
        }
    }
}

/// The real terminal.
pub struct Tty;

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;

impl Prompt for Tty {
    fn tell(&mut self, message: &str) {
        println!("{message}");
    }

    fn can_ask(&self) -> bool {
        std::io::stdin().is_terminal()
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
