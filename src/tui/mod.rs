//! The terminal `agentctl claude watch` draws on, and the two guarantees that
//! make entering it safe.
//!
//! A TUI takes the terminal away from the shell: raw mode swallows the line
//! discipline, the alternate screen hides the scrollback, and the cursor is
//! hidden. A process that stops without undoing all three leaves the user with
//! a shell that does not echo. So this module never enters the terminal
//! without first arranging for it to be left, by two independent routes:
//!
//! - **A panic hook**, installed *before* the hook chain it wraps, so the
//!   terminal is restored and only then does the previously installed hook —
//!   the default one that prints the message and the backtrace, or whatever a
//!   host installed — get to run. The other order would print the panic
//!   message into the alternate screen, where it vanishes the moment the
//!   screen is left (plan AC14).
//! - **A [`cleanup`] registry entry**, so `signals::install`'s emergency path
//!   restores the terminal on TERM, HUP or INT, where no destructor runs at
//!   all (plan AC27's `watch` clause).
//!
//! [`Tui`]'s destructor covers the third route — an ordinary return, `q`, or
//! an error — restoring the terminal first and withdrawing the registry entry
//! only afterwards, so that no instant between the two is uncovered (see
//! [`leave`]).
//!
//! # Nothing logs onto the frame
//!
//! A `tracing` line written to standard error while the alternate screen is up
//! is painted over by the next draw and lost. So entering also tells
//! [`log_writer`] to hold log output in memory, and every restore route
//! flushes it to standard error once the terminal is back.
//!
//! # Nothing here is unit-tested against a real terminal
//!
//! Entering raw mode inside a test would corrupt the harness's own output and
//! would fail outright under a captured stdout. So the terminal calls are the
//! thin part, and the part that carries the invariant — that a restore
//! callback is installed ahead of the previous panic hook *and* registered
//! with the cleanup registry — is [`install_restore`], which takes the
//! callback as a parameter and is driven by a spy in the tests. That is the
//! registration proof plan AC14 asks for; the loop itself is exercised
//! against a [`TestBackend`](ratatui::backend::TestBackend).

pub mod app;
pub mod ui;

#[cfg(test)]
pub mod fixtures;

use std::io::Stdout;
use std::io::stdout;
use std::panic;

use crossterm::cursor::Hide;
use crossterm::cursor::Show;
use crossterm::execute;
use crossterm::terminal::EnterAlternateScreen;
use crossterm::terminal::LeaveAlternateScreen;
use crossterm::terminal::disable_raw_mode;
use crossterm::terminal::enable_raw_mode;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use crate::error::AppError;
use crate::runtime::cleanup;
use crate::runtime::cleanup::CleanupToken;
use crate::runtime::log_writer;

/// The terminal `watch` draws on.
pub type WatchTerminal = Terminal<CrosstermBackend<Stdout>>;

/// An entered terminal, restored when this value is dropped.
///
/// Held by value for the whole of the watch loop; there is deliberately no
/// way to get one without the restore paths being armed first.
#[derive(Debug)]
pub struct Tui {
    terminal: WatchTerminal,
    token: CleanupToken,
}

impl Tui {
    /// The terminal to draw on.
    pub fn terminal_mut(&mut self) -> &mut WatchTerminal {
        &mut self.terminal
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        leave(self.token, restore_terminal_and_flush);
    }
}

/// Gives the terminal back and then withdraws the registry entry that would
/// have done it.
///
/// The order matters and it is the opposite of the intuitive one. Withdrawing
/// first would leave the window between the two covered by nothing, so a TERM
/// arriving there would end the process with raw mode still on and the user
/// with a shell that does not echo. Restoring first means the worst case is
/// that the restore runs twice, which costs nothing: every call inside it is a
/// no-op on a terminal that is already back.
///
/// Returns whether an entry was still registered when it was withdrawn.
fn leave<F>(token: CleanupToken, restore: F) -> bool
where
    F: FnOnce(),
{
    restore();
    cleanup::unregister(token)
}

/// Puts the terminal into raw mode on the alternate screen, arming both
/// restore paths first.
///
/// # Errors
///
/// Returns [`AppError::Io`] when raw mode, the alternate screen, or the size
/// query fails. On any of those the restore paths are wound back before
/// returning, so a failed entry leaves nothing armed.
pub fn enter() -> Result<Tui, AppError> {
    let token = install_restore(restore_terminal_and_flush);
    // From here until the terminal is given back, a `tracing` line written to
    // standard error would land inside the frame about to be drawn over it.
    // The writer holds them in memory instead; the restore delivers them.
    log_writer::hold_terminal();

    match try_enter() {
        Ok(terminal) => Ok(Tui { terminal, token }),
        Err(err) => {
            leave(token, restore_terminal_and_flush);
            Err(err)
        }
    }
}

/// The terminal calls themselves, in the order that keeps a partial failure
/// undoable.
fn try_enter() -> Result<WatchTerminal, AppError> {
    enable_raw_mode()
        .map_err(|err| terminal_error("the terminal could not be put into raw mode", &err))?;
    execute!(stdout(), EnterAlternateScreen, Hide)
        .map_err(|err| terminal_error("the alternate screen could not be entered", &err))?;
    Terminal::new(CrosstermBackend::new(stdout()))
        .map_err(|err| terminal_error("the terminal size could not be read", &err))
}

/// Arms both restore paths for `restore`, and returns the registry token.
///
/// The order is the invariant plan AC14 pins: the panic hook is installed
/// around whatever hook is already in place, so `restore` runs *before* that
/// hook and the panic message lands on a terminal that has been put back.
///
/// Separate from [`enter`] and generic over the callback so a test can arm a
/// spy instead of the real terminal and observe both routes.
fn install_restore<F>(restore: F) -> CleanupToken
where
    F: Fn() + Clone + Send + Sync + 'static,
{
    let chained = restore.clone();
    let previous = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        chained();
        previous(info);
    }));

    cleanup::register_restore(Box::new(restore))
}

/// Undoes everything [`try_enter`] does, in reverse, and then delivers
/// whatever `tracing` wrote while the terminal was held.
///
/// This is the callback every restore route runs: the destructor, the panic
/// hook, and the cleanup registry on TERM, HUP or INT. The flush comes last
/// because its whole purpose is to put those lines on a terminal the user can
/// still read — the alternate screen is gone by then.
fn restore_terminal_and_flush() {
    restore_terminal();
    log_writer::release_terminal();
}

/// Undoes everything [`try_enter`] does, in reverse.
///
/// Every failure is swallowed. This runs on the way out of the process —
/// frequently from the signal thread or from inside a panic — where there is
/// no caller left to handle an error, and where a terminal that was never
/// entered (a failed [`enter`]) makes each call a harmless no-op anyway.
fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(stdout(), LeaveAlternateScreen, Show);
}

/// Wraps a terminal failure as an [`AppError::Io`].
///
/// The source is rebuilt rather than moved because `crossterm` and `ratatui`
/// hand back different error types across these three calls, and the context
/// string is what the user actually reads.
fn terminal_error(context: &str, err: &std::io::Error) -> AppError {
    AppError::Io {
        context: context.to_owned(),
        source: std::io::Error::new(err.kind(), err.to_string()),
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
