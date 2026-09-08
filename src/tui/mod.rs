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
//! an error — and withdraws the registry entry as it goes.
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
        // Withdrawn first: once this destructor has restored the terminal
        // there is nothing left for a later `emergency()` to undo, and an
        // entry that outlived its terminal would fire against whatever has
        // taken the terminal over since.
        cleanup::unregister(self.token);
        restore_terminal();
    }
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
    let token = install_restore(restore_terminal);

    match try_enter() {
        Ok(terminal) => Ok(Tui { terminal, token }),
        Err(err) => {
            cleanup::unregister(token);
            restore_terminal();
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
