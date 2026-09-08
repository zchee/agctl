//! Termination-signal handling.
//!
//! `agentctl` can be holding a namespace lock and a half-written credential
//! temporary file when the user hits Ctrl-C, and can have the terminal in raw
//! mode and on the alternate screen when `watch` is killed. Dying on the
//! default disposition would leave both behind. So TERM, HUP and INT are
//! handled: each sets the pass-wide [`Cancel`], runs [`cleanup::emergency`],
//! and exits with the conventional `128 + signo` status.
//!
//! The work happens on a dedicated thread draining `signal_hook`'s iterator,
//! not in a signal handler. That matters: unlinking files and restoring the
//! terminal are not async-signal-safe, and doing them from a real handler
//! would risk deadlocking against whatever the interrupted thread was holding.
//! `signal_hook` registers a handler that does nothing but wake this thread.

use std::io;
use std::process;
use std::thread;

use signal_hook::consts::SIGHUP;
use signal_hook::consts::SIGINT;
use signal_hook::consts::SIGTERM;
use signal_hook::iterator::Signals;

use crate::runtime::cleanup;
use crate::runtime::coordinator::Cancel;

/// The signals `agentctl` handles.
const HANDLED: [i32; 3] = [SIGTERM, SIGHUP, SIGINT];

/// The conventional exit status for a process killed by `signal`.
///
/// Uses checked arithmetic rather than `128 + signal` because overflow checks
/// are compiled out in every profile of this project, so a nonsensical signal
/// number would otherwise wrap into a plausible status.
fn exit_status_for(signal: i32) -> i32 {
    signal.checked_add(128).unwrap_or(128)
}

/// Installs the termination-signal handler thread.
///
/// On any of TERM, HUP or INT the handler sets `cancel`, runs emergency
/// cleanup, and terminates the process with `128 + signo` — 143, 129 and 130
/// respectively.
///
/// # Errors
///
/// Returns the underlying [`io::Error`] if the signals cannot be registered or
/// the handler thread cannot be started.
pub fn install(cancel: Cancel) -> io::Result<()> {
    let mut signals = Signals::new(HANDLED)?;
    thread::Builder::new().name("agentctl-signals".to_owned()).spawn(move || {
        // Only the first signal is ever acted on: handling it ends the
        // process, so there is no second iteration to write.
        if let Some(signal) = signals.forever().next() {
            cancel.cancel();
            cleanup::emergency();
            process::exit(exit_status_for(signal));
        }
    })?;
    Ok(())
}

#[cfg(test)]
#[path = "signals_tests.rs"]
mod tests;
