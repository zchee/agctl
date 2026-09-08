//! Proof that the terminal-restore path is armed, without a terminal.
//!
//! Neither test enters raw mode or the alternate screen. What they assert is
//! the part that can go wrong silently: that [`install_restore`] puts its
//! callback *ahead* of the panic hook already in place (plan AC14's second
//! clause), and that it also lands in the cleanup registry so the signal
//! thread's [`cleanup::emergency`] restores the terminal where no destructor
//! runs (plan AC27's `watch` clause).
//!
//! # Why a panic can be caught here at all
//!
//! `Cargo.toml` sets `panic = "abort"` on the dev and release profiles, so
//! the shipped binary aborts. Cargo ignores that setting for the **test**
//! profile, which is what makes [`catch_unwind`](std::panic::catch_unwind)
//! work below.
//!
//! # Why the global hook is safe to touch
//!
//! The panic hook and the cleanup registry are both process-global, and
//! `emergency` drains the registry. `nextest` runs each test in its own
//! process, which is the runner this project's gate uses, so neither test can
//! reach the other's state.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use super::*;

/// Records what ran, in order.
type Log = Arc<Mutex<Vec<&'static str>>>;

/// Appends to a log, recovering from a poisoned mutex so a panicking test
/// still records.
fn record(log: &Log, entry: &'static str) {
    match log.lock() {
        Ok(mut entries) => entries.push(entry),
        Err(poisoned) => poisoned.into_inner().push(entry),
    }
}

/// Reads a log back.
fn entries(log: &Log) -> Vec<&'static str> {
    match log.lock() {
        Ok(entries) => entries.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

#[test]
fn every_restore_route_gives_back_the_terminal_and_then_flushes_the_held_log() {
    // The three routes share one callback, so what this pins is that the
    // callback does both halves and in that order: the flush is only worth
    // anything once the alternate screen is gone.
    log_writer::hold_terminal();

    restore_terminal_and_flush();

    assert!(
        !log_writer::is_held(),
        "leaving the terminal must let `tracing` reach standard error again"
    );
}

#[test]
fn the_restore_runs_before_the_previously_installed_panic_hook() {
    let log: Log = Arc::new(Mutex::new(Vec::new()));

    // Stand in for whatever hook the process already had — in production the
    // default one that prints the message the user reads.
    let previous = Arc::clone(&log);
    std::panic::set_hook(Box::new(move |_info| record(&previous, "previous hook")));

    let restore = Arc::clone(&log);
    let token = install_restore(move || record(&restore, "restore"));

    let result = std::panic::catch_unwind(|| panic!("a draw went wrong"));
    assert!(result.is_err(), "the panic should have unwound into `catch_unwind`");

    assert_eq!(
        entries(&log),
        vec!["restore", "previous hook"],
        "the terminal must be restored before the hook that prints the panic, or the message \
         lands on the alternate screen and vanishes with it"
    );

    // Leave the process with the default hook rather than one that writes
    // into a log this test owns.
    let _ = std::panic::take_hook();
    assert!(cleanup::unregister(token), "the registry entry should still have been there");
}

#[test]
fn the_terminal_is_restored_before_the_registry_entry_is_withdrawn() {
    // A signal landing while the destructor is mid-restore has to find an
    // entry still in the registry: that is the only thing that would restore
    // the terminal on a route where no destructor finishes. Withdrawing first
    // would leave that instant covered by nothing.
    let token = cleanup::register_restore(Box::new(|| {}));
    let live_during_restore = Arc::new(AtomicBool::new(false));

    let probe = Arc::clone(&live_during_restore);
    let withdrawn_afterwards = leave(token, move || {
        // Taking the entry is how `cleanup` lets a caller ask whether one is
        // there; consuming it only makes `leave`'s own withdrawal a no-op,
        // which is what the second assertion reads.
        probe.store(cleanup::unregister(token), Ordering::SeqCst);
    });

    assert!(
        live_during_restore.load(Ordering::SeqCst),
        "the registry entry must still be in place while the terminal is being restored"
    );
    assert!(
        !withdrawn_afterwards,
        "and the withdrawal must come after it, so it found nothing left to take"
    );
}

#[test]
fn the_restore_is_registered_with_the_cleanup_registry() {
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let restore = Arc::clone(&log);
    let token = install_restore(move || record(&restore, "restore"));

    // What the signal thread does on TERM, HUP or INT.
    cleanup::emergency();

    assert_eq!(
        entries(&log),
        vec!["restore"],
        "emergency cleanup must restore the terminal: a signal ends the process without \
         running any destructor"
    );
    assert!(
        !cleanup::unregister(token),
        "`emergency` takes ownership of the entries it runs, so nothing should be left"
    );

    let _ = std::panic::take_hook();
}
