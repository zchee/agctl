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
