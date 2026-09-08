//! Tests for signal handling.
//!
//! The end-to-end behaviour -- SIGTERM during a held refresh exits 143 with
//! the lock released and the temporary file removed -- is AC27, and lands with
//! the e2e suite once there is a command to interrupt. What is testable here
//! is the exit-status mapping and that installation succeeds.

use super::*;

#[test]
fn exit_status_follows_the_128_plus_signo_convention() {
    let tests = [
        ("SIGHUP exits 129", SIGHUP, 129),
        ("SIGINT exits 130", SIGINT, 130),
        ("SIGTERM exits 143", SIGTERM, 143),
    ];

    for (name, signal, expected) in tests {
        assert_eq!(exit_status_for(signal), expected, "{name}");
    }
}

#[test]
fn exit_status_does_not_wrap_on_an_absurd_signal_number() {
    // Overflow checks are compiled out in every profile, so `128 + signal`
    // would wrap silently into a plausible status. The checked form falls back
    // to a fixed value instead.
    assert_eq!(exit_status_for(i32::MAX), 128, "an unrepresentable status must not wrap");
}

#[test]
fn the_handled_set_is_exactly_term_hup_and_int() {
    assert_eq!(HANDLED.len(), 3);
    for signal in [SIGTERM, SIGHUP, SIGINT] {
        assert!(HANDLED.contains(&signal), "signal {signal} should be handled");
    }
}

#[test]
fn install_succeeds_and_leaves_the_cancel_flag_untouched() {
    let cancel = Cancel::new();
    install(cancel.clone()).expect("installing signal handling should succeed");
    assert!(!cancel.is_cancelled(), "installing must not itself request cancellation");
}
