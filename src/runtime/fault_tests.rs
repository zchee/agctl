//! Tests for the fault-injection switch.
//!
//! Nothing here reads the process environment: `std::env::set_var` is
//! `unsafe` in edition 2024 and a test that mutated the environment would
//! race every other test in the binary. [`Fault::from_list`] is the seam that
//! makes the parser testable without it.

use super::*;

#[test]
fn none_has_no_active_faults() {
    let fault = Fault::none();
    assert!(!fault.is("rename_fail"));
    assert!(!fault.is(""));
}

#[cfg(feature = "testing")]
#[test]
fn from_list_parses_names() {
    let tests: Vec<(&str, Vec<&str>, Vec<&str>)> = vec![
        ("empty input", vec![], vec!["rename_fail"]),
        ("single name", vec!["rename_fail"], vec!["hold_lock"]),
        ("two names", vec!["rename_fail", "hold_lock"], vec!["flock_enotsup"]),
        ("padded names", vec!["rename_fail", "hold_lock"], vec![""]),
    ];
    let inputs = ["", "rename_fail", "rename_fail,hold_lock", "  rename_fail , hold_lock ,, "];

    for ((name, active, inactive), raw) in tests.into_iter().zip(inputs) {
        let fault = Fault::from_list(raw);
        for entry in active {
            assert!(fault.is(entry), "{name}: `{entry}` should be active in `{raw}`");
        }
        for entry in inactive {
            assert!(!fault.is(entry), "{name}: `{entry}` should be inactive in `{raw}`");
        }
    }
}

#[cfg(feature = "testing")]
#[test]
fn pause_point_returns_immediately_when_not_armed() {
    let fault = Fault::from_list("rename_fail");
    let start = Instant::now();
    fault.pause_point("before_rename");
    assert!(start.elapsed() < Duration::from_secs(1), "an unarmed pause point must not block");
}

#[cfg(feature = "testing")]
#[test]
fn pause_point_is_named_with_the_pause_prefix() {
    // `pause_point("before_rename")` is armed by the fault `pause_before_rename`,
    // which is the spelling plan AC21 uses on the command line.
    let fault = Fault::from_list("pause_before_rename");
    assert!(fault.is("pause_before_rename"));
    assert!(!fault.is("before_rename"));
}

#[test]
fn stall_until_returns_at_once_when_already_cancelled() {
    let cancel = crate::runtime::coordinator::Cancel::new();
    cancel.cancel();
    let start = Instant::now();
    Fault::stall_until(&cancel, Instant::now() + Duration::from_secs(30));
    assert!(start.elapsed() < Duration::from_secs(1), "a cancelled stall must return at once");
}

#[test]
fn stall_until_returns_at_the_deadline() {
    let cancel = crate::runtime::coordinator::Cancel::new();
    let start = Instant::now();
    Fault::stall_until(&cancel, Instant::now() + Duration::from_millis(120));
    let elapsed = start.elapsed();
    assert!(elapsed >= Duration::from_millis(100), "stalled only {elapsed:?}");
    assert!(elapsed < Duration::from_secs(5), "stalled far past the deadline: {elapsed:?}");
}

#[cfg(feature = "testing")]
#[test]
fn from_env_reads_the_documented_variable_names() {
    assert_eq!(FAULT_ENV, "AGCTL_FAULT");
    assert_eq!(FAULT_RESUME_ENV, "AGCTL_FAULT_RESUME");
    assert_eq!(PAUSE_BUDGET, Duration::from_secs(10));

    // The variable is not set in a test run, so this is the "no faults"
    // path -- which is the one every other test in this binary depends on.
    assert_eq!(Fault::from_env(), Fault::none());
}
