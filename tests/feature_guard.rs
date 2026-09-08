//! The `testing` feature gate (AC38).
//!
//! This file is always compiled, which is the whole point. `tests/cli_smoke.rs`
//! carries an inner `#![cfg(feature = "testing")]`, so without the feature it
//! compiles to nothing -- and a `compile_error!` placed inside it would vanish
//! along with the tests it was meant to guard, leaving `cargo test` reporting
//! a cheerful zero failures for a suite that never ran.
//!
//! So the guard lives here instead, in a target with no `cfg` on the file
//! itself. Building the test targets without `--all-features` fails loudly and
//! says how to fix it.
//!
//! See plan section 3.9.

#[cfg(not(feature = "testing"))]
compile_error!("agentctl e2e tests require --all-features (see /check)");

/// Present so the target has a test to run once the feature is enabled, and so
/// a passing run is evidence the guard is satisfied rather than skipped.
#[cfg(feature = "testing")]
#[test]
fn the_testing_feature_is_enabled() {}
