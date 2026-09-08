//! Tests for the emergency-cleanup registry.
//!
//! The registry is process-wide state. `cargo nextest` runs each test in its
//! own process, so these do not interfere; they are still written to assert
//! only on their own entries so they stay correct under a shared-process
//! runner.

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use super::*;

#[test]
fn emergency_removes_a_registered_temporary_file() {
    let dir = tempfile::tempdir().expect("creating a temporary directory should succeed");
    let path = dir.path().join(".credentials.json.tmp.0123abcd");
    std::fs::write(&path, b"pretend token material")
        .expect("writing the temporary file should succeed");
    assert!(path.exists(), "the file should exist before cleanup runs");

    register_tmp_path(path.clone());
    emergency();

    assert!(!path.exists(), "emergency cleanup must unlink the registered temporary file");
}

#[test]
fn emergency_runs_a_restore_callback_exactly_once() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    register_restore(Box::new(move || {
        counter.fetch_add(1, Ordering::SeqCst);
    }));

    emergency();
    assert_eq!(calls.load(Ordering::SeqCst), 1, "the callback should have run");

    // Idempotence is what makes this safe to call from a signal thread while
    // another call is already unwinding.
    emergency();
    emergency();
    assert_eq!(calls.load(Ordering::SeqCst), 1, "a second emergency must not run it again");
}

#[test]
fn emergency_removes_files_and_runs_callbacks_in_the_same_pass() {
    let dir = tempfile::tempdir().expect("creating a temporary directory should succeed");
    let first = dir.path().join("first.tmp.aaaaaaaa");
    let second = dir.path().join("second.tmp.bbbbbbbb");
    std::fs::write(&first, b"one").expect("writing should succeed");
    std::fs::write(&second, b"two").expect("writing should succeed");

    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);

    register_tmp_path(first.clone());
    register_restore(Box::new(move || {
        counter.fetch_add(1, Ordering::SeqCst);
    }));
    register_tmp_path(second.clone());

    emergency();

    assert!(!first.exists(), "the first temporary file should be gone");
    assert!(!second.exists(), "the second temporary file should be gone");
    assert_eq!(calls.load(Ordering::SeqCst), 1, "the callback should have run once");
}

#[test]
fn unregister_withdraws_an_entry_so_emergency_leaves_it_alone() {
    let dir = tempfile::tempdir().expect("creating a temporary directory should succeed");
    let path = dir.path().join("renamed-into-place.tmp.cccccccc");
    std::fs::write(&path, b"already renamed").expect("writing should succeed");

    let token = register_tmp_path(path.clone());
    assert!(unregister(token), "withdrawing a live entry should report success");

    emergency();

    assert!(path.exists(), "a withdrawn path must survive emergency cleanup");
}

#[test]
fn unregister_reports_failure_for_an_unknown_or_repeated_token() {
    let dir = tempfile::tempdir().expect("creating a temporary directory should succeed");
    let path = dir.path().join("once.tmp.dddddddd");
    let token = register_tmp_path(path);

    assert!(unregister(token), "the first withdrawal should succeed");
    assert!(!unregister(token), "withdrawing the same token twice should report failure");
}

#[test]
fn a_withdrawn_restore_callback_does_not_run() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let token = register_restore(Box::new(move || {
        counter.fetch_add(1, Ordering::SeqCst);
    }));

    assert!(unregister(token), "withdrawing a live callback should report success");
    emergency();

    assert_eq!(calls.load(Ordering::SeqCst), 0, "a withdrawn callback must not run");
}

#[test]
fn emergency_tolerates_a_path_that_is_already_gone() {
    let dir = tempfile::tempdir().expect("creating a temporary directory should succeed");
    let path = dir.path().join("never-created.tmp.eeeeeeee");

    register_tmp_path(path);
    // The point is that this returns rather than panicking or propagating:
    // a missing file is the state emergency cleanup was trying to reach.
    emergency();
}

#[test]
fn emergency_on_an_empty_registry_is_a_no_op() {
    emergency();
    emergency();
}
