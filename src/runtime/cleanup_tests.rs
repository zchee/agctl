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

// The child-entry and spawn-window tests below need nextest's process-per-test
// isolation: the registry and the spawn counter are process-wide, so under a
// shared-process `cargo test` `take_children` drains every test's entries and
// a concurrent `exec_command` test holds a spawn guard of its own.
#[test]
fn take_children_hands_out_every_registered_child_exactly_once() {
    let first = register_child(4_000_001, "2026-09-17T00:00:00.000001Z".to_owned());
    register_child(4_000_002, "2026-09-17T00:00:00.000002Z".to_owned());

    let taken = take_children();
    let pids: Vec<u32> = taken.iter().map(|entry| entry.pid).collect();
    assert!(pids.contains(&4_000_001) && pids.contains(&4_000_002), "taken: {taken:?}");
    assert_eq!(
        taken.iter().find(|entry| entry.pid == 4_000_001).map(|entry| entry.start_time.as_str()),
        Some("2026-09-17T00:00:00.000001Z"),
        "the start time travels with the process id"
    );

    // Draining is what stops two overlapping exits signalling a child twice.
    assert!(
        take_children().iter().all(|entry| entry.pid != 4_000_001 && entry.pid != 4_000_002),
        "a second take must not hand the same children out again"
    );
    assert!(!unregister(first), "a taken child is no longer registered");
}

#[test]
fn unregister_withdraws_a_child_so_the_signal_path_never_sees_it() {
    let token = register_child(4_000_003, "2026-09-17T00:00:00.000003Z".to_owned());
    assert!(unregister(token), "withdrawing a live child entry should report success");
    assert!(
        take_children().iter().all(|entry| entry.pid != 4_000_003),
        "a reaped-and-withdrawn child must not be handed to the signal path"
    );
}

#[test]
fn emergency_leaves_registered_children_to_the_signal_path() {
    // `emergency` also runs when a pass hits its deadline and when `watch`
    // quits, and neither may kill a child another context is waiting on.
    register_child(4_000_004, "2026-09-17T00:00:00.000004Z".to_owned());
    emergency();
    assert!(
        take_children().iter().any(|entry| entry.pid == 4_000_004),
        "emergency cleanup must not consume the child entries"
    );
}

#[test]
fn a_spawn_guard_holds_the_window_open_until_it_is_dropped() {
    let outer = begin_spawn();
    assert!(spawns_in_flight(), "an open guard must be visible to the signal path");
    let inner = begin_spawn();
    drop(outer);
    assert!(spawns_in_flight(), "the window stays open while any spawner still holds a guard");
    drop(inner);
    assert!(!spawns_in_flight(), "and closes once the last guard is dropped");
}

#[test]
fn the_spawn_window_opens_before_cancellation_is_read() {
    // Review R2-1: the latch closes the spawn window only if the counter is
    // already raised when cancellation is read. Nothing else can observe that
    // order, so the probe asserts it at the moment of the read — on both the
    // refusing and the admitting path.
    let refused = begin_spawn_unless(|| {
        assert!(spawns_in_flight(), "cancellation was read before the spawn window opened");
        true
    });
    assert!(refused.is_none(), "a cancelled run must not be admitted to spawn");
    assert!(!spawns_in_flight(), "a refused spawn must close the window it opened");

    let admitted = begin_spawn_unless(|| {
        assert!(spawns_in_flight(), "cancellation was read before the spawn window opened");
        false
    });
    assert!(admitted.is_some(), "an uncancelled run is admitted");
    assert!(spawns_in_flight(), "and its window stays open while the guard is held");
    drop(admitted);
    assert!(!spawns_in_flight(), "until the guard is dropped");
}

#[test]
fn begin_spawn_unless_cancelled_follows_the_cancel_flag() {
    let cancel = Cancel::new();
    let guard = begin_spawn_unless_cancelled(&cancel);
    assert!(guard.is_some(), "an uncancelled run may spawn");
    drop(guard);

    cancel.cancel();
    assert!(begin_spawn_unless_cancelled(&cancel).is_none(), "a cancelled run may not");
    assert!(!spawns_in_flight(), "and leaves no window open behind it");
}
