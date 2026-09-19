use std::time::Duration;
use std::time::Instant;

use super::*;
use crate::provider::codex::auth_store;
use crate::provider::codex::proof;
use crate::provider::codex::proof::PostExitReport;
use crate::provider::codex::testkit;

#[test]
fn the_lock_lives_beside_the_namespaces_and_is_exclusive() {
    let (_dir, paths) = testkit::store();
    let record = testkit::owned_record(testkit::USER, testkit::ACCT);
    let owned = proof::owned(&record).expect("owned");
    let cancel = Cancel::new();
    let guard = acquire_codex(
        &paths,
        owned,
        LockBudget::Command(Duration::from_secs(1)),
        &cancel,
        &Fault::none(),
    )
    .expect("locks");
    let expected =
        paths.codex_locks_dir().join(format!("{}+{}.lock", testkit::USER, testkit::ACCT));
    assert_eq!(guard.path(), expected);
    assert!(expected.is_file());
    assert!(
        !paths.codex_namespace_dir(testkit::USER, testkit::ACCT).expect("dir").exists(),
        "taking the lock creates nothing inside the namespace"
    );

    // A second holder in the same process gets `Busy` after a short pass budget.
    let started = Instant::now();
    let second = acquire_codex(
        &paths,
        owned,
        LockBudget::Pass(Duration::from_millis(300)),
        &cancel,
        &Fault::none(),
    );
    assert_eq!(second.err(), Some(LockError::Busy));
    assert!(started.elapsed() < Duration::from_secs(3), "the pass budget bounds the wait");

    drop(guard);
    let again = acquire_codex(
        &paths,
        owned,
        LockBudget::Pass(Duration::from_millis(300)),
        &cancel,
        &Fault::none(),
    );
    assert!(again.is_ok(), "released on drop");
}

#[test]
fn a_cancelled_wait_is_cancelled() {
    let (_dir, paths) = testkit::store();
    let record = testkit::owned_record(testkit::USER, testkit::ACCT);
    let owned = proof::owned(&record).expect("owned");
    let _held = testkit::lock_for(&paths, &record);
    let cancel = Cancel::new();
    cancel.cancel();
    let err = acquire_codex(
        &paths,
        owned,
        LockBudget::Command(Duration::from_secs(5)),
        &cancel,
        &Fault::none(),
    );
    assert_eq!(err.err(), Some(LockError::Cancelled));
}

#[test]
fn the_install_lock_is_the_same_lock() {
    let (_dir, paths) = testkit::store();
    let scratch = tempfile::tempdir().expect("tempdir");
    testkit::write_0600(
        &scratch.path().join(auth_store::shown_name()),
        &testkit::fresh_auth_bytes(),
    );
    let report = PostExitReport::from_child(
        Vec::new(),
        Vec::new(),
        testkit::clean_survey(),
        testkit::exit_status(0),
    );
    let login = auth_store::verify_login(scratch.path(), &report).expect("verifies");
    let _held = testkit::lock_for(&paths, &testkit::owned_record(testkit::USER, testkit::ACCT));
    let err = acquire_codex_for_install(
        &paths,
        &login,
        LockBudget::Pass(Duration::from_millis(200)),
        &Cancel::new(),
        &Fault::none(),
    );
    assert_eq!(
        err.err(),
        Some(LockError::Busy),
        "a registered owner and a login contend for one lock"
    );
}

#[test]
fn budgets_report_their_wait() {
    assert_eq!(LockBudget::Pass(Duration::from_secs(1)).duration(), Duration::from_secs(1));
    assert_eq!(LockBudget::Command(Duration::from_secs(5)).duration(), Duration::from_secs(5));
}

/// Takes the lock for the testkit's owned record with a one-second budget.
#[cfg(feature = "testing")]
fn guard_for_testkit_record(paths: &Paths) -> CodexNamespaceGuard {
    let record = testkit::owned_record(testkit::USER, testkit::ACCT);
    let owned = proof::owned(&record).expect("owned");
    acquire_codex(
        paths,
        owned,
        LockBudget::Command(Duration::from_secs(1)),
        &Cancel::new(),
        &Fault::none(),
    )
    .expect("locks")
}

/// Numbered deviation 13, the direct pin: the registry update refuses to take
/// `.config.lock` while this thread holds a Codex namespace guard.
#[cfg(feature = "testing")]
#[test]
#[should_panic(
    expected = "agctl lock order violated: .config.lock requested while this thread holds a Codex namespace guard"
)]
fn the_registry_update_panics_while_this_thread_holds_a_codex_guard() {
    let (_dir, paths) = testkit::store();
    let _guard = guard_for_testkit_record(&paths);
    assert_eq!(crate::runtime::lock_order::held_codex_guards(), 1, "the guard counted itself");
    let _ = crate::config::AgctlConfig::update(&paths, |_| ());
}

/// The positive-control twin: the same update runs once the guard is gone,
/// and a guard held by ANOTHER thread is not this thread's ordering fault.
#[cfg(feature = "testing")]
#[test]
fn the_registry_update_runs_after_the_drop_and_ignores_other_threads() {
    use std::sync::mpsc;
    use std::thread;

    use crate::runtime::lock_order::held_codex_guards;

    let (_dir, paths) = testkit::store();
    let guard = guard_for_testkit_record(&paths);
    assert_eq!(held_codex_guards(), 1, "the guard counted itself");
    drop(guard);
    assert_eq!(held_codex_guards(), 0, "the drop uncounted it");
    crate::config::AgctlConfig::update(&paths, |_| ()).expect("updates with no guard held");

    let (held_tx, held_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    thread::scope(|scope| {
        let paths = &paths;
        scope.spawn(move || {
            let guard = guard_for_testkit_record(paths);
            held_tx.send(held_codex_guards()).expect("reports");
            release_rx.recv().expect("released");
            drop(guard);
            assert_eq!(held_codex_guards(), 0, "dropped on the thread that made it");
        });
        assert_eq!(held_rx.recv().expect("held"), 1, "the other thread counts its own guard");
        assert_eq!(held_codex_guards(), 0, "this thread holds none");
        let updated = crate::config::AgctlConfig::update(paths, |_| ());
        release_tx.send(()).expect("releases");
        updated.expect("another thread's guard does not trip this thread");
    });
}
