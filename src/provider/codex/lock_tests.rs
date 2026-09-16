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
        false,
        Vec::new(),
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
