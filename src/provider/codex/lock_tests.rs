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

/// Holds `.config.lock` on a second open file description of this process
/// (an `flock` belongs to the description, so `update`'s own open contends
/// with it), and proves the contention is real: a third description with a
/// zero budget gets `Busy`.
#[cfg(feature = "testing")]
fn hold_config_lock(paths: &Paths) -> crate::secret::namespace_lock::NamespaceLockGuard {
    paths.ensure_dirs().expect("the store directories exist");
    let cancel = Cancel::new();
    let later = Instant::now() + Duration::from_secs(30);
    let held = namespace_lock::lock_file(&paths.config_lock(), later, &cancel, &Fault::none())
        .expect("a second open file description takes .config.lock");
    let third =
        namespace_lock::lock_file(&paths.config_lock(), Instant::now(), &cancel, &Fault::none());
    assert!(matches!(third, Err(LockError::Busy)), "the lock is not contended: {:?}", third.err());
    held
}

/// Round N5 (C1b-2 review): the lock-order assertion runs BEFORE
/// `.config.lock` is taken, so a thread holding a Codex guard panics at once
/// instead of waiting on a contended lock and returning `Refused`. With the
/// assertion moved after the lock (mutant M7) the call waits, gets `Refused`,
/// returns before the assertion, and this test fails: no panic comes back.
#[cfg(feature = "testing")]
#[test]
fn a_held_codex_guard_panics_before_waiting_on_a_contended_config_lock() {
    let (_dir, paths) = testkit::store();
    let _other = hold_config_lock(&paths);
    let _guard = guard_for_testkit_record(&paths);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::config::AgctlConfig::update(&paths, |_| ())
    }));
    let payload = result.expect_err("the lock-order assertion fired; no wait on the lock");
    let message = payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|text| (*text).to_owned()))
        .unwrap_or_default();
    assert!(
        message.contains(
            "agctl lock order violated: .config.lock requested while this thread holds a Codex namespace guard"
        ),
        "a different panic: {message:?}"
    );
}

/// The twin: the SAME contended update with no guard live is refused and does
/// not panic — the panic above comes from the guard, not from the contention.
#[cfg(feature = "testing")]
#[test]
fn a_contended_config_lock_without_a_guard_is_refused_not_a_panic() {
    let (_dir, paths) = testkit::store();
    let _other = hold_config_lock(&paths);
    assert_eq!(crate::runtime::lock_order::held_codex_guards(), 0, "no guard is live");
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::config::AgctlConfig::update(&paths, |_| ())
    }));
    let returned = result.expect("no panic without a guard");
    assert!(
        matches!(returned, Err(crate::error::AppError::Refused { .. })),
        "a contended .config.lock is refused: {returned:?}"
    );
}

/// Round N3: the underflow panic (a token dropped on a thread that did not
/// make it) carries the same `agctl lock order violated: ` prefix the release
/// gate lists, so it cannot reach a release artifact unseen. The assertion's
/// message is pinned by the tests above; the overflow cannot be reached.
#[cfg(feature = "testing")]
#[test]
fn a_token_dropped_on_another_thread_panics_with_the_gated_prefix() {
    let token = crate::runtime::lock_order::HeldCodexGuard::take();
    let payload = std::thread::spawn(move || {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(token)))
            .expect_err("dropping on another thread underflows that thread's count")
    })
    .join()
    .expect("the dropping thread reports its panic");
    let message = payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|text| (*text).to_owned()))
        .unwrap_or_default();
    assert!(message.starts_with("agctl lock order violated: "), "{message:?}");
    // The count of 1 this thread keeps (it made the token and never saw it
    // dropped) belongs to this test's own thread and ends with it.
}
