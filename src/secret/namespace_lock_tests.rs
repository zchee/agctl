//! Tests for the namespace lock (plan AC48, L3).

use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use tempfile::TempDir;

use super::*;

fn store() -> (TempDir, Paths) {
    let dir = TempDir::new().expect("a temporary directory should be available");
    let paths = Paths::with_config_dir(dir.path().join("agentctl"));
    (dir, paths)
}

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

#[test]
fn acquiring_writes_a_body_naming_this_process() {
    // Plan AC48(c).
    let (_dir, paths) = store();
    let guard = acquire(&paths, "acct", "org", soon(), &Cancel::new(), Fault::none())
        .expect("an uncontended lock should be acquired");

    let body = read_body(guard.path()).expect("the body should be readable");
    assert_eq!(body.pid, std::process::id());
    assert!(!body.acquired_at.is_empty(), "the body records when it was taken");
    assert_eq!(body.pid_start_time, None, "not populated in this build; see the field's docs");

    assert_eq!(guard.path(), paths.lock_path("acct", "org"));
    let mode = std::fs::metadata(guard.path()).expect("the lock file exists").permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    assert_eq!(
        std::fs::metadata(paths.locks_dir())
            .expect("the locks directory exists")
            .permissions()
            .mode()
            & 0o777,
        crate::config::paths::DIR_MODE
    );
}

#[test]
fn the_lock_file_survives_the_guard() {
    // Never unlinked: `flock` is an inode lock, and a recreated file is a
    // second inode that two processes could hold at once.
    let (_dir, paths) = store();
    let path = {
        let guard = acquire(&paths, "acct", "org", soon(), &Cancel::new(), Fault::none())
            .expect("the lock should be acquired");
        guard.path().to_path_buf()
    };
    assert!(path.exists(), "the lock file outlives the guard");
}

#[test]
fn a_symlink_at_the_lock_path_is_refused() {
    // Plan AC48(a).
    let (dir, paths) = store();
    std::fs::create_dir_all(paths.locks_dir()).expect("directories should be creatable");
    let elsewhere = dir.path().join("elsewhere");
    std::fs::write(&elsewhere, b"{}").expect("the target should be writable");
    std::os::unix::fs::symlink(&elsewhere, paths.lock_path("acct", "org"))
        .expect("the symlink should be creatable");

    let err = acquire(&paths, "acct", "org", soon(), &Cancel::new(), Fault::none())
        .expect_err("a symlinked lock path must be refused");
    assert!(matches!(err, LockError::RefusedSymlink(_)), "got {err:?}");
    assert_eq!(std::fs::read_to_string(&elsewhere).expect("readable"), "{}");
}

#[test]
fn an_invalid_segment_is_refused_before_any_file_is_created() {
    let (_dir, paths) = store();
    for (acct, org) in [("..", "org"), ("acct", "../.."), ("a/b", "org"), ("", "org")] {
        let err = acquire(&paths, acct, org, soon(), &Cancel::new(), Fault::none())
            .expect_err("an unusable segment must be refused");
        assert!(matches!(err, LockError::Unavailable(_)), "({acct}, {org}) gave {err:?}");
    }
}

#[test]
fn a_second_holder_waits_and_then_acquires_when_the_first_releases() {
    let (_dir, paths) = store();
    let first = acquire(&paths, "acct", "org", soon(), &Cancel::new(), Fault::none())
        .expect("the first acquire should succeed");

    let released = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = std::sync::Arc::clone(&released);
    let path = paths.clone();
    let waiter = std::thread::spawn(move || {
        let start = Instant::now();
        let guard = acquire(
            &path,
            "acct",
            "org",
            Instant::now() + Duration::from_secs(10),
            &Cancel::new(),
            Fault::none(),
        );
        (guard.is_ok(), start.elapsed(), flag.load(std::sync::atomic::Ordering::SeqCst))
    });

    // Long enough that the waiter has certainly failed at least one attempt.
    std::thread::sleep(Duration::from_millis(600));
    released.store(true, std::sync::atomic::Ordering::SeqCst);
    drop(first);

    let (acquired, waited, saw_release) =
        waiter.join().expect("the waiting thread should not panic");
    assert!(acquired, "the second holder should get the lock once the first drops it");
    assert!(waited >= Duration::from_millis(500), "it waited only {waited:?}");
    assert!(saw_release, "it acquired after the release, not before");
}

#[test]
fn a_contended_lock_reports_busy_at_the_deadline() {
    let (_dir, paths) = store();
    let _held = acquire(&paths, "acct", "org", soon(), &Cancel::new(), Fault::none())
        .expect("the first acquire should succeed");

    let start = Instant::now();
    let err = acquire(
        &paths,
        "acct",
        "org",
        Instant::now() + Duration::from_millis(300),
        &Cancel::new(),
        Fault::none(),
    )
    .expect_err("a held lock should time out");
    assert_eq!(err, LockError::Busy);
    assert!(start.elapsed() < Duration::from_secs(5), "it gave up promptly");
}

#[test]
fn cancellation_beats_the_deadline() {
    let (_dir, paths) = store();
    let _held = acquire(&paths, "acct", "org", soon(), &Cancel::new(), Fault::none())
        .expect("the first acquire should succeed");

    let cancel = Cancel::new();
    cancel.cancel();
    let err = acquire(
        &paths,
        "acct",
        "org",
        Instant::now() + Duration::from_secs(60),
        &cancel,
        Fault::none(),
    )
    .expect_err("a cancelled wait should not block");
    assert_eq!(err, LockError::Cancelled);
}

#[test]
fn read_body_returns_none_for_a_missing_or_unparseable_file() {
    let (dir, _paths) = store();
    assert_eq!(read_body(&dir.path().join("absent")), None);

    let corrupt = dir.path().join("corrupt");
    std::fs::write(&corrupt, b"not json").expect("writable");
    assert_eq!(read_body(&corrupt), None);

    let huge = dir.path().join("huge");
    std::fs::write(&huge, vec![b'x'; 8192]).expect("writable");
    assert_eq!(read_body(&huge), None);
}

#[test]
fn two_namespaces_do_not_contend() {
    let (_dir, paths) = store();
    let _first = acquire(&paths, "acct", "org-a", soon(), &Cancel::new(), Fault::none())
        .expect("the first namespace should lock");
    let _second = acquire(&paths, "acct", "org-b", soon(), &Cancel::new(), Fault::none())
        .expect("a different namespace should lock independently");
}

#[cfg(feature = "testing")]
#[test]
fn an_unsupported_flock_fails_closed() {
    // Plan AC48(b): a filesystem without `flock` is one agentctl declines to
    // refresh on, rather than one it writes to without mutual exclusion.
    let (_dir, paths) = store();
    let err =
        acquire(&paths, "acct", "org", soon(), &Cancel::new(), Fault::from_list("flock_enotsup"))
            .expect_err("an unsupported flock must not be treated as an acquired lock");
    assert!(matches!(err, LockError::Unavailable(_)), "got {err:?}");
}

#[cfg(feature = "testing")]
#[test]
fn hold_lock_keeps_the_lock_until_the_deadline() {
    // Plan AC7 and AC35 lean on this to make a second process actually wait.
    let (_dir, paths) = store();
    let start = Instant::now();
    let _guard = acquire(
        &paths,
        "acct",
        "org",
        Instant::now() + Duration::from_millis(300),
        &Cancel::new(),
        Fault::from_list("hold_lock"),
    )
    .expect("the lock is still acquired, just held");
    assert!(start.elapsed() >= Duration::from_millis(250), "it returned before the deadline");
}

#[test]
fn the_documented_timings_are_the_plan_s() {
    assert_eq!(RETRY_INTERVAL, Duration::from_millis(250));
    assert_eq!(COMMAND_LOCK_TIMEOUT, Duration::from_secs(5));
}
