//! Tests for the namespace lock (plan AC48, L3).

use std::os::fd::AsFd;
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

#[test]
fn a_symlinked_locks_directory_is_refused() {
    // A link at `.locks` puts this store's locks — and with them its idea of
    // who may write a namespace — under somebody else's control, so both the
    // directory check and the descriptor the lock is opened relative to
    // refuse it.
    let (dir, paths) = store();
    let elsewhere = dir.path().join("someone-elses-locks");
    std::fs::create_dir_all(&elsewhere).expect("directories should be creatable");
    std::fs::create_dir_all(paths.namespace_root()).expect("directories should be creatable");
    std::os::unix::fs::symlink(&elsewhere, paths.locks_dir())
        .expect("the symlink should be creatable");

    let err = acquire(&paths, "acct", "org", soon(), &Cancel::new(), Fault::none())
        .expect_err("a symlinked locks directory must be refused");
    assert!(matches!(err, LockError::RefusedSymlink(_)), "got {err:?}");

    let planted: Vec<_> = std::fs::read_dir(&elsewhere)
        .expect("listable")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(planted.is_empty(), "a lock file was created through the link: {planted:?}");
}

#[test]
fn a_file_where_the_locks_directory_belongs_is_refused() {
    let (_dir, paths) = store();
    std::fs::create_dir_all(paths.namespace_root()).expect("directories should be creatable");
    std::fs::write(paths.locks_dir(), b"not a directory").expect("the file should be writable");

    let err = acquire(&paths, "acct", "org", soon(), &Cancel::new(), Fault::none())
        .expect_err("a file where the locks directory belongs must be refused");
    assert!(matches!(err, LockError::Unavailable(_)), "got {err:?}");
}

#[test]
fn a_symlinked_configuration_directory_is_followed_rather_than_refused() {
    // The counterpart to the `.locks` rule, and the reason the two paths are
    // opened differently. `.locks` lives inside a directory agentctl created,
    // so a link there is nobody's legitimate layout. The configuration
    // directory is a path the *user* names, and a dotfile manager pointing it
    // at a repository is ordinary; `Paths::ensure_dirs` and the config writer
    // both follow it, so the lock has to as well or the layout is only
    // half-supported.
    let dir = TempDir::new().expect("a temporary directory should be available");
    let real = dir.path().join("dotfiles-agentctl");
    std::fs::create_dir_all(&real).expect("directories should be creatable");
    let linked = dir.path().join("agentctl");
    std::os::unix::fs::symlink(&real, &linked).expect("the symlink should be creatable");

    let paths = Paths::with_config_dir(linked);
    let guard = lock_file(&paths.config_lock(), soon(), &Cancel::new(), &Fault::none())
        .expect("a symlinked configuration directory is a supported layout");
    assert!(real.join(".config.lock").exists(), "the lock landed in the real directory");
    drop(guard);
}

#[test]
fn many_threads_racing_to_create_one_fresh_lock_file_all_open_it() {
    // A regression test for a fault a single-shot test misses. Darwin does
    // not retry `openat`'s lookup when another thread wins an `O_CREAT` race,
    // so `openat(dirfd, name, O_RDWR | O_CREAT, ..)` on a lock file that does
    // not exist yet returns `ENOENT` — not `EEXIST` — for a large fraction of
    // the racers: a two-thread probe measured 328 failures in 800 attempts on
    // this machine, and it cost roughly four `AgentctlConfig::update` runs in
    // five before `open_lock_file` split the create out behind `O_EXCL`.
    //
    // `open_lock_file` is exercised rather than `acquire` on purpose: the
    // fault is in the create, and going through `acquire` would serialise the
    // threads on the `flock` and spend the whole test in its 250 ms backoff.
    const THREADS: usize = 8;
    const ROUNDS: usize = 60;

    for round in 0..ROUNDS {
        let dir = TempDir::new().expect("a temporary directory should be available");
        let path = dir.path().join(".config.lock");
        let name = path.file_name().expect("the path names a file");
        let parent = rustix::fs::open(
            dir.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("the temporary directory should be openable");

        let failures = std::sync::Mutex::new(Vec::new());
        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                scope.spawn(|| {
                    if let Err(err) = open_lock_file(parent.as_fd(), name, &path) {
                        failures
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .push(err.to_string());
                    }
                });
            }
        });

        let failures = failures.into_inner().unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(failures.is_empty(), "round {round}: {failures:?}");
        assert!(path.exists(), "round {round}: the lock file should have been created");
    }
}

#[test]
fn a_lock_file_that_is_a_symlink_is_still_refused_when_it_has_to_be_created_around() {
    // The create path uses `O_CREAT | O_EXCL`, which reports a planted link as
    // `EEXIST`; the retry then opens it `O_NOFOLLOW` and reports it properly.
    let (dir, paths) = store();
    std::fs::create_dir_all(paths.namespace_root()).expect("directories should be creatable");
    std::fs::create_dir_all(paths.locks_dir()).expect("directories should be creatable");
    let elsewhere = dir.path().join("planted.lock");
    std::fs::write(&elsewhere, b"{}").expect("the file should be writable");
    std::os::unix::fs::symlink(&elsewhere, paths.lock_path("acct", "org"))
        .expect("the symlink should be creatable");

    let err = acquire(&paths, "acct", "org", soon(), &Cancel::new(), Fault::none())
        .expect_err("a symlinked lock file must be refused");
    assert!(matches!(err, LockError::RefusedSymlink(_)), "got {err:?}");
    assert_eq!(
        std::fs::read_to_string(&elsewhere).expect("readable"),
        "{}",
        "the link's target was written through"
    );
}
