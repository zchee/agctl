//! Tests for the configuration-lock peer (spike S13's V8, rulings G5, G6, G15).
//!
//! Every test runs against a temporary `$HOME` whose `.claude.json` is a
//! **symbolic link** into `$HOME/.claude-real/`, the reference machine's shape,
//! so the literal-path rule is exercised rather than assumed. Nothing here
//! reaches the developer's own `~/.claude.json`.
//!
//! The seams are recorded, not mocked: [`SpyFs`] passes every operation through
//! to [`RealFs`] with the slot it was given, and [`SpyClock`] records sleeps
//! into the same timeline without sleeping, so "nothing is waited on while
//! held" and "a stale lock is never removed" are claims about a sequence a test
//! can read.

use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;

use tempfile::TempDir;

use super::*;
use crate::runtime::coordinator::Cancel;
use crate::secret::claude_lock::RealFs;
use crate::secret::claude_lock::TimeSource;

/// What the seams saw, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Op {
    /// A `mkdir` of that path, and whether it succeeded.
    Mkdir(PathBuf, bool),
    /// An `rmdir` of that path.
    Rmdir(PathBuf),
    /// A sleep of that long.
    Sleep(Duration),
}

type Timeline = Arc<Mutex<Vec<Op>>>;

fn ops(timeline: &Timeline) -> Vec<Op> {
    timeline.lock().unwrap_or_else(PoisonError::into_inner).clone()
}

fn push(timeline: &Timeline, op: Op) {
    timeline.lock().unwrap_or_else(PoisonError::into_inner).push(op);
}

/// The real directory operations, recorded.
struct SpyFs {
    timeline: Timeline,
}

impl LockFs for SpyFs {
    fn mkdir(&self, at: LockSlot<'_>) -> Result<(), FsError> {
        let result = RealFs.mkdir(at);
        push(&self.timeline, Op::Mkdir(at.shown.to_path_buf(), result.is_ok()));
        result
    }

    fn rmdir(&self, at: LockSlot<'_>) -> Result<(), FsError> {
        let result = RealFs.rmdir(at);
        push(&self.timeline, Op::Rmdir(at.shown.to_path_buf()));
        result
    }

    fn mtime(&self, at: LockSlot<'_>) -> Option<SystemTime> {
        RealFs.mtime(at)
    }
}

/// Real clocks whose sleeps are recorded and free, and which can cancel a run
/// from inside the first sleep.
struct SpyClock {
    timeline: Timeline,
    cancel_on_first_sleep: Option<Cancel>,
}

impl TimeSource for SpyClock {
    fn wall(&self) -> SystemTime {
        SystemTime::now()
    }

    fn monotonic(&self) -> Instant {
        Instant::now()
    }

    fn sleep(&self, how_long: Duration, _cancel: &Cancel) -> bool {
        push(&self.timeline, Op::Sleep(how_long));
        match &self.cancel_on_first_sleep {
            Some(cancel) => {
                cancel.cancel();
                true
            }
            None => false,
        }
    }
}

/// A temporary home with `.claude.json` linked into `.claude-real/`.
///
/// Returns the home, the link and the target.
fn linked_home() -> (TempDir, PathBuf, PathBuf) {
    let home = TempDir::new().expect("a temporary home");
    let real = home.path().join(".claude-real");
    fs::create_dir_all(&real).expect("the link target's directory is creatable");
    let target = real.join(".claude.json");
    fs::write(&target, "{}").expect("the target is writable");
    let link = home.path().join(".claude.json");
    std::os::unix::fs::symlink(&target, &link).expect("the link is plantable");
    (home, link, target)
}

fn seams(cancel_on_first_sleep: Option<Cancel>) -> (Timeline, Clock, Arc<dyn LockFs>) {
    let timeline: Timeline = Arc::new(Mutex::new(Vec::new()));
    let clock = Clock::from_source(Arc::new(SpyClock {
        timeline: Arc::clone(&timeline),
        cancel_on_first_sleep,
    }));
    let fs: Arc<dyn LockFs> = Arc::new(SpyFs { timeline: Arc::clone(&timeline) });
    (timeline, clock, fs)
}

fn ctx_with(cancel: Cancel) -> PassCtx {
    PassCtx::standalone(cancel, Instant::now() + Duration::from_secs(60))
}

fn modified(path: &Path) -> SystemTime {
    fs::symlink_metadata(path)
        .and_then(|meta| meta.modified())
        .unwrap_or_else(|err| panic!("`{}` should be stat-able: {err}", path.display()))
}

fn set_mtime(path: &Path, at: SystemTime) {
    let since = at.duration_since(SystemTime::UNIX_EPOCH).expect("after the epoch");
    let stamp = rustix::fs::Timespec {
        tv_sec: i64::try_from(since.as_secs()).expect("a plausible second"),
        tv_nsec: i64::from(since.subsec_nanos()),
    };
    rustix::fs::utimensat(
        rustix::fs::CWD,
        path,
        &rustix::fs::Timestamps { last_access: stamp, last_modification: stamp },
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .expect("the modification time should be settable");
}

#[test]
fn the_lock_is_beside_the_literal_path_not_the_realpath() {
    // Drift 1: `lockfilePath` is `${configPath}.lock` and never goes through
    // `realpath`, so the lock sits beside the link. A build that locked beside
    // the target would hold a lock no Claude Code session ever takes.
    let (home, link, target) = linked_home();
    let (timeline, clock, fs) = seams(None);
    let beside_link = home.path().join(".claude.json.lock");
    let mut beside_target = target.as_os_str().to_os_string();
    beside_target.push(".lock");
    let beside_target = PathBuf::from(beside_target);

    let hold = acquire(&link, &clock, fs, &ctx_with(Cancel::new())).expect("a free lock is taken");

    assert!(beside_link.is_dir(), "`$HOME/.claude.json.lock` exists while held");
    assert!(!beside_target.exists(), "the realpath sibling never exists");
    assert_eq!(hold.shown(), beside_link.as_path(), "the hold names the literal lock");
    assert_eq!(fs::read_link(&link).expect("still a link"), target, "the link is untouched");
    hold.drift_check().expect("nothing moved the lock");
    assert!(hold.elapsed() < CONFIG_PROFILE.hold_budget, "a fresh hold is inside the budget");

    drop(hold);
    assert!(!beside_link.exists(), "released on drop");
    assert!(!beside_target.exists(), "the realpath sibling never existed");
    assert_eq!(
        ops(&timeline),
        vec![Op::Mkdir(beside_link.clone(), true), Op::Rmdir(beside_link)],
        "one mkdir, no wait, one rmdir"
    );
}

#[test]
fn a_held_config_lock_is_waited_on_outside_the_hold_then_skipped() {
    // Ruling G6: `[200, 400, 800] ms × (1 + rand)`, three sleeps and four
    // attempts, with nothing of agctl's held during any of them; then `Busy`.
    // The peer's lock is never touched — neither removed nor re-stamped.
    let (home, link, _target) = linked_home();
    let planted = home.path().join(".claude.json.lock");
    fs::create_dir(&planted).expect("a peer's fresh lock");
    let planted_mtime = modified(&planted);
    let (timeline, clock, fs) = seams(None);

    let err =
        acquire(&link, &clock, fs, &ctx_with(Cancel::new())).expect_err("a held lock is busy");
    assert_eq!(err, ConfigLockError::Busy);

    let seen = ops(&timeline);
    let sleeps: Vec<Duration> = seen
        .iter()
        .filter_map(|op| match op {
            Op::Sleep(how_long) => Some(*how_long),
            _ => None,
        })
        .collect();
    assert_eq!(sleeps.len(), 3, "three rungs: {seen:?}");
    for (k, (slept, rung)) in sleeps.iter().zip(CONTENTION_LADDER).enumerate() {
        assert!(
            *slept >= rung && *slept < rung.saturating_mul(2),
            "sleep {k} was {slept:?}, outside [{rung:?}, {:?})",
            rung.saturating_mul(2)
        );
    }
    let total: Duration = sleeps.iter().sum();
    assert!(total <= Duration::from_millis(2800), "the ladder is at most 2 800 ms: {total:?}");
    assert!(
        !seen.iter().any(|op| matches!(op, Op::Mkdir(_, true))),
        "no mkdir succeeded: {seen:?}"
    );
    assert!(!seen.iter().any(|op| matches!(op, Op::Rmdir(_))), "nothing was removed: {seen:?}");
    assert_eq!(
        seen.iter().filter(|op| matches!(op, Op::Mkdir(_, false))).count(),
        4,
        "an attempt before each rung and one after the last: {seen:?}"
    );
    // Strictly alternating attempt/sleep: no sleep follows a successful mkdir.
    assert!(
        matches!(seen.last(), Some(Op::Mkdir(_, false))),
        "it ends on the last attempt: {seen:?}"
    );

    assert!(planted.is_dir(), "the planted directory still exists");
    assert_eq!(modified(&planted), planted_mtime, "and its mtime is unchanged");
}

#[test]
fn a_stale_config_lock_is_reported_and_never_removed() {
    // Ruling G5: a stale lock ends the ladder at the first rung. Waiting cannot
    // clear it, and breaking it is not agctl's — a wrong break corrupts the
    // file a peer is writing.
    let (home, link, _target) = linked_home();
    let planted = home.path().join(".claude.json.lock");
    fs::create_dir(&planted).expect("an abandoned lock");
    let aged = SystemTime::now().checked_sub(Duration::from_secs(60)).expect("a plausible instant");
    set_mtime(&planted, aged);
    let (timeline, clock, fs) = seams(None);

    let err = acquire(&link, &clock, fs, &ctx_with(Cancel::new())).expect_err("stale is reported");
    let ConfigLockError::Stale { age_ms } = err else { panic!("expected Stale, got {err:?}") };
    assert!(age_ms >= 10_000, "at least the staleness window: {age_ms}");
    assert!(age_ms >= 59_000, "the planted age: {age_ms}");

    let seen = ops(&timeline);
    assert!(!seen.iter().any(|op| matches!(op, Op::Sleep(_))), "no sleep: {seen:?}");
    assert!(!seen.iter().any(|op| matches!(op, Op::Rmdir(_))), "no rmdir recorded: {seen:?}");
    assert_eq!(seen, vec![Op::Mkdir(planted.clone(), false)], "one attempt and nothing else");
    assert!(planted.is_dir(), "the stale directory is still present");
    assert_eq!(modified(&planted), aged, "and its mtime is unchanged");
}

#[test]
fn the_config_lock_is_released_on_drop_and_on_cancellation() {
    let lock_of = |home: &TempDir| home.path().join(".claude.json.lock");

    // Drop gives the lock back.
    {
        let (home, link, _target) = linked_home();
        let (_timeline, clock, fs) = seams(None);
        let hold = acquire(&link, &clock, fs, &ctx_with(Cancel::new())).expect("taken");
        assert!(lock_of(&home).is_dir());
        drop(hold);
        assert!(!lock_of(&home).exists(), "gone after drop");
    }

    // Cancelled during rung 1: `Cancelled`, and nothing of agctl's created.
    {
        let (home, link, _target) = linked_home();
        fs::create_dir(lock_of(&home)).expect("a peer's fresh lock");
        let cancel = Cancel::new();
        let (timeline, clock, fs) = seams(Some(cancel.clone()));
        let err = acquire(&link, &clock, fs, &ctx_with(cancel.clone())).expect_err("cancelled");
        assert_eq!(err, ConfigLockError::Cancelled);
        assert!(cancel.is_cancelled());
        let seen = ops(&timeline);
        assert_eq!(seen.iter().filter(|op| matches!(op, Op::Sleep(_))).count(), 1, "{seen:?}");
        assert!(!seen.iter().any(|op| matches!(op, Op::Mkdir(_, true) | Op::Rmdir(_))), "{seen:?}");
        assert!(lock_of(&home).is_dir(), "the peer's lock is left as it was");
    }

    // A deadline that has passed stops the ladder after its sleep as well.
    {
        let (home, link, _target) = linked_home();
        fs::create_dir(lock_of(&home)).expect("a peer's fresh lock");
        let (_timeline, clock, fs) = seams(None);
        let expired = PassCtx::standalone(Cancel::new(), Instant::now());
        assert_eq!(
            acquire(&link, &clock, fs, &expired).expect_err("stopped"),
            ConfigLockError::Cancelled
        );
    }

    // The emergency registry releases a live hold — and unlinks the temporary
    // file the hold is tracking — as SIGTERM/SIGINT/SIGHUP would.
    {
        let (home, link, target) = linked_home();
        let (_timeline, clock, fs) = seams(None);
        let hold = acquire(&link, &clock, fs, &ctx_with(Cancel::new())).expect("taken");
        let target_dir = Arc::new(
            rustix::fs::open(
                target.parent().expect("a parent"),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .expect("the target's directory opens"),
        );
        let temp = target.with_file_name(".claude.json.tmp.1.0123456789ab");
        hold.track_temp(target_dir, OsString::from(".claude.json.tmp.1.0123456789ab"));
        fs::write(&temp, "partial").expect("a temporary file");

        cleanup::emergency();
        assert!(!lock_of(&home).exists(), "the emergency release removed the lock");
        assert!(!temp.exists(), "and the tracked temporary file");
        assert_eq!(fs::read(&target).expect("readable"), b"{}", "the target is untouched");
        assert!(fs::symlink_metadata(&link).expect("the link").file_type().is_symlink());

        // A drop after the emergency release removes nothing: the emergency
        // closure already gave the lock back, so the name may be a peer's by now
        // (review round 1 F2). A peer takes it, and the drop leaves it alone.
        fs::create_dir(lock_of(&home)).expect("a peer takes the released lock");
        let peer_mtime = modified(&lock_of(&home));
        drop(hold);
        assert!(lock_of(&home).is_dir(), "the peer's lock still exists after the drop");
        assert_eq!(modified(&lock_of(&home)), peer_mtime, "and is untouched");
    }

    // An untracked temporary file is never unlinked by a release.
    {
        let (home, link, target) = linked_home();
        let (_timeline, clock, fs) = seams(None);
        let hold = acquire(&link, &clock, fs, &ctx_with(Cancel::new())).expect("taken");
        let target_dir = Arc::new(
            rustix::fs::open(
                target.parent().expect("a parent"),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .expect("the target's directory opens"),
        );
        let renamed = target.with_file_name(".claude.json.tmp.2.0123456789ab");
        fs::write(&renamed, "kept").expect("a file");
        hold.track_temp(target_dir, OsString::from(".claude.json.tmp.2.0123456789ab"));
        hold.untrack_temp();
        hold.release();
        assert!(!lock_of(&home).exists(), "released");
        assert!(renamed.exists(), "an untracked name is left alone");
    }
}
