//! Tests for Claude Code's lock protocol.
//!
//! Three seams carry the whole suite, and all three exist because the claims
//! being checked are claims about a **sequence**, not about a final state:
//!
//! - a [`SpyFs`] that passes every `mkdir`/`rmdir` through to the real
//!   filesystem and records it, so "one non-blocking attempt" and "released
//!   in reverse order" are checkable;
//! - a [`FakeClock`] that records its sleeps **into the same timeline**, so
//!   "no wait of any kind occurs while a lock is held" is one assertion over
//!   one ordered list rather than an inference;
//! - a [`FakeHolders`] that answers the holder question without any process
//!   on the machine being stopped.
//!
//! Modification times are planted with `utimensat` and compared exactly. A
//! tolerance-based comparison fails this suite: several rows differ by a
//! single nanosecond.

use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Instant;
use std::time::SystemTime;

use super::*;

// ---------------------------------------------------------------------------
// The shared timeline
// ---------------------------------------------------------------------------

/// One observable operation, in the order it happened.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Op {
    /// A `mkdir` attempt and whether it succeeded.
    Mkdir(PathBuf, bool),
    /// A `rmdir` attempt.
    Rmdir(PathBuf),
    /// A wait. Recorded here, in the same list as the directory operations,
    /// so that "no wait while holding" is a property of one sequence.
    Sleep(Duration),
}

/// The timeline, with the moment each operation happened.
#[derive(Default)]
struct Timeline {
    ops: Vec<(Instant, Op)>,
}

impl Timeline {
    fn push(&mut self, op: Op) {
        self.ops.push((Instant::now(), op));
    }
}

/// A timeline several seams write to.
#[derive(Clone, Default)]
struct Shared(Arc<Mutex<Timeline>>);

impl Shared {
    fn push(&self, op: Op) {
        lock(&self.0).push(op);
    }

    fn ops(&self) -> Vec<Op> {
        lock(&self.0).ops.iter().map(|(_, op)| op.clone()).collect()
    }

    fn stamped(&self) -> Vec<(Instant, Op)> {
        lock(&self.0).ops.clone()
    }

    /// Every `mkdir` attempt on `path`, successful or not.
    fn mkdir_attempts(&self, path: &Path) -> usize {
        self.ops().iter().filter(|op| matches!(op, Op::Mkdir(seen, _) if seen == path)).count()
    }

    /// Whether any wait happened between a successful `mkdir` and the
    /// `rmdir` that gave it back.
    ///
    /// This is invariant I17's first clause, and architect N-1's whole point:
    /// the peer gives up on its refresh after 4 000 ms (fact F53), so a
    /// 12-second sampling window inside a hold is not slow but fatal.
    fn slept_while_holding(&self) -> bool {
        let mut held = 0_usize;
        for op in self.ops() {
            match op {
                Op::Mkdir(_, true) => held = held.saturating_add(1),
                Op::Rmdir(_) => held = held.saturating_sub(1),
                Op::Sleep(_) if held > 0 => return true,
                Op::Sleep(_) | Op::Mkdir(_, false) => {}
            }
        }
        false
    }
}

/// Locks a mutex, recovering from poisoning so one failing assertion does not
/// cascade into a dozen unrelated ones.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

// ---------------------------------------------------------------------------
// The three seams
// ---------------------------------------------------------------------------

/// The real directory operations, recorded — and optionally with a peer that
/// retakes a lock the instant it is released.
struct SpyFs {
    timeline: Shared,
    real: RealFs,
    /// Paths a "peer" recreates immediately after a successful `rmdir`,
    /// which is the only way to reach section 3.8's `retaken`.
    retake: Mutex<Vec<PathBuf>>,
    /// Paths a "peer" creates just *before* agentctl's own `mkdir`, which is
    /// the only way to reach an `EEXIST` on a lock that was free when the
    /// lock-free probe looked at it.
    plant_before: Mutex<Vec<PathBuf>>,
}

impl SpyFs {
    fn new(timeline: Shared) -> Self {
        Self {
            timeline,
            real: RealFs,
            retake: Mutex::new(Vec::new()),
            plant_before: Mutex::new(Vec::new()),
        }
    }

    /// Makes a peer recreate `path` the moment agentctl removes it.
    fn retake_after_rmdir(&self, path: &Path) {
        lock(&self.retake).push(path.to_path_buf());
    }

    /// Makes a peer win the race for `path` on every attempt.
    fn plant_before_mkdir(&self, path: &Path) {
        lock(&self.plant_before).push(path.to_path_buf());
    }
}

impl LockFs for SpyFs {
    fn mkdir(&self, path: &Path) -> Result<(), FsError> {
        if lock(&self.plant_before).iter().any(|planted| planted == path) {
            // The peer's own `mkdir`, not agentctl's: deliberately not
            // recorded, because the timeline is a record of what agentctl did.
            let _ = self.real.mkdir(path);
        }
        let result = self.real.mkdir(path);
        self.timeline.push(Op::Mkdir(path.to_path_buf(), result.is_ok()));
        result
    }

    fn rmdir(&self, path: &Path) -> Result<(), FsError> {
        let result = self.real.rmdir(path);
        self.timeline.push(Op::Rmdir(path.to_path_buf()));
        if result.is_ok() && lock(&self.retake).iter().any(|held| held == path) {
            let _ = self.real.mkdir(path);
        }
        result
    }
}

/// Applies scheduled actions to the filesystem.
///
/// A wall-clock step is applied by the caller, under its own lock, because it
/// changes the clock rather than the world.
fn apply(actions: &[Action]) {
    for action in actions {
        match action {
            Action::Mtime(path, at) => set_mtime(path, *at),
            Action::Remove(path) => {
                let _ = RealFs.rmdir(path);
            }
            Action::WallJump(..) => {}
        }
    }
}

/// What the fake clock does to the world at a given moment.
#[derive(Debug, Clone)]
enum Action {
    /// A holder heartbeat: set a lock's modification time.
    Mtime(PathBuf, SystemTime),
    /// The lock disappears.
    Remove(PathBuf),
    /// The wall clock steps, forwards or backwards, while the monotonic
    /// clock does not.
    WallJump(Duration, bool),
}

/// A clock whose waits are free and whose two hands can be made to disagree.
///
/// Actions are scheduled against the **count of `wall()` calls**, because
/// that count is exactly the rule's own structure: call 1 is Sample A, 2 is
/// Sample B and 3 is Sample C. Scheduling on call 3 therefore lands an
/// action in the two-syscall window between Sample B and Sample C — the
/// window Sample C exists to close (critic C2).
struct FakeClock {
    timeline: Shared,
    inner: Mutex<Fake>,
}

struct Fake {
    wall: SystemTime,
    mono: Instant,
    wall_calls: u32,
    on_wall: Vec<(u32, Action)>,
    sleeps: u32,
    on_sleep: Vec<(u32, Action)>,
    cancel_on_sleep: Option<Cancel>,
    slept: Vec<Duration>,
}

impl FakeClock {
    fn new(timeline: Shared, base: SystemTime) -> Arc<Self> {
        Arc::new(Self {
            timeline,
            inner: Mutex::new(Fake {
                wall: base,
                mono: Instant::now(),
                wall_calls: 0,
                on_wall: Vec::new(),
                sleeps: 0,
                on_sleep: Vec::new(),
                cancel_on_sleep: None,
                slept: Vec::new(),
            }),
        })
    }

    /// Runs `action` on the `call`-th `wall()` call: 1 is Sample A, 2 is
    /// Sample B and 3 is Sample C.
    fn schedule(&self, call: u32, action: Action) {
        lock(&self.inner).on_wall.push((call, action));
    }

    /// Runs `action` at the end of the `nth` sleep, which is how a holder
    /// heartbeats part-way through fact F36's contention schedule.
    fn schedule_on_sleep(&self, nth: u32, action: Action) {
        lock(&self.inner).on_sleep.push((nth, action));
    }

    fn cancel_next_sleep(&self, cancel: Cancel) {
        lock(&self.inner).cancel_on_sleep = Some(cancel);
    }

    fn slept(&self) -> Vec<Duration> {
        lock(&self.inner).slept.clone()
    }
}

impl TimeSource for FakeClock {
    fn wall(&self) -> SystemTime {
        let actions = {
            let mut inner = lock(&self.inner);
            inner.wall_calls = inner.wall_calls.saturating_add(1);
            let call = inner.wall_calls;
            let due: Vec<Action> = inner
                .on_wall
                .iter()
                .filter(|(at, _)| *at == call)
                .map(|(_, action)| action.clone())
                .collect();
            for action in &due {
                if let Action::WallJump(by, forward) = action {
                    inner.wall = if *forward {
                        inner.wall.checked_add(*by).unwrap_or(inner.wall)
                    } else {
                        inner.wall.checked_sub(*by).unwrap_or(inner.wall)
                    };
                }
            }
            due
        };

        // Filesystem actions run outside the lock: `set_mtime` and `rmdir`
        // are syscalls and holding a mutex across them would be gratuitous.
        apply(&actions);
        lock(&self.inner).wall
    }

    fn monotonic(&self) -> Instant {
        lock(&self.inner).mono
    }

    fn sleep(&self, how_long: Duration, cancel: &Cancel) -> bool {
        self.timeline.push(Op::Sleep(how_long));
        let (requested, due) = {
            let mut inner = lock(&self.inner);
            inner.slept.push(how_long);
            inner.sleeps = inner.sleeps.saturating_add(1);
            let nth = inner.sleeps;
            inner.wall = inner.wall.checked_add(how_long).unwrap_or(inner.wall);
            inner.mono = inner.mono.checked_add(how_long).unwrap_or(inner.mono);
            let due: Vec<Action> = inner
                .on_sleep
                .iter()
                .filter(|(at, _)| *at == nth)
                .map(|(_, action)| action.clone())
                .collect();
            (inner.cancel_on_sleep.take(), due)
        };
        apply(&due);
        if let Some(requested) = requested {
            requested.cancel();
        }
        cancel.is_cancelled()
    }
}

/// The holder question, answered without stopping anything.
struct FakeHolders {
    evidence: HolderEvidence3,
    pids: Vec<u32>,
}

impl FakeHolders {
    fn none_stopped() -> Self {
        Self { evidence: HolderEvidence3::NoStoppedClaude, pids: Vec::new() }
    }

    fn stopped(pids: &[u32]) -> Self {
        Self { evidence: HolderEvidence3::StoppedClaudePresent, pids: pids.to_vec() }
    }

    fn unknown() -> Self {
        Self { evidence: HolderEvidence3::None, pids: Vec::new() }
    }
}

impl HolderEvidence for FakeHolders {
    fn stopped_claude_present(&self) -> HolderEvidence3 {
        self.evidence
    }

    fn stopped_pids(&self) -> Vec<u32> {
        self.pids.clone()
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A store directory, an agentctl store beside it, and the three lock paths.
///
/// **No test in this file calls [`cleanup::emergency`].** That function is
/// process-wide and takes *every* registered entry, so calling it would
/// release the locks of any hold live in another thread — a cross-test
/// interference that only appears under `cargo test`, where the whole suite
/// shares one process. The registry's real behaviour is proved instead by the
/// two child-process tests at the end of this file, which is also what plan
/// AC64 asks for.
struct Fixture {
    _root: tempfile::TempDir,
    paths: Paths,
    store: PathBuf,
    primary: PathBuf,
    legacy: PathBuf,
    storage: PathBuf,
    timeline: Shared,
    fs: Arc<SpyFs>,
    base: SystemTime,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("a temporary directory");
        let store = root.path().join("store");
        fs::create_dir_all(&store).expect("the store directory should be creatable");
        let paths = Paths::with_config_dir(root.path().join("config"));
        paths.ensure_dirs().expect("the agentctl store should be creatable");

        let timeline = Shared::default();
        let fs_spy = Arc::new(SpyFs::new(timeline.clone()));
        let [primary, legacy, storage] = plan(&store).map(|lock| lock.path);

        Self {
            _root: root,
            paths,
            store,
            primary,
            legacy,
            storage,
            timeline,
            fs: fs_spy,
            base: SystemTime::now(),
        }
    }

    /// The three lock paths in acquisition order.
    fn all(&self) -> [PathBuf; 3] {
        [self.primary.clone(), self.legacy.clone(), self.storage.clone()]
    }

    /// Plants a lock directory whose modification time is `age` old.
    fn plant(&self, path: &Path, age: Duration) {
        RealFs.mkdir(path).expect("the lock directory should be creatable");
        set_mtime(path, self.base.checked_sub(age).expect("a plausible age"));
    }

    fn fake_clock(&self) -> Arc<FakeClock> {
        FakeClock::new(self.timeline.clone(), self.base)
    }

    fn seams<'a>(&self, clock: &Arc<FakeClock>, holders: &'a dyn HolderEvidence) -> Seams<'a> {
        Seams {
            fs: Arc::clone(&self.fs) as Arc<dyn LockFs>,
            holders,
            clock: Clock::from_source(Arc::clone(clock) as Arc<dyn TimeSource>),
        }
    }

    /// The held-lock records this store currently has.
    fn records(&self) -> Vec<(PathBuf, HeldLockRecord)> {
        held_records(&self.paths)
    }
}

/// A pass context with a generous deadline and its own cancellation flag.
fn ctx_with(cancel: &Cancel) -> PassCtx {
    PassCtx::standalone(cancel.clone(), Instant::now() + Duration::from_secs(600))
}

/// Sets a path's modification time exactly, without following links.
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
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .expect("the modification time should be settable");
}

/// One second past the refresh profile's staleness window.
fn stale_age() -> Duration {
    REFRESH_PROFILE.stale + Duration::from_secs(1)
}

// ---------------------------------------------------------------------------
// AC62 — the acquire truth table
// ---------------------------------------------------------------------------

#[test]
fn acquire_creates_all_three_in_the_peers_nesting() {
    let fixture = Fixture::new();
    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    let seams = fixture.seams(&clock, &holders);
    let cancel = Cancel::new();

    let acquired = acquire_with(
        &fixture.store,
        Tree::Agentctl,
        &fixture.paths,
        &ctx_with(&cancel),
        &Fault::none(),
        &seams,
    )
    .expect("an uncontended store");

    let AcquireOutcome::Held(hold) = acquired.outcome else { panic!("expected a hold") };
    assert_eq!(hold.store_dir(), fixture.store, "the hold knows what it is about");
    assert_eq!(hold.tree(), Tree::Agentctl, "and which tree it is in (invariant I11′)");
    assert_eq!(hold.paths(), fixture.all().to_vec(), "primary, legacy, `.storage-write` innermost");
    for path in fixture.all() {
        assert!(
            path.is_dir(),
            "`{}` is a directory, as `proper-lockfile` makes it",
            path.display()
        );
    }
    assert_eq!(
        fixture.timeline.ops(),
        vec![
            Op::Mkdir(fixture.primary.clone(), true),
            Op::Mkdir(fixture.legacy.clone(), true),
            Op::Mkdir(fixture.storage.clone(), true),
        ],
        "three `mkdir`s, in the peer's own nesting, and nothing else"
    );
    assert!(!fixture.timeline.slept_while_holding(), "invariant I17: no wait inside the hold");
    assert!(acquired.break_record.is_none(), "nothing was stale, so nothing was broken");

    // Step 6: the record exists, names the tree, and was written before the
    // first `mkdir` — which is why a crash leaves evidence at all.
    let records = fixture.records();
    assert_eq!(records.len(), 1, "one record per live hold");
    let (path, record) = &records[0];
    assert_eq!(path, hold.record_path());
    assert_eq!(record.agentctl_pid, std::process::id());
    assert_eq!(record.tree, Tree::Agentctl);
    assert_eq!(record.store_dir, fixture.store);
    assert_eq!(record.paths, fixture.all().to_vec());
    assert!(!record.taken_at.is_empty());
    assert_eq!(mode_of(path), FILE_MODE, "0600, like every other file agentctl writes");

    drop(hold);
    for path in fixture.all() {
        assert!(!path.exists(), "released on drop: `{}`", path.display());
    }
    assert!(fixture.records().is_empty(), "and the record is cleared");
}

#[test]
fn releasing_runs_in_reverse_order() {
    let fixture = Fixture::new();
    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    let seams = fixture.seams(&clock, &holders);
    let cancel = Cancel::new();

    let acquired = acquire_with(
        &fixture.store,
        Tree::Live,
        &fixture.paths,
        &ctx_with(&cancel),
        &Fault::none(),
        &seams,
    )
    .expect("an uncontended store");
    let AcquireOutcome::Held(hold) = acquired.outcome else { panic!("expected a hold") };
    drop(hold);

    // Deduplicated by first appearance: another module's test may drain the
    // process-wide cleanup registry while this one is running, which would
    // release the same three paths a second time in the same order. The
    // claim under test is the order, not the count.
    let mut releases: Vec<PathBuf> = Vec::new();
    for op in fixture.timeline.ops() {
        if let Op::Rmdir(path) = op
            && !releases.contains(&path)
        {
            releases.push(path);
        }
    }
    assert_eq!(
        releases,
        vec![fixture.storage.clone(), fixture.legacy.clone(), fixture.primary.clone()],
        "innermost first"
    );
}

#[test]
fn storage_write_is_one_non_blocking_attempt_per_round() {
    // Plan AC62: `.storage-write`'s profile carries `retries: 0` precisely so
    // that none of fact F47's ten-step, ~7.5 s ladder enters the hold. A
    // second attempt, or any wait, would show up in the timeline.
    let fixture = Fixture::new();
    fixture.plant(&fixture.storage, Duration::from_secs(1));
    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    let seams = fixture.seams(&clock, &holders);
    let cancel = Cancel::new();

    let acquired = acquire_with(
        &fixture.store,
        Tree::Agentctl,
        &fixture.paths,
        &ctx_with(&cancel),
        &Fault::none(),
        &seams,
    )
    .expect("a contended store is busy, not an error");

    let AcquireOutcome::Busy { holder_alive, stopped_pids } = acquired.outcome else {
        panic!("expected busy")
    };
    assert!(!holder_alive, "nothing was beating; the primary was never held by anyone");
    assert!(stopped_pids.is_empty());

    let rounds = usize::try_from(MAX_RESTARTS).expect("a small number") + 1;
    assert_eq!(
        fixture.mkdir_attempts_per_round(),
        rounds,
        "one round per restart, capped at MAX_RESTARTS"
    );
    assert_eq!(
        fixture.timeline.mkdir_attempts(&fixture.storage),
        rounds,
        "exactly one `.storage-write` attempt per round, never a retry inside one"
    );
    assert!(clock.slept().is_empty(), "and no wait at all: the primary was free");
    assert!(!fixture.timeline.slept_while_holding());
    assert!(fixture.records().is_empty(), "the record is cleared on every release");
}

impl Fixture {
    /// How many acquisition rounds the timeline shows, counted by attempts on
    /// the primary lock.
    fn mkdir_attempts_per_round(&self) -> usize {
        self.timeline.mkdir_attempts(&self.primary)
    }
}

#[test]
fn an_eexist_at_each_position_releases_everything_and_restarts() {
    // Plan AC62's middle clause, one row per position. The expected timeline
    // for one round is written out rather than summarised, because the claim
    // is about the order. The `MAX_RESTARTS` cap itself is counted by
    // `storage_write_is_one_non_blocking_attempt_per_round`.
    //
    // Position 1: the primary, lost to a peer that wins the race *after* the
    // lock-free probe found it free. A primary that was already there when
    // the probe looked is waited out on fact F36's schedule instead, which is
    // the row below.
    let fixture = Fixture::new();
    fixture.fs.plant_before_mkdir(&fixture.primary);
    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    let seams = fixture.seams(&clock, &holders);
    let cancel = Cancel::new();
    let acquired = acquire_with(
        &fixture.store,
        Tree::Agentctl,
        &fixture.paths,
        &ctx_with(&cancel),
        &Fault::none(),
        &seams,
    )
    .expect("busy, not an error");
    assert!(matches!(acquired.outcome, AcquireOutcome::Busy { .. }));
    assert_eq!(
        fixture.timeline.ops()[0],
        Op::Mkdir(fixture.primary.clone(), false),
        "the first position fails, and nothing had been taken to release"
    );
    assert!(
        !fixture.timeline.ops().iter().any(|op| matches!(op, Op::Rmdir(_))),
        "nothing was held, so nothing is released: {:?}",
        fixture.timeline.ops()
    );
    assert!(!fixture.timeline.slept_while_holding());

    // Position 2: the legacy lock. Fact F46: a legacy `ELOCKED` releases the
    // primary and rethrows.
    let fixture = Fixture::new();
    fixture.plant(&fixture.legacy, Duration::from_secs(1));
    let clock = fixture.fake_clock();
    let seams = fixture.seams(&clock, &holders);
    let acquired = acquire_with(
        &fixture.store,
        Tree::Agentctl,
        &fixture.paths,
        &ctx_with(&cancel),
        &Fault::none(),
        &seams,
    )
    .expect("busy, not an error");
    assert!(matches!(acquired.outcome, AcquireOutcome::Busy { .. }));
    assert_eq!(
        fixture.timeline.ops()[..3],
        [
            Op::Mkdir(fixture.primary.clone(), true),
            Op::Mkdir(fixture.legacy.clone(), false),
            Op::Rmdir(fixture.primary.clone()),
        ],
        "the primary is released first, before anything is retried"
    );
    assert!(!fixture.timeline.slept_while_holding());

    // Position 3: `.storage-write`, the innermost.
    let fixture = Fixture::new();
    fixture.plant(&fixture.storage, Duration::from_secs(1));
    let clock = fixture.fake_clock();
    let seams = fixture.seams(&clock, &holders);
    let acquired = acquire_with(
        &fixture.store,
        Tree::Agentctl,
        &fixture.paths,
        &ctx_with(&cancel),
        &Fault::none(),
        &seams,
    )
    .expect("busy, not an error");
    assert!(matches!(acquired.outcome, AcquireOutcome::Busy { .. }));
    assert_eq!(
        fixture.timeline.ops()[..5],
        [
            Op::Mkdir(fixture.primary.clone(), true),
            Op::Mkdir(fixture.legacy.clone(), true),
            Op::Mkdir(fixture.storage.clone(), false),
            Op::Rmdir(fixture.legacy.clone()),
            Op::Rmdir(fixture.primary.clone()),
        ],
        "both held locks released, innermost first"
    );
    assert!(!fixture.timeline.slept_while_holding());
}

#[test]
fn a_beating_primary_is_waited_on_the_peers_own_schedule() {
    // Plan AC62 and AC68: a live session holding the refresh lock is not a
    // refusal. The schedule is fact F36's — five rounds of 1 000 + rand·1 000
    // ms, then a top-up to the 7 500 ms floor — and it runs lock-free.
    let fixture = Fixture::new();
    fixture.plant(&fixture.primary, Duration::from_secs(1));
    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    let seams = fixture.seams(&clock, &holders);
    let cancel = Cancel::new();

    // The holder heartbeats part-way through the schedule. Any change at all
    // is what "alive" means to the peer (fact F36's `holderAlive`).
    clock.schedule_on_sleep(
        2,
        Action::Mtime(
            fixture.primary.clone(),
            fixture.base.checked_add(Duration::from_secs(2)).expect("plausible"),
        ),
    );

    let acquired = acquire_with(
        &fixture.store,
        Tree::Agentctl,
        &fixture.paths,
        &ctx_with(&cancel),
        &Fault::none(),
        &seams,
    )
    .expect("busy, not an error");

    let AcquireOutcome::Busy { holder_alive, stopped_pids } = acquired.outcome else {
        panic!("expected busy")
    };
    assert!(holder_alive, "the modification time moved, which is the peer's own test");
    assert!(stopped_pids.is_empty(), "no stopped process was involved");

    let slept = clock.slept();
    assert_eq!(
        slept.len(),
        usize::try_from(CONTENTION_ROUNDS).expect("a small number"),
        "five rounds, and no top-up: the jittered rounds already passed the floor"
    );
    for nap in &slept {
        assert!(*nap >= CONTENTION_ROUND_BASE, "each round waits at least the fixed part");
        assert!(
            *nap < CONTENTION_ROUND_BASE + CONTENTION_ROUND_JITTER,
            "and at most the fixed part plus the jitter"
        );
    }
    assert!(!fixture.timeline.slept_while_holding(), "the schedule runs with nothing held");
    assert_eq!(fixture.timeline.mkdir_attempts(&fixture.primary), 0, "and nothing was attempted");
}

#[test]
fn a_primary_released_during_the_schedule_lets_the_acquisition_proceed() {
    // Plan AC68's positive half.
    let fixture = Fixture::new();
    fixture.plant(&fixture.primary, Duration::from_secs(1));
    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    let seams = fixture.seams(&clock, &holders);
    let cancel = Cancel::new();

    // The session releases the lock during the first round.
    clock.schedule_on_sleep(1, Action::Remove(fixture.primary.clone()));

    let acquired = acquire_with(
        &fixture.store,
        Tree::Agentctl,
        &fixture.paths,
        &ctx_with(&cancel),
        &Fault::none(),
        &seams,
    )
    .expect("the holder let go");
    assert!(matches!(acquired.outcome, AcquireOutcome::Held(_)), "the swap completes");
}

#[test]
fn a_cancelled_schedule_is_an_error_not_a_busy() {
    let fixture = Fixture::new();
    fixture.plant(&fixture.primary, Duration::from_secs(1));
    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    let seams = fixture.seams(&clock, &holders);
    let cancel = Cancel::new();
    clock.cancel_next_sleep(cancel.clone());

    let error = acquire_with(
        &fixture.store,
        Tree::Agentctl,
        &fixture.paths,
        &ctx_with(&cancel),
        &Fault::none(),
        &seams,
    )
    .expect_err("cancellation is not a busy store");
    assert_eq!(error, LockError::Cancelled);
}

// ---------------------------------------------------------------------------
// AC63 — the break rule, table-driven
// ---------------------------------------------------------------------------

/// Runs the break rule against a planted primary lock.
fn run_rule(
    fixture: &Fixture,
    clock: &Arc<FakeClock>,
    holders: &dyn HolderEvidence,
    fault: &Fault,
) -> BreakOutcome {
    let cancel = Cancel::new();
    let seams = fixture.seams(clock, holders);
    resolve_stale_with(&fixture.primary, &REFRESH_PROFILE, &ctx_with(&cancel), fault, &seams)
}

#[test]
fn a_lock_nobody_is_beating_is_broken_once() {
    let fixture = Fixture::new();
    fixture.plant(&fixture.primary, stale_age());
    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();

    let outcome = run_rule(&fixture, &clock, &holders, &Fault::none());

    assert_eq!(outcome.decision, Decision::Broken);
    assert!(!fixture.primary.exists(), "the directory is gone");
    let record = outcome.record.expect("a break is audited");
    assert_eq!(record.outcome, Outcome::Broken);
    assert_eq!(record.reason, None, "every reason in the vocabulary is a reason NOT to break");
    assert_eq!(record.event, "lock_break");
    assert_eq!(record.path, fixture.primary);
    assert_eq!(record.holder_evidence, HolderEvidence3::NoStoppedClaude);
    let (a, b, c) = samples(&record);
    assert_eq!(a.mtime_ns, b.mtime_ns, "all three samples recorded, and identical");
    assert_eq!(b.mtime_ns, c.mtime_ns);
    assert_eq!(record.interval_wall_ms, millis(STALE_SAMPLE_INTERVAL));
    assert_eq!(record.interval_monotonic_ms, millis(STALE_SAMPLE_INTERVAL));
    assert_eq!(clock.slept(), vec![STALE_SAMPLE_INTERVAL], "one wait, and it is the sampling one");
}

#[test]
fn a_single_heartbeat_before_sample_a_is_a_positive() {
    // Plan AC63, critic M7: version 1 listed this as a negative, which
    // enshrined a wrong assertion. The rule's window *starts* at Sample A, so
    // a holder's last heartbeat — however real — is indistinguishable from
    // the lock's initial state once Sample A has read it. What makes the
    // break safe is not that nothing ever wrote to the directory, but that
    // nothing wrote to it across the sampling interval.
    let fixture = Fixture::new();
    RealFs.mkdir(&fixture.primary).expect("creatable");
    // A real heartbeat, and then silence: the holder wedged 61 s ago.
    set_mtime(&fixture.primary, fixture.base);
    set_mtime(&fixture.primary, fixture.base.checked_sub(stale_age()).expect("a plausible age"));

    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    let outcome = run_rule(&fixture, &clock, &holders, &Fault::none());

    assert_eq!(outcome.decision, Decision::Broken);
    assert!(!fixture.primary.exists());
}

#[test]
fn a_heartbeat_anywhere_inside_the_window_abandons_the_break() {
    // Plan AC63's negatives at t = 5 s (a holder beating on fact F45's own
    // period), t = 6 s and t = 11.9 s. All three are observed by Sample B;
    // what differs between the rows is the modification time the audit
    // records, which is why each row asserts on it.
    for offset in [Duration::from_secs(5), Duration::from_secs(6), Duration::from_millis(11_900)] {
        let fixture = Fixture::new();
        fixture.plant(&fixture.primary, stale_age());
        let clock = fixture.fake_clock();
        let holders = FakeHolders::none_stopped();
        let beat_at = fixture.base.checked_add(offset).expect("a plausible instant");
        // Call 2 is Sample B: the action lands before its `stat`.
        clock.schedule(2, Action::Mtime(fixture.primary.clone(), beat_at));

        let outcome = run_rule(&fixture, &clock, &holders, &Fault::none());

        assert_eq!(
            outcome.decision,
            Decision::Abandoned(Reason::HeartbeatObserved),
            "a heartbeat at {offset:?} is observed"
        );
        assert!(fixture.primary.is_dir(), "the directory is untouched");
        let record = outcome.record.expect("an abandoned break is audited too");
        assert_eq!(record.outcome, Outcome::Abandoned);
        assert_eq!(record.reason, Some(Reason::HeartbeatObserved));
        let sample_b = record.sample_b.expect("Sample B was taken");
        assert_ne!(record.sample_a.mtime_ns, sample_b.mtime_ns);
        assert_eq!(sample_b.mtime_ns, nanos_since_epoch(beat_at), "the recorded value is exact");
        assert!(record.sample_c.is_none(), "the rule stopped at Sample B");
    }
}

#[test]
fn a_heartbeat_one_nanosecond_wide_still_abandons_the_break() {
    // Plan AC63's last line: "a tolerance-based mtime comparison fails the
    // suite". This is that row. The comparison has to be exact because fact
    // F54's argument — a broken holder stands down at its next heartbeat —
    // only holds if a heartbeat is never mistaken for silence.
    let fixture = Fixture::new();
    fixture.plant(&fixture.primary, stale_age());
    let planted = mtime_of(&fixture.primary).expect("planted");
    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    clock.schedule(
        2,
        Action::Mtime(
            fixture.primary.clone(),
            planted.checked_add(Duration::from_nanos(1)).expect("one nanosecond later"),
        ),
    );

    let outcome = run_rule(&fixture, &clock, &holders, &Fault::none());
    assert_eq!(outcome.decision, Decision::Abandoned(Reason::HeartbeatObserved));
    assert!(fixture.primary.is_dir());
}

#[test]
fn a_heartbeat_between_sample_b_and_sample_c_abandons_at_sample_c() {
    // Plan AC63's t = 12.1 s row and critic C2's whole point: version 1 wrote
    // the audit entry in this gap, which is milliseconds a wedged holder can
    // use to resume and heartbeat while still believing it holds the lock.
    // The outcome is `abandoned` with `heartbeat_observed`, matching the
    // audit vocabulary (architect NEW-6).
    let fixture = Fixture::new();
    fixture.plant(&fixture.primary, stale_age());
    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    let beat_at = fixture.base.checked_add(Duration::from_millis(12_100)).expect("plausible");
    // Call 3 is Sample C: the action lands after Sample B and before C.
    clock.schedule(3, Action::Mtime(fixture.primary.clone(), beat_at));

    let outcome = run_rule(&fixture, &clock, &holders, &Fault::none());

    assert_eq!(outcome.decision, Decision::Abandoned(Reason::HeartbeatObserved));
    assert!(fixture.primary.is_dir(), "the directory is untouched");
    let record = outcome.record.expect("audited");
    let sample_b = record.sample_b.expect("Sample B");
    let sample_c = record.sample_c.expect("Sample C was reached");
    assert_eq!(record.sample_a.mtime_ns, sample_b.mtime_ns, "A and B agreed");
    assert_ne!(sample_b.mtime_ns, sample_c.mtime_ns, "C is where it was caught");
}

#[test]
fn the_injected_resume_reaches_the_same_window() {
    // The same case as above, through the production-shaped seam W4a's e2e
    // will use rather than through the fake clock.
    let fixture = Fixture::new();
    fixture.plant(&fixture.primary, stale_age());
    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();

    let outcome =
        run_rule(&fixture, &clock, &holders, &Fault::from_list("lock_resume_after_sample_b"));

    assert_eq!(outcome.decision, Decision::Abandoned(Reason::HeartbeatObserved));
    assert!(fixture.primary.is_dir());
}

#[test]
fn a_lock_younger_than_its_profile_is_too_young() {
    let fixture = Fixture::new();
    fixture.plant(&fixture.primary, Duration::from_secs(59));
    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();

    let outcome = run_rule(&fixture, &clock, &holders, &Fault::none());

    assert_eq!(outcome.decision, Decision::Abandoned(Reason::TooYoung));
    assert!(fixture.primary.is_dir());
    let record = outcome.record.expect("an abandoned break is audited");
    assert_eq!(record.reason, Some(Reason::TooYoung));
    assert!(record.sample_b.is_none(), "the rule never got as far as waiting");
    assert!(clock.slept().is_empty(), "and cost nothing");
}

#[test]
fn the_public_rule_runs_against_the_real_clock_and_filesystem() {
    // The contract's own signature, over the real clock, the real
    // filesystem and the real holder check. Driven with a lock that is too
    // young so the assertion costs no wall-clock time: reaching any later
    // condition through this entry point would mean waiting the full
    // sampling interval, which is what the injected seams exist to avoid.
    let fixture = Fixture::new();
    fixture.plant(&fixture.primary, Duration::from_secs(1));
    let cancel = Cancel::new();

    let outcome = resolve_stale(
        &fixture.primary,
        &REFRESH_PROFILE,
        &Clock::system(),
        &ProcHolders,
        &ctx_with(&cancel),
    );

    assert_eq!(outcome.decision, Decision::Abandoned(Reason::TooYoung));
    assert!(fixture.primary.is_dir(), "and it removed nothing");
    let record = outcome.record.expect("audited");
    assert_eq!(
        record.holder_evidence,
        HolderEvidence3::None,
        "a lock too young to break costs no process-table sweep at all, and the \
         record says so rather than claiming a check that did not happen"
    );
}

#[test]
fn the_real_holder_check_never_claims_a_sweep_it_did_not_finish() {
    // The mapping spike V12 asked for, at the boundary where it is decided:
    // an incomplete answer from `runtime::proc` becomes `none`, never
    // `no_stopped_claude`, and the pids the terminal message would name come
    // from the same sweep.
    let evidence = ProcHolders.stopped_claude_present();
    let pids = ProcHolders.stopped_pids();
    match proc::claude_processes() {
        Err(_) => assert_eq!(evidence, HolderEvidence3::None, "an unfinished sweep is unknown"),
        Ok(found) => {
            let stopped = found.iter().any(|(_, state)| *state == proc::Holder::Stopped);
            if stopped {
                assert_eq!(evidence, HolderEvidence3::StoppedClaudePresent);
            } else {
                assert_eq!(evidence, HolderEvidence3::NoStoppedClaude);
                assert!(pids.is_empty(), "and nothing to name: {pids:?}");
            }
        }
    }
}

#[test]
fn each_profile_has_its_own_staleness_window() {
    // Fact F47: `.storage-write` is stale at 15 s, not 60 s. Borrowing the
    // wrong window for the wrong lock is what `LockProfile` exists to stop.
    let fixture = Fixture::new();
    fixture.plant(&fixture.storage, Duration::from_secs(20));
    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    let cancel = Cancel::new();
    let seams = fixture.seams(&clock, &holders);

    let too_young = resolve_stale_with(
        &fixture.storage,
        &REFRESH_PROFILE,
        &ctx_with(&cancel),
        &Fault::none(),
        &seams,
    );
    assert_eq!(too_young.decision, Decision::Abandoned(Reason::TooYoung), "60 s window");

    let clock = fixture.fake_clock();
    let seams = fixture.seams(&clock, &holders);
    let broken = resolve_stale_with(
        &fixture.storage,
        &STORAGE_WRITE_PROFILE,
        &ctx_with(&cancel),
        &Fault::none(),
        &seams,
    );
    assert_eq!(broken.decision, Decision::Broken, "15 s window");
}

#[test]
fn a_lock_that_vanishes_at_any_sample_writes_no_audit_entry() {
    // Plan AC63: `vanished`, and deliberately the one reason with no entry —
    // nothing was there and nothing was done.
    for call in [1_u32, 2, 3] {
        let fixture = Fixture::new();
        fixture.plant(&fixture.primary, stale_age());
        let clock = fixture.fake_clock();
        let holders = FakeHolders::none_stopped();
        clock.schedule(call, Action::Remove(fixture.primary.clone()));

        let outcome = run_rule(&fixture, &clock, &holders, &Fault::none());

        assert_eq!(
            outcome.decision,
            Decision::Abandoned(Reason::Vanished),
            "gone before sample {call}"
        );
        assert!(outcome.record.is_none(), "and not audited");
    }
}

#[test]
fn a_clock_step_in_either_direction_abandons_the_break() {
    // Architect N-3. A backward step is the obvious case; a forward one
    // inflates both ages and would otherwise pass undiagnosed, which is why
    // the wall clock is compared against the monotonic one rather than
    // trusted.
    for (by, forward) in [
        (Duration::from_secs(30), true),
        (Duration::from_secs(30), false),
        (CLOCK_SKEW_TOLERANCE + Duration::from_millis(1), true),
    ] {
        let fixture = Fixture::new();
        fixture.plant(&fixture.primary, stale_age());
        let clock = fixture.fake_clock();
        let holders = FakeHolders::none_stopped();
        clock.schedule(2, Action::WallJump(by, forward));

        let outcome = run_rule(&fixture, &clock, &holders, &Fault::none());

        assert_eq!(
            outcome.decision,
            Decision::Abandoned(Reason::ClockJump),
            "a {} jump of {by:?}",
            if forward { "forward" } else { "backward" }
        );
        assert!(fixture.primary.is_dir());
        let record = outcome.record.expect("audited");
        assert_eq!(record.reason, Some(Reason::ClockJump));
        assert_ne!(
            record.interval_wall_ms, record.interval_monotonic_ms,
            "the two intervals are recorded so the decision can be checked"
        );
    }
}

#[test]
fn a_clock_within_tolerance_does_not_abandon_the_break() {
    let fixture = Fixture::new();
    fixture.plant(&fixture.primary, stale_age());
    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    clock.schedule(2, Action::WallJump(CLOCK_SKEW_TOLERANCE, true));

    let outcome = run_rule(&fixture, &clock, &holders, &Fault::none());
    assert_eq!(outcome.decision, Decision::Broken, "exactly at the tolerance is not a jump");
}

#[test]
fn a_stopped_same_user_claude_abandons_the_break_before_any_wait() {
    // Plan AC63 and AC80. Deliberately coarse: it abandons whether or not
    // that process has anything to do with this store, because attributing a
    // lock to a store would need another process's environment and phase 2
    // reads none (ruling 4). Over-refusing costs a retry; under-refusing
    // costs a credential.
    let fixture = Fixture::new();
    fixture.plant(&fixture.primary, stale_age());
    let clock = fixture.fake_clock();
    let holders = FakeHolders::stopped(&[41_207]);

    let outcome = run_rule(&fixture, &clock, &holders, &Fault::none());

    assert_eq!(outcome.decision, Decision::Abandoned(Reason::HolderStopped));
    assert!(fixture.primary.is_dir());
    assert!(clock.slept().is_empty(), "abandoned before the 12-second wait is entered");
    let record = outcome.record.expect("an abandoned break is audited");
    assert_eq!(record.holder_evidence, HolderEvidence3::StoppedClaudePresent);
    assert_eq!(record.agentctl_pid, std::process::id(), "our own pid, never the holder's");
    let json = serde_json::to_string(&record).expect("serializable");
    assert!(!json.contains("41207"), "the audit entry names no holder pid (AC80)");
}

#[test]
fn unavailable_evidence_continues_on_modification_times_alone() {
    // Spike V12's one substantive requirement, at the level that records it:
    // `none` means "I do not know" and the rule goes on; it must never be
    // written as `no_stopped_claude`, which would be a false negative.
    let fixture = Fixture::new();
    fixture.plant(&fixture.primary, stale_age());
    let clock = fixture.fake_clock();
    let holders = FakeHolders::unknown();

    let outcome = run_rule(&fixture, &clock, &holders, &Fault::none());

    assert_eq!(outcome.decision, Decision::Broken);
    let record = outcome.record.expect("audited");
    assert_eq!(record.holder_evidence, HolderEvidence3::None);
}

#[test]
fn a_cancelled_sampling_wait_decides_nothing_and_audits_nothing() {
    let fixture = Fixture::new();
    fixture.plant(&fixture.primary, stale_age());
    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    let cancel = Cancel::new();
    clock.cancel_next_sleep(cancel.clone());
    let seams = fixture.seams(&clock, &holders);

    let outcome = resolve_stale_with(
        &fixture.primary,
        &REFRESH_PROFILE,
        &ctx_with(&cancel),
        &Fault::none(),
        &seams,
    );

    assert_eq!(outcome.decision, Decision::Cancelled);
    assert!(outcome.record.is_none(), "nothing was decided, so there is nothing to record");
    assert!(fixture.primary.is_dir());
}

#[test]
fn a_lock_retaken_after_the_rmdir_is_busy_and_is_not_broken_twice() {
    // Plan AC63's last positive-turned-negative: at most one break per
    // acquire, so agentctl cannot loop against a peer that recreates a lock.
    let fixture = Fixture::new();
    fixture.plant(&fixture.primary, stale_age());
    fixture.fs.retake_after_rmdir(&fixture.primary);
    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    let seams = fixture.seams(&clock, &holders);
    let cancel = Cancel::new();

    let acquired = acquire_with(
        &fixture.store,
        Tree::Agentctl,
        &fixture.paths,
        &ctx_with(&cancel),
        &Fault::none(),
        &seams,
    )
    .expect("busy, not an error");

    let AcquireOutcome::Busy { holder_alive, .. } = acquired.outcome else {
        panic!("expected busy")
    };
    assert!(holder_alive, "somebody took it the instant it was released");
    let record = acquired.break_record.expect("the break is audited");
    assert_eq!(record.outcome, Outcome::Broken, "the directory *was* removed");
    assert_eq!(record.reason, Some(Reason::Retaken), "and immediately retaken");
    assert_eq!(record.store_dir.as_deref(), Some(fixture.store.as_path()));
    assert_eq!(record.tree, Some(Tree::Agentctl));
    assert_eq!(
        fixture.timeline.ops().iter().filter(|op| matches!(op, Op::Rmdir(_))).count(),
        1,
        "one `rmdir` in total: no second break was attempted"
    );
}

#[test]
fn only_one_break_is_attempted_per_acquire() {
    // Two stale locks, one break. The second is reported busy rather than
    // removed, which is what bounds the damage a wrong staleness verdict can
    // do to one directory per acquire.
    let fixture = Fixture::new();
    fixture.plant(&fixture.primary, stale_age());
    fixture.plant(&fixture.legacy, stale_age());
    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    let seams = fixture.seams(&clock, &holders);
    let cancel = Cancel::new();

    let acquired = acquire_with(
        &fixture.store,
        Tree::Agentctl,
        &fixture.paths,
        &ctx_with(&cancel),
        &Fault::none(),
        &seams,
    )
    .expect("busy, not an error");

    assert!(matches!(acquired.outcome, AcquireOutcome::Busy { .. }));
    assert!(!fixture.primary.exists(), "the first stale lock was broken");
    assert!(fixture.legacy.is_dir(), "the second was left alone");
    assert_eq!(clock.slept(), vec![STALE_SAMPLE_INTERVAL], "one sampling interval, not two");
}

// ---------------------------------------------------------------------------
// AC64 — the pre-write drift check, and release on the way out
// ---------------------------------------------------------------------------

#[test]
fn a_third_party_touching_any_held_lock_is_refusal_a() {
    // Plan AC64. One `stat` triple, and any difference from the value
    // recorded at that lock's own `mkdir` refuses the write. This replaces
    // version 2's heartbeat thread, which under a 3 000 ms hold could never
    // fire — so refusal A was unreachable in production and only a fake clock
    // ever exercised it (architect NEW-2).
    for position in 0..3_usize {
        let fixture = Fixture::new();
        let clock = fixture.fake_clock();
        let holders = FakeHolders::none_stopped();
        let seams = fixture.seams(&clock, &holders);
        let cancel = Cancel::new();

        let acquired = acquire_with(
            &fixture.store,
            Tree::Agentctl,
            &fixture.paths,
            &ctx_with(&cancel),
            &Fault::none(),
            &seams,
        )
        .expect("an uncontended store");
        let AcquireOutcome::Held(hold) = acquired.outcome else { panic!("expected a hold") };

        assert_eq!(hold.drift_check(), Ok(()), "nothing has moved yet");

        let touched = fixture.all()[position].clone();
        set_mtime(&touched, fixture.base.checked_add(Duration::from_secs(1)).expect("later"));

        assert_eq!(
            hold.drift_check(),
            Err(LockError::Compromised(touched.clone())),
            "position {position} is checked too"
        );

        drop(hold);
        for path in fixture.all() {
            assert!(!path.exists(), "everything is released: `{}`", path.display());
        }
        assert!(fixture.records().is_empty(), "and the record cleared");
    }
}

#[test]
fn a_hold_past_its_budget_refuses_rather_than_writing() {
    // Fact F53: past 4 000 ms the peer's own refresh throws. The check sits
    // in `drift_check` because that is the last moment at which abandoning
    // still costs nothing.
    let fixture = Fixture::new();
    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    let seams = fixture.seams(&clock, &holders);
    let cancel = Cancel::new();

    let acquired = acquire_with(
        &fixture.store,
        Tree::Agentctl,
        &fixture.paths,
        &ctx_with(&cancel),
        &Fault::none(),
        &seams,
    )
    .expect("an uncontended store");
    let AcquireOutcome::Held(mut hold) = acquired.outcome else { panic!("expected a hold") };

    // Reaching the budget takes three seconds of real time, so the hold's own
    // start is moved instead of the test waiting for it. The margin is half a
    // second rather than a millisecond because the fake clock's monotonic
    // hand only advances on a sleep, and no sleep happens here.
    hold.first_mkdir = hold
        .clock
        .monotonic()
        .checked_sub(HOLD_BUDGET + Duration::from_millis(500))
        .expect("a plausible instant");

    assert!(
        matches!(hold.drift_check(), Err(LockError::BudgetExceeded { .. })),
        "the budget is enforced, not merely documented"
    );
}

#[test]
fn the_measured_hold_stays_inside_the_budget() {
    // Plan AC70's second half, at unit scope: the hold measured from the
    // first `mkdir` to the last `rmdir`, on the real clock, asserted strictly
    // below fact F53's 4 000 ms floor.
    let fixture = Fixture::new();
    let holders = FakeHolders::none_stopped();
    let seams = Seams {
        fs: Arc::clone(&fixture.fs) as Arc<dyn LockFs>,
        holders: &holders,
        clock: Clock::system(),
    };
    let cancel = Cancel::new();

    let acquired = acquire_with(
        &fixture.store,
        Tree::Agentctl,
        &fixture.paths,
        &ctx_with(&cancel),
        &Fault::none(),
        &seams,
    )
    .expect("an uncontended store");
    let AcquireOutcome::Held(hold) = acquired.outcome else { panic!("expected a hold") };
    hold.drift_check().expect("nothing moved, and the budget is not spent");
    let reported = hold.hold_elapsed();
    assert!(reported < HOLD_BUDGET, "the hold reports {reported:?} of its {HOLD_BUDGET:?}");
    drop(hold);

    let stamped = fixture.timeline.stamped();
    let first_mkdir = stamped
        .iter()
        .find(|(_, op)| matches!(op, Op::Mkdir(_, true)))
        .map(|(at, _)| *at)
        .expect("a first `mkdir`");
    let last_rmdir = stamped
        .iter()
        .filter(|(_, op)| matches!(op, Op::Rmdir(_)))
        .map(|(at, _)| *at)
        .next_back()
        .expect("a last `rmdir`");
    let held = last_rmdir.saturating_duration_since(first_mkdir);
    assert!(held < HOLD_BUDGET, "the hold lasted {held:?}, budget {HOLD_BUDGET:?}");
    assert!(held < Duration::from_millis(4000), "and strictly under fact F53's floor");
}

#[test]
fn the_injected_leak_leaves_the_directories_and_a_record_that_names_them() {
    // Plan AC64's last clause. `doctor --remove-stale`'s reader is S19's
    // half, so this asserts on the **record file** — the shape S19 reads —
    // rather than on `doctor` output, which is not on this branch.
    let fixture = Fixture::new();
    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    let seams = fixture.seams(&clock, &holders);
    let cancel = Cancel::new();

    let acquired = acquire_with(
        &fixture.store,
        Tree::Live,
        &fixture.paths,
        &ctx_with(&cancel),
        &Fault::from_list("swap_lock_leak"),
        &seams,
    )
    .expect("an uncontended store");
    let AcquireOutcome::Held(hold) = acquired.outcome else { panic!("expected a hold") };
    let record_path = hold.record_path().to_path_buf();
    drop(hold);

    for path in fixture.all() {
        assert!(path.is_dir(), "leaked, as a crashed hold would leave it: `{}`", path.display());
    }
    let record = read_held_record(&record_path).expect("the record survives the leak");
    assert_eq!(record.tree, Tree::Live, "and says which tree they are in");
    assert_eq!(record.paths, fixture.all().to_vec(), "naming every leaked directory");
    assert_eq!(record.agentctl_pid, std::process::id());
    assert_eq!(
        held_records(&fixture.paths).len(),
        1,
        "and it is discoverable without knowing its name"
    );

    // Left as found: the leaked directories are what a crashed hold leaves,
    // and the temporary directory takes them with it. The registry still
    // holds this hold's restore closure, which is harmless — the paths are
    // gone by the time anything could run it.
    for path in fixture.all() {
        let _ = RealFs.rmdir(&path);
    }
}

// ---------------------------------------------------------------------------
// AC64 — a real process, a real SIGTERM and a real panic
// ---------------------------------------------------------------------------

/// Tells a re-executed copy of this test binary to act as the child.
///
/// Read **only** here, in a `#[cfg(test)]` file: it is not a crate seam, it
/// cannot reach a release artifact, and `tests/e2e_lock.rs` asserts that no
/// non-test source mentions it.
const CHILD_ROLE_ENV: &str = "AGENTCTL_LOCK_CHILD_ROLE";

/// Where the child builds its store and reports progress.
const CHILD_DIR_ENV: &str = "AGENTCTL_LOCK_CHILD_DIR";

/// The child half of the two signal tests. A no-op in a normal run.
#[test]
fn lock_child_harness() {
    let Ok(role) = std::env::var(CHILD_ROLE_ENV) else { return };
    let dir = PathBuf::from(
        std::env::var(CHILD_DIR_ENV).expect("the parent hands the child a directory"),
    );

    // The two production paths out of a process that is holding locks: the
    // signal thread, and a panic hook. Both run the emergency registry.
    let cancel = Cancel::new();
    crate::runtime::signals::install(cancel.clone()).expect("the signal thread should start");
    std::panic::set_hook(Box::new(|_| cleanup::emergency()));

    let store = dir.join("store");
    fs::create_dir_all(&store).expect("the store should be creatable");
    let paths = Paths::with_config_dir(dir.join("config"));
    paths.ensure_dirs().expect("the agentctl store should be creatable");

    let ctx = PassCtx::standalone(cancel, Instant::now() + Duration::from_secs(60));
    let acquired = acquire(
        &store,
        Tree::Agentctl,
        &paths,
        &Clock::system(),
        &ctx,
        &Fault::from_list("swap_lock_leak"),
    )
    .expect("an uncontended store");
    let AcquireOutcome::Held(hold) = acquired.outcome else { panic!("expected a hold") };

    // Forgotten on purpose: `Drop` must not be what the parent observes, or
    // the test would pass without the registry doing anything. The fault
    // above makes `Drop` inert as well, so this is belt and braces.
    std::mem::forget(hold);
    fs::write(dir.join("held"), "1").expect("the parent is waiting for this");

    if role == "panic" {
        panic!("the child panics while holding three locks");
    }
    // Otherwise wait to be signalled.
    std::thread::sleep(Duration::from_secs(30));
}

/// Runs the child in one of its two roles and returns its store directory.
fn run_child(role: &str) -> (tempfile::TempDir, std::process::Child) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let mut child =
        std::process::Command::new(std::env::current_exe().expect("this test binary has a path"))
            .arg("--exact")
            .arg("secret::claude_lock::tests::lock_child_harness")
            .arg("--nocapture")
            .env(CHILD_ROLE_ENV, role)
            .env(CHILD_DIR_ENV, dir.path())
            .env_remove(crate::runtime::fault::FAULT_ENV)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("the test binary should be re-executable");

    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if dir.path().join("held").exists() {
            return (dir, child);
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    // Reaped before the panic: a child left unwaited becomes a zombie for as
    // long as the test binary lives.
    let _ = child.kill();
    let _ = child.wait();
    panic!("the child never reported that it was holding");
}

/// The three lock paths the child took, given its temporary directory.
fn child_locks(dir: &Path) -> [PathBuf; 3] {
    plan(&dir.join("store")).map(|lock| lock.path)
}

#[test]
fn a_sigterm_releases_every_lock_a_child_was_holding() {
    let (dir, mut child) = run_child("sigterm");
    for path in child_locks(dir.path()) {
        assert!(path.is_dir(), "the child holds `{}`", path.display());
    }

    let raw = i32::try_from(child.id()).expect("a plausible pid");
    let pid = rustix::process::Pid::from_raw(raw).expect("a plausible pid");
    rustix::process::kill_process(pid, rustix::process::Signal::TERM)
        .expect("signalling our own child");
    let status = child.wait().expect("the child should be reapable");

    for path in child_locks(dir.path()) {
        assert!(!path.exists(), "released on SIGTERM: `{}`", path.display());
    }
    assert!(held_records_in(dir.path()).is_empty(), "and the record cleared");
    assert_eq!(status.code(), Some(143), "128 + SIGTERM, as `runtime::signals` promises");
}

#[test]
fn a_panic_releases_every_lock_the_panicking_process_was_holding() {
    let (dir, mut child) = run_child("panic");
    let status = child.wait().expect("the child should be reapable");

    for path in child_locks(dir.path()) {
        assert!(!path.exists(), "released by the panic hook: `{}`", path.display());
    }
    assert!(held_records_in(dir.path()).is_empty(), "and the record cleared");
    assert!(!status.success(), "the child did fail: {status:?}");
}

/// The held-lock records under a child's store.
fn held_records_in(dir: &Path) -> Vec<(PathBuf, HeldLockRecord)> {
    held_records(&Paths::with_config_dir(dir.join("config")))
}

// ---------------------------------------------------------------------------
// AC80 — the vocabulary itself
// ---------------------------------------------------------------------------

#[test]
fn the_holder_evidence_vocabulary_is_exactly_three_words() {
    // Plan AC80, and deliberately an assertion on the **vocabulary** rather
    // than on one record: a later edit must not be able to reintroduce
    // attribution through the audit field.
    let spellings = [
        (HolderEvidence3::StoppedClaudePresent, "\"stopped_claude_present\""),
        (HolderEvidence3::NoStoppedClaude, "\"no_stopped_claude\""),
        (HolderEvidence3::None, "\"none\""),
    ];
    for (value, spelling) in spellings {
        let json = serde_json::to_string(&value).expect("serializable");
        assert_eq!(json, spelling);
        assert!(
            !json.chars().any(char::is_numeric),
            "no value in this vocabulary names a process: {json}"
        );
        for forbidden in ["pid", "store", "dir", "path"] {
            assert!(
                !json.contains(forbidden),
                "no value claims a {forbidden} was identified: {json}"
            );
        }
    }
}

#[test]
fn the_outcome_and_reason_vocabularies_are_exactly_section_38s() {
    assert_eq!(serde_json::to_string(&Outcome::Broken).expect("ok"), "\"broken\"");
    assert_eq!(serde_json::to_string(&Outcome::Abandoned).expect("ok"), "\"abandoned\"");

    let reasons = [
        (Reason::HeartbeatObserved, "\"heartbeat_observed\""),
        (Reason::TooYoung, "\"too_young\""),
        (Reason::Vanished, "\"vanished\""),
        (Reason::ClockJump, "\"clock_jump\""),
        (Reason::Retaken, "\"retaken\""),
        (Reason::HolderStopped, "\"holder_stopped\""),
    ];
    for (value, spelling) in reasons {
        assert_eq!(serde_json::to_string(&value).expect("ok"), spelling);
    }
    assert_eq!(serde_json::to_string(&Tree::Agentctl).expect("ok"), "\"agentctl\"");
    assert_eq!(serde_json::to_string(&Tree::Live).expect("ok"), "\"live\"");
}

#[test]
fn a_break_record_carries_one_pid_and_it_is_ours() {
    // Architect NEW-10: a `pid` field sitting beside `holder_evidence` would
    // read as the *holder's* pid, and an implementation that wrote one there
    // would have passed AC80. The field is named unambiguously and the record
    // has no other.
    let fixture = Fixture::new();
    fixture.plant(&fixture.primary, stale_age());
    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    let outcome = run_rule(&fixture, &clock, &holders, &Fault::none());
    let record = outcome.record.expect("audited");

    let json = serde_json::to_value(&record).expect("serializable");
    let object = json.as_object().expect("an object");
    let pid_keys: Vec<&String> = object.keys().filter(|key| key.contains("pid")).collect();
    assert_eq!(pid_keys, vec!["agentctl_pid"], "one pid field, unambiguously ours");
    assert_eq!(object["event"], "lock_break");
    assert!(object.contains_key("sample_a"));
    assert!(object.contains_key("interval_wall_ms"));
    assert!(object.contains_key("interval_monotonic_ms"));
    assert!(!object.contains_key("reason"), "a clean break records no reason");
}

#[test]
fn the_held_lock_record_has_the_shape_the_stale_remover_reads() {
    // Section 3.9 row 2 and plan AC73's second half: `doctor --remove-stale`
    // accepts a path outside `namespace_root()` only when a held-lock record
    // names that exact path and the recorded process is dead. S19 owns the
    // reader; this pins the shape both halves agreed on.
    let record = HeldLockRecord {
        agentctl_pid: 4242,
        tree: Tree::Live,
        store_dir: PathBuf::from("/store"),
        paths: vec![PathBuf::from("/store/.oauth_refresh.lock")],
        taken_at: "2026-09-09T00:00:00Z".to_owned(),
    };
    let json = serde_json::to_value(&record).expect("serializable");
    assert_eq!(
        json,
        serde_json::json!({
            "agentctl_pid": 4242,
            "tree": "live",
            "store_dir": "/store",
            "paths": ["/store/.oauth_refresh.lock"],
            "taken_at": "2026-09-09T00:00:00Z",
        })
    );
    let round_trip: HeldLockRecord = serde_json::from_value(json).expect("the shape round-trips");
    assert_eq!(round_trip, record);
}

// ---------------------------------------------------------------------------
// The constants, and the derivations they are not allowed to drift from
// ---------------------------------------------------------------------------

#[test]
fn the_sampling_interval_stays_clear_of_the_peers_heartbeat() {
    assert!(
        STALE_SAMPLE_INTERVAL > PEER_HEARTBEAT * 2,
        "a single peer heartbeat anywhere in the window must fail the comparison"
    );
}

#[test]
fn every_budget_stays_under_the_floor_it_is_derived_from() {
    // Fact F53: the peer's scope-expansion helper gives up after 4 000 ms.
    assert!(HOLD_BUDGET < Duration::from_millis(4000));
    // Spike V8: a session inside its first 30 s abandons its configuration
    // lock ladder after 1 500 ms and then writes the document unlocked.
    assert!(CONFIG_HOLD_BUDGET < Duration::from_millis(1500));
    assert_eq!(CONFIG_PROFILE.hold_budget, CONFIG_HOLD_BUDGET);
}

#[test]
fn every_profile_refuses_to_retry_under_the_hold() {
    for profile in [REFRESH_PROFILE, STORAGE_WRITE_PROFILE, CONFIG_PROFILE] {
        assert_eq!(profile.retries, 0, "a retry is a wait, and a wait belongs outside the hold");
        assert_eq!(profile.update, PEER_HEARTBEAT);
    }
    assert_eq!(REFRESH_PROFILE.stale, Duration::from_secs(60), "fact F46");
    assert_eq!(STORAGE_WRITE_PROFILE.stale, Duration::from_secs(15), "fact F47");
    assert_eq!(CONFIG_PROFILE.stale, Duration::from_secs(10), "fact F50, spike V8");
}

#[test]
fn the_legacy_lock_sits_beside_the_resolved_store_directory() {
    // Fact F17/F46, and on macOS the resolved and lexical spellings differ in
    // the common case: `$TMPDIR` lives under `/var`, a link to `/private/var`.
    let fixture = Fixture::new();
    let resolved = namespace::canonical(&fixture.store).expect("the store resolves");
    assert_eq!(fixture.legacy, PathBuf::from(format!("{}.lock", resolved.display())));
    assert_eq!(fixture.primary, fixture.store.join(".oauth_refresh.lock"));
    assert_eq!(fixture.storage, fixture.store.join(".storage-write"));
}

#[test]
fn the_real_operations_make_and_remove_a_directory() {
    // `AT_REMOVEDIR` is the whole point: `unlink` cannot remove a directory,
    // which is the defect `agentctl-nz5` records.
    let dir = tempfile::tempdir().expect("a temporary directory");
    let lock = dir.path().join(".oauth_refresh.lock");

    RealFs.mkdir(&lock).expect("creatable");
    assert!(lock.is_dir(), "a directory, as `proper-lockfile` makes it");
    assert_eq!(RealFs.mkdir(&lock), Err(FsError::Exists), "a second attempt is contention");
    // Darwin answers `EPERM` here rather than `EISDIR`; either way `unlink`
    // will not remove a directory, which is exactly why
    // `cleanup::register_tmp_path` cannot clean a lock up and
    // `register_restore` has to.
    assert!(
        std::fs::remove_file(&lock).is_err(),
        "`unlink` cannot remove a directory on any platform this runs on"
    );
    assert!(lock.is_dir(), "and it is still there");
    RealFs.rmdir(&lock).expect("removable with AT_REMOVEDIR");
    assert!(!lock.exists());
    assert_eq!(RealFs.rmdir(&lock), Err(FsError::NotFound));
}

#[test]
fn a_symlink_where_a_lock_should_be_is_never_removed() {
    // A link at a lock path is somebody else's plant. `symlink_metadata`
    // keeps the sampling from reading the target's modification time, and
    // `rmdir` refuses a link outright — the safe side of that trade.
    let dir = tempfile::tempdir().expect("a temporary directory");
    let target = dir.path().join("target");
    fs::create_dir(&target).expect("creatable");
    let link = dir.path().join(".oauth_refresh.lock");
    std::os::unix::fs::symlink(&target, &link).expect("linkable");

    assert!(matches!(RealFs.rmdir(&link), Err(FsError::Other(_))), "a link is not removed");
    assert!(link.exists(), "and is still there");
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// The three samples of a record that reached Sample C.
fn samples(record: &LockBreakRecord) -> (Sample, Sample, Sample) {
    (
        record.sample_a.clone(),
        record.sample_b.clone().expect("Sample B"),
        record.sample_c.clone().expect("Sample C"),
    )
}

/// A file's permission bits.
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::symlink_metadata(path).expect("readable").permissions().mode() & 0o777
}
