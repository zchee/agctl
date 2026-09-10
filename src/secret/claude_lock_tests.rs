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

use crate::config::paths::FILE_MODE;
use crate::secret::audit;
use crate::secret::audit::AuditEntry;
use crate::secret::audit::AuditEvent;

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
///
/// Every operation is passed through with the **same slot** it was given, so
/// the spy cannot accidentally turn a descriptor-relative operation into a
/// path-based one; what it records is the slot's `shown` path, which exists for
/// exactly this purpose.
struct SpyFs {
    timeline: Shared,
    real: RealFs,
    /// Paths a "peer" recreates immediately after a successful `rmdir`,
    /// which is the only way to reach section 3.8's `retaken`.
    retake: Mutex<Vec<PathBuf>>,
    /// Paths a "peer" creates just *before* agctl's own `mkdir`, which is
    /// the only way to reach an `EEXIST` on a lock that was free when the
    /// lock-free probe looked at it.
    plant_before: Mutex<Vec<PathBuf>>,
    /// Paths whose modification time cannot be read.
    ///
    /// The real `mtime` is a `statat` that returns `Option`, and every caller
    /// in the protocol already has to handle the `None`. Reaching it on a
    /// directory that certainly exists needs a real `statat` to fail — a
    /// racing `rmdir` between the `mkdir` and the `statat`, `EACCES` on the
    /// parent, `EIO` — none of which a test can stage against the real
    /// filesystem without also changing what the directory *is*. So the seam
    /// answers `None` for a chosen path, which is exactly the observable
    /// those causes share and nothing more.
    unreadable_mtime: Mutex<Vec<PathBuf>>,
    /// Runs cancelled the moment a named directory is removed.
    ///
    /// Cancellation in production arrives from a signal or a deadline, which
    /// is asynchronous to everything a fake clock controls: the clock's own
    /// hooks all fire *inside* a `sleep`, and a `sleep` reports the
    /// cancellation to its own caller, so a clock-driven cancel can only ever
    /// reach the wait it happened in. This hook fires between two waits
    /// instead, which is what the two cancellation sites *after* a completed
    /// break need — a user pressing Ctrl-C while the break rule is removing a
    /// peer's directory.
    cancel_after_rmdir: Mutex<Vec<(PathBuf, Cancel)>>,
}

impl SpyFs {
    fn new(timeline: Shared) -> Self {
        Self {
            timeline,
            real: RealFs,
            retake: Mutex::new(Vec::new()),
            plant_before: Mutex::new(Vec::new()),
            unreadable_mtime: Mutex::new(Vec::new()),
            cancel_after_rmdir: Mutex::new(Vec::new()),
        }
    }

    /// Makes a peer recreate `path` the moment agctl removes it.
    fn retake_after_rmdir(&self, path: &Path) {
        lock(&self.retake).push(path.to_path_buf());
    }

    /// Makes a peer win the race for `path` on every attempt.
    fn plant_before_mkdir(&self, path: &Path) {
        lock(&self.plant_before).push(path.to_path_buf());
    }

    /// Makes `path`'s modification time unreadable from now on.
    fn hide_mtime(&self, path: &Path) {
        lock(&self.unreadable_mtime).push(path.to_path_buf());
    }

    /// Cancels `cancel` the moment `path` is removed.
    fn cancel_after_rmdir(&self, path: &Path, cancel: Cancel) {
        lock(&self.cancel_after_rmdir).push((path.to_path_buf(), cancel));
    }
}

impl LockFs for SpyFs {
    fn mkdir(&self, at: LockSlot<'_>) -> Result<(), FsError> {
        if lock(&self.plant_before).iter().any(|planted| planted.as_path() == at.shown) {
            // The peer's own `mkdir`, not agctl's: deliberately not
            // recorded, because the timeline is a record of what agctl did.
            let _ = self.real.mkdir(at);
        }
        let result = self.real.mkdir(at);
        self.timeline.push(Op::Mkdir(at.shown.to_path_buf(), result.is_ok()));
        result
    }

    fn rmdir(&self, at: LockSlot<'_>) -> Result<(), FsError> {
        let result = self.real.rmdir(at);
        self.timeline.push(Op::Rmdir(at.shown.to_path_buf()));
        if result.is_ok() && lock(&self.retake).iter().any(|held| held.as_path() == at.shown) {
            let _ = self.real.mkdir(at);
        }
        for (path, cancel) in lock(&self.cancel_after_rmdir).iter() {
            if path.as_path() == at.shown {
                cancel.cancel();
            }
        }
        result
    }

    fn mtime(&self, at: LockSlot<'_>) -> Option<SystemTime> {
        if lock(&self.unreadable_mtime).iter().any(|hidden| hidden.as_path() == at.shown) {
            return None;
        }
        // Passed through and deliberately **not** recorded: the timeline is
        // what agctl did to the filesystem, and a `stat` does nothing to it.
        self.real.mtime(at)
    }
}

/// Applies scheduled actions to the filesystem.
///
/// By path, because these are a *peer's* actions — a Claude Code session
/// heartbeating or releasing its own lock — and a peer holds no descriptor of
/// agctl's.
///
/// A wall-clock step is applied by the caller, under its own lock, because it
/// changes the clock rather than the world.
fn apply(actions: &[Action]) {
    for action in actions {
        match action {
            Action::Mtime(path, at) => set_mtime(path, *at),
            Action::Remove(path) => {
                let _ = fs::remove_dir(path);
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

/// A store directory, an agctl store beside it, and the three lock paths.
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
    /// The environment the live store's spelling comes from, which is what
    /// `Tree::Live` is checked against.
    env: EnvView,
    tree: Tree,
    /// The spelling handed to [`LockSubject`], as production hands it.
    store: PathBuf,
    /// Where the artefacts actually land — the store as the anchor reached it.
    ///
    /// The two differ in the live tree, and only there: [`LockAnchor::open`]
    /// resolves the store the environment names before it walks to it, and on
    /// macOS `tempfile`'s spelling is never the resolved one (`$TMPDIR` lives
    /// under `/var`, a link to `/private/var`).
    resolved: PathBuf,
    primary: PathBuf,
    legacy: PathBuf,
    storage: PathBuf,
    timeline: Shared,
    fs: Arc<SpyFs>,
    base: SystemTime,
}

impl Fixture {
    /// A store inside agctl's own tree.
    ///
    /// Under `namespace_root()`, because that is now a **precondition** rather
    /// than a convention: `Tree::Agctl` with a store anywhere else is
    /// refused before anything is created (review P1-2).
    fn new() -> Self {
        Self::in_tree(Tree::Agctl)
    }

    /// A store that *is* the live one this environment names — the only store
    /// `Tree::Live` accepts.
    fn live() -> Self {
        Self::in_tree(Tree::Live)
    }

    /// The live store reached through a symbolic link, which is what a normal
    /// machine looks like: `$HOME/.claude` is a link to a directory elsewhere
    /// (fact F41, `agctl-p1-live-tree-symlinked-store-anchor-ory`).
    fn live_through_link() -> Self {
        Self::build(Tree::Live, true)
    }

    fn in_tree(tree: Tree) -> Self {
        Self::build(tree, false)
    }

    /// `through_link`: plant the store as a symbolic link to a directory
    /// elsewhere under the temporary root instead of creating it in place.
    fn build(tree: Tree, through_link: bool) -> Self {
        let root = tempfile::tempdir().expect("a temporary directory");
        let paths = Paths::with_config_dir(root.path().join("config"));
        paths.ensure_dirs().expect("the agctl store should be creatable");
        let env = EnvView::with_home(root.path().to_path_buf());
        let store = match tree {
            Tree::Agctl => paths.namespace_dir("acct", "org"),
            Tree::Live => namespace::live_store_dir(&env),
        };
        if through_link {
            let target = root.path().join("elsewhere").join("claude");
            fs::create_dir_all(&target).expect("the link target should be creatable");
            if let Some(parent) = store.parent() {
                fs::create_dir_all(parent).expect("the store's parent should be creatable");
            }
            std::os::unix::fs::symlink(&target, &store)
                .expect("the store link should be plantable");
        } else {
            fs::create_dir_all(&store).expect("the store directory should be creatable");
        }
        // `Tree::Agctl` resolves nothing — a link below its own root is an
        // attack, not a configuration — so there the artefacts land under the
        // spelling the caller handed in.
        let resolved = match tree {
            Tree::Agctl => store.clone(),
            Tree::Live => namespace::canonical(&store).expect("the live store resolves"),
        };

        let timeline = Shared::default();
        let fs_spy = Arc::new(SpyFs::new(timeline.clone()));
        let [primary, legacy, storage] = lock_paths(&resolved);

        Self {
            _root: root,
            paths,
            env,
            tree,
            store,
            resolved,
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

    /// What this fixture's hold is about.
    fn subject(&self) -> LockSubject<'_> {
        LockSubject { store_dir: &self.store, tree: self.tree }
    }

    /// The two descriptors a hold of this store is addressed through.
    ///
    /// A fresh one per acquire, exactly as production does: the walk is what
    /// refuses a redirected store, so re-using one would be re-using a check.
    fn anchor(&self) -> LockAnchor {
        LockAnchor::open(self.subject(), &self.paths, &self.env)
            .expect("the store is reachable and is in the tree it claims")
    }

    /// One acquire over this fixture's seams.
    #[expect(clippy::result_large_err, reason = "mirrors `acquire_with`'s own signature")]
    fn acquire(
        &self,
        seams: &Seams<'_>,
        cancel: &Cancel,
        fault: &Fault,
    ) -> Result<Acquisition, AcquireFailure> {
        acquire_with(self.anchor(), &self.paths, &ctx_with(cancel), fault, seams)
    }

    /// Plants a lock directory whose modification time is `age` old.
    ///
    /// By path: a planted lock is a *peer's*, and this is how the peer makes
    /// one.
    fn plant(&self, path: &Path, age: Duration) {
        fs::create_dir(path).expect("the lock directory should be creatable");
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

    /// The held-lock records this store currently has, through the one reader.
    fn records(&self) -> Vec<held_locks::HeldLockFile> {
        held_locks::read_all(&self.paths)
    }

    /// A path inside this fixture's temporary root but outside the store, for
    /// the tests that need somewhere a redirected write would land.
    fn scratch(&self, name: &str) -> PathBuf {
        self._root.path().join(name)
    }
}

/// The three lock paths one store's hold uses.
///
/// Spelled here rather than taken from [`plan`], so the fixture states the
/// expectation instead of confirming the module against itself. The legacy lock
/// is the store's sibling (fact F17).
fn lock_paths(store: &Path) -> [PathBuf; 3] {
    let parent = store.parent().expect("a store directory has a parent");
    let mut legacy = store.file_name().expect("a store directory has a name").to_os_string();
    legacy.push(LEGACY_LOCK_SUFFIX);
    [store.join(REFRESH_LOCK), parent.join(legacy), store.join(STORAGE_WRITE_LOCK)]
}

/// A descriptor for `dir`, for the tests that are about the real directory
/// operations rather than about a hold.
fn dir_fd(dir: &Path) -> std::os::fd::OwnedFd {
    file_store::open_dir_under(dir, dir).expect("the directory should be openable")
}

/// One lock directory's modification time, by path, the way a peer would read
/// it.
fn mtime_of(path: &Path) -> Option<SystemTime> {
    fs::symlink_metadata(path).ok()?.modified().ok()
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

    let acquired = fixture.acquire(&seams, &cancel, &Fault::none()).expect("an uncontended store");

    let AcquireOutcome::Held(hold) = acquired.outcome else { panic!("expected a hold") };
    assert_eq!(hold.store_dir(), fixture.store, "the hold knows what it is about");
    assert_eq!(hold.tree(), Tree::Agctl, "and which tree it is in (invariant I11′)");
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
    let held = &records[0];
    assert_eq!(held.file, hold.record_path());
    assert_eq!(held.record.agctl_pid, std::process::id());
    assert_eq!(
        held.record.agctl_start_time,
        proc::self_start_time(&Cancel::new()),
        "and when that process started, so a recycled id cannot pass for it"
    );
    assert_eq!(held.record.tree, Tree::Agctl);
    assert_eq!(held.record.store_dir, fixture.store);
    assert_eq!(held.record.paths, fixture.all().to_vec());
    assert!(!held.record.taken_at.is_empty());
    assert_eq!(mode_of(&held.file), FILE_MODE, "0600, like every other file agctl writes");

    drop(hold);
    for path in fixture.all() {
        assert!(!path.exists(), "released on drop: `{}`", path.display());
    }
    assert!(fixture.records().is_empty(), "and the record is cleared");
}

#[test]
fn releasing_runs_in_reverse_order() {
    // In the live tree, which is also this file's one check that a hold of the
    // live store is reachable at all: `Tree::Live` accepts exactly the store
    // directory the environment names.
    let fixture = Fixture::live();
    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    let seams = fixture.seams(&clock, &holders);
    let cancel = Cancel::new();

    let acquired = fixture.acquire(&seams, &cancel, &Fault::none()).expect("an uncontended store");
    let AcquireOutcome::Held(hold) = acquired.outcome else { panic!("expected a hold") };
    assert_eq!(hold.tree(), Tree::Live);
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

    let acquired = fixture
        .acquire(&seams, &cancel, &Fault::none())
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
    let acquired = fixture.acquire(&seams, &cancel, &Fault::none()).expect("busy, not an error");
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
    let acquired = fixture.acquire(&seams, &cancel, &Fault::none()).expect("busy, not an error");
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
    let acquired = fixture.acquire(&seams, &cancel, &Fault::none()).expect("busy, not an error");
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

    let acquired = fixture.acquire(&seams, &cancel, &Fault::none()).expect("busy, not an error");

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

    let acquired = fixture.acquire(&seams, &cancel, &Fault::none()).expect("the holder let go");
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

    let error = fixture
        .acquire(&seams, &cancel, &Fault::none())
        .expect_err("cancellation is not a busy store");
    assert_eq!(error.error, LockError::Cancelled);
    assert!(error.break_record.is_none(), "nothing was stale, so no break travels with it");
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
) -> BreakAttempt {
    run_rule_on(fixture, REFRESH_LOCK, &REFRESH_PROFILE, clock, holders, fault)
}

/// Runs the break rule against one named artefact inside the store.
///
/// The anchor is opened here rather than handed in because the slot borrows
/// from it: the descriptor has to outlive the rule that operates through it,
/// which is the same reason production keeps it for the life of the hold.
fn run_rule_on(
    fixture: &Fixture,
    name: &str,
    profile: &LockProfile,
    clock: &Arc<FakeClock>,
    holders: &dyn HolderEvidence,
    fault: &Fault,
) -> BreakAttempt {
    let cancel = Cancel::new();
    let seams = fixture.seams(clock, holders);
    let anchor = fixture.anchor();
    let shown = fixture.store.join(name);
    let at = anchor.in_store(OsStr::new(name), &shown);
    resolve_stale_with(fixture.subject(), at, profile, &ctx_with(&cancel), fault, &seams)
}

/// The record a draft becomes, with the two fields only a swap knows.
///
/// Every assertion about a break goes through this, because that is the only
/// way to get a record at all: `BreakDraft::complete` is not optional, so a
/// caller cannot reach the log with `service` and `target` unset.
fn completed(draft: BreakDraft) -> LockBreakRecord {
    draft.complete(namespace::LIVE_SERVICE.to_owned(), Target::Live)
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
    let record = completed(outcome.record.expect("a break is audited"));
    assert_eq!(record.outcome, Outcome::Broken);
    assert_eq!(record.reason, None, "every reason in the vocabulary is a reason NOT to break");
    assert_eq!(record.path, fixture.primary);
    assert_eq!(record.store_dir, fixture.store, "the rule is told which store it is resolving");
    assert_eq!(record.tree, Tree::Agctl, "and which tree that store is in");
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
    fs::create_dir(&fixture.primary).expect("creatable");
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
    let anchor = fixture.anchor();

    let outcome = resolve_stale(
        fixture.subject(),
        anchor.in_store(OsStr::new(REFRESH_LOCK), &fixture.primary),
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

    let too_young = run_rule_on(
        &fixture,
        STORAGE_WRITE_LOCK,
        &REFRESH_PROFILE,
        &clock,
        &holders,
        &Fault::none(),
    );
    assert_eq!(too_young.decision, Decision::Abandoned(Reason::TooYoung), "60 s window");

    let clock = fixture.fake_clock();
    let broken = run_rule_on(
        &fixture,
        STORAGE_WRITE_LOCK,
        &STORAGE_WRITE_PROFILE,
        &clock,
        &holders,
        &Fault::none(),
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
    let record = completed(outcome.record.expect("an abandoned break is audited"));
    assert_eq!(record.holder_evidence, HolderEvidence3::StoppedClaudePresent);
    let entry = AuditEntry::new(AuditEvent::LockBreak(record));
    assert_eq!(entry.agctl_pid, std::process::id(), "our own pid, never the holder's");
    let json = serde_json::to_string(&entry).expect("serializable");
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

    let anchor = fixture.anchor();
    let outcome = resolve_stale_with(
        fixture.subject(),
        anchor.in_store(OsStr::new(REFRESH_LOCK), &fixture.primary),
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
    // acquire, so agctl cannot loop against a peer that recreates a lock.
    let fixture = Fixture::new();
    fixture.plant(&fixture.primary, stale_age());
    fixture.fs.retake_after_rmdir(&fixture.primary);
    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    let seams = fixture.seams(&clock, &holders);
    let cancel = Cancel::new();

    let acquired = fixture.acquire(&seams, &cancel, &Fault::none()).expect("busy, not an error");

    let AcquireOutcome::Busy { holder_alive, .. } = acquired.outcome else {
        panic!("expected busy")
    };
    assert!(holder_alive, "somebody took it the instant it was released");
    let record = acquired.break_record.expect("the break is audited");
    assert_eq!(record.outcome, Outcome::Broken, "the directory *was* removed");
    assert_eq!(record.reason, Some(Reason::Retaken), "and immediately retaken");
    assert_eq!(record.store_dir, fixture.store);
    assert_eq!(record.tree, Tree::Agctl);
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

    let acquired = fixture.acquire(&seams, &cancel, &Fault::none()).expect("busy, not an error");

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

        let acquired =
            fixture.acquire(&seams, &cancel, &Fault::none()).expect("an uncontended store");
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
fn a_lock_whose_modification_time_cannot_be_read_is_refused_at_the_take() {
    // `agctl-p2-lock-take-without-mtime-no-drift-check-axs`. Refusal A is
    // the only thing that tells agctl a third party touched a lock it
    // holds, and it compares against the reading taken at that lock's own
    // `mkdir`. A lock with no such reading is a lock held with refusal A
    // switched off, so the take refuses instead of recording `None`.
    for position in 0..3_usize {
        let fixture = Fixture::new();
        let clock = fixture.fake_clock();
        let holders = FakeHolders::none_stopped();
        let seams = fixture.seams(&clock, &holders);
        let cancel = Cancel::new();

        let unreadable = fixture.all()[position].clone();
        fixture.fs.hide_mtime(&unreadable);

        let err = fixture
            .acquire(&seams, &cancel, &Fault::none())
            .expect_err("a lock that cannot be re-stated is not a lock agctl holds");
        let LockError::Io { context, message } = err.error else {
            panic!("position {position}: expected `Io`, got {err:?}");
        };
        assert!(
            context.contains(&unreadable.display().to_string()),
            "position {position}: the refusal names the lock, got `{context}`"
        );
        assert!(
            message.contains("modification time could not be read"),
            "position {position}: and says why, got `{message}`"
        );

        // Everything taken is given back in reverse order — including the
        // directory whose own `mkdir` succeeded, which is the one a `held`
        // that stopped short of it would have leaked.
        let taken: Vec<PathBuf> = fixture.all()[..=position].to_vec();
        let mut expected: Vec<Op> =
            taken.iter().map(|path| Op::Mkdir(path.clone(), true)).collect();
        expected.extend(taken.iter().rev().map(|path| Op::Rmdir(path.clone())));
        assert_eq!(
            fixture.timeline.ops(),
            expected,
            "position {position}: taken in order, released in reverse, nothing else attempted"
        );

        for path in fixture.all() {
            assert!(!path.exists(), "position {position}: `{}` is absent", path.display());
        }
        assert!(
            fixture.records().is_empty(),
            "position {position}: the held-lock record is cleared, as on every other take failure"
        );
        assert!(
            !audit::log_path(&fixture.paths).exists(),
            "position {position}: nothing was stale, so the refusal invents no audit entry"
        );
    }
}

#[test]
fn every_lock_a_hold_took_recorded_a_readable_modification_time() {
    // The other half of the same fix: `HeldOne::mtime` is an `Option` because
    // the reading can fail, and this pins that a hold never carries one that
    // did. The only `None` the take produces is on its way out through
    // `TakeFailure::Io`, and that entry never becomes a `HeldLocks`.
    let fixture = Fixture::new();
    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    let seams = fixture.seams(&clock, &holders);
    let cancel = Cancel::new();

    let acquired = fixture.acquire(&seams, &cancel, &Fault::none()).expect("an uncontended store");
    let AcquireOutcome::Held(hold) = acquired.outcome else { panic!("expected a hold") };

    assert_eq!(hold.held.len(), 3, "three locks, three readings");
    for (one, path) in hold.held.iter().zip(fixture.all()) {
        assert_eq!(one.artefact.path, path, "in acquisition order");
        assert!(one.mtime.is_some(), "`{}` recorded a reading", path.display());
        assert_eq!(
            one.mtime,
            mtime_of(&path),
            "and it is the directory's own, read the way a peer would read it"
        );
    }
}

#[test]
fn an_unreadable_modification_time_is_drift_on_either_side() {
    // The comparison used to be `Option == Option`, so a lock whose reading
    // was missing at `mkdir` time and missing again now compared *equal* and
    // refusal A never fired for it. All three shapes are drift.
    for case in ["missing on the recorded side", "missing on the re-read side", "missing on both"] {
        let fixture = Fixture::new();
        let clock = fixture.fake_clock();
        let holders = FakeHolders::none_stopped();
        let seams = fixture.seams(&clock, &holders);
        let cancel = Cancel::new();

        let acquired =
            fixture.acquire(&seams, &cancel, &Fault::none()).expect("an uncontended store");
        let AcquireOutcome::Held(mut hold) = acquired.outcome else { panic!("expected a hold") };
        assert_eq!(hold.drift_check(), Ok(()), "{case}: the hold starts sound");

        if case != "missing on the re-read side" {
            // Not reachable through the take any more, which is the point of
            // the other half of this fix; reached here directly so that the
            // second guard is checked rather than merely argued.
            hold.held[0].mtime = None;
        }
        if case != "missing on the recorded side" {
            fixture.fs.hide_mtime(&fixture.primary);
        }

        assert_eq!(
            hold.drift_check(),
            Err(LockError::Compromised(fixture.primary.clone())),
            "{case}: an unreadable reading is not evidence that nothing moved"
        );
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

    let acquired = fixture.acquire(&seams, &cancel, &Fault::none()).expect("an uncontended store");
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

    let acquired = fixture.acquire(&seams, &cancel, &Fault::none()).expect("an uncontended store");
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
    let fixture = Fixture::live();
    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    let seams = fixture.seams(&clock, &holders);
    let cancel = Cancel::new();

    let acquired = fixture
        .acquire(&seams, &cancel, &Fault::from_list("swap_lock_leak"))
        .expect("an uncontended store");
    let AcquireOutcome::Held(hold) = acquired.outcome else { panic!("expected a hold") };
    let record_path = hold.record_path().to_path_buf();
    drop(hold);

    for path in fixture.all() {
        assert!(path.is_dir(), "leaked, as a crashed hold would leave it: `{}`", path.display());
    }
    let records = fixture.records();
    let held = records.first().expect("the record survives the leak");
    assert_eq!(records.len(), 1, "and it is discoverable without knowing its name");
    assert_eq!(held.file, record_path);
    assert_eq!(held.record.tree, Tree::Live, "and says which tree they are in");
    assert_eq!(held.record.paths, fixture.all().to_vec(), "naming every leaked directory");
    assert_eq!(held.record.agctl_pid, std::process::id());

    // Left as found: the leaked directories are what a crashed hold leaves,
    // and the temporary directory takes them with it. The registry still
    // holds this hold's restore closure, which is harmless — the paths are
    // gone by the time anything could run it.
    for path in fixture.all() {
        let _ = fs::remove_dir(&path);
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
const CHILD_ROLE_ENV: &str = "AGCTL_LOCK_CHILD_ROLE";

/// Where the child builds its store and reports progress.
const CHILD_DIR_ENV: &str = "AGCTL_LOCK_CHILD_DIR";

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

    let paths = Paths::with_config_dir(dir.join("config"));
    paths.ensure_dirs().expect("the agctl store should be creatable");
    let store = child_store(&dir);
    fs::create_dir_all(&store).expect("the store should be creatable");

    let ctx = PassCtx::standalone(cancel, Instant::now() + Duration::from_secs(60));
    let acquired = acquire(
        LockSubject { store_dir: &store, tree: Tree::Agctl },
        &paths,
        &EnvView::with_home(dir.clone()),
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

/// The store directory the child locks, inside its own namespace root.
fn child_store(dir: &Path) -> PathBuf {
    Paths::with_config_dir(dir.join("config")).namespace_dir("acct", "org")
}

/// The three lock paths the child took, given its temporary directory.
fn child_locks(dir: &Path) -> [PathBuf; 3] {
    lock_paths(&child_store(dir))
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
fn held_records_in(dir: &Path) -> Vec<held_locks::HeldLockFile> {
    held_locks::read_all(&Paths::with_config_dir(dir.join("config")))
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
    assert_eq!(serde_json::to_string(&Tree::Agctl).expect("ok"), "\"agctl\"");
    assert_eq!(serde_json::to_string(&Tree::Live).expect("ok"), "\"live\"");
}

#[test]
fn a_break_record_carries_one_pid_and_it_is_ours() {
    // Architect NEW-10: a `pid` field sitting beside `holder_evidence` would
    // read as the *holder's* pid, and an implementation that wrote one there
    // would have passed AC80. The field is named unambiguously and the record
    // has no other.
    // Asserted on the **audit entry**, because that is the object section 3.8
    // fixes and the only shape a record ever reaches a file in: the provenance
    // fields — `ts`, `monotonic_ms`, `agctl_pid` — belong to the entry, and
    // a second copy of them inside the record would duplicate them here.
    let fixture = Fixture::new();
    fixture.plant(&fixture.primary, stale_age());
    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    let outcome = run_rule(&fixture, &clock, &holders, &Fault::none());
    let record = completed(outcome.record.expect("audited"));

    let entry = AuditEntry::new(AuditEvent::LockBreak(record));
    let json = serde_json::to_value(&entry).expect("serializable");
    let object = json.as_object().expect("an object");
    let pid_keys: Vec<&String> = object.keys().filter(|key| key.contains("pid")).collect();
    assert_eq!(pid_keys, vec!["agctl_pid"], "one pid field, unambiguously ours");
    assert_eq!(object["agctl_pid"], std::process::id());
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
        agctl_pid: 4242,
        agctl_start_time: Some("2026-09-09T00:00:00Z".to_owned()),
        tree: Tree::Live,
        store_dir: PathBuf::from("/store"),
        paths: vec![PathBuf::from("/store/.oauth_refresh.lock")],
        taken_at: "2026-09-09T00:00:00Z".to_owned(),
    };
    let json = serde_json::to_value(&record).expect("serializable");
    assert_eq!(
        json,
        serde_json::json!({
            "agctl_pid": 4242,
            "agctl_start_time": "2026-09-09T00:00:00Z",
            "tree": "live",
            "store_dir": "/store",
            "paths": ["/store/.oauth_refresh.lock"],
            "taken_at": "2026-09-09T00:00:00Z",
        })
    );
    let round_trip: HeldLockRecord = serde_json::from_value(json).expect("the shape round-trips");
    assert_eq!(round_trip, record);

    // And a record from a build that predates the start time still reads: the
    // field defaults to "unknown" rather than making the record unparseable,
    // which would turn a leak nobody can explain into a leak nobody can clear.
    let older = serde_json::json!({
        "agctl_pid": 4242,
        "tree": "live",
        "store_dir": "/store",
        "paths": ["/store/.oauth_refresh.lock"],
        "taken_at": "2026-09-09T00:00:00Z",
    });
    let read: HeldLockRecord = serde_json::from_value(older).expect("an older record still reads");
    assert_eq!(read.agctl_start_time, None);
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
fn the_legacy_lock_is_the_entry_the_resolved_spelling_names() {
    // Fact F17/F46: the peer names the legacy lock after `realpath` of the
    // store directory. agctl does not call `realpath` — it walks to the
    // store one `O_NOFOLLOW` component at a time and creates the artefact
    // relative to the parent that walk reached — and this test is what proves
    // the two land on the same directory entry, which is the whole reason
    // dropping `canonicalize` is safe.
    //
    // The distinction is visible on macOS in the common case rather than the
    // exotic one: `$TMPDIR` lives under `/var`, a link to `/private/var`, so
    // the lexical and resolved spellings of every fixture path differ.
    let fixture = Fixture::new();
    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    let seams = fixture.seams(&clock, &holders);
    let cancel = Cancel::new();

    let plans = plan(&fixture.anchor()).map(|lock| lock.artefact.path);
    assert_eq!(plans.to_vec(), fixture.all().to_vec(), "the plan spells them lexically");
    assert_eq!(fixture.primary, fixture.store.join(REFRESH_LOCK));
    assert_eq!(fixture.storage, fixture.store.join(STORAGE_WRITE_LOCK));

    let acquired = fixture.acquire(&seams, &cancel, &Fault::none()).expect("an uncontended store");
    let AcquireOutcome::Held(hold) = acquired.outcome else { panic!("expected a hold") };

    let resolved = namespace::canonical(&fixture.store).expect("the store resolves");
    let peers_spelling = PathBuf::from(format!("{}{LEGACY_LOCK_SUFFIX}", resolved.display()));
    assert_ne!(peers_spelling, fixture.legacy, "the two spellings really do differ here");
    assert!(
        peers_spelling.is_dir(),
        "the lock agctl made is the one `{}` names",
        peers_spelling.display()
    );

    drop(hold);
    assert!(!peers_spelling.exists(), "and releasing it removes that same entry");
}

#[test]
fn the_real_operations_make_and_remove_a_directory() {
    // `AT_REMOVEDIR` is the whole point: `unlink` cannot remove a directory,
    // which is the defect `agctl-nz5` records.
    let dir = tempfile::tempdir().expect("a temporary directory");
    let lock = dir.path().join(REFRESH_LOCK);
    let fd = dir_fd(dir.path());
    let at = LockSlot { dir: fd.as_fd(), name: OsStr::new(REFRESH_LOCK), shown: &lock };

    RealFs.mkdir(at).expect("creatable");
    assert!(lock.is_dir(), "a directory, as `proper-lockfile` makes it");
    assert_eq!(RealFs.mkdir(at), Err(FsError::Exists), "a second attempt is contention");
    assert_eq!(RealFs.mtime(at), mtime_of(&lock), "and the same directory a path would stat");
    // Darwin answers `EPERM` here rather than `EISDIR`; either way `unlink`
    // will not remove a directory, which is exactly why
    // `cleanup::register_tmp_path` cannot clean a lock up and
    // `register_restore` has to.
    assert!(
        std::fs::remove_file(&lock).is_err(),
        "`unlink` cannot remove a directory on any platform this runs on"
    );
    assert!(lock.is_dir(), "and it is still there");
    RealFs.rmdir(at).expect("removable with AT_REMOVEDIR");
    assert!(!lock.exists());
    assert_eq!(RealFs.rmdir(at), Err(FsError::NotFound));
    assert_eq!(RealFs.mtime(at), None, "and a lock that is gone has no modification time");
}

#[test]
fn a_symlink_where_a_lock_should_be_is_never_removed() {
    // A link at a lock path is somebody else's plant. `AT_SYMLINK_NOFOLLOW`
    // keeps the sampling from reading the target's modification time, and
    // `AT_REMOVEDIR` refuses a link outright — the safe side of that trade.
    let dir = tempfile::tempdir().expect("a temporary directory");
    let target = dir.path().join("target");
    fs::create_dir(&target).expect("creatable");
    let link = dir.path().join(REFRESH_LOCK);
    std::os::unix::fs::symlink(&target, &link).expect("linkable");
    let fd = dir_fd(dir.path());
    let at = LockSlot { dir: fd.as_fd(), name: OsStr::new(REFRESH_LOCK), shown: &link };

    assert!(matches!(RealFs.rmdir(at), Err(FsError::Other(_))), "a link is not removed");
    assert!(link.exists(), "and is still there");
    assert_ne!(
        RealFs.mtime(at),
        mtime_of(&target),
        "and the sample is the link's own time, never the target's"
    );
}

#[test]
fn a_symlinked_component_above_the_store_is_refused_before_anything_is_created() {
    // Review P0-1, reproduced. A same-user attacker who can create one
    // symbolic link under `<config>/claude` plants `<acct>` as a link to the
    // live store. Every lexical check still says
    // `<root>/<acct>/<org>/.oauth_refresh.lock` is inside `namespace_root()`,
    // so a path-based hold would `mkdir` — and later `rmdir` — Claude Code's
    // live locks while the record and the audit entry both said
    // `tree: agctl`.
    let root = tempfile::tempdir().expect("a temporary directory");
    let paths = Paths::with_config_dir(root.path().join("config"));
    paths.ensure_dirs().expect("the agctl store should be creatable");

    // The attacker's target, shaped like a real store so that a redirected
    // hold would succeed rather than fail for some unrelated reason.
    let elsewhere = root.path().join("elsewhere");
    fs::create_dir_all(elsewhere.join("org")).expect("the target should be creatable");
    std::os::unix::fs::symlink(&elsewhere, paths.namespace_root().join("acct"))
        .expect("the link should be creatable");

    let store = paths.namespace_dir("acct", "org");
    assert!(
        paths.is_under_namespace_root(&store),
        "the lexical check is satisfied — that is the point"
    );

    let cancel = Cancel::new();
    let env = EnvView::with_home(root.path().to_path_buf());
    let subject = LockSubject { store_dir: &store, tree: Tree::Agctl };

    // No seams are injected, and none could be: the refusal happens while the
    // anchor is being opened, which is before any `LockFs` is consulted. That
    // ordering is the guarantee — a hold that cannot be addressed cannot be
    // attempted.
    let refused = LockAnchor::open(subject, &paths, &env)
        .expect_err("a symbolic link on the way to the store is refused");
    assert!(matches!(refused, LockError::Unreachable { .. }), "{refused:?}");

    // And the same refusal through the entry point a caller uses, so it cannot
    // be reached by skipping the anchor.
    let also_refused =
        acquire(subject, &paths, &env, &Clock::system(), &ctx_with(&cancel), &Fault::none())
            .expect_err("and `acquire` refuses for the same reason");
    assert!(matches!(also_refused.error, LockError::Unreachable { .. }), "{also_refused:?}");
    assert!(
        also_refused.break_record.is_none(),
        "and it carries no break: the anchor is walked before the break rule can run"
    );

    for name in [REFRESH_LOCK, STORAGE_WRITE_LOCK] {
        let planted = elsewhere.join("org").join(name);
        assert!(!planted.exists(), "nothing was created in the target: `{}`", planted.display());
    }
    let legacy = elsewhere.join(format!("org{LEGACY_LOCK_SUFFIX}"));
    assert!(!legacy.exists(), "and no legacy lock beside it either");
    assert!(held_locks::read_all(&paths).is_empty(), "and no held-lock record claims one");
}

#[test]
fn a_store_outside_the_namespace_root_cannot_claim_the_agctl_tree() {
    // Review P1-2. `tree` is the field `doctor`, `--remove-stale`'s attested
    // branch and invariant I11′'s containment all key on, so it is derived
    // from the store directory rather than believed.
    let root = tempfile::tempdir().expect("a temporary directory");
    let paths = Paths::with_config_dir(root.path().join("config"));
    paths.ensure_dirs().expect("the agctl store should be creatable");
    let env = EnvView::with_home(root.path().to_path_buf());
    let store = root.path().join("somewhere-else");
    fs::create_dir(&store).expect("creatable");

    let refused =
        LockAnchor::open(LockSubject { store_dir: &store, tree: Tree::Agctl }, &paths, &env)
            .expect_err("a store outside the root is not agctl's");
    assert_eq!(refused, LockError::WrongTree { store_dir: store.clone(), tree: Tree::Agctl });
    assert!(refused.to_string().contains("agctl's own tree"), "{refused}");
}

#[test]
fn a_store_that_is_not_the_live_one_cannot_claim_the_live_tree() {
    // The other half of P1-2, and the one that matters most: `live` is the
    // increment W4b adds, and it means *the* store this environment names.
    let fixture = Fixture::new();
    let refused = LockAnchor::open(
        LockSubject { store_dir: &fixture.store, tree: Tree::Live },
        &fixture.paths,
        &fixture.env,
    )
    .expect_err("agctl's own namespace is not the live store");
    assert_eq!(
        refused,
        LockError::WrongTree { store_dir: fixture.store.clone(), tree: Tree::Live }
    );

    // And the live store itself is accepted, so the check is not simply "no".
    let live = Fixture::live();
    LockAnchor::open(live.subject(), &live.paths, &live.env)
        .expect("the live store is the live store");
}

// ---------------------------------------------------------------------------
// The live store through a symbolic link
// (`agctl-p1-live-tree-symlinked-store-anchor-ory`)
// ---------------------------------------------------------------------------

#[test]
fn a_symlinked_live_store_is_locked_where_it_resolves_to() {
    // The default configuration on a real machine: `$HOME/.claude` is a link
    // to a directory elsewhere (fact F41). Before this, `Tree::Live` anchored
    // at the *lexical* parent and walked `.claude` with `O_NOFOLLOW`, so every
    // acquire returned `Unreachable` — the live tree could not be locked at
    // all. The naive repair, following the link but keeping `$HOME` as the
    // anchor, is worse than the defect: the legacy artefact would be
    // `$HOME/.claude.lock` while the peer holds `realpath(dir) + ".lock"`
    // (fact F17), and the F54/F55 race would be lost silently.
    let fixture = Fixture::live_through_link();
    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    let seams = fixture.seams(&clock, &holders);
    let cancel = Cancel::new();

    assert!(
        fs::symlink_metadata(&fixture.store).expect("planted").file_type().is_symlink(),
        "the fixture really does reach the live store through a link"
    );
    assert_ne!(fixture.resolved, fixture.store, "and the two spellings differ");

    let acquired = fixture.acquire(&seams, &cancel, &Fault::none()).expect("an uncontended store");
    let AcquireOutcome::Held(hold) = acquired.outcome else { panic!("expected a hold") };
    assert_eq!(hold.tree(), Tree::Live);
    assert_eq!(hold.store_dir(), fixture.resolved, "the hold is about the resolved store");

    // The load-bearing assertion: the legacy artefact is the entry the peer
    // names, and *not* the one beside the link. The expected spelling comes
    // from `fs::canonicalize` rather than from `namespace::canonical`, which is
    // what production itself resolves with and what `Fixture::resolved` holds:
    // an NFC or `realpath` divergence inside that helper would cancel out on
    // both sides of the comparison and this test would pass through it.
    let peers_spelling = PathBuf::from(format!(
        "{}{LEGACY_LOCK_SUFFIX}",
        fs::canonicalize(&fixture.store).expect("the live store resolves").display()
    ));
    assert_eq!(fixture.legacy, peers_spelling);
    assert!(peers_spelling.is_dir(), "`{}` is agctl's", peers_spelling.display());
    let beside_the_link = PathBuf::from(format!("{}{LEGACY_LOCK_SUFFIX}", fixture.store.display()));
    assert!(
        !beside_the_link.exists(),
        "and nothing was created at `{}`, which is a different entry",
        beside_the_link.display()
    );

    for path in fixture.all() {
        assert!(path.is_dir(), "all three are taken: `{}`", path.display());
    }
    let held = fixture.records().pop().expect("a held-lock record");
    assert_eq!(held.record.store_dir, fixture.resolved);
    assert_eq!(held.record.paths, fixture.all().to_vec());
    // `HeldLockRecord::anchor()` is `store_dir.parent()`, and `doctor
    // --remove-stale` walks from it with `O_NOFOLLOW`. Recording the lexical
    // spelling would name `$HOME`, whose next component is the link — so a
    // leaked lock could never be removed by the tool that exists to remove it.
    assert_eq!(held.record.anchor(), fixture.resolved.parent());

    drop(hold);
    for path in fixture.all() {
        assert!(!path.exists(), "released on drop: `{}`", path.display());
    }
}

#[test]
fn the_live_store_is_matched_by_identity_and_not_by_spelling() {
    // Two spellings of one directory are one store. The environment names the
    // link; a caller that spells the resolved target is asking about the same
    // directory and is accepted, and both anchor at the same resolved parent.
    let fixture = Fixture::live_through_link();
    let by_target = LockSubject { store_dir: fixture.resolved.as_path(), tree: Tree::Live };
    let anchor = LockAnchor::open(by_target, &fixture.paths, &fixture.env)
        .expect("the resolved spelling names the live store");
    assert_eq!(anchor.store_dir(), fixture.resolved);

    // A sibling of the *resolved* store is not the live store, so the
    // resolution has not turned the check into containment.
    let sibling = fixture.resolved.with_file_name("not-claude");
    fs::create_dir(&sibling).expect("creatable");
    let refused = LockAnchor::open(
        LockSubject { store_dir: &sibling, tree: Tree::Live },
        &fixture.paths,
        &fixture.env,
    )
    .expect_err("a store beside the live one is not the live one");
    assert_eq!(refused, LockError::WrongTree { store_dir: sibling, tree: Tree::Live });
}

#[test]
fn a_live_store_that_does_not_resolve_is_refused_before_anything_is_created() {
    // A dangling link is not a store. The refusal is `Unreachable` rather than
    // `WrongTree`, because the environment does name this path — it is the
    // path that is not there.
    let root = tempfile::tempdir().expect("a temporary directory");
    let paths = Paths::with_config_dir(root.path().join("config"));
    paths.ensure_dirs().expect("the agctl store should be creatable");
    let env = EnvView::with_home(root.path().to_path_buf());
    let store = namespace::live_store_dir(&env);
    std::os::unix::fs::symlink(root.path().join("gone"), &store).expect("plantable");

    let refused =
        LockAnchor::open(LockSubject { store_dir: &store, tree: Tree::Live }, &paths, &env)
            .expect_err("a dangling live store cannot be locked");
    let LockError::Unreachable { path, message } = &refused else {
        panic!("expected `Unreachable`, got {refused:?}")
    };
    assert_eq!(path, &store, "named by the spelling the caller used");
    assert!(message.contains("could not be resolved"), "and why: {message}");
    assert!(!root.path().join("gone").exists(), "and nothing was created at the target");
}

#[test]
fn a_live_store_link_to_something_that_is_not_a_directory_is_refused() {
    // The walk still runs after the resolution, and it still refuses. The
    // resolved last component exists here, so this is the walk's own refusal
    // below the resolved anchor rather than the resolution's.
    let root = tempfile::tempdir().expect("a temporary directory");
    let paths = Paths::with_config_dir(root.path().join("config"));
    paths.ensure_dirs().expect("the agctl store should be creatable");
    let env = EnvView::with_home(root.path().to_path_buf());
    let target = root.path().join("a-file");
    fs::write(&target, b"not a directory").expect("writable");
    let store = namespace::live_store_dir(&env);
    std::os::unix::fs::symlink(&target, &store).expect("plantable");

    let refused =
        LockAnchor::open(LockSubject { store_dir: &store, tree: Tree::Live }, &paths, &env)
            .expect_err("a live store that resolves to a file cannot be locked");
    assert!(matches!(refused, LockError::Unreachable { .. }), "{refused:?}");
    assert_eq!(
        fs::read(&target).expect("still readable"),
        b"not a directory",
        "and the target was left alone"
    );
}

#[test]
fn a_symlinked_agctl_store_is_still_refused() {
    // `Tree::Agctl` is deliberately not relaxed. agctl owns every
    // component below its own root, so a link planted at the store is an
    // attack rather than a configuration, and following it would put a lock
    // wherever the attacker pointed.
    let root = tempfile::tempdir().expect("a temporary directory");
    let paths = Paths::with_config_dir(root.path().join("config"));
    paths.ensure_dirs().expect("the agctl store should be creatable");
    let env = EnvView::with_home(root.path().to_path_buf());

    let elsewhere = root.path().join("elsewhere");
    fs::create_dir(&elsewhere).expect("creatable");
    let store = paths.namespace_dir("acct", "org");
    fs::create_dir_all(store.parent().expect("a parent")).expect("creatable");
    std::os::unix::fs::symlink(&elsewhere, &store).expect("the store link should be plantable");

    let refused =
        LockAnchor::open(LockSubject { store_dir: &store, tree: Tree::Agctl }, &paths, &env)
            .expect_err("a symbolic link at agctl's own store is refused");
    let LockError::Unreachable { path, message } = &refused else {
        panic!("expected `Unreachable`, got {refused:?}")
    };
    assert_eq!(path, &store);
    assert!(message.contains("symbolic link"), "and why: {message}");
    assert_eq!(
        fs::read_dir(&elsewhere).expect("readable").count(),
        0,
        "and nothing was created in what it pointed at"
    );
}

// ---------------------------------------------------------------------------
// Refusal E on the lock side
// (`agctl-p2-live-tree-securestorage-dir-refusal-r4v`)
// ---------------------------------------------------------------------------

/// A temporary root, agctl's own store under it, and an `EnvView` whose
/// `CLAUDE_SECURESTORAGE_CONFIG_DIR` is whatever the case is about.
fn securestorage_fixture(value: Option<&str>) -> (tempfile::TempDir, Paths, EnvView) {
    let root = tempfile::tempdir().expect("a temporary directory");
    let paths = Paths::with_config_dir(root.path().join("config"));
    paths.ensure_dirs().expect("the agctl store should be creatable");
    let mut env = EnvView::with_home(root.path().to_path_buf());
    env.securestorage_dir = value.map(str::to_owned);
    (root, paths, env)
}

#[test]
fn a_set_securestorage_dir_refuses_the_live_tree_before_anything_is_created() {
    // `WriteTarget::live` refuses this environment, and until now the lock side
    // accepted it: the store `live_store_dir` returns with the variable set is
    // the *namespace* it points at, so a swap could have locked the namespace
    // while the write half refused — or, worse, locked it under the name
    // "live". The two halves must agree about what "live" means (risk R42).
    let root = tempfile::tempdir().expect("a temporary directory");
    let paths = Paths::with_config_dir(root.path().join("config"));
    paths.ensure_dirs().expect("the agctl store should be creatable");
    let namespace_dir = root.path().join("pointed-at");
    fs::create_dir(&namespace_dir).expect("creatable");
    let mut env = EnvView::with_home(root.path().to_path_buf());
    env.securestorage_dir = Some(namespace_dir.to_string_lossy().into_owned());

    // The store the environment now names is the namespace itself, so this is
    // the subject a caller would build — the refusal is not about the caller
    // having named the wrong directory.
    let store = namespace::live_store_dir(&env);
    assert_eq!(store, namespace_dir, "the environment names the namespace");

    let refused =
        LockAnchor::open(LockSubject { store_dir: &store, tree: Tree::Live }, &paths, &env)
            .expect_err("a shell pointed at a namespace has no live store to lock");
    let LockError::Unreachable { path, message } = &refused else {
        panic!("expected `Unreachable`, got {refused:?}")
    };
    assert_eq!(path, &store);
    assert!(message.contains(namespace::SECURESTORAGE_ENV), "it names the variable: {message}");
    assert!(
        message.contains(&namespace_dir.to_string_lossy().into_owned()),
        "and the value, so the user can find the shell that set it: {message}"
    );

    // Before anything is created: the namespace is exactly as it was found.
    assert_eq!(
        fs::read_dir(&namespace_dir).expect("readable").count(),
        0,
        "no lock artefact was created inside it"
    );
    assert!(
        !PathBuf::from(format!("{}{LEGACY_LOCK_SUFFIX}", namespace_dir.display())).exists(),
        "and none beside it"
    );
}

#[test]
fn an_empty_securestorage_dir_is_not_refused() {
    // Fact F14's gate is truthiness, not presence. An empty value is falsy to
    // Claude Code, so it names the live store exactly as an unset variable
    // would — refusing it would lock the user out of their own live store on a
    // shell that merely exported the variable empty.
    let (root, paths, env) = securestorage_fixture(Some(""));
    let store = namespace::live_store_dir(&env);
    assert_eq!(store, root.path().join(".claude"), "an empty value falls back to `~/.claude`");
    fs::create_dir(&store).expect("creatable");

    LockAnchor::open(LockSubject { store_dir: &store, tree: Tree::Live }, &paths, &env)
        .expect("an empty value names the live store");
}

#[test]
fn a_set_securestorage_dir_leaves_the_agctl_tree_alone() {
    // The refusal is about what "live" means, and agctl's own tree does not
    // depend on the variable at all: a `--claude-config-dir` session in a shell
    // pointed at a namespace still has its own locks to take.
    let (_root, paths, env) = securestorage_fixture(Some("/somewhere/else"));
    let store = paths.namespace_dir("acct", "org");
    fs::create_dir_all(&store).expect("creatable");

    LockAnchor::open(LockSubject { store_dir: &store, tree: Tree::Agctl }, &paths, &env)
        .expect("agctl's own tree is not the live one and never was");
}

#[test]
fn the_lock_and_write_halves_refuse_exactly_the_same_environments() {
    // The drift guard for risk R42. `namespace::securestorage_namespace` is the
    // one definition of fact F14's gate; this pins the write half's answer to
    // it across all three shapes the variable can have, so a future edit to
    // either side that changes the gate fails here rather than in production.
    // Only the *derivation* is exercised — no keychain item is named, opened or
    // written.
    let home = PathBuf::from("/does/not/need/to/exist");
    for (value, pointed_at_a_namespace) in
        [(None, false), (Some(""), false), (Some("/a/namespace"), true)]
    {
        let mut env = EnvView::with_home(home.clone());
        env.securestorage_dir = value.map(str::to_owned);

        assert_eq!(
            namespace::securestorage_namespace(&env).is_some(),
            pointed_at_a_namespace,
            "the gate, for {value:?}"
        );
        assert_eq!(
            crate::secret::keychain_write::WriteTarget::live(&env).is_err(),
            pointed_at_a_namespace,
            "and the write half agrees, for {value:?}"
        );
    }
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

// ---------------------------------------------------------------------------
// A completed break survives every failing way out of `acquire_with`
// (`agctl-nq3`, invariant I16)
// ---------------------------------------------------------------------------

/// Does what `status.rs` `refresh_in_place` owes a break, and reads the log
/// back.
///
/// Invariant I16 is about the **audit line**, not about the draft, so these
/// tests perform the caller's own two statements — `BreakDraft::complete` then
/// `audit::append` — and then assert on what landed on disk. `acquire_with`
/// deliberately appends nothing itself: no I/O may grow between Sample C and
/// the `rmdir`, which is why the draft is returned in the first place.
fn append_and_read(paths: &Paths, draft: Option<BreakDraft>) -> Vec<LockBreakRecord> {
    if let Some(draft) = draft {
        audit::append(paths, &AuditEntry::new(AuditEvent::LockBreak(completed(draft))))
            .expect("the audit log should be appendable");
    }
    audit::tail(paths, 16)
        .expect("the audit log should be readable")
        .entries
        .into_iter()
        .filter_map(|entry| match entry.event {
            AuditEvent::LockBreak(record) => Some(record),
            AuditEvent::Write { .. } => None,
        })
        .collect()
}

/// Asserts the one `broken` line a completed break owes, with its fields.
fn assert_one_broken_line(records: &[LockBreakRecord], fixture: &Fixture, path: &Path, at: &str) {
    assert_eq!(records.len(), 1, "{at}: exactly one lock-break line");
    let record = &records[0];
    assert_eq!(record.outcome, Outcome::Broken, "{at}: the peer's directory *was* removed");
    assert_eq!(record.reason, None, "{at}: a clean break records no reason");
    assert_eq!(record.path, path, "{at}: naming the directory that was removed");
    assert_eq!(record.store_dir, fixture.store, "{at}: and the store it guards");
    assert_eq!(record.tree, Tree::Agctl, "{at}: and which tree that store is in");
    assert!(record.sample_b.is_some(), "{at}: Sample B survived the failure");
    assert!(record.sample_c.is_some(), "{at}: and Sample C, the one taken before the `rmdir`");
    assert_eq!(record.holder_evidence, HolderEvidence3::NoStoppedClaude, "{at}: and the evidence");
}

#[test]
fn a_break_survives_a_cancellation_at_the_top_of_a_restart_iteration() {
    // Err site 1 of six: the `loop`'s own cancellation check, reached on a
    // second iteration after a `TakeFailure::Exists` restart. The break
    // happened on the first iteration, so the draft is already complete when
    // the run is cancelled.
    let fixture = Fixture::new();
    fixture.plant(&fixture.legacy, stale_age());
    let cancel = Cancel::new();
    // Cancelled while the break rule is unwinding, not during a wait: the run
    // then survives to the restart and dies at the top of the loop.
    fixture.fs.cancel_after_rmdir(&fixture.legacy, cancel.clone());
    // And a peer holds `.storage-write`, which is what forces the restart.
    fixture.fs.plant_before_mkdir(&fixture.storage);

    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    let seams = fixture.seams(&clock, &holders);

    let failure = fixture
        .acquire(&seams, &cancel, &Fault::none())
        .expect_err("a cancelled run is an error, not a busy store");
    assert_eq!(failure.error, LockError::Cancelled);

    // Which cancellation site this is, pinned: only the top-of-loop one is
    // reached *after* a whole take was attempted and unwound. Site 4's
    // schedule runs before step 4, so it never gets here.
    let ops = fixture.timeline.ops();
    assert!(
        ops.contains(&Op::Mkdir(fixture.storage.clone(), false)),
        "the peer held `.storage-write`, so the take failed there: {ops:?}"
    );
    assert_eq!(
        ops.last(),
        Some(&Op::Rmdir(fixture.primary.clone())),
        "and the take was unwound in reverse before the loop restarted: {ops:?}"
    );

    let records = append_and_read(&fixture.paths, failure.break_record);
    assert_one_broken_line(&records, &fixture, &fixture.legacy, "site 1");
    assert!(fixture.records().is_empty(), "and the failed take left no held-lock record");
}

#[test]
fn a_break_survives_a_cancellation_in_the_contention_wait() {
    // Err site 4 of six: fact F36's schedule, which runs *after* step 1's
    // break rule, so a cancellation inside it strands a completed draft.
    let fixture = Fixture::new();
    // The primary is alive, so the schedule is entered at all; the legacy
    // lock is the stale one that gets broken.
    fixture.plant(&fixture.primary, Duration::from_secs(1));
    fixture.plant(&fixture.legacy, stale_age());
    let cancel = Cancel::new();
    fixture.fs.cancel_after_rmdir(&fixture.legacy, cancel.clone());

    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    let seams = fixture.seams(&clock, &holders);

    let failure = fixture
        .acquire(&seams, &cancel, &Fault::none())
        .expect_err("a cancelled contention wait is an error");
    assert_eq!(failure.error, LockError::Cancelled);
    assert!(fixture.primary.is_dir(), "the live primary was never touched");
    let ops = fixture.timeline.ops();
    assert!(
        !ops.iter().any(|op| matches!(op, Op::Mkdir(..))),
        "cancelled inside the schedule, so step 4 was never reached: {ops:?}"
    );
    assert!(matches!(ops.last(), Some(Op::Sleep(_))), "and it died in a wait: {ops:?}");

    let records = append_and_read(&fixture.paths, failure.break_record);
    assert_one_broken_line(&records, &fixture, &fixture.legacy, "site 4");
}

#[test]
fn a_break_survives_a_held_locks_directory_that_cannot_be_reached() {
    // Err site 5 of six, and the one `agctl-nq3` was filed for: after
    // `1yj` a symbolic link at `<namespace_root>/held-locks` makes step 3
    // fail deterministically. Before this fix that gave anyone who could
    // plant one link a repeatable way to have agctl remove a peer's lock
    // and write nothing about it.
    let fixture = Fixture::new();
    fixture.plant(&fixture.primary, stale_age());
    let elsewhere = fixture.scratch("elsewhere");
    fs::create_dir(&elsewhere).expect("the decoy should be creatable");
    std::os::unix::fs::symlink(&elsewhere, held_locks::dir(&fixture.paths))
        .expect("the link should be plantable");

    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    let seams = fixture.seams(&clock, &holders);
    let cancel = Cancel::new();

    let failure = fixture
        .acquire(&seams, &cancel, &Fault::none())
        .expect_err("a redirected held-locks directory refuses the hold");
    assert!(
        matches!(failure.error, LockError::Unreachable { .. }),
        "the refusal is unchanged: {:?}",
        failure.error
    );
    assert!(!fixture.primary.exists(), "and the peer's lock is gone — which is the point");
    let ops = fixture.timeline.ops();
    assert!(
        !ops.iter().any(|op| matches!(op, Op::Mkdir(..))),
        "refused at step 3, before the first `mkdir`: {ops:?}"
    );

    let records = append_and_read(&fixture.paths, failure.break_record);
    assert_one_broken_line(&records, &fixture, &fixture.primary, "site 5");
}

#[test]
fn a_break_survives_a_take_that_could_not_be_completed() {
    // Err site 6 of six. After `axs` this is reachable with no `mkdir`
    // failure at all: the second lock is created and its modification time
    // cannot be read, so the hold is refused. The draft it strands can carry
    // a completed *removal*, which is the most valuable one to lose.
    let fixture = Fixture::new();
    fixture.plant(&fixture.primary, stale_age());
    fixture.fs.hide_mtime(&fixture.legacy);

    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    let seams = fixture.seams(&clock, &holders);
    let cancel = Cancel::new();

    let failure = fixture
        .acquire(&seams, &cancel, &Fault::none())
        .expect_err("a lock that cannot be re-stated is not a lock agctl holds");
    assert!(
        matches!(failure.error, LockError::Io { .. }),
        "the refusal is unchanged: {:?}",
        failure.error
    );
    let ops = fixture.timeline.ops();
    assert!(
        ops.contains(&Op::Mkdir(fixture.legacy.clone(), true)),
        "the second lock was created — the refusal is the `stat`, not the `mkdir`: {ops:?}"
    );
    for path in fixture.all() {
        assert!(!path.exists(), "nothing is held: `{}`", path.display());
    }
    assert!(fixture.records().is_empty(), "and the held-lock record is cleared");

    let records = append_and_read(&fixture.paths, failure.break_record);
    assert_one_broken_line(&records, &fixture, &fixture.primary, "site 6");
}

#[test]
fn the_two_sampling_refusals_carry_no_break_because_they_decided_nothing() {
    // Err sites 2 and 3 of six, for completeness: a sampling wait that is
    // cancelled and a sampling that fails both return `record: None`, so the
    // uniform `break_record` they now pass is `None`. Asserted rather than
    // reasoned about, because "this arm cannot carry a draft" is exactly the
    // claim `agctl-ahh` got wrong for four of the six.
    let fixture = Fixture::new();
    fixture.plant(&fixture.primary, stale_age());
    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    let seams = fixture.seams(&clock, &holders);
    let cancel = Cancel::new();
    clock.cancel_next_sleep(cancel.clone());

    let failure = fixture
        .acquire(&seams, &cancel, &Fault::none())
        .expect_err("a cancelled sampling wait is an error");
    assert_eq!(failure.error, LockError::Cancelled);
    assert!(failure.break_record.is_none(), "nothing was decided, so there is nothing to record");
    assert!(fixture.primary.is_dir(), "and the peer's lock was left exactly as it was");
    assert!(append_and_read(&fixture.paths, None).is_empty(), "so the audit log stays empty");
}

// ---------------------------------------------------------------------------
// The held-locks directory is reached by a walk
// (`agctl-p2-held-locks-dir-through-symlink-1yj`)
// ---------------------------------------------------------------------------

#[test]
fn a_symlink_at_the_held_locks_directory_refuses_the_hold_before_anything_is_taken() {
    // w2-rereview P2-a. The record used to be filed by path: `Path::is_dir`
    // to decide whether the directory existed — which follows links — then a
    // path-based `DirBuilder`, then a path-based create of the record itself.
    // A link planted at that one leaf name sent the record, and every record
    // after it, into a directory of somebody else's choosing. The record is
    // what `doctor` and `--remove-stale` read to decide whether a lock
    // *outside* the namespace root may be removed, so a record an attacker can
    // place is a record that can name paths agctl would then act on.
    let fixture = Fixture::new();
    let elsewhere = fixture.scratch("elsewhere");
    fs::create_dir(&elsewhere).expect("the decoy should be creatable");

    let held_dir = held_locks::dir(&fixture.paths);
    assert!(!held_dir.exists(), "the first hold is what would create it");
    std::os::unix::fs::symlink(&elsewhere, &held_dir).expect("the link should be plantable");
    assert!(held_dir.is_dir(), "`is_dir` follows the link and says yes, which was the bug");

    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    let seams = fixture.seams(&clock, &holders);
    let cancel = Cancel::new();
    let err = fixture
        .acquire(&seams, &cancel, &Fault::none())
        .expect_err("a redirected held-locks directory refuses the hold");

    // An existing variant, and the right one: `Unreachable` is already "the
    // way from the permitted anchor down could not be walked without
    // following a symbolic link". No new error family.
    let LockError::Unreachable { path, message } = &err.error else {
        panic!("expected `Unreachable`, got {err:?}")
    };
    assert_eq!(path, &held_dir, "the refusal names the directory it would not walk");
    assert!(message.contains("symbolic link"), "and why: {message}");

    // Nothing went through the link.
    assert!(
        fs::read_dir(&elsewhere).expect("readable").next().is_none(),
        "no record was written through the link"
    );
    assert!(
        fs::symlink_metadata(&held_dir).expect("still there").file_type().is_symlink(),
        "and the link was neither followed nor replaced by a real directory"
    );

    // And the hold never started: the record is step 3, the three `mkdir`s are
    // step 4, so a refusal here leaves the store exactly as it was.
    assert_eq!(fixture.timeline.ops(), Vec::new(), "not one directory operation was attempted");
    for path in fixture.all() {
        assert!(!path.exists(), "no lock artefact was taken: `{}`", path.display());
    }
}

#[test]
fn a_symlink_at_the_record_file_name_is_refused_by_the_open_itself() {
    // The directory can be honest and the leaf still be a trap: the record
    // name is `<pid>-<monotonic ms>.json`, and the pid is not a secret. The
    // create is `O_EXCL`, so a link there is `EEXIST` rather than a write
    // through it — and the loop moves to the next name rather than failing,
    // which is what it already did for a name that was simply taken.
    let fixture = Fixture::new();
    let elsewhere = fixture.scratch("target.json");
    let held_dir = held_locks::dir(&fixture.paths);
    fs::create_dir_all(&held_dir).expect("the held-locks directory should be creatable");

    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    let seams = fixture.seams(&clock, &holders);
    let cancel = Cancel::new();

    // The name this hold will try first. The fake clock's monotonic reading is
    // frozen until something advances it, so this is the same stamp the
    // acquire will compute — the link is on the candidate, not beside it, and
    // the assertions below would be vacuous otherwise.
    let stamp = monotonic_ms(&seams.clock);
    let pid = std::process::id();
    let first = held_dir.join(format!("{pid}-{stamp}.json"));
    std::os::unix::fs::symlink(&elsewhere, &first).expect("the link should be plantable");

    let acquired = fixture.acquire(&seams, &cancel, &Fault::none()).expect("the hold proceeds");
    let AcquireOutcome::Held(hold) = acquired.outcome else { panic!("expected a hold") };

    assert!(!elsewhere.exists(), "nothing was written through the link");
    assert_eq!(
        hold.record_path(),
        held_dir.join(format!("{pid}-{}.json", stamp + 1)),
        "the taken name was skipped and the next one used, which is what proves the \
         first was actually a candidate"
    );
    assert_eq!(fixture.records().len(), 1, "and there is exactly one real record");
    assert!(
        fs::symlink_metadata(&first).expect("still there").file_type().is_symlink(),
        "the planted link is untouched"
    );
}

#[test]
fn a_real_held_locks_directory_behaves_exactly_as_before() {
    // The other half of the claim: the fix refuses a link and changes nothing
    // else. The record lands in the directory, at 0600, under the same
    // `<pid>-<monotonic ms>.json` name, and its bytes are what the reader
    // round-trips — which is what makes `doctor` and `--remove-stale`, who
    // read this file and nothing else, unaffected by the change.
    let fixture = Fixture::new();
    let held_dir = held_locks::dir(&fixture.paths);
    fs::create_dir_all(&held_dir).expect("the held-locks directory should be creatable");

    let clock = fixture.fake_clock();
    let holders = FakeHolders::none_stopped();
    let seams = fixture.seams(&clock, &holders);
    let cancel = Cancel::new();
    let acquired = fixture.acquire(&seams, &cancel, &Fault::none()).expect("an uncontended store");
    let AcquireOutcome::Held(hold) = acquired.outcome else { panic!("expected a hold") };

    let records = fixture.records();
    assert_eq!(records.len(), 1, "one record per live hold");
    let held = &records[0];
    assert_eq!(held.file, hold.record_path());
    assert_eq!(
        held.file.parent(),
        Some(held_dir.as_path()),
        "in the directory, not through anything"
    );
    assert_eq!(mode_of(&held.file), FILE_MODE, "0600, as it always was");

    // The name is still `<pid>-<monotonic ms>.json`.
    let name = held.file.file_name().expect("a file name").to_string_lossy().into_owned();
    let (pid, rest) = name.split_once('-').expect("`<pid>-<stamp>.json`");
    assert_eq!(pid.parse::<u32>().ok(), Some(std::process::id()));
    let stamp = rest.strip_suffix(".json").expect("the `.json` extension");
    assert!(stamp.parse::<u64>().is_ok(), "a monotonic millisecond count: {stamp}");

    // The bytes are exactly what serializing the parsed record produces, so
    // nothing about the encoding moved: no pretty printing, no trailing
    // newline, no reordered or renamed field.
    let bytes = fs::read(&held.file).expect("the record should be readable");
    let round_trip = serde_json::to_string(&held.record).expect("the record serializes");
    assert_eq!(
        String::from_utf8(bytes).expect("the record is UTF-8"),
        round_trip,
        "the record file is byte-for-byte the serialization of the record `doctor` reads"
    );

    drop(hold);
    assert!(fixture.records().is_empty(), "and the record is cleared on release");
    assert!(held_dir.is_dir(), "while the directory itself stays");
}
