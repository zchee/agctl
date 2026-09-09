//! Claude Code's lock protocol, implemented as a **peer** rather than
//! imitated (plan section 3.8, decisions D-013/D-022, invariants I3′/I11′/I17).
//!
//! # Nothing here has a caller yet
//!
//! W2 lands this module and the keychain writer with **no** call site: a swap
//! (W4a/W4b) is what wires them together. That is deliberate — it is the one
//! module in the crate that removes a directory it did not create, so it gets
//! its own step and its own security review before anything can reach it.
//!
//! # The shape of a hold, and why it is that shape
//!
//! `proper-lockfile` — the library Claude Code uses — makes a lock by
//! `mkdir` and releases it by `rmdir`, heartbeating the directory's
//! modification time every [`PEER_HEARTBEAT`] and treating a lock older than
//! its `stale` window as abandoned (fact F45). A credential-store hold is
//! **three** such directories, in the peer's own nesting (facts F46, F58):
//! the primary refresh lock inside the store directory, the legacy lock
//! beside its *resolved* spelling, and `.storage-write` innermost.
//!
//! Two properties make holding three of a peer's locks survivable, and both
//! are structural rather than hoped for:
//!
//! - **All staleness is resolved before the first successful `mkdir`.** The
//!   break rule takes 12 seconds; F53 says the peer gives up on its refresh
//!   after 4 000 ms. A sampling wait inside a hold is therefore not a slow
//!   path but a guaranteed failure for the peer, so an `EEXIST` at any of the
//!   three positions releases everything already held and restarts from the
//!   lock-free probe instead of waiting (architect N-1).
//! - **`.storage-write` is taken with one non-blocking `mkdir`.** Fact F47's
//!   own retry ladder is a ten-step, ~7.5 s affair; importing it into the hold
//!   would blow the budget on its own. One attempt, `retries: 0`, and a
//!   restart on failure.
//!
//! [`HOLD_BUDGET`] is **derived** from F53's give-up floor rather than
//! chosen: 4 000 ms minus 1 000 ms of margin. Section 3.4 itemises where
//! every millisecond of it goes.
//!
//! # Why breaking a lock is survivable at all
//!
//! Not because a late holder gives up on its own — it does not. A holder
//! whose `stat` succeeds with an unchanged modification time keeps believing
//! it holds the lock however late it is. The real argument is fact **F54**:
//! after a break, the holder's next heartbeat sees the modification time has
//! moved, fires `onCompromised`, and the refresh body checks
//! `isCompromised()` *before* its POST — returning `lock_compromised` — and
//! again after it, with the abort signal threaded into the request. The
//! victim stands down rather than racing. Fact **F55** bounds the exposure at
//! one heartbeat, ≤ 5 s, which is why Sample C sits immediately before the
//! `rmdir` with no I/O in between, why the hold is under 3 s, and why the
//! holder check exists at all.
//!
//! That distinction is load-bearing, not stylistic: the false version of the
//! argument would license a tolerance-based modification-time comparison, and
//! the true one forbids it. Every comparison here is exact.

use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;

use serde::Deserialize;
use serde::Serialize;

use crate::config::paths::DIR_MODE;
use crate::config::paths::FILE_MODE;
use crate::config::paths::Paths;
use crate::provider::claude::namespace;
use crate::runtime::cleanup;
use crate::runtime::cleanup::CleanupToken;
use crate::runtime::coordinator::Cancel;
use crate::runtime::coordinator::PassCtx;
use crate::runtime::fault::Fault;
use crate::runtime::proc;
use crate::secret::foreign_activity::REFRESH_LOCK;
use crate::secret::foreign_activity::STORAGE_WRITE_LOCK;

/// The peer's heartbeat period (fact F45's `update`).
///
/// agentctl runs no heartbeat of its own — a 3 000 ms hold can never reach
/// 5 s, so one could only ever be dead code pretending to be a safety net
/// (architect NEW-2). The number still governs [`STALE_SAMPLE_INTERVAL`]'s
/// margin, which is why it stays a named constant.
pub const PEER_HEARTBEAT: Duration = Duration::from_secs(5);

/// The legacy lock's suffix: `<realpath(store dir)>.lock`, beside the
/// directory rather than inside it (fact F17/F46).
///
/// `commands::doctor` spells the same suffix for its own reporting; the two
/// are deliberately not shared, because `secret/` does not depend on
/// `commands/`.
pub const LEGACY_LOCK_SUFFIX: &str = ".lock";

/// How many rounds fact F36's contention schedule waits before it decides.
pub const CONTENTION_ROUNDS: u32 = 5;

/// The fixed part of one F36 round.
pub const CONTENTION_ROUND_BASE: Duration = Duration::from_millis(1000);

/// The random part of one F36 round: `1000 + rand·1000` ms.
pub const CONTENTION_ROUND_JITTER: Duration = Duration::from_millis(1000);

/// F36's floor (`z0`): the schedule tops itself up to this before deciding
/// whether a holder is beating.
pub const CONTENTION_FLOOR: Duration = Duration::from_millis(7500);

/// How long the break rule waits between Sample A and Sample B.
///
/// **Must stay greater than 2 × [`PEER_HEARTBEAT`].** 12 s is 2.4 × F45's
/// 5 s, which is the margin that makes a single peer heartbeat landing
/// anywhere in the window fail the modification-time comparison. Never
/// reduce it toward 10 s.
pub const STALE_SAMPLE_INTERVAL: Duration = Duration::from_secs(12);

/// How far the wall clock and the monotonic clock may disagree across the
/// sampling interval before the break is abandoned.
///
/// Catches a step in **either** direction (architect N-3): a backward jump
/// makes the two deltas differ by their sum, and a forward jump inflates both
/// ages and would otherwise pass undiagnosed.
pub const CLOCK_SKEW_TOLERANCE: Duration = Duration::from_secs(1);

/// The longest a credential-store hold may last, from the first `mkdir` to
/// the last `rmdir`.
///
/// **Derived, not chosen:** fact F53 says the peer's scope-expansion helper
/// gives up after 4 000 ms at the floor and throws
/// `OAuthRefreshLockContendedError`, so the budget is 4 000 − 1 000 ms of
/// margin. Section 3.4's table itemises the four terms that must fit inside
/// it: 500 ms of process-spawn allowance, an 800 ms re-read, a 1 200 ms
/// write, and 500 ms for the six directory operations plus the drift check.
pub const HOLD_BUDGET: Duration = Duration::from_millis(3000);

/// The `.claude.json` configuration lock's budget (spike S13, V8; S24 uses
/// it).
///
/// A different derivation from a different peer behaviour: a session inside
/// its first 30 s abandons its own acquire ladder after 1 500 ms and then
/// writes the whole document **unlocked**, which would erase a swap. 1 200 ms
/// leaves 300 ms under that floor.
pub const CONFIG_HOLD_BUDGET: Duration = Duration::from_millis(1200);

/// How many times an `EEXIST` may send [`acquire`] back to the lock-free
/// probe before it reports the store busy.
pub const MAX_RESTARTS: u32 = 3;

/// The directory under `namespace_root()` holding one file per live hold.
pub const HELD_LOCKS_DIR: &str = "held-locks";

/// One lock family's `proper-lockfile` options.
///
/// Two families exist and they do not share options (spike S13, S13-1): the
/// credential-store locks are F46/F47's, and the configuration lock is
/// `proper-lockfile`'s defaults. Keeping them in one type is what stops a
/// caller borrowing the wrong staleness window for the wrong lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockProfile {
    /// How old the peer lets a lock get before treating it as abandoned.
    pub stale: Duration,
    /// The peer's heartbeat period for this family.
    pub update: Duration,
    /// How many times agentctl retries a blocked `mkdir`. Always zero: a
    /// retry is a wait, and a wait belongs outside the hold.
    pub retries: u32,
    /// The longest a hold of this family may last.
    pub hold_budget: Duration,
}

/// The primary and legacy refresh locks (fact F46).
pub const REFRESH_PROFILE: LockProfile = LockProfile {
    stale: Duration::from_secs(60),
    update: PEER_HEARTBEAT,
    retries: 0,
    hold_budget: HOLD_BUDGET,
};

/// `.storage-write` (fact F47), restored to the held set by the corrected
/// F58 and taken with a single non-blocking `mkdir`.
pub const STORAGE_WRITE_PROFILE: LockProfile = LockProfile {
    stale: Duration::from_secs(15),
    update: PEER_HEARTBEAT,
    retries: 0,
    hold_budget: HOLD_BUDGET,
};

/// The `.claude.json` configuration lock (fact F50, spike V8).
pub const CONFIG_PROFILE: LockProfile = LockProfile {
    stale: Duration::from_secs(10),
    update: PEER_HEARTBEAT,
    retries: 0,
    hold_budget: CONFIG_HOLD_BUDGET,
};

/// Which directory tree a hold or a break is in.
///
/// Recorded because invariant I11′'s containment is the plan's largest
/// relaxation: in W4a every removal stays inside `namespace_root()`, and only
/// W4b lets one reach the live `~/.claude`. `doctor` and `--remove-stale`
/// need to be able to tell the two apart without guessing from a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tree {
    /// A store directory agentctl created and owns.
    Agentctl,
    /// The live Claude Code store.
    Live,
}

/// What a live hold writes to disk before it takes anything.
///
/// Fact F45's locks are directories and the kernel releases nothing when a
/// process dies, so this file is the only evidence a crash leaves behind —
/// which is why it is written **before** the first `mkdir` (section 3.4 step
/// 6) and cleared after the last `rmdir`. `doctor` reads it to explain
/// directories nobody can otherwise account for, and `--remove-stale` uses it
/// to justify accepting a path outside `namespace_root()` (section 3.9 row 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldLockRecord {
    /// The agentctl process that took the locks. Named unambiguously and
    /// grouped with the provenance fields, because a bare `pid` beside a
    /// holder-evidence field would read as the *holder's* pid (architect
    /// NEW-10).
    pub agentctl_pid: u32,
    /// Which tree the locks are in.
    pub tree: Tree,
    /// The store directory the hold is about.
    pub store_dir: PathBuf,
    /// Every directory the hold intends to create, in acquisition order.
    pub paths: Vec<PathBuf>,
    /// When the record was written, RFC 3339.
    pub taken_at: String,
}

/// Why a lock could not be taken, held or trusted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LockError {
    /// **Refusal A**: a lock agentctl holds had its modification time moved
    /// under it, so the protocol has already been violated and nothing may be
    /// written.
    #[error("`{0}` was modified while agentctl held it; the lock is compromised")]
    Compromised(PathBuf),
    /// The hold outlived its profile's budget, which would make the peer's
    /// own refresh throw (fact F53).
    #[error("the hold reached {elapsed_ms} ms, past the {budget_ms} ms budget")]
    BudgetExceeded {
        /// How long the hold had lasted when it was noticed.
        elapsed_ms: u64,
        /// The profile's budget.
        budget_ms: u64,
    },
    /// The run was cancelled while waiting.
    #[error("cancelled while acquiring the Claude Code locks")]
    Cancelled,
    /// A filesystem operation failed for a reason that is not contention.
    #[error("{context}: {message}")]
    Io {
        /// What was being attempted.
        context: String,
        /// The underlying failure.
        message: String,
    },
}

// ---------------------------------------------------------------------------
// Seams: the clock, the two directory operations, and the holder evidence
// ---------------------------------------------------------------------------

/// Where time comes from.
///
/// Injectable because the break rule's honesty rests on a 12-second wait and
/// a comparison between two clocks, and a test that could not move either
/// would have to either take 12 s per case or assert something weaker than
/// the rule.
pub trait TimeSource: Send + Sync {
    /// The wall clock, which can step in either direction.
    fn wall(&self) -> SystemTime;
    /// The monotonic clock, which cannot.
    fn monotonic(&self) -> Instant;
    /// Waits `how_long` or until cancellation, and reports whether
    /// cancellation is now set.
    fn sleep(&self, how_long: Duration, cancel: &Cancel) -> bool;
}

/// The real clocks.
struct SystemClock;

impl TimeSource for SystemClock {
    fn wall(&self) -> SystemTime {
        SystemTime::now()
    }

    fn monotonic(&self) -> Instant {
        Instant::now()
    }

    fn sleep(&self, how_long: Duration, cancel: &Cancel) -> bool {
        // Waiting on the cancellation condvar rather than sleeping, so a
        // Ctrl-C during the 12-second sampling window ends it at once instead
        // of twelve seconds later (invariant I17: the wait is cancellable).
        cancel.wait_timeout(how_long)
    }
}

/// Both clocks and the sleeper, as one injectable value.
#[derive(Clone)]
pub struct Clock {
    source: Arc<dyn TimeSource>,
}

impl Clock {
    /// The real clocks.
    pub fn system() -> Self {
        Self { source: Arc::new(SystemClock) }
    }

    /// A clock over any other [`TimeSource`].
    pub fn from_source(source: Arc<dyn TimeSource>) -> Self {
        Self { source }
    }

    /// The wall clock.
    pub fn wall(&self) -> SystemTime {
        self.source.wall()
    }

    /// The monotonic clock.
    pub fn monotonic(&self) -> Instant {
        self.source.monotonic()
    }

    /// Waits, cancellably; `true` means cancellation was requested.
    pub fn sleep(&self, how_long: Duration, cancel: &Cancel) -> bool {
        self.source.sleep(how_long, cancel)
    }
}

impl std::fmt::Debug for Clock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Clock")
    }
}

/// Why a directory operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsError {
    /// `EEXIST` — somebody else holds this lock.
    Exists,
    /// `ENOENT` — it is not there.
    NotFound,
    /// Anything else.
    Other(String),
}

/// The two directory operations a `proper-lockfile` lock is made of.
///
/// A trait, not a pair of functions, for one reason: acceptance criterion
/// AC62 asserts that `.storage-write` is attempted **once** and that no wait
/// happens while anything is held, and both are claims about the *sequence*
/// of operations. A spy that records the sequence can check them; no
/// after-the-fact inspection of the filesystem can.
pub trait LockFs: Send + Sync {
    /// One non-blocking `mkdir` at 0700.
    ///
    /// # Errors
    ///
    /// [`FsError::Exists`] when somebody already holds it.
    fn mkdir(&self, path: &Path) -> Result<(), FsError>;

    /// `rmdir`, which is `unlinkat` with `AT_REMOVEDIR`.
    ///
    /// # Errors
    ///
    /// [`FsError::NotFound`] when it has already gone.
    fn rmdir(&self, path: &Path) -> Result<(), FsError>;
}

/// The real directory operations.
pub struct RealFs;

impl LockFs for RealFs {
    fn mkdir(&self, path: &Path) -> Result<(), FsError> {
        match rustix::fs::mkdir(path, LOCK_DIR_MODE) {
            Ok(()) => Ok(()),
            Err(rustix::io::Errno::EXIST) => Err(FsError::Exists),
            Err(rustix::io::Errno::NOENT) => Err(FsError::NotFound),
            Err(errno) => Err(FsError::Other(errno.to_string())),
        }
    }

    fn rmdir(&self, path: &Path) -> Result<(), FsError> {
        // `AT_REMOVEDIR` is the whole point: `unlink` and `remove_file`
        // cannot remove a directory, which is the defect `agentctl-nz5`
        // records one module over.
        match rustix::fs::unlinkat(rustix::fs::CWD, path, rustix::fs::AtFlags::REMOVEDIR) {
            Ok(()) => Ok(()),
            Err(rustix::io::Errno::NOENT) => Err(FsError::NotFound),
            Err(errno) => Err(FsError::Other(errno.to_string())),
        }
    }
}

/// The mode every lock directory is created with: 0700, spelled the way
/// `file_store` spells 0600, so no numeric conversion is needed.
///
/// A test pins it against [`DIR_MODE`], which is the crate's one spelling of
/// the same number.
const LOCK_DIR_MODE: rustix::fs::Mode = rustix::fs::Mode::RWXU;

/// What the holder check found, and the only vocabulary the audit log uses
/// for it.
///
/// Three values, and **none of them names a process or claims a store was
/// identified** (plan AC80). Attribution to a particular store directory
/// would need another process's environment, and phase 2 reads none — the
/// mechanism was deleted as a class, not bounded, after the review found
/// unrelated plaintext secrets in that output (ruling 4). The rule is
/// therefore coarser and **strictly more conservative**: a stopped `claude`
/// anywhere blocks a break, whether or not it has anything to do with this
/// store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HolderEvidence3 {
    /// A same-user `claude` is stopped. Abandon.
    StoppedClaudePresent,
    /// Every same-user `claude` was readable and none is stopped.
    NoStoppedClaude,
    /// The question could not be answered. **Not** the same as
    /// `NoStoppedClaude`: recording "none found" after failing to look is a
    /// false negative, and a false negative here licenses a break (spike
    /// V12).
    None,
}

/// Whether any same-user `claude` process is stopped.
pub trait HolderEvidence: Send + Sync {
    /// The one question the break rule asks.
    fn stopped_claude_present(&self) -> HolderEvidence3;

    /// The stopped process ids, for section 3.4's `busy` message only.
    ///
    /// **Never audited.** A bare `busy` is a dead end for a user whose
    /// `Ctrl-Z`'d pane is blocking every break, so the terminal names the
    /// pids and disclaims attribution in the same sentence (architect
    /// NEW-9); AC80 governs the audit vocabulary, not the terminal. The
    /// default is empty, so an implementation cannot leak pids by accident.
    fn stopped_pids(&self) -> Vec<u32> {
        Vec::new()
    }
}

/// The real holder check: `runtime::proc`, in-process, no child and no argv
/// (decision D-022).
pub struct ProcHolders;

impl HolderEvidence for ProcHolders {
    fn stopped_claude_present(&self) -> HolderEvidence3 {
        match proc::claude_processes() {
            // An unreadable process table, or one process of ours that could
            // not be classified, is "I do not know" — never "none found".
            Err(_) => HolderEvidence3::None,
            Ok(found) if found.iter().any(|(_, state)| *state == proc::Holder::Stopped) => {
                HolderEvidence3::StoppedClaudePresent
            }
            Ok(_) => HolderEvidence3::NoStoppedClaude,
        }
    }

    fn stopped_pids(&self) -> Vec<u32> {
        proc::claude_processes()
            .unwrap_or_default()
            .into_iter()
            .filter(|(_, state)| *state == proc::Holder::Stopped)
            .map(|(pid, _)| pid)
            .collect()
    }
}

/// The production holder check, as a value a `&dyn` can point at for the
/// life of the process.
static PROC_HOLDERS: ProcHolders = ProcHolders;

/// Everything [`acquire`] talks to that a test replaces.
///
/// `fs` is shared rather than borrowed because [`HeldLocks`] releases through
/// it on drop and from the emergency cleanup registry, both of which outlive
/// any borrow the caller could lend.
pub struct Seams<'a> {
    /// The two directory operations.
    pub fs: Arc<dyn LockFs>,
    /// The holder check. Borrowed, and asked its question at the moment the
    /// rule asks it rather than in advance.
    pub holders: &'a dyn HolderEvidence,
    /// Both clocks and the sleeper.
    pub clock: Clock,
}

impl Seams<'static> {
    /// The production seams.
    pub fn real(clock: Clock) -> Self {
        Self { fs: Arc::new(RealFs), holders: &PROC_HOLDERS, clock }
    }
}

// ---------------------------------------------------------------------------
// The audit record for a break (section 3.8)
// ---------------------------------------------------------------------------

/// One modification-time sample.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sample {
    /// When the sample was taken, RFC 3339.
    pub at: String,
    /// The lock directory's modification time, in nanoseconds since the Unix
    /// epoch. Recorded at full resolution because the comparison between
    /// samples is exact and a rounded record could not be used to check it.
    pub mtime_ns: i128,
    /// How old the lock was at that moment.
    pub age_ms: u64,
}

/// Whether a break happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The directory was removed.
    Broken,
    /// It was left alone.
    Abandoned,
}

/// Why, in exactly section 3.8's words.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// A sample differed from the one before it, so something is beating.
    HeartbeatObserved,
    /// The lock was not old enough for its profile.
    TooYoung,
    /// It disappeared between samples. Written to no audit entry: nothing
    /// was there and nothing was done.
    Vanished,
    /// The two clocks disagreed by more than [`CLOCK_SKEW_TOLERANCE`].
    ClockJump,
    /// It was recreated between the `rmdir` and agentctl's own `mkdir`.
    Retaken,
    /// A same-user `claude` is stopped.
    HolderStopped,
}

/// The audit entry for one break attempt (section 3.8's JSON).
///
/// Written **after** the decision, never in the gap between Sample C and the
/// `rmdir`: version 1 of this design appended it there, which is
/// milliseconds a wedged holder can use to resume and heartbeat while still
/// believing it holds the lock. This implementation goes further and
/// performs no I/O in [`resolve_stale`] at all — the record is *returned*, so
/// "after the decision" is true by construction rather than by care.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockBreakRecord {
    /// When the decision was reached, RFC 3339.
    pub ts: String,
    /// Milliseconds on the monotonic clock since this process started.
    pub monotonic_ms: u64,
    /// The agentctl process that decided. Never the holder's pid — see
    /// [`HolderEvidence::stopped_pids`].
    pub agentctl_pid: u32,
    /// Always `lock_break`.
    pub event: String,
    /// The lock directory.
    pub path: PathBuf,
    /// The store directory it belongs to. Filled by [`acquire`], which knows
    /// it; [`resolve_stale`] on its own is given only a lock path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub store_dir: Option<PathBuf>,
    /// Which tree, likewise filled by [`acquire`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tree: Option<Tree>,
    /// The keychain service the swap was for. Filled by the W4a caller.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// `live` or `namespace:<sha8>`. Filled by the W4a caller.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// The first sample.
    pub sample_a: Sample,
    /// The sample [`STALE_SAMPLE_INTERVAL`] later.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_b: Option<Sample>,
    /// The sample taken immediately before the `rmdir`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_c: Option<Sample>,
    /// How much wall-clock time passed between A and B.
    pub interval_wall_ms: u64,
    /// How much monotonic time passed between A and B. The two are compared,
    /// which is what catches a clock step in either direction.
    pub interval_monotonic_ms: u64,
    /// What the holder check found.
    pub holder_evidence: HolderEvidence3,
    /// Whether the directory was removed.
    pub outcome: Outcome,
    /// Why not, when it was not — and `retaken` when it was removed and
    /// immediately taken by somebody else. Absent for a clean break: every
    /// member of the vocabulary is a reason *not* to have broken one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<Reason>,
}

/// What [`resolve_stale`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The directory was removed.
    Broken,
    /// It was left alone, for one of section 3.8's reasons.
    Abandoned(Reason),
    /// The sampling wait was cancelled. Nothing was sampled further and
    /// nothing was removed, so there is nothing to audit.
    Cancelled,
    /// A filesystem operation failed. Nothing was removed.
    Failed(String),
}

/// A break attempt's decision and its audit entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreakOutcome {
    /// What happened.
    pub decision: Decision,
    /// The entry to append, or `None` when there is nothing to record: a
    /// lock that vanished, a cancelled wait, or a failed operation.
    pub record: Option<LockBreakRecord>,
}

// ---------------------------------------------------------------------------
// Acquisition
// ---------------------------------------------------------------------------

/// What [`acquire`] came back with.
#[derive(Debug)]
pub enum AcquireOutcome {
    /// All three directories are held.
    Held(HeldLocks),
    /// Somebody else has one of them.
    Busy {
        /// Whether the primary lock's modification time moved during fact
        /// F36's schedule.
        holder_alive: bool,
        /// The stopped `claude` process ids, for the terminal message only —
        /// never audited (plan AC80, architect NEW-9).
        stopped_pids: Vec<u32>,
    },
}

/// [`acquire`]'s result, with the one break it may have performed.
///
/// The record travels back to the caller instead of being appended here, so
/// that no code between Sample C and the `rmdir` can grow an I/O call. The
/// W4a caller appends it through `secret::audit` (invariant I16).
#[derive(Debug)]
pub struct Acquisition {
    /// Held or busy.
    pub outcome: AcquireOutcome,
    /// The single break this acquire attempted, if any.
    pub break_record: Option<LockBreakRecord>,
}

/// One held directory and the modification time it had when it was created.
#[derive(Debug, Clone)]
struct HeldOne {
    path: PathBuf,
    mtime: Option<SystemTime>,
}

/// A live hold of the three credential-store locks.
///
/// Released in reverse order on drop, along with the held-lock record. A
/// process that dies instead is covered by [`cleanup::register_restore`],
/// which is registered with the same reverse-order `rmdir` — and it has to be
/// `register_restore` rather than `register_tmp_path`, because that one
/// unlinks and cannot remove a directory.
pub struct HeldLocks {
    store_dir: PathBuf,
    tree: Tree,
    held: Vec<HeldOne>,
    record_path: PathBuf,
    first_mkdir: Instant,
    hold_budget: Duration,
    clock: Clock,
    fs: Arc<dyn LockFs>,
    cleanup: Option<CleanupToken>,
    leak: bool,
    released: bool,
}

impl HeldLocks {
    /// The store directory this hold is about.
    pub fn store_dir(&self) -> &Path {
        &self.store_dir
    }

    /// Which tree the hold is in.
    pub fn tree(&self) -> Tree {
        self.tree
    }

    /// The held-lock record's path, so `doctor` and the tests can name it.
    pub fn record_path(&self) -> &Path {
        &self.record_path
    }

    /// The directories held, in acquisition order.
    pub fn paths(&self) -> Vec<PathBuf> {
        self.held.iter().map(|one| one.path.clone()).collect()
    }

    /// How long the hold has lasted, from the first `mkdir`.
    ///
    /// Measured on the same clock that stamped the first `mkdir`, not on
    /// `Instant::now()`: mixing an injected monotonic clock with the real one
    /// would make this the one number a test could not check.
    pub fn hold_elapsed(&self) -> Duration {
        self.clock.monotonic().saturating_duration_since(self.first_mkdir)
    }

    /// Section 3.4 step 8: one `stat` triple immediately before the write.
    ///
    /// Any modification time differing from the value recorded at its
    /// `mkdir` means a third party has touched a lock agentctl holds, which
    /// is **refusal A** — the protocol has been violated and nothing may be
    /// written. The budget is checked in the same place, because this is the
    /// last moment at which abandoning still costs nothing.
    ///
    /// This replaces the 5-second heartbeat thread version 2 ran here. Under
    /// a 3 000 ms hold that thread could never fire, so refusal A was
    /// unreachable in production and only a fake clock ever exercised it
    /// (architect NEW-2). One `stat` triple makes the check real and removes
    /// a thread, a join and a cleanup path from the most dangerous code in
    /// the crate.
    ///
    /// # Errors
    ///
    /// [`LockError::Compromised`] naming the lock that moved, or
    /// [`LockError::BudgetExceeded`].
    pub fn drift_check(&self) -> Result<(), LockError> {
        for one in &self.held {
            if mtime_of(&one.path) != one.mtime {
                return Err(LockError::Compromised(one.path.clone()));
            }
        }

        let elapsed = self.hold_elapsed();
        if elapsed > self.hold_budget {
            return Err(LockError::BudgetExceeded {
                elapsed_ms: millis(elapsed),
                budget_ms: millis(self.hold_budget),
            });
        }
        Ok(())
    }

    /// Releases everything in reverse order and clears the record.
    fn release(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        for one in self.held.iter().rev() {
            let _ = self.fs.rmdir(&one.path);
        }
        let _ = std::fs::remove_file(&self.record_path);
        if let Some(token) = self.cleanup.take() {
            cleanup::unregister(token);
        }
    }
}

impl Drop for HeldLocks {
    fn drop(&mut self) {
        if self.leak {
            // The injected leak (`swap_lock_leak`): the directories and the
            // record are left exactly as a crashed hold would leave them, so
            // a test can prove that `doctor` and `--remove-stale` can still
            // name and clear them.
            return;
        }
        self.release();
    }
}

impl std::fmt::Debug for HeldLocks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeldLocks")
            .field("store_dir", &self.store_dir)
            .field("tree", &self.tree)
            .field("paths", &self.paths())
            .field("record", &self.record_path)
            .finish()
    }
}

/// One of the three locks a credential-store hold is made of.
struct LockPlan {
    path: PathBuf,
    profile: LockProfile,
}

/// The three directories, in the peer's own nesting.
///
/// Primary first, then the legacy lock beside the **resolved** spelling of
/// the store directory, then `.storage-write` innermost (facts F46 and the
/// corrected F58). The order is the peer's, not a preference: taking
/// `.storage-write` first would be a genuine ABBA deadlock against a session
/// whose own nesting is refresh body → persist → `.storage-write`.
fn plan(store_dir: &Path) -> [LockPlan; 3] {
    // The legacy lock is named after the resolved directory (fact F17), and
    // on macOS the resolved and lexical spellings differ in the common case
    // rather than the exotic one — `$TMPDIR` lives under `/var`, a link to
    // `/private/var`. When the directory cannot be resolved at all there is
    // nothing better than the lexical spelling, and the `mkdir` below will
    // fail honestly if that spelling is wrong.
    let resolved = namespace::canonical(store_dir).unwrap_or_else(|_| store_dir.to_path_buf());
    let mut legacy = resolved.into_os_string();
    legacy.push(LEGACY_LOCK_SUFFIX);

    [
        LockPlan { path: store_dir.join(REFRESH_LOCK), profile: REFRESH_PROFILE },
        LockPlan { path: PathBuf::from(legacy), profile: REFRESH_PROFILE },
        LockPlan { path: store_dir.join(STORAGE_WRITE_LOCK), profile: STORAGE_WRITE_PROFILE },
    ]
}

/// Takes all three credential-store locks, or reports the store busy.
///
/// Phase B step 5 and Phase C steps 6–8, in order:
///
/// 1. **With nothing held**, `stat` all three; for any that exists and is
///    stale by its own profile, run [`resolve_stale`]'s full rule — including
///    its 12-second sampling wait. At most **one** break per acquire, so
///    agentctl cannot loop against a peer that recreates a lock.
/// 2. **With nothing held**, wait out a primary that is present and not
///    stale on fact F36's schedule. If it is released during the schedule the
///    acquisition proceeds; if it is still there, the store is busy.
/// 3. Write the held-lock record **before** the first `mkdir`.
/// 4. `mkdir` the three in the peer's nesting. An `EEXIST` at **any**
///    position releases everything already held, clears the record, and
///    returns to step 1 — never a wait, never a sampling window, while
///    holding anything (architect N-1). At most [`MAX_RESTARTS`] restarts.
///
/// # Errors
///
/// [`LockError::Cancelled`] when the run is cancelled, and
/// [`LockError::Io`] when a directory operation fails for a reason that is
/// not contention.
pub fn acquire(
    store_dir: &Path,
    tree: Tree,
    paths: &Paths,
    clock: &Clock,
    ctx: &PassCtx,
    fault: &Fault,
) -> Result<Acquisition, LockError> {
    let seams = Seams::real(clock.clone());
    acquire_with(store_dir, tree, paths, ctx, fault, &seams)
}

/// [`acquire`] over injected seams.
///
/// # Errors
///
/// See [`acquire`].
pub fn acquire_with(
    store_dir: &Path,
    tree: Tree,
    paths: &Paths,
    ctx: &PassCtx,
    fault: &Fault,
    seams: &Seams<'_>,
) -> Result<Acquisition, LockError> {
    let plans = plan(store_dir);
    let mut break_record: Option<LockBreakRecord> = None;
    let mut broken_path: Option<PathBuf> = None;
    let mut restarts = 0_u32;

    loop {
        if ctx.cancel().is_cancelled() {
            return Err(LockError::Cancelled);
        }

        // --- Step 1: resolve staleness, holding nothing -------------------
        for lock in &plans {
            let Some(mtime) = mtime_of(&lock.path) else { continue };
            let age = age_of(&seams.clock, mtime);
            if age < lock.profile.stale && !fault.is("lock_stale") {
                continue;
            }
            if break_record.is_some() {
                // One break per acquire. A second stale lock is reported
                // busy rather than broken.
                return Ok(busy(false, Vec::new(), break_record));
            }

            let outcome = resolve_stale_with(&lock.path, &lock.profile, ctx, fault, seams);
            let mut record = outcome.record;
            if let Some(entry) = record.as_mut() {
                entry.store_dir = Some(store_dir.to_path_buf());
                entry.tree = Some(tree);
            }
            break_record = record;

            match outcome.decision {
                // Gone, either way: carry on to the mkdirs.
                Decision::Broken => broken_path = Some(lock.path.clone()),
                Decision::Abandoned(Reason::Vanished) => {}
                Decision::Abandoned(Reason::HolderStopped) => {
                    return Ok(busy(false, seams.holders.stopped_pids(), break_record));
                }
                // Something is beating, or the clocks disagree. Fall through
                // to F36's schedule, which is what decides `holder_alive`.
                Decision::Abandoned(_) => break,
                Decision::Cancelled => return Err(LockError::Cancelled),
                Decision::Failed(message) => {
                    return Err(LockError::Io {
                        context: format!("could not resolve `{}`", lock.path.display()),
                        message,
                    });
                }
            }
        }

        // --- Step 2: wait out a live primary, holding nothing -------------
        let primary = &plans[0];

        // A lock that was broken and is already back is section 3.8's
        // `retaken`, and it ends the acquire: at most one break, so there is
        // no second one to attempt, and waiting out the new holder would be
        // waiting out a lock agentctl itself just freed.
        if let Some(broken) = broken_path.as_deref()
            && mtime_of(broken).is_some()
        {
            if let Some(entry) = break_record.as_mut() {
                entry.reason = Some(Reason::Retaken);
            }
            return Ok(busy(true, Vec::new(), break_record));
        }

        if let Some(mtime) = mtime_of(&primary.path) {
            match contention_wait(&primary.path, mtime, ctx, seams) {
                Contention::Released => {}
                Contention::StillHeld { holder_alive } => {
                    return Ok(busy(holder_alive, Vec::new(), break_record));
                }
                Contention::Cancelled => return Err(LockError::Cancelled),
            }
        }

        // --- Step 3: the record, before the first mkdir -------------------
        let record_path = write_held_record(paths, store_dir, tree, &plans, &seams.clock)?;

        // --- Step 4: mkdir ×3 in the peer's nesting -----------------------
        //
        // The hold is timed from **here**, before the first `mkdir`, not
        // from after the third: the peer's give-up floor starts running the
        // moment the primary exists, so measuring from the end would
        // understate exactly the term the budget is derived from.
        let first_mkdir = seams.clock.monotonic();
        match take_all(&plans, seams, fault) {
            Ok(held) => {
                let hold = HeldLocks {
                    store_dir: store_dir.to_path_buf(),
                    tree,
                    held,
                    record_path,
                    first_mkdir,
                    hold_budget: primary.profile.hold_budget,
                    clock: seams.clock.clone(),
                    fs: Arc::clone(&seams.fs),
                    cleanup: None,
                    leak: fault.is("swap_lock_leak"),
                    released: false,
                };
                let hold = register_emergency_release(hold);
                return Ok(Acquisition { outcome: AcquireOutcome::Held(hold), break_record });
            }
            Err(TakeFailure::Exists { path, held }) => {
                release_all(&held, seams);
                let _ = std::fs::remove_file(&record_path);

                // A lock recreated between our own `rmdir` and our own
                // `mkdir` is the one case section 3.8 calls `retaken`, and it
                // ends the acquire: at most one break, so there is no second
                // one to attempt.
                if broken_path.as_deref() == Some(path.as_path())
                    && let Some(entry) = break_record.as_mut()
                {
                    entry.reason = Some(Reason::Retaken);
                    return Ok(busy(true, Vec::new(), break_record));
                }

                restarts = restarts.saturating_add(1);
                if restarts > MAX_RESTARTS {
                    return Ok(busy(false, Vec::new(), break_record));
                }
            }
            Err(TakeFailure::Io { path, held, message }) => {
                release_all(&held, seams);
                let _ = std::fs::remove_file(&record_path);
                return Err(LockError::Io {
                    context: format!("could not create `{}`", path.display()),
                    message,
                });
            }
        }
    }
}

/// Wraps a busy answer.
fn busy(
    holder_alive: bool,
    stopped_pids: Vec<u32>,
    break_record: Option<LockBreakRecord>,
) -> Acquisition {
    Acquisition { outcome: AcquireOutcome::Busy { holder_alive, stopped_pids }, break_record }
}

/// Why the three `mkdir`s did not all succeed.
enum TakeFailure {
    /// Somebody holds `path`; `held` is what was taken before that.
    Exists { path: PathBuf, held: Vec<HeldOne> },
    /// `path` could not be created at all.
    Io { path: PathBuf, held: Vec<HeldOne>, message: String },
}

/// `mkdir`s the three in order, recording each one's modification time.
///
/// Every attempt is a single non-blocking `mkdir` — including
/// `.storage-write`, whose profile carries `retries: 0` precisely so that
/// none of fact F47's ten-step ladder enters the hold.
fn take_all(
    plans: &[LockPlan; 3],
    seams: &Seams,
    fault: &Fault,
) -> Result<Vec<HeldOne>, TakeFailure> {
    let mut held: Vec<HeldOne> = Vec::with_capacity(plans.len());
    for (position, lock) in plans.iter().enumerate() {
        let contended = position == 0 && fault.is("lock_contended");
        let result = if contended { Err(FsError::Exists) } else { seams.fs.mkdir(&lock.path) };
        match result {
            Ok(()) => held.push(HeldOne { path: lock.path.clone(), mtime: mtime_of(&lock.path) }),
            Err(FsError::Exists) => {
                return Err(TakeFailure::Exists { path: lock.path.clone(), held });
            }
            Err(FsError::NotFound) => {
                return Err(TakeFailure::Io {
                    path: lock.path.clone(),
                    held,
                    message: "the parent directory is not there".to_owned(),
                });
            }
            Err(FsError::Other(message)) => {
                return Err(TakeFailure::Io { path: lock.path.clone(), held, message });
            }
        }
    }
    Ok(held)
}

/// Releases what was taken, in reverse order.
fn release_all(held: &[HeldOne], seams: &Seams<'_>) {
    for one in held.iter().rev() {
        let _ = seams.fs.rmdir(&one.path);
    }
}

/// Registers the reverse-order release with the emergency cleanup registry.
///
/// The registry is what runs on SIGTERM, SIGHUP and SIGINT, and what a panic
/// hook runs; `Drop` covers everything else. It has to be
/// [`cleanup::register_restore`] and not `register_tmp_path`, because that
/// one unlinks and a lock is a **directory**.
fn register_emergency_release(mut hold: HeldLocks) -> HeldLocks {
    let paths: Vec<PathBuf> = hold.held.iter().rev().map(|one| one.path.clone()).collect();
    let record = hold.record_path.clone();
    let fs = Arc::clone(&hold.fs);
    hold.cleanup = Some(cleanup::register_restore(Box::new(move || {
        for path in paths {
            let _ = fs.rmdir(&path);
        }
        let _ = std::fs::remove_file(&record);
    })));
    hold
}

/// What fact F36's schedule concluded about a primary lock somebody holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Contention {
    /// It went away; the acquisition may proceed.
    Released,
    /// It is still there.
    StillHeld {
        /// Whether its modification time moved, which is the peer's own
        /// definition of a live holder.
        holder_alive: bool,
    },
    /// The wait was cancelled.
    Cancelled,
}

/// Waits on fact F36's own schedule, holding nothing.
///
/// Reproduced rather than invented: five rounds of `1000 + rand·1000` ms, a
/// second sample, and — if less than [`CONTENTION_FLOOR`] has passed — a
/// top-up to that floor and one more sample. `holder_alive` is "the
/// modification time moved", which is exactly how a Claude Code session
/// decides the same question.
///
/// A lock that disappears at any sample ends the wait immediately: that is
/// the case where a live session releases the lock and the swap should carry
/// on (plan AC68), not report a refusal.
fn contention_wait(path: &Path, first: SystemTime, ctx: &PassCtx, seams: &Seams<'_>) -> Contention {
    let mut waited = Duration::ZERO;
    for _ in 0..CONTENTION_ROUNDS {
        let nap = CONTENTION_ROUND_BASE.saturating_add(round_jitter());
        if seams.clock.sleep(nap, ctx.cancel()) {
            return Contention::Cancelled;
        }
        waited = waited.saturating_add(nap);
        if mtime_of(path).is_none() {
            return Contention::Released;
        }
    }

    let Some(second) = mtime_of(path) else { return Contention::Released };
    if second != first {
        return Contention::StillHeld { holder_alive: true };
    }
    if waited >= CONTENTION_FLOOR {
        return Contention::StillHeld { holder_alive: false };
    }

    let top_up = CONTENTION_FLOOR.saturating_sub(waited);
    if seams.clock.sleep(top_up, ctx.cancel()) {
        return Contention::Cancelled;
    }
    match mtime_of(path) {
        None => Contention::Released,
        Some(third) => Contention::StillHeld { holder_alive: third != first },
    }
}

/// The random half of one F36 round.
fn round_jitter() -> Duration {
    let span = u64::try_from(CONTENTION_ROUND_JITTER.as_millis()).unwrap_or(1000);
    Duration::from_millis(u64::from(rand::random::<u32>()) % span.max(1))
}

// ---------------------------------------------------------------------------
// The break rule (section 3.8)
// ---------------------------------------------------------------------------

/// Decides whether one lock directory may be removed, and removes it.
///
/// The only code in the crate that removes a directory it did not create, so
/// the predicate is written out rather than left to a reader. **It runs only
/// with nothing held** (architect N-1). All conditions must hold in order and
/// any failure abandons the break:
///
/// 1. `stat` succeeds — **Sample A** — and the lock is at least
///    `profile.stale` old.
/// 2. **Holder evidence**: any same-user `claude` in a stopped state
///    abandons the break. Evidence that could not be gathered is
///    [`HolderEvidence3::None`] and the rule continues on modification times
///    alone; it is never `no_stopped_claude` (spike V12).
/// 3. Wait [`STALE_SAMPLE_INTERVAL`], cancellably.
/// 4. **Sample B**: `stat` succeeds and the modification time equals A's
///    **exactly** — nanoseconds, never a tolerance.
/// 5. The lock is still at least `profile.stale` old, **and** the wall and
///    monotonic clocks agree to within [`CLOCK_SKEW_TOLERANCE`].
/// 6. **Sample C**, immediately before the `rmdir`, with no I/O of any kind
///    in between — no audit append, no log line, no allocation that can
///    block.
///
/// Then `rmdir`. Whether the lock is recreated afterwards is
/// [`acquire`]'s business, because it is the one that goes on to `mkdir`; a
/// recreation there is `retaken` and ends the acquire.
///
/// **Known and accepted:** a heartbeat landing just after Sample C is
/// unobservable to any sampling rule. The window is two syscalls wide and is
/// the residual risk R36 accepts.
pub fn resolve_stale(
    lock_path: &Path,
    profile: &LockProfile,
    clock: &Clock,
    holders: &dyn HolderEvidence,
    ctx: &PassCtx,
) -> BreakOutcome {
    let seams = Seams { fs: Arc::new(RealFs), holders, clock: clock.clone() };
    resolve_stale_with(lock_path, profile, ctx, &Fault::none(), &seams)
}

/// [`resolve_stale`] over injected seams.
pub fn resolve_stale_with(
    lock_path: &Path,
    profile: &LockProfile,
    ctx: &PassCtx,
    fault: &Fault,
    seams: &Seams<'_>,
) -> BreakOutcome {
    let clock = &seams.clock;

    // --- Sample A -------------------------------------------------------
    let wall_a = clock.wall();
    let mono_a = clock.monotonic();
    let Some(mtime_a) = mtime_of(lock_path) else { return vanished() };
    let age_a = elapsed(wall_a, mtime_a);
    let sample_a = sample(wall_a, mtime_a, age_a);

    let mut record = LockBreakRecord {
        ts: rfc3339(wall_a),
        monotonic_ms: monotonic_ms(clock),
        agentctl_pid: std::process::id(),
        event: "lock_break".to_owned(),
        path: lock_path.to_path_buf(),
        store_dir: None,
        tree: None,
        service: None,
        target: None,
        sample_a,
        sample_b: None,
        sample_c: None,
        interval_wall_ms: 0,
        interval_monotonic_ms: 0,
        holder_evidence: HolderEvidence3::None,
        outcome: Outcome::Abandoned,
        reason: None,
    };

    if age_a < profile.stale {
        return abandoned(record, Reason::TooYoung, clock);
    }

    // --- Holder evidence ------------------------------------------------
    record.holder_evidence = seams.holders.stopped_claude_present();
    if record.holder_evidence == HolderEvidence3::StoppedClaudePresent {
        return abandoned(record, Reason::HolderStopped, clock);
    }

    // --- The sampling wait ----------------------------------------------
    if clock.sleep(STALE_SAMPLE_INTERVAL, ctx.cancel()) {
        return BreakOutcome { decision: Decision::Cancelled, record: None };
    }

    // --- Sample B -------------------------------------------------------
    let wall_b = clock.wall();
    let mono_b = clock.monotonic();
    let Some(mtime_b) = mtime_of(lock_path) else { return vanished() };
    let age_b = elapsed(wall_b, mtime_b);
    record.sample_b = Some(sample(wall_b, mtime_b, age_b));

    let (wall_delta, forward) = signed_delta(wall_a, wall_b);
    let mono_delta = mono_b.saturating_duration_since(mono_a);
    record.interval_wall_ms = millis(wall_delta);
    record.interval_monotonic_ms = millis(mono_delta);

    if mtime_b != mtime_a {
        return abandoned(record, Reason::HeartbeatObserved, clock);
    }
    // The clock check comes **before** the age check, and the order is the
    // finding rather than a preference: a wall clock that has stepped
    // backwards makes the second age *smaller*, so an age test placed first
    // would report `too_young` for what is really a clock jump — the wrong
    // diagnosis, and one that hides the condition architect N-3 added.
    if clock_skew(wall_delta, forward, mono_delta) > CLOCK_SKEW_TOLERANCE {
        return abandoned(record, Reason::ClockJump, clock);
    }
    if age_b < profile.stale {
        return abandoned(record, Reason::TooYoung, clock);
    }

    // The injected resume: a holder that was wedged and comes back in
    // exactly the window Sample C exists to close.
    if fault.is("lock_resume_after_sample_b") {
        touch(lock_path);
    }

    // --- Sample C, then the rmdir, with nothing in between --------------
    let wall_c = clock.wall();
    let Some(mtime_c) = mtime_of(lock_path) else { return vanished() };
    if mtime_c != mtime_b {
        record.sample_c = Some(sample(wall_c, mtime_c, elapsed(wall_c, mtime_c)));
        return abandoned(record, Reason::HeartbeatObserved, clock);
    }
    let removal = seams.fs.rmdir(lock_path);

    // Everything below is after the decision. Nothing above allocates, logs
    // or appends between Sample C and the `rmdir`.
    record.sample_c = Some(sample(wall_c, mtime_c, elapsed(wall_c, mtime_c)));
    match removal {
        Ok(()) => {
            record.ts = rfc3339(clock.wall());
            record.outcome = Outcome::Broken;
            record.reason = None;
            tracing::info!(
                path = %lock_path.display(),
                holder_evidence = ?record.holder_evidence,
                "removed a stale Claude Code lock"
            );
            BreakOutcome { decision: Decision::Broken, record: Some(record) }
        }
        Err(FsError::NotFound) => vanished(),
        Err(FsError::Exists) => BreakOutcome {
            decision: Decision::Failed(
                "the lock path is not an empty directory; refusing to remove it".to_owned(),
            ),
            record: None,
        },
        Err(FsError::Other(message)) => {
            BreakOutcome { decision: Decision::Failed(message), record: None }
        }
    }
}

/// The lock disappeared: nothing was there and nothing was done, so section
/// 3.8 writes no audit entry.
fn vanished() -> BreakOutcome {
    BreakOutcome { decision: Decision::Abandoned(Reason::Vanished), record: None }
}

/// Stamps an abandoned decision onto the record.
fn abandoned(mut record: LockBreakRecord, reason: Reason, clock: &Clock) -> BreakOutcome {
    record.ts = rfc3339(clock.wall());
    record.outcome = Outcome::Abandoned;
    record.reason = Some(reason);
    BreakOutcome { decision: Decision::Abandoned(reason), record: Some(record) }
}

/// How far apart the two clocks' views of the interval are.
///
/// A **backward** wall-clock step makes the distance the sum of the two
/// deltas rather than their difference, which is why the direction is carried
/// rather than the magnitude alone.
fn clock_skew(wall_delta: Duration, forward: bool, mono_delta: Duration) -> Duration {
    if !forward {
        return wall_delta.saturating_add(mono_delta);
    }
    if wall_delta > mono_delta {
        wall_delta.saturating_sub(mono_delta)
    } else {
        mono_delta.saturating_sub(wall_delta)
    }
}

/// The wall-clock interval and whether it ran forwards.
fn signed_delta(from: SystemTime, to: SystemTime) -> (Duration, bool) {
    match to.duration_since(from) {
        Ok(delta) => (delta, true),
        Err(err) => (err.duration(), false),
    }
}

// ---------------------------------------------------------------------------
// The held-lock record
// ---------------------------------------------------------------------------

/// How many names are tried before giving up on a unique record file.
const RECORD_NAME_ATTEMPTS: u32 = 8;

/// Writes the held-lock record, before anything is taken.
fn write_held_record(
    paths: &Paths,
    store_dir: &Path,
    tree: Tree,
    plans: &[LockPlan; 3],
    clock: &Clock,
) -> Result<PathBuf, LockError> {
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::fs::OpenOptionsExt;

    let dir = paths.namespace_root().join(HELD_LOCKS_DIR);
    if !dir.is_dir() {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(DIR_MODE);
        builder.create(&dir).map_err(|err| LockError::Io {
            context: format!("could not create `{}`", dir.display()),
            message: err.to_string(),
        })?;
    }

    let record = HeldLockRecord {
        agentctl_pid: std::process::id(),
        tree,
        store_dir: store_dir.to_path_buf(),
        paths: plans.iter().map(|lock| lock.path.clone()).collect(),
        taken_at: rfc3339(clock.wall()),
    };
    let json = serde_json::to_string(&record).map_err(|err| LockError::Io {
        context: "could not serialize the held-lock record".to_owned(),
        message: err.to_string(),
    })?;

    let pid = record.agentctl_pid;
    let base = monotonic_ms(clock);
    for attempt in 0..RECORD_NAME_ATTEMPTS {
        let stamp = base.saturating_add(u64::from(attempt));
        let path = dir.join(format!("{pid}-{stamp}.json"));
        match std::fs::OpenOptions::new().write(true).create_new(true).mode(FILE_MODE).open(&path) {
            Ok(mut file) => {
                return match std::io::Write::write_all(&mut file, json.as_bytes()) {
                    Ok(()) => Ok(path),
                    Err(err) => Err(LockError::Io {
                        context: format!("could not write `{}`", path.display()),
                        message: err.to_string(),
                    }),
                };
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(err) => {
                return Err(LockError::Io {
                    context: format!("could not create `{}`", path.display()),
                    message: err.to_string(),
                });
            }
        }
    }

    Err(LockError::Io {
        context: format!("could not name a held-lock record under `{}`", dir.display()),
        message: "every candidate name was taken".to_owned(),
    })
}

/// Reads a held-lock record, if it has a readable one.
///
/// `None` for every failure: an unreadable or half-written record means the
/// writer crashed, which is exactly the state it exists to describe and not a
/// reason to fail a `doctor` run.
pub fn read_held_record(path: &Path) -> Option<HeldLockRecord> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() > 64 * 1024 {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

/// Every held-lock record this store knows about.
pub fn held_records(paths: &Paths) -> Vec<(PathBuf, HeldLockRecord)> {
    let dir = paths.namespace_root().join(HELD_LOCKS_DIR);
    let Ok(entries) = std::fs::read_dir(&dir) else { return Vec::new() };
    let mut out: Vec<(PathBuf, HeldLockRecord)> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter_map(|path| read_held_record(&path).map(|record| (path, record)))
        .collect();
    out.sort_by(|left, right| left.0.cmp(&right.0));
    out
}

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------

/// When this process started, for the monotonic milliseconds in a record.
static PROCESS_START: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Milliseconds on the monotonic clock since this process started.
fn monotonic_ms(clock: &Clock) -> u64 {
    millis(clock.monotonic().saturating_duration_since(*PROCESS_START))
}

/// A `Duration` in whole milliseconds, saturating rather than wrapping —
/// overflow checks are compiled out in every profile (constraint C-006).
fn millis(of: Duration) -> u64 {
    u64::try_from(of.as_millis()).unwrap_or(u64::MAX)
}

/// One lock directory's modification time, without following a symbolic
/// link.
///
/// A link where a lock directory should be is somebody else's plant, and
/// `symlink_metadata` is what keeps this from reading the target's time
/// instead. Such a path is also unremovable by the break: `rmdir` on a
/// symbolic link fails, which is the safe side of that trade.
fn mtime_of(path: &Path) -> Option<SystemTime> {
    std::fs::symlink_metadata(path).ok()?.modified().ok()
}

/// How long ago `mtime` was, saturating at zero for a clock that has gone
/// backwards.
fn elapsed(now: SystemTime, mtime: SystemTime) -> Duration {
    now.duration_since(mtime).unwrap_or_default()
}

/// How old a lock is, by the injected clock.
fn age_of(clock: &Clock, mtime: SystemTime) -> Duration {
    elapsed(clock.wall(), mtime)
}

/// Builds one audit sample.
fn sample(at: SystemTime, mtime: SystemTime, age: Duration) -> Sample {
    Sample { at: rfc3339(at), mtime_ns: nanos_since_epoch(mtime), age_ms: millis(age) }
}

/// A `SystemTime` as nanoseconds since the Unix epoch, negative before it.
fn nanos_since_epoch(at: SystemTime) -> i128 {
    match at.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(since) => i128::try_from(since.as_nanos()).unwrap_or(i128::MAX),
        Err(before) => {
            i128::try_from(before.duration().as_nanos()).map_or(i128::MIN, |nanos| -nanos)
        }
    }
}

/// A `SystemTime` as RFC 3339, or the epoch when it cannot be represented.
///
/// Stored as a string rather than a `jiff::Timestamp` to match the lock body
/// and the account registry, which do the same and keep `jiff`'s optional
/// serde support out of the manifest.
fn rfc3339(at: SystemTime) -> String {
    let micros = match at.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(since) => i64::try_from(since.as_micros()).unwrap_or(i64::MAX),
        Err(before) => {
            i64::try_from(before.duration().as_micros()).map_or(i64::MIN, |micros| -micros)
        }
    };
    jiff::Timestamp::from_microsecond(micros).unwrap_or(jiff::Timestamp::UNIX_EPOCH).to_string()
}

/// Sets a lock's modification time to now, for the injected-resume fault.
fn touch(path: &Path) {
    let now =
        rustix::fs::Timestamps { last_access: now_timespec(), last_modification: now_timespec() };
    let _ =
        rustix::fs::utimensat(rustix::fs::CWD, path, &now, rustix::fs::AtFlags::SYMLINK_NOFOLLOW);
}

/// The current time as a `Timespec`.
fn now_timespec() -> rustix::fs::Timespec {
    let since = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    rustix::fs::Timespec {
        tv_sec: i64::try_from(since.as_secs()).unwrap_or(i64::MAX),
        tv_nsec: i64::from(since.subsec_nanos()),
    }
}

#[cfg(test)]
#[path = "claude_lock_tests.rs"]
mod tests;
