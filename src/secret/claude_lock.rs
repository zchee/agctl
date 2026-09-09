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
//!
//! # Why the hold is addressed by descriptor and not by path
//!
//! Every operation this module performs — `mkdir`, `stat`, `rmdir` — is
//! relative to a directory descriptor obtained by **one** `O_NOFOLLOW`
//! component walk per acquire ([`LockAnchor`]), and never to a path resolved
//! afresh from the root.
//!
//! A path-based hold is redirectable, and the redirection defeats every check
//! around it. A same-user attacker who can create one symbolic link under
//! `<config dir>/claude` — the threat class `file_store`'s walk and
//! `doctor --remove-stale` were both written for — plants `<acct>` as a link to
//! `~/.claude`. Then `mkdir("<root>/<acct>/<org>/.oauth_refresh.lock")` creates
//! Claude Code's **live** lock, `rmdir` removes one, and the lexical
//! containment check that invariant I11′ rests on still says the path is inside
//! `namespace_root()`, because as a *spelling* it is. The held-lock record and
//! the audit entry would both say `tree: agentctl` while the break landed in
//! the live store — simultaneously "break a live lock" and "escape the root".
//!
//! A descriptor closes it in both directions: the walk refuses the link before
//! anything is created, and the `rmdir` that gives a lock back lands in the
//! same inode the `mkdir` took it in, so no rename between them can move it.
//! The same walk is what makes [`Tree`] a derived fact rather than a caller's
//! claim, because the anchor it starts from is chosen by the tree and a store
//! that is not below that anchor cannot be reached from it at all.

use std::ffi::OsStr;
use std::ffi::OsString;
use std::os::fd::AsFd;
use std::os::fd::BorrowedFd;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;

use crate::config::paths::Paths;
use crate::provider::claude::namespace;
use crate::provider::claude::namespace::EnvView;
use crate::runtime::cleanup;
use crate::runtime::cleanup::CleanupToken;
use crate::runtime::coordinator::Cancel;
use crate::runtime::coordinator::PassCtx;
use crate::runtime::fault::Fault;
use crate::runtime::proc;
use crate::secret::file_store;
use crate::secret::foreign_activity::REFRESH_LOCK;
use crate::secret::foreign_activity::STORAGE_WRITE_LOCK;
use crate::secret::held_locks;

/// The words this module records a break in, and the record it writes.
///
/// Re-exported from [`crate::secret::audit`] rather than declared here, because
/// the record is appended to the audit log and a second declaration of the same
/// fields would duplicate the log's provenance members. The aliases
/// keep the names the break rule reads best — `Sample`, `Outcome`, `Reason` —
/// pointing at the one type each.
pub use crate::secret::audit::BreakOutcome as Outcome;
pub use crate::secret::audit::BreakReason as Reason;
pub use crate::secret::audit::HolderEvidence as HolderEvidence3;
pub use crate::secret::audit::LockBreakRecord;
pub use crate::secret::audit::LockSample as Sample;
pub use crate::secret::audit::Target;
pub use crate::secret::audit::Tree;
pub use crate::secret::held_locks::HeldLockRecord;

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

/// What one hold is about: the store directory, and which tree it is in.
///
/// The two travel together because the tree is **checked** against the store
/// directory rather than believed (see [`LockAnchor::open`]): invariant I11′'s
/// containment is the plan's largest relaxation — in W4a every removal stays
/// inside `namespace_root()`, and only W4b lets one reach the live
/// `~/.claude` — and a `tree` a caller could simply assert would put that
/// containment in the caller's hands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockSubject<'a> {
    /// The credential store directory the locks guard.
    pub store_dir: &'a Path,
    /// Which tree the caller believes it is in.
    pub tree: Tree,
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
    /// **Containment**: the store directory is not in the tree the caller
    /// named, so the hold — and any break inside it — would land somewhere
    /// invariant I11′ does not allow.
    #[error("`{}` is not {}, so agentctl will not lock it as one", .store_dir.display(), .tree.label())]
    WrongTree {
        /// The store directory as the caller spelled it.
        store_dir: PathBuf,
        /// The tree the caller claimed it was in.
        tree: Tree,
    },
    /// The way from the permitted anchor down to the store directory could not
    /// be walked without following a symbolic link, or a component of it is
    /// missing or is not a directory.
    #[error("`{}` cannot be locked: {message}", .path.display())]
    Unreachable {
        /// The directory the walk was heading for.
        path: PathBuf,
        /// What the walk refused, in its own words.
        message: String,
    },
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

/// One lock artefact, addressed the way it is operated on.
///
/// A descriptor and a **name**, never a path, because a path is re-resolved
/// from the root on every syscall and a symbolic link planted anywhere along
/// it redirects the operation. That is not hypothetical: with `<acct>` replaced
/// by a link, `mkdir("<root>/<acct>/<org>/.oauth_refresh.lock")` creates the
/// live store's lock while every lexical check still says the path is inside
/// `namespace_root()`. `dir` is opened once per acquire by an `O_NOFOLLOW`
/// component walk and kept for the life of the hold, so the directory the
/// `rmdir` lands in is the same inode the `mkdir` landed in.
#[derive(Clone, Copy)]
pub struct LockSlot<'a> {
    /// The directory the artefact lives in, opened `O_DIRECTORY | O_NOFOLLOW`.
    pub dir: BorrowedFd<'a>,
    /// The artefact's own name inside `dir`: exactly one component.
    pub name: &'a OsStr,
    /// What the artefact is called in a record or a message. Carried rather
    /// than derived so a test's spy can record a timeline a reader recognises;
    /// **no operation is ever performed on it.**
    pub shown: &'a Path,
}

impl std::fmt::Debug for LockSlot<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockSlot").field("name", &self.name).field("shown", &self.shown).finish()
    }
}

/// The three directory operations a `proper-lockfile` lock is made of, all
/// relative to an already-opened directory.
///
/// A trait, not three functions, for one reason: acceptance criterion AC62
/// asserts that `.storage-write` is attempted **once** and that no wait happens
/// while anything is held, and both are claims about the *sequence* of
/// operations. A spy that records the sequence can check them; no
/// after-the-fact inspection of the filesystem can.
pub trait LockFs: Send + Sync {
    /// One non-blocking `mkdirat` at 0700.
    ///
    /// # Errors
    ///
    /// [`FsError::Exists`] when somebody already holds it.
    fn mkdir(&self, at: LockSlot<'_>) -> Result<(), FsError>;

    /// `rmdir`, which is `unlinkat` with `AT_REMOVEDIR`.
    ///
    /// # Errors
    ///
    /// [`FsError::NotFound`] when it has already gone.
    fn rmdir(&self, at: LockSlot<'_>) -> Result<(), FsError>;

    /// The artefact's modification time, or `None` when it is not there.
    ///
    /// Part of this trait rather than a free function so that **every** read
    /// the protocol makes is relative to the same descriptor as the write: a
    /// path-based `stat` beside descriptor-based `mkdir` and `rmdir` would
    /// leave the sampling — the whole evidence base of the break rule — open to
    /// the redirection the descriptor exists to close.
    fn mtime(&self, at: LockSlot<'_>) -> Option<SystemTime>;
}

/// The real directory operations.
pub struct RealFs;

impl LockFs for RealFs {
    fn mkdir(&self, at: LockSlot<'_>) -> Result<(), FsError> {
        match rustix::fs::mkdirat(at.dir, at.name, LOCK_DIR_MODE) {
            Ok(()) => Ok(()),
            Err(rustix::io::Errno::EXIST) => Err(FsError::Exists),
            Err(rustix::io::Errno::NOENT) => Err(FsError::NotFound),
            Err(errno) => Err(FsError::Other(errno.to_string())),
        }
    }

    fn rmdir(&self, at: LockSlot<'_>) -> Result<(), FsError> {
        // `AT_REMOVEDIR` is the whole point: `unlink` and `remove_file`
        // cannot remove a directory, which is the defect `agentctl-nz5`
        // records one module over. It also refuses anything that is not a
        // directory, so a regular file or a symbolic link at the artefact's
        // name is never removed.
        match rustix::fs::unlinkat(at.dir, at.name, rustix::fs::AtFlags::REMOVEDIR) {
            Ok(()) => Ok(()),
            Err(rustix::io::Errno::NOENT) => Err(FsError::NotFound),
            Err(errno) => Err(FsError::Other(errno.to_string())),
        }
    }

    fn mtime(&self, at: LockSlot<'_>) -> Option<SystemTime> {
        // `AT_SYMLINK_NOFOLLOW`: a link where a lock directory should be is
        // somebody else's plant, and this is what keeps the sampling from
        // reading the target's modification time instead of the link's. Such a
        // path is also unremovable by the break — `AT_REMOVEDIR` refuses a
        // link — which is the safe side of that trade.
        let flags = rustix::fs::AtFlags::SYMLINK_NOFOLLOW;
        let stat = rustix::fs::statat(at.dir, at.name, flags).ok()?;
        modified(&stat)
    }
}

/// A `statat` result's modification time, at full resolution.
///
/// Nanoseconds are load-bearing: the comparison between two samples is exact,
/// and a conversion that rounded would silently grant the tolerance section
/// 3.8 forbids.
fn modified(stat: &rustix::fs::Stat) -> Option<SystemTime> {
    let secs = stat.st_mtime;
    let nanos = u32::try_from(stat.st_mtime_nsec).ok()?;
    let Ok(forward) = u64::try_from(secs) else {
        // Before 1970. The seconds run backwards from the epoch and the
        // nanoseconds still run forwards from there, so the two are applied in
        // opposite directions rather than added.
        let back = u64::try_from(secs.checked_neg()?).ok()?;
        return SystemTime::UNIX_EPOCH
            .checked_sub(Duration::from_secs(back))?
            .checked_add(Duration::from_nanos(u64::from(nanos)));
    };
    SystemTime::UNIX_EPOCH.checked_add(Duration::new(forward, nanos))
}

/// Which of a hold's two directories one artefact lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Which {
    /// Inside the store directory: the primary lock and `.storage-write`.
    Store,
    /// Beside it, in the store directory's parent: the legacy lock.
    Parent,
}

/// One lock artefact's identity: where it lives, what it is called there, and
/// what it is called to a human.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Artefact {
    /// Which of the hold's two directories holds the name.
    dir: Which,
    /// The name inside that directory.
    name: OsString,
    /// The path a record and a message spell.
    path: PathBuf,
}

/// The two directory descriptors every lock of one hold is addressed through.
///
/// Opened by a single `O_NOFOLLOW` component walk from the anchor the *tree*
/// permits — [`Paths::namespace_root`] for [`Tree::Agentctl`], the live store's
/// parent for [`Tree::Live`] — and kept for the life of the hold. Two
/// consequences, and both are the point:
///
/// - a symbolic link anywhere below the anchor is refused **before** the first
///   `mkdir`, so nothing is created in whatever it pointed at;
/// - `tree` stops being a claim and becomes a derived fact, which is what
///   invariant I11′'s containment needs it to be.
pub struct LockAnchor {
    /// The store directory itself.
    store: OwnedFd,
    /// Its parent: the legacy lock is `<store>.lock`, *beside* the store rather
    /// than inside it (fact F17).
    parent: OwnedFd,
    /// The store directory's own name inside `parent` — the spelling the walk
    /// accepted, which is what the legacy lock's name is built from.
    store_name: OsString,
    /// The store directory as the caller spelled it, for records and messages.
    store_dir: PathBuf,
    /// Which tree the walk proved it is in.
    tree: Tree,
}

impl LockAnchor {
    /// Opens the two descriptors a hold of `subject` needs, refusing a store
    /// that is not in the tree it claims and a way to it that cannot be walked
    /// without following a symbolic link.
    ///
    /// # Errors
    ///
    /// [`LockError::WrongTree`] when the store directory is neither under
    /// [`Paths::namespace_root`] (for [`Tree::Agentctl`]) nor the live store
    /// itself (for [`Tree::Live`]), and [`LockError::Unreachable`] when the
    /// walk refuses a component or cannot find one.
    pub fn open(subject: LockSubject<'_>, paths: &Paths, env: &EnvView) -> Result<Self, LockError> {
        let store_dir = subject.store_dir;
        let wrong_tree =
            || LockError::WrongTree { store_dir: store_dir.to_path_buf(), tree: subject.tree };

        // The anchor is chosen by the tree, and the walk from it is what makes
        // the choice binding: a store that is not below the anchor cannot be
        // reached from it at all (`strip_prefix` fails inside the walk), and one
        // that is below it is reached one `O_NOFOLLOW` component at a time.
        let anchor = match subject.tree {
            Tree::Agentctl => {
                if !paths.is_under_namespace_root(store_dir) {
                    return Err(wrong_tree());
                }
                paths.namespace_root()
            }
            Tree::Live => {
                // Equality, not containment: `live` means *the* live store, the
                // one this environment names, and nothing else. W4b is the
                // increment that lets a break reach it, and a store that merely
                // sits beside it is not it.
                if store_dir != namespace::live_store_dir(env) {
                    return Err(wrong_tree());
                }
                // The legacy lock is the store's sibling, so the anchor has to
                // be the parent — and the store's own component is still walked
                // `O_NOFOLLOW` below it.
                store_dir.parent().ok_or_else(wrong_tree)?.to_path_buf()
            }
        };

        let store_name = store_dir.file_name().ok_or_else(wrong_tree)?.to_os_string();
        let store = file_store::open_dir_under(&anchor, store_dir).map_err(|err| {
            LockError::Unreachable { path: store_dir.to_path_buf(), message: err.to_string() }
        })?;

        // The parent by descriptor rather than by a second walk: `..` inside an
        // already-opened directory is never a symbolic link, so this reaches
        // the store's real parent — which is also the directory `realpath`
        // would have named, without `realpath`'s willingness to follow a link
        // planted at the store itself.
        let flags = rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC;
        let parent = rustix::fs::openat(&store, "..", flags, rustix::fs::Mode::empty()).map_err(
            |errno| LockError::Unreachable {
                path: store_dir.to_path_buf(),
                message: format!("its parent directory could not be opened: {errno}"),
            },
        )?;

        Ok(Self {
            store,
            parent,
            store_name,
            store_dir: store_dir.to_path_buf(),
            tree: subject.tree,
        })
    }

    /// The store directory this hold is about.
    pub fn store_dir(&self) -> &Path {
        &self.store_dir
    }

    /// Which tree the walk proved the store directory is in.
    pub fn tree(&self) -> Tree {
        self.tree
    }

    /// The slot one artefact of this hold is operated on through.
    fn slot<'a>(&'a self, of: &'a Artefact) -> LockSlot<'a> {
        let dir = match of.dir {
            Which::Store => self.store.as_fd(),
            Which::Parent => self.parent.as_fd(),
        };
        LockSlot { dir, name: &of.name, shown: &of.path }
    }

    /// A slot for one name inside the store directory, for a caller that wants
    /// to run the break rule against a single artefact.
    pub fn in_store<'a>(&'a self, name: &'a OsStr, shown: &'a Path) -> LockSlot<'a> {
        LockSlot { dir: self.store.as_fd(), name, shown }
    }
}

impl std::fmt::Debug for LockAnchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockAnchor")
            .field("store_dir", &self.store_dir)
            .field("tree", &self.tree)
            .finish()
    }
}

/// The mode every lock directory is created with: 0700, spelled the way
/// `file_store` spells 0600, so no numeric conversion is needed.
///
/// A test pins it against [`crate::config::paths::DIR_MODE`], which is the
/// crate's one spelling of the same number.
const LOCK_DIR_MODE: rustix::fs::Mode = rustix::fs::Mode::RWXU;

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
    /// The three directory operations.
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

/// Everything the break rule can observe about one break, waiting for the two
/// fields only its caller knows.
///
/// The record is [`LockBreakRecord`] — one field list, one JSON shape,
/// section 3.8's — and it is deliberately **not** reachable from here as a
/// pile of `Option`s. The rule fills the thirteen members it can see; the swap
/// supplies `service` and `target`, which it alone knows; and
/// [`complete`](BreakDraft::complete) is the only way to get from one to the
/// other, so no field can arrive at the log empty because a caller forgot it.
///
/// The draft is *returned* rather than appended, which is what makes "no I/O
/// between Sample C and the `rmdir`" true by construction: there is no logging
/// call in [`resolve_stale`] to grow one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreakDraft {
    /// The lock directory, as the hold spells it.
    path: PathBuf,
    /// The store directory it guards.
    store_dir: PathBuf,
    /// Which tree that store is in.
    tree: Tree,
    /// The first sample.
    sample_a: Sample,
    /// The sample [`STALE_SAMPLE_INTERVAL`] later, when the rule got that far.
    sample_b: Option<Sample>,
    /// The sample taken immediately before the `rmdir`.
    sample_c: Option<Sample>,
    /// How much wall-clock time passed between A and B.
    interval_wall_ms: u64,
    /// How much monotonic time passed between A and B. The two are compared,
    /// which is what catches a clock step in either direction.
    interval_monotonic_ms: u64,
    /// What the holder check found.
    holder_evidence: HolderEvidence3,
    /// Whether the directory was removed.
    outcome: Outcome,
    /// Why not, when it was not — and `retaken` when it was removed and
    /// immediately taken by somebody else.
    reason: Option<Reason>,
}

impl BreakDraft {
    /// Fills in the swap's own two fields and hands back the record to append.
    ///
    /// `service` is the keychain item the swap is for and `target` says which
    /// item that is; both belong to the caller because the rule is given a lock
    /// artefact and nothing else.
    pub fn complete(self, service: String, target: Target) -> LockBreakRecord {
        LockBreakRecord {
            path: self.path,
            store_dir: self.store_dir,
            tree: self.tree,
            service,
            target,
            sample_a: self.sample_a,
            sample_b: self.sample_b,
            sample_c: self.sample_c,
            interval_wall_ms: self.interval_wall_ms,
            interval_monotonic_ms: self.interval_monotonic_ms,
            holder_evidence: self.holder_evidence,
            outcome: self.outcome,
            reason: self.reason,
        }
    }
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

/// A break attempt's decision and the draft record for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreakAttempt {
    /// What happened.
    pub decision: Decision,
    /// The draft to complete and append, or `None` when there is nothing to
    /// record: a lock that vanished, a cancelled wait, or a failed operation.
    pub record: Option<BreakDraft>,
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
    pub break_record: Option<BreakDraft>,
}

/// [`acquire`]'s failure, carrying the break it may already have performed.
///
/// The break rule `rmdir`s a peer's lock directory at [`Sample`] C and hands
/// back a [`BreakDraft`]; every way out of [`acquire_with`] after that moment
/// owes that draft to the audit log, and six of those ways are `Err`. Before
/// this type they returned a bare [`LockError`], the draft died with the stack
/// frame, and agentctl had removed another process's lock with nothing durable
/// to say so — invariant I16's exact prohibition.
///
/// So the draft is carried rather than dropped, and it is carried in a struct
/// with **no `From<LockError>` conversion**: `?` on a [`LockError`] inside
/// [`acquire_with`] does not compile, so a site added later cannot fall out of
/// the function without naming the draft it is holding.
#[derive(Debug)]
pub struct AcquireFailure {
    /// Why the acquire failed.
    pub error: LockError,
    /// The single break this acquire completed before failing, if any.
    pub break_record: Option<BreakDraft>,
}

impl AcquireFailure {
    /// A failure decided before the break rule could have run at all.
    ///
    /// The only use is [`acquire`]'s anchor walk, which happens before
    /// [`acquire_with`] is entered, so there is no draft in existence to lose.
    /// Deliberately not a [`From`] impl: a conversion usable by `?` is a
    /// conversion a future `?` can use at a site where a draft *does* exist.
    fn before_any_break(error: LockError) -> Self {
        Self { error, break_record: None }
    }
}

/// One held directory and the modification time it had when it was created.
///
/// The modification time is `Option` only because the reading can fail, and
/// [`take_all`] treats that failure as a refusal: a `None` never reaches a
/// [`HeldLocks`], because the only `HeldOne` carrying one is the entry
/// [`take_all`] pushes on its way out through [`TakeFailure::Io`], purely so
/// that the directory it names is released with the rest. [`drift_check`]
/// refuses on a `None` regardless, which is the second of the two guards —
/// the field's type cannot state the invariant, so the check does.
///
/// [`drift_check`]: HeldLocks::drift_check
#[derive(Debug, Clone)]
struct HeldOne {
    artefact: Artefact,
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
    anchor: Arc<LockAnchor>,
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
        self.anchor.store_dir()
    }

    /// Which tree the hold is in.
    pub fn tree(&self) -> Tree {
        self.anchor.tree()
    }

    /// The held-lock record's path, so `doctor` and the tests can name it.
    pub fn record_path(&self) -> &Path {
        &self.record_path
    }

    /// The directories held, in acquisition order.
    pub fn paths(&self) -> Vec<PathBuf> {
        self.held.iter().map(|one| one.artefact.path.clone()).collect()
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
    /// An **unreadable** modification time on either side is refusal A too,
    /// not equality. Comparing the two `Option`s directly made a `None` at
    /// `mkdir` time agree with a `None` now, so the one artefact whose
    /// compromise could least be ruled out was the one this check waved
    /// through. An unreadable reading is not evidence that nothing moved.
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
            let moved = match (one.mtime, self.fs.mtime(self.anchor.slot(&one.artefact))) {
                (Some(recorded), Some(now)) => now != recorded,
                // Either reading missing: refuse. `None == None` is what made
                // this check inert for an artefact whose modification time
                // could not be read at all.
                _ => true,
            };
            if moved {
                return Err(LockError::Compromised(one.artefact.path.clone()));
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
            let _ = self.fs.rmdir(self.anchor.slot(&one.artefact));
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
            .field("store_dir", &self.store_dir())
            .field("tree", &self.tree())
            .field("paths", &self.paths())
            .field("record", &self.record_path)
            .finish()
    }
}

/// One of the three locks a credential-store hold is made of.
struct LockPlan {
    artefact: Artefact,
    profile: LockProfile,
}

/// The three directories, in the peer's own nesting.
///
/// Primary first, then the legacy lock beside the store directory, then
/// `.storage-write` innermost (facts F46 and the corrected F58). The order is
/// the peer's, not a preference: taking `.storage-write` first would be a
/// genuine ABBA deadlock against a session whose own nesting is refresh body →
/// persist → `.storage-write`.
///
/// The legacy lock's name comes from the **opened chain** — the store
/// directory's own component as the `O_NOFOLLOW` walk accepted it, placed in
/// the parent that walk reached — and not from `realpath`. Fact F17 says the
/// peer names it after the resolved directory, and this produces exactly that
/// directory entry, because a walk that refused every symbolic link below the
/// anchor has already resolved everything `realpath` would have: the parent
/// descriptor is the resolved parent's inode. Calling `canonicalize` instead
/// would ask the kernel to *follow* a link planted at the store, which is
/// precisely the redirection this hold must not accept — the lexical and
/// resolved spellings of the path differ on macOS in the common case
/// (`$TMPDIR` lives under `/var`, a link to `/private/var`), and both name the
/// same entry in the same directory.
fn plan(anchor: &LockAnchor) -> [LockPlan; 3] {
    let mut legacy_name = anchor.store_name.clone();
    legacy_name.push(LEGACY_LOCK_SUFFIX);
    let legacy_path = match anchor.store_dir.parent() {
        Some(parent) => parent.join(&legacy_name),
        // Unreachable: `LockAnchor::open` refuses a store directory with no
        // parent. Spelled rather than unwrapped so it stays unreachable.
        None => PathBuf::from(&legacy_name),
    };

    [
        LockPlan {
            artefact: Artefact {
                dir: Which::Store,
                name: OsString::from(REFRESH_LOCK),
                path: anchor.store_dir.join(REFRESH_LOCK),
            },
            profile: REFRESH_PROFILE,
        },
        LockPlan {
            artefact: Artefact { dir: Which::Parent, name: legacy_name, path: legacy_path },
            profile: REFRESH_PROFILE,
        },
        LockPlan {
            artefact: Artefact {
                dir: Which::Store,
                name: OsString::from(STORAGE_WRITE_LOCK),
                path: anchor.store_dir.join(STORAGE_WRITE_LOCK),
            },
            profile: STORAGE_WRITE_PROFILE,
        },
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
/// An [`AcquireFailure`] whose `error` is [`LockError::WrongTree`] when the
/// store directory is not in the tree `subject` names and
/// [`LockError::Unreachable`] when the way to it cannot be walked without
/// following a symbolic link — both **before** anything is created. Then
/// [`LockError::Cancelled`] when the run is cancelled, and [`LockError::Io`]
/// when a directory operation fails for a reason that is not contention.
///
/// Every one of those carries `break_record`, which the caller owes the audit
/// log before it maps the error to anything (invariant I16).
#[expect(
    clippy::result_large_err,
    reason = "the lint's remedy is a no-op here: `Acquisition` is 328 bytes and \
              `AcquireFailure` 240, so the `Result` this returns is 328 bytes \
              either way — sized by its `Ok` variant, exactly as it was before \
              the error type carried the draft. Boxing the error would move no \
              fewer bytes and would add an allocation to the break path"
)]
pub fn acquire(
    subject: LockSubject<'_>,
    paths: &Paths,
    env: &EnvView,
    clock: &Clock,
    ctx: &PassCtx,
    fault: &Fault,
) -> Result<Acquisition, AcquireFailure> {
    let seams = Seams::real(clock.clone());
    // Spelled out rather than `?`: there is no `From<LockError>` for
    // `AcquireFailure`, precisely so that no `?` inside the acquire can drop a
    // draft, and this site is where that costs one line.
    let anchor = LockAnchor::open(subject, paths, env).map_err(AcquireFailure::before_any_break)?;
    acquire_with(anchor, paths, ctx, fault, &seams)
}

/// [`acquire`] over injected seams and an already-opened anchor.
///
/// # Errors
///
/// See [`acquire`].
#[expect(
    clippy::result_large_err,
    reason = "the lint's remedy is a no-op here: `Acquisition` is 328 bytes and \
              `AcquireFailure` 240, so the `Result` this returns is 328 bytes \
              either way — sized by its `Ok` variant, exactly as it was before \
              the error type carried the draft. Boxing the error would move no \
              fewer bytes and would add an allocation to the break path"
)]
pub fn acquire_with(
    anchor: LockAnchor,
    paths: &Paths,
    ctx: &PassCtx,
    fault: &Fault,
    seams: &Seams<'_>,
) -> Result<Acquisition, AcquireFailure> {
    let anchor = Arc::new(anchor);
    let plans = plan(&anchor);
    let subject = LockSubject { store_dir: anchor.store_dir(), tree: anchor.tree() };
    let mut break_record: Option<BreakDraft> = None;
    let mut broken: Option<Artefact> = None;
    let mut restarts = 0_u32;

    loop {
        // Site 1 of six. On a restart iteration `break_record` can already
        // hold a completed break, which is why every one of these six spells
        // the draft out rather than returning a bare error.
        if ctx.cancel().is_cancelled() {
            return Err(AcquireFailure { error: LockError::Cancelled, break_record });
        }

        // --- Step 1: resolve staleness, holding nothing -------------------
        for lock in &plans {
            let at = anchor.slot(&lock.artefact);
            let Some(mtime) = seams.fs.mtime(at) else { continue };
            let age = age_of(&seams.clock, mtime);
            if age < lock.profile.stale && !fault.is("lock_stale") {
                continue;
            }
            if break_record.is_some() {
                // One break per acquire. A second stale lock is reported
                // busy rather than broken.
                return Ok(busy(false, Vec::new(), break_record));
            }

            let outcome = resolve_stale_with(subject, at, &lock.profile, ctx, fault, seams);
            break_record = outcome.record;

            match outcome.decision {
                // Gone, either way: carry on to the mkdirs.
                Decision::Broken => broken = Some(lock.artefact.clone()),
                Decision::Abandoned(Reason::Vanished) => {}
                Decision::Abandoned(Reason::HolderStopped) => {
                    return Ok(busy(false, seams.holders.stopped_pids(), break_record));
                }
                // Something is beating, or the clocks disagree. Fall through
                // to F36's schedule, which is what decides `holder_alive`.
                Decision::Abandoned(_) => break,
                // Sites 2 and 3. Both follow a break rule that decided
                // *this* iteration, so `break_record` is what that decision
                // just returned — `None` for a cancelled or failed sampling.
                // Passed anyway: an arm that reasons about the value rather
                // than passing it is an arm that stops being right when the
                // rule changes.
                Decision::Cancelled => {
                    return Err(AcquireFailure { error: LockError::Cancelled, break_record });
                }
                Decision::Failed(message) => {
                    return Err(AcquireFailure {
                        error: LockError::Io {
                            context: format!(
                                "could not resolve `{}`",
                                lock.artefact.path.display()
                            ),
                            message,
                        },
                        break_record,
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
        if let Some(artefact) = broken.as_ref()
            && seams.fs.mtime(anchor.slot(artefact)).is_some()
        {
            if let Some(entry) = break_record.as_mut() {
                entry.reason = Some(Reason::Retaken);
            }
            return Ok(busy(true, Vec::new(), break_record));
        }

        if let Some(mtime) = seams.fs.mtime(anchor.slot(&primary.artefact)) {
            match contention_wait(anchor.slot(&primary.artefact), mtime, ctx, seams) {
                Contention::Released => {}
                Contention::StillHeld { holder_alive } => {
                    return Ok(busy(holder_alive, Vec::new(), break_record));
                }
                // Site 4: reachable with a completed break, because the
                // schedule this cancels runs *after* step 1's break rule.
                Contention::Cancelled => {
                    return Err(AcquireFailure { error: LockError::Cancelled, break_record });
                }
            }
        }

        // --- Step 3: the record, before the first mkdir -------------------
        //
        // Site 5, and the one `agentctl-nq3` was filed for: after `1yj` a
        // symbolic link at `<namespace_root>/held-locks` makes this fail
        // deterministically, so a peer's lock could be removed and the only
        // durable evidence of it discarded, on demand. `?` would do that
        // again; the match is what carries the draft out.
        let record_path = match write_held_record(paths, &anchor, &plans, &seams.clock) {
            Ok(path) => path,
            Err(error) => return Err(AcquireFailure { error, break_record }),
        };

        // --- Step 4: mkdir ×3 in the peer's nesting -----------------------
        //
        // The hold is timed from **here**, before the first `mkdir`, not
        // from after the third: the peer's give-up floor starts running the
        // moment the primary exists, so measuring from the end would
        // understate exactly the term the budget is derived from.
        let first_mkdir = seams.clock.monotonic();
        match take_all(&anchor, &plans, seams, fault) {
            Ok(held) => {
                let hold = HeldLocks {
                    anchor: Arc::clone(&anchor),
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
            Err(TakeFailure::Exists { artefact, held }) => {
                release_all(&anchor, &held, seams);
                let _ = std::fs::remove_file(&record_path);

                // A lock recreated between our own `rmdir` and our own
                // `mkdir` is the one case section 3.8 calls `retaken`, and it
                // ends the acquire: at most one break, so there is no second
                // one to attempt.
                if broken.as_ref() == Some(&artefact)
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
            Err(TakeFailure::Io { artefact, held, message }) => {
                release_all(&anchor, &held, seams);
                let _ = std::fs::remove_file(&record_path);
                // Site 6, and after `axs` it is reachable with no `mkdir`
                // failure at all — an unreadable modification time straight
                // after agentctl's own `mkdirat`. It can carry a completed
                // *removal* draft, which is the most valuable one to lose.
                return Err(AcquireFailure {
                    error: LockError::Io {
                        // "take", not "create": this arm is also reached by a
                        // directory that was created and could not then be
                        // stated, and "could not create" would contradict its
                        // own message.
                        context: format!("could not take `{}`", artefact.path.display()),
                        message,
                    },
                    break_record,
                });
            }
        }
    }
}

/// Wraps a busy answer.
fn busy(
    holder_alive: bool,
    stopped_pids: Vec<u32>,
    break_record: Option<BreakDraft>,
) -> Acquisition {
    Acquisition { outcome: AcquireOutcome::Busy { holder_alive, stopped_pids }, break_record }
}

/// Why the three `mkdir`s did not all succeed.
enum TakeFailure {
    /// Somebody holds `artefact`; `held` is what was taken before that.
    Exists { artefact: Artefact, held: Vec<HeldOne> },
    /// `artefact` could not be created, or was created and could not then be
    /// stated, which is the same refusal: neither is a hold.
    Io { artefact: Artefact, held: Vec<HeldOne>, message: String },
}

/// `mkdir`s the three in order, recording each one's modification time.
///
/// Every attempt is a single non-blocking `mkdir` — including
/// `.storage-write`, whose profile carries `retries: 0` precisely so that
/// none of fact F47's ten-step ladder enters the hold.
///
/// A directory whose modification time cannot be read immediately after its
/// own `mkdir` is a [`TakeFailure::Io`], not a hold. Refusal A is the only
/// thing that tells agentctl a third party touched a lock it holds, and it
/// compares against the reading taken here; without one there is nothing to
/// compare against, so the lock would be held with that check switched off.
/// The directory exists by then, so it joins `held` on the way out and is
/// released in reverse order with everything before it.
fn take_all(
    anchor: &LockAnchor,
    plans: &[LockPlan; 3],
    seams: &Seams,
    fault: &Fault,
) -> Result<Vec<HeldOne>, TakeFailure> {
    let mut held: Vec<HeldOne> = Vec::with_capacity(plans.len());
    for (position, lock) in plans.iter().enumerate() {
        let at = anchor.slot(&lock.artefact);
        let contended = position == 0 && fault.is("lock_contended");
        let result = if contended { Err(FsError::Exists) } else { seams.fs.mkdir(at) };
        match result {
            Ok(()) => {
                let Some(mtime) = seams.fs.mtime(at) else {
                    held.push(HeldOne { artefact: lock.artefact.clone(), mtime: None });
                    return Err(TakeFailure::Io {
                        artefact: lock.artefact.clone(),
                        held,
                        message: "it was created, but its modification time could not be read, \
                                  so a third party touching it could not be detected"
                            .to_owned(),
                    });
                };
                held.push(HeldOne { artefact: lock.artefact.clone(), mtime: Some(mtime) });
            }
            Err(FsError::Exists) => {
                return Err(TakeFailure::Exists { artefact: lock.artefact.clone(), held });
            }
            Err(FsError::NotFound) => {
                return Err(TakeFailure::Io {
                    artefact: lock.artefact.clone(),
                    held,
                    message: "the parent directory is not there".to_owned(),
                });
            }
            Err(FsError::Other(message)) => {
                return Err(TakeFailure::Io { artefact: lock.artefact.clone(), held, message });
            }
        }
    }
    Ok(held)
}

/// Releases what was taken, in reverse order.
fn release_all(anchor: &LockAnchor, held: &[HeldOne], seams: &Seams<'_>) {
    for one in held.iter().rev() {
        let _ = seams.fs.rmdir(anchor.slot(&one.artefact));
    }
}

/// Registers the reverse-order release with the emergency cleanup registry.
///
/// The registry is what runs on SIGTERM, SIGHUP and SIGINT, and what a panic
/// hook runs; `Drop` covers everything else. It has to be
/// [`cleanup::register_restore`] and not `register_tmp_path`, because that
/// one unlinks and a lock is a **directory**.
fn register_emergency_release(mut hold: HeldLocks) -> HeldLocks {
    let artefacts: Vec<Artefact> = hold.held.iter().rev().map(|one| one.artefact.clone()).collect();
    let record = hold.record_path.clone();
    let fs = Arc::clone(&hold.fs);
    // The anchor's descriptors are moved into the closure as well, because the
    // release has to land in the directories the `mkdir`s landed in — a signal
    // handler re-resolving a path is a signal handler that can be redirected.
    let anchor = Arc::clone(&hold.anchor);
    hold.cleanup = Some(cleanup::register_restore(Box::new(move || {
        for artefact in &artefacts {
            let _ = fs.rmdir(anchor.slot(artefact));
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
fn contention_wait(
    at: LockSlot<'_>,
    first: SystemTime,
    ctx: &PassCtx,
    seams: &Seams<'_>,
) -> Contention {
    let mut waited = Duration::ZERO;
    for _ in 0..CONTENTION_ROUNDS {
        let nap = CONTENTION_ROUND_BASE.saturating_add(round_jitter());
        if seams.clock.sleep(nap, ctx.cancel()) {
            return Contention::Cancelled;
        }
        waited = waited.saturating_add(nap);
        if seams.fs.mtime(at).is_none() {
            return Contention::Released;
        }
    }

    let Some(second) = seams.fs.mtime(at) else { return Contention::Released };
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
    match seams.fs.mtime(at) {
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
    subject: LockSubject<'_>,
    at: LockSlot<'_>,
    profile: &LockProfile,
    clock: &Clock,
    holders: &dyn HolderEvidence,
    ctx: &PassCtx,
) -> BreakAttempt {
    let seams = Seams { fs: Arc::new(RealFs), holders, clock: clock.clone() };
    resolve_stale_with(subject, at, profile, ctx, &Fault::none(), &seams)
}

/// [`resolve_stale`] over injected seams.
pub fn resolve_stale_with(
    subject: LockSubject<'_>,
    at: LockSlot<'_>,
    profile: &LockProfile,
    ctx: &PassCtx,
    fault: &Fault,
    seams: &Seams<'_>,
) -> BreakAttempt {
    let clock = &seams.clock;

    // --- Sample A -------------------------------------------------------
    let wall_a = clock.wall();
    let mono_a = clock.monotonic();
    let Some(mtime_a) = seams.fs.mtime(at) else { return vanished() };
    let age_a = elapsed(wall_a, mtime_a);
    let sample_a = sample(wall_a, mtime_a, age_a);

    let mut record = BreakDraft {
        path: at.shown.to_path_buf(),
        store_dir: subject.store_dir.to_path_buf(),
        tree: subject.tree,
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
        return abandoned(record, Reason::TooYoung);
    }

    // --- Holder evidence ------------------------------------------------
    record.holder_evidence = seams.holders.stopped_claude_present();
    if record.holder_evidence == HolderEvidence3::StoppedClaudePresent {
        return abandoned(record, Reason::HolderStopped);
    }

    // --- The sampling wait ----------------------------------------------
    if clock.sleep(STALE_SAMPLE_INTERVAL, ctx.cancel()) {
        return BreakAttempt { decision: Decision::Cancelled, record: None };
    }

    // --- Sample B -------------------------------------------------------
    let wall_b = clock.wall();
    let mono_b = clock.monotonic();
    let Some(mtime_b) = seams.fs.mtime(at) else { return vanished() };
    let age_b = elapsed(wall_b, mtime_b);
    record.sample_b = Some(sample(wall_b, mtime_b, age_b));

    let (wall_delta, forward) = signed_delta(wall_a, wall_b);
    let mono_delta = mono_b.saturating_duration_since(mono_a);
    record.interval_wall_ms = millis(wall_delta);
    record.interval_monotonic_ms = millis(mono_delta);

    if mtime_b != mtime_a {
        return abandoned(record, Reason::HeartbeatObserved);
    }
    // The clock check comes **before** the age check, and the order is the
    // finding rather than a preference: a wall clock that has stepped
    // backwards makes the second age *smaller*, so an age test placed first
    // would report `too_young` for what is really a clock jump — the wrong
    // diagnosis, and one that hides the condition architect N-3 added.
    if clock_skew(wall_delta, forward, mono_delta) > CLOCK_SKEW_TOLERANCE {
        return abandoned(record, Reason::ClockJump);
    }
    if age_b < profile.stale {
        return abandoned(record, Reason::TooYoung);
    }

    // The injected resume: a holder that was wedged and comes back in
    // exactly the window Sample C exists to close.
    if fault.is("lock_resume_after_sample_b") {
        touch(at);
    }

    // --- Sample C, then the rmdir, with nothing in between --------------
    let wall_c = clock.wall();
    let Some(mtime_c) = seams.fs.mtime(at) else { return vanished() };
    if mtime_c != mtime_b {
        record.sample_c = Some(sample(wall_c, mtime_c, elapsed(wall_c, mtime_c)));
        return abandoned(record, Reason::HeartbeatObserved);
    }
    let removal = seams.fs.rmdir(at);

    // Everything below is after the decision. Nothing above allocates, logs
    // or appends between Sample C and the `rmdir`.
    record.sample_c = Some(sample(wall_c, mtime_c, elapsed(wall_c, mtime_c)));
    match removal {
        Ok(()) => {
            record.outcome = Outcome::Broken;
            record.reason = None;
            tracing::info!(
                path = %at.shown.display(),
                holder_evidence = ?record.holder_evidence,
                "removed a stale Claude Code lock"
            );
            BreakAttempt { decision: Decision::Broken, record: Some(record) }
        }
        Err(FsError::NotFound) => vanished(),
        Err(FsError::Exists) => BreakAttempt {
            decision: Decision::Failed(
                "the lock path is not an empty directory; refusing to remove it".to_owned(),
            ),
            record: None,
        },
        Err(FsError::Other(message)) => {
            BreakAttempt { decision: Decision::Failed(message), record: None }
        }
    }
}

/// The lock disappeared: nothing was there and nothing was done, so section
/// 3.8 writes no audit entry.
fn vanished() -> BreakAttempt {
    BreakAttempt { decision: Decision::Abandoned(Reason::Vanished), record: None }
}

/// Stamps an abandoned decision onto the draft.
///
/// No clock reading here any more: the entry's `ts` and `monotonic_ms` belong
/// to [`crate::secret::audit::AuditEntry`], which stamps them where the line is
/// written. That
/// is also the honest place for them — they say when the *entry* was made, and
/// a decision that is returned rather than logged has not been recorded yet.
fn abandoned(mut record: BreakDraft, reason: Reason) -> BreakAttempt {
    record.outcome = Outcome::Abandoned;
    record.reason = Some(reason);
    BreakAttempt { decision: Decision::Abandoned(reason), record: Some(record) }
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
///
/// The record is [`held_locks::HeldLockRecord`] — the reader's own type, not a
/// second declaration of the same fields — so `doctor` and this writer cannot
/// disagree about a name or a `tree` spelling.
///
/// # Where the record lands is decided by a walk, not by a path
///
/// The directory is `<namespace_root>/held-locks`, and it does not exist until
/// the first hold, so this function may be the one to make it. It used to
/// answer "is it there?" with `Path::is_dir` — which **follows** symbolic
/// links — and make it with a path-based `DirBuilder`, after which the record
/// was created by path as well. A symbolic link planted at that one leaf name
/// therefore sent the record, and every later record, into a directory of
/// somebody else's choosing: the file itself was still `create_new`, so this
/// was integrity and not disclosure, but the record is what `doctor` and
/// `--remove-stale` read to decide whether a lock outside the namespace root
/// may be removed, and a record an attacker can place is a record that can
/// name paths agentctl would then act on.
///
/// So the directory is resolved once, from [`Paths::namespace_root`] down,
/// one `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` component at a time
/// ([`file_store::create_dir_under`]), and the record is created relative to
/// the descriptor that walk produced — `O_WRONLY | O_CREAT | O_EXCL |
/// O_NOFOLLOW | O_CLOEXEC` at 0600. A link at `held-locks` is refused before
/// anything is written; a link left at the record's own name is refused by
/// `O_NOFOLLOW` on that name. Nothing is resolved by path twice, so there is
/// no window between the check and the write for a name to change in.
///
/// The record's **bytes and file name are unchanged**: the same
/// `serde_json::to_string` of the same [`HeldLockRecord`], under the same
/// `<pid>-<monotonic ms>.json`. `doctor` and `--remove-stale` read what they
/// always did.
fn write_held_record(
    paths: &Paths,
    anchor: &LockAnchor,
    plans: &[LockPlan; 3],
    clock: &Clock,
) -> Result<PathBuf, LockError> {
    let dir = held_locks::dir(paths);
    let dir_fd = file_store::create_dir_under(&paths.namespace_root(), &dir)
        .map_err(|err| LockError::Unreachable { path: dir.clone(), message: err.to_string() })?;

    let record = HeldLockRecord {
        agentctl_pid: std::process::id(),
        // Read here rather than at the removal, because the point of the field
        // is to say which process this was: a `doctor` run months later can
        // only compare a recorded start time against the one the id carries
        // now, and a recycled id then reads as recycled instead of as the
        // holder.
        agentctl_start_time: proc::self_start_time(&Cancel::new()),
        tree: anchor.tree(),
        store_dir: anchor.store_dir().to_path_buf(),
        paths: plans.iter().map(|lock| lock.artefact.path.clone()).collect(),
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
        let name = format!("{pid}-{stamp}.json");
        // The path is built only to name the file in the returned value and in
        // an error; every syscall below goes through `dir_fd`.
        let path = dir.join(&name);
        match file_store::create_new_file_at(dir_fd.as_fd(), &name, json.as_bytes()) {
            Ok(()) => return Ok(path),
            // That name is taken — by an earlier record, or by whatever else
            // is sitting there. Either way this hold needs a different one,
            // and `O_EXCL` means nothing was disturbed.
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

// There is deliberately no reader here. `held_locks::read_all` is the crate's
// one, and it is the careful one: it opens each record `O_NOFOLLOW` and stops
// at a 4 KiB cap, where the reader this module used to carry followed symbolic
// links and allowed 64 KiB. Two readers of the same file, one of them safe, is
// a choice waiting to be made wrongly.

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
    Sample { at: timestamp(at), mtime_ns: nanos_since_epoch(mtime), age_ms: millis(age) }
}

/// A `SystemTime` as nanoseconds since the Unix epoch, negative before it.
///
/// `i64` rather than the plan's `i128`, for a mechanical reason rather than a
/// preference: a 128-bit integer does not survive serde's buffering of a
/// flattened field, and this number reaches the log through
/// [`crate::secret::audit::AuditEntry`]'s `flatten`. Nanoseconds since 1970 fit
/// in an `i64` until the year 2262.
fn nanos_since_epoch(at: SystemTime) -> i64 {
    match at.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(since) => i64::try_from(since.as_nanos()).unwrap_or(i64::MAX),
        Err(before) => i64::try_from(before.duration().as_nanos()).map_or(i64::MIN, |nanos| -nanos),
    }
}

/// A `SystemTime` as the `jiff::Timestamp` the audit record carries, or the
/// epoch when it cannot be represented.
fn timestamp(at: SystemTime) -> jiff::Timestamp {
    jiff::Timestamp::from_microsecond(micros_since_epoch(at)).unwrap_or(jiff::Timestamp::UNIX_EPOCH)
}

/// A `SystemTime` as RFC 3339, or the epoch when it cannot be represented.
///
/// The held-lock record stores its `taken_at` as a string rather than a
/// `jiff::Timestamp` to match the namespace lock body and the account
/// registry, which do the same and keep `jiff`'s optional serde support out of
/// the manifest.
fn rfc3339(at: SystemTime) -> String {
    timestamp(at).to_string()
}

/// A `SystemTime` in whole microseconds since the epoch, saturating.
fn micros_since_epoch(at: SystemTime) -> i64 {
    match at.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(since) => i64::try_from(since.as_micros()).unwrap_or(i64::MAX),
        Err(before) => {
            i64::try_from(before.duration().as_micros()).map_or(i64::MIN, |micros| -micros)
        }
    }
}

/// Sets a lock's modification time to now, for the injected-resume fault.
fn touch(at: LockSlot<'_>) {
    let now =
        rustix::fs::Timestamps { last_access: now_timespec(), last_modification: now_timespec() };
    let _ = rustix::fs::utimensat(at.dir, at.name, &now, rustix::fs::AtFlags::SYMLINK_NOFOLLOW);
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
