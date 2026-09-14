//! Claude Code's `.claude.json` configuration lock, taken as a **peer** (spike
//! S13's V8, decision D-021, ruling G15).
//!
//! The peer's lock is `proper-lockfile` with its default options: one `mkdir`
//! directory at `${configPath}.lock`, stale after 10 s, heartbeat 5 s, and a
//! retry ladder that lives in the caller rather than in the library. It is the
//! same primitive [`claude_lock`](crate::secret::claude_lock) takes three of
//! for the credential store, and this module reuses that module's directory
//! operations ([`LockFs`]) and clock ([`Clock`]) — but it is its own module,
//! because every rule that matters differs:
//!
//! - **one slot, at the literal path.** `lockfilePath` is never passed through
//!   `realpath`, so for `~/.claude.json` — a symbolic link on the reference
//!   machine — the lock is `~/.claude.json.lock`, beside the **link** (drift
//!   1). The directory is opened once, following the links on the way to it,
//!   and the `mkdir`, the `stat` and the `rmdir` all land relative to that one
//!   descriptor.
//! - **a stale lock is reported, never broken** (ruling G5). A wrong break
//!   corrupts a 166-key file the peer is in the middle of writing; the peer's
//!   own stale rule reclaims an abandoned lock within 10 s. So a lock older
//!   than [`CONFIG_PROFILE`]`.stale` ends the ladder with
//!   [`ConfigLockError::Stale`]: waiting cannot clear it, and removing it is
//!   not agctl's to do.
//! - **the ladder runs with nothing held** (ruling G6). A peer inside its
//!   first 30 s gives up on this lock after 1 500 ms and then writes the whole
//!   document *unlocked*, so a wait inside a hold would turn a delay into a
//!   clobber. [`CONTENTION_LADDER`] sleeps only while agctl holds nothing.
//! - **no held-lock record** (ruling G15). The peer's 10 s staleness is the
//!   backstop for a killed agctl, and `doctor --remove-stale` learns no new
//!   artefact class.
//!
//! What happens under the hold is [`claude_json`]'s; this module only takes,
//! checks and gives back the lock. A session seed's read takes it through
//! [`try_once`] instead — one `mkdir`, no ladder — and reads without it when it
//! is not free (M6, ruling Q5).
//!
//! [`claude_json`]: crate::provider::claude::claude_json

use std::ffi::OsString;
use std::os::fd::AsFd;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;

use rustix::fs::AtFlags;
use rustix::fs::Mode;
use rustix::fs::OFlags;

use crate::provider::claude::namespace;
use crate::runtime::cleanup;
use crate::runtime::cleanup::CleanupToken;
use crate::runtime::coordinator::PassCtx;
use crate::secret::claude_lock::CONFIG_PROFILE;
use crate::secret::claude_lock::Clock;
use crate::secret::claude_lock::FsError;
use crate::secret::claude_lock::LockFs;
use crate::secret::claude_lock::LockSlot;

/// The waits between attempts on a held configuration lock (ruling G6).
///
/// Each wait is `rung × (1 + rand)`, so the whole ladder is at most 2 800 ms —
/// the peer's own `kdr` ladder, cut to three rungs. Four attempts, three
/// sleeps, and nothing held during any of them.
pub const CONTENTION_LADDER: [Duration; 3] =
    [Duration::from_millis(200), Duration::from_millis(400), Duration::from_millis(800)];

/// Why the configuration lock could not be taken or trusted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigLockError {
    /// A Claude Code session held the lock through the whole ladder.
    #[error("a Claude Code session held the configuration lock through every retry")]
    Busy,
    /// The lock is older than the peer's staleness window. Never broken.
    #[error(
        "the configuration lock is {age_ms} ms old, past the peer's staleness window; agctl never \
         breaks it"
    )]
    Stale {
        /// How old the lock directory was when it was found.
        age_ms: u64,
    },
    /// The run was cancelled while waiting.
    #[error("cancelled while waiting for the configuration lock")]
    Cancelled,
    /// The lock agctl holds had its modification time moved under it: a peer
    /// broke it, which needs a hold older than 10 s, which means agctl was
    /// stopped.
    #[error("`{}` was modified while agctl held it; the lock is compromised", .0.display())]
    Compromised(PathBuf),
    /// The directory the lock belongs in could not be opened.
    #[error("`{}` cannot be locked: {message}", .path.display())]
    Unreachable {
        /// The directory, as the configuration path spells it.
        path: PathBuf,
        /// Why not.
        message: String,
    },
    /// A directory operation failed for a reason that is not contention.
    #[error("{context}: {message}")]
    Io {
        /// What was being attempted.
        context: String,
        /// The underlying failure.
        message: String,
    },
}

/// A temporary file the hold's release unlinks if it is still there: the
/// directory it was created in, and its name.
type TrackedTemp = Arc<Mutex<Option<(Arc<OwnedFd>, OsString)>>>;

/// A held configuration lock.
///
/// Released by `rmdir` through the descriptor it was taken through — in
/// [`ConfigHold::release`], in `Drop`, and from the emergency cleanup registry
/// on SIGTERM, SIGINT and SIGHUP, which also unlinks a temporary file the hold
/// is tracking ([`ConfigHold::track_temp`]).
pub struct ConfigHold {
    /// The literal parent of the configuration path.
    dir: Arc<OwnedFd>,
    /// `<configuration file name>.lock`.
    name: OsString,
    /// The lock directory's path, for messages only.
    shown: PathBuf,
    /// The lock directory's modification time as agctl's `mkdir` left it.
    mtime: Option<SystemTime>,
    /// When the `mkdir` succeeded, on [`ConfigHold::clock`].
    acquired_at: Instant,
    clock: Clock,
    fs: Arc<dyn LockFs>,
    temp: TrackedTemp,
    cleanup: Option<CleanupToken>,
    released: bool,
}

impl ConfigHold {
    /// How long the lock has been held, on the clock that stamped the `mkdir`.
    pub fn elapsed(&self) -> Duration {
        self.clock.monotonic().saturating_duration_since(self.acquired_at)
    }

    /// The lock directory's path, for messages.
    pub fn shown(&self) -> &Path {
        &self.shown
    }

    /// The last check before a rename: the lock directory's modification time
    /// must equal the one recorded at `mkdir` **exactly**, and a missing reading
    /// on either side is a failure (`HeldLocks::drift_check`'s rule).
    ///
    /// # Errors
    ///
    /// [`ConfigLockError::Compromised`] when the time moved or cannot be read.
    pub fn drift_check(&self) -> Result<(), ConfigLockError> {
        match (self.mtime, self.fs.mtime(self.slot())) {
            (Some(recorded), Some(now)) if recorded == now => Ok(()),
            _ => Err(ConfigLockError::Compromised(self.shown.clone())),
        }
    }

    /// Hands the hold a temporary file to unlink if the process stops before
    /// the caller has renamed or removed it.
    ///
    /// Registered **before** the file is created, so there is no instant at
    /// which the file exists and nothing would remove it.
    pub fn track_temp(&self, dir: Arc<OwnedFd>, name: OsString) {
        *lock_temp(&self.temp) = Some((dir, name));
    }

    /// Withdraws the temporary file, once it has been renamed into place or
    /// removed.
    pub fn untrack_temp(&self) {
        *lock_temp(&self.temp) = None;
    }

    /// Gives the lock back.
    pub fn release(mut self) {
        self.release_now();
    }

    fn slot(&self) -> LockSlot<'_> {
        LockSlot { dir: self.dir.as_fd(), name: &self.name, shown: &self.shown }
    }

    fn release_now(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        unlink_tracked(&self.temp);
        // The emergency registration is withdrawn **before** the `rmdir`, never
        // after. Once the directory is gone a Claude Code session may take the
        // lock under the same name, and a signal landing between an `rmdir` and
        // a later withdrawal would run the emergency closure's own `rmdir`
        // against that session's lock — a break ruling G5 forbids. In this
        // order a signal in the gap leaves agctl's own lock behind instead,
        // which the peer's 10 s staleness reclaims (§D15's killed-mid-hold row).
        //
        // And the withdrawal's answer decides the `rmdir` (review round 1 F2):
        // `false` means the emergency closure already ran and removed the lock,
        // so the name may now be a peer's fresh lock, which a second `rmdir`
        // would break.
        let owned = self.cleanup.take().is_none_or(cleanup::unregister);
        if owned {
            let _ = self.fs.rmdir(self.slot());
        }
    }
}

impl Drop for ConfigHold {
    fn drop(&mut self) {
        self.release_now();
    }
}

impl std::fmt::Debug for ConfigHold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigHold")
            .field("shown", &self.shown)
            .field("mtime", &self.mtime)
            .finish()
    }
}

/// Takes the configuration lock for `config_path`, waiting on the contention
/// ladder with nothing held.
///
/// 1. The **literal** parent of `config_path` is opened once, `O_DIRECTORY`,
///    following the links on the way to it — the lock is beside the path the
///    environment names, not beside its target.
/// 2. One `mkdir` of `<file name>.lock`. On `EEXIST` the lock's age decides:
///    a vanished lock is retried at once (once per rung), a stale one ends the
///    ladder as [`ConfigLockError::Stale`], and a fresh one is waited on for
///    the next rung of [`CONTENTION_LADDER`]. After the third rung's retry the
///    answer is [`ConfigLockError::Busy`].
/// 3. On success the modification time is recorded for
///    [`ConfigHold::drift_check`], and the release is registered with the
///    emergency cleanup registry.
///
/// Nothing is ever removed here: a lock that is not agctl's is never broken.
///
/// # Errors
///
/// [`ConfigLockError::Busy`], [`ConfigLockError::Stale`] and
/// [`ConfigLockError::Cancelled`] for the ladder's three ends;
/// [`ConfigLockError::Unreachable`] when the directory cannot be opened or has
/// gone; [`ConfigLockError::Io`] for any other `mkdir` failure.
pub fn acquire(
    config_path: &Path,
    clock: &Clock,
    fs: Arc<dyn LockFs>,
    ctx: &PassCtx,
) -> Result<ConfigHold, ConfigLockError> {
    let (parent, dir, name, shown) = open_parent(config_path)?;
    let slot = LockSlot { dir: dir.as_fd(), name: &name, shown: &shown };

    let mut rungs = CONTENTION_LADDER.iter();
    let mut retried_vanished = false;
    loop {
        match fs.mkdir(slot) {
            Ok(()) => break,
            Err(FsError::Exists) => match fs.mtime(slot) {
                // Released between the `mkdir` and the `stat`: try again at once,
                // but only once per rung, so a lock that flickers cannot spin.
                None if !retried_vanished => {
                    retried_vanished = true;
                    continue;
                }
                None => {}
                Some(mtime) => {
                    let age = clock.wall().duration_since(mtime).unwrap_or(Duration::ZERO);
                    if age >= CONFIG_PROFILE.stale {
                        return Err(ConfigLockError::Stale { age_ms: millis(age) });
                    }
                }
            },
            Err(FsError::NotFound) => {
                return Err(ConfigLockError::Unreachable {
                    path: parent,
                    message: "the directory went away".to_owned(),
                });
            }
            Err(FsError::Other(message)) => {
                return Err(ConfigLockError::Io {
                    context: format!("could not create `{}`", shown.display()),
                    message,
                });
            }
        }
        let Some(rung) = rungs.next() else { return Err(ConfigLockError::Busy) };
        retried_vanished = false;
        if clock.sleep(jittered(*rung), ctx.cancel()) || ctx.should_stop() {
            return Err(ConfigLockError::Cancelled);
        }
    }
    Ok(held(dir, name, shown, clock, fs))
}

/// One attempt at the configuration lock, for a read that must never wait:
/// the session seed's (M6, ruling Q5).
///
/// Exactly one `mkdir` of `<file name>.lock` beside the **literal** path,
/// through the same parent descriptor [`acquire`] opens. No ladder, no sleep,
/// no retry and no removal — a lock that is not free is reported and left
/// exactly as it was (ruling G5), and the caller reads without it.
///
/// # Errors
///
/// [`ConfigLockError::Busy`] when the lock exists and is not stale, or
/// vanished between the `mkdir` and its `stat`; [`ConfigLockError::Stale`]
/// when it is older than the peer's staleness window;
/// [`ConfigLockError::Unreachable`] and [`ConfigLockError::Io`] as for
/// [`acquire`]. Never `Cancelled` or `Compromised`.
pub fn try_once(
    config_path: &Path,
    clock: &Clock,
    fs: Arc<dyn LockFs>,
) -> Result<ConfigHold, ConfigLockError> {
    let (parent, dir, name, shown) = open_parent(config_path)?;
    let slot = LockSlot { dir: dir.as_fd(), name: &name, shown: &shown };
    match fs.mkdir(slot) {
        Ok(()) => {}
        Err(FsError::Exists) => {
            return Err(match fs.mtime(slot) {
                Some(mtime) => {
                    let age = clock.wall().duration_since(mtime).unwrap_or(Duration::ZERO);
                    if age >= CONFIG_PROFILE.stale {
                        ConfigLockError::Stale { age_ms: millis(age) }
                    } else {
                        ConfigLockError::Busy
                    }
                }
                None => ConfigLockError::Busy,
            });
        }
        Err(FsError::NotFound) => {
            return Err(ConfigLockError::Unreachable {
                path: parent,
                message: "the directory went away".to_owned(),
            });
        }
        Err(FsError::Other(message)) => {
            return Err(ConfigLockError::Io {
                context: format!("could not create `{}`", shown.display()),
                message,
            });
        }
    }
    Ok(held(dir, name, shown, clock, fs))
}

/// The literal parent of `config_path`, opened once `O_DIRECTORY` following
/// the links on the way to it, with the lock's name and its shown path.
fn open_parent(
    config_path: &Path,
) -> Result<(PathBuf, Arc<OwnedFd>, OsString, PathBuf), ConfigLockError> {
    let (Some(parent), Some(name)) =
        (config_path.parent(), namespace::config_lock_name(config_path))
    else {
        return Err(ConfigLockError::Unreachable {
            path: config_path.to_path_buf(),
            message: "the configuration path has no directory and file name".to_owned(),
        });
    };
    let shown = parent.join(&name);
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
    let dir = rustix::fs::open(parent, flags, Mode::empty()).map_err(|errno| {
        ConfigLockError::Unreachable {
            path: parent.to_path_buf(),
            message: format!("its directory could not be opened: {errno}"),
        }
    })?;
    Ok((parent.to_path_buf(), Arc::new(dir), name, shown))
}

/// The hold a successful `mkdir` makes: its time on `clock`, the directory's
/// modification time for [`ConfigHold::drift_check`], and the release
/// registered with the emergency cleanup registry.
fn held(
    dir: Arc<OwnedFd>,
    name: OsString,
    shown: PathBuf,
    clock: &Clock,
    fs: Arc<dyn LockFs>,
) -> ConfigHold {
    let slot = LockSlot { dir: dir.as_fd(), name: &name, shown: &shown };
    let acquired_at = clock.monotonic();
    let mtime = fs.mtime(slot);
    let temp: TrackedTemp = Arc::new(Mutex::new(None));
    let token = {
        let (dir, name, shown) = (Arc::clone(&dir), name.clone(), shown.clone());
        let (fs, temp) = (Arc::clone(&fs), Arc::clone(&temp));
        // The descriptor moves into the closure, so a signal handler's release
        // lands in the directory the `mkdir` landed in rather than re-resolving
        // a path.
        cleanup::register_restore(Box::new(move || {
            unlink_tracked(&temp);
            let _ = fs.rmdir(LockSlot { dir: dir.as_fd(), name: &name, shown: &shown });
        }))
    };
    ConfigHold {
        dir,
        name,
        shown,
        mtime,
        acquired_at,
        clock: clock.clone(),
        fs,
        temp,
        cleanup: Some(token),
        released: false,
    }
}

/// One rung's wait: `rung + rand·rung`, in whole milliseconds, so it lies in
/// `[rung, 2·rung)`.
fn jittered(rung: Duration) -> Duration {
    let span = millis(rung).max(1);
    rung.saturating_add(Duration::from_millis(u64::from(rand::random::<u32>()) % span))
}

/// Unlinks the tracked temporary file, if any, and forgets it.
fn unlink_tracked(temp: &TrackedTemp) {
    if let Some((dir, name)) = lock_temp(temp).take() {
        let _ = rustix::fs::unlinkat(&*dir, &name, AtFlags::empty());
    }
}

/// The tracked temporary file's slot, recovering from a poisoned lock: a panic
/// elsewhere is exactly when the release must still run.
fn lock_temp(temp: &TrackedTemp) -> MutexGuard<'_, Option<(Arc<OwnedFd>, OsString)>> {
    temp.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A `Duration` in whole milliseconds, saturating.
fn millis(of: Duration) -> u64 {
    u64::try_from(of.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
#[path = "config_lock_tests.rs"]
mod tests;
