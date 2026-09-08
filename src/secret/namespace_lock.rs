//! The lock that makes a namespace single-writer.
//!
//! # Why the lock file lives outside the namespace
//!
//! `flock` locks an *inode*, not a path. A lock file inside the namespace
//! directory would be deletable — by `accounts remove`, by a Claude Code
//! `/logout` that clears the store (fact F35), by a user tidying up — and the
//! moment it is deleted and recreated, two processes hold locks on two
//! different inodes and both believe they are alone. So the lock lives in
//! `<namespace_root>/.locks/<acct>.<org>.lock`, is created once, and is
//! **never unlinked** (plan section 3.5). Nothing in agentctl removes it,
//! including the code that removes the namespace it protects.
//!
//! # Why not `fd-lock`
//!
//! `fd_lock::RwLock` hands out a guard that borrows the lock object, so a
//! guard that owns its file is self-referential and does not compile without
//! either a self-referential-struct crate or leaking the lock object. What is
//! wanted here is exactly one owned `File` whose lock is released when the
//! guard drops, which `rustix::fs::flock` on an owned handle gives directly.
//! `fd-lock` was removed from the manifest rather than left unused.
//!
//! # Fail closed
//!
//! Any error that is not "somebody else holds it" makes acquisition fail with
//! [`LockError::Unavailable`], and a caller that cannot take the lock does not
//! write. A filesystem that does not implement `flock` — a network mount, a
//! container's overlay — is therefore a filesystem agentctl declines to
//! refresh on, rather than one it silently refreshes on without mutual
//! exclusion. That is invariant I12, and it is the conservative side of a
//! trade whose other side is two processes rotating one refresh chain.

#![cfg_attr(not(test), expect(dead_code, reason = "consumed by lane D and lane C"))]

use std::fs::File;
use std::io::Seek;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

use rustix::fs::FlockOperation;
use rustix::fs::Mode;
use rustix::fs::OFlags;
use serde::Deserialize;
use serde::Serialize;

use crate::config::paths::Paths;
use crate::config::paths::validate_segment;
use crate::runtime::coordinator::Cancel;
use crate::runtime::fault::Fault;

/// How often a blocked acquire retries (plan section 3.5).
pub const RETRY_INTERVAL: Duration = Duration::from_millis(250);

/// The default wait for the interactive commands, which have no pass deadline
/// of their own.
pub const COMMAND_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// An acquired lock.
///
/// The exclusive `flock` is released when this drops, and by the kernel if
/// the process dies — which is what makes a crash during a refresh safe: the
/// next process can take the lock immediately (plan AC27), and what it finds
/// on disk is either the old credentials or a pending file, never a
/// half-written one.
///
/// Also used for the configuration lock, which wants exactly the same
/// behaviour over a different path.
#[derive(Debug)]
pub struct NamespaceLockGuard {
    file: File,
    path: PathBuf,
}

impl NamespaceLockGuard {
    /// The lock file this guard holds.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for NamespaceLockGuard {
    fn drop(&mut self) {
        // Best effort: closing the descriptor releases the lock anyway, and
        // there is no caller left to tell about a failure.
        let _ = rustix::fs::flock(&self.file, FlockOperation::Unlock);
    }
}

/// Why a lock could not be taken.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LockError {
    /// Somebody else holds it, and the deadline passed while waiting.
    #[error("another process holds the namespace lock")]
    Busy,
    /// There is a symbolic link where the lock file should be.
    #[error("`{0}` is a symbolic link; refusing to lock through it")]
    RefusedSymlink(PathBuf),
    /// Locking failed for a reason that is not contention.
    #[error("the namespace lock is unavailable: {0}")]
    Unavailable(String),
    /// The run was cancelled while waiting.
    #[error("cancelled while waiting for the namespace lock")]
    Cancelled,
}

/// What an acquired lock records about its holder.
///
/// Written into the file body so `doctor` can say *who* holds a lock, and
/// whether that process is alive, stopped or gone (plan AC45).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockBody {
    /// The holder's process id.
    pub pid: u32,
    /// When that process started, for telling a live holder from a recycled
    /// pid.
    ///
    /// Always `null` in this build. Reading it portably means a `sysctl` FFI
    /// call on macOS, and nothing in phase 1 consumes it — `doctor`, which
    /// does, lands in W2 and can fill it in then. The field exists now so a
    /// lock body written today stays readable when it does.
    pub pid_start_time: Option<String>,
    /// When the lock was taken, RFC 3339.
    pub acquired_at: String,
}

/// Takes the namespace lock for one `(account, organization)` pair.
///
/// Retries every [`RETRY_INTERVAL`] until `deadline`, then reports
/// [`LockError::Busy`]. Cancellation is noticed immediately rather than at
/// the end of the next interval.
///
/// # Errors
///
/// See [`LockError`]. Every variant except `Busy` means the caller must not
/// write, and `Busy` means it must re-read before deciding (plan section 3.3
/// step 3: a caller that loses the race re-reads and adopts a file the winner
/// just refreshed).
pub fn acquire(
    paths: &Paths,
    acct: &str,
    org: &str,
    deadline: Instant,
    cancel: &Cancel,
    fault: Fault,
) -> Result<NamespaceLockGuard, LockError> {
    validate_segment(acct).map_err(|err| LockError::Unavailable(err.to_string()))?;
    validate_segment(org).map_err(|err| LockError::Unavailable(err.to_string()))?;

    let locks_dir = paths.locks_dir();
    create_locks_dir(&locks_dir)?;

    let path = paths.lock_path(acct, org);
    let mut guard = lock_file(&path, deadline, cancel, &fault)?;
    write_body(&mut guard)?;

    // Used by plan AC7 and AC35 to make a second process actually wait, and
    // to prove a `watch` frame keeps redrawing while a worker is stuck.
    if fault.is("hold_lock") {
        Fault::stall_until(cancel, deadline);
    }
    Ok(guard)
}

/// Takes an exclusive `flock` on `path`, creating the file if needed.
///
/// Shared with [`crate::config::AgentctlConfig::save`], which wants the same
/// semantics over `.config.lock`.
///
/// # Errors
///
/// See [`LockError`].
pub fn lock_file(
    path: &Path,
    deadline: Instant,
    cancel: &Cancel,
    fault: &Fault,
) -> Result<NamespaceLockGuard, LockError> {
    if fault.is("flock_enotsup") {
        return Err(LockError::Unavailable(
            "flock is not supported on this filesystem (injected by AGENTCTL_FAULT)".to_owned(),
        ));
    }

    // `O_NOFOLLOW` rather than an `lstat` first: the check and the open are
    // then one syscall, so a link cannot be swapped in between them.
    let flags = OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW;
    let fd = rustix::fs::open(path, flags, Mode::RUSR | Mode::WUSR).map_err(|errno| {
        if errno == rustix::io::Errno::LOOP || errno == rustix::io::Errno::MLINK {
            LockError::RefusedSymlink(path.to_path_buf())
        } else {
            LockError::Unavailable(format!("could not open `{}`: {errno}", path.display()))
        }
    })?;
    let file = File::from(fd);

    loop {
        match rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return Ok(NamespaceLockGuard { file, path: path.to_path_buf() }),
            Err(errno) if errno == rustix::io::Errno::WOULDBLOCK => {
                if cancel.is_cancelled() {
                    return Err(LockError::Cancelled);
                }
                if Instant::now() >= deadline {
                    return Err(LockError::Busy);
                }
                // Waiting on the cancellation condvar rather than sleeping, so
                // `Ctrl-C` is noticed at once instead of up to 250 ms later.
                if cancel.wait_timeout(RETRY_INTERVAL) {
                    return Err(LockError::Cancelled);
                }
            }
            Err(errno) => {
                return Err(LockError::Unavailable(format!(
                    "could not lock `{}`: {errno}",
                    path.display()
                )));
            }
        }
    }
}

/// Reads a lock file's body, if it has a readable one.
///
/// Returns `None` for every failure: an unreadable or unparseable body means
/// the holder is older, or newer, or crashed mid-write, and none of those is
/// worth failing a `doctor` run over.
pub fn read_body(path: &Path) -> Option<LockBody> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() > 4096 {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

/// Replaces the lock file's body with a description of this holder.
fn write_body(guard: &mut NamespaceLockGuard) -> Result<(), LockError> {
    let body = LockBody {
        pid: std::process::id(),
        pid_start_time: None,
        acquired_at: jiff::Timestamp::now().to_string(),
    };
    let json = serde_json::to_string(&body).map_err(|err| {
        LockError::Unavailable(format!("could not serialize the lock body: {err}"))
    })?;

    let mut write = || -> std::io::Result<()> {
        guard.file.set_len(0)?;
        guard.file.rewind()?;
        guard.file.write_all(json.as_bytes())?;
        guard.file.flush()
    };
    write().map_err(|err| {
        LockError::Unavailable(format!("could not write `{}`: {err}", guard.path.display()))
    })
}

/// Creates the locks directory at 0700.
fn create_locks_dir(dir: &Path) -> Result<(), LockError> {
    use std::os::unix::fs::DirBuilderExt;

    if dir.is_dir() {
        return Ok(());
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(crate::config::paths::DIR_MODE);
    builder.create(dir).map_err(|err| {
        LockError::Unavailable(format!("could not create `{}`: {err}", dir.display()))
    })
}

#[cfg(test)]
#[path = "namespace_lock_tests.rs"]
mod tests;
