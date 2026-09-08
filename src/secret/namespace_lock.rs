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

use std::ffi::OsStr;
use std::fs::File;
use std::io::Seek;
use std::io::Write;
use std::os::fd::AsFd;
use std::os::fd::BorrowedFd;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

use rustix::fs::FlockOperation;
use rustix::fs::Mode;
use rustix::fs::OFlags;
use rustix::io::Errno;
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
    /// Filled from [`crate::runtime::proc::self_start_time`] at acquire time,
    /// which reads `ps -o lstart=` once per process. `null` when `ps` could not
    /// be run: `doctor` then falls back to the process id alone, which is
    /// weaker but still useful, rather than the acquire failing over a
    /// diagnostic field.
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

    // The locks directory is opened `O_NOFOLLOW` and the lock file is taken
    // relative to that descriptor, so there is no second path resolution
    // between checking `.locks` and using it.
    let dir = create_locks_dir(&paths.locks_dir())?;

    let path = paths.lock_path(acct, org);
    let name = path.file_name().ok_or_else(|| {
        LockError::Unavailable(format!("`{}` does not name a lock file", path.display()))
    })?;
    let mut guard = lock_at(dir.as_fd(), name, &path, deadline, cancel, &fault)?;
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
/// Shared with [`crate::config::AgentctlConfig::update`], which wants the same
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
    let dir = open_parent_dir(path)?;
    let name = path.file_name().ok_or_else(|| {
        LockError::Unavailable(format!("`{}` does not name a lock file", path.display()))
    })?;
    lock_at(dir.as_fd(), name, path, deadline, cancel, fault)
}

/// Takes the exclusive `flock` on `name` inside an already-opened directory.
///
/// Splitting this out is what lets the two callers differ where they must:
/// [`acquire`] hands in a `.locks` descriptor opened `O_NOFOLLOW`, because a
/// link there is nobody's legitimate layout, while [`lock_file`] resolves the
/// configuration directory normally, because that one may well be a symlink
/// the user put there and every other path in the store follows it.
fn lock_at(
    dir: BorrowedFd<'_>,
    name: &OsStr,
    path: &Path,
    deadline: Instant,
    cancel: &Cancel,
    fault: &Fault,
) -> Result<NamespaceLockGuard, LockError> {
    if fault.is("flock_enotsup") {
        return Err(LockError::Unavailable(
            // Not naming the environment variable is deliberate: this literal
            // is in code the default-feature build compiles, so spelling it
            // would put a test-only variable name into the release artifact
            // (plan AC37). `crate::runtime::fault` says which switch this is.
            "flock is not supported on this filesystem (injected by the test fault switch)"
                .to_owned(),
        ));
    }

    let file = open_lock_file(dir, name, path)?;

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

/// How many times [`open_lock_file`] re-looks before giving up.
///
/// Each round costs two `openat` calls and only happens while another process
/// is creating the same lock file, so a handful is generous; the bound is
/// there so churn cannot spin forever.
const CREATE_ATTEMPTS: u32 = 8;

/// Opens the lock file inside `dir`, creating it if it is not there yet.
///
/// Deliberately not one `openat(.., O_CREAT, ..)` call. Darwin does not retry
/// `openat`'s lookup when another thread wins the create race: two processes
/// reaching a fresh lock file at the same moment make it return `ENOENT` — not
/// `EEXIST` — about 40% of the time, measured on this machine with a
/// two-thread probe. Path-based `open(2)` does not have the fault, but a path
/// is exactly what the descriptor exists to stop resolving a second time. So
/// the create is split: open what is there, and only when there is nothing
/// there create it with `O_EXCL`, reading `EEXIST` as "somebody just made it"
/// and looking again.
///
/// A planted symlink is refused either way round: `O_NOFOLLOW` refuses it on
/// the open of an existing file, and `O_CREAT | O_EXCL` refuses it — as
/// `EEXIST`, which sends us back to the `O_NOFOLLOW` open that reports it
/// properly.
fn open_lock_file(dir: BorrowedFd<'_>, name: &OsStr, path: &Path) -> Result<File, LockError> {
    let existing = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let fresh = OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC;

    for _ in 0..CREATE_ATTEMPTS {
        match rustix::fs::openat(dir, name, existing, Mode::empty()) {
            Ok(fd) => return Ok(File::from(fd)),
            Err(errno) if errno == Errno::NOENT => {}
            Err(errno) => return Err(open_error(errno, path)),
        }
        match rustix::fs::openat(dir, name, fresh, Mode::RUSR | Mode::WUSR) {
            Ok(fd) => return Ok(File::from(fd)),
            Err(errno) if errno == Errno::EXIST => continue,
            Err(errno) => return Err(open_error(errno, path)),
        }
    }

    Err(LockError::Unavailable(format!(
        "could not open `{}`: it kept being created and removed underneath us",
        path.display()
    )))
}

/// Maps an `openat` failure on the lock file onto a [`LockError`].
fn open_error(errno: Errno, path: &Path) -> LockError {
    if errno == Errno::LOOP || errno == Errno::MLINK {
        LockError::RefusedSymlink(path.to_path_buf())
    } else {
        LockError::Unavailable(format!("could not open `{}`: {errno}", path.display()))
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
        pid_start_time: crate::runtime::proc::self_start_time(),
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

/// Creates the locks directory at 0700, refusing a symbolic link.
///
/// `Path::is_dir` follows links, so it would happily accept a `.locks`
/// pointing anywhere and then create every lock file there. The check is
/// therefore an `lstat`: a link at this path is somebody else deciding where
/// this store's locks live, which is a decision to refuse rather than to
/// follow.
fn create_locks_dir(dir: &Path) -> Result<OwnedFd, LockError> {
    use std::os::unix::fs::DirBuilderExt;

    let exists = match std::fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(LockError::RefusedSymlink(dir.to_path_buf()));
        }
        Ok(meta) if meta.is_dir() => true,
        Ok(_) => {
            return Err(LockError::Unavailable(format!("`{}` is not a directory", dir.display())));
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
        Err(err) => {
            return Err(LockError::Unavailable(format!(
                "could not stat `{}`: {err}",
                dir.display()
            )));
        }
    };

    if !exists {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(crate::config::paths::DIR_MODE);
        builder.create(dir).map_err(|err| {
            LockError::Unavailable(format!("could not create `{}`: {err}", dir.display()))
        })?;
    }

    // `O_NOFOLLOW` closes the window the `lstat` above leaves open: a link
    // swapped in between the two would be followed by a second resolution,
    // and there is no second resolution once the descriptor is held. Darwin
    // reports `O_DIRECTORY | O_NOFOLLOW` on a link as `ENOTDIR`, so that
    // errno joins `ELOOP` here — the `lstat` already established that a
    // directory was there a moment ago.
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    rustix::fs::open(dir, flags, Mode::empty()).map_err(|errno| {
        if errno == Errno::LOOP || errno == Errno::MLINK || errno == Errno::NOTDIR {
            LockError::RefusedSymlink(dir.to_path_buf())
        } else {
            LockError::Unavailable(format!("could not open `{}`: {errno}", dir.display()))
        }
    })
}

/// Opens the directory holding `path`, so the lock file is taken relative to
/// a descriptor rather than by a path resolved a second time.
///
/// Deliberately *without* `O_NOFOLLOW`. The only caller is [`lock_file`], and
/// the only path it is given is `.config.lock`, whose parent is the
/// configuration directory — a directory the user names, and one that a
/// dotfile manager may well have made a symlink. Everything else in the store
/// resolves it normally (`Paths::ensure_dirs`, the config writer), so refusing
/// it only here would half-support a layout rather than support or reject it.
/// Nothing is gained security-wise either: an attacker who can plant a link at
/// the configured path could equally plant a real directory there.
fn open_parent_dir(path: &Path) -> Result<OwnedFd, LockError> {
    let parent = path.parent().ok_or_else(|| {
        LockError::Unavailable(format!("`{}` has no parent directory", path.display()))
    })?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
    rustix::fs::open(parent, flags, Mode::empty()).map_err(|errno| {
        LockError::Unavailable(format!("could not open `{}`: {errno}", parent.display()))
    })
}

#[cfg(test)]
#[path = "namespace_lock_tests.rs"]
mod tests;
