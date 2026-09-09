//! agentctl's own credential file: reading it, replacing it atomically, and
//! recovering when the replacement did not land.
//!
//! The file is `<config_dir>/claude/<acct>/<org>/.credentials.json`, in
//! Claude Code's on-disk shape (decision D-009, fact F40), so that phase 2
//! can point a Claude Code session at the directory and have it work. That
//! choice is what makes the read rules here worth stating precisely.
//!
//! # Absent is not the same as failed
//!
//! `ENOENT`, `EISDIR`, `ENOTDIR`, `EACCES` and `EPERM` mean *absent* — there
//! is nothing here to read, which for a fresh namespace is the normal state.
//! Everything else means *failed*, and in particular a symlink or an
//! oversized file is a failure, never an absence (plan AC46). The difference
//! matters because "absent" leads to `needs login` and eventually to writing
//! a new file over that path, and a symlink pointing somewhere else is
//! exactly the case where writing would be wrong.
//!
//! # The write is not allowed to be creative
//!
//! [`write_credentials`] validates the target is under
//! [`Paths::namespace_root`](crate::config::paths::Paths::namespace_root)
//! *before* it does anything (invariant I1), writes to `<path>.tmp.<8 hex>`
//! with `O_EXCL` at 0600, `fsync`s, and renames. There is no in-place
//! fallback: Claude Code has one (fact F40) and it is the right call for a
//! program that must not fail to save a login, but a truncate-then-write of a
//! credentials file is a window in which a crash leaves no credentials at all.
//! agentctl would rather leave the old file in place and hand the new one to
//! the next run, which is what [`WriteOutcome::SavedToPending`] is.
//!
//! # The path check and the directory walk are two different checks
//!
//! [`Paths::is_under_namespace_root`](crate::config::paths::Paths::is_under_namespace_root)
//! is lexical: it says what a path *spells*, not where it *points*. On its own
//! it does not stop a symlinked `<acct>` or `<org>` component from redirecting
//! a write — or a delete — into a running Claude Code's store, which is a
//! directory another local process can create before agentctl first writes
//! there. So every mutation in this module goes through
//! [`open_namespace_dir`], which walks down from the namespace root one
//! component at a time with `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` and then
//! performs the leaf operation relative to the descriptor it returns. A link
//! anywhere along the chain is [`FileStoreError::RefusedSymlink`], and a
//! component swapped for a link *after* the walk cannot redirect anything,
//! because there is no path left to re-resolve.
//!
//! # Pending
//!
//! When the rename fails, the new credentials are still valid and the old
//! ones may already have been invalidated by the refresh. Throwing them away
//! would cost the user a login. So they are parked as
//! `.credentials.json.pending`, alongside a `.pending.meta` recording the
//! digests of the file they were derived from — written *before* the pending
//! file, so a crash between the two leaves a meta with no pending, which
//! resolves to "nothing to do" rather than to a replay of unknown data.
//! [`resolve_pending`] implements the decision table from plan section 3.3.

#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "remaining items are consumed by W2 (accounts, import, doctor) and W3 (watch)"
    )
)]

use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Write;
use std::os::fd::AsFd;
use std::os::fd::BorrowedFd;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

use rustix::fs::AtFlags;
use rustix::fs::CWD;
use rustix::fs::FileType;
use rustix::fs::Mode;
use rustix::fs::OFlags;
use rustix::io::Errno;
use serde::Deserialize;
use serde::Serialize;

use crate::config::paths::DIR_MODE;
use crate::config::paths::Paths;
use crate::provider::claude::credentials::Credentials;
use crate::provider::claude::credentials::Digests;
use crate::runtime::cleanup;
use crate::runtime::coordinator::PassCtx;
use crate::runtime::fault::Fault;
use crate::secret::foreign_activity::ForeignActivity;

/// The largest credentials file that will be read (fact F40).
pub const MAX_CREDENTIALS_BYTES: u64 = 1 << 20;

/// The largest pending-metadata file that will be read.
pub const MAX_META_BYTES: u64 = 4096;

/// The credential file's name, chosen to match Claude Code (decision D-009).
pub const CREDENTIALS_FILE: &str = ".credentials.json";

/// Where credentials wait when a rename failed.
pub const PENDING_FILE: &str = ".credentials.json.pending";

/// What the pending credentials were derived from.
pub const PENDING_META: &str = ".pending.meta";

/// The mode every file this module creates ends up with.
const FILE_MODE_BITS: Mode = Mode::RUSR.union(Mode::WUSR);

/// Enough of a file's identity to notice it changed underneath us.
///
/// Size and mtime alone would miss a same-size rewrite inside one mtime
/// granularity; the device and inode catch a replacement. Claude Code
/// fingerprints its own store the same way (fact F16), which is not a
/// coincidence — this is the check that runs immediately before the rename.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileSnapshot {
    /// Device number.
    pub dev: u64,
    /// Inode number.
    pub ino: u64,
    /// Size in bytes.
    pub size: u64,
    /// Modification time in nanoseconds since the epoch.
    pub mtime_ns: i128,
}

/// What a credential read found.
#[derive(Debug)]
pub enum ReadOutcome {
    /// There is nothing at that path to read.
    Absent,
    /// The file was read.
    Present {
        /// Its contents.
        bytes: Vec<u8>,
        /// Its identity at the moment it was read.
        snap: FileSnapshot,
    },
}

/// Why a credential file could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum FileStoreError {
    /// The path, or a directory on the way to it, is a symbolic link. Never
    /// followed, never overwritten.
    #[error("`{0}` is a symbolic link; agentctl will not read or write through one")]
    RefusedSymlink(PathBuf),
    /// The path exists but is not what belongs there: a credentials or
    /// metadata file must be a regular file, and a component of the namespace
    /// directory must be a directory.
    #[error("`{0}` is not the plain file or directory that belongs at that path")]
    NotRegular(PathBuf),
    /// The file is larger than the format allows.
    #[error("`{path}` is {size} bytes, larger than the {limit}-byte limit")]
    TooLarge {
        /// The offending path.
        path: PathBuf,
        /// Its size.
        size: u64,
        /// The limit it broke.
        limit: u64,
    },
    /// The path is not inside this store's namespace root (invariant I1).
    #[error("`{0}` is outside the agentctl namespace root; refusing to write")]
    OutsideNamespaceRoot(PathBuf),
    /// A directory that had to be empty was not. Reported rather than
    /// recursed: see [`remove_dir_under`].
    #[error("`{0}` is not empty")]
    NotEmpty(PathBuf),
    /// The pass was cancelled, or ran out of deadline, while the replacement
    /// was staged but not yet renamed into place.
    #[error("cancelled before `{0}` could be replaced")]
    Cancelled(PathBuf),
    /// An underlying filesystem call failed.
    #[error("{context}")]
    Io {
        /// What was being attempted.
        context: String,
        /// The operating-system error.
        #[source]
        source: io::Error,
    },
    /// A JSON document in the namespace could not be parsed.
    #[error("{0}")]
    Json(String),
}

impl FileStoreError {
    /// Wraps an [`io::Error`] with what was being attempted.
    fn io(context: impl Into<String>, source: io::Error) -> Self {
        Self::Io { context: context.into(), source }
    }

    /// Wraps a `rustix` errno with what was being attempted.
    fn errno(context: impl Into<String>, errno: Errno) -> Self {
        Self::io(context, as_io_error(errno))
    }
}

/// A `rustix` errno as the [`io::Error`] the rest of the crate speaks.
fn as_io_error(errno: Errno) -> io::Error {
    io::Error::from_raw_os_error(errno.raw_os_error())
}

/// `O_NOFOLLOW` reports a symlink as `ELOOP` on Linux and macOS, and as
/// `EMLINK` on some BSDs.
fn is_symlink_errno(errno: Errno) -> bool {
    errno == Errno::LOOP || errno == Errno::MLINK
}

/// The identity of an already-opened file.
fn snapshot_of(meta: &fs::Metadata) -> FileSnapshot {
    FileSnapshot {
        dev: meta.dev(),
        ino: meta.ino(),
        size: meta.size(),
        // Seconds and nanoseconds are combined explicitly rather than through
        // `SystemTime`, which cannot represent a pre-epoch mtime on every
        // platform. `i128` makes the multiplication exact for any `i64`
        // second count, so there is nothing to check.
        mtime_ns: i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec()),
    }
}

/// `lstat`s a path.
///
/// Returns `Ok(None)` when nothing is there, and an error when the path is a
/// symbolic link: every caller of this is about to decide whether to trust or
/// replace the file, and a link is a decision to refuse, not to follow.
///
/// # Errors
///
/// Returns the underlying [`io::Error`], or an `InvalidInput` error naming
/// the link.
pub fn snapshot(path: &Path) -> io::Result<Option<FileSnapshot>> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    if meta.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("`{}` is a symbolic link", path.display()),
        ));
    }
    Ok(Some(snapshot_of(&meta)))
}

/// [`snapshot`] for a file agentctl only ever reads and never writes, such as
/// Claude Code's own `.claude.json`: symbolic links are followed, because on
/// this machine `~/.claude.json` *is* one (fact F41) and refusing it would
/// blind the live row rather than protect anything.
///
/// # Errors
///
/// Returns the underlying `stat` error for anything other than a missing file.
pub fn snapshot_following(path: &Path) -> io::Result<Option<FileSnapshot>> {
    match fs::metadata(path) {
        Ok(meta) => Ok(Some(snapshot_of(&meta))),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

/// [`read_file`] for a file agentctl only ever reads and never writes: the
/// same regular-file and size rules, but a symbolic link is followed rather
/// than refused (see [`snapshot_following`]).
///
/// # Errors
///
/// Returns [`FileStoreError`] for a non-regular target, an oversized file, or
/// any errno outside the absent set.
pub fn read_file_following(path: &Path, limit: u64) -> Result<ReadOutcome, FileStoreError> {
    let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let fd = match rustix::fs::open(path, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(errno) => return classify_open(path, errno),
    };
    read_opened(File::from(fd), path, limit)
}

/// Reads `<ns_dir>/.credentials.json` under the fact-F40 rules.
///
/// # Errors
///
/// Returns [`FileStoreError`] for a symlink, a non-regular file, an oversized
/// file, or any errno outside the absent set.
pub fn read_credentials(ns_dir: &Path) -> Result<ReadOutcome, FileStoreError> {
    read_file(&ns_dir.join(CREDENTIALS_FILE), MAX_CREDENTIALS_BYTES)
}

/// Opens a file with `O_NOFOLLOW` and reads it, applying the size limit.
///
/// The size limit is the caller's, because the callers differ by three orders
/// of magnitude: a credentials blob is capped at
/// [`MAX_CREDENTIALS_BYTES`], its metadata at [`MAX_META_BYTES`], and
/// `.claude.json` — which a Claude Code session grows without bound — at
/// [`crate::provider::claude::discovery::MAX_CLAUDE_JSON_BYTES`].
///
/// # Errors
///
/// Returns [`FileStoreError`] for a symlink, a non-regular file, an oversized
/// file, or any errno outside the absent set of fact F40.
pub fn read_file(path: &Path, limit: u64) -> Result<ReadOutcome, FileStoreError> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let fd = match rustix::fs::open(path, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(errno) => return classify_open(path, errno),
    };
    read_opened(File::from(fd), path, limit)
}

/// [`read_file`], relative to an already-opened namespace directory.
fn read_file_at(
    dir: BorrowedFd<'_>,
    name: &str,
    limit: u64,
    display: &Path,
) -> Result<ReadOutcome, FileStoreError> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let fd = match rustix::fs::openat(dir, name, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(errno) => return classify_open(display, errno),
    };
    read_opened(File::from(fd), display, limit)
}

/// Applies the regular-file and size rules to an open descriptor.
fn read_opened(mut file: File, path: &Path, limit: u64) -> Result<ReadOutcome, FileStoreError> {
    let meta = file
        .metadata()
        .map_err(|err| FileStoreError::io(format!("could not stat `{}`", path.display()), err))?;
    if !meta.is_file() {
        return Err(FileStoreError::NotRegular(path.to_path_buf()));
    }
    if meta.size() > limit {
        return Err(FileStoreError::TooLarge {
            path: path.to_path_buf(),
            size: meta.size(),
            limit,
        });
    }

    // Bounded by one byte past the limit so a file that grew between the stat
    // and the read is caught rather than read unboundedly.
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|err| FileStoreError::io(format!("could not read `{}`", path.display()), err))?;
    let read = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if read > limit {
        return Err(FileStoreError::TooLarge { path: path.to_path_buf(), size: read, limit });
    }

    Ok(ReadOutcome::Present { bytes, snap: snapshot_of(&meta) })
}

/// Maps an `open` failure onto absent, refused, or failed (fact F40).
///
/// Spelled as comparisons rather than as match arms because `rustix`'s errno
/// values are associated constants on a newtype, which cannot appear in
/// patterns.
fn classify_open(path: &Path, errno: Errno) -> Result<ReadOutcome, FileStoreError> {
    let absent = [Errno::NOENT, Errno::ISDIR, Errno::NOTDIR, Errno::ACCESS, Errno::PERM];
    if absent.contains(&errno) {
        return Ok(ReadOutcome::Absent);
    }
    if is_symlink_errno(errno) {
        return Err(FileStoreError::RefusedSymlink(path.to_path_buf()));
    }
    Err(FileStoreError::errno(format!("could not open `{}`", path.display()), errno))
}

/// What a write did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteOutcome {
    /// The new credentials are in place.
    Written {
        /// The identity of the file that now holds them.
        snap: FileSnapshot,
    },
    /// The rename failed; the credentials are parked as pending.
    SavedToPending {
        /// The rename failure, for the user-facing row.
        error: String,
    },
}

/// Everything one credential write needs.
pub struct WriteRequest<'a> {
    /// This store, for the namespace-root check.
    pub paths: &'a Paths,
    /// The namespace directory to write into.
    pub ns_dir: &'a Path,
    /// The serialized blob, from
    /// [`Credentials::to_blob_json`](crate::provider::claude::credentials::Credentials::to_blob_json).
    pub blob_json: &'a str,
    /// The digests of the file these credentials were derived from, or `None`
    /// on a first write. Recorded in the pending metadata.
    pub prior: Option<&'a Digests>,
    /// The new access-token expiry, recorded in the pending metadata.
    pub new_expires_at_ms: i64,
    /// Injected faults, if any.
    pub fault: Fault,
}

/// Replaces a namespace's credentials atomically.
///
/// # Errors
///
/// Returns [`FileStoreError::OutsideNamespaceRoot`] when the target is not
/// under the namespace root, [`FileStoreError::RefusedSymlink`] or
/// [`FileStoreError::NotRegular`] when the existing target — or any directory
/// on the way to it — is not a plain file or a plain directory,
/// [`FileStoreError::Cancelled`] when the pass stopped while the replacement
/// was staged, and [`FileStoreError::Io`] for a filesystem failure. A failed
/// *rename* is not an error: it returns [`WriteOutcome::SavedToPending`].
pub fn write_credentials(
    req: &WriteRequest<'_>,
    ctx: &PassCtx,
) -> Result<WriteOutcome, FileStoreError> {
    let target = req.ns_dir.join(CREDENTIALS_FILE);
    if !req.paths.is_under_namespace_root(&target) {
        return Err(FileStoreError::OutsideNamespaceRoot(target));
    }

    let dir = open_namespace_dir(req.paths, req.ns_dir)?;
    let dir = dir.as_fd();

    // Refuse before creating anything: a symlink at the target means somebody
    // else is managing this path and the rename would land somewhere unknown.
    match entry_at(dir, CREDENTIALS_FILE, &target)? {
        Entry::Absent | Entry::Regular => {}
        Entry::Symlink => return Err(FileStoreError::RefusedSymlink(target)),
        Entry::Other => return Err(FileStoreError::NotRegular(target)),
    }

    let tmp_name = format!("{CREDENTIALS_FILE}.tmp.{}", hex8());
    let tmp = req.ns_dir.join(&tmp_name);
    let token = cleanup::register_tmp_path(tmp.clone());
    if let Err(err) = create_new_file_at(dir, &tmp_name, req.blob_json.as_bytes()) {
        let _ = unlink_at(dir, &tmp_name);
        cleanup::unregister(token);
        return Err(FileStoreError::io(format!("could not write `{}`", tmp.display()), err));
    }

    // The window plan AC21's third clause aims at: the POST has returned, the
    // new credentials are on disk, and the namespace has not yet been
    // replaced. A Claude Code session appearing here is the case the caller
    // must re-check for before it renames.
    req.fault.pause_point("before_rename");

    // The same window is the last moment at which a cancelled pass can leave
    // the namespace exactly as it found it: after the rename there is nothing
    // left to undo, and before the write there is nothing to gain.
    if ctx.should_stop() {
        let _ = unlink_at(dir, &tmp_name);
        cleanup::unregister(token);
        return Err(FileStoreError::Cancelled(target));
    }

    let rename = if req.fault.is("rename_fail") {
        Err(io::Error::new(
            io::ErrorKind::CrossesDevices,
            // The variable's name is deliberately not spelled here: this
            // literal is in code the default-feature build compiles, so
            // naming it would put a test-only environment variable into the
            // release artifact (plan AC37). `crate::runtime::fault` documents
            // which switch reaches this.
            "rename failure injected by the test fault switch",
        ))
    } else {
        rustix::fs::renameat(dir, tmp_name.as_str(), dir, CREDENTIALS_FILE).map_err(as_io_error)
    };

    match rename {
        Ok(()) => {
            // The mode was set on the temporary file's inode, which the rename
            // carries over, so there is nothing left to chmod here.
            let snap = snapshot_at(dir, CREDENTIALS_FILE, &target);
            cleanup::unregister(token);
            match snap {
                Ok(Some(snap)) => Ok(WriteOutcome::Written { snap }),
                Ok(None) => Err(FileStoreError::io(
                    format!("`{}` vanished immediately after being written", target.display()),
                    io::Error::from(io::ErrorKind::NotFound),
                )),
                Err(err) => Err(err),
            }
        }
        Err(err) => {
            let outcome = save_to_pending(req, dir, &tmp_name, &err);
            cleanup::unregister(token);
            outcome
        }
    }
}

/// Parks a written temporary file as `.credentials.json.pending`.
///
/// The metadata goes first, deliberately. A crash between the two leaves a
/// meta with no pending file, which [`resolve_pending`] reads as "nothing to
/// replay"; the other order would leave credentials with no record of what
/// they were derived from, which is unreplayable *and* indistinguishable from
/// a valid pending.
fn save_to_pending(
    req: &WriteRequest<'_>,
    dir: BorrowedFd<'_>,
    tmp_name: &str,
    cause: &io::Error,
) -> Result<WriteOutcome, FileStoreError> {
    let meta = PendingMeta {
        derived_from_access_sha256: req.prior.map(|d| d.access_sha256.clone()),
        derived_from_refresh_sha256: req.prior.and_then(|d| d.refresh_sha256.clone()),
        created_at: jiff::Timestamp::now().to_string(),
        new_expires_at: req.new_expires_at_ms,
    };
    let meta_json = serde_json::to_string(&meta).map_err(|err| {
        FileStoreError::Json(format!("could not serialize pending metadata: {err}"))
    })?;

    let meta_path = req.ns_dir.join(PENDING_META);
    let _ = unlink_at(dir, PENDING_META);
    if let Err(err) = create_new_file_at(dir, PENDING_META, meta_json.as_bytes()) {
        let _ = unlink_at(dir, tmp_name);
        return Err(FileStoreError::io(format!("could not write `{}`", meta_path.display()), err));
    }

    let pending = req.ns_dir.join(PENDING_FILE);
    let _ = unlink_at(dir, PENDING_FILE);
    if let Err(errno) = rustix::fs::renameat(dir, tmp_name, dir, PENDING_FILE) {
        let _ = unlink_at(dir, tmp_name);
        let _ = unlink_at(dir, PENDING_META);
        return Err(FileStoreError::errno(
            format!("could not park credentials at `{}`", pending.display()),
            errno,
        ));
    }

    Ok(WriteOutcome::SavedToPending { error: cause.to_string() })
}

/// What `.credentials.json.pending` was derived from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingMeta {
    /// `sha256` of the access token in the file this replaced, or `null` when
    /// there was no file (a first write).
    pub derived_from_access_sha256: Option<String>,
    /// `sha256` of that file's refresh token.
    pub derived_from_refresh_sha256: Option<String>,
    /// When the pending file was created, RFC 3339.
    pub created_at: String,
    /// The new access token's expiry, in milliseconds since the epoch.
    pub new_expires_at: i64,
}

/// What resolving a pending file decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingDecision {
    /// There was nothing pending.
    NoPending,
    /// The pending credentials were moved into place.
    Replayed {
        /// Whether they were parked before any file existed.
        first_write: bool,
    },
    /// The pending credentials were deleted unused.
    Discarded(PendingDiscardReason),
}

/// Why a pending file was discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingDiscardReason {
    /// The metadata was missing, unparseable, or one of the files was not a
    /// plain file of a sane size.
    Invalid,
    /// A Claude Code session or a keychain migration has taken the namespace
    /// over since the pending file was written.
    NamespaceTakenOver,
    /// The credentials file changed since the pending file was derived from
    /// it, so replaying would undo that change.
    FileChanged,
    /// The credentials file was removed, and the pending file was derived
    /// from one that existed.
    FileRemoved,
}

impl PendingDiscardReason {
    /// The reason as it appears in the state column.
    pub fn label(self) -> &'static str {
        match self {
            Self::Invalid => "invalid",
            Self::NamespaceTakenOver => "namespace taken over",
            Self::FileChanged => "file changed",
            Self::FileRemoved => "file removed",
        }
    }
}

/// Applies the pending decision table from plan section 3.3.
///
/// # Errors
///
/// Returns [`FileStoreError`] only for failures that leave the namespace in
/// an unknown state — including a symlinked `<acct>` or `<org>` component,
/// which would make the replay land outside the store; every *decidable*
/// outcome — including a corrupt or hostile pending file — is a
/// [`PendingDecision`].
pub fn resolve_pending(
    ns_dir: &Path,
    foreign: &ForeignActivity,
) -> Result<PendingDecision, FileStoreError> {
    let Some(dir) = open_ns_dir(ns_dir)? else { return Ok(PendingDecision::NoPending) };
    let dir = dir.as_fd();

    let pending_path = ns_dir.join(PENDING_FILE);
    let meta_path = ns_dir.join(PENDING_META);
    let current_path = ns_dir.join(CREDENTIALS_FILE);

    // A meta with no pending file is the crash window described in
    // `save_to_pending`: there is nothing to replay, so clear the marker.
    if matches!(entry_at(dir, PENDING_FILE, &pending_path)?, Entry::Absent) {
        let _ = unlink_at(dir, PENDING_META);
        return Ok(PendingDecision::NoPending);
    }

    // Absent here means the path is a directory or unreadable, which is as
    // invalid as a corrupt file; so is a symlink, so every failure collapses.
    let pending = match read_file_at(dir, PENDING_FILE, MAX_CREDENTIALS_BYTES, &pending_path) {
        Ok(ReadOutcome::Present { bytes, .. }) => Some(bytes),
        _ => None,
    };
    let meta = match read_file_at(dir, PENDING_META, MAX_META_BYTES, &meta_path) {
        Ok(ReadOutcome::Present { bytes, .. }) => {
            serde_json::from_slice::<PendingMeta>(&bytes).ok()
        }
        _ => None,
    };

    let (Some(pending_bytes), Some(meta)) = (pending, meta) else {
        return discard(dir, PendingDiscardReason::Invalid);
    };
    if Credentials::parse_blob(&pending_bytes).is_err() {
        return discard(dir, PendingDiscardReason::Invalid);
    }

    if !matches!(foreign, ForeignActivity::None) {
        return discard(dir, PendingDiscardReason::NamespaceTakenOver);
    }

    let current = match read_file_at(dir, CREDENTIALS_FILE, MAX_CREDENTIALS_BYTES, &current_path) {
        Ok(ReadOutcome::Present { bytes, .. }) => Credentials::parse_blob(&bytes).ok(),
        Ok(ReadOutcome::Absent) => None,
        // An unreadable current file is not something to overwrite blindly.
        Err(err) => return Err(err),
    };

    match current {
        Some(current) => {
            let digests = current.digests();
            let matches = meta.derived_from_access_sha256.as_deref()
                == Some(digests.access_sha256.as_str())
                && meta.derived_from_refresh_sha256 == digests.refresh_sha256;
            if matches {
                replay(dir, ns_dir, false)
            } else {
                discard(dir, PendingDiscardReason::FileChanged)
            }
        }
        None if meta.derived_from_access_sha256.is_none()
            && meta.derived_from_refresh_sha256.is_none() =>
        {
            replay(dir, ns_dir, true)
        }
        None => discard(dir, PendingDiscardReason::FileRemoved),
    }
}

/// Moves the pending file into place and clears the metadata.
///
/// The mode is set on the pending file *before* the rename, because a rename
/// carries the inode and its mode across, and chmod-after-rename would be a
/// second lookup of a name that is now the live credentials file.
fn replay(
    dir: BorrowedFd<'_>,
    ns_dir: &Path,
    first_write: bool,
) -> Result<PendingDecision, FileStoreError> {
    let pending_path = ns_dir.join(PENDING_FILE);
    chmod_0600_at(dir, PENDING_FILE, &pending_path)?;
    rustix::fs::renameat(dir, PENDING_FILE, dir, CREDENTIALS_FILE).map_err(|errno| {
        FileStoreError::errno(format!("could not replay `{}`", pending_path.display()), errno)
    })?;
    let _ = unlink_at(dir, PENDING_META);
    Ok(PendingDecision::Replayed { first_write })
}

/// Deletes both pending files and reports why.
fn discard(
    dir: BorrowedFd<'_>,
    reason: PendingDiscardReason,
) -> Result<PendingDecision, FileStoreError> {
    let _ = unlink_at(dir, PENDING_FILE);
    let _ = unlink_at(dir, PENDING_META);
    Ok(PendingDecision::Discarded(reason))
}

/// Removes a namespace's files and then its directories.
///
/// The lock file is untouched: it lives outside the namespace, is never
/// unlinked, and removing it would break `flock`'s inode semantics for
/// whoever is waiting on it (plan section 3.5).
///
/// # Errors
///
/// Returns [`FileStoreError::OutsideNamespaceRoot`] when `ns_dir` is not
/// under the namespace root, [`FileStoreError::RefusedSymlink`] when a
/// component of it is a link — deleting *through* one is the same escape as
/// writing through one — and [`FileStoreError::Io`] for a removal that failed
/// for a reason other than the file already being gone.
pub fn remove_namespace(paths: &Paths, ns_dir: &Path) -> Result<(), FileStoreError> {
    if !paths.is_under_namespace_root(ns_dir) {
        return Err(FileStoreError::OutsideNamespaceRoot(ns_dir.to_path_buf()));
    }

    let root = paths.namespace_root();
    let Some(chain) = open_chain(&root, ns_dir, Walk::MustExist)? else { return Ok(()) };
    let Some(leaf) = chain.last() else { return Ok(()) };

    let mut names: Vec<OsString> =
        vec![CREDENTIALS_FILE.into(), PENDING_FILE.into(), PENDING_META.into()];
    let stray = list_stray_tmp(ns_dir)
        .map_err(|err| FileStoreError::io(format!("could not list `{}`", ns_dir.display()), err))?;
    names.extend(stray.iter().filter_map(|path| path.file_name().map(OsStr::to_os_string)));

    for name in names {
        match rustix::fs::unlinkat(&leaf.fd, name.as_os_str(), AtFlags::empty()) {
            Ok(()) => {}
            Err(errno) if errno == Errno::NOENT => {}
            Err(errno) => {
                return Err(FileStoreError::errno(
                    format!("could not remove `{}`", ns_dir.join(&name).display()),
                    errno,
                ));
            }
        }
    }

    // Climb toward the namespace root, removing directories that are now
    // empty. `AT_REMOVEDIR` refuses a non-empty directory, which is the check
    // wanted here: a sibling organization's namespace must survive. Index 0 is
    // the root itself, which is never removed.
    for index in (1..chain.len()).rev() {
        let Some(name) = chain[index].name.as_ref() else { break };
        let removed =
            rustix::fs::unlinkat(&chain[index - 1].fd, name.as_os_str(), AtFlags::REMOVEDIR);
        if removed.is_err() {
            break;
        }
    }
    Ok(())
}

/// Lists leftover `.credentials.json.tmp.<8 hex>` files.
///
/// A stray one is a crashed write, and it holds token material at rest, so
/// `doctor` reports them and `login`/`remove` clean them up (risk R24).
///
/// # Errors
///
/// Returns the underlying [`io::Error`], except that a missing directory is
/// an empty list.
pub fn list_stray_tmp(ns_dir: &Path) -> io::Result<Vec<PathBuf>> {
    let prefix = format!("{CREDENTIALS_FILE}.tmp.");
    let entries = match fs::read_dir(ns_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };

    let mut found = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(suffix) = name.strip_prefix(&prefix) else { continue };
        if suffix.len() == 8 && suffix.bytes().all(|b| b.is_ascii_hexdigit()) {
            found.push(entry.path());
        }
    }
    found.sort();
    Ok(found)
}

/// Eight random hex digits, for a temporary file name.
///
/// Shape taken from Claude Code's writer (fact F40) so a stray file is
/// recognisable by either tool. Collision is handled by `O_EXCL`, not by the
/// randomness.
pub fn hex8() -> String {
    format!("{:08x}", rand::random::<u32>())
}

/// Whether a walk may create the components it does not find.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Walk {
    /// Create a missing component with `mkdirat` at 0700.
    Create,
    /// A missing component ends the walk.
    MustExist,
}

/// One directory on the way from the namespace root down to a namespace.
struct DirStep {
    /// The open descriptor, never obtained by following a link.
    fd: OwnedFd,
    /// This directory's name within its parent; `None` for the root, which
    /// has no parent in the chain and is therefore never removed.
    name: Option<OsString>,
}

/// What `lstat`ing one name inside a namespace directory found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Entry {
    /// Nothing is there.
    Absent,
    /// A regular file.
    Regular,
    /// A symbolic link, whatever it points at.
    Symlink,
    /// Something else: a directory, a socket, a device.
    Other,
}

/// Opens a namespace directory without ever following a symbolic link.
///
/// The walk starts at [`Paths::namespace_root`] — after that directory and
/// the configuration directory above it have been created — and descends one
/// component at a time with `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`, creating
/// what is missing with `mkdirat` at 0700. The returned descriptor is what
/// every subsequent operation on the namespace is performed relative to, so
/// no later operation re-resolves a path that could have changed underneath
/// it.
///
/// # Errors
///
/// Returns [`FileStoreError::RefusedSymlink`] for a link anywhere along the
/// chain, [`FileStoreError::NotRegular`] for a component that exists but is
/// not a directory, [`FileStoreError::OutsideNamespaceRoot`] when `ns_dir`
/// does not spell a path below the root, and [`FileStoreError::Io`]
/// otherwise.
pub fn open_namespace_dir(paths: &Paths, ns_dir: &Path) -> Result<OwnedFd, FileStoreError> {
    // The two levels above the namespace root are this store's own roots, and
    // `Paths::ensure_dirs` may not have run yet (`login` creates the store on
    // its first use). They are created by path; the walk below then refuses a
    // link *at* the root, so a redirected root is caught either way.
    create_dir_0700(paths.config_dir())?;
    let root = paths.namespace_root();
    create_dir_0700(&root)?;

    let chain = open_chain(&root, ns_dir, Walk::Create)?.ok_or_else(|| {
        FileStoreError::io(
            format!("`{}` vanished while it was being created", ns_dir.display()),
            io::Error::from(io::ErrorKind::NotFound),
        )
    })?;
    let leaf = chain
        .into_iter()
        .next_back()
        .ok_or_else(|| FileStoreError::OutsideNamespaceRoot(ns_dir.to_path_buf()))?;
    Ok(leaf.fd)
}

/// Removes one empty *directory* under the namespace root, resolving the way
/// to it without ever following a symbolic link.
///
/// `doctor --remove-stale` is the only caller, and it is the only thing in
/// agentctl that removes a lock artefact at all. Its own path check is
/// lexical — it compares spellings — and a lexical check cannot see a
/// symbolic link planted at `<acct>` or `<org>`:
/// `<root>/<acct>/<org>/.oauth_refresh.lock` spells a location under the root
/// while naming Claude Code's live lock in the user's home directory, which is
/// exactly what invariant I11′ exists to protect. So the parent is walked down
/// from the root one `O_NOFOLLOW` component at a time and the artefact is
/// removed relative to the descriptor that walk produced — a directory nothing
/// could have redirected between the check and the removal.
///
/// This replaced a phase-1 `remove_file_under_root` that unlinked *without*
/// `AT_REMOVEDIR`, which could not remove a lock artefact at all: every one of
/// them is a directory (`agentctl-nz5`, fact F45). Nothing else in the crate
/// needed the file version, so it is gone rather than left as a second, wrong
/// way to do this.
///
/// # Errors
///
/// [`FileStoreError::OutsideNamespaceRoot`] when the path does not spell a
/// location under
/// [`Paths::namespace_root`](crate::config::paths::Paths::namespace_root), and
/// otherwise as [`remove_dir_under`] anchored there.
pub fn remove_dir_under_root(paths: &Paths, path: &Path) -> Result<(), FileStoreError> {
    // Stated here rather than left to the walk's `strip_prefix`, which cannot
    // answer until the root itself exists — and "is this mine to remove?" is
    // not a question whose answer should depend on that.
    if !paths.is_under_namespace_root(path) {
        return Err(FileStoreError::OutsideNamespaceRoot(path.to_path_buf()));
    }
    remove_dir_under(&paths.namespace_root(), path)
}

/// [`remove_dir_under_root`] with the `O_NOFOLLOW` walk anchored elsewhere.
///
/// `doctor --remove-stale` uses the other anchor for the single path outside
/// the namespace root it will act on: a lock directory a crashed agentctl left
/// in the store it was holding, named by a held-lock record whose process is
/// dead (plan section 3.9). That anchor is the record's store directory's
/// *parent*, which leaves both components the record cannot vouch for — the
/// store directory and the artefact name — to be walked and refused here.
///
/// Nothing recurses. `AT_REMOVEDIR` fails with `ENOTEMPTY` on a directory with
/// anything inside it, and that is reported: a lock directory holding a file
/// is not the empty artefact a lapsed lock leaves, and removing a tree is not
/// something this command may do. `AT_REMOVEDIR` also refuses anything that is
/// not a directory, so a regular file or a symbolic link at the final
/// component arrives as [`FileStoreError::NotRegular`] rather than being
/// deleted.
///
/// # Errors
///
/// [`FileStoreError::RefusedSymlink`] for a link anywhere along the chain,
/// [`FileStoreError::OutsideNamespaceRoot`] when the path does not spell a
/// location below `anchor`, [`FileStoreError::NotEmpty`] for a directory with
/// anything in it, [`FileStoreError::NotRegular`] when the final component is
/// not a directory, and [`FileStoreError::Io`] when the parent is not there or
/// the removal itself fails.
pub fn remove_dir_under(anchor: &Path, path: &Path) -> Result<(), FileStoreError> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(FileStoreError::OutsideNamespaceRoot(path.to_path_buf()));
    };
    let Some(chain) = open_chain(anchor, parent, Walk::MustExist)? else {
        return Err(FileStoreError::io(
            format!("`{}` is not there", parent.display()),
            io::Error::from(io::ErrorKind::NotFound),
        ));
    };
    let leaf = chain
        .into_iter()
        .next_back()
        .ok_or_else(|| FileStoreError::OutsideNamespaceRoot(path.to_path_buf()))?;
    rustix::fs::unlinkat(&leaf.fd, name, AtFlags::REMOVEDIR).map_err(|errno| match errno {
        Errno::NOTEMPTY => FileStoreError::NotEmpty(path.to_path_buf()),
        // Every parent was opened with `O_DIRECTORY`, so at this point
        // `ENOTDIR` can only be about `name` itself: a regular file, a socket,
        // or a symbolic link, none of which `AT_REMOVEDIR` will touch.
        // `EISDIR` is the same refusal on the platforms that spell it that way.
        Errno::NOTDIR | Errno::ISDIR => FileStoreError::NotRegular(path.to_path_buf()),
        other => FileStoreError::errno(format!("could not remove `{}`", path.display()), other),
    })
}

/// Opens `ns_dir` for an operation that was not handed the [`Paths`] it came
/// from.
///
/// [`resolve_pending`]'s signature carries only the namespace directory, so
/// the walk is anchored at that path's grandparent — which is
/// [`Paths::namespace_root`] for every path
/// [`Paths::namespace_dir`](crate::config::paths::Paths::namespace_dir)
/// builds — and therefore covers exactly the two components another process
/// could have planted, `<acct>` and `<org>`.
fn open_ns_dir(ns_dir: &Path) -> Result<Option<OwnedFd>, FileStoreError> {
    let Some(anchor) = ns_dir.parent().and_then(Path::parent) else {
        return Err(FileStoreError::OutsideNamespaceRoot(ns_dir.to_path_buf()));
    };
    let Some(chain) = open_chain(anchor, ns_dir, Walk::MustExist)? else { return Ok(None) };
    Ok(chain.into_iter().next_back().map(|step| step.fd))
}

/// Walks from `root` down to `ns_dir`, one `O_NOFOLLOW` component at a time.
///
/// Returns `Ok(None)` when a component is missing and the walk may not create
/// it. The returned chain always starts with `root` itself.
fn open_chain(
    root: &Path,
    ns_dir: &Path,
    walk: Walk,
) -> Result<Option<Vec<DirStep>>, FileStoreError> {
    let Some(root_fd) = open_dir_at(CWD, root.as_os_str(), root)? else { return Ok(None) };
    let mut chain = vec![DirStep { fd: root_fd, name: None }];

    let relative = ns_dir
        .strip_prefix(root)
        .map_err(|_| FileStoreError::OutsideNamespaceRoot(ns_dir.to_path_buf()))?;

    let mut shown = root.to_path_buf();
    for component in relative.components() {
        let name = match component {
            Component::CurDir => continue,
            Component::Normal(name) => name,
            _ => return Err(FileStoreError::OutsideNamespaceRoot(ns_dir.to_path_buf())),
        };
        shown.push(name);

        let child = {
            let parent = match chain.last() {
                Some(step) => step.fd.as_fd(),
                None => return Err(FileStoreError::OutsideNamespaceRoot(ns_dir.to_path_buf())),
            };
            match open_dir_at(parent, name, &shown)? {
                Some(fd) => fd,
                None if walk == Walk::Create => create_dir_at(parent, name, &shown)?,
                None => return Ok(None),
            }
        };
        chain.push(DirStep { fd: child, name: Some(name.to_os_string()) });
    }
    Ok(Some(chain))
}

/// Opens one directory relative to `dir`, refusing anything that is not one.
///
/// `shown` is the path the caller would recognise, used only for the error.
fn open_dir_at(
    dir: BorrowedFd<'_>,
    name: &OsStr,
    shown: &Path,
) -> Result<Option<OwnedFd>, FileStoreError> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    match rustix::fs::openat(dir, name, flags, Mode::empty()) {
        Ok(fd) => Ok(Some(fd)),
        Err(errno) if is_symlink_errno(errno) => {
            Err(FileStoreError::RefusedSymlink(shown.to_path_buf()))
        }
        // Darwin evaluates `O_DIRECTORY` against the link itself, so a
        // symlinked directory arrives as `ENOTDIR` rather than `ELOOP`, and a
        // dangling one can arrive as `ENOENT` — the two errnos that also have
        // innocent meanings. An `lstat` tells them apart. It is a second look
        // at the same name, but not a race worth worrying about: the open
        // already refused to traverse anything, so all this decides is which
        // error the caller is handed, and a name swapped in between still
        // cannot be walked through.
        Err(errno) if errno == Errno::NOTDIR || errno == Errno::NOENT => {
            match entry_at(dir, name, shown)? {
                Entry::Symlink => Err(FileStoreError::RefusedSymlink(shown.to_path_buf())),
                Entry::Absent => Ok(None),
                Entry::Regular | Entry::Other => {
                    Err(FileStoreError::NotRegular(shown.to_path_buf()))
                }
            }
        }
        Err(errno) => {
            Err(FileStoreError::errno(format!("could not open `{}`", shown.display()), errno))
        }
    }
}

/// Creates one directory relative to `dir` and opens it, both `O_NOFOLLOW`.
///
/// `mkdirat`'s mode argument is masked by the process umask, and this
/// directory holds refresh tokens (risk R22), so the mode is set again on the
/// descriptor rather than left to whatever the umask allowed.
fn create_dir_at(
    dir: BorrowedFd<'_>,
    name: &OsStr,
    shown: &Path,
) -> Result<OwnedFd, FileStoreError> {
    match rustix::fs::mkdirat(dir, name, Mode::RWXU) {
        Ok(()) => {}
        // Another process creating it first is a race agentctl wins by
        // re-opening rather than by failing; the re-open still refuses a link.
        Err(errno) if errno == Errno::EXIST => {}
        Err(errno) => {
            return Err(FileStoreError::errno(
                format!("could not create `{}`", shown.display()),
                errno,
            ));
        }
    }

    let fd = open_dir_at(dir, name, shown)?.ok_or_else(|| {
        FileStoreError::io(
            format!("`{}` vanished immediately after it was created", shown.display()),
            io::Error::from(io::ErrorKind::NotFound),
        )
    })?;
    rustix::fs::fchmod(&fd, Mode::RWXU).map_err(|errno| {
        FileStoreError::errno(format!("could not set the mode of `{}`", shown.display()), errno)
    })?;
    Ok(fd)
}

/// `lstat`s one name inside an already-opened namespace directory.
fn entry_at<P: rustix::path::Arg>(
    dir: BorrowedFd<'_>,
    name: P,
    shown: &Path,
) -> Result<Entry, FileStoreError> {
    match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Ok(match FileType::from_raw_mode(stat.st_mode) {
            FileType::RegularFile => Entry::Regular,
            FileType::Symlink => Entry::Symlink,
            _ => Entry::Other,
        }),
        Err(errno) if errno == Errno::NOENT => Ok(Entry::Absent),
        Err(errno) => {
            Err(FileStoreError::errno(format!("could not stat `{}`", shown.display()), errno))
        }
    }
}

/// The identity of one name inside an already-opened namespace directory.
fn snapshot_at(
    dir: BorrowedFd<'_>,
    name: &str,
    shown: &Path,
) -> Result<Option<FileSnapshot>, FileStoreError> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let fd = match rustix::fs::openat(dir, name, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(errno) if errno == Errno::NOENT => return Ok(None),
        Err(errno) if is_symlink_errno(errno) => {
            return Err(FileStoreError::RefusedSymlink(shown.to_path_buf()));
        }
        Err(errno) => {
            return Err(FileStoreError::errno(
                format!("could not open `{}`", shown.display()),
                errno,
            ));
        }
    };
    let meta = File::from(fd)
        .metadata()
        .map_err(|err| FileStoreError::io(format!("could not stat `{}`", shown.display()), err))?;
    Ok(Some(snapshot_of(&meta)))
}

/// Removes one name from an already-opened namespace directory.
fn unlink_at(dir: BorrowedFd<'_>, name: &str) -> io::Result<()> {
    rustix::fs::unlinkat(dir, name, AtFlags::empty()).map_err(as_io_error)
}

/// Sets one file's mode to 0600 without following a link at `name`.
fn chmod_0600_at(dir: BorrowedFd<'_>, name: &str, shown: &Path) -> Result<(), FileStoreError> {
    // `fchmodat`'s `AT_SYMLINK_NOFOLLOW` is unimplemented on Linux, so the
    // link is refused by the open instead and the mode set on the descriptor.
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let fd = rustix::fs::openat(dir, name, flags, Mode::empty()).map_err(|errno| {
        if is_symlink_errno(errno) {
            FileStoreError::RefusedSymlink(shown.to_path_buf())
        } else {
            FileStoreError::errno(format!("could not open `{}`", shown.display()), errno)
        }
    })?;
    rustix::fs::fchmod(&fd, FILE_MODE_BITS).map_err(|errno| {
        FileStoreError::errno(format!("could not set the mode of `{}`", shown.display()), errno)
    })
}

/// Creates one directory at [`DIR_MODE`], tolerating one that already exists.
///
/// Used only for this store's own two roots, which the `O_NOFOLLOW` walk
/// re-checks afterwards. Every level individually rather than
/// `create_dir_all`, which applies the umask and commonly leaves a directory
/// group-readable — a directory holding refresh tokens (risk R22).
fn create_dir_0700(dir: &Path) -> Result<(), FileStoreError> {
    if dir.is_dir() {
        return Ok(());
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, DIR_MODE);
    builder
        .create(dir)
        .map_err(|err| FileStoreError::io(format!("could not create `{}`", dir.display()), err))
}

/// Creates a file at 0600 with `O_EXCL` inside an already-opened directory,
/// writes it, and `fsync`s it.
///
/// `openat`'s mode argument is masked by the process umask, so the mode is set
/// again on the descriptor: this file holds a refresh token, and it is the
/// inode the rename will carry into place.
fn create_new_file_at(dir: BorrowedFd<'_>, name: &str, bytes: &[u8]) -> io::Result<()> {
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let fd = rustix::fs::openat(dir, name, flags, FILE_MODE_BITS).map_err(as_io_error)?;
    rustix::fs::fchmod(&fd, FILE_MODE_BITS).map_err(as_io_error)?;
    let mut file = File::from(fd);
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
#[path = "file_store_tests.rs"]
mod tests;
