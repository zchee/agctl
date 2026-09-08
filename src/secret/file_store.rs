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

#![cfg_attr(not(test), expect(dead_code, reason = "consumed by lane D and lane C"))]

use std::fs;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;

use rustix::fs::Mode;
use rustix::fs::OFlags;
use serde::Deserialize;
use serde::Serialize;

use crate::config::paths::FILE_MODE;
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
    /// The path is a symbolic link. Never followed, never overwritten.
    #[error("`{0}` is a symbolic link; agentctl will not read or write through one")]
    RefusedSymlink(PathBuf),
    /// The path exists but is not a regular file.
    #[error("`{0}` is not a regular file")]
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
    Ok(Some(FileSnapshot {
        dev: meta.dev(),
        ino: meta.ino(),
        size: meta.size(),
        // Seconds and nanoseconds are combined explicitly rather than through
        // `SystemTime`, which cannot represent a pre-epoch mtime on every
        // platform. `i128` makes the multiplication exact for any `i64`
        // second count, so there is nothing to check.
        mtime_ns: i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec()),
    }))
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
fn read_file(path: &Path, limit: u64) -> Result<ReadOutcome, FileStoreError> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    let fd = match rustix::fs::open(path, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(errno) => return classify_open(path, errno),
    };

    let mut file = File::from(fd);
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

    Ok(ReadOutcome::Present {
        bytes,
        snap: FileSnapshot {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.size(),
            mtime_ns: i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec()),
        },
    })
}

/// Maps an `open` failure onto absent, refused, or failed (fact F40).
///
/// Spelled as comparisons rather than as match arms because `rustix`'s errno
/// values are associated constants on a newtype, which cannot appear in
/// patterns.
fn classify_open(path: &Path, errno: rustix::io::Errno) -> Result<ReadOutcome, FileStoreError> {
    use rustix::io::Errno;

    let absent = [Errno::NOENT, Errno::ISDIR, Errno::NOTDIR, Errno::ACCESS, Errno::PERM];
    if absent.contains(&errno) {
        return Ok(ReadOutcome::Absent);
    }
    // `O_NOFOLLOW` on a symlink is ELOOP on macOS and EMLINK on some BSDs.
    if errno == Errno::LOOP || errno == Errno::MLINK {
        return Err(FileStoreError::RefusedSymlink(path.to_path_buf()));
    }
    Err(FileStoreError::io(
        format!("could not open `{}`", path.display()),
        io::Error::from_raw_os_error(errno.raw_os_error()),
    ))
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
/// [`FileStoreError::NotRegular`] when the existing target is not a plain
/// file, and [`FileStoreError::Io`] for a filesystem failure. A failed
/// *rename* is not an error: it returns
/// [`WriteOutcome::SavedToPending`].
pub fn write_credentials(
    req: &WriteRequest<'_>,
    _ctx: &PassCtx,
) -> Result<WriteOutcome, FileStoreError> {
    let target = req.ns_dir.join(CREDENTIALS_FILE);
    if !req.paths.is_under_namespace_root(&target) {
        return Err(FileStoreError::OutsideNamespaceRoot(target));
    }

    // Refuse before creating anything: a symlink at the target means somebody
    // else is managing this path and the rename would land somewhere unknown.
    match fs::symlink_metadata(&target) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(FileStoreError::RefusedSymlink(target));
        }
        Ok(meta) if !meta.is_file() => return Err(FileStoreError::NotRegular(target)),
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(FileStoreError::io(format!("could not stat `{}`", target.display()), err));
        }
    }

    ensure_namespace_dirs(req.paths, req.ns_dir)?;

    let tmp = req.ns_dir.join(format!("{CREDENTIALS_FILE}.tmp.{}", hex8()));
    let token = cleanup::register_tmp_path(tmp.clone());
    let write = write_new_file(&tmp, req.blob_json.as_bytes());
    if let Err(err) = write {
        let _ = fs::remove_file(&tmp);
        cleanup::unregister(token);
        return Err(FileStoreError::io(format!("could not write `{}`", tmp.display()), err));
    }

    // The window plan AC21's third clause aims at: the POST has returned, the
    // new credentials are on disk, and the namespace has not yet been
    // replaced. A Claude Code session appearing here is the case the caller
    // must re-check for before it renames.
    req.fault.pause_point("before_rename");

    let rename = if req.fault.is("rename_fail") {
        Err(io::Error::new(
            io::ErrorKind::CrossesDevices,
            "rename failure injected by AGENTCTL_FAULT",
        ))
    } else {
        fs::rename(&tmp, &target)
    };

    match rename {
        Ok(()) => {
            let result = fs::set_permissions(&target, PermissionsExt::from_mode(FILE_MODE))
                .and_then(|()| snapshot(&target));
            cleanup::unregister(token);
            match result {
                Ok(Some(snap)) => Ok(WriteOutcome::Written { snap }),
                Ok(None) => Err(FileStoreError::io(
                    format!("`{}` vanished immediately after being written", target.display()),
                    io::Error::from(io::ErrorKind::NotFound),
                )),
                Err(err) => Err(FileStoreError::io(
                    format!("could not finish writing `{}`", target.display()),
                    err,
                )),
            }
        }
        Err(err) => {
            let outcome = save_to_pending(req, &tmp, &err);
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
    tmp: &Path,
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
    let _ = fs::remove_file(&meta_path);
    if let Err(err) = write_new_file(&meta_path, meta_json.as_bytes()) {
        let _ = fs::remove_file(tmp);
        return Err(FileStoreError::io(format!("could not write `{}`", meta_path.display()), err));
    }

    let pending = req.ns_dir.join(PENDING_FILE);
    let _ = fs::remove_file(&pending);
    if let Err(err) = fs::rename(tmp, &pending) {
        let _ = fs::remove_file(tmp);
        let _ = fs::remove_file(&meta_path);
        return Err(FileStoreError::io(
            format!("could not park credentials at `{}`", pending.display()),
            err,
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
/// an unknown state; every *decidable* outcome — including a corrupt or
/// hostile pending file — is a [`PendingDecision`].
pub fn resolve_pending(
    ns_dir: &Path,
    foreign: &ForeignActivity,
) -> Result<PendingDecision, FileStoreError> {
    let pending_path = ns_dir.join(PENDING_FILE);
    let meta_path = ns_dir.join(PENDING_META);

    // A meta with no pending file is the crash window described in
    // `save_to_pending`: there is nothing to replay, so clear the marker.
    if !path_exists(&pending_path) {
        let _ = fs::remove_file(&meta_path);
        return Ok(PendingDecision::NoPending);
    }

    let pending = match read_file(&pending_path, MAX_CREDENTIALS_BYTES) {
        Ok(ReadOutcome::Present { bytes, .. }) => Some(bytes),
        // Absent here means the path is a directory or unreadable, which is
        // as invalid as a corrupt file.
        Ok(ReadOutcome::Absent) => None,
        Err(_) => None,
    };
    let meta = match read_file(&meta_path, MAX_META_BYTES) {
        Ok(ReadOutcome::Present { bytes, .. }) => {
            serde_json::from_slice::<PendingMeta>(&bytes).ok()
        }
        _ => None,
    };

    let (Some(pending_bytes), Some(meta)) = (pending, meta) else {
        return discard(ns_dir, PendingDiscardReason::Invalid);
    };
    if Credentials::parse_blob(&pending_bytes).is_err() {
        return discard(ns_dir, PendingDiscardReason::Invalid);
    }

    if !matches!(foreign, ForeignActivity::None) {
        return discard(ns_dir, PendingDiscardReason::NamespaceTakenOver);
    }

    let current = match read_credentials(ns_dir) {
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
                replay(ns_dir, false)
            } else {
                discard(ns_dir, PendingDiscardReason::FileChanged)
            }
        }
        None if meta.derived_from_access_sha256.is_none()
            && meta.derived_from_refresh_sha256.is_none() =>
        {
            replay(ns_dir, true)
        }
        None => discard(ns_dir, PendingDiscardReason::FileRemoved),
    }
}

/// Moves the pending file into place and clears the metadata.
fn replay(ns_dir: &Path, first_write: bool) -> Result<PendingDecision, FileStoreError> {
    let pending = ns_dir.join(PENDING_FILE);
    let target = ns_dir.join(CREDENTIALS_FILE);
    fs::rename(&pending, &target).map_err(|err| {
        FileStoreError::io(format!("could not replay `{}`", pending.display()), err)
    })?;
    fs::set_permissions(&target, PermissionsExt::from_mode(FILE_MODE)).map_err(|err| {
        FileStoreError::io(format!("could not set the mode of `{}`", target.display()), err)
    })?;
    let _ = fs::remove_file(ns_dir.join(PENDING_META));
    Ok(PendingDecision::Replayed { first_write })
}

/// Deletes both pending files and reports why.
fn discard(ns_dir: &Path, reason: PendingDiscardReason) -> Result<PendingDecision, FileStoreError> {
    let _ = fs::remove_file(ns_dir.join(PENDING_FILE));
    let _ = fs::remove_file(ns_dir.join(PENDING_META));
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
/// under the namespace root, and [`FileStoreError::Io`] for a removal that
/// failed for a reason other than the file already being gone.
pub fn remove_namespace(paths: &Paths, ns_dir: &Path) -> Result<(), FileStoreError> {
    if !paths.is_under_namespace_root(ns_dir) {
        return Err(FileStoreError::OutsideNamespaceRoot(ns_dir.to_path_buf()));
    }

    let mut targets =
        vec![ns_dir.join(CREDENTIALS_FILE), ns_dir.join(PENDING_FILE), ns_dir.join(PENDING_META)];
    targets.extend(list_stray_tmp(ns_dir).map_err(|err| {
        FileStoreError::io(format!("could not list `{}`", ns_dir.display()), err)
    })?);

    for target in targets {
        match fs::remove_file(&target) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(FileStoreError::io(
                    format!("could not remove `{}`", target.display()),
                    err,
                ));
            }
        }
    }

    // Climb toward the namespace root, removing directories that are now
    // empty. `remove_dir` refuses a non-empty directory, which is the check
    // wanted here: a sibling organization's namespace must survive.
    let root = paths.namespace_root();
    let mut dir = ns_dir.to_path_buf();
    while dir != root && paths.is_under_namespace_root(&dir) {
        if fs::remove_dir(&dir).is_err() {
            break;
        }
        match dir.parent() {
            Some(parent) => dir = parent.to_path_buf(),
            None => break,
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

/// Whether anything at all exists at `path`, links included.
fn path_exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

/// Creates the namespace directory chain, every level at mode 0700.
///
/// Every level individually rather than `create_dir_all`, which applies the
/// umask and commonly leaves a directory group-readable — a directory holding
/// refresh tokens (risk R22).
fn ensure_namespace_dirs(paths: &Paths, ns_dir: &Path) -> Result<(), FileStoreError> {
    let relative = ns_dir
        .strip_prefix(paths.config_dir())
        .map_err(|_| FileStoreError::OutsideNamespaceRoot(ns_dir.to_path_buf()))?;

    let mut dir = paths.config_dir().to_path_buf();
    create_dir_0700(&dir)?;
    for component in relative.components() {
        dir = dir.join(component);
        create_dir_0700(&dir)?;
    }
    Ok(())
}

/// Creates one directory at mode 0700, tolerating one that already exists.
fn create_dir_0700(dir: &Path) -> Result<(), FileStoreError> {
    if dir.is_dir() {
        return Ok(());
    }
    let mut builder = fs::DirBuilder::new();
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, crate::config::paths::DIR_MODE);
    builder
        .create(dir)
        .map_err(|err| FileStoreError::io(format!("could not create `{}`", dir.display()), err))
}

/// Creates a file at 0600 with `O_EXCL`, writes it, and `fsync`s it.
fn write_new_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file =
        fs::OpenOptions::new().write(true).create_new(true).mode(FILE_MODE).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
#[path = "file_store_tests.rs"]
mod tests;
