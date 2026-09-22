//! One credential file inside a directory agctl owns, and the only primitive
//! that replaces one.
//!
//! Carved out of `file_store`'s Claude writer so phase 3's Codex namespaces
//! write through the same `O_EXCL` temporary → `fsync` → `renameat` sequence
//! rather than a second copy of it. Claude's writer is now a thin caller that
//! passes its own names and [`StopPolicy::DiscardStaged`]; its behaviour is
//! unchanged.
//!
//! # The root is part of the value
//!
//! [`SecretFile::open`] is the only constructor and every field is private, so
//! a `SecretFile` cannot exist without naming the root it must stay under
//! (plan H5, AC97, AC122 clause 6). Every operation first checks that the
//! file's path *spells* a location strictly below that root and that the name
//! is one plain path component. The check is lexical, like
//! [`Paths::is_under_namespace_root`](crate::config::paths::Paths::is_under_namespace_root):
//! the directory descriptor comes from the caller's `O_NOFOLLOW` walk, and the
//! leaf operation is relative to it, so no path is resolved again here.
//!
//! # Two stop policies
//!
//! Claude's writer abandons a staged replacement when its pass has been told
//! to stop, and registers the temporary with the emergency cleanup so a signal
//! removes it: before the rename nothing has been lost. A Codex refresh is
//! different: once the token endpoint has answered, the staged file holds the
//! only copy of a server-rotated grant, and deleting it costs the user a login
//! (plan ledger #197, #231, risk R70). [`StopPolicy::Complete`] therefore
//! ignores the pass's stop signal once the file is staged **and does not
//! register the temporary with cleanup**, so a process exit between the
//! `fsync` and the rename leaves the grant on disk, where `doctor` reports it,
//! rather than unlinking it.

use std::io;
use std::os::fd::BorrowedFd;
use std::path::Path;

use crate::config::paths::is_single_component;
use crate::config::paths::lexical_normalize;
use crate::runtime::cleanup;
use crate::runtime::cleanup::CleanupToken;
use crate::runtime::coordinator::PassCtx;
use crate::runtime::fault::Fault;
use crate::secret::file_store::Entry;
use crate::secret::file_store::FileStoreError;
use crate::secret::file_store::ReadOutcome;
use crate::secret::file_store::WriteOutcome;
use crate::secret::file_store::as_io_error;
use crate::secret::file_store::create_new_file_at;
use crate::secret::file_store::entry_at;
use crate::secret::file_store::hex8;
use crate::secret::file_store::read_file_at;
use crate::secret::file_store::read_file_at_strict;
use crate::secret::file_store::snapshot_at;
use crate::secret::file_store::unlink_at;
use crate::secret::pending;
use crate::secret::pending::PendingSpec;

/// What a write does when its pass is told to stop, and whether a process exit
/// may remove its staged file.
#[derive(Debug, Clone, Copy)]
pub enum StopPolicy<'c> {
    /// Claude's rule (phase 1, pinned by `file_store_tests.rs`): the temporary
    /// is registered with [`cleanup`], and a pass that should stop after the
    /// `fsync` unlinks it and returns [`FileStoreError::Cancelled`], leaving
    /// the old file in place.
    DiscardStaged(&'c PassCtx),
    /// Once staged, the file is renamed into place — or parked as pending —
    /// whatever the pass says, and the temporary is **not** registered with
    /// [`cleanup`]: a process exit leaves it on disk (risk R70). For a writer
    /// whose staged bytes may be the only copy of a credential.
    Complete,
}

/// The fault-injection points a write honours, named by its caller.
///
/// The names differ per writer so a test can fail one writer's rename without
/// failing another's: Claude's are `before_rename` and `rename_fail`.
#[derive(Debug, Clone, Copy)]
pub struct WriteFaults<'f> {
    /// The active fault set.
    pub fault: &'f Fault,
    /// The [`Fault::pause_point`] name between the `fsync` and the rename.
    pub before_rename: &'static str,
    /// The [`Fault::is`] name that turns the rename into a failure.
    pub rename_fail: &'static str,
}

/// One named file in an already-opened directory, bound to the root it must
/// stay under.
#[derive(Debug, Clone, Copy)]
pub struct SecretFile<'a> {
    /// The directory this file must spell a path strictly below.
    root: &'a Path,
    /// The directory holding the file, from the caller's `O_NOFOLLOW` walk.
    dir: BorrowedFd<'a>,
    /// The file's name inside `dir`: one plain path component.
    name: &'a str,
    /// The file's path as the user would recognise it: checked against
    /// `root`, and used in error sentences. Nothing is resolved through it.
    shown: &'a Path,
}

impl<'a> SecretFile<'a> {
    /// Binds a file name in `dir` to the root it must stay under.
    ///
    /// Infallible on purpose: the checks run at the start of every operation,
    /// so a value that fails them can be built but never used.
    pub fn open(root: &'a Path, dir: BorrowedFd<'a>, name: &'a str, shown: &'a Path) -> Self {
        Self { root, dir, name, shown }
    }

    /// Refuses a name that is not one plain component, a displayed path that
    /// does not end in it, and a displayed path not strictly below the root.
    fn check(&self) -> Result<(), FileStoreError> {
        let single = is_single_component(self.name);
        let named = self.shown.file_name().is_some_and(|leaf| leaf == self.name);
        let root = lexical_normalize(self.root);
        let target = lexical_normalize(self.shown);
        if single && named && target != root && target.starts_with(&root) {
            Ok(())
        } else {
            Err(FileStoreError::OutsideNamespaceRoot(self.shown.to_path_buf()))
        }
    }

    /// Reads the file under the regular-file and size rules of
    /// [`read_file_at`].
    ///
    /// # Errors
    ///
    /// [`FileStoreError::OutsideNamespaceRoot`] when the root check fails, and
    /// otherwise as [`read_file_at`].
    pub fn read(&self, limit: u64) -> Result<ReadOutcome, FileStoreError> {
        self.check()?;
        read_file_at(self.dir, self.name, limit, self.shown)
    }

    /// [`SecretFile::read`], but a file that exists and cannot be opened is an
    /// error rather than absent ([`read_file_at_strict`]). For a caller whose
    /// "absent" decides whether a credential is discarded.
    ///
    /// # Errors
    ///
    /// [`FileStoreError::OutsideNamespaceRoot`] when the root check fails, and
    /// otherwise as [`read_file_at_strict`].
    pub fn read_strict(&self, limit: u64) -> Result<ReadOutcome, FileStoreError> {
        self.check()?;
        read_file_at_strict(self.dir, self.name, limit, self.shown)
    }

    /// Removes the file, returning whether one was there.
    ///
    /// # Errors
    ///
    /// [`FileStoreError::OutsideNamespaceRoot`] when the root check fails, and
    /// [`FileStoreError::Io`] when the unlink fails for any reason other than
    /// the file not being there.
    pub fn remove(&self) -> Result<bool, FileStoreError> {
        self.check()?;
        match unlink_at(self.dir, self.name) {
            Ok(()) => Ok(true),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(err) => {
                Err(FileStoreError::io(format!("could not remove `{}`", self.shown.display()), err))
            }
        }
    }

    /// Replaces the file atomically with `bytes`.
    ///
    /// `O_EXCL` temporary `<name>.tmp.<8 hex>` at 0600 → `fsync` → (under
    /// [`StopPolicy::DiscardStaged`] only: registered with cleanup, and
    /// abandoned if the pass should stop) → `renameat` → directory `fsync`.
    /// A failed rename parks the bytes as pending when `pending` is `Some`;
    /// with `None` it is an error and the temporary is removed, because the
    /// caller still holds what it asked to write.
    ///
    /// # Errors
    ///
    /// [`FileStoreError::OutsideNamespaceRoot`] when the root check fails or
    /// `pending` names a different target, [`FileStoreError::RefusedSymlink`]
    /// or [`FileStoreError::NotRegular`] when the existing target is not a
    /// plain file, [`FileStoreError::Cancelled`] when a
    /// [`StopPolicy::DiscardStaged`] pass stopped while the file was staged,
    /// and [`FileStoreError::Io`] for a filesystem failure. A failed rename
    /// with a pending spec is not an error: it returns
    /// [`WriteOutcome::SavedToPending`].
    pub fn write(
        &self,
        bytes: &[u8],
        pending: Option<PendingSpec<'_>>,
        stop: StopPolicy<'_>,
        faults: &WriteFaults<'_>,
    ) -> Result<WriteOutcome, FileStoreError> {
        self.check()?;
        if let Some(spec) = &pending {
            // `check` passed, so `shown` has a parent: its leaf is `name`.
            let dir_shown = self.shown.parent().unwrap_or(self.shown);
            pending::check_spec_names(spec, dir_shown)?;
            if spec.target_name != self.name {
                return Err(FileStoreError::OutsideNamespaceRoot(
                    self.shown.with_file_name(spec.target_name),
                ));
            }
        }
        let dir = self.dir;
        let target = self.shown;

        // Refuse before creating anything: a symlink at the target means somebody
        // else is managing this path and the rename would land somewhere unknown.
        match entry_at(dir, self.name, target)? {
            Entry::Absent | Entry::Regular => {}
            Entry::Symlink => return Err(FileStoreError::RefusedSymlink(target.to_path_buf())),
            Entry::Other => return Err(FileStoreError::NotRegular(target.to_path_buf())),
        }

        let tmp_name = format!("{}.tmp.{}", self.name, hex8());
        let tmp = target.with_file_name(&tmp_name);
        let token = match stop {
            StopPolicy::DiscardStaged(_) => Some(cleanup::register_tmp_path(tmp.clone())),
            StopPolicy::Complete => None,
        };
        if let Err(err) = create_new_file_at(dir, &tmp_name, bytes) {
            // `EEXIST` from the `O_EXCL` create means the name belongs to a file
            // this write did not create: under `Complete` that can only be an
            // earlier write's kept temporary, which may hold a rotated grant, so
            // it is left alone. `DiscardStaged` keeps phase 1's unconditional
            // unlink.
            let foreign = err.kind() == io::ErrorKind::AlreadyExists;
            if !(foreign && matches!(stop, StopPolicy::Complete)) {
                let _ = unlink_at(dir, &tmp_name);
            }
            release(token);
            return Err(FileStoreError::io(format!("could not write `{}`", tmp.display()), err));
        }

        // The window plan AC21's third clause aims at: the POST has returned, the
        // new credentials are on disk, and the file has not yet been replaced. A
        // session appearing here is the case the caller must re-check for before
        // it renames.
        faults.fault.pause_point(faults.before_rename);

        // Under `DiscardStaged` the same window is the last moment at which a
        // cancelled pass can leave the file exactly as it found it: after the
        // rename there is nothing left to undo, and before the write there is
        // nothing to gain. Under `Complete` the staged bytes may be the only copy
        // of a rotated grant, and stopping here would destroy it.
        if let StopPolicy::DiscardStaged(ctx) = stop
            && ctx.should_stop()
        {
            let _ = unlink_at(dir, &tmp_name);
            release(token);
            return Err(FileStoreError::Cancelled(target.to_path_buf()));
        }

        let rename = if faults.fault.is(faults.rename_fail) {
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
            rustix::fs::renameat(dir, tmp_name.as_str(), dir, self.name).map_err(as_io_error)
        };

        match rename {
            Ok(()) => {
                if rustix::fs::fsync(dir).is_err() {
                    // The rename has happened; nothing can be abandoned now.
                    tracing::warn!(
                        "a credential file's directory could not be flushed after the rename"
                    );
                }
                // The mode was set on the temporary file's inode, which the rename
                // carries over, so there is nothing left to chmod here.
                let snap = snapshot_at(dir, self.name, target);
                release(token);
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
                let outcome = match &pending {
                    Some(spec) => self.save_to_pending(spec, &tmp_name, &err, stop),
                    None => {
                        let _ = unlink_at(dir, &tmp_name);
                        Err(FileStoreError::io(
                            format!(
                                "could not rename `{}` onto `{}`",
                                tmp.display(),
                                target.display()
                            ),
                            err,
                        ))
                    }
                };
                release(token);
                outcome
            }
        }
    }

    /// Parks `bytes` as pending without trying the target at all.
    ///
    /// For a writer that already knows the rename cannot happen: a rotated
    /// grant whose writes kept failing after the refresh was applied (review
    /// S30 LOW-1). The target is not examined — a target that is torn, a link,
    /// or unreadable is exactly why the caller is here — and the temporary is
    /// staged and parked under [`StopPolicy::Complete`]'s rules: it is not
    /// registered with cleanup, and a failure to park keeps it, naming it in the
    /// error, because it may be the only copy of the grant.
    ///
    /// # Errors
    ///
    /// [`FileStoreError::OutsideNamespaceRoot`] when the root check fails or the
    /// spec names another target, and [`FileStoreError::Io`] when the temporary
    /// cannot be written or the pending pair cannot be saved.
    pub fn park(
        &self,
        bytes: &[u8],
        spec: PendingSpec<'_>,
        faults: &WriteFaults<'_>,
    ) -> Result<WriteOutcome, FileStoreError> {
        self.check()?;
        let dir_shown = self.shown.parent().unwrap_or(self.shown);
        pending::check_spec_names(&spec, dir_shown)?;
        if spec.target_name != self.name {
            return Err(FileStoreError::OutsideNamespaceRoot(
                self.shown.with_file_name(spec.target_name),
            ));
        }
        let tmp_name = format!("{}.tmp.{}", self.name, hex8());
        let tmp = self.shown.with_file_name(&tmp_name);
        if let Err(err) = create_new_file_at(self.dir, &tmp_name, bytes) {
            if err.kind() != io::ErrorKind::AlreadyExists {
                let _ = unlink_at(self.dir, &tmp_name);
            }
            return Err(FileStoreError::io(format!("could not write `{}`", tmp.display()), err));
        }
        faults.fault.pause_point(faults.before_rename);
        let cause = io::Error::other("the writes before it failed; parked without a rename");
        self.save_to_pending(&spec, &tmp_name, &cause, StopPolicy::Complete)
    }

    /// Parks a written temporary file under the spec's pending name.
    ///
    /// The metadata goes first, deliberately. A crash between the two leaves a
    /// meta with no pending file, which the resolver reads as "nothing to
    /// replay"; the other order would leave credentials with no record of what
    /// they were derived from, which is unreplayable *and* indistinguishable
    /// from a valid pending.
    ///
    /// Under [`StopPolicy::Complete`] a failure here does not remove the
    /// temporary: it may hold the only copy of a rotated grant, and a stray
    /// temporary is something `doctor` reports.
    fn save_to_pending(
        &self,
        spec: &PendingSpec<'_>,
        tmp_name: &str,
        cause: &io::Error,
        stop: StopPolicy<'_>,
    ) -> Result<WriteOutcome, FileStoreError> {
        let keep_tmp = matches!(stop, StopPolicy::Complete);
        let dir = self.dir;
        let meta_json = pending::meta_json(spec)?;
        // Under `Complete` the error names the temporary it kept, so neither the
        // caller nor the user can mistake "the grant is on disk under this name"
        // for "nothing was staged". `DiscardStaged`'s sentences are unchanged.
        let kept = |context: String| {
            if keep_tmp {
                let tmp = self.shown.with_file_name(tmp_name);
                format!("{context}; the staged credential was kept at `{}`", tmp.display())
            } else {
                context
            }
        };

        let meta_path = self.shown.with_file_name(spec.meta_name);
        let _ = unlink_at(dir, spec.meta_name);
        if let Err(err) = create_new_file_at(dir, spec.meta_name, meta_json.as_bytes()) {
            if !keep_tmp {
                let _ = unlink_at(dir, tmp_name);
            }
            return Err(FileStoreError::io(
                kept(format!("could not write `{}`", meta_path.display())),
                err,
            ));
        }

        let pending_path = self.shown.with_file_name(spec.pending_name);
        let _ = unlink_at(dir, spec.pending_name);
        if let Err(errno) = rustix::fs::renameat(dir, tmp_name, dir, spec.pending_name) {
            if !keep_tmp {
                let _ = unlink_at(dir, tmp_name);
            }
            let _ = unlink_at(dir, spec.meta_name);
            return Err(FileStoreError::errno(
                kept(format!("could not park credentials at `{}`", pending_path.display())),
                errno,
            ));
        }

        Ok(WriteOutcome::SavedToPending { error: cause.to_string() })
    }
}

/// Forgets a cleanup registration, if the write made one.
fn release(token: Option<CleanupToken>) {
    if let Some(token) = token {
        cleanup::unregister(token);
    }
}

#[cfg(test)]
#[path = "secret_file_tests.rs"]
mod tests;
