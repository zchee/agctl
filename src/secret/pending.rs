//! The pending-credential protocol, independent of whose credential it is.
//!
//! When a credential writer's rename fails, the new credential may be the only
//! valid one left — a refresh has already rotated the old one away — so it is
//! parked under a pending name with a metadata file recording what it was
//! derived from, and the next run decides whether to replay it or discard it.
//! Phase 1 wrote that decision table for Claude's `.credentials.json`
//! (`file_store`); phase 3 needs the same table for Codex's `auth.json`. This
//! module is the table with the vendor taken out: the names come from a
//! [`PendingSpec`], and "does this parse" and "what are its digests" come from
//! a [`PendingCredential`] implementation.
//!
//! # The table
//!
//! | on disk | decision |
//! |---------|----------|
//! | no pending file | [`PendingDecision::NoPending`] (a lone meta is removed) |
//! | pending or meta unreadable, a link, oversized, or not parseable | discarded, `invalid` |
//! | the namespace was taken over by somebody else | discarded, `namespace taken over` |
//! | target present, its digests equal the meta's `derived_from_*` | replayed |
//! | target present, digests differ | discarded, `file changed` |
//! | target absent (or unparseable†), meta has no `derived_from_*` | replayed, first write |
//! | target absent (or unparseable†), meta has `derived_from_*` | discarded, `file removed` |
//!
//! † Only when [`PendingCredential::UNUSABLE_IS_ABSENT`] is `true`,
//! as it is for Claude. Otherwise an unparseable target is an error and both
//! files are kept.
//!
//! The order of the rows is the order of the checks, and it is Claude's
//! phase-1 order unchanged: validity first, then foreign activity, then the
//! digest comparison.
//!
//! # No `unlinkat` here
//!
//! Every removal goes through `file_store`'s descriptor-relative helpers, so
//! the set of files that spell a directory or file removal stays the one
//! `scripts/phase3-greps.sh` pins.

use std::os::fd::BorrowedFd;
use std::path::Path;

use serde::Deserialize;
use serde::Serialize;

use crate::config::paths::is_single_component;
use crate::secret::file_store::Entry;
use crate::secret::file_store::FileStoreError;
use crate::secret::file_store::MAX_CREDENTIALS_BYTES;
use crate::secret::file_store::MAX_META_BYTES;
use crate::secret::file_store::ReadOutcome;
use crate::secret::file_store::chmod_0600_at;
use crate::secret::file_store::entry_at;
use crate::secret::file_store::read_file_at;
use crate::secret::file_store::read_file_at_strict;
use crate::secret::file_store::unlink_at;

/// Fingerprints of the token material, safe to write to disk and to compare.
///
/// Used for two things that both need to answer "is this the same credential?"
/// without holding the credential: folding a keychain entry into the live row
/// (plan AC42) and deciding whether a pending credential still applies to the
/// file it was derived from (plan section 3.3).
///
/// Lives here rather than beside Claude's credential type because the pending
/// protocol is its first vendor-neutral consumer;
/// `provider::claude::credentials` re-exports it under its old path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digests {
    /// `sha256(access_token)`, hex.
    pub access_sha256: String,
    /// `sha256(refresh_token)`, hex, when there is one.
    pub refresh_sha256: Option<String>,
}

/// What the pending protocol needs to know about one vendor's credential file.
///
/// Associated functions rather than methods: the protocol only ever has bytes
/// in hand, and asking a parsed value for its digests would mean every
/// implementation had to be constructible here.
pub trait PendingCredential {
    /// Whether a pending meta must carry `new_expires_at` to be valid.
    ///
    /// Claude's meta has always required it, so a meta without one has always
    /// been discarded as `invalid`; keeping that is what keeps Claude's
    /// pending behaviour byte-identical. A vendor whose credential has no
    /// expiry to record leaves this `false`.
    const META_REQUIRES_EXPIRY: bool = false;

    /// Whether a file that is present but unusable counts as absent: a
    /// target that does not parse, or a target, pending file or meta that
    /// exists and cannot be opened.
    ///
    /// Claude's phase-1 table says it does (`true`, the default, which keeps
    /// Claude byte-identical: its reads go through `read_file_at`, whose F40
    /// rule reads an unopenable file as absent). A vendor whose own writer
    /// rewrites the file in place can leave it torn for a moment, and whose
    /// pending file may be the only copy of a rotated grant, says `false`: the
    /// resolver then reads with `read_file_at_strict` and returns an error for
    /// any such file, keeping both the pending file and the target for the
    /// next run (reviews S29a F8, S30 F1). A pending file that is a link, not a
    /// regular file, or oversized is still `invalid` either way — no writer of
    /// ours leaves one.
    const UNUSABLE_IS_ABSENT: bool = true;

    /// Whether `bytes` are a credential this vendor's writer would have written.
    fn validate(bytes: &[u8]) -> bool;

    /// The digests of the credential in `bytes`, or `None` when they do not
    /// parse.
    fn digests(bytes: &[u8]) -> Option<Digests>;
}

/// The names and derivation of one pending credential.
///
/// The three names are single path components inside the namespace directory
/// the operation is handed as a descriptor.
#[derive(Debug, Clone, Copy)]
pub struct PendingSpec<'a> {
    /// The credential file a replay renames onto.
    pub target_name: &'a str,
    /// Where a credential waits after a failed rename.
    pub pending_name: &'a str,
    /// What the pending credential was derived from.
    pub meta_name: &'a str,
    /// The digests of the file the credential was derived from, or `None` on
    /// a first write. Recorded in the meta when a write parks a credential.
    pub prior: Option<&'a Digests>,
    /// The new access token's expiry, in milliseconds since the epoch, when
    /// the vendor has one to record.
    pub expires_at_ms: Option<i64>,
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
    /// A session or a keychain migration has taken the namespace over since
    /// the pending file was written.
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

/// What a resolution changed on disk, for a caller that records every write.
///
/// `None` from [`resolve_pending_with`] means no credential file was touched:
/// nothing was pending, or only a lone meta was cleared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingWrite {
    /// The digests of the target file before the resolution, when it parsed.
    pub before: Option<Digests>,
    /// The digests of the pending credential that was replayed or dropped,
    /// when it parsed.
    pub pending: Option<Digests>,
}

/// The meta as a writer emits it.
///
/// The member order and spelling are Claude's `PendingMeta`'s, and
/// `new_expires_at` is omitted rather than written as `null` when there is no
/// expiry, so a Claude write produces exactly the bytes it always has.
#[derive(Serialize)]
struct MetaOut<'a> {
    derived_from_access_sha256: Option<&'a str>,
    derived_from_refresh_sha256: Option<&'a str>,
    created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    new_expires_at: Option<i64>,
}

/// The meta as the resolver reads it.
///
/// `Option` fields are optional to serde's derive, so a meta written without
/// `new_expires_at` parses; [`PendingCredential::META_REQUIRES_EXPIRY`] then
/// decides whether that is valid. `created_at` stays required, as it was.
#[derive(Deserialize)]
struct MetaIn {
    derived_from_access_sha256: Option<String>,
    derived_from_refresh_sha256: Option<String>,
    #[expect(dead_code, reason = "required for validity; its value is never consulted")]
    created_at: String,
    new_expires_at: Option<i64>,
}

/// Refuses a spec whose names could leave the directory they are resolved in,
/// or could alias one another.
///
/// Each of the three names is handed to `openat`/`renameat`/`unlinkat`
/// relative to a walked directory descriptor, and those calls resolve `..` and
/// `/` inside a name; so every name must be one plain component, or the root
/// binding the descriptor stands for is gone. The three must also differ: a
/// pending name equal to the target would park over the live file, and a meta
/// name equal to either would be unlinked as "the meta". Checked before any
/// file is examined or staged. `dir_shown` is the directory as the user would
/// recognise it, for the error.
///
/// # Errors
///
/// [`FileStoreError::OutsideNamespaceRoot`] naming the first offending name.
pub(crate) fn check_spec_names(
    spec: &PendingSpec<'_>,
    dir_shown: &Path,
) -> Result<(), FileStoreError> {
    let names = [spec.target_name, spec.pending_name, spec.meta_name];
    if let Some(bad) = names.iter().find(|name| !is_single_component(name)) {
        return Err(FileStoreError::OutsideNamespaceRoot(dir_shown.join(bad)));
    }
    if spec.pending_name == spec.target_name || spec.meta_name == spec.target_name {
        return Err(FileStoreError::OutsideNamespaceRoot(dir_shown.join(spec.target_name)));
    }
    if spec.meta_name == spec.pending_name {
        return Err(FileStoreError::OutsideNamespaceRoot(dir_shown.join(spec.pending_name)));
    }
    Ok(())
}

/// The meta a failed rename parks beside the pending credential.
///
/// # Errors
///
/// Returns [`FileStoreError::Json`] when the meta cannot be serialized.
pub(crate) fn meta_json(spec: &PendingSpec<'_>) -> Result<String, FileStoreError> {
    let meta = MetaOut {
        derived_from_access_sha256: spec.prior.map(|d| d.access_sha256.as_str()),
        derived_from_refresh_sha256: spec.prior.and_then(|d| d.refresh_sha256.as_deref()),
        created_at: jiff::Timestamp::now().to_string(),
        new_expires_at: spec.expires_at_ms,
    };
    serde_json::to_string(&meta)
        .map_err(|err| FileStoreError::Json(format!("could not serialize pending metadata: {err}")))
}

/// Applies the pending decision table to one namespace directory.
///
/// `dir` is a descriptor the caller's `O_NOFOLLOW` walk produced, and every
/// operation is relative to it. `shown` is that directory as the user would
/// recognise it, used only in error sentences. `foreign_taken_over` is the
/// caller's own judgement of whether somebody else now manages the namespace;
/// how it is reached differs by vendor, and the table only needs the answer.
///
/// # Errors
///
/// Returns [`FileStoreError::OutsideNamespaceRoot`] for a spec
/// [`check_spec_names`] refuses, before anything is touched, and otherwise
/// [`FileStoreError`] only for failures that leave the namespace in an
/// unknown state — an unreadable target file, or a replay rename that failed.
/// Every *decidable* outcome, including a corrupt or hostile pending file, is a
/// [`PendingDecision`].
pub(crate) fn resolve_pending_with<C: PendingCredential>(
    dir: BorrowedFd<'_>,
    shown: &Path,
    spec: &PendingSpec<'_>,
    foreign_taken_over: bool,
) -> Result<(PendingDecision, Option<PendingWrite>), FileStoreError> {
    check_spec_names(spec, shown)?;
    let pending_path = shown.join(spec.pending_name);
    let meta_path = shown.join(spec.meta_name);
    let current_path = shown.join(spec.target_name);

    // A meta with no pending file is the crash window between writing the meta
    // and parking the credential: there is nothing to replay, so clear it.
    if matches!(entry_at(dir, spec.pending_name, &pending_path)?, Entry::Absent) {
        let _ = unlink_at(dir, spec.meta_name);
        return Ok((PendingDecision::NoPending, None));
    }

    // The reader follows the vendor's rule. Under Claude's (`read_file_at`),
    // absent here means the path is a directory or unreadable, which is as
    // invalid as a corrupt file; so is a symlink, so every failure collapses.
    // Under the strict rule an open failure is an error that keeps every file.
    let read = |name: &str, limit: u64, shown: &Path| {
        if C::UNUSABLE_IS_ABSENT {
            read_file_at(dir, name, limit, shown)
        } else {
            read_file_at_strict(dir, name, limit, shown)
        }
    };
    let pending = match read(spec.pending_name, MAX_CREDENTIALS_BYTES, &pending_path) {
        Ok(ReadOutcome::Present { bytes, .. }) => Some(bytes),
        Err(err) if !C::UNUSABLE_IS_ABSENT && is_open_failure(&err) => return Err(err),
        _ => None,
    };
    let pending_digests = pending.as_deref().and_then(C::digests);
    let meta = match read(spec.meta_name, MAX_META_BYTES, &meta_path) {
        Ok(ReadOutcome::Present { bytes, .. }) => serde_json::from_slice::<MetaIn>(&bytes).ok(),
        Err(err) if !C::UNUSABLE_IS_ABSENT && is_open_failure(&err) => return Err(err),
        _ => None,
    };

    let (Some(pending_bytes), Some(meta)) = (pending, meta) else {
        return Ok(discard(dir, spec, PendingDiscardReason::Invalid, None, pending_digests));
    };
    if !C::validate(&pending_bytes) || (C::META_REQUIRES_EXPIRY && meta.new_expires_at.is_none()) {
        return Ok(discard(dir, spec, PendingDiscardReason::Invalid, None, pending_digests));
    }

    if foreign_taken_over {
        return Ok(discard(
            dir,
            spec,
            PendingDiscardReason::NamespaceTakenOver,
            None,
            pending_digests,
        ));
    }

    let current = match read(spec.target_name, MAX_CREDENTIALS_BYTES, &current_path) {
        Ok(ReadOutcome::Present { bytes, .. }) => match C::digests(&bytes) {
            Some(digests) => Some(digests),
            None if C::UNUSABLE_IS_ABSENT => None,
            None => {
                return Err(FileStoreError::Json(format!(
                    "`{}` is present but does not parse; the pending credential is kept for the next run",
                    current_path.display()
                )));
            }
        },
        Ok(ReadOutcome::Absent) => None,
        // An unreadable current file is not something to overwrite blindly.
        Err(err) => return Err(err),
    };

    match current {
        Some(current) => {
            let matches = meta.derived_from_access_sha256.as_deref()
                == Some(current.access_sha256.as_str())
                && meta.derived_from_refresh_sha256 == current.refresh_sha256;
            if matches {
                replay(dir, shown, spec, false, Some(current), pending_digests)
            } else {
                Ok(discard(
                    dir,
                    spec,
                    PendingDiscardReason::FileChanged,
                    Some(current),
                    pending_digests,
                ))
            }
        }
        None if meta.derived_from_access_sha256.is_none()
            && meta.derived_from_refresh_sha256.is_none() =>
        {
            replay(dir, shown, spec, true, None, pending_digests)
        }
        None => Ok(discard(dir, spec, PendingDiscardReason::FileRemoved, None, pending_digests)),
    }
}

/// Whether a strict read failed to open or read a file that is there, as
/// opposed to finding a link, a non-regular file or an oversized one.
fn is_open_failure(err: &FileStoreError) -> bool {
    matches!(err, FileStoreError::Io { .. })
}

/// Moves the pending file into place and clears the metadata.
///
/// The mode is set on the pending file *before* the rename, because a rename
/// carries the inode and its mode across, and chmod-after-rename would be a
/// second lookup of a name that is now the live credentials file.
fn replay(
    dir: BorrowedFd<'_>,
    shown: &Path,
    spec: &PendingSpec<'_>,
    first_write: bool,
    before: Option<Digests>,
    pending: Option<Digests>,
) -> Result<(PendingDecision, Option<PendingWrite>), FileStoreError> {
    let pending_path = shown.join(spec.pending_name);
    chmod_0600_at(dir, spec.pending_name, &pending_path)?;
    rustix::fs::renameat(dir, spec.pending_name, dir, spec.target_name).map_err(|errno| {
        FileStoreError::errno(format!("could not replay `{}`", pending_path.display()), errno)
    })?;
    let _ = unlink_at(dir, spec.meta_name);
    Ok((PendingDecision::Replayed { first_write }, Some(PendingWrite { before, pending })))
}

/// Deletes both pending files and reports why.
fn discard(
    dir: BorrowedFd<'_>,
    spec: &PendingSpec<'_>,
    reason: PendingDiscardReason,
    before: Option<Digests>,
    pending: Option<Digests>,
) -> (PendingDecision, Option<PendingWrite>) {
    let _ = unlink_at(dir, spec.pending_name);
    let _ = unlink_at(dir, spec.meta_name);
    (PendingDecision::Discarded(reason), Some(PendingWrite { before, pending }))
}

#[cfg(test)]
#[path = "pending_tests.rs"]
mod tests;
