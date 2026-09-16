//! Taking a Codex namespace lock, and the only producer of its proof.
//!
//! One lock file per `(user, account)` pair, `codex/.locks/<user>+<acct>.lock`,
//! outside the namespace directory for the reason Claude's locks are
//! (`config::paths`). It is agctl's own lock: nothing here opens, creates or
//! `flock`s any lock inside a Codex home — Codex's `daemon.lock` included
//! (invariant I21) — so a Codex process can never be made to wait on agctl.
//!
//! The functions below are the only callers of
//! [`CodexNamespaceGuard::wrap`](crate::provider::codex::proof::CodexNamespaceGuard)
//! (plan AC119). Both take a proof, never raw ids: a registry row must first
//! be an [`OwnedRecord`], and a login must first be a [`VerifiedLogin`].

use std::ffi::OsStr;
use std::time::Duration;
use std::time::Instant;

use crate::config::paths::Paths;
use crate::provider::codex::proof::CodexNamespaceGuard;
use crate::provider::codex::proof::OwnedRecord;
use crate::provider::codex::proof::VerifiedLogin;
use crate::runtime::coordinator::Cancel;
use crate::runtime::fault::Fault;
use crate::secret::namespace_lock;
use crate::secret::namespace_lock::LockError;

/// How long a caller will wait for a namespace lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockBudget {
    /// Inside a `status`/`watch` pass: short, so a held lock costs one row a
    /// `busy` and the refresh POST keeps its own allowance (plan section 3.3).
    Pass(Duration),
    /// An interactive command — `login`, `accounts` — which has no pass
    /// deadline: typically
    /// [`COMMAND_LOCK_TIMEOUT`](crate::secret::namespace_lock::COMMAND_LOCK_TIMEOUT).
    Command(Duration),
}

impl LockBudget {
    /// The wait this budget allows.
    pub fn duration(self) -> Duration {
        match self {
            Self::Pass(wait) | Self::Command(wait) => wait,
        }
    }
}

/// Takes the lock for an owned registry row.
///
/// # Errors
///
/// [`LockError`]: `Busy` when the budget ran out, `Cancelled`, and
/// `Unavailable`/`RefusedSymlink` when the lock cannot be taken at all.
pub fn acquire_codex(
    paths: &Paths,
    owned: OwnedRecord<'_>,
    budget: LockBudget,
    cancel: &Cancel,
    fault: &Fault,
) -> Result<CodexNamespaceGuard, LockError> {
    acquire(paths, owned.user(), owned.acct(), budget, cancel, fault)
}

/// Takes the lock for a verified login that is about to be installed.
///
/// # Errors
///
/// As [`acquire_codex`].
pub fn acquire_codex_for_install(
    paths: &Paths,
    login: &VerifiedLogin,
    budget: LockBudget,
    cancel: &Cancel,
    fault: &Fault,
) -> Result<CodexNamespaceGuard, LockError> {
    let owned = login.owned_record();
    acquire(paths, owned.user(), owned.acct(), budget, cancel, fault)
}

/// The shared body: derive and validate the lock path, then take it.
fn acquire(
    paths: &Paths,
    user: &str,
    acct: &str,
    budget: LockBudget,
    cancel: &Cancel,
    fault: &Fault,
) -> Result<CodexNamespaceGuard, LockError> {
    let path =
        paths.codex_lock_path(user, acct).map_err(|err| LockError::Unavailable(err.to_string()))?;
    let name = path.file_name().and_then(OsStr::to_str).ok_or_else(|| {
        LockError::Unavailable(format!("`{}` does not name a lock file", path.display()))
    })?;
    // `Instant + Duration` panics on overflow. A budget that large is not one
    // any caller passes; it fails closed as an immediate attempt (then `Busy`)
    // rather than as a panic.
    let now = Instant::now();
    let deadline = now.checked_add(budget.duration()).unwrap_or(now);
    let guard = namespace_lock::acquire_at(
        &paths.codex_locks_dir(),
        name,
        deadline,
        cancel,
        fault.clone(),
    )?;
    Ok(CodexNamespaceGuard::wrap(guard))
}

#[cfg(test)]
#[path = "lock_tests.rs"]
mod tests;
