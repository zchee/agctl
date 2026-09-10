//! "Is somebody else using this namespace?" — asked before every write.
//!
//! agctl owns the namespaces it creates, but ownership is a claim, not a
//! guarantee. A Claude Code session can be pointed at one of them at any time
//! (that is the whole point of decision D-009's file shape), and once it is,
//! it will take a refresh lock, rewrite the store, and eventually migrate the
//! credentials into the keychain and delete the file (fact F35). Writing into
//! a namespace while that is happening is how two processes end up rotating
//! one refresh chain, which invalidates the other's token and costs the user
//! a login.
//!
//! So [`detect`] looks for the traces such a session leaves, and it is run
//! three times per refresh: during discovery, again under the namespace lock,
//! and again immediately before the rename (plan sections 3.3 and 3.5). The
//! residual race is the rename syscall itself, which is documented and
//! accepted (risk R23).
//!
//! Everything here is read-only. agctl never removes a lock artefact —
//! `doctor --remove-stale` is the single, interactive, heavily-qualified
//! exception (invariant I11).

use std::path::Path;
use std::time::SystemTime;

use crate::provider::claude::namespace;
use crate::secret::KeychainReader;
use crate::secret::ServiceEntry;

/// Claude Code's primary refresh lock, inside the store directory (fact F17).
pub const REFRESH_LOCK: &str = ".oauth_refresh.lock";

/// Claude Code's read-modify-write guard (fact F37).
pub const STORAGE_WRITE_LOCK: &str = ".storage-write";

/// What somebody else is doing with a namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForeignActivity {
    /// Nothing. agctl may proceed.
    None,
    /// A Claude Code lock artefact is present.
    ClaudeLock {
        /// The artefact's file name.
        name: String,
        /// How long ago it was last touched. Claude Code's holders heartbeat
        /// every 5 s and self-lapse after 60 s (facts F31, F36), so the age
        /// is what tells a live session from a crashed one — though agctl
        /// refuses either way.
        age_ms: u64,
    },
    /// A keychain item exists for this namespace: a session has migrated the
    /// credentials out of the file and agctl must stop writing it
    /// (fact F35, invariant I2).
    MigratedToKeychain {
        /// The service name that was found.
        service: String,
    },
}

/// The two spellings a namespace can be hashed under.
///
/// A Claude Code session pointed at the namespace hashes the string it was
/// *given*, so that is the primary spelling; but the user may have been given
/// a path through a symlink, in which case the canonical spelling hashes
/// differently and names a second possible item. Both are checked, because
/// missing either one means writing into a migrated namespace.
pub struct OwnedMeta<'a> {
    /// `sha8` of the namespace directory as agctl spelled it at login.
    pub export_sha8: &'a str,
    /// `sha8` of the same directory after symlink resolution, when it differs.
    pub canonical_sha8: Option<&'a str>,
}

/// Looks for signs that something other than agctl owns this namespace.
///
/// The keychain is only consulted when `listing` — the `dump-keychain`
/// attribute listing from this pass — actually contains the service name.
/// That keeps a namespace with no migration from issuing a
/// `find-generic-password` at all, which is what plan AC20 asserts, and it
/// keeps the common case to zero extra subprocesses.
pub fn detect(
    ns_dir: &Path,
    owned: &OwnedMeta<'_>,
    listing: &[ServiceEntry],
    reader: &dyn KeychainReader,
) -> ForeignActivity {
    let mut artefacts = vec![ns_dir.join(REFRESH_LOCK), ns_dir.join(STORAGE_WRITE_LOCK)];
    // The legacy lock sits *beside* the directory, named after its resolved
    // path with `.lock` appended (fact F17).
    if let Ok(canonical) = namespace::canonical(ns_dir) {
        let mut legacy = canonical.clone().into_os_string();
        legacy.push(".lock");
        artefacts.push(legacy.into());
    }

    for artefact in artefacts {
        if let Some(age_ms) = artefact_age_ms(&artefact) {
            let name = artefact
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| artefact.to_string_lossy().into_owned());
            return ForeignActivity::ClaudeLock { name, age_ms };
        }
    }

    for sha8 in [Some(owned.export_sha8), owned.canonical_sha8].into_iter().flatten() {
        let service = format!("{}-{sha8}", namespace::LIVE_SERVICE);
        if !listing.iter().any(|entry| entry.service == service) {
            continue;
        }
        match reader.read(&service) {
            // The item is there and readable: the namespace has migrated.
            Ok(Some(_)) => return ForeignActivity::MigratedToKeychain { service },
            // Listed but gone by the time it was read. Nothing owns it now.
            Ok(None) => {}
            // Listed but unreadable — locked, timed out, refused. The listing
            // is evidence enough: an item under this namespace's name exists,
            // so agctl stops writing. Failing closed here costs a refresh;
            // failing open costs the user's session.
            Err(_) => return ForeignActivity::MigratedToKeychain { service },
        }
    }

    ForeignActivity::None
}

/// How long ago a lock artefact was modified, or `None` if it is not there.
///
/// A clock that has gone backwards saturates to zero rather than wrapping —
/// overflow checks are off in every profile (constraint C-006) and a wrapped
/// age would read as roughly 584 million years, which is comfortably older
/// than any staleness threshold.
fn artefact_age_ms(path: &Path) -> Option<u64> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    let age = SystemTime::now().duration_since(modified).unwrap_or_default();
    Some(u64::try_from(age.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
#[path = "foreign_activity_tests.rs"]
mod tests;
