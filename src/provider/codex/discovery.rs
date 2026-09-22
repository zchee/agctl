//! Which Codex accounts a pass looks at, and what `doctor` should report as
//! left behind (plan section 3.1, section 3.3 step 2).
//!
//! Nothing here reads a credential. A source says where a row's credentials
//! are and, for an owned namespace, what the daemon evidence is; the read
//! itself happens in `auth_store` — under the namespace lock for an owned row
//! — so `LockedCredentials` is never built here (a planted `from_locked_read`
//! in this file fails `scripts/phase3-greps.sh`'s `locked_read` rule).

use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::SystemTime;

use crate::config::codex::CodexAccountRecord;
use crate::config::codex::CodexKind;
use crate::config::paths::Paths;
use crate::provider::codex::auth_store;
use crate::provider::codex::home;
use crate::provider::codex::home::CodexEnv;
use crate::provider::codex::home::DaemonEvidence;
use crate::provider::codex::home::HomeError;
use crate::provider::codex::proof;
use crate::provider::codex::proof::OwnedRecord;
use crate::runtime::coordinator::Cancel;

/// The name every login scratch home starts with (plan section 3.3, L2′).
pub const SCRATCH_PREFIX: &str = "agctl-codex-login-";

/// A scratch home older than this, with nothing holding it, is left behind:
/// the login's ten-minute deadline plus five (architect L7).
pub const SCRATCH_STALE_AFTER: Duration = Duration::from_secs(15 * 60);

/// Where one row's credentials are.
#[derive(Debug)]
pub enum CodexSource<'a> {
    /// The user's own `CODEX_HOME`: read-only, never refreshed.
    Live {
        /// The resolved home.
        home: PathBuf,
    },
    /// Another Codex home recorded by `import`: read-only.
    HomeReadOnly {
        /// The record.
        record: &'a CodexAccountRecord,
        /// The recorded home. Never a write target (invariant I27).
        dir: &'a Path,
    },
    /// An agctl-owned namespace.
    Owned {
        /// The record.
        record: &'a CodexAccountRecord,
        /// The proof a lock and a namespace handle take.
        owned: OwnedRecord<'a>,
        /// Codex daemon evidence in the namespace, taken without any lock.
        evidence: DaemonEvidence,
    },
    /// An owned record whose ids cannot name a namespace.
    InvalidOwned {
        /// The record.
        record: &'a CodexAccountRecord,
    },
}

impl CodexSource<'_> {
    /// The registry record behind the row; `None` for the live home.
    pub fn record(&self) -> Option<&CodexAccountRecord> {
        match self {
            Self::Live { .. } => None,
            Self::HomeReadOnly { record, .. }
            | Self::Owned { record, .. }
            | Self::InvalidOwned { record } => Some(record),
        }
    }
}

/// The rows a pass looks at, in registry order after the live home.
///
/// Forgotten and `live` records are skipped: the live home is discovered from
/// `env`, not from the registry, and a forgotten row is hidden by the user.
///
/// # Errors
///
/// None; a live home that cannot be resolved is returned beside the rows, so
/// the registry's rows are still shown.
pub fn sources<'a>(
    paths: &Paths,
    accounts: &'a [CodexAccountRecord],
    env: &CodexEnv,
    cancel: &Cancel,
) -> (Vec<CodexSource<'a>>, Option<HomeError>) {
    let mut rows = Vec::new();
    let live_error = match home::codex_home(env) {
        Ok(home) => {
            rows.push(CodexSource::Live { home });
            None
        }
        Err(err) => Some(err),
    };
    for record in accounts.iter().filter(|record| !record.forgotten) {
        match &record.kind {
            CodexKind::Live => {}
            CodexKind::HomeReadOnly { dir } => rows.push(CodexSource::HomeReadOnly { record, dir }),
            CodexKind::Owned { .. } => match proof::owned(record) {
                Some(owned) => {
                    let evidence = paths
                        .codex_namespace_dir(owned.user(), owned.acct())
                        .map(|dir| home::daemon_evidence(&dir, cancel))
                        .unwrap_or(DaemonEvidence::None);
                    rows.push(CodexSource::Owned { record, owned, evidence });
                }
                None => rows.push(CodexSource::InvalidOwned { record }),
            },
        }
    }
    (rows, live_error)
}

/// Something agctl's own tree holds that no record explains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Orphan {
    /// A namespace directory with no owned record.
    NamespaceWithoutRecord {
        /// The user directory's name.
        user: String,
        /// The account directory's name.
        acct: String,
    },
    /// An owned record whose namespace holds no credential file.
    RecordWithoutCredentials {
        /// The record's user id.
        user: String,
        /// The record's account id.
        acct: String,
    },
    /// A login scratch home older than [`SCRATCH_STALE_AFTER`].
    StaleScratch {
        /// Its directory name.
        name: String,
        /// How old it is.
        age: Duration,
    },
}

/// Everything under `codex_root()` that no record explains (for `doctor`).
///
/// Names from disk are reported as found and never used as paths to write
/// through; only directories are considered, and dot-names (`.locks`,
/// `.state`, `.scratch`) are agctl's own.
///
/// # Errors
///
/// [`io::Error`] when a directory that exists cannot be listed. An absent
/// Codex tree has no orphans.
pub fn orphans(
    paths: &Paths,
    accounts: &[CodexAccountRecord],
    now: SystemTime,
) -> io::Result<Vec<Orphan>> {
    let owned: Vec<(&str, &str)> = accounts
        .iter()
        .filter_map(proof::owned)
        .map(|owned| (owned.user(), owned.acct()))
        .collect();
    let mut found = Vec::new();

    for user in directories(&paths.codex_root())? {
        if user.starts_with('.') {
            continue;
        }
        for acct in directories(&paths.codex_root().join(&user))? {
            if !owned.contains(&(user.as_str(), acct.as_str())) {
                found.push(Orphan::NamespaceWithoutRecord { user: user.clone(), acct });
            }
        }
    }

    for (user, acct) in &owned {
        let Ok(dir) = paths.codex_namespace_dir(user, acct) else { continue };
        match fs::symlink_metadata(dir.join(auth_store::shown_name())) {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                found.push(Orphan::RecordWithoutCredentials {
                    user: (*user).to_owned(),
                    acct: (*acct).to_owned(),
                });
            }
            Err(err) => return Err(err),
        }
    }

    for name in directories(&paths.codex_scratch_root())? {
        if !name.starts_with(SCRATCH_PREFIX) {
            continue;
        }
        let modified = fs::symlink_metadata(paths.codex_scratch_root().join(&name))?.modified()?;
        let age = now.duration_since(modified).unwrap_or(Duration::ZERO);
        if age > SCRATCH_STALE_AFTER {
            found.push(Orphan::StaleScratch { name, age });
        }
    }
    Ok(found)
}

/// The names of the real directories (not links) in `dir`, sorted; none when
/// `dir` does not exist.
fn directories(dir: &Path) -> io::Result<Vec<String>> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    names.sort();
    Ok(names)
}

#[cfg(test)]
#[path = "discovery_tests.rs"]
mod tests;
