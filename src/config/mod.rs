//! The account registry: what agentctl knows about, and how it knows it.
//!
//! One JSON document, `config.json`, holds one [`AccountRecord`] per account
//! agentctl has been told about. The record's [`AccountKind`] is the important
//! part, because it decides where the credentials come from and — far more
//! importantly — whether agentctl may write them:
//!
//! - [`AccountKind::Owned`] — created by `agentctl claude login`. The
//!   credentials live in this store, under `claude/<acct>/<org>/`, and
//!   agentctl refreshes them.
//! - [`AccountKind::Live`] — the credentials Claude Code itself is using.
//!   Read-only, always (decision D-001): a refresh here would rotate the
//!   token out from under a running session.
//! - [`AccountKind::ConfigDirReadOnly`] — a keychain item belonging to some
//!   other `CLAUDE_CONFIG_DIR`. Read-only for the same reason, and displayed
//!   only so the user can see it exists.
//! - [`AccountKind::Metadata`] — imported from something that carried no
//!   usable secret, such as `claude-account-switcher`'s account list
//!   (decision D-007). Always `needs login`.
//!
//! The registry is small and rewritten whole. It is still written under a lock
//! and through a temporary file, because two `agentctl` processes racing to
//! add an account must not leave a truncated document behind.

#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "remaining items are consumed by W2 (accounts, import, doctor) and W3 (watch)"
    )
)]

pub mod import;
pub mod paths;

use std::fs;
use std::io;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

use serde::Deserialize;
use serde::Serialize;

use crate::config::paths::FILE_MODE;
use crate::config::paths::Paths;
use crate::error::AppError;
use crate::runtime::coordinator::Cancel;
use crate::runtime::fault::Fault;
use crate::secret::namespace_lock;

/// The schema version this build writes and understands.
pub const CONFIG_VERSION: u32 = 1;

/// How long `save` waits for the configuration lock before giving up.
///
/// Short on purpose: the only thing held under this lock is a rewrite of a
/// small file, so a wait this long already means something is wrong.
pub const CONFIG_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// The registry document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentctlConfig {
    /// Schema version; [`CONFIG_VERSION`] for anything this build wrote.
    pub version: u32,
    /// Every account this store knows about, in insertion order.
    #[serde(default)]
    pub accounts: Vec<AccountRecord>,
}

impl Default for AgentctlConfig {
    fn default() -> Self {
        Self { version: CONFIG_VERSION, accounts: Vec::new() }
    }
}

/// One account, keyed by `(account_uuid, organization_uuid)` (decision D-008).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountRecord {
    /// The Anthropic account UUID.
    pub account_uuid: String,
    /// The organization UUID, or [`paths::UNKNOWN_ORG`] when the login could
    /// not name one.
    pub organization_uuid: String,
    /// The account's email address, when it is known.
    pub email: Option<String>,
    /// The organization's display name, when it is known.
    pub org_name: Option<String>,
    /// A user-chosen label, from `login --label`.
    pub label: Option<String>,
    /// Where the credentials live and whether agentctl may write them.
    pub kind: AccountKind,
    /// Whether the user has asked for this row to be hidden.
    #[serde(default)]
    pub forgotten: bool,
    /// When the record was created, RFC 3339 in UTC.
    pub created_at: String,
}

impl AccountRecord {
    /// The `(account, organization)` pair that keys this record.
    pub fn key(&self) -> (&str, &str) {
        (self.account_uuid.as_str(), self.organization_uuid.as_str())
    }

    /// The identifier shown in the table and accepted by `--account`.
    ///
    /// The bare account UUID when that is unambiguous within `all`, and
    /// `<acct>/<org>` when it is not.
    pub fn display_id(&self, all: &[AccountRecord]) -> String {
        let duplicated =
            all.iter().filter(|other| other.account_uuid == self.account_uuid).count() > 1;
        if duplicated {
            format!("{}/{}", self.account_uuid, self.organization_uuid)
        } else {
            self.account_uuid.clone()
        }
    }
}

/// Where an account's credentials live.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AccountKind {
    /// Created by `agentctl claude login`; agentctl owns and refreshes it.
    Owned {
        /// The namespace directory as it was spelled at login time, NFC
        /// normalized. Recorded so a moved store can be reported rather than
        /// silently producing a different keychain service name (risk R20).
        export_spelling: String,
        /// `sha8(export_spelling)` — the keychain service name a Claude Code
        /// session pointed at this namespace would migrate to (fact F35).
        export_sha8: String,
    },
    /// The credentials a running Claude Code session is using. Read-only.
    Live,
    /// A keychain item belonging to another `CLAUDE_CONFIG_DIR`. Read-only.
    ConfigDirReadOnly {
        /// The configuration directory the item is named after.
        dir: PathBuf,
        /// The keychain service name.
        service: String,
        /// Whether `dir` resolves to the same physical directory as the live
        /// store, which makes this a stale sibling rather than a separate
        /// account.
        shares_live_dir: bool,
    },
    /// Imported metadata with no usable secret.
    Metadata {
        /// What it was imported from, such as `claude-switcher`.
        source: String,
    },
}

impl AgentctlConfig {
    /// Reads the registry, treating an absent file as an empty registry.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Io`] when the file exists but cannot be read, and
    /// [`AppError::Config`] when it is not a registry this build understands.
    pub fn load(paths: &Paths) -> Result<Self, AppError> {
        let path = paths.config_file();
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(err) => {
                return Err(AppError::Io {
                    context: format!("could not read `{}`", path.display()),
                    source: err,
                });
            }
        };

        let config: Self = serde_json::from_slice(&bytes).map_err(|err| {
            AppError::Config(format!("`{}` is not a valid agentctl config: {err}", path.display()))
        })?;
        if config.version != CONFIG_VERSION {
            return Err(AppError::Config(format!(
                "`{}` is version {}, but this build understands version {CONFIG_VERSION}",
                path.display(),
                config.version
            )));
        }
        Ok(config)
    }

    /// Reads the registry, applies `f` to it, and writes it back — all under
    /// one hold of the configuration lock.
    ///
    /// This is the only way to change the registry, and the reason is the
    /// lock. `flock` is per open file description, so a caller that took
    /// `.config.lock` itself and then called a self-locking `save` would
    /// deadlock against its own descriptor; and a caller that did not take the
    /// lock would read, think, and write across a window in which another
    /// process could have added an account, which the write would then erase.
    /// Re-reading the file *inside* the lock closes both: `f` never sees a
    /// registry older than the lock it is protected by.
    ///
    /// `f` must not itself call `update`, `load` or anything else that touches
    /// the registry — it runs while the lock is held, so a nested acquisition
    /// would block until [`CONFIG_LOCK_TIMEOUT`] and then fail.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Refused`] when the lock is held past
    /// [`CONFIG_LOCK_TIMEOUT`], [`AppError::Config`] when the file on disk is
    /// not a registry this build understands, and [`AppError::Io`] for any
    /// filesystem failure along the way. `f`'s value is returned only when the
    /// write succeeded.
    pub fn update<R>(paths: &Paths, f: impl FnOnce(&mut Self) -> R) -> Result<R, AppError> {
        paths.ensure_dirs()?;

        let lock_path = paths.config_lock();
        let cancel = Cancel::new();
        let now = Instant::now();
        let deadline = now.checked_add(CONFIG_LOCK_TIMEOUT).unwrap_or(now);
        let guard = namespace_lock::lock_file(&lock_path, deadline, &cancel, &Fault::none())
            .map_err(|err| AppError::Refused {
                reason: format!("could not lock `{}`: {err}", lock_path.display()),
            })?;

        let mut config = Self::load(paths)?;
        let value = f(&mut config);
        config.write_locked(paths, &guard)?;
        Ok(value)
    }

    /// Writes the registry atomically. The caller holds the configuration
    /// lock, which is what the guard argument is there to prove.
    fn write_locked(
        &self,
        paths: &Paths,
        _guard: &namespace_lock::NamespaceLockGuard,
    ) -> Result<(), AppError> {
        let document = serde_json::to_string_pretty(self)
            .map_err(|err| AppError::Config(format!("could not serialize the config: {err}")))?;

        let target = paths.config_file();
        let tmp = target.with_extension(format!("json.tmp.{}", crate::secret::file_store::hex8()));
        let token = crate::runtime::cleanup::register_tmp_path(tmp.clone());
        let write = write_then_rename(&tmp, &target, document.as_bytes());
        crate::runtime::cleanup::unregister(token);
        match write {
            Ok(()) => Ok(()),
            Err(err) => {
                let _ = fs::remove_file(&tmp);
                Err(AppError::Io {
                    context: format!("could not write `{}`", target.display()),
                    source: err,
                })
            }
        }
    }

    /// Inserts or replaces the record for `(account_uuid, organization_uuid)`.
    pub fn upsert(&mut self, rec: AccountRecord) {
        match self.accounts.iter_mut().find(|existing| existing.key() == rec.key()) {
            Some(existing) => *existing = rec,
            None => self.accounts.push(rec),
        }
    }

    /// Looks up one record by its exact key.
    pub fn get(&self, acct: &str, org: &str) -> Option<&AccountRecord> {
        self.accounts.iter().find(|rec| rec.key() == (acct, org))
    }

    /// Resolves a user-supplied identifier to exactly one record.
    ///
    /// `<account_uuid>/<organization_uuid>` is tried first, because it is the
    /// spelling the ambiguity message below tells the user to fall back to and
    /// so must never itself be ambiguous. Anything else is matched against
    /// three fields at once — the account UUID, the email address, and the
    /// `login --label` label — and has to name exactly one record.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Config`] when nothing matches, or when more than
    /// one record does — in which case the message lists the unambiguous
    /// spellings so the user can pick one.
    pub fn resolve_id(&self, id: &str) -> Result<&AccountRecord, AppError> {
        if let Some((acct, org)) = id.split_once('/')
            && let Some(rec) = self.get(acct, org)
        {
            return Ok(rec);
        }

        let matches: Vec<&AccountRecord> = self
            .accounts
            .iter()
            .filter(|rec| {
                rec.account_uuid == id
                    || rec.email.as_deref() == Some(id)
                    || rec.label.as_deref() == Some(id)
            })
            .collect();

        match matches.as_slice() {
            [] => Err(AppError::Config(format!("no account matches `{id}`"))),
            [only] => Ok(only),
            many => {
                let candidates: Vec<String> = many
                    .iter()
                    .map(|rec| format!("{}/{}", rec.account_uuid, rec.organization_uuid))
                    .collect();
                Err(AppError::Config(format!(
                    "`{id}` matches {} accounts; use one of: {}",
                    many.len(),
                    candidates.join(", ")
                )))
            }
        }
    }
}

/// Writes `bytes` to `tmp` at 0600, fsyncs it, and renames it over `target`.
fn write_then_rename(
    tmp: &std::path::Path,
    target: &std::path::Path,
    bytes: &[u8],
) -> io::Result<()> {
    let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(FILE_MODE).open(tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(tmp, target)?;
    fs::set_permissions(target, std::os::unix::fs::PermissionsExt::from_mode(FILE_MODE))
}

/// Builds a record with `created_at` set to now.
///
/// # Errors
///
/// Returns [`AppError::Config`] when either identifier is unusable as a
/// directory name.
pub fn new_record(
    account_uuid: String,
    organization_uuid: String,
    kind: AccountKind,
) -> Result<AccountRecord, AppError> {
    paths::validate_segment(&account_uuid)?;
    paths::validate_segment(&organization_uuid)?;
    Ok(AccountRecord {
        account_uuid,
        organization_uuid,
        email: None,
        org_name: None,
        label: None,
        kind,
        forgotten: false,
        created_at: jiff::Timestamp::now().to_string(),
    })
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
