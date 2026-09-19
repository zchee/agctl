//! The account registry: what agctl knows about, and how it knows it.
//!
//! One JSON document, `config.json`, holds one [`AccountRecord`] per account
//! agctl has been told about. The record's [`AccountKind`] is the important
//! part, because it decides where the credentials come from and — far more
//! importantly — whether agctl may write them:
//!
//! - [`AccountKind::Owned`] — created by `agctl claude login`. The
//!   credentials live in this store, under `claude/<acct>/<org>/`, and
//!   agctl refreshes them.
//! - [`AccountKind::Live`] — the credentials Claude Code itself is using.
//!   Read-only, always (decision D-001): a refresh here would rotate the
//!   token out from under a running session.
//! - [`AccountKind::ConfigDirReadOnly`] — a keychain item belonging to some
//!   other `CLAUDE_CONFIG_DIR`. Read-only for the same reason, and displayed
//!   only so the user can see it exists.
//! - [`AccountKind::Foreign`] — a credential that exists on the machine but
//!   belongs to something else: another tool's keychain item, or a token in
//!   the environment. agctl reports that it is there and never reads it,
//!   so such a row is always `needs login`.
//!
//! The registry is small and rewritten whole. It is still written under a lock
//! and through a temporary file, because two `agctl` processes racing to
//! add an account must not leave a truncated document behind.
//!
//! # Two providers, two lists, one file
//!
//! Codex accounts live in [`AgctlConfig::codex_accounts`] as
//! [`CodexAccountRecord`](codex::CodexAccountRecord)s, not as a fifth
//! [`AccountKind`]. The reasons are in [`codex`]; the consequence here is the
//! [`AgctlConfig::version`], which is **derived from the content at every
//! write** rather than remembered: 1 while there are no Codex rows, 2 once
//! there are, and back to 1 when the last one is removed. That is what lets a
//! Claude-only registry stay byte-identical to what a phase-2 build wrote, and
//! what makes such a build's refusal of a version-2 file truthful rather than
//! a version bump nobody needed (plan D-038, AC99).

pub mod codex;
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

/// The schema version of a registry with Claude accounts and nothing else.
///
/// The version is **derived at every write** from what the document holds, not
/// remembered from what was read (plan decision D-038): a registry whose last
/// Codex row was removed goes back to 1, and a phase-2 build can read it again.
/// The two constants are therefore a property of the content, not a setting.
pub const CONFIG_VERSION: u32 = 1;

/// The schema version of a registry that holds at least one Codex account.
///
/// A phase-2 build refuses this file by version rather than ignoring the
/// member it does not know (risk R50). That refusal is the honest answer: such
/// a build would drop every `codex_accounts` row on its next write, and a
/// silently emptied registry is worse than one that says it is too new.
pub const CONFIG_VERSION_CODEX: u32 = 2;

/// Every version this build reads.
pub const SUPPORTED_VERSIONS: std::ops::RangeInclusive<u32> = CONFIG_VERSION..=CONFIG_VERSION_CODEX;

/// How long `save` waits for the configuration lock before giving up.
///
/// Short on purpose: the only thing held under this lock is a rewrite of a
/// small file, so a wait this long already means something is wrong.
pub const CONFIG_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// The registry document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgctlConfig {
    /// Schema version; [`CONFIG_VERSION`] for anything this build wrote.
    pub version: u32,
    /// Every account this store knows about, in insertion order.
    #[serde(default)]
    pub accounts: Vec<AccountRecord>,
    /// Keychain service names the user has asked `status` and `doctor` to stop
    /// reporting (`accounts forget`).
    ///
    /// Separate from [`AccountRecord::forgotten`] because the rows this hides
    /// have no record to carry a flag: an `unclaimed` or `identity unknown`
    /// item is discovered from the keychain listing alone, and the registry is
    /// keyed by `(account, organization)` — identifiers such an item, by
    /// definition, may not have. The name is remembered, nothing else; the
    /// keychain item itself is never touched (plan AC47, invariant I1).
    #[serde(default)]
    pub forgotten_services: Vec<String>,
    /// Every Codex account this store knows about, in insertion order.
    ///
    /// A list of its own rather than more [`AccountRecord`]s, for the reasons
    /// [`codex`] gives. It is **skipped when empty**, so a registry with no
    /// Codex account serializes to exactly the bytes this build's predecessor
    /// wrote — which, with the derived [`AgctlConfig::version`], is the whole
    /// of what keeps a Claude-only store readable by a phase-2 binary
    /// (plan AC99).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub codex_accounts: Vec<codex::CodexAccountRecord>,
}

impl Default for AgctlConfig {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            accounts: Vec::new(),
            forgotten_services: Vec::new(),
            codex_accounts: Vec::new(),
        }
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
    /// Where the credentials live and whether agctl may write them.
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
    /// Created by `agctl claude login`; agctl owns and refreshes it.
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
    /// A credential belonging to something that is not agctl and not
    /// Claude Code, so there is nothing here agctl may read.
    ///
    /// Synthesized by discovery from the keychain listing and from the
    /// environment; no command records one.
    Foreign {
        /// What owns it: a third-party tool, or an environment variable.
        source: String,
    },
}

impl AccountKind {
    /// The kind as one stable, machine-readable token, for the `kind` member
    /// of `status --json`, the `Kind` column of `accounts list`, and the
    /// `kind` field of the tracing span.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Owned { .. } => "owned",
            Self::Live => "live",
            Self::ConfigDirReadOnly { .. } => "config_dir",
            Self::Foreign { .. } => "foreign",
        }
    }
}

impl AgctlConfig {
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
            AppError::Config(format!("`{}` is not a valid agctl config: {err}", path.display()))
        })?;
        if !SUPPORTED_VERSIONS.contains(&config.version) {
            return Err(AppError::Config(format!(
                "`{}` is version {}, but this build understands version {CONFIG_VERSION} and \
                 version {CONFIG_VERSION_CODEX}",
                path.display(),
                config.version
            )));
        }
        // A version-1 document with Codex rows in it was written by something
        // that did not derive the version — a hand edit, or a merge of two
        // files. Refused rather than accepted, because the two halves
        // disagree about what the file is: a phase-2 build would read the
        // same bytes, believe the version, and erase the rows on its next
        // write (plan AC99, D-038).
        if config.version == CONFIG_VERSION && !config.codex_accounts.is_empty() {
            return Err(AppError::Config(format!(
                "`{}` says version {CONFIG_VERSION} but holds {} Codex account(s); a registry \
                 with Codex accounts is version {CONFIG_VERSION_CODEX}",
                path.display(),
                config.codex_accounts.len()
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
        // The only place `.config.lock` is taken. A thread holding a Codex
        // namespace guard must not block here (numbered deviation 13).
        #[cfg(feature = "testing")]
        crate::runtime::lock_order::assert_no_codex_guard_before_config_lock();
        let guard = namespace_lock::lock_file(&lock_path, deadline, &cancel, &Fault::none())
            .map_err(|err| AppError::Refused {
                reason: format!("could not lock `{}`: {err}", lock_path.display()),
            })?;

        let mut config = Self::load(paths)?;
        let value = f(&mut config);
        config.write_locked(paths, &guard)?;
        Ok(value)
    }

    /// The version this document *is*, from what it holds (plan D-038).
    ///
    /// Derived rather than stored, so the stamp cannot drift from the content:
    /// an emptied `codex_accounts` returns the file to version 1 and a
    /// phase-2 build can read it again, and no code path can add a Codex row
    /// and forget to raise the version.
    fn derived_version(&self) -> u32 {
        if self.codex_accounts.is_empty() { CONFIG_VERSION } else { CONFIG_VERSION_CODEX }
    }

    /// The exact bytes [`AgctlConfig::write_locked`] renames into place.
    ///
    /// Split out so the derivation is testable without a store, a lock or a
    /// filesystem: what a document serializes to is the whole of the
    /// compatibility promise (AC99), and a test that had to take a lock to
    /// check it would be testing the lock.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Config`] when the document cannot be serialized.
    fn document(&self) -> Result<String, AppError> {
        let stamped = Self { version: self.derived_version(), ..self.clone() };
        serde_json::to_string_pretty(&stamped)
            .map_err(|err| AppError::Config(format!("could not serialize the config: {err}")))
    }

    /// Writes the registry atomically. The caller holds the configuration
    /// lock, which is what the guard argument is there to prove.
    fn write_locked(
        &self,
        paths: &Paths,
        _guard: &namespace_lock::NamespaceLockGuard,
    ) -> Result<(), AppError> {
        let document = self.document()?;

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
