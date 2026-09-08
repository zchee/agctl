//! Learning about accounts from something that is not agentctl.
//!
//! Two sources, one rule: **an import records what is already true and
//! changes nothing else** (decision D-007). Nothing here writes a credential,
//! moves one, or deletes one, and neither source is asked for token material
//! in the first place.
//!
//! - `--from claude-switcher` reads a third-party tool's account list (fact
//!   F10). That file holds identities and no secrets; the switcher's secrets
//!   live in its own `claude-switcher:<email>` keychain items, which agentctl
//!   never reads and never writes (invariant I1). So an imported account is
//!   [`AccountKind::Metadata`] and renders `needs login` until the user logs
//!   it in — which is the honest state, not a limitation.
//! - `--from keychain` records Claude Code credential items belonging to
//!   other configuration directories as [`AccountKind::ConfigDirReadOnly`].
//!   Those are read, once, to learn who they belong to; they are never
//!   written and never refreshed (decision D-009).
//!
//! # Why the planners are pure
//!
//! Every function here takes what it needs as an argument — the file's bytes,
//! the keychain listing, the registry as it stands — and returns an
//! [`ImportPlan`] describing what *would* happen. Nothing here touches the
//! registry. That is what makes `--dry-run` the same code path as a real run
//! with one call omitted, rather than a second implementation that can drift
//! from the first, and it is what lets the acceptance tests assert on a whole
//! import without a keychain or a store.
//!
//! # Identity still never comes from a path
//!
//! A keychain item names a *directory spelling*, not an account (fact F14).
//! So the account a `--claude-config-dir` import records is whoever the
//! item's `tokenAccount` says it is, and an item that names nobody produces a
//! record keyed by the service name that renders `identity unknown`
//! (invariant I13). The directory decides which item to look at and nothing
//! else.

use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;

use serde::Deserialize;

use crate::config::AccountKind;
use crate::config::AccountRecord;
use crate::config::AgentctlConfig;
use crate::config::new_record;
use crate::config::paths::UNKNOWN_ORG;
use crate::error::AppError;
use crate::provider::claude::credentials::Identity;
use crate::provider::claude::namespace;
use crate::provider::claude::namespace::EnvView;
use crate::provider::claude::namespace::LIVE_SERVICE;
use crate::provider::claude::namespace::ServiceKind;
use crate::secret::KeychainReader;
use crate::secret::ServiceEntry;
use crate::secret::location;
use crate::secret::location::Resolved;

/// The `source` recorded on an account imported from the switcher.
pub const SWITCHER_SOURCE: &str = "claude-switcher";

/// The switcher account-file schema version this build understands.
pub const SWITCHER_VERSION: u32 = 2;

/// The largest switcher account file that will be read.
///
/// The real file is a few kilobytes of identities. A megabyte is far above
/// anything the tool produces and still small enough that a corrupt or
/// hostile file cannot exhaust memory.
pub const MAX_SWITCHER_BYTES: u64 = 1 << 20;

/// The `provider` value whose entries agentctl can use.
const CLAUDE_PROVIDER: &str = "claude";

/// The prefix of the keychain services an import considers.
///
/// Narrower than discovery's prefix on purpose: it excludes the legacy
/// `Claude Code-<sha8>` API-key items (fact F5) and the `claude-switcher:*`
/// items (fact F10) at the listing call, so this command never even asks the
/// keychain about an item it must not touch.
pub const IMPORT_SERVICE_PREFIX: &str = crate::secret::CLAUDE_SERVICE_PREFIX;

/// What an import would do about one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Add this account to the registry.
    Record {
        /// The record to upsert.
        record: Box<AccountRecord>,
        /// What to show beside it: an email address, or a directory.
        detail: String,
    },
    /// The registry already knows this account. It is left exactly as it is,
    /// so an import can never downgrade a logged-in account to metadata.
    AlreadyKnown {
        /// How the existing record is addressed.
        id: String,
        /// The existing record's kind.
        kind: &'static str,
    },
    /// Not an account this import can record.
    Skipped {
        /// What was skipped, in the user's terms.
        what: String,
        /// The short tag the summary groups by.
        reason: String,
    },
    /// Something the user should see that is not itself an account.
    Warning(String),
}

/// Everything one `import` run would do, in source order.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ImportPlan {
    /// One decision per entry considered.
    pub decisions: Vec<Decision>,
}

impl ImportPlan {
    /// The records this plan would add, in order.
    pub fn records(&self) -> Vec<AccountRecord> {
        self.decisions
            .iter()
            .filter_map(|decision| match decision {
                Decision::Record { record, .. } => Some((**record).clone()),
                _ => None,
            })
            .collect()
    }

    /// The lines to print: one per decision, then the summary.
    pub fn lines(&self) -> Vec<String> {
        let mut lines: Vec<String> = self.decisions.iter().map(render).collect();
        lines.push(self.summary());
        lines
    }

    /// The closing line: `imported N, skipped M (codex), already known K`.
    ///
    /// The skipped count is broken down by reason, because "3 skipped" and
    /// "3 skipped because they are Codex accounts" mean very different things
    /// to somebody wondering whether the import worked.
    pub fn summary(&self) -> String {
        let mut imported = 0_usize;
        let mut known = 0_usize;
        let mut skipped: BTreeMap<&str, usize> = BTreeMap::new();
        for decision in &self.decisions {
            match decision {
                Decision::Record { .. } => imported = imported.saturating_add(1),
                Decision::AlreadyKnown { .. } => known = known.saturating_add(1),
                Decision::Skipped { reason, .. } => {
                    *skipped.entry(reason.as_str()).or_default() += 1;
                }
                Decision::Warning(_) => {}
            }
        }

        let total: usize = skipped.values().copied().fold(0, usize::saturating_add);
        let detail = match skipped.len() {
            0 => String::new(),
            1 => format!(" ({})", skipped.keys().copied().collect::<String>()),
            _ => {
                let parts: Vec<String> =
                    skipped.iter().map(|(reason, count)| format!("{count} {reason}")).collect();
                format!(" ({})", parts.join(", "))
            }
        };
        format!("imported {imported}, skipped {total}{detail}, already known {known}")
    }
}

/// Renders one decision as a line.
fn render(decision: &Decision) -> String {
    match decision {
        Decision::Record { record, detail } => format!(
            "import {}: {}/{} ({detail})",
            kind_label(&record.kind),
            record.account_uuid,
            record.organization_uuid
        ),
        Decision::AlreadyKnown { id, kind } => format!("already known as {kind}: {id}"),
        Decision::Skipped { what, reason } => format!("skipped ({reason}): {what}"),
        Decision::Warning(text) => format!("warning: {text}"),
    }
}

/// The word this crate uses for an account kind in user-facing output.
fn kind_label(kind: &AccountKind) -> &'static str {
    match kind {
        AccountKind::Owned { .. } => "owned",
        AccountKind::Live => "live",
        AccountKind::ConfigDirReadOnly { .. } => "config-dir-read-only",
        AccountKind::Metadata { .. } => "metadata",
    }
}

// ---------------------------------------------------------------------------
// claude-switcher
// ---------------------------------------------------------------------------

/// The switcher's account file, as much of it as agentctl reads.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct SwitcherFile {
    /// The schema version. Required: a file that does not say which schema it
    /// is written in is not one to guess at.
    version: u32,
    /// The accounts, in the order the switcher listed them.
    #[serde(default)]
    accounts: Vec<SwitcherAccount>,
}

/// One entry of the switcher's `accounts[]` (fact F10).
///
/// Every field is optional because this file belongs to another tool: a
/// version of it that stops writing `org_name`, or starts writing a third
/// provider, must degrade to "skipped, here is why" rather than to a parse
/// failure that hides the entries agentctl *can* use.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SwitcherAccount {
    /// The address the switcher displays and keys its keychain item by.
    #[serde(default)]
    pub email: Option<String>,
    /// The organization name the switcher cached.
    #[serde(default)]
    pub org_name: Option<String>,
    /// `claude` or `codex`; anything else is skipped.
    #[serde(default)]
    pub provider: Option<String>,
    /// The `oauthAccount` object the switcher copied out of `.claude.json`.
    /// `null` for every Codex entry.
    #[serde(default)]
    pub oauth_account: Option<SwitcherOauthAccount>,
}

/// The identity fields of a switcher entry's `oauth_account`.
///
/// The real object carries a dozen more keys — trial dates, onboarding flags,
/// seat tier. None of them is identity, so none of them is read.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SwitcherOauthAccount {
    /// The Anthropic account UUID.
    #[serde(default, rename = "accountUuid")]
    pub account_uuid: Option<String>,
    /// The account's email address.
    #[serde(default, rename = "emailAddress")]
    pub email_address: Option<String>,
    /// The organization UUID, absent on a personal account.
    #[serde(default, rename = "organizationUuid")]
    pub organization_uuid: Option<String>,
    /// The organization's display name.
    #[serde(default, rename = "organizationName")]
    pub organization_name: Option<String>,
}

/// The switcher's account file, at the location the tool hard-codes.
///
/// Not derived from `XDG_CONFIG_HOME`: this is another program's path, and
/// that program spells it `~/.config/claude-switcher/accounts.json`
/// regardless of what XDG says. Reproducing agentctl's own conventions here
/// would look at a file the switcher never writes.
pub fn default_switcher_path(home: &Path) -> PathBuf {
    home.join(".config").join("claude-switcher").join("accounts.json")
}

/// Parses a switcher account file.
///
/// # Errors
///
/// Returns [`AppError::Config`] naming `path` and the first thing wrong with
/// it: unparseable JSON, a missing `version`, or a schema version this build
/// does not understand.
pub fn parse_switcher(bytes: &[u8], path: &Path) -> Result<Vec<SwitcherAccount>, AppError> {
    let file: SwitcherFile = serde_json::from_slice(bytes).map_err(|err| {
        AppError::Config(format!(
            "`{}` is not a claude-switcher account file: {err}",
            path.display()
        ))
    })?;
    if file.version != SWITCHER_VERSION {
        return Err(AppError::Config(format!(
            "`{}` is claude-switcher schema version {}, but agentctl understands version \
             {SWITCHER_VERSION}",
            path.display(),
            file.version
        )));
    }
    Ok(file.accounts)
}

/// Decides what to do with each parsed switcher entry.
///
/// Codex entries are counted and skipped; a Claude entry whose
/// `oauth_account` names no account UUID is skipped too, because an email
/// address is not an account identifier and inventing a key for it would
/// produce a row nothing can ever be logged into (invariant I13).
pub fn plan_switcher(accounts: &[SwitcherAccount], existing: &AgentctlConfig) -> ImportPlan {
    let mut plan = ImportPlan::default();
    let mut planned: Vec<(String, String)> = Vec::new();

    for account in accounts {
        let label = account
            .email
            .clone()
            .or_else(|| account.oauth_account.as_ref().and_then(|o| o.email_address.clone()))
            .unwrap_or_else(|| "<no email>".to_owned());

        match account.provider.as_deref() {
            Some(CLAUDE_PROVIDER) => {}
            Some(other) => {
                plan.decisions.push(Decision::Skipped { what: label, reason: other.to_owned() });
                continue;
            }
            None => {
                plan.decisions
                    .push(Decision::Skipped { what: label, reason: "no provider".to_owned() });
                continue;
            }
        }

        let Some(uuid) =
            account.oauth_account.as_ref().and_then(|oauth| oauth.account_uuid.clone())
        else {
            plan.decisions
                .push(Decision::Skipped { what: label, reason: "no account uuid".to_owned() });
            continue;
        };
        let oauth = account.oauth_account.as_ref();
        let org = oauth
            .and_then(|oauth| oauth.organization_uuid.clone())
            .unwrap_or_else(|| UNKNOWN_ORG.to_owned());

        if let Some(decision) = already_planned(existing, &planned, &uuid, &org) {
            plan.decisions.push(decision);
            continue;
        }

        let kind = AccountKind::Metadata { source: SWITCHER_SOURCE.to_owned() };
        let mut record = match new_record(uuid.clone(), org.clone(), kind) {
            Ok(record) => record,
            Err(err) => {
                plan.decisions.push(Decision::Skipped {
                    what: format!("{label}: {err}"),
                    reason: "unusable ids".to_owned(),
                });
                continue;
            }
        };
        record.email = oauth
            .and_then(|oauth| oauth.email_address.clone())
            .or_else(|| account.email.clone())
            .filter(|value| !value.is_empty());
        record.org_name = oauth
            .and_then(|oauth| oauth.organization_name.clone())
            .or_else(|| account.org_name.clone())
            .filter(|value| !value.is_empty());

        planned.push((uuid, org));
        plan.decisions.push(Decision::Record { record: Box::new(record), detail: label });
    }
    plan
}

// ---------------------------------------------------------------------------
// keychain
// ---------------------------------------------------------------------------

/// Decides what to do with each per-configuration-directory keychain item.
///
/// With `dirs` empty every `Claude Code-credentials-<sha8>` item in `listing`
/// that nothing already claims is considered. With `dirs` given, each one is
/// hashed the way Claude Code would hash it (fact F14: the *raw* spelling,
/// NFC-normalized, never a resolved path) and only that item is looked for.
///
/// The keychain is read — once per item, for the identity — and never
/// written (invariant I1).
pub fn plan_keychain(
    dirs: &[PathBuf],
    listing: &[ServiceEntry],
    reader: &dyn KeychainReader,
    env: &EnvView,
    existing: &AgentctlConfig,
) -> ImportPlan {
    // The live item is claimed by definition: it has its own row, built from
    // the environment rather than from the registry, and it is never a
    // per-directory account.
    let mut claimed: Vec<String> = vec![namespace::service_name(env)];
    claimed.extend(existing.accounts.iter().filter_map(|record| match &record.kind {
        AccountKind::ConfigDirReadOnly { service, .. } => Some(service.clone()),
        _ => None,
    }));

    if dirs.is_empty() {
        plan_listed_services(listing, reader, env, existing, &claimed)
    } else {
        plan_named_dirs(dirs, listing, reader, env, existing, &claimed)
    }
}

/// Considers every credential item in the listing that nothing claims.
fn plan_listed_services(
    listing: &[ServiceEntry],
    reader: &dyn KeychainReader,
    env: &EnvView,
    existing: &AgentctlConfig,
    claimed: &[String],
) -> ImportPlan {
    let mut plan = ImportPlan::default();
    let mut planned: Vec<(String, String)> = Vec::new();
    let live_hashes = live_dir_hashes(env);

    for entry in listing {
        if claimed.contains(&entry.service) {
            continue;
        }
        // Anything that is not a per-directory credential item — a legacy
        // API-key item, a name from some other tool — classifies as `None`
        // and is not an account to import (fact F5).
        let Some(ServiceKind::ConfigDir(sha8)) = namespace::classify(&entry.service) else {
            continue;
        };

        let kind = AccountKind::ConfigDirReadOnly {
            // Unknown: the item names a hash, and a hash cannot be turned
            // back into the directory that produced it.
            dir: PathBuf::new(),
            service: entry.service.clone(),
            shares_live_dir: live_hashes.contains(&sha8),
        };
        push_keychain_record(
            &mut plan,
            &mut planned,
            existing,
            reader,
            kind,
            &entry.service,
            &entry.service,
        );
    }
    plan
}

/// Considers exactly the directories the user named.
fn plan_named_dirs(
    dirs: &[PathBuf],
    listing: &[ServiceEntry],
    reader: &dyn KeychainReader,
    env: &EnvView,
    existing: &AgentctlConfig,
    claimed: &[String],
) -> ImportPlan {
    let mut plan = ImportPlan::default();
    let mut planned: Vec<(String, String)> = Vec::new();
    let live_service = namespace::service_name(env);
    let live_canonical = namespace::canonical(&namespace::live_store_dir(env)).ok();

    for dir in dirs {
        let shown = dir.display().to_string();
        let service = service_for_dir(dir, env);

        // Only an empty `--claude-config-dir` hashes to the unsuffixed name,
        // because the naming rule's gate is truthiness (fact F14). That item
        // is the live credential, which has its own row and is never a
        // per-directory account.
        if service == LIVE_SERVICE {
            plan.decisions.push(Decision::Skipped {
                what: shown,
                reason: "names the live keychain item".to_owned(),
            });
            continue;
        }
        if claimed.contains(&service) {
            // A directory can hash to the live item's own name — the two
            // spellings agree — in which case the account it names is the
            // live row, not a per-directory one.
            let (id, kind) = if service == live_service {
                ("live".to_owned(), "live")
            } else {
                (service.clone(), "config-dir-read-only")
            };
            plan.decisions.push(Decision::AlreadyKnown { id, kind });
            continue;
        }
        if !listing.iter().any(|entry| entry.service == service) {
            plan.decisions.push(Decision::Skipped {
                what: format!("no keychain item for {shown} (service `{service}`)"),
                reason: "no keychain item".to_owned(),
            });
            continue;
        }

        let shares_live_dir = shares_live_dir_by_path(dir, live_canonical.as_deref());
        if shares_live_dir {
            plan.decisions.push(Decision::Warning(format!(
                "{shown} is an alias of the live config dir; recorded as a stale sibling"
            )));
        }
        let kind = AccountKind::ConfigDirReadOnly {
            // The spelling as given, not where it resolves to: that spelling
            // is what the item is named after (fact F14, risk R20).
            dir: dir.clone(),
            service: service.clone(),
            shares_live_dir,
        };
        push_keychain_record(&mut plan, &mut planned, existing, reader, kind, &service, &shown);
    }
    plan
}

/// Builds one `ConfigDirReadOnly` decision and appends it.
///
/// `service` is both the item to read and the key to fall back to when that
/// item names nobody; `detail` is what the line shows beside the record.
fn push_keychain_record(
    plan: &mut ImportPlan,
    planned: &mut Vec<(String, String)>,
    existing: &AgentctlConfig,
    reader: &dyn KeychainReader,
    kind: AccountKind,
    service: &str,
    detail: &str,
) {
    let identity = identity_of(reader, service);
    let (uuid, org) = match &identity {
        Some(identity) => (
            identity.account_uuid.clone(),
            identity.organization_uuid.clone().unwrap_or_else(|| UNKNOWN_ORG.to_owned()),
        ),
        None => (service.to_owned(), UNKNOWN_ORG.to_owned()),
    };

    if let Some(decision) = already_planned(existing, planned, &uuid, &org) {
        plan.decisions.push(decision);
        return;
    }

    let record = match &identity {
        Some(identity) => match new_record(uuid.clone(), org.clone(), kind) {
            Ok(mut record) => {
                record.email = identity.email.clone();
                record.org_name = identity.org_name.clone();
                record
            }
            Err(err) => {
                plan.decisions.push(Decision::Skipped {
                    what: format!("{detail}: {err}"),
                    reason: "unusable ids".to_owned(),
                });
                return;
            }
        },
        // Keyed by the service name rather than by an account, and
        // deliberately not run through `validate_segment`: a service name
        // holds a space, and it is not a path. A `ConfigDirReadOnly` record
        // never gets a namespace directory — agentctl may not write one
        // (decision D-009) — so nothing derives a path from this key.
        None => service_keyed_record(uuid.clone(), kind),
    };

    let shown = match &identity {
        Some(_) => detail.to_owned(),
        None => format!("{detail}, identity unknown"),
    };
    planned.push((uuid, org));
    plan.decisions.push(Decision::Record { record: Box::new(record), detail: shown });
}

/// A record for an item that names nobody.
fn service_keyed_record(service: String, kind: AccountKind) -> AccountRecord {
    AccountRecord {
        account_uuid: service,
        organization_uuid: UNKNOWN_ORG.to_owned(),
        email: None,
        org_name: None,
        label: None,
        kind,
        forgotten: false,
        created_at: jiff::Timestamp::now().to_string(),
    }
}

/// Whoever a keychain item's `tokenAccount` says it belongs to (fact F33).
fn identity_of(reader: &dyn KeychainReader, service: &str) -> Option<Identity> {
    match location::from_keychain(reader, service) {
        Resolved::Credentials(credentials) => credentials.identity(),
        _ => None,
    }
}

/// The service name Claude Code would use for a session pointed at `dir`.
///
/// Built by asking [`namespace::service_name`] rather than by hashing here,
/// so the truthiness gate and the NFC rule stay stated in exactly one place.
fn service_for_dir(dir: &Path, env: &EnvView) -> String {
    let view = EnvView {
        securestorage_dir: None,
        config_dir: Some(dir.to_string_lossy().into_owned()),
        home: env.home.clone(),
        oauth_token_set: false,
    };
    namespace::service_name(&view)
}

/// The hashes a keychain item naming the live store directory could carry.
///
/// Two, not one: the spelling the environment gives and the path it resolves
/// to hash differently whenever the directory is reached through a symlink,
/// which on the reference machine it is (fact F41). An item under either one
/// is a stale sibling of the live row rather than a separate account.
fn live_dir_hashes(env: &EnvView) -> Vec<String> {
    let live_dir = namespace::live_store_dir(env);
    let mut hashes = vec![namespace::sha8(&namespace::export_spelling(&live_dir))];
    if let Ok(canonical) = namespace::canonical(&live_dir) {
        let hash = namespace::sha8(&namespace::export_spelling(&canonical));
        if !hashes.contains(&hash) {
            hashes.push(hash);
        }
    }
    hashes
}

/// Whether `dir` resolves to the same physical directory as the live store.
///
/// Path resolution, used for this question and this question only — never for
/// identity (invariant I13, fact F41).
fn shares_live_dir_by_path(dir: &Path, live_canonical: Option<&Path>) -> bool {
    match (namespace::canonical(dir).ok(), live_canonical) {
        (Some(resolved), Some(live)) => resolved == live,
        _ => false,
    }
}

/// The decision for a key the registry — or this run — already covers.
fn already_planned(
    existing: &AgentctlConfig,
    planned: &[(String, String)],
    uuid: &str,
    org: &str,
) -> Option<Decision> {
    if let Some(record) = existing.get(uuid, org) {
        return Some(Decision::AlreadyKnown {
            id: record.display_id(&existing.accounts),
            kind: kind_label(&record.kind),
        });
    }
    if planned.iter().any(|(planned_uuid, planned_org)| planned_uuid == uuid && planned_org == org)
    {
        return Some(Decision::Skipped {
            what: format!("{uuid}/{org}"),
            reason: "duplicate".to_owned(),
        });
    }
    None
}

#[cfg(test)]
#[path = "import_tests.rs"]
mod tests;
