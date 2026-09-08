//! Turning a machine's keychain and this store's registry into a list of rows.
//!
//! Discovery is where the awkward facts about a real machine get handled, and
//! all of them come from one place: a keychain item is named after a *string*,
//! not after an account (fact F14). So the same account can appear under
//! several names, two names can point at one directory, and a name can outlive
//! the credentials it was created for.
//!
//! The rules that fall out of that, each earning its place:
//!
//! - **Fold by digest, never by path.** Two entries are the same account only
//!   when their token digests match. On the development machine the live item
//!   and `…-5cdc535f` name one physical directory and hold *different*
//!   credentials (facts F6, F41), so folding by path would merge two accounts
//!   into one row and show the wrong numbers.
//! - **Same directory, different credentials, is a stale sibling.** Hidden by
//!   default and counted in the footer, because it is real but not actionable.
//! - **Identity comes from `tokenAccount`, or from `.claude.json` for the
//!   live row only** (invariant I13, fact F33). A blob without one is
//!   `identity unknown` and stays visible, because the fix — log in — is
//!   something the user can act on.
//! - **An unrecognised Claude Code item is `unclaimed`, and shown.** It is a
//!   true statement about the machine. `accounts forget` hides it.
//! - **`claude-switcher:*` items are listed and never touched** (fact F10).
//!   They belong to a third-party tool that rewrites the live item on every
//!   switch; agentctl neither reads nor writes them.

#![cfg_attr(not(test), expect(dead_code, reason = "consumed by lane D and lane C"))]

use crate::config::AccountKind;
use crate::config::AccountRecord;
use crate::config::AgentctlConfig;
use crate::config::paths::Paths;
use crate::config::paths::UNKNOWN_ORG;
use crate::provider::claude::account::AccountRow;
use crate::provider::claude::account::AccountState;
use crate::provider::claude::account::Source;
use crate::provider::claude::credentials::Credentials;
use crate::provider::claude::credentials::Digests;
use crate::provider::claude::credentials::Identity;
use crate::provider::claude::namespace;
use crate::provider::claude::namespace::EnvView;
use crate::provider::claude::namespace::ServiceKind;
use crate::runtime::coordinator::PassCtx;
use crate::secret::KeychainReader;
use crate::secret::KeychainStatus;
use crate::secret::ServiceEntry;
use crate::secret::foreign_activity;
use crate::secret::foreign_activity::ForeignActivity;
use crate::secret::foreign_activity::OwnedMeta;
use crate::secret::location;
use crate::secret::location::Resolved;

/// The service-name prefixes discovery asks the keychain about.
///
/// `Claude Code` rather than `Claude Code-credentials`, so the legacy
/// `Claude Code-<sha8>` API-key items (fact F5) show up in the listing and get
/// rejected by [`namespace::classify`] — proving they are ignored, rather
/// than never looking at them.
const KEYCHAIN_PREFIXES: [&str; 2] = ["Claude Code", crate::secret::SWITCHER_SERVICE_PREFIX];

/// Appended to an owned row's note when the keychain could not be read, so
/// the migration probe could not run (plan section 3.3 step 1).
const MIGRATION_PROBE_SKIPPED: &str = "keychain locked — migration probe skipped";

/// Everything one pass found.
#[derive(Debug)]
pub struct Discovery {
    /// One row per account, in the order they should be rendered.
    pub rows: Vec<AccountRow>,
    /// What the keychain preflight said.
    pub preflight: KeychainStatus,
    /// The keychain items seen, attributes only.
    pub listing: Vec<ServiceEntry>,
}

/// Builds the row list for one pass.
pub fn discover(
    cfg: &AgentctlConfig,
    paths: &Paths,
    reader: &dyn KeychainReader,
    env: &EnvView,
    ctx: &PassCtx,
) -> Discovery {
    let preflight = reader.preflight();
    let keychain_readable = preflight == KeychainStatus::Unlocked;

    let mut listing = Vec::new();
    if keychain_readable {
        for prefix in KEYCHAIN_PREFIXES {
            match reader.list_services(prefix) {
                Ok(entries) => listing.extend(entries),
                Err(err) => {
                    tracing::debug!(prefix, error = %err, "could not list keychain services");
                }
            }
        }
        listing.sort_by(|a, b| a.service.cmp(&b.service));
        listing.dedup_by(|a, b| a.service == b.service);
    }

    let mut rows = Vec::new();
    let live_service = namespace::service_name(env);
    let live = live_row(&live_service, &preflight, reader, env);
    let live_digests = live.credentials.as_ref().map(Credentials::digests);
    rows.push(live);

    let mut claimed_services: Vec<String> = vec![live_service.clone()];
    for record in &cfg.accounts {
        if ctx.should_stop() {
            return Discovery { rows, preflight, listing };
        }
        if let AccountKind::ConfigDirReadOnly { service, .. } = &record.kind {
            claimed_services.push(service.clone());
        }
        if let Some(row) =
            record_row(record, cfg, paths, reader, &preflight, &listing, live_digests.as_ref())
        {
            rows.push(row);
        }
    }

    rows.extend(unclaimed_rows(
        &listing,
        &claimed_services,
        &live_service,
        reader,
        env,
        live_digests.as_ref(),
    ));

    if env.oauth_token_set {
        rows.push(env_token_row());
    }

    Discovery { rows, preflight, listing }
}

/// Builds the row for whatever Claude Code is using right now.
fn live_row(
    service: &str,
    preflight: &KeychainStatus,
    reader: &dyn KeychainReader,
    env: &EnvView,
) -> AccountRow {
    let resolved = match preflight {
        KeychainStatus::Unlocked => location::from_keychain(reader, service),
        // Not even attempted: a preflight that says the keychain is not
        // readable makes the read a certain prompt or a certain failure, and
        // invariant I10 forbids answering it from the file.
        KeychainStatus::Locked => Resolved::Locked,
        KeychainStatus::Timeout => Resolved::Transient("keychain timed out".to_owned()),
        KeychainStatus::Unavailable(detail) => {
            Resolved::Transient(format!("keychain unavailable: {detail}"))
        }
    };

    let (credentials, mut state, source) = match resolved {
        Resolved::Credentials(credentials) => {
            (Some(*credentials), AccountState::Ok, Source::Keychain)
        }
        Resolved::Absent => (None, AccountState::NeedsLogin, Source::None),
        Resolved::Locked => {
            (None, AccountState::KeychainLocked { detail: String::new() }, Source::None)
        }
        Resolved::Transient(detail) if matches!(preflight, KeychainStatus::Timeout) => {
            let _ = detail;
            (None, AccountState::KeychainTimeout, Source::None)
        }
        Resolved::Transient(detail) => (None, AccountState::Error(detail), Source::None),
    };

    // The live row is the one place `.claude.json` is evidence (fact F33):
    // it records the last login through this configuration directory, which
    // is exactly what the live credentials are.
    let identity = credentials
        .as_ref()
        .and_then(Credentials::identity)
        .or_else(|| claude_json_identity(&namespace::claude_json_path(env)));

    if credentials.is_some() && identity.is_none() {
        state = AccountState::IdentityUnknown;
    }

    let record = record_from_identity(identity.as_ref(), AccountKind::Live);
    let id = identity
        .as_ref()
        .map_or_else(|| "live".to_owned(), |identity| identity.account_uuid.clone());

    AccountRow {
        id,
        record,
        state,
        source,
        credentials,
        visible_by_default: true,
        note: Some(format!("keychain service `{service}`")),
    }
}

/// Builds the row for one registry record, or `None` when it folds into
/// another row.
fn record_row(
    record: &AccountRecord,
    cfg: &AgentctlConfig,
    paths: &Paths,
    reader: &dyn KeychainReader,
    preflight: &KeychainStatus,
    listing: &[ServiceEntry],
    live_digests: Option<&Digests>,
) -> Option<AccountRow> {
    let id = record.display_id(&cfg.accounts);

    if record.forgotten {
        return Some(AccountRow {
            id,
            record: record.clone(),
            state: AccountState::Forgotten,
            source: Source::None,
            credentials: None,
            visible_by_default: false,
            note: None,
        });
    }

    match &record.kind {
        // Synthesized separately, from the environment rather than from the
        // registry, because which item is "live" depends on the environment
        // the command was run in.
        AccountKind::Live => None,
        AccountKind::Metadata { source } => Some(AccountRow {
            id,
            record: record.clone(),
            state: AccountState::NeedsLogin,
            source: Source::None,
            credentials: None,
            visible_by_default: true,
            note: Some(format!("imported from {source}")),
        }),
        AccountKind::ConfigDirReadOnly { service, shares_live_dir, .. } => {
            let resolved = match preflight {
                KeychainStatus::Unlocked => location::from_keychain(reader, service),
                KeychainStatus::Locked => Resolved::Locked,
                KeychainStatus::Timeout => Resolved::Transient("keychain timed out".to_owned()),
                KeychainStatus::Unavailable(detail) => {
                    Resolved::Transient(format!("keychain unavailable: {detail}"))
                }
            };
            let credentials = match resolved {
                Resolved::Credentials(credentials) => Some(*credentials),
                _ => None,
            };
            if folds_into_live(live_digests, credentials.as_ref()) {
                return None;
            }

            let state = if *shares_live_dir {
                AccountState::StaleSiblingOfLive
            } else {
                read_only_state(credentials.as_ref(), preflight)
            };
            Some(AccountRow {
                id,
                record: record.clone(),
                state,
                source: if credentials.is_some() { Source::Keychain } else { Source::None },
                credentials,
                visible_by_default: !*shares_live_dir,
                note: Some(format!("keychain service `{service}`")),
            })
        }
        AccountKind::Owned { export_sha8, .. } => {
            let ns_dir = paths.namespace_dir(&record.account_uuid, &record.organization_uuid);
            let canonical_sha8 = canonical_sha8(&ns_dir);
            let owned = OwnedMeta {
                export_sha8,
                canonical_sha8: canonical_sha8
                    .as_deref()
                    .filter(|sha| *sha != export_sha8.as_str()),
            };

            // With an unreadable keychain the migration probe cannot run.
            // The row still uses the file, and says so: reporting `needs
            // login` here would be wrong and alarming (plan section 3.3
            // step 1).
            let probe_listing: &[ServiceEntry] =
                if matches!(preflight, KeychainStatus::Unlocked) { listing } else { &[] };
            let activity = foreign_activity::detect(&ns_dir, &owned, probe_listing, reader);

            let mut note = (!matches!(preflight, KeychainStatus::Unlocked))
                .then(|| MIGRATION_PROBE_SKIPPED.to_owned());

            let (credentials, state, source) = match &activity {
                ForeignActivity::MigratedToKeychain { service } => {
                    let credentials = match location::from_keychain(reader, service) {
                        Resolved::Credentials(credentials) => Some(*credentials),
                        _ => None,
                    };
                    let source =
                        if credentials.is_some() { Source::Keychain } else { Source::None };
                    (
                        credentials,
                        AccountState::MigratedToKeychain { service: service.clone() },
                        source,
                    )
                }
                ForeignActivity::ClaudeLock { name, age_ms } => {
                    let credentials = credentials_from_file(&ns_dir);
                    let source = if credentials.is_some() { Source::File } else { Source::None };
                    (
                        credentials,
                        AccountState::ClaudeSessionDetected { lock: name.clone(), age_ms: *age_ms },
                        source,
                    )
                }
                ForeignActivity::None => match location::from_file(&ns_dir) {
                    Resolved::Credentials(credentials) => {
                        (Some(*credentials), AccountState::Ok, Source::File)
                    }
                    Resolved::Absent => (None, AccountState::NeedsLogin, Source::None),
                    Resolved::Locked => {
                        (None, AccountState::KeychainLocked { detail: String::new() }, Source::None)
                    }
                    Resolved::Transient(detail) => {
                        (None, AccountState::Error(detail), Source::None)
                    }
                },
            };

            if note.is_some() && credentials.is_none() {
                note = Some(format!("{MIGRATION_PROBE_SKIPPED} (migration unknown)"));
            }

            Some(AccountRow {
                id,
                record: record.clone(),
                state,
                source,
                credentials,
                visible_by_default: true,
                note,
            })
        }
    }
}

/// Builds rows for keychain items no registry record claims.
fn unclaimed_rows(
    listing: &[ServiceEntry],
    claimed: &[String],
    live_service: &str,
    reader: &dyn KeychainReader,
    env: &EnvView,
    live_digests: Option<&Digests>,
) -> Vec<AccountRow> {
    let live_dir = namespace::live_store_dir(env);
    let live_spelling_sha8 = namespace::sha8(&namespace::export_spelling(&live_dir));
    let live_canonical_sha8 = canonical_sha8(&live_dir);

    let mut rows = Vec::new();
    for entry in listing {
        if claimed.iter().any(|service| service == &entry.service) {
            continue;
        }
        if entry.service.starts_with(crate::secret::SWITCHER_SERVICE_PREFIX) {
            rows.push(foreign_row(entry));
            continue;
        }

        // Legacy `Claude Code-<sha8>` API-key items classify as `None` and
        // are dropped here (fact F5, plan AC18).
        let Some(ServiceKind::ConfigDir(sha8)) = namespace::classify(&entry.service) else {
            continue;
        };
        if entry.service == live_service {
            continue;
        }

        let credentials = match location::from_keychain(reader, &entry.service) {
            Resolved::Credentials(credentials) => Some(*credentials),
            _ => None,
        };
        if folds_into_live(live_digests, credentials.as_ref()) {
            continue;
        }

        let shares_live_dir =
            sha8 == live_spelling_sha8 || Some(sha8.as_str()) == live_canonical_sha8.as_deref();
        let identity = credentials.as_ref().and_then(Credentials::identity);
        let state = if shares_live_dir {
            AccountState::StaleSiblingOfLive
        } else if credentials.is_some() && identity.is_none() {
            AccountState::IdentityUnknown
        } else {
            AccountState::Unclaimed
        };

        let record = record_from_identity(
            identity.as_ref(),
            AccountKind::ConfigDirReadOnly {
                dir: std::path::PathBuf::new(),
                service: entry.service.clone(),
                shares_live_dir,
            },
        );
        rows.push(AccountRow {
            id: identity
                .as_ref()
                .map_or_else(|| entry.service.clone(), |identity| identity.account_uuid.clone()),
            record,
            state,
            source: if credentials.is_some() { Source::Keychain } else { Source::None },
            credentials,
            visible_by_default: !shares_live_dir,
            note: Some(format!("keychain service `{}`", entry.service)),
        });
    }
    rows
}

/// A `claude-switcher:*` item: listed, hidden, and never read.
fn foreign_row(entry: &ServiceEntry) -> AccountRow {
    let email = entry
        .service
        .strip_prefix(crate::secret::SWITCHER_SERVICE_PREFIX)
        .map(str::to_owned)
        .filter(|value| !value.is_empty());
    let mut record =
        record_from_identity(None, AccountKind::Metadata { source: "claude-switcher".to_owned() });
    record.email = email;
    AccountRow {
        id: entry.service.clone(),
        record,
        state: AccountState::Unclaimed,
        source: Source::None,
        credentials: None,
        visible_by_default: false,
        note: Some("foreign: managed by claude-account-switcher, never read or written".to_owned()),
    }
}

/// The row for `CLAUDE_CODE_OAUTH_TOKEN` (fact F19).
fn env_token_row() -> AccountRow {
    AccountRow {
        id: "env".to_owned(),
        record: record_from_identity(
            None,
            AccountKind::Metadata { source: namespace::OAUTH_TOKEN_ENV.to_owned() },
        ),
        state: AccountState::EnvToken,
        source: Source::Env,
        credentials: None,
        visible_by_default: true,
        note: Some(format!(
            "{} is set and short-circuits every credential store",
            namespace::OAUTH_TOKEN_ENV
        )),
    }
}

/// The state of a row agentctl may read but never refresh.
fn read_only_state(credentials: Option<&Credentials>, preflight: &KeychainStatus) -> AccountState {
    match (credentials, preflight) {
        (Some(credentials), _) => {
            if credentials.identity().is_none() {
                AccountState::IdentityUnknown
            } else {
                AccountState::Ok
            }
        }
        (None, KeychainStatus::Locked) => AccountState::KeychainLocked { detail: String::new() },
        (None, KeychainStatus::Timeout) => AccountState::KeychainTimeout,
        (None, KeychainStatus::Unavailable(detail)) => {
            AccountState::Error(format!("keychain unavailable: {detail}"))
        }
        (None, KeychainStatus::Unlocked) => AccountState::NeedsLogin,
    }
}

/// Whether two credentials are the same account, by digest alone.
fn folds_into_live(live: Option<&Digests>, candidate: Option<&Credentials>) -> bool {
    match (live, candidate) {
        (Some(live), Some(candidate)) => *live == candidate.digests(),
        _ => false,
    }
}

/// Reads a namespace's credentials, discarding the failure reason.
fn credentials_from_file(ns_dir: &std::path::Path) -> Option<Credentials> {
    match location::from_file(ns_dir) {
        Resolved::Credentials(credentials) => Some(*credentials),
        _ => None,
    }
}

/// `sha8` of a directory's canonical spelling, when it resolves.
fn canonical_sha8(dir: &std::path::Path) -> Option<String> {
    let canonical = namespace::canonical(dir).ok()?;
    Some(namespace::sha8(&namespace::export_spelling(&canonical)))
}

/// Builds a display-only record from an identity that may not exist.
fn record_from_identity(identity: Option<&Identity>, kind: AccountKind) -> AccountRecord {
    AccountRecord {
        account_uuid: identity.map(|i| i.account_uuid.clone()).unwrap_or_default(),
        organization_uuid: identity
            .and_then(|i| i.organization_uuid.clone())
            .unwrap_or_else(|| UNKNOWN_ORG.to_owned()),
        email: identity.and_then(|i| i.email.clone()),
        org_name: identity.and_then(|i| i.org_name.clone()),
        label: None,
        kind,
        forgotten: false,
        created_at: String::new(),
    }
}

/// Reads `oauthAccount` out of a `.claude.json` (facts F30, F33).
///
/// Every failure is `None`. The file is rewritten continuously by running
/// Claude Code sessions (fact F41), so catching a partial write is expected
/// rather than exceptional, and the consequence — `identity unknown` on one
/// pass — is mild.
fn claude_json_identity(path: &std::path::Path) -> Option<Identity> {
    let bytes = std::fs::read(path).ok()?;
    let document: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let account = document.get("oauthAccount")?;
    let text = |key: &str| account.get(key).and_then(serde_json::Value::as_str).map(str::to_owned);
    Some(Identity {
        account_uuid: text("accountUuid")?,
        organization_uuid: text("organizationUuid"),
        email: text("emailAddress"),
        org_name: text("organizationName"),
    })
}

#[cfg(test)]
#[path = "discovery_tests.rs"]
mod tests;
