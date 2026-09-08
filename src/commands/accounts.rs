//! `agentctl claude accounts` — inspecting and editing what agentctl knows.
//!
//! Six subcommands, and what separates them is how much they are allowed to
//! touch:
//!
//! - `list` and `show` read. They run the same discovery `status` does, so a
//!   row here is the same row there, with the registry's own fields and the
//!   namespace's on-disk state spelled out rather than compressed into a
//!   table cell.
//! - `forget` and `unforget` write one flag in the registry and nothing else.
//!   The keychain item they hide is never read, never written, never removed
//!   (plan AC47, invariant I1).
//! - `remove` and `relocate` mutate a namespace, so both hold that namespace's
//!   lock for the whole mutation (invariant I3) and both refuse a row agentctl
//!   does not own (invariant I9).
//!
//! # What `remove` will not do
//!
//! The live credential and the per-configuration-directory keychain items are
//! somebody else's (decision D-001). agentctl cannot delete a keychain item at
//! all — there is no code path, and that is the point of invariant I1 — so a
//! `remove` aimed at one of those rows would either do nothing or delete a
//! registry record while leaving the credential exactly where it was. Both are
//! worse than refusing and naming `accounts forget`, which is the operation
//! that actually exists for them.
//!
//! # Why the namespace lock is *waited* on rather than skipped
//!
//! A `remove --delete-secret` racing a `status` that is mid-refresh would
//! delete the namespace out from under a rename. So it waits, bounded by
//! [`COMMAND_LOCK_TIMEOUT`], and proceeds only once it holds the lock (plan
//! AC26). The lock file itself is never unlinked, even by the command that
//! deletes the directory it protects: `flock` is an inode lock, and a
//! recreated lock file is a second inode two processes could hold at once
//! (plan section 3.5).

use std::path::Path;
use std::path::PathBuf;
use std::time::Instant;

use tabled::builder::Builder;
use tabled::settings::Style;

use crate::cli::AccountsCommand;
use crate::commands::Prompt;
use crate::commands::Tty;
use crate::commands::login;
use crate::config::AccountKind;
use crate::config::AccountRecord;
use crate::config::AgentctlConfig;
use crate::config::paths::Paths;
use crate::config::paths::UNKNOWN_ORG;
use crate::config::paths::validate_segment;
use crate::error::AppError;
use crate::provider::claude;
use crate::provider::claude::account::AccountRow;
use crate::provider::claude::credentials::Credentials;
use crate::provider::claude::discovery;
use crate::provider::claude::namespace;
use crate::provider::claude::namespace::EnvView;
use crate::provider::claude::oauth;
use crate::provider::claude::oauth::OauthClient;
use crate::render::table::footer;
use crate::runtime::coordinator::Cancel;
use crate::runtime::coordinator::PassCtx;
use crate::runtime::fault::Fault;
use crate::secret::KeychainReader;
use crate::secret::file_store;
use crate::secret::file_store::ReadOutcome;
use crate::secret::file_store::WriteRequest;
use crate::secret::namespace_lock;
use crate::secret::namespace_lock::COMMAND_LOCK_TIMEOUT;

/// The column headings of `accounts list`, in order.
pub const HEADINGS: [&str; 7] = ["Id", "Account", "Org", "Kind", "Source", "State", "Location"];

/// What an unavailable cell looks like, matching the `status` table.
const EMPTY_CELL: &str = crate::render::table::EMPTY_CELL;

/// Runs `agentctl claude accounts …`.
///
/// # Errors
///
/// Returns [`AppError`] for every failure. `AppError::Refused` covers the
/// invariant-I9 refusals and a cancelled confirmation — both mean the store is
/// exactly as it was.
pub fn run(
    config_dir: Option<&Path>,
    command: &AccountsCommand,
    cancel: &Cancel,
) -> Result<(), AppError> {
    let paths = Paths::resolve(config_dir)?;
    paths.ensure_dirs()?;
    let env = EnvView::from_process();
    let accounts = Accounts { paths: &paths, env: &env, cancel };
    let io = &mut Tty;

    match command {
        AccountsCommand::List { all } => {
            let ctx = accounts.ctx();
            let reader = crate::secret::default_reader(&ctx);
            list(&accounts, reader.as_ref(), &ctx, *all, io)
        }
        AccountsCommand::Show { id } => {
            let ctx = accounts.ctx();
            let reader = crate::secret::default_reader(&ctx);
            show(&accounts, reader.as_ref(), &ctx, id, io)
        }
        AccountsCommand::Remove { id, delete_secret, yes } => {
            let removal = Removal { id, delete_secret: *delete_secret, yes: *yes };
            remove(&accounts, &removal, io)
        }
        AccountsCommand::Relocate { id, yes } => {
            let client = OauthClient::from_env(&claude::user_agent())?;
            relocate(&accounts, Some(&client), id, *yes, io)
        }
        AccountsCommand::Forget { service } => forget(&accounts, service, true, io),
        AccountsCommand::Unforget { service } => forget(&accounts, service, false, io),
    }
}

/// The store one `accounts` invocation works on.
pub struct Accounts<'a> {
    /// Where the store lives.
    pub paths: &'a Paths,
    /// The environment discovery reads the live entry's identity from.
    pub env: &'a EnvView,
    /// The process-wide cancellation flag.
    pub cancel: &'a Cancel,
}

impl Accounts<'_> {
    /// A context bounded by the same wait the lock uses.
    ///
    /// `accounts` has no pass deadline of its own — it is not `status` — so
    /// the keychain reads it spawns are bounded by the interactive budget
    /// rather than by nothing (invariant I12).
    fn ctx(&self) -> PassCtx {
        let now = Instant::now();
        PassCtx::standalone(
            self.cancel.clone(),
            now.checked_add(COMMAND_LOCK_TIMEOUT).unwrap_or(now),
        )
    }

    /// The deadline a namespace lock acquisition should wait until.
    ///
    /// Checked addition because this project builds with overflow checks off,
    /// and a wrapped deadline would land in the past and turn the bounded wait
    /// plan AC26 requires into no wait at all.
    fn lock_deadline(&self) -> Instant {
        let now = Instant::now();
        now.checked_add(COMMAND_LOCK_TIMEOUT).unwrap_or(now)
    }

    /// The registry as it is on disk right now.
    fn config(&self) -> Result<AgentctlConfig, AppError> {
        AgentctlConfig::load(self.paths)
    }
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

/// `accounts list [--all]`.
///
/// The same visibility rule and hidden-row footer as `status` (plan section
/// 3.2), because they are the same rows: a stale sibling, a `claude-switcher`
/// item and a forgotten service are hidden here exactly as they are there, and
/// `--all` reveals them here exactly as it does there.
///
/// # Errors
///
/// Returns [`AppError`] when the registry cannot be read.
pub fn list(
    accounts: &Accounts<'_>,
    reader: &dyn KeychainReader,
    ctx: &PassCtx,
    all: bool,
    io: &mut dyn Prompt,
) -> Result<(), AppError> {
    let config = accounts.config()?;
    let found = discovery::discover(&config, accounts.paths, reader, accounts.env, ctx);
    let live_service = namespace::service_name(accounts.env);

    let mut builder = Builder::default();
    builder.push_record(HEADINGS);
    let mut hidden = 0usize;
    for row in &found.rows {
        if !all && !row.visible_by_default {
            hidden = hidden.saturating_add(1);
            continue;
        }
        builder.push_record(list_record(row, &live_service));
    }

    let mut table = builder.build();
    table.with(Style::psql());
    let mut out = table.to_string();
    if hidden > 0 {
        out.push('\n');
        out.push_str(&footer(hidden));
    }
    io.tell(&out);
    Ok(())
}

/// One row of the `accounts list` table.
fn list_record(row: &AccountRow, live_service: &str) -> [String; 7] {
    [
        row.id.clone(),
        row.record.email.clone().unwrap_or_else(|| EMPTY_CELL.to_owned()),
        row.record.org_name.clone().unwrap_or_else(|| row.record.organization_uuid.clone()),
        row.record.kind.name().to_owned(),
        row.source.name().to_owned(),
        row.state.label(),
        location(&row.record, live_service),
    ]
}

/// Where a row's credentials are named, in the terms of its kind.
///
/// For an `Owned` row this is the `export_spelling` — the namespace directory
/// as it was spelled at login, which is the string a Claude Code session
/// pointed at this namespace would hash into a keychain service name (fact
/// F35). It is worth a column of its own precisely because a moved store keeps
/// the old spelling, and that mismatch is what `doctor` reports (risk R20).
fn location(record: &AccountRecord, live_service: &str) -> String {
    match &record.kind {
        AccountKind::Owned { export_spelling, .. } => export_spelling.clone(),
        AccountKind::ConfigDirReadOnly { service, .. } => service.clone(),
        AccountKind::Live => live_service.to_owned(),
        AccountKind::Foreign { source } => source.clone(),
    }
}

// ---------------------------------------------------------------------------
// show
// ---------------------------------------------------------------------------

/// `accounts show <id>`.
///
/// Resolved against the *discovered* rows rather than against the registry
/// alone, so every row `status` prints can be inspected — including the live
/// entry and an unclaimed keychain item, neither of which has a registry
/// record. When the row is one agentctl owns, the namespace's on-disk state is
/// reported too: the directory, the lock file and its holder, and whether a
/// pending or stray temporary file is sitting there.
///
/// No token material is printed. The credential file is opened only to read
/// its expiry timestamps and its identity block (invariant I4).
///
/// # Errors
///
/// Returns [`AppError::Config`] when `id` names no row or more than one.
pub fn show(
    accounts: &Accounts<'_>,
    reader: &dyn KeychainReader,
    ctx: &PassCtx,
    id: &str,
    io: &mut dyn Prompt,
) -> Result<(), AppError> {
    let config = accounts.config()?;
    let found = discovery::discover(&config, accounts.paths, reader, accounts.env, ctx);
    let row = resolve_row(&found.rows, id)?;
    let record = &row.record;

    let mut out = Vec::new();
    out.push(format!("id                 {}", row.id));
    out.push(format!("account            {}", or_dash(record.account_uuid.as_str())));
    out.push(format!("organization       {}", or_dash(record.organization_uuid.as_str())));
    out.push(format!("email              {}", opt(record.email.as_deref())));
    out.push(format!("org name           {}", opt(record.org_name.as_deref())));
    out.push(format!("label              {}", opt(record.label.as_deref())));
    out.push(format!("kind               {}", record.kind.name()));
    out.push(format!("source             {}", row.source.name()));
    out.push(format!("state              {}", row.state.label()));
    out.push(format!("note               {}", opt(row.note.as_deref())));
    out.push(format!("forgotten          {}", record.forgotten));
    out.push(format!("created            {}", or_dash(record.created_at.as_str())));
    out.push(format!(
        "location           {}",
        location(record, &namespace::service_name(accounts.env))
    ));

    if let Some(credentials) = row.credentials.as_ref() {
        out.push(format!("plan               {}", opt(credentials.subscription_type.as_deref())));
        out.push(format!("scopes             {}", credentials.scopes.join(" ")));
        out.push(format!("access expires     {}", expiry(Some(credentials.expires_at_ms))));
        out.push(format!("refresh expires    {}", expiry(credentials.refresh_token_expires_at_ms)));
    }

    if matches!(record.kind, AccountKind::Owned { .. }) {
        out.extend(namespace_report(accounts.paths, record));
    }

    io.tell(&out.join("\n"));
    Ok(())
}

/// The on-disk state of one owned namespace.
fn namespace_report(paths: &Paths, record: &AccountRecord) -> Vec<String> {
    let ns_dir = paths.namespace_dir(&record.account_uuid, &record.organization_uuid);
    let lock_path = paths.lock_path(&record.account_uuid, &record.organization_uuid);

    let mut out = vec![
        format!("namespace          {}", ns_dir.display()),
        format!("credentials file   {}", present(&ns_dir.join(file_store::CREDENTIALS_FILE))),
        format!("pending write      {}", present(&ns_dir.join(file_store::PENDING_FILE))),
        format!("pending metadata   {}", present(&ns_dir.join(file_store::PENDING_META))),
        format!("lock file          {}", lock_path.display()),
    ];

    match namespace_lock::read_body(&lock_path) {
        Some(body) => {
            let holder = crate::runtime::proc::holder(body.pid);
            out.push(format!(
                "lock holder        pid {} ({}), taken {}",
                body.pid,
                holder.label(),
                body.acquired_at
            ));
        }
        // A lock file with no readable body is the normal state once its
        // holder has gone: the body is left behind, but an unparseable one
        // means only that it was written by another build or caught mid-write.
        None => out.push("lock holder        — (no readable body)".to_owned()),
    }

    match file_store::list_stray_tmp(&ns_dir) {
        Ok(stray) if stray.is_empty() => out.push("stray temporaries  none".to_owned()),
        Ok(stray) => {
            let names: Vec<String> = stray.iter().map(|path| path.display().to_string()).collect();
            out.push(format!("stray temporaries  {}", names.join(", ")));
        }
        Err(err) => out.push(format!("stray temporaries  could not be listed: {err}")),
    }
    out
}

/// Resolves a user-supplied identifier against the discovered rows.
///
/// The `<account>/<organization>` spelling is tried first and exactly, because
/// it is what the ambiguity message tells the user to fall back to and so must
/// never itself be ambiguous — which is also how a live row and an owned
/// record for the same account are told apart (they differ in organization, or
/// else they are one row).
///
/// # Errors
///
/// Returns [`AppError::Config`] naming the unambiguous spellings when more
/// than one row matches, and a plain "no account matches" when none does.
fn resolve_row<'a>(rows: &'a [AccountRow], id: &str) -> Result<&'a AccountRow, AppError> {
    if let Some(row) = rows.iter().find(|row| key_spelling(&row.record) == id) {
        return Ok(row);
    }

    let matches: Vec<&AccountRow> = rows
        .iter()
        .filter(|row| {
            row.id == id
                || row.record.account_uuid == id
                || row.record.email.as_deref() == Some(id)
                || row.record.label.as_deref() == Some(id)
        })
        .collect();

    match matches.as_slice() {
        [] => Err(AppError::Config(format!(
            "no account matches `{id}`; `agentctl claude accounts list --all` shows every row"
        ))),
        [only] => Ok(only),
        many => {
            let candidates: Vec<String> =
                many.iter().map(|row| key_spelling(&row.record)).collect();
            Err(AppError::Config(format!(
                "`{id}` matches {} rows; use one of: {}",
                many.len(),
                candidates.join(", ")
            )))
        }
    }
}

/// The `<account>/<organization>` spelling of one record.
fn key_spelling(record: &AccountRecord) -> String {
    format!("{}/{}", record.account_uuid, record.organization_uuid)
}

// ---------------------------------------------------------------------------
// remove
// ---------------------------------------------------------------------------

/// What one `accounts remove` was asked to do.
pub struct Removal<'a> {
    /// The account identifier, as the user spelled it.
    pub id: &'a str,
    /// Whether the credential file goes too, or only the registry record.
    pub delete_secret: bool,
    /// Whether the confirmation was answered up front.
    pub yes: bool,
}

/// `accounts remove <id> [--delete-secret] [--yes]` (plan AC26, invariant I9).
///
/// # Errors
///
/// Returns [`AppError::Refused`] when the row is not one agentctl owns, when
/// the confirmation is declined, or when the namespace lock could not be taken
/// inside [`COMMAND_LOCK_TIMEOUT`]; [`AppError::Config`] when `id` names no
/// record; [`AppError::Io`] when the removal itself fails.
pub fn remove(
    accounts: &Accounts<'_>,
    removal: &Removal<'_>,
    io: &mut dyn Prompt,
) -> Result<(), AppError> {
    let config = accounts.config()?;
    let record = config.resolve_id(removal.id)?.clone();
    let id = key_spelling(&record);

    match &record.kind {
        AccountKind::Owned { .. } => {}
        // A foreign row is synthesized by discovery and never recorded, so
        // `resolve_id` cannot return one; the arm keeps the match exhaustive
        // and says the truthful thing if that ever changes.
        AccountKind::Foreign { source } => {
            return Err(AppError::Refused {
                reason: format!(
                    "`{id}` belongs to {source}; agentctl never reads or writes it, so there is \
                 nothing to remove"
                ),
            });
        }
        // Invariant I9. Neither of these is agentctl's to delete: the
        // credentials are in the keychain, which phase 1 never writes.
        AccountKind::Live | AccountKind::ConfigDirReadOnly { .. } => {
            return Err(AppError::Refused {
                reason: format!(
                    "`{id}` is a read-only row: its credentials live in the login keychain, which \
                 agentctl never writes or deletes. Use `agentctl claude accounts forget` to stop \
                 reporting it, or remove the item with Keychain Access."
                ),
            });
        }
    }

    if removal.delete_secret {
        delete_namespace(accounts, &record, &id, removal.yes, io)?;
    }

    let key = (record.account_uuid.clone(), record.organization_uuid.clone());
    AgentctlConfig::update(accounts.paths, |config| {
        config.accounts.retain(|rec| rec.key() != (key.0.as_str(), key.1.as_str()));
    })?;

    if removal.delete_secret {
        io.tell(&format!("Removed `{id}` and deleted its stored credentials."));
    } else {
        io.tell(&format!(
            "Removed the record for `{id}`. Its stored credentials are still on disk; \
             re-run with `--delete-secret` to delete them too."
        ));
    }
    Ok(())
}

/// Deletes one namespace under its lock, after saying what that means.
fn delete_namespace(
    accounts: &Accounts<'_>,
    record: &AccountRecord,
    id: &str,
    yes: bool,
    io: &mut dyn Prompt,
) -> Result<(), AppError> {
    let ns_dir = accounts.paths.namespace_dir(&record.account_uuid, &record.organization_uuid);

    if !yes {
        io.tell(&format!(
            "This deletes `{}`, including any pending write and any leftover temporary file.\n\
             The refresh token in it is the only copy agentctl holds: logging in again is the \
             only way back. Nothing in the login keychain is touched.",
            ns_dir.display()
        ));
        if !io.confirm(&format!("Delete the stored credentials for `{id}`?"))? {
            return Err(AppError::Refused { reason: "cancelled; nothing was removed".to_owned() });
        }
    }

    // The bounded wait plan AC26 asks for: a `status` mid-refresh holds this
    // lock, and deleting the namespace under it would pull the directory out
    // from beneath a rename.
    let guard = namespace_lock::acquire(
        accounts.paths,
        &record.account_uuid,
        &record.organization_uuid,
        accounts.lock_deadline(),
        accounts.cancel,
        fault(),
    )
    .map_err(|err| AppError::Refused {
        reason: format!("could not take the namespace lock for `{id}`: {err}"),
    })?;

    let removed = file_store::remove_namespace(accounts.paths, &ns_dir);

    // Released, not deleted. The lock file lives outside the namespace and is
    // never unlinked — including here, by the command that just deleted
    // everything the lock protects (plan section 3.5, invariant I9).
    drop(guard);

    removed.map_err(|err| AppError::Io {
        context: format!("could not remove `{}`: {err}", ns_dir.display()),
        source: std::io::Error::other(err.to_string()),
    })
}

// ---------------------------------------------------------------------------
// relocate
// ---------------------------------------------------------------------------

/// `accounts relocate <id> [--yes]` (plan AC40).
///
/// Moves a namespace that was created as `_unknown-org` — because the login
/// could not name an organization (decision D-008) — into the organization the
/// credential now names. The organization comes from the credential's
/// `tokenAccount`, and failing that from the profile endpoint, which is the
/// same fallback `login` uses (fact F26); it is never inferred from a path
/// (invariant I13).
///
/// # How the move is made
///
/// By reading the credential and writing it into the new namespace through
/// [`file_store::write_credentials`], then removing the old namespace — not by
/// renaming the directory. The writer already refuses a target outside the
/// store, a symlinked component and a non-regular file, and already writes
/// 0600 through a temporary file; a bare `rename` would need all of that
/// re-implemented against paths it does not control. A namespace holds one
/// file, so the copy is the whole move.
///
/// If the process dies between the write and the removal, both namespaces
/// exist and the registry still points at the old one — `doctor` lists the
/// stray `_unknown-org` directory, and re-running `relocate` finishes the job.
///
/// # Errors
///
/// Returns [`AppError::Refused`] when the row is not an owned `_unknown-org`
/// namespace, when the target namespace already exists (plan AC40), when the
/// confirmation is declined, or when either lock could not be taken;
/// [`AppError::Config`] when no organization can be established.
pub fn relocate(
    accounts: &Accounts<'_>,
    client: Option<&OauthClient>,
    id: &str,
    yes: bool,
    io: &mut dyn Prompt,
) -> Result<(), AppError> {
    let config = accounts.config()?;
    let record = config.resolve_id(id)?.clone();
    let spelling = key_spelling(&record);

    if !matches!(record.kind, AccountKind::Owned { .. }) {
        return Err(AppError::Refused {
            reason: format!(
                "`{spelling}` is not a namespace agentctl created, so there is nothing to move"
            ),
        });
    }
    if record.organization_uuid != UNKNOWN_ORG {
        return Err(AppError::Refused {
            reason: format!(
                "`{spelling}` already names an organization; `relocate` only moves a namespace \
                 created as `{UNKNOWN_ORG}`"
            ),
        });
    }

    let source = accounts.paths.namespace_dir(&record.account_uuid, UNKNOWN_ORG);
    let credentials = read_namespace(&source)?;
    let (organization_uuid, org_name) = organization_of(&credentials, client, accounts.cancel)?;
    validate_segment(&organization_uuid)?;

    let target = accounts.paths.namespace_dir(&record.account_uuid, &organization_uuid);
    if std::fs::symlink_metadata(&target).is_ok() {
        return Err(AppError::Refused {
            reason: format!(
                "`{}` already exists; move or remove it before relocating `{spelling}` into it",
                target.display()
            ),
        });
    }

    if !yes {
        io.tell(&format!(
            "This moves `{}` to `{}` and updates the record to name organization {organization_uuid}.",
            source.display(),
            target.display()
        ));
        if !io.confirm(&format!("Relocate `{spelling}`?"))? {
            return Err(AppError::Refused { reason: "cancelled; nothing was moved".to_owned() });
        }
    }

    // Both namespaces are mutated, so both locks are held (invariant I3), and
    // always in this order — source, then target. Two relocations of one
    // account contend on the source lock first and therefore cannot deadlock
    // against each other, and a concurrent `login` into the target takes only
    // the target lock.
    let source_guard = lock(accounts, &record.account_uuid, UNKNOWN_ORG)?;
    let target_guard = lock(accounts, &record.account_uuid, &organization_uuid)?;

    // Invariant I9: a pending write describes credentials this move is about
    // to supersede, and a stray temporary file holds token material at rest.
    login::clear_stale_files(accounts.paths, &source)?;

    let blob = credentials.to_blob_json();
    let request = WriteRequest {
        paths: accounts.paths,
        ns_dir: &target,
        blob_json: &blob,
        prior: None,
        new_expires_at_ms: credentials.expires_at_ms,
        fault: fault(),
    };
    file_store::write_credentials(&request, &accounts.ctx()).map_err(|err| {
        AppError::Config(format!("could not write `{}`: {err}", target.display()))
    })?;

    file_store::remove_namespace(accounts.paths, &source).map_err(|err| AppError::Io {
        context: format!("could not remove `{}`: {err}", source.display()),
        source: std::io::Error::other(err.to_string()),
    })?;

    drop(target_guard);
    drop(source_guard);

    let export_spelling = namespace::export_spelling(&target);
    let export_sha8 = namespace::sha8(&export_spelling);
    let account_uuid = record.account_uuid.clone();
    let moved = AccountRecord {
        organization_uuid: organization_uuid.clone(),
        org_name: org_name.or_else(|| record.org_name.clone()),
        kind: AccountKind::Owned { export_spelling, export_sha8 },
        ..record
    };
    AgentctlConfig::update(accounts.paths, |config| {
        config.accounts.retain(|rec| rec.key() != (account_uuid.as_str(), UNKNOWN_ORG));
        config.upsert(moved);
    })?;

    io.tell(&format!("Relocated `{spelling}` to `{account_uuid}/{organization_uuid}`."));
    Ok(())
}

/// Reads a namespace's credentials, or says why it cannot.
fn read_namespace(ns_dir: &Path) -> Result<Credentials, AppError> {
    match file_store::read_credentials(ns_dir) {
        Ok(ReadOutcome::Present { bytes, .. }) => Credentials::parse_blob(&bytes).map_err(|err| {
            AppError::Config(format!("`{}` could not be read: {err}", ns_dir.display()))
        }),
        Ok(ReadOutcome::Absent) => Err(AppError::Refused {
            reason: format!(
                "`{}` holds no credentials; run `agentctl claude login` instead",
                ns_dir.display()
            ),
        }),
        Err(err) => {
            Err(AppError::Config(format!("`{}` could not be read: {err}", ns_dir.display())))
        }
    }
}

/// The organization a credential belongs to: from the blob, else the profile.
///
/// The profile call is the realistic source. A namespace is `_unknown-org`
/// precisely because neither the exchange nor the profile named an
/// organization at login time, so the blob usually cannot answer either — but
/// it is asked first because it costs no request and because a credential that
/// *was* refreshed since may now carry one.
fn organization_of(
    credentials: &Credentials,
    client: Option<&OauthClient>,
    cancel: &Cancel,
) -> Result<(String, Option<String>), AppError> {
    if let Some(identity) = credentials.identity()
        && let Some(uuid) = identity.organization_uuid
    {
        return Ok((uuid, identity.org_name));
    }

    let Some(client) = client else {
        return Err(AppError::Config(
            "the stored credential names no organization and no profile lookup is available"
                .to_owned(),
        ));
    };
    let document = oauth::profile(client, credentials, cancel)
        .map_err(|err| AppError::Config(format!("the account profile could not be read: {err}")))?;
    let organization = document.get("organization");
    let uuid = organization
        .and_then(|org| org.get("uuid"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let name = organization
        .and_then(|org| org.get("name"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);

    match uuid {
        Some(uuid) => Ok((uuid, name)),
        None => Err(AppError::Config(
            "neither the stored credential nor the account profile names an organization, so \
             there is nowhere to relocate this namespace to"
                .to_owned(),
        )),
    }
}

/// Takes one namespace lock, with the interactive wait.
fn lock(
    accounts: &Accounts<'_>,
    acct: &str,
    org: &str,
) -> Result<namespace_lock::NamespaceLockGuard, AppError> {
    namespace_lock::acquire(
        accounts.paths,
        acct,
        org,
        accounts.lock_deadline(),
        accounts.cancel,
        fault(),
    )
    .map_err(|err| AppError::Refused {
        reason: format!("could not take the namespace lock for `{acct}/{org}`: {err}"),
    })
}

// ---------------------------------------------------------------------------
// forget / unforget
// ---------------------------------------------------------------------------

/// `accounts forget <service>` and `accounts unforget <service>` (plan AC47).
///
/// Registry-only, and deliberately so: the keychain item named here is not
/// read, not written and not removed. What changes is whether `status` and
/// `doctor` report it — and `accounts list --all` still shows it, marked
/// `forgotten`, so a hidden row can always be found again.
///
/// Two places carry the flag, because the rows this hides come in two shapes.
/// A service that has a registry record gets [`AccountRecord::forgotten`]; an
/// unclaimed one, which by definition has no record and may have no account
/// identifier to key one by, is remembered by name in
/// [`AgentctlConfig::forgotten_services`].
///
/// # Errors
///
/// Returns [`AppError::Refused`] for the live service — hiding the credential
/// Claude Code is using would hide the row the user is most likely asking
/// about — and whatever the registry write reports.
pub fn forget(
    accounts: &Accounts<'_>,
    service: &str,
    hide: bool,
    io: &mut dyn Prompt,
) -> Result<(), AppError> {
    let live_service = namespace::service_name(accounts.env);
    if hide && service == live_service {
        return Err(AppError::Refused {
            reason: format!(
                "`{service}` is the credential Claude Code is using right now; hiding it would \
                 hide the live row"
            ),
        });
    }

    let changed = AgentctlConfig::update(accounts.paths, |config| {
        let recorded = config.accounts.iter_mut().find(|rec| names_service(rec, service));
        if let Some(record) = recorded {
            let changed = record.forgotten != hide;
            record.forgotten = hide;
            return changed;
        }

        let known = config.forgotten_services.iter().any(|name| name == service);
        match (hide, known) {
            (true, false) => {
                config.forgotten_services.push(service.to_owned());
                true
            }
            (false, true) => {
                config.forgotten_services.retain(|name| name != service);
                true
            }
            _ => false,
        }
    })?;

    match (hide, changed) {
        (true, true) => io.tell(&format!(
            "`{service}` is hidden from `status` and `doctor`; \
             `accounts list --all` still shows it. The keychain was not touched."
        )),
        (true, false) => io.tell(&format!("`{service}` was already hidden.")),
        (false, true) => io.tell(&format!("`{service}` is reported again.")),
        (false, false) => io.tell(&format!("`{service}` was not hidden.")),
    }
    Ok(())
}

/// Whether a record is the one that owns this keychain service name.
fn names_service(record: &AccountRecord, service: &str) -> bool {
    match &record.kind {
        AccountKind::ConfigDirReadOnly { service: recorded, .. } => recorded == service,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------

/// The fault set this process should honour.
///
/// Always empty without the `testing` feature, which is what keeps the
/// injection points unreachable in a release build (plan section 3.9).
fn fault() -> Fault {
    #[cfg(feature = "testing")]
    {
        Fault::from_env()
    }
    #[cfg(not(feature = "testing"))]
    {
        Fault::none()
    }
}

/// `value`, or an em dash when it is empty.
fn or_dash(value: &str) -> String {
    if value.is_empty() { EMPTY_CELL.to_owned() } else { value.to_owned() }
}

/// An optional string, or an em dash.
fn opt(value: Option<&str>) -> String {
    value.map_or_else(|| EMPTY_CELL.to_owned(), str::to_owned)
}

/// Whether a path exists, without following a link to decide.
fn present(path: &PathBuf) -> String {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            format!("{} (a symbolic link — agentctl refuses to read it)", path.display())
        }
        Ok(_) => format!("{} (present)", path.display()),
        Err(_) => format!("{} (absent)", path.display()),
    }
}

/// An expiry timestamp, rendered, with no token anywhere near it.
fn expiry(millis: Option<i64>) -> String {
    let Some(millis) = millis else { return format!("{EMPTY_CELL} (not recorded)") };
    match jiff::Timestamp::from_millisecond(millis) {
        Ok(at) => {
            let now = jiff::Timestamp::now();
            if at <= now {
                format!("{at} (expired)")
            } else {
                format!("{at} (in {})", crate::usage::model::render_countdown(now, at))
            }
        }
        Err(_) => format!("{millis} (not a usable timestamp)"),
    }
}

#[cfg(test)]
#[path = "accounts_tests.rs"]
mod tests;
