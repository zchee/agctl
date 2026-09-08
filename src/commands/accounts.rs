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
use crate::secret::SWITCHER_SERVICE_PREFIX;
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
/// Returns [`AppError`] for every failure. A command that refuses a row and
/// renders nothing — the invariant-I9 refusals — is [`AppError::Config`], so
/// it exits 1: exit 2 is reserved for a run that produced a table with a
/// degraded row in it. `AppError::Refused` stays on the two outcomes that are
/// not a judgement about the row — a declined confirmation and a lock held
/// past the wait — and both mean the store is exactly as it was.
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

    let service = match &record.kind {
        AccountKind::ConfigDirReadOnly { service, .. } => Some(service.as_str()),
        _ => None,
    };

    let mut out = Vec::new();
    out.push(format!("id                 {}", row.id));
    out.push(account_line(record, service));
    out.push(format!("organization       {}", or_dash(record.organization_uuid.as_str())));
    out.push(format!("email              {}", opt(record.email.as_deref())));
    out.push(format!("org name           {}", opt(record.org_name.as_deref())));
    out.push(format!("label              {}", opt(record.label.as_deref())));
    out.push(format!("kind               {}", record.kind.name()));
    if let Some(service) = service {
        out.push(format!("service            {service}"));
    }
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
        out.extend(namespace_report(accounts.paths, record, accounts.cancel));
    }

    io.tell(&out.join("\n"));
    Ok(())
}

/// The `account` line, which must never present a service name as a UUID.
///
/// A `ConfigDirReadOnly` item whose credential blob names nobody has no
/// account UUID to be keyed by, so `import` keys its record by the keychain
/// service name instead (there is no namespace directory to derive from it,
/// so nothing else depends on the key being a UUID). Printed under a bare
/// `account` label, that string reads as an Anthropic account identifier — a
/// user would copy it into `--account` expecting an account and get a
/// keychain item — so this says what it actually is.
fn account_line(record: &AccountRecord, service: Option<&str>) -> String {
    if service == Some(record.account_uuid.as_str()) {
        return format!(
            "account            {EMPTY_CELL} (the keychain item names no account, so this record \
             is keyed by its service name)"
        );
    }
    format!("account            {}", or_dash(record.account_uuid.as_str()))
}

/// The on-disk state of one owned namespace.
fn namespace_report(paths: &Paths, record: &AccountRecord, cancel: &Cancel) -> Vec<String> {
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
            let holder = crate::runtime::proc::holder(body.pid, cancel);
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
/// Returns [`AppError::Config`] when the row is not one agentctl owns and when
/// `id` names no record; [`AppError::Refused`] when the confirmation is
/// declined or the namespace lock could not be taken inside
/// [`COMMAND_LOCK_TIMEOUT`]; [`AppError::Io`] when the removal itself fails.
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
            return Err(AppError::Config(format!(
                "`{id}` belongs to {source}; agentctl never reads or writes it, so there is \
                 nothing to remove"
            )));
        }
        // Invariant I9. Neither of these is agentctl's to delete: the
        // credentials are in the keychain, which phase 1 never writes.
        AccountKind::Live | AccountKind::ConfigDirReadOnly { .. } => {
            // Named by its keychain service where it has one. A record for an
            // item that named nobody is keyed by that service name, so `id`
            // here would be `<service>/_unknown-org` — which reads as an
            // account and an organization and is neither.
            let named = match &record.kind {
                AccountKind::ConfigDirReadOnly { service, .. } => {
                    format!("keychain service `{service}`")
                }
                _ => format!("`{id}`"),
            };
            return Err(AppError::Config(format!(
                "{named} is a read-only row (kind `{}`): its credentials live in the login \
                 keychain, which agentctl never writes or deletes. Use `agentctl claude accounts \
                 forget` to stop reporting it, or remove the item with Keychain Access.",
                record.kind.name()
            )));
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
/// # What runs before the locks, and what does not
///
/// The credential is read once before the locks are taken, and that read
/// decides exactly one thing: which organization this account belongs to. It
/// may cost an HTTP request, and unless `--yes` was given it is followed by an
/// unbounded wait for a human — neither of which may happen with a namespace
/// lock held. So nothing that read saw is written. Under the locks the source
/// is read again and its digests compared against the first read; a `status`
/// that refreshed in between rotated the refresh token (fact F8), and writing
/// the superseded blob would leave the account with a dead refresh chain and
/// no copy of the live one. A mismatch aborts and changes nothing.
///
/// # The crash windows
///
/// The order under the locks is: write the target, update the registry, remove
/// the source. A crash after the write leaves the credential in both places
/// with the registry still naming the old one; re-running finishes the job,
/// because a target holding a credential with the same digests is recognised
/// as this move's own earlier attempt rather than as a collision. A crash
/// after the registry update leaves the account working under its new name and
/// a stray `_unknown-org` directory behind, which `accounts remove` clears —
/// the reverse order would instead have left the registry naming a namespace
/// that no longer exists, which is an account that cannot be read at all.
///
/// # Errors
///
/// Returns [`AppError::Config`] when the row is not an owned `_unknown-org`
/// namespace, when the target namespace already exists (plan AC40), when the
/// namespace changed while the question was on screen, and when no
/// organization can be established; [`AppError::Refused`] when the
/// confirmation is declined or either lock could not be taken.
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
        return Err(AppError::Config(format!(
            "`{spelling}` is not a namespace agentctl created, so there is nothing to move"
        )));
    }
    if record.organization_uuid != UNKNOWN_ORG {
        return Err(AppError::Config(format!(
            "`{spelling}` already names an organization; `relocate` only moves a namespace \
             created as `{UNKNOWN_ORG}`"
        )));
    }

    let source = accounts.paths.namespace_dir(&record.account_uuid, UNKNOWN_ORG);
    let probe = read_namespace(&source)?;
    let (organization_uuid, org_name) = organization_of(&probe, client, accounts.cancel)?;
    validate_segment(&organization_uuid)?;
    let target = accounts.paths.namespace_dir(&record.account_uuid, &organization_uuid);

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
    // the target lock — which is why the target is not examined until this
    // lock is in hand.
    let source_guard = lock(accounts, &record.account_uuid, UNKNOWN_ORG)?;
    let target_guard = lock(accounts, &record.account_uuid, &organization_uuid)?;

    let plan = Relocation {
        record: &record,
        probe: &probe,
        source: &source,
        target: &target,
        organization_uuid: &organization_uuid,
        org_name,
        spelling: &spelling,
    };
    let outcome = move_namespace(accounts, &plan);

    drop(target_guard);
    drop(source_guard);
    let resumed = outcome?;

    let account_uuid = &record.account_uuid;
    if resumed {
        io.tell(&format!(
            "Relocated `{spelling}` to `{account_uuid}/{organization_uuid}`. The credential was \
             already in place from an earlier run; this finished the move."
        ));
    } else {
        io.tell(&format!("Relocated `{spelling}` to `{account_uuid}/{organization_uuid}`."));
    }
    Ok(())
}

/// One relocation, as decided before the locks were taken.
struct Relocation<'a> {
    /// The registry record being moved.
    record: &'a AccountRecord,
    /// The credential the pre-lock read saw. Never written — only its digests
    /// are used, to prove the source has not changed since.
    probe: &'a Credentials,
    /// The `_unknown-org` namespace.
    source: &'a Path,
    /// Where it is going.
    target: &'a Path,
    /// The organization the target is named for.
    organization_uuid: &'a str,
    /// Its display name, when one was learned.
    org_name: Option<String>,
    /// `<account>/<organization>`, for messages.
    spelling: &'a str,
}

/// The half of `relocate` that runs with both namespace locks held.
///
/// Returns whether the target already held this move's own earlier attempt, in
/// which case the write was skipped.
///
/// # Errors
///
/// Returns [`AppError::Config`] when the source changed under the lock or the
/// target is occupied by something else, and [`AppError::Io`] when a write or
/// a removal fails.
fn move_namespace(accounts: &Accounts<'_>, plan: &Relocation<'_>) -> Result<bool, AppError> {
    let current = under_lock_read(plan.source)?;
    let Some(current) = current else {
        return Err(changed(plan.source));
    };
    if current.digests() != plan.probe.digests() {
        return Err(changed(plan.source));
    }

    // Plan AC40, and only now that the target lock is held: a `login` into
    // this organization that landed while the confirmation was on screen took
    // exactly this lock, and a check made before taking it would have run
    // against a namespace that did not exist yet.
    let resumed = match under_lock_read(plan.target)? {
        // This move's own earlier attempt: the write landed and the process
        // died before the registry was updated. Finishing it is what makes
        // re-running `relocate` the fix rather than a second problem.
        Some(existing) if existing.digests() == current.digests() => true,
        Some(_) => return Err(occupied(plan)),
        None if std::fs::symlink_metadata(plan.target).is_ok() => return Err(occupied(plan)),
        None => false,
    };

    // Invariant I9: a pending write describes credentials this move is about
    // to supersede, and a stray temporary file holds token material at rest.
    login::clear_stale_files(accounts.paths, plan.source)?;

    if !resumed {
        let blob = current.to_blob_json();
        let request = WriteRequest {
            paths: accounts.paths,
            ns_dir: plan.target,
            blob_json: &blob,
            prior: None,
            new_expires_at_ms: current.expires_at_ms,
            fault: fault(),
        };
        file_store::write_credentials(&request, &accounts.ctx()).map_err(|err| {
            AppError::Config(format!("could not write `{}`: {err}", plan.target.display()))
        })?;
    }

    // Before the source is removed, not after. A crash here leaves a stray
    // directory; the other order leaves a registry entry naming a namespace
    // that is gone, which is an account nothing can read.
    let account_uuid = plan.record.account_uuid.clone();
    let export_spelling = namespace::export_spelling(plan.target);
    let export_sha8 = namespace::sha8(&export_spelling);
    let moved = AccountRecord {
        organization_uuid: plan.organization_uuid.to_owned(),
        org_name: plan.org_name.clone().or_else(|| plan.record.org_name.clone()),
        kind: AccountKind::Owned { export_spelling, export_sha8 },
        ..plan.record.clone()
    };
    AgentctlConfig::update(accounts.paths, |config| {
        config.accounts.retain(|rec| rec.key() != (account_uuid.as_str(), UNKNOWN_ORG));
        config.upsert(moved);
    })?;

    file_store::remove_namespace(accounts.paths, plan.source).map_err(|err| AppError::Io {
        context: format!("could not remove `{}`", plan.source.display()),
        source: std::io::Error::other(err.to_string()),
    })?;
    Ok(resumed)
}

/// Reads one namespace's credential under a held lock.
///
/// `None` is an absent namespace rather than a failure, because both callers
/// have a use for that answer: a missing source means the namespace changed,
/// and a missing target means there is nothing in the way.
///
/// # Errors
///
/// Returns [`AppError::Config`] when the file is there but cannot be used.
fn under_lock_read(ns_dir: &Path) -> Result<Option<Credentials>, AppError> {
    match file_store::read_credentials(ns_dir) {
        Ok(ReadOutcome::Present { bytes, .. }) => {
            Credentials::parse_blob(&bytes).map(Some).map_err(|err| {
                AppError::Config(format!("`{}` could not be read: {err}", ns_dir.display()))
            })
        }
        Ok(ReadOutcome::Absent) => Ok(None),
        Err(err) => {
            Err(AppError::Config(format!("`{}` could not be read: {err}", ns_dir.display())))
        }
    }
}

/// The source moved under us between the pre-lock read and the lock.
fn changed(source: &Path) -> AppError {
    AppError::Config(format!(
        "`{}` changed during relocate; nothing was moved. Something refreshed or removed the \
         credential while this command was deciding — re-run `agentctl claude accounts relocate` \
         and it will work from what is there now.",
        source.display()
    ))
}

/// The target namespace holds something that is not this move's own work.
fn occupied(plan: &Relocation<'_>) -> AppError {
    AppError::Config(format!(
        "`{}` already exists and holds a different credential; move or remove it before \
         relocating `{}` into it",
        plan.target.display(),
        plan.spelling
    ))
}

/// Reads a namespace's credentials, or says why it cannot.
fn read_namespace(ns_dir: &Path) -> Result<Credentials, AppError> {
    match file_store::read_credentials(ns_dir) {
        Ok(ReadOutcome::Present { bytes, .. }) => Credentials::parse_blob(&bytes).map_err(|err| {
            AppError::Config(format!("`{}` could not be read: {err}", ns_dir.display()))
        }),
        Ok(ReadOutcome::Absent) => Err(AppError::Config(format!(
            "`{}` holds no credentials; run `agentctl claude login` instead",
            ns_dir.display()
        ))),
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
/// Returns [`AppError::Config`] for the live service — hiding the credential
/// Claude Code is using would hide the row the user is most likely asking
/// about — and for a service that is not a Claude Code credential item at all,
/// plus whatever the registry write reports.
pub fn forget(
    accounts: &Accounts<'_>,
    service: &str,
    hide: bool,
    io: &mut dyn Prompt,
) -> Result<(), AppError> {
    let live_service = namespace::service_name(accounts.env);
    if hide && service == live_service {
        return Err(AppError::Config(format!(
            "`{service}` is the credential Claude Code is using right now; hiding it would hide \
             the live row"
        )));
    }

    // Anything agentctl cannot classify is not a row this flag governs. A
    // `claude-switcher:*` item is hidden by default already and is never read
    // (fact F10), and `forgotten_services` is consulted only where an
    // unclaimed `Claude Code-credentials-<sha8>` item is being decided about
    // — so recording one here would change nothing while telling the user
    // agentctl had done something to another tool's credential.
    if namespace::classify(service).is_none() {
        let whose = if service.starts_with(SWITCHER_SERVICE_PREFIX) {
            format!("`{service}` belongs to claude-switcher")
        } else {
            format!(
                "`{service}` is not an item agentctl reports — only `{live}` and \
                 `{live}-<8 hex>` are",
                live = namespace::LIVE_SERVICE
            )
        };
        return Err(AppError::Config(format!(
            "{whose}; agentctl never reads or writes it, so there is nothing to hide or report"
        )));
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
