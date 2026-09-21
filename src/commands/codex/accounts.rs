//! `agctl codex accounts` — list, show, remove, forget and unforget the rows
//! of `codex_accounts` (plan AC107, AC115, AC125's `remove` clause).
//!
//! # Two registries that cannot see each other
//!
//! Every lookup here is against `codex_accounts` and nothing else, and the
//! Claude command is the mirror of that (invariant I28, plan AC112). A Codex
//! account is keyed by `(chatgpt_user_id, chatgpt_account_id)`, its
//! credentials live under a different root behind a different lock, and an
//! email that names a Claude account resolves to nothing here — which is what
//! `ac107_show_resolves_within_codex_accounts_only` proves through the binary.
//!
//! # What `remove --delete-secret` may delete, and what it may not
//!
//! Only the files agctl itself wrote, by name, never a tree. The unlinking
//! is [`OwnedNamespace::remove_named_files`], which lists the namespace and
//! **refuses before the first unlink** if it holds anything agctl did not
//! create — a Codex session's `sessions/`, a `config.toml`, a database — so a
//! refusal leaves the credential, the pending pair, the staged temporaries and
//! the refresh marker all exactly where they were (plan AC115, decision M10,
//! risk PM25). This module adds nothing ahead of that call that could delete,
//! which is what makes "refuses and removes nothing" true rather than
//! aspirational.
//!
//! A `Live` or `HomeReadOnly` row has no namespace agctl wrote, so
//! `--delete-secret` on one is **refused by name** rather than quietly
//! ignored: invariant I21 is that agctl never writes — or deletes — a file
//! under a `CODEX_HOME` it did not create. `forget` is what stops reporting
//! such a row.
//!
//! # Lock order
//!
//! The namespace guard is released **before** `.config.lock` is taken, the
//! same order `login` uses and for the same reason: `AgctlConfig::update`'s
//! closure must not call into anything that locks. Under the `testing`
//! feature the lock-order witness panics if that is ever violated, so the
//! order is checked rather than merely intended.

use std::io;
use std::time::Duration;

use crate::cli::Cli;
use crate::cli::CodexAccountsCommand;
use crate::commands::Prompt;
use crate::commands::Tty;
use crate::config::AgctlConfig;
use crate::config::codex::CodexAccountRecord;
use crate::config::codex::CodexKind;
use crate::config::codex::RefreshPolicy;
use crate::config::paths::Paths;
use crate::error::AppError;
use crate::provider::codex::audit;
use crate::provider::codex::auth_store::OwnedNamespace;
use crate::provider::codex::lock;
use crate::provider::codex::lock::LockBudget;
use crate::provider::codex::proof;
use crate::runtime::coordinator::Cancel;

/// How long `remove --delete-secret` waits for the namespace lock.
///
/// A command budget, not a pass budget: a person is waiting, and another
/// agctl holding this namespace is a reason to say so rather than to block.
const REMOVE_LOCK_BUDGET: Duration = Duration::from_secs(5);

/// Runs `agctl codex accounts <subcommand>`.
///
/// # Errors
///
/// [`AppError::Config`] when the id matches no row or more than one,
/// [`AppError::Refused`] when the row's kind makes the operation impossible
/// or the namespace lock is held, and whatever the registry update reports.
pub fn run(cli: &Cli, command: &CodexAccountsCommand, cancel: &Cancel) -> Result<(), AppError> {
    let paths = Paths::resolve(cli.config_dir.as_deref())?;
    let io = &mut Tty;
    match command {
        CodexAccountsCommand::List { all } => list(&paths, *all, io),
        CodexAccountsCommand::Show { id } => show(&paths, id, io),
        CodexAccountsCommand::Remove { id, delete_secret, yes } => {
            let removal = Removal { id, delete_secret: *delete_secret, yes: *yes };
            remove(&paths, &removal, cancel, io)
        }
        CodexAccountsCommand::Forget { id } => forget(&paths, id, true, io),
        CodexAccountsCommand::Unforget { id } => forget(&paths, id, false, io),
        // `set` and `refresh` are C4's: they change refresh policy and send
        // POSTs, which is a different capability from anything here.
        other => Err(AppError::not_implemented(&format!("agctl codex accounts {}", name(other)))),
    }
}

/// One `remove` invocation's arguments.
pub struct Removal<'a> {
    /// The id, email or label the user typed.
    pub id: &'a str,
    /// Whether to delete the credential file agctl wrote.
    pub delete_secret: bool,
    /// Whether the confirmation was given up front.
    pub yes: bool,
}

/// The canonical spelling of a row, and the one `list` prints.
///
/// `<user>/<account>`, because that pair is the key (decision D-039): an
/// email is a convenience and two rows can share one.
fn key(record: &CodexAccountRecord) -> String {
    format!("{}/{}", record.chatgpt_user_id, record.chatgpt_account_id)
}

/// The row `id` names, within `codex_accounts` only.
///
/// # Errors
///
/// [`AppError::Config`] naming the unambiguous spellings when more than one
/// row matches, and a plain "no account matches" when none does.
fn resolve<'a>(
    rows: &'a [CodexAccountRecord],
    id: &str,
) -> Result<&'a CodexAccountRecord, AppError> {
    if let Some(row) = rows.iter().find(|row| key(row) == id) {
        return Ok(row);
    }
    let matches: Vec<&CodexAccountRecord> = rows
        .iter()
        .filter(|row| {
            row.chatgpt_user_id == id
                || row.chatgpt_account_id == id
                || row.email.as_deref() == Some(id)
                || row.label.as_deref() == Some(id)
        })
        .collect();
    match matches.as_slice() {
        [] => Err(AppError::Config(format!(
            "no account matches `{id}`; `agctl codex accounts list --all` shows every row"
        ))),
        [only] => Ok(only),
        many => Err(AppError::Config(format!(
            "`{id}` matches {} rows; use one of: {}",
            many.len(),
            many.iter().map(|row| key(row)).collect::<Vec<_>>().join(", ")
        ))),
    }
}

/// `agctl codex accounts list`.
///
/// # Errors
///
/// Whatever loading the registry reports.
pub fn list(paths: &Paths, all: bool, io: &mut dyn Prompt) -> Result<(), AppError> {
    let config = AgctlConfig::load(paths)?;
    let shown: Vec<&CodexAccountRecord> =
        config.codex_accounts.iter().filter(|row| all || !row.forgotten).collect();
    if shown.is_empty() {
        let hidden = config.codex_accounts.len();
        io.tell(&if hidden == 0 {
            "no Codex accounts; `agctl codex login` adds one".to_owned()
        } else {
            format!("no Codex accounts shown; {hidden} forgotten (`--all` shows them)")
        });
        return Ok(());
    }
    for row in shown {
        io.tell(&format!(
            "{}  {}  {}{}",
            key(row),
            kind_name(&row.kind),
            row.email.as_deref().unwrap_or("-"),
            if row.forgotten { "  (forgotten)" } else { "" }
        ));
    }
    Ok(())
}

/// `agctl codex accounts show <id>`.
///
/// # Errors
///
/// As [`resolve`], plus whatever loading the registry reports.
pub fn show(paths: &Paths, id: &str, io: &mut dyn Prompt) -> Result<(), AppError> {
    let config = AgctlConfig::load(paths)?;
    let row = resolve(&config.codex_accounts, id)?;
    io.tell(&format!("id:       {}", key(row)));
    io.tell(&format!("user:     {}", row.chatgpt_user_id));
    io.tell(&format!("account:  {}", row.chatgpt_account_id));
    io.tell(&format!("email:    {}", row.email.as_deref().unwrap_or("-")));
    io.tell(&format!("plan:     {}", row.plan_type.as_deref().unwrap_or("-")));
    io.tell(&format!("label:    {}", row.label.as_deref().unwrap_or("-")));
    io.tell(&format!("kind:     {}", kind_name(&row.kind)));
    match &row.kind {
        CodexKind::Owned { export_spelling, refresh } => {
            io.tell(&format!("store:    {export_spelling}"));
            io.tell(&format!("refresh:  {}", refresh_name(*refresh)));
        }
        CodexKind::Live => io.tell("store:    the Codex home this environment names (read-only)"),
        CodexKind::HomeReadOnly { dir } => {
            io.tell(&format!("store:    {} (read-only)", dir.display()));
        }
    }
    io.tell(&format!("created:  {}", row.created_at));
    if row.forgotten {
        io.tell("hidden:   yes (`agctl codex accounts unforget` shows it again)");
    }
    Ok(())
}

/// `agctl codex accounts forget <id>` and `unforget <id>`.
///
/// Registry only, under `.config.lock`: a hidden row's credentials are not
/// touched, which is the whole difference between this and `remove`.
///
/// # Errors
///
/// As [`resolve`], plus whatever the registry update reports.
pub fn forget(paths: &Paths, id: &str, hide: bool, io: &mut dyn Prompt) -> Result<(), AppError> {
    let config = AgctlConfig::load(paths)?;
    let row = resolve(&config.codex_accounts, id)?;
    let (user, acct, shown) =
        (row.chatgpt_user_id.clone(), row.chatgpt_account_id.clone(), key(row));
    if row.forgotten == hide {
        io.tell(&format!("{shown} is already {}", if hide { "forgotten" } else { "shown" }));
        return Ok(());
    }
    AgctlConfig::update(paths, |config| {
        if let Some(row) = find_mut(config, &user, &acct) {
            row.forgotten = hide;
        }
    })?;
    io.tell(&format!(
        "{shown} is now {}",
        if hide { "hidden from reports" } else { "shown again" }
    ));
    Ok(())
}

/// `agctl codex accounts remove <id> [--delete-secret] [--yes]`.
///
/// # Errors
///
/// As [`resolve`]; [`AppError::Refused`] when the row's kind has no namespace
/// agctl wrote, when the confirmation is declined or impossible, when the
/// namespace lock is held, and when the namespace holds entries agctl did not
/// create; plus whatever the registry update reports.
pub fn remove(
    paths: &Paths,
    removal: &Removal<'_>,
    cancel: &Cancel,
    io: &mut dyn Prompt,
) -> Result<(), AppError> {
    let config = AgctlConfig::load(paths)?;
    let record = resolve(&config.codex_accounts, removal.id)?.clone();
    let shown = key(&record);

    if removal.delete_secret {
        // Invariant I21: neither of these has a namespace agctl wrote, so
        // there is nothing here agctl may delete. Said by name rather than
        // ignored, so `--delete-secret` never silently does less than it says.
        match &record.kind {
            CodexKind::Owned { .. } => {}
            CodexKind::Live => {
                return Err(AppError::Refused {
                    reason: format!(
                        "`{shown}` is the credential the Codex home this environment names holds; \
                         agctl never writes or deletes a file under a home it did not create. \
                         `agctl codex accounts forget {shown}` stops reporting it."
                    ),
                });
            }
            CodexKind::HomeReadOnly { dir } => {
                return Err(AppError::Refused {
                    reason: format!(
                        "`{shown}` was imported read-only from `{}`; agctl never writes or \
                         deletes a file under a home it did not create. \
                         `agctl codex accounts forget {shown}` stops reporting it.",
                        dir.display()
                    ),
                });
            }
        }
        if !removal.yes
            && !io.confirm(&format!(
                "delete the credential agctl stored for `{shown}` and forget the account?"
            ))?
        {
            io.tell("nothing was removed");
            return Ok(());
        }
        delete_namespace(paths, &record, &shown, cancel, io)?;
    }

    let (user, acct) = (record.chatgpt_user_id.clone(), record.chatgpt_account_id.clone());
    AgctlConfig::update(paths, |config| {
        config
            .codex_accounts
            .retain(|row| row.chatgpt_user_id != user || row.chatgpt_account_id != acct);
    })?;
    io.tell(&format!("{shown} is no longer recorded"));
    Ok(())
}

/// Unlinks the named files of an owned namespace and audits the removal.
///
/// # Why the existence check is inside the lock
///
/// `OwnedNamespace::open` creates the directory it opens
/// (`NamespaceDir::open` → `file_store::create_dir_under`), so opening one
/// here in order to delete it would make `remove` *write* — and for a record
/// whose credential is already gone it would create a namespace and
/// immediately `rmdir` it. So the directory is looked at first. That look is
/// taken **under the namespace guard**, never before it: outside the lock the
/// answer could change under another agctl between the look and the open, and
/// the point of the check is to decide whether to open at all.
///
/// Three things the check deliberately does not do. It is an `lstat`
/// ([`std::fs::symlink_metadata`]), so a symbolic link at the namespace path
/// is seen as a link rather than followed. **Only `NotFound` skips the
/// namespace work** — a link, a regular file, `EACCES` or any other error
/// goes on to `OwnedNamespace::open`, which owns that refusal and states it
/// properly; this function does not invent a second opinion about a path it
/// cannot read. And when it does skip, there is no write, therefore no
/// [`WriteReceipt`] and therefore **no `delete` line in the audit log** —
/// nothing happened to record (plan AC125).
///
/// The remaining races are harmless by construction: a namespace that appears
/// after the skip is an orphan `doctor` reports, and one that vanishes before
/// the open is re-created and `rmdir`ed by the removal itself.
///
/// [`WriteReceipt`]: crate::provider::codex::auth_store::WriteReceipt
fn delete_namespace(
    paths: &Paths,
    record: &CodexAccountRecord,
    shown: &str,
    cancel: &Cancel,
    io: &mut dyn Prompt,
) -> Result<(), AppError> {
    let owned = proof::owned(record).ok_or_else(|| AppError::Refused {
        reason: format!("`{shown}` is not an owned account, so agctl stores no credential for it"),
    })?;
    let dir = paths.codex_namespace_dir(&record.chatgpt_user_id, &record.chatgpt_account_id)?;
    let fault = crate::commands::status::current_fault();

    let guard =
        lock::acquire_codex(paths, owned, LockBudget::Command(REMOVE_LOCK_BUDGET), cancel, &fault)
            .map_err(|err| AppError::Refused { reason: err.to_string() })?;

    // Under the guard, and an lstat: only "it is not there" skips the work.
    if matches!(std::fs::symlink_metadata(&dir), Err(ref err) if err.kind() == io::ErrorKind::NotFound)
    {
        io.tell(&format!("{shown} has no stored credential; nothing to delete"));
        return Ok(());
    }

    let ns = OwnedNamespace::open(paths, owned, &guard)
        .map_err(|err| AppError::Refused { reason: err.to_string() })?;
    // Refuses before the first unlink when the namespace holds anything agctl
    // did not create (plan AC115).
    let receipt =
        ns.remove_named_files().map_err(|err| AppError::Refused { reason: err.to_string() })?;
    // Audited under the guard, after the unlinks have landed. A refused entry
    // leaves the removal standing and is reported, never undone (plan AC117).
    audit::append(paths, receipt)?;
    io.tell(&format!("{shown}: the stored credential and its refresh marker are gone"));
    // The guard drops here, before `AgctlConfig::update` takes `.config.lock`
    // — the order `login` uses, and the one the `testing`-only lock-order
    // witness asserts.
    Ok(())
}

/// What a row's kind is called in `list` and `show`.
///
/// Spelled here rather than on `CodexKind`: the serialized vocabulary is the
/// registry's contract (`#[serde(rename_all = "snake_case")]`) and what a
/// person reads is this command's, so changing one must not silently change
/// the other.
fn kind_name(kind: &CodexKind) -> &'static str {
    match kind {
        CodexKind::Owned { .. } => "owned",
        CodexKind::Live => "live",
        CodexKind::HomeReadOnly { .. } => "read-only home",
    }
}

/// What a refresh policy is called in `show`.
fn refresh_name(refresh: RefreshPolicy) -> &'static str {
    match refresh {
        RefreshPolicy::Auto => "auto (agctl may refresh this grant)",
        RefreshPolicy::Never => "never (agctl never sends this refresh token)",
    }
}

/// The row for `(user, acct)`, for a registry update's closure.
fn find_mut<'a>(
    config: &'a mut AgctlConfig,
    user: &str,
    acct: &str,
) -> Option<&'a mut CodexAccountRecord> {
    config
        .codex_accounts
        .iter_mut()
        .find(|row| row.chatgpt_user_id == user && row.chatgpt_account_id == acct)
}

/// What to call a subcommand this wave has not landed.
fn name(command: &CodexAccountsCommand) -> &'static str {
    match command {
        CodexAccountsCommand::List { .. } => "list",
        CodexAccountsCommand::Show { .. } => "show",
        CodexAccountsCommand::Remove { .. } => "remove",
        CodexAccountsCommand::Forget { .. } => "forget",
        CodexAccountsCommand::Unforget { .. } => "unforget",
        CodexAccountsCommand::Set { .. } => "set",
        CodexAccountsCommand::Refresh { .. } => "refresh",
    }
}

#[cfg(test)]
#[path = "accounts_tests.rs"]
mod tests;
