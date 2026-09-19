//! `agctl codex login` — decision D-037's L2′ (plan section 3.3).
//!
//! agctl does not implement the vendor's OAuth flow. It runs the vendor's own
//! `codex login` against a scratch home it owns, checks what that run left
//! behind, and then **copies** the bytes it verified into the namespace. The
//! order below is normative and the reasons are not interchangeable:
//!
//! 1. `scratch.lock` first, so two logins cannot interleave.
//! 2. A fresh keychain listing **before** the child, because the check that
//!    matters afterwards is a difference, not a count.
//! 3. `<scratch>/auth.json` registered with `runtime::cleanup` **before** the
//!    spawn, so a terminating signal takes the credential away even if it
//!    arrives one instruction after the child wrote it.
//! 4. A second fresh listing after it exits, then the survey, then
//!    `verify_login` — evidence before trust.
//! 5. The install copies the bytes `verify_login` parsed, not the file: a
//!    surviving child rewriting the scratch file in place cannot change what
//!    lands (architect M5, fact F66).
//! 6. The namespace lock is released **before** `AgctlConfig::update`, because
//!    `update`'s closure must not call into anything that locks
//!    (`config/mod.rs:235-248`). The two are never nested.
//!
//! The scratch `auth.json` is unlinked on every path out of here that unwinds,
//! the refusals included: a verified credential that was not installed is still
//! a credential lying in a temporary directory. This crate builds with
//! `panic = "abort"`, which runs no destructor, so agctl's own output must not
//! be able to panic in the window between the child's write and the
//! post-install unlink. Two things hold for that: every line this command
//! prints goes through [`say`], which drops a line it cannot deliver, and the
//! tracing subscriber is built with `log_internal_errors(false)` (`main.rs`), so
//! a log line it cannot deliver is dropped too instead of being reported with a
//! panicking `eprintln!`. A closed stdout or stderr (`agctl codex login 2>&1 |
//! head -1`) is therefore never what decides whether a credential is removed.
//! **Any other panic** in that window would still leave the file until a later
//! login's sweep (see `login_child::Scratch`).

use std::io;
use std::io::Write;
use std::time::Duration;
use std::time::Instant;

use crate::cli::Cli;
use crate::cli::CodexLoginArgs;
use crate::config::AgctlConfig;
use crate::config::codex::CodexAccountRecord;
use crate::config::codex::CodexKind;
use crate::config::codex::RefreshPolicy;
use crate::config::paths::Paths;
use crate::error::AppError;
use crate::provider::codex::audit;
use crate::provider::codex::auth_store;
use crate::provider::codex::auth_store::InstallNamespace;
use crate::provider::codex::auth_store::WriteKind;
use crate::provider::codex::home::KEYRING_SERVICE;
use crate::provider::codex::lock;
use crate::provider::codex::lock::LockBudget;
use crate::provider::codex::login_child;
use crate::provider::codex::proof::PostExitReport;
use crate::runtime::coordinator::Cancel;
use crate::runtime::coordinator::PassCtx;
use crate::secret::security_cli::SecurityCli;

use super::codex_env_from_process;

/// How long `login` waits for another login to finish before refusing.
const SCRATCH_LOCK_BUDGET: Duration = Duration::from_secs(5);

/// How long the namespace lock is waited for at install time.
const INSTALL_LOCK_BUDGET: Duration = Duration::from_secs(5);

/// How old a scratch home must be before a later login sweeps it.
///
/// The child's deadline plus five minutes (architect L7): anything younger
/// could still belong to a login in progress that this process cannot see,
/// and the lock is only held for the lifetime of a process, not of a
/// directory.
const STALE_SCRATCH_AGE: Duration = Duration::from_secs(15 * 60);

/// The fault name for a crash between the install and the registry update.
///
/// Plan AC105: the grant exists and no record names it, which `doctor` reports
/// as `namespace without record` and the next login adopts.
const FAULT_AFTER_WRITE: &str = "codex_login_after_write";

/// The pause point between `verify_login` and `install` (`testing` only).
///
/// Enabled as `AGCTL_FAULT=pause_codex_login_before_install`, through the same
/// `Fault::pause_point` every other pause in the crate uses.
const PAUSE_BEFORE_INSTALL: &str = "codex_login_before_install";

/// Runs `agctl codex login`.
///
/// # Errors
///
/// Returns [`AppError`] when another login holds the lifecycle lock, when the
/// vendor's binary is missing or its run is refused, when the credential it
/// wrote cannot be verified, or when the install or the registry update fails.
pub fn run(cli: &Cli, args: &CodexLoginArgs, cancel: &Cancel) -> Result<(), AppError> {
    let paths = Paths::resolve(cli.config_dir.as_deref())?;
    paths.ensure_dirs()?;
    paths.ensure_codex_dirs()?;
    let fault = crate::commands::status::current_fault();

    // Step 1. One login at a time. Held until this function returns.
    let _lifecycle = login_child::acquire_scratch_lock(&paths, SCRATCH_LOCK_BUDGET, cancel, &fault)
        .map_err(refused)?;

    // The root is judged BEFORE anything touches it. `ensure_codex_dirs`
    // trusts a root that already exists — a symlink, another user's directory,
    // a 0755 one — so the sweep below, the one destructive operation on the
    // root, may run only on a descriptor that has been verified. A refusal here
    // means no sweep at all.
    let root_path = paths.codex_scratch_root();
    let root = login_child::open_scratch_root(&root_path).map_err(refused)?;

    // Under the lock, and only through the verified descriptor: scratch homes a
    // killed login left behind (plan AC105, AC125).
    login_child::sweep_stale_at(&root, &root_path, STALE_SCRATCH_AGE, &mut io::stderr().lock());

    // The binary is found before a scratch home exists, so "not on PATH" leaves
    // nothing to clean up.
    let bin = login_child::resolve_codex_bin().map_err(refused)?;

    // The child gets a generous deadline of its own; the pass context exists
    // to own the child handle and to kill it when that deadline passes.
    let now = Instant::now();
    let ctx = PassCtx::standalone(
        cancel.clone(),
        now.checked_add(login_child::LOGIN_DEADLINE).unwrap_or(now),
    );

    // A concrete `SecurityCli`, not a `Box<dyn KeychainReader>`: the two
    // listings must be two dumps, and only the concrete type exposes the call
    // that bypasses the memo. `login` builds this instance and hands it to
    // nobody, so clearing its memo affects no other reader.
    let reader = SecurityCli::from_env(ctx.clone());

    // Step 2. Listing #1, before anything runs.
    let before = listing(reader.as_ref()).map_err(|reason| AppError::Refused {
        reason: format!("could not read the keychain before the login: {reason}"),
    })?;

    // Steps 3-6. From here the scratch home is discarded when `scratch` drops —
    // the credential unlinked, the directory removed — on every path out of
    // this function, the error paths included.
    let scratch = login_child::Scratch::create(&root_path, root).map_err(refused)?;
    let report = login_child::run(&scratch, &bin, &ctx, &before, || listing(reader.as_ref()))
        .map_err(refused)?;

    install_verified(&paths, &scratch, &report, args, cancel, &fault)
}

/// Steps 7-14: verify, notice, lock, install, audit, release, record.
fn install_verified(
    paths: &Paths,
    scratch: &login_child::Scratch,
    report: &PostExitReport,
    args: &CodexLoginArgs,
    cancel: &Cancel,
    fault: &crate::runtime::fault::Fault,
) -> Result<(), AppError> {
    // Step 7. Evidence first: the report decides whether the document is even
    // read, and `verify_login` parses it exactly once.
    let login = auth_store::verify_login(scratch.path(), report).map_err(refused)?;

    // Step 8. Who this is, and whether it is the account the live home already
    // holds (fact F82).
    let identity = login.identity();
    if let Some(notice) = live_identity_notice(&identity.user_id, &identity.account_id) {
        say(&notice);
    }

    // Steps 9-13, in plan section 3.3's order: namespace lock → install (with
    // the refresh-state reset it performs under the same guard, plan AC114) →
    // unlink the scratch copy → audit → release.
    let overwrote = {
        let guard = lock::acquire_codex_for_install(
            paths,
            &login,
            LockBudget::Command(INSTALL_LOCK_BUDGET),
            cancel,
            fault,
        )
        .map_err(refused)?;

        // `testing` only: a test that has seen the namespace lock appear knows
        // `verify_login` has parsed the document, and swaps the scratch file
        // while agctl waits here. The install below must still land the bytes
        // that were verified (plan AC126). A release build returns at once.
        fault.pause_point(PAUSE_BEFORE_INSTALL);

        let install = InstallNamespace::open_for_install(paths, login, &guard).map_err(refused)?;
        let (receipt, _) = install.install(fault).map_err(refused)?;

        // Step 12, straight after the install: the two 0600 copies of the
        // grant must not coexist across the wait for the configuration lock.
        scratch.unlink_credential();

        let kind = receipt.kind();
        // Step 13, audited under the namespace lock, after the write has
        // landed. A failure here leaves the write standing and is reported,
        // never rolled back (`audit.rs:585-592`).
        audit::append(paths, receipt)?;
        kind
        // Step 14a: the guard drops here, before `AgctlConfig::update` below.
    };

    if fault.is(FAULT_AFTER_WRITE) {
        return Err(AppError::Refused {
            reason: format!(
                "stopped between the install and the registry update (injected by \
                 `{FAULT_AFTER_WRITE}`)"
            ),
        });
    }

    // Step 14b. The registry, under `.config.lock`, with the namespace lock
    // already released.
    record_account(paths, &identity, args)?;

    say(&format!(
        "logged in as {} ({})",
        identity.email.as_deref().unwrap_or(&identity.user_id),
        describe(overwrote)
    ));
    Ok(())
}

/// Prints one line on stdout, and never panics.
///
/// `println!` panics when stdout is a pipe whose reader has gone (`EPIPE`: Rust
/// ignores `SIGPIPE`), and under `panic = "abort"` that panic would skip the
/// `Scratch` drop and leave a verified credential in the scratch home. So a
/// line that cannot be delivered is dropped instead: the user loses a message,
/// never the cleanup.
fn say(line: &str) {
    let _ = writeln!(io::stdout().lock(), "{line}");
}

/// A refusal carrying `err`'s own sentence.
fn refused(err: impl std::fmt::Display) -> AppError {
    AppError::Refused { reason: err.to_string() }
}

/// Takes one fresh keychain listing, or an empty one when this build has no
/// keychain to read.
///
/// The error is the bare reason; each caller says when it happened, and the
/// second listing turns it into a refusal rather than an empty list.
fn listing(reader: Option<&SecurityCli>) -> Result<Vec<String>, String> {
    let Some(reader) = reader else { return Ok(Vec::new()) };
    let entries = reader.list_services_uncached(KEYRING_SERVICE).map_err(|err| err.to_string())?;
    // An entry with no account column still counts: it is a `Codex Auth`
    // item, and the difference between the two listings is what matters. The
    // service name stands in for it so a gained item is never invisible.
    Ok(entries
        .into_iter()
        .map(|entry| entry.account.unwrap_or_else(|| format!("{} (no account)", entry.service)))
        .collect())
}

/// The fact F82 notice: the live home already holds this same identity.
fn live_identity_notice(user: &str, acct: &str) -> Option<String> {
    let env = codex_env_from_process();
    let home = crate::provider::codex::home::codex_home(&env).ok()?;
    let credentials = match auth_store::read_live(&home) {
        crate::provider::codex::auth_store::CodexResolved::Credentials(credentials) => credentials,
        _ => return None,
    };
    let live = credentials.identity()?;
    (live.user_id == user && live.account_id == acct).then(|| {
        format!(
            "note: `{}` already holds this same account; agctl now has its own copy, and the two \
             grants refresh independently",
            home.display()
        )
    })
}

/// Writes or replaces the registry record for a login.
fn record_account(
    paths: &Paths,
    identity: &crate::provider::codex::credentials::CodexIdentity,
    args: &CodexLoginArgs,
) -> Result<(), AppError> {
    let refresh = if args.no_refresh { RefreshPolicy::Never } else { RefreshPolicy::Auto };
    let export_spelling = paths
        .codex_namespace_dir(&identity.user_id, &identity.account_id)?
        .to_string_lossy()
        .into_owned();

    AgctlConfig::update(paths, |config| {
        let existing = config.codex_accounts.iter_mut().find(|record| {
            record.chatgpt_user_id == identity.user_id
                && record.chatgpt_account_id == identity.account_id
        });
        match existing {
            Some(record) => {
                record.email.clone_from(&identity.email);
                record.plan_type.clone_from(&identity.plan);
                if args.label.is_some() {
                    record.label.clone_from(&args.label);
                }
                record.kind = CodexKind::Owned { export_spelling, refresh };
                record.forgotten = false;
            }
            None => config.codex_accounts.push(CodexAccountRecord {
                chatgpt_user_id: identity.user_id.clone(),
                chatgpt_account_id: identity.account_id.clone(),
                email: identity.email.clone(),
                plan_type: identity.plan.clone(),
                label: args.label.clone(),
                kind: CodexKind::Owned { export_spelling, refresh },
                forgotten: false,
                created_at: now_rfc3339(),
            }),
        }
    })?;
    Ok(())
}

/// `now` as RFC 3339 in UTC, the spelling the registry uses.
fn now_rfc3339() -> String {
    jiff::Timestamp::now().to_string()
}

/// How the install is described to the user.
fn describe(kind: WriteKind) -> &'static str {
    match kind {
        WriteKind::LoginInstall { overwrote: true } => "replacing the grant that was there",
        _ => "a new grant",
    }
}

#[cfg(test)]
#[path = "login_tests.rs"]
mod tests;
