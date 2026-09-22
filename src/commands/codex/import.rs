//! `agctl codex import` — record the accounts another Codex home holds.
//!
//! The whole command is: resolve the home, decide whether its `auth.json` is
//! the credential Codex is actually using, read it **read-only**, and record
//! what its claims say. Plan section 3.3's `import` paragraph, AC106.
//!
//! # Nothing under the source home is touched
//!
//! Not one byte. The home is opened for reading through
//! [`auth_store::read_live`], which is the crate's single `auth.json` opener
//! (invariant I23) and whose final component is never followed through a
//! symbolic link; no directory under it is created, no lock in it is taken,
//! and no file in it is written, renamed or removed. That is not a promise
//! about intent — invariant I21 makes it structural, because the only path
//! this module ever hands to a writer is the registry's, and the recorded
//! `dir` is never passed to `SecretFile` or `OwnedNamespace`. The e2e proof
//! runs the import twice against a home whose directories are 0500 and whose
//! `auth.json` is 0400, and compares a manifest of it before and after.
//!
//! # Metadata only, and an import never overwrites what you have
//!
//! The record holds the two ids, the email and the plan the claims named, and
//! where the credentials live — never a token (decision D-007's posture, the
//! same one `agctl claude import` takes). An account already in the registry
//! is reported and left alone whatever kind it is, which is what makes a
//! second import a no-op rather than a way to turn a logged-in account back
//! into a read-only row, and why running this twice leaves the registry file
//! byte-identical.
//!
//! # One rule about the store mode, shared with `status`
//!
//! A home can keep its credentials in the keychain rather than in
//! `auth.json` (fact F62), and under `auto` the answer depends on whether an
//! item is listed (fact F94). Recording an identity read out of a file Codex
//! is not using would make two commands say two things about one home, so
//! this command asks the same question `status` asks, through the same
//! read-only listing call ([`pass::list_keyring`]) and the same decision
//! function ([`home::file_in_effect`]). When the answer is "not read", the
//! import refuses and **never opens `auth.json` at all** (plan AC95).
//!
//! `multi-auth/` is not a source (open question U32): the only thing this
//! command reads is a Codex home's own `auth.json`.

use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

use crate::cli::Cli;
use crate::cli::CodexImportArgs;
use crate::cli::CodexImportSource;
use crate::commands::codex::codex_env_from_process;
use crate::commands::codex::pass;
use crate::commands::codex::pass::KeyringListing;
use crate::config::AgctlConfig;
use crate::config::codex::CodexAccountRecord;
use crate::config::codex::CodexKind;
use crate::config::paths::Paths;
use crate::error::AppError;
use crate::provider::codex::auth_store;
use crate::provider::codex::auth_store::CodexResolved;
use crate::provider::codex::credentials::CodexIdentity;
use crate::provider::codex::home;
use crate::provider::codex::home::CodexEnv;
use crate::provider::codex::home::ConfigNote;
use crate::provider::codex::home::FileInEffect;
use crate::provider::codex::home::HomeError;
use crate::runtime::coordinator::Cancel;
use crate::runtime::coordinator::PassCtx;

/// How long the keychain reads an import makes may take in total.
///
/// Generous, for the same reason `agctl claude import`'s is: the per-call
/// budgets inside `security(1)` are the real limits, and this only stops a
/// wedged keychain from holding the command open forever.
const IMPORT_DEADLINE: Duration = Duration::from_secs(60);

/// One import, with every ambient input supplied.
pub struct Import<'a> {
    /// The store to record into.
    pub paths: &'a Paths,
    /// The parsed command line.
    pub args: &'a CodexImportArgs,
    /// The home to read, already resolved by [`resolve_home`].
    pub home: &'a Path,
    /// The keychain listing, needed only for a home in `auto` store mode.
    /// Read-only, always (invariant I21).
    pub keyring: &'a KeyringListing,
}

/// Runs `agctl codex import`.
///
/// # Errors
///
/// [`AppError::Refused`] when the home cannot be resolved, when its
/// credentials are not in a file agctl may read, or when the file holds no
/// usable identity; whatever [`AgctlConfig::update`] reports when the registry
/// cannot be written. All of them are fatal: an import either records what it
/// found or it does not.
pub fn run(cli: &Cli, args: &CodexImportArgs, cancel: &Cancel) -> Result<(), AppError> {
    // Neither `ensure_dirs` nor `ensure_codex_dirs` is called here, and that is
    // the whole of what makes `--dry-run` write *nothing*: `AgctlConfig::update`
    // creates the store's directories itself when it has something to record,
    // so a run that records nothing leaves a store that did not exist still not
    // existing — including the empty `claude/`, `claude/.locks` and
    // `cache/claude` a Codex-only run would otherwise create (plan AC97). The
    // Codex lock, marker and cache roots are never created by this command at
    // all: it takes no namespace lock and writes no credential.
    let paths = Paths::resolve(cli.config_dir.as_deref())?;

    let env = codex_env_from_process();
    let home = resolve_home(args, &env)?;

    // The listing is taken only when the home's own `config.toml` puts it in
    // `auto` mode, so a `file`-mode home — the default, and the common case —
    // costs no keychain call at all. `status` decides it the same way
    // (`pass::keyring_listing`).
    let keyring = if home::store_mode(&home).0 == home::StoreMode::Auto {
        let now = Instant::now();
        let deadline = now.checked_add(IMPORT_DEADLINE).unwrap_or(now);
        let ctx = PassCtx::standalone(cancel.clone(), deadline);
        let reader = crate::secret::default_reader(&ctx);
        pass::list_keyring(reader.as_ref())
    } else {
        KeyringListing::NotNeeded
    };

    let import = Import { paths: &paths, args, home: &home, keyring: &keyring };
    for line in run_with(&import)? {
        println!("{line}");
    }
    Ok(())
}

/// The home this run reads, under `codex_home`'s rules (plan AC95).
///
/// `--codex-home` is fed through the same [`home::codex_home`] as the
/// environment variable, so "must exist", "must be a directory" and "is
/// canonicalized" have **one** implementation rather than two that can drift.
/// Only the refusal differs: it names the flag the user typed rather than the
/// variable they did not.
///
/// # Errors
///
/// [`AppError::Refused`] naming the rule the home broke.
pub fn resolve_home(args: &CodexImportArgs, env: &CodexEnv) -> Result<PathBuf, AppError> {
    let Some(flag) = args.codex_home.as_deref() else {
        return home::codex_home(env).map_err(refused);
    };
    let named = CodexEnv::new(Some(flag.as_os_str().to_owned()), None);
    home::codex_home(&named).map_err(|err| {
        let reason = match err {
            HomeError::Missing(path) => {
                format!("`--codex-home` names `{}`, but that path does not exist", path.display())
            }
            HomeError::NotDirectory(path) => {
                format!(
                    "`--codex-home` names `{}`, but that path is not a directory",
                    path.display()
                )
            }
            HomeError::Unreadable { path, reason } => {
                format!("could not read `--codex-home` `{}`: {reason}", path.display())
            }
            // Unreachable with a value set, and stated rather than unwrapped.
            HomeError::NoHomeDirectory => "`--codex-home` names nothing".to_owned(),
        };
        AppError::Refused { reason: format!("codex home unreadable: {reason}") }
    })
}

/// The import itself, with the store, the home and the listing supplied,
/// returning the lines a real run would print.
///
/// Split out of [`run`] for the reason `agctl claude import`'s twin is: the
/// tests drive a complete import against a temporary store and a chosen
/// listing, and assert on both the output and the registry, without going near
/// the process environment or the real keychain (invariant I25).
///
/// # Errors
///
/// See [`run`].
pub fn run_with(import: &Import<'_>) -> Result<Vec<String>, AppError> {
    // Matched rather than assumed, so a second source cannot be added to the
    // command line without being wired up here.
    let CodexImportSource::CodexHome = import.args.from;

    let mut lines = Vec::new();
    let identity = read_identity(import, &mut lines)?;

    let existing = AgctlConfig::load(import.paths)?;
    let already = existing.codex_accounts.iter().any(|record| names(record, &identity));

    let who = identity.email.clone().unwrap_or_else(|| identity.user_id.clone());
    if already {
        // Decision D-007: reported and left alone, whatever kind it is. The
        // registry is not even rewritten, so a second run leaves the file
        // byte-identical.
        lines.push(format!("{who} is already recorded; nothing was changed"));
        return Ok(lines);
    }

    lines.push(format!("{who}: read-only, from `{}`", import.home.display()));
    if import.args.dry_run {
        lines.push("--dry-run: nothing was written".to_owned());
        return Ok(lines);
    }

    let dir = import.home.to_path_buf();
    AgctlConfig::update(import.paths, |config| record_once(config, &identity, dir))?;
    Ok(lines)
}

/// Appends the row for `identity` unless the registry already names those ids.
///
/// The body of the `AgctlConfig::update` closure, lifted out so a test can
/// drive it: the re-check below only matters in the window between the load
/// above and this write, which no ordinary run can enter, so left inside the
/// closure it was unfalsifiable — `if true` there passed the whole suite
/// (review C2-b, Q6). Called with the registry the update re-read **under
/// `.config.lock`**: another process may have recorded these ids since, and
/// two rows for one account is not something a later run can undo.
fn record_once(config: &mut AgctlConfig, identity: &CodexIdentity, dir: PathBuf) {
    if config.codex_accounts.iter().any(|record| names(record, identity)) {
        return;
    }
    config.codex_accounts.push(CodexAccountRecord {
        chatgpt_user_id: identity.user_id.clone(),
        chatgpt_account_id: identity.account_id.clone(),
        email: identity.email.clone(),
        plan_type: identity.plan.clone(),
        label: None,
        kind: CodexKind::HomeReadOnly { dir },
        forgotten: false,
        created_at: jiff::Timestamp::now().to_string(),
    });
}

/// Whether `record` is the account `identity` names.
fn names(record: &CodexAccountRecord, identity: &CodexIdentity) -> bool {
    record.chatgpt_user_id == identity.user_id && record.chatgpt_account_id == identity.account_id
}

/// The identity the home's credential names, or the refusal that stopped it.
///
/// The store-mode gate runs **first**, so a home whose credentials live in the
/// keychain is refused with zero reads of `auth.json` (plan AC95).
fn read_identity(import: &Import<'_>, lines: &mut Vec<String>) -> Result<CodexIdentity, AppError> {
    let home = import.home;
    let (mode, config_note) = home::store_mode(home);
    if let Some(note) = config_note {
        lines.push(match note {
            // The parser's message can quote the offending line, and that line
            // can hold a key (risk R61): a number, never the text.
            ConfigNote::Unparseable { line: Some(line) } => {
                format!("note: `config.toml` is not TOML (line {line}); assuming the default store")
            }
            ConfigNote::Unparseable { line: None } => {
                "note: `config.toml` is not TOML; assuming the default store".to_owned()
            }
            ConfigNote::Unreadable => {
                "note: `config.toml` could not be read; assuming the default store".to_owned()
            }
        });
    }

    match home::file_in_effect(&mode, || import.keyring.probe(home)) {
        FileInEffect::NotRead(mode) => {
            return Err(AppError::Refused {
                reason: format!(
                    "`{}` keeps its credentials in `{}`, which agctl does not read; there is \
                     nothing to import from it",
                    home.display(),
                    mode.label()
                ),
            });
        }
        FileInEffect::Read { note } => {
            if let Some(note) = note {
                lines.push(format!("note: {note}"));
            }
        }
    }

    let credentials = match auth_store::read_live(home) {
        CodexResolved::Credentials(credentials) => credentials,
        CodexResolved::Absent => {
            return Err(AppError::Refused {
                reason: format!(
                    "`{}` holds no `{}`; log in with `codex` there first",
                    home.display(),
                    auth_store::shown_name()
                ),
            });
        }
        // Fact F66: Codex rewrites the file in place without a lock, so a torn
        // read is a retry, never "there is nothing here".
        CodexResolved::Torn => {
            return Err(AppError::Refused {
                reason: format!(
                    "`{}`'s `{}` was being rewritten; run this again",
                    home.display(),
                    auth_store::shown_name()
                ),
            });
        }
        CodexResolved::Transient(reason) => return Err(AppError::Refused { reason }),
    };

    credentials.identity().ok_or_else(|| AppError::Refused {
        reason: format!(
            "`{}`'s credential names no ChatGPT user or account, so there is no account to record",
            home.display()
        ),
    })
}

/// A refusal carrying `err`'s own sentence.
fn refused(err: impl std::fmt::Display) -> AppError {
    AppError::Refused { reason: err.to_string() }
}

#[cfg(test)]
#[path = "import_tests.rs"]
mod tests;
