//! `agentctl claude import` — record accounts another tool already knows.
//!
//! The whole command is: build a plan, print it, and — unless `--dry-run` —
//! apply it to the registry. Everything that decides *what* the plan says
//! lives in [`crate::config::import`], which is pure; this module supplies the
//! three ambient inputs those planners refuse to fetch for themselves (the
//! file's bytes, the keychain listing, the environment) and performs the one
//! write.
//!
//! # One write, and it is the registry
//!
//! `AgentctlConfig::update` is the only mutation, and it is reached once, at
//! the end, after every decision is made. No credential is written, moved or
//! deleted; the keychain is read and never written (invariant I1); and
//! `--dry-run` reaches neither, which is why it leaves a store that did not
//! exist still not existing.
//!
//! # An import never overwrites what you have
//!
//! An account already in the registry is reported and left alone, whatever
//! kind it is (decision D-007). That is what makes a second import a no-op
//! rather than a way to turn a logged-in account back into metadata, and it
//! is why running this command twice produces a byte-identical registry.

use std::path::Path;
use std::time::Duration;
use std::time::Instant;

use crate::cli::ImportArgs;
use crate::cli::ImportSource;
use crate::config::AgentctlConfig;
use crate::config::import;
use crate::config::import::ImportPlan;
use crate::config::paths::Paths;
use crate::error::AppError;
use crate::provider::claude::namespace::EnvView;
use crate::runtime::coordinator::Cancel;
use crate::runtime::coordinator::PassCtx;
use crate::secret::KeychainReader;
use crate::secret::KeychainStatus;
use crate::secret::file_store;
use crate::secret::file_store::ReadOutcome;

/// How long the keychain reads an import makes may take in total.
///
/// Generous, because the per-call budgets inside `security(1)` are the real
/// limits; this only stops a wedged keychain from holding the command open
/// forever.
const IMPORT_DEADLINE: Duration = Duration::from_secs(60);

/// One import, with every ambient input supplied.
pub struct Import<'a> {
    /// The store to record into.
    pub paths: &'a Paths,
    /// The parsed command line.
    pub args: &'a ImportArgs,
    /// The keychain. Read-only, always.
    pub reader: &'a dyn KeychainReader,
    /// The environment the keychain naming rule depends on (fact F14).
    pub env: &'a EnvView,
}

/// Runs `agentctl claude import`.
///
/// # Errors
///
/// Returns [`AppError::Config`] when the source cannot be read or understood —
/// a missing switcher file, a schema this build does not know, an unreadable
/// keychain — and whatever [`AgentctlConfig::update`] reports when the
/// registry cannot be written. All of them are fatal: an import either
/// records what it found or it does not.
pub fn run(config_dir: Option<&Path>, args: &ImportArgs, cancel: &Cancel) -> Result<(), AppError> {
    let paths = Paths::resolve(config_dir)?;
    let env = EnvView::from_process();
    let now = Instant::now();
    let deadline = now.checked_add(IMPORT_DEADLINE).unwrap_or(now);
    let ctx = PassCtx::standalone(cancel.clone(), deadline);
    let reader = crate::secret::default_reader(&ctx);

    let import = Import { paths: &paths, args, reader: reader.as_ref(), env: &env };
    for line in run_with(&import)? {
        println!("{line}");
    }
    Ok(())
}

/// The import itself, with the store, the keychain and the environment
/// supplied, returning the lines a real run would print.
///
/// Split out of [`run`] so the acceptance tests can drive a complete import
/// against a temporary store and a scripted keychain, and assert on both the
/// output and the registry, without going near the process environment or the
/// real keychain.
///
/// # Errors
///
/// See [`run`].
pub fn run_with(import: &Import<'_>) -> Result<Vec<String>, AppError> {
    let existing = AgentctlConfig::load(import.paths)?;
    let mut plan = match import.args.from {
        ImportSource::ClaudeSwitcher => switcher_plan(import, &existing)?,
        ImportSource::Keychain => keychain_plan(import, &existing)?,
    };
    plan.decisions.splice(0..0, ignored_flag_warnings(import.args));

    let records = plan.records();
    let mut lines = plan.lines();
    if import.args.dry_run {
        lines.push("--dry-run: nothing was written".to_owned());
        return Ok(lines);
    }
    if !records.is_empty() {
        AgentctlConfig::update(import.paths, |config| {
            for record in records {
                config.upsert(record);
            }
        })?;
    }
    Ok(lines)
}

/// Plans an import from the `claude-account-switcher` account file (fact F10).
fn switcher_plan(import: &Import<'_>, existing: &AgentctlConfig) -> Result<ImportPlan, AppError> {
    let path = match import.args.path.as_deref() {
        Some(path) => path.to_path_buf(),
        None => {
            if import.env.home.as_os_str().is_empty() {
                return Err(AppError::Config(
                    "no home directory to look for `claude-switcher/accounts.json` in; pass \
                     --path"
                        .to_owned(),
                ));
            }
            import::default_switcher_path(&import.env.home)
        }
    };

    // Symlinks are followed: this is another tool's file, agentctl only ever
    // reads it, and refusing a link would break a perfectly ordinary
    // dotfile-manager setup. The size cap is what keeps that safe.
    let bytes = match file_store::read_file_following(&path, import::MAX_SWITCHER_BYTES) {
        Ok(ReadOutcome::Present { bytes, .. }) => bytes,
        Ok(ReadOutcome::Absent) => {
            return Err(AppError::Config(format!(
                "no claude-switcher account file at `{}`",
                path.display()
            )));
        }
        Err(err) => {
            return Err(AppError::Config(format!("could not read `{}`: {err}", path.display())));
        }
    };

    let accounts = import::parse_switcher(&bytes, &path)?;
    Ok(import::plan_switcher(&accounts, existing))
}

/// Plans an import of per-configuration-directory keychain items.
fn keychain_plan(import: &Import<'_>, existing: &AgentctlConfig) -> Result<ImportPlan, AppError> {
    match import.reader.preflight() {
        KeychainStatus::Unlocked => {}
        KeychainStatus::Locked => {
            return Err(AppError::Config(
                "the keychain is locked, so there is nothing to import from; unlock it and run \
                 this again"
                    .to_owned(),
            ));
        }
        KeychainStatus::Timeout => {
            return Err(AppError::Config(
                "the keychain did not answer in time; nothing was imported".to_owned(),
            ));
        }
        KeychainStatus::Unavailable(detail) => {
            return Err(AppError::Config(format!(
                "the keychain is not available ({detail}); nothing was imported"
            )));
        }
    }

    let listing = import
        .reader
        .list_services(import::IMPORT_SERVICE_PREFIX)
        .map_err(|err| AppError::Config(format!("could not list keychain services: {err}")))?;

    Ok(import::plan_keychain(
        &import.args.claude_config_dir,
        &listing,
        import.reader,
        import.env,
        existing,
    ))
}

/// Warnings for flags that mean nothing for the chosen source.
///
/// Reported rather than rejected: a wrong flag here changes nothing, and a
/// user who passed one has a wrong idea about what the command did, which is
/// worth saying out loud.
fn ignored_flag_warnings(args: &ImportArgs) -> Vec<import::Decision> {
    let mut warnings = Vec::new();
    match args.from {
        ImportSource::ClaudeSwitcher if !args.claude_config_dir.is_empty() => {
            warnings.push(import::Decision::Warning(
                "--claude-config-dir means nothing for --from claude-switcher; ignored".to_owned(),
            ));
        }
        ImportSource::Keychain if args.path.is_some() => {
            warnings.push(import::Decision::Warning(
                "--path means nothing for --from keychain; ignored".to_owned(),
            ));
        }
        _ => {}
    }
    warnings
}

#[cfg(test)]
#[path = "import_tests.rs"]
mod tests;
