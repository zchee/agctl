//! Isolated Claude Code sessions (`agentctl claude use`/`exec`/`env`).
//!
//! **This module is a skeleton.** S15 gives it exactly enough to make
//! `export.rs`'s `exec`/`env` land: [`ensure_session`] creates the session
//! directory and the D-019 MCP symlink, and nothing else. S16 extends
//! [`ensure_session`] with the tier 1/tier 2 symlinks, the `.claude.json`
//! seed, idempotent self-repair beyond the symlink, and adds
//! `forget_session` for `use --forget`. The constants below are S16's
//! allowlists, carried here now because [`TIER1`]/[`TIER2_DIRS`] are already
//! referenced by this module's doc comments and by `doctor` (S17).

// The seeding allowlists, `seed_floor`, and `SessionOptions::fresh_context`
// have no production reader yet: S16 is the one that seeds tier 1/tier 2 and
// the `.claude.json` floor, and consumes `fresh_context` to decide whether
// tier 2 is symlinked at all. Scoped to the non-test build, as the rest of
// this crate's not-yet-wired items are, because the unit tests below already
// exercise the directory- and symlink-facing half of this module.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "S16 (isolate.rs seeding) and S17 (doctor's isolation section) are the first \
                  production callers"
    )
)]

use std::os::unix::fs::DirBuilderExt;
use std::path::Path;
use std::path::PathBuf;

use crate::config::AccountKind;
use crate::config::AccountRecord;
use crate::config::paths::DIR_MODE;
use crate::config::paths::Paths;
use crate::error::AppError;
use crate::provider::claude::namespace;
use crate::provider::claude::namespace::EnvView;
use crate::runtime::coordinator::PassCtx;

/// Tier 1: symlinked files/dirs whose loss changes how Claude Code behaves.
pub const TIER1: &[&str] = &["settings.json", "CLAUDE.md", "skills"];

/// Tier 2: symlinked DIRECTORIES whose loss changes what the user can
/// resume; `--fresh-context` omits them.
pub const TIER2_DIRS: &[&str] =
    &["projects", "shell-snapshots", "file-history", "sessions", "session-env"];

/// Never symlinked: a file with its own uncaptured lock (architect 9).
pub const NEVER_LINKED: &[&str] = &["history.jsonl"];

/// `.claude.json` keys copied verbatim at seeding when present in the live
/// file (`.omc/handoffs/w0-s11.md`).
pub const SEED_KEYS: &[&str] = &[
    "hasCompletedOnboarding",
    "lastOnboardingVersion",
    "lastReleaseNotesSeen",
    "hasSeenAutoDefaultNotice",
    "hasCompletedClaudeInChromeOnboarding",
    "theme",
    "preferredNotifChannel",
    "editorMode",
    "autoUpdates",
    "autoUpdatesProtectedForNative",
    "installMethod",
    "bypassPermissionsModeAccepted",
    "hasAcknowledgedCostThreshold",
    "shiftEnterKeyBindingInstalled",
    "verbose",
];

/// Account/subscription-scoped keys that must never be seeded (plan AC54's
/// leak test; also `doctor`'s vocabulary).
pub const NEVER_SEED: &[&str] = &[
    "oauthAccount",
    "userID",
    "machineID",
    "cachedUsageUtilization",
    "overageCreditGrantCache",
    "passesEligibilityCache",
    "s1mAccessCache",
    "s1mNonSubscriberAccessCache",
    "customApiKeyResponses",
    "mcpServers",
    "projects",
    "modelAccessCache",
    "orgModelDefaultCache",
    "cachedExtraUsageDisabledReason",
    "additionalModelOptionsCache",
    "additionalModelOptionsAnsweredAt",
    "additionalModelCostsCache",
    "autoCompactWindowsCache",
    "clientDataCacheSlots",
];

/// The name of the D-019 MCP symlink inside a session directory.
pub const MCP_LINK: &str = "mcp.json";

/// The floor written when the live file lacks `hasCompletedOnboarding`.
///
/// A function rather than a `const` alongside [`SEED_KEYS`]/[`NEVER_SEED`]:
/// [`serde_json::Value`] is not constructible in a `const` context once the
/// crate's `preserve_order` feature is on (`Value::Object` becomes an
/// `indexmap::IndexMap`, which is not `const`-safe even for a variant this
/// never builds — the restriction is on the type, not the value). S16, the
/// first consumer, calls this instead.
pub fn seed_floor() -> Vec<(&'static str, serde_json::Value)> {
    vec![("hasCompletedOnboarding", serde_json::Value::Bool(true))]
}

/// What `use`/`exec`/`env` were asked for, beyond the account itself.
#[derive(Debug, Clone, Default)]
pub struct SessionOptions {
    /// Overrides the generated session directory. Must be absolute.
    pub claude_config_dir: Option<PathBuf>,
    /// Omits the tier 2 directory symlinks (S16).
    pub fresh_context: bool,
    /// Omits the MCP symlink (and, upstream, the flag and the alias).
    pub no_mcp: bool,
}

/// Where one session landed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionDir {
    /// The session's Claude Code config directory.
    pub path: PathBuf,
    /// `Some(path/mcp.json)` unless `no_mcp` was given.
    pub mcp_config: Option<PathBuf>,
}

/// Prepares one isolated session directory.
///
/// S15's scope is exactly two things: create `path` at mode 0700 (parents as
/// needed; an `opts.claude_config_dir` override must be absolute, refused
/// otherwise) and, unless `opts.no_mcp`, place the D-019 symlink
/// `path/mcp.json -> canonical(<live .claude.json>)`. A `mcp.json` that
/// already exists and is not exactly that symlink is refused, naming the
/// path (invariant I19). **S16 extends this** with the tier 1/tier 2
/// symlinks, the `.claude.json` seed, and the read-twice-and-compare
/// liveness check; none of that runs yet.
///
/// Only an [`AccountKind::Owned`] account has a namespace to isolate:
/// `Live` and `ConfigDirReadOnly` are refused, naming the kind.
///
/// `ctx` is accepted now, ahead of use, because the signature is fixed for
/// S16, which threads it through the seed's retry-and-cancel loop; nothing
/// in S15's body reads it.
///
/// # Errors
///
/// Returns [`AppError::Config`] for a non-`Owned` account or a relative
/// `claude_config_dir` override, and [`AppError::Io`] when the directory or
/// the symlink cannot be created.
pub fn ensure_session(
    paths: &Paths,
    rec: &AccountRecord,
    opts: &SessionOptions,
    env: &EnvView,
    _ctx: &PassCtx,
) -> Result<SessionDir, AppError> {
    let (account_uuid, organization_uuid) = match &rec.kind {
        AccountKind::Owned { .. } => (rec.account_uuid.as_str(), rec.organization_uuid.as_str()),
        other => {
            return Err(AppError::Config(format!(
                "only an account agentctl owns can be isolated into a session; `{}` is `{}`, whose \
                 credentials live outside agentctl's own store",
                rec.account_uuid,
                other.name()
            )));
        }
    };

    let path = match &opts.claude_config_dir {
        Some(dir) if dir.is_absolute() => dir.clone(),
        Some(dir) => {
            return Err(AppError::Config(format!(
                "--claude-config-dir must be an absolute path; `{}` is not",
                dir.display()
            )));
        }
        None => paths.session_dir(account_uuid, organization_uuid),
    };

    create_session_dir(&path)?;

    let mcp_config = if opts.no_mcp { None } else { Some(link_mcp_config(&path, env)?) };

    Ok(SessionDir { path, mcp_config })
}

/// Creates one session directory at [`DIR_MODE`], parents included,
/// tolerating one that already exists.
///
/// Mirrors [`crate::config::paths`]'s own `create_dir_mode` rather than
/// calling it: that helper is private to its module, and duplicating four
/// lines here is cheaper than widening its visibility for one caller.
fn create_session_dir(path: &Path) -> Result<(), AppError> {
    if path.is_dir() {
        return Ok(());
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(DIR_MODE);
    builder.create(path).map_err(|err| AppError::Io {
        context: format!("could not create the session directory `{}`", path.display()),
        source: err,
    })
}

/// Places (or verifies) the D-019 `mcp.json` symlink inside `session_dir`.
///
/// The target is `canonical(claude_json_path(env))` — the live
/// `.claude.json` agentctl's own environment names, not the session's own.
/// Idempotent: a symlink already pointing at the same target is left alone.
/// Anything else already at that path is invariant I19's refusal, naming the
/// path.
fn link_mcp_config(session_dir: &Path, env: &EnvView) -> Result<PathBuf, AppError> {
    let live_claude_json = namespace::claude_json_path(env);
    let target = namespace::canonical(&live_claude_json).map_err(|err| AppError::Io {
        context: format!("could not resolve `{}`", live_claude_json.display()),
        source: err,
    })?;

    let link = session_dir.join(MCP_LINK);
    match std::fs::symlink_metadata(&link) {
        Ok(meta) if meta.file_type().is_symlink() => {
            let existing = std::fs::read_link(&link).map_err(|err| AppError::Io {
                context: format!("could not read the existing symlink `{}`", link.display()),
                source: err,
            })?;
            if existing == target {
                return Ok(link);
            }
            Err(AppError::Config(format!(
                "`{}` already exists and points at `{}`, not `{}`; agentctl will not replace a \
                 symlink it did not place there",
                link.display(),
                existing.display(),
                target.display()
            )))
        }
        Ok(_) => Err(AppError::Config(format!(
            "`{}` already exists and is not the symlink agentctl would place there; move or \
             remove it before starting this session",
            link.display()
        ))),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            std::os::unix::fs::symlink(&target, &link).map_err(|err| AppError::Io {
                context: format!("could not create the symlink `{}`", link.display()),
                source: err,
            })?;
            Ok(link)
        }
        Err(err) => Err(AppError::Io {
            context: format!("could not inspect `{}`", link.display()),
            source: err,
        }),
    }
}

#[cfg(test)]
#[path = "isolate_tests.rs"]
mod tests;
