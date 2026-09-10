//! Isolated Claude Code sessions (`agctl claude use`/`exec`/`env`).
//!
//! [`ensure_session`] builds one session directory: the directory itself at
//! mode 0700, the D-019 MCP symlink, the tier 1/tier 2 symlinks into the live
//! Claude Code configuration, and the one-time `.claude.json` seed (plan
//! section 3.3, AC53–AC57). Every placement is idempotent and refuses,
//! naming the path, when something agctl did not put there already
//! occupies an allowlisted path (invariant I19, AC56). [`forget_session`] is
//! `use --forget`'s teardown (AC79). The constants below are the allowlists
//! this module, `export.rs` and `doctor` (S17) all read.

use std::io::Write as _;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::path::PathBuf;

use crate::commands::Prompt;
use crate::config::AccountKind;
use crate::config::AccountRecord;
use crate::config::paths::DIR_MODE;
use crate::config::paths::FILE_MODE;
use crate::config::paths::Paths;
use crate::config::paths::lexical_normalize;
use crate::error::AppError;
use crate::provider::claude::discovery;
use crate::provider::claude::namespace;
use crate::provider::claude::namespace::EnvView;
use crate::runtime::coordinator::PassCtx;
use crate::secret::file_store;
use crate::secret::file_store::ReadOutcome;

/// Tier 1: symlinked files/dirs whose loss changes how Claude Code behaves.
pub const TIER1: &[&str] = &["settings.json", "CLAUDE.md", "skills"];

/// Tier 2: symlinked DIRECTORIES whose loss changes what the user can
/// resume; `--fresh-context` omits them.
pub const TIER2_DIRS: &[&str] =
    &["projects", "shell-snapshots", "file-history", "sessions", "session-env"];

/// Never symlinked: a file with its own uncaptured lock (architect 9).
///
/// Seeding never touches these; `doctor` reads the list so it can report
/// `history.jsonl` as "not linked by design" rather than as unexposed.
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

/// The seeded session-local config's file name inside a session directory.
pub const SEED_FILE: &str = ".claude.json";

/// How many times [`read_twice_and_compare`] reads the live file and
/// compares before refusing to seed a possibly torn copy (M6): one first
/// attempt plus three retries, per plan section 3.3.
const LIVE_READ_ATTEMPTS: u32 = 4;

/// The floor written when the live file lacks `hasCompletedOnboarding`.
///
/// A function rather than a `const` alongside [`SEED_KEYS`]/[`NEVER_SEED`]:
/// [`serde_json::Value`] is not constructible in a `const` context once the
/// crate's `preserve_order` feature is on (`Value::Object` becomes an
/// `indexmap::IndexMap`, which is not `const`-safe even for a variant this
/// never builds — the restriction is on the type, not the value).
pub fn seed_floor() -> Vec<(&'static str, serde_json::Value)> {
    vec![("hasCompletedOnboarding", serde_json::Value::Bool(true))]
}

/// What `use`/`exec`/`env` were asked for, beyond the account itself.
#[derive(Debug, Clone, Default)]
pub struct SessionOptions {
    /// Overrides the generated session directory. Must be absolute.
    pub claude_config_dir: Option<PathBuf>,
    /// Omits the tier 2 directory symlinks.
    pub fresh_context: bool,
    /// Omits the MCP symlink (and, upstream, the flag and the alias).
    pub no_mcp: bool,
}

/// Where one session landed, and what its tier 1/tier 2 pass found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionDir {
    /// The session's Claude Code config directory.
    pub path: PathBuf,
    /// `Some(path/mcp.json)` unless `no_mcp` was given.
    pub mcp_config: Option<PathBuf>,
    /// Tier 1/tier 2 entry names symlinked by this call: the live config
    /// directory had them, and the session had no symlink for them yet (or
    /// this call's idempotent repair replaced one that had gone missing).
    pub linked: Vec<String>,
    /// Tier 1/tier 2 entry names the live config directory does not have
    /// (or, for tier 2, that `--fresh-context` omitted). Nothing was created
    /// for them.
    pub missing: Vec<String>,
    /// Session-directory paths whose tier 1/tier 2 symlink already pointed
    /// at the live entry before this call — left untouched (I19's "leaves
    /// correct ones alone"). Named `already_linked` rather than `occupied`
    /// so it cannot be confused with `doctor`'s `occupied` state, which means
    /// the opposite: something foreign sits at that path.
    pub already_linked: Vec<PathBuf>,
}

/// Prepares one isolated session directory (plan section 3.3).
///
/// Creates `path` at mode 0700 (parents as needed; an
/// `opts.claude_config_dir` override must be absolute, refused otherwise),
/// symlinks every tier 1/tier 2 entry the live Claude Code configuration
/// directory has (AC53; `opts.fresh_context` omits tier 2 entirely), places
/// the D-019 MCP symlink unless `opts.no_mcp` (AC55), and seeds
/// `<path>/.claude.json` once from the live `.claude.json` (AC54). Every
/// placement is idempotent: an existing, correct symlink or an
/// already-seeded file is left alone; anything else already at an
/// allowlisted path is invariant I19's refusal, naming the path, and nothing
/// after it in this call is touched (AC56).
///
/// Only an [`AccountKind::Owned`] account has a namespace to isolate:
/// `Live` and `ConfigDirReadOnly` are refused, naming the kind.
///
/// `ctx` bounds the seed's read-twice-and-compare retry loop (M6): a run
/// that is cancelled or past its deadline gives up between retries rather
/// than running out the whole retry budget.
///
/// # Errors
///
/// Returns [`AppError::Config`] for a non-`Owned` account, a relative
/// `claude_config_dir` override, an I19 conflict, or a live `.claude.json`
/// that will not read consistently; [`AppError::Io`] when a directory, a
/// symlink or the seed file cannot be created; and [`AppError::Refused`]
/// when `ctx` is cancelled mid-seed.
pub fn ensure_session(
    paths: &Paths,
    rec: &AccountRecord,
    opts: &SessionOptions,
    env: &EnvView,
    ctx: &PassCtx,
) -> Result<SessionDir, AppError> {
    let (account_uuid, organization_uuid) = match &rec.kind {
        AccountKind::Owned { .. } => (rec.account_uuid.as_str(), rec.organization_uuid.as_str()),
        other => {
            return Err(AppError::Config(format!(
                "only an account agctl owns can be isolated into a session; `{}` is `{}`, whose \
                 credentials live outside agctl's own store",
                rec.account_uuid,
                other.name()
            )));
        }
    };

    let path = match &opts.claude_config_dir {
        Some(dir) if dir.is_absolute() => {
            // N-2: refused before anything else, so a `..`/`.` spelling
            // never reaches `is_live_store_dir`'s comparison (whose own
            // fallback normalizes defensively, but should not have to be the
            // only thing standing between a malformed override and the live
            // directory).
            if has_dot_component(dir) {
                return Err(AppError::Config(format!(
                    "--claude-config-dir `{}` must be an absolute, normalized path",
                    dir.display()
                )));
            }
            if is_live_store_dir(dir, env) {
                return Err(AppError::Config(format!(
                    "--claude-config-dir `{}` is the live Claude Code configuration directory; \
                     an isolated session cannot be the very thing it isolates from",
                    dir.display()
                )));
            }
            dir.clone()
        }
        Some(dir) => {
            return Err(AppError::Config(format!(
                "--claude-config-dir must be an absolute path; `{}` is not",
                dir.display()
            )));
        }
        None => {
            let dir = paths.session_dir(account_uuid, organization_uuid);
            // Defense in depth, matching `forget_session`'s own check: this
            // cannot fail through the normal call path, since `session_dir`
            // always composes a path under `session_root()` from validated
            // segments (`new_record` runs `validate_segment` on both, the
            // same convention `namespace_dir` relies on).
            if !paths.is_under_session_root(&dir) {
                return Err(AppError::Config(format!(
                    "`{}` is not under `{}`; refusing to use it as a session directory",
                    dir.display(),
                    paths.session_root().display()
                )));
            }
            dir
        }
    };

    create_session_dir(&path)?;

    let live_dir = namespace::live_store_dir(env);
    let (linked, missing, already_linked) = link_tiers(&path, &live_dir, opts.fresh_context)?;

    let mcp_config = if opts.no_mcp { None } else { Some(link_mcp_config(&path, env)?) };

    seed_claude_json(&path, env, ctx)?;

    Ok(SessionDir { path, mcp_config, linked, missing, already_linked })
}

/// Whether `dir` has a `.` or `..` segment anywhere in it.
///
/// `--claude-config-dir` is refused outright when this is true (N-2): the
/// override must already be an absolute, normalized path, so a spelling like
/// `<live>/x/..` (with `x` not yet existing) never reaches a comparison that
/// assumes the spelling means what it says.
///
/// Splits the raw spelling on `/` rather than using [`Path::components`],
/// which silently normalizes a mid-path `.` away (it reports one only when
/// it leads a *relative* path) — exactly the segment this check exists to
/// catch. `..` is unaffected either way: [`Path::components`] always
/// preserves it. [`Path::to_string_lossy`] cannot hide a `.`/`..` segment
/// from this split: both are plain ASCII, so lossy replacement of an
/// invalid byte sequence elsewhere in the path never produces or removes
/// one.
fn has_dot_component(p: &Path) -> bool {
    p.to_string_lossy().split('/').any(|segment| segment == "." || segment == "..")
}

/// Whether `dir` is the live Claude Code configuration directory itself
/// (plan section 3.3; a `--claude-config-dir` override equal to it would
/// symlink and seed on top of the very store a session exists to isolate
/// from).
///
/// Compares canonicalized paths so a symlinked spelling of the same
/// directory is still caught; when either side cannot be canonicalized (the
/// override does not exist yet, most commonly — it is about to be created)
/// falls back to comparing the normalized spelling instead of skipping the
/// check. That fallback lexically normalizes both sides first (N-2): a
/// missing path component makes `canonical` fail, and
/// `namespace::export_spelling` only NFC-normalizes and trims a trailing
/// `/` — it does not fold `.`/`..` — so an unfolded `..` could otherwise
/// dodge the comparison even though it resolves onto the live directory.
fn is_live_store_dir(dir: &Path, env: &EnvView) -> bool {
    let live = namespace::live_store_dir(env);
    match (namespace::canonical(dir), namespace::canonical(&live)) {
        (Ok(a), Ok(b)) => a == b,
        _ => {
            let dir_norm = lexical_normalize(dir);
            let live_norm = lexical_normalize(&live);
            namespace::export_spelling(&dir_norm) == namespace::export_spelling(&live_norm)
        }
    }
}

/// Creates one session directory at [`DIR_MODE`], parents included,
/// tolerating one that already exists.
///
/// Mirrors [`crate::config::paths`]'s own `create_dir_mode` rather than
/// calling it: that helper is private to its module, and duplicating four
/// lines here is cheaper than widening its visibility for one caller.
///
/// Uses [`std::fs::symlink_metadata`] rather than [`Path::is_dir`], which
/// follows a symlink: a symlink at `path` — left by an earlier experiment or
/// any same-user actor — would otherwise silently redirect every placement
/// this call makes into whatever the link points at (invariant I19, plan
/// AC56). Anything at `path` that is not a plain directory is refused,
/// naming the path, and nothing is created inside the link's target.
fn create_session_dir(path: &Path) -> Result<(), AppError> {
    create_session_dir_seamed(path, || {})
}

/// [`create_session_dir`]'s real body, with `before_create` run as a seam
/// between the initial existence check and the leaf directory's creation —
/// production passes a no-op; a test can plant something at `path` in that
/// window and assert the create fails closed (N-1) instead of racing a real
/// writer thread.
///
/// The check→create window itself used to be closed by a single
/// `DirBuilder::recursive(true)` call over the whole path: std's
/// `create_dir_all` maps `mkdir`'s `EEXIST` to `Ok(())` whenever
/// `path.is_dir()` — which *follows* a symlink — so anything planted at
/// `path` in that window that resolves to a directory was silently accepted.
/// The parent chain is still created recursively (nothing security-sensitive
/// hinges on an intermediate directory here), but the leaf is created with
/// `recursive(false)`: that is a bare `mkdir`, which fails `EEXIST` for any
/// existing directory entry — symlink included, since `mkdir` never follows
/// the final component. An `EEXIST` is then re-`symlink_metadata`'d: a plain
/// directory means a benign racing `use` won the leaf first and is left
/// alone; anything else — the symlink this seam exists to test, or an
/// attacker's regular file — is invariant I19's refusal, naming the path.
fn create_session_dir_seamed(path: &Path, before_create: impl FnOnce()) -> Result<(), AppError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => return Ok(()),
        Ok(_) => {
            return Err(AppError::Config(format!(
                "`{}` already exists and is not the plain directory agctl would create \
                 there; move or remove it before starting this session",
                path.display()
            )));
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(AppError::Io {
                context: format!("could not inspect `{}`", path.display()),
                source: err,
            });
        }
    }

    if let Some(parent) = path.parent() {
        let mut parents = std::fs::DirBuilder::new();
        parents.recursive(true).mode(DIR_MODE);
        parents.create(parent).map_err(|err| AppError::Io {
            context: format!("could not create `{}`", parent.display()),
            source: err,
        })?;
    }

    before_create();

    let mut leaf = std::fs::DirBuilder::new();
    leaf.recursive(false).mode(DIR_MODE);
    match leaf.create(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            match std::fs::symlink_metadata(path) {
                Ok(meta) if meta.is_dir() => Ok(()),
                Ok(_) => Err(AppError::Config(format!(
                    "`{}` already exists and is not the plain directory agctl would create \
                 there; move or remove it before starting this session",
                    path.display()
                ))),
                Err(err) => Err(AppError::Io {
                    context: format!("could not inspect `{}`", path.display()),
                    source: err,
                }),
            }
        }
        Err(err) => Err(AppError::Io {
            context: format!("could not create the session directory `{}`", path.display()),
            source: err,
        }),
    }
}

/// `(linked, missing, already_linked)`, [`link_tiers`]'s report — factored
/// out so its signature stays under clippy's type-complexity threshold.
type TierLinkReport = (Vec<String>, Vec<String>, Vec<PathBuf>);

/// Symlinks every present tier 1/tier 2 entry from `live_dir` into
/// `session_dir` (plan AC53).
///
/// `fresh_context` omits tier 2 entirely: those names are neither linked nor
/// reported as missing, since their absence here was requested rather than
/// discovered. An entry `live_dir` does not have is reported in `missing`
/// and nothing is created for it; so is a tier 2 name that resolves to a
/// file rather than a directory (AC53: tier 2 is directories only). An entry
/// whose session-dir symlink already points at the live target is left
/// alone and reported in `already_linked`. Anything else already at that
/// path is invariant I19's refusal, naming the path — the check runs before
/// any placement for that entry, so a refusal midway through the list
/// leaves every entry already handled exactly as it was and touches nothing
/// after it.
fn link_tiers(
    session_dir: &Path,
    live_dir: &Path,
    fresh_context: bool,
) -> Result<TierLinkReport, AppError> {
    let tier2: &[&str] = if fresh_context { &[] } else { TIER2_DIRS };

    let mut linked = Vec::new();
    let mut missing = Vec::new();
    let mut already_linked = Vec::new();

    for name in TIER1.iter().copied().chain(tier2.iter().copied()) {
        let live_path = live_dir.join(name);
        let link = session_dir.join(name);

        let target = match namespace::canonical(&live_path) {
            Ok(target) => target,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                missing.push(name.to_owned());
                continue;
            }
            Err(err) => {
                return Err(AppError::Io {
                    context: format!("could not resolve `{}`", live_path.display()),
                    source: err,
                });
            }
        };

        if TIER2_DIRS.contains(&name) {
            let is_dir = std::fs::metadata(&target).map(|meta| meta.is_dir()).unwrap_or(false);
            if !is_dir {
                missing.push(name.to_owned());
                continue;
            }
        }

        match std::fs::symlink_metadata(&link) {
            Ok(meta) if meta.file_type().is_symlink() => {
                let existing = std::fs::read_link(&link).map_err(|err| AppError::Io {
                    context: format!("could not read the existing symlink `{}`", link.display()),
                    source: err,
                })?;
                if existing == target {
                    already_linked.push(link);
                    continue;
                }
                return Err(AppError::Config(format!(
                    "`{}` already exists and points at `{}`, not `{}`; agctl will not \
                     replace a symlink it did not place there",
                    link.display(),
                    existing.display(),
                    target.display()
                )));
            }
            Ok(_) => {
                return Err(AppError::Config(format!(
                    "`{}` already exists and is not the symlink agctl would place there; \
                     move or remove it before starting this session",
                    link.display()
                )));
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                std::os::unix::fs::symlink(&target, &link).map_err(|err| AppError::Io {
                    context: format!("could not create the symlink `{}`", link.display()),
                    source: err,
                })?;
                linked.push(name.to_owned());
            }
            Err(err) => {
                return Err(AppError::Io {
                    context: format!("could not inspect `{}`", link.display()),
                    source: err,
                });
            }
        }
    }

    Ok((linked, missing, already_linked))
}

/// Places (or verifies) the D-019 `mcp.json` symlink inside `session_dir`.
///
/// The target is `canonical(claude_json_path(env))` — the live
/// `.claude.json` agctl's own environment names, not the session's own.
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
                "`{}` already exists and points at `{}`, not `{}`; agctl will not replace a \
                 symlink it did not place there",
                link.display(),
                existing.display(),
                target.display()
            )))
        }
        Ok(_) => Err(AppError::Config(format!(
            "`{}` already exists and is not the symlink agctl would place there; move or \
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

/// Seeds `<session_dir>/.claude.json` from the live file, once (plan AC54).
///
/// Skips entirely when the seed already exists as a plain file: this never
/// rewrites it after the first run (invariant I18). Uses
/// [`std::fs::symlink_metadata`] rather than [`Path::exists`], which follows
/// a symlink — a symlink at the seed path, dangling or not, would otherwise
/// point Claude Code's first config write at whatever it targets instead of
/// being refused (invariant I19, plan AC56); anything at that path other
/// than a plain file is refused, naming the path. Copies [`SEED_KEYS`]
/// verbatim from the live file, present-only, then fills any [`seed_floor`]
/// entry the live file lacked. Serialised as 2-space pretty JSON in
/// [`SEED_KEYS`]'s own order — deterministic and stable across releases,
/// which matters more here than matching the live file's own key order — at
/// mode [`FILE_MODE`].
fn seed_claude_json(session_dir: &Path, env: &EnvView, ctx: &PassCtx) -> Result<(), AppError> {
    let seed_path = session_dir.join(SEED_FILE);
    match std::fs::symlink_metadata(&seed_path) {
        Ok(meta) if meta.is_file() => return Ok(()),
        Ok(_) => {
            return Err(AppError::Config(format!(
                "`{}` already exists and is not the plain file agctl would seed there; move \
                 or remove it before starting this session",
                seed_path.display()
            )));
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(AppError::Io {
                context: format!("could not inspect `{}`", seed_path.display()),
                source: err,
            });
        }
    }

    let live_path = namespace::claude_json_path(env);
    let live_bytes = read_twice_and_compare(&live_path, ctx, read_live_claude_json)?;

    let live_obj = match live_bytes {
        Some(bytes) => {
            let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|err| {
                AppError::Config(format!(
                    "`{}` is not valid JSON, so it cannot be seeded from: {err}",
                    live_path.display()
                ))
            })?;
            match value {
                serde_json::Value::Object(map) => map,
                _ => {
                    return Err(AppError::Config(format!(
                        "`{}` is not a JSON object at its top level, so it cannot be seeded from",
                        live_path.display()
                    )));
                }
            }
        }
        None => serde_json::Map::new(),
    };

    let mut seed = serde_json::Map::new();
    for key in SEED_KEYS {
        if let Some(value) = live_obj.get(*key) {
            seed.insert((*key).to_owned(), value.clone());
        }
    }
    for (key, value) in seed_floor() {
        seed.entry(key.to_owned()).or_insert(value);
    }

    if let Some(leaked) = NEVER_SEED.iter().find(|key| seed.contains_key(**key)) {
        return Err(AppError::Config(format!(
            "refusing to write `{}`: `{leaked}` would be seeded, and it is on the never-seed \
             list (unreachable in principle, since `SEED_KEYS` and `NEVER_SEED` are disjoint)",
            seed_path.display()
        )));
    }

    let text = serde_json::to_string_pretty(&serde_json::Value::Object(seed)).map_err(|err| {
        AppError::Config(format!("could not render the session seed as JSON: {err}"))
    })?;

    write_seed_file(&seed_path, &text)
}

/// Writes `text` to `path` at [`FILE_MODE`], tolerating a concurrent seed
/// that won the race to create it first.
///
/// `create_new`'s `AlreadyExists` also fires for a *dangling* symlink at
/// `path` (the create fails because the target does not exist, not because a
/// regular file is there) — the quietest form of the P1-1/I19 hazard, since
/// nothing about the error alone distinguishes it from the benign race this
/// tolerance exists for. So the arm looks again with
/// [`std::fs::symlink_metadata`]: only a regular file — the winning racer's
/// own seed — is treated as already seeded; a symlink or anything else is
/// invariant I19's refusal, naming the path.
fn write_seed_file(path: &Path, text: &str) -> Result<(), AppError> {
    let mut file =
        match std::fs::OpenOptions::new().write(true).create_new(true).mode(FILE_MODE).open(path) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                return match std::fs::symlink_metadata(path) {
                    Ok(meta) if meta.is_file() => Ok(()),
                    Ok(_) => Err(AppError::Config(format!(
                        "`{}` already exists and is not the plain file agctl would seed \
                         there; move or remove it before starting this session",
                        path.display()
                    ))),
                    Err(err) => Err(AppError::Io {
                        context: format!("could not inspect `{}`", path.display()),
                        source: err,
                    }),
                };
            }
            Err(err) => {
                return Err(AppError::Io {
                    context: format!("could not create `{}`", path.display()),
                    source: err,
                });
            }
        };
    file.write_all(text.as_bytes()).map_err(|err| AppError::Io {
        context: format!("could not write `{}`", path.display()),
        source: err,
    })
}

/// Reads `path` through `read` twice and compares the results, retrying up
/// to [`LIVE_READ_ATTEMPTS`] times when a live writer tears the read (M6),
/// and giving up early when `ctx` should stop — cancelled, or past its
/// deadline — between retries.
///
/// `read` is a seam rather than a direct filesystem call so the retry loop
/// is testable without racing a real writer thread: a test's `read` can
/// return different bytes on successive calls to simulate a tear
/// deterministically.
///
/// # Errors
///
/// Propagates whatever `read` returns; returns [`AppError::Refused`] when
/// `ctx` signals it should stop before a retry, and [`AppError::Config`]
/// naming `path` when every attempt disagreed with itself.
fn read_twice_and_compare<R>(
    path: &Path,
    ctx: &PassCtx,
    mut read: R,
) -> Result<Option<Vec<u8>>, AppError>
where
    R: FnMut(&Path) -> Result<Option<Vec<u8>>, AppError>,
{
    for attempt in 0..LIVE_READ_ATTEMPTS {
        if attempt > 0 && ctx.should_stop() {
            return Err(AppError::Refused {
                reason: "cancelled while re-reading the live `.claude.json` to seed a session"
                    .to_owned(),
            });
        }
        let first = read(path)?;
        let second = read(path)?;
        if first == second {
            return Ok(first);
        }
    }
    Err(AppError::Config(format!(
        "`{}` changed between two reads, {LIVE_READ_ATTEMPTS} times in a row; a live Claude \
         Code session may be rewriting it continuously (fact F50); refusing to seed a possibly \
         torn copy — try again",
        path.display()
    )))
}

/// The default `read` for [`read_twice_and_compare`]: the live
/// `.claude.json` through [`file_store::read_file_following`] — which
/// follows a symlink, since the live file itself may be one — capped at
/// [`discovery::MAX_CLAUDE_JSON_BYTES`], the bound the discovery pass
/// already applies to the same file for the same reason: it grows without
/// bound under a running session.
fn read_live_claude_json(path: &Path) -> Result<Option<Vec<u8>>, AppError> {
    match file_store::read_file_following(path, discovery::MAX_CLAUDE_JSON_BYTES) {
        Ok(ReadOutcome::Present { bytes, .. }) => Ok(Some(bytes)),
        Ok(ReadOutcome::Absent) => Ok(None),
        Err(err) => Err(AppError::Io {
            context: format!("could not read `{}`", path.display()),
            source: std::io::Error::other(err.to_string()),
        }),
    }
}

/// `use --forget <id>`: removes an isolated session directory (plan AC79).
///
/// Only [`Paths::session_dir`] and paths beneath it are touched — the
/// account's namespace and its lock are left exactly as they were, which is
/// the whole reason the session directory lives outside `namespace_root()`
/// in the first place (plan section 3.3). The directory holds only symlinks
/// (tier 1/tier 2, the D-019 MCP link) and one regular file (the seeded
/// `.claude.json`), so a plain recursive removal is correct:
/// [`std::fs::remove_dir_all`] identifies each entry's own type before
/// acting on it and never descends through a symlink to remove what it
/// points at, only the link itself.
///
/// # Errors
///
/// Returns [`AppError::Config`] for a non-`Owned` account or a resolved path
/// outside [`Paths::session_root`]; [`AppError::Refused`] when the
/// confirmation is declined or there is no terminal to ask at (unless
/// `yes`); and [`AppError::Io`] when the removal itself fails.
pub fn forget_session(
    paths: &Paths,
    rec: &AccountRecord,
    prompt: &mut dyn Prompt,
    yes: bool,
) -> Result<(), AppError> {
    let (account_uuid, organization_uuid) = match &rec.kind {
        AccountKind::Owned { .. } => (rec.account_uuid.as_str(), rec.organization_uuid.as_str()),
        other => {
            return Err(AppError::Config(format!(
                "only an account agctl owns can have an isolated session; `{}` is `{}`, which \
                 has none",
                rec.account_uuid,
                other.name()
            )));
        }
    };

    let session_dir = paths.session_dir(account_uuid, organization_uuid);
    // Defense in depth: `Paths::session_dir` always composes a path under
    // `session_root()` from validated segments, so this cannot fail through
    // the normal call path. It stays as the same "check before act" guard
    // `Paths::is_under_namespace_root` gives the credential writer.
    if !paths.is_under_session_root(&session_dir) {
        return Err(AppError::Config(format!(
            "`{}` is not under `{}`; refusing to remove it",
            session_dir.display(),
            paths.session_root().display()
        )));
    }

    if !session_dir.exists() {
        prompt.tell(&format!(
            "`{}` has no isolated session directory; nothing to forget.",
            rec.account_uuid
        ));
        return Ok(());
    }

    if !yes {
        prompt.tell(&format!(
            "This removes the isolated session directory `{}` for `{}`, including its \
             `.claude.json` seed and every symlink into your live Claude Code configuration. \
             The account's own stored credentials and namespace are not touched.",
            session_dir.display(),
            rec.account_uuid
        ));
        if !prompt.confirm("Remove this session directory?")? {
            return Err(AppError::Refused { reason: "cancelled; nothing was removed".to_owned() });
        }
    }

    std::fs::remove_dir_all(&session_dir).map_err(|err| AppError::Io {
        context: format!("could not remove `{}`", session_dir.display()),
        source: err,
    })
}

#[cfg(test)]
#[path = "isolate_tests.rs"]
mod tests;
