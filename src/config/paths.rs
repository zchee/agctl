//! Where agentctl keeps its own state, and nothing else.
//!
//! Every path this crate is allowed to write to is derived here, from one
//! root: the configuration directory. Invariant I1 is stated as "nothing
//! outside `config_dir()`/`cache_dir()`", and [`Paths::is_under_namespace_root`]
//! is the check that makes it enforceable at the one place it matters — the
//! credential writer — rather than hoped for.
//!
//! The layout is:
//!
//! ```text
//! <config_dir>/                         0700
//!   config.json                         0600
//!   .config.lock                        0600, never unlinked
//!   claude/                             0700   namespace_root()
//!     .locks/                           0700   locks_dir()
//!       <acct>.<org>.lock               0600, never unlinked
//!     <acct>/<org>/                     0700   namespace_dir()
//!       .credentials.json               0600
//!   cache/claude/                       0700   cache_dir()
//! ```
//!
//! The lock files live *outside* the namespace directory on purpose (plan
//! section 3.5): `flock` is an inode lock, so a lock file inside a directory
//! that another tool may delete and recreate is a lock two processes can hold
//! at once. Out of the namespace, never unlinked, the inode is stable.

use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

use etcetera::BaseStrategy;

use crate::error::AppError;

/// The organization placeholder used when a login could not name one
/// (decision D-008). `accounts relocate` moves such a namespace afterwards.
pub const UNKNOWN_ORG: &str = "_unknown-org";

/// Where isolated `claude use`/`exec`/`env` sessions live (plan section 3.3,
/// decision D-011).
pub const SESSION_ROOT: &str = "claude-sessions";

/// The directory mode for everything agentctl creates.
pub const DIR_MODE: u32 = 0o700;

/// The file mode for everything agentctl creates.
pub const FILE_MODE: u32 = 0o600;

/// The environment form of `--config-dir`.
pub const CONFIG_DIR_ENV: &str = "AGENTCTL_CONFIG_DIR";

/// The resolved location of this agentctl store.
///
/// Two stores with different [`Paths::config_dir`] values are independent and
/// have independent locks (invariant I14): logging the same account into both
/// makes two holders of one refresh chain, which is documented rather than
/// prevented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    config_dir: PathBuf,
}

impl Paths {
    /// Resolves the configuration directory.
    ///
    /// Precedence: `--config-dir`, then `AGENTCTL_CONFIG_DIR`, then the XDG
    /// configuration directory with `agentctl` appended. `etcetera`'s
    /// `choose_base_strategy` is XDG on every platform this targets —
    /// including macOS, where the "native" strategy would be
    /// `~/Library/Application Support` — which is what decision D-004 asks
    /// for.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Config`] when no home directory can be determined
    /// and no override was given.
    pub fn resolve(cli_override: Option<&Path>) -> Result<Self, AppError> {
        let env_override = std::env::var_os(CONFIG_DIR_ENV).map(PathBuf::from);
        let xdg = || {
            etcetera::choose_base_strategy().map(|strategy| strategy.config_dir()).map_err(|err| {
                AppError::Config(format!(
                    "could not determine the XDG configuration directory ({err}); pass --config-dir or set {CONFIG_DIR_ENV}"
                ))
            })
        };
        Self::resolve_from(cli_override, env_override.as_deref(), xdg)
    }

    /// The precedence rule on its own, with the two ambient inputs supplied.
    ///
    /// Split out so the precedence is testable without mutating the process
    /// environment, which is `unsafe` in edition 2024 and would race every
    /// other test in the binary.
    ///
    /// # Errors
    ///
    /// Propagates whatever `xdg` returns, but only when neither override is
    /// present — an override means the base directory is never consulted.
    pub fn resolve_from<F>(
        cli_override: Option<&Path>,
        env_override: Option<&Path>,
        xdg: F,
    ) -> Result<Self, AppError>
    where
        F: FnOnce() -> Result<PathBuf, AppError>,
    {
        let config_dir = match (cli_override, env_override) {
            (Some(dir), _) => dir.to_path_buf(),
            (None, Some(dir)) => dir.to_path_buf(),
            (None, None) => xdg()?.join("agentctl"),
        };
        Ok(Self { config_dir })
    }

    /// Builds a value around an already-chosen directory.
    ///
    /// Every command reaches its store through [`Paths::resolve`], so the only
    /// callers left are the tests, which hand out a `tempfile::TempDir` rather
    /// than going near the real `$HOME`. Kept because that is exactly what a
    /// store-relative test needs, and because a constructor taking the
    /// directory is the honest counterpart to one that resolves it.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the test harnesses build stores in temporary directories")
    )]
    pub fn with_config_dir(config_dir: PathBuf) -> Self {
        Self { config_dir }
    }

    /// The root of this store.
    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    /// The account registry.
    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.json")
    }

    /// The lock guarding read-modify-write of the account registry. Created
    /// once and never unlinked.
    pub fn config_lock(&self) -> PathBuf {
        self.config_dir.join(".config.lock")
    }

    /// The root under which every Claude namespace lives.
    pub fn namespace_root(&self) -> PathBuf {
        self.config_dir.join("claude")
    }

    /// The namespace directory for one `(account, organization)` pair.
    pub fn namespace_dir(&self, acct: &str, org: &str) -> PathBuf {
        self.namespace_root().join(acct).join(org)
    }

    /// Where the namespace locks live — beside the namespaces, never inside
    /// one.
    pub fn locks_dir(&self) -> PathBuf {
        self.namespace_root().join(".locks")
    }

    /// The lock file for one namespace. Created once and never unlinked.
    pub fn lock_path(&self, acct: &str, org: &str) -> PathBuf {
        self.locks_dir().join(format!("{acct}.{org}.lock"))
    }

    /// Where usage responses are cached between passes.
    pub fn cache_dir(&self) -> PathBuf {
        self.config_dir.join("cache").join("claude")
    }

    /// Creates the store's directories, each level at mode 0700.
    ///
    /// `std::fs::create_dir_all` applies the process umask, which commonly
    /// leaves a directory group- and world-readable, so each level is created
    /// individually with an explicit mode. Levels that already exist are left
    /// as they are — including their modes, which `doctor` reports on rather
    /// than silently tightening.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Io`] naming the directory that could not be made.
    pub fn ensure_dirs(&self) -> Result<(), AppError> {
        for dir in [self.config_dir.clone(), self.namespace_root(), self.locks_dir()] {
            create_dir_mode(&dir)?;
        }
        create_dir_mode(&self.config_dir.join("cache"))?;
        create_dir_mode(&self.cache_dir())
    }

    /// Whether `p` *spells* a path strictly below [`Paths::namespace_root`].
    ///
    /// The comparison is lexical: `.` and `..` are folded out of both paths
    /// and no symlink is resolved. That is deliberate, and it is also the
    /// limit of what this answers.
    ///
    /// **What it guarantees:** the string the writer will hand to `rename`
    /// begins with the namespace root and is not the root itself, so no
    /// caller can be talked into writing over `claude/` with a namespace path
    /// of `.`, or out of the store with one full of `..`. That property is
    /// stable — it is about the path, and a path does not change under you.
    ///
    /// **What it does not guarantee:** where that path *leads*. A symlinked
    /// `<acct>` or `<org>` component spells something under the root and
    /// resolves to somewhere else entirely — a running Claude Code's store,
    /// say. Resolving links here would not fix that either, because the
    /// answer can change between the check and the write. The escape is
    /// closed instead by
    /// [`file_store::open_namespace_dir`](crate::secret::file_store::open_namespace_dir),
    /// which walks the chain with `O_DIRECTORY | O_NOFOLLOW` and performs
    /// every leaf operation relative to the descriptor it returns, so there
    /// is no path left to re-resolve; and, for the lock files, by
    /// [`crate::secret::namespace_lock`], which does the same for `.locks`.
    /// This check and that walk are both required; neither replaces the
    /// other.
    pub fn is_under_namespace_root(&self, p: &Path) -> bool {
        let root = lexical_normalize(&self.namespace_root());
        let target = lexical_normalize(p);
        target != root && target.starts_with(&root)
    }

    /// The root of every isolated session directory.
    ///
    /// Deliberately outside [`Paths::namespace_root`] (plan section 3.3):
    /// [`crate::secret::file_store::remove_namespace`] unlinks a fixed name
    /// list under a namespace directory and then climbs it with
    /// `AT_REMOVEDIR`, so a session's copied `mcpServers` symlink and seeded
    /// `.claude.json` sitting inside a namespace would make that climb fail
    /// silently. `use --forget <id>` is this tree's own teardown instead.
    pub fn session_root(&self) -> PathBuf {
        self.config_dir.join(SESSION_ROOT)
    }

    /// The isolated session directory for one `(account, organization)` pair.
    ///
    /// Callers pass identifiers that have already gone through
    /// [`validate_segment`] — every [`crate::config::AccountRecord`] does, at
    /// [`crate::config::new_record`] time — exactly as
    /// [`Paths::namespace_dir`] assumes of its own arguments.
    pub fn session_dir(&self, acct: &str, org: &str) -> PathBuf {
        self.session_root().join(acct).join(org)
    }

    /// Whether `p` *spells* a path strictly below [`Paths::session_root`].
    ///
    /// Lexical, exactly as [`Paths::is_under_namespace_root`] is: it answers
    /// what the path says, not what it resolves to. `use --forget <id>` uses
    /// this to refuse a path outside `claude-sessions/` (plan AC79).
    pub fn is_under_session_root(&self, p: &Path) -> bool {
        let root = lexical_normalize(&self.session_root());
        let target = lexical_normalize(p);
        target != root && target.starts_with(&root)
    }
}

/// Creates one directory at [`DIR_MODE`], tolerating one that already exists.
fn create_dir_mode(dir: &Path) -> Result<(), AppError> {
    use std::os::unix::fs::DirBuilderExt;

    if dir.is_dir() {
        return Ok(());
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(DIR_MODE);
    builder.create(dir).map_err(|err| AppError::Io {
        context: format!("could not create the directory `{}`", dir.display()),
        source: err,
    })
}

/// Folds `.` and `..` out of a path without touching the filesystem.
///
/// A `..` that would climb above the path's root is kept as a component, so a
/// path that escapes cannot compare equal to — or start with — anything the
/// caller considers a root.
fn lexical_normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in p.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                // `pop` returns false at the top of a relative path, where the
                // `..` has to be kept: `../x` is not `x`.
                if !out.pop() {
                    out.push(Component::ParentDir);
                }
            }
            other => out.push(other),
        }
    }
    out
}

/// Checks that `s` is usable as a single path segment.
///
/// Account and organization identifiers arrive from an OAuth response and end
/// up as directory names, so they are validated rather than trusted: no
/// separators, no `.`/`..`, no empty string, and a conservative ASCII
/// alphabet. UUIDs and [`UNKNOWN_ORG`] pass; a value carrying `../` does not.
///
/// # Errors
///
/// Returns [`AppError::Config`] describing which rule the value broke.
pub fn validate_segment(s: &str) -> Result<(), AppError> {
    if s.is_empty() {
        return Err(AppError::Config("an account or organization id cannot be empty".to_owned()));
    }
    if s == "." || s == ".." {
        return Err(AppError::Config(format!("`{s}` cannot be used as a directory name")));
    }
    if let Some(bad) =
        s.chars().find(|c| !matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '_' | '-'))
    {
        return Err(AppError::Config(format!(
            "the id `{s}` contains `{bad}`, which is not allowed in a namespace directory name"
        )));
    }
    Ok(())
}

#[cfg(test)]
#[path = "paths_tests.rs"]
mod tests;
