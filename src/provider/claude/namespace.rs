//! Claude Code's keychain naming rule, reimplemented exactly.
//!
//! Everything in this module exists to answer one question: *which keychain
//! item holds the credentials for a given configuration directory?* Claude
//! Code answers it by hashing an environment variable, and agctl has to
//! answer it the same way — not approximately — because the consequences of
//! disagreeing are asymmetric. Guess a name that is not in use and agctl
//! shows an account as absent. Guess the name of a *live* item and agctl
//! could show one account's usage under another account's row, or decide a
//! namespace is free when a running session owns it.
//!
//! The rule (fact F14, read out of the Claude Code 2.1.263 binary):
//!
//! ```text
//! service = "Claude Code-credentials" + suffix
//! suffix  = ""                        when the gate is falsy
//!         = "-" + sha256(NFC(raw))[0..8]  otherwise
//!
//! gate, raw =
//!   CLAUDE_SECURESTORAGE_CONFIG_DIR present -> (that value,      that value)
//!   otherwise                               -> (CLAUDE_CONFIG_DIR, CLAUDE_CONFIG_DIR ?? ~/.claude)
//! ```
//!
//! Three details that are easy to get wrong, and each of which would produce
//! a plausible-looking wrong answer:
//!
//! - **The gate is truthiness, not presence.** `CLAUDE_SECURESTORAGE_CONFIG_DIR=""`
//!   yields the *unsuffixed* live name even when `CLAUDE_CONFIG_DIR` is set,
//!   because an empty string is falsy in JavaScript. Presence only decides
//!   which variable gets hashed.
//! - **The hash is of the raw environment string**, NFC-normalized and
//!   nothing else. Not `realpath`, not `path.resolve`, not a trailing-slash
//!   fix. Two spellings of one directory are two different items, which is
//!   exactly the situation on the machine this was developed against: the
//!   live item and `…-5cdc535f` name the same physical directory through
//!   different spellings and hold *different* credentials (facts F6, F41).
//! - **NFC is applied on both branches.** A decomposed path from the shell
//!   and a composed one from a config file must hash alike.
//!
//! [`canonical`] exists for one narrow purpose — deciding whether two entries
//! point at the same physical directory — and is never used for identity.
//! Invariant I13: identity comes from the credentials, never from a path.

#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "remaining items are consumed by W2 (accounts, import, doctor) and W3 (watch)"
    )
)]

use std::io;
use std::path::Path;
use std::path::PathBuf;

use sha2::Digest;
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;

/// The unsuffixed service name: the credentials Claude Code is using now.
pub const LIVE_SERVICE: &str = "Claude Code-credentials";

/// The environment variable Claude Code hashes when it is present.
pub const SECURESTORAGE_ENV: &str = "CLAUDE_SECURESTORAGE_CONFIG_DIR";

/// The environment variable Claude Code hashes otherwise.
pub const CONFIG_DIR_ENV: &str = "CLAUDE_CONFIG_DIR";

/// A token in this variable short-circuits credential lookup entirely
/// (fact F19).
pub const OAUTH_TOKEN_ENV: &str = "CLAUDE_CODE_OAUTH_TOKEN";

/// What a keychain service name turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceKind {
    /// `Claude Code-credentials` — whatever Claude Code is using right now.
    Live,
    /// `Claude Code-credentials-<8 hex>` — a specific configuration
    /// directory, identified only by the hash of how it was spelled.
    ConfigDir(String),
}

/// The environment values the naming rule depends on.
///
/// Captured into a value rather than read at each use so the rule is testable
/// without mutating the process environment — which is `unsafe` in edition
/// 2024 and would race every other test in the binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvView {
    /// `CLAUDE_SECURESTORAGE_CONFIG_DIR`, distinguishing unset from empty.
    pub securestorage_dir: Option<String>,
    /// `CLAUDE_CONFIG_DIR`, distinguishing unset from empty.
    pub config_dir: Option<String>,
    /// The user's home directory.
    pub home: PathBuf,
    /// Whether `CLAUDE_CODE_OAUTH_TOKEN` holds a non-empty value.
    pub oauth_token_set: bool,
}

impl EnvView {
    /// Reads the current process environment.
    ///
    /// Values are taken through `var_os` and converted lossily, so a path
    /// that is not valid UTF-8 is still *present* — treating it as unset
    /// would silently change which keychain item agctl looks for.
    pub fn from_process() -> Self {
        let read =
            |name: &str| std::env::var_os(name).map(|value| value.to_string_lossy().into_owned());
        Self {
            securestorage_dir: read(SECURESTORAGE_ENV),
            config_dir: read(CONFIG_DIR_ENV),
            home: std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default(),
            oauth_token_set: read(OAUTH_TOKEN_ENV).is_some_and(|value| !value.is_empty()),
        }
    }

    /// An environment with nothing set but a home directory, for tests and
    /// for the `--config-dir`-only paths.
    pub fn with_home(home: PathBuf) -> Self {
        Self { securestorage_dir: None, config_dir: None, home, oauth_token_set: false }
    }
}

/// The first eight hex digits of the SHA-256 of `raw`, NFC-normalized.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(sha8("/Users/zchee/.claude"), "95313c21");
/// ```
pub fn sha8(raw: &str) -> String {
    let normalized: String = raw.nfc().collect();
    let digest = Sha256::digest(normalized.as_bytes());
    let hex = hex::encode(digest);
    hex.get(..8).unwrap_or(hex.as_str()).to_owned()
}

/// The keychain service name Claude Code would use in this environment
/// (fact F14).
pub fn service_name(env: &EnvView) -> String {
    let (unsuffixed, raw) = match env.securestorage_dir.as_deref() {
        // Present: this variable is both the gate and the hash input.
        Some(value) => (value.is_empty(), value.to_owned()),
        // Absent: `CLAUDE_CONFIG_DIR` is the gate, and `be()` — the same
        // variable, defaulting to `~/.claude` — is the hash input.
        None => (env.config_dir.as_deref().is_none_or(str::is_empty), config_dir_or_default(env)),
    };

    if unsuffixed { LIVE_SERVICE.to_owned() } else { format!("{LIVE_SERVICE}-{}", sha8(&raw)) }
}

/// Classifies a keychain service name.
///
/// Returns `None` for anything that is not a Claude Code *credentials* item,
/// which deliberately includes the legacy `Claude Code-<sha8>` API-key items
/// (fact F5) and `claude-switcher:*` items belonging to a third-party tool
/// (fact F10). Both exist on real machines; neither is a credential agctl
/// can read or reason about.
pub fn classify(service: &str) -> Option<ServiceKind> {
    if service == LIVE_SERVICE {
        return Some(ServiceKind::Live);
    }
    let suffix = service.strip_prefix(LIVE_SERVICE)?.strip_prefix('-')?;
    if suffix.len() == 8 && suffix.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        Some(ServiceKind::ConfigDir(suffix.to_owned()))
    } else {
        None
    }
}

/// Resolves `dir` through symlinks and normalizes the result.
///
/// Used for exactly one question — do two entries name the same physical
/// directory? — and never for identity (invariant I13). On the development
/// machine `~/.claude` is a symlink to a directory whose own spelling hashes
/// to `5cdc535f`, so without this the same directory looks like two
/// unrelated accounts (fact F41).
///
/// # Errors
///
/// Propagates the [`io::Error`] from `canonicalize`, which fails when the
/// directory does not exist.
pub fn canonical(dir: &Path) -> io::Result<PathBuf> {
    let resolved = std::fs::canonicalize(dir)?;
    Ok(PathBuf::from(normalize(&resolved.to_string_lossy())))
}

/// How a directory is spelled for naming purposes: NFC, no trailing slash.
///
/// This is what gets recorded in an [`crate::config::AccountKind::Owned`]
/// record and hashed into `export_sha8`, because it is the spelling a Claude
/// Code session would be handed — not where it resolves to.
pub fn export_spelling(dir: &Path) -> String {
    let text = normalize(&dir.to_string_lossy());
    let trimmed = text.trim_end_matches('/');
    if trimmed.is_empty() { text } else { trimmed.to_owned() }
}

/// The namespace `CLAUDE_SECURESTORAGE_CONFIG_DIR` points this shell at, if
/// any.
///
/// Fact F14's gate, in one place: the variable is *truthy*, not merely present,
/// so an empty value is `None` — it names the live item exactly as an unset
/// variable would. Every caller that has to answer "is this shell pointed at a
/// namespace?" asks this rather than spelling `is_empty()` again, because the
/// two halves of a swap disagreeing about that question is how a namespace ends
/// up locked while the live item is written (risk R42).
///
/// Returning the value rather than a `bool`: both refusals name it, and a
/// refusal that says only "the variable is set" leaves the user hunting for
/// which shell set it.
pub(crate) fn securestorage_namespace(env: &EnvView) -> Option<&str> {
    env.securestorage_dir.as_deref().filter(|value| !value.is_empty())
}

/// The directory whose store Claude Code reads right now (fact F30, `A_()`).
///
/// `CLAUDE_SECURESTORAGE_CONFIG_DIR` wins when it holds a non-empty value —
/// truthiness again, so an empty value falls back to `~/.claude` rather than
/// to `CLAUDE_CONFIG_DIR`. This is the directory that holds `.credentials.json`,
/// `.oauth_refresh.lock` and `.storage-write`.
///
/// One deliberate divergence: Claude Code's `be()` uses `??`, so
/// `CLAUDE_CONFIG_DIR=""` yields the empty string and a *relative*
/// `.credentials.json` in the process's working directory. agctl treats
/// that as `~/.claude` instead. Reading a file called `.credentials.json`
/// out of whatever directory the user happened to `cd` into, and then
/// presenting it as their live credentials, is not a behaviour worth
/// reproducing faithfully. The divergence cannot affect a service name: an
/// empty `CLAUDE_CONFIG_DIR` is falsy, so the name is unsuffixed and the hash
/// input is never consulted.
pub fn live_store_dir(env: &EnvView) -> PathBuf {
    match env.securestorage_dir.as_deref() {
        Some(value) if !value.is_empty() => PathBuf::from(normalize(value)),
        Some(_) => env.home.join(".claude"),
        None => {
            let dir = config_dir_or_default(env);
            if dir.is_empty() { env.home.join(".claude") } else { PathBuf::from(dir) }
        }
    }
}

/// Where the `.claude.json` holding `oauthAccount` lives (fact F30).
///
/// Keyed on `CLAUDE_CONFIG_DIR` or `$HOME` — **not** on
/// [`live_store_dir`]. The two diverge whenever
/// `CLAUDE_SECURESTORAGE_CONFIG_DIR` is set, which is what makes phase 2's
/// `--new-only` isolation incomplete (risk R10).
///
/// Consulted only for the live row (invariant I13).
pub fn claude_json_path(env: &EnvView) -> PathBuf {
    match env.config_dir.as_deref() {
        Some(value) if !value.is_empty() => PathBuf::from(normalize(value)).join(".claude.json"),
        _ => env.home.join(".claude.json"),
    }
}

/// Claude Code's `be()`: `CLAUDE_CONFIG_DIR` if present, else `~/.claude`,
/// NFC-normalized either way.
fn config_dir_or_default(env: &EnvView) -> String {
    match env.config_dir.as_deref() {
        Some(value) => normalize(value),
        None => normalize(&env.home.join(".claude").to_string_lossy()),
    }
}

/// NFC normalization, the one transformation Claude Code applies.
fn normalize(text: &str) -> String {
    text.nfc().collect()
}

#[cfg(test)]
#[path = "namespace_tests.rs"]
mod tests;
