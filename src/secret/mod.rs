//! Reading secrets. Never writing them.
//!
//! [`KeychainReader`] is deliberately a *reader*. It has no `write` and no
//! `delete`, and it never will in phase 1: invariant I1 says no code path
//! writes or deletes a keychain item, and the cheapest way to make that true
//! is to give the rest of the crate no vocabulary for saying it (plan AC15,
//! AC25). The `security(1)` transport for writes exists — fact F29 records
//! how Claude Code does it — and is phase-2 work, behind the same trait
//! growing a second, separately reviewed method.
//!
//! The submodules split by mechanism:
//!
//! - [`security_cli`] runs `/usr/bin/security` under a time budget.
//! - [`file_store`] is agentctl's own credential file, in Claude Code's
//!   on-disk shape (fact F40).
//! - [`namespace_lock`] is the `flock` that makes a namespace single-writer.
//! - [`held_locks`] reads the records agentctl writes while it holds a Claude
//!   Code lock, which is how `doctor` finds a leaked one.
//! - [`foreign_activity`] answers "is somebody else using this namespace?".
//! - [`location`] picks between the keychain and the file for one account.

#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "remaining items are consumed by W2 (accounts, import, doctor) and W3 (watch)"
    )
)]

pub mod audit;
pub mod file_store;
pub mod foreign_activity;
pub mod held_locks;
pub mod keychain_write;
pub mod location;
pub mod namespace_lock;
pub mod security_cli;

#[cfg(feature = "testing")]
pub mod fake_security;

#[cfg(test)]
pub mod fake_reader;

use crate::error::AppError;
use crate::error::KeychainClass;
use crate::runtime::coordinator::PassCtx;

/// The keychain service name prefix every Claude Code credential item shares.
pub const CLAUDE_SERVICE_PREFIX: &str = "Claude Code-credentials";

/// The service prefix used by `claude-account-switcher`, a third-party tool
/// whose items agentctl recognises but never touches (fact F10).
pub const SWITCHER_SERVICE_PREFIX: &str = "claude-switcher:";

/// Selects the keychain backend under the `testing` feature.
#[cfg(feature = "testing")]
pub const KEYCHAIN_BACKEND_ENV: &str = "AGENTCTL_KEYCHAIN_BACKEND";

/// Overrides the `security(1)` binary under the `testing` feature.
#[cfg(feature = "testing")]
pub const SECURITY_BIN_ENV: &str = "AGENTCTL_SECURITY_BIN";

/// The production `security(1)` binary. An absolute path, never resolved
/// through `PATH`: this process must not be talked into running some other
/// program by an inherited environment.
pub const SECURITY_BIN: &str = "/usr/bin/security";

/// Reads credential blobs out of the macOS keychain.
///
/// # No write side
///
/// There is no `write`, `update` or `delete` method, and adding one is a
/// phase-2 decision, not an implementation detail. See the module
/// documentation.
pub trait KeychainReader {
    /// Asks whether the keychain can be read at all, before any item is
    /// named.
    ///
    /// Runs `security show-keychain-info` under a 2 000 ms budget. Exit
    /// status 36 means the keychain is locked (fact F34).
    ///
    /// This is **not** memoized. Claude Code memoizes it for its process
    /// lifetime, which is right for a session that starts, works and exits;
    /// `agentctl watch` runs for hours, and a keychain that locks — or is
    /// unlocked — between passes must be noticed on the next one (plan AC44).
    fn preflight(&self) -> KeychainStatus;

    /// Lists the generic-password items whose service name starts with
    /// `prefix`, reading attributes only.
    ///
    /// Runs `security dump-keychain` under a 10 000 ms budget. No password
    /// material is requested and none is returned.
    ///
    /// # Errors
    ///
    /// Returns [`KeychainError`] when the dump could not be produced.
    fn list_services(&self, prefix: &str) -> Result<Vec<ServiceEntry>, KeychainError>;

    /// Reads one item's password.
    ///
    /// Runs `security find-generic-password -a <account> -w -s <service>`
    /// under a 2 000 ms budget. Exit status 44 — no such item — is `Ok(None)`
    /// rather than an error, because "this account has no keychain item" is a
    /// normal, expected answer.
    ///
    /// # Errors
    ///
    /// Returns [`KeychainError::Locked`] on exit status 36, and the
    /// corresponding variant for a timeout, a spawn failure or a classified
    /// stderr.
    fn read(&self, service: &str) -> Result<Option<Vec<u8>>, KeychainError>;
}

/// What the keychain preflight found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeychainStatus {
    /// Readable.
    Unlocked,
    /// Present but locked; the user must unlock it.
    Locked,
    /// Not reachable at all, with the reason as `security(1)` gave it.
    Unavailable(String),
    /// `security(1)` did not answer inside its budget.
    Timeout,
}

/// One keychain item, attributes only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceEntry {
    /// The `svce` attribute.
    pub service: String,
    /// The `acct` attribute, when the item has one.
    pub account: Option<String>,
    /// The `cdat` (creation) attribute, as printed.
    pub cdat: Option<String>,
    /// The `mdat` (modification) attribute, as printed.
    pub mdat: Option<String>,
}

/// Why a keychain read failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeychainError {
    /// The keychain is locked.
    #[error("keychain locked")]
    Locked,
    /// `security(1)` exceeded its budget and was killed.
    #[error("security timed out after {0} ms")]
    Timeout(u64),
    /// `security(1)` exited non-zero with a classifiable message.
    #[error("security failed: {class:?}: {stderr}")]
    Failed {
        /// Which of the ten classes the message fell into.
        class: StderrClass,
        /// The message, trimmed.
        stderr: String,
    },
    /// `security(1)` could not be started at all.
    #[error("security could not be spawned: {0}")]
    Spawn(String),
}

impl KeychainError {
    /// Whether a later pass might succeed where this one failed.
    ///
    /// Everything except an outright missing binary is transient: a locked
    /// keychain gets unlocked, a timeout is a busy machine. This is what
    /// invariant I10 leans on — a transient keychain failure must never be
    /// answered by falling back to the plaintext file, because that is how
    /// two processes end up holding one refresh chain.
    pub fn is_transient(&self) -> bool {
        !matches!(self, Self::Spawn(_))
    }

    /// The class this error reports to the user through [`AppError`].
    pub fn class(&self) -> KeychainClass {
        match self {
            Self::Locked => KeychainClass::Locked,
            Self::Timeout(_) => KeychainClass::Timeout,
            Self::Spawn(reason) => KeychainClass::Other(reason.clone()),
            Self::Failed { class, .. } => match class {
                StderrClass::ItemNotFound => KeychainClass::NotFound,
                StderrClass::KeychainLocked => KeychainClass::Locked,
                StderrClass::KeychainUnavailable | StderrClass::NoKeychain => {
                    KeychainClass::Unavailable
                }
                other => KeychainClass::Other(format!("{other:?}")),
            },
        }
    }
}

impl From<KeychainError> for AppError {
    fn from(err: KeychainError) -> Self {
        Self::Keychain { class: err.class() }
    }
}

/// The ten classes `security(1)` stderr falls into (fact F34).
///
/// The order of the variants is the order the classifier tries them in, and
/// both are Claude Code's, verbatim. Matching Claude Code matters because the
/// classification decides whether a failure is transient — and therefore
/// whether agentctl leaves a namespace alone — so the two tools must agree
/// about what a given message means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StderrClass {
    /// Nothing was written to stderr.
    Empty,
    /// An item with that service name already exists.
    DuplicateItem,
    /// The keychain file could not be opened.
    KeychainUnavailable,
    /// There is no default keychain.
    NoKeychain,
    /// No item matched.
    ItemNotFound,
    /// The item exists but this process may not be shown it without a prompt.
    InteractionNotAllowed,
    /// The user dismissed the prompt.
    UserCanceled,
    /// Authentication or authorization failed.
    AuthFailed,
    /// The keychain is locked.
    KeychainLocked,
    /// Anything else.
    Other,
}

/// Classifies a `security(1)` stderr message (fact F34).
///
/// First match wins, tried in the order the variants are declared, matching
/// case-insensitively on substrings.
pub fn classify_stderr(stderr: &str) -> StderrClass {
    let trimmed = stderr.trim();
    if trimmed.is_empty() {
        return StderrClass::Empty;
    }
    let haystack = trimmed.to_lowercase();
    let has = |needle: &str| haystack.contains(needle);

    if has("errsecduplicateitem") || has("already exists") {
        StderrClass::DuplicateItem
    } else if has("unable to open") || has("could not open") {
        StderrClass::KeychainUnavailable
    } else if has("errsecnodefaultkeychain") || has("default keychain") || has("no keychain") {
        StderrClass::NoKeychain
    } else if has("errsecitemnotfound") || has("item could not be found") {
        StderrClass::ItemNotFound
    } else if has("errsecinteractionnotallowed")
        || has("interaction is not allowed")
        || has("no user interaction")
    {
        StderrClass::InteractionNotAllowed
    } else if has("errsecusercanceled") || has("cancel") {
        StderrClass::UserCanceled
    } else if has("errsecauthfailed")
        || has("authorization")
        || has("authentication")
        || has("name or passphrase")
    {
        StderrClass::AuthFailed
    } else if has("locked") || has("unlock") {
        StderrClass::KeychainLocked
    } else {
        StderrClass::Other
    }
}

/// A reader that answers "there is no keychain here" to everything.
///
/// Selected by `AGENTCTL_KEYCHAIN_BACKEND=none` under the `testing` feature,
/// and the default for every test that is not specifically exercising the
/// keychain: it makes it impossible for a test run to reach the real
/// keychain by accident.
#[derive(Debug, Clone, Copy, Default)]
pub struct DisabledReader;

impl KeychainReader for DisabledReader {
    fn preflight(&self) -> KeychainStatus {
        KeychainStatus::Unavailable("disabled".to_owned())
    }

    fn list_services(&self, _prefix: &str) -> Result<Vec<ServiceEntry>, KeychainError> {
        Ok(Vec::new())
    }

    fn read(&self, _service: &str) -> Result<Option<Vec<u8>>, KeychainError> {
        Ok(None)
    }
}

/// Builds the reader this process should use.
///
/// Production is always [`security_cli::SecurityCli`] against
/// [`SECURITY_BIN`], with the current `$USER` as the item account (fact F14).
/// Under the `testing` feature two environment variables redirect it:
/// `AGENTCTL_KEYCHAIN_BACKEND=none` selects [`DisabledReader`], and
/// `AGENTCTL_SECURITY_BIN` points at the fake script from
/// [`fake_security`].
pub fn default_reader(ctx: &PassCtx) -> Box<dyn KeychainReader + Send + Sync> {
    #[cfg(feature = "testing")]
    if std::env::var(KEYCHAIN_BACKEND_ENV).is_ok_and(|value| value == "none") {
        return Box::new(DisabledReader);
    }

    #[cfg(feature = "testing")]
    let bin = std::env::var_os(SECURITY_BIN_ENV)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(SECURITY_BIN));
    #[cfg(not(feature = "testing"))]
    let bin = std::path::PathBuf::from(SECURITY_BIN);

    Box::new(security_cli::SecurityCli::new(bin, current_account(), ctx.clone()))
}

/// The `acct` attribute Claude Code stores its items under: `$USER`.
///
/// Falls back to `LOGNAME` and then to the empty string; an empty account
/// still produces a well-formed `find-generic-password` call, which simply
/// finds nothing.
pub fn current_account() -> String {
    std::env::var("USER").or_else(|_| std::env::var("LOGNAME")).unwrap_or_else(|_| String::new())
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
