//! Usage providers. Claude first, Codex second (constraint C-001).
//!
//! [`UsageProvider`] is the seam between "which vendor's API is this" and
//! everything downstream of a fetch — the cache, the table, the exit status.
//! It is narrow on purpose: one call, one account, one snapshot. The
//! interesting per-vendor work (which endpoint, which headers, how a refresh
//! is done, what a 401 body means) stays behind the implementation, and the
//! pass in [`crate::commands::status`] is written against the trait plus
//! [`FetchError`] alone.
//!
//! # The credential does not cross the seam
//!
//! A usage client needs one thing from an account's credential — the headers
//! that authenticate the request — and [`UsageAuth`] is exactly that and
//! nothing else. [`AccountRef`] therefore carries a `dyn UsageAuth` rather
//! than a concrete credential type, which is what lets the second provider's
//! client be written without either provider's credential type appearing in
//! the other's signature, and what keeps the plaintext behind each provider's
//! single exposure site (invariant I20). The header value a client receives
//! does carry the token; what it never receives is the `SecretString` or a
//! field it could expose a second time.
//!
//! # Why the error type is not the vendor's
//!
//! The pass branches on four things and no more: "the token is dead"
//! ([`FetchError::Unauthorized`], the refresh-once trigger), "slow down"
//! ([`FetchError::RateLimited`], the stale-cache path), "try again later"
//! (everything transient) and "this will not work" (everything else). A
//! provider that reported `ureq::Error` directly would push HTTP handling
//! into the pass, and a second provider would then push a second HTTP
//! library's error type in beside it.

pub mod claude;
pub mod codex;

use std::fmt;
use std::time::Duration;

use crate::provider::claude::credentials::Credentials;
use crate::runtime::coordinator::Cancel;
use crate::usage::model::UsageSnapshot;

/// The vendors agctl reads usage for.
///
/// Names a provider where the choice decides a path or a label and nothing
/// more, such as [`crate::config::paths::Paths::cache_dir_for`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    /// Anthropic's Claude.
    Claude,
    /// OpenAI's Codex CLI.
    Codex,
}

/// The default `User-Agent`, for every provider.
///
/// The product token is the package name rather than a literal, so a rename
/// of the binary cannot leave the header naming something that no longer
/// exists. Honest, not mimicked, for the reason
/// [`claude::user_agent`] states: a client that lies about who it is cannot
/// be rate-limited, deprecated or excluded separately from the product it is
/// pretending to be. One value for both providers, because it is one client.
pub const USER_AGENT_DEFAULT: &str =
    concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

/// Which environment variable overrides one provider's `User-Agent`.
fn user_agent_env(provider: Provider) -> &'static str {
    match provider {
        Provider::Claude => claude::USER_AGENT_ENV,
        Provider::Codex => codex::USER_AGENT_ENV,
    }
}

/// The `User-Agent` for one provider, override included.
///
/// An unset or blank override yields [`USER_AGENT_DEFAULT`]; a blank string
/// would otherwise produce a header that some proxies drop and others reject.
pub fn user_agent(provider: Provider) -> String {
    user_agent_or_default(std::env::var(user_agent_env(provider)).ok().as_deref())
}

/// [`user_agent`] without the environment, which is the whole of its rule.
///
/// Split out so the rule is tested by calling it rather than by mutating the
/// process environment: `std::env::set_var` is `unsafe` in edition 2024, and a
/// test that set it would race every other test in the binary.
fn user_agent_or_default(override_value: Option<&str>) -> String {
    match override_value {
        Some(value) if !value.trim().is_empty() => value.to_owned(),
        _ => USER_AGENT_DEFAULT.to_owned(),
    }
}

/// What one account authenticates a usage request with.
///
/// The seam between a provider's credential type and the request its usage
/// client builds. It is deliberately two methods and no accessor: a caller
/// gets a finished header value, never a [`secrecy::SecretString`] and never a
/// field it could expose again, so the plaintext is taken out at each
/// provider's single private exposure site and nowhere else (invariant
/// I20/I6). The header value does of course carry the token — that is what a
/// bearer header is — so it is a value to build a request from and not one to
/// log.
///
/// [`fmt::Debug`] is a supertrait so that an implementation can be formatted
/// at all, not as a redaction mechanism: a `#[derive(Debug)]` satisfies the
/// bound just as well as a redacting one. What keeps a token out of a
/// `tracing` line or a panic payload is [`AccountRef`]'s own hand-written
/// `Debug`, which never formats `auth` (invariant I24, plan AC96). Each
/// provider's credential type still owes its own redacting `Debug` for when it
/// is formatted directly.
pub trait UsageAuth: fmt::Debug {
    /// The `Authorization` header value for a request made as this account.
    fn authorization_header(&self) -> String;

    /// Header pairs this credential requires beyond the authorization, such
    /// as Codex's `ChatGPT-Account-Id` and its FedRAMP flag.
    ///
    /// Empty for Claude: `anthropic-beta` is a property of the endpoint, not
    /// of the credential, so it stays where the request is built.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the Codex usage client (S31) is the first production caller; Claude's \
                      endpoint headers are constants of the request"
        )
    )]
    fn extra_headers(&self) -> Vec<(&'static str, String)>;
}

/// Claude's credentials, as something a usage request can be built from.
///
/// The `impl` lives here rather than beside [`Credentials`] so that plan P6's
/// list of Claude sites this phase touches stays exhaustive and short: the
/// trait is new, the credential type is not.
impl UsageAuth for Credentials {
    fn authorization_header(&self) -> String {
        Credentials::authorization_header(self)
    }

    fn extra_headers(&self) -> Vec<(&'static str, String)> {
        Vec::new()
    }
}

/// The one account a [`UsageProvider::fetch`] call is about.
///
/// Borrowed rather than owned so a pass can hand a worker a view of a row it
/// already holds, and so a credential is never copied — copying one means
/// exposing its plaintext, and invariant I6 allows exactly two sites in the
/// crate for that.
///
/// The credential arrives as a `dyn UsageAuth` rather than as a concrete
/// `Credentials`, which is what lets a second provider's usage client be
/// written against this one type. It also narrows what a holder can reach to
/// the finished header and `Debug`: there is no accessor beyond the header,
/// where the old `&Credentials` exposed a `SecretString` field one
/// `expose_secret()` away.
pub struct AccountRef<'a> {
    /// The row's display id, for the tracing span. Never a secret.
    pub id: &'a str,
    /// How to authenticate as this account.
    pub auth: &'a dyn UsageAuth,
}

impl fmt::Debug for AccountRef<'_> {
    /// Prints the row id and nothing about the credential.
    ///
    /// Hand-written rather than derived because a derived one would print
    /// whatever sits behind `auth`, and the `UsageAuth: fmt::Debug` bound is
    /// satisfied by `#[derive(Debug)]` — so a provider whose credential type
    /// forgot to redact would put its token into every `{:?}` of an account.
    /// Redaction here must not depend on that discipline (invariant I24, plan
    /// AC96); the S30 Codex credential, which wraps a whole parsed `auth.json`,
    /// is the case this is written for.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountRef").field("id", &self.id).finish_non_exhaustive()
    }
}

/// Why a usage fetch did not produce a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    /// The server rejected the bearer token.
    ///
    /// For an account agctl owns this is the refresh-once trigger: the
    /// access token expired between the expiry check and the request, which
    /// happens routinely because the two use different clocks.
    #[error("the access token was rejected")]
    Unauthorized,

    /// The server asked the caller to slow down.
    #[error("rate limited{}", match retry_after {
        Some(after) => format!(", retry in {}s", after.as_secs()),
        None => String::new(),
    })]
    RateLimited {
        /// The `retry-after` hint, when the server sent a parseable one.
        retry_after: Option<Duration>,
    },

    /// Any other status the run cannot use.
    #[error("HTTP {status}")]
    Http {
        /// The status as received.
        status: u16,
    },

    /// The request never completed: connection, TLS, timeout.
    #[error("{0}")]
    Transport(String),

    /// The response arrived but was not the document this build understands.
    #[error("the usage response could not be read: {0}")]
    Parse(String),

    /// The pass was cancelled or hit its deadline before the request.
    #[error("cancelled")]
    Cancelled,
}

impl FetchError {
    /// Whether retrying later stands a chance.
    ///
    /// Drives whether the row is shown as `stale` — worth another pass — or
    /// as a hard failure. A 5xx and a dropped connection are transient; a
    /// rejected token and an unreadable document are not, because the next
    /// pass would do exactly the same thing and fail exactly the same way.
    pub fn is_transient(&self) -> bool {
        match self {
            Self::RateLimited { .. } | Self::Transport(_) => true,
            Self::Http { status } => *status >= 500,
            Self::Unauthorized | Self::Parse(_) | Self::Cancelled => false,
        }
    }
}

/// One vendor's usage API.
pub trait UsageProvider {
    /// Fetches one account's current usage.
    ///
    /// Implementations must honour `cancel` — a pass that has been cancelled
    /// or has passed its deadline gets [`FetchError::Cancelled`] rather than
    /// a request — and must bound the request in time themselves; the
    /// coordinator can kill a child process but not an in-process socket
    /// read.
    ///
    /// # Errors
    ///
    /// See [`FetchError`].
    fn fetch(&self, account: &AccountRef<'_>, cancel: &Cancel)
    -> Result<UsageSnapshot, FetchError>;
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
