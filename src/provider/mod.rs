//! Usage providers. Claude first, others later (constraint C-001).
//!
//! [`UsageProvider`] is the seam between "which vendor's API is this" and
//! everything downstream of a fetch — the cache, the table, the exit status.
//! It is narrow on purpose: one call, one account, one snapshot. The
//! interesting per-vendor work (which endpoint, which headers, how a refresh
//! is done, what a 401 body means) stays behind the implementation, and the
//! pass in [`crate::commands::status`] is written against the trait plus
//! [`FetchError`] alone.
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

use std::time::Duration;

use crate::provider::claude::credentials::Credentials;
use crate::runtime::coordinator::Cancel;
use crate::usage::model::UsageSnapshot;

/// The one account a [`UsageProvider::fetch`] call is about.
///
/// Borrowed rather than owned so a pass can hand a worker a view of a row it
/// already holds, and so a `Credentials` is never copied — copying one means
/// exposing its plaintext, and invariant I6 allows exactly two sites in the
/// crate for that.
#[derive(Debug)]
pub struct AccountRef<'a> {
    /// The row's display id, for the tracing span. Never a secret.
    pub id: &'a str,
    /// The credentials to authenticate with.
    pub credentials: &'a Credentials,
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
