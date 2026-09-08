//! The process-wide error type and the exit-code contract.
//!
//! Every command funnels its failures into [`AppError`], and `main` turns the
//! resulting value into a process exit status through [`AppError::exit_code`].
//! The contract is the one fixed by plan section 3.3 step 5:
//!
//! - [`EXIT_OK`] — the run produced a complete, healthy result.
//! - [`EXIT_FATAL`] — the run produced nothing useful.
//! - [`EXIT_PARTIAL`] — the run produced output, but at least one *shown* row
//!   failed, was refused, was locked, was busy, or could only be read stale.
//!
//! The partial/fatal split matters to callers that script `agentctl`: a exit
//! status of 2 still carries a usable table on stdout, so a wrapper can render
//! it and flag the degraded rows, whereas 1 means there is nothing to render.

// `Config`, `Io`, `Keychain`, `Refused` and `Partial` all have construction
// sites now. `Http` and `Auth` do not, and the reason is a design decision
// rather than an unfinished one: every network failure a pass meets becomes a
// row state (`rate-limited`, `needs login`, `error`) beside a rendered table,
// not a failure of the whole run. W3's `watch` is the remaining candidate for
// a caller. Scoped to the non-test build because `error_tests.rs` constructs
// every variant, and spelled `expect` so it starts warning once they do.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "Http and Auth have no caller yet; W3 may add one")
)]

use std::time::Duration;

use thiserror::Error;

/// The run produced a complete, healthy result.
pub const EXIT_OK: i32 = 0;

/// The run failed outright and produced nothing useful.
pub const EXIT_FATAL: i32 = 1;

/// The run produced output, but at least one shown row is degraded.
pub const EXIT_PARTIAL: i32 = 2;

/// How a read through `security(1)` failed.
///
/// The variants named here are the ones the phase-1 data flow branches on
/// (plan section 3.3 step 1). W1 lane A owns the full ten-class stderr
/// classifier from F34; it carries any class this enum does not name
/// explicitly through [`KeychainClass::Other`], so widening the classifier
/// does not change this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeychainClass {
    /// The keychain exists but is locked; the user must unlock it.
    Locked,
    /// No keychain is reachable at all.
    Unavailable,
    /// The `security(1)` child exceeded its time budget and was killed.
    Timeout,
    /// The keychain is readable and holds no item under that service name.
    NotFound,
    /// Any other classified failure, carrying the class label verbatim.
    Other(String),
}

impl std::fmt::Display for KeychainClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Locked => f.write_str("locked"),
            Self::Unavailable => f.write_str("unavailable"),
            Self::Timeout => f.write_str("timeout"),
            Self::NotFound => f.write_str("not found"),
            Self::Other(class) => f.write_str(class),
        }
    }
}

/// Renders the optional `retry-after` hint attached to an HTTP failure.
///
/// Returns the empty string when the response carried no hint, so the message
/// does not claim a retry window the server never sent.
fn retry_suffix(retry_after: Option<Duration>) -> String {
    match retry_after {
        Some(after) => format!(" (retry in {}s)", after.as_secs()),
        None => String::new(),
    }
}

/// Every failure `agentctl` reports to its caller.
#[derive(Debug, Error)]
pub enum AppError {
    /// The request cannot be carried out as configured. Fatal.
    #[error("{0}")]
    Config(String),

    /// An operating-system call the run depends on failed. Fatal.
    #[error("{context}")]
    Io {
        /// What the process was trying to do, in the user's terms.
        context: String,
        /// The underlying operating-system error.
        #[source]
        source: std::io::Error,
    },

    /// A keychain-backed credential could not be read.
    #[error("keychain read failed: {class}")]
    Keychain {
        /// Which classified failure occurred.
        class: KeychainClass,
    },

    /// An HTTP request to Anthropic returned a status the run cannot use.
    #[error("HTTP {status}{}", retry_suffix(*retry_after))]
    Http {
        /// The HTTP status code as received.
        status: u16,
        /// The server's `retry-after` hint, when it sent one.
        retry_after: Option<Duration>,
    },

    /// An OAuth grant was rejected.
    #[error("{}", if *invalid_grant {
        "the stored refresh token was rejected (invalid_grant); run `agentctl claude login`"
    } else {
        "authentication failed"
    })]
    Auth {
        /// Whether the server answered `invalid_grant`, which means the stored
        /// refresh chain is dead and only a fresh login can recover it.
        invalid_grant: bool,
    },

    /// `agentctl` declined to act, to avoid disturbing another holder.
    #[error("refused: {reason}")]
    Refused {
        /// Why the action was declined, in the user's terms.
        reason: String,
    },

    /// The pass rendered, but some shown rows could not be completed.
    #[error("{failed} shown account(s) could not be read")]
    Partial {
        /// How many shown rows are degraded.
        failed: usize,
    },
}

impl AppError {
    /// Maps this error onto the process exit status defined in plan section
    /// 3.3 step 5.
    ///
    /// Never returns [`EXIT_OK`]: an `AppError` value always means the run was
    /// at least degraded. Success is the `Ok` arm at the call site.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Config(_) | Self::Io { .. } => EXIT_FATAL,
            Self::Keychain { .. }
            | Self::Http { .. }
            | Self::Auth { .. }
            | Self::Refused { .. }
            | Self::Partial { .. } => EXIT_PARTIAL,
        }
    }

    /// Builds a [`AppError::Config`] for a subcommand that is accepted by the
    /// parser but not yet implemented.
    ///
    /// W1 to W3 replace each of these with the real command; until then the
    /// command exits [`EXIT_FATAL`] rather than pretending to have run.
    pub fn not_implemented(command: &str) -> Self {
        Self::Config(format!("`{command}` is not implemented yet"))
    }
}

#[cfg(test)]
#[path = "error_tests.rs"]
mod tests;
