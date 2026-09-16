//! What a Codex row can say: its state and its credits.
//!
//! The vocabulary of plan section 3.6, with the stable names
//! `schemas/status.v2.json` enumerates. The row type that carries these, and
//! its `TuiRow` implementation, arrive with the usage pass (S33); defining the
//! names first lets the refresh and discovery steps between here and there
//! produce states the renderer will already know.

use jiff::Timestamp;

use crate::provider::codex::auth_store::UnknownClass;
use crate::provider::codex::home::StoreMode;

/// A Codex account's credits (fact F78-b: `balance` is a decimal *string* on
/// the wire, kept as one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodexCredits {
    /// The response carried a credits object.
    Balance {
        /// The balance as the server spelled it.
        balance: Option<String>,
        /// Whether the account's credits are unlimited.
        unlimited: bool,
    },
    /// No credits object in the response.
    Unavailable,
}

/// One Codex row's state (plan section 3.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodexState {
    /// Usage was read.
    Ok,
    /// The access token is expired and will not be refreshed from here.
    Expired {
        /// The row's instruction, such as `run agctl codex login`.
        reason: String,
    },
    /// No credential, or a dead grant.
    NeedsLogin,
    /// A mode with no usage endpoint (`apikey`, Bedrock). Exit-neutral.
    NoUsageSource {
        /// The auth mode's label.
        mode: String,
    },
    /// The response had no `rate_limit`.
    NoUsageWindows,
    /// The home stores credentials where agctl does not read them.
    StoreModeUnsupported {
        /// The configured mode.
        mode: StoreMode,
    },
    /// The Codex home could not be resolved or read.
    HomeUnreadable {
        /// Why, without file content.
        reason: String,
    },
    /// `auth.json` was being rewritten. Transient.
    TornRead,
    /// The usage endpoint rejected the token.
    Unauthorized {
        /// Whether a refresh was sent recently (the floor).
        refreshed_recently: bool,
    },
    /// An imported home that is the live home with a different grant.
    StaleSiblingOfLive,
    /// Hidden by the user.
    Forgotten,
    /// A Codex session is using the namespace.
    CodexSessionDetected {
        /// The evidence, as `doctor` names it.
        evidence: String,
    },
    /// The namespace lock was held by another process.
    Busy,
    /// The namespace lock could not be taken at all.
    LockUnavailable,
    /// A cached result, not refreshed this pass.
    Stale,
    /// The endpoint asked for a pause.
    RateLimited {
        /// The `retry-after` hint, in seconds.
        retry_after: Option<u64>,
    },
    /// A parked refresh was moved into place.
    PendingReplayed,
    /// A parked refresh was deleted unused.
    PendingDiscarded {
        /// The resolver's label.
        reason: String,
    },
    /// A refresh response was discarded.
    RefreshDiscarded,
    /// The refreshed id token names a different account (fact F92).
    IdentityDrift,
    /// A refresh was sent and its outcome is unknown; no automatic re-send.
    RefreshOutcomeUnknown {
        /// Since when.
        since: Timestamp,
        /// Why.
        class: UnknownClass,
        /// Whether `accounts refresh --resend` is allowed now.
        resend_eligible: bool,
    },
    /// The refresh marker cannot be read or written; no POST.
    RefreshStateUnavailable {
        /// Why, as a path and an errno.
        reason: String,
    },
    /// A refresh lost a race with another writer.
    RefreshRacedExternal,
    /// The account's refresh policy is `never`.
    RefreshDisabled,
    /// A 401 inside the refresh floor.
    UnauthorizedFloor,
    /// Three counted failures: only `login` or `--reset-floor` lifts this.
    UnauthorizedTerminal,
    /// An adopted grant was rejected too.
    AdoptedGrantDead,
    /// A newer external grant replaced the refresh response.
    DiscardedExternal,
    /// Anything else, as a sentence.
    Error(String),
}

impl CodexState {
    /// The state's stable name in `status.v2.json`.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Expired { .. } => "expired",
            Self::NeedsLogin => "needs_login",
            Self::NoUsageSource { .. } => "no_usage_source",
            Self::NoUsageWindows => "no_usage_windows",
            Self::StoreModeUnsupported { .. } => "store_mode_unsupported",
            Self::HomeUnreadable { .. } => "home_unreadable",
            Self::TornRead => "torn_read",
            Self::Unauthorized { .. } => "unauthorized",
            Self::StaleSiblingOfLive => "stale_sibling_of_live",
            Self::Forgotten => "forgotten",
            Self::CodexSessionDetected { .. } => "codex_session_detected",
            Self::Busy => "busy",
            Self::LockUnavailable => "lock_unavailable",
            Self::Stale => "stale",
            Self::RateLimited { .. } => "rate_limited",
            Self::PendingReplayed => "pending_replayed",
            Self::PendingDiscarded { .. } => "pending_discarded",
            Self::RefreshDiscarded => "refresh_discarded",
            Self::IdentityDrift => "identity_drift",
            Self::RefreshOutcomeUnknown { .. } => "refresh_outcome_unknown",
            Self::RefreshStateUnavailable { .. } => "refresh_state_unavailable",
            Self::RefreshRacedExternal => "refresh_raced_external",
            Self::RefreshDisabled => "refresh_disabled",
            Self::UnauthorizedFloor => "unauthorized_floor",
            Self::UnauthorizedTerminal => "unauthorized_terminal",
            Self::AdoptedGrantDead => "adopted_grant_dead",
            Self::DiscardedExternal => "discarded_external",
            Self::Error(_) => "error",
        }
    }

    /// Whether the state leaves the exit status untouched (plan AC103):
    /// a row with nothing to read is not a degraded row.
    pub fn is_exit_neutral(&self) -> bool {
        matches!(self, Self::Ok | Self::NoUsageSource { .. } | Self::Forgotten)
    }
}

#[cfg(test)]
#[path = "account_tests.rs"]
mod tests;
