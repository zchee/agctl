//! What one row of `agctl claude status` is, and what its state means.
//!
//! [`AccountState`] is the vocabulary the whole program shares for "what is
//! going on with this account". Two of its methods carry real weight beyond
//! display:
//!
//! - [`AccountState::is_failure`] drives the process exit status. Plan
//!   section 3.3 step 5: exit 2 when any *shown* row failed, was refused, was
//!   locked, was busy, or could only be read stale. A row that is hidden by
//!   default cannot make the process exit 2, which is why
//!   [`AccountRow::visible_by_default`] and this are separate questions.
//! - [`AccountState::allows_network`] is the gate on doing any HTTP at all.
//!   It answers "does this row hold a token worth spending a request on",
//!   which is not the same as "is this row healthy": a namespace with a
//!   Claude Code session in it still has a perfectly good access token to
//!   read usage with — what it must not do is *refresh*, and that is enforced
//!   separately by the refusal in the refresh path.

use crate::config::AccountRecord;
use crate::provider::claude::credentials::Credentials;

/// What is going on with one account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountState {
    /// Fresh credentials; usage was or can be fetched.
    Ok,
    /// The access token has expired.
    Expired {
        /// Whether this row is one agctl may not refresh — the live row,
        /// a foreign configuration directory, a migrated namespace. Such a
        /// row can only wait for its owner to refresh it (decision D-001).
        read_only: bool,
    },
    /// There is no usable credential; the user must log in.
    NeedsLogin,
    /// A credential was found but does not say who it belongs to. Older blobs
    /// carry no `tokenAccount` (fact F4), and a path is not identity
    /// (invariant I13).
    IdentityUnknown,
    /// A keychain item naming the same physical directory as the live store,
    /// holding different credentials. Hidden by default (plan AC42).
    StaleSiblingOfLive,
    /// A Claude Code credentials item that no agctl record claims.
    Unclaimed,
    /// A credential belonging to something that is not agctl and not
    /// Claude Code — another tool's keychain item (fact F10). Listed so the
    /// user can see it is there, hidden by default, and never read.
    ///
    /// Distinct from [`AccountState::Unclaimed`], which is a Claude Code
    /// credentials item agctl *could* adopt. Nothing here is adoptable, so
    /// a consumer branching on the `state` token must be able to tell the two
    /// apart.
    Foreign {
        /// What owns it, as the row's `kind` also spells it.
        source: String,
    },
    /// Hidden at the user's request by `accounts forget`.
    Forgotten,
    /// A keychain item exists for this namespace: a Claude Code session has
    /// migrated the credentials out of the file (fact F35). Displayed from
    /// the keychain, never refreshed, never written (invariant I2).
    MigratedToKeychain {
        /// The service name that was found.
        service: String,
    },
    /// This namespace's keychain item is held by a **different** identity —
    /// a hot-swap put another account there — and the record's own credential
    /// is in the adopted copy beside it (decisions D-017, D-024).
    ///
    /// Distinct from [`AccountState::MigratedToKeychain`], which is the same
    /// account's credential in a place agctl may not write. Here the item
    /// is readable and writable but is *not this row's*, so it is never read
    /// for this row, never refreshed for it, and never adopted into it
    /// (ruling OQ2(d), W3 re-review N1). The row is still perfectly usable:
    /// the adopted copy holds a real token, which is why this is not a
    /// failure state.
    Adopted {
        /// Who holds the item, as an email address when the blob named one
        /// and an account UUID otherwise. Never a token and never a raw blob.
        occupant: String,
    },
    /// A Claude Code lock artefact is present in the namespace.
    ClaudeSessionDetected {
        /// The artefact's name.
        lock: String,
        /// How long ago it was touched.
        age_ms: u64,
    },
    /// The keychain is locked; the user must unlock it.
    KeychainLocked {
        /// What `security(1)` said, when it said anything.
        detail: String,
    },
    /// `security(1)` did not answer inside its budget.
    KeychainTimeout,
    /// Another process holds this namespace's lock.
    Busy,
    /// The namespace lock could not be taken for a reason that is not
    /// contention — the fail-closed path (invariant I12).
    LockUnavailable,
    /// The displayed numbers came from the cache after a live fetch failed.
    Stale,
    /// The usage response carried no windows at all, which is what an API or
    /// console account looks like (plan AC49).
    NoSubscriptionLimits,
    /// A pending write from an earlier run was moved into place.
    PendingReplayed,
    /// A pending write from an earlier run was discarded.
    PendingDiscarded {
        /// Why, from
        /// [`PendingDiscardReason::label`](crate::secret::file_store::PendingDiscardReason::label).
        reason: String,
    },
    /// The server asked us to slow down.
    RateLimited {
        /// The `retry-after` hint, in seconds, when the server sent one.
        retry_after_s: Option<u64>,
    },
    /// A refresh completed but the namespace changed before it could be
    /// written, so the new credentials were dropped (plan AC21).
    RefreshDiscarded,
    /// `CLAUDE_CODE_OAUTH_TOKEN` is set, which short-circuits every store
    /// (fact F19).
    EnvToken,
    /// Anything else, with the reason.
    Error(String),
}

impl AccountState {
    /// The state as it appears in the table's `State` column.
    pub fn label(&self) -> String {
        match self {
            Self::Ok => "ok".to_owned(),
            Self::Expired { read_only: true } => {
                "expired (read-only; refreshed by its owner)".to_owned()
            }
            Self::Expired { read_only: false } => "expired".to_owned(),
            Self::NeedsLogin => "needs login".to_owned(),
            Self::IdentityUnknown => "identity unknown".to_owned(),
            Self::StaleSiblingOfLive => "stale sibling of live".to_owned(),
            Self::Unclaimed => "unclaimed".to_owned(),
            Self::Foreign { source } => format!("foreign ({source})"),
            Self::Forgotten => "forgotten".to_owned(),
            Self::MigratedToKeychain { service } => format!("migrated to keychain ({service})"),
            Self::Adopted { occupant } => {
                format!("adopted (its keychain item is held by another identity: {occupant})")
            }
            Self::ClaudeSessionDetected { lock, age_ms } => format!(
                "claude session detected — refresh refused (lock {lock}, age {}s)",
                age_ms / 1000
            ),
            Self::KeychainLocked { detail } if detail.is_empty() => "keychain locked".to_owned(),
            Self::KeychainLocked { detail } => format!("keychain locked ({detail})"),
            Self::KeychainTimeout => "keychain timeout (transient)".to_owned(),
            Self::Busy => "busy".to_owned(),
            Self::LockUnavailable => "lock unavailable".to_owned(),
            Self::Stale => "stale".to_owned(),
            Self::NoSubscriptionLimits => {
                "no subscription limits (API/console account?)".to_owned()
            }
            Self::PendingReplayed => "pending replayed".to_owned(),
            Self::PendingDiscarded { reason } => format!("pending discarded: {reason}"),
            Self::RateLimited { retry_after_s: Some(seconds) } => {
                format!("rate-limited (retry in {seconds}s)")
            }
            Self::RateLimited { retry_after_s: None } => "rate-limited".to_owned(),
            Self::RefreshDiscarded => {
                "refresh discarded: namespace changed during refresh".to_owned()
            }
            Self::EnvToken => "env token".to_owned(),
            Self::Error(reason) => reason.clone(),
        }
    }

    /// The state as one stable, machine-readable token.
    ///
    /// Separate from [`AccountState::label`] on purpose: the label is a
    /// sentence for a person and is free to be reworded, while this is what
    /// `status --json` puts in the `state` member and what a script branches
    /// on, so it is part of the report's schema
    /// (`schemas/status.v1.json`) and changes only with the report version.
    /// Neither carries the variant's payload — the label spells that out for a
    /// reader, and `note` carries it in the document.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Expired { .. } => "expired",
            Self::NeedsLogin => "needs_login",
            Self::IdentityUnknown => "identity_unknown",
            Self::StaleSiblingOfLive => "stale_sibling_of_live",
            Self::Unclaimed => "unclaimed",
            Self::Foreign { .. } => "foreign",
            Self::Forgotten => "forgotten",
            Self::MigratedToKeychain { .. } => "migrated_to_keychain",
            Self::Adopted { .. } => "adopted",
            Self::ClaudeSessionDetected { .. } => "claude_session_detected",
            Self::KeychainLocked { .. } => "keychain_locked",
            Self::KeychainTimeout => "keychain_timeout",
            Self::Busy => "busy",
            Self::LockUnavailable => "lock_unavailable",
            Self::Stale => "stale",
            Self::NoSubscriptionLimits => "no_subscription_limits",
            Self::PendingReplayed => "pending_replayed",
            Self::PendingDiscarded { .. } => "pending_discarded",
            Self::RateLimited { .. } => "rate_limited",
            Self::RefreshDiscarded => "refresh_discarded",
            Self::EnvToken => "env_token",
            Self::Error(_) => "error",
        }
    }

    /// Whether a shown row in this state makes the process exit 2.
    ///
    /// The informational states are not failures: an `unclaimed` item is a
    /// true statement about the machine, not something that went wrong, and a
    /// hidden row (`stale sibling of live`, `forgotten`) is not shown at all.
    /// Everything that means "you asked for numbers and did not get them" is.
    pub fn is_failure(&self) -> bool {
        match self {
            Self::Ok
            | Self::StaleSiblingOfLive
            | Self::Unclaimed
            | Self::Foreign { .. }
            | Self::Forgotten
            | Self::MigratedToKeychain { .. }
            | Self::Adopted { .. }
            | Self::PendingReplayed
            | Self::EnvToken => false,
            Self::Expired { .. }
            | Self::NeedsLogin
            | Self::IdentityUnknown
            | Self::ClaudeSessionDetected { .. }
            | Self::KeychainLocked { .. }
            | Self::KeychainTimeout
            | Self::Busy
            | Self::LockUnavailable
            | Self::Stale
            | Self::NoSubscriptionLimits
            | Self::PendingDiscarded { .. }
            | Self::RateLimited { .. }
            | Self::RefreshDiscarded
            | Self::Error(_) => true,
        }
    }

    /// Whether this row may make an HTTP request.
    ///
    /// `false` means there is no token worth spending a request on, or the
    /// server has told us to stop. Refreshing is a stricter question again:
    /// a detected session allows a usage fetch but never a refresh.
    pub fn allows_network(&self) -> bool {
        match self {
            Self::Ok
            | Self::Expired { read_only: false }
            | Self::MigratedToKeychain { .. }
            | Self::Adopted { .. }
            | Self::ClaudeSessionDetected { .. }
            | Self::PendingReplayed
            | Self::Stale
            | Self::EnvToken => true,
            Self::Expired { read_only: true }
            | Self::NeedsLogin
            | Self::IdentityUnknown
            | Self::StaleSiblingOfLive
            | Self::Unclaimed
            | Self::Foreign { .. }
            | Self::Forgotten
            | Self::KeychainLocked { .. }
            | Self::KeychainTimeout
            | Self::Busy
            | Self::LockUnavailable
            | Self::NoSubscriptionLimits
            | Self::PendingDiscarded { .. }
            | Self::RateLimited { .. }
            | Self::RefreshDiscarded
            | Self::Error(_) => false,
        }
    }
}

/// Where a row's credentials came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The macOS keychain.
    Keychain,
    /// This store's `.credentials.json`.
    File,
    /// `CLAUDE_CODE_OAUTH_TOKEN`.
    Env,
    /// Nowhere: there is no credential.
    None,
}

impl Source {
    /// The source as one stable, machine-readable token, for the `source`
    /// member of `status --json` and the `Source` column of `accounts list`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Keychain => "keychain",
            Self::File => "file",
            Self::Env => "env",
            Self::None => "none",
        }
    }
}

/// One row of the status table.
#[derive(Debug)]
pub struct AccountRow {
    /// The identifier `--account` accepts for this row.
    pub id: String,
    /// What the registry knows about it.
    pub record: AccountRecord,
    /// What is going on with it.
    pub state: AccountState,
    /// Where its credentials came from.
    pub source: Source,
    /// The credentials, when they were readable.
    pub credentials: Option<Credentials>,
    /// Whether the row is shown without `--all`. Hidden rows are counted in
    /// the footer and never affect the exit status.
    pub visible_by_default: bool,
    /// A short explanation shown alongside the state, when there is one.
    pub note: Option<String>,
}

#[cfg(test)]
#[path = "account_tests.rs"]
mod tests;
