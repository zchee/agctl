//! The Codex half of the account registry.
//!
//! A separate list in the same document, not a fifth [`AccountKind`] variant
//! (plan decision D-029). The two providers share a file and nothing else:
//! a Codex account is keyed by `(chatgpt_user_id, chatgpt_account_id)` rather
//! than by `(account_uuid, organization_uuid)`, its credentials live in a
//! different tree under a different lock, and a Claude command must not be
//! able to reach one even by accident. Widening [`AccountKind`] would have put
//! Codex rows in front of every `match` in `discovery`, `status`, `accounts`
//! and `doctor` — where the compiler would have demanded an arm and the
//! reviewer would have had to check each one — for rows those commands have
//! no business seeing at all (invariant I28, plan AC112).
//!
//! # What a record is for
//!
//! Metadata, and where the credentials are. The record never holds a token; it
//! holds what the identity is (the two ids, and the email and plan the claims
//! named), what the user called it, and which of the three kinds it is. The
//! kind is what decides whether agctl may write:
//!
//! - [`CodexKind::Owned`] — created by `agctl codex login`. The credentials
//!   live in this store, under `codex/<user>/<acct>/`, and agctl refreshes
//!   them subject to [`RefreshPolicy`].
//! - [`CodexKind::Live`] — the credentials the user's own `codex` is using,
//!   in `$CODEX_HOME`. Read-only, always (invariant I21): agctl never writes
//!   a file under a `CODEX_HOME` it did not create.
//! - [`CodexKind::HomeReadOnly`] — another Codex home, recorded by
//!   `agctl codex import`. Read-only for the same reason.
//!
//! [`AccountKind`]: crate::config::AccountKind

use std::path::PathBuf;

use serde::Deserialize;
use serde::Serialize;

/// One Codex account, keyed by `(chatgpt_user_id, chatgpt_account_id)`
/// (plan decision D-039).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodexAccountRecord {
    /// The ChatGPT user id from the id token's claims.
    pub chatgpt_user_id: String,
    /// The ChatGPT account (workspace) id from the same claims.
    pub chatgpt_account_id: String,
    /// The account's email address, when the claims carried one.
    pub email: Option<String>,
    /// The subscription tier, as the wire spells it (`plus`, `pro`, …).
    pub plan_type: Option<String>,
    /// A user-chosen label, from `codex login --label`.
    pub label: Option<String>,
    /// Where the credentials live and whether agctl may write them.
    pub kind: CodexKind,
    /// Whether the user has asked for this row to be hidden.
    #[serde(default)]
    pub forgotten: bool,
    /// When the record was created, RFC 3339 in UTC.
    pub created_at: String,
}

/// Where a Codex account's credentials live.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CodexKind {
    /// Created by `agctl codex login`; agctl owns the namespace and may
    /// refresh the grant in it.
    Owned {
        /// The namespace directory as it was spelled at login time. Recorded
        /// for the same reason the Claude twin is: a moved store can then be
        /// reported rather than silently resolving somewhere else. It is
        /// **never** a path agctl writes through — every write derives its
        /// path from the validated ids under `codex_root()` (invariant I27).
        export_spelling: String,
        /// Whether agctl may send a refresh POST for this account.
        ///
        /// Always written, never omitted: a policy that is absent from the
        /// file reads as "whatever this build defaults to", and the whole
        /// point of `accounts set --refresh never` is that the answer does
        /// not depend on the build.
        #[serde(default)]
        refresh: RefreshPolicy,
    },
    /// The credentials the user's own `codex` is using. Read-only.
    Live,
    /// Another Codex home, recorded by `import`. Read-only.
    HomeReadOnly {
        /// The home directory the credentials were read from.
        dir: PathBuf,
    },
}

/// Whether agctl refreshes an owned Codex grant on its own.
///
/// [`Copy`] because a proof value carries one by value through a whole pass
/// (plan section 3.8), and one word is cheaper to copy than to borrow.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshPolicy {
    /// Refresh when the access token is expired or rejected — the default,
    /// and the only mode in which agctl ever sends a refresh token.
    #[default]
    Auto,
    /// Never send a refresh. The row reports `expired (run agctl codex
    /// login)` instead, and no POST is made from any command.
    Never,
}

#[cfg(test)]
#[path = "codex_tests.rs"]
mod tests;
