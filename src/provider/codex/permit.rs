//! The capability to send a Codex refresh POST.
//!
//! # Why a value, and not a rule written down
//!
//! `watch` must never send a refresh (plan section 10, U44 = option 5). Until
//! review S33-C2 that property was held by text greps over the files that name
//! [`refresh::run`](super::refresh::run): a helper importing it under an alias,
//! or a POST written inside a function `watch` already calls, defeated every
//! one of them and still compiled. The rule now has a value behind it.
//!
//! [`PostPermit`] holds the only refresh client a command builds, and
//! [`super::refresh::run`] and [`super::refresh::record_retry_get`] take one.
//! Two consequences follow from the types alone:
//!
//! - a caller with no permit cannot POST, whatever it aliases — the call does
//!   not type-check;
//! - a [`RefreshCtx`](super::refresh::RefreshCtx) is inert: it carries the
//!   store, the deadline, the lock budget, the cancel key and the fault seam,
//!   and nothing that can reach the token host.
//!
//! The field is private to this module, so a permit cannot be built by
//! literal anywhere else (`scripts/phase3-structural.sh` clauses 12 and 13),
//! and [`PostPermit::from_env`] is the one constructor a command may call —
//! pinned to `commands/codex/status.rs` by `scripts/phase3-greps.sh`, which
//! matches the *path* rather than the call, so an aliased import is a hit on
//! its own `use` line.

use crate::provider::codex::oauth::RefreshClient;

/// The capability to send one account's refresh token to the token host.
///
/// Built by `agctl codex status` (and, from S34, `agctl codex accounts
/// refresh`) on the command thread. `watch` builds none, which is what makes
/// "`watch` never POSTs" a property of the program rather than of a grep.
#[derive(Debug)]
pub struct PostPermit {
    /// The token endpoint. Reachable only inside `provider::codex`, so no
    /// command can take the client back out of the permit.
    client: RefreshClient,
}

impl PostPermit {
    /// The permit a real command holds: the token endpoint this process
    /// should use.
    pub(crate) fn from_env() -> Self {
        Self { client: RefreshClient::from_env() }
    }

    /// A permit over an explicit client, for the tests inside
    /// `provider::codex` and `commands::codex::status`. Compiled out of every
    /// shipped binary.
    #[cfg(test)]
    pub(crate) fn with_client(client: RefreshClient) -> Self {
        Self { client }
    }

    /// The client the driver posts with.
    pub(super) fn client(&self) -> &RefreshClient {
        &self.client
    }
}
