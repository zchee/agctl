//! Everything specific to Claude subscription accounts.
//!
//! The split is by concern rather than by layer, because the concerns are
//! what the invariants are written about:
//!
//! - [`namespace`] — Claude Code's keychain naming rule (fact F14) and the
//!   directories it keys on. Nothing here reads a secret.
//! - [`credentials`] — the blob: parsing, refreshing, digests, and the one
//!   place a token is exposed.
//! - [`oauth`] — the OAuth response types. Lane D fills in the client.
//! - [`account`] — what a row is and what its state means.
//! - [`discovery`] — turning a keychain and a registry into rows.
//! - [`usage`] — the usage endpoint: request, response, normalization.
//! - [`swap`] — what `use --live` decides, and in which of plan section
//!   3.4's three phases it decides it. No I/O.
//! - [`adopt`] — what becomes of the credential a swap displaces (decision
//!   D-017). No I/O.
//! - [`claude_json`] — the live `~/.claude.json`'s one `oauthAccount`
//!   rewrite after an applied live swap or undo (decision D-021), as a peer of
//!   Claude Code's configuration lock.

pub mod account;
pub mod adopt;
pub mod claude_json;
pub mod credentials;
pub mod discovery;
pub mod live_sessions;
pub mod namespace;
pub mod oauth;
pub mod swap;
pub mod usage;

/// The environment variable that replaces
/// [`USER_AGENT_DEFAULT`](super::USER_AGENT_DEFAULT) for Anthropic.
///
/// Production-visible on purpose (plan section 3.2): if Anthropic ever starts
/// refusing the honest agent, the user can put Claude Code's back without
/// waiting for a release.
pub const USER_AGENT_ENV: &str = "AGCTL_CLAUDE_USER_AGENT";

/// The `User-Agent` agctl sends to Anthropic, override included.
///
/// Honest, not mimicked. Probe S3 established that this value is accepted on
/// both the usage endpoint and the token endpoint — a refresh grant carrying
/// it returned 200 — so there is no reason to impersonate Claude Code's
/// `claude-cli/<version> (external, cli)`, and every reason not to: a client
/// that lies about who it is cannot be rate-limited, deprecated or excluded
/// separately from the product it is pretending to be. Decision U13.
///
/// The default and the override rule now live in
/// [`super::user_agent`], which both providers share: the
/// value this returns is the one it always was, and there is one place left
/// where a second provider could have grown a second answer to "who is this
/// client".
pub fn user_agent() -> String {
    super::user_agent(super::Provider::Claude)
}
