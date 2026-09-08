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

pub mod account;
pub mod credentials;
pub mod discovery;
pub mod namespace;
pub mod oauth;
