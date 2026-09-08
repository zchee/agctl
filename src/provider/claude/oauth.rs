//! The OAuth response types.
//!
//! **This file is lane D's**, and holds only the part lane A had to land
//! first: [`Credentials::merge_refresh`](super::credentials::Credentials::merge_refresh)
//! folds a token response into stored credentials, so the response type has to
//! exist before the credential type compiles. The PKCE helpers, the authorize
//! URL, the loopback listener and the exchange/refresh calls go here too, on
//! top of these structs.
//!
//! Two things lane D will need to know, both discovered while landing this:
//!
//! - `SecretString` in secrecy 0.10 is `SecretBox<str>`, and `str` is neither
//!   `Sized` nor `Clone`. So [`TokenResponse`] cannot `#[derive(Clone)]`, and
//!   it cannot `#[derive(Deserialize)]` either — the crate's blanket impl is
//!   `SecretBox<T> where T: Zeroize + Clone + DeserializeOwned + Sized`, which
//!   `str` fails on three counts. Deserializing it needs a private
//!   `#[derive(Deserialize)]` mirror with `String` fields that is converted
//!   over, or `#[serde(deserialize_with)]` on each secret field.
//! - For the same reason, anything that consumes a response takes it **by
//!   value**. Copying a token out of a `&TokenResponse` would mean exposing
//!   the plaintext at a third call site, and invariant I6 allows exactly two
//!   in the whole crate.

#![cfg_attr(not(test), expect(dead_code, reason = "the OAuth client lands with lane D"))]

use secrecy::SecretString;
use serde::Deserialize;
use serde_json::Value;

/// A successful response from the token endpoint (facts F8, F25).
pub struct TokenResponse {
    /// The new bearer token.
    pub access_token: SecretString,
    /// The new refresh token, when the server rotated it. Absent means keep
    /// the one already stored (fact F8).
    pub refresh_token: Option<SecretString>,
    /// Access-token lifetime, in **seconds**.
    pub expires_in: i64,
    /// Refresh-token lifetime, in **seconds**, when the server sent one.
    pub refresh_token_expires_in: Option<i64>,
    /// The granted scopes, space-separated.
    pub scope: Option<String>,
    /// Always `Bearer` in practice; carried so lane D can notice if it is not.
    pub token_type: Option<String>,
    /// The account the token belongs to; half of the namespace key (D-008).
    pub account: Option<ExchangeAccount>,
    /// The organization the token belongs to; the other half.
    pub organization: Option<ExchangeOrganization>,
    /// The workspace block, kept untyped because nothing in phase 1 reads it.
    pub workspace: Option<Value>,
}

/// The `account` block of an exchange response (fact F25).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ExchangeAccount {
    /// The Anthropic account UUID.
    pub uuid: String,
    /// The account's email address.
    pub email_address: Option<String>,
}

/// The `organization` block of an exchange response (fact F25).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ExchangeOrganization {
    /// The organization UUID.
    pub uuid: String,
    /// The organization's display name.
    pub name: Option<String>,
}

#[cfg(test)]
#[path = "oauth_tests.rs"]
mod tests;
