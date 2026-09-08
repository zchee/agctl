//! The credential blob: parsing it, merging a refresh into it, and writing it
//! back out in the shape Claude Code expects.
//!
//! # Why the round-trip matters
//!
//! agentctl writes `.credentials.json` in exactly Claude Code's format
//! (fact F40, decision D-009) so a Claude Code session pointed at an agentctl
//! namespace can read it. That makes the file a shared format, and shared
//! formats grow fields. Anything this build does not recognise is kept in
//! [`Credentials::extra`] and written back out unchanged, so an agentctl
//! refresh never *loses* a field a newer Claude Code added — losing one would
//! silently degrade the session that reads the file next.
//!
//! # The one place a token is exposed
//!
//! Invariant I6 allows exactly two sites in the whole crate where a token's
//! plaintext is taken out of its `SecretString`. This module owns the first,
//! inside [`Credentials::with_exposed`],
//! and everything that needs the plaintext — serializing the blob, hashing
//! the digests, building the refresh POST body — goes through it. The second
//! is the HTTP `Authorization` header builder, which lane C owns.
//!
//! [`Credentials`] therefore has a hand-written [`fmt::Debug`] that prints
//! digests instead of tokens; deriving it would have put access tokens in
//! every `tracing` line that logged one.

#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "remaining items are consumed by W2 (accounts, import, doctor) and W3 (watch)"
    )
)]

use std::fmt;

use secrecy::ExposeSecret;
use secrecy::SecretString;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Map;
use serde_json::Value;
use sha2::Digest;
use sha2::Sha256;

use crate::provider::claude::oauth::TokenResponse;

/// The key the blob object hangs under, in both the keychain item and the
/// file (fact F4).
pub const BLOB_ROOT: &str = "claudeAiOauth";

/// How long before expiry a token counts as expired (fact F27).
pub const REFRESH_MARGIN_MS: i64 = 300_000;

/// Claude Code's public OAuth client id (fact F8).
pub const CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";

/// The scopes a live Claude Code credential carries, and the set agentctl
/// requests at login (facts F4, F28).
pub const DEFAULT_SCOPES: [&str; 5] = [
    "user:file_upload",
    "user:inference",
    "user:mcp_servers",
    "user:profile",
    "user:sessions:claude_code",
];

/// One account's OAuth credentials.
pub struct Credentials {
    /// The bearer token for the usage API.
    pub access_token: SecretString,
    /// The token that mints new access tokens. Absent in blobs written by
    /// something that only had an access token to store.
    pub refresh_token: Option<SecretString>,
    /// When the access token expires, in milliseconds since the epoch.
    pub expires_at_ms: i64,
    /// When the refresh token expires. Absent in older blobs (fact F4).
    pub refresh_token_expires_at_ms: Option<i64>,
    /// The scopes the token carries.
    pub scopes: Vec<String>,
    /// The subscription tier, as the server named it.
    pub subscription_type: Option<String>,
    /// The rate-limit tier, as the server named it.
    pub rate_limit_tier: Option<String>,
    /// The OAuth client id the token was minted for. Absent in older blobs.
    pub client_id: Option<String>,
    /// Who the token belongs to. Absent in older blobs, which is why an
    /// imported account can be `identity unknown`.
    pub token_account: Option<TokenAccount>,
    /// Every key this build does not recognise, preserved in order.
    pub extra: Map<String, Value>,
}

/// The identity block newer blobs carry (fact F4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TokenAccount {
    /// The account UUID.
    pub uuid: Option<String>,
    /// The account's email address.
    #[serde(rename = "emailAddress")]
    pub email_address: Option<String>,
    /// The organization UUID.
    #[serde(rename = "organizationUuid")]
    pub organization_uuid: Option<String>,
    /// The organization's display name.
    #[serde(rename = "organizationName")]
    pub organization_name: Option<String>,
    /// The workspace id, when the token is workspace-scoped.
    #[serde(rename = "workspaceId")]
    pub workspace_id: Option<String>,
    /// The workspace's display name.
    #[serde(rename = "workspaceName")]
    pub workspace_name: Option<String>,
}

/// Who a credential belongs to, once it is known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The Anthropic account UUID — half of the namespace key (D-008).
    pub account_uuid: String,
    /// The organization UUID, when the blob named one.
    pub organization_uuid: Option<String>,
    /// The account's email address.
    pub email: Option<String>,
    /// The organization's display name.
    pub org_name: Option<String>,
}

/// Fingerprints of the token material, safe to write to disk and to compare.
///
/// Used for two things that both need to answer "is this the same credential?"
/// without holding the credential: folding a keychain entry into the live row
/// (plan AC42) and deciding whether a `.credentials.json.pending` still
/// applies to the file it was derived from (plan section 3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digests {
    /// `sha256(access_token)`, hex.
    pub access_sha256: String,
    /// `sha256(refresh_token)`, hex, when there is one.
    pub refresh_sha256: Option<String>,
}

/// Why a credential blob could not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CredentialsError {
    /// The bytes are not JSON.
    #[error("the credentials blob is not valid JSON: {0}")]
    Json(String),
    /// The JSON has no `claudeAiOauth` object.
    #[error("the credentials blob has no `{BLOB_ROOT}` object")]
    MissingRoot,
    /// A field this build requires is absent or the wrong type.
    #[error("the credentials blob field `{0}` is missing or has the wrong type")]
    MissingField(&'static str),
    /// A timestamp computation did not fit in an `i64`.
    #[error("the token expiry `{0}` does not fit in a 64-bit millisecond timestamp")]
    ExpiryOverflow(&'static str),
    /// A refresh was attempted without a refresh token.
    #[error("this account has no refresh token; run `agentctl claude login`")]
    NoRefreshToken,
}

impl Credentials {
    /// Parses a blob in Claude Code's shape.
    ///
    /// `accessToken` and `expiresAt` are required; everything else is
    /// optional, because older blobs genuinely lack `refreshTokenExpiresAt`,
    /// `clientId` and `tokenAccount` (fact F4) and refusing them would hide
    /// real accounts from the user.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialsError`] naming what was wrong.
    pub fn parse_blob(bytes: &[u8]) -> Result<Self, CredentialsError> {
        let root: Value =
            serde_json::from_slice(bytes).map_err(|err| CredentialsError::Json(err.to_string()))?;
        let object =
            root.get(BLOB_ROOT).and_then(Value::as_object).ok_or(CredentialsError::MissingRoot)?;

        // Recognised keys are taken *out*, so whatever is left is exactly the
        // set this build does not know about.
        let mut extra = object.clone();
        let access_token = take_string(&mut extra, "accessToken")
            .ok_or(CredentialsError::MissingField("accessToken"))?;
        let expires_at_ms =
            take_i64(&mut extra, "expiresAt").ok_or(CredentialsError::MissingField("expiresAt"))?;
        let refresh_token = take_string(&mut extra, "refreshToken");
        let refresh_token_expires_at_ms = take_i64(&mut extra, "refreshTokenExpiresAt");
        let scopes = extra
            .shift_remove("scopes")
            .and_then(|value| match value {
                Value::Array(items) => Some(
                    items
                        .into_iter()
                        .filter_map(|item| item.as_str().map(str::to_owned))
                        .collect::<Vec<String>>(),
                ),
                _ => None,
            })
            .unwrap_or_default();
        let subscription_type = take_string(&mut extra, "subscriptionType");
        let rate_limit_tier = take_string(&mut extra, "rateLimitTier");
        let client_id = take_string(&mut extra, "clientId");
        let token_account = extra
            .shift_remove("tokenAccount")
            .and_then(|value| serde_json::from_value::<TokenAccount>(value).ok());

        Ok(Self {
            access_token: SecretString::from(access_token),
            refresh_token: refresh_token.map(SecretString::from),
            expires_at_ms,
            refresh_token_expires_at_ms,
            scopes,
            subscription_type,
            rate_limit_tier,
            client_id,
            token_account,
            extra,
        })
    }

    /// Serializes the blob, ready to be written to `.credentials.json`.
    ///
    /// Known keys are emitted in the order Claude Code writes them, then
    /// every unrecognised key in the order it arrived. Absent optional fields
    /// are omitted rather than written as `null`, which is what Claude Code
    /// does and what makes the round-trip of an old blob byte-stable.
    pub fn to_blob_json(&self) -> String {
        let blob = self.with_exposed(|access, refresh| {
            let mut inner = Map::new();
            inner.insert("accessToken".to_owned(), Value::String(access.to_owned()));
            if let Some(refresh) = refresh {
                inner.insert("refreshToken".to_owned(), Value::String(refresh.to_owned()));
            }
            inner.insert("expiresAt".to_owned(), Value::from(self.expires_at_ms));
            if let Some(expires) = self.refresh_token_expires_at_ms {
                inner.insert("refreshTokenExpiresAt".to_owned(), Value::from(expires));
            }
            inner.insert(
                "scopes".to_owned(),
                Value::Array(self.scopes.iter().map(|s| Value::String(s.clone())).collect()),
            );
            insert_optional(&mut inner, "subscriptionType", self.subscription_type.as_deref());
            insert_optional(&mut inner, "rateLimitTier", self.rate_limit_tier.as_deref());
            insert_optional(&mut inner, "clientId", self.client_id.as_deref());
            if let Some(account) = &self.token_account
                && let Ok(value) = serde_json::to_value(account)
            {
                inner.insert("tokenAccount".to_owned(), value);
            }
            for (key, value) in &self.extra {
                inner.entry(key.clone()).or_insert_with(|| value.clone());
            }
            inner
        });

        let mut root = Map::new();
        root.insert(BLOB_ROOT.to_owned(), Value::Object(blob));
        Value::Object(root).to_string()
    }

    /// The `Authorization` header value for a request made as this account.
    ///
    /// Built here, beside [`Credentials::to_blob_json`], for the same reason
    /// [`Credentials::refresh_body`] is: routing it through
    /// [`Credentials::with_exposed`] keeps the whole crate at the two
    /// exposure sites invariant I6 allows. The OAuth profile call (fact F26)
    /// and the usage call (fact F20) both go through here.
    pub fn authorization_header(&self) -> String {
        self.with_exposed(|access, _| format!("Bearer {access}"))
    }

    /// The refresh POST body (fact F8).
    ///
    /// Built here rather than in the OAuth client so the refresh token does
    /// not need a second exposure site.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialsError::NoRefreshToken`] when there is nothing to
    /// refresh with, which is the `needs login` path.
    pub fn refresh_body(&self, client_id: &str) -> Result<String, CredentialsError> {
        self.with_exposed(|_, refresh| {
            let refresh = refresh.ok_or(CredentialsError::NoRefreshToken)?;
            let mut body = Map::new();
            body.insert("grant_type".to_owned(), Value::String("refresh_token".to_owned()));
            body.insert("refresh_token".to_owned(), Value::String(refresh.to_owned()));
            body.insert("client_id".to_owned(), Value::String(client_id.to_owned()));
            body.insert("scope".to_owned(), Value::String(self.scopes.join(" ")));
            Ok(Value::Object(body).to_string())
        })
    }

    /// Whether the access token is expired, or will be within `margin_ms`
    /// (fact F27).
    ///
    /// Overflow answers "expired". Overflow checks are off in every profile
    /// here (constraint C-006), so a wrapped addition would otherwise produce
    /// a large negative instant and report a long-dead token as fresh.
    pub fn access_expired(&self, now_ms: i64, margin_ms: i64) -> bool {
        match now_ms.checked_add(margin_ms) {
            Some(threshold) => threshold >= self.expires_at_ms,
            None => true,
        }
    }

    /// Folds a refresh response into these credentials (facts F8, F18).
    ///
    /// Two rules carry weight:
    ///
    /// - **A response without a `refresh_token` keeps the old one.** The
    ///   server does not rotate refresh tokens on every exchange, and
    ///   overwriting the stored one with nothing would end the chain.
    /// - **`expires_in` is in seconds** while everything stored is in
    ///   milliseconds, and the conversion is checked.
    ///
    /// Takes the response by value: `SecretString` is not `Clone`, so moving
    /// the tokens out is what keeps this from needing an exposure site of its
    /// own.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialsError::ExpiryOverflow`] when the new expiry does
    /// not fit in an `i64` of milliseconds.
    pub fn merge_refresh(&mut self, r: TokenResponse, now_ms: i64) -> Result<(), CredentialsError> {
        let expires_at_ms = deadline_ms(now_ms, r.expires_in, "expires_in")?;
        let refresh_expires = match r.refresh_token_expires_in {
            Some(seconds) => Some(deadline_ms(now_ms, seconds, "refresh_token_expires_in")?),
            None => self.refresh_token_expires_at_ms,
        };

        self.access_token = r.access_token;
        if let Some(refresh) = r.refresh_token {
            self.refresh_token = Some(refresh);
        }
        self.expires_at_ms = expires_at_ms;
        self.refresh_token_expires_at_ms = refresh_expires;
        if let Some(scope) = r.scope {
            self.scopes = scope.split_whitespace().map(str::to_owned).collect();
        }
        Ok(())
    }

    /// Who these credentials belong to, from `tokenAccount` alone.
    ///
    /// Never from a directory path, and never from `.claude.json` — that file
    /// records the last login through a configuration directory, which is
    /// evidence about the live row and nothing else (invariant I13,
    /// fact F33).
    pub fn identity(&self) -> Option<Identity> {
        let account = self.token_account.as_ref()?;
        let account_uuid = account.uuid.clone()?;
        Some(Identity {
            account_uuid,
            organization_uuid: account.organization_uuid.clone(),
            email: account.email_address.clone(),
            org_name: account.organization_name.clone(),
        })
    }

    /// Fingerprints of the token material.
    pub fn digests(&self) -> Digests {
        self.with_exposed(|access, refresh| Digests {
            access_sha256: sha256_hex(access),
            refresh_sha256: refresh.map(sha256_hex),
        })
    }

    /// The crate's first and only credential exposure site (invariant I6).
    ///
    /// Everything that needs plaintext token material calls through here, so
    /// there is exactly one line to audit — and exactly one line for the
    /// gate's audit grep to find, which is why the name of the call does not
    /// appear anywhere else in this file.
    fn with_exposed<R>(&self, f: impl FnOnce(&str, Option<&str>) -> R) -> R {
        let refresh = self.refresh_token.as_ref();
        f(self.access_token.expose_secret(), refresh.map(|t| t.expose_secret()))
    }
}

impl fmt::Debug for Credentials {
    /// Prints digests where the tokens would go.
    ///
    /// Hand-written rather than derived: a derived `Debug` would put access
    /// tokens into any `tracing` line that formatted a `Credentials`, and
    /// `SecretString`'s own redaction does not survive being placed in a
    /// field of a derived struct that someone later prints with `{:#?}`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let digests = self.digests();
        f.debug_struct("Credentials")
            .field("access_token", &"<redacted>")
            .field("access_sha256", &digests.access_sha256)
            .field("refresh_token", &self.refresh_token.as_ref().map(|_| "<redacted>"))
            .field("refresh_sha256", &digests.refresh_sha256)
            .field("expires_at_ms", &self.expires_at_ms)
            .field("refresh_token_expires_at_ms", &self.refresh_token_expires_at_ms)
            .field("scopes", &self.scopes)
            .field("subscription_type", &self.subscription_type)
            .field("rate_limit_tier", &self.rate_limit_tier)
            .field("client_id", &self.client_id)
            .field("token_account", &self.token_account)
            .field("extra_keys", &self.extra.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// `now_ms + seconds * 1000`, checked at both steps.
fn deadline_ms(now_ms: i64, seconds: i64, field: &'static str) -> Result<i64, CredentialsError> {
    seconds
        .checked_mul(1000)
        .and_then(|millis| now_ms.checked_add(millis))
        .ok_or(CredentialsError::ExpiryOverflow(field))
}

/// Hex SHA-256 of a string.
fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

/// Removes a string-valued key, leaving a wrong-typed one exactly where it is.
///
/// The type is checked before the removal rather than after, because
/// `serde_json`'s `preserve_order` map is index-backed: `shift_remove`
/// followed by `insert` would put the value back at the *end*, which is a
/// reordering the byte-stable round-trip this passthrough exists for cannot
/// afford.
fn take_string(map: &mut Map<String, Value>, key: &str) -> Option<String> {
    if !matches!(map.get(key), Some(Value::String(_))) {
        return None;
    }
    match map.shift_remove(key) {
        Some(Value::String(text)) => Some(text),
        _ => None,
    }
}

/// Removes an integer-valued key, leaving a wrong-typed one where it is.
fn take_i64(map: &mut Map<String, Value>, key: &str) -> Option<i64> {
    let number = map.get(key).and_then(Value::as_i64)?;
    map.shift_remove(key);
    Some(number)
}

/// Inserts a string field when it has a value.
fn insert_optional(map: &mut Map<String, Value>, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        map.insert(key.to_owned(), Value::String(value.to_owned()));
    }
}

#[cfg(test)]
#[path = "credentials_tests.rs"]
mod tests;
