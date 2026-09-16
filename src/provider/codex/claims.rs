//! The id token's payload, read against an allowlist.
//!
//! Codex takes an account's identity from the claims in its stored id token
//! and from nowhere else (facts F63, F85): `email` at the top level (or under
//! `https://api.openai.com/profile`), and the plan, user id, account id and
//! FedRAMP flag under `https://api.openai.com/auth`. The access token is
//! decoded only for `exp` (fact F65). This module does exactly that and keeps
//! exactly those fields.
//!
//! # Why an allowlist
//!
//! A live id token also carries the organization list with titles, a session
//! id, the authentication methods and more (fact F61). Every one of those is
//! something a `Debug` render, a trace field or a `--json` document could
//! leak (invariant I24). [`Claims`] has a field for each claim agctl uses and
//! no catch-all, so a claim that is not listed here cannot be carried out of
//! the decode at all — which is what lets its `Debug` be derived.
//!
//! # No signature check
//!
//! The token came from a file only its owner can read, and agctl uses the
//! claims to *label* a row and to name a directory, never to authorize
//! anything. Verifying the signature would need the issuer's keys, a network
//! fetch, and a trust decision this tool is not placed to make.
//!
//! # What an error may say
//!
//! [`ClaimsError`] carries fixed sentences only. The input is a bearer
//! credential, and an error built from it — a decode error quoting the
//! offending segment, a JSON error quoting a value — would put token bytes in
//! the one place nobody thinks to redact.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;

/// The claim object Codex's identity lives under.
const AUTH_CLAIM: &str = "https://api.openai.com/auth";

/// Where an email lives when the top-level claim is absent.
const PROFILE_CLAIM: &str = "https://api.openai.com/profile";

/// The largest token this module will decode. A live id token is about
/// 2 KiB (fact F61); anything a hundred times that is not one.
const MAX_TOKEN_BYTES: usize = 256 * 1024;

/// The claims agctl reads, and nothing else.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Claims {
    /// The account's email address.
    pub email: Option<String>,
    /// `chatgpt_user_id`, falling back to `user_id` (fact F85).
    pub chatgpt_user_id: Option<String>,
    /// `chatgpt_account_id`: the workspace the login chose (fact F91).
    pub chatgpt_account_id: Option<String>,
    /// `chatgpt_plan_type`, as the token spells it.
    pub plan_type: Option<String>,
    /// `chatgpt_account_is_fedramp`; absent reads as `false`, as Codex reads
    /// it.
    pub is_fedramp: bool,
    /// The token's own expiry, in seconds since the epoch.
    pub exp: Option<i64>,
}

/// Why a token's payload could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClaimsError {
    /// Not three non-empty, dot-separated segments.
    #[error("the token is not a three-part JWT")]
    Shape,
    /// Larger than any token this build expects.
    #[error("the token is larger than the {MAX_TOKEN_BYTES}-byte limit")]
    TooLarge,
    /// The payload segment is not base64url.
    #[error("the token's payload is not base64url")]
    Encoding,
    /// The payload is not a JSON object.
    #[error("the token's payload is not a JSON object")]
    Json,
}

/// Decodes a JWT's payload and extracts the allowlisted claims.
///
/// Three non-empty segments separated by `.`, the middle one base64url
/// without padding (fact F85). A trailing `=` is tolerated, since some
/// encoders emit it and nothing is gained by refusing.
///
/// # Errors
///
/// [`ClaimsError`], naming which rule the token broke and never its bytes.
pub fn parse(token: &str) -> Result<Claims, ClaimsError> {
    let payload = payload(token)?;
    let email =
        string_at(&payload, &["email"]).or_else(|| string_at(&payload, &[PROFILE_CLAIM, "email"]));
    let chatgpt_user_id = string_at(&payload, &[AUTH_CLAIM, "chatgpt_user_id"])
        .or_else(|| string_at(&payload, &[AUTH_CLAIM, "user_id"]));
    Ok(Claims {
        email,
        chatgpt_user_id,
        chatgpt_account_id: string_at(&payload, &[AUTH_CLAIM, "chatgpt_account_id"]),
        plan_type: string_at(&payload, &[AUTH_CLAIM, "chatgpt_plan_type"]),
        is_fedramp: payload
            .get(AUTH_CLAIM)
            .and_then(|auth| auth.get("chatgpt_account_is_fedramp"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        exp: payload.get("exp").and_then(Value::as_i64),
    })
}

/// A token's `exp` claim alone, for the access token (fact F65).
///
/// `Ok(None)` is a token that decodes but carries no integer `exp`, which is
/// the case where Codex falls back to `last_refresh`.
///
/// # Errors
///
/// As [`parse`].
pub fn expiry(token: &str) -> Result<Option<i64>, ClaimsError> {
    Ok(payload(token)?.get("exp").and_then(Value::as_i64))
}

/// The payload object of a three-part token.
fn payload(token: &str) -> Result<serde_json::Map<String, Value>, ClaimsError> {
    if token.len() > MAX_TOKEN_BYTES {
        return Err(ClaimsError::TooLarge);
    }
    let mut parts = token.split('.');
    let (Some(header), Some(body), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(ClaimsError::Shape);
    };
    if header.is_empty() || body.is_empty() || signature.is_empty() {
        return Err(ClaimsError::Shape);
    }
    let bytes =
        URL_SAFE_NO_PAD.decode(body.trim_end_matches('=')).map_err(|_| ClaimsError::Encoding)?;
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(Value::Object(map)) => Ok(map),
        _ => Err(ClaimsError::Json),
    }
}

/// The string at `path` inside `object`, when every step is there.
fn string_at(object: &serde_json::Map<String, Value>, path: &[&str]) -> Option<String> {
    let (last, parents) = path.split_last()?;
    let mut current = object;
    for key in parents {
        current = current.get(*key)?.as_object()?;
    }
    current.get(*last)?.as_str().map(str::to_owned)
}

#[cfg(test)]
#[path = "claims_tests.rs"]
mod tests;
