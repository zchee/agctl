//! The Claude usage endpoint: the request, the response, and what a failure
//! means.
//!
//! # The request (fact F1)
//!
//! `GET <base>/api/oauth/usage` with a bearer token, `anthropic-beta:
//! oauth-2025-04-20`, `Accept: application/json` and the
//! [`USER_AGENT_DEFAULT`](super::USER_AGENT_DEFAULT) header. The endpoint is
//! undocumented, so every one of those was observed rather than assumed, and
//! the base is overridable only under the `testing` feature — a
//! production-visible override of an endpoint that receives a bearer token
//! would be an exfiltration vector (plan section 3.9, AC37).
//!
//! # Two response shapes, one vocabulary
//!
//! Current responses carry a `limits[]` array. Older ones carry flat
//! `five_hour` / `seven_day` / `seven_day_<model>` objects. [`normalize`]
//! prefers the array and falls back to the flat keys, so the renderer sees
//! one shape. A `kind` this build has never seen becomes
//! [`WindowKind::Unknown`] and is still rendered, with the kind string
//! visible: an unrecognised window that disappeared silently is how a user
//! ends up over a limit they were never shown (risk R3, plan AC4).
//!
//! A response that describes **no** window at all is not an error and not an
//! empty success — it is what an API or console account looks like, and it
//! gets its own state so the row says so (plan AC49).
//!
//! # No token is exposed here
//!
//! The bearer header comes from
//! [`Credentials::authorization_header`](crate::provider::claude::credentials::Credentials::authorization_header),
//! which routes through the crate's single `SecretString` exposure site
//! (invariant I6). Nothing in this module reads a token's plaintext.
//!
//! # Refreshing is somebody else's job
//!
//! [`TokenRefresher`] is the seam the pass calls when the server rejects a
//! token. This module never refreshes on its own, because refreshing safely
//! means taking the namespace lock, re-checking for a Claude Code session and
//! re-reading the file first (plan section 3.3 step 3), and none of that is
//! an HTTP concern. The 401 arrives here; the decision about it is made in
//! [`crate::commands::status`].

use std::time::Duration;

use jiff::Timestamp;
use serde_json::Map;
use serde_json::Value;

use crate::provider::AccountRef;
use crate::provider::FetchError;
use crate::provider::UsageProvider;
use crate::provider::claude::credentials::Credentials;
use crate::provider::claude::oauth;
use crate::provider::claude::oauth::OauthClient;
use crate::provider::claude::oauth::OauthError;
use crate::provider::claude::oauth::TokenResponse;
use crate::runtime::coordinator::Cancel;
use crate::usage::model::CreditsState;
use crate::usage::model::LimitWindow;
use crate::usage::model::UsageSnapshot;
use crate::usage::model::WindowKind;
use crate::usage::model::clamp_percent;
use crate::usage::model::percent_floor;

/// Where the usage endpoint lives.
pub const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";

/// The path under the base URL (fact F1).
pub const USAGE_PATH: &str = "/api/oauth/usage";

/// The beta opt-in header the endpoint requires.
pub const BETA_HEADER: &str = "anthropic-beta";

/// The beta opt-in value the endpoint requires.
pub const BETA_VALUE: &str = "oauth-2025-04-20";

/// How long a connection may take to establish.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The largest response body this build will read.
///
/// A usage document is a few kilobytes; the ceiling stops a wrong endpoint —
/// a captive portal, a proxy error page — from being read into memory whole.
pub const MAX_BODY_BYTES: u64 = 1 << 22;

/// The scope whose weekly window has a column of its own in the table.
pub const HEADLINE_SCOPE: &str = "Fable";

/// Redirects the base URL. Test seam only (plan section 3.9).
#[cfg(feature = "testing")]
pub const USAGE_URL_ENV: &str = "AGENTCTL_CLAUDE_USAGE_URL";

/// A client for one pass's worth of usage requests.
///
/// Holds its own `ureq` agent so connections are pooled across the accounts
/// in a pass, and so the timeouts are set once rather than per request.
#[derive(Debug)]
pub struct UsageClient {
    base_url: String,
    agent: ureq::Agent,
}

impl UsageClient {
    /// Builds a client against an explicit base URL.
    ///
    /// `total_timeout` is the whole-request budget from `--timeout`;
    /// [`CONNECT_TIMEOUT`] bounds the connection separately, so a host that
    /// accepts a connection and then goes quiet is cut off by the former and
    /// a black-holed address by the latter.
    ///
    /// `http_status_as_error` is turned **off** deliberately: a 401 and a 429
    /// are answers this module must read headers from, not errors.
    pub fn new(base_url: &str, user_agent: &str, total_timeout: Duration) -> Self {
        let config = ureq::config::Config::builder()
            .timeout_global(Some(total_timeout))
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .http_status_as_error(false)
            .user_agent(user_agent)
            .build();
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            agent: ureq::Agent::new_with_config(config),
        }
    }

    /// Builds the client this process should use.
    ///
    /// Production always talks to [`DEFAULT_BASE_URL`]. Under the `testing`
    /// feature [`USAGE_URL_ENV`] redirects it at an `httpmock` server.
    pub fn from_env(total_timeout: Duration) -> Self {
        #[cfg(feature = "testing")]
        let base = std::env::var(USAGE_URL_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_owned());
        #[cfg(not(feature = "testing"))]
        let base = DEFAULT_BASE_URL.to_owned();

        Self::new(&base, &super::user_agent(), total_timeout)
    }

    /// The full usage URL.
    pub fn usage_url(&self) -> String {
        format!("{}{USAGE_PATH}", self.base_url)
    }
}

impl UsageProvider for UsageClient {
    fn fetch(
        &self,
        account: &AccountRef<'_>,
        cancel: &Cancel,
    ) -> Result<UsageSnapshot, FetchError> {
        if cancel.is_cancelled() {
            return Err(FetchError::Cancelled);
        }
        tracing::trace!(account.id = account.id, "fetching usage");

        let response = self
            .agent
            .get(self.usage_url())
            // Through `Credentials`, never by unwrapping the `SecretString`
            // here: that keeps the crate at the single exposure site
            // invariant I6 asks for, and keeps the audit grep's answer at one
            // line. The value goes straight into the header map and is
            // dropped with the request; it is never logged, because the span
            // for a fetch records the status and the retry hint, never a
            // header.
            .header("authorization", account.credentials.authorization_header())
            .header(BETA_HEADER, BETA_VALUE)
            .header("accept", "application/json")
            .call()
            .map_err(map_transport_error)?;

        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| parse_retry_after(value, Timestamp::now()));

        match status {
            200..=299 => {}
            401 | 403 => return Err(FetchError::Unauthorized),
            429 => return Err(FetchError::RateLimited { retry_after }),
            other => return Err(FetchError::Http { status: other }),
        }

        let body: Value = response
            .into_body()
            .with_config()
            .limit(MAX_BODY_BYTES)
            .read_json()
            .map_err(|err| FetchError::Parse(err.to_string()))?;

        // The body is always kept: the cache stores it verbatim so that a
        // stale render and a `--raw` dump both work, and a build that learns
        // to read a new field understands entries an older one wrote. What
        // `--raw` controls is whether it is *printed* (invariant I4 — the
        // body carries usage figures and no token material).
        parse_usage(&body, Timestamp::now(), true).map_err(FetchError::Parse)
    }
}

/// Maps a `ureq` failure onto the pass's vocabulary.
///
/// Every arm is transport: a status was never received, so there is nothing
/// to branch on but "the request did not complete". The message is the
/// error's own `Display`, which for `ureq` names the failure class and the
/// host — never a response body, and so never an echoed token.
fn map_transport_error(err: ureq::Error) -> FetchError {
    match err {
        ureq::Error::Timeout(what) => FetchError::Transport(format!("timed out ({what})")),
        other => FetchError::Transport(other.to_string()),
    }
}

/// Reads a `retry-after` header value.
///
/// RFC 9110 allows both a delay in seconds and an HTTP-date, and Anthropic
/// has been observed sending neither, one, or the other. A date already in
/// the past yields [`Duration::ZERO`] — "you may retry now" — rather than
/// `None`, because the server did answer the question.
///
/// All arithmetic is checked (constraint C-006).
pub fn parse_retry_after(value: &str, now: Timestamp) -> Option<Duration> {
    let text = value.trim();
    if text.is_empty() {
        return None;
    }

    if let Ok(seconds) = text.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }

    let at = jiff::fmt::rfc2822::parse(text).ok()?.timestamp();
    let millis = at.as_millisecond().checked_sub(now.as_millisecond())?;
    if millis <= 0 {
        return Some(Duration::ZERO);
    }
    u64::try_from(millis).ok().map(Duration::from_millis)
}

/// Turns a usage response into a snapshot.
///
/// # Errors
///
/// Returns a message when the body is not a JSON object. A body that *is* an
/// object but describes no window is not an error: that is plan AC49's API
/// account, and the caller renders it as `no subscription limits`.
pub fn parse_usage(
    root: &Value,
    fetched_at: Timestamp,
    keep_raw: bool,
) -> Result<UsageSnapshot, String> {
    let object = root
        .as_object()
        .ok_or_else(|| format!("expected a JSON object, got {}", json_type_name(root)))?;

    Ok(UsageSnapshot {
        fetched_at,
        windows: normalize(object),
        // Credits land in W2 (plan section 3.8, decision D-006). Until then
        // the column reads `n/a`, which is true: this build has not looked.
        credits: CreditsState::Unavailable,
        raw: keep_raw.then(|| root.clone()),
    })
}

/// Maps a usage response body onto usage windows (plan section 3.3 step 4).
///
/// `limits[]` wins whenever it is present and non-empty. The flat legacy keys
/// are consulted only as a fallback, so an account served both shapes is read
/// through the newer one — which is the one that carries `is_active` and the
/// scope display names.
pub fn normalize(root: &Map<String, Value>) -> Vec<LimitWindow> {
    if let Some(entries) = root.get("limits").and_then(Value::as_array)
        && !entries.is_empty()
    {
        let windows: Vec<LimitWindow> = entries.iter().filter_map(window_from_limit).collect();
        if !windows.is_empty() {
            return windows;
        }
    }
    legacy_windows(root)
}

/// Maps one `limits[]` entry.
///
/// An entry with no string `kind` is dropped: `kind` is the only thing that
/// says what the number means, and a percentage with no name is not something
/// that can honestly be put in a table.
fn window_from_limit(entry: &Value) -> Option<LimitWindow> {
    let object = entry.as_object()?;
    let kind_text = object.get("kind").and_then(Value::as_str)?;
    if kind_text.is_empty() {
        return None;
    }

    let scope_label = object
        .get("scope")
        .and_then(Value::as_object)
        .and_then(|scope| scope.get("model"))
        .and_then(Value::as_object)
        .and_then(|model| model.get("display_name"))
        .and_then(Value::as_str)
        .map(str::to_owned);

    let kind = match kind_text {
        "session" => WindowKind::Session,
        "weekly_all" => WindowKind::WeeklyAll,
        // A scoped window with no readable display name still exists and
        // still constrains the account; `scoped` is a truthful placeholder.
        "weekly_scoped" => {
            WindowKind::WeeklyScoped(scope_label.clone().unwrap_or_else(|| "scoped".to_owned()))
        }
        other => WindowKind::Unknown(other.to_owned()),
    };

    let percent = object.get("percent").and_then(Value::as_f64);
    Some(LimitWindow {
        kind,
        percent: percent.and_then(clamp_percent),
        percent_floor: percent.and_then(percent_floor),
        severity: object.get("severity").and_then(Value::as_str).map(str::to_owned),
        resets_at: object.get("resets_at").and_then(Value::as_str).and_then(parse_timestamp),
        scope_label,
        is_active: object.get("is_active").and_then(Value::as_bool).unwrap_or(false),
    })
}

/// Maps the flat pre-`limits[]` keys (plan principle P3).
///
/// Order is fixed rather than taken from the object: session, then the
/// all-model week, then each scoped week in the order the body listed it. The
/// table's first three columns depend on that order being stable across
/// accounts.
fn legacy_windows(root: &Map<String, Value>) -> Vec<LimitWindow> {
    let mut windows = Vec::new();

    if let Some(window) = legacy_window(root.get("five_hour"), WindowKind::Session, None) {
        windows.push(window);
    }
    if let Some(window) = legacy_window(root.get("seven_day"), WindowKind::WeeklyAll, None) {
        windows.push(window);
    }

    for (key, value) in root {
        let Some(scope) = key.strip_prefix("seven_day_") else {
            continue;
        };
        if scope.is_empty() {
            continue;
        }
        if let Some(window) = legacy_window(
            Some(value),
            WindowKind::WeeklyScoped(scope.to_owned()),
            Some(scope.to_owned()),
        ) {
            windows.push(window);
        }
    }

    windows
}

/// Maps one flat legacy window object, or `None` when it is null or absent.
fn legacy_window(
    value: Option<&Value>,
    kind: WindowKind,
    scope_label: Option<String>,
) -> Option<LimitWindow> {
    let object = value?.as_object()?;
    let percent = object.get("utilization").and_then(Value::as_f64);
    Some(LimitWindow {
        kind,
        percent: percent.and_then(clamp_percent),
        percent_floor: percent.and_then(percent_floor),
        severity: None,
        resets_at: object.get("resets_at").and_then(Value::as_str).and_then(parse_timestamp),
        scope_label,
        // The flat shape predates `is_active`; claiming one of these windows
        // is the active constraint would be an invention.
        is_active: false,
    })
}

/// Parses an RFC 3339 timestamp, discarding anything unparseable.
///
/// A window with an unreadable `resets_at` is still a window; the countdown
/// cell reads `—` and the percentage is unaffected.
fn parse_timestamp(text: &str) -> Option<Timestamp> {
    text.parse::<Timestamp>().ok()
}

/// Names a JSON value's type for an error message.
fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

/// Why a token refresh did not produce new credentials.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RefreshError {
    /// The refresh chain is dead; only a fresh login recovers it.
    ///
    /// Never retried as transient (fact R26, plan AC29): retrying an
    /// `invalid_grant` cannot succeed, and a row that says `rate-limited`
    /// when it means `needs login` sends the user to wait instead of to act.
    #[error("the stored refresh token was rejected (invalid_grant)")]
    InvalidGrant,

    /// The token endpoint asked the caller to slow down.
    ///
    /// A 429 there carries no `retry-after` in practice and — importantly —
    /// does **not** consume the grant, so it is transient (S3 probe, W0
    /// handoff).
    #[error("the token endpoint is rate limiting{}", match retry_after_s {
        Some(seconds) => format!(", retry in {seconds}s"),
        None => String::new(),
    })]
    RateLimited {
        /// The hint, in seconds, when the server sent one.
        retry_after_s: Option<u64>,
    },

    /// Anything else that might work next pass.
    #[error("{0}")]
    Transient(String),

    /// The pass was cancelled or hit its deadline mid-refresh.
    #[error("cancelled")]
    Cancelled,
}

/// Mints a new access token from stored credentials.
///
/// The production implementation is [`OauthClient`] (below); the pass tests
/// substitute doubles so no test can reach the real token endpoint.
///
/// `Send + Sync` because a refresher is shared across the workers of one
/// pass.
pub trait TokenRefresher: Send + Sync {
    /// Exchanges the stored refresh token for a new access token (fact F8).
    ///
    /// # Errors
    ///
    /// See [`RefreshError`].
    fn refresh(
        &self,
        credentials: &Credentials,
        cancel: &Cancel,
    ) -> Result<TokenResponse, RefreshError>;
}

impl TokenRefresher for OauthClient {
    fn refresh(
        &self,
        credentials: &Credentials,
        cancel: &Cancel,
    ) -> Result<TokenResponse, RefreshError> {
        oauth::refresh(self, credentials, cancel).map_err(|err| match err {
            OauthError::InvalidGrant => RefreshError::InvalidGrant,
            // A 429 on the token endpoint does not consume the grant (S3
            // probe), so it is transient and must never become `needs login`.
            OauthError::Http { status: 429, .. } => {
                RefreshError::RateLimited { retry_after_s: None }
            }
            OauthError::Cancelled => RefreshError::Cancelled,
            // `Timeout`, `Transport`, `Refused`, `Credentials` and every other
            // `Http` status are all "try again next pass"; `StateMismatch`
            // cannot arise on a refresh grant.
            other => RefreshError::Transient(other.to_string()),
        })
    }
}

#[cfg(test)]
#[path = "usage_tests.rs"]
mod tests;
