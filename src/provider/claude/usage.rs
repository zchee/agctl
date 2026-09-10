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
//! # Credits come from `extra_usage`, never from `spend`
//!
//! A response describes the same credit balance twice, in `extra_usage` and
//! in `spend`, and the two disagree in shape and sometimes in value. Only
//! `extra_usage` is read (decision D-006): it is the object the web UI drives
//! its own credits panel from, so following it is what keeps agctl and the
//! site quoting the same number. `spend` is peeked at for exactly two
//! contradiction checks and is otherwise passed through untouched, visible in
//! `--raw` alone — parsing it into a second typed value would create a second
//! answer to the same question and no rule for choosing between them.
//!
//! Both checks emit a [`tracing::warn`], because the failure they detect is
//! silent otherwise: the column reads `n/a` or a stale figure while the
//! server did send a number, and only `--raw` would show it.
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

use std::fmt;
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
use crate::usage::model::Credits;
use crate::usage::model::CreditsState;
use crate::usage::model::DEFAULT_MONEY_EXPONENT;
use crate::usage::model::LimitWindow;
use crate::usage::model::MAX_MONEY_EXPONENT;
use crate::usage::model::Money;
use crate::usage::model::UsageSnapshot;
use crate::usage::model::WindowKind;
use crate::usage::model::clamp_percent;
use crate::usage::model::percent_floor;
use crate::usage::model::percent_round;

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

/// How far `extra_usage.utilization` and `spend.percent` may drift before the
/// disagreement is worth a warning (risk R14).
///
/// One point, because the two are computed from the same balance at slightly
/// different moments and rounded differently; anything larger means the
/// column and the web UI would show materially different numbers.
pub const PERCENT_AGREEMENT_TOLERANCE: f64 = 1.0;

/// Redirects the base URL. Test seam only (plan section 3.9).
#[cfg(feature = "testing")]
pub const USAGE_URL_ENV: &str = "AGCTL_CLAUDE_USAGE_URL";

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

    let (credits, warnings) = credits_from_body(root);
    for warning in warnings {
        // The enclosing `account` span (see `commands::status::run_account`)
        // carries `account.id`, so the row is named without this function
        // having to be told which one it is parsing.
        tracing::warn!(
            credits.warning = %warning,
            "the credits column may not match the web UI for this account; \
             `agctl claude status --raw` shows what the server sent"
        );
    }

    Ok(UsageSnapshot {
        fetched_at,
        windows: normalize(object),
        credits,
        raw: keep_raw.then(|| root.clone()),
    })
}

/// Something the credits parser saw that the column cannot show.
///
/// Returned rather than logged so that [`credits_from_body`] stays a pure
/// function a test can assert the whole list against (plan AC22);
/// [`parse_usage`] is the single place that turns one of these into a
/// `tracing::warn!`.
#[derive(Debug, Clone, PartialEq)]
pub enum CreditsWarning {
    /// The response carried no `extra_usage`, but its `spend` object claims
    /// the account has credits.
    ///
    /// This is the under-delivery case (risk R14) and the only detector for
    /// it: the column will read `n/a` while the web UI shows a figure.
    SpendWithoutExtraUsage,
    /// `extra_usage.utilization` and `spend.percent` disagree by more than
    /// [`PERCENT_AGREEMENT_TOLERANCE`].
    PercentDisagrees {
        /// What `extra_usage` said, unrounded.
        extra_usage: f64,
        /// What `spend` said.
        spend: f64,
    },
    /// `decimal_places` was outside `0..=`[`MAX_MONEY_EXPONENT`].
    ///
    /// [`DEFAULT_MONEY_EXPONENT`] is used instead, so the figure is still
    /// shown; the warning is what says the decimal point may be misplaced.
    ExponentOutOfRange {
        /// The value the server sent.
        decimal_places: i64,
    },
}

impl fmt::Display for CreditsWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SpendWithoutExtraUsage => f.write_str(
                "the response carried no `extra_usage` but its `spend` object reports credits",
            ),
            Self::PercentDisagrees { extra_usage, spend } => write!(
                f,
                "`extra_usage.utilization` ({extra_usage}) and `spend.percent` ({spend}) \
                 disagree by more than {PERCENT_AGREEMENT_TOLERANCE} point"
            ),
            Self::ExponentOutOfRange { decimal_places } => write!(
                f,
                "`decimal_places` was {decimal_places}, outside 0..={MAX_MONEY_EXPONENT}; \
                 {DEFAULT_MONEY_EXPONENT} was assumed"
            ),
        }
    }
}

/// Reads the credits column's figures out of a usage body (plan section 3.8).
///
/// `extra_usage` is the only source. Its absence is
/// [`CreditsState::Unavailable`] rather than an error, because a response
/// shape that predates the object is a real thing to meet and an account
/// whose windows parsed fine should still get a row.
///
/// All the arithmetic here is checked: this project builds with
/// `-C overflow-checks=off` (constraint C-006), and a wrapped or saturated
/// money figure would be rendered as confidently as a correct one.
pub fn credits_from_body(root: &Value) -> (CreditsState, Vec<CreditsWarning>) {
    let mut warnings = Vec::new();
    let object = root.as_object();
    let spend = object.and_then(|object| object.get("spend")).and_then(Value::as_object);

    // A non-object `extra_usage` — `null`, most often — is "the server said
    // nothing", not a malformed document: the same key is `null` on every
    // account that has never touched credits.
    let Some(extra) =
        object.and_then(|object| object.get("extra_usage")).and_then(Value::as_object)
    else {
        if spend.is_some_and(spend_reports_credits) {
            warnings.push(CreditsWarning::SpendWithoutExtraUsage);
        }
        return (CreditsState::Unavailable, warnings);
    };

    // `is_enabled` is the one field fact F20 declares as a required boolean;
    // an `extra_usage` object without it is not the declared shape, so it is
    // reported as "no figure" rather than invented into an `On` with nothing in
    // it. The `spend` under-delivery detector still runs for that case.
    let enabled = match extra.get("is_enabled").and_then(Value::as_bool) {
        Some(enabled) => enabled,
        None => {
            if spend.is_some_and(spend_reports_credits) {
                warnings.push(CreditsWarning::SpendWithoutExtraUsage);
            }
            return (CreditsState::Unavailable, warnings);
        }
    };
    if !enabled {
        let reason = extra.get("disabled_reason").and_then(Value::as_str).map(str::to_owned);
        return (CreditsState::Off { reason }, warnings);
    }

    let exponent = match extra.get("decimal_places").and_then(Value::as_i64) {
        None => DEFAULT_MONEY_EXPONENT,
        Some(places) => match u8::try_from(places).ok().filter(|p| *p <= MAX_MONEY_EXPONENT) {
            Some(exponent) => exponent,
            None => {
                warnings.push(CreditsWarning::ExponentOutOfRange { decimal_places: places });
                DEFAULT_MONEY_EXPONENT
            }
        },
    };

    // No currency is not USD: `Money` renders a bare figure for an empty
    // code, which says "this many, in whatever the server meant" rather than
    // inventing a symbol the server never sent.
    let currency = extra.get("currency").and_then(Value::as_str).unwrap_or_default();

    let utilization = extra.get("utilization").and_then(Value::as_f64);
    if let Some(utilization) = utilization
        && let Some(spend) = spend
        && let Some(spend_percent) = spend.get("percent").and_then(Value::as_f64)
        && utilization.is_finite()
        && spend_percent.is_finite()
        && (utilization - spend_percent).abs() > PERCENT_AGREEMENT_TOLERANCE
    {
        warnings.push(CreditsWarning::PercentDisagrees {
            extra_usage: utilization,
            spend: spend_percent,
        });
    }

    let credits = Credits {
        used: money(extra.get("used_credits"), currency, exponent),
        limit: money(extra.get("monthly_limit"), currency, exponent),
        percent: utilization.and_then(percent_round),
    };
    (CreditsState::On(credits), warnings)
}

/// Builds one [`Money`] from a minor-unit field, or `None` when it is absent
/// or unreadable.
fn money(value: Option<&Value>, currency: &str, exponent: u8) -> Option<Money> {
    let amount_minor = minor_units(value?)?;
    Some(Money { amount_minor, currency: currency.to_owned(), exponent })
}

/// Reads a minor-unit amount, which the endpoint spells as either an integer
/// or a float.
///
/// The observed body sends `monthly_limit: 500000` and
/// `used_credits: 21956.0` in the same object, so both spellings have to
/// work. A float is rounded to the nearest whole minor unit and refused
/// outright when it is not finite or does not fit an `i64`: `as` saturates
/// silently, and an [`i64::MAX`] appearing in a money column is a worse
/// answer than an em dash.
fn minor_units(value: &Value) -> Option<i64> {
    if let Some(exact) = value.as_i64() {
        return Some(exact);
    }

    /// `i64::MIN`, which is exactly representable as an `f64` because it is
    /// a power of two.
    const MIN: f64 = -9_223_372_036_854_775_808.0;
    /// One past `i64::MAX`. Exclusive, because `i64::MAX` itself is *not*
    /// representable and rounds up to this value.
    const PAST_MAX: f64 = 9_223_372_036_854_775_808.0;

    let rounded = value.as_f64()?.round();
    if !rounded.is_finite() || rounded < MIN || rounded >= PAST_MAX {
        return None;
    }
    // Exact: the bounds above admit only whole numbers an `i64` holds.
    Some(rounded as i64)
}

/// Whether a `spend` object is claiming this account has credits.
///
/// Not "any non-null field": every response carries a `spend.disclaimer` and
/// a `spend.severity`, so a walk that counted prose would warn on every body
/// that merely lacks `extra_usage`, and a warning that fires constantly is
/// one nobody reads. What matters for the under-delivery case is whether
/// `spend` reports a live figure — an enabled switch, a non-zero percentage
/// or amount, or a ceiling — so those are what this looks at.
///
/// This is a peek, not a parse: nothing here is kept, and `spend` still
/// reaches the user only through `--raw` (plan section 3.8).
fn spend_reports_credits(spend: &Map<String, Value>) -> bool {
    if spend.get("enabled").and_then(Value::as_bool) == Some(true) {
        return true;
    }
    if ["limit", "balance", "cap"]
        .iter()
        .any(|key| spend.get(*key).is_some_and(|value| !value.is_null()))
    {
        return true;
    }
    if spend.get("percent").and_then(Value::as_f64).is_some_and(|percent| percent != 0.0) {
        return true;
    }
    spend
        .get("used")
        .and_then(Value::as_object)
        .and_then(|used| used.get("amount_minor"))
        .and_then(Value::as_f64)
        .is_some_and(|amount| amount != 0.0)
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
