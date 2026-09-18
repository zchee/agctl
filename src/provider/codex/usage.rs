//! The Codex usage endpoint: the request, the response, and what a failure
//! means.
//!
//! # The request (facts F67, F78, F79)
//!
//! `GET <base>/backend-api/wham/usage` with a bearer token, `Accept:
//! application/json`, the
//! [`USER_AGENT_ENV`](crate::provider::codex::USER_AGENT_ENV)-overridable
//! agent, and whatever [`UsageAuth::extra_headers`](crate::provider::UsageAuth::extra_headers)
//! hands over: for Codex credentials the account id header, and
//! `X-OpenAI-Fedramp: true` for a FedRAMP account (omitted otherwise). The
//! authorization and the extra headers arrive finished — this module never
//! reads a credential — and the base URL is overridable only under the
//! `testing` feature, because a production-visible override of an endpoint
//! that receives a bearer token is an exfiltration vector.
//!
//! # A header value is checked before it is sent
//!
//! The account id is derived from an id token's claims, which is
//! attacker-influenced input, and a value carrying CR/LF would let it write
//! further headers into the request. Every extra header value this module
//! sends is therefore rejected unless it is non-empty visible ASCII (no space,
//! no control byte), the authorization unless it is exactly two such tokens
//! separated by one space, and a rejection names the header and never its
//! value (carry-over #268). The refusal happens before the connection: a
//! malformed value produces zero requests, not a request with the header
//! dropped.
//!
//! # The response names the account's email
//!
//! `email` is on every response (fact F78-a). It is removed from the body
//! [`normalize`] keeps, so neither the cache, `--raw` nor a `Debug` of
//! [`CodexUsage`] can carry it; the version-2 identity takes the address from
//! the id token, not from here.
//!
//! # 403 is not 401 (decision D-035)
//!
//! A 401 means the token was rejected and is the refresh-once trigger. A 403
//! on this endpoint means the account may not read usage at all — a FedRAMP
//! workspace seen without the header, an enterprise policy — and refreshing
//! would send a second request with the same outcome, so it is reported as
//! [`FetchError::Http`] and the refresh path never runs.
//!
//! # Windows are classified by duration, never by position
//!
//! On the account W0 captured, `primary_window` is the **weekly** window,
//! `secondary_window` is null and the five-hour one is in
//! `additional_rate_limits[0]` (fact F78-c), so the pair is not a fixed
//! (session, weekly). Reading `primary_window` as "the session window" would
//! label a weekly figure as a session one. [`normalize`]
//! looks only at `limit_window_seconds` (plan section 3.5), and a duration it
//! does not recognise becomes [`WindowKind::Unknown`] with the hour count
//! visible rather than being dropped.
//!
//! # This module has no `UsageProvider` implementation
//!
//! [`UsageProvider`](crate::provider::UsageProvider) returns a
//! [`UsageSnapshot`](crate::usage::model::UsageSnapshot), whose credits are
//! Claude's `CreditsState` — a money-shaped type that cannot hold Codex's
//! decimal-string balance without inventing a currency for it. The Codex
//! client therefore returns [`CodexUsage`], which carries
//! [`CodexCredits`] instead, and plan section 9.3's `CreditsState` grep (m2)
//! stays at zero hits inside this tree.

use std::io::Read;
use std::time::Duration;

use jiff::Timestamp;
use serde_json::Map;
use serde_json::Value;

use crate::provider::AccountRef;
use crate::provider::FetchError;
use crate::provider::Provider;
use crate::provider::claude::usage::parse_retry_after;
use crate::provider::codex::account::CodexCredits;
use crate::provider::codex::account::CodexState;
use crate::provider::codex::credentials::ACCOUNT_ID_HEADER;
use crate::provider::codex::is_known_plan;
use crate::render::json_v2::JsonCreditsV2;
use crate::render::json_v2::JsonWindowV2;
use crate::runtime::coordinator::Cancel;
use crate::usage::model::LimitWindow;
use crate::usage::model::WindowKind;
use crate::usage::model::clamp_percent;
use crate::usage::model::percent_floor;

/// Where the usage endpoint lives (fact F67).
pub const DEFAULT_BASE_URL: &str = "https://chatgpt.com";

/// The path under the base URL (fact F67).
pub const USAGE_PATH: &str = "/backend-api/wham/usage";

/// How long name resolution, the connection (TLS included) and sending the
/// request headers may each take, at most.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The largest response body this build will read.
///
/// A usage document is a few kilobytes; the ceiling stops a wrong endpoint —
/// a captive portal, a proxy error page, an SSO login page — from being read
/// into memory whole. It bounds the body twice: the bytes on the wire, and
/// the bytes after content decoding. The agent asks for gzip, and the wire
/// limit sits under the decoder, so a small compressed body could otherwise
/// decode to gigabytes (review S31 F2).
pub const MAX_BODY_BYTES: u64 = 1 << 22;

/// The longest window that is still a session window, in seconds (6 h).
///
/// The observed session window is five hours; the slack above it absorbs a
/// vendor that rounds or re-tunes the window without turning it into a
/// window this build refuses to name.
pub const SESSION_MAX_SECONDS: i64 = 21_600;

/// The shortest window that still counts as weekly, in seconds (6 d).
pub const WEEKLY_MIN_SECONDS: i64 = 518_400;

/// The longest window that still counts as weekly, in seconds (8 d).
pub const WEEKLY_MAX_SECONDS: i64 = 691_200;

/// The longest vendor-supplied label this build will echo.
const MAX_LABEL_CHARS: usize = 64;

/// What a vendor label is replaced by when it is not plain enough to echo.
const UNRECOGNISED_LABEL: &str = "<unrecognised>";

/// The plan value used when the response names a tier this build does not
/// know (fact F63).
const UNKNOWN_PLAN: &str = "unknown";

/// The kind label for a window whose duration is missing or not a positive
/// whole number of hours.
const UNKNOWN_DURATION: &str = "unknown duration";

/// The top-level member that carries the account's email (fact F78-a).
const EMAIL_MEMBER: &str = "email";

/// Redirects the base URL. Test seam only (plan section 3.9).
#[cfg(feature = "testing")]
pub const USAGE_URL_ENV: &str = "AGCTL_CODEX_USAGE_URL";

/// Where a `testing` build sends a usage GET when [`USAGE_URL_ENV`] is unset:
/// the loopback discard port, a refused connection before a byte leaves the
/// host (review S31 F8, the twin of the token client's fallback, ledger D12).
/// A test binary never falls back to the vendor, and never with a bearer
/// token.
#[cfg(feature = "testing")]
pub const TESTING_FALLBACK_BASE_URL: &str = "http://127.0.0.1:9";

/// One window, with the vendor names version 2 carries beside it.
///
/// Codex's `additional_rate_limits[]` rows describe a limit that Claude has
/// no equivalent of — a metered feature, named by the vendor — so the three
/// names live here rather than in [`LimitWindow`], which is the shape both
/// providers share.
#[derive(Debug, Clone, PartialEq)]
pub struct CodexWindow {
    /// The window itself, in the vocabulary the renderer already speaks.
    pub window: LimitWindow,
    /// The vendor's own name for the limit, when it sent one.
    pub limit_name: Option<String>,
    /// Which metered feature the window covers, when the vendor said.
    pub metered_feature: Option<String>,
    /// The model slug the window's ordinary requests are billed as.
    pub normal_model_slug: Option<String>,
}

impl CodexWindow {
    /// The version-2 JSON object for this window.
    ///
    /// Built from [`LimitWindow`]'s own conversion and then filled in, so a
    /// member added to the shared conversion cannot be forgotten here.
    pub fn to_json_v2(&self) -> JsonWindowV2 {
        JsonWindowV2 {
            limit_name: self.limit_name.clone(),
            metered_feature: self.metered_feature.clone(),
            normal_model_slug: self.normal_model_slug.clone(),
            ..JsonWindowV2::from(&self.window)
        }
    }
}

/// One Codex account's usage at one moment.
///
/// `Debug` is written by hand: the kept body is summarised as its member
/// count, so formatting a usage can never print a vendor string this type did
/// not normalise.
#[derive(Clone, PartialEq)]
pub struct CodexUsage {
    /// When the response this was built from was received.
    pub fetched_at: Timestamp,
    /// Every window the response described, in the order section 3.5 puts
    /// them: the account's own windows first, then each additional limit.
    pub windows: Vec<CodexWindow>,
    /// What is known about credits.
    pub credits: CodexCredits,
    /// The subscription tier the response named, which overrides the id
    /// token's claim (plan section 3.5).
    pub plan_type: Option<String>,
    /// A sentence for the row when the response says something the windows
    /// do not, such as an account that is currently not allowed to send.
    pub note: Option<String>,
    /// The response body without its `email` member, kept for `--raw` and for
    /// the cache.
    pub raw: Option<Value>,
    /// Whether the response carried a `rate_limit` object at all.
    has_rate_limit: bool,
}

impl std::fmt::Debug for CodexUsage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodexUsage")
            .field("fetched_at", &self.fetched_at)
            .field("windows", &self.windows)
            .field("credits", &self.credits)
            .field("plan_type", &self.plan_type)
            .field("note", &self.note)
            .field("raw_members", &self.raw.as_ref().and_then(Value::as_object).map(Map::len))
            .field("has_rate_limit", &self.has_rate_limit)
            .finish()
    }
}

impl CodexUsage {
    /// The row state this usage implies.
    ///
    /// A response with no `rate_limit` is not an error and not an empty
    /// success: it is what an account with no subscription windows looks
    /// like, and it gets its own state so the row says so (plan AC86).
    pub fn state(&self) -> CodexState {
        if self.has_rate_limit { CodexState::Ok } else { CodexState::NoUsageWindows }
    }

    /// The version-2 JSON credits object for this account.
    pub fn credits_json_v2(&self) -> JsonCreditsV2 {
        match &self.credits {
            CodexCredits::Balance { balance, unlimited } => JsonCreditsV2 {
                kind: "balance",
                balance: balance.clone(),
                unlimited: Some(*unlimited),
                ..JsonCreditsV2::unavailable()
            },
            CodexCredits::Unavailable => JsonCreditsV2::unavailable(),
        }
    }
}

/// A client for one pass's worth of Codex usage requests.
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
    /// `timeout` is `--timeout`. Every phase is bounded on its own rather than
    /// by one whole-request budget (plan section 9.3: no `timeout_global` or
    /// `timeout_per_call` in this tree), so a [`FetchError::Transport`] names
    /// the phase that timed out: resolution, the connection and sending the
    /// headers each get [`CONNECT_TIMEOUT`] or `timeout`, whichever is
    /// shorter, and waiting for the response and reading its body each get
    /// `timeout`. The pass's own deadline bounds their sum.
    ///
    /// `http_status_as_error` is turned **off** deliberately: a 401, a 403
    /// and a 429 are answers this module must read a status and headers
    /// from, not errors.
    ///
    /// Redirects are **not followed** (`max_redirects(0)`, under which `ureq`
    /// returns the 3xx response itself). The endpoint is fixed, so there is
    /// no legitimate redirect, and following one would send the account id
    /// and FedRAMP headers to the `Location` host — `ureq` strips only the
    /// authorization — and turn that host's 401 into
    /// [`FetchError::Unauthorized`], the refresh trigger, for a token the
    /// usage endpoint never rejected (review S31 F1). A 3xx is
    /// [`FetchError::Http`].
    pub fn new(base_url: &str, user_agent: &str, timeout: Duration) -> Self {
        let short = timeout.min(CONNECT_TIMEOUT);
        let config = ureq::config::Config::builder()
            .timeout_resolve(Some(short))
            .timeout_connect(Some(short))
            .timeout_send_request(Some(short))
            .timeout_send_body(Some(short))
            .timeout_recv_response(Some(timeout))
            .timeout_recv_body(Some(timeout))
            .http_status_as_error(false)
            .max_redirects(0)
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
    /// feature [`USAGE_URL_ENV`] redirects it at an `httpmock` server, which
    /// is how every test in this crate exercises the endpoint without
    /// contacting the vendor, and an unset seam fails closed to
    /// [`TESTING_FALLBACK_BASE_URL`].
    ///
    /// Commands build their client here and nowhere else (review S31 N2):
    /// [`UsageClient::new`] trusts the agent string it is given.
    pub fn from_env(timeout: Duration) -> Self {
        #[cfg(feature = "testing")]
        let base = std::env::var(USAGE_URL_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| TESTING_FALLBACK_BASE_URL.to_owned());
        #[cfg(not(feature = "testing"))]
        let base = DEFAULT_BASE_URL.to_owned();

        Self::new(&base, &crate::provider::user_agent(Provider::Codex), timeout)
    }

    /// The full usage URL.
    pub fn usage_url(&self) -> String {
        format!("{}{USAGE_PATH}", self.base_url)
    }

    /// Fetches one account's current usage.
    ///
    /// Not a [`UsageProvider`](crate::provider::UsageProvider) implementation
    /// — see the module documentation for why the return type is
    /// [`CodexUsage`] and not a shared snapshot.
    ///
    /// # Errors
    ///
    /// [`FetchError::Cancelled`] when the pass was already cancelled,
    /// [`FetchError::Parse`] when a header value cannot be sent or the account
    /// id header is missing (no request is made in either case), or when the
    /// response body cannot be used — larger than [`MAX_BODY_BYTES`]
    /// included — and otherwise the status's meaning: 401 is
    /// [`FetchError::Unauthorized`], 429 is [`FetchError::RateLimited`] with
    /// the `retry-after` hint when the server sent a readable one, and every
    /// other status — 403 included (decision D-035) — is
    /// [`FetchError::Http`].
    pub fn fetch(
        &self,
        account: &AccountRef<'_>,
        cancel: &Cancel,
    ) -> Result<CodexUsage, FetchError> {
        if cancel.is_cancelled() {
            return Err(FetchError::Cancelled);
        }
        tracing::trace!(account.id = account.id, "fetching codex usage");

        // Through `UsageAuth`, which hands out finished header values and
        // never a `SecretString`: the plaintext is taken out only at this
        // provider's private `exposed` (invariant I20). The values go
        // straight into the header map and are dropped with the request;
        // neither is ever logged, because the span for a fetch records the
        // status and the retry hint, never a header.
        let authorization = account.auth.authorization_header();
        check_authorization(&authorization)?;
        let extra = account.auth.extra_headers();
        for (name, value) in &extra {
            check_header_value(name, value)?;
        }
        require_account_id(&extra)?;

        let mut request = self
            .agent
            .get(self.usage_url())
            .header("authorization", &authorization)
            .header("accept", "application/json");
        for (name, value) in &extra {
            request = request.header(*name, value);
        }

        let response = request.call().map_err(map_transport_error)?;

        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| parse_retry_after(value, Timestamp::now()));

        match status {
            200..=299 => {}
            401 => return Err(FetchError::Unauthorized),
            429 => return Err(FetchError::RateLimited { retry_after }),
            other => return Err(FetchError::Http { status: other }),
        }

        // `limit` bounds the wire bytes and `take` the decoded ones; one byte
        // over the ceiling is read so that "exactly at" and "over" differ.
        let mut decoded = Vec::new();
        response
            .into_body()
            .with_config()
            .limit(MAX_BODY_BYTES)
            .reader()
            .take(MAX_BODY_BYTES.saturating_add(1))
            .read_to_end(&mut decoded)
            .map_err(|err| FetchError::Parse(err.to_string()))?;
        if !u64::try_from(decoded.len()).is_ok_and(|len| len <= MAX_BODY_BYTES) {
            return Err(FetchError::Parse(
                "the response body is larger than this build reads".to_owned(),
            ));
        }
        let body: Value =
            serde_json::from_slice(&decoded).map_err(|err| FetchError::Parse(err.to_string()))?;

        // The body is always kept, less its `email` member: the cache stores
        // it so that a stale render and a `--raw` dump both work, and what
        // `--raw` controls is only whether it is printed (fact F78-a).
        normalize(&body, Timestamp::now(), true).map_err(FetchError::Parse)
    }
}

/// Rejects an extra header value this build will not put on the wire.
///
/// The account id comes from an id token's claims; it is not this process's
/// own string. A value with a CR or an LF in it would continue the request
/// with headers of the holder's choosing, so the check is for visible ASCII
/// (`0x21..=0x7e`) rather than for those two bytes alone — an account id or a
/// flag has no reason to contain a space either — and it runs before the
/// connection is made.
///
/// # Errors
///
/// [`FetchError::Parse`] naming the header. The value is never included: an
/// error message is the one place a header value most reliably ends up in a
/// log.
fn check_header_value(name: &str, value: &str) -> Result<(), FetchError> {
    if is_visible_ascii(value) {
        Ok(())
    } else {
        Err(FetchError::Parse(format!("the {name} header value cannot be sent")))
    }
}

/// Refuses a request that would go out without the account id header.
///
/// The header is part of the request Codex itself makes (fact F67) and of
/// the exact set plan AC101 pins. The server does not require it (fact
/// F79-a), but a request without it reads the usage of whichever workspace
/// the token defaults to, not necessarily the one the row names — and the
/// Codex credential type drops the header rather than send an id that is not
/// visible ASCII, so an absent header is also how a hostile id arrives here
/// (ledger #274 (c2)). Either way no request is made.
///
/// # Errors
///
/// [`FetchError::Parse`] naming the header.
fn require_account_id(extra: &[(&'static str, String)]) -> Result<(), FetchError> {
    if extra.iter().any(|(name, _)| name.eq_ignore_ascii_case(ACCOUNT_ID_HEADER)) {
        Ok(())
    } else {
        Err(FetchError::Parse(format!("the {ACCOUNT_ID_HEADER} header is missing")))
    }
}

/// Rejects an authorization value that is not `<scheme> <credentials>`.
///
/// Two non-empty visible-ASCII tokens and exactly one space between them —
/// the only shape a bearer header has. An empty value (a document with no
/// access token) is refused too: a request without a token would only earn
/// a 401 that reads like an expired one.
///
/// # Errors
///
/// [`FetchError::Parse`], never including the value, which carries the
/// token.
fn check_authorization(value: &str) -> Result<(), FetchError> {
    let usable = value.split_once(' ').is_some_and(|(scheme, credentials)| {
        is_visible_ascii(scheme) && is_visible_ascii(credentials)
    });
    if usable {
        Ok(())
    } else {
        Err(FetchError::Parse("the authorization header value cannot be sent".to_owned()))
    }
}

/// Whether `value` is non-empty and every byte is visible ASCII.
fn is_visible_ascii(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_graphic())
}

/// Maps a `ureq` failure onto the pass's vocabulary.
///
/// Every arm is transport: a status was never received, so there is nothing
/// to branch on but "the request did not complete". The message is the
/// error's own `Display`, which for `ureq` names the failure class and the
/// host — never a response body, and so never an echoed token.
///
/// A twin of the Claude client's own mapping rather than a shared helper:
/// the two providers' clients are meant to be readable apart, and a five-line
/// match is a smaller cost than a dependency between them.
fn map_transport_error(err: ureq::Error) -> FetchError {
    match err {
        ureq::Error::Timeout(what) => FetchError::Transport(format!("timed out ({what})")),
        other => FetchError::Transport(other.to_string()),
    }
}

/// Turns a usage response into [`CodexUsage`] (plan section 3.5).
///
/// # Errors
///
/// Returns a message when the body is not a JSON object. A body that *is* an
/// object but carries no `rate_limit` is not an error: that is the account
/// with no subscription windows, and [`CodexUsage::state`] reports it.
///
/// With `keep_raw` the body is kept without its top-level `email` member
/// (fact F78-a); every other member is kept as received.
pub fn normalize(
    root: &Value,
    fetched_at: Timestamp,
    keep_raw: bool,
) -> Result<CodexUsage, String> {
    let object = root.as_object().ok_or_else(|| "the response was not a JSON object".to_owned())?;

    let rate_limit = object.get("rate_limit").and_then(Value::as_object);
    let mut windows = Vec::new();
    if let Some(limit) = rate_limit {
        windows.extend(account_windows(limit, fetched_at));
    }
    windows.extend(additional_windows(object.get("additional_rate_limits"), fetched_at));

    let note = note(object, rate_limit);

    Ok(CodexUsage {
        fetched_at,
        windows,
        credits: credits(object),
        plan_type: plan_type(object),
        note,
        raw: keep_raw.then(|| {
            let mut kept = object.clone();
            kept.remove(EMAIL_MEMBER);
            Value::Object(kept)
        }),
        has_rate_limit: rate_limit.is_some(),
    })
}

/// The row's note when the response says a limit is binding (plan section
/// 3.5): the state stays `ok`, because the windows were read.
///
/// The most specific statement wins: the vendor's `rate_limit_reached_type`
/// (an object whose `type` is a vendor enum, fact F67, passed through
/// [`label`]), then `limit_reached`, then `allowed == false`.
fn note(object: &Map<String, Value>, rate_limit: Option<&Map<String, Value>>) -> Option<String> {
    let reached_type = object
        .get("rate_limit_reached_type")
        .and_then(Value::as_object)
        .and_then(|reached| label(reached.get("type")));
    if let Some(kind) = reached_type {
        return Some(format!("limit reached: {kind}"));
    }
    let flag = |name: &str| rate_limit.and_then(|limit| limit.get(name)).and_then(Value::as_bool);
    if flag("limit_reached") == Some(true) {
        return Some("limit reached".to_owned());
    }
    if flag("allowed") == Some(false) {
        return Some("requests are not currently allowed".to_owned());
    }
    None
}

/// The account's own windows, classified by duration (plan section 3.5).
fn account_windows(rate_limit: &Map<String, Value>, fetched_at: Timestamp) -> Vec<CodexWindow> {
    ["primary_window", "secondary_window"]
        .into_iter()
        .filter_map(|slot| rate_limit.get(slot).and_then(Value::as_object))
        .map(|window| CodexWindow {
            window: limit_window(window, duration_kind(window), None, fetched_at),
            limit_name: None,
            metered_feature: None,
            normal_model_slug: None,
        })
        .collect()
}

/// The `additional_rate_limits[]` rows, as continuation windows.
///
/// Each row is a limit of its own — a metered feature with its own pair of
/// windows — so its kind is the vendor's name for it rather than a duration:
/// two rows can both carry a weekly window, and collapsing them onto
/// [`WindowKind::WeeklyAll`] would make the table say the account has two
/// weekly limits with no way to tell which is which.
fn additional_windows(value: Option<&Value>, fetched_at: Timestamp) -> Vec<CodexWindow> {
    let Some(rows) = value.and_then(Value::as_array) else {
        return Vec::new();
    };

    let mut windows = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        let Some(row) = row.as_object() else {
            continue;
        };
        let limit_name = label(row.get("limit_name"));
        let metered_feature = label(row.get("metered_feature"));
        let normal_model_slug = label(row.get("normal_model_slug"));
        let base = limit_name
            .clone()
            .or_else(|| metered_feature.clone())
            .unwrap_or_else(|| format!("additional[{index}]"));

        let Some(limit) = row.get("rate_limit").and_then(Value::as_object) else {
            continue;
        };
        for slot in ["primary_window", "secondary_window"] {
            let Some(window) = limit.get(slot).and_then(Value::as_object) else {
                continue;
            };
            let slot_name = slot.trim_end_matches("_window");
            let kind = WindowKind::Unknown(format!("{base}:{slot_name}"));
            windows.push(CodexWindow {
                window: limit_window(window, kind, Some(base.clone()), fetched_at),
                limit_name: limit_name.clone(),
                metered_feature: metered_feature.clone(),
                normal_model_slug: normal_model_slug.clone(),
            });
        }
    }
    windows
}

/// One window object, in the shared vocabulary.
///
/// `is_active` is `false` for every Codex window: the response says which
/// limit was *reached*, not which one is currently binding, and marking a
/// window active on that evidence would put the marker on the wrong row for
/// every account that is not at a limit.
fn limit_window(
    window: &Map<String, Value>,
    kind: WindowKind,
    scope_label: Option<String>,
    fetched_at: Timestamp,
) -> LimitWindow {
    let percent = window.get("used_percent").and_then(Value::as_f64).and_then(clamp_percent);
    LimitWindow {
        kind,
        percent,
        percent_floor: percent.and_then(percent_floor),
        severity: None,
        resets_at: resets_at(window, fetched_at),
        scope_label,
        is_active: false,
    }
}

/// Which window a duration describes (plan section 3.5).
///
/// Read from `limit_window_seconds` and never from the member's position: on
/// the account W0 captured, `primary_window` is the weekly one.
fn duration_kind(window: &Map<String, Value>) -> WindowKind {
    let Some(seconds) = window.get("limit_window_seconds").and_then(Value::as_i64) else {
        return WindowKind::Unknown(UNKNOWN_DURATION.to_owned());
    };
    if seconds > 0 && seconds <= SESSION_MAX_SECONDS {
        return WindowKind::Session;
    }
    if (WEEKLY_MIN_SECONDS..=WEEKLY_MAX_SECONDS).contains(&seconds) {
        return WindowKind::WeeklyAll;
    }
    match seconds.checked_div(3_600) {
        Some(hours) if hours > 0 => WindowKind::Unknown(format!("{hours}h")),
        _ => WindowKind::Unknown(UNKNOWN_DURATION.to_owned()),
    }
}

/// When a window rolls over.
///
/// `reset_at` is an absolute epoch second and is preferred; `reset_after_seconds`
/// is relative to the moment the response was read and is the fallback. All
/// arithmetic is checked (constraint C-006), so a server sending a value near
/// [`i64::MAX`] yields no timestamp rather than a wrapped one.
fn resets_at(window: &Map<String, Value>, fetched_at: Timestamp) -> Option<Timestamp> {
    if let Some(at) = window.get("reset_at").and_then(Value::as_i64)
        && let Ok(timestamp) = Timestamp::from_second(at)
    {
        return Some(timestamp);
    }
    let after = window.get("reset_after_seconds").and_then(Value::as_i64)?;
    let at = fetched_at.as_second().checked_add(after)?;
    Timestamp::from_second(at).ok()
}

/// A vendor-supplied label, or a placeholder when it is not plain enough.
///
/// The names in `additional_rate_limits[]` are chosen by the vendor and end
/// up in a terminal and in `--json`. Echoing an arbitrary string there would
/// let a response move the cursor or rewrite the line; the allowed set is
/// therefore alphanumerics and a few separators, with `:` excluded so a
/// label can never be mistaken for the `<name>:<slot>` kind string built from
/// it. An absent or non-string member yields `None`; a present one always
/// yields something, because a limit the user is being shown a percentage
/// for should not lose its name silently (risk R3).
fn label(value: Option<&Value>) -> Option<String> {
    let text = value?.as_str()?;
    let plain = !text.is_empty()
        && text.chars().count() <= MAX_LABEL_CHARS
        && !text.starts_with(' ')
        && !text.ends_with(' ')
        && text
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '+' | ' '));
    if plain { Some(text.to_owned()) } else { Some(UNRECOGNISED_LABEL.to_owned()) }
}

/// What the response says about credits (fact F78-b).
fn credits(object: &Map<String, Value>) -> CodexCredits {
    let Some(credits) = object.get("credits").and_then(Value::as_object) else {
        return CodexCredits::Unavailable;
    };
    CodexCredits::Balance {
        balance: balance(credits.get("balance")),
        unlimited: credits.get("unlimited").and_then(Value::as_bool).unwrap_or(false),
    }
}

/// The balance, exactly as the wire spelled it.
///
/// The member is a decimal **string** on this endpoint, and a decimal amount
/// of money that has been through an `f64` is no longer the amount that was
/// sent — so it is kept as text and never parsed into a float. A JSON
/// number is not the documented shape and is treated as no balance: this
/// build's `serde_json` holds a number as an `f64` already, so echoing one
/// would show a rounded amount as if it were the vendor's (review S31 F4).
fn balance(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(text) if is_decimal(text) => Some(text.clone()),
        _ => None,
    }
}

/// Whether a string is a plain decimal figure.
fn is_decimal(text: &str) -> bool {
    let digits = text.strip_prefix('-').unwrap_or(text);
    let (whole, fraction) = match digits.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (digits, None),
    };
    let numeric = |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
    numeric(whole) && fraction.is_none_or(numeric)
}

/// The response's plan type, which overrides the id token's claim.
///
/// A tier this build does not know becomes `unknown` rather than being echoed:
/// the vendor adds tiers without notice, so an unrecognised value is expected,
/// but it is a response-controlled string and the registry is not the place to
/// find that out.
fn plan_type(object: &Map<String, Value>) -> Option<String> {
    let plan = object.get("plan_type")?.as_str()?;
    if is_known_plan(plan) { Some(plan.to_owned()) } else { Some(UNKNOWN_PLAN.to_owned()) }
}

#[cfg(test)]
#[path = "usage_tests.rs"]
mod tests;
