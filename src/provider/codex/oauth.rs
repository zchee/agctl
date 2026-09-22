//! The Codex token endpoint's refresh half: one POST, and the table that
//! decides what its outcome means (decision D-035, fact F65).
//!
//! # One send per grant
//!
//! [`refresh`] is `pub(super)` and consumes an [`InflightToken`], which only
//! the refresh marker's `write_inflight`/`write_resend` produce after the
//! marker file and its directory are `fsync`ed (invariant I26). Its only
//! caller is `refresh.rs`, pinned by plan AC119 and §9.3; from `commands/` a
//! call does not compile (AC122 clause 8).
//!
//! # The class table
//!
//! Pinned to `ureq` 3.4.1 (`Cargo.lock`). A refresh token that reached the
//! server may already be spent, so the table answers one question for every
//! way a request can end: **could the token have been consumed?**
//!
//! | `ureq` result | outcome |
//! |---|---|
//! | a `Cancel` seen before the send | [`RefreshOutcome::PreSend`] |
//! | `HostNotFound`, `Io` with `ConnectionRefused`, `Timeout::{Resolve, Connect}`, `Tls(_)`, `ConnectionFailed` | [`RefreshOutcome::PreSend`] |
//! | 2xx with a readable JSON body carrying `access_token` | [`RefreshOutcome::Applied`] |
//! | 2xx whose body cannot be read, does not parse, or has no `access_token` | [`RefreshOutcome::Ambiguous`] (`ServerBody`) |
//! | 401; 400 with `invalid_grant`; any non-2xx whose error code is `refresh_token_{expired, reused, invalidated}` | [`RefreshOutcome::Permanent`] |
//! | 429 | [`RefreshOutcome::RateLimited`], with `retry-after` |
//! | 5xx | [`RefreshOutcome::ServerError`] |
//! | any other 4xx | [`RefreshOutcome::Rejected`] (answered before processing; risk R67) |
//! | any other status (1xx, 3xx — redirects are not followed) | [`RefreshOutcome::Ambiguous`] (`ServerBody`) |
//! | a TLS failure (`Rustls`, or an `Io` carrying a `rustls::Error`) | [`RefreshOutcome::Ambiguous`] (`Tls`) |
//! | every other `Io` kind; `Timeout::{SendRequest, SendBody, Await100, RecvResponse, RecvBody}` (and `Global`/`PerCall`, never configured); `Protocol`, `BodyStalled`, `BodyExceedsLimit`, `LargeResponseHeader`, `Decompress`, `Json`, `ConnectProxyFailed`, `TlsRequired`, `Pem`, `StatusCode`, `Http`, `BadUri`, `RedirectFailed`, `TooManyRedirects`, `InvalidProxyUrl`, `RequireHttpsOnly`, `Other`; and the `#[non_exhaustive]` wildcard | [`RefreshOutcome::Ambiguous`] (`Transport`) |
//!
//! **The TLS decision (plan ledger #236).** A handshake failure is never
//! `PreSend`. In 3.4.1 the handshake runs inside the connector
//! (`tls/rustls.rs`, `conn.complete_io(..)?`) and its failure reaches the
//! caller as `Error::Io` with kind `InvalidData` wrapping a `rustls::Error` —
//! exactly the shape of a TLS record error while *reading the response*, after
//! the body has gone out. The error carries no phase, so nothing in it proves
//! the request was never written; the tests drive both a server that answers
//! the `ClientHello` with a fatal alert and a self-signed server, and both
//! land here. A handshake that merely takes too long is different: it is
//! bounded by the connect phase, so it surfaces as `Timeout::Connect`, which is
//! `PreSend`. `Error::Tls(&str)` is raised only while the connector is being
//! configured (`rustls invalid dns name`, a PEM that does not parse), before a
//! byte is sent, and stays `PreSend`.
//!
//! # The agent
//!
//! [`refresh_agent`] bounds each of `ureq`'s six phases on its own and never
//! sets a whole-request budget (`timeout_global`/`timeout_per_call`), which
//! would report the earliest configured timeout instead of the phase that
//! actually ran out. `timeout_await_100` stays at its default: no
//! `Expect: 100-continue` is sent, so it never runs. Statuses are responses,
//! not errors (`http_status_as_error(false)`), because a permanent failure is
//! read from the body. Redirects are not followed (`max_redirects(0)`): a
//! refresh token must never be re-POSTed to a `Location` host (review S31 F1).
//! No cookie is stored or sent — this build of `ureq` has no cookie jar (the
//! `cookies` feature is off), and a test pins it, because the token host
//! answers with `set-cookie` (fact F80).

use std::io;
use std::io::Read;
use std::time::Duration;

use jiff::Timestamp;
use secrecy::zeroize::Zeroizing;
use serde_json::Value;

use crate::provider::Provider;
use crate::provider::claude::usage::parse_retry_after;
use crate::provider::codex::auth_store::InflightToken;
use crate::provider::codex::credentials::LockedCredentials;
use crate::provider::codex::credentials::RefreshResponse;
use crate::runtime::coordinator::Cancel;

/// The token endpoint (fact F65). The only spelling of the host in `src/`
/// (plan §9.3).
pub const TOKEN_URL: &str = "https://auth.openai.com/oauth/token";

/// Codex's OAuth client id (fact F65). Presenting it from a client that is not
/// Codex is risk R60, acknowledged by the user at U44.
pub const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";

/// Redirects the token endpoint. Test seam only (plan section 3.9); on the
/// release gate's list of names that must be absent from an artifact.
#[cfg(feature = "testing")]
pub const TOKEN_URL_ENV: &str = "AGCTL_CODEX_TOKEN_URL";

/// Where a `testing` build posts when [`TOKEN_URL_ENV`] is unset or blank: the
/// discard port on loopback, which nothing listens on, so the send fails as a
/// refused connection before a byte leaves the host (review S32-C1 F2). A test
/// binary never falls back to the vendor's token host.
#[cfg(feature = "testing")]
pub const TESTING_FALLBACK_TOKEN_URL: &str = "http://127.0.0.1:9/oauth/token";

/// Name resolution (decision D-035's budget table).
pub const TIMEOUT_RESOLVE: Duration = Duration::from_secs(2);
/// The TCP connection, and the TLS handshake inside it.
pub const TIMEOUT_CONNECT: Duration = Duration::from_secs(3);
/// Writing the request line and headers.
pub const TIMEOUT_SEND_REQUEST: Duration = Duration::from_secs(2);
/// Writing the body.
pub const TIMEOUT_SEND_BODY: Duration = Duration::from_secs(2);
/// Waiting for the response headers.
pub const TIMEOUT_RECV_RESPONSE: Duration = Duration::from_secs(8);
/// Reading the response body.
pub const TIMEOUT_RECV_BODY: Duration = Duration::from_secs(2);

/// The six phase timeouts, in the order `ureq` runs them.
pub const PHASE_TIMEOUTS: [Duration; 6] = [
    TIMEOUT_RESOLVE,
    TIMEOUT_CONNECT,
    TIMEOUT_SEND_REQUEST,
    TIMEOUT_SEND_BODY,
    TIMEOUT_RECV_RESPONSE,
    TIMEOUT_RECV_BODY,
];

/// The largest token response this module reads, decoded. A real response is
/// a few kilobytes (fact F80: three tokens and a 1 KB opaque member).
pub const MAX_RESPONSE_BYTES: u64 = 256 * 1024;

/// Error codes Codex treats as a dead refresh token, compared ignoring ASCII
/// case (`login/src/auth/manager.rs`, `classify_refresh_token_failure`).
const PERMANENT_CODES: [(&str, PermanentClass); 3] = [
    ("refresh_token_expired", PermanentClass::Expired),
    ("refresh_token_reused", PermanentClass::Reused),
    ("refresh_token_invalidated", PermanentClass::Invalidated),
];

/// Why a refresh's outcome is unknown, for the marker and `doctor`'s label
/// (plan ledger #236).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmbiguousClass {
    /// The request may have reached the server and no response was read.
    Transport,
    /// A response came back that is not one of the documented answers: a 2xx
    /// body that cannot be used, or a status outside the table.
    ServerBody,
    /// A TLS failure, during the handshake or after it (risk R69).
    Tls,
    /// The response was applied and the credential could not be written
    /// (plan section 3.3). Never produced by [`refresh`]; the refresh driver
    /// records it.
    WriteFailed,
}

impl AmbiguousClass {
    /// The label a row and an audit line carry.
    pub fn label(self) -> &'static str {
        match self {
            Self::Transport | Self::ServerBody => "ambiguous",
            Self::Tls => "tls",
            Self::WriteFailed => "write_failed",
        }
    }
}

/// Which dead-grant answer the server gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermanentClass {
    /// A 401.
    Unauthorized,
    /// A 400 whose error code is `invalid_grant`.
    InvalidGrant,
    /// `refresh_token_expired`.
    Expired,
    /// `refresh_token_reused`.
    Reused,
    /// `refresh_token_invalidated`.
    Invalidated,
}

impl PermanentClass {
    /// The label a row and an audit line carry.
    pub fn label(self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::InvalidGrant => "invalid_grant",
            Self::Expired => "refresh_token_expired",
            Self::Reused => "refresh_token_reused",
            Self::Invalidated => "refresh_token_invalidated",
        }
    }
}

/// How one refresh POST ended. There is no `Cancelled`: a cancel is
/// observable only before the send, where it is [`RefreshOutcome::PreSend`]
/// (plan ledger #198).
pub enum RefreshOutcome {
    /// A usable response: fold it into the file.
    Applied(RefreshResponse),
    /// The grant is dead.
    Permanent(PermanentClass),
    /// Proven never sent. The reason names the failure, never a token.
    PreSend(String),
    /// A 4xx other than 429, answered before the token was processed (R67).
    Rejected(u16),
    /// A 429. Whether the token was consumed is unknown.
    RateLimited {
        /// The server's `retry-after`, when it sent a readable one.
        retry_after: Option<Duration>,
    },
    /// A 5xx. Whether the token was consumed is unknown.
    ServerError(u16),
    /// Everything else: the token may have been consumed.
    Ambiguous(AmbiguousClass),
}

impl std::fmt::Debug for RefreshOutcome {
    /// The class only; an `Applied` response prints which members came back.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Applied(response) => f.debug_tuple("Applied").field(response).finish(),
            Self::Permanent(class) => f.debug_tuple("Permanent").field(class).finish(),
            Self::PreSend(reason) => f.debug_tuple("PreSend").field(reason).finish(),
            Self::Rejected(status) => f.debug_tuple("Rejected").field(status).finish(),
            Self::RateLimited { retry_after } => {
                f.debug_struct("RateLimited").field("retry_after", retry_after).finish()
            }
            Self::ServerError(status) => f.debug_tuple("ServerError").field(status).finish(),
            Self::Ambiguous(class) => f.debug_tuple("Ambiguous").field(class).finish(),
        }
    }
}

/// The agent every refresh POST goes through (decision D-035's budget table).
pub fn refresh_agent(user_agent: &str) -> ureq::Agent {
    agent_with(user_agent, PHASE_TIMEOUTS)
}

/// [`refresh_agent`] with the six phases given, so a test can exercise a
/// timeout row without waiting the production budget out.
fn agent_with(user_agent: &str, phases: [Duration; 6]) -> ureq::Agent {
    let [resolve, connect, send_request, send_body, recv_response, recv_body] = phases;
    let config = ureq::config::Config::builder()
        .timeout_resolve(Some(resolve))
        .timeout_connect(Some(connect))
        .timeout_send_request(Some(send_request))
        .timeout_send_body(Some(send_body))
        .timeout_recv_response(Some(recv_response))
        .timeout_recv_body(Some(recv_body))
        .http_status_as_error(false)
        .max_redirects(0)
        .user_agent(user_agent)
        .build();
    ureq::Agent::new_with_config(config)
}

/// The token endpoint and the agent that reaches it.
#[derive(Debug)]
pub struct RefreshClient {
    token_url: String,
    agent: ureq::Agent,
}

impl RefreshClient {
    /// A client for an explicit token URL.
    pub fn new(token_url: &str, user_agent: &str) -> Self {
        Self { token_url: token_url.to_owned(), agent: refresh_agent(user_agent) }
    }

    /// The client this process should use: [`TOKEN_URL`] with agctl's own
    /// user agent (fact F93: the token host needs no Codex header). Under the
    /// `testing` feature [`TOKEN_URL_ENV`] points it at a fake endpoint, which
    /// is the only way any test in this crate sends a refresh, and an unset
    /// seam fails closed to [`TESTING_FALLBACK_TOKEN_URL`], never the vendor.
    pub fn from_env() -> Self {
        #[cfg(feature = "testing")]
        let url = std::env::var(TOKEN_URL_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| TESTING_FALLBACK_TOKEN_URL.to_owned());
        #[cfg(not(feature = "testing"))]
        let url = TOKEN_URL.to_owned();
        Self::new(&url, &crate::provider::user_agent(Provider::Codex))
    }

    /// The token URL this client posts to.
    pub fn token_url(&self) -> &str {
        &self.token_url
    }
}

/// Sends one refresh POST and classifies how it ended.
///
/// Consumes `token`, which exists only after the marker recording this send
/// is durable, and which must be the one written for `credentials`' grant: a
/// token for another grant is refused before anything is sent. The body is
/// built from `credentials` into a buffer that is zeroed when this returns
/// (review S30 F9), and nothing here logs a body, a token or a header value.
pub(super) fn refresh<'g>(
    credentials: &LockedCredentials<'g>,
    token: InflightToken<'g>,
    client: &RefreshClient,
    cancel: &Cancel,
) -> RefreshOutcome {
    if credentials.refresh_digest8().as_deref() != Some(token.digest8()) {
        return RefreshOutcome::PreSend(
            "the marker records a different grant than the one to send".to_owned(),
        );
    }
    if cancel.is_cancelled() {
        return RefreshOutcome::PreSend("cancelled before the send".to_owned());
    }
    let mut body = Zeroizing::new(Vec::new());
    if let Err(err) = credentials.write_refresh_body_to(&mut *body, CLIENT_ID) {
        return RefreshOutcome::PreSend(format!(
            "the request body could not be built: {}",
            err.kind()
        ));
    }
    drop(token);

    let sent = client
        .agent
        .post(&client.token_url)
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .send(&body[..]);
    let mut response = match sent {
        Ok(response) => response,
        Err(err) => return classify_error(err),
    };

    let status = response.status().as_u16();
    let retry_after = response
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| parse_retry_after(value, Timestamp::now()));
    let text = read_body(&mut response);
    classify_response(status, retry_after, text.as_deref().map(|bytes| &bytes[..]))
}

/// The body, decoded and capped, or `None` when it could not be read whole.
fn read_body(response: &mut ureq::http::Response<ureq::Body>) -> Option<Zeroizing<Vec<u8>>> {
    let mut decoded = Zeroizing::new(Vec::new());
    response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES)
        .reader()
        .take(MAX_RESPONSE_BYTES.saturating_add(1))
        .read_to_end(&mut decoded)
        .ok()?;
    u64::try_from(decoded.len()).is_ok_and(|len| len <= MAX_RESPONSE_BYTES).then_some(decoded)
}

/// A received response's class (the status half of the table).
fn classify_response(
    status: u16,
    retry_after: Option<Duration>,
    body: Option<&[u8]>,
) -> RefreshOutcome {
    if (200..300).contains(&status) {
        let Some(body) = body else { return RefreshOutcome::Ambiguous(AmbiguousClass::ServerBody) };
        return match RefreshResponse::parse(body) {
            Ok(response) if response.has_access_token() => RefreshOutcome::Applied(response),
            Ok(_) | Err(_) => RefreshOutcome::Ambiguous(AmbiguousClass::ServerBody),
        };
    }
    let code = body.and_then(error_code);
    if let Some(code) = code.as_deref()
        && let Some((_, class)) =
            PERMANENT_CODES.iter().find(|(name, _)| name.eq_ignore_ascii_case(code))
    {
        return RefreshOutcome::Permanent(*class);
    }
    match status {
        401 => RefreshOutcome::Permanent(PermanentClass::Unauthorized),
        400 if code.as_deref().is_some_and(|code| code.eq_ignore_ascii_case("invalid_grant")) => {
            RefreshOutcome::Permanent(PermanentClass::InvalidGrant)
        }
        429 => RefreshOutcome::RateLimited { retry_after },
        500..=599 => RefreshOutcome::ServerError(status),
        400..=499 => RefreshOutcome::Rejected(status),
        _ => RefreshOutcome::Ambiguous(AmbiguousClass::ServerBody),
    }
}

/// The error code of a failure body, where Codex looks for it: `error` as a
/// string, `error.code`, or a top-level `code`.
fn error_code(body: &[u8]) -> Option<String> {
    let Value::Object(map) = serde_json::from_slice::<Value>(body).ok()? else { return None };
    match map.get("error") {
        Some(Value::String(code)) => return Some(code.clone()),
        Some(Value::Object(error)) => {
            if let Some(code) = error.get("code").and_then(Value::as_str) {
                return Some(code.to_owned());
            }
        }
        _ => {}
    }
    map.get("code").and_then(Value::as_str).map(str::to_owned)
}

/// A request that produced no response: the transport half of the table.
fn classify_error(err: ureq::Error) -> RefreshOutcome {
    use ureq::Error;
    use ureq::Timeout;

    match err {
        Error::HostNotFound => RefreshOutcome::PreSend("host not found".to_owned()),
        Error::Io(io) if io.kind() == io::ErrorKind::ConnectionRefused => {
            RefreshOutcome::PreSend("connection refused".to_owned())
        }
        Error::Timeout(Timeout::Resolve) => {
            RefreshOutcome::PreSend("timed out resolving the host".to_owned())
        }
        Error::Timeout(Timeout::Connect) => {
            RefreshOutcome::PreSend("timed out connecting".to_owned())
        }
        Error::Tls(what) => RefreshOutcome::PreSend(format!("tls configuration: {what}")),
        Error::ConnectionFailed => RefreshOutcome::PreSend("connection failed".to_owned()),
        Error::Rustls(_) => RefreshOutcome::Ambiguous(AmbiguousClass::Tls),
        Error::Io(io) if carries_rustls_error(&io) => {
            RefreshOutcome::Ambiguous(AmbiguousClass::Tls)
        }
        // Every other I/O kind, `Protocol`, `BodyExceedsLimit`, `Json`,
        // `LargeResponseHeader`, `ConnectProxyFailed`, the remaining timeouts
        // and every variant a later `ureq` adds: the token may have gone out.
        _ => RefreshOutcome::Ambiguous(AmbiguousClass::Transport),
    }
}

/// Whether an I/O error is a TLS failure: `rustls` reports through `io::Error`
/// with the `rustls::Error` as its payload.
fn carries_rustls_error(err: &io::Error) -> bool {
    err.get_ref().is_some_and(|inner| inner.downcast_ref::<rustls::Error>().is_some())
}

#[cfg(test)]
#[path = "oauth_tests.rs"]
mod tests;
