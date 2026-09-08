//! The OAuth client: PKCE, the authorize URL, the loopback callback, and the
//! two token grants.
//!
//! # Why this is hand-rolled rather than built on `oauth2`
//!
//! Two properties of Anthropic's endpoint put it outside what the `oauth2`
//! crate models. The token endpoint takes a **JSON** request body, not the
//! `application/x-www-form-urlencoded` body RFC 6749 specifies and that crate
//! sends; and the manual mode hands the user one `code#state` string to paste
//! rather than a redirect URI to open. Adopting `oauth2` would mean replacing
//! its request serializer and its redirect handling, which is most of what it
//! does, so the flow is written out here instead (plan section 2). What is
//! left is small: two POSTs, one GET, one URL builder, and a listener that
//! accepts exactly one request.
//!
//! # Two things about the response type
//!
//! Both were discovered while lane A landed [`TokenResponse`], and both still
//! shape this module:
//!
//! - `SecretString` in secrecy 0.10 is `SecretBox<str>`, and `str` is neither
//!   `Sized` nor `Clone`. So [`TokenResponse`] cannot `#[derive(Clone)]`, and
//!   it cannot `#[derive(Deserialize)]` either — the crate's blanket impl is
//!   `SecretBox<T> where T: Zeroize + Clone + DeserializeOwned + Sized`, which
//!   `str` fails on three counts. It is deserialized through the private
//!   [`TokenResponseWire`] mirror below and converted over.
//! - For the same reason, anything that consumes a response takes it **by
//!   value**. Copying a token out of a `&TokenResponse` would mean exposing
//!   the plaintext at a third call site, and invariant I6 allows exactly two
//!   in the whole crate.
//!
//! # Secrets in this module
//!
//! Nothing here exposes a stored token. The refresh POST body is built by
//! [`Credentials::refresh_body`] and the profile `Authorization` header by
//! [`Credentials::authorization_header`], both of which route through the one
//! exposure site in `credentials.rs`.
//!
//! The PKCE verifier is the one piece of secret-ish material this module holds
//! itself, and it is deliberately **not** a `SecretString`: reading one back
//! would be that third exposure site. It is a single-use nonce that lives for
//! one login, is never written anywhere, and is zeroized when [`Pkce`] drops;
//! its `Debug` prints `<redacted>` so it cannot reach a log line. The
//! trade — one plain `String` in memory for a hard, greppable ceiling on
//! exposure sites — is the one invariant I6 asks for.
//!
//! # Cancellation
//!
//! `ureq` is blocking and cannot be interrupted mid-request, so cancellation
//! is observed at the points where this module is *between* requests: before
//! each POST, during the rate-limit backoff, and on every poll of the loopback
//! listener. A request already in flight is bounded by its own timeout
//! ([`TOKEN_TIMEOUT`], [`PROFILE_TIMEOUT`]) instead.

use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;
use std::time::Duration;
use std::time::Instant;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::Rng;
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::Map;
use serde_json::Value;
use sha2::Digest;
use sha2::Sha256;
use url::Url;

use crate::error::AppError;
use crate::provider::claude::credentials::CLIENT_ID;
use crate::provider::claude::credentials::Credentials;
use crate::provider::claude::credentials::CredentialsError;
use crate::provider::claude::credentials::DEFAULT_SCOPES;
use crate::provider::claude::credentials::TokenAccount;
use crate::runtime::coordinator::Cancel;

/// Where a subscription login starts (fact F9).
///
/// Phase 1 is subscription-only (constraint C-001), so this is the only base
/// the client uses; [`AUTHORIZE_URL_CONSOLE`] records the other one.
pub const AUTHORIZE_URL_CLAUDE_AI: &str = "https://claude.com/cai/oauth/authorize";

/// Where a **console** (API-account) login would start (fact F9).
///
/// Unused in phase 1 and kept as documentation of the other half of fact F9,
/// so a future console mode does not have to rediscover it.
#[expect(dead_code, reason = "the console flow is out of scope until phase 2 (C-001)")]
pub const AUTHORIZE_URL_CONSOLE: &str = "https://platform.claude.com/oauth/authorize";

/// The token endpoint, for both grants (facts F8, F25).
pub const TOKEN_URL: &str = "https://platform.claude.com/v1/oauth/token";

/// The identity fallback endpoint (fact F26).
pub const PROFILE_URL: &str = "https://api.anthropic.com/api/oauth/profile";

/// Where the authorization server sends the user in manual mode, which
/// displays a `code#state` string to paste back (fact F9).
pub const MANUAL_REDIRECT_URI: &str = "https://platform.claude.com/oauth/code/callback";

/// The time budget for one call to the token endpoint (fact F8).
pub const TOKEN_TIMEOUT: Duration = Duration::from_secs(30);

/// The time budget for the profile call (fact F26).
pub const PROFILE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the loopback listener waits for the browser to come back.
pub const LOOPBACK_TIMEOUT: Duration = Duration::from_secs(600);

/// How often the loopback listener re-checks for a connection, cancellation
/// and its deadline.
pub const LOOPBACK_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// The floor on the wait before a rate-limited exchange is retried.
///
/// The token endpoint answers 429 with no `retry-after` header (probe S3), so
/// there is nothing to honour and a floor is what is left. The observed 429
/// did **not** consume the authorization code, which is what makes retrying
/// with the same code correct rather than a way to burn the login.
pub const RATE_LIMIT_RETRY_MIN: Duration = Duration::from_secs(5);

/// How much of a failing response body is kept for the error message.
pub const MAX_ERROR_BODY_BYTES: usize = 512;

/// The largest token response that will be read.
const MAX_RESPONSE_BYTES: u64 = 1 << 20;

/// The environment variable that replaces the requested scope set.
pub const SCOPES_ENV: &str = "AGENTCTL_CLAUDE_OAUTH_SCOPES";

/// Test-only override for the token endpoint (plan section 3.9).
#[cfg(feature = "testing")]
pub const TOKEN_URL_ENV: &str = "AGENTCTL_CLAUDE_TOKEN_URL";

/// Test-only override for the authorize endpoint (plan section 3.9).
#[cfg(feature = "testing")]
pub const AUTHORIZE_URL_ENV: &str = "AGENTCTL_CLAUDE_AUTHORIZE_URL";

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
    ///
    /// Anchored to the original login: probe S3 saw it fall from 2 377 445 to
    /// 2 375 685 over half an hour of refreshing, so a rotation does not reset
    /// the refresh chain's own expiry.
    pub refresh_token_expires_in: Option<i64>,
    /// The granted scopes, space-separated.
    pub scope: Option<String>,
    /// Always `Bearer` in practice; anything else is warned about in
    /// [`to_credentials`].
    pub token_type: Option<String>,
    /// The account the token belongs to; half of the namespace key (D-008).
    pub account: Option<ExchangeAccount>,
    /// The organization the token belongs to; the other half.
    pub organization: Option<ExchangeOrganization>,
    /// The workspace block, kept untyped because only its `id` and `name` are
    /// read, and only to fill `tokenAccount` (fact F4). Observed `null`.
    pub workspace: Option<Value>,
}

impl std::fmt::Debug for TokenResponse {
    /// Prints everything except the tokens.
    ///
    /// Hand-written rather than derived. `SecretString`'s own `Debug` does
    /// redact, so a derived impl would happen to be safe today, but that
    /// safety would then depend on a dependency's formatting choice rather
    /// than on anything stated here — and this type is what a failing HTTP
    /// test prints.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"<redacted>")
            .field("refresh_token", &self.refresh_token.as_ref().map(|_| "<redacted>"))
            .field("expires_in", &self.expires_in)
            .field("refresh_token_expires_in", &self.refresh_token_expires_in)
            .field("scope", &self.scope)
            .field("token_type", &self.token_type)
            .field("account", &self.account)
            .field("organization", &self.organization)
            .field("workspace", &self.workspace)
            .finish()
    }
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

/// The wire form of [`TokenResponse`], with plain `String` tokens.
///
/// Exists only because `SecretString` cannot derive `Deserialize` (see the
/// module documentation). Unknown keys are ignored rather than rejected, which
/// is what let the endpoint add `token_uuid` after the fixture was captured
/// without breaking this build.
#[derive(Debug, Deserialize)]
struct TokenResponseWire {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: i64,
    refresh_token_expires_in: Option<i64>,
    scope: Option<String>,
    token_type: Option<String>,
    account: Option<ExchangeAccount>,
    organization: Option<ExchangeOrganization>,
    workspace: Option<Value>,
}

impl From<TokenResponseWire> for TokenResponse {
    fn from(wire: TokenResponseWire) -> Self {
        Self {
            access_token: SecretString::from(wire.access_token),
            refresh_token: wire.refresh_token.map(SecretString::from),
            expires_in: wire.expires_in,
            refresh_token_expires_in: wire.refresh_token_expires_in,
            scope: wire.scope,
            token_type: wire.token_type,
            account: wire.account,
            organization: wire.organization,
            workspace: wire.workspace,
        }
    }
}

/// Why an OAuth step failed.
#[derive(Debug, thiserror::Error)]
pub enum OauthError {
    /// The grant was rejected as dead. Never retried (risk R26).
    #[error("the grant was rejected (invalid_grant); run `agentctl claude login`")]
    InvalidGrant,

    /// The `state` that came back is not the one that went out.
    #[error("the authorization response carried the wrong `state`; nothing was written")]
    StateMismatch,

    /// The authorization server refused before any code was issued — the user
    /// declined, or the request itself was rejected.
    #[error("the authorization request was refused: {0}")]
    Refused(String),

    /// The endpoint answered with a status this step cannot use.
    #[error("HTTP {status}: {body}")]
    Http {
        /// The status as received.
        status: u16,
        /// At most [`MAX_ERROR_BODY_BYTES`] of the body, with any token
        /// material replaced.
        body: String,
    },

    /// The request never completed.
    #[error("could not reach the authorization server: {0}")]
    Transport(String),

    /// The run was cancelled between requests.
    #[error("cancelled")]
    Cancelled,

    /// A deadline passed while waiting.
    #[error("timed out waiting for the authorization response")]
    Timeout,

    /// The stored credentials could not produce a request.
    #[error(transparent)]
    Credentials(#[from] CredentialsError),
}

/// Where the authorization server should send the user back to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Redirect {
    /// Show the user a `code#state` string to paste (fact F9).
    Manual,
    /// Come back to a loopback listener on this port.
    Loopback {
        /// The port `127.0.0.1` is listening on.
        port: u16,
    },
}

impl Redirect {
    /// The `redirect_uri` this mode sends in both the authorize URL and the
    /// exchange body. The two must match exactly or the exchange is rejected.
    pub fn uri(&self) -> String {
        match self {
            Self::Manual => MANUAL_REDIRECT_URI.to_owned(),
            Self::Loopback { port } => format!("http://localhost:{port}/callback"),
        }
    }
}

/// One login's PKCE material (RFC 7636) plus its CSRF `state`.
///
/// The verifier is private and zeroized on drop; see the module documentation
/// for why it is a `String` rather than a `SecretString`.
pub struct Pkce {
    verifier: String,
    /// `BASE64URL(SHA256(verifier))`, unpadded — the `code_challenge`.
    pub challenge: String,
    /// 32 random bytes, base64url-unpadded — the `state`.
    pub state: String,
}

impl std::fmt::Debug for Pkce {
    /// Prints the challenge and state but never the verifier.
    ///
    /// Hand-written rather than derived for the same reason `Credentials` is:
    /// a derived `Debug` would put the verifier into any `tracing` line that
    /// formatted one.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkce")
            .field("verifier", &"<redacted>")
            .field("challenge", &self.challenge)
            .field("state", &self.state)
            .finish()
    }
}

impl Drop for Pkce {
    fn drop(&mut self) {
        // `secrecy` re-exports `zeroize`, so this needs no dependency of its
        // own. Best effort: a `String` that reallocated during construction
        // may have left a copy behind, which is why the verifier is generated
        // at its final length and never grown.
        secrecy::zeroize::Zeroize::zeroize(&mut self.verifier);
    }
}

/// Generates a fresh verifier, its challenge, and a `state`.
///
/// 32 bytes each, from `rand`'s thread RNG — a reseeding ChaCha12 CSPRNG, not
/// the arithmetic generator the name might suggest. Base64url-unpadded gives
/// 43 characters, inside RFC 7636's 43..=128 range.
pub fn pkce() -> Pkce {
    let verifier = URL_SAFE_NO_PAD.encode(random_bytes());
    let challenge = code_challenge(&verifier);
    Pkce { verifier, challenge, state: URL_SAFE_NO_PAD.encode(random_bytes()) }
}

/// The S256 code challenge for a verifier (RFC 7636 section 4.2).
pub fn code_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// 32 cryptographically random bytes.
fn random_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

/// The scopes to request at login.
///
/// The five scopes a live Claude Code credential carries (facts F4, F28).
/// `AGENTCTL_CLAUDE_OAUTH_SCOPES` replaces the set, space-separated; probe S3
/// showed the server grants exactly these five whatever is asked for, so the
/// override is a diagnostic rather than a feature.
pub fn requested_scopes() -> Vec<String> {
    match std::env::var(SCOPES_ENV) {
        Ok(raw) if !raw.trim().is_empty() => raw.split_whitespace().map(str::to_owned).collect(),
        _ => DEFAULT_SCOPES.iter().map(|scope| (*scope).to_owned()).collect(),
    }
}

/// The endpoints and the HTTP agents one login or refresh talks through.
pub struct OauthClient {
    authorize_url: String,
    token_url: String,
    profile_url: String,
    client_id: String,
    user_agent: String,
    token_agent: ureq::Agent,
    profile_agent: ureq::Agent,
}

impl OauthClient {
    /// Builds a client for the real endpoints.
    ///
    /// With the `testing` feature, `AGENTCTL_CLAUDE_TOKEN_URL` and
    /// `AGENTCTL_CLAUDE_AUTHORIZE_URL` redirect the two endpoints at a mock
    /// server. Both are compiled out otherwise: a release build that could be
    /// pointed at an arbitrary token endpoint by an environment variable is an
    /// exfiltration vector (plan section 3.9, AC37).
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Config`] when an endpoint override is not a URL.
    pub fn from_env(user_agent: &str) -> Result<Self, AppError> {
        let authorize = url_override(AUTHORIZE_URL_ENV_NAME).unwrap_or_else(default_authorize_url);
        let token = url_override(TOKEN_URL_ENV_NAME).unwrap_or_else(|| TOKEN_URL.to_owned());
        Self::with_endpoints(&authorize, &token, PROFILE_URL, user_agent)
    }

    /// Builds a client against explicit endpoints.
    ///
    /// Crate-internal, and the only constructor that takes URLs: the
    /// production path reaches it through [`OauthClient::from_env`], and the
    /// tests reach it directly rather than by mutating the process
    /// environment, which is `unsafe` in edition 2024 and would race every
    /// other test in the binary.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Config`] when a URL does not parse.
    pub fn with_endpoints(
        authorize_url: &str,
        token_url: &str,
        profile_url: &str,
        user_agent: &str,
    ) -> Result<Self, AppError> {
        for url in [authorize_url, token_url, profile_url] {
            Url::parse(url).map_err(|err| {
                AppError::Config(format!("`{url}` is not a usable OAuth endpoint: {err}"))
            })?;
        }
        Ok(Self {
            authorize_url: authorize_url.to_owned(),
            token_url: token_url.to_owned(),
            profile_url: profile_url.to_owned(),
            client_id: CLIENT_ID.to_owned(),
            user_agent: user_agent.to_owned(),
            token_agent: agent(TOKEN_TIMEOUT),
            profile_agent: agent(PROFILE_TIMEOUT),
        })
    }
}

/// Builds an agent whose whole operation is bounded by `timeout`.
///
/// `http_status_as_error(false)` matters: a 4xx has a body naming *why*, and
/// turning the status into an error before the body is read would throw that
/// away and leave every failure spelled `HTTP 400`.
fn agent(timeout: Duration) -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .http_status_as_error(false)
        .build();
    ureq::Agent::new_with_config(config)
}

/// The authorize endpoint used when nothing overrides it.
fn default_authorize_url() -> String {
    AUTHORIZE_URL_CLAUDE_AI.to_owned()
}

/// The name of the token-endpoint override, or `None` in a release build.
#[cfg(feature = "testing")]
const TOKEN_URL_ENV_NAME: Option<&str> = Some(TOKEN_URL_ENV);

/// The name of the token-endpoint override, or `None` in a release build.
#[cfg(not(feature = "testing"))]
const TOKEN_URL_ENV_NAME: Option<&str> = None;

/// The name of the authorize-endpoint override, or `None` in a release build.
#[cfg(feature = "testing")]
const AUTHORIZE_URL_ENV_NAME: Option<&str> = Some(AUTHORIZE_URL_ENV);

/// The name of the authorize-endpoint override, or `None` in a release build.
#[cfg(not(feature = "testing"))]
const AUTHORIZE_URL_ENV_NAME: Option<&str> = None;

/// Reads an endpoint override, if this build has one to read.
fn url_override(name: Option<&str>) -> Option<String> {
    let value = std::env::var(name?).ok()?;
    if value.trim().is_empty() { None } else { Some(value) }
}

/// Builds the URL the user opens to authorize this login (fact F9).
///
/// The parameter order is Claude Code's, reproduced exactly: `code`,
/// `client_id`, `response_type`, `redirect_uri`, `scope`, `code_challenge`,
/// `code_challenge_method`, `state`. Order is not supposed to matter to an
/// OAuth server and almost certainly does not here, but this URL is the one
/// piece of the flow a human reads and compares against a working client, so
/// it is worth being byte-comparable.
///
/// # Errors
///
/// Returns [`OauthError::Refused`] when the configured authorize URL does not
/// parse, which [`OauthClient::with_endpoints`] has already ruled out for any
/// client that exists.
pub fn authorize_url(
    client: &OauthClient,
    pkce: &Pkce,
    redirect: &Redirect,
    scopes: &[String],
) -> Result<Url, OauthError> {
    let mut url = Url::parse(&client.authorize_url)
        .map_err(|err| OauthError::Refused(format!("the authorize URL is unusable: {err}")))?;
    url.query_pairs_mut()
        .append_pair("code", "true")
        .append_pair("client_id", &client.client_id)
        .append_pair("response_type", "code")
        .append_pair("redirect_uri", &redirect.uri())
        .append_pair("scope", &scopes.join(" "))
        .append_pair("code_challenge", &pkce.challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", &pkce.state);
    Ok(url)
}

/// Splits the `code#state` string the manual redirect displays (fact F9).
///
/// Split at the **first** `#`: the code is opaque and a later `#` belongs to
/// the state, not to a second separator.
///
/// # Errors
///
/// Returns [`OauthError::Refused`] when the input has no separator or either
/// half is empty, which is what a half-copied paste looks like.
pub fn parse_manual_code(input: &str) -> Result<(String, String), OauthError> {
    let text = input.trim();
    let Some((code, state)) = text.split_once('#') else {
        return Err(OauthError::Refused(
            "expected a `code#state` value; the pasted text has no `#`".to_owned(),
        ));
    };
    let (code, state) = (code.trim(), state.trim());
    if code.is_empty() || state.is_empty() {
        return Err(OauthError::Refused(
            "expected a `code#state` value; one half of the pasted text is empty".to_owned(),
        ));
    }
    Ok((code.to_owned(), state.to_owned()))
}

/// Checks a returned `state` against the one this login sent.
///
/// The loopback path checks it inside [`loopback_wait`]; the manual path,
/// where the user pastes both halves, checks it here. Same comparison either
/// way, and a mismatch means nothing is written (AC12).
///
/// # Errors
///
/// Returns [`OauthError::StateMismatch`].
pub fn verify_state(expected: &str, actual: &str) -> Result<(), OauthError> {
    if constant_time_eq(expected.as_bytes(), actual.as_bytes()) {
        Ok(())
    } else {
        Err(OauthError::StateMismatch)
    }
}

/// Exchanges an authorization code for tokens (facts F9, F25).
///
/// A 429 is retried **once**, after `max(retry-after, RATE_LIMIT_RETRY_MIN)`.
/// Probe S3 established that the token endpoint's rate limit does not consume
/// the authorization code, so the same code is sent again; without that fact
/// the retry would risk turning a transient limit into a lost login.
///
/// # Errors
///
/// See [`OauthError`]. `invalid_grant` means the code is spent or wrong and is
/// never retried.
pub fn exchange(
    client: &OauthClient,
    code: &str,
    state: &str,
    pkce: &Pkce,
    redirect: &Redirect,
    cancel: &Cancel,
) -> Result<TokenResponse, OauthError> {
    exchange_with_backoff(client, code, state, pkce, redirect, cancel, RATE_LIMIT_RETRY_MIN)
}

/// [`exchange`] with the retry floor supplied, so a test does not have to wait
/// five seconds to prove the retry happens.
fn exchange_with_backoff(
    client: &OauthClient,
    code: &str,
    state: &str,
    pkce: &Pkce,
    redirect: &Redirect,
    cancel: &Cancel,
    retry_floor: Duration,
) -> Result<TokenResponse, OauthError> {
    let body = exchange_body(client, code, state, pkce, redirect);

    match post_token(client, &body, cancel) {
        Ok(response) => Ok(response),
        Err(failure) if failure.is_rate_limited() => {
            let wait = failure.retry_after.unwrap_or(retry_floor).max(retry_floor);
            tracing::warn!(
                "the token endpoint is rate limited; retrying once in {}s",
                wait.as_secs()
            );
            if cancel.wait_timeout(wait) {
                return Err(OauthError::Cancelled);
            }
            post_token(client, &body, cancel).map_err(|failure| failure.error)
        }
        Err(failure) => Err(failure.error),
    }
}

/// The exchange request body (fact F9).
fn exchange_body(
    client: &OauthClient,
    code: &str,
    state: &str,
    pkce: &Pkce,
    redirect: &Redirect,
) -> String {
    let mut body = Map::new();
    body.insert("grant_type".to_owned(), Value::String("authorization_code".to_owned()));
    body.insert("code".to_owned(), Value::String(code.to_owned()));
    body.insert("redirect_uri".to_owned(), Value::String(redirect.uri()));
    body.insert("client_id".to_owned(), Value::String(client.client_id.clone()));
    body.insert("code_verifier".to_owned(), Value::String(pkce.verifier.clone()));
    body.insert("state".to_owned(), Value::String(state.to_owned()));
    Value::Object(body).to_string()
}

/// Trades the stored refresh token for a new access token (fact F8).
///
/// A 429 here is **not** retried: it becomes `Http { status: 429 }`, which the
/// caller renders as `rate limited` and treats as transient. Retrying inside a
/// refresh would hold the namespace lock across the wait, and the next pass
/// will try again anyway.
///
/// # Errors
///
/// See [`OauthError`]. `invalid_grant` means the refresh chain is dead and
/// only a fresh login recovers it (risk R26, AC29) — it is never transient.
#[cfg_attr(not(test), expect(dead_code, reason = "the refresh path lands with lane C"))]
pub fn refresh(
    client: &OauthClient,
    creds: &Credentials,
    cancel: &Cancel,
) -> Result<TokenResponse, OauthError> {
    let body = creds.refresh_body(&client.client_id)?;
    post_token(client, &body, cancel).map_err(|failure| failure.error)
}

/// A token-endpoint failure, plus the hint needed to decide about retrying.
struct TokenFailure {
    error: OauthError,
    retry_after: Option<Duration>,
}

impl TokenFailure {
    /// Whether this is the transient rate limit probe S3 characterised.
    fn is_rate_limited(&self) -> bool {
        matches!(self.error, OauthError::Http { status: 429, .. })
    }

    /// Wraps an error that carries no retry hint.
    fn plain(error: OauthError) -> Self {
        Self { error, retry_after: None }
    }
}

/// POSTs a JSON body to the token endpoint and parses what comes back.
fn post_token(
    client: &OauthClient,
    body: &str,
    cancel: &Cancel,
) -> Result<TokenResponse, TokenFailure> {
    if cancel.is_cancelled() {
        return Err(TokenFailure::plain(OauthError::Cancelled));
    }

    let sent = client
        .token_agent
        .post(&client.token_url)
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .header("user-agent", &client.user_agent)
        .send(body);

    let mut response = match sent {
        Ok(response) => response,
        Err(err) => return Err(TokenFailure::plain(transport_error(err))),
    };

    let status = response.status().as_u16();
    let retry_after = retry_after(response.headers());
    let text = match response.body_mut().with_config().limit(MAX_RESPONSE_BYTES).read_to_string() {
        Ok(text) => text,
        Err(err) => return Err(TokenFailure::plain(transport_error(err))),
    };

    if (200..300).contains(&status) {
        return match serde_json::from_str::<TokenResponseWire>(&text) {
            Ok(wire) => Ok(wire.into()),
            Err(err) => Err(TokenFailure::plain(OauthError::Http {
                status,
                body: format!("the token response could not be parsed: {err}"),
            })),
        };
    }

    if is_invalid_grant(&text) {
        return Err(TokenFailure::plain(OauthError::InvalidGrant));
    }
    Err(TokenFailure { error: OauthError::Http { status, body: redact(&text) }, retry_after })
}

/// Fetches the profile, the identity fallback when the exchange named no
/// account (fact F26).
///
/// # Errors
///
/// See [`OauthError`]. The caller treats any failure here as "identity still
/// unknown" rather than as a failed login.
pub fn profile(
    client: &OauthClient,
    creds: &Credentials,
    cancel: &Cancel,
) -> Result<Value, OauthError> {
    if cancel.is_cancelled() {
        return Err(OauthError::Cancelled);
    }

    let sent = client
        .profile_agent
        .get(&client.profile_url)
        .header("authorization", creds.authorization_header())
        .header("accept", "application/json")
        .header("user-agent", &client.user_agent)
        .call();

    let mut response = sent.map_err(transport_error)?;
    let status = response.status().as_u16();
    let text = response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES)
        .read_to_string()
        .map_err(transport_error)?;

    if !(200..300).contains(&status) {
        return Err(OauthError::Http { status, body: redact(&text) });
    }
    serde_json::from_str(&text).map_err(|err| OauthError::Http {
        status,
        body: format!("the profile response could not be parsed: {err}"),
    })
}

/// Maps a `ureq` failure onto a transport or timeout error.
fn transport_error(err: ureq::Error) -> OauthError {
    match err {
        ureq::Error::Timeout(_) => OauthError::Timeout,
        other => OauthError::Transport(other.to_string()),
    }
}

/// Reads `retry-after` as a whole number of seconds.
///
/// Only the delta-seconds form is understood; the HTTP-date form is treated as
/// absent, which falls back to the floor rather than to guessing.
fn retry_after(headers: &ureq::http::HeaderMap) -> Option<Duration> {
    let value = headers.get("retry-after")?.to_str().ok()?;
    value.trim().parse::<u64>().ok().map(Duration::from_secs)
}

/// Whether an error body says `invalid_grant` (fact F8).
///
/// Both shapes seen in the wild are accepted: a bare `"error": "invalid_grant"`
/// and the nested `"error": {"type": "invalid_grant"}` the endpoint uses for
/// its typed errors.
fn is_invalid_grant(body: &str) -> bool {
    let Ok(document) = serde_json::from_str::<Value>(body) else { return false };
    let Some(error) = document.get("error") else { return false };
    match error {
        Value::String(text) => text == "invalid_grant",
        Value::Object(_) => error.get("type").and_then(Value::as_str) == Some("invalid_grant"),
        _ => false,
    }
}

/// Makes a response body safe to put in an error message.
///
/// Token material is replaced *before* the length limit is applied, so a
/// truncation cannot leave a token prefix behind.
fn redact(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut rest = body;
    while let Some(start) = rest.find("sk-ant") {
        out.push_str(&rest[..start]);
        out.push_str("<redacted>");
        let tail = &rest[start..];
        let end = tail
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
            .unwrap_or(tail.len());
        rest = &tail[end..];
    }
    out.push_str(rest);

    if out.len() <= MAX_ERROR_BODY_BYTES {
        return out;
    }
    // `floor_char_boundary` is still unstable, so the cut point is walked back
    // to one by hand rather than slicing blind and panicking on a multi-byte
    // character.
    let mut cut = MAX_ERROR_BODY_BYTES;
    while cut > 0 && !out.is_char_boundary(cut) {
        cut -= 1;
    }
    out.truncate(cut);
    out.push('…');
    out
}

/// Binds a loopback listener on an arbitrary free port.
///
/// # Errors
///
/// Returns [`OauthError::Transport`] when `127.0.0.1` cannot be bound, which
/// is the signal for the caller to fall back to the manual flow.
pub fn listen_loopback() -> Result<TcpListener, OauthError> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|err| {
        OauthError::Transport(format!("could not bind a loopback listener: {err}"))
    })?;
    listener.set_nonblocking(true).map_err(|err| {
        OauthError::Transport(format!("could not poll the loopback listener: {err}"))
    })?;
    Ok(listener)
}

/// The port a loopback listener ended up on.
///
/// # Errors
///
/// Returns [`OauthError::Transport`] when the socket has no local address,
/// which would mean it was closed underneath us.
pub fn loopback_port(listener: &TcpListener) -> Result<u16, OauthError> {
    listener.local_addr().map(|addr| addr.port()).map_err(|err| {
        OauthError::Transport(format!("the loopback listener has no address: {err}"))
    })
}

/// Waits for the browser to come back with an authorization code.
///
/// Accepts exactly one request, parses only its request line, and answers with
/// a small page either way. The `state` is compared without an early exit —
/// this is a CSRF token, so a timing side channel is cheap to avoid and there
/// is no reason to leave one.
///
/// A mismatch is [`OauthError::StateMismatch`] and **nothing is written**
/// (AC12): the caller has not reached the exchange, so there are no
/// credentials to write.
///
/// # Errors
///
/// See [`OauthError`].
pub fn loopback_wait(
    listener: TcpListener,
    expected_state: &str,
    deadline: Instant,
    cancel: &Cancel,
) -> Result<String, OauthError> {
    let stream = accept_one(&listener, deadline, cancel)?;
    let outcome = read_callback(stream, expected_state);
    // The listener is dropped here, so a second visit to the port is refused
    // rather than silently accepted and ignored.
    drop(listener);
    outcome
}

/// Polls for one connection until the deadline or cancellation.
fn accept_one(
    listener: &TcpListener,
    deadline: Instant,
    cancel: &Cancel,
) -> Result<TcpStream, OauthError> {
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) => {
                return Err(OauthError::Transport(format!("the loopback listener failed: {err}")));
            }
        }
        if cancel.is_cancelled() {
            return Err(OauthError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(OauthError::Timeout);
        }
        if cancel.wait_timeout(LOOPBACK_POLL_INTERVAL) {
            return Err(OauthError::Cancelled);
        }
    }
}

/// Reads one request line, answers it, and reports what it carried.
fn read_callback(stream: TcpStream, expected_state: &str) -> Result<String, OauthError> {
    stream.set_nonblocking(false).map_err(|err| {
        OauthError::Transport(format!("could not read the loopback request: {err}"))
    })?;
    // A connection that opens and then says nothing must not hold the login
    // open for the rest of the ten minutes.
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));

    let mut reader = BufReader::new(&stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).map_err(|err| {
        OauthError::Transport(format!("could not read the loopback request: {err}"))
    })?;

    let outcome = parse_callback(&request_line, expected_state);
    let page = match &outcome {
        Ok(_) => "<!doctype html><title>agentctl</title><p>Login complete. You can close this tab.",
        Err(_) => "<!doctype html><title>agentctl</title><p>Login failed. Return to the terminal.",
    };
    let status = if outcome.is_ok() { "200 OK" } else { "400 Bad Request" };
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: text/html; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{page}",
        page.len()
    );
    // Best effort: the code is already in hand, and a browser that hung up
    // before reading the page does not make the login any less complete.
    let _ = (&stream).write_all(response.as_bytes());
    let _ = (&stream).flush();

    outcome
}

/// Pulls `code` and `state` out of a request line such as
/// `GET /callback?code=…&state=… HTTP/1.1`.
fn parse_callback(request_line: &str, expected_state: &str) -> Result<String, OauthError> {
    let mut parts = request_line.split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        return Err(OauthError::Refused("the loopback request was not HTTP".to_owned()));
    };
    if !method.eq_ignore_ascii_case("GET") {
        return Err(OauthError::Refused(format!("the loopback request used `{method}`, not GET")));
    }

    // The request target is origin-form, so it is joined onto a base to be
    // parsed. The host is irrelevant — only the query is read.
    let url =
        Url::parse("http://localhost/").and_then(|base| base.join(target)).map_err(|err| {
            OauthError::Refused(format!("the loopback request target is not a URL: {err}"))
        })?;

    let mut code = None;
    let mut state = None;
    let mut error = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "code" => code = Some(value.into_owned()),
            "state" => state = Some(value.into_owned()),
            "error" => error = Some(value.into_owned()),
            _ => {}
        }
    }

    if let Some(error) = error {
        return Err(OauthError::Refused(error));
    }
    let (Some(code), Some(state)) = (code, state) else {
        return Err(OauthError::Refused(
            "the loopback request carried no authorization code".to_owned(),
        ));
    };
    if !constant_time_eq(state.as_bytes(), expected_state.as_bytes()) {
        return Err(OauthError::StateMismatch);
    }
    Ok(code)
}

/// Compares two byte strings without an early exit.
///
/// Lengths are compared first — that much is observable anyway, and `state` is
/// a fixed length this process chose.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Turns a fresh token response into storable credentials (facts F4, F40).
///
/// Takes the response by value, because `SecretString` is not `Clone` and
/// moving the tokens out is what keeps this from needing an exposure site.
///
/// The expiry arithmetic and the scope handling are not repeated here: the
/// response is folded in through
/// [`Credentials::merge_refresh`], which is the same checked path a refresh
/// takes. The dummy access token it is given is overwritten by that call
/// before anything can read it.
///
/// # Errors
///
/// Returns [`CredentialsError::ExpiryOverflow`] when `expires_in` does not fit
/// in an `i64` of milliseconds.
pub fn to_credentials(
    mut response: TokenResponse,
    now_ms: i64,
    scopes_requested: &[String],
) -> Result<Credentials, CredentialsError> {
    if let Some(kind) = response.token_type.as_deref()
        && !kind.eq_ignore_ascii_case("bearer")
    {
        tracing::warn!("the token endpoint returned token_type `{kind}`, not `Bearer`");
    }

    let token_account = token_account(&mut response);
    let mut credentials = Credentials {
        access_token: SecretString::from(""),
        refresh_token: None,
        expires_at_ms: 0,
        refresh_token_expires_at_ms: None,
        // Replaced by `merge_refresh` when the response names its scopes,
        // which it always has in practice; this is the fallback for a server
        // that stops saying so.
        scopes: scopes_requested.to_vec(),
        subscription_type: None,
        rate_limit_tier: None,
        client_id: Some(CLIENT_ID.to_owned()),
        token_account,
        extra: Map::new(),
    };
    credentials.merge_refresh(response, now_ms)?;
    Ok(credentials)
}

/// Builds the `tokenAccount` block from an exchange response (facts F4, F25).
fn token_account(response: &mut TokenResponse) -> Option<TokenAccount> {
    let account = response.account.take();
    let organization = response.organization.take();
    let workspace = response.workspace.take();
    // A response that named none of the three has no `tokenAccount` to write,
    // and writing an object of six nulls would make an older blob and a newer
    // one differ for no reason. A response that named *any* of them keeps all
    // of it: the same "never drop a field the server sent" rule the blob
    // round-trip is built on.
    if account.is_none()
        && organization.is_none()
        && !workspace.as_ref().is_some_and(Value::is_object)
    {
        return None;
    }

    let (workspace_id, workspace_name) = match workspace {
        Some(Value::Object(fields)) => (
            fields
                .get("id")
                .or_else(|| fields.get("uuid"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            fields.get("name").and_then(Value::as_str).map(str::to_owned),
        ),
        _ => (None, None),
    };

    Some(TokenAccount {
        uuid: account.as_ref().map(|a| a.uuid.clone()),
        email_address: account.and_then(|a| a.email_address),
        organization_uuid: organization.as_ref().map(|o| o.uuid.clone()),
        organization_name: organization.and_then(|o| o.name),
        workspace_id,
        workspace_name,
    })
}

#[cfg(test)]
#[path = "oauth_tests.rs"]
mod tests;
