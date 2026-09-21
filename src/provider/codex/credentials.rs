//! One Codex `auth.json`, held as a document.
//!
//! # A document, not a struct
//!
//! Codex's own reader drops every member it does not know when it saves
//! (fact F90), and grows new ones between releases. agctl makes the stronger
//! promise (plan AC87): a file it reads and writes back keeps every member it
//! does not understand, in its original position — at the top level, inside
//! `tokens`, between known keys. So [`Credentials`] keeps the parsed
//! [`Value`] itself, in the order it arrived (`serde_json`'s
//! `preserve_order`), and serializes it back with Codex's own formatter:
//! pretty, two-space indent, no trailing newline (fact F90). A refresh changes
//! at most four leaves of it and nothing else.
//!
//! # The tokens are not in the document
//!
//! A `Value` is plain data: it prints, clones and drops like any other. So
//! every member that holds a credential — the three tokens, and the API-key,
//! access-key and identity members of the other modes (fact F61) — is taken
//! *out* of the document at parse time, moved into a [`SecretString`], and
//! replaced in place by `null`. Position is kept by the placeholder; the value
//! is put back only inside [`Credentials::write_json_to`], into a copy that
//! goes straight to the sink.
//!
//! # The second exposure site
//!
//! Invariant I20 allows exactly two places in the crate that take a token's
//! plaintext out of its `SecretString`: Claude's `fn exposed` and this
//! module's. Everything here that needs a token — the document written to a
//! sink, the digests, the `Authorization` header, the claims decode, the
//! refresh body — goes through [`exposed`], one secret at a time.
//! `scripts/phase3-greps.sh` counts the call and refuses a public one.
//!
//! # `LockedCredentials`
//!
//! A refresh body may only be built from credentials read under the namespace
//! lock (invariant I26). [`LockedCredentials`] is defined here, beside
//! [`exposed`], with a private constructor; the only way to obtain one is
//! [`LockedCredentials::from_locked_read`], which borrows the lock proof for
//! the value's whole life, and whose callers `auth_store.rs` alone may be
//! (plan AC119's source test).

use std::fmt;
use std::io;
use std::io::Write;
use std::marker::PhantomData;
use std::time::Duration;

use jiff::SignedDuration;
use jiff::Timestamp;
use secrecy::ExposeSecret;
use secrecy::SecretString;
use serde_json::Map;
use serde_json::Value;
use sha2::Digest;
use sha2::Sha256;

use crate::provider::UsageAuth;
use crate::provider::codex::claims;
use crate::provider::codex::claims::Claims;
use crate::provider::codex::claims::ClaimsError;
use crate::provider::codex::is_known_plan;
use crate::provider::codex::proof::CodexNamespaceGuard;
use crate::secret::audit;
use crate::secret::pending::Digests;
use crate::secret::pending::PendingCredential;

/// How long before its `exp` an access token counts as expired (fact F65).
pub const ACCESS_REFRESH_MARGIN: Duration = Duration::from_secs(5 * 60);

/// How old `last_refresh` may be before a token without a readable `exp`
/// counts as expired (fact F65).
pub const LAST_REFRESH_INTERVAL: SignedDuration = SignedDuration::from_hours(8 * 24);

/// The header naming the workspace a usage request reads (fact F67).
///
/// The one spelling of the name in the crate (plan section 9.3): this type
/// builds the pair, and the usage client requires it by this constant
/// (ledger #277).
pub(crate) const ACCOUNT_ID_HEADER: &str = "ChatGPT-Account-Id";

/// The `tokens` object's name.
const TOKENS: &str = "tokens";

/// Top-level members that hold a credential in some mode (fact F61).
const TOP_LEVEL_SECRETS: [&str; 5] = [
    "OPENAI_API_KEY",
    "personal_access_token",
    "bedrock_api_key",
    "bedrock_access_keys",
    "agent_identity",
];

/// Members of `tokens` that hold a credential.
const TOKEN_SECRETS: [&str; 3] = ["id_token", "access_token", "refresh_token"];

/// Every top-level member fact F61 names, in the order the fact lists them.
///
/// The one list `doctor`'s field-set comparison (premortem PM22) reports
/// against. It is compiled in, so the names it prints came from this crate and
/// never from the file on disk.
pub const KNOWN_MEMBERS: [&str; 8] = [
    "auth_mode",
    "OPENAI_API_KEY",
    "tokens",
    "last_refresh",
    "agent_identity",
    "personal_access_token",
    "bedrock_api_key",
    "bedrock_access_keys",
];

/// Where a secret sits in the document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecretPath {
    /// A member of the top-level object.
    TopLevel(&'static str),
    /// A member of `tokens`.
    Token(&'static str),
}

/// How a secret's plaintext maps back to a JSON value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecretKind {
    /// A JSON string; the plaintext is the string.
    Str,
    /// Any other JSON value; the plaintext is its compact serialization.
    Json,
}

/// One credential taken out of the document.
struct Secret {
    path: SecretPath,
    kind: SecretKind,
    value: SecretString,
}

/// The auth mode a document is in (fact F61).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMode {
    /// `apikey`.
    ApiKey,
    /// `chatgpt`: a ChatGPT login, the mode with a usage source.
    ChatGpt,
    /// `chatgptauthtokens`: ChatGPT tokens supplied externally.
    ChatGptAuthTokens,
    /// `headers`.
    Headers,
    /// `agentidentity`.
    AgentIdentity,
    /// `personalaccesstoken`.
    PersonalAccessToken,
    /// `bedrockapikey`.
    BedrockApiKey,
    /// `bedrockaccesskeys`.
    BedrockAccessKeys,
    /// A mode this build does not know, sanitized for display.
    Unknown(String),
}

impl AuthMode {
    /// The mode as the file spells it.
    pub fn label(&self) -> &str {
        match self {
            Self::ApiKey => "apikey",
            Self::ChatGpt => "chatgpt",
            Self::ChatGptAuthTokens => "chatgptauthtokens",
            Self::Headers => "headers",
            Self::AgentIdentity => "agentidentity",
            Self::PersonalAccessToken => "personalaccesstoken",
            Self::BedrockApiKey => "bedrockapikey",
            Self::BedrockAccessKeys => "bedrockaccesskeys",
            Self::Unknown(value) => value,
        }
    }

    /// The mode an explicit `auth_mode` string names.
    fn from_wire(value: &str) -> Self {
        match value {
            "apikey" => Self::ApiKey,
            "chatgpt" => Self::ChatGpt,
            "chatgptauthtokens" => Self::ChatGptAuthTokens,
            "headers" => Self::Headers,
            "agentidentity" => Self::AgentIdentity,
            "personalaccesstoken" => Self::PersonalAccessToken,
            "bedrockapikey" => Self::BedrockApiKey,
            "bedrockaccesskeys" => Self::BedrockAccessKeys,
            other => {
                let shown = other.len() <= 32
                    && other.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
                Self::Unknown(if shown { other.to_owned() } else { "<unrecognised>".to_owned() })
            }
        }
    }
}

/// Who a Codex credential belongs to. No secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexIdentity {
    /// The ChatGPT user id.
    pub user_id: String,
    /// The ChatGPT account (workspace) id.
    pub account_id: String,
    /// The email address the claims named.
    pub email: Option<String>,
    /// The plan, when it is one this build knows; `unknown` otherwise.
    pub plan: Option<String>,
}

/// What a document is, read once at parse time.
#[derive(Debug, Clone, PartialEq, Eq)]
struct View {
    auth_mode: AuthMode,
    account_id: Option<String>,
    claims: Option<Claims>,
    access_exp: Option<i64>,
    last_refresh: Option<Timestamp>,
}

/// Why a document could not be used.
///
/// Every sentence is fixed or positional. A `serde_json` message for a
/// type mismatch quotes the value, and the values here are tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CredentialsError {
    /// The document ends early: empty, or cut off mid-write (fact F66).
    #[error("the Codex credential file ends before its JSON does; it may be mid-write")]
    Truncated,
    /// The bytes are not JSON.
    #[error("the Codex credential file is not valid JSON (line {line}, column {column})")]
    Json {
        /// Where the parser stopped.
        line: usize,
        /// Where the parser stopped.
        column: usize,
    },
    /// The document is not a JSON object.
    #[error("the Codex credential file is not a JSON object")]
    NotAnObject,
    /// A member has a type Codex would not accept.
    #[error("the Codex credential file's member `{0}` has the wrong type")]
    WrongType(&'static str),
    /// A member an operation needs is absent.
    #[error("the Codex credential file has no `{0}`")]
    MissingField(&'static str),
    /// The id token's claims could not be read.
    #[error("the id token could not be read: {0}")]
    Claims(ClaimsError),
}

/// One Codex `auth.json`.
pub struct Credentials {
    /// The document with every secret replaced in place by `null`.
    doc: Map<String, Value>,
    /// The secrets, in the order they were taken out.
    secrets: Vec<Secret>,
    /// What the document is.
    view: View,
}

impl Credentials {
    /// Parses a document in Codex's shape (fact F61).
    ///
    /// Nothing is required at this level beyond "a JSON object whose known
    /// members have their known types": an `apikey` document has no
    /// `tokens`, and an older one may lack `last_refresh`. When there is an
    /// id token its claims must decode (plan AC89).
    ///
    /// # Errors
    ///
    /// [`CredentialsError::Truncated`] for an empty or cut-off document — the
    /// torn read of fact F66 — and otherwise the variant naming what was
    /// wrong.
    pub fn parse(bytes: &[u8]) -> Result<Self, CredentialsError> {
        let root: Value = serde_json::from_slice(bytes).map_err(|err| {
            if err.is_eof() {
                CredentialsError::Truncated
            } else {
                CredentialsError::Json { line: err.line(), column: err.column() }
            }
        })?;
        let Value::Object(mut doc) = root else { return Err(CredentialsError::NotAnObject) };

        let mut secrets = Vec::new();
        for name in TOP_LEVEL_SECRETS {
            if let Some(slot) = doc.get_mut(name) {
                take_secret(slot, SecretPath::TopLevel(name), false, &mut secrets)?;
            }
        }
        match doc.get_mut(TOKENS) {
            None | Some(Value::Null) => {}
            Some(Value::Object(tokens)) => {
                for name in TOKEN_SECRETS {
                    if let Some(slot) = tokens.get_mut(name) {
                        take_secret(slot, SecretPath::Token(name), true, &mut secrets)?;
                    }
                }
            }
            Some(_) => return Err(CredentialsError::WrongType(TOKENS)),
        }

        let view = derive_view(&doc, &secrets)?;
        Ok(Self { doc, secrets, view })
    }

    /// Writes the document, secrets included, in Codex's format (fact F90):
    /// pretty-printed, two-space indent, no trailing newline, every member in
    /// the position it had.
    ///
    /// The one route by which a whole `auth.json` leaves this type. The
    /// secrets are put back into a copy of the document inside [`exposed`],
    /// one at a time, and the copy is dropped when this returns.
    ///
    /// # Errors
    ///
    /// The sink's [`io::Error`].
    pub fn write_json_to<W: Write>(&self, sink: &mut W) -> io::Result<()> {
        let mut doc = self.doc.clone();
        for secret in &self.secrets {
            exposed(&secret.value, |plain| place(&mut doc, secret.path, secret.kind, plain))?;
        }
        serde_json::to_writer_pretty(sink, &Value::Object(doc)).map_err(io::Error::other)
    }

    /// The auth mode, explicit or inferred (fact F61, plan AC88).
    pub fn auth_mode(&self) -> &AuthMode {
        &self.view.auth_mode
    }

    /// Whether this document can be used to read usage: a ChatGPT mode with
    /// an access token (plan AC88).
    pub fn has_usage_source(&self) -> bool {
        matches!(self.view.auth_mode, AuthMode::ChatGpt | AuthMode::ChatGptAuthTokens)
            && self.secret(SecretPath::Token("access_token")).is_some()
    }

    /// Whether the access token is expired, or will be within `margin`
    /// (fact F65, plan AC90).
    ///
    /// `exp <= now + margin` from the access token's own claim; when it has
    /// no readable `exp`, `last_refresh < now - 8 days`; when neither is
    /// known, expired. Every step is checked arithmetic, and overflow answers
    /// "expired": overflow checks are off in every build here (C-006).
    pub fn access_expired(&self, now: Timestamp, margin: Duration) -> bool {
        if let Some(exp) = self.view.access_exp {
            let threshold =
                i64::try_from(margin.as_secs()).ok().and_then(|m| now.as_second().checked_add(m));
            return threshold.is_none_or(|threshold| exp <= threshold);
        }
        match (self.view.last_refresh, now.checked_sub(LAST_REFRESH_INTERVAL)) {
            (Some(last), Ok(cutoff)) => last < cutoff,
            _ => true,
        }
    }

    /// Who this credential belongs to, when the claims name a user and an
    /// account.
    ///
    /// The account id is `tokens.account_id`, which Codex fills from the id
    /// token's claim at login and sends as `ChatGPT-Account-Id` (facts F63,
    /// F91); the claim is used only when the member is absent. A mismatch
    /// between the two is [`Credentials::identity_drift`].
    pub fn identity(&self) -> Option<CodexIdentity> {
        let claims = self.view.claims.as_ref()?;
        let user_id = claims.chatgpt_user_id.clone()?;
        let account_id =
            self.view.account_id.clone().or_else(|| claims.chatgpt_account_id.clone())?;
        let plan = claims
            .plan_type
            .as_deref()
            .map(|plan| if is_known_plan(plan) { plan.to_owned() } else { "unknown".to_owned() });
        Some(CodexIdentity { user_id, account_id, email: claims.email.clone(), plan })
    }

    /// Whether `tokens.account_id` and the id token's account claim disagree
    /// (fact F92: Codex's refresh keeps the first and replaces the second).
    pub fn identity_drift(&self) -> bool {
        let claim = self.view.claims.as_ref().and_then(|c| c.chatgpt_account_id.as_deref());
        matches!((self.view.account_id.as_deref(), claim), (Some(kept), Some(claim)) if kept != claim)
    }

    /// The fingerprints of the access and refresh tokens, when there is an
    /// access token.
    pub fn digests(&self) -> Option<Digests> {
        let access = self.secret(SecretPath::Token("access_token"))?;
        let access_sha256 = exposed(&access.value, sha256_hex);
        let refresh_sha256 = self
            .secret(SecretPath::Token("refresh_token"))
            .map(|refresh| exposed(&refresh.value, sha256_hex));
        Some(Digests { access_sha256, refresh_sha256 })
    }

    /// The first eight hex digits of the refresh token's digest.
    pub fn refresh_digest8(&self) -> Option<String> {
        self.digests()?.refresh_sha256.as_deref().and_then(audit::digest8)
    }

    /// The first eight hex digits of the access token's digest.
    pub fn access_digest8(&self) -> Option<String> {
        audit::digest8(&self.digests()?.access_sha256)
    }

    /// When `last_refresh` says the grant was last refreshed.
    pub fn last_refresh(&self) -> Option<Timestamp> {
        self.view.last_refresh
    }

    /// The access token's expiry, in seconds since the epoch.
    pub fn access_expires_at(&self) -> Option<i64> {
        self.view.access_exp
    }

    /// The members of [`KNOWN_MEMBERS`] this document does not have.
    ///
    /// Static strings: a name here came from this crate's list, never from the
    /// file (premortem PM22, the S35 lead ruling of 2026-09-22).
    pub fn missing_known_members(&self) -> Vec<&'static str> {
        KNOWN_MEMBERS.iter().filter(|name| !self.doc.contains_key(**name)).copied().collect()
    }

    /// How many members the document has that [`KNOWN_MEMBERS`] does not name.
    ///
    /// A count and never the names: a member name is file content, and a
    /// credential pasted as a key would otherwise be echoed to the terminal
    /// and into `--json` (invariant I24).
    pub fn unknown_member_count(&self) -> usize {
        self.doc.keys().filter(|name| !KNOWN_MEMBERS.contains(&name.as_str())).count()
    }

    /// The secret at `path`, when the document has one.
    fn secret(&self, path: SecretPath) -> Option<&Secret> {
        self.secrets.iter().find(|secret| secret.path == path)
    }

    /// Replaces (or adds) the secret at a `tokens` member.
    fn set_token(
        &mut self,
        name: &'static str,
        value: SecretString,
    ) -> Result<(), CredentialsError> {
        let tokens = self
            .doc
            .get_mut(TOKENS)
            .and_then(Value::as_object_mut)
            .ok_or(CredentialsError::MissingField(TOKENS))?;
        // `insert` keeps an existing key's position (`preserve_order`); a new
        // key goes last, where Codex's own serializer would put a member it
        // had just learned about.
        tokens.insert(name.to_owned(), Value::Null);
        let path = SecretPath::Token(name);
        match self.secrets.iter_mut().find(|secret| secret.path == path) {
            Some(secret) => {
                secret.kind = SecretKind::Str;
                secret.value = value;
            }
            None => self.secrets.push(Secret { path, kind: SecretKind::Str, value }),
        }
        Ok(())
    }
}

impl fmt::Debug for Credentials {
    /// Prints the mode, the ids and digest prefixes; never a token, never the
    /// document.
    ///
    /// Hand-written: a derived `Debug` would print `doc`, which holds every
    /// member agctl does not understand — any of which may be a credential a
    /// newer Codex added — and this type is exactly what an `AccountRef`
    /// carries into a trace (invariant I24, plan AC89/AC96).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let claims = self.view.claims.as_ref();
        f.debug_struct("Credentials")
            .field("auth_mode", &self.view.auth_mode.label())
            .field("account_id", &self.view.account_id)
            .field("user_id", &claims.and_then(|c| c.chatgpt_user_id.as_deref()))
            .field("plan", &claims.and_then(|c| c.plan_type.as_deref()))
            .field("is_fedramp", &claims.is_some_and(|c| c.is_fedramp))
            .field("access_digest8", &self.access_digest8())
            .field("refresh_digest8", &self.refresh_digest8())
            .field("access_exp", &self.view.access_exp)
            .field("last_refresh", &self.view.last_refresh)
            .finish_non_exhaustive()
    }
}

impl UsageAuth for Credentials {
    /// `Bearer <access token>`, or an empty string when the document has no
    /// access token (a row without a usage source never reaches a request).
    fn authorization_header(&self) -> String {
        self.secret(SecretPath::Token("access_token"))
            .map(|access| exposed(&access.value, |token| format!("Bearer {token}")))
            .unwrap_or_default()
    }

    /// `ChatGPT-Account-Id`, and `X-OpenAI-Fedramp: true` when the claim says
    /// so (fact F67).
    ///
    /// The account id comes from the file, so it is checked before it becomes
    /// a header value: a byte outside visible ASCII would either be refused by
    /// the HTTP client or split the header.
    fn extra_headers(&self) -> Vec<(&'static str, String)> {
        let mut headers = Vec::new();
        if let Some(account) = self.view.account_id.as_deref().filter(|id| is_header_safe(id)) {
            headers.push((ACCOUNT_ID_HEADER, account.to_owned()));
        }
        if self.view.claims.as_ref().is_some_and(|claims| claims.is_fedramp) {
            headers.push(("X-OpenAI-Fedramp", "true".to_owned()));
        }
        headers
    }
}

impl PendingCredential for Credentials {
    /// A present `auth.json` that does not parse, or a pending file, meta or
    /// target that exists and cannot be opened, is **not** absent (reviews
    /// S29a F8, S30 F1): Codex's in-place writer can leave the file torn (fact
    /// F66), a pass run under another uid can leave files agctl cannot open,
    /// and the pending file beside either may be the only copy of a rotated
    /// grant. The resolver keeps every file and reports an error; the next pass
    /// decides.
    const UNUSABLE_IS_ABSENT: bool = false;

    fn validate(bytes: &[u8]) -> bool {
        Credentials::parse(bytes).is_ok_and(|credentials| credentials.digests().is_some())
    }

    fn digests(bytes: &[u8]) -> Option<Digests> {
        Credentials::parse(bytes).ok()?.digests()
    }
}

/// The token endpoint's answer to a refresh (fact F65): each member optional.
///
/// An absent `refresh_token` means "keep the one you have", not "rotated"
/// (fact F92).
pub struct RefreshResponse {
    id_token: Option<SecretString>,
    access_token: Option<SecretString>,
    refresh_token: Option<SecretString>,
    earliest_refresh_at: Option<Timestamp>,
}

impl RefreshResponse {
    /// Parses a response body.
    ///
    /// # Errors
    ///
    /// [`CredentialsError::Json`]/[`CredentialsError::Truncated`] for a body
    /// that is not JSON, [`CredentialsError::NotAnObject`], and
    /// [`CredentialsError::WrongType`] for a token member that is not a string.
    pub fn parse(bytes: &[u8]) -> Result<Self, CredentialsError> {
        let root: Value = serde_json::from_slice(bytes).map_err(|err| {
            if err.is_eof() {
                CredentialsError::Truncated
            } else {
                CredentialsError::Json { line: err.line(), column: err.column() }
            }
        })?;
        let Value::Object(mut body) = root else { return Err(CredentialsError::NotAnObject) };
        let mut take = |name: &'static str| match body.shift_remove(name) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(token)) => Ok(Some(SecretString::from(token))),
            Some(_) => Err(CredentialsError::WrongType(name)),
        };
        let id_token = take("id_token")?;
        let access_token = take("access_token")?;
        let refresh_token = take("refresh_token")?;
        // Fact F80 / ledger 282a: a server hint, read only when it is a whole
        // number of seconds that names a representable time. Anything else is
        // ignored rather than refused — the grant in the rest of the body is
        // what matters. Every other member (`oai_is`, `scope`, …) is dropped
        // here, unread and never persisted.
        let earliest_refresh_at = body
            .get("earliest_refresh_at")
            .and_then(Value::as_i64)
            .and_then(|seconds| Timestamp::from_second(seconds).ok());
        Ok(Self { id_token, access_token, refresh_token, earliest_refresh_at })
    }

    /// Whether the response carries an access token: a 2xx without one is not
    /// a usable grant (decision D-035's class table).
    pub fn has_access_token(&self) -> bool {
        self.access_token.is_some()
    }

    /// The server's `earliest_refresh_at`, when it sent a usable one (fact
    /// F80, ledger 282a).
    pub fn earliest_refresh_at(&self) -> Option<Timestamp> {
        self.earliest_refresh_at
    }
}

impl fmt::Debug for RefreshResponse {
    /// Which members came back; never their values.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefreshResponse")
            .field("id_token", &self.id_token.is_some())
            .field("access_token", &self.access_token.is_some())
            .field("refresh_token", &self.refresh_token.is_some())
            .field("earliest_refresh_at", &self.earliest_refresh_at)
            .finish()
    }
}

/// What a merge found beyond the new tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MergeOutcome {
    /// The new id token names a different account or user than the file
    /// (fact F92). The file's `tokens.account_id` is kept, as Codex keeps it.
    pub identity_drift: bool,
    /// The refresh token changed.
    pub refresh_rotated: bool,
    /// The response carried an id token whose claims do not decode. The
    /// file's current id token was kept, and the new access and refresh
    /// tokens were merged anyway: by now the old refresh token is spent, and
    /// dropping the response would lose the only copy of the rotated grant
    /// (review S30 F3). The next refresh brings a fresh id token.
    pub id_token_unreadable: bool,
}

/// Credentials read under a held namespace lock, and the only value a refresh
/// body can be built from (invariant I26).
///
/// Carries the namespace it was read from and the digests the file had at
/// that read, so a write can refuse credentials from another namespace (review
/// S30 F7) and compare the file with the read the merge was built on, rather
/// than with a snapshot taken by a separate read (review S30 F4).
pub struct LockedCredentials<'g> {
    inner: Credentials,
    ids: (String, String),
    base: Option<Digests>,
    _guard: PhantomData<&'g CodexNamespaceGuard>,
}

impl<'g> LockedCredentials<'g> {
    /// Private: the two routes in are [`LockedCredentials::from_locked_read`]
    /// and [`LockedCredentials::merge_refresh`].
    fn new(inner: Credentials, ids: (String, String), base: Option<Digests>) -> Self {
        Self { inner, ids, base, _guard: PhantomData }
    }

    /// Wraps credentials that were read from namespace `ids` while `_proof`
    /// was held, recording the digests the file had at that read.
    ///
    /// The borrow is the point: the value cannot outlive the lock. Callers are
    /// pinned to `auth_store.rs` by plan AC119's source test — a sibling
    /// module could call this with a guard for the right namespace and bytes
    /// it did not read under it, which privacy alone cannot stop.
    pub(super) fn from_locked_read(
        inner: Credentials,
        ids: (&str, &str),
        _proof: &'g CodexNamespaceGuard,
    ) -> Self {
        let base = inner.digests();
        Self::new(inner, (ids.0.to_owned(), ids.1.to_owned()), base)
    }

    /// The `(user, account)` of the namespace these were read from.
    pub fn ids(&self) -> (&str, &str) {
        (&self.ids.0, &self.ids.1)
    }

    /// The digests the file had when these were read. A merge keeps them: they
    /// are what a write compares the file with, and what a pending file records
    /// it was derived from.
    pub(super) fn base_digests(&self) -> Option<&Digests> {
        self.base.as_ref()
    }

    /// The credentials.
    pub fn credentials(&self) -> &Credentials {
        &self.inner
    }

    /// The credentials, no longer bound to the lock they were read under.
    ///
    /// For a usage GET, which reads a token and writes nothing: holding the
    /// namespace lock for the length of a request would make every other
    /// agctl process's refresh of this namespace `busy` meanwhile. What an
    /// unbound value cannot do is the point of the type — build a refresh
    /// body ([`LockedCredentials::write_refresh_body_to`]) or be written
    /// (`OwnedNamespace::write` takes `&LockedCredentials`) — so unbinding
    /// gives up exactly the capabilities a read-only caller does not need
    /// (invariant I26).
    pub fn into_credentials(self) -> Credentials {
        self.inner
    }

    /// The first eight hex digits of the refresh token's digest.
    pub fn refresh_digest8(&self) -> Option<String> {
        self.inner.refresh_digest8()
    }

    /// Writes the refresh POST body (fact F65):
    /// `{"client_id": …, "grant_type": "refresh_token", "refresh_token": …}`.
    ///
    /// Into a sink rather than returned, so the one string holding a refresh
    /// token is the request's own buffer. Its single caller is the refresh
    /// client (plan AC119).
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::InvalidInput`] when there is no refresh token, and the
    /// sink's own errors.
    pub fn write_refresh_body_to<W: Write>(&self, sink: &mut W, client_id: &str) -> io::Result<()> {
        let Some(refresh) = self.inner.secret(SecretPath::Token("refresh_token")) else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "no refresh token"));
        };
        exposed(&refresh.value, |token| {
            let mut body = Map::new();
            body.insert("client_id".to_owned(), Value::String(client_id.to_owned()));
            body.insert("grant_type".to_owned(), Value::String("refresh_token".to_owned()));
            body.insert("refresh_token".to_owned(), Value::String(token.to_owned()));
            serde_json::to_writer(sink, &Value::Object(body)).map_err(io::Error::other)
        })
    }

    /// Folds a refresh response into the document (facts F65, F92).
    ///
    /// At most four leaves change — `tokens.id_token`, `tokens.access_token`,
    /// `tokens.refresh_token` for each member the response carried, and
    /// `last_refresh`, stamped even when nothing came back — and
    /// `tokens.account_id` is kept as it is (plan AC87). The result is the same
    /// typestate: merging does not release the lock.
    ///
    /// # Errors
    ///
    /// [`CredentialsError::MissingField`] when the document has no `tokens`,
    /// checked before the response is consumed. A new id token that cannot be
    /// read is not an error: see [`MergeOutcome::id_token_unreadable`].
    pub fn merge_refresh(
        self,
        response: RefreshResponse,
        now: Timestamp,
    ) -> Result<(LockedCredentials<'g>, MergeOutcome), CredentialsError> {
        let LockedCredentials { mut inner, ids, base, .. } = self;
        // A document without `tokens` has no grant to merge into, whether or
        // not the response carried anything. Checked before anything is moved,
        // and the only failure left after it is unreachable (below).
        if !inner.doc.get(TOKENS).is_some_and(Value::is_object) {
            return Err(CredentialsError::MissingField(TOKENS));
        }
        let before_refresh = inner.refresh_digest8();
        let before_user = inner.view.claims.as_ref().and_then(|c| c.chatgpt_user_id.clone());
        let RefreshResponse { id_token, access_token, refresh_token, .. } = response;
        // Review S30 F3: an id token whose claims do not decode is not merged,
        // so the view below cannot fail on it and the rest of the grant lands.
        let mut id_token_unreadable = false;
        let id_token = match id_token {
            Some(token) if exposed(&token, claims::parse).is_err() => {
                id_token_unreadable = true;
                None
            }
            other => other,
        };
        for (name, value) in [
            ("id_token", id_token),
            ("access_token", access_token),
            ("refresh_token", refresh_token),
        ] {
            if let Some(value) = value {
                inner.set_token(name, value)?;
            }
        }
        inner.doc.insert("last_refresh".to_owned(), Value::String(codex_timestamp(now)));
        // Cannot fail: the document parsed when it was read, the only members
        // changed are string tokens and a string stamp, and the one token whose
        // decode can fail was checked above.
        inner.view = derive_view(&inner.doc, &inner.secrets)?;

        let claims = inner.view.claims.as_ref();
        let user_changed = matches!(
            (before_user.as_deref(), claims.and_then(|c| c.chatgpt_user_id.as_deref())),
            (Some(old), Some(new)) if old != new
        );
        let outcome = MergeOutcome {
            identity_drift: inner.identity_drift() || user_changed,
            refresh_rotated: inner.refresh_digest8() != before_refresh,
            id_token_unreadable,
        };
        Ok((LockedCredentials::new(inner, ids, base), outcome))
    }
}

impl fmt::Debug for LockedCredentials<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockedCredentials")
            .field("ids", &self.ids)
            .field("credentials", &self.inner)
            .finish_non_exhaustive()
    }
}

/// The crate's second, and last, secret exposure site (invariant I20).
///
/// One function, one line: Claude's credentials module holds the other.
fn exposed<R>(secret: &SecretString, f: impl FnOnce(&str) -> R) -> R {
    f(secret.expose_secret())
}

/// Moves the credential at `slot` into `secrets`, leaving `null` in its place.
///
/// `null` itself is not a credential (Codex always writes `OPENAI_API_KEY`,
/// as `null` when unset) and stays. A `tokens` member must be a string.
fn take_secret(
    slot: &mut Value,
    path: SecretPath,
    must_be_string: bool,
    secrets: &mut Vec<Secret>,
) -> Result<(), CredentialsError> {
    let name = match path {
        SecretPath::TopLevel(name) | SecretPath::Token(name) => name,
    };
    match std::mem::take(slot) {
        Value::Null => {}
        Value::String(token) => {
            secrets.push(Secret { path, kind: SecretKind::Str, value: SecretString::from(token) });
        }
        _ if must_be_string => return Err(CredentialsError::WrongType(name)),
        other => {
            let text =
                serde_json::to_string(&other).map_err(|_| CredentialsError::WrongType(name))?;
            secrets.push(Secret { path, kind: SecretKind::Json, value: SecretString::from(text) });
        }
    }
    Ok(())
}

/// Puts one secret's plaintext back at its path in `doc`.
fn place(
    doc: &mut Map<String, Value>,
    path: SecretPath,
    kind: SecretKind,
    plain: &str,
) -> io::Result<()> {
    let value = match kind {
        SecretKind::Str => Value::String(plain.to_owned()),
        // The text was produced by `serde_json::to_string` at parse time.
        SecretKind::Json => serde_json::from_str(plain).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "a stored credential member did not re-parse",
            )
        })?,
    };
    let slot = match path {
        SecretPath::TopLevel(name) => doc.get_mut(name),
        SecretPath::Token(name) => doc
            .get_mut(TOKENS)
            .and_then(Value::as_object_mut)
            .and_then(|tokens| tokens.get_mut(name)),
    };
    let Some(slot) = slot else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a credential member lost its place",
        ));
    };
    *slot = value;
    Ok(())
}

/// Reads what a document is from its non-secret members and its secrets.
fn derive_view(doc: &Map<String, Value>, secrets: &[Secret]) -> Result<View, CredentialsError> {
    let find = |path: SecretPath| secrets.iter().find(|secret| secret.path == path);

    let auth_mode = match doc.get("auth_mode") {
        None | Some(Value::Null) => {
            if find(SecretPath::TopLevel("personal_access_token")).is_some() {
                AuthMode::PersonalAccessToken
            } else if find(SecretPath::TopLevel("bedrock_api_key")).is_some() {
                AuthMode::BedrockApiKey
            } else if find(SecretPath::TopLevel("bedrock_access_keys")).is_some() {
                AuthMode::BedrockAccessKeys
            } else if find(SecretPath::TopLevel("OPENAI_API_KEY")).is_some() {
                AuthMode::ApiKey
            } else {
                AuthMode::ChatGpt
            }
        }
        Some(Value::String(mode)) => AuthMode::from_wire(mode),
        Some(_) => return Err(CredentialsError::WrongType("auth_mode")),
    };

    let account_id = match doc.get(TOKENS).and_then(|tokens| tokens.get("account_id")) {
        None | Some(Value::Null) => None,
        Some(Value::String(id)) => Some(id.clone()),
        Some(_) => return Err(CredentialsError::WrongType("account_id")),
    };

    let claims = match find(SecretPath::Token("id_token")) {
        Some(id) => Some(exposed(&id.value, claims::parse).map_err(CredentialsError::Claims)?),
        None => None,
    };
    let access_exp = find(SecretPath::Token("access_token"))
        .and_then(|access| exposed(&access.value, claims::expiry).ok().flatten());
    let last_refresh =
        doc.get("last_refresh").and_then(Value::as_str).and_then(|at| at.parse().ok());

    Ok(View { auth_mode, account_id, claims, access_exp, last_refresh })
}

/// `sha256(text)`, hex.
fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

/// Whether `value` can be an HTTP header value unchanged.
fn is_header_safe(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_graphic())
}

/// `now` the way Codex's `last_refresh` spells an instant: RFC 3339 in UTC
/// with `Z`, and a fraction of 0, 3, 6 or 9 digits — the fewest that are
/// exact (`chrono`'s `SecondsFormat::AutoSi`, fact F61's `<str:27>`).
fn codex_timestamp(now: Timestamp) -> String {
    let base = now.strftime("%Y-%m-%dT%H:%M:%S");
    let nanos = now.subsec_nanosecond().unsigned_abs();
    let fraction = if nanos == 0 {
        String::new()
    } else if nanos.is_multiple_of(1_000_000) {
        format!(".{:03}", nanos / 1_000_000)
    } else if nanos.is_multiple_of(1_000) {
        format!(".{:06}", nanos / 1_000)
    } else {
        format!(".{nanos:09}")
    };
    format!("{base}{fraction}Z")
}

#[cfg(test)]
#[path = "credentials_tests.rs"]
mod tests;
