use std::time::Duration;

use super::*;

#[test]
fn transience_decides_whether_another_pass_is_worth_it() {
    let transient = [
        FetchError::RateLimited { retry_after: Some(Duration::from_secs(30)) },
        FetchError::RateLimited { retry_after: None },
        FetchError::Transport("connection reset".to_owned()),
        FetchError::Http { status: 500 },
        FetchError::Http { status: 503 },
    ];
    for error in transient {
        assert!(error.is_transient(), "{error} should be transient");
    }

    let permanent = [
        FetchError::Unauthorized,
        FetchError::Http { status: 400 },
        FetchError::Http { status: 404 },
        FetchError::Parse("no `limits` array".to_owned()),
        FetchError::Cancelled,
    ];
    for error in permanent {
        assert!(!error.is_transient(), "{error} should not be transient");
    }
}

#[test]
fn rate_limited_renders_its_hint_only_when_the_server_sent_one() {
    // The message must not claim a retry window the server never named:
    // a user who reads "retry in 0s" and retries immediately gets another
    // 429 and no explanation.
    let with_hint = FetchError::RateLimited { retry_after: Some(Duration::from_secs(30)) };
    assert_eq!(with_hint.to_string(), "rate limited, retry in 30s");

    let without = FetchError::RateLimited { retry_after: None };
    assert_eq!(without.to_string(), "rate limited");
}

/// A parsed credential whose tokens are sentinels no other fixture uses.
fn sentinel_credentials() -> Credentials {
    let blob = format!(
        r#"{{"claudeAiOauth":{{"accessToken":"{ACCESS_SENTINEL}",
            "refreshToken":"{REFRESH_SENTINEL}","expiresAt":1756000000000,
            "scopes":["user:inference"],"subscriptionType":"max"}}}}"#
    );
    Credentials::parse_blob(blob.as_bytes()).expect("the sentinel blob should parse")
}

/// The access token no `Debug` render may contain.
const ACCESS_SENTINEL: &str = "agctl-test-claude-at-ac96";

/// The refresh token no `Debug` render may contain.
const REFRESH_SENTINEL: &str = "agctl-test-claude-rt-ac96";

#[test]
fn an_account_ref_debug_renders_no_token_and_no_bearer_string() {
    // Plan AC96, the end-to-end half: a real Claude credential behind the
    // seam. `AccountRef`'s hand-written `Debug` does not format `auth` at
    // all, and `Credentials` redacts on its own as well, so both layers are
    // asserted here at once — a `tracing` line, a panic payload or an `{:#?}`
    // of a pass's account must never carry the token it authenticates with.
    let credentials = sentinel_credentials();
    let account = AccountRef { id: "acct-uuid", auth: &credentials };

    for rendered in [format!("{account:?}"), format!("{account:#?}")] {
        assert!(!rendered.contains(ACCESS_SENTINEL), "the access token leaked into: {rendered}");
        assert!(!rendered.contains(REFRESH_SENTINEL), "the refresh token leaked into: {rendered}");
        assert!(!rendered.contains("Bearer"), "a bearer string leaked into: {rendered}");
        assert!(rendered.contains("acct-uuid"), "the row id is not a secret and identifies it");
    }
}

/// A credential type that does exactly what the seam must survive: it holds a
/// token in a plain field and derives `Debug`, so its own render prints the
/// token in full.
#[derive(Debug)]
struct UnredactedAuth {
    token: String,
}

impl UsageAuth for UnredactedAuth {
    fn authorization_header(&self) -> String {
        format!("Bearer {}", self.token)
    }

    fn extra_headers(&self) -> Vec<(&'static str, String)> {
        Vec::new()
    }
}

#[test]
fn an_account_ref_debug_redacts_even_a_credential_that_does_not() {
    // Plan AC96, the structural half. The `UsageAuth: fmt::Debug` bound
    // accepts a derived `Debug`, so the bound alone proves nothing; what makes
    // the seam safe is that `AccountRef`'s `Debug` never formats `auth`. This
    // fails the moment someone replaces that impl with a derive — which is the
    // shape S30's Codex credential (a parsed `auth.json`: id token, access
    // token, refresh token, API key) would arrive in.
    let auth = UnredactedAuth { token: PROBE_SENTINEL.to_owned() };
    assert!(
        format!("{auth:?}").contains(PROBE_SENTINEL),
        "the probe must leak on its own, or it proves nothing about the seam"
    );

    let account = AccountRef { id: "acct-uuid", auth: &auth };
    for rendered in [format!("{account:?}"), format!("{account:#?}")] {
        assert!(!rendered.contains(PROBE_SENTINEL), "the probe token leaked into: {rendered}");
        assert!(!rendered.contains("Bearer"), "a bearer string leaked into: {rendered}");
        assert!(rendered.contains("acct-uuid"), "the row id is not a secret and identifies it");
    }
}

/// The token a derived `Debug` behind the seam must still not reach a render.
const PROBE_SENTINEL: &str = "agctl-test-probe-derived-ac96";

#[test]
fn the_authorization_header_is_the_only_way_through_the_seam() {
    // The header itself is the one deliberate plaintext return per provider
    // (invariant I20), so it does carry the token — and it is the trait's
    // only route to one. Claude adds no credential-borne headers: the
    // `anthropic-beta` header belongs to the endpoint, not to the account.
    let credentials = sentinel_credentials();
    let auth: &dyn UsageAuth = &credentials;

    assert_eq!(auth.authorization_header(), format!("Bearer {ACCESS_SENTINEL}"));
    assert!(auth.extra_headers().is_empty());
}

#[test]
fn the_user_agent_is_the_package_name_and_version_for_every_provider() {
    // Plan AC100. The product token comes from the package rather than from a
    // literal, and the two providers share it: agctl does not present itself
    // as two different clients.
    assert_eq!(USER_AGENT_DEFAULT, concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION")));
    assert!(
        USER_AGENT_DEFAULT.starts_with("agctl/") && USER_AGENT_DEFAULT.len() > "agctl/".len(),
        "the header a server sees names this client and a version: {USER_AGENT_DEFAULT}"
    );
    // Against the function rather than the constant, and without touching the
    // environment: whatever this machine has set, the Claude header is still
    // the one `claude::user_agent` produced before the two providers shared a
    // default.
    assert_eq!(user_agent(Provider::Claude), claude::user_agent());
}

#[test]
fn each_provider_has_its_own_user_agent_override() {
    assert_eq!(user_agent_env(Provider::Claude), "AGCTL_CLAUDE_USER_AGENT");
    assert_eq!(user_agent_env(Provider::Claude), claude::USER_AGENT_ENV);
    assert_eq!(user_agent_env(Provider::Codex), "AGCTL_CODEX_USER_AGENT");
    assert_eq!(user_agent_env(Provider::Codex), CODEX_USER_AGENT_ENV);
}

#[test]
fn a_blank_override_yields_the_default_rather_than_an_empty_header() {
    assert_eq!(user_agent_or_default(Some("codex_cli_rs/0.1")), "codex_cli_rs/0.1");
    assert_eq!(user_agent_or_default(None), USER_AGENT_DEFAULT);
    assert_eq!(user_agent_or_default(Some("")), USER_AGENT_DEFAULT);
    assert_eq!(user_agent_or_default(Some("   \t ")), USER_AGENT_DEFAULT);
}

#[test]
fn error_messages_name_the_status_without_a_body() {
    // Bodies are never interpolated into an error: a token can appear in an
    // echoed request and this string reaches stderr and the JSON report.
    assert_eq!(FetchError::Http { status: 502 }.to_string(), "HTTP 502");
    assert_eq!(FetchError::Unauthorized.to_string(), "the access token was rejected");
}
