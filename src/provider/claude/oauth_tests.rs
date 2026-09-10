//! Tests for the OAuth client.
//!
//! The HTTP tests drive a real `httpmock` server rather than a stubbed
//! transport, so the request that gets asserted on is the one `ureq` actually
//! puts on the wire — headers, JSON body and all. That matters here more than
//! usual: every fact these tests pin down (the exchange body, the refresh
//! body, the 429 retry, `invalid_grant`) was read off a live endpoint during
//! plan step S3, and a stubbed transport would let a serialization change slip
//! past the assertions unnoticed.

use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;
use std::time::Instant;

use httpmock::Method;
use httpmock::MockServer;

use super::*;

/// The redacted capture from plan step S3.
fn fixture_bytes() -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/claude/exchange-response.json");
    std::fs::read(&path).unwrap_or_else(|err| panic!("fixture `{}`: {err}", path.display()))
}

/// A client pointed at a mock server.
fn client_for(server: &MockServer) -> OauthClient {
    OauthClient::with_endpoints(
        &server.url("/cai/oauth/authorize"),
        &server.url("/v1/oauth/token"),
        &server.url("/api/oauth/profile"),
        "agctl/test",
    )
    .expect("the mock endpoints should parse")
}

/// Credentials with a refresh token, as they would come off disk.
fn stored_credentials() -> Credentials {
    let blob = serde_json::json!({
        "claudeAiOauth": {
            "accessToken": "sk-ant-oat01-stored-access",
            "refreshToken": "sk-ant-ort01-stored-refresh",
            "expiresAt": 1_700_000_000_000_i64,
            "scopes": ["user:inference", "user:profile"],
        }
    });
    Credentials::parse_blob(blob.to_string().as_bytes()).expect("the blob should parse")
}

/// The five scopes agctl asks for.
fn default_scopes() -> Vec<String> {
    DEFAULT_SCOPES.iter().map(|scope| (*scope).to_owned()).collect()
}

#[test]
fn a_response_carries_every_field_the_exchange_returns() {
    let response = TokenResponse {
        access_token: SecretString::from("access"),
        refresh_token: Some(SecretString::from("refresh")),
        expires_in: 28_800,
        refresh_token_expires_in: Some(2_377_445),
        scope: Some("user:inference".to_owned()),
        token_type: Some("Bearer".to_owned()),
        account: Some(ExchangeAccount {
            uuid: "11111111-1111-4111-8111-111111111111".to_owned(),
            email_address: Some("user@example.com".to_owned()),
        }),
        organization: Some(ExchangeOrganization {
            uuid: "22222222-2222-4222-8222-222222222222".to_owned(),
            name: Some("Example Org".to_owned()),
        }),
        workspace: Some(serde_json::json!({"id": "w", "name": "Workspace"})),
    };

    assert_eq!(response.expires_in, 28_800);
    assert_eq!(response.refresh_token_expires_in, Some(2_377_445));
    assert_eq!(response.scope.as_deref(), Some("user:inference"));
    assert_eq!(response.token_type.as_deref(), Some("Bearer"));
    assert!(response.refresh_token.is_some());
    assert_eq!(
        response.account.as_ref().map(|a| a.uuid.as_str()),
        Some("11111111-1111-4111-8111-111111111111")
    );
    assert_eq!(response.organization.as_ref().and_then(|o| o.name.as_deref()), Some("Example Org"));
    assert_eq!(
        response.workspace.as_ref().and_then(|w| w.get("id")),
        Some(&serde_json::json!("w"))
    );
}

#[test]
fn the_captured_exchange_response_deserializes_including_the_new_field() {
    // The endpoint grew a `token_uuid` after the fixture was captured; the
    // wire mirror ignores unknown keys, which is what keeps that from being a
    // breaking change (plan step S3).
    let bytes = fixture_bytes();
    let document: serde_json::Value =
        serde_json::from_slice(&bytes).expect("the fixture should be JSON");
    assert!(document.get("token_uuid").is_some(), "the fixture still carries the new field");

    let wire: TokenResponseWire =
        serde_json::from_slice(&bytes).expect("the fixture should deserialize");
    let response = TokenResponse::from(wire);

    assert_eq!(response.expires_in, 28_800);
    assert_eq!(response.refresh_token_expires_in, Some(2_377_445));
    assert_eq!(response.token_type.as_deref(), Some("Bearer"));
    assert_eq!(
        response.scope.as_deref(),
        Some(
            "user:file_upload user:inference user:mcp_servers user:profile user:sessions:claude_code"
        )
    );
    assert_eq!(
        response.account.as_ref().map(|a| a.uuid.as_str()),
        Some("11111111-1111-4111-8111-111111111111")
    );
    assert_eq!(
        response.organization.as_ref().map(|o| o.uuid.as_str()),
        Some("22222222-2222-4222-8222-222222222222")
    );
    assert!(response.workspace.is_none(), "the capture observed no workspace block");
}

#[test]
fn a_token_responses_debug_output_never_shows_a_token() {
    // This type is what a failing HTTP test prints, so its `Debug` is the
    // most likely accidental route from a live token to a log or a CI record.
    let response = TokenResponse {
        access_token: SecretString::from("sk-ant-oat01-secret-access"),
        refresh_token: Some(SecretString::from("sk-ant-ort01-secret-refresh")),
        expires_in: 28_800,
        refresh_token_expires_in: Some(2_377_445),
        scope: Some("user:inference".to_owned()),
        token_type: Some("Bearer".to_owned()),
        account: None,
        organization: None,
        workspace: None,
    };

    let rendered = format!("{response:?}");
    assert!(!rendered.contains("sk-ant"), "a token reached Debug output: {rendered}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
    // The fields that are not secret stay legible, or the impl is useless for
    // the debugging it exists for.
    assert!(rendered.contains("28800"), "{rendered}");
    assert!(rendered.contains("Bearer"), "{rendered}");
}

#[test]
fn the_rfc_7636_appendix_b_vector_produces_the_documented_challenge() {
    assert_eq!(
        code_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
}

#[test]
fn generated_pkce_material_is_the_right_length_and_never_repeats() {
    let first = pkce();
    let second = pkce();

    // 32 bytes base64url-unpadded is 43 characters, inside RFC 7636's
    // 43..=128 range for a verifier.
    assert_eq!(first.verifier.len(), 43);
    assert_eq!(first.state.len(), 43);
    assert_eq!(first.challenge, code_challenge(&first.verifier));
    assert!(
        first.verifier.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "the verifier must be url-safe: {}",
        first.challenge
    );
    assert_ne!(first.verifier, second.verifier);
    assert_ne!(first.state, second.state);
}

#[test]
fn the_pkce_debug_output_never_shows_the_verifier() {
    let material = pkce();
    let rendered = format!("{material:?}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
    assert!(!rendered.contains(&material.verifier), "the verifier leaked into Debug");
}

#[test]
fn the_authorize_url_carries_claude_codes_parameters_in_order() {
    let client =
        OauthClient::with_endpoints(AUTHORIZE_URL_CLAUDE_AI, TOKEN_URL, PROFILE_URL, "agctl/test")
            .expect("the real endpoints should parse");
    let material =
        Pkce { verifier: "v".to_owned(), challenge: "chal".to_owned(), state: "st".to_owned() };

    let url = authorize_url(&client, &material, &Redirect::Manual, &default_scopes())
        .expect("the URL should build");

    assert_eq!(url.scheme(), "https");
    assert_eq!(url.host_str(), Some("claude.com"));
    assert_eq!(url.path(), "/cai/oauth/authorize");
    assert_eq!(
        url.query().expect("the URL should carry a query"),
        concat!(
            "code=true",
            "&client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e",
            "&response_type=code",
            "&redirect_uri=https%3A%2F%2Fplatform.claude.com%2Foauth%2Fcode%2Fcallback",
            "&scope=user%3Afile_upload+user%3Ainference+user%3Amcp_servers+user%3Aprofile",
            "+user%3Asessions%3Aclaude_code",
            "&code_challenge=chal",
            "&code_challenge_method=S256",
            "&state=st",
        )
    );
}

#[test]
fn a_loopback_redirect_names_the_bound_port() {
    assert_eq!(Redirect::Loopback { port: 51234 }.uri(), "http://localhost:51234/callback");
    assert_eq!(Redirect::Manual.uri(), MANUAL_REDIRECT_URI);
}

#[test]
fn parse_manual_code_splits_at_the_first_hash() {
    let (code, state) = parse_manual_code("  abc#def#ghi \n").expect("the paste should parse");
    assert_eq!(code, "abc");
    assert_eq!(state, "def#ghi", "a later `#` belongs to the state, not to a second separator");
}

#[test]
fn parse_manual_code_rejects_a_half_copied_paste() {
    for input in ["abcdef", "#state", "code#", "   "] {
        let err = parse_manual_code(input).expect_err("`{input}` should be rejected");
        assert!(matches!(err, OauthError::Refused(_)), "{input}: {err}");
    }
}

#[test]
fn verify_state_accepts_only_the_state_that_went_out() {
    assert!(verify_state("abc", "abc").is_ok());
    assert!(matches!(verify_state("abc", "abd"), Err(OauthError::StateMismatch)));
    assert!(matches!(verify_state("abc", "abcd"), Err(OauthError::StateMismatch)));
    assert!(matches!(verify_state("abc", ""), Err(OauthError::StateMismatch)));
}

#[test]
fn the_exchange_sends_the_documented_body_and_parses_the_response() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(Method::POST)
            .path("/v1/oauth/token")
            .header("content-type", "application/json")
            .header("user-agent", "agctl/test")
            .json_body_includes(
                serde_json::json!({
                    "grant_type": "authorization_code",
                    "code": "THE-CODE",
                    "redirect_uri": "http://localhost:4242/callback",
                    "client_id": CLIENT_ID,
                    "code_verifier": "THE-VERIFIER",
                    "state": "THE-STATE",
                })
                .to_string(),
            );
        then.status(200).header("content-type", "application/json").body(fixture_bytes());
    });

    let client = client_for(&server);
    let material = Pkce {
        verifier: "THE-VERIFIER".to_owned(),
        challenge: "chal".to_owned(),
        state: "THE-STATE".to_owned(),
    };
    let response = exchange(
        &client,
        "THE-CODE",
        "THE-STATE",
        &material,
        &Redirect::Loopback { port: 4242 },
        &Cancel::new(),
    )
    .expect("the exchange should succeed");

    mock.assert();
    assert_eq!(response.expires_in, 28_800);
    assert_eq!(
        response.account.as_ref().map(|a| a.uuid.as_str()),
        Some("11111111-1111-4111-8111-111111111111")
    );
}

#[test]
fn a_rate_limited_exchange_is_retried_exactly_once() {
    // Probe S3: the token endpoint answers 429 with a `rate_limit_error` body,
    // no `retry-after`, and without consuming the authorization code — which
    // is what makes resending the same code the right move. A second 429 is
    // the end of it; the caller is told, rather than the endpoint hammered.
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(Method::POST).path("/v1/oauth/token");
        then.status(429).json_body(serde_json::json!({
            "type": "error",
            "error": {"type": "rate_limit_error", "message": "Number of requests has exceeded your rate limit"}
        }));
    });

    let client = client_for(&server);
    let material =
        Pkce { verifier: "v".to_owned(), challenge: "c".to_owned(), state: "s".to_owned() };
    let err = exchange_with_backoff(
        &client,
        "code",
        "s",
        &material,
        &Redirect::Manual,
        &Cancel::new(),
        Duration::from_millis(10),
    )
    .expect_err("a persistent 429 should surface");

    assert_eq!(mock.calls(), 2, "the exchange should send the code exactly twice");
    assert!(matches!(err, OauthError::Http { status: 429, .. }), "{err}");
}

#[test]
fn an_already_cancelled_run_never_contacts_the_endpoint() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(Method::POST).path("/v1/oauth/token");
        then.status(200).body(fixture_bytes());
    });

    let client = client_for(&server);
    let material =
        Pkce { verifier: "v".to_owned(), challenge: "c".to_owned(), state: "s".to_owned() };
    let cancel = Cancel::new();
    cancel.cancel();

    let err = exchange(&client, "code", "s", &material, &Redirect::Manual, &cancel)
        .expect_err("a cancelled run should not start a request");

    assert!(matches!(err, OauthError::Cancelled), "{err}");
    assert_eq!(mock.calls(), 0, "cancellation is checked before the request is sent");
}

#[test]
fn cancelling_during_the_backoff_stops_before_the_second_attempt() {
    // The backoff waits on the cancellation condvar rather than sleeping, so
    // `Ctrl-C` during a rate-limit wait ends the login at once instead of
    // after the full five seconds. The floor here is set to thirty seconds so
    // that a run which ignored cancellation would visibly hang rather than
    // race to a pass.
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(Method::POST).path("/v1/oauth/token");
        then.status(429).json_body(serde_json::json!({"error": {"type": "rate_limit_error"}}));
    });

    let client = client_for(&server);
    let material =
        Pkce { verifier: "v".to_owned(), challenge: "c".to_owned(), state: "s".to_owned() };
    let cancel = Cancel::new();

    let started = Instant::now();
    let err = std::thread::scope(|scope| {
        scope.spawn(|| {
            // Cancel only once the first attempt has actually been sent, so
            // the assertion below is about the backoff and not about the
            // pre-flight check the previous test covers.
            while mock.calls() == 0 {
                std::thread::sleep(Duration::from_millis(5));
            }
            cancel.cancel();
        });
        exchange_with_backoff(
            &client,
            "code",
            "s",
            &material,
            &Redirect::Manual,
            &cancel,
            Duration::from_secs(30),
        )
        .expect_err("a cancelled backoff should not be waited out")
    });

    assert!(matches!(err, OauthError::Cancelled), "{err}");
    assert_eq!(mock.calls(), 1, "the retry must not be sent after cancellation");
    assert!(started.elapsed() < Duration::from_secs(30), "the backoff was slept through");
}

#[test]
fn the_refresh_body_carries_the_stored_scopes_and_the_client_id() {
    // AC29's first clause. The body is built by `Credentials::refresh_body`,
    // so this also proves the OAuth client does not rebuild it and lose the
    // `scope` field on the way.
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(Method::POST).path("/v1/oauth/token").json_body(serde_json::json!({
            "grant_type": "refresh_token",
            "refresh_token": "sk-ant-ort01-stored-refresh",
            "client_id": CLIENT_ID,
            "scope": "user:inference user:profile",
        }));
        then.status(200).json_body(serde_json::json!({
            "access_token": "new-access",
            "expires_in": 28_800,
            "token_type": "Bearer",
        }));
    });

    let client = client_for(&server);
    let response = refresh(&client, &stored_credentials(), &Cancel::new())
        .expect("the refresh should succeed");

    mock.assert();
    assert_eq!(response.expires_in, 28_800);
    assert!(
        response.refresh_token.is_none(),
        "a response without a refresh token keeps the stored one (fact F8)"
    );
}

#[test]
fn a_rate_limited_refresh_is_not_retried() {
    // The refresh path holds the namespace lock, so waiting inside it would
    // block every other writer; 429 becomes a transient row state instead
    // (plan section 3.3).
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(Method::POST).path("/v1/oauth/token");
        then.status(429).json_body(serde_json::json!({"error": {"type": "rate_limit_error"}}));
    });

    let client = client_for(&server);
    let err =
        refresh(&client, &stored_credentials(), &Cancel::new()).expect_err("a 429 should surface");

    assert_eq!(mock.calls(), 1);
    assert!(matches!(err, OauthError::Http { status: 429, .. }), "{err}");
}

#[test]
fn an_invalid_grant_is_reported_as_such_in_both_spellings() {
    // AC29, risk R26: a dead refresh chain must reach the caller as
    // `InvalidGrant` and never as a transient HTTP failure, because the two
    // lead to opposite decisions — `needs login` versus retry next pass.
    for body in [
        serde_json::json!({"error": "invalid_grant", "error_description": "expired"}),
        serde_json::json!({"error": {"type": "invalid_grant", "message": "expired"}}),
    ] {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(Method::POST).path("/v1/oauth/token");
            then.status(400).json_body(body.clone());
        });

        let client = client_for(&server);
        let err = refresh(&client, &stored_credentials(), &Cancel::new())
            .expect_err("the grant should be rejected");
        assert!(matches!(err, OauthError::InvalidGrant), "{body}: {err}");
    }
}

#[test]
fn a_server_error_surfaces_as_http_with_the_body() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(Method::POST).path("/v1/oauth/token");
        then.status(503).body("upstream unavailable");
    });

    let client = client_for(&server);
    let err =
        refresh(&client, &stored_credentials(), &Cancel::new()).expect_err("a 5xx should surface");

    match err {
        OauthError::Http { status, body } => {
            assert_eq!(status, 503);
            assert!(body.contains("upstream unavailable"), "{body}");
        }
        other => panic!("expected an HTTP failure, got {other}"),
    }
}

#[test]
fn error_bodies_lose_their_token_material_before_they_are_truncated() {
    let redacted = redact("bad token sk-ant-oat01-AbC123_xyz for account 9");
    assert_eq!(redacted, "bad token <redacted> for account 9");

    // Redaction runs first so a truncation cannot leave a token prefix behind.
    let long = format!("sk-ant-oat01-{}", "A".repeat(4096));
    let redacted = redact(&long);
    assert!(!redacted.contains("sk-ant"), "{redacted}");
    assert_eq!(redacted, "<redacted>");

    let bulk = "x".repeat(4096);
    let redacted = redact(&bulk);
    assert!(redacted.len() <= MAX_ERROR_BODY_BYTES + '…'.len_utf8(), "{}", redacted.len());
    assert!(redacted.ends_with('…'));
}

#[test]
fn retry_after_is_read_only_in_its_delta_seconds_form() {
    let mut headers = ureq::http::HeaderMap::new();
    assert_eq!(retry_after(&headers), None);

    headers.insert("retry-after", ureq::http::HeaderValue::from_static("7"));
    assert_eq!(retry_after(&headers), Some(Duration::from_secs(7)));

    // The HTTP-date form is treated as absent rather than guessed at.
    headers.insert(
        "retry-after",
        ureq::http::HeaderValue::from_static("Wed, 09 Sep 2026 00:00:00 GMT"),
    );
    assert_eq!(retry_after(&headers), None);
}

#[test]
fn the_profile_call_sends_the_bearer_token() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(Method::GET)
            .path("/api/oauth/profile")
            .header("authorization", "Bearer sk-ant-oat01-stored-access");
        then.status(200).json_body(serde_json::json!({
            "account": {"uuid": "acct-1", "email_address": "user@example.com"},
            "organization": {"uuid": "org-1", "name": "Example Org"},
        }));
    });

    let client = client_for(&server);
    let document = profile(&client, &stored_credentials(), &Cancel::new())
        .expect("the profile should be readable");

    mock.assert();
    assert_eq!(document["account"]["uuid"], serde_json::json!("acct-1"));
}

#[test]
fn to_credentials_builds_the_f40_blob_shape() {
    let wire: TokenResponseWire =
        serde_json::from_slice(&fixture_bytes()).expect("the fixture should deserialize");
    let now_ms = 1_757_000_000_000_i64;

    let credentials = to_credentials(TokenResponse::from(wire), now_ms, &default_scopes())
        .expect("the response should convert");

    assert_eq!(credentials.expires_at_ms, now_ms + 28_800 * 1000);
    assert_eq!(credentials.refresh_token_expires_at_ms, Some(now_ms + 2_377_445 * 1000));
    assert_eq!(credentials.scopes, default_scopes(), "the granted scopes are the F4 five");
    assert_eq!(credentials.client_id.as_deref(), Some(CLIENT_ID));

    let account = credentials.token_account.clone().expect("the response named an account");
    assert_eq!(account.uuid.as_deref(), Some("11111111-1111-4111-8111-111111111111"));
    assert_eq!(account.email_address.as_deref(), Some("user@example.com"));
    assert_eq!(account.organization_uuid.as_deref(), Some("22222222-2222-4222-8222-222222222222"));
    assert_eq!(account.organization_name.as_deref(), Some("Example Org"));
    assert_eq!(account.workspace_id, None);

    let blob: Value =
        serde_json::from_str(&credentials.to_blob_json()).expect("the blob should be JSON");
    let inner = &blob["claudeAiOauth"];
    assert_eq!(inner["accessToken"], serde_json::json!("<REDACTED-ACCESS-TOKEN>"));
    assert_eq!(inner["refreshToken"], serde_json::json!("<REDACTED-REFRESH-TOKEN>"));
    assert_eq!(inner["expiresAt"], serde_json::json!(now_ms + 28_800_000));
    assert_eq!(inner["clientId"], serde_json::json!(CLIENT_ID));
    assert_eq!(
        inner["tokenAccount"]["organizationUuid"],
        serde_json::json!("22222222-2222-4222-8222-222222222222")
    );
}

#[test]
fn to_credentials_keeps_the_requested_scopes_when_the_server_names_none() {
    let response = TokenResponse {
        access_token: SecretString::from("access"),
        refresh_token: None,
        expires_in: 60,
        refresh_token_expires_in: None,
        scope: None,
        token_type: Some("Bearer".to_owned()),
        account: None,
        organization: None,
        workspace: Some(serde_json::json!({"id": "ws-1", "name": "Workspace"})),
    };

    let credentials =
        to_credentials(response, 0, &default_scopes()).expect("the response should convert");

    assert_eq!(credentials.scopes, default_scopes());
    let account = credentials.token_account.expect("a workspace alone still names a token account");
    assert_eq!(account.workspace_id.as_deref(), Some("ws-1"));
    assert_eq!(account.workspace_name.as_deref(), Some("Workspace"));
    assert_eq!(account.uuid, None);
}

#[test]
fn to_credentials_refuses_an_expiry_that_does_not_fit() {
    let response = TokenResponse {
        access_token: SecretString::from("access"),
        refresh_token: None,
        expires_in: i64::MAX,
        refresh_token_expires_in: None,
        scope: None,
        token_type: None,
        account: None,
        organization: None,
        workspace: None,
    };

    // Overflow checks are off in every profile here (constraint C-006), so
    // this has to be caught by the checked arithmetic rather than by a panic.
    let err = to_credentials(response, 0, &default_scopes())
        .expect_err("an absurd lifetime should be refused");
    assert!(matches!(err, CredentialsError::ExpiryOverflow(_)), "{err}");
}

#[test]
fn the_loopback_listener_returns_the_code_from_one_request() {
    let listener = listen_loopback().expect("binding a loopback port should work");
    let port = loopback_port(&listener).expect("the listener should have an address");

    let caller = std::thread::spawn(move || {
        let mut stream =
            TcpStream::connect(("127.0.0.1", port)).expect("the callback should connect");
        std::io::Write::write_all(
            &mut stream,
            b"GET /callback?code=THE-CODE&state=THE-STATE HTTP/1.1\r\nhost: localhost\r\n\r\n",
        )
        .expect("the callback should be sent");
        let mut reply = String::new();
        let _ = stream.read_to_string(&mut reply);
        reply
    });

    let code = loopback_wait(listener, "THE-STATE", deadline(5), &Cancel::new())
        .expect("the callback should be accepted");
    let reply = caller.join().expect("the caller thread should finish");

    assert_eq!(code, "THE-CODE");
    assert!(reply.starts_with("HTTP/1.1 200 OK"), "{reply}");
    assert!(reply.contains("Login complete"), "{reply}");
}

#[test]
fn a_callback_with_the_wrong_state_is_refused() {
    // AC12: the mismatch is noticed before the exchange, so no token is ever
    // minted and there is nothing to write.
    let listener = listen_loopback().expect("binding a loopback port should work");
    let port = loopback_port(&listener).expect("the listener should have an address");

    let caller = std::thread::spawn(move || {
        let mut stream =
            TcpStream::connect(("127.0.0.1", port)).expect("the callback should connect");
        std::io::Write::write_all(
            &mut stream,
            b"GET /callback?code=THE-CODE&state=FORGED HTTP/1.1\r\n\r\n",
        )
        .expect("the callback should be sent");
        let mut reply = String::new();
        let _ = stream.read_to_string(&mut reply);
        reply
    });

    let err = loopback_wait(listener, "THE-STATE", deadline(5), &Cancel::new())
        .expect_err("a forged state should be refused");
    let reply = caller.join().expect("the caller thread should finish");

    assert!(matches!(err, OauthError::StateMismatch), "{err}");
    assert!(reply.starts_with("HTTP/1.1 400 Bad Request"), "{reply}");
}

#[test]
fn a_callback_carrying_an_error_is_reported_verbatim() {
    let listener = listen_loopback().expect("binding a loopback port should work");
    let port = loopback_port(&listener).expect("the listener should have an address");

    let caller = std::thread::spawn(move || {
        let mut stream =
            TcpStream::connect(("127.0.0.1", port)).expect("the callback should connect");
        std::io::Write::write_all(
            &mut stream,
            b"GET /callback?error=access_denied HTTP/1.1\r\n\r\n",
        )
        .expect("the callback should be sent");
    });

    let err = loopback_wait(listener, "THE-STATE", deadline(5), &Cancel::new())
        .expect_err("a refusal should surface");
    caller.join().expect("the caller thread should finish");

    match err {
        OauthError::Refused(reason) => assert_eq!(reason, "access_denied"),
        other => panic!("expected a refusal, got {other}"),
    }
}

#[test]
fn the_loopback_listener_gives_up_at_its_deadline() {
    let listener = listen_loopback().expect("binding a loopback port should work");
    let err = loopback_wait(listener, "THE-STATE", Instant::now(), &Cancel::new())
        .expect_err("an elapsed deadline should end the wait");
    assert!(matches!(err, OauthError::Timeout), "{err}");
}

#[test]
fn the_loopback_listener_stops_when_the_run_is_cancelled() {
    let listener = listen_loopback().expect("binding a loopback port should work");
    let cancel = Cancel::new();
    cancel.cancel();

    let err = loopback_wait(listener, "THE-STATE", deadline(30), &cancel)
        .expect_err("cancellation should end the wait");
    assert!(matches!(err, OauthError::Cancelled), "{err}");
}

#[test]
fn a_callback_that_is_not_a_get_is_refused() {
    assert!(matches!(
        parse_callback("POST /callback?code=a&state=b HTTP/1.1", "b"),
        Err(OauthError::Refused(_))
    ));
    assert!(matches!(parse_callback("garbage\r\n", "b"), Err(OauthError::Refused(_))));
    assert!(matches!(
        parse_callback("GET /callback?state=b HTTP/1.1", "b"),
        Err(OauthError::Refused(_))
    ));
}

#[test]
fn requested_scopes_defaults_to_the_f4_five() {
    // The environment is not mutated here: setting a variable is `unsafe` in
    // edition 2024 and would race every other test in this binary. What is
    // asserted is the default, which is what every run that does not override
    // it gets.
    if std::env::var_os(SCOPES_ENV).is_none() {
        assert_eq!(requested_scopes(), default_scopes());
    }
}

/// An instant `seconds` from now, saturating rather than panicking.
fn deadline(seconds: u64) -> Instant {
    let now = Instant::now();
    now.checked_add(Duration::from_secs(seconds)).unwrap_or(now)
}
