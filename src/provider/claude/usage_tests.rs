use httpmock::Method::GET;
use httpmock::MockServer;
use serde_json::json;

use super::*;

/// The live capture: credits off, three `limits[]` windows (plan AC2).
const CAPTURED: &str = include_str!("../../../fixtures/claude/usage-2026-09-08.json");
/// The live capture from a credits-enabled account (plan AC22's second vector).
const CREDITS_ON: &str = include_str!("../../../fixtures/claude/usage-extra-usage-enabled.json");
/// Synthetic: no `limits[]`, only the flat legacy keys (plan AC3).
const LEGACY: &str = include_str!("../../../fixtures/claude/usage-legacy-only.json");
/// Synthetic: a `kind` this build has never seen (plan AC4).
const UNKNOWN_KIND: &str = include_str!("../../../fixtures/claude/usage-unknown-kind.json");
/// Synthetic: no window anywhere in the body (plan AC49).
const EMPTY_LIMITS: &str = include_str!("../../../fixtures/claude/usage-empty-limits.json");

fn value(text: &str) -> Value {
    serde_json::from_str(text).expect("the fixture should be valid JSON")
}

fn ts(text: &str) -> Timestamp {
    text.parse::<Timestamp>().expect("the test literal should be a valid RFC 3339 timestamp")
}

fn snapshot(text: &str, keep_raw: bool) -> UsageSnapshot {
    parse_usage(&value(text), ts("2026-09-08T00:00:00Z"), keep_raw)
        .expect("every fixture body is a JSON object")
}

/// Credentials whose access token is the given string.
fn credentials(access: &str) -> Credentials {
    let blob = json!({
        "claudeAiOauth": {
            "accessToken": access,
            "refreshToken": "sk-ant-ort01-refresh",
            "expiresAt": 4_102_444_800_000i64,
            "scopes": ["user:inference", "user:profile"],
        }
    });
    Credentials::parse_blob(blob.to_string().as_bytes()).expect("the blob is well formed")
}

fn client(server: &MockServer) -> UsageClient {
    UsageClient::new(&server.base_url(), "agentctl/test", Duration::from_secs(5))
}

#[test]
fn ac2_the_captured_fixture_yields_exactly_three_windows() {
    let snapshot = snapshot(CAPTURED, false);

    assert_eq!(snapshot.windows.len(), 3, "the capture describes three windows");
    assert_eq!(snapshot.windows[0].kind, WindowKind::Session);
    assert_eq!(snapshot.windows[0].percent_floor, Some(21));
    assert_eq!(snapshot.windows[1].kind, WindowKind::WeeklyAll);
    assert_eq!(snapshot.windows[1].percent_floor, Some(35));
    assert_eq!(snapshot.windows[2].kind, WindowKind::WeeklyScoped("Fable".to_owned()));
    assert_eq!(snapshot.windows[2].percent_floor, Some(56));

    let active: Vec<bool> = snapshot.windows.iter().map(|w| w.is_active).collect();
    assert_eq!(active, vec![false, false, true], "only the scoped weekly is active");

    assert_eq!(
        snapshot.windows[0].resets_at,
        Some(ts("2026-09-08T03:29:59.817079+00:00")),
        "resets_at survives the sub-second precision the server sends"
    );
    assert_eq!(snapshot.windows[2].scope_label.as_deref(), Some("Fable"));
}

#[test]
fn ac2_the_flat_keys_are_ignored_when_limits_is_present() {
    // The capture carries `nimbus_quill` with `utilization: 0.0` alongside
    // `limits[]`. Reading both shapes would invent a fourth window.
    let snapshot = snapshot(CAPTURED, false);
    assert!(
        snapshot
            .windows
            .iter()
            .all(|w| !matches!(&w.kind, WindowKind::Unknown(k) if k == "nimbus_quill")),
        "an unrecognised flat key must not become a window while `limits[]` exists"
    );
}

#[test]
fn ac3_the_legacy_keys_map_when_limits_is_empty() {
    let snapshot = snapshot(LEGACY, false);

    let kinds: Vec<&WindowKind> = snapshot.windows.iter().map(|w| &w.kind).collect();
    assert_eq!(
        kinds,
        vec![
            &WindowKind::Session,
            &WindowKind::WeeklyAll,
            &WindowKind::WeeklyScoped("opus".to_owned()),
        ],
        "five_hour, seven_day and seven_day_opus, in that order"
    );

    let percents: Vec<Option<u8>> = snapshot.windows.iter().map(|w| w.percent_floor).collect();
    assert_eq!(percents, vec![Some(21), Some(35), Some(56)]);

    assert!(
        snapshot.windows.iter().all(|w| !w.is_active),
        "the flat shape predates is_active, so nothing may claim to be active"
    );
    assert_eq!(snapshot.windows[2].scope_label.as_deref(), Some("opus"));
}

#[test]
fn ac3_null_legacy_windows_are_dropped_not_rendered_as_zero() {
    // `seven_day_sonnet: null` means "this account has no such window", not
    // "this account is at 0 %".
    let snapshot = snapshot(LEGACY, false);
    assert!(
        !snapshot.windows.iter().any(|w| w.kind == WindowKind::WeeklyScoped("sonnet".to_owned())),
        "a null legacy window must not appear"
    );
}

#[test]
fn ac4_an_unrecognised_kind_becomes_a_visible_unknown_window() {
    let snapshot = snapshot(UNKNOWN_KIND, false);

    assert_eq!(snapshot.windows.len(), 3);
    let unknown = snapshot
        .windows
        .iter()
        .find(|w| matches!(&w.kind, WindowKind::Unknown(_)))
        .expect("the monthly_foo entry must survive normalization");
    assert_eq!(unknown.kind, WindowKind::Unknown("monthly_foo".to_owned()));
    assert_eq!(unknown.percent_floor, Some(7));
    assert!(unknown.is_active);
    assert_eq!(unknown.label(), "monthly_foo (unknown kind)");
}

#[test]
fn ac49_a_body_with_no_window_anywhere_parses_to_zero_windows() {
    // Not an error and not a panic: the caller turns this into the
    // `no subscription limits` state and exit 2.
    let snapshot = snapshot(EMPTY_LIMITS, false);
    assert!(snapshot.windows.is_empty());
    assert_eq!(snapshot.next_reset(), None);
    assert_eq!(snapshot.credits, CreditsState::Unavailable);
}

#[test]
fn credits_are_unavailable_in_this_build_even_when_the_body_has_them() {
    // Plan section 3.8: W1 defines the types and renders `n/a`; the
    // `extra_usage` parser lands in W2. This test is what will fail loudly
    // when that parser arrives, which is the intent.
    assert_eq!(snapshot(CREDITS_ON, false).credits, CreditsState::Unavailable);
    assert_eq!(snapshot(CAPTURED, false).credits, CreditsState::Unavailable);
}

#[test]
fn both_real_fixtures_round_trip_through_raw_untouched() {
    for text in [CAPTURED, CREDITS_ON] {
        let original = value(text);
        let snapshot = parse_usage(&original, ts("2026-09-08T00:00:00Z"), true)
            .expect("a real capture is a JSON object");
        let raw = snapshot.raw.expect("--raw keeps the body");
        assert_eq!(raw, original, "the raw body must be byte-for-byte the response");
        assert!(raw.get("spend").is_some(), "`spend` survives untouched (plan section 3.8)");
    }
}

#[test]
fn raw_is_absent_unless_it_was_asked_for() {
    assert!(snapshot(CAPTURED, false).raw.is_none());
}

#[test]
fn a_non_object_body_is_a_parse_failure() {
    let error = parse_usage(&json!([1, 2, 3]), ts("2026-09-08T00:00:00Z"), false)
        .expect_err("an array is not a usage document");
    assert!(error.contains("an array"), "the message should name what arrived: {error}");
}

#[test]
fn a_limits_entry_without_a_kind_is_dropped() {
    let body = json!({"limits": [{"percent": 50}, {"kind": "session", "percent": 10}]});
    let windows = normalize(body.as_object().expect("object"));
    assert_eq!(windows.len(), 1);
    assert_eq!(windows[0].kind, WindowKind::Session);
}

#[test]
fn a_scoped_window_without_a_display_name_still_appears() {
    let body = json!({"limits": [{"kind": "weekly_scoped", "percent": 12, "scope": null}]});
    let windows = normalize(body.as_object().expect("object"));
    assert_eq!(windows[0].kind, WindowKind::WeeklyScoped("scoped".to_owned()));
    assert_eq!(windows[0].scope_label, None);
}

#[test]
fn a_limits_array_of_only_unusable_entries_falls_back_to_the_legacy_keys() {
    // Otherwise an account served a malformed array would report "no
    // subscription limits" while its flat keys said 21 %.
    let body = json!({
        "limits": [{"percent": 50}],
        "five_hour": {"utilization": 21.0, "resets_at": null},
    });
    let windows = normalize(body.as_object().expect("object"));
    assert_eq!(windows.len(), 1);
    assert_eq!(windows[0].kind, WindowKind::Session);
    assert_eq!(windows[0].percent_floor, Some(21));
}

#[test]
fn an_unparseable_resets_at_leaves_the_percentage_intact() {
    let body = json!({"limits": [{"kind": "session", "percent": 21, "resets_at": "tomorrow"}]});
    let windows = normalize(body.as_object().expect("object"));
    assert_eq!(windows[0].percent_floor, Some(21));
    assert_eq!(windows[0].resets_at, None);
}

#[test]
fn retry_after_reads_both_forms_rfc_9110_allows() {
    let now = ts("2026-09-08T00:00:00Z");

    assert_eq!(parse_retry_after("30", now), Some(Duration::from_secs(30)));
    assert_eq!(parse_retry_after("  30  ", now), Some(Duration::from_secs(30)));
    assert_eq!(parse_retry_after("0", now), Some(Duration::ZERO));

    // HTTP-date, the IMF-fixdate spelling servers actually send.
    assert_eq!(
        parse_retry_after("Tue, 08 Sep 2026 00:02:00 GMT", now),
        Some(Duration::from_secs(120))
    );
    // A date already past means "retry now", not "no hint".
    assert_eq!(parse_retry_after("Mon, 07 Sep 2026 00:00:00 GMT", now), Some(Duration::ZERO));

    assert_eq!(parse_retry_after("", now), None);
    assert_eq!(parse_retry_after("soon", now), None);
    assert_eq!(parse_retry_after("-5", now), None);
}

#[test]
fn the_request_carries_exactly_the_headers_the_endpoint_needs() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(GET)
            .path(USAGE_PATH)
            .header("authorization", "Bearer sk-ant-oat01-observed")
            .header(BETA_HEADER, BETA_VALUE)
            .header("accept", "application/json")
            .header("user-agent", "agentctl/test");
        then.status(200).body(CAPTURED);
    });

    let client = client(&server);
    let credentials = credentials("sk-ant-oat01-observed");
    let account = AccountRef { id: "acct", credentials: &credentials };
    let snapshot =
        client.fetch(&account, &Cancel::new()).expect("a 200 with the captured body should parse");

    mock.assert_calls(1);
    assert_eq!(snapshot.windows.len(), 3);
}

#[test]
fn a_401_is_reported_as_unauthorized_so_the_pass_can_refresh_once() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        // The exact body the S3 probe observed for an expired access token.
        then.status(401).json_body(json!({
            "type": "error",
            "error": {
                "type": "authentication_error",
                "message": "OAuth access token has expired. Re-authenticate to continue."
            },
            "request_id": null
        }));
    });

    let credentials = credentials("sk-ant-oat01-expired");
    let error = client(&server)
        .fetch(&AccountRef { id: "acct", credentials: &credentials }, &Cancel::new())
        .expect_err("a 401 is not a snapshot");

    mock.assert_calls(1);
    assert_eq!(error, FetchError::Unauthorized);
    assert!(!error.is_transient(), "a rejected token is not worth retrying unchanged");
}

#[test]
fn a_429_carries_its_retry_hint_through() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(429).header("retry-after", "30").body("{}");
    });

    let credentials = credentials("sk-ant-oat01-limited");
    let error = client(&server)
        .fetch(&AccountRef { id: "acct", credentials: &credentials }, &Cancel::new())
        .expect_err("a 429 is not a snapshot");

    mock.assert_calls(1);
    assert_eq!(error, FetchError::RateLimited { retry_after: Some(Duration::from_secs(30)) });
    assert!(error.is_transient());
}

#[test]
fn a_429_without_a_hint_is_still_a_rate_limit() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(429).body("{}");
    });

    let credentials = credentials("sk-ant-oat01-limited");
    let error = client(&server)
        .fetch(&AccountRef { id: "acct", credentials: &credentials }, &Cancel::new())
        .expect_err("a 429 is not a snapshot");
    assert_eq!(error, FetchError::RateLimited { retry_after: None });
}

#[test]
fn other_statuses_are_reported_with_their_code_and_no_body() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(503).body("upstream said sk-ant-should-never-be-echoed");
    });

    let credentials = credentials("sk-ant-oat01-ok");
    let error = client(&server)
        .fetch(&AccountRef { id: "acct", credentials: &credentials }, &Cancel::new())
        .expect_err("a 503 is not a snapshot");

    assert_eq!(error, FetchError::Http { status: 503 });
    assert!(error.is_transient(), "a 5xx is worth another pass");
    assert!(!error.to_string().contains("sk-ant"), "a body must never reach the message");
}

#[test]
fn a_body_that_is_not_a_usage_document_is_a_parse_failure() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(200).body("<html>captive portal</html>");
    });

    let credentials = credentials("sk-ant-oat01-ok");
    let error = client(&server)
        .fetch(&AccountRef { id: "acct", credentials: &credentials }, &Cancel::new())
        .expect_err("HTML is not a usage document");
    assert!(matches!(error, FetchError::Parse(_)), "got {error:?}");
    assert!(!error.is_transient());
}

#[test]
fn a_cancelled_pass_makes_no_request_at_all() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(200).body(CAPTURED);
    });

    let cancel = Cancel::new();
    cancel.cancel();

    let credentials = credentials("sk-ant-oat01-ok");
    let error = client(&server)
        .fetch(&AccountRef { id: "acct", credentials: &credentials }, &cancel)
        .expect_err("a cancelled pass does not fetch");

    assert_eq!(error, FetchError::Cancelled);
    mock.assert_calls(0);
}

#[test]
fn the_usage_url_is_the_base_plus_the_path_with_no_double_slash() {
    let with_slash =
        UsageClient::new("https://example.test/", "agentctl/test", Duration::from_secs(1));
    assert_eq!(with_slash.usage_url(), "https://example.test/api/oauth/usage");

    let without = UsageClient::new("https://example.test", "agentctl/test", Duration::from_secs(1));
    assert_eq!(without.usage_url(), "https://example.test/api/oauth/usage");
}

#[test]
fn refresh_errors_say_what_the_row_should_do_about_them() {
    assert_eq!(
        RefreshError::InvalidGrant.to_string(),
        "the stored refresh token was rejected (invalid_grant)"
    );
    assert_eq!(
        RefreshError::RateLimited { retry_after_s: Some(5) }.to_string(),
        "the token endpoint is rate limiting, retry in 5s"
    );
    assert_eq!(
        RefreshError::RateLimited { retry_after_s: None }.to_string(),
        "the token endpoint is rate limiting"
    );
    assert_eq!(RefreshError::Cancelled.to_string(), "cancelled");
    assert_eq!(RefreshError::Transient("dns".to_owned()).to_string(), "dns");
}
