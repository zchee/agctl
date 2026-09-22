use std::io::Write;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use flate2::Compression;
use flate2::write::GzEncoder;
use httpmock::Method::GET;
use httpmock::Method::POST;
use httpmock::MockServer;
use serde_json::json;
use tracing_subscriber::fmt::MakeWriter;

use crate::provider::UsageAuth;
use crate::provider::codex::credentials::Credentials;
use crate::provider::codex::testkit;
use crate::provider::codex::testkit::IdClaims;

use super::*;
use crate::provider::codex::testkit::record_header_names;

const F78: &str = include_str!("../../../fixtures/codex/usage-2026-09-16.json");
const CREDITS_ABSENT: &str = include_str!("../../../fixtures/codex/usage-credits-absent.json");
const CREDITS_UNLIMITED: &str =
    include_str!("../../../fixtures/codex/usage-credits-unlimited.json");
const NO_RATE_LIMIT: &str = include_str!("../../../fixtures/codex/usage-no-rate-limit.json");
const SENTINEL_EMAIL: &str = include_str!("../../../fixtures/codex/usage-sentinel-email.json");

/// The email `usage-sentinel-email.json` carries, so a leak is a substring.
const EMAIL_SENTINEL: &str = "agctl-test-codex-email-0001";

/// An access-token expiry far enough ahead that no test sees it as stale.
const FAR_EXPIRY: i64 = 4_102_444_800;

/// The header names `ureq` adds on its own, which the exact-set test allows.
const TRANSPORT_HEADERS: [&str; 2] = ["host", "accept-encoding"];

fn parse(text: &str) -> Value {
    serde_json::from_str(text).expect("the fixture should be valid JSON")
}

fn fetched_at() -> Timestamp {
    "2026-09-16T12:00:00Z".parse().expect("the test literal is a valid RFC 3339 timestamp")
}

fn normalized(text: &str) -> CodexUsage {
    normalize(&parse(text), fetched_at(), true).expect("every fixture body is a JSON object")
}

fn at(second: i64) -> Timestamp {
    Timestamp::from_second(second).expect("the test literal is a valid epoch second")
}

fn client(server: &MockServer) -> UsageClient {
    UsageClient::new(&server.base_url(), "agctl/test", Duration::from_secs(5))
}

/// Synthetic Codex credentials: the testkit document, optionally edited.
fn credentials(edit: impl FnOnce(&mut Value)) -> Credentials {
    let mut doc = testkit::chatgpt_doc(Some(FAR_EXPIRY), None);
    edit(&mut doc);
    Credentials::parse(&testkit::pretty(&doc)).expect("a synthetic document parses")
}

fn bearer() -> String {
    format!("Bearer {}", testkit::access_token(Some(FAR_EXPIRY)))
}

/// A `UsageAuth` whose header values the test chooses outright, so the
/// client's own refusal is exercised without depending on what the Codex
/// credential type filters first.
#[derive(Debug)]
struct FakeAuth {
    authorization: String,
    extra: Vec<(&'static str, String)>,
}

impl UsageAuth for FakeAuth {
    fn authorization_header(&self) -> String {
        self.authorization.clone()
    }

    fn extra_headers(&self) -> Vec<(&'static str, String)> {
        self.extra.clone()
    }
}

/// A log writer that keeps everything written to it.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Captured {
    fn text(&self) -> String {
        let buffer = self.0.lock().expect("the capture buffer is not poisoned");
        String::from_utf8_lossy(&buffer).into_owned()
    }
}

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("the capture buffer is not poisoned").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Captured {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Runs `body` against a subscriber that captures every line it logs.
fn captured_logs(body: impl FnOnce()) -> String {
    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(captured.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .finish();
    tracing::subscriber::with_default(subscriber, body);
    captured.text()
}

// --- AC85: the F78 capture ------------------------------------------------

#[test]
fn f78_capture_yields_the_weekly_window_then_both_spark_windows() {
    let usage = normalized(F78);

    let kinds: Vec<&WindowKind> = usage.windows.iter().map(|w| &w.window.kind).collect();
    assert_eq!(
        kinds,
        [
            &WindowKind::WeeklyAll,
            &WindowKind::Unknown("GPT-5.3-Codex-Spark:primary".to_owned()),
            &WindowKind::Unknown("GPT-5.3-Codex-Spark:secondary".to_owned()),
        ],
        "primary_window is the weekly one (F78-c) and the null secondary_window adds nothing"
    );

    let weekly = &usage.windows[0];
    assert_eq!(weekly.window.percent, Some(9.0));
    assert_eq!(weekly.window.percent_floor, Some(9));
    assert_eq!(weekly.window.resets_at, Some(at(1_790_120_247)));
    assert_eq!(weekly.window.scope_label, None);
    assert_eq!((&weekly.limit_name, &weekly.metered_feature), (&None, &None));

    for (window, reset) in usage.windows[1..].iter().zip([1_789_586_276, 1_790_173_076]) {
        assert_eq!(window.limit_name.as_deref(), Some("GPT-5.3-Codex-Spark"));
        assert_eq!(window.metered_feature.as_deref(), Some("codex_bengalfox"));
        assert_eq!(window.normal_model_slug, None, "a null slug stays absent");
        assert_eq!(window.window.scope_label.as_deref(), Some("GPT-5.3-Codex-Spark"));
        assert_eq!(window.window.percent, Some(0.0));
        assert_eq!(window.window.resets_at, Some(at(reset)));
    }
    assert!(usage.windows.iter().all(|w| !w.window.is_active), "no Codex window is marked active");

    assert_eq!(usage.plan_type.as_deref(), Some("pro"));
    assert_eq!(
        usage.credits,
        CodexCredits::Balance { balance: Some("12.34".to_owned()), unlimited: false }
    );
    assert_eq!(usage.state(), CodexState::Ok);
    assert_eq!(usage.note, None, "rate_limit_reached_type is null and every flag is clear");
}

#[test]
fn f78_capture_version_2_json_snapshot() {
    let usage = normalized(F78);
    let document = json!({
        "windows": usage.windows.iter().map(CodexWindow::to_json_v2).collect::<Vec<_>>(),
        "credits": usage.credits_json_v2(),
    });
    let rendered =
        serde_json::to_string_pretty(&document).expect("the version-2 objects serialize");

    assert!(rendered.contains("\"limit_name\": \"GPT-5.3-Codex-Spark\""), "{rendered}");
    assert!(rendered.contains("\"metered_feature\": \"codex_bengalfox\""), "{rendered}");
    assert!(rendered.contains("\"balance\": \"12.34\""), "the balance stays a string: {rendered}");
    insta::assert_snapshot!("f78_capture_json_v2", rendered);
}

#[test]
fn raw_body_is_kept_without_the_email_member() {
    let usage = normalized(F78);
    let raw = usage.raw.as_ref().and_then(Value::as_object).expect("the body is kept");

    assert!(!raw.contains_key("email"), "raw kept the email member: {raw:?}");
    let original = parse(F78);
    let original = original.as_object().expect("the fixture is an object");
    assert_eq!(raw.len(), original.len() - 1, "only the email member is removed");
    assert_eq!(raw.get("rate_limit_reset_credits"), original.get("rate_limit_reset_credits"));

    let without = normalize(&parse(F78), fetched_at(), false).expect("the fixture is an object");
    assert_eq!(without.raw, None);
}

#[test]
fn windows_are_classified_by_duration_not_by_position() {
    let usage = normalized(CREDITS_ABSENT);

    let kinds: Vec<&WindowKind> = usage.windows.iter().map(|w| &w.window.kind).collect();
    assert_eq!(kinds, [&WindowKind::WeeklyAll, &WindowKind::Session]);
    assert_eq!(usage.windows[0].window.percent_floor, Some(41));
    assert_eq!(usage.windows[1].window.percent_floor, Some(7));

    // The same pair with the slots swapped still says the same thing.
    let mut swapped = parse(CREDITS_ABSENT);
    let limit = swapped["rate_limit"].as_object_mut().expect("the fixture has a rate_limit");
    let primary = limit.remove("primary_window").expect("the fixture has a primary window");
    let secondary = limit.remove("secondary_window").expect("the fixture has a secondary window");
    limit.insert("primary_window".to_owned(), secondary);
    limit.insert("secondary_window".to_owned(), primary);
    let swapped = normalize(&swapped, fetched_at(), false).expect("still an object");
    let kinds: Vec<&WindowKind> = swapped.windows.iter().map(|w| &w.window.kind).collect();
    assert_eq!(kinds, [&WindowKind::Session, &WindowKind::WeeklyAll]);
}

#[test]
fn durations_outside_session_and_weekly_are_named_not_dropped() {
    let cases = [
        (json!(18_000), WindowKind::Session),
        (json!(21_600), WindowKind::Session),
        (json!(21_601), WindowKind::Unknown("6h".to_owned())),
        (json!(86_400), WindowKind::Unknown("24h".to_owned())),
        (json!(518_400), WindowKind::WeeklyAll),
        (json!(691_200), WindowKind::WeeklyAll),
        (json!(2_592_000), WindowKind::Unknown("720h".to_owned())),
        (json!(1_800), WindowKind::Session),
        (json!(0), WindowKind::Unknown("unknown duration".to_owned())),
        (json!(-5), WindowKind::Unknown("unknown duration".to_owned())),
        (json!("604800"), WindowKind::Unknown("unknown duration".to_owned())),
        (Value::Null, WindowKind::Unknown("unknown duration".to_owned())),
    ];
    for (seconds, expected) in cases {
        let body = json!({
            "rate_limit": { "primary_window": { "used_percent": 1, "limit_window_seconds": seconds } }
        });
        let usage = normalize(&body, fetched_at(), false).expect("an object");
        assert_eq!(usage.windows.len(), 1, "seconds {seconds}");
        assert_eq!(usage.windows[0].window.kind, expected, "seconds {seconds}");
    }
}

#[test]
fn percent_is_clamped_and_reset_falls_back_to_the_relative_member() {
    let body = json!({
        "rate_limit": {
            "primary_window": { "used_percent": 140.5, "limit_window_seconds": 18_000, "reset_after_seconds": 60 },
            "secondary_window": { "used_percent": -3, "limit_window_seconds": 604_800, "reset_after_seconds": i64::MAX }
        }
    });
    let usage = normalize(&body, fetched_at(), false).expect("an object");

    assert_eq!(usage.windows[0].window.percent, Some(100.0));
    assert_eq!(usage.windows[0].window.resets_at, Some(at(fetched_at().as_second() + 60)));
    assert_eq!(usage.windows[1].window.percent, Some(0.0));
    assert_eq!(usage.windows[1].window.resets_at, None, "an overflowing reset yields nothing");
}

#[test]
fn vendor_labels_are_echoed_only_when_plain() {
    let row = |name: Value| {
        json!({
            "rate_limit": {},
            "additional_rate_limits": [{
                "limit_name": name,
                "metered_feature": "feature\u{1b}[2J",
                "rate_limit": { "primary_window": { "used_percent": 5, "limit_window_seconds": 18_000 } }
            }]
        })
    };

    let plain = normalize(&row(json!("Model 7.1-mini")), fetched_at(), false).expect("an object");
    assert_eq!(plain.windows[0].limit_name.as_deref(), Some("Model 7.1-mini"));
    assert_eq!(plain.windows[0].metered_feature.as_deref(), Some("<unrecognised>"));

    for hostile in [json!("a:b"), json!("x\r\ny"), json!(" padded"), json!("n".repeat(65))] {
        let usage = normalize(&row(hostile.clone()), fetched_at(), false).expect("an object");
        assert_eq!(usage.windows[0].limit_name.as_deref(), Some("<unrecognised>"), "{hostile}");
        assert_eq!(
            usage.windows[0].window.kind,
            WindowKind::Unknown("<unrecognised>:primary".to_owned())
        );
    }

    let unnamed = normalize(&row(Value::Null), fetched_at(), false).expect("an object");
    assert_eq!(unnamed.windows[0].limit_name, None);
    assert_eq!(
        unnamed.windows[0].window.kind,
        WindowKind::Unknown("<unrecognised>:primary".to_owned()),
        "with no limit_name the metered feature names the row"
    );
}

// --- AC86: credits and the absent rate limit ------------------------------

#[test]
fn credits_absent_is_unavailable() {
    let usage = normalized(CREDITS_ABSENT);
    assert_eq!(usage.credits, CodexCredits::Unavailable);
    assert_eq!(usage.credits_json_v2().kind, "unavailable");
    assert_eq!(usage.plan_type.as_deref(), Some("plus"));
    assert_eq!(usage.state(), CodexState::Ok);
}

#[test]
fn unlimited_credits_with_a_reached_limit_is_a_note_not_a_state() {
    let usage = normalized(CREDITS_UNLIMITED);
    assert_eq!(usage.credits, CodexCredits::Balance { balance: None, unlimited: true });
    let json = usage.credits_json_v2();
    assert_eq!((json.kind, json.balance, json.unlimited), ("balance", None, Some(true)));
    assert_eq!(usage.note.as_deref(), Some("limit reached: rate_limit_reached"));
    assert_eq!(usage.state(), CodexState::Ok);
    assert_eq!(usage.windows.len(), 1);
    assert_eq!(usage.windows[0].window.percent, Some(100.0));
}

#[test]
fn no_rate_limit_is_the_no_usage_windows_state() {
    let usage = normalized(NO_RATE_LIMIT);
    assert!(usage.windows.is_empty());
    assert_eq!(usage.state(), CodexState::NoUsageWindows);
    assert_eq!(
        usage.credits,
        CodexCredits::Balance { balance: Some("0.00".to_owned()), unlimited: false }
    );
    assert_eq!(usage.plan_type.as_deref(), Some("free"));
}

#[test]
fn note_prefers_the_most_specific_statement() {
    let with = |reached: Value, limit_reached: bool, allowed: bool| {
        let body = json!({
            "rate_limit": { "allowed": allowed, "limit_reached": limit_reached },
            "rate_limit_reached_type": reached,
        });
        normalize(&body, fetched_at(), false).expect("an object")
    };

    assert_eq!(
        with(json!({ "type": "workspace_owner_credits_depleted" }), true, false).note.as_deref(),
        Some("limit reached: workspace_owner_credits_depleted")
    );
    assert_eq!(with(Value::Null, true, false).note.as_deref(), Some("limit reached"));
    assert_eq!(
        with(json!("primary"), true, true).note.as_deref(),
        Some("limit reached"),
        "a bare string is not the object F67 describes"
    );

    let not_allowed = with(Value::Null, false, false);
    assert_eq!(not_allowed.note.as_deref(), Some("requests are not currently allowed"));
    assert_eq!(not_allowed.state(), CodexState::Ok, "allowed:false keeps the row ok");

    assert_eq!(with(Value::Null, false, true).note, None);
}

#[test]
fn balance_is_kept_as_the_wire_spelled_it() {
    let cases = [
        (json!("12.34"), Some("12.34")),
        (json!("0.10"), Some("0.10")),
        (json!("-1.5"), Some("-1.5")),
        (json!("100"), Some("100")),
        (json!(7.25), None),
        (json!(12.10), None),
        (json!(3), None),
        (json!("1e3"), None),
        (json!("12."), None),
        (json!(".5"), None),
        (json!(""), None),
        (json!("NaN"), None),
        (json!(true), None),
        (Value::Null, None),
    ];
    for (balance, expected) in cases {
        let body = json!({ "credits": { "balance": balance, "unlimited": false } });
        let usage = normalize(&body, fetched_at(), false).expect("an object");
        assert_eq!(
            usage.credits,
            CodexCredits::Balance { balance: expected.map(str::to_owned), unlimited: false },
            "balance {balance}"
        );
    }
}

#[test]
fn an_unknown_plan_is_not_echoed() {
    let usage =
        normalize(&json!({ "plan_type": "ultra\u{7}" }), fetched_at(), false).expect("an object");
    assert_eq!(usage.plan_type.as_deref(), Some("unknown"));
    let usage = normalize(&json!({}), fetched_at(), false).expect("an object");
    assert_eq!(usage.plan_type, None);
}

#[test]
fn a_non_object_body_is_an_error() {
    for body in [json!([]), json!("usage"), Value::Null] {
        assert!(normalize(&body, fetched_at(), true).is_err(), "{body}");
    }
}

// --- AC101 unit half: the request, against a fake endpoint ---------------

#[test]
fn base_url_trailing_slashes_are_trimmed() {
    let client = UsageClient::new("http://127.0.0.1:9/", "agctl/test", Duration::from_secs(1));
    assert_eq!(client.usage_url(), "http://127.0.0.1:9/backend-api/wham/usage");
}

/// The header names of each recorded request, less the ones `ureq` adds.
fn sent_header_names(names: &Mutex<Vec<Vec<String>>>) -> Vec<Vec<String>> {
    names
        .lock()
        .expect("the header record is not poisoned")
        .iter()
        .map(|request| {
            request
                .iter()
                .filter(|name| !TRANSPORT_HEADERS.contains(&name.as_str()))
                .cloned()
                .collect()
        })
        .collect()
}

#[test]
fn request_carries_exactly_the_expected_headers() {
    let server = MockServer::start();
    let names = Arc::new(Mutex::new(Vec::new()));
    let mock = server.mock(|when, then| {
        when.method(GET)
            .path(USAGE_PATH)
            .header("authorization", bearer())
            .header("accept", "application/json")
            .header("user-agent", "agctl/test")
            .header("chatgpt-account-id", testkit::ACCT)
            .header_missing("x-openai-fedramp")
            .is_true(record_header_names(Arc::clone(&names)));
        then.status(200).body(F78);
    });

    let auth = credentials(|_| {});
    let usage = client(&server)
        .fetch(&AccountRef { id: "acct", auth: &auth }, &Cancel::new())
        .expect("the fake endpoint answers 200");

    mock.assert_calls(1);
    assert_eq!(usage.windows.len(), 3);
    assert_eq!(
        sent_header_names(&names),
        [["accept", "authorization", "chatgpt-account-id", "user-agent"]]
    );
}

/// Plan AC101 and ledger #274 (d): both credential variants are answered
/// with the one F78 body, and each request is pinned to its full header set,
/// the two sets differing only in `x-openai-fedramp`.
#[test]
fn fedramp_header_is_sent_only_for_a_fedramp_account() {
    let server = MockServer::start();
    let fedramp_names = Arc::new(Mutex::new(Vec::new()));
    let plain_names = Arc::new(Mutex::new(Vec::new()));
    let fedramp = server.mock(|when, then| {
        when.method(GET)
            .path(USAGE_PATH)
            .header("authorization", bearer())
            .header("accept", "application/json")
            .header("user-agent", "agctl/test")
            .header("chatgpt-account-id", testkit::ACCT)
            .header("x-openai-fedramp", "true")
            .is_true(record_header_names(Arc::clone(&fedramp_names)));
        then.status(200).body(F78);
    });
    let plain = server.mock(|when, then| {
        when.method(GET)
            .path(USAGE_PATH)
            .header("authorization", bearer())
            .header("accept", "application/json")
            .header("user-agent", "agctl/test")
            .header("chatgpt-account-id", testkit::ACCT)
            .header_missing("x-openai-fedramp")
            .is_true(record_header_names(Arc::clone(&plain_names)));
        then.status(200).body(F78);
    });
    let client = client(&server);

    let without = credentials(|_| {});
    client
        .fetch(&AccountRef { id: "plain", auth: &without }, &Cancel::new())
        .expect("the plain account is served");
    fedramp.assert_calls(0);
    plain.assert_calls(1);

    let with = credentials(|doc| {
        doc["tokens"]["id_token"] =
            json!(testkit::id_token(&IdClaims { fedramp: Some(true), ..IdClaims::default() }));
    });
    client
        .fetch(&AccountRef { id: "fedramp", auth: &with }, &Cancel::new())
        .expect("the fedramp account is served");
    fedramp.assert_calls(1);
    plain.assert_calls(1);

    assert_eq!(
        sent_header_names(&plain_names),
        [["accept", "authorization", "chatgpt-account-id", "user-agent"]]
    );
    assert_eq!(
        sent_header_names(&fedramp_names),
        [["accept", "authorization", "chatgpt-account-id", "user-agent", "x-openai-fedramp"]]
    );
}

/// Fact F79-b: the endpoint answers with three `set-cookie` headers, and a
/// client that kept them would send one account's cookies with the next
/// account's request in the same pass. `ureq`'s `cookies` feature is off in
/// this build; this pins that a second request carries no `cookie` header.
#[test]
fn a_set_cookie_is_not_sent_back_on_the_next_request() {
    let server = MockServer::start();
    let names = Arc::new(Mutex::new(Vec::new()));
    let mock = server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH).is_true(record_header_names(Arc::clone(&names)));
        then.status(200)
            .header("set-cookie", "__cf_bm=agctl-test-cookie; Path=/; HttpOnly")
            .body(F78);
    });
    let auth = credentials(|_| {});
    let client = client(&server);

    for id in ["first", "second"] {
        client
            .fetch(&AccountRef { id, auth: &auth }, &Cancel::new())
            .expect("the fake endpoint answers 200");
    }

    mock.assert_calls(2);
    let recorded = names.lock().expect("the header record is not poisoned");
    assert!(
        recorded.iter().all(|request| !request.iter().any(|name| name == "cookie")),
        "a request carried a cookie: {recorded:?}"
    );
}

#[test]
fn status_401_is_unauthorized() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(401).body("{\"detail\":\"token expired\"}");
    });
    let auth = credentials(|_| {});
    let err = client(&server)
        .fetch(&AccountRef { id: "acct", auth: &auth }, &Cancel::new())
        .expect_err("401 is an error");
    assert_eq!(err, FetchError::Unauthorized);
    mock.assert_calls(1);
}

#[test]
fn status_403_is_http_and_never_a_refresh() {
    let server = MockServer::start();
    let usage = server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(403).body("{\"detail\":\"forbidden\"}");
    });
    let posts = server.mock(|when, then| {
        when.method(POST);
        then.status(500);
    });
    let auth = credentials(|_| {});
    let err = client(&server)
        .fetch(&AccountRef { id: "acct", auth: &auth }, &Cancel::new())
        .expect_err("403 is an error");
    assert_eq!(err, FetchError::Http { status: 403 });
    assert_ne!(err, FetchError::Unauthorized, "403 must not reach the refresh-once path");
    usage.assert_calls(1);
    posts.assert_calls(0);
}

#[test]
fn status_429_reports_retry_after_and_is_not_retried() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(429).header("retry-after", "30");
    });
    let auth = credentials(|_| {});
    let err = client(&server)
        .fetch(&AccountRef { id: "acct", auth: &auth }, &Cancel::new())
        .expect_err("429 is an error");
    assert_eq!(err, FetchError::RateLimited { retry_after: Some(Duration::from_secs(30)) });
    mock.assert_calls(1);
}

#[test]
fn status_429_without_retry_after_has_no_hint() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(429);
    });
    let auth = credentials(|_| {});
    let err = client(&server)
        .fetch(&AccountRef { id: "acct", auth: &auth }, &Cancel::new())
        .expect_err("429 is an error");
    assert_eq!(err, FetchError::RateLimited { retry_after: None });
    mock.assert_calls(1);
}

#[test]
fn other_statuses_are_http() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(503).body("<html>maintenance</html>");
    });
    let auth = credentials(|_| {});
    let err = client(&server)
        .fetch(&AccountRef { id: "acct", auth: &auth }, &Cancel::new())
        .expect_err("503 is an error");
    assert_eq!(err, FetchError::Http { status: 503 });
    mock.assert_calls(1);
}

#[test]
fn body_over_four_mebibytes_is_a_parse_error() {
    let padding = "x".repeat(usize::try_from(MAX_BODY_BYTES).expect("4 MiB fits in usize"));
    let body = serde_json::to_string(&json!({ "plan_type": "pro", "padding": padding }))
        .expect("the oversized body serializes");
    assert!(u64::try_from(body.len()).is_ok_and(|len| len > MAX_BODY_BYTES));

    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(200).body(body);
    });
    let auth = credentials(|_| {});
    let err = client(&server)
        .fetch(&AccountRef { id: "acct", auth: &auth }, &Cancel::new())
        .expect_err("an oversized body is refused");
    assert!(matches!(err, FetchError::Parse(_)), "{err:?}");
    mock.assert_calls(1);
}

/// Review S31 F2: the wire limit sits under the gzip decoder, so the decoded
/// bytes are bounded too. The compressed body is a few kilobytes; decoded it
/// is over the ceiling.
#[test]
fn a_gzip_body_over_four_mebibytes_decoded_is_a_parse_error() {
    let padding = "x".repeat(usize::try_from(MAX_BODY_BYTES).expect("4 MiB fits in usize"));
    let document = serde_json::to_vec(&json!({ "plan_type": "pro", "padding": padding }))
        .expect("the oversized body serializes");
    assert!(u64::try_from(document.len()).is_ok_and(|len| len > MAX_BODY_BYTES));
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(&document).expect("gzip into memory");
    let compressed = encoder.finish().expect("gzip into memory");
    assert!(
        u64::try_from(compressed.len()).is_ok_and(|len| len < MAX_BODY_BYTES),
        "the compressed body alone is under the wire limit"
    );

    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(200)
            .header("content-type", "application/json")
            .header("content-encoding", "gzip")
            .body(compressed);
    });
    let auth = credentials(|_| {});
    let err = client(&server)
        .fetch(&AccountRef { id: "acct", auth: &auth }, &Cancel::new())
        .expect_err("an oversized decoded body is refused");
    assert_eq!(
        err,
        FetchError::Parse("the response body is larger than this build reads".to_owned())
    );
    mock.assert_calls(1);
}

/// The decoded ceiling is a ceiling, not a cut-off below it: a gzip body that
/// decodes to a normal document is read.
#[test]
fn a_gzip_body_under_the_ceiling_is_read() {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(F78.as_bytes()).expect("gzip into memory");
    let compressed = encoder.finish().expect("gzip into memory");

    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(200).header("content-encoding", "gzip").body(compressed);
    });
    let auth = credentials(|_| {});
    let usage = client(&server)
        .fetch(&AccountRef { id: "acct", auth: &auth }, &Cancel::new())
        .expect("a gzip usage document is read");
    assert_eq!(usage.windows.len(), 3);
}

/// Review S31 F1: a fixed endpoint follows no redirect. The 3xx is the
/// answer, the `Location` target is never contacted (it would receive the
/// account id and FedRAMP headers), and its 401 can never become the refresh
/// trigger.
#[test]
fn a_redirect_is_not_followed() {
    let server = MockServer::start();
    let origin = server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(302).header("location", server.url("/elsewhere"));
    });
    let target = server.mock(|when, then| {
        when.any_request().path("/elsewhere");
        then.status(401);
    });
    let posts = server.mock(|when, then| {
        when.method(POST);
        then.status(500);
    });
    let auth = credentials(|doc| {
        doc["tokens"]["id_token"] =
            json!(testkit::id_token(&IdClaims { fedramp: Some(true), ..IdClaims::default() }));
    });

    let err = client(&server)
        .fetch(&AccountRef { id: "acct", auth: &auth }, &Cancel::new())
        .expect_err("a redirect is an error");

    assert_eq!(err, FetchError::Http { status: 302 });
    origin.assert_calls(1);
    target.assert_calls(0);
    posts.assert_calls(0);
}

#[test]
fn a_non_json_success_is_a_parse_error() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(200).body("<html>sign in</html>");
    });
    let auth = credentials(|_| {});
    let err = client(&server)
        .fetch(&AccountRef { id: "acct", auth: &auth }, &Cancel::new())
        .expect_err("HTML is not a usage document");
    assert!(matches!(err, FetchError::Parse(_)), "{err:?}");
}

#[test]
fn a_cancelled_pass_sends_nothing() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.any_request();
        then.status(200).body(F78);
    });
    let cancel = Cancel::new();
    cancel.cancel();
    let auth = credentials(|_| {});
    let err = client(&server)
        .fetch(&AccountRef { id: "acct", auth: &auth }, &cancel)
        .expect_err("a cancelled pass does not fetch");
    assert_eq!(err, FetchError::Cancelled);
    mock.assert_calls(0);
}

#[test]
fn an_unsendable_extra_header_is_refused_before_any_request() {
    let hostile =
        ["acct\r\nX-Injected: 1", "acct\nX-Injected: 1", "acct id", "acct\u{0}", "acct\u{e9}", ""];
    for value in hostile {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.any_request();
            then.status(200).body(F78);
        });
        let auth = FakeAuth {
            authorization: bearer(),
            extra: vec![("ChatGPT-Account-Id", value.to_owned())],
        };
        let err = client(&server)
            .fetch(&AccountRef { id: "acct", auth: &auth }, &Cancel::new())
            .expect_err("a hostile account id is refused");

        assert_eq!(
            err,
            FetchError::Parse("the ChatGPT-Account-Id header value cannot be sent".to_owned()),
            "value {value:?}"
        );
        assert!(!err.to_string().contains("X-Injected"), "the error echoed the value: {err}");
        mock.assert_calls(0);
    }
}

#[test]
fn an_unsendable_authorization_is_refused_before_any_request() {
    let token = testkit::access_token(Some(FAR_EXPIRY));
    let hostile = [
        String::new(),
        "Bearer".to_owned(),
        "Bearer ".to_owned(),
        format!("Bearer  {token}"),
        format!("Bearer {token}\r\nX-Injected: 1"),
        format!("Bearer {token} extra"),
        format!("Bearer\t{token}"),
    ];
    for value in hostile {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.any_request();
            then.status(200).body(F78);
        });
        let auth = FakeAuth { authorization: value.clone(), extra: Vec::new() };
        let err = client(&server)
            .fetch(&AccountRef { id: "acct", auth: &auth }, &Cancel::new())
            .expect_err("a malformed authorization is refused");

        assert_eq!(
            err,
            FetchError::Parse("the authorization header value cannot be sent".to_owned()),
            "value {value:?}"
        );
        testkit::assert_no_needles(&err.to_string(), "the refusal");
        mock.assert_calls(0);
    }
}

/// The refusal for a missing account id header, as `fetch` spells it.
fn missing_account_id() -> FetchError {
    FetchError::Parse("the ChatGPT-Account-Id header is missing".to_owned())
}

/// A CR/LF account id in `auth.json`: the Codex credential type drops the
/// pair rather than hand it over, and the client then refuses the request
/// for lacking the header (ledger #274 (c2)). The two layers agree: an
/// unsendable id never fetches, with or without the header.
#[test]
fn a_hostile_account_id_in_credentials_never_reaches_the_wire() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.any_request();
        then.status(200).body(F78);
    });

    let auth = credentials(|doc| {
        doc["tokens"]["account_id"] = json!("acct\r\nX-Injected: 1");
    });
    let err = client(&server)
        .fetch(&AccountRef { id: "acct", auth: &auth }, &Cancel::new())
        .expect_err("a hostile account id is refused");

    assert_eq!(err, missing_account_id());
    assert!(!err.to_string().contains("X-Injected"), "the error echoed the value: {err}");
    mock.assert_calls(0);
}

/// Credentials with no `tokens.account_id`, and a `UsageAuth` that hands over
/// no extra headers at all: neither is a usable Codex account (facts F67,
/// F91; plan AC101), so neither makes a request (ledger #274 (c2)).
#[test]
fn a_missing_account_id_is_refused_before_any_request() {
    let without_id = credentials(|doc| {
        let tokens = doc["tokens"].as_object_mut().expect("the testkit document has tokens");
        tokens.remove("account_id");
    });
    let no_extras = FakeAuth { authorization: bearer(), extra: Vec::new() };
    let only_fedramp =
        FakeAuth { authorization: bearer(), extra: vec![("X-OpenAI-Fedramp", "true".to_owned())] };
    let cases: [(&str, &dyn UsageAuth); 3] = [
        ("credentials without tokens.account_id", &without_id),
        ("no extra headers", &no_extras),
        ("the fedramp flag alone", &only_fedramp),
    ];

    for (case, auth) in cases {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.any_request();
            then.status(200).body(F78);
        });
        let err = client(&server)
            .fetch(&AccountRef { id: "acct", auth }, &Cancel::new())
            .expect_err("an account without an id is refused");

        assert_eq!(err, missing_account_id(), "{case}");
        testkit::assert_no_needles(&err.to_string(), case);
        mock.assert_calls(0);
    }
}

#[test]
fn the_account_id_header_is_recognised_in_any_case() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH).header("chatgpt-account-id", testkit::ACCT);
        then.status(200).body(F78);
    });
    let auth = FakeAuth {
        authorization: bearer(),
        extra: vec![("chatgpt-account-id", testkit::ACCT.to_owned())],
    };

    client(&server)
        .fetch(&AccountRef { id: "acct", auth: &auth }, &Cancel::new())
        .expect("a lower-case header name is still the account id header");
    mock.assert_calls(1);
}

// --- No email, no secret, anywhere this module writes --------------------

#[test]
fn the_email_never_leaves_normalize() {
    let usage = normalized(SENTINEL_EMAIL);
    assert!(SENTINEL_EMAIL.contains(EMAIL_SENTINEL), "the fixture carries the sentinel");

    let debug = format!("{usage:?}");
    assert!(!debug.contains(EMAIL_SENTINEL), "Debug leaked the email: {debug}");
    let raw = serde_json::to_string(&usage.raw).expect("raw serializes");
    assert!(!raw.contains(EMAIL_SENTINEL), "raw leaked the email: {raw}");
    let windows = serde_json::to_string(
        &usage.windows.iter().map(CodexWindow::to_json_v2).collect::<Vec<_>>(),
    )
    .expect("the windows serialize");
    assert!(!windows.contains(EMAIL_SENTINEL), "v2 windows leaked the email: {windows}");
    let credits = serde_json::to_string(&usage.credits_json_v2()).expect("credits serialize");
    assert!(!credits.contains(EMAIL_SENTINEL), "v2 credits leaked the email: {credits}");
}

#[test]
fn a_traced_fetch_logs_no_email_token_or_header_value() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(200).body(SENTINEL_EMAIL);
    });
    let auth = credentials(|_| {});
    let client = client(&server);

    let mut outcome = None;
    let logs = captured_logs(|| {
        outcome = Some(client.fetch(&AccountRef { id: "acct", auth: &auth }, &Cancel::new()));
    });
    let usage = outcome.expect("the body ran").expect("the fake endpoint answers 200");

    assert!(logs.contains("fetching codex usage"), "the trace line was captured: {logs}");
    assert!(!logs.contains(EMAIL_SENTINEL), "the log leaked the email:\n{logs}");
    assert!(!logs.contains(testkit::ACCT), "the log leaked the account id:\n{logs}");
    assert!(!logs.to_ascii_lowercase().contains("bearer"), "the log leaked a header:\n{logs}");
    testkit::assert_no_needles(&logs, "the fetch log");
    assert!(!format!("{usage:?}").contains(EMAIL_SENTINEL));
}

#[test]
fn from_env_never_falls_back_to_the_vendor_in_a_testing_build() {
    // Read, never set: a process variable set here would race every other
    // test. Whatever the seam holds, a `testing` build's URL is it or the
    // loopback fallback — never the vendor's host (review S31 F8).
    let client = UsageClient::from_env(Duration::from_secs(1));
    #[cfg(feature = "testing")]
    {
        let base = std::env::var(USAGE_URL_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| TESTING_FALLBACK_BASE_URL.to_owned());
        assert_eq!(client.usage_url(), format!("{}{USAGE_PATH}", base.trim_end_matches('/')));
        assert!(!client.usage_url().starts_with(DEFAULT_BASE_URL));
        assert!(TESTING_FALLBACK_BASE_URL.starts_with("http://127.0.0.1:"));
    }
    #[cfg(not(feature = "testing"))]
    assert_eq!(client.usage_url(), format!("{DEFAULT_BASE_URL}{USAGE_PATH}"));
}

#[cfg(feature = "testing")]
#[test]
fn the_testing_fallback_refuses_before_a_request_is_read() {
    let client = UsageClient::new(TESTING_FALLBACK_BASE_URL, "agctl/test", Duration::from_secs(2));
    let credentials = credentials(|_| {});
    let account = AccountRef { id: "user-fallback", auth: &credentials };

    let outcome = client.fetch(&account, &Cancel::new());

    assert!(matches!(outcome, Err(FetchError::Transport(_))), "{outcome:?}");
}
