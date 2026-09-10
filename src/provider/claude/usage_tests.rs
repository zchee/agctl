use std::io::Write;
use std::sync::Arc;
use std::sync::Mutex;

use httpmock::Method::GET;
use httpmock::MockServer;
use serde_json::json;
use tracing_subscriber::fmt::MakeWriter;

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
/// Synthetic: credits on, no ceiling (plan section 3.8).
const CREDITS_UNLIMITED: &str =
    include_str!("../../../fixtures/claude/usage-extra-usage-unlimited.json");
/// Synthetic: credits on, no `used_credits` (plan section 3.8).
const CREDITS_UNMEASURED: &str =
    include_str!("../../../fixtures/claude/usage-extra-usage-unmeasured.json");
/// Synthetic: `spend` reports credits that `extra_usage` never mentions (R14).
const SPEND_ONLY: &str =
    include_str!("../../../fixtures/claude/usage-spend-without-extra-usage.json");
/// Synthetic: neither credits object appears at all (plan section 3.8).
const NO_CREDITS: &str = include_str!("../../../fixtures/claude/usage-no-credits.json");

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
    UsageClient::new(&server.base_url(), "agctl/test", Duration::from_secs(5))
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
    // The body still carries `extra_usage`, switched off: an account with no
    // subscription window can still have credits, and the two are separate
    // facts about it.
    assert_eq!(snapshot.credits, CreditsState::Off { reason: None });
}

// ---------------------------------------------------------------------------
// AC22 — credits, from `extra_usage` and nothing else (plan section 3.8)
// ---------------------------------------------------------------------------

/// A dollar amount in minor units, at the usual two decimal places.
fn usd(amount_minor: i64) -> Money {
    Money { amount_minor, currency: "USD".to_owned(), exponent: 2 }
}

/// The credits state and warnings a body produces.
fn credits(text: &str) -> (CreditsState, Vec<CreditsWarning>) {
    credits_from_body(&value(text))
}

/// An `extra_usage` object wrapped in an otherwise-bare body.
fn extra_usage(object: Value) -> Value {
    json!({ "extra_usage": object })
}

#[test]
fn ac22_the_live_capture_reports_credits_switched_off() {
    // The account this was captured from has never enabled credits, so
    // `is_enabled` is false and every figure beside it is null. `off` and
    // `n/a` are different answers and this body deserves the first.
    let (state, warnings) = credits(CAPTURED);
    assert_eq!(state, CreditsState::Off { reason: None });
    assert_eq!(warnings, Vec::new());
    // `spend` is present here too, and reports nothing: it must not turn a
    // resolved `Off` into a warning.
    assert_eq!(snapshot(CAPTURED, false).credits, CreditsState::Off { reason: None });
}

#[test]
fn ac22_the_credits_enabled_capture_maps_to_the_figures_the_site_shows() {
    // The one real body with credits on: monthly_limit 500000, used_credits
    // 21956.0, utilization 4.3911999999999995, decimal_places 2. The cell
    // this becomes is `$219.56 / $5000.00 (4%)`.
    let (state, warnings) = credits(CREDITS_ON);
    assert_eq!(
        state,
        CreditsState::On(Credits {
            used: Some(usd(21_956)),
            limit: Some(usd(500_000)),
            percent: Some(4),
        })
    );
    assert_eq!(warnings, Vec::new(), "utilization 4.39 and spend.percent 4 agree to a point");
}

#[test]
fn ac22_used_credits_arrives_as_a_float_and_monthly_limit_as_an_integer() {
    // Both spellings appear in the same real object, so a parser that read
    // only `as_i64` would drop the figure the column exists to show.
    let object = value(CREDITS_ON);
    let extra = object.get("extra_usage").and_then(Value::as_object).expect("the object is there");
    assert!(extra["used_credits"].is_f64(), "the capture sends used_credits as 21956.0");
    assert!(extra["monthly_limit"].is_i64(), "and monthly_limit as 500000");
}

#[test]
fn ac22_an_account_with_no_ceiling_keeps_its_used_figure() {
    let (state, warnings) = credits(CREDITS_UNLIMITED);
    assert_eq!(
        state,
        CreditsState::On(Credits { used: Some(usd(1234)), limit: None, percent: None })
    );
    assert_eq!(warnings, Vec::new());
}

#[test]
fn ac22_credits_on_with_no_used_figure_is_on_and_unmeasured() {
    // Not `Unavailable`: the account has credits. The renderer is what
    // decides an unmeasured spend shows as an em dash.
    let (state, warnings) = credits(CREDITS_UNMEASURED);
    assert_eq!(
        state,
        CreditsState::On(Credits { used: None, limit: Some(usd(500_000)), percent: None })
    );
    assert_eq!(warnings, Vec::new());
}

#[test]
fn ac22_r14_spend_reporting_credits_that_extra_usage_omits_warns_once() {
    // The under-delivery case: the column will read `n/a` while the web UI
    // shows $125.00 of $500.00. The warning is the only thing that says so.
    let (state, warnings) = credits(SPEND_ONLY);
    assert_eq!(state, CreditsState::Unavailable);
    assert_eq!(warnings, vec![CreditsWarning::SpendWithoutExtraUsage]);
}

#[test]
fn ac22_a_body_with_neither_credits_object_is_unavailable_and_silent() {
    for text in [NO_CREDITS, UNKNOWN_KIND] {
        let (state, warnings) = credits(text);
        assert_eq!(state, CreditsState::Unavailable);
        assert_eq!(warnings, Vec::new(), "nothing is being withheld, so nothing is warned about");
    }
}

#[test]
fn ac22_a_spend_object_of_only_prose_and_zeroes_is_not_a_withheld_figure() {
    // Every response carries a disclaimer and a severity. Warning on those
    // would fire on every account that simply predates `extra_usage`, and a
    // warning that always fires is one nobody reads.
    let body = json!({
        "spend": {
            "used": {"amount_minor": 0, "currency": "USD", "exponent": 2},
            "limit": null,
            "percent": 0,
            "severity": "normal",
            "enabled": false,
            "disclaimer": "Usage credits cover you when you hit your plan limits.",
            "can_purchase_credits": false,
        }
    });
    assert_eq!(credits_from_body(&body), (CreditsState::Unavailable, Vec::new()));
}

#[test]
fn ac22_each_thing_spend_can_say_about_a_live_balance_is_detected() {
    let cases = [
        ("enabled", json!({"enabled": true})),
        ("a ceiling", json!({"limit": {"amount_minor": 5000}})),
        ("a balance", json!({"balance": {"amount_minor": 100}})),
        ("a cap", json!({"cap": {"credits": {"amount_minor": 500_000, "exponent": 2}}})),
        ("a percentage", json!({"percent": 25})),
        ("an amount", json!({"used": {"amount_minor": 12500}})),
    ];
    for (what, spend) in cases {
        let (state, warnings) = credits_from_body(&json!({ "spend": spend }));
        assert_eq!(state, CreditsState::Unavailable, "{what}");
        assert_eq!(warnings, vec![CreditsWarning::SpendWithoutExtraUsage], "{what}");
    }
}

#[test]
fn ac22_r14_a_percentage_that_disagrees_with_spend_by_more_than_a_point_warns() {
    let body = json!({
        "extra_usage": {"is_enabled": true, "utilization": 25.0, "used_credits": 1234},
        "spend": {"percent": 90},
    });
    let (state, warnings) = credits_from_body(&body);
    assert_eq!(warnings, vec![CreditsWarning::PercentDisagrees { extra_usage: 25.0, spend: 90.0 }]);
    // The warning does not change the answer: `extra_usage` is still the
    // source, so the cell shows 25 % and `--raw` shows the disagreement.
    assert!(matches!(state, CreditsState::On(Credits { percent: Some(25), .. })));

    // Exactly a point apart is agreement; the tolerance is inclusive.
    let close = json!({
        "extra_usage": {"is_enabled": true, "utilization": 25.0},
        "spend": {"percent": 26},
    });
    assert_eq!(credits_from_body(&close).1, Vec::new());
}

#[test]
fn ac22_disabled_credits_carry_the_servers_own_reason() {
    let (state, warnings) = credits_from_body(&extra_usage(
        json!({"is_enabled": false, "disabled_reason": "past_due"}),
    ));
    assert_eq!(state, CreditsState::Off { reason: Some("past_due".to_owned()) });
    assert_eq!(warnings, Vec::new());
}

#[test]
fn ac22_a_decimal_places_the_currency_cannot_have_falls_back_to_two_and_warns() {
    for places in [-1i64, 7, 99] {
        let (state, warnings) = credits_from_body(&extra_usage(json!({
            "is_enabled": true,
            "used_credits": 1234,
            "currency": "USD",
            "decimal_places": places,
        })));
        assert_eq!(
            warnings,
            vec![CreditsWarning::ExponentOutOfRange { decimal_places: places }],
            "decimal_places {places}"
        );
        let CreditsState::On(credits) = state else { panic!("credits are on") };
        assert_eq!(credits.used, Some(usd(1234)), "the figure is still shown, at two places");
    }
}

#[test]
fn ac22_decimal_places_zero_and_three_are_honoured() {
    let cases = [(0u8, "JPY", "JPY 1234"), (3, "BHD", "BHD 1.234")];
    for (places, currency, expected) in cases {
        let (state, warnings) = credits_from_body(&extra_usage(json!({
            "is_enabled": true,
            "used_credits": 1234,
            "currency": currency,
            "decimal_places": places,
        })));
        assert_eq!(warnings, Vec::new());
        let CreditsState::On(credits) = state else { panic!("credits are on") };
        let used = credits.used.expect("used_credits was sent");
        assert_eq!(used.exponent, places);
        assert_eq!(used.to_string(), expected);
    }
}

#[test]
fn ac22_a_negative_balance_is_a_real_state_and_is_shown_as_one() {
    // Decision U6: a refunded account has spent a negative amount. Clamping
    // it to zero would hide a credit the user actually holds.
    let (state, warnings) = credits_from_body(&extra_usage(json!({
        "is_enabled": true,
        "used_credits": -500,
        "currency": "USD",
        "decimal_places": 2,
    })));
    assert_eq!(warnings, Vec::new());
    let CreditsState::On(credits) = state else { panic!("credits are on") };
    assert_eq!(credits.used, Some(usd(-500)));
    assert_eq!(credits.used.expect("used").to_string(), "-$5.00");
}

#[test]
fn ac22_utilization_is_taken_as_a_percentage_and_never_multiplied() {
    // Fact F23a: `extra_usage.utilization` is already 0-100. A build that
    // treated it as a fraction would show 439 % for the captured account.
    let cases: [(Value, Option<u8>); 7] = [
        (json!(-1), Some(0)),
        (json!(0), Some(0)),
        (json!(4.3911999999999995), Some(4)),
        (json!(99.5), Some(100)),
        (json!(100.4), Some(100)),
        (json!(250), Some(100)),
        (json!(null), None),
    ];
    for (utilization, expected) in cases {
        let (state, _) = credits_from_body(&extra_usage(json!({
            "is_enabled": true,
            "utilization": utilization,
        })));
        let CreditsState::On(credits) = state else { panic!("credits are on") };
        assert_eq!(credits.percent, expected, "utilization {utilization}");
    }
}

#[test]
fn ac22_a_currency_the_server_did_not_send_is_not_invented_as_dollars() {
    let (state, _) = credits_from_body(&extra_usage(json!({
        "is_enabled": true,
        "used_credits": 1234,
        "currency": null,
    })));
    let CreditsState::On(credits) = state else { panic!("credits are on") };
    let used = credits.used.expect("used_credits was sent");
    assert_eq!(used.currency, "");
    assert_eq!(used.to_string(), "12.34", "a bare figure, not a dollar sign");
}

#[test]
fn ac22_an_unreadable_money_field_is_absent_rather_than_saturated() {
    // `as` would land these on `i64::MAX`, and a confident `$92233720368...`
    // in a money column is worse than an em dash.
    for used in [json!("many"), json!(1e300), json!(-1e300), json!({}), json!(null)] {
        let (state, _) = credits_from_body(&extra_usage(json!({
            "is_enabled": true,
            "used_credits": used,
        })));
        let CreditsState::On(credits) = state else { panic!("credits are on") };
        assert_eq!(credits.used, None, "used_credits {used}");
    }
}

#[test]
fn ac22_an_extra_usage_without_the_declared_is_enabled_flag_is_unavailable() {
    // Fact F20 declares `is_enabled` as a required boolean. An object that
    // lacks it (or carries a non-boolean) is not the declared shape, and a
    // figure must not be invented from it.
    for body in [
        json!({"extra_usage": {}}),
        json!({"extra_usage": {"is_enabled": "yes", "used_credits": 100}}),
        json!({"extra_usage": {"is_enabled": null, "monthly_limit": 500000}}),
    ] {
        let (state, warnings) = credits_from_body(&body);
        assert_eq!(state, CreditsState::Unavailable, "body {body}");
        assert!(warnings.is_empty(), "no spend, so nothing to warn about: {body}");
    }
    let (state, warnings) = credits_from_body(&json!({
        "extra_usage": {},
        "spend": {"enabled": true, "percent": 25}
    }));
    assert_eq!(state, CreditsState::Unavailable);
    assert_eq!(warnings, vec![CreditsWarning::SpendWithoutExtraUsage]);
}

#[test]
fn ac22_a_body_that_is_not_an_object_has_no_credits_and_no_warning() {
    assert_eq!(credits_from_body(&json!([1, 2, 3])), (CreditsState::Unavailable, Vec::new()));
    assert_eq!(credits_from_body(&json!(null)), (CreditsState::Unavailable, Vec::new()));
}

/// A `MakeWriter` that keeps everything written to it.
///
/// The credits warnings are the only thing that tells a user their column may
/// disagree with the web UI, so "the warning was emitted" has to be a claim
/// about the log the process actually writes — not about a list a helper
/// returned and a caller might have dropped on the floor.
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

#[test]
fn ac22_the_warning_reaches_the_log_naming_the_row_and_raw() {
    let logs = captured_logs(|| {
        // The span `commands::status::run_account` enters around every parse.
        let span = tracing::info_span!("account", account.id = "owner@example.com");
        let _entered = span.enter();
        parse_usage(&value(SPEND_ONLY), ts("2026-09-08T00:00:00Z"), false)
            .expect("the fixture is a usage document");
    });

    assert!(logs.contains("WARN"), "got:\n{logs}");
    assert!(logs.contains("owner@example.com"), "the span names the row: got:\n{logs}");
    assert!(logs.contains("--raw"), "and the message says where the figure survives: got:\n{logs}");
    assert!(logs.contains("`spend` object reports credits"), "got:\n{logs}");
}

#[test]
fn a_body_with_nothing_to_warn_about_logs_nothing() {
    let logs = captured_logs(|| {
        parse_usage(&value(CREDITS_ON), ts("2026-09-08T00:00:00Z"), false)
            .expect("a real capture is a usage document");
    });
    assert_eq!(logs, "", "a healthy body is silent: got:\n{logs}");
}

#[test]
fn spend_is_never_parsed_into_the_snapshot_only_into_raw() {
    // Plan section 3.8: the only typed thing that may come out of `spend` is
    // the two warnings. Everything else about it survives in `--raw` alone.
    let snapshot = parse_usage(&value(CREDITS_ON), ts("2026-09-08T00:00:00Z"), true)
        .expect("a real capture is a JSON object");
    let raw = snapshot.raw.expect("--raw keeps the body");
    assert_eq!(raw["spend"]["used"]["amount_minor"], 21956);
    assert_eq!(raw["spend"]["percent"], 4);
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
            .header("user-agent", "agctl/test");
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
        UsageClient::new("https://example.test/", "agctl/test", Duration::from_secs(1));
    assert_eq!(with_slash.usage_url(), "https://example.test/api/oauth/usage");

    let without = UsageClient::new("https://example.test", "agctl/test", Duration::from_secs(1));
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
