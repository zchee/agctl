use jiff::Timestamp;
use jiff::tz::Offset;
use jiff::tz::TimeZone;
use serde_json::Value;
use serde_json::json;

use super::*;
use crate::provider::claude::usage::credits_from_body;
use crate::usage::model::UsageSnapshot;
use crate::usage::model::clamp_percent;
use crate::usage::model::percent_floor;

/// The credits-enabled live capture, so the cell can be asserted against the
/// figures a real account produces rather than against invented ones.
const CREDITS_ON: &str = include_str!("../../fixtures/claude/usage-extra-usage-enabled.json");

/// The fixed "now" every snapshot is rendered against, so a countdown is a
/// constant rather than a moving target.
///
/// 09:00 on Tuesday 2026-09-08 in the zone below.
const NOW: &str = "2026-09-08T00:00:00Z";

/// The zone every snapshot is rendered in.
///
/// Injected rather than [`TimeZone::system`], and a fixed offset rather than a
/// named entry, for two reasons: a snapshot recorded in one zone must not be
/// re-recorded in another, and `+09:00` puts the weekly reset on a different
/// *local* day from its UTC day, so the snapshots pin the local-calendar rule
/// rather than accidentally agreeing with UTC.
fn tz() -> TimeZone {
    TimeZone::fixed(Offset::constant(9))
}

fn ts(text: &str) -> Timestamp {
    text.parse::<Timestamp>().expect("the test literal should be a valid RFC 3339 timestamp")
}

fn window(kind: WindowKind, percent: f64, resets_at: Option<&str>) -> LimitWindow {
    LimitWindow {
        kind,
        percent: clamp_percent(percent),
        percent_floor: percent_floor(percent),
        severity: None,
        resets_at: resets_at.map(ts),
        scope_label: None,
        is_active: false,
    }
}

fn usage(windows: Vec<LimitWindow>, credits: CreditsState) -> UsageSnapshot {
    UsageSnapshot { fetched_at: ts(NOW), windows, credits, raw: None }
}

/// The three windows a healthy subscription account reports.
fn healthy_windows() -> Vec<LimitWindow> {
    vec![
        window(WindowKind::Session, 21.0, Some("2026-09-08T02:13:40Z")),
        window(WindowKind::WeeklyAll, 35.0, Some("2026-09-10T20:00:00Z")),
        window(WindowKind::WeeklyScoped("Fable".to_owned()), 56.0, Some("2026-09-10T20:00:00Z")),
    ]
}

fn healthy_row(account: &str) -> StatusRow {
    StatusRow {
        account: account.to_owned(),
        org: "Acme".to_owned(),
        plan: "max".to_owned(),
        state: "ok".to_owned(),
        note: None,
        usage: Some(usage(healthy_windows(), CreditsState::Unavailable)),
        visible_by_default: true,
    }
}

/// A row with no numbers, in the given state.
fn empty_row(account: &str, state: &str) -> StatusRow {
    StatusRow {
        account: account.to_owned(),
        org: String::new(),
        plan: String::new(),
        state: state.to_owned(),
        note: None,
        usage: None,
        visible_by_default: true,
    }
}

fn report(rows: Vec<StatusRow>, show_all: bool) -> Report {
    Report { rows, now: ts(NOW), tz: tz(), show_all }
}

/// The cells of the rendered row whose first column contains `needle`.
///
/// The reset columns are asserted by position rather than by `contains`,
/// because "the `5h reset` cell is blank" is a claim about a column and a
/// substring search cannot make it.
fn cells_of(rendered: &str, needle: &str) -> Vec<String> {
    let line = rendered
        .lines()
        .find(|line| line.contains(needle))
        .unwrap_or_else(|| panic!("no row contains `{needle}`:\n{rendered}"));
    line.split('|').map(|cell| cell.trim().to_owned()).collect()
}

/// Where one heading sits, so the assertions below name columns rather than
/// indices and a reordering fails loudly instead of silently.
fn column(heading: &str) -> usize {
    HEADINGS
        .iter()
        .position(|candidate| *candidate == heading)
        .unwrap_or_else(|| panic!("`{heading}` is not one of the headings: {HEADINGS:?}"))
}

#[test]
fn two_healthy_accounts_render_as_one_aligned_table() {
    let report =
        report(vec![healthy_row("alice@example.com"), healthy_row("bob@example.com")], false);
    insta::assert_snapshot!("two_accounts", render(&report));
}

#[test]
fn hidden_rows_are_summarised_in_a_footer() {
    let mut sibling = healthy_row("5cdc535f");
    sibling.usage = None;
    sibling.state = "stale sibling of live".to_owned();
    sibling.visible_by_default = false;

    let mut switcher = empty_row("claude-switcher:user", "unclaimed");
    switcher.visible_by_default = false;

    let report = report(vec![healthy_row("alice@example.com"), sibling, switcher], false);
    let rendered = render(&report);

    assert!(rendered.ends_with("2 entries hidden (--all)"), "got:\n{rendered}");
    assert!(!rendered.contains("5cdc535f"), "a hidden row must not be printed");
    insta::assert_snapshot!("hidden_footer", rendered);
}

#[test]
fn all_reveals_the_hidden_rows_and_drops_the_footer() {
    let mut sibling = empty_row("5cdc535f", "stale sibling of live");
    sibling.visible_by_default = false;

    let report = report(vec![healthy_row("alice@example.com"), sibling], true);
    let rendered = render(&report);

    assert!(rendered.contains("5cdc535f"));
    assert!(!rendered.contains("hidden (--all)"));
    insta::assert_snapshot!("all_rows", rendered);
}

#[test]
fn ac4_an_unknown_window_gets_a_continuation_row_naming_its_kind() {
    let mut windows = healthy_windows();
    windows.push(window(
        WindowKind::Unknown("monthly_foo".to_owned()),
        7.0,
        Some("2026-10-01T00:00:00Z"),
    ));
    windows.push(window(WindowKind::WeeklyScoped("opus".to_owned()), 12.0, None));

    let mut row = healthy_row("alice@example.com");
    row.usage = Some(usage(windows, CreditsState::Unavailable));

    let rendered = render(&report(vec![row], false));
    assert!(rendered.contains("↳ monthly_foo (unknown kind)"), "got:\n{rendered}");
    assert!(rendered.contains("↳ opus (weekly)"), "got:\n{rendered}");
    insta::assert_snapshot!("continuation_rows", rendered);
}

#[test]
fn a_row_with_no_numbers_shows_em_dashes_rather_than_zeroes() {
    // `0%` would be a claim about the account. An account whose keychain is
    // locked has not been measured at all.
    let mut row = empty_row("alice@example.com", "keychain locked");
    row.org = "Acme".to_owned();

    let rendered = render(&report(vec![row], false));
    assert!(!rendered.contains("0%"), "got:\n{rendered}");
    insta::assert_snapshot!("no_numbers", rendered);
}

#[test]
fn degraded_states_render_with_their_notes() {
    let mut rate_limited = healthy_row("alice@example.com");
    rate_limited.state = "rate-limited (retry in 30s)".to_owned();
    rate_limited.note = Some("showing cached values".to_owned());

    let mut detected = empty_row(
        "bob@example.com",
        "claude session detected — refresh refused (lock .oauth_refresh.lock, age 3s)",
    );
    detected.org = "Acme".to_owned();

    let no_limits = StatusRow {
        account: "carol@example.com".to_owned(),
        org: "Acme".to_owned(),
        plan: String::new(),
        state: "no subscription limits (API/console account?)".to_owned(),
        note: None,
        usage: Some(usage(Vec::new(), CreditsState::Unavailable)),
        visible_by_default: true,
    };

    insta::assert_snapshot!(
        "degraded_states",
        render(&report(vec![rate_limited, detected, no_limits], false))
    );
}

/// The credits state a usage body parses to.
///
/// Every credits cell in these tests goes through the real parser rather than
/// a hand-built [`CreditsState`], so the snapshot pins a rendering that some
/// response can actually produce — a cell format no body reaches is a format
/// nobody is testing.
fn parsed_credits(body: &Value) -> CreditsState {
    let (credits, _) = credits_from_body(body);
    credits
}

/// An `extra_usage` object wrapped in an otherwise-bare body.
fn extra_usage(object: Value) -> Value {
    json!({ "extra_usage": object })
}

#[test]
fn the_credits_cell_covers_every_state_the_column_can_reach() {
    // Plan AC23's five cell formats, each from the body that produces it.
    let unavailable = parsed_credits(&json!({}));
    let off = parsed_credits(&extra_usage(
        json!({"is_enabled": false, "disabled_reason": "user disabled"}),
    ));
    let capped = parsed_credits(&extra_usage(json!({
        "is_enabled": true,
        "monthly_limit": 5000,
        "used_credits": 1234.0,
        "utilization": 24.68,
        "currency": "USD",
        "decimal_places": 2,
    })));
    let uncapped = parsed_credits(&extra_usage(json!({
        "is_enabled": true,
        "monthly_limit": null,
        "used_credits": 1234.0,
        "utilization": null,
        "currency": "USD",
        "decimal_places": 2,
    })));
    let unmeasured = parsed_credits(&extra_usage(json!({
        "is_enabled": true,
        "monthly_limit": null,
        "used_credits": null,
        "utilization": null,
        "currency": "USD",
        "decimal_places": 2,
    })));

    let rows: Vec<StatusRow> = [
        ("n/a", unavailable),
        ("off", off),
        ("capped", capped),
        ("uncapped", uncapped),
        ("unmeasured", unmeasured),
    ]
    .into_iter()
    .map(|(name, credits)| StatusRow {
        account: name.to_owned(),
        org: "Acme".to_owned(),
        plan: "max".to_owned(),
        state: "ok".to_owned(),
        note: None,
        usage: Some(usage(healthy_windows(), credits)),
        visible_by_default: true,
    })
    .collect();

    let rendered = render(&report(rows, false));
    assert!(rendered.contains("$12.34 / $50.00 (25%)"), "got:\n{rendered}");
    assert!(rendered.contains("$12.34 / Unlimited"), "got:\n{rendered}");
    assert!(
        !rendered.contains("— / Unlimited"),
        "credits with no `used_credits` are unavailable, not an unlimited nothing:\n{rendered}"
    );
    insta::assert_snapshot!("credits_cells", rendered);
}

#[test]
fn ac23_the_credits_enabled_capture_renders_the_figures_it_carries() {
    // The one real body with credits on, straight through the parser and the
    // renderer: used_credits 21956.0 of monthly_limit 500000 at utilization
    // 4.3912. Kept out of the snapshot so the pinned cell formats stay
    // byte-identical while the real figures are still asserted.
    let body: Value = serde_json::from_str(CREDITS_ON).expect("the fixture is valid JSON");
    let mut row = healthy_row("owner@example.com");
    row.usage = Some(usage(healthy_windows(), parsed_credits(&body)));

    let rendered = render(&report(vec![row], false));
    assert!(rendered.contains("$219.56 / $5000.00 (4%)"), "got:\n{rendered}");
}

#[test]
fn an_empty_report_still_explains_itself() {
    let mut hidden = empty_row("sibling", "stale sibling of live");
    hidden.visible_by_default = false;

    let rendered = render(&report(vec![hidden], false));
    assert!(rendered.contains("Account"), "the headings survive an empty body");
    assert!(rendered.ends_with("1 entry hidden (--all)"), "got:\n{rendered}");
}

#[test]
fn the_footer_agrees_with_itself_on_number() {
    assert_eq!(footer(1), "1 entry hidden (--all)");
    assert_eq!(footer(2), "2 entries hidden (--all)");
}

#[test]
fn the_column_order_is_the_one_the_plan_fixes() {
    // Nine of these are plan section 3.1's; `5h reset` and `Weekly reset`
    // replaced the single `Next reset` countdown on the user's request of
    // 2026-09-09.
    assert_eq!(
        HEADINGS,
        [
            "Account",
            "Org",
            "Plan",
            "5h",
            "Weekly",
            "Fable (weekly)",
            "Credits",
            "5h reset",
            "Weekly reset",
            "State"
        ]
    );
}

#[test]
fn both_reset_columns_carry_a_local_time_and_a_countdown() {
    // The healthy windows reset at 02:13:40Z and 20:00:00Z, which in +09:00
    // are 11:13 the same local morning and 05:00 on Friday the 11th. The
    // weekly cell is the point of the whole column: `2d20h` alone never said
    // which morning.
    let rendered = render(&report(vec![healthy_row("alice@example.com")], false));
    let cells = cells_of(&rendered, "alice@example.com");

    assert_eq!(cells[column("5h reset")], "11:13 AM (2h13m)", "got:\n{rendered}");
    assert_eq!(cells[column("Weekly reset")], "Fri 5:00 AM (2d20h)", "got:\n{rendered}");
}

#[test]
fn a_row_with_only_a_weekly_window_leaves_the_five_hour_reset_an_em_dash() {
    let mut row = healthy_row("alice@example.com");
    row.usage = Some(usage(
        vec![window(WindowKind::WeeklyAll, 35.0, Some("2026-09-10T20:00:00Z"))],
        CreditsState::Unavailable,
    ));

    let rendered = render(&report(vec![row], false));
    let cells = cells_of(&rendered, "alice@example.com");

    assert_eq!(cells[column("5h reset")], EMPTY_CELL, "got:\n{rendered}");
    assert_eq!(cells[column("Weekly reset")], "Fri 5:00 AM (2d20h)", "got:\n{rendered}");
}

#[test]
fn a_window_that_carries_no_reset_is_an_em_dash_rather_than_a_bare_countdown() {
    // A window with a percentage and no `resets_at` is a real shape — the
    // captured body has one — and the percentage columns must still fill.
    let mut row = healthy_row("alice@example.com");
    row.usage = Some(usage(
        vec![window(WindowKind::Session, 21.0, None), window(WindowKind::WeeklyAll, 35.0, None)],
        CreditsState::Unavailable,
    ));

    let rendered = render(&report(vec![row], false));
    let cells = cells_of(&rendered, "alice@example.com");

    assert_eq!(cells[column("5h")], "21%", "the figure is there; only the reset is missing");
    assert_eq!(cells[column("5h reset")], EMPTY_CELL, "got:\n{rendered}");
    assert_eq!(cells[column("Weekly reset")], EMPTY_CELL, "got:\n{rendered}");
}

#[test]
fn a_continuation_rows_reset_sits_in_the_weekly_column() {
    // Such a window is never the five-hour one, so that cell stays blank —
    // not an em dash, which would claim a figure was unavailable.
    let mut windows = healthy_windows();
    windows.push(window(
        WindowKind::Unknown("monthly_foo".to_owned()),
        7.0,
        Some("2026-10-01T00:00:00Z"),
    ));

    let mut row = healthy_row("alice@example.com");
    row.usage = Some(usage(windows, CreditsState::Unavailable));

    let rendered = render(&report(vec![row], false));
    let cells = cells_of(&rendered, "↳ monthly_foo");

    assert_eq!(cells[column("5h reset")], "", "got:\n{rendered}");
    // Twenty-three days out: past a week, so the date names the day rather
    // than a weekday that would come round again first.
    assert_eq!(cells[column("Weekly reset")], "Oct 1 9:00 AM (23d0h)", "got:\n{rendered}");
}
