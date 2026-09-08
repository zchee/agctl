use jiff::Timestamp;

use super::*;
use crate::usage::model::Credits;
use crate::usage::model::Money;
use crate::usage::model::clamp_percent;
use crate::usage::model::percent_floor;

/// The fixed "now" every snapshot is rendered against, so a countdown is a
/// constant rather than a moving target.
const NOW: &str = "2026-09-08T00:00:00Z";

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
    Report { rows, now: ts(NOW), show_all }
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

#[test]
fn the_credits_cell_covers_every_state_the_column_can_reach() {
    // Plan AC23's cell formats. W1 only ever produces `n/a`; the rest are
    // pinned now so the W2 parser lands against a fixed rendering.
    let unavailable = CreditsState::Unavailable;
    let off = CreditsState::Off { reason: Some("user disabled".to_owned()) };
    let capped = CreditsState::On(Credits {
        used: Some(Money { amount_minor: 1234, currency: "USD".to_owned(), exponent: 2 }),
        limit: Some(Money { amount_minor: 5000, currency: "USD".to_owned(), exponent: 2 }),
        percent: Some(25),
    });
    let uncapped = CreditsState::On(Credits {
        used: Some(Money { amount_minor: 1234, currency: "USD".to_owned(), exponent: 2 }),
        limit: None,
        percent: None,
    });
    let unmeasured = CreditsState::On(Credits { used: None, limit: None, percent: None });

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
            "Next reset",
            "State"
        ]
    );
}
