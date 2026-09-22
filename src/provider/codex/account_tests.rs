use std::collections::BTreeSet;

use jiff::Timestamp;

use super::*;

fn every_state() -> Vec<CodexState> {
    vec![
        CodexState::Ok,
        CodexState::Expired { reason: "run agctl codex login".to_owned() },
        CodexState::NeedsLogin,
        CodexState::NoUsageSource { mode: "apikey".to_owned() },
        CodexState::NoUsageWindows,
        CodexState::StoreModeUnsupported { mode: StoreMode::Keyring },
        CodexState::HomeUnreadable { reason: "x".to_owned() },
        CodexState::TornRead,
        CodexState::Unauthorized { refreshed_recently: false },
        CodexState::StaleSiblingOfLive,
        CodexState::Forgotten,
        CodexState::CodexSessionDetected { evidence: "pid alive".to_owned() },
        CodexState::Busy,
        CodexState::LockUnavailable,
        CodexState::Stale,
        CodexState::RateLimited { retry_after: Some(30) },
        CodexState::RefreshDiscarded,
        CodexState::IdentityDrift,
        CodexState::RefreshOutcomeUnknown {
            since: Timestamp::UNIX_EPOCH,
            class: UnknownClass::Interrupted,
            resend_eligible: false,
        },
        CodexState::RefreshStateUnavailable { reason: "x".to_owned() },
        CodexState::RefreshDisabled,
        CodexState::UnauthorizedFloor,
        CodexState::UnauthorizedTerminal,
        CodexState::AdoptedGrantDead,
        CodexState::DiscardedExternal,
        CodexState::Error("x".to_owned()),
    ]
}

#[test]
fn every_state_has_a_distinct_snake_case_name() {
    let states = every_state();
    let names: BTreeSet<&str> = states.iter().map(CodexState::name).collect();
    assert_eq!(names.len(), states.len(), "names are unique: {names:?}");
    for name in names {
        assert!(name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'), "{name}");
    }
}

#[test]
fn only_ok_no_usage_source_and_forgotten_are_exit_neutral() {
    let neutral: Vec<&str> =
        every_state().iter().filter(|s| s.is_exit_neutral()).map(CodexState::name).collect();
    assert_eq!(neutral, ["ok", "no_usage_source", "forgotten"]);
}

#[test]
fn credits_keep_the_wire_string() {
    let credits = CodexCredits::Balance { balance: Some("12.34".to_owned()), unlimited: false };
    assert_ne!(credits, CodexCredits::Unavailable);
    assert!(matches!(credits, CodexCredits::Balance { balance: Some(ref b), .. } if b == "12.34"));
    assert_eq!(StoreMode::Keyring.label(), "keyring");
    assert_eq!(StoreMode::Unknown("x".to_owned()).label(), "x");
}

// ---------------------------------------------------------------------------
// The finished row (S33): labels, cells, and the three renderings
// ---------------------------------------------------------------------------

use insta::assert_snapshot;
use jiff::tz::Offset;
use jiff::tz::TimeZone;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use serde_json::Value;
use serde_json::json;

use crate::provider::codex::usage::normalize;
use crate::render::json_v2::StatusReportV2;
use crate::render::json_v2::assert_valid_v2;
use crate::render::row::TuiRow;
use crate::render::table::CODEX_HEADINGS;
use crate::render::table::CodexReport;
use crate::render::table::render_codex;
use crate::tui::app::App;
use crate::tui::app::Event;
use crate::tui::ui;

/// The fixed clock every rendering below is drawn against.
const NOW: &str = "2026-09-16T12:00:00Z";

/// The leak needles of plan section 9.4 that a row could plausibly carry.
const NEEDLES: [&str; 6] = [
    "agctl-test-codex-at-",
    "agctl-test-codex-rt-",
    "agctl-test-codex-ak-",
    "agctl-test-codex-jwt-",
    "eyJ",
    "Bearer ",
];

fn now() -> Timestamp {
    NOW.parse().expect("the test literal is a valid RFC 3339 timestamp")
}

fn tz() -> TimeZone {
    TimeZone::fixed(Offset::constant(9))
}

/// A usage body with a five-hour and a weekly window, credits, and one
/// additional limit — every shape the table has a cell or a row for.
fn body(session: f64, weekly: f64) -> Value {
    json!({
        "plan_type": "plus",
        "rate_limit": {
            "allowed": true,
            "limit_reached": false,
            "primary_window": {
                "used_percent": session,
                "limit_window_seconds": 18_000,
                "reset_at": 1_789_578_000,
            },
            "secondary_window": {
                "used_percent": weekly,
                "limit_window_seconds": 604_800,
                "reset_at": 1_789_999_200,
            },
        },
        "additional_rate_limits": [{
            "limit_name": "GPT-5.3-Codex-Spark",
            "metered_feature": "codex_bengalfox",
            "rate_limit": {
                "primary_window": {
                    "used_percent": 3.0,
                    "limit_window_seconds": 18_000,
                    "reset_at": 1_789_578_000,
                },
            },
        }],
        "credits": { "has_credits": true, "unlimited": false, "balance": "12.34" },
    })
}

fn row(index: usize, email: &str, state: CodexState, usage: Option<Value>) -> CodexRowOutcome {
    CodexRowOutcome {
        index,
        id: format!("user-{index:04}"),
        user_id: format!("user-{index:04}"),
        account_id: format!("acct-{index:04}"),
        email: Some(email.to_owned()),
        plan: Some("plus".to_owned()),
        kind: CodexRowKind::Owned,
        state,
        lock_state: "none",
        note: None,
        usage: usage.map(|body| normalize(&body, now(), true).expect("the body is an object")),
        visible_by_default: true,
    }
}

fn two_rows() -> Vec<CodexRowOutcome> {
    let first = row(0, "owner@example.com", CodexState::Ok, Some(body(21.6, 35.2)));
    let mut second = row(1, "", CodexState::NoUsageSource { mode: "apikey".to_owned() }, None);
    second.email = None;
    second.kind = CodexRowKind::Live;
    second.plan = None;
    vec![first, second]
}

#[test]
fn every_state_has_a_label_and_the_torn_one_names_the_file_through_the_store() {
    for state in every_state() {
        assert!(!state.label().is_empty(), "{} has an empty label", state.name());
    }
    assert_eq!(
        CodexState::TornRead.label(),
        format!("{} was being rewritten; retrying next pass", auth_store::shown_name())
    );
    assert_eq!(
        CodexState::Expired { reason: "run agctl codex login".to_owned() }.label(),
        "expired (run agctl codex login)"
    );
    assert_eq!(CodexState::UnauthorizedFloor.label(), "unauthorized (refresh floor)");
    assert_eq!(CodexState::UnauthorizedTerminal.label(), "unauthorized (refresh did not help)");
    assert_eq!(
        CodexState::RefreshOutcomeUnknown {
            since: Timestamp::UNIX_EPOCH,
            class: UnknownClass::RateLimited,
            resend_eligible: true,
        }
        .label(),
        "refresh outcome unknown (rate_limited)"
    );
}

#[test]
fn degraded_states_carry_a_badge_and_healthy_ones_do_not() {
    assert_eq!(badge(&CodexState::Stale), Some("stale"));
    assert_eq!(badge(&CodexState::TornRead), Some("stale"));
    assert_eq!(badge(&CodexState::Busy), Some("busy"));
    assert_eq!(
        badge(&CodexState::CodexSessionDetected { evidence: "pid alive".to_owned() }),
        Some("codex-detected")
    );
    assert_eq!(badge(&CodexState::AdoptedGrantDead), Some("needs login"));
    assert_eq!(badge(&CodexState::Ok), None);
    assert_eq!(badge(&CodexState::NoUsageSource { mode: "apikey".to_owned() }), None);
}

#[test]
fn the_first_five_hour_and_weekly_windows_get_columns_and_every_other_window_a_row() {
    let row = row(0, "owner@example.com", CodexState::Ok, Some(body(21.6, 35.2)));
    let table = row.to_table_row();

    assert_eq!(table.session.as_ref().and_then(|w| w.percent_floor), Some(21));
    assert_eq!(table.weekly.as_ref().and_then(|w| w.percent_floor), Some(35));
    // The additional limit's five-hour window is its own limit, not the
    // account's: a continuation row, never the `5h` column.
    let extra: Vec<String> = table.extra.iter().map(LimitWindow::label).collect();
    assert_eq!(extra, ["GPT-5.3-Codex-Spark:primary (unknown kind)"]);
    assert_eq!(row.gauges(), vec![("5h", 21), ("weekly", 35)]);
    assert_eq!(row.block_height(), 5);
}

#[test]
fn the_credits_cell_covers_every_shape() {
    let mut row = row(0, "a@example.com", CodexState::Ok, Some(body(1.0, 1.0)));
    assert_eq!(row.credits_cell(), "12.34");

    let usage = row.usage.as_mut().expect("the row has usage");
    usage.credits = CodexCredits::Balance { balance: Some("0".to_owned()), unlimited: true };
    assert_eq!(row.credits_cell(), "Unlimited");
    let usage = row.usage.as_mut().expect("the row has usage");
    usage.credits = CodexCredits::Balance { balance: None, unlimited: false };
    assert_eq!(row.credits_cell(), EMPTY_CELL);
    let usage = row.usage.as_mut().expect("the row has usage");
    usage.credits = CodexCredits::Unavailable;
    assert_eq!(row.credits_cell(), "n/a");
    row.usage = None;
    assert_eq!(row.credits_cell(), "n/a");
}

#[test]
fn the_account_cell_prefers_the_email_and_falls_back_to_the_display_id() {
    let mut row = row(3, "someone@example.com", CodexState::Ok, None);
    assert_eq!(row.account(), "someone@example.com");
    row.email = Some(String::new());
    assert_eq!(row.account(), "user-0003");
    row.note = Some("auto (file in effect)".to_owned());
    assert_eq!(row.state_cell(), "ok (auto (file in effect))");
}

#[test]
fn ac103_the_codex_table_has_nine_columns_and_continuation_rows() {
    let mut rows = two_rows();
    let mut hidden = row(2, "sibling@example.com", CodexState::StaleSiblingOfLive, None);
    hidden.visible_by_default = false;
    rows.push(hidden);
    let report = CodexReport {
        rows: rows.iter().map(CodexRowOutcome::to_table_row).collect(),
        now: now(),
        tz: tz(),
        show_all: false,
    };

    let rendered = render_codex(&report);

    let heading_line = rendered.lines().next().expect("a heading line");
    let headings: Vec<&str> = heading_line.split('|').map(str::trim).collect();
    assert_eq!(headings, CODEX_HEADINGS);
    assert!(rendered.contains("↳ GPT-5.3-Codex-Spark:primary (unknown kind)"), "{rendered}");
    assert!(rendered.contains("no usage source (apikey)"), "{rendered}");
    assert!(!rendered.contains("sibling@example.com"), "a hidden row was printed:\n{rendered}");
    assert!(rendered.ends_with("1 entry hidden (--all)"), "{rendered}");
    assert_snapshot!("codex_table", rendered);
}

#[test]
fn ac104_the_codex_watch_display_renders_through_the_shared_frame() {
    let mut app = App::new("2026-09-16T12:00:30Z".parse().expect("valid"));
    app.reduce(Event::Rows(two_rows()));
    app.reduce(Event::PassFinished {
        at: now(),
        next: Some("2026-09-16T12:05:00Z".parse().expect("valid")),
    });
    let mut terminal =
        Terminal::new(TestBackend::new(84, 16)).expect("a test backend reports its size");

    terminal.draw(|frame| ui::draw(frame, &app)).expect("a test backend never fails to draw");

    let text = format!("{}", terminal.backend());
    assert!(text.contains(CodexRowOutcome::WATCH_TITLE), "{text}");
    assert!(!text.contains("agctl claude"), "the Codex display names a Claude command:\n{text}");
    assert_snapshot!("codex_watch_two_rows", terminal.backend());
}

#[test]
fn ac102_every_state_serializes_into_a_valid_v2_row_without_a_needle() {
    let rows: Vec<CodexRowOutcome> = every_state()
        .into_iter()
        .enumerate()
        .map(|(index, state)| row(index, "owner@example.com", state, Some(body(50.0, 60.0))))
        .collect();

    let report = StatusReportV2::from_rows(&rows, now(), 0);

    assert_valid_v2(&report);
    let text = serde_json::to_string(&report).expect("a report serializes");
    for needle in NEEDLES {
        assert!(!text.contains(needle), "the v2 document carries `{needle}`");
    }
    let first = &report.rows[0];
    assert_eq!(first.provider, "codex");
    assert_eq!(first.identity.user_id, "user-0000");
    assert_eq!(first.identity.account_id, "acct-0000");
    assert_eq!(first.identity.plan_type.as_deref(), Some("plus"));
    assert_eq!(first.credits.kind, "balance");
    assert_eq!(first.credits.balance.as_deref(), Some("12.34"));
    assert!(first.session_reset.is_some() && first.weekly_reset.is_some());
    assert_eq!(first.windows.len(), 3);
}
