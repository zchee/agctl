//! The frame, drawn into a buffer rather than onto a terminal.
//!
//! [`TestBackend`] is a `Buffer` with a `Backend` implementation, so a whole
//! frame can be rendered and compared without a terminal existing. The
//! snapshots are what plan AC14 pins; the smaller assertions around them say
//! *why* a snapshot looks the way it does, so a future diff can be read as
//! intended or not.

use insta::assert_snapshot;
use ratatui::Terminal;
use ratatui::backend::TestBackend;

use super::*;
use crate::tui::app::App;
use crate::tui::app::Event;
use crate::tui::fixtures;
use crate::usage::model::CreditsState;

/// Renders one frame at a fixed size and returns the terminal to read back.
fn render(app: &App, width: u16, height: u16) -> Terminal<TestBackend> {
    let mut terminal = Terminal::new(TestBackend::new(width, height))
        .expect("a test backend always reports its size");
    terminal.draw(|frame| draw(frame, app)).expect("a test backend never fails to draw");
    terminal
}

/// A display mid-run: two accounts fetched half a minute ago, one hidden.
fn two_accounts() -> App {
    let mut app = App::new(fixtures::at("2026-09-08T12:00:30Z"));
    let mut hidden = fixtures::row(2, "sibling@example.com", AccountState::StaleSiblingOfLive);
    hidden.visible_by_default = false;
    app.reduce(Event::Rows(vec![
        fixtures::row_with_usage(0, "owner@example.com"),
        fixtures::row_with_credits(1, "second@example.com"),
        hidden,
    ]));
    app.reduce(Event::PassFinished {
        at: fixtures::at("2026-09-08T12:00:00Z"),
        next: Some(fixtures::at("2026-09-08T12:05:00Z")),
    });
    app
}

#[test]
fn two_accounts_render_as_expected() {
    let terminal = render(&two_accounts(), 84, 20);

    assert_snapshot!(terminal.backend());
}

#[test]
fn a_degraded_account_shows_its_badge_and_its_state() {
    let mut app = App::new(fixtures::at("2026-09-08T12:00:30Z"));
    let mut detected = fixtures::row_with_usage(0, "owner@example.com");
    detected.state = AccountState::ClaudeSessionDetected {
        lock: ".oauth_refresh.lock".to_owned(),
        age_ms: 4000,
    };
    let mut locked = fixtures::row(
        1,
        "live@example.com",
        AccountState::KeychainLocked { detail: String::new() },
    );
    locked.plan = String::new();
    app.reduce(Event::Rows(vec![detected, locked]));
    app.reduce(Event::PassStarted);

    let terminal = render(&app, 84, 20);

    assert_snapshot!(terminal.backend());
}

#[test]
fn an_empty_display_says_so_rather_than_showing_nothing() {
    let app = App::new(fixtures::at(fixtures::NOW));

    let terminal = render(&app, 60, 8);

    assert_snapshot!(terminal.backend());
}

#[test]
fn the_header_names_the_clock_the_frame_was_drawn_against() {
    let app = two_accounts();

    let header = header_line(&app);

    assert!(header.contains("2 accounts"), "{header}");
    assert!(header.contains("last fetch 30s ago"), "{header}");
    assert!(header.contains("next fetch in 4m"), "{header}");
    assert!(!header.contains("fetching"), "no pass is in flight: {header}");
}

#[test]
fn a_pass_in_flight_is_announced_and_marks_the_numbers_stale() {
    let mut app = two_accounts();
    app.reduce(Event::PassStarted);

    let header = header_line(&app);

    assert!(header.contains("fetching"), "{header}");
    assert!(header.contains("stale"), "the numbers on screen are the previous pass's: {header}");
}

#[test]
fn a_display_with_no_fetch_yet_shows_em_dashes_rather_than_zeroes() {
    let app = App::new(fixtures::at(fixtures::NOW));

    let header = header_line(&app);

    assert!(header.contains("last fetch —"), "{header}");
    assert!(header.contains("next fetch —"), "{header}");
}

#[test]
fn the_footer_points_at_the_command_that_shows_the_hidden_rows() {
    let app = two_accounts();

    let footer = footer_text(&app);

    assert!(footer.starts_with(HELP_LINE), "{footer}");
    assert_eq!(
        footer.lines().nth(1),
        Some("1 entry hidden (agentctl claude status --all)"),
        "`watch` has no `--all` of its own, so the footer names the command that does"
    );
}

#[test]
fn a_display_with_nothing_hidden_shows_only_the_help_line() {
    let mut app = App::new(fixtures::at(fixtures::NOW));
    app.reduce(Event::Rows(vec![fixtures::row_with_usage(0, "owner@example.com")]));

    assert_eq!(footer_text(&app), HELP_LINE);
}

#[test]
fn every_badge_state_has_a_badge_and_the_healthy_ones_do_not() {
    assert_eq!(badge(&AccountState::Stale), Some("stale"));
    assert_eq!(badge(&AccountState::RateLimited { retry_after_s: Some(30) }), Some("rate-limited"));
    assert_eq!(
        badge(&AccountState::ClaudeSessionDetected { lock: "l".to_owned(), age_ms: 1 }),
        Some("claude-detected")
    );
    assert_eq!(
        badge(&AccountState::KeychainLocked { detail: String::new() }),
        Some("keychain-locked")
    );
    assert_eq!(badge(&AccountState::KeychainTimeout), Some("keychain-locked"));
    assert_eq!(badge(&AccountState::Busy), Some("busy"));
    assert_eq!(badge(&AccountState::NeedsLogin), Some("needs login"));

    assert_eq!(badge(&AccountState::Ok), None);
    assert_eq!(badge(&AccountState::PendingReplayed), None);
}

#[test]
fn a_row_earns_one_gauge_per_window_the_response_described() {
    let plain = fixtures::row_with_usage(0, "owner@example.com");
    assert_eq!(gauges(&plain), vec![("5h", 21), ("weekly", 35), ("Fable", 56)]);

    let with_credits = fixtures::row_with_credits(1, "second@example.com");
    assert_eq!(
        gauges(&with_credits),
        vec![("5h", 4), ("weekly", 11), ("Fable", 7), ("credits", 25)],
        "credits earn a gauge only when they are on and carry a utilisation figure"
    );
}

#[test]
fn credits_that_are_off_or_unreported_earn_no_gauge() {
    let mut row = fixtures::row(0, "owner@example.com", AccountState::Ok);
    row.usage = Some(fixtures::usage(1.0, 2.0, 3.0, CreditsState::Off { reason: None }));
    assert_eq!(gauges(&row).len(), 3, "`off` is not a percentage");

    row.usage = Some(fixtures::usage(1.0, 2.0, 3.0, CreditsState::Unavailable));
    assert_eq!(gauges(&row).len(), 3, "neither is `n/a`");
}

#[test]
fn a_row_without_numbers_earns_no_gauges_and_the_shortest_block() {
    let row = fixtures::row(0, "owner@example.com", AccountState::NeedsLogin);

    assert!(gauges(&row).is_empty(), "a bar at zero would claim nothing had been used");
    assert_eq!(block_height(&row), 3, "two borders and the detail line");
    assert_eq!(block_height(&fixtures::row_with_credits(1, "second@example.com")), 7);
}

#[test]
fn the_detail_line_carries_the_badge_the_state_and_the_next_reset() {
    let mut row = fixtures::row_with_usage(0, "owner@example.com");
    row.state = AccountState::RateLimited { retry_after_s: Some(42) };
    row.note = Some("showing the cached value".to_owned());

    let line = detail_line(&row, fixtures::at("2026-09-08T12:00:00Z"));

    assert_eq!(
        line,
        "[rate-limited] · rate-limited (retry in 42s) · (showing the cached value) · \
         next reset in 2h13m"
    );
}

#[test]
fn only_the_selected_account_carries_the_marker() {
    let row = fixtures::row_with_usage(0, "owner@example.com");

    assert!(account_title(&row, true).starts_with(SELECTED_MARKER));
    assert!(!account_title(&row, false).starts_with(SELECTED_MARKER));
    assert!(account_title(&row, false).contains("owner@example.com · Acme · max"));
}

#[test]
fn an_account_with_no_org_or_plan_shows_em_dashes() {
    let mut row = fixtures::row(0, "owner@example.com", AccountState::IdentityUnknown);
    row.org = String::new();
    row.plan = String::new();

    let title = account_title(&row, false);

    assert!(title.contains("owner@example.com · — · —"), "{title}");
}
