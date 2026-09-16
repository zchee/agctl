//! Tests for the row seam (plan AC118, and AC104's shared-code half).
//!
//! Most of this file moved here from `tui::ui_tests` with the bodies it
//! tests: the assertions are deliberately unchanged, because "the moved
//! bodies behave exactly as they did" is the claim. What is new is at the
//! bottom — the two consts, the state token and the visibility question the
//! trait adds.

use super::*;
use crate::provider::claude::account::AccountState;
use crate::tui::fixtures;
use crate::usage::model::CreditsState;

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
    assert_eq!(plain.gauges(), vec![("5h", 21), ("weekly", 35), ("Fable", 56)]);

    let with_credits = fixtures::row_with_credits(1, "second@example.com");
    assert_eq!(
        with_credits.gauges(),
        vec![("5h", 4), ("weekly", 11), ("Fable", 7), ("credits", 25)],
        "credits earn a gauge only when they are on and carry a utilisation figure"
    );
}

#[test]
fn credits_that_are_off_or_unreported_earn_no_gauge() {
    let mut row = fixtures::row(0, "owner@example.com", AccountState::Ok);
    row.usage = Some(fixtures::usage(1.0, 2.0, 3.0, CreditsState::Off { reason: None }));
    assert_eq!(row.gauges().len(), 3, "`off` is not a percentage");

    row.usage = Some(fixtures::usage(1.0, 2.0, 3.0, CreditsState::Unavailable));
    assert_eq!(row.gauges().len(), 3, "neither is `n/a`");
}

#[test]
fn a_row_without_numbers_earns_no_gauges_and_the_shortest_block() {
    let row = fixtures::row(0, "owner@example.com", AccountState::NeedsLogin);

    assert!(row.gauges().is_empty(), "a bar at zero would claim nothing had been used");
    assert_eq!(row.block_height(), 3, "two borders and the detail line");
    assert_eq!(fixtures::row_with_credits(1, "second@example.com").block_height(), 7);
}

#[test]
fn the_detail_line_carries_the_badge_the_state_and_the_next_reset() {
    let mut row = fixtures::row_with_usage(0, "owner@example.com");
    row.state = AccountState::RateLimited { retry_after_s: Some(42) };
    row.note = Some("showing the cached value".to_owned());

    let line = row.detail_line(fixtures::at("2026-09-08T12:00:00Z"));

    assert_eq!(
        line,
        "[rate-limited] · rate-limited (retry in 42s) · (showing the cached value) · \
         next reset in 2h13m"
    );
}

#[test]
fn only_the_selected_account_carries_the_marker() {
    let row = fixtures::row_with_usage(0, "owner@example.com");

    assert!(row.account_title(true).starts_with(SELECTED_MARKER));
    assert!(!row.account_title(false).starts_with(SELECTED_MARKER));
    assert!(row.account_title(false).contains("owner@example.com · Acme · max"));
}

#[test]
fn an_account_with_no_org_or_plan_shows_em_dashes() {
    let mut row = fixtures::row(0, "owner@example.com", AccountState::IdentityUnknown);
    row.org = String::new();
    row.plan = String::new();

    let title = row.account_title(false);

    assert!(title.contains("owner@example.com · — · —"), "{title}");
}

#[test]
fn the_two_consts_name_the_claude_commands_and_nothing_else() {
    // Plan ledger #141: `ui.rs` used to hardcode both. A Codex display that
    // inherited them would tell the user to run a command that reports the
    // other provider's accounts.
    assert_eq!(RowOutcome::WATCH_TITLE, "agctl claude watch");
    assert_eq!(RowOutcome::HIDDEN_HINT, "agctl claude status --all");
}

#[test]
fn the_state_token_is_the_machine_readable_half_of_the_detail_line() {
    let row = fixtures::row(0, "owner@example.com", AccountState::NeedsLogin);

    assert_eq!(row.state_token(), AccountState::NeedsLogin.name());
    assert!(
        row.detail_line(fixtures::at(fixtures::NOW)).contains("[needs login]"),
        "the prose form still carries the badge; the token is for deciding, not for reading"
    );
}

#[test]
fn visibility_is_the_row_s_own_answer() {
    let mut row = fixtures::row_with_usage(0, "owner@example.com");
    assert!(TuiRow::visible_by_default(&row));

    row.visible_by_default = false;
    assert!(
        !TuiRow::visible_by_default(&row),
        "the display asks the row, so a hidden Codex row hides for the same reason"
    );
}
