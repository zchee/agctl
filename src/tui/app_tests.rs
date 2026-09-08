//! The reducer, one event at a time.
//!
//! Every [`Event`] variant is driven here, because the reducer is the whole of
//! the watch loop's decision-making: the loop itself only moves values
//! between a channel, a terminal and this function.

use super::*;
use crate::provider::claude::account::AccountState;
use crate::tui::fixtures;

/// A fresh display, dated at the fixtures' clock.
fn app() -> App {
    App::new(fixtures::at(fixtures::NOW))
}

/// Two shown rows and one hidden one, as a pass would deliver them.
fn mixed_rows() -> Vec<RowOutcome> {
    let mut hidden = fixtures::row(2, "sibling@example.com", AccountState::StaleSiblingOfLive);
    hidden.visible_by_default = false;
    vec![
        fixtures::row_with_usage(0, "first@example.com"),
        fixtures::row_with_usage(1, "second@example.com"),
        hidden,
    ]
}

#[test]
fn rows_are_split_into_the_shown_ones_and_a_hidden_count() {
    let mut app = app();

    assert_eq!(app.reduce(Event::Rows(mixed_rows())), Effect::None);

    assert_eq!(app.rows.len(), 2, "only the rows `status` shows without `--all` are displayed");
    assert_eq!(app.hidden, 1, "the rest are counted for the footer");
    assert_eq!(app.rows[0].account, "first@example.com", "discovery order is preserved");
}

#[test]
fn rows_clear_the_stale_flag() {
    let mut app = app();
    app.reduce(Event::Rows(mixed_rows()));
    app.reduce(Event::PassStarted);
    assert!(app.stale, "a second pass makes the numbers on screen the previous pass's");

    app.reduce(Event::Rows(mixed_rows()));

    assert!(!app.stale, "the new pass's own numbers are not stale");
}

#[test]
fn the_first_pass_is_never_stale() {
    let mut app = app();

    app.reduce(Event::PassStarted);

    assert!(app.fetching);
    assert!(!app.stale, "there is nothing on screen for the first pass to be stale relative to");
}

#[test]
fn a_finished_pass_records_when_it_ended_and_when_the_next_is_due() {
    let mut app = app();
    let at = fixtures::at("2026-09-08T12:00:30Z");
    let next = fixtures::at("2026-09-08T12:05:30Z");

    app.reduce(Event::PassStarted);
    assert_eq!(app.reduce(Event::PassFinished { at, next: Some(next) }), Effect::None);

    assert!(!app.fetching);
    assert_eq!(app.last_fetch, Some(at));
    assert_eq!(app.next_fetch, Some(next));
}

#[test]
fn a_pass_with_no_schedule_leaves_the_next_fetch_unset() {
    let mut app = app();
    let at = fixtures::at("2026-09-08T12:00:30Z");

    app.reduce(Event::PassFinished { at, next: None });

    assert_eq!(app.next_fetch, None, "an interval that does not fit the clock schedules nothing");
    assert_eq!(app.last_fetch, Some(at), "the pass still happened");
}

#[test]
fn a_tick_moves_the_clock_the_frame_is_drawn_against() {
    let mut app = app();
    let later = fixtures::at("2026-09-08T12:04:00Z");

    assert_eq!(app.reduce(Event::Tick(later)), Effect::None);

    assert_eq!(app.now, later);
}

#[test]
fn quit_and_refresh_leave_as_effects_rather_than_state() {
    let mut app = app();
    let before = app.selected;

    assert_eq!(app.reduce(Event::Key(Key::Quit)), Effect::Quit);
    assert_eq!(app.reduce(Event::Key(Key::Refresh)), Effect::Refresh);

    assert_eq!(app.selected, before, "neither key moves the selection");
    assert!(app.rows.is_empty(), "neither key touches the rows");
}

#[test]
fn the_selection_moves_between_the_rows_and_stops_at_both_ends() {
    let mut app = app();
    app.reduce(Event::Rows(mixed_rows()));

    app.reduce(Event::Key(Key::Up));
    assert_eq!(app.selected, 0, "up from the first row stays on the first row");

    app.reduce(Event::Key(Key::Down));
    assert_eq!(app.selected, 1);

    app.reduce(Event::Key(Key::Down));
    assert_eq!(app.selected, 1, "down from the last row stays on the last row");

    app.reduce(Event::Key(Key::Up));
    assert_eq!(app.selected, 0);
}

#[test]
fn an_empty_display_keeps_the_selection_at_zero() {
    let mut app = app();

    app.reduce(Event::Key(Key::Down));

    assert_eq!(app.selected, 0, "there is no row one to select");
}

#[test]
fn a_shorter_pass_pulls_the_selection_back_inside_the_rows() {
    let mut app = app();
    app.reduce(Event::Rows(mixed_rows()));
    app.reduce(Event::Key(Key::Down));
    assert_eq!(app.selected, 1);

    // The second account was removed in another terminal.
    app.reduce(Event::Rows(vec![fixtures::row_with_usage(0, "first@example.com")]));

    assert_eq!(app.selected, 0, "a selection past the end would blank the highlight");
}
