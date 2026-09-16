//! One frame of `agctl claude watch`.
//!
//! The frame is a header line, one bordered block per shown account, and a
//! footer. Everything it needs is in the [`App`] it is handed; nothing here
//! reads a clock, a file or the terminal, which is what lets a whole frame be
//! snapshot-tested against
//! [`TestBackend`](ratatui::backend::TestBackend) (plan AC14).
//!
//! # A gauge only exists when its number does
//!
//! An account gets one gauge per window the response actually described —
//! the five-hour session, the all-model week, the headline scoped week — plus
//! one for credits when they are switched on *and* the server sent a
//! utilisation figure. A window that is missing gets no gauge rather than an
//! empty one at zero: a bar at zero is a claim that nothing has been used,
//! which is a different statement from "the server did not say" (the same
//! reasoning as the table's em dash, `render::table`).
//!
//! That makes an account's block a variable height, and the layout is
//! computed from the rows rather than fixed, so two accounts with different
//! window sets both fit.
//!
//! # Badges compress the state, they do not replace it
//!
//! The badge is a two-word summary of what plan section 3.3 decided about the
//! row — `stale`, `rate-limited`, `claude-detected`, `keychain-locked`,
//! `busy`, `needs login` — and the full state label sits next to it on the
//! same line. The badge is for scanning six accounts at a glance; the label
//! is what says which lock, how long ago, and how many seconds to wait. What
//! a row's badge, gauges, title and height *are* is
//! [`TuiRow`](crate::render::row::TuiRow)'s business, not this module's:
//! nothing here knows which provider it is drawing.

use jiff::Timestamp;
use ratatui::Frame;
use ratatui::layout::Constraint;
use ratatui::layout::Layout;
use ratatui::layout::Rect;
use ratatui::widgets::Block;
use ratatui::widgets::Gauge;
use ratatui::widgets::Paragraph;

use crate::render::row::TuiRow;
use crate::tui::app::App;
use crate::usage::model::render_countdown;

/// The keys the footer advertises.
pub const HELP_LINE: &str = "q quit · r refresh · ↑↓ select";

/// What an unavailable figure looks like, matching the `status` table.
pub const EMPTY_CELL: &str = "—";

/// How wide the name in front of each gauge is.
const GAUGE_LABEL_WIDTH: u16 = 10;

/// Draws the whole frame.
pub fn draw<R: TuiRow>(frame: &mut Frame<'_>, app: &App<R>) {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(footer_height(app)),
    ])
    .areas(frame.area());

    frame.render_widget(Paragraph::new(header_line(app)), header);
    draw_accounts(frame, app, body);
    frame.render_widget(Paragraph::new(footer_text(app)), footer);
}

/// The status line above the accounts.
pub fn header_line<R: TuiRow>(app: &App<R>) -> String {
    let mut parts = vec![format!("{} · {}", R::WATCH_TITLE, account_count(app.rows.len()))];

    parts.push(match app.last_fetch {
        // `render_countdown` measures forwards, so the arguments are the
        // other way round for an elapsed time: from the fetch, to now.
        Some(at) => format!("last fetch {} ago", render_countdown(at, app.now)),
        None => format!("last fetch {EMPTY_CELL}"),
    });
    // The countdown and `fetching` are alternatives, not companions. While a
    // pass is in flight the next one has not been scheduled yet, so
    // `next_fetch` still holds the moment the *previous* pass aimed at — a
    // number that counts down past zero and then sits there while the display
    // says it is fetching. Showing one or the other keeps the header honest.
    if app.fetching {
        parts.push("fetching".to_owned());
    } else {
        parts.push(match app.next_fetch {
            Some(at) => format!("next fetch in {}", render_countdown(app.now, at)),
            None => format!("next fetch {EMPTY_CELL}"),
        });
    }
    if app.stale {
        parts.push("stale".to_owned());
    }

    parts.join(" · ")
}

/// The help line, and the hidden-row count when there is one.
pub fn footer_text<R: TuiRow>(app: &App<R>) -> String {
    if app.hidden == 0 {
        return HELP_LINE.to_owned();
    }
    format!("{HELP_LINE}\n{}", hidden_footer::<R>(app.hidden))
}

/// How many rows this display is not showing, and where to see them.
///
/// `watch` has no `--all` of its own (plan section 3.2), so the footer points
/// at the command that does rather than at a flag this one does not accept —
/// and at *that provider's* command, which is what
/// [`TuiRow::HIDDEN_HINT`] carries.
pub fn hidden_footer<R: TuiRow>(hidden: usize) -> String {
    let noun = if hidden == 1 { "entry" } else { "entries" };
    format!("{hidden} {noun} hidden ({})", R::HIDDEN_HINT)
}

/// Renders one bordered block per shown account, top-aligned.
fn draw_accounts<R: TuiRow>(frame: &mut Frame<'_>, app: &App<R>, area: Rect) {
    if app.rows.is_empty() {
        frame.render_widget(Paragraph::new("no accounts to show"), area);
        return;
    }

    let mut constraints: Vec<Constraint> =
        app.rows.iter().map(|row| Constraint::Length(row.block_height())).collect();
    // Soaks up whatever is left so the blocks stay at their natural heights
    // instead of stretching to fill the terminal.
    constraints.push(Constraint::Min(0));

    let slots = Layout::vertical(constraints).split(area);
    for (index, row) in app.rows.iter().enumerate() {
        let Some(slot) = slots.get(index) else {
            // The terminal is shorter than the accounts need; the rest are
            // simply off-screen rather than drawn on top of each other.
            break;
        };
        draw_account(frame, row, index == app.selected, app.now, *slot);
    }
}

/// Renders one account.
fn draw_account<R: TuiRow>(
    frame: &mut Frame<'_>,
    row: &R,
    selected: bool,
    now: Timestamp,
    area: Rect,
) {
    let block = Block::bordered().title(row.account_title(selected));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let bars = row.gauges();
    let mut constraints: Vec<Constraint> = vec![Constraint::Length(1); bars.len()];
    constraints.push(Constraint::Length(1));
    let lines = Layout::vertical(constraints).split(inner);

    for (index, (name, percent)) in bars.iter().enumerate() {
        let Some(line) = lines.get(index) else {
            break;
        };
        let [label, bar] =
            Layout::horizontal([Constraint::Length(GAUGE_LABEL_WIDTH), Constraint::Min(0)])
                .areas(*line);
        frame.render_widget(Paragraph::new(*name), label);
        // `percent` came from `percent_floor`, which clamps to `0..=100`, so
        // the widget's own bound is already satisfied.
        frame.render_widget(
            Gauge::default().percent(u16::from(*percent)).label(format!("{percent}%")),
            bar,
        );
    }

    if let Some(line) = lines.last() {
        frame.render_widget(Paragraph::new(row.detail_line(now)), *line);
    }
}

/// `N accounts`, pluralised.
fn account_count(shown: usize) -> String {
    let noun = if shown == 1 { "account" } else { "accounts" };
    format!("{shown} {noun}")
}

/// How many lines the footer needs.
fn footer_height<R: TuiRow>(app: &App<R>) -> u16 {
    if app.hidden == 0 { 1 } else { 2 }
}

#[cfg(test)]
#[path = "ui_tests.rs"]
mod tests;
