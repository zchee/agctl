//! One frame of `agentctl claude watch`.
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
//! is what says which lock, how long ago, and how many seconds to wait.

use jiff::Timestamp;
use ratatui::Frame;
use ratatui::layout::Constraint;
use ratatui::layout::Layout;
use ratatui::layout::Rect;
use ratatui::widgets::Block;
use ratatui::widgets::Gauge;
use ratatui::widgets::Paragraph;

use crate::commands::status::RowOutcome;
use crate::provider::claude::account::AccountState;
use crate::provider::claude::usage::HEADLINE_SCOPE;
use crate::tui::app::App;
use crate::usage::model::CreditsState;
use crate::usage::model::UsageSnapshot;
use crate::usage::model::WindowKind;
use crate::usage::model::render_countdown;

/// The keys the footer advertises.
pub const HELP_LINE: &str = "q quit · r refresh · ↑↓ select";

/// The marker in front of the selected account.
pub const SELECTED_MARKER: &str = "▸";

/// What an unavailable figure looks like, matching the `status` table.
pub const EMPTY_CELL: &str = "—";

/// How wide the name in front of each gauge is.
const GAUGE_LABEL_WIDTH: u16 = 10;

/// Lines an account block spends on something other than a gauge: the two
/// borders and the detail line.
const BLOCK_CHROME: u16 = 3;

/// Draws the whole frame.
pub fn draw(frame: &mut Frame<'_>, app: &App) {
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
pub fn header_line(app: &App) -> String {
    let mut parts = vec![format!("agentctl claude watch · {}", account_count(app.rows.len()))];

    parts.push(match app.last_fetch {
        // `render_countdown` measures forwards, so the arguments are the
        // other way round for an elapsed time: from the fetch, to now.
        Some(at) => format!("last fetch {} ago", render_countdown(at, app.now)),
        None => format!("last fetch {EMPTY_CELL}"),
    });
    parts.push(match app.next_fetch {
        Some(at) => format!("next fetch in {}", render_countdown(app.now, at)),
        None => format!("next fetch {EMPTY_CELL}"),
    });
    if app.fetching {
        parts.push("fetching".to_owned());
    }
    if app.stale {
        parts.push("stale".to_owned());
    }

    parts.join(" · ")
}

/// The help line, and the hidden-row count when there is one.
pub fn footer_text(app: &App) -> String {
    if app.hidden == 0 {
        return HELP_LINE.to_owned();
    }
    format!("{HELP_LINE}\n{}", hidden_footer(app.hidden))
}

/// How many rows this display is not showing, and where to see them.
///
/// `watch` has no `--all` of its own (plan section 3.2), so the footer points
/// at the command that does rather than at a flag this one does not accept.
pub fn hidden_footer(hidden: usize) -> String {
    let noun = if hidden == 1 { "entry" } else { "entries" };
    format!("{hidden} {noun} hidden (agentctl claude status --all)")
}

/// The badge for a row, when its state has one.
///
/// `None` is the ordinary case: a healthy row, or one whose state the label
/// alone says better than any two-word summary could.
pub fn badge(state: &AccountState) -> Option<&'static str> {
    match state {
        AccountState::Stale => Some("stale"),
        AccountState::RateLimited { .. } => Some("rate-limited"),
        AccountState::ClaudeSessionDetected { .. } => Some("claude-detected"),
        AccountState::KeychainLocked { .. } | AccountState::KeychainTimeout => {
            Some("keychain-locked")
        }
        AccountState::Busy => Some("busy"),
        AccountState::NeedsLogin => Some("needs login"),
        _ => None,
    }
}

/// The gauges one row earns, in display order.
pub fn gauges(row: &RowOutcome) -> Vec<(&'static str, u8)> {
    let Some(usage) = row.usage.as_ref() else {
        return Vec::new();
    };

    let mut out = Vec::new();
    if let Some(percent) = window_percent(usage, &WindowKind::Session) {
        out.push(("5h", percent));
    }
    if let Some(percent) = window_percent(usage, &WindowKind::WeeklyAll) {
        out.push(("weekly", percent));
    }
    if let Some(percent) =
        usage.scoped_window(HEADLINE_SCOPE).and_then(|window| window.percent_floor)
    {
        out.push((HEADLINE_SCOPE, percent));
    }
    if let CreditsState::On(credits) = &usage.credits
        && let Some(percent) = credits.percent
    {
        out.push(("credits", percent));
    }
    out
}

/// The line under an account's gauges: badge, state, note, next reset.
pub fn detail_line(row: &RowOutcome, now: Timestamp) -> String {
    let mut parts = Vec::new();
    if let Some(badge) = badge(&row.state) {
        parts.push(format!("[{badge}]"));
    }
    parts.push(row.state.label());
    if let Some(note) = row.note.as_ref().filter(|note| !note.is_empty()) {
        parts.push(format!("({note})"));
    }
    if let Some(resets_at) = row.usage.as_ref().and_then(UsageSnapshot::next_reset) {
        parts.push(format!("next reset in {}", render_countdown(now, resets_at)));
    }
    parts.join(" · ")
}

/// An account block's title: who it is, and whether it is selected.
pub fn account_title(row: &RowOutcome, selected: bool) -> String {
    let marker = if selected { SELECTED_MARKER } else { " " };
    let plan = if row.plan.is_empty() { EMPTY_CELL } else { row.plan.as_str() };
    let org = if row.org.is_empty() { EMPTY_CELL } else { row.org.as_str() };
    format!("{marker} {} · {org} · {plan} ", row.account)
}

/// How tall an account's block is.
///
/// Bounded by construction — [`gauges`] returns at most four entries — so the
/// addition cannot overflow the `u16` even with overflow checks compiled out.
pub fn block_height(row: &RowOutcome) -> u16 {
    let count = u16::try_from(gauges(row).len()).unwrap_or(0);
    BLOCK_CHROME.saturating_add(count)
}

/// Renders one bordered block per shown account, top-aligned.
fn draw_accounts(frame: &mut Frame<'_>, app: &App, area: Rect) {
    if app.rows.is_empty() {
        frame.render_widget(Paragraph::new("no accounts to show"), area);
        return;
    }

    let mut constraints: Vec<Constraint> =
        app.rows.iter().map(|row| Constraint::Length(block_height(row))).collect();
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
fn draw_account(
    frame: &mut Frame<'_>,
    row: &RowOutcome,
    selected: bool,
    now: Timestamp,
    area: Rect,
) {
    let block = Block::bordered().title(account_title(row, selected));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let bars = gauges(row);
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
        frame.render_widget(Paragraph::new(detail_line(row, now)), *line);
    }
}

/// A window's floored percentage, when the response carried one.
fn window_percent(usage: &UsageSnapshot, kind: &WindowKind) -> Option<u8> {
    usage.window(kind).and_then(|window| window.percent_floor)
}

/// `N accounts`, pluralised.
fn account_count(shown: usize) -> String {
    let noun = if shown == 1 { "account" } else { "accounts" };
    format!("{shown} {noun}")
}

/// How many lines the footer needs.
fn footer_height(app: &App) -> u16 {
    if app.hidden == 0 { 1 } else { 2 }
}

#[cfg(test)]
#[path = "ui_tests.rs"]
mod tests;
