//! The `status` table.
//!
//! Nine columns, fixed by plan section 3.1:
//!
//! ```text
//! Account | Org | Plan | 5h | Weekly | Fable (weekly) | Credits | Next reset | State
//! ```
//!
//! # Continuation rows
//!
//! An account can have windows that no column names — a weekly scope other
//! than the headline one, or a `kind` this build has never seen. Dropping
//! them would hide a limit the user is subject to (risk R3), and widening the
//! table per account would make two accounts unalignable. So each gets a
//! continuation row directly under its account: the first cell names the
//! window (`↳ opus (weekly)`, `↳ monthly_foo (unknown kind)`) and the
//! percentage sits in the `Weekly` column. The label, not the column, is what
//! says what the number means — which is why an unknown kind renders its kind
//! string verbatim rather than being quietly filed as weekly.
//!
//! # Empty cells
//!
//! A missing figure is an em dash, never `0%` and never a blank. `0%` is a
//! claim about the account; a blank is ambiguous between "nothing to say" and
//! "something went wrong". The em dash says the figure is unavailable, which
//! is the only true statement available.

use tabled::builder::Builder;
use tabled::settings::Style;

use crate::provider::claude::usage::HEADLINE_SCOPE;
use crate::render::Report;
use crate::render::StatusRow;
use crate::usage::model::CreditsState;
use crate::usage::model::LimitWindow;
use crate::usage::model::UsageSnapshot;
use crate::usage::model::WindowKind;
use crate::usage::model::render_countdown;

/// What an unavailable figure looks like.
pub const EMPTY_CELL: &str = "—";

/// The marker a continuation row starts with.
pub const CONTINUATION_MARKER: &str = "↳";

/// The column headings, in order.
pub const HEADINGS: [&str; 9] =
    ["Account", "Org", "Plan", "5h", "Weekly", "Fable (weekly)", "Credits", "Next reset", "State"];

/// Renders a whole report: the table, then the hidden-row footer.
///
/// A report with no shown rows still prints its headings and its footer, so
/// `status` on a machine whose only account is a stale sibling explains
/// itself rather than printing nothing.
pub fn render(report: &Report) -> String {
    let mut builder = Builder::default();
    builder.push_record(HEADINGS);

    for row in report.shown() {
        builder.push_record(account_record(row, report));
        if let Some(usage) = &row.usage {
            for window in usage.extra_windows(HEADLINE_SCOPE) {
                builder.push_record(continuation_record(window, report));
            }
        }
    }

    let mut table = builder.build();
    table.with(Style::psql());

    let mut out = table.to_string();
    let hidden = report.hidden_count();
    if hidden > 0 {
        out.push('\n');
        out.push_str(&footer(hidden));
    }
    out
}

/// The hidden-row footer (plan section 3.2).
pub fn footer(hidden: usize) -> String {
    let noun = if hidden == 1 { "entry" } else { "entries" };
    format!("{hidden} {noun} hidden (--all)")
}

/// One account's own row.
fn account_record(row: &StatusRow, report: &Report) -> [String; 9] {
    let usage = row.usage.as_ref();
    [
        row.account.clone(),
        or_empty(&row.org),
        or_empty(&row.plan),
        usage.map_or_else(empty, |u| percent_cell(u.window(&WindowKind::Session))),
        usage.map_or_else(empty, |u| percent_cell(u.window(&WindowKind::WeeklyAll))),
        usage.map_or_else(empty, |u| percent_cell(u.scoped_window(HEADLINE_SCOPE))),
        usage.map_or_else(empty, |u| credits_cell(&u.credits)),
        usage.map_or_else(empty, |u| reset_cell(u, report)),
        row.state_cell(),
    ]
}

/// One window that has no column of its own.
fn continuation_record(window: &LimitWindow, report: &Report) -> [String; 9] {
    let reset =
        window.resets_at.map_or_else(empty, |resets_at| render_countdown(report.now, resets_at));
    [
        format!("  {CONTINUATION_MARKER} {}", window.label()),
        String::new(),
        String::new(),
        String::new(),
        percent_cell(Some(window)),
        String::new(),
        String::new(),
        reset,
        String::new(),
    ]
}

/// A percentage cell, floored (fact F21).
fn percent_cell(window: Option<&LimitWindow>) -> String {
    match window.and_then(|window| window.percent_floor) {
        Some(percent) => format!("{percent}%"),
        None => empty(),
    }
}

/// The credits cell (plan section 3.8).
///
/// Four shapes, and the difference between the last two is the point: `off`
/// means the account has credits and switched them off, `n/a` means the
/// response carried no `extra_usage` at all. Collapsing them would tell a
/// user with credits enabled that they are disabled.
fn credits_cell(credits: &CreditsState) -> String {
    match credits {
        CreditsState::Unavailable => "n/a".to_owned(),
        CreditsState::Off { .. } => "off".to_owned(),
        CreditsState::On(credits) => {
            // Credits are switched on but the server sent no `used_credits`.
            // Rendering `— / Unlimited` would put a ceiling next to a figure
            // that does not exist; the whole cell is unavailable (plan
            // section 3.8).
            let Some(used) = credits.used.as_ref() else {
                return empty();
            };
            let limit =
                credits.limit.as_ref().map_or_else(|| "Unlimited".to_owned(), ToString::to_string);
            match credits.percent {
                Some(percent) => format!("{used} / {limit} ({percent}%)"),
                None => format!("{used} / {limit}"),
            }
        }
    }
}

/// The soonest reset across the row's windows, as a countdown.
fn reset_cell(usage: &UsageSnapshot, report: &Report) -> String {
    usage.next_reset().map_or_else(empty, |resets_at| render_countdown(report.now, resets_at))
}

/// The em dash, as an owned string.
fn empty() -> String {
    EMPTY_CELL.to_owned()
}

/// `value`, or an em dash when it is blank.
fn or_empty(value: &str) -> String {
    if value.is_empty() { empty() } else { value.to_owned() }
}

#[cfg(test)]
#[path = "table_tests.rs"]
mod tests;
