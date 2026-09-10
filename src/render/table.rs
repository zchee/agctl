//! The `status` table.
//!
//! Ten columns. Plan section 3.1 fixed nine of them, ending in a single
//! `Next reset` countdown; on the user's request of 2026-09-09 that one cell
//! became two, so that the five-hour window and the seven-day all-models
//! window each say when they roll over rather than only the sooner of the two
//! saying how long it has left:
//!
//! ```text
//! Account | Org | Plan | 5h | Weekly | Fable (weekly) | Credits | 5h reset | Weekly reset | State
//! ```
//!
//! Each reset cell carries a countdown and the absolute local time it names
//! (user request of 2026-09-09), the countdown flush left and the
//! parenthesised absolute time flush right within the column (user request
//! of 2026-09-11) — see [`crate::render::reset::justify`] for why `tabled`
//! cannot do that per cell on its own, which is why this module builds each
//! reset column in two passes rather than one cell at a time. The JSON
//! report's `next_reset` member is untouched by either change: it is a
//! published interface, and the soonest reset across every window is still a
//! fact a consumer may be reading.
//!
//! # The eleventh column
//!
//! `status --by-identity` folds the live credential's row into the row of the
//! account that owns it and adds a `Kind` column after `Plan`, where the
//! folded row reads `live+owned`. The column exists **only** under that flag:
//! plan section 3.1 fixed ten columns for the default table, and an opt-in
//! view is not a reason to widen what everyone else sees. Which rows survive
//! the fold is decided in `commands::status` — see [`crate::render`] on why a
//! renderer is given no room to decide what to hide.
//!
//! # Continuation rows
//!
//! An account can have windows that no column names — a weekly scope other
//! than the headline one, or a `kind` this build has never seen. Dropping
//! them would hide a limit the user is subject to (risk R3), and widening the
//! table per account would make two accounts unalignable. So each gets a
//! continuation row directly under its account: the first cell names the
//! window (`↳ opus (weekly)`, `↳ monthly_foo (unknown kind)`), the
//! percentage sits in the `Weekly` column and the reset in `Weekly reset` —
//! `5h reset` stays blank, because such a window is never the five-hour one.
//! The label, not the column, is what says what the number means — which is
//! why an unknown kind renders its kind string verbatim rather than being
//! quietly filed as weekly.
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
use crate::render::reset;
use crate::usage::model::CreditsState;
use crate::usage::model::LimitWindow;
use crate::usage::model::WindowKind;

/// What an unavailable figure looks like.
pub const EMPTY_CELL: &str = "—";

/// The marker a continuation row starts with.
pub const CONTINUATION_MARKER: &str = "↳";

/// The column headings, in order.
pub const HEADINGS: [&str; 10] = [
    "Account",
    "Org",
    "Plan",
    "5h",
    "Weekly",
    "Fable (weekly)",
    "Credits",
    "5h reset",
    "Weekly reset",
    "State",
];

/// The heading of the column `--by-identity` adds.
pub const KIND_HEADING: &str = "Kind";

/// Where that column goes: after `Plan`, with the other three columns that
/// say *which account this is* rather than what it is using.
pub const KIND_INDEX: usize = 3;

/// Where `5h reset` sits in a ten-cell record, before `--by-identity` splices
/// `Kind` in.
const SESSION_RESET_INDEX: usize = 7;

/// Where `Weekly reset` sits, before `--by-identity` splices `Kind` in.
const WEEKLY_RESET_INDEX: usize = 8;

/// [`HEADINGS`], plus [`KIND_HEADING`] when `by_identity`.
///
/// A function rather than a second constant so the ten headings stay written
/// down exactly once: a column added to `HEADINGS` cannot be forgotten here.
pub fn headings(by_identity: bool) -> Vec<&'static str> {
    let mut headings = HEADINGS.to_vec();
    if by_identity {
        headings.insert(KIND_INDEX, KIND_HEADING);
    }
    headings
}

/// Renders a whole report: the table, then the hidden-row footer.
///
/// A report with no shown rows still prints its headings and its footer, so
/// `status` on a machine whose only account is a stale sibling explains
/// itself rather than printing nothing.
pub fn render(report: &Report) -> String {
    let mut builder = Builder::default();
    builder.push_record(headings(report.by_identity));

    // Two passes, because a justified cell's padding depends on every other
    // row in its column (the countdown flush left, the absolute time flush
    // right — `crate::render::reset::justify`), and that width is only known
    // once every row has been seen. The first pass builds each row's other
    // nine (or ten, under `--by-identity`) cells directly and sets the two
    // reset cells aside as raw data; the second computes each reset column's
    // width and fills the justified text in before any record reaches the
    // builder.
    let mut records: Vec<Vec<String>> = Vec::new();
    let mut session_column: Vec<ResetSlot> = Vec::new();
    let mut weekly_column: Vec<ResetSlot> = Vec::new();

    for row in report.shown() {
        let usage = row.usage.as_ref();
        session_column.push(reset_slot(usage.and_then(|u| u.window(&WindowKind::Session)), report));
        weekly_column
            .push(reset_slot(usage.and_then(|u| u.window(&WindowKind::WeeklyAll)), report));
        // A continuation row's kind cell is blank for the same reason its
        // `Org` and `Plan` cells are: the window belongs to the account named
        // above it, and repeating the account's attributes on it would read
        // as a second account.
        records.push(with_kind(account_record(row), report, row.kind));

        if let Some(usage) = &row.usage {
            for window in usage.extra_windows(HEADLINE_SCOPE) {
                // Never the five-hour window, so that cell is left blank
                // rather than justified — see `continuation_record`.
                session_column.push(ResetSlot::Final(String::new()));
                weekly_column.push(reset_slot(Some(window), report));
                records.push(with_kind(continuation_record(window), report, ""));
            }
        }
    }

    let session_width = column_width(&session_column);
    let weekly_width = column_width(&weekly_column);
    let session_index = reset_index(SESSION_RESET_INDEX, report);
    let weekly_index = reset_index(WEEKLY_RESET_INDEX, report);

    for ((record, session), weekly) in
        records.iter_mut().zip(session_column.iter()).zip(weekly_column.iter())
    {
        record[session_index] = session.finalize(session_width);
        record[weekly_index] = weekly.finalize(weekly_width);
    }

    for record in records {
        builder.push_record(record);
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

/// A ten-cell record, with `kind` spliced in at [`KIND_INDEX`] under
/// `--by-identity` and left out entirely otherwise.
fn with_kind(cells: [String; 10], report: &Report, kind: &str) -> Vec<String> {
    let mut cells = cells.to_vec();
    if report.by_identity {
        cells.insert(KIND_INDEX, kind.to_owned());
    }
    cells
}

/// One account's own row.
///
/// The two reset cells are left blank here: `render`'s second pass fills
/// them in once every row's [`ResetSlot`] has been collected and each
/// column's width is known.
fn account_record(row: &StatusRow) -> [String; 10] {
    let usage = row.usage.as_ref();
    [
        row.account.clone(),
        or_empty(&row.org),
        or_empty(&row.plan),
        usage.map_or_else(empty, |u| percent_cell(u.window(&WindowKind::Session))),
        usage.map_or_else(empty, |u| percent_cell(u.window(&WindowKind::WeeklyAll))),
        usage.map_or_else(empty, |u| percent_cell(u.scoped_window(HEADLINE_SCOPE))),
        usage.map_or_else(empty, |u| credits_cell(&u.credits)),
        String::new(),
        String::new(),
        row.state_cell(),
    ]
}

/// One window that has no column of its own.
///
/// Its `Weekly reset` cell is left blank for the same reason as
/// [`account_record`]'s; its `5h reset` cell is left blank for good, because
/// such a window is never the five-hour one (see `render`, which gives it
/// [`ResetSlot::Final`] rather than a pair to justify).
fn continuation_record(window: &LimitWindow) -> [String; 10] {
    [
        format!("  {CONTINUATION_MARKER} {}", window.label()),
        String::new(),
        String::new(),
        String::new(),
        percent_cell(Some(window)),
        String::new(),
        String::new(),
        // Not the five-hour window — that one has a column of its own and
        // never reaches here — so the cell is left blank rather than being
        // given an em dash, which would claim a figure was unavailable.
        String::new(),
        String::new(),
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

/// One reset column's cell, before its column's width is known: either a
/// countdown/absolute pair to [justify](reset::justify), or text that is
/// already final and must not be touched by justification.
///
/// An em dash covers both ways of a real window having nothing to say — the
/// response described no such window, or described one with no `resets_at`
/// — because the reader's question is about the figure, not about which of
/// the two happened. `Final` also carries the blank a continuation row's
/// `5h reset` cell always is (`account_record`, `continuation_record`).
enum ResetSlot {
    Pair(String, String),
    Final(String),
}

impl ResetSlot {
    /// This slot's own contribution to its column's width.
    ///
    /// A pair's is its natural minimum — `len(countdown) + 1 +
    /// len("(absolute)")`, [`reset::justify`]'s own floor — and `Final`'s is
    /// simply its length: the rule that a `—` or a blank cell counts toward
    /// the column's width the same as any other row (see
    /// [`reset::justify`]'s doc), which in practice never matters, since
    /// neither is ever the widest cell in a column that also holds a pair.
    fn natural_width(&self) -> usize {
        match self {
            ResetSlot::Pair(countdown, absolute) => {
                countdown.chars().count() + 1 + absolute.chars().count() + 2
            }
            ResetSlot::Final(text) => text.chars().count(),
        }
    }

    /// This slot's finished cell text, once the column's width is known.
    fn finalize(&self, width: usize) -> String {
        match self {
            ResetSlot::Pair(countdown, absolute) => reset::justify(countdown, absolute, width),
            ResetSlot::Final(text) => text.clone(),
        }
    }
}

/// The reset slot for one window: a pair to justify when it has a
/// `resets_at`, an em dash otherwise.
fn reset_slot(window: Option<&LimitWindow>, report: &Report) -> ResetSlot {
    match window.and_then(|window| window.resets_at) {
        Some(resets_at) => {
            let (countdown, absolute) = reset::parts(report.now, resets_at, &report.tz);
            ResetSlot::Pair(countdown, absolute)
        }
        None => ResetSlot::Final(empty()),
    }
}

/// The width a reset column's cells should be justified to: the widest
/// [`ResetSlot::natural_width`] among every row sharing the column, or zero
/// for a column with no rows (an empty report still prints its headings).
fn column_width(column: &[ResetSlot]) -> usize {
    column.iter().map(ResetSlot::natural_width).max().unwrap_or(0)
}

/// `index`, shifted by one when `--by-identity` spliced `Kind` in before it
/// (`with_kind`) — both reset columns sit after [`KIND_INDEX`], so both shift
/// together.
fn reset_index(index: usize, report: &Report) -> usize {
    if report.by_identity && index >= KIND_INDEX { index + 1 } else { index }
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
