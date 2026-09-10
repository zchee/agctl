//! When a window rolls over, in the reader's own zone.
//!
//! The table used to carry one `Next reset` cell holding a countdown —
//! `2h13m`, `2d20h` — and a countdown alone cannot be planned around: it says
//! how long, never *when*. `2d6h` does not name an afternoon, and a weekly
//! window that rolls over on Sunday at two in the afternoon is a fact worth
//! stating as a time of day. So each cell carries both (user request of
//! 2026-09-09) — and, on the user's follow-up request of 2026-09-11, the
//! countdown leads: it is the figure a reader scans the column for, and the
//! absolute time follows it in parentheses as the answer to "which one is
//! that". [`justify`] additionally lines every cell in one reset column up so
//! every countdown starts flush left and every closing paren ends flush
//! right, because `tabled` only knows how to pad a whole cell and cannot
//! split one cell into two independently-aligned halves.
//!
//! # The three shapes, and why the prefix changes
//!
//! ```text
//! 1h12m (4:15 PM)          this afternoon
//! 2d6h (Sun 02:00 PM)      another day, less than a week away
//! 7d5h (Sep 16 02:00 PM)   a week or more away
//! ```
//!
//! A bare clock time is unambiguous only on the day it is read, so a reset on
//! another local day carries its weekday. A weekday, in turn, is unambiguous
//! only inside one week: "Sun" seven days out names the same word as "Sun"
//! tomorrow, so from seven days the date replaces it. The cut is the calendar
//! ambiguity, not a display preference.
//!
//! The hour is zero-padded once a weekday or a date joins it — `Sun 01:59 PM`,
//! `Sep 16 02:00 PM` — so that every absolute time inside one shape is the
//! same width, which is what lets [`justify`] give every row in a column the
//! same right edge without measuring each one specially. The bare today shape
//! keeps the un-padded hour (`7:09 AM`): it never shares a column position
//! with a weekday or date form's clock, so nothing depends on its width
//! matching theirs. The day of month stays un-padded in every shape (`Sep 6`,
//! not `Sep 06`) — only the hour needs a constant width to line a column up.
//!
//! # Local means local
//!
//! Every comparison here is made on the *zoned* value, not on the UTC
//! timestamp. 23:30 UTC on a Saturday is 08:30 Sunday in `+09:00`, and a
//! weekday taken from the timestamp would print the wrong day for half the
//! world. The zone arrives as an argument ([`crate::render::Report::tz`])
//! rather than being read here, so a snapshot test can pin one.

use jiff::Timestamp;
use jiff::Zoned;
use jiff::tz::TimeZone;

use crate::usage::model::render_countdown;

/// Seven days in milliseconds: at or beyond this a weekday names two days.
const WEEK_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// A reset on the same local calendar day as `now`: `4:15 PM`.
const TIME_ONLY: &str = "%-I:%M %p";

/// A reset on another local day, less than a week out: `Sun 02:00 PM`.
///
/// The hour is zero-padded (`%I`, not `%-I`) so every absolute time in this
/// shape is the same width — see the module doc on why [`justify`] needs
/// that.
const WITH_WEEKDAY: &str = "%a %I:%M %p";

/// A reset a week or more out, where the weekday no longer names it:
/// `Sep 16 02:00 PM`. The day of month stays un-padded (`Sep 6`, not
/// `Sep 06`); only the hour needs the constant width.
const WITH_DATE: &str = "%b %-d %I:%M %p";

/// The countdown and the absolute local time for one reset, un-joined.
///
/// A caller building a whole column — [`crate::render::table`] — needs both
/// halves of every row before it can compute the column's width, so it
/// cannot go through [`render_reset`], which already joins the two into one
/// string. [`justify`] is the other half: it takes what this returns and the
/// width the caller computed, and produces the final cell.
pub fn parts(now: Timestamp, resets_at: Timestamp, tz: &TimeZone) -> (String, String) {
    (render_countdown(now, resets_at), absolute_local(now, resets_at, tz))
}

/// Lays `countdown` flush left and `(absolute)` flush right within `width`,
/// the gap between them filled with spaces.
///
/// `width` is the column's own width: the widest `len(countdown) + 1 +
/// len("(absolute)")` among every row sharing the column — a `—` cell or a
/// `now (…)` cell counts toward that maximum the same as any other row,
/// which is why this takes plain strings rather than anything that knows
/// about "missing" — computed by the caller, since only the caller sees
/// every row in the column at once. A `width` narrower than this cell's own
/// natural length still renders; the gap is never less than one space.
///
/// # Examples
///
/// ```text
/// justify("1h42m", "7:09 AM", 15)             -> "1h42m (7:09 AM)"
/// justify("19h32m", "Sat 12:59 AM", 21)       -> "19h32m (Sat 12:59 AM)"
/// justify("6d5h", "Thu 10:59 AM", 21)         -> "6d5h   (Thu 10:59 AM)"
/// ```
pub fn justify(countdown: &str, absolute: &str, width: usize) -> String {
    let paren = format!("({absolute})");
    let natural = countdown.chars().count() + paren.chars().count();
    let pad = width.saturating_sub(natural).max(1);
    format!("{countdown}{}{paren}", " ".repeat(pad))
}

/// The whole cell for one window's reset, with no column-wide padding: the
/// countdown, then the absolute local time in parentheses.
///
/// Kept for a caller with no column to justify against — a single cell has
/// no other row to line its closing paren up with, so the padding
/// [`justify`] exists for would have nothing to compute against.
/// `render/table.rs`'s own reset columns go through [`parts`] and [`justify`]
/// instead, once per column rather than once per cell, so every row in a
/// column shares the same width.
///
/// The countdown is [`render_countdown`] — the same function the `watch`
/// detail line uses, so the two presentations cannot drift apart — and a
/// reset that has already passed renders as `now`, which is what a window
/// rolling over between the fetch and the render looks like.
///
/// # Examples
///
/// ```text
/// 1h12m (4:15 PM)
/// 2d6h (Sun 02:00 PM)
/// 7d5h (Sep 16 02:00 PM)
/// now (11:59 PM)
/// ```
// Only the non-test build has no caller: `reset_tests.rs` exercises this
// directly, so `cfg(test)` already gives it a real one there, and applying
// `expect` unconditionally would turn that into an "unfulfilled expectation"
// warning under `cargo test`/`nextest`.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "kept as the un-padded single-cell form for a caller with no column to justify \
                  against, per the reset-column justification redesign of 2026-09-11 — \
                  render/table.rs's own cells now go through `parts` and `justify` instead"
    )
)]
pub fn render_reset(now: Timestamp, resets_at: Timestamp, tz: &TimeZone) -> String {
    let (countdown, absolute) = parts(now, resets_at, tz);
    format!("{countdown} ({absolute})")
}

/// The absolute half of the cell: a 12-hour local clock time, prefixed by as
/// much of the date as it takes to name the day unambiguously.
///
/// The minute always carries two digits, and the hour carries a leading zero
/// once a weekday or a date joins it (see the module doc); on its own — the
/// same local day as `now` — the hour carries none, so `2:05 PM` and
/// `12:00 AM` read as clock times rather than as fields.
///
/// # Examples
///
/// ```text
/// 12:00 AM   local midnight, today
/// 12:05 PM   five past noon, today
/// Sun 08:30 AM
/// Sep 16 02:00 PM
/// ```
pub fn absolute_local(now: Timestamp, at: Timestamp, tz: &TimeZone) -> String {
    let now_local = now.to_zoned(tz.clone());
    let at_local = at.to_zoned(tz.clone());
    at_local.strftime(shape(&now_local, &at_local)).to_string()
}

/// Which of the three formats names `at_local` from where `now_local` stands.
fn shape(now_local: &Zoned, at_local: &Zoned) -> &'static str {
    if now_local.date() == at_local.date() {
        return TIME_ONLY;
    }
    if a_week_or_more(now_local.timestamp(), at_local.timestamp()) {
        WITH_DATE
    } else {
        WITH_WEEKDAY
    }
}

/// Whether two instants are at least a week apart, in either direction.
///
/// Either direction because a reset can be in the past: a window that rolled
/// over eight days ago is as badly served by a weekday as one that rolls over
/// eight days from now.
///
/// The subtraction is checked (constraint C-006): this project builds with
/// `-C overflow-checks=off`, so a wrapped difference between two extreme
/// timestamps would silently choose the wrong format. Two instants whose
/// difference does not fit an `i64` of milliseconds are certainly more than a
/// week apart.
fn a_week_or_more(now: Timestamp, at: Timestamp) -> bool {
    match at.as_millisecond().checked_sub(now.as_millisecond()) {
        Some(delta) => delta.unsigned_abs() >= WEEK_MS,
        None => true,
    }
}

#[cfg(test)]
#[path = "reset_tests.rs"]
mod tests;
