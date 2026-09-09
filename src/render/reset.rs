//! When a window rolls over, in the reader's own zone.
//!
//! The table used to carry one `Next reset` cell holding a countdown —
//! `2h13m`, `2d20h` — and a countdown alone cannot be planned around: it says
//! how long, never *when*. `2d6h` does not name an afternoon, and a weekly
//! window that rolls over on Sunday at two in the afternoon is a fact worth
//! stating as a time of day. So each cell carries both: the absolute local
//! time first, the countdown after it in parentheses (user request of
//! 2026-09-09).
//!
//! # The three shapes, and why the prefix changes
//!
//! ```text
//! 4:15 PM (1h12m)          this afternoon
//! Sun 2:00 PM (2d6h)       another day, less than a week away
//! Sep 16 2:00 PM (7d5h)    a week or more away
//! ```
//!
//! A bare clock time is unambiguous only on the day it is read, so a reset on
//! another local day carries its weekday. A weekday, in turn, is unambiguous
//! only inside one week: "Sun" seven days out names the same word as "Sun"
//! tomorrow, so from seven days the date replaces it. The cut is the calendar
//! ambiguity, not a display preference.
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

/// A reset on another local day, less than a week out: `Sun 2:00 PM`.
const WITH_WEEKDAY: &str = "%a %-I:%M %p";

/// A reset a week or more out, where the weekday no longer names it:
/// `Sep 16 2:00 PM`.
const WITH_DATE: &str = "%b %-d %-I:%M %p";

/// The whole cell for one window's reset: when it happens, and how far off
/// that is.
///
/// The countdown is [`render_countdown`] — the same function the `watch`
/// detail line uses, so the two presentations cannot drift apart — and a
/// reset that has already passed renders as `now`, which is what a window
/// rolling over between the fetch and the render looks like.
///
/// # Examples
///
/// ```text
/// 4:15 PM (1h12m)
/// Sun 2:00 PM (2d6h)
/// Sep 16 2:00 PM (7d5h)
/// 11:59 PM (now)
/// ```
pub fn render_reset(now: Timestamp, resets_at: Timestamp, tz: &TimeZone) -> String {
    format!("{} ({})", absolute_local(now, resets_at, tz), render_countdown(now, resets_at))
}

/// The absolute half of the cell: a 12-hour local clock time, prefixed by as
/// much of the date as it takes to name the day unambiguously.
///
/// The hour carries no leading zero and the minute always carries two, so
/// `2:05 PM` and `12:00 AM` read as clock times rather than as fields.
///
/// # Examples
///
/// ```text
/// 12:00 AM   local midnight, today
/// 12:05 PM   five past noon, today
/// Sun 8:30 AM
/// Sep 16 2:00 PM
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
