//! Tests for the reset cell: the absolute local time and its prefix rules.
//!
//! Every zone here is injected — a fixed offset, or a named entry asserted to
//! agree with one — and never [`TimeZone::system`]. A test that read the
//! machine's zone would pass in Tokyo and fail in Berlin, which is the one
//! thing these assertions must not do.

use jiff::tz::Offset;

use super::*;

/// The zone most of these tests render in: `+09:00`, fixed and DST-free.
///
/// Fixed rather than named so the assertions do not depend on a tzdb being
/// present, and `+09:00` specifically because it is far enough east that the
/// local date differs from the UTC date for a quarter of the day — which is
/// what pins "the weekday follows the *local* calendar".
fn plus_nine() -> TimeZone {
    TimeZone::fixed(Offset::constant(9))
}

/// A zone west of UTC, for the same instants seen from the other side.
fn minus_seven() -> TimeZone {
    TimeZone::fixed(Offset::constant(-7))
}

fn ts(text: &str) -> Timestamp {
    text.parse::<Timestamp>().expect("the test literal should be a valid RFC 3339 timestamp")
}

/// 10:00 on Wednesday 2026-09-09, in `+09:00`.
const NOW: &str = "2026-09-09T01:00:00Z";

#[test]
fn a_reset_on_the_same_local_day_is_a_bare_clock_time() {
    // 05:00Z is 14:00 in +09:00, the same local day as `NOW`, so the weekday
    // would say nothing the reader does not already know.
    assert_eq!(absolute_local(ts(NOW), ts("2026-09-09T05:00:00Z"), &plus_nine()), "2:00 PM");
}

#[test]
fn a_reset_on_another_local_day_carries_its_weekday() {
    // 2026-09-13 is a Sunday, four days out — inside the week, so the weekday
    // still names exactly one day.
    assert_eq!(absolute_local(ts(NOW), ts("2026-09-13T05:00:00Z"), &plus_nine()), "Sun 2:00 PM");
}

#[test]
fn a_reset_a_week_or_more_out_carries_the_date_instead() {
    // Seven days and four hours: "Wed" would name both this Wednesday and
    // that one, so the month and day replace it.
    assert_eq!(absolute_local(ts(NOW), ts("2026-09-16T05:00:00Z"), &plus_nine()), "Sep 16 2:00 PM");
}

#[test]
fn the_week_boundary_is_at_exactly_seven_days() {
    let now = ts(NOW);
    let tz = plus_nine();

    // 6d23h: still a week the reader can count on their fingers.
    assert_eq!(absolute_local(now, ts("2026-09-16T00:00:00Z"), &tz), "Wed 9:00 AM");
    // Exactly 7d: the weekday has stopped being an answer.
    assert_eq!(absolute_local(now, ts("2026-09-16T01:00:00Z"), &tz), "Sep 16 10:00 AM");
}

#[test]
fn a_day_of_the_month_is_not_zero_padded() {
    // The continuation rows in the table snapshots carry a first-of-the-month
    // reset, and `Oct 01` would read as a field rather than as a date.
    assert_eq!(absolute_local(ts(NOW), ts("2026-10-01T00:00:00Z"), &plus_nine()), "Oct 1 9:00 AM");
}

#[test]
fn midnight_and_noon_are_the_twelves_and_not_the_zeroes() {
    let now = ts(NOW);
    let tz = plus_nine();

    // 15:00Z is 00:00 on Thursday 2026-09-10 in +09:00.
    assert_eq!(absolute_local(now, ts("2026-09-09T15:00:00Z"), &tz), "Thu 12:00 AM");
    // 03:00Z is local noon, the same day.
    assert_eq!(absolute_local(now, ts("2026-09-09T03:00:00Z"), &tz), "12:00 PM");
}

#[test]
fn the_minute_is_always_two_digits_and_the_hour_never_is() {
    assert_eq!(absolute_local(ts(NOW), ts("2026-09-09T05:05:00Z"), &plus_nine()), "2:05 PM");
    assert_eq!(absolute_local(ts(NOW), ts("2026-09-09T00:09:00Z"), &plus_nine()), "9:09 AM");
}

#[test]
fn the_weekday_follows_the_local_date_and_not_the_utc_one() {
    // 23:30 UTC on Saturday 2026-09-12 is 08:30 on *Sunday* in +09:00. A
    // weekday taken from the timestamp would print "Sat" and be wrong for
    // every reader east of about UTC+01.
    let now = ts("2026-09-12T01:00:00Z");
    let at = ts("2026-09-12T23:30:00Z");
    assert_eq!(absolute_local(now, at, &plus_nine()), "Sun 8:30 AM");
    // The same instant, west of UTC: 16:30 on the Saturday. One instant, two
    // zones, two different weekdays — which is the whole reason the
    // comparison is made on the zoned value.
    assert_eq!(absolute_local(now, at, &minus_seven()), "Sat 4:30 PM");
}

#[test]
fn the_zone_decides_whether_two_instants_share_a_day() {
    // One instant pair, two zones, two answers. In +09:00 `now` is Wednesday
    // morning and the reset is Wednesday afternoon; in -07:00 both are
    // Tuesday evening.
    let now = ts(NOW);
    let at = ts("2026-09-09T05:00:00Z");
    assert_eq!(absolute_local(now, at, &plus_nine()), "2:00 PM");
    assert_eq!(absolute_local(now, at, &minus_seven()), "10:00 PM");
}

#[test]
fn a_named_zone_agrees_with_the_fixed_offset_it_stands_for() {
    // Asia/Tokyo has never observed DST, so the named entry and +09:00 must
    // render identically. If this fails, the tzdb is not what it claims and
    // the fixed-offset tests above are the ones to trust.
    let tokyo = TimeZone::get("Asia/Tokyo").expect("the platform tzdb should know Asia/Tokyo");
    let now = ts(NOW);
    for at in ["2026-09-09T05:00:00Z", "2026-09-13T05:00:00Z", "2026-09-16T05:00:00Z"] {
        assert_eq!(
            absolute_local(now, ts(at), &tokyo),
            absolute_local(now, ts(at), &plus_nine()),
            "{at} should render the same in Asia/Tokyo and in +09:00"
        );
    }
}

#[test]
fn a_reset_in_the_past_still_says_when_it_was() {
    // A window rolling over between the fetch and the render is ordinary, and
    // `now` is the honest countdown for it — but the absolute half still
    // names the moment, so the row is not reduced to a bare `(now)`.
    let cell = render_reset(ts(NOW), ts("2026-09-09T00:30:00Z"), &plus_nine());
    assert_eq!(cell, "9:30 AM (now)");

    let long_gone = render_reset(ts(NOW), ts("2026-09-01T00:30:00Z"), &plus_nine());
    assert_eq!(long_gone, "Sep 1 9:30 AM (now)", "eight days back is a date, not a weekday");
}

#[test]
fn the_cell_is_the_absolute_time_then_the_countdown_in_parentheses() {
    let now = ts(NOW);
    let tz = plus_nine();

    assert_eq!(render_reset(now, ts("2026-09-09T02:12:00Z"), &tz), "11:12 AM (1h12m)");
    assert_eq!(render_reset(now, ts("2026-09-13T05:00:00Z"), &tz), "Sun 2:00 PM (4d4h)");
    assert_eq!(render_reset(now, ts("2026-09-16T05:00:00Z"), &tz), "Sep 16 2:00 PM (7d4h)");
    assert_eq!(render_reset(now, ts("2026-09-09T01:00:45Z"), &tz), "10:00 AM (45s)");
}
