use jiff::Timestamp;

use super::*;

/// A timestamp, or a panic naming the literal that failed to parse.
fn ts(text: &str) -> Timestamp {
    text.parse::<Timestamp>().expect("the test literal should be a valid RFC 3339 timestamp")
}

fn window(kind: WindowKind, percent: f64, resets_at: Option<&str>) -> LimitWindow {
    LimitWindow {
        kind,
        percent: clamp_percent(percent),
        percent_floor: percent_floor(percent),
        severity: None,
        resets_at: resets_at.map(ts),
        scope_label: None,
        is_active: false,
    }
}

#[test]
fn clamp_percent_maps_the_ac24_vectors() {
    // Plan AC24: -1, 100.4, 250, NaN -> 0, 100, 100, None.
    let tests: [(f64, Option<u8>); 4] =
        [(-1.0, Some(0)), (100.4, Some(100)), (250.0, Some(100)), (f64::NAN, None)];
    for (input, expected) in tests {
        assert_eq!(percent_floor(input), expected, "percent_floor({input})");
    }
}

#[test]
fn ac24_percent_round_maps_the_same_vectors_to_the_nearest_whole_number() {
    // Plan AC24, for the credits figure: -1, 100.4, 250, NaN -> 0, 100, 100,
    // None. `utilization` already arrives as 0-100 (fact F23a), so it is
    // rounded where it stands and never scaled.
    let tests: [(f64, Option<u8>); 8] = [
        (-1.0, Some(0)),
        (0.0, Some(0)),
        (0.4, Some(0)),
        (4.3911999999999995, Some(4)),
        (99.5, Some(100)),
        (100.4, Some(100)),
        (250.0, Some(100)),
        (f64::NAN, None),
    ];
    for (input, expected) in tests {
        assert_eq!(percent_round(input), expected, "percent_round({input})");
    }
}

#[test]
fn percent_round_and_percent_floor_disagree_where_it_matters() {
    // The two exist side by side on purpose: a window percentage is floored
    // so agentctl never reads a point above the web UI (fact F21), while
    // plan section 3.8 specifies the credits figure as rounded.
    assert_eq!(percent_floor(35.9), Some(35));
    assert_eq!(percent_round(35.9), Some(36));
}

#[test]
fn percent_floor_never_rounds_up() {
    // Fact F21: the web UI floors, so 35.9 must read 35 and not 36. Rounding
    // half-up here is what would put agentctl a point above the site.
    assert_eq!(percent_floor(35.9), Some(35));
    assert_eq!(percent_floor(0.999), Some(0));
    assert_eq!(percent_floor(99.999), Some(99));
}

#[test]
fn clamp_percent_keeps_the_unrounded_value() {
    assert_eq!(clamp_percent(4.3911999999999995), Some(4.3911999999999995));
    assert_eq!(clamp_percent(-3.0), Some(0.0));
    assert_eq!(clamp_percent(f64::INFINITY), Some(100.0));
    assert_eq!(clamp_percent(f64::NEG_INFINITY), Some(0.0));
    assert_eq!(clamp_percent(f64::NAN), None);
}

#[test]
fn money_renders_usd_with_a_symbol_and_others_with_a_code() {
    let tests = [
        (Money { amount_minor: 1234, currency: "USD".to_owned(), exponent: 2 }, "$12.34"),
        (Money { amount_minor: 500_000, currency: "USD".to_owned(), exponent: 2 }, "$5000.00"),
        (Money { amount_minor: 1234, currency: "EUR".to_owned(), exponent: 2 }, "EUR 12.34"),
        (Money { amount_minor: 1234, currency: "JPY".to_owned(), exponent: 0 }, "JPY 1234"),
        (Money { amount_minor: 21956, currency: "USD".to_owned(), exponent: 2 }, "$219.56"),
    ];
    for (money, expected) in tests {
        assert_eq!(money.to_string(), expected);
    }
}

#[test]
fn money_never_panics_on_the_ac24_edges() {
    // Plan AC24: every exponent in {0, 2, 3, 6}, and negatives, must render.
    // `i64::MIN` is the one that would trip a naive `-amount`, because its
    // magnitude does not fit back into an `i64`.
    for exponent in [0u8, 2, 3, 6, 7, u8::MAX] {
        for amount in [0i64, 1, -1, i64::MAX, i64::MIN] {
            let money = Money { amount_minor: amount, currency: "USD".to_owned(), exponent };
            let rendered = money.to_string();
            assert!(!rendered.is_empty(), "exponent {exponent}, amount {amount}");
            assert_eq!(rendered.starts_with('-'), amount < 0, "sign for {amount}");
        }
    }
}

#[test]
fn ac24_money_renders_each_exponent_the_endpoint_can_send() {
    // Plan AC24: 0, 2, 3 and 6 decimal places, and a negative at each.
    let tests: [(i64, u8, &str); 8] = [
        (1234, 0, "$1234"),
        (-1234, 0, "-$1234"),
        (1234, 2, "$12.34"),
        (-1234, 2, "-$12.34"),
        (1234, 3, "$1.234"),
        (-1234, 3, "-$1.234"),
        (1234, MAX_MONEY_EXPONENT, "$0.001234"),
        (-1234, MAX_MONEY_EXPONENT, "-$0.001234"),
    ];
    for (amount_minor, exponent, expected) in tests {
        let money = Money { amount_minor, currency: "USD".to_owned(), exponent };
        assert_eq!(money.to_string(), expected, "{amount_minor} at 10^-{exponent}");
    }
}

#[test]
fn money_pads_the_fraction_to_the_exponent() {
    let money = Money { amount_minor: 5, currency: "USD".to_owned(), exponent: 3 };
    assert_eq!(money.to_string(), "$0.005");
    let negative = Money { amount_minor: -5, currency: "USD".to_owned(), exponent: 2 };
    assert_eq!(negative.to_string(), "-$0.05");
}

#[test]
fn render_countdown_picks_the_coarsest_useful_unit() {
    let now = ts("2026-09-08T00:00:00Z");
    let tests = [
        ("2026-09-11T04:30:00Z", "3d4h"),
        ("2026-09-08T02:13:40Z", "2h13m"),
        ("2026-09-08T00:45:00Z", "45m"),
        ("2026-09-08T00:00:30Z", "30s"),
        ("2026-09-08T00:00:00Z", "now"),
        ("2026-09-07T00:00:00Z", "now"),
    ];
    for (target, expected) in tests {
        assert_eq!(render_countdown(now, ts(target)), expected, "target {target}");
    }
}

#[test]
fn render_countdown_survives_the_extremes() {
    // Overflow checks are off in every profile (constraint C-006), so this is
    // proving the explicit `checked_sub`, not the compiler.
    let min = Timestamp::MIN;
    let max = Timestamp::MAX;
    assert_eq!(render_countdown(max, min), "now");
    assert!(!render_countdown(min, max).is_empty());
}

#[test]
fn snapshot_selects_windows_by_kind_and_scope() {
    let snapshot = UsageSnapshot {
        fetched_at: ts("2026-09-08T00:00:00Z"),
        windows: vec![
            window(WindowKind::Session, 21.0, Some("2026-09-08T03:30:00Z")),
            window(WindowKind::WeeklyAll, 35.0, Some("2026-09-10T20:00:00Z")),
            window(
                WindowKind::WeeklyScoped("Fable".to_owned()),
                56.0,
                Some("2026-09-10T20:00:00Z"),
            ),
            window(WindowKind::WeeklyScoped("opus".to_owned()), 12.0, None),
            window(WindowKind::Unknown("monthly_foo".to_owned()), 7.0, None),
        ],
        credits: CreditsState::Unavailable,
        raw: None,
    };

    assert_eq!(snapshot.window(&WindowKind::Session).and_then(|w| w.percent_floor), Some(21));
    assert_eq!(snapshot.scoped_window("fable").and_then(|w| w.percent_floor), Some(56));
    assert_eq!(snapshot.scoped_window("haiku"), None);

    let extras: Vec<String> = snapshot.extra_windows("Fable").iter().map(|w| w.label()).collect();
    assert_eq!(extras, vec!["opus (weekly)", "monthly_foo (unknown kind)"]);

    assert_eq!(snapshot.next_reset(), Some(ts("2026-09-08T03:30:00Z")));
}

#[test]
fn next_reset_is_none_when_no_window_resets() {
    let snapshot = UsageSnapshot {
        fetched_at: ts("2026-09-08T00:00:00Z"),
        windows: vec![window(WindowKind::Session, 0.0, None)],
        credits: CreditsState::Unavailable,
        raw: None,
    };
    assert_eq!(snapshot.next_reset(), None);
}

#[test]
fn window_labels_name_unknown_kinds_verbatim() {
    // Risk R3: the kind string is the only evidence the user has that the
    // server grew a window this build has never seen.
    let unknown = window(WindowKind::Unknown("monthly_foo".to_owned()), 7.0, None);
    assert_eq!(unknown.label(), "monthly_foo (unknown kind)");
    assert_eq!(window(WindowKind::Session, 0.0, None).label(), "session");
    assert_eq!(window(WindowKind::WeeklyAll, 0.0, None).label(), "weekly");
}
