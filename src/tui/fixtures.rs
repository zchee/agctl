//! Row builders the TUI's tests share.
//!
//! Not a `*_tests.rs` file because it holds no tests: the reducer's tests, the
//! frame snapshot and the watch loop's tests all need
//! [`RowOutcome`](crate::commands::status::RowOutcome) values, and a `mod
//! tests` cannot be reached from a sibling module. Gated to `cfg(test)`, so
//! none of it exists in a shipped binary.
//!
//! Every timestamp here is a literal. A snapshot built against `Timestamp::now`
//! would differ on every run; these fixtures pin the clock so a frame is a
//! function of its inputs alone.

use jiff::Timestamp;
use serde_json::json;

use crate::commands::status::RowOutcome;
use crate::config::AccountKind;
use crate::config::new_record;
use crate::provider::claude::account::AccountState;
use crate::provider::claude::account::Source;
use crate::usage::model::Credits;
use crate::usage::model::CreditsState;
use crate::usage::model::LimitWindow;
use crate::usage::model::Money;
use crate::usage::model::UsageSnapshot;
use crate::usage::model::WindowKind;

/// The moment every fixture is dated from.
pub const NOW: &str = "2026-09-08T12:00:00Z";

/// Parses one of this module's literal timestamps.
pub fn at(literal: &str) -> Timestamp {
    literal.parse().expect("the fixture timestamps are valid RFC 3339")
}

/// A row with no numbers, in whatever state the caller names.
pub fn row(index: usize, account: &str, state: AccountState) -> RowOutcome {
    let record = new_record(
        format!("{index:08}-2222-3333-4444-555555555555"),
        "66666666-7777-8888-9999-000000000000".to_owned(),
        AccountKind::Owned {
            export_spelling: format!("/store/claude/{index}"),
            export_sha8: "deadbeef".to_owned(),
        },
    )
    .expect("the fixture identifiers are valid path segments");

    RowOutcome {
        index,
        id: account.to_owned(),
        record,
        source: Source::File,
        account: account.to_owned(),
        org: "Acme".to_owned(),
        plan: "max".to_owned(),
        state,
        lock_state: "none",
        note: None,
        usage: None,
        visible_by_default: true,
    }
}

/// A healthy row carrying the three headline windows.
pub fn row_with_usage(index: usize, account: &str) -> RowOutcome {
    let mut row = row(index, account, AccountState::Ok);
    row.usage = Some(usage(21.6, 35.2, 56.9, CreditsState::Unavailable));
    row
}

/// A healthy row that also has credits switched on.
pub fn row_with_credits(index: usize, account: &str) -> RowOutcome {
    let mut row = row(index, account, AccountState::Ok);
    row.usage = Some(usage(
        4.0,
        11.0,
        7.0,
        CreditsState::On(Credits {
            used: Some(Money { amount_minor: 1234, currency: "USD".to_owned(), exponent: 2 }),
            limit: Some(Money { amount_minor: 50_000, currency: "USD".to_owned(), exponent: 2 }),
            percent: Some(25),
        }),
    ));
    row
}

/// A snapshot with the session, weekly and headline-scoped windows filled in.
pub fn usage(session: f64, weekly: f64, scoped: f64, credits: CreditsState) -> UsageSnapshot {
    UsageSnapshot {
        fetched_at: at(NOW),
        windows: vec![
            window(WindowKind::Session, session, "2026-09-08T14:13:00Z"),
            window(WindowKind::WeeklyAll, weekly, "2026-09-11T16:00:00Z"),
            window(WindowKind::WeeklyScoped("Fable".to_owned()), scoped, "2026-09-11T16:00:00Z"),
        ],
        credits,
        raw: Some(json!({ "note": "fixture" })),
    }
}

/// One window, with its percentage floored the way the parser floors it.
pub fn window(kind: WindowKind, percent: f64, resets_at: &str) -> LimitWindow {
    LimitWindow {
        kind,
        percent: Some(percent),
        percent_floor: crate::usage::model::percent_floor(percent),
        severity: None,
        resets_at: Some(at(resets_at)),
        scope_label: None,
        is_active: false,
    }
}
