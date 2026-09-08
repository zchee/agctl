//! Tests for the `status --json` document (plan AC9, AC23).
//!
//! The schema is the contract, so nearly every test here ends by validating an
//! emitted document against `schemas/status.v1.json` with the `jsonschema`
//! crate. That is deliberate belt and braces: the schema is `additionalProperties:
//! false` and lists every member as required, so a field this module renames,
//! drops or retypes fails here rather than in a user's script.

use serde_json::json;

use super::*;
use crate::provider::claude::account::AccountState;
use crate::provider::claude::account::Source;
use crate::usage::model::percent_floor;

/// A window with a percentage and a reset.
fn window(kind: WindowKind, percent: f64, is_active: bool) -> LimitWindow {
    LimitWindow {
        kind,
        percent: Some(percent),
        percent_floor: percent_floor(percent),
        severity: None,
        resets_at: Some("2026-09-10T00:00:00Z".parse().expect("a valid timestamp")),
        scope_label: None,
        is_active,
    }
}

/// A snapshot carrying `windows` and `credits`.
fn snapshot(windows: Vec<LimitWindow>, credits: CreditsState) -> UsageSnapshot {
    UsageSnapshot {
        fetched_at: "2026-09-09T12:00:00Z".parse().expect("a valid timestamp"),
        windows,
        credits,
        raw: None,
    }
}

/// One row, with everything a real pass would have filled in.
fn row(state: &AccountState, usage: Option<&UsageSnapshot>) -> JsonRow {
    JsonRow {
        id: "acct-1".to_owned(),
        account_uuid: "acct-1".to_owned(),
        organization_uuid: "org-1".to_owned(),
        email: Some("owner@example.com".to_owned()),
        org_name: Some("Acme".to_owned()),
        kind: "owned",
        source: Source::File.name(),
        state: state.name(),
        state_label: state.label(),
        lock_state: "none",
        windows: windows_of(usage),
        credits: credits_of(usage),
        next_reset: next_reset_of(usage),
        note: None,
    }
}

/// A report holding exactly `rows`.
fn report(rows: Vec<JsonRow>) -> StatusReport {
    let mut report =
        StatusReport::new("2026-09-09T12:00:00Z".parse().expect("a valid timestamp"), 0);
    report.rows = rows;
    report
}

#[test]
fn an_empty_report_validates() {
    let report = report(Vec::new());
    assert_valid(&report);

    let value = serde_json::to_value(&report).expect("a report serializes");
    assert_eq!(value["version"], json!(1));
    assert_eq!(value["hidden"], json!(0));
    assert!(value.get("raw").is_none(), "`raw` is absent without --raw, not null");
}

#[test]
fn windows_carry_the_kind_the_label_and_both_percentages() {
    let usage = snapshot(
        vec![
            window(WindowKind::Session, 21.4, false),
            window(WindowKind::WeeklyAll, 35.0, false),
            window(WindowKind::WeeklyScoped("Fable".to_owned()), 56.9, true),
            window(WindowKind::Unknown("monthly_foo".to_owned()), 3.5, false),
        ],
        CreditsState::Unavailable,
    );
    let row = row(&AccountState::Ok, Some(&usage));

    let kinds: Vec<&str> = row.windows.iter().map(|window| window.kind).collect();
    assert_eq!(kinds, ["session", "weekly_all", "weekly_scoped", "unknown"]);

    let scoped = &row.windows[2];
    assert_eq!(scoped.label, "Fable (weekly)", "the scope survives in the label");
    assert_eq!(scoped.percent, Some(56.9));
    assert_eq!(scoped.percent_floor, Some(56), "floored, so agentctl never reads above the site");
    assert!(scoped.is_active);

    assert_eq!(
        row.windows[3].label, "monthly_foo (unknown kind)",
        "an unrecognised kind keeps the server's own string (risk R3)"
    );
    assert_eq!(row.next_reset.as_deref(), Some("2026-09-10T00:00:00Z"));
    assert_valid(&report(vec![row]));
}

#[test]
fn credits_on_flattens_the_money_into_minor_units() {
    // Plan AC23: the `on` shape, with both figures and the percentage.
    let credits = CreditsState::On(Credits {
        used: Some(Money { amount_minor: 1234, currency: "USD".to_owned(), exponent: 2 }),
        limit: Some(Money { amount_minor: 5000, currency: "USD".to_owned(), exponent: 2 }),
        percent: Some(25),
    });
    let usage = snapshot(Vec::new(), credits);
    let row = row(&AccountState::Ok, Some(&usage));

    assert_eq!(row.credits.state, "on");
    assert_eq!(row.credits.used_minor, Some(1234));
    assert_eq!(row.credits.limit_minor, Some(5000));
    assert_eq!(row.credits.currency.as_deref(), Some("USD"));
    assert_eq!(row.credits.exponent, Some(2));
    assert_eq!(row.credits.percent, Some(25));
    assert_eq!(row.credits.disabled_reason, None);
    assert_eq!(row.credits.scope, "organization", "credits belong to the org (fact F22)");
    assert_valid(&report(vec![row]));
}

#[test]
fn credits_denomination_falls_back_to_the_limit() {
    // An account with a ceiling and no spend yet: the currency is only on the
    // limit, and minor units with no currency would be unusable.
    let credits = CreditsState::On(Credits {
        used: None,
        limit: Some(Money { amount_minor: 5000, currency: "EUR".to_owned(), exponent: 2 }),
        percent: None,
    });
    let usage = snapshot(Vec::new(), credits);
    let row = row(&AccountState::Ok, Some(&usage));

    assert_eq!(row.credits.used_minor, None);
    assert_eq!(row.credits.currency.as_deref(), Some("EUR"));
    assert_eq!(row.credits.exponent, Some(2));
    assert_valid(&report(vec![row]));
}

#[test]
fn credits_off_is_not_credits_unavailable() {
    // The distinction plan section 3.8 insists on: telling a user with credits
    // enabled that they are disabled would be a false statement about billing.
    let off = snapshot(Vec::new(), CreditsState::Off { reason: Some("not_eligible".to_owned()) });
    let off = row(&AccountState::Ok, Some(&off));
    assert_eq!(off.credits.state, "off");
    assert_eq!(off.credits.disabled_reason.as_deref(), Some("not_eligible"));
    assert_eq!(off.credits.used_minor, None);

    let silent = snapshot(Vec::new(), CreditsState::Unavailable);
    let silent = row(&AccountState::Ok, Some(&silent));
    assert_eq!(silent.credits.state, "unavailable");
    assert_eq!(silent.credits.disabled_reason, None);

    assert_valid(&report(vec![off, silent]));
}

#[test]
fn a_row_that_fetched_nothing_still_carries_credits_and_windows() {
    // Plan AC23 says `credits` is on *every* row. A consumer must not have to
    // tell an absent member from a null one.
    let row = row(&AccountState::NeedsLogin, None);
    assert_eq!(row.credits.state, "unavailable");
    assert_eq!(row.credits.scope, "organization");
    assert!(row.windows.is_empty());
    assert_eq!(row.next_reset, None);
    assert_valid(&report(vec![row]));
}

#[test]
fn every_state_token_is_in_the_schema_and_differs_from_its_label() {
    // The enum in the schema is the published list; a variant added without
    // updating the schema fails here rather than in a consumer.
    let states = [
        AccountState::Ok,
        AccountState::Expired { read_only: true },
        AccountState::NeedsLogin,
        AccountState::IdentityUnknown,
        AccountState::StaleSiblingOfLive,
        AccountState::Unclaimed,
        AccountState::Forgotten,
        AccountState::MigratedToKeychain { service: "Claude Code-credentials-1234abcd".to_owned() },
        AccountState::ClaudeSessionDetected {
            lock: ".oauth_refresh.lock".to_owned(),
            age_ms: 12_000,
        },
        AccountState::KeychainLocked { detail: String::new() },
        AccountState::KeychainTimeout,
        AccountState::Busy,
        AccountState::LockUnavailable,
        AccountState::Stale,
        AccountState::NoSubscriptionLimits,
        AccountState::PendingReplayed,
        AccountState::PendingDiscarded { reason: "invalid".to_owned() },
        AccountState::RateLimited { retry_after_s: Some(30) },
        AccountState::RefreshDiscarded,
        AccountState::EnvToken,
        AccountState::Error("something went wrong".to_owned()),
    ];

    let mut tokens: Vec<&str> = states.iter().map(AccountState::name).collect();
    let count = tokens.len();
    tokens.sort_unstable();
    tokens.dedup();
    assert_eq!(tokens.len(), count, "each state has its own token: {tokens:?}");

    let rows: Vec<JsonRow> = states.iter().map(|state| row(state, None)).collect();
    for (state, row) in states.iter().zip(&rows) {
        assert_eq!(row.state, state.name());
        assert_eq!(row.state_label, state.label());
    }
    assert_valid(&report(rows));
}

#[test]
fn every_lock_state_the_pass_can_report_is_in_the_schema() {
    // The vocabulary `commands::status` writes into `lock_state`. Plan AC7's
    // JSON clause pins `busy`; the rest travel with it.
    for lock_state in ["none", "busy", "adopted", "claude_detected", "migrated", "unavailable"] {
        let mut row = row(&AccountState::Busy, None);
        row.lock_state = lock_state;
        assert_valid(&report(vec![row]));
    }
}

#[test]
fn an_unknown_lock_state_is_rejected_by_the_schema() {
    // Proves the validator is actually validating rather than accepting
    // anything, which is what the assertions above rest on.
    let mut row = row(&AccountState::Ok, None);
    row.lock_state = "improvised";
    let report = report(vec![row]);

    let schema: Value = serde_json::from_str(SCHEMA).expect("the published schema is valid JSON");
    let validator = jsonschema::validator_for(&schema).expect("the published schema compiles");
    let instance = serde_json::to_value(&report).expect("a report serializes");
    assert!(!validator.is_valid(&instance), "an unlisted lock_state must fail validation");
}

#[test]
fn raw_bodies_are_carried_verbatim_under_their_row_id() {
    // Plan AC23's second half: `--raw` carries the untouched body, including
    // the `spend` object this build never parses into a typed value.
    let body = json!({
        "five_hour": { "utilization": 21 },
        "extra_usage": { "is_enabled": false },
        "spend": { "percent": 25, "amount": "12.34" },
    });
    let mut report = report(vec![row(&AccountState::Ok, None)]);
    let mut raw = Map::new();
    raw.insert("acct-1".to_owned(), body.clone());
    report.raw = Some(raw);

    let value = serde_json::to_value(&report).expect("a report serializes");
    assert_eq!(value["raw"]["acct-1"], body, "the body is reproduced byte for byte");
    assert_eq!(value["raw"]["acct-1"]["spend"]["percent"], json!(25));
    assert_valid(&report);
}
