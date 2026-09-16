//! Tests for the version-2 document (plan AC118, and AC102's shape half).

use serde_json::Value;

use super::*;
use crate::provider::claude::account::AccountState;
use crate::render::row::RowSource;
use crate::runtime::coordinator::Cancel;
use crate::runtime::coordinator::PassCtx;
use crate::tui::fixtures;

/// A [`RowSource`] over rows a pass already produced.
///
/// The Claude pass builds its rows inside `collect`, which needs a store, a
/// keychain and a clock; what AC118 is about is the seam, so this source
/// hands back rows the fixtures built. When the Codex pass implements
/// `RowSource` for real (S33) this stays as the proof that a source's rows
/// reach the document unchanged.
struct FixtureRows;

impl RowSource for FixtureRows {
    type Row = RowOutcome;

    fn rows(&self, _ctx: &PassCtx) -> Option<Vec<Self::Row>> {
        Some(vec![
            fixtures::row_with_usage(0, "owner@example.com"),
            fixtures::row_with_credits(1, "second@example.com"),
            fixtures::row(2, "third@example.com", AccountState::NeedsLogin),
        ])
    }
}

/// A pass context with a deadline far enough out to be irrelevant.
fn ctx() -> PassCtx {
    PassCtx::standalone(
        Cancel::new(),
        std::time::Instant::now() + std::time::Duration::from_secs(60),
    )
}

#[test]
fn the_phase_one_rows_render_into_a_valid_version_two_document() {
    // Plan AC118. The rows are the phase-1 fixtures, unchanged; what is under
    // test is that the second document shape can carry them at all, before
    // any Codex row exists to be carried beside them.
    let rows = FixtureRows.rows(&ctx()).expect("the source produced rows");
    let report = StatusReportV2::from_rows(&rows, fixtures::at(fixtures::NOW), 1);

    assert_valid_v2(&report);
    assert_eq!(report.version, 2);
    assert_eq!(report.rows.len(), 3);
    assert_eq!(report.hidden, 1);
}

#[test]
fn every_claude_row_names_its_provider_and_its_identity() {
    let mut rows = vec![fixtures::row_with_usage(0, "owner@example.com")];
    rows[0].record.email = Some("owner@example.com".to_owned());
    rows[0].record.org_name = Some("Acme".to_owned());

    let report = StatusReportV2::from_rows(&rows, fixtures::at(fixtures::NOW), 0);
    let row = report.rows.first().expect("one row");

    assert_eq!(row.provider, "claude");
    // The identity comes from the registry record, exactly as version 1's
    // `account_uuid`/`organization_uuid`/`email` members do: one row, one
    // answer, whichever document is asked.
    assert_eq!(row.identity.user_id, rows[0].record.account_uuid);
    assert_eq!(row.identity.account_id, rows[0].record.organization_uuid);
    assert_eq!(row.identity.email, rows[0].record.email);
    assert_eq!(row.identity.org_name, rows[0].record.org_name);
    assert_eq!(row.identity.plan_type.as_deref(), Some("max"));
}

#[test]
fn a_row_with_no_plan_reports_no_plan_rather_than_an_empty_string() {
    // The table renders an unknown plan as an em dash; a document that said
    // `""` would be claiming the vendor sent an empty tier.
    let mut rows = vec![fixtures::row(0, "owner@example.com", AccountState::NeedsLogin)];
    rows[0].plan = String::new();

    let report = StatusReportV2::from_rows(&rows, fixtures::at(fixtures::NOW), 0);
    assert_eq!(report.rows[0].identity.plan_type, None);
}

#[test]
fn a_claude_row_s_credits_say_money_and_carry_no_balance_string() {
    // The tag is what tells a consumer which members mean anything. Claude
    // reports minor units and a currency; the decimal string is Codex's, and
    // a Claude row that carried one would be inventing a figure.
    let with_credits = vec![fixtures::row_with_credits(1, "second@example.com")];
    let report = StatusReportV2::from_rows(&with_credits, fixtures::at(fixtures::NOW), 0);
    let credits = &report.rows[0].credits;

    assert_eq!(credits.kind, "money");
    assert!(credits.used_minor.is_some());
    assert!(credits.currency.is_some());
    assert!(credits.balance.is_none(), "a balance string is the Codex shape");
    assert!(credits.unlimited.is_none());

    let without = vec![fixtures::row(0, "owner@example.com", AccountState::NeedsLogin)];
    let report = StatusReportV2::from_rows(&without, fixtures::at(fixtures::NOW), 0);
    assert_eq!(report.rows[0].credits.kind, "unavailable");
}

#[test]
fn the_two_documents_agree_about_one_account_s_credits() {
    // v2's credits are built from v1's object rather than from the model, so
    // the two renderings of one row cannot drift into disagreeing about how
    // much has been spent.
    let row = fixtures::row_with_credits(1, "second@example.com");
    let v1 = credits_of(row.usage.as_ref());
    let v2 = JsonCreditsV2::from(v1.clone());

    assert_eq!(v2.used_minor, v1.used_minor);
    assert_eq!(v2.limit_minor, v1.limit_minor);
    assert_eq!(v2.percent, v1.percent);
    assert_eq!(v2.currency, v1.currency);
    assert_eq!(v2.scope, v1.scope);
}

#[test]
fn a_window_carries_the_three_vendor_names_as_members_even_when_empty() {
    // §3.5: Codex's `additional_rate_limits` entries are told apart by name,
    // not by where they sat in the response. The members exist on every
    // window so a consumer can read them without knowing which provider it
    // is looking at.
    let rows = vec![fixtures::row_with_usage(0, "owner@example.com")];
    let report = StatusReportV2::from_rows(&rows, fixtures::at(fixtures::NOW), 0);
    let document = serde_json::to_value(&report).expect("a report serializes");
    let window = &document["rows"][0]["windows"][0];

    for member in ["limit_name", "metered_feature", "normal_model_slug"] {
        assert_eq!(window[member], Value::Null, "{member} is null for a Claude window");
        assert!(window.get(member).is_some(), "{member} is present all the same");
    }
}

#[test]
fn the_v1_schema_and_the_v2_schema_are_different_documents() {
    // AC98's other half, stated here rather than only in a gate: adding v2
    // must not have edited v1.
    let v1: Value = serde_json::from_str(crate::render::json::SCHEMA).expect("v1 is valid JSON");
    let v2: Value = serde_json::from_str(SCHEMA_V2).expect("v2 is valid JSON");

    assert_eq!(v1["properties"]["version"]["const"], serde_json::json!(1));
    assert_eq!(v2["properties"]["version"]["const"], serde_json::json!(2));
    assert_ne!(v1["$id"], v2["$id"]);
}
