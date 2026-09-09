//! Tests for the `status --json` document (plan AC9, AC23).
//!
//! The schema is the contract, so nearly every test here ends by validating an
//! emitted document against `schemas/status.v1.json` with the `jsonschema`
//! crate. That is deliberate belt and braces: the schema is `additionalProperties:
//! false` and lists every member as required, so a field this module renames,
//! drops or retypes fails here rather than in a user's script.

use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

use serde_json::json;
use tempfile::TempDir;

use super::*;
use crate::config::AccountKind;
use crate::config::AgentctlConfig;
use crate::config::paths::Paths;
use crate::provider::claude::account::AccountRow;
use crate::provider::claude::account::AccountState;
use crate::provider::claude::account::Source;
use crate::provider::claude::discovery;
use crate::provider::claude::namespace::EnvView;
use crate::runtime::coordinator::Cancel;
use crate::runtime::coordinator::PassCtx;
use crate::secret::SWITCHER_SERVICE_PREFIX;
use crate::secret::fake_reader::FakeReader;
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
        session_reset: session_reset_of(usage),
        weekly_reset: weekly_reset_of(usage),
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

/// Every [`AccountState`] this build can put in a row.
fn all_states() -> [AccountState; 22] {
    [
        AccountState::Ok,
        AccountState::Expired { read_only: true },
        AccountState::NeedsLogin,
        AccountState::IdentityUnknown,
        AccountState::StaleSiblingOfLive,
        AccountState::Unclaimed,
        AccountState::Foreign { source: "claude-switcher".to_owned() },
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
    ]
}

/// The `enum` the published schema lists for one member of `row`.
///
/// Read out of the schema file rather than restated here, so a test asserting
/// membership is asserting against the document a consumer actually validates
/// with — which is the whole point of these tests.
fn schema_enum(member: &str) -> Vec<String> {
    let schema: Value = serde_json::from_str(SCHEMA).expect("the published schema is valid JSON");
    let listed = schema["$defs"]["row"]["properties"][member]["enum"]
        .as_array()
        .unwrap_or_else(|| panic!("the schema constrains `{member}` with an enum"))
        .clone();
    listed
        .iter()
        .map(|value| value.as_str().expect("every enum member is a string").to_owned())
        .collect()
}

/// The document member for one discovered row, as `status --json` builds it.
///
/// The usage members are the ones a row that fetched nothing carries, which is
/// what every foreign row is: agentctl never reads such a credential, so there
/// is nothing to fetch usage with.
fn json_row_of(row: &AccountRow) -> JsonRow {
    JsonRow {
        id: row.id.clone(),
        account_uuid: row.record.account_uuid.clone(),
        organization_uuid: row.record.organization_uuid.clone(),
        email: row.record.email.clone(),
        org_name: row.record.org_name.clone(),
        kind: row.record.kind.name(),
        source: row.source.name(),
        state: row.state.name(),
        state_label: row.state.label(),
        lock_state: "none",
        windows: Vec::new(),
        credits: JsonCredits::unavailable(),
        next_reset: None,
        session_reset: None,
        weekly_reset: None,
        note: row.note.clone(),
    }
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
fn the_two_reset_members_name_their_own_window_and_are_nullable() {
    // The table's two reset columns need one named window each; these are
    // those two windows' resets, additive beside `next_reset` so that a
    // consumer already reading it sees no change.
    let usage = snapshot(
        vec![
            window(WindowKind::Session, 21.0, false),
            window(WindowKind::WeeklyAll, 35.0, false),
            window(WindowKind::WeeklyScoped("Fable".to_owned()), 56.0, true),
        ],
        CreditsState::Unavailable,
    );
    let both = row(&AccountState::Ok, Some(&usage));
    assert_eq!(both.session_reset.as_deref(), Some("2026-09-10T00:00:00Z"));
    assert_eq!(both.weekly_reset.as_deref(), Some("2026-09-10T00:00:00Z"));
    assert_eq!(
        both.next_reset.as_deref(),
        Some("2026-09-10T00:00:00Z"),
        "the soonest-across-every-window member is unchanged by the addition"
    );
    assert_valid(&report(vec![both]));

    // `weekly_reset` is the all-models window alone. A per-model weekly one
    // has a column of its own in the table and stays in `windows` here.
    let scoped = snapshot(
        vec![window(WindowKind::WeeklyScoped("Fable".to_owned()), 56.0, true)],
        CreditsState::Unavailable,
    );
    let scoped = row(&AccountState::Ok, Some(&scoped));
    assert_eq!(scoped.session_reset, None);
    assert_eq!(scoped.weekly_reset, None);
    assert_valid(&report(vec![scoped]));

    // A window carrying no `resets_at` is as null as no window at all: the
    // member answers "when does it roll over", and there is no answer.
    let mut unresetting = window(WindowKind::Session, 21.0, false);
    unresetting.resets_at = None;
    let unresetting = snapshot(vec![unresetting], CreditsState::Unavailable);
    let unresetting = row(&AccountState::Ok, Some(&unresetting));
    assert_eq!(unresetting.session_reset, None);
    assert_valid(&report(vec![unresetting]));

    // A row that fetched nothing carries both members as null rather than
    // dropping them, for the same reason `credits` is on every row.
    let nothing = row(&AccountState::NeedsLogin, None);
    let document = report(vec![nothing]);
    assert_valid(&document);
    let value = serde_json::to_value(&document).expect("a report serializes");
    let object = value["rows"][0].as_object().expect("a row is an object");
    for member in ["session_reset", "weekly_reset"] {
        assert!(object.contains_key(member), "`{member}` is null, not absent: {value}");
        assert!(object[member].is_null(), "`{member}` should be null here: {value}");
    }
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
    let states = all_states();

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

#[test]
fn every_kind_and_source_token_is_in_the_schema() {
    // Decision D-010 renamed `AccountKind::Metadata` to `Foreign`, and
    // `schemas/status.v1.json` went on publishing `metadata` for a whole wave
    // because nothing compared the two. This is that comparison: the tokens
    // come from the enums, the lists come from the schema file, and a variant
    // renamed on either side fails here.
    let kinds = [
        AccountKind::Owned {
            export_spelling: "/store/claude/acct-1/org-1".to_owned(),
            export_sha8: "0123abcd".to_owned(),
        },
        AccountKind::Live,
        AccountKind::ConfigDirReadOnly {
            dir: PathBuf::from("/elsewhere/.claude"),
            service: "Claude Code-credentials-6cdd6b98".to_owned(),
            shares_live_dir: false,
        },
        AccountKind::Foreign { source: "claude-switcher".to_owned() },
    ];
    // Exhaustive on purpose: a variant added to `AccountKind` stops this
    // matching, which is the reminder that the array above and the schema
    // beside it both need it.
    for kind in &kinds {
        match kind {
            AccountKind::Owned { .. }
            | AccountKind::Live
            | AccountKind::ConfigDirReadOnly { .. }
            | AccountKind::Foreign { .. } => {}
        }
    }

    let published = schema_enum("kind");
    for kind in &kinds {
        let token = kind.name().to_owned();
        assert!(
            published.contains(&token),
            "`{token}` is not in the schema's `kind` enum: {published:?}"
        );
    }
    assert_eq!(
        published.len(),
        kinds.len(),
        "the schema lists a `kind` this build cannot produce: {published:?}"
    );

    let sources = [Source::Keychain, Source::File, Source::Env, Source::None];
    for source in sources {
        match source {
            Source::Keychain | Source::File | Source::Env | Source::None => {}
        }
    }
    let published = schema_enum("source");
    for source in sources {
        let token = source.name().to_owned();
        assert!(
            published.contains(&token),
            "`{token}` is not in the schema's `source` enum: {published:?}"
        );
    }
    assert_eq!(
        published.len(),
        sources.len(),
        "the schema lists a `source` this build cannot produce: {published:?}"
    );

    let published = schema_enum("state");
    for state in all_states() {
        let token = state.name().to_owned();
        assert!(
            published.contains(&token),
            "`{token}` is not in the schema's `state` enum: {published:?}"
        );
    }
    assert_eq!(
        published.len(),
        all_states().len(),
        "the schema lists a `state` this build cannot produce: {published:?}"
    );

    // And one row per kind validates, which is what the membership assertions
    // above are ultimately claiming.
    let rows: Vec<JsonRow> = kinds
        .iter()
        .map(|kind| {
            let mut row = row(&AccountState::Ok, None);
            row.kind = kind.name();
            row
        })
        .collect();
    assert_valid(&report(rows));
}

#[test]
fn the_foreign_rows_discovery_synthesizes_validate() {
    // The two rows that carry `kind: "foreign"`, taken from discovery itself
    // rather than hand-written here: the `CLAUDE_CODE_OAUTH_TOKEN` row (fact
    // F19) and a `claude-switcher:*` keychain item (fact F10). Neither is ever
    // recorded in the registry, so the schema is the only place their `kind`
    // is written down — which is exactly how it drifted.
    let dir = TempDir::new().expect("a temporary directory should be creatable");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).expect("the fake home should be creatable");
    let paths = Paths::with_config_dir(dir.path().join("config"));
    let env = EnvView { oauth_token_set: true, ..EnvView::with_home(home) };

    let switcher = format!("{SWITCHER_SERVICE_PREFIX}someone@example.com");
    let reader = FakeReader::unlocked().with_entry(&switcher);
    let cancel = Cancel::new();
    let ctx = PassCtx::standalone(cancel.clone(), Instant::now() + Duration::from_secs(30));

    let found = discovery::discover(&AgentctlConfig::default(), &paths, &reader, &env, &ctx);

    let foreign: Vec<&AccountRow> = found
        .rows
        .iter()
        .filter(|row| matches!(row.record.kind, AccountKind::Foreign { .. }))
        .collect();
    assert_eq!(foreign.len(), 2, "the env token and the switcher item: {found:?}");
    assert!(
        foreign.iter().any(|row| row.id == switcher),
        "the switcher item is a row: {foreign:?}"
    );
    assert!(
        foreign.iter().any(|row| row.state.name() == "env_token"),
        "the environment token is a row: {foreign:?}"
    );
    assert!(
        !foreign.iter().any(|row| row.id == switcher && row.visible_by_default),
        "the switcher item is shown only under --all"
    );
    assert!(
        !reader.reads().contains(&switcher),
        "a foreign item is listed, never read: {:?}",
        reader.reads()
    );

    // `--all`, so both rows are in the document and nothing is hidden.
    let rows: Vec<JsonRow> = found.rows.iter().map(json_row_of).collect();
    let document = report(rows);
    assert_valid(&document);

    let value = serde_json::to_value(&document).expect("a report serializes");
    let kinds: Vec<&str> = value["rows"]
        .as_array()
        .expect("rows is an array")
        .iter()
        .filter_map(|row| row["kind"].as_str())
        .collect();
    assert_eq!(kinds.iter().filter(|kind| **kind == "foreign").count(), 2, "{value}");
}

// ---------------------------------------------------------------------------
// `doctor`'s isolation section (plan AC58)
// ---------------------------------------------------------------------------

/// One fully populated isolation row.
fn isolation_row() -> IsolationRow {
    IsolationRow {
        id: "acct-1".to_owned(),
        path: "/tmp/claude-sessions/acct-1/org-1".to_owned(),
        exports: IsolationExports {
            securestorage_dir: "/tmp/claude/acct-1/org-1".to_owned(),
            config_dir: "/tmp/claude-sessions/acct-1/org-1".to_owned(),
            sha8_match: true,
        },
        links: vec![
            IsolationLink {
                name: "settings.json".to_owned(),
                tier: "tier1",
                state: "linked",
                target: Some("/home/user/.claude/settings.json".to_owned()),
            },
            IsolationLink {
                name: "mcp.json".to_owned(),
                tier: "mcp",
                state: "absent",
                target: None,
            },
        ],
        seeded_keys: vec!["theme".to_owned()],
        leaked_keys: Vec::new(),
        unexposed: vec!["cache".to_owned()],
        mcp: IsolationMcp { linked: false, target: None, credential_entries: None },
        drift: IsolationDrift {
            live_mtime_ms: Some(2_000),
            seed_mtime_ms: Some(1_000),
            changed_since_seed: true,
        },
        migrated: false,
        forget_command: "agentctl claude use --forget acct-1".to_owned(),
    }
}

#[test]
fn a_doctor_report_with_a_populated_row_validates() {
    let report = DoctorReport::new(
        vec![isolation_row()],
        IsolationPolicy { disable_sideload_flags: Some(true), backend_observable: false },
    );
    assert_valid_doctor(&report);
}

#[test]
fn a_doctor_report_with_no_sessions_validates() {
    let report = DoctorReport::new(
        Vec::new(),
        IsolationPolicy { disable_sideload_flags: None, backend_observable: false },
    );
    assert_valid_doctor(&report);
}

#[test]
fn a_doctor_report_with_a_leaked_key_and_a_readable_mcp_count_validates() {
    let mut row = isolation_row();
    row.leaked_keys = vec!["oauthAccount".to_owned()];
    row.mcp = IsolationMcp {
        linked: true,
        target: Some("/home/user/.claude.json".to_owned()),
        credential_entries: Some(3),
    };
    let report = DoctorReport::new(
        vec![row],
        IsolationPolicy { disable_sideload_flags: Some(false), backend_observable: false },
    );
    assert_valid_doctor(&report);
}

#[test]
fn a_doctor_report_with_a_migrated_namespace_and_a_seed_link_validates() {
    // Plan AC58's "migration state" clause, and the `seed` tier / `seeded`
    // state P1-1 added to the `link` vocabulary.
    let mut row = isolation_row();
    row.migrated = true;
    row.links.push(IsolationLink {
        name: ".claude.json".to_owned(),
        tier: "seed",
        state: "seeded",
        target: None,
    });
    let report = DoctorReport::new(
        vec![row],
        IsolationPolicy { disable_sideload_flags: None, backend_observable: false },
    );
    assert_valid_doctor(&report);
}
