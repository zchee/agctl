//! `status --json`, version 2: one document shape for two providers.
//!
//! Version 1 is Anthropic's vocabulary written down — `account_uuid`,
//! `organization_uuid`, `org_name`, a credits object in minor units. None of
//! those are questions a Codex row can answer, and none of them may change:
//! `schemas/status.v1.json` is a published interface and `agctl claude status
//! --json` keeps emitting it byte for byte (plan AC98).
//!
//! So version 2 is a second document rather than an extension of the first.
//! What it changes is exactly what the second provider forced:
//!
//! - every row says which **provider** it came from, and carries its
//!   **identity** as a neutral pair of ids plus the plan, rather than as two
//!   Anthropic-shaped UUID members;
//! - **credits** are a tagged union. Claude reports money in minor units;
//!   Codex reports a balance the wire sends as a *decimal string* (W0 fact
//!   F78) plus an `unlimited` flag. Reproducing that string rather than
//!   parsing it into a float is deliberate: a balance is money, and the
//!   binary float nearest to `12.34` is not `12.34`;
//! - a **window** may carry the three names Codex's `additional_rate_limits`
//!   entries have (`limit_name`, `metered_feature`, `normal_model_slug`), so
//!   a consumer can tell two continuation rows apart. A window's *meaning*
//!   comes from its kind, never from its position in the response (W0
//!   correction 2).
//!
//! # No CLI flag reaches this yet
//!
//! `agctl codex status --json` emits it from S33. What S29b ships is the
//! shape, the schema and the proof that the phase-1 rows fit through it
//! (plan AC118): a report format whose first consumer arrives with its first
//! producer is a format nobody has checked.
//!
//! # No token material, ever
//!
//! Invariant I24, exactly as in [`super::json`]: this module is built from a
//! row's identity, its state and its usage figures, and can no more reach a
//! credential than the v1 renderer can.

#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the v2 document has no CLI producer until `agctl codex status --json` (S33); \
                  S29b ships the shape, the schema and AC118's proof that phase-1 rows fit it"
    )
)]

use jiff::Timestamp;
use serde::Serialize;

use crate::commands::status::RowOutcome;
use crate::provider::Provider;
use crate::render::json::CREDITS_SCOPE;
use crate::render::json::JsonCredits;
use crate::render::json::credits_of;
use crate::render::json::next_reset_of;
use crate::render::json::session_reset_of;
use crate::render::json::weekly_reset_of;
use crate::usage::model::LimitWindow;
use crate::usage::model::UsageSnapshot;
use crate::usage::model::WindowKind;

/// The report version this module emits, and the schema it validates against.
pub const REPORT_VERSION_V2: u32 = 2;

/// The `provider` token for one provider.
///
/// The same spelling the store's directories and the cache use, so a reader
/// who sees `codex` in a document knows which directory it came from.
pub fn provider_token(provider: Provider) -> &'static str {
    match provider {
        Provider::Claude => "claude",
        Provider::Codex => "codex",
    }
}

/// One whole version-2 document.
#[derive(Debug, Clone, Serialize)]
pub struct StatusReportV2 {
    /// Always [`REPORT_VERSION_V2`] for this build.
    pub version: u32,
    /// When the report was built, RFC 3339 in UTC.
    pub generated_at: String,
    /// The rows the run displayed, in display order.
    pub rows: Vec<JsonRowV2>,
    /// How many rows `--all` would have added.
    pub hidden: usize,
}

impl StatusReportV2 {
    /// An empty report stamped with `now`.
    pub fn new(now: Timestamp, hidden: usize) -> Self {
        Self { version: REPORT_VERSION_V2, generated_at: now.to_string(), rows: Vec::new(), hidden }
    }

    /// The report `rows` produce, in the order they are given in.
    pub fn from_rows<R: IntoJsonRowV2>(rows: &[R], now: Timestamp, hidden: usize) -> Self {
        Self {
            rows: rows.iter().map(IntoJsonRowV2::to_json_row_v2).collect(),
            ..Self::new(now, hidden)
        }
    }
}

/// A row that can be published in a version-2 document.
///
/// The companion of [`TuiRow`](crate::render::row::TuiRow): one says what a
/// row looks like on a screen, this one says what it looks like to a program.
/// A [`RowSource`](crate::render::row::RowSource) requires both, so a
/// provider cannot ship a row that only one of the two presentations can
/// render.
pub trait IntoJsonRowV2 {
    /// This row as a version-2 row.
    fn to_json_row_v2(&self) -> JsonRowV2;
}

/// One account.
#[derive(Debug, Clone, Serialize)]
pub struct JsonRowV2 {
    /// Which vendor this row's usage came from, from [`provider_token`].
    pub provider: &'static str,
    /// The identifier `--account` accepts for this row.
    pub id: String,
    /// Who the row is, in provider-neutral terms.
    pub identity: JsonIdentityV2,
    /// Where the credentials live and whether agctl may write them.
    pub kind: &'static str,
    /// Where this row's credentials were read from, when the provider
    /// distinguishes that from the kind.
    pub source: Option<&'static str>,
    /// The row state as a stable token.
    pub state: &'static str,
    /// The same state as the sentence the table prints.
    pub state_label: String,
    /// What the namespace lock did on this pass.
    pub lock_state: &'static str,
    /// The short explanation the table appends to the state.
    pub note: Option<String>,
    /// Every usage window the response described.
    pub windows: Vec<JsonWindowV2>,
    /// What is known about credits.
    pub credits: JsonCreditsV2,
    /// The soonest reset across every window, RFC 3339.
    pub next_reset: Option<String>,
    /// When the five-hour session window rolls over, RFC 3339.
    pub session_reset: Option<String>,
    /// When the seven-day all-models window rolls over, RFC 3339.
    pub weekly_reset: Option<String>,
}

/// Who a row is.
///
/// Two ids and two labels, because that is what both providers have:
/// Anthropic's `(account_uuid, organization_uuid)` and ChatGPT's
/// `(chatgpt_user_id, chatgpt_account_id)` are the same question asked twice —
/// which person, and which workspace of theirs. A consumer that needs the
/// vendor's own spelling for a Claude row still has version 1.
#[derive(Debug, Clone, Serialize)]
pub struct JsonIdentityV2 {
    /// Which person: the Anthropic account UUID, or the ChatGPT user id.
    pub user_id: String,
    /// Which workspace: the Anthropic organization UUID, or the ChatGPT
    /// account id.
    pub account_id: String,
    /// The subscription tier, as the credential or the response spelled it.
    pub plan_type: Option<String>,
    /// The account's email address, when it is known.
    pub email: Option<String>,
    /// The organization's display name, when the provider has one.
    pub org_name: Option<String>,
}

/// One usage window.
#[derive(Debug, Clone, Serialize)]
pub struct JsonWindowV2 {
    /// `session`, `weekly_all`, `weekly_scoped` or `unknown`.
    pub kind: &'static str,
    /// The window's display label.
    pub label: String,
    /// The percentage the server sent, clamped to `0..=100`.
    pub percent: Option<f64>,
    /// The same figure floored, which is what the table shows.
    pub percent_floor: Option<u8>,
    /// When the window rolls over, RFC 3339.
    pub resets_at: Option<String>,
    /// Whether this is the window currently constraining the account.
    pub is_active: bool,
    /// The vendor's own name for the limit, when it sent one.
    pub limit_name: Option<String>,
    /// Which metered feature the window covers, when the vendor said.
    pub metered_feature: Option<String>,
    /// The model slug the window's ordinary requests are billed as.
    pub normal_model_slug: Option<String>,
}

impl From<&LimitWindow> for JsonWindowV2 {
    fn from(window: &LimitWindow) -> Self {
        Self {
            kind: window_kind_v2(&window.kind),
            label: window.label(),
            percent: window.percent,
            percent_floor: window.percent_floor,
            resets_at: window.resets_at.map(|resets_at| resets_at.to_string()),
            is_active: window.is_active,
            // Claude's windows carry none of the three; the Codex normaliser
            // (S31) fills them in from `additional_rate_limits`.
            limit_name: None,
            metered_feature: None,
            normal_model_slug: None,
        }
    }
}

/// The `kind` token for one window.
fn window_kind_v2(kind: &WindowKind) -> &'static str {
    match kind {
        WindowKind::Session => "session",
        WindowKind::WeeklyAll => "weekly_all",
        WindowKind::WeeklyScoped(_) => "weekly_scoped",
        WindowKind::Unknown(_) => "unknown",
    }
}

/// What is known about an account's paid-usage balance.
///
/// Tagged by `kind`, with every member present whatever the tag, for the
/// reason version 1's credits object is flat: a consumer testing a member
/// gets an answer rather than having to tell an absent member from a null
/// one.
#[derive(Debug, Clone, Serialize)]
pub struct JsonCreditsV2 {
    /// `money` (Claude's minor units), `balance` (Codex's decimal string),
    /// `off` or `unavailable`.
    pub kind: &'static str,
    /// The amount spent, in minor units of `currency`.
    pub used_minor: Option<i64>,
    /// The ISO 4217 code the minor units are in.
    pub currency: Option<String>,
    /// How many decimal places a minor unit represents.
    pub exponent: Option<u8>,
    /// The monthly ceiling in minor units, absent for an uncapped account.
    pub limit_minor: Option<i64>,
    /// The server's own utilisation percentage, rounded.
    pub percent: Option<u8>,
    /// The balance exactly as the wire spelled it, digits and all.
    ///
    /// A string, not a number: the response sends one (W0 fact F78), and a
    /// decimal amount of money that has been through an `f64` is no longer
    /// the amount that was sent.
    pub balance: Option<String>,
    /// Whether the plan's balance is uncapped.
    pub unlimited: Option<bool>,
    /// Why credits are switched off, when the server said.
    pub disabled_reason: Option<String>,
    /// Whose figures these are: an organization's, or an account's.
    pub scope: &'static str,
}

impl JsonCreditsV2 {
    /// The object a row with nothing to say about credits carries.
    pub fn unavailable() -> Self {
        Self {
            kind: "unavailable",
            used_minor: None,
            currency: None,
            exponent: None,
            limit_minor: None,
            percent: None,
            balance: None,
            unlimited: None,
            disabled_reason: None,
            scope: CREDITS_SCOPE,
        }
    }
}

impl From<JsonCredits> for JsonCreditsV2 {
    /// Claude's credits, as version 2 states them.
    ///
    /// Built from the version-1 object rather than from
    /// [`CreditsState`](crate::usage::model::CreditsState) directly, so the
    /// two documents cannot disagree about one account: whatever v1 says a
    /// Claude row's credits are, v2 says the same in its own vocabulary.
    fn from(credits: JsonCredits) -> Self {
        Self {
            kind: match credits.state {
                "on" => "money",
                other => other,
            },
            used_minor: credits.used_minor,
            currency: credits.currency,
            exponent: credits.exponent,
            limit_minor: credits.limit_minor,
            percent: credits.percent,
            disabled_reason: credits.disabled_reason,
            scope: credits.scope,
            // `balance` and `unlimited` are the Codex members. Filled from
            // the base case rather than written out, so a member added there
            // cannot be forgotten on this path.
            ..Self::unavailable()
        }
    }
}

impl IntoJsonRowV2 for RowOutcome {
    fn to_json_row_v2(&self) -> JsonRowV2 {
        let usage = self.usage.as_ref();
        JsonRowV2 {
            provider: provider_token(Provider::Claude),
            id: self.id.clone(),
            identity: JsonIdentityV2 {
                user_id: self.record.account_uuid.clone(),
                account_id: self.record.organization_uuid.clone(),
                plan_type: (!self.plan.is_empty()).then(|| self.plan.clone()),
                email: self.record.email.clone(),
                org_name: self.record.org_name.clone(),
            },
            kind: self.record.kind.name(),
            source: Some(self.source.name()),
            state: self.state.name(),
            state_label: self.state.label(),
            lock_state: self.lock_state,
            note: self.note.clone(),
            windows: windows_v2(usage),
            credits: JsonCreditsV2::from(credits_of(usage)),
            next_reset: next_reset_of(usage),
            session_reset: session_reset_of(usage),
            weekly_reset: weekly_reset_of(usage),
        }
    }
}

/// The `windows` member for a row that may not have fetched anything.
fn windows_v2(usage: Option<&UsageSnapshot>) -> Vec<JsonWindowV2> {
    usage.map(|usage| usage.windows.iter().map(JsonWindowV2::from).collect()).unwrap_or_default()
}

/// The published schema, compiled into the test binary.
#[cfg(test)]
pub const SCHEMA_V2: &str = include_str!("../../schemas/status.v2.json");

/// Validates a report against [`SCHEMA_V2`], naming every failure.
///
/// # Panics
///
/// Panics when the document does not validate, which is the assertion.
#[cfg(test)]
pub fn assert_valid_v2(report: &StatusReportV2) {
    let schema: serde_json::Value =
        serde_json::from_str(SCHEMA_V2).expect("the published schema is valid JSON");
    let validator = jsonschema::validator_for(&schema).expect("the published schema compiles");
    let instance = serde_json::to_value(report).expect("a report serializes");

    let errors: Vec<String> = validator
        .iter_errors(&instance)
        .map(|err| format!("{}: {err}", err.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "the emitted document does not match schemas/status.v2.json:\n{}\n\ndocument:\n{}",
        errors.join("\n"),
        serde_json::to_string_pretty(&instance).unwrap_or_default()
    );
}

#[cfg(test)]
#[path = "json_v2_tests.rs"]
mod tests;
