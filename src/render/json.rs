//! `status --json`: the machine-readable report, version 1.
//!
//! The document this module serializes is a published interface. Its shape is
//! fixed by plan section 3.2 and 3.8, and `schemas/status.v1.json` is the
//! normative statement of it — every document the tests emit is validated
//! against that file, so a field that changes name or type fails the suite
//! rather than a user's script.
//!
//! # Why the types are not the ones the pass uses
//!
//! [`UsageSnapshot`] and friends are shaped for a program that is deciding
//! things: an enum per state, a payload per variant, a `Money` that keeps
//! minor units and an exponent apart. A JSON consumer wants none of that
//! shape and all of that information, flattened and stably named. Serializing
//! the internal types directly would publish `serde`'s enum representation as
//! the interface and make every internal refactor a breaking change, so the
//! conversion is written out here instead.
//!
//! # No token material, ever
//!
//! Invariant I4. Nothing in this module can reach a token: it is built from
//! [`UsageSnapshot`] (usage figures and the untouched response body), the
//! account identifiers, and the row's state — never from
//! [`Credentials`](crate::provider::claude::credentials::Credentials). The
//! `raw` member carries usage bodies, which the API returns without any
//! credential in them (plan AC9 greps the emitted document for Anthropic's
//! token prefix to keep it that way — which is also why that prefix is not
//! written out anywhere in this file or in the schema beside it).

use jiff::Timestamp;
use serde::Serialize;
use serde_json::Map;
use serde_json::Value;

use crate::usage::model::Credits;
use crate::usage::model::CreditsState;
use crate::usage::model::LimitWindow;
use crate::usage::model::Money;
use crate::usage::model::UsageSnapshot;
use crate::usage::model::WindowKind;

/// The report version this build emits, and the schema it validates against.
pub const REPORT_VERSION: u32 = 1;

/// The scope every credit figure is reported at (fact F22).
///
/// Extra-usage credits belong to the organization, not to the account, so two
/// accounts in one organization report the same figure. A consumer that summed
/// the rows would double-count, which is what this constant exists to warn it
/// about.
pub const CREDITS_SCOPE: &str = "organization";

/// One whole `status --json` document.
#[derive(Debug, Clone, Serialize)]
pub struct StatusReport {
    /// The document version; always [`REPORT_VERSION`] for this build.
    pub version: u32,
    /// When the report was built, RFC 3339 in UTC.
    pub generated_at: String,
    /// The rows the run displayed, in the same order the table shows them.
    pub rows: Vec<JsonRow>,
    /// How many rows `--all` would have added. Zero when `--all` was given.
    pub hidden: usize,
    /// The untouched usage bodies, keyed by row id. Present only with `--raw`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<Map<String, Value>>,
}

impl StatusReport {
    /// An empty report stamped with `now`.
    pub fn new(now: Timestamp, hidden: usize) -> Self {
        Self {
            version: REPORT_VERSION,
            generated_at: now.to_string(),
            rows: Vec::new(),
            hidden,
            raw: None,
        }
    }
}

/// One account.
#[derive(Debug, Clone, Serialize)]
pub struct JsonRow {
    /// The identifier `--account` accepts for this row.
    pub id: String,
    /// The Anthropic account UUID, empty when the row has no identity.
    pub account_uuid: String,
    /// The organization UUID, or `_unknown-org`.
    pub organization_uuid: String,
    /// The account's email address, when it is known.
    pub email: Option<String>,
    /// The organization's display name, when it is known.
    pub org_name: Option<String>,
    /// Where the credentials live and whether agentctl may write them, from
    /// [`AccountKind::name`](crate::config::AccountKind::name).
    pub kind: &'static str,
    /// Where this row's credentials were read from, from
    /// [`Source::name`](crate::provider::claude::account::Source::name).
    pub source: &'static str,
    /// The row state as a stable token, from
    /// [`AccountState::name`](crate::provider::claude::account::AccountState::name).
    pub state: &'static str,
    /// The same state as the sentence the table prints.
    pub state_label: String,
    /// What the namespace lock did on this pass (plan AC7).
    pub lock_state: &'static str,
    /// Every usage window the response described.
    pub windows: Vec<JsonWindow>,
    /// What is known about extra-usage credits (plan section 3.8).
    pub credits: JsonCredits,
    /// The soonest reset across every window, RFC 3339.
    pub next_reset: Option<String>,
    /// The short explanation the table appends to the state.
    pub note: Option<String>,
}

/// One usage window.
#[derive(Debug, Clone, Serialize)]
pub struct JsonWindow {
    /// `session`, `weekly_all`, `weekly_scoped` or `unknown`.
    pub kind: &'static str,
    /// The window's display label, which is where a scoped window's scope and
    /// an unrecognised window's raw kind string appear.
    pub label: String,
    /// The percentage the server sent, clamped to `0..=100`.
    pub percent: Option<f64>,
    /// The same figure floored, which is what the table and the web UI show
    /// (fact F21).
    pub percent_floor: Option<u8>,
    /// When the window rolls over, RFC 3339.
    pub resets_at: Option<String>,
    /// Whether this is the window currently constraining the account.
    pub is_active: bool,
}

impl From<&LimitWindow> for JsonWindow {
    fn from(window: &LimitWindow) -> Self {
        Self {
            kind: window_kind(&window.kind),
            label: window.label(),
            percent: window.percent,
            percent_floor: window.percent_floor,
            resets_at: window.resets_at.map(|resets_at| resets_at.to_string()),
            is_active: window.is_active,
        }
    }
}

/// The `kind` token for one window.
fn window_kind(kind: &WindowKind) -> &'static str {
    match kind {
        WindowKind::Session => "session",
        WindowKind::WeeklyAll => "weekly_all",
        WindowKind::WeeklyScoped(_) => "weekly_scoped",
        WindowKind::Unknown(_) => "unknown",
    }
}

/// An account's extra-usage credits, flattened (plan section 3.8, AC23).
///
/// Every row carries this object, including a row that never fetched anything:
/// a consumer testing `credits.state` gets a real answer rather than having to
/// distinguish an absent member from a null one.
#[derive(Debug, Clone, Serialize)]
pub struct JsonCredits {
    /// `on`, `off`, or `unavailable` — the last meaning the response carried
    /// no `extra_usage` object at all, which is not the same as switched off.
    pub state: &'static str,
    /// The amount spent, in minor units of `currency`.
    pub used_minor: Option<i64>,
    /// The ISO 4217 code the figures are in.
    pub currency: Option<String>,
    /// How many decimal places a minor unit represents.
    pub exponent: Option<u8>,
    /// The monthly ceiling in minor units, absent for an uncapped account.
    pub limit_minor: Option<i64>,
    /// The server's own utilisation percentage, rounded.
    pub percent: Option<u8>,
    /// Why credits are switched off, when the server said.
    pub disabled_reason: Option<String>,
    /// Always [`CREDITS_SCOPE`]: these figures are the organization's.
    pub scope: &'static str,
}

impl JsonCredits {
    /// The object a row with no usage at all carries.
    pub fn unavailable() -> Self {
        Self {
            state: "unavailable",
            used_minor: None,
            currency: None,
            exponent: None,
            limit_minor: None,
            percent: None,
            disabled_reason: None,
            scope: CREDITS_SCOPE,
        }
    }
}

impl From<&CreditsState> for JsonCredits {
    fn from(credits: &CreditsState) -> Self {
        match credits {
            CreditsState::Unavailable => Self::unavailable(),
            CreditsState::Off { reason } => {
                Self { state: "off", disabled_reason: reason.clone(), ..Self::unavailable() }
            }
            CreditsState::On(on) => Self::from_on(on),
        }
    }
}

impl JsonCredits {
    /// The `on` case, where the currency and exponent have to be recovered.
    ///
    /// They come from whichever figure the server actually sent: an account
    /// with a limit and no spend yet carries them only on the limit, and one
    /// with an uncapped plan only on the used amount. Reporting minor units
    /// without saying what they are minor units *of* would make the figure
    /// unusable.
    fn from_on(on: &Credits) -> Self {
        let denomination: Option<&Money> = on.used.as_ref().or(on.limit.as_ref());
        Self {
            state: "on",
            used_minor: on.used.as_ref().map(|money| money.amount_minor),
            currency: denomination.map(|money| money.currency.clone()),
            exponent: denomination.map(|money| money.exponent),
            limit_minor: on.limit.as_ref().map(|money| money.amount_minor),
            percent: on.percent,
            disabled_reason: None,
            scope: CREDITS_SCOPE,
        }
    }
}

/// The `windows` member for a row that may not have fetched anything.
pub fn windows_of(usage: Option<&UsageSnapshot>) -> Vec<JsonWindow> {
    usage.map(|usage| usage.windows.iter().map(JsonWindow::from).collect()).unwrap_or_default()
}

/// The `credits` member for a row that may not have fetched anything.
pub fn credits_of(usage: Option<&UsageSnapshot>) -> JsonCredits {
    usage.map_or_else(JsonCredits::unavailable, |usage| JsonCredits::from(&usage.credits))
}

/// The `next_reset` member for a row that may not have fetched anything.
pub fn next_reset_of(usage: Option<&UsageSnapshot>) -> Option<String> {
    usage.and_then(UsageSnapshot::next_reset).map(|resets_at| resets_at.to_string())
}

/// The published schema, compiled into the test binary.
///
/// Not a `*_tests.rs` item, for the same reason
/// [`crate::secret::fake_reader`] is not one: `commands::status`'s tests drive
/// whole passes and then assert the same thing about what they emitted, and a
/// sibling module's `mod tests` cannot be reached from another module.
#[cfg(test)]
pub const SCHEMA: &str = include_str!("../../schemas/status.v1.json");

/// Validates a report against [`SCHEMA`], naming every failure.
///
/// The schema lists every member as required and forbids additional ones, so
/// this catches a field renamed, retyped or dropped — in either direction —
/// rather than leaving it for a consumer's script to discover.
///
/// # Panics
///
/// Panics when the document does not validate, which is the assertion.
#[cfg(test)]
pub fn assert_valid(report: &StatusReport) {
    let schema: Value = serde_json::from_str(SCHEMA).expect("the published schema is valid JSON");
    let validator = jsonschema::validator_for(&schema).expect("the published schema compiles");
    let instance = serde_json::to_value(report).expect("a report serializes");

    let errors: Vec<String> = validator
        .iter_errors(&instance)
        .map(|err| format!("{}: {err}", err.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "the emitted document does not match schemas/status.v1.json:\n{}\n\ndocument:\n{}",
        errors.join("\n"),
        serde_json::to_string_pretty(&instance).unwrap_or_default()
    );
}

#[cfg(test)]
#[path = "json_tests.rs"]
mod tests;
