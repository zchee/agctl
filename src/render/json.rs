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
    /// When the five-hour session window rolls over, RFC 3339.
    ///
    /// Additive next to [`JsonRow::next_reset`] rather than a replacement for
    /// it: the table's two reset columns need one named window each, and a
    /// consumer already reading `next_reset` must not have to change. In UTC,
    /// like every other instant in the document — the table's local rendering
    /// is presentation, and a consumer that wants it has `generated_at` and a
    /// zone of its own.
    pub session_reset: Option<String>,
    /// When the seven-day all-models window rolls over, RFC 3339.
    pub weekly_reset: Option<String>,
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

/// The `session_reset` member: the five-hour window's own reset.
pub fn session_reset_of(usage: Option<&UsageSnapshot>) -> Option<String> {
    window_reset_of(usage, &WindowKind::Session)
}

/// The `weekly_reset` member: the seven-day all-models window's own reset.
pub fn weekly_reset_of(usage: Option<&UsageSnapshot>) -> Option<String> {
    window_reset_of(usage, &WindowKind::WeeklyAll)
}

/// One named window's reset, for a row that may not have fetched anything.
///
/// `None` covers both a response that described no such window and one that
/// described it without a `resets_at`, which is the same distinction the
/// table's em dash declines to make.
fn window_reset_of(usage: Option<&UsageSnapshot>, kind: &WindowKind) -> Option<String> {
    usage
        .and_then(|usage| usage.window(kind))
        .and_then(|window| window.resets_at)
        .map(|resets_at| resets_at.to_string())
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

// ---------------------------------------------------------------------------
// `doctor`'s isolation section (plan AC58)
// ---------------------------------------------------------------------------
//
// This is a separate document from [`StatusReport`], not an extension of it:
// `StatusReport`'s shape is normatively fixed by plan section 3.2 and 3.8, and
// mixing `doctor`'s isolation facts into it would publish a `status --json`
// consumer's contract as a side effect of a `doctor` change. No CLI flag
// reaches this yet — `DoctorArgs` gains nothing in this wave — so today it is
// exercised only by unit tests that build a [`DoctorReport`] directly and by
// `doctor`'s own text renderer, which walks the same fields. A later wave that
// wires up `doctor --json` serializes this type as-is.

/// The report version this build would emit for `doctor --json`.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "a future `doctor --json` is the first production constructor")
)]
pub const DOCTOR_REPORT_VERSION: u32 = 1;

/// The document `doctor`'s isolation section renders, in table and JSON form
/// alike (plan AC58).
///
/// `doctor.rs` builds [`IsolationRow`]/[`IsolationPolicy`] values directly for
/// its text renderer today; this wrapper is what a future `doctor --json`
/// would serialize, exercised for now only by [`assert_valid_doctor`]'s tests.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "a future `doctor --json` is the first production constructor")
)]
#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    /// The document version.
    pub version: u32,
    /// One entry per `<acct>/<org>` directory found under `session_root()`.
    pub isolation: Vec<IsolationRow>,
    /// The two machine-wide facts that apply regardless of how many sessions
    /// exist.
    pub isolation_policy: IsolationPolicy,
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "a future `doctor --json` is the first production constructor")
)]
impl DoctorReport {
    /// Builds a report from its two parts.
    pub fn new(isolation: Vec<IsolationRow>, isolation_policy: IsolationPolicy) -> Self {
        Self { version: DOCTOR_REPORT_VERSION, isolation, isolation_policy }
    }
}

/// One isolated session directory, as `doctor` found it.
#[derive(Debug, Clone, Serialize)]
pub struct IsolationRow {
    /// The registry id this session belongs to, or `unregistered`.
    pub id: String,
    /// The session directory itself.
    pub path: String,
    /// The two environment variables `use`/`exec`/`env` would export, and
    /// whether the sha8 they hash to matches the registered one.
    pub exports: IsolationExports,
    /// Every `TIER1`/`TIER2_DIRS` entry plus the MCP symlink, and what state
    /// each is in.
    pub links: Vec<IsolationLink>,
    /// The top-level key names of the seeded `.claude.json`, sorted; empty
    /// when it was never seeded.
    pub seeded_keys: Vec<String>,
    /// `seeded_keys` intersected with the never-seed allowlist — non-empty is
    /// an error condition (plan AC54's leak test).
    pub leaked_keys: Vec<String>,
    /// Top-level entries of the live config directory that are on neither
    /// allowlist, sorted.
    pub unexposed: Vec<String>,
    /// The D-019 MCP symlink specifically.
    pub mcp: IsolationMcp,
    /// How the live `.claude.json` compares with the seed, by modification
    /// time.
    pub drift: IsolationDrift,
    /// Whether a Claude Code session has migrated this namespace's
    /// credentials into the keychain — the same probe `attention_section`
    /// runs for AC58's "migration state" clause, reused rather than
    /// duplicated. `false` for an unregistered or non-`Owned` session, which
    /// has no namespace to migrate.
    pub migrated: bool,
    /// The exact command that tears this session down.
    pub forget_command: String,
}

/// [`IsolationRow::exports`].
#[derive(Debug, Clone, Serialize)]
pub struct IsolationExports {
    /// What `CLAUDE_SECURESTORAGE_CONFIG_DIR` would be set to.
    pub securestorage_dir: String,
    /// What `CLAUDE_CONFIG_DIR` would be set to — the session path itself.
    pub config_dir: String,
    /// Whether `sha8(securestorage_dir)` equals the registry's recorded
    /// `export_sha8` (plan AC50). `false` for an unregistered or non-`Owned`
    /// session, which is itself worth flagging.
    pub sha8_match: bool,
}

/// One allowlisted entry's symlink state.
///
/// The seeded `.claude.json` gets a row too (`name: ".claude.json"`,
/// `tier: "seed"`), but it is never expected to be a symlink (invariant
/// I18), so it carries its own, disjoint state vocabulary: `seeded`
/// (a plain file is there), `occupied` (something else is — a symlink or a
/// directory), or `absent`. `target` is always `None` for that row.
#[derive(Debug, Clone, Serialize)]
pub struct IsolationLink {
    /// The file or directory name, e.g. `settings.json`, `mcp.json`, or
    /// `.claude.json`.
    pub name: String,
    /// `tier1`, `tier2`, `mcp`, or `seed`.
    pub tier: &'static str,
    /// `linked`, `missing-target`, `occupied`, or `absent` for a symlinked
    /// entry; `seeded`, `occupied`, or `absent` for the `seed` tier.
    pub state: &'static str,
    /// The symlink's raw target, when the entry is a symlink at all. Always
    /// `None` for the `seed` tier.
    pub target: Option<String>,
}

/// [`IsolationRow::mcp`].
#[derive(Debug, Clone, Serialize)]
pub struct IsolationMcp {
    /// Whether `mcp.json` is a symlink at all.
    pub linked: bool,
    /// Its target, when it is one.
    pub target: Option<String>,
    /// How many `mcpServers` entries in the target file carry a non-empty
    /// `env` or `headers` object. `None` when the target could not be read or
    /// parsed — never a failure, only a gap in the report (D-019 exposure 3:
    /// a count, never a key name or a value).
    pub credential_entries: Option<u32>,
}

/// [`IsolationRow::drift`].
#[derive(Debug, Clone, Serialize)]
pub struct IsolationDrift {
    /// The live `.claude.json`'s modification time, milliseconds since the
    /// epoch.
    pub live_mtime_ms: Option<i64>,
    /// The seeded `.claude.json`'s modification time, same units.
    pub seed_mtime_ms: Option<i64>,
    /// Whether the live file is newer than the seed — informational, not an
    /// error: agentctl never rewrites the seed (invariant I18).
    pub changed_since_seed: bool,
}

/// The two machine-wide isolation facts (decisions D-019, D-020).
#[derive(Debug, Clone, Serialize)]
pub struct IsolationPolicy {
    /// `policySettings.disableSideloadFlags`, read from the live
    /// `settings.json` and the managed profile. `None` when neither file sets
    /// it.
    pub disable_sideload_flags: Option<bool>,
    /// Always `false`: agentctl cannot observe which secure-storage backend a
    /// session activates from outside it (decision D-020).
    pub backend_observable: bool,
}

/// The published doctor schema, compiled into the test binary.
#[cfg(test)]
pub const DOCTOR_SCHEMA: &str = include_str!("../../schemas/doctor.v1.json");

/// Validates a [`DoctorReport`] against [`DOCTOR_SCHEMA`], naming every
/// failure.
///
/// A sibling of [`assert_valid`] rather than a case it grows into: `assert_valid`
/// is called from `commands::status`'s own tests against `status.v1.json`, a
/// schema normatively scoped to plan sections 3.2/3.8, and widening its
/// signature to cover a second, unrelated schema would touch call sites this
/// change has no reason to touch.
///
/// # Panics
///
/// Panics when the document does not validate, which is the assertion.
#[cfg(test)]
pub fn assert_valid_doctor(report: &DoctorReport) {
    let schema: Value =
        serde_json::from_str(DOCTOR_SCHEMA).expect("the published doctor schema is valid JSON");
    let validator =
        jsonschema::validator_for(&schema).expect("the published doctor schema compiles");
    let instance = serde_json::to_value(report).expect("a doctor report serializes");

    let errors: Vec<String> = validator
        .iter_errors(&instance)
        .map(|err| format!("{}: {err}", err.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "the emitted document does not match schemas/doctor.v1.json:\n{}\n\ndocument:\n{}",
        errors.join("\n"),
        serde_json::to_string_pretty(&instance).unwrap_or_default()
    );
}

#[cfg(test)]
#[path = "json_tests.rs"]
mod tests;
