//! The normalized usage vocabulary: windows, percentages, credits, money.
//!
//! Three decisions in here are load-bearing rather than stylistic.
//!
//! **A percentage is optional.** The API sends `percent` as a JSON number, and
//! a JSON number can be a `NaN` once it has been through a float. `NaN`
//! compares false against everything, so a clamp would silently pass it
//! through and the table would print `NaN%`. [`clamp_percent`] turns it into
//! `None` and the renderer prints an em dash, which is a true statement.
//!
//! **Two percentages are kept, not one.** [`LimitWindow::percent`] is what the
//! server said; [`LimitWindow::percent_floor`] is that value floored to a whole
//! number. The table shows the floor so that agentctl and the web UI agree to
//! the point (fact F21, plan AC1) — rounding half-up would show `36%` where
//! the site shows `35%`.
//!
//! **Credits come from `extra_usage` alone.** [`CreditsState`] distinguishes
//! "switched off" from "the response said nothing", because those are
//! different facts about an account and only one of them is worth acting on.
//! The parser that fills them is
//! [`credits_from_body`](crate::provider::claude::usage::credits_from_body)
//! (plan section 3.8, decision D-006); `spend` is never read into any of
//! these types, so a figure this vocabulary cannot express survives only in
//! `--raw`.

use std::fmt;

use jiff::Timestamp;
use serde_json::Value;

/// The largest `exponent` [`Money`] will honour.
///
/// Beyond this the minor-unit divisor stops fitting anything sane, and the
/// only currencies in play use 0, 2 or 3. Anything larger is clamped rather
/// than rejected: a display type must not fail (plan AC24).
pub const MAX_MONEY_EXPONENT: u8 = 6;

/// The exponent assumed when the server sends none, or sends a nonsensical
/// one.
///
/// Two, because every currency the endpoint has been observed to quote is a
/// two-decimal one and because the alternative — refusing to show a figure
/// the server did send — is worse than showing it with the wrong number of
/// decimals (plan section 3.8).
pub const DEFAULT_MONEY_EXPONENT: u8 = 2;

/// One usage window, whatever the provider called it.
#[derive(Debug, Clone, PartialEq)]
pub struct LimitWindow {
    /// Which window this is.
    pub kind: WindowKind,
    /// The percentage consumed, clamped to `0..=100`, or `None` when the
    /// server sent something that is not a number.
    pub percent: Option<f64>,
    /// [`LimitWindow::percent`] floored to a whole number, for display.
    pub percent_floor: Option<u8>,
    /// The server's own severity label, when it sent one.
    pub severity: Option<String>,
    /// When the window rolls over.
    pub resets_at: Option<Timestamp>,
    /// The scope's display name, for a scoped window.
    pub scope_label: Option<String>,
    /// Whether this is the window currently constraining the account.
    pub is_active: bool,
}

impl LimitWindow {
    /// The label this window carries in the table's continuation rows.
    ///
    /// Named windows say what they are scoped to; an unrecognised kind says
    /// so verbatim, because the kind string is the only evidence the user has
    /// that something new appeared (risk R3).
    pub fn label(&self) -> String {
        match &self.kind {
            WindowKind::Session => "session".to_owned(),
            WindowKind::WeeklyAll => "weekly".to_owned(),
            WindowKind::WeeklyScoped(scope) => format!("{scope} (weekly)"),
            WindowKind::Unknown(kind) => format!("{kind} (unknown kind)"),
        }
    }
}

/// Which window a [`LimitWindow`] describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowKind {
    /// The rolling five-hour session window.
    Session,
    /// The weekly window covering every model.
    WeeklyAll,
    /// A weekly window scoped to one model, named by its display name.
    WeeklyScoped(String),
    /// A `kind` this build does not recognise, kept verbatim.
    Unknown(String),
}

/// What is known about an account's extra-usage credits.
#[derive(Debug, Clone, PartialEq)]
pub enum CreditsState {
    /// The response carried no `extra_usage` object. Rendered `n/a`.
    ///
    /// Not the same as [`CreditsState::Off`]: this build looked and the
    /// server said nothing, which is what an account on an older API shape
    /// looks like. When `spend` nonetheless carried a figure, the parser has
    /// already logged a warning pointing at `--raw` (risk R14).
    Unavailable,
    /// Credits exist for this account but are switched off.
    Off {
        /// The server's `disabled_reason`, when it gave one.
        reason: Option<String>,
    },
    /// Credits are on, with the numbers below.
    On(Credits),
}

/// The credit figures for an account with extra usage enabled.
#[derive(Debug, Clone, PartialEq)]
pub struct Credits {
    /// How much has been spent.
    pub used: Option<Money>,
    /// The monthly ceiling, or `None` for an uncapped account.
    pub limit: Option<Money>,
    /// The server's own utilisation percentage, rounded and clamped.
    pub percent: Option<u8>,
}

/// An amount of money in minor units.
///
/// Minor units rather than a float because money compared or summed as `f64`
/// drifts, and because the API already sends `amount_minor` and `exponent`
/// separately — reconstituting a float would throw away the exactness the
/// server took care to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Money {
    /// The amount, in units of `10^-exponent` of the currency. May be
    /// negative: a refunded or credited account is a real state (decision U6).
    pub amount_minor: i64,
    /// The ISO 4217 code.
    pub currency: String,
    /// How many decimal places the minor unit represents.
    pub exponent: u8,
}

impl fmt::Display for Money {
    /// Renders `$12.34` for USD and `EUR 12.34` for anything else.
    ///
    /// Never panics, for any `amount_minor` (including [`i64::MIN`]) and any
    /// exponent (plan AC24). The magnitude is taken with
    /// [`i64::unsigned_abs`], which is total, and the exponent is clamped to
    /// [`MAX_MONEY_EXPONENT`] before it reaches the power, so the divisor
    /// always fits a `u64`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let exponent = usize::from(self.exponent.min(MAX_MONEY_EXPONENT));
        let scale = 10u64.pow(self.exponent.min(MAX_MONEY_EXPONENT).into());
        let magnitude = self.amount_minor.unsigned_abs();
        let whole = magnitude / scale;
        let fraction = magnitude % scale;

        let sign = if self.amount_minor < 0 { "-" } else { "" };
        if self.currency == "USD" {
            f.write_str(sign)?;
            f.write_str("$")?;
        } else if self.currency.is_empty() {
            f.write_str(sign)?;
        } else {
            write!(f, "{sign}{} ", self.currency)?;
        }

        if exponent == 0 {
            write!(f, "{whole}")
        } else {
            write!(f, "{whole}.{fraction:0exponent$}")
        }
    }
}

/// One account's usage at one moment.
#[derive(Debug, Clone, PartialEq)]
pub struct UsageSnapshot {
    /// When the response this was built from was received.
    pub fetched_at: Timestamp,
    /// Every window the response described, in the order it described them.
    pub windows: Vec<LimitWindow>,
    /// What is known about credits.
    pub credits: CreditsState,
    /// The untouched response body, kept only for `--raw` (invariant I4: it
    /// carries no token material, only usage figures).
    pub raw: Option<Value>,
}

impl UsageSnapshot {
    /// The first window of a given kind, if the response carried one.
    pub fn window(&self, kind: &WindowKind) -> Option<&LimitWindow> {
        self.windows.iter().find(|window| &window.kind == kind)
    }

    /// The first weekly window scoped to `scope`, compared case-insensitively.
    ///
    /// Case-insensitive because the column heading is fixed (`Fable (weekly)`)
    /// while the server sends a display name it may capitalise differently
    /// from one release to the next; a case flip should not blank the column.
    pub fn scoped_window(&self, scope: &str) -> Option<&LimitWindow> {
        self.windows.iter().find(|window| match &window.kind {
            WindowKind::WeeklyScoped(name) => name.eq_ignore_ascii_case(scope),
            _ => false,
        })
    }

    /// Every window that does not have a column of its own, in order.
    ///
    /// These become the continuation rows under an account (plan section 3.3
    /// step 4): scoped weeklies other than the headline one, and anything of
    /// an unrecognised kind.
    pub fn extra_windows(&self, headline_scope: &str) -> Vec<&LimitWindow> {
        self.windows
            .iter()
            .filter(|window| match &window.kind {
                WindowKind::WeeklyScoped(name) => !name.eq_ignore_ascii_case(headline_scope),
                WindowKind::Unknown(_) => true,
                WindowKind::Session | WindowKind::WeeklyAll => false,
            })
            .collect()
    }

    /// The soonest reset across every window.
    pub fn next_reset(&self) -> Option<Timestamp> {
        self.windows.iter().filter_map(|window| window.resets_at).min()
    }
}

/// Clamps a server-sent percentage into `0..=100`, rejecting non-numbers.
///
/// `NaN` becomes `None` rather than a clamped value: `f64::clamp` panics on a
/// `NaN` bound and returns `NaN` for a `NaN` input, and printing `NaN%` in a
/// usage table would be worse than admitting the figure is unavailable.
pub fn clamp_percent(value: f64) -> Option<f64> {
    if value.is_nan() {
        return None;
    }
    Some(value.clamp(0.0, 100.0))
}

/// Floors an already-clamped percentage for display (fact F21).
///
/// The cast is safe for every finite input because the value is clamped to
/// `0.0..=100.0` first; Rust's float-to-int casts saturate rather than
/// wrapping, so even an unclamped infinity would land on `255` rather than
/// producing nonsense.
pub fn percent_floor(value: f64) -> Option<u8> {
    let clamped = clamp_percent(value)?;
    Some(clamped.floor() as u8)
}

/// Rounds an already-clamped percentage to the nearest whole number.
///
/// Rounding, not flooring, and the difference from [`percent_floor`] is
/// deliberate. A window percentage is floored because the web UI floors it
/// and agentctl must never read a point above the site (fact F21). The
/// credits figure is `extra_usage.utilization`, which plan section 3.8
/// specifies as rounded; whether the site floors it too has not been
/// observed, so the two helpers sit side by side and a later edit has to
/// choose one rather than inherit whichever it happens to import.
///
/// The cast is exact for every input: [`clamp_percent`] has already rejected
/// `NaN` and confined the value to `0.0..=100.0`, so the rounded result is a
/// whole number in `0..=100`.
pub fn percent_round(value: f64) -> Option<u8> {
    let clamped = clamp_percent(value)?;
    Some(clamped.round() as u8)
}

/// Formats the time until `target` as a compact countdown.
///
/// Renders `3d4h`, `2h13m`, `45m`, `30s`, and `now` for a reset that has
/// already passed — a stale window rolling over between the fetch and the
/// render is ordinary, not an error worth a negative duration.
///
/// All arithmetic is checked (constraint C-006): this project builds with
/// `-C overflow-checks=off`, so a wrapped subtraction between two extreme
/// timestamps would print a confidently wrong countdown instead of failing.
pub fn render_countdown(now: Timestamp, target: Timestamp) -> String {
    let Some(millis) = target.as_millisecond().checked_sub(now.as_millisecond()) else {
        return "now".to_owned();
    };
    if millis <= 0 {
        return "now".to_owned();
    }

    let seconds = millis / 1000;
    let minutes = seconds / 60;
    let hours = minutes / 60;
    let days = hours / 24;

    if days > 0 {
        format!("{days}d{}h", hours % 24)
    } else if hours > 0 {
        format!("{hours}h{}m", minutes % 60)
    } else if minutes > 0 {
        format!("{minutes}m")
    } else {
        format!("{seconds}s")
    }
}

#[cfg(test)]
#[path = "model_tests.rs"]
mod tests;
