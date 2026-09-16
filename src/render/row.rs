//! What the watch display needs from a row, whoever produced it.
//!
//! [`TuiRow`] is the whole of it: six questions and two strings. Everything
//! `tui::ui` draws — the gauges, the line under them, the block's title and
//! height, whether the row is shown at all — is an answer to one of them, so
//! the frame code can be written once and handed a Claude row or a Codex row
//! without knowing which it has.
//!
//! # Why the bodies live here and not in `tui::ui`
//!
//! They used to be free functions over
//! [`RowOutcome`](crate::commands::status::RowOutcome) in `tui::ui`, which
//! made the drawing code and the Claude-specific answers one module. A second
//! provider would have had to add a second copy of the frame, or a `match` on
//! the provider inside it. Moving the answers into a trait implementation
//! leaves `tui::ui` with nothing provider-shaped in it, and leaves exactly one
//! place — this file — where "what a Claude row looks like in the TUI" is
//! written down. The bodies themselves are unchanged, which is what the
//! `tui` snapshots pin (plan AC104, AC118).
//!
//! # The two consts are commands, not decoration
//!
//! The header says which command is running and the footer says which command
//! shows the hidden rows. Both name `agctl claude …` today; a Codex display
//! that inherited those strings would tell the user to run a command that
//! reports the other provider's accounts (plan ledger #141).

use jiff::Timestamp;

use crate::commands::status::RowOutcome;
use crate::provider::claude::account::AccountState;
use crate::provider::claude::usage::HEADLINE_SCOPE;
use crate::render::json_v2::IntoJsonRowV2;
use crate::render::table::EMPTY_CELL;
use crate::runtime::coordinator::PassCtx;
use crate::usage::model::CreditsState;
use crate::usage::model::UsageSnapshot;
use crate::usage::model::WindowKind;
use crate::usage::model::render_countdown;

/// The marker in front of the selected account.
pub const SELECTED_MARKER: &str = "▸";

/// Lines an account block spends on something other than a gauge: the two
/// borders and the detail line.
const BLOCK_CHROME: u16 = 3;

/// One row of a watch display.
pub trait TuiRow {
    /// What the header calls this display, before the account count.
    const WATCH_TITLE: &'static str;

    /// The command the footer names for the rows this display hides.
    const HIDDEN_HINT: &'static str;

    /// The gauges this row earns, in display order.
    ///
    /// A window the response did not describe earns no gauge rather than one
    /// at zero: a bar at zero is a claim that nothing has been used, which is
    /// a different statement from "the server did not say".
    fn gauges(&self) -> Vec<(&'static str, u8)>;

    /// The line under the gauges: badge, state, note, next reset.
    fn detail_line(&self, now: Timestamp) -> String;

    /// The block's title: who this is, and whether it is selected.
    fn account_title(&self, selected: bool) -> String;

    /// How tall the block is, borders included.
    fn block_height(&self) -> u16;

    /// Whether the row appears without `--all`.
    fn visible_by_default(&self) -> bool;

    /// The row's state as one stable, machine-readable token.
    ///
    /// The neutral half of what [`TuiRow::detail_line`] renders in prose: a
    /// caller that wants to decide something about a row — a colour, a count,
    /// an exit status — reads this rather than parsing the sentence.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the Codex display (S33) is the first production caller; the Claude TUI \
                      renders the prose form and decides nothing from the token"
        )
    )]
    fn state_token(&self) -> &'static str;
}

/// Where one provider's rows for a pass come from.
///
/// The seam a combined `agctl status` would concatenate (plan ledger #103):
/// each provider implements it once, and a caller that wants every row on the
/// machine asks each source in turn rather than knowing how either of them
/// produces rows. Its associated type must be renderable both ways —
/// [`TuiRow`] for the display, [`IntoJsonRowV2`] for the document — so a
/// provider cannot ship a row that only one presentation can show.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the Codex pass implements it at S33, and the combined command is 3.2's \
                  (U42 = no); S29b ships the seam so the row types are built against it"
    )
)]
pub trait RowSource {
    /// This source's row type.
    type Row: TuiRow + IntoJsonRowV2 + Send;

    /// One pass's rows, in discovery order, or `None` when the pass failed
    /// before it could look — which is not the same as "no accounts", and is
    /// why the display keeps the numbers already on screen.
    fn rows(&self, ctx: &PassCtx) -> Option<Vec<Self::Row>>;
}

/// The badge for a Claude row, when its state has one.
///
/// `None` is the ordinary case: a healthy row, or one whose state the label
/// alone says better than any two-word summary could.
pub fn badge(state: &AccountState) -> Option<&'static str> {
    match state {
        AccountState::Stale => Some("stale"),
        AccountState::RateLimited { .. } => Some("rate-limited"),
        AccountState::ClaudeSessionDetected { .. } => Some("claude-detected"),
        AccountState::KeychainLocked { .. } | AccountState::KeychainTimeout => {
            Some("keychain-locked")
        }
        AccountState::Busy => Some("busy"),
        AccountState::NeedsLogin => Some("needs login"),
        _ => None,
    }
}

impl TuiRow for RowOutcome {
    const WATCH_TITLE: &'static str = "agctl claude watch";
    const HIDDEN_HINT: &'static str = "agctl claude status --all";

    fn gauges(&self) -> Vec<(&'static str, u8)> {
        let Some(usage) = self.usage.as_ref() else {
            return Vec::new();
        };

        let mut out = Vec::new();
        if let Some(percent) = window_percent(usage, &WindowKind::Session) {
            out.push(("5h", percent));
        }
        if let Some(percent) = window_percent(usage, &WindowKind::WeeklyAll) {
            out.push(("weekly", percent));
        }
        if let Some(percent) =
            usage.scoped_window(HEADLINE_SCOPE).and_then(|window| window.percent_floor)
        {
            out.push((HEADLINE_SCOPE, percent));
        }
        if let CreditsState::On(credits) = &usage.credits
            && let Some(percent) = credits.percent
        {
            out.push(("credits", percent));
        }
        out
    }

    fn detail_line(&self, now: Timestamp) -> String {
        let mut parts = Vec::new();
        if let Some(badge) = badge(&self.state) {
            parts.push(format!("[{badge}]"));
        }
        parts.push(self.state.label());
        if let Some(note) = self.note.as_ref().filter(|note| !note.is_empty()) {
            parts.push(format!("({note})"));
        }
        if let Some(resets_at) = self.usage.as_ref().and_then(UsageSnapshot::next_reset) {
            parts.push(format!("next reset in {}", render_countdown(now, resets_at)));
        }
        parts.join(" · ")
    }

    fn account_title(&self, selected: bool) -> String {
        let marker = if selected { SELECTED_MARKER } else { " " };
        let plan = if self.plan.is_empty() { EMPTY_CELL } else { self.plan.as_str() };
        let org = if self.org.is_empty() { EMPTY_CELL } else { self.org.as_str() };
        format!("{marker} {} · {org} · {plan} ", self.account)
    }

    /// Bounded by construction — [`TuiRow::gauges`] returns at most four
    /// entries — so the addition cannot overflow the `u16` even with overflow
    /// checks compiled out.
    fn block_height(&self) -> u16 {
        let count = u16::try_from(self.gauges().len()).unwrap_or(0);
        BLOCK_CHROME.saturating_add(count)
    }

    fn visible_by_default(&self) -> bool {
        self.visible_by_default
    }

    fn state_token(&self) -> &'static str {
        self.state.name()
    }
}

/// A window's floored percentage, when the response carried one.
fn window_percent(usage: &UsageSnapshot, kind: &WindowKind) -> Option<u8> {
    usage.window(kind).and_then(|window| window.percent_floor)
}

#[cfg(test)]
#[path = "row_tests.rs"]
mod tests;
