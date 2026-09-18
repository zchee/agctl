//! What a Codex row can say: its state, its credits, and the finished row
//! both presentations render.
//!
//! The vocabulary of plan section 3.6, with the stable names
//! `schemas/status.v2.json` enumerates, and [`CodexRowOutcome`] — the Codex
//! twin of Claude's `RowOutcome` (ledger #274 (e)). The row implements
//! [`TuiRow`] for `agctl codex watch` and [`IntoJsonRowV2`] for `agctl codex
//! status --json`, and builds the [`CodexTableRow`] the table prints, so the
//! three renderings of one pass are three views of one value.
//!
//! # No credential reaches a row
//!
//! A row holds ids, an email, a plan, a state and usage figures. The pass
//! drops the credential it read before a row exists, so no renderer below
//! this type can reach a token (invariant I24).

use jiff::Timestamp;

use crate::provider::Provider;
use crate::provider::codex::auth_store;
use crate::provider::codex::auth_store::UnknownClass;
use crate::provider::codex::home::StoreMode;
use crate::provider::codex::usage::CodexUsage;
use crate::render::json_v2::IntoJsonRowV2;
use crate::render::json_v2::JsonCreditsV2;
use crate::render::json_v2::JsonIdentityV2;
use crate::render::json_v2::JsonRowV2;
use crate::render::json_v2::provider_token;
use crate::render::row::SELECTED_MARKER;
use crate::render::row::TuiRow;
use crate::render::table::CodexTableRow;
use crate::render::table::EMPTY_CELL;
use crate::usage::model::LimitWindow;
use crate::usage::model::WindowKind;
use crate::usage::model::render_countdown;

/// Lines a Codex account block spends on something other than a gauge: the
/// two borders and the detail line (the Claude display's own figure).
const BLOCK_CHROME: u16 = 3;

/// A Codex account's credits (fact F78-b: `balance` is a decimal *string* on
/// the wire, kept as one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodexCredits {
    /// The response carried a credits object.
    Balance {
        /// The balance as the server spelled it.
        balance: Option<String>,
        /// Whether the account's credits are unlimited.
        unlimited: bool,
    },
    /// No credits object in the response.
    Unavailable,
}

/// One Codex row's state (plan section 3.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodexState {
    /// Usage was read.
    Ok,
    /// The access token is expired and will not be refreshed from here.
    Expired {
        /// The row's instruction, such as `run agctl codex login`.
        reason: String,
    },
    /// No credential, or a dead grant.
    NeedsLogin,
    /// A mode with no usage endpoint (`apikey`, Bedrock). Exit-neutral.
    NoUsageSource {
        /// The auth mode's label.
        mode: String,
    },
    /// The response had no `rate_limit`.
    NoUsageWindows,
    /// The home stores credentials where agctl does not read them.
    StoreModeUnsupported {
        /// The configured mode.
        mode: StoreMode,
    },
    /// The Codex home could not be resolved or read.
    HomeUnreadable {
        /// Why, without file content.
        reason: String,
    },
    /// `auth.json` was being rewritten. Transient.
    TornRead,
    /// The usage endpoint rejected the token.
    Unauthorized {
        /// Whether a refresh was sent recently (the floor).
        refreshed_recently: bool,
    },
    /// An imported home that is the live home with a different grant.
    StaleSiblingOfLive,
    /// Hidden by the user.
    Forgotten,
    /// A Codex session is using the namespace.
    CodexSessionDetected {
        /// The evidence, as `doctor` names it.
        evidence: String,
    },
    /// The namespace lock was held by another process.
    Busy,
    /// The namespace lock could not be taken at all.
    LockUnavailable,
    /// A cached result, not refreshed this pass.
    Stale,
    /// The endpoint asked for a pause.
    RateLimited {
        /// The `retry-after` hint, in seconds.
        retry_after: Option<u64>,
    },
    /// A parked refresh was moved into place.
    PendingReplayed,
    /// A parked refresh was deleted unused.
    PendingDiscarded {
        /// The resolver's label.
        reason: String,
    },
    /// A refresh response was discarded.
    RefreshDiscarded,
    /// The refreshed id token names a different account (fact F92).
    IdentityDrift,
    /// A refresh was sent and its outcome is unknown; no automatic re-send.
    RefreshOutcomeUnknown {
        /// Since when.
        since: Timestamp,
        /// Why.
        class: UnknownClass,
        /// Whether `accounts refresh --resend` is allowed now.
        resend_eligible: bool,
    },
    /// The refresh marker cannot be read or written; no POST.
    RefreshStateUnavailable {
        /// Why, as a path and an errno.
        reason: String,
    },
    /// The account's refresh policy is `never`.
    RefreshDisabled,
    /// A 401 inside the refresh floor.
    UnauthorizedFloor,
    /// Three counted failures: only `login` or `--reset-floor` lifts this.
    UnauthorizedTerminal,
    /// An adopted grant was rejected too.
    AdoptedGrantDead,
    /// A newer external grant replaced the refresh response.
    DiscardedExternal,
    /// Anything else, as a sentence.
    Error(String),
}

impl CodexState {
    /// The state's stable name in `status.v2.json`.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Expired { .. } => "expired",
            Self::NeedsLogin => "needs_login",
            Self::NoUsageSource { .. } => "no_usage_source",
            Self::NoUsageWindows => "no_usage_windows",
            Self::StoreModeUnsupported { .. } => "store_mode_unsupported",
            Self::HomeUnreadable { .. } => "home_unreadable",
            Self::TornRead => "torn_read",
            Self::Unauthorized { .. } => "unauthorized",
            Self::StaleSiblingOfLive => "stale_sibling_of_live",
            Self::Forgotten => "forgotten",
            Self::CodexSessionDetected { .. } => "codex_session_detected",
            Self::Busy => "busy",
            Self::LockUnavailable => "lock_unavailable",
            Self::Stale => "stale",
            Self::RateLimited { .. } => "rate_limited",
            Self::PendingReplayed => "pending_replayed",
            Self::PendingDiscarded { .. } => "pending_discarded",
            Self::RefreshDiscarded => "refresh_discarded",
            Self::IdentityDrift => "identity_drift",
            Self::RefreshOutcomeUnknown { .. } => "refresh_outcome_unknown",
            Self::RefreshStateUnavailable { .. } => "refresh_state_unavailable",
            Self::RefreshDisabled => "refresh_disabled",
            Self::UnauthorizedFloor => "unauthorized_floor",
            Self::UnauthorizedTerminal => "unauthorized_terminal",
            Self::AdoptedGrantDead => "adopted_grant_dead",
            Self::DiscardedExternal => "discarded_external",
            Self::Error(_) => "error",
        }
    }

    /// Whether the state leaves the exit status untouched (plan AC103):
    /// a row with nothing to read is not a degraded row.
    pub fn is_exit_neutral(&self) -> bool {
        matches!(self, Self::Ok | Self::NoUsageSource { .. } | Self::Forgotten)
    }
}

impl CodexState {
    /// The state as the sentence the table prints (`state_label` in version
    /// 2). Prose, not stable across versions; [`CodexState::name`] is the
    /// token.
    pub fn label(&self) -> String {
        match self {
            Self::Ok => "ok".to_owned(),
            Self::Expired { reason } => format!("expired ({reason})"),
            Self::NeedsLogin => "needs login".to_owned(),
            Self::NoUsageSource { mode } => format!("no usage source ({mode})"),
            Self::NoUsageWindows => "no usage windows".to_owned(),
            Self::StoreModeUnsupported { mode } => {
                format!("not read (credential store: {})", mode.label())
            }
            Self::HomeUnreadable { reason } => reason.clone(),
            Self::TornRead => {
                format!("{} was being rewritten; retrying next pass", auth_store::shown_name())
            }
            Self::Unauthorized { .. } => "unauthorized".to_owned(),
            Self::StaleSiblingOfLive => "stale sibling of live".to_owned(),
            Self::Forgotten => "forgotten".to_owned(),
            Self::CodexSessionDetected { evidence } => {
                format!("codex session detected ({evidence})")
            }
            Self::Busy => "busy".to_owned(),
            Self::LockUnavailable => "lock unavailable".to_owned(),
            Self::Stale => "stale".to_owned(),
            Self::RateLimited { retry_after: Some(seconds) } => {
                format!("rate-limited (retry in {seconds}s)")
            }
            Self::RateLimited { retry_after: None } => "rate-limited".to_owned(),
            Self::PendingReplayed => "pending replayed".to_owned(),
            Self::PendingDiscarded { reason } => format!("pending discarded ({reason})"),
            Self::RefreshDiscarded => "refresh discarded".to_owned(),
            Self::IdentityDrift => "identity drift".to_owned(),
            Self::RefreshOutcomeUnknown { class, .. } => {
                format!("refresh outcome unknown ({})", class.label())
            }
            Self::RefreshStateUnavailable { reason } => {
                format!("refresh state unavailable: {reason}")
            }
            Self::RefreshDisabled => "refresh disabled".to_owned(),
            Self::UnauthorizedFloor => "unauthorized (refresh floor)".to_owned(),
            Self::UnauthorizedTerminal => "unauthorized (refresh did not help)".to_owned(),
            Self::AdoptedGrantDead => "needs login (adopted grant dead)".to_owned(),
            Self::DiscardedExternal => "refresh discarded (external writer)".to_owned(),
            Self::Error(message) => message.clone(),
        }
    }
}

/// The badge a watch block puts in front of a degraded Codex row, when its
/// state has one. `None` for a healthy row and for states the label says
/// better.
pub fn badge(state: &CodexState) -> Option<&'static str> {
    match state {
        CodexState::Stale | CodexState::TornRead => Some("stale"),
        CodexState::RateLimited { .. } => Some("rate-limited"),
        CodexState::CodexSessionDetected { .. } => Some("codex-detected"),
        CodexState::Busy => Some("busy"),
        CodexState::Expired { .. } => Some("expired"),
        CodexState::NeedsLogin | CodexState::AdoptedGrantDead => Some("needs login"),
        CodexState::RefreshOutcomeUnknown { .. } | CodexState::RefreshStateUnavailable { .. } => {
            Some("refresh unknown")
        }
        _ => None,
    }
}

/// Where a Codex row's credential lives (decision D-029's three kinds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodexRowKind {
    /// The user's own Codex home. Read-only.
    Live,
    /// A home recorded by `import`. Read-only.
    HomeReadOnly,
    /// An agctl-owned namespace.
    Owned,
}

impl CodexRowKind {
    /// The kind as the registry, the table's `Kind` column and version 2's
    /// `kind` member spell it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::HomeReadOnly => "home_read_only",
            Self::Owned => "owned",
        }
    }
}

/// One finished Codex row.
#[derive(Debug, Clone)]
pub struct CodexRowOutcome {
    /// The row's position in discovery order.
    pub index: usize,
    /// The display id `--account` accepts (decision D-039): the user id when
    /// unique, else `<user>/<account>`. An identifier, never a secret.
    pub id: String,
    /// The ChatGPT user id; empty when the credential named nobody.
    pub user_id: String,
    /// The ChatGPT account (workspace) id; empty when unknown.
    pub account_id: String,
    /// The account's email address, when the claims or the registry had one.
    pub email: Option<String>,
    /// The plan: the response's when it named one, else the claim's.
    pub plan: Option<String>,
    /// Where the credential lives.
    pub kind: CodexRowKind,
    /// What the pass concluded.
    pub state: CodexState,
    /// What the namespace lock did on this pass.
    pub lock_state: &'static str,
    /// A short explanation appended to the state.
    pub note: Option<String>,
    /// The numbers, when this row has any.
    pub usage: Option<CodexUsage>,
    /// Whether the row appears without `--all`.
    pub visible_by_default: bool,
}

impl CodexRowOutcome {
    /// The first column: the email when known, else the display id.
    pub fn account(&self) -> &str {
        self.email.as_deref().filter(|email| !email.is_empty()).unwrap_or(&self.id)
    }

    /// The state column's full text: the label, then the note in
    /// parentheses.
    pub fn state_cell(&self) -> String {
        match self.note.as_deref().filter(|note| !note.is_empty()) {
            Some(note) => format!("{} ({note})", self.state.label()),
            None => self.state.label(),
        }
    }

    /// The first window of `kind` the response described.
    fn window(&self, kind: &WindowKind) -> Option<&LimitWindow> {
        self.windows().find(|window| &window.kind == kind)
    }

    /// Every window, in the order the response described them.
    fn windows(&self) -> impl Iterator<Item = &LimitWindow> {
        self.usage.iter().flat_map(|usage| usage.windows.iter().map(|codex| &codex.window))
    }

    /// Every window that has no column of its own: all but the first
    /// five-hour and the first weekly window.
    fn extra_windows(&self) -> Vec<&LimitWindow> {
        let (mut session_seen, mut weekly_seen) = (false, false);
        self.windows()
            .filter(|window| match window.kind {
                WindowKind::Session if !session_seen => {
                    session_seen = true;
                    false
                }
                WindowKind::WeeklyAll if !weekly_seen => {
                    weekly_seen = true;
                    false
                }
                _ => true,
            })
            .collect()
    }

    /// The credits cell: the balance as the wire spelled it, `Unlimited`,
    /// an em dash for a credits object without a balance, `n/a` without one.
    pub fn credits_cell(&self) -> String {
        match self.usage.as_ref().map(|usage| &usage.credits) {
            Some(CodexCredits::Balance { unlimited: true, .. }) => "Unlimited".to_owned(),
            Some(CodexCredits::Balance { balance: Some(balance), .. }) => balance.clone(),
            Some(CodexCredits::Balance { balance: None, .. }) => EMPTY_CELL.to_owned(),
            Some(CodexCredits::Unavailable) | None => "n/a".to_owned(),
        }
    }

    /// The row the table prints.
    pub fn to_table_row(&self) -> CodexTableRow {
        CodexTableRow {
            account: self.account().to_owned(),
            plan: self.plan.clone().unwrap_or_default(),
            kind: self.kind.name(),
            session: self.window(&WindowKind::Session).cloned(),
            weekly: self.window(&WindowKind::WeeklyAll).cloned(),
            extra: self.extra_windows().into_iter().cloned().collect(),
            credits: self.credits_cell(),
            state: self.state_cell(),
            visible_by_default: self.visible_by_default,
        }
    }

    /// The soonest reset across every window.
    fn next_reset(&self) -> Option<Timestamp> {
        self.windows().filter_map(|window| window.resets_at).min()
    }
}

impl TuiRow for CodexRowOutcome {
    const WATCH_TITLE: &'static str = "agctl codex watch";
    const HIDDEN_HINT: &'static str = "agctl codex status --all";

    fn gauges(&self) -> Vec<(&'static str, u8)> {
        let mut out = Vec::new();
        if let Some(percent) = self.window(&WindowKind::Session).and_then(|w| w.percent_floor) {
            out.push(("5h", percent));
        }
        if let Some(percent) = self.window(&WindowKind::WeeklyAll).and_then(|w| w.percent_floor) {
            out.push(("weekly", percent));
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
        if let Some(resets_at) = self.next_reset() {
            parts.push(format!("next reset in {}", render_countdown(now, resets_at)));
        }
        parts.join(" · ")
    }

    fn account_title(&self, selected: bool) -> String {
        let marker = if selected { SELECTED_MARKER } else { " " };
        let plan = self.plan.as_deref().filter(|plan| !plan.is_empty()).unwrap_or(EMPTY_CELL);
        format!("{marker} {} · {} · {plan} ", self.account(), self.kind.name())
    }

    /// At most two gauges, so the sum cannot overflow.
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

impl IntoJsonRowV2 for CodexRowOutcome {
    fn to_json_row_v2(&self) -> JsonRowV2 {
        let reset_of = |kind: &WindowKind| {
            self.window(kind).and_then(|window| window.resets_at).map(|at| at.to_string())
        };
        JsonRowV2 {
            provider: provider_token(Provider::Codex),
            id: self.id.clone(),
            identity: JsonIdentityV2 {
                user_id: self.user_id.clone(),
                account_id: self.account_id.clone(),
                plan_type: self.plan.clone(),
                email: self.email.clone(),
                // A ChatGPT workspace's title is PII this build does not store
                // (plan U40: the id, not the title).
                org_name: None,
            },
            kind: self.kind.name(),
            // Codex credentials are only ever read from a file, so there is no
            // second answer to "where" beside the kind.
            source: None,
            state: self.state.name(),
            state_label: self.state.label(),
            lock_state: self.lock_state,
            note: self.note.clone(),
            windows: self
                .usage
                .iter()
                .flat_map(|usage| usage.windows.iter().map(|window| window.to_json_v2()))
                .collect(),
            credits: self
                .usage
                .as_ref()
                .map_or_else(JsonCreditsV2::unavailable, CodexUsage::credits_json_v2),
            next_reset: self.next_reset().map(|at| at.to_string()),
            session_reset: reset_of(&WindowKind::Session),
            weekly_reset: reset_of(&WindowKind::WeeklyAll),
        }
    }
}

#[cfg(test)]
#[path = "account_tests.rs"]
mod tests;
