//! Supervised Remote Control disconnect/reconnect. Observations only reject;
//! a fresh operator attestation is the sole authority for each input group.

use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

use serde::Serialize;

use crate::commands::Attestation;
use crate::commands::Prompt;
use crate::provider::claude::claude_json::ConfigReport;
use crate::provider::claude::discovery::MAX_CLAUDE_JSON_BYTES;
use crate::provider::claude::live_sessions;
use crate::provider::claude::live_sessions::DetailedScan;
use crate::provider::claude::live_sessions::DetailedSession;
use crate::provider::claude::live_sessions::Reread;
use crate::provider::claude::live_sessions::Scan;
use crate::provider::claude::live_sessions::State;
use crate::provider::claude::oauth::PROFILE_TIMEOUT;
use crate::provider::claude::oauth::TOKEN_TIMEOUT;
use crate::provider::claude::swap::Outcome;
use crate::runtime::cleanup;
use crate::runtime::cleanup::ExitNotice;
use crate::runtime::coordinator::PassCtx;
use crate::runtime::proc;
use crate::runtime::signals;
use crate::runtime::tmux;
use crate::runtime::tmux::CaptureVerdict;
use crate::runtime::tmux::Keys;
use crate::secret::audit::ConfigOutcome;
use crate::secret::config_lock::CONTENTION_LADDER;
use crate::secret::file_store;
use crate::secret::security_cli::READ_TIMEOUT;

/// Operator-latency budget for the entire disconnect stage.
pub const RC_DISCONNECT_BUDGET: Duration = Duration::from_secs(30);
/// Reserve for every bounded post-stage network/read/config-lock wait.
pub const RC_STAGE_RESERVE: Duration = TOKEN_TIMEOUT
    .saturating_add(PROFILE_TIMEOUT)
    .saturating_add(READ_TIMEOUT.saturating_mul(2))
    .saturating_add(CONTENTION_LADDER[0].saturating_mul(2))
    .saturating_add(CONTENTION_LADDER[1].saturating_mul(2))
    .saturating_add(CONTENTION_LADDER[2].saturating_mul(2))
    .saturating_add(Duration::from_secs(5));
/// A shorter stage never starts.
pub const RC_STAGE_MIN: Duration = Duration::from_secs(5);
/// Polling cadence, including cancellation while a question is open.
pub const RC_POLL: Duration = Duration::from_millis(250);
/// Empirical panel mount gap, not an input-readiness guarantee.
pub const RC_PANEL_SETTLE: Duration = Duration::from_secs(1);
/// Locally unchanged registry observations, not an input-readiness guarantee.
pub const RC_QUIET: Duration = Duration::from_secs(1);
/// Empirical account reconciliation margin, not proof of account or history.
pub const RC_RECONNECT_SETTLE: Duration = Duration::from_secs(25);
/// Bridge liveness observation window, never an account-ownership check.
pub const RC_RECONNECT_CONFIRM: Duration = RC_RECONNECT_SETTLE;
/// One fresh per-pane/group answer's maximum wait.
pub const RC_ATTEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Candidate floor for the operator's first AC167 build; S13 verifies it.
pub const RC_MIN_VERSION: (u32, u32, u32) = (2, 1, 281);
/// Provisional only: no AC167 record exists until the operator completes S13.
pub const RC_LAST_VERIFIED_VERSION: (u32, u32, u32) = (2, 1, 281);

/// The exact disclosure shared by the question and the README source assertion.
pub const RESIDUAL: &str = "A wrong attestation can put /remote-control into a draft as model text, or Enter into a prompt that opened after the registry's last write. Mode/settings changes not yet landed, concurrent typing, misattested live-store provenance, rebinding and command collisions remain possible. A screen check cannot exclude typing or a render change before delivery; custom keybindings or command collisions can change what the keys do. The reconnect wait is empirical, and a connected bridge does not prove the intended account or retained history.";

/// Only these eleven integer counts reach the outcome's Remote Control object.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct Counts {
    /// Live bridged sessions with validated panes at discovery.
    pub eligible: usize,
    /// Sessions observed unbridged after starting their disconnect sequence.
    pub disconnected: usize,
    /// New bridges observed stable after an applied, config-complete swap.
    pub reconnected: usize,
    /// Bridges observed stable after restoring an unchanged account.
    pub restored: usize,
    /// Eligible sessions that neither disappeared nor disconnected.
    pub not_disconnected: usize,
    /// Disconnected sessions without confirmed reconnection.
    pub not_confirmed: usize,
    /// Sessions whose required checks rejected an input attempt.
    pub skipped: usize,
    /// Sessions that disappeared or were already unbridged before opening.
    pub gone: usize,
    /// Reconnect attempts requiring no input because a bridge was already set.
    pub already_connected: usize,
    /// Input groups without a complete answer before the deadline.
    pub not_attested: usize,
    /// Input groups explicitly declined with a complete non-y answer.
    pub attestation_declined: usize,
}

/// Action after the swap releases all namespace and Claude Code locks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Config and item both changed; wait, then request a fresh bridge.
    Reconnect,
    /// The item did not change; best-effort restore, still freshly attested.
    Restore,
    /// Applied item, but config recovery must precede manual reconnection.
    ConfigRecovery,
    /// Item outcome unknown; status must precede manual reconnection.
    StatusRecovery,
    /// An already-active pass cannot have disconnected a session.
    None,
}

/// Exhaustive mapping keeps new swap outcomes from silently requesting input.
pub fn action(outcome: &Outcome, config: Option<&ConfigReport>) -> Action {
    match outcome {
        Outcome::Applied
            if config.is_some_and(|report| report.outcome == ConfigOutcome::Applied) =>
        {
            Action::Reconnect
        }
        Outcome::Applied => Action::ConfigRecovery,
        Outcome::Unknown => Action::StatusRecovery,
        Outcome::AlreadyActive => Action::None,
        Outcome::Refused(_)
        | Outcome::Cancelled
        | Outcome::Failed
        | Outcome::NeedsRefresh
        | Outcome::Discarded
        | Outcome::Busy => Action::Restore,
    }
}

/// Shared by outcome warnings and the signal thread's counts-only notice.
pub fn not_confirmed_warning(count: usize) -> String {
    format!(
        "Remote Control was not confirmed reconnected in {count} session(s); run /remote-control there manually."
    )
}

/// Failure prose is computed only from the exported counts and the recovery action.
pub fn warnings(counts: &Counts, action: Action) -> Vec<String> {
    let mut result = Vec::new();
    if counts.not_disconnected != 0 {
        result.push(format!("Remote Control did not disconnect in {} session(s); no swap was made. If a status panel remains open, press Escape there.", counts.not_disconnected));
    }
    if counts.not_confirmed != 0 {
        result.push(not_confirmed_warning(counts.not_confirmed));
    }
    if counts.skipped != 0 {
        result.push(format!(
            "Remote Control input was skipped in {} session(s) because a required check failed.",
            counts.skipped
        ));
    }
    if counts.not_attested != 0 {
        result.push(format!("Remote Control attestation was not obtained for {} input group(s); no input was sent for those groups.", counts.not_attested));
    }
    if counts.attestation_declined != 0 {
        result.push(format!("Remote Control attestation was declined for {} input group(s); no input was sent for those groups.", counts.attestation_declined));
    }
    if counts.disconnected != 0 {
        match action {
            Action::ConfigRecovery => result.push(format!("Run the config recovery command reported above, then /remote-control in {} session(s).", counts.disconnected)),
            Action::StatusRecovery => result.push(format!("Run agctl claude status, then /remote-control in {} session(s).", counts.disconnected)),
            Action::Reconnect | Action::Restore | Action::None => {}
        }
    }
    result
}

/// Three ASCII unsigned-decimal components only; conversion rejects overflow.
pub fn parse_version(value: &str) -> Option<(u32, u32, u32)> {
    let mut components = value.split('.');
    let mut number = || {
        let part = components.next()?;
        if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        part.parse().ok()
    };
    let version = (number()?, number()?, number()?);
    components.next().is_none().then_some(version)
}

fn version_text((major, minor, patch): (u32, u32, u32)) -> String {
    format!("{major}.{minor}.{patch}")
}

/// Fixes the stage end behind the pass reserve, rejecting insufficient time.
pub fn stage_deadline(now: Instant, stage_limit: Option<Instant>) -> Option<Instant> {
    let end = stage_limit?.min(now.checked_add(budget(RC_DISCONNECT_BUDGET))?);
    (end.saturating_duration_since(now) >= RC_STAGE_MIN).then_some(end)
}

/// Actual whole-second window shown when constructing the consent question.
pub fn stage_window(now: Instant, stage_limit: Option<Instant>) -> u64 {
    stage_limit.map_or(0, |end| {
        end.saturating_duration_since(now).min(budget(RC_DISCONNECT_BUDGET)).as_secs()
    })
}

/// Settle plus one bounded answer per session, independent confirmation windows, and margin.
pub fn reconnect_budget(sessions: usize) -> Duration {
    budget(
        RC_RECONNECT_SETTLE
            .saturating_add(RC_RECONNECT_CONFIRM)
            .saturating_add(
                RC_ATTEST_TIMEOUT.saturating_mul(u32::try_from(sessions).unwrap_or(u32::MAX)),
            )
            .saturating_add(Duration::from_secs(10)),
    )
}

#[cfg(feature = "testing")]
fn budget(default: Duration) -> Duration {
    std::env::var("AGCTL_RC_BUDGET_MS")
        .ok()
        .and_then(|value| value.parse().ok())
        .map(Duration::from_millis)
        .unwrap_or(default)
}
#[cfg(not(feature = "testing"))]
fn budget(default: Duration) -> Duration {
    default
}

/// This reads only the already-known live config. Passing is not mode verification.
pub fn config_mode_permits(path: &Path) -> bool {
    let Ok(file_store::ReadOutcome::Present { bytes, .. }) =
        file_store::read_file_following(path, MAX_CLAUDE_JSON_BYTES)
    else {
        return false;
    };
    let Ok(serde_json::Value::Object(document)) = serde_json::from_slice(&bytes) else {
        return false;
    };
    match document.get("editorMode") {
        None => true,
        Some(serde_json::Value::String(mode)) => mode == "normal",
        Some(_) => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Group {
    Opening,
    Disconnect,
    Reconnect,
    Restore,
}
impl Group {
    fn keys(self) -> Keys {
        if self == Self::Disconnect { Keys::Disconnect } else { Keys::RemoteControl }
    }
    fn operation(self) -> &'static str {
        match self {
            Self::Opening => "opening",
            Self::Disconnect => "expected-panel disconnect",
            Self::Reconnect => "reconnect",
            Self::Restore => "restore",
        }
    }
    fn connecting(self) -> bool {
        matches!(self, Self::Reconnect | Self::Restore)
    }
}

fn question(session: &DetailedSession, group: Group) -> String {
    format!(
        "Session {} in {}: agctl will type {} for {}. Attest that this session uses the live store, its complete input line is empty, and its editor is not in vim mode. Type y to attest for this group only; any other answer stops this attempt. This question consumes the remaining stage time. [y/N]",
        session.name.as_deref().unwrap_or("unnamed"),
        session.pane.as_ref().map_or("", |pane| pane.as_str()),
        group.keys().description(),
        group.operation()
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum GroupResult {
    Sent,
    Gone,
    Disconnected,
    AlreadyConnected,
    Skipped(&'static str),
    Expired,
    Unattested(Attestation),
}

/// One session's state for local quiet observation; a backdated timestamp cannot replace this.
#[derive(Default)]
struct Quiet {
    observed: Option<(State, Instant)>,
}
impl Quiet {
    fn ready(&mut self, state: &State, group: Group, now: Instant, epoch_ms: i64) -> bool {
        if self.observed.as_ref().is_none_or(|(prior, _)| prior != state) {
            self.observed = Some((state.clone(), now));
        }
        let shape = if group == Group::Disconnect {
            state.status == "waiting" && state.waiting_for.as_deref() == Some("dialog open")
        } else {
            state.status == "idle" && state.waiting_for.is_none()
        };
        shape
            && epoch_ms
                .checked_sub(state.status_updated_at)
                .is_some_and(|age| age >= RC_QUIET.as_millis() as i64)
            && self
                .observed
                .as_ref()
                .is_some_and(|(_, since)| now.saturating_duration_since(*since) >= RC_QUIET)
    }
}

fn observe(session: &DetailedSession, group: Group, read: Reread) -> Result<State, GroupResult> {
    let state = match read {
        Reread::Gone => return Err(GroupResult::Gone),
        Reread::Replaced | Reread::Unrecognized => {
            return Err(GroupResult::Skipped("registry_unrecognized"));
        }
        Reread::State(state) => state,
    };
    if session.pane.as_ref() != Some(&state.pane) {
        return Err(GroupResult::Skipped("pane_changed"));
    }
    if group.connecting() {
        if state.bridge_on {
            return Err(GroupResult::AlreadyConnected);
        }
    } else {
        if !state.bridge_on {
            return Err(if group == Group::Opening {
                GroupResult::Gone
            } else {
                GroupResult::Disconnected
            });
        }
        if !state.same_bridge {
            return Err(GroupResult::Skipped("bridge_changed"));
        }
    }
    Ok(state)
}

fn foreground(
    proof: Option<proc::TtyForeground>,
    pane: &tmux::PaneState,
    rdev: Option<u32>,
) -> Result<(), &'static str> {
    let Some(proof) = proof else { return Err("foreground_unreadable") };
    if proof.holder != proc::Holder::Alive {
        return Err("stopped_or_dead");
    }
    if proof.pgid == 0 || proof.pgid != proof.tpgid {
        return Err("not_in_foreground");
    }
    if proof.tdev == u32::MAX || Some(proof.tdev) != rdev {
        return Err("another_terminal");
    }
    if pane.in_mode {
        return Err("copy_mode");
    }
    if pane.dead {
        return Err("dead_pane");
    }
    if pane.synchronized {
        return Err("synchronized");
    }
    Ok(())
}

struct Stage<'a> {
    dir: &'a Path,
    config: &'a Path,
    bin: &'a Path,
    ctx: &'a PassCtx,
    end: Instant,
    notice: &'a ExitNotice,
}
impl Stage<'_> {
    fn running(&self) -> bool {
        !self.ctx.cancel().is_cancelled() && Instant::now() < self.end
    }

    fn foreground(&self, session: &DetailedSession) -> Result<(), &'static str> {
        if !self.running() {
            return Err("stage_expired");
        }
        let Some(pane) = &session.pane else { return Err("pane_unrecognized") };
        let pane =
            tmux::pane_state(self.bin, pane, self.ctx, self.end).map_err(|_| "pane_unreadable")?;
        let rdev = rustix::fs::stat(&pane.tty)
            .ok()
            .filter(|stat| {
                rustix::fs::FileType::from_raw_mode(stat.st_mode)
                    == rustix::fs::FileType::CharacterDevice
            })
            .map(|stat| stat.st_rdev as u32);
        foreground(proc::tty_foreground(session.key.pid()), &pane, rdev)
    }

    fn group(
        &self,
        session: &DetailedSession,
        group: Group,
        prompt: &mut dyn Prompt,
    ) -> GroupResult {
        let mut quiet = Quiet::default();
        let before = loop {
            if !self.running() {
                return GroupResult::Expired;
            }
            let state = match observe(session, group, live_sessions::reread(self.dir, &session.key))
            {
                Ok(state) => state,
                Err(result) => return result,
            };
            if quiet.ready(&state, group, Instant::now(), jiff::Timestamp::now().as_millisecond()) {
                break state;
            }
            self.ctx
                .cancel()
                .wait_timeout(RC_POLL.min(self.end.saturating_duration_since(Instant::now())));
        };
        if let Err(reason) = self.foreground(session) {
            return GroupResult::Skipped(reason);
        }
        if !config_mode_permits(self.config) {
            return GroupResult::Skipped("config_mode_rejected");
        }
        let Some(pane) = &session.pane else { return GroupResult::Skipped("pane_unrecognized") };
        let verdict = tmux::capture(self.bin, pane, group.keys(), self.ctx, self.end);
        if verdict != CaptureVerdict::NoRejection {
            return GroupResult::Skipped(verdict.reason());
        }
        if !self.running() {
            return GroupResult::Unattested(Attestation::NotObtained);
        }
        let end =
            Instant::now().checked_add(RC_ATTEST_TIMEOUT).map_or(self.end, |end| end.min(self.end));
        let answer = if prompt.can_ask() {
            prompt.attest(&question(session, group), end, self.ctx.cancel())
        } else {
            Attestation::NotObtained
        };
        if !self.running() {
            return GroupResult::Unattested(Attestation::NotObtained);
        }
        if answer != Attestation::Yes {
            return GroupResult::Unattested(answer);
        }
        // Only file reads occur between capture and send. Any observed tuple
        // change invalidates the human answer, including an observed bridge change.
        if live_sessions::reread(self.dir, &session.key) != Reread::State(before) {
            return GroupResult::Skipped("attestation_stale");
        }
        if !self.running() {
            return GroupResult::Unattested(Attestation::NotObtained);
        }
        if group == Group::Opening {
            self.notice.begin();
        }
        match tmux::send(self.bin, pane, group.keys(), self.ctx, self.end) {
            Ok(()) => GroupResult::Sent,
            Err(_) => GroupResult::Skipped("send_failed"),
        }
    }
}

struct Progress {
    session: DetailedSession,
    opened: bool,
    sent: bool,
    disconnected: bool,
    gone: bool,
}

/// State carried past `swap_phases` so reconnect runs after every lock drops.
pub struct RemoteControl {
    dir: PathBuf,
    config: PathBuf,
    sessions: Vec<Progress>,
    /// The ineligible sessions retain the original non-automation hint.
    pub hint: Scan,
    /// The eleven output counts; no session identity is serializable.
    pub counts: Counts,
    stage_limit: Option<Instant>,
    bin: Option<PathBuf>,
}

impl RemoteControl {
    /// Builds a live-only plan from Phase A's single detailed scan.
    pub fn new(scan: DetailedScan, dir: PathBuf, config: PathBuf, ctx: &PassCtx) -> Self {
        let mut hint = scan.hint;
        if let Scan::Read { remote, .. } = &mut hint {
            *remote = scan
                .sessions
                .iter()
                .filter(|session| session.pane.is_none())
                .map(|session| live_sessions::RemoteSession { name: session.name.clone() })
                .collect();
        }
        let sessions: Vec<_> = scan
            .sessions
            .into_iter()
            .filter(|session| session.pane.is_some())
            .map(|session| Progress {
                session,
                opened: false,
                sent: false,
                disconnected: false,
                gone: false,
            })
            .collect();
        Self {
            counts: Counts { eligible: sessions.len(), ..Counts::default() },
            dir,
            config,
            sessions,
            hint,
            stage_limit: ctx.deadline().checked_sub(RC_STAGE_RESERVE),
            bin: None,
        }
    }

    /// Newer versions warn once each, before consent; they are not rejected by the ceiling.
    pub fn version_notes(&self) -> Vec<String> {
        let mut versions: Vec<_> = self
            .sessions
            .iter()
            .filter_map(|item| item.session.state.as_ref())
            .filter_map(|state| parse_version(&state.version))
            .filter(|version| *version > RC_LAST_VERIFIED_VERSION)
            .collect();
        versions.sort_unstable();
        versions.dedup();
        versions
            .into_iter()
            .map(|version| {
                format!(
                    "Remote Control automation was last verified on {}; this session runs {}",
                    version_text(RC_LAST_VERIFIED_VERSION),
                    version_text(version)
                )
            })
            .collect()
    }

    /// The flag's TTY-only sentence, with a real remaining stage window.
    pub fn consent_clause(&self, now: Instant) -> Option<String> {
        if self.sessions.is_empty() {
            return None;
        }
        let mut parts: Vec<_> = self
            .sessions
            .iter()
            .take(3)
            .map(|item| {
                let pane = item.session.pane.as_ref().map_or("", |pane| pane.as_str());
                item.session
                    .name
                    .as_ref()
                    .map_or_else(|| pane.to_owned(), |name| format!("`{name}` in {pane}"))
            })
            .collect();
        if self.sessions.len() > 3 {
            parts.push(format!("and {} more", self.sessions.len() - 3));
        }
        let k = self.sessions.len();
        let s = if k == 1 { "" } else { "s" };
        let list = parts.join(", ");
        let secs = stage_window(now, self.stage_limit);
        Some(format!(
            ". With --restart-remote-control, agctl will type /remote-control and the disconnect keys into {k} tmux pane{s} ({list}) before the swap, wait up to {secs} seconds, less the time this question stays open, for Remote Control to stop there, and type /remote-control there again after the swap. If any of them does not disconnect in time, agctl makes no swap and tries to start Remote Control again in the ones it disconnected. agctl cannot tell which of these sessions use this store; you must attest live-store use, empty input and non-vim editing separately for every pane and input group. {RESIDUAL}"
        ))
    }

    /// All-session preflight, then one disconnect sequence each. False forbids the swap.
    pub fn disconnect(&mut self, ctx: &PassCtx, prompt: &mut dyn Prompt) -> bool {
        let started = Instant::now();
        let notice = cleanup::register_exit_notice(0, not_confirmed_warning);
        let success = self.disconnect_inner(ctx, prompt, &notice);
        signals::defer_to_exit();
        self.counts.not_disconnected = self
            .counts
            .eligible
            .saturating_sub(self.counts.disconnected)
            .saturating_sub(self.counts.gone);
        tracing::info!(stage = "disconnect", counts = ?self.counts, elapsed_ms = started.elapsed().as_millis(), "Remote Control stage");
        success
    }

    fn disconnect_inner(
        &mut self,
        ctx: &PassCtx,
        prompt: &mut dyn Prompt,
        notice: &ExitNotice,
    ) -> bool {
        if self.sessions.is_empty() {
            return true;
        }
        let Some(end) = stage_deadline(Instant::now(), self.stage_limit) else { return false };
        if ctx.cancel().is_cancelled() {
            return false;
        }
        let Some(bin) = self.bin.clone().or_else(|| tmux::resolve_tmux_bin().ok()) else {
            self.counts.skipped = self.sessions.len();
            return false;
        };
        self.bin = Some(bin.clone());
        let stage = Stage { dir: &self.dir, config: &self.config, bin: &bin, ctx, end, notice };
        let mut panes = BTreeMap::new();
        for item in &self.sessions {
            if let Some(pane) = &item.session.pane {
                *panes.entry(pane.as_str().to_owned()).or_insert(0_usize) += 1;
            }
        }
        let mut failed = false;
        for item in &mut self.sessions {
            if !stage.running() {
                return false;
            }
            let result = if item.session.pane.as_ref().is_some_and(|pane| panes[pane.as_str()] > 1)
            {
                Err(GroupResult::Skipped("duplicate_pane"))
            } else {
                observe(
                    &item.session,
                    Group::Opening,
                    live_sessions::reread(&self.dir, &item.session.key),
                )
                .and_then(|state| {
                    if parse_version(&state.version).is_none_or(|version| version < RC_MIN_VERSION)
                    {
                        return Err(GroupResult::Skipped("version_rejected"));
                    }
                    stage.foreground(&item.session).map_err(GroupResult::Skipped)?;
                    if proc::ancestor_of_self(item.session.key.pid()) {
                        return Err(GroupResult::Skipped("ancestor_of_agctl"));
                    }
                    Ok(state)
                })
            };
            match result {
                Ok(_) => {}
                Err(GroupResult::Gone) => {
                    item.gone = true;
                    self.counts.gone += 1;
                }
                Err(result) => {
                    record_failure(&mut self.counts, &result, prompt);
                    failed = true;
                }
            }
        }
        if failed {
            return false;
        }
        for item in &mut self.sessions {
            if item.gone {
                continue;
            }
            let result = stage.group(&item.session, Group::Opening, prompt);
            match result {
                GroupResult::Sent => item.opened = true,
                GroupResult::Gone => {
                    item.gone = true;
                    self.counts.gone += 1;
                    continue;
                }
                other => {
                    record_failure(&mut self.counts, &other, prompt);
                    failed = true;
                    break;
                }
            }
            if ctx
                .cancel()
                .wait_timeout(RC_PANEL_SETTLE.min(end.saturating_duration_since(Instant::now())))
                || !stage.running()
            {
                failed = true;
                break;
            }
            match stage.group(&item.session, Group::Disconnect, prompt) {
                GroupResult::Sent => item.sent = true,
                GroupResult::Disconnected => {
                    item.disconnected = true;
                    self.counts.disconnected += 1;
                }
                GroupResult::Gone => {
                    item.gone = true;
                    self.counts.gone += 1;
                    notice.confirmed();
                }
                other => {
                    record_failure(&mut self.counts, &other, prompt);
                    failed = true;
                    break;
                }
            }
        }
        loop {
            let mut pending = false;
            for item in &mut self.sessions {
                if !item.opened || item.gone || item.disconnected {
                    continue;
                }
                match live_sessions::reread(&self.dir, &item.session.key) {
                    Reread::Gone => {
                        item.gone = true;
                        self.counts.gone += 1;
                        notice.confirmed();
                    }
                    Reread::State(state) if !state.bridge_on => {
                        item.disconnected = true;
                        self.counts.disconnected += 1;
                    }
                    Reread::State(state) if state.same_bridge => pending = true,
                    Reread::State(_) | Reread::Replaced | Reread::Unrecognized => {
                        self.counts.skipped += 1;
                        failed = true;
                    }
                }
            }
            if failed || !pending || !stage.running() {
                break;
            }
            ctx.cancel().wait_timeout(RC_POLL.min(end.saturating_duration_since(Instant::now())));
        }
        !failed
            && !ctx.cancel().is_cancelled()
            && self.sessions.iter().all(|item| item.disconnected || item.gone)
    }

    /// Outside all swap locks, attempts at most one freshly attested reconnect per disconnected session.
    pub fn finish(&mut self, ctx: &PassCtx, prompt: &mut dyn Prompt, action: Action) {
        if self.counts.disconnected == 0 {
            return;
        }
        let started = Instant::now();
        let notice = cleanup::register_exit_notice(self.counts.disconnected, not_confirmed_warning);
        self.finish_inner(ctx, prompt, action, started, &notice);
        signals::defer_to_exit();
        tracing::info!(stage = if action == Action::Restore { "restore" } else { "reconnect" }, counts = ?self.counts, elapsed_ms = started.elapsed().as_millis(), "Remote Control stage");
        if ctx.cancel().is_cancelled() {
            prompt.tell(&not_confirmed_warning(self.counts.not_confirmed));
        }
    }

    fn finish_inner(
        &mut self,
        ctx: &PassCtx,
        prompt: &mut dyn Prompt,
        action: Action,
        started: Instant,
        notice: &ExitNotice,
    ) {
        if !matches!(action, Action::Reconnect | Action::Restore) || ctx.cancel().is_cancelled() {
            self.counts.not_confirmed = self.counts.disconnected;
            return;
        }
        let Some(bin) = &self.bin else {
            self.counts.not_confirmed = self.counts.disconnected;
            return;
        };
        let end =
            started.checked_add(reconnect_budget(self.counts.disconnected)).unwrap_or(started);
        if action == Action::Reconnect {
            ctx.cancel().wait_timeout(
                RC_RECONNECT_SETTLE.min(end.saturating_duration_since(Instant::now())),
            );
        }
        let stage = Stage { dir: &self.dir, config: &self.config, bin, ctx, end, notice };
        let group = if action == Action::Restore { Group::Restore } else { Group::Reconnect };
        std::thread::scope(|scope| {
            let mut pending = Vec::new();
            for item in self.sessions.iter().filter(|item| item.disconnected) {
                if !stage.running() {
                    self.counts.not_confirmed += 1;
                    continue;
                }
                match stage.group(&item.session, group, prompt) {
                    GroupResult::Sent => {
                        let stage = &stage;
                        let session = &item.session;
                        // Start observing this bridge immediately after its own
                        // send, including while the next human question is open.
                        // These workers only reread files; they never type or log.
                        match std::thread::Builder::new().spawn_scoped(scope, move || {
                            let mut first_on = None;
                            while stage.running() {
                                let read = live_sessions::reread(stage.dir, &session.key);
                                let now = Instant::now();
                                if !stage.running() {
                                    return false;
                                }
                                match read {
                                    Reread::State(state) if state.bridge_on => {
                                        let since = *first_on.get_or_insert(now);
                                        if now.saturating_duration_since(since)
                                            >= RC_RECONNECT_CONFIRM
                                        {
                                            stage.notice.confirmed();
                                            return true;
                                        }
                                    }
                                    Reread::State(_) if first_on.is_none() => {}
                                    Reread::State(_)
                                    | Reread::Gone
                                    | Reread::Replaced
                                    | Reread::Unrecognized => return false,
                                }
                                stage.ctx.cancel().wait_timeout(
                                    RC_POLL
                                        .min(stage.end.saturating_duration_since(Instant::now())),
                                );
                            }
                            false
                        }) {
                            Ok(worker) => pending.push(worker),
                            Err(_) => self.counts.not_confirmed += 1,
                        }
                    }
                    GroupResult::AlreadyConnected => {
                        self.counts.already_connected += 1;
                        notice.confirmed();
                    }
                    GroupResult::Gone => {
                        self.counts.gone += 1;
                        notice.confirmed();
                    }
                    other => {
                        record_failure(&mut self.counts, &other, prompt);
                        self.counts.not_confirmed += 1;
                    }
                }
            }
            for worker in pending {
                if worker.join().unwrap_or(false) {
                    if action == Action::Restore {
                        self.counts.restored += 1;
                    } else {
                        self.counts.reconnected += 1;
                    }
                } else {
                    self.counts.not_confirmed += 1;
                }
            }
        });
    }
}

fn record_failure(counts: &mut Counts, result: &GroupResult, prompt: &mut dyn Prompt) {
    signals::defer_to_exit();
    match result {
        GroupResult::Skipped(reason) => {
            counts.skipped += 1;
            prompt.tell(&format!("Remote Control input skipped: {reason}."));
        }
        GroupResult::Unattested(Attestation::Declined) => counts.attestation_declined += 1,
        GroupResult::Unattested(Attestation::NotObtained) => counts.not_attested += 1,
        GroupResult::Sent
        | GroupResult::Gone
        | GroupResult::Disconnected
        | GroupResult::AlreadyConnected
        | GroupResult::Expired
        | GroupResult::Unattested(Attestation::Yes) => {}
    }
}

#[cfg(test)]
#[path = "remote_control_tests.rs"]
mod tests;
