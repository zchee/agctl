//! The one path by which agctl sends a Codex refresh (decision D-035, plan
//! section 3.3, invariant I26).
//!
//! # The order
//!
//! [`run`] is the only caller of [`oauth::refresh`] and takes the namespace
//! lock itself, so the order that makes a send safe cannot be split across
//! callers (plan ledger #283 ruling 2):
//!
//! 1. **The time check, before the lock:** the caller's deadline must leave
//!    the lock budget + [`REFRESH_POST_BUDGET`] + [`WRITE_ALLOWANCE`], else
//!    `stale` and nothing is sent.
//! 2. The lock, through S30's typestate (`lock::acquire_codex` → a
//!    `CodexNamespaceGuard`); `busy` when the budget runs out.
//! 3. **`resolve_pending` first:** a grant a crashed pass parked is replayed,
//!    which changes the file's digest, so a marker it left is recognised as
//!    stale below rather than stranded. A resolver error sends nothing
//!    (review S30 INFO-1).
//! 4. The read (a torn file is retried once after 50 ms).
//! 5. The marker, then the mode's own gates:
//!    - **Proactive** — marker compare → daemon evidence → fresh? adopt →
//!      server floor → send. No 401 floor.
//!    - **AfterUnauthorized** — the file's access digest differs from the
//!      rejected one? adopt → marker compare → daemon evidence → terminal /
//!      401 floor → server floor → send.
//!    - **Resend** — the marker must record this grant as unknown → not
//!      already re-sent → `since + 1 h` (`max(retry-after, 1 h)` for
//!      `rate_limited`) → no stray staged temporary → daemon evidence → send.
//! 6. The send: a pre-POST re-read (a changed file is adopted when fresh,
//!    never fought) → the marker written and `fsync`ed, yielding the token
//!    the POST consumes → [`oauth::refresh`].
//! 7. The outcome (below). The marker is cleared only on a definite one.
//!
//! # Outcomes
//!
//! - **Applied:** re-read under the lock; merge onto the current document
//!   when it still holds the grant sent; write with `StopPolicy::Complete`
//!   (inside writer 1). A write that fails is retried a bounded number of
//!   times — never `?`ed — and after each failure the file is re-read, so a
//!   write that landed before reporting an error is not written twice (review
//!   S30 LOW-1, INFO-4). If none lands, the grant is parked as pending; if
//!   that fails too, the outcome is `unknown (write_failed)` and the marker
//!   stays, so no second POST is sent.
//! - **Permanent:** the file changed → the other writer's grant is kept
//!   (`refresh raced an external writer`); unchanged → `needs login`, and the
//!   dead grant is recorded so later passes send nothing for it.
//! - **PreSend / Rejected:** marker cleared, `stale`.
//! - **RateLimited / ServerError / Ambiguous:** marker kept, class recorded,
//!   `refresh outcome unknown`, no automatic re-send (risk R63).
//!
//! Every landed write's receipt goes to `codex::audit::append`; a log that
//! refuses the entry leaves the write standing, logged at `warn` and noted as
//! `audit log refused` (plan AC117).

use std::thread;
use std::time::Duration;
use std::time::Instant;

use jiff::SignedDuration;
use jiff::Timestamp;

use crate::config::codex::RefreshPolicy;
use crate::config::paths::Paths;
use crate::error::AppError;
use crate::provider::codex::audit;
use crate::provider::codex::audit::CodexEvent;
use crate::provider::codex::auth_store::CodexWrite;
use crate::provider::codex::auth_store::DefiniteOutcome;
use crate::provider::codex::auth_store::EarliestRefresh;
use crate::provider::codex::auth_store::NamespaceRead;
use crate::provider::codex::auth_store::OwnedNamespace;
use crate::provider::codex::auth_store::RefreshState;
use crate::provider::codex::auth_store::RefreshStateRead;
use crate::provider::codex::auth_store::Settled;
use crate::provider::codex::auth_store::UnknownClass;
use crate::provider::codex::credentials::ACCESS_REFRESH_MARGIN;
use crate::provider::codex::credentials::LockedCredentials;
use crate::provider::codex::credentials::RefreshResponse;
use crate::provider::codex::home::DaemonEvidence;
use crate::provider::codex::lock;
use crate::provider::codex::lock::LockBudget;
use crate::provider::codex::oauth;
use crate::provider::codex::oauth::AmbiguousClass;
use crate::provider::codex::oauth::PermanentClass;
use crate::provider::codex::oauth::RefreshClient;
use crate::provider::codex::oauth::RefreshOutcome;
use crate::provider::codex::proof::OwnedRecord;
use crate::runtime::coordinator::Cancel;
use crate::runtime::fault::Fault;
use crate::secret::file_store::FileStoreError;
use crate::secret::file_store::WriteOutcome;
use crate::secret::namespace_lock::LockError;
use crate::secret::pending::PendingDecision;

/// The sum of the refresh agent's six phase timeouts: the only sound "POST
/// timeout", because `ureq`'s phase timers chain (decision D-035's budget
/// table). 19 s.
pub const REFRESH_POST_BUDGET: Duration = sum(oauth::PHASE_TIMEOUTS);

/// Time kept after the POST for the credential write.
pub const WRITE_ALLOWANCE: Duration = Duration::from_secs(1);

/// The lock budget a `status` pass uses (decision D-035).
pub const PASS_LOCK_BUDGET: Duration = Duration::from_secs(1);

/// How long a `refresh outcome unknown` waits before the user's one
/// `--resend` (U45: kept at one hour; ledger #282).
pub const RESEND_WAIT: Duration = Duration::from_secs(60 * 60);

/// Sent refreshes followed by a 401 before the row is terminal.
pub const TERMINAL_DID_NOT_HELP: u8 = 3;

/// The longest `retry-after` the marker records (review S32-C1 carry): a
/// server value beyond it is clamped, so a hostile or broken header cannot
/// postpone `--resend` indefinitely.
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(24 * 60 * 60);

/// How far ahead an `earliest_refresh_at` may lie (review S32-C1 carry): the
/// fact F80 value is nine days after issue; anything past thirty is clamped.
pub const MAX_EARLIEST_REFRESH_AHEAD: SignedDuration = SignedDuration::from_hours(30 * 24);

/// The wait before a torn file is read again (plan AC94).
const TORN_RETRY: Duration = Duration::from_millis(50);

/// Writes attempted after an applied response before it is parked.
const POST_APPLIED_ATTEMPTS: u32 = 3;

/// Aborts between the durable marker and the POST (plan AC128 (1)).
const FAULT_ABORT_AFTER_MARKER: &str = "codex_abort_after_marker";
/// Aborts between a parked grant and the marker clear (plan AC128 (8)).
const FAULT_ABORT_AFTER_PENDING: &str = "codex_abort_after_pending";
/// Pauses before the pre-POST re-read (plan AC124 (b)).
const PAUSE_BEFORE_POST_SNAPSHOT: &str = "codex_before_post_snapshot";
/// Pauses after the marker, immediately before the POST (plan AC124 (a)).
const PAUSE_AFTER_POST_SNAPSHOT: &str = "codex_after_post_snapshot";

const fn sum(phases: [Duration; 6]) -> Duration {
    let mut total = Duration::ZERO;
    let mut index = 0;
    while index < phases.len() {
        total = match total.checked_add(phases[index]) {
            Some(total) => total,
            None => Duration::MAX,
        };
        index += 1;
    }
    total
}

/// Why a consent was not given.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConsentRefusal {
    /// Not an interactive terminal: neither an answer nor `--yes` counts, so a
    /// re-send or a floor reset cannot be scheduled.
    #[error("this needs an interactive terminal; `--yes` is refused when stdin is not one")]
    NotATerminal,
    /// The answer was not `yes`.
    #[error("not confirmed")]
    NotConfirmed,
}

/// The one refusal type both consents share.
pub type ResendRefusal = ConsentRefusal;
/// The one refusal type both consents share.
pub type ResetRefusal = ConsentRefusal;

fn confirmed(answer: &str, stdin_is_tty: bool, yes_flag: bool) -> Result<(), ConsentRefusal> {
    if !stdin_is_tty {
        return Err(ConsentRefusal::NotATerminal);
    }
    if yes_flag || answer.trim().eq_ignore_ascii_case("yes") {
        Ok(())
    } else {
        Err(ConsentRefusal::NotConfirmed)
    }
}

/// The user's confirmation of one `accounts refresh --resend` (risk R63).
///
/// The field is private, so `commands/` cannot build one except through
/// [`ResendConsent::after_confirmation`], whose single call site is pinned
/// (plan AC119, AC122 clause 10).
#[derive(Debug)]
pub struct ResendConsent(());

impl ResendConsent {
    /// A consent, when stdin is a terminal and the user answered `yes` or
    /// passed `--yes`.
    ///
    /// # Errors
    ///
    /// [`ConsentRefusal`].
    pub fn after_confirmation(
        answer: &str,
        stdin_is_tty: bool,
        yes_flag: bool,
    ) -> Result<Self, ResendRefusal> {
        confirmed(answer, stdin_is_tty, yes_flag).map(|()| Self(()))
    }
}

/// The user's confirmation of one `accounts refresh --reset-floor`.
#[derive(Debug)]
pub struct ResetConsent(());

impl ResetConsent {
    /// As [`ResendConsent::after_confirmation`].
    ///
    /// # Errors
    ///
    /// [`ConsentRefusal`].
    pub fn after_confirmation(
        answer: &str,
        stdin_is_tty: bool,
        yes_flag: bool,
    ) -> Result<Self, ResetRefusal> {
        confirmed(answer, stdin_is_tty, yes_flag).map(|()| Self(()))
    }
}

/// What triggered a refresh; each has its own gates (plan ledger #227).
#[derive(Debug)]
pub enum SendMode {
    /// The access token is expired or within 300 s of it (U36).
    Proactive,
    /// `/wham/usage` answered 401 to the bearer whose digest this is.
    AfterUnauthorized {
        /// The first eight hex digits of the rejected access token's digest.
        rejected_access_digest8: String,
    },
    /// The user's audited one-shot re-send.
    Resend(ResendConsent),
}

/// What a refresh needs from its caller.
#[derive(Debug)]
pub struct RefreshCtx<'a> {
    /// The store.
    pub paths: &'a Paths,
    /// The token endpoint.
    pub client: &'a RefreshClient,
    /// When the caller's own budget runs out.
    pub deadline: Instant,
    /// How long to wait for the namespace lock.
    pub lock_budget: LockBudget,
    /// The caller's cancellation.
    pub cancel: &'a Cancel,
    /// Injected faults (empty in production).
    pub fault: &'a Fault,
}

/// Why nothing was sent and the row is `stale`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StaleReason {
    /// Less time left than the lock, the POST and the write need.
    NotEnoughTime,
    /// Cancelled before the send.
    Cancelled,
    /// `auth.json` stayed torn.
    Torn,
    /// A Codex daemon's pid record exists and cannot be read (review S30 F8).
    DaemonRecordUnreadable,
    /// The file changed before the POST and its new grant is not fresh.
    ChangedBeforePost,
    /// Proven never sent; retried on a later pass.
    PreSend(String),
    /// A 4xx answered before processing (risk R67).
    Rejected(u16),
}

/// Why no POST was needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdoptReason {
    /// The access token is not due.
    Fresh,
    /// The file's access token is not the one the server rejected: another
    /// writer refreshed; retry the GET.
    ExternalAccess,
    /// The file changed before the POST and holds a fresh grant.
    ChangedBeforePost,
}

/// Why the row needs a login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeedsLoginReason {
    /// No `auth.json`.
    Absent,
    /// No refresh token in it.
    NoRefreshToken,
    /// The token host called this grant dead.
    Dead,
    /// The user's one `--resend` was answered with this 4xx; the unknown
    /// marker stays with its re-send spent, so nothing is sent again.
    ResendRejected(u16),
}

/// Why a `--resend` was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResendBlock {
    /// The row is not `refresh outcome unknown` for this grant.
    NotUnknown,
    /// The marker's one re-send is spent.
    AlreadyResent,
    /// Not before this.
    TooEarly(Timestamp),
    /// A staged temporary may hold a rotated grant (risk R70).
    StrayTmp,
}

/// Where one refresh ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshStep {
    /// Nothing sent; try on a later pass.
    Stale(StaleReason),
    /// Another process holds the namespace lock.
    Busy,
    /// Nothing sent; the file's grant is used as it is.
    Adopted(AdoptReason),
    /// The rotated grant is on disk, or parked as pending.
    Refreshed {
        /// Parked as pending rather than renamed into place.
        parked: bool,
    },
    /// `needs login`.
    NeedsLogin(NeedsLoginReason),
    /// The server called the grant sent dead while another writer's newer
    /// grant was in the file; it was kept. The caller verifies it with one GET
    /// (plan AC124 (a)/(a′)).
    RacedExternal,
    /// The response was not written: the file holds another writer's grant.
    DiscardedExternal,
    /// `refresh outcome unknown (<class>)`; no automatic re-send.
    OutcomeUnknown {
        /// Since when.
        since: Timestamp,
        /// Why.
        class: UnknownClass,
        /// When `--resend` becomes possible; `None` once it is spent.
        resend_eligible_at: Option<Timestamp>,
    },
    /// The marker cannot be read or written; nothing sent.
    StateUnavailable(String),
    /// A live Codex daemon uses the namespace; nothing sent.
    SessionDetected(u32),
    /// A 401 inside the floor; nothing sent, not counted.
    UnauthorizedFloor {
        /// When the floor ends.
        until: Timestamp,
    },
    /// Three sent refreshes did not help; nothing sent until `login` or
    /// `--reset-floor`.
    UnauthorizedTerminal,
    /// The token host asked for no refresh of this grant before this time.
    NotBefore(Timestamp),
    /// The record's refresh policy is `never`.
    Disabled,
    /// A `--resend` was refused.
    ResendRefused(ResendBlock),
    /// Something else failed; nothing was sent after it.
    Failed(String),
}

/// Something worth a note on the row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshNote {
    /// A landed write's audit entry was refused.
    AuditLogRefused,
    /// Daemon evidence that did not stop the refresh.
    CodexSession(DaemonEvidence),
    /// The new id token names another account (fact F92).
    IdentityDrift,
    /// The new id token did not decode and the old one was kept.
    IdTokenUnreadable,
    /// A parked grant was replayed first.
    PendingReplayed,
    /// A parked grant was discarded first.
    PendingDiscarded,
    /// A marker for an older grant was cleared.
    StaleMarkerCleared,
}

/// A refresh's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshReport {
    /// Where it ended.
    pub step: RefreshStep,
    /// Notes for the row.
    pub notes: Vec<RefreshNote>,
}

/// Refreshes an owned namespace if, and only if, its mode's gates allow a
/// send. The only POST path.
pub fn run(owned: OwnedRecord<'_>, mode: SendMode, ctx: &RefreshCtx<'_>) -> RefreshReport {
    let mut notes = Vec::new();
    let step = locked_run(owned, mode, ctx, &mut notes);
    RefreshReport { step, notes }
}

fn locked_run(
    owned: OwnedRecord<'_>,
    mode: SendMode,
    ctx: &RefreshCtx<'_>,
    notes: &mut Vec<RefreshNote>,
) -> RefreshStep {
    if owned.refresh() != RefreshPolicy::Auto {
        return RefreshStep::Disabled;
    }
    let needed = ctx
        .lock_budget
        .duration()
        .checked_add(REFRESH_POST_BUDGET)
        .and_then(|needed| needed.checked_add(WRITE_ALLOWANCE));
    let left = ctx.deadline.saturating_duration_since(Instant::now());
    if needed.is_none_or(|needed| left < needed) {
        return RefreshStep::Stale(StaleReason::NotEnoughTime);
    }
    if ctx.cancel.is_cancelled() {
        return RefreshStep::Stale(StaleReason::Cancelled);
    }

    let guard = match lock::acquire_codex(ctx.paths, owned, ctx.lock_budget, ctx.cancel, ctx.fault)
    {
        Ok(guard) => guard,
        Err(LockError::Busy) => return RefreshStep::Busy,
        Err(LockError::Cancelled) => return RefreshStep::Stale(StaleReason::Cancelled),
        Err(err) => return RefreshStep::Failed(err.to_string()),
    };
    let ns = match OwnedNamespace::open(ctx.paths, owned, &guard) {
        Ok(ns) => ns,
        Err(err) => return RefreshStep::Failed(err.to_string()),
    };
    let driver = Driver { ns: &ns, ctx, ids: (owned.user(), owned.acct()) };
    driver.drive(mode, notes)
}

/// One locked refresh.
struct Driver<'n, 'g, 'c> {
    ns: &'n OwnedNamespace<'g>,
    ctx: &'n RefreshCtx<'c>,
    ids: (&'n str, &'n str),
}

/// What the marker says about the grant in the file.
enum Marker {
    /// The grant was sent and its outcome is unknown.
    Unknown { state: RefreshState, since: Timestamp, class: UnknownClass },
    /// No send of this grant is outstanding.
    Clear(RefreshState),
}

/// Whether the send records a new marker or re-sends an unknown one.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SendKind {
    Inflight,
    Resend,
}

impl<'g> Driver<'_, 'g, '_> {
    fn drive(&self, mode: SendMode, notes: &mut Vec<RefreshNote>) -> RefreshStep {
        let (decision, receipt, _evidence) = match self.ns.resolve_pending(self.ctx.cancel) {
            Ok(resolved) => resolved,
            Err(err) => {
                return RefreshStep::Failed(format!(
                    "a parked credential could not be resolved, so nothing was sent: {err}"
                ));
            }
        };
        if let Some(receipt) = receipt {
            self.audited(audit::append(self.ctx.paths, receipt), notes);
        }
        match decision {
            PendingDecision::Replayed { .. } => notes.push(RefreshNote::PendingReplayed),
            PendingDecision::Discarded(_) => notes.push(RefreshNote::PendingDiscarded),
            PendingDecision::NoPending => {}
        }

        let credentials = match self.read() {
            Ok(NamespaceRead::Credentials(credentials)) => *credentials,
            Ok(NamespaceRead::Absent) => return RefreshStep::NeedsLogin(NeedsLoginReason::Absent),
            Ok(NamespaceRead::Torn) => return self.torn(),
            Err(err) => return RefreshStep::Failed(err.to_string()),
        };
        let state = match self.ns.refresh_state().load() {
            RefreshStateRead::Present(state) => state,
            RefreshStateRead::Absent => RefreshState::default(),
            RefreshStateRead::Unavailable(reason) => return RefreshStep::StateUnavailable(reason),
        };
        let Some(grant) = credentials.refresh_digest8() else {
            return RefreshStep::NeedsLogin(NeedsLoginReason::NoRefreshToken);
        };
        if state.dead_digest8.as_deref() == Some(grant.as_str()) {
            return RefreshStep::NeedsLogin(NeedsLoginReason::Dead);
        }

        match mode {
            SendMode::Proactive => self.proactive(credentials, &grant, state, notes),
            SendMode::AfterUnauthorized { rejected_access_digest8 } => {
                self.after_unauthorized(credentials, &grant, state, &rejected_access_digest8, notes)
            }
            SendMode::Resend(consent) => self.resend(credentials, &grant, state, consent, notes),
        }
    }

    fn proactive(
        &self,
        credentials: LockedCredentials<'g>,
        grant: &str,
        state: RefreshState,
        notes: &mut Vec<RefreshNote>,
    ) -> RefreshStep {
        let state = match self.compare_marker(state, grant, notes) {
            Ok(Marker::Clear(state)) => state,
            Ok(Marker::Unknown { state, since, class }) => {
                return unknown_step(&state, since, class);
            }
            Err(step) => return step,
        };
        if let Some(step) = self.evidence_gate(notes) {
            return step;
        }
        if !credentials.credentials().access_expired(Timestamp::now(), ACCESS_REFRESH_MARGIN) {
            return RefreshStep::Adopted(AdoptReason::Fresh);
        }
        if let Some(step) = server_floor(&state, grant) {
            return step;
        }
        self.send(credentials, grant, SendKind::Inflight, notes)
    }

    fn after_unauthorized(
        &self,
        credentials: LockedCredentials<'g>,
        grant: &str,
        state: RefreshState,
        rejected: &str,
        notes: &mut Vec<RefreshNote>,
    ) -> RefreshStep {
        if credentials.credentials().access_digest8().as_deref() != Some(rejected) {
            return RefreshStep::Adopted(AdoptReason::ExternalAccess);
        }
        let state = match self.compare_marker(state, grant, notes) {
            Ok(Marker::Clear(state)) => state,
            Ok(Marker::Unknown { state, since, class }) => {
                return unknown_step(&state, since, class);
            }
            Err(step) => return step,
        };
        if let Some(step) = self.evidence_gate(notes) {
            return step;
        }
        if state.did_not_help >= TERMINAL_DID_NOT_HELP {
            return RefreshStep::UnauthorizedTerminal;
        }
        if let Some(until) = floor_until(&state)
            && Timestamp::now() < until
        {
            return RefreshStep::UnauthorizedFloor { until };
        }
        if let Some(step) = server_floor(&state, grant) {
            return step;
        }
        self.send(credentials, grant, SendKind::Inflight, notes)
    }

    fn resend(
        &self,
        credentials: LockedCredentials<'g>,
        grant: &str,
        state: RefreshState,
        consent: ResendConsent,
        notes: &mut Vec<RefreshNote>,
    ) -> RefreshStep {
        let (state, since, class) = match self.compare_marker(state, grant, notes) {
            Ok(Marker::Unknown { state, since, class }) => (state, since, class),
            Ok(Marker::Clear(_)) => return RefreshStep::ResendRefused(ResendBlock::NotUnknown),
            Err(step) => return step,
        };
        if state.resent {
            return RefreshStep::ResendRefused(ResendBlock::AlreadyResent);
        }
        let eligible_at = resend_eligible_at(since, class, state.retry_after);
        if Timestamp::now() < eligible_at {
            return RefreshStep::ResendRefused(ResendBlock::TooEarly(eligible_at));
        }
        match self.ns.has_stray_tmp() {
            Ok(false) => {}
            Ok(true) => return RefreshStep::ResendRefused(ResendBlock::StrayTmp),
            Err(err) => return RefreshStep::Failed(err.to_string()),
        }
        if let Some(step) = self.evidence_gate(notes) {
            return step;
        }
        // Consumed here: one consent, one send.
        let ResendConsent(()) = consent;
        self.send(credentials, grant, SendKind::Resend, notes)
    }

    /// The read, with the one torn retry.
    fn read(&self) -> Result<NamespaceRead<'g>, FileStoreError> {
        match self.ns.read()? {
            NamespaceRead::Torn => {
                thread::sleep(TORN_RETRY);
                self.ns.read()
            }
            other => Ok(other),
        }
    }

    /// A file that stayed torn: `refresh outcome unknown` when a send is
    /// outstanding, `stale` otherwise.
    fn torn(&self) -> RefreshStep {
        match self.ns.refresh_state().load() {
            RefreshStateRead::Present(state) => match &state.inflight {
                Some(inflight) => {
                    let since = state.ambiguous_since.unwrap_or(inflight.sent_at);
                    let class = state.class.unwrap_or(UnknownClass::Interrupted);
                    unknown_step(&state, since, class)
                }
                None => RefreshStep::Stale(StaleReason::Torn),
            },
            RefreshStateRead::Absent => RefreshStep::Stale(StaleReason::Torn),
            RefreshStateRead::Unavailable(reason) => RefreshStep::StateUnavailable(reason),
        }
    }

    /// The marker compare: a send of this grant outstanding is unknown — and
    /// classified `interrupted` if nothing classified it (the process died);
    /// a send of another grant is stale and cleared.
    fn compare_marker(
        &self,
        state: RefreshState,
        grant: &str,
        notes: &mut Vec<RefreshNote>,
    ) -> Result<Marker, RefreshStep> {
        let Some(inflight) = state.inflight.clone() else { return Ok(Marker::Clear(state)) };
        if inflight.sent_digest8 != grant {
            self.ns
                .refresh_state()
                .clear_inflight(DefiniteOutcome::External)
                .map_err(|err| RefreshStep::StateUnavailable(err.to_string()))?;
            notes.push(RefreshNote::StaleMarkerCleared);
            return match self.ns.refresh_state().load() {
                RefreshStateRead::Present(state) => Ok(Marker::Clear(state)),
                RefreshStateRead::Absent => Ok(Marker::Clear(RefreshState::default())),
                RefreshStateRead::Unavailable(reason) => Err(RefreshStep::StateUnavailable(reason)),
            };
        }
        let class = match state.class {
            Some(class) => class,
            None => {
                self.ns
                    .refresh_state()
                    .mark_interrupted(Timestamp::now())
                    .map_err(|err| RefreshStep::StateUnavailable(err.to_string()))?;
                self.audit_event(
                    CodexEvent::Ambiguous { class: UnknownClass::Interrupted, sent_digest8: grant },
                    notes,
                );
                UnknownClass::Interrupted
            }
        };
        let since = state.ambiguous_since.unwrap_or(inflight.sent_at);
        let state = match self.ns.refresh_state().load() {
            RefreshStateRead::Present(state) => state,
            RefreshStateRead::Absent => state,
            RefreshStateRead::Unavailable(reason) => {
                return Err(RefreshStep::StateUnavailable(reason));
            }
        };
        Ok(Marker::Unknown { state, since, class })
    }

    /// Daemon evidence under the lock: a live daemon or a record that cannot
    /// be read stops the send (decision D-032, review S30 F8).
    fn evidence_gate(&self, notes: &mut Vec<RefreshNote>) -> Option<RefreshStep> {
        match self.ns.daemon_evidence(self.ctx.cancel) {
            DaemonEvidence::None => None,
            DaemonEvidence::PidAlive(pid) => Some(RefreshStep::SessionDetected(pid)),
            DaemonEvidence::RecordUnreadable => {
                Some(RefreshStep::Stale(StaleReason::DaemonRecordUnreadable))
            }
            evidence @ (DaemonEvidence::Recycled(_) | DaemonEvidence::ArtefactOnly) => {
                notes.push(RefreshNote::CodexSession(evidence));
                None
            }
        }
    }

    /// The pre-POST re-read, the durable marker, and the POST.
    fn send(
        &self,
        credentials: LockedCredentials<'g>,
        grant: &str,
        kind: SendKind,
        notes: &mut Vec<RefreshNote>,
    ) -> RefreshStep {
        self.ctx.fault.pause_point(PAUSE_BEFORE_POST_SNAPSHOT);
        // Only "should this still be sent?" is decided here. Whether the answer
        // may be written is decided by the writer against the read the merge is
        // built on (review S30 F4), never by this snapshot.
        match self.ns.snapshot_for_post() {
            Ok(Some(snapshot)) if snapshot.refresh_digest8().as_deref() == Some(grant) => {}
            Ok(_) => return self.changed_before_post(),
            Err(err) => return RefreshStep::Failed(err.to_string()),
        }
        if self.ctx.cancel.is_cancelled() {
            return RefreshStep::Stale(StaleReason::Cancelled);
        }

        let token = match kind {
            SendKind::Inflight => self.ns.refresh_state().write_inflight(&credentials),
            SendKind::Resend => self.ns.refresh_state().write_resend(&credentials),
        };
        let token = match token {
            Ok(token) => token,
            Err(err) => return RefreshStep::StateUnavailable(err.to_string()),
        };
        if kind == SendKind::Resend {
            self.audit_event(CodexEvent::Resend { sent_digest8: grant }, notes);
        }
        if self.ctx.fault.is(FAULT_ABORT_AFTER_MARKER) {
            std::process::abort();
        }
        self.ctx.fault.pause_point(PAUSE_AFTER_POST_SNAPSHOT);

        let outcome = oauth::refresh(&credentials, token, self.ctx.client, self.ctx.cancel);
        self.settle(credentials, grant, kind, outcome, notes)
    }

    /// The file moved between the read and the POST: adopt it when fresh.
    fn changed_before_post(&self) -> RefreshStep {
        match self.read() {
            Ok(NamespaceRead::Credentials(credentials))
                if !credentials
                    .credentials()
                    .access_expired(Timestamp::now(), ACCESS_REFRESH_MARGIN) =>
            {
                RefreshStep::Adopted(AdoptReason::ChangedBeforePost)
            }
            Ok(NamespaceRead::Absent) => RefreshStep::NeedsLogin(NeedsLoginReason::Absent),
            Ok(_) => RefreshStep::Stale(StaleReason::ChangedBeforePost),
            Err(err) => RefreshStep::Failed(err.to_string()),
        }
    }

    fn settle(
        &self,
        credentials: LockedCredentials<'g>,
        grant: &str,
        kind: SendKind,
        outcome: RefreshOutcome,
        notes: &mut Vec<RefreshNote>,
    ) -> RefreshStep {
        match outcome {
            RefreshOutcome::Applied(response) => {
                let earliest = clamp_earliest(response.earliest_refresh_at(), Timestamp::now());
                self.applied(credentials, grant, response, earliest, notes)
            }
            RefreshOutcome::Permanent(class) => self.permanent(grant, class, notes),
            // A re-send answers for a grant whose first send is still unknown:
            // clearing the marker would re-arm an automatic send of it with no
            // consent (review S32-C2 F1, deviation D26). The marker goes back
            // to unknown instead — the re-send not spent when it never left,
            // spent when a 4xx answered it.
            RefreshOutcome::PreSend(_) if kind == SendKind::Resend => self.restore_unknown(false),
            RefreshOutcome::Rejected(status) if kind == SendKind::Resend => {
                match self.ns.refresh_state().restore_unknown(true) {
                    Ok(()) => RefreshStep::NeedsLogin(NeedsLoginReason::ResendRejected(status)),
                    Err(err) => RefreshStep::StateUnavailable(err.to_string()),
                }
            }
            RefreshOutcome::PreSend(reason) => self
                .clear(DefiniteOutcome::PreSend, RefreshStep::Stale(StaleReason::PreSend(reason))),
            RefreshOutcome::Rejected(status) => self.clear(
                DefiniteOutcome::Rejected,
                RefreshStep::Stale(StaleReason::Rejected(status)),
            ),
            RefreshOutcome::RateLimited { retry_after } => self.unknown(
                grant,
                UnknownClass::RateLimited,
                retry_after.map(|wait| wait.min(MAX_RETRY_AFTER)),
                notes,
            ),
            RefreshOutcome::ServerError(_) => {
                self.unknown(grant, UnknownClass::ServerError, None, notes)
            }
            RefreshOutcome::Ambiguous(class) => {
                let class = match class {
                    AmbiguousClass::Transport | AmbiguousClass::ServerBody => {
                        UnknownClass::Ambiguous
                    }
                    AmbiguousClass::Tls => UnknownClass::Tls,
                    AmbiguousClass::WriteFailed => UnknownClass::WriteFailed,
                };
                self.unknown(grant, class, None, notes)
            }
        }
    }

    /// A re-send that never left: the unknown marker again, `--resend` still
    /// available.
    fn restore_unknown(&self, resent: bool) -> RefreshStep {
        if let Err(err) = self.ns.refresh_state().restore_unknown(resent) {
            return RefreshStep::StateUnavailable(err.to_string());
        }
        match self.ns.refresh_state().load() {
            RefreshStateRead::Present(state) => match (state.inflight.as_ref(), state.class) {
                (Some(inflight), Some(class)) => {
                    let since = state.ambiguous_since.unwrap_or(inflight.sent_at);
                    unknown_step(&state, since, class)
                }
                _ => RefreshStep::StateUnavailable("the restored marker is incomplete".to_owned()),
            },
            RefreshStateRead::Absent => {
                RefreshStep::StateUnavailable("the restored marker is missing".to_owned())
            }
            RefreshStateRead::Unavailable(reason) => RefreshStep::StateUnavailable(reason),
        }
    }

    /// A definite outcome with nothing to record but the cleared send.
    fn clear(&self, outcome: DefiniteOutcome, step: RefreshStep) -> RefreshStep {
        match self.ns.refresh_state().clear_inflight(outcome) {
            Ok(()) => step,
            Err(err) => RefreshStep::StateUnavailable(err.to_string()),
        }
    }

    /// The marker stays, with the class; no automatic re-send (risk R63).
    fn unknown(
        &self,
        grant: &str,
        class: UnknownClass,
        retry_after: Option<Duration>,
        notes: &mut Vec<RefreshNote>,
    ) -> RefreshStep {
        let now = Timestamp::now();
        if let Err(err) = self.ns.refresh_state().mark_unknown(class, now, retry_after) {
            // The in-flight marker is already durable, so the next pass
            // classifies this send `interrupted`: still no second POST.
            tracing::warn!(error = %err, "a refresh's unknown outcome could not be recorded");
        }
        self.audit_event(CodexEvent::Ambiguous { class, sent_digest8: grant }, notes);
        match self.ns.refresh_state().load() {
            RefreshStateRead::Present(state) => {
                let since = state.ambiguous_since.unwrap_or(now);
                unknown_step(&state, since, class)
            }
            RefreshStateRead::Absent | RefreshStateRead::Unavailable(_) => {
                RefreshStep::OutcomeUnknown {
                    since: now,
                    class,
                    resend_eligible_at: Some(resend_eligible_at(now, class, retry_after)),
                }
            }
        }
    }

    /// The server called the grant dead.
    fn permanent(
        &self,
        grant: &str,
        class: PermanentClass,
        notes: &mut Vec<RefreshNote>,
    ) -> RefreshStep {
        let current = match self.read() {
            Ok(NamespaceRead::Credentials(credentials)) => credentials.refresh_digest8(),
            Ok(NamespaceRead::Absent | NamespaceRead::Torn) | Err(_) => None,
        };
        match current {
            Some(kept) if kept != grant => {
                let step = self.clear(DefiniteOutcome::Permanent, RefreshStep::RacedExternal);
                self.audit_event(
                    CodexEvent::AdoptedExternal { sent_digest8: grant, kept_digest8: Some(&kept) },
                    notes,
                );
                step
            }
            _ => {
                let settled =
                    Settled { earliest_refresh: None, dead_digest8: Some(grant.to_owned()) };
                let step = match self
                    .ns
                    .refresh_state()
                    .settle_inflight(DefiniteOutcome::Permanent, settled)
                {
                    Ok(()) => RefreshStep::NeedsLogin(NeedsLoginReason::Dead),
                    Err(err) => RefreshStep::StateUnavailable(err.to_string()),
                };
                self.audit_event(CodexEvent::NeedsLogin { class, sent_digest8: grant }, notes);
                step
            }
        }
    }

    /// Writes an applied response: merge once, bounded retries, park, and
    /// `unknown (write_failed)` only when even parking fails.
    fn applied(
        &self,
        original: LockedCredentials<'g>,
        grant: &str,
        response: RefreshResponse,
        earliest: Option<Timestamp>,
        notes: &mut Vec<RefreshNote>,
    ) -> RefreshStep {
        // Merge onto the current document when it still holds the grant sent,
        // so another writer's changes to the rest of the file survive. When it
        // does not, merge onto the read the send came from: the writer then
        // compares the file with that read and reports the discard.
        let base = match self.read() {
            Ok(NamespaceRead::Credentials(current))
                if current.refresh_digest8().as_deref() == Some(grant) =>
            {
                *current
            }
            _ => original,
        };
        let (merged, merge) = match base.merge_refresh(response, Timestamp::now()) {
            Ok(merged) => merged,
            Err(err) => {
                tracing::warn!(error = %err, "an applied refresh could not be merged");
                return self.unknown(grant, UnknownClass::WriteFailed, None, notes);
            }
        };
        if merge.identity_drift {
            notes.push(RefreshNote::IdentityDrift);
        }
        if merge.id_token_unreadable {
            notes.push(RefreshNote::IdTokenUnreadable);
        }
        let written = merged.credentials().digests();
        let settled = Settled {
            earliest_refresh: earliest
                .zip(merged.refresh_digest8())
                .map(|(at, grant_digest8)| EarliestRefresh { grant_digest8, at }),
            dead_digest8: None,
        };

        for _ in 0..POST_APPLIED_ATTEMPTS {
            match self.ns.write(&merged, self.ctx.fault) {
                Ok(CodexWrite::Landed { outcome, receipt }) => {
                    self.audited(audit::append(self.ctx.paths, receipt), notes);
                    let parked = matches!(outcome, WriteOutcome::SavedToPending { .. });
                    return self.landed(parked, settled, notes);
                }
                Ok(CodexWrite::ChangedSinceRead { receipt }) => {
                    self.audited(audit::append(self.ctx.paths, receipt), notes);
                    return self.clear(DefiniteOutcome::External, RefreshStep::DiscardedExternal);
                }
                Ok(CodexWrite::Torn) => thread::sleep(TORN_RETRY),
                Err(err) => {
                    tracing::warn!(error = %err, "writing an applied refresh failed; retrying");
                }
            }
            // A write can land and still report an error (the post-rename
            // snapshot): look before writing the same merge again.
            if let Ok(NamespaceRead::Credentials(current)) = self.ns.read()
                && current.credentials().digests() == written
            {
                let written8 = current.refresh_digest8();
                self.audit_event(
                    CodexEvent::AppliedAfterError {
                        sent_digest8: grant,
                        written_digest8: written8.as_deref(),
                    },
                    notes,
                );
                return self.landed(false, settled, notes);
            }
        }

        match self.ns.park(&merged, self.ctx.fault) {
            Ok(CodexWrite::Landed { receipt, .. }) => {
                self.audited(audit::append(self.ctx.paths, receipt), notes);
                self.landed(true, settled, notes)
            }
            Ok(CodexWrite::ChangedSinceRead { receipt }) => {
                self.audited(audit::append(self.ctx.paths, receipt), notes);
                self.unknown(grant, UnknownClass::WriteFailed, None, notes)
            }
            Ok(CodexWrite::Torn) => self.unknown(grant, UnknownClass::WriteFailed, None, notes),
            Err(err) => {
                // The grant may still be on disk as a kept temporary (review
                // S29a F5): the marker stays, and this is never definite.
                tracing::warn!(error = %err, "an applied refresh could not be written or parked");
                self.unknown(grant, UnknownClass::WriteFailed, None, notes)
            }
        }
    }

    /// The rotated grant is on disk (or parked): clear the send.
    fn landed(&self, parked: bool, settled: Settled, notes: &mut Vec<RefreshNote>) -> RefreshStep {
        if parked && self.ctx.fault.is(FAULT_ABORT_AFTER_PENDING) {
            std::process::abort();
        }
        let step = match self.ns.refresh_state().settle_inflight(DefiniteOutcome::Applied, settled)
        {
            Ok(()) => RefreshStep::Refreshed { parked },
            // The file now holds a different grant than the marker, so the
            // next pass reads the marker as stale and clears it.
            Err(err) => {
                tracing::warn!(error = %err, "the refresh marker could not be cleared after a landed write");
                RefreshStep::Refreshed { parked }
            }
        };
        let evidence = self.ns.daemon_evidence(self.ctx.cancel);
        if evidence != DaemonEvidence::None {
            notes.push(RefreshNote::CodexSession(evidence));
        }
        step
    }

    /// The outcome of `audit::append(receipt)`, the one consumer of a write
    /// receipt: a refused entry leaves the landed write standing (plan AC117).
    fn audited(&self, appended: Result<(), AppError>, notes: &mut Vec<RefreshNote>) {
        if let Err(err) = appended {
            tracing::warn!(error = %err, "the Codex audit log refused an entry for a write that landed");
            notes.push(RefreshNote::AuditLogRefused);
        }
    }

    fn audit_event(&self, event: CodexEvent<'_>, notes: &mut Vec<RefreshNote>) {
        self.audited(audit::append_event(self.ctx.paths, self.ids, event), notes);
    }
}

/// The step for an unknown outcome.
fn unknown_step(state: &RefreshState, since: Timestamp, class: UnknownClass) -> RefreshStep {
    let resend_eligible_at =
        (!state.resent).then(|| resend_eligible_at(since, class, state.retry_after));
    RefreshStep::OutcomeUnknown { since, class, resend_eligible_at }
}

/// `since + 1 h`, or `since + max(retry-after, 1 h)` for `rate_limited`.
fn resend_eligible_at(
    since: Timestamp,
    class: UnknownClass,
    retry_after: Option<Duration>,
) -> Timestamp {
    let wait = match (class, retry_after) {
        (UnknownClass::RateLimited, Some(retry_after)) => {
            retry_after.min(MAX_RETRY_AFTER).max(RESEND_WAIT)
        }
        _ => RESEND_WAIT,
    };
    SignedDuration::try_from(wait)
        .ok()
        .and_then(|wait| since.checked_add(wait).ok())
        .unwrap_or(Timestamp::MAX)
}

/// When the 401 floor after the last send ends.
fn floor_until(state: &RefreshState) -> Option<Timestamp> {
    let last = state.last_sent_at?;
    let minutes = i64::from(state.floor_min);
    let floor = SignedDuration::from_mins(minutes);
    Some(last.checked_add(floor).unwrap_or(Timestamp::MAX))
}

/// The token host's floor on this grant (ledger 282a).
fn server_floor(state: &RefreshState, grant: &str) -> Option<RefreshStep> {
    let earliest = state.earliest_refresh.as_ref()?;
    (earliest.grant_digest8 == grant && Timestamp::now() < earliest.at)
        .then_some(RefreshStep::NotBefore(earliest.at))
}

/// A usable `earliest_refresh_at`: in the future, clamped to thirty days.
fn clamp_earliest(at: Option<Timestamp>, now: Timestamp) -> Option<Timestamp> {
    let at = at.filter(|at| *at > now)?;
    let limit = now.checked_add(MAX_EARLIEST_REFRESH_AHEAD).unwrap_or(Timestamp::MAX);
    Some(at.min(limit))
}

/// What the retry GET after an `AfterUnauthorized` send answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryGet {
    /// A 2xx: the floor and the count reset.
    Succeeded,
    /// Another 401: the refresh did not help.
    Unauthorized,
}

/// Records the retry GET's answer after a sent `AfterUnauthorized` refresh
/// (plan AC114).
///
/// # Errors
///
/// [`AppError`] when the lock, the namespace or the marker is unavailable.
pub fn record_retry_get(
    owned: OwnedRecord<'_>,
    result: RetryGet,
    ctx: &RefreshCtx<'_>,
) -> Result<(), AppError> {
    let guard = lock::acquire_codex(ctx.paths, owned, ctx.lock_budget, ctx.cancel, ctx.fault)
        .map_err(|err| AppError::Config(err.to_string()))?;
    let ns = OwnedNamespace::open(ctx.paths, owned, &guard)
        .map_err(|err| AppError::Config(err.to_string()))?;
    let state = ns.refresh_state();
    match result {
        RetryGet::Succeeded => state.reset_floor(),
        RetryGet::Unauthorized => state.record_did_not_help(),
    }
    .map_err(|err| AppError::Config(err.to_string()))
}

/// Lifts the terminal 401 state and the floor, on the user's confirmation
/// (plan section 3.3, `accounts refresh --reset-floor`). The caller holds the
/// namespace lock through `ns`.
///
/// # Errors
///
/// [`AppError`] when the marker cannot be written. A refused audit entry is
/// logged at `warn`; the reset stands.
pub fn reset_floor(
    paths: &Paths,
    ns: &OwnedNamespace<'_>,
    consent: ResetConsent,
) -> Result<(), AppError> {
    let ResetConsent(()) = consent;
    ns.refresh_state().reset_floor().map_err(|err| AppError::Config(err.to_string()))?;
    let owned = ns.owned();
    if let Err(err) =
        audit::append_event(paths, (owned.user(), owned.acct()), CodexEvent::FloorReset)
    {
        tracing::warn!(error = %err, "the Codex audit log refused a floor reset entry");
    }
    Ok(())
}

#[cfg(test)]
#[path = "refresh_tests.rs"]
mod tests;
