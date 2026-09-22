//! The read-only Codex pass: plan the rows, read each credential, ask the
//! usage endpoint, normalize what came back.
//!
//! # Why this is not in `status.rs`
//!
//! `agctl codex status` and `agctl codex watch` run the same pass; only
//! `status` may send a refresh (plan section 10, U44 = option 5). While the
//! pass lived beside the refresh, the file the greps allow-listed as "may
//! drive a refresh" was also the file the unattended loop calls into, so a
//! POST written inside [`run_row`] would have been sent on every `watch` tick
//! with every gate still green (review S33-C2, probe B). The pass lives here
//! instead: nothing in this file can obtain a
//! [`PostPermit`](crate::provider::codex::permit::PostPermit), so nothing in
//! it can POST, and `scripts/phase3-greps.sh` can hold the boundary by naming
//! one file rather than one function.
//!
//! Everything here only reads. The two places a refresh token is sent both
//! live in [`status`](super::status), on the command thread, around this pass
//! rather than inside it (ledger #233). Plan section 3.3's in-row reading —
//! "401 -> `refresh::run` once, then retry the GET" — describes a worker POST
//! and is superseded by deviation D3 (ledger #289): the 401 refresh is a
//! post-pass on the command thread, so nothing in this file sends anything.
//!
//! # Every credential read, and what it may do
//!
//! - the live home and an imported home ([`read_home`]): `auth_store::read_live`,
//!   read-only, never a lock, never refreshed, never fetched once expired;
//! - an owned namespace ([`read_owned`]): under its namespace lock through
//!   `OwnedNamespace::read`, after which the credential is unbound from the
//!   lock ([`LockedCredentials::into_credentials`]) so no lock is held for a
//!   request; the refresh marker is read beside it with `load()` and never
//!   written by a worker.
//!
//! No credential outlives the row it was read for: a [`CodexRowOutcome`]
//! holds ids, figures and states, never a token (invariant I24).

use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use jiff::Timestamp;
use serde_json::Map;
use serde_json::Value;

use crate::config::codex::CodexAccountRecord;
use crate::config::codex::CodexKind;
use crate::config::codex::RefreshPolicy;
use crate::config::paths::Paths;
use crate::error::AppError;
use crate::provider::AccountRef;
use crate::provider::FetchError;
use crate::provider::Provider;
use crate::provider::codex::account::CodexRowKind;
use crate::provider::codex::account::CodexRowOutcome;
use crate::provider::codex::account::CodexState;
use crate::provider::codex::auth_store;
use crate::provider::codex::auth_store::CodexResolved;
use crate::provider::codex::auth_store::NamespaceRead;
use crate::provider::codex::auth_store::OwnedNamespace;
use crate::provider::codex::auth_store::RefreshState;
use crate::provider::codex::auth_store::RefreshStateRead;
use crate::provider::codex::auth_store::UnknownClass;
use crate::provider::codex::credentials::ACCESS_REFRESH_MARGIN;
use crate::provider::codex::credentials::Credentials;
use crate::provider::codex::credentials::LockedCredentials;
use crate::provider::codex::discovery;
use crate::provider::codex::discovery::CodexSource;
use crate::provider::codex::home;
use crate::provider::codex::home::CodexEnv;
use crate::provider::codex::home::DaemonEvidence;
use crate::provider::codex::home::FileInEffect;
use crate::provider::codex::home::KeyringProbe;
use crate::provider::codex::home::StoreMode;
use crate::provider::codex::lock;
use crate::provider::codex::lock::LockBudget;
use crate::provider::codex::proof;
use crate::provider::codex::refresh;
use crate::provider::codex::refresh::NeedsLoginReason;
use crate::provider::codex::refresh::PASS_LOCK_BUDGET;
use crate::provider::codex::refresh::RefreshNote;
use crate::provider::codex::refresh::RefreshReport;
use crate::provider::codex::refresh::RefreshStep;
use crate::provider::codex::refresh::StaleReason;
use crate::provider::codex::usage;
use crate::provider::codex::usage::CodexUsage;
use crate::provider::codex::usage::UsageClient;
use crate::runtime::coordinator::Cancel;
use crate::runtime::coordinator::DEFAULT_MAX_WORKERS;
use crate::runtime::coordinator::Job;
use crate::runtime::coordinator::PassCtx;
use crate::runtime::coordinator::run_pass;
use crate::runtime::fault::Fault;
use crate::secret::KeychainReader;
use crate::secret::ServiceEntry;
use crate::secret::namespace_lock::LockError;
use crate::usage::cache;
use crate::usage::cache::CacheEntry;

/// The wait before a torn `auth.json` is read again (plan AC94).
const TORN_RETRY: Duration = Duration::from_millis(50);

/// What a read-only row says once its access token is expired.
pub const EXPIRED_READ_ONLY: &str = "read-only; run codex to refresh";

/// What an owned row with refresh policy `never` says once expired.
pub const EXPIRED_NEVER: &str = "run agctl codex login";

/// What an owned `auto` row says in `watch`, which never refreshes (U44 = 5).
pub const EXPIRED_IN_WATCH: &str = "run agctl codex status";

/// The one wording for a grant whose `--resend` is spent, whichever way it
/// was spent (review S32-C2 R2-I2).
pub const RESEND_SPENT: &str = "its one --resend is spent; run agctl codex login";

/// The cache options.
#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// `--refresh`: fetch even when a cached value would do. It sends no
    /// refresh token and lifts no floor (plan AC114).
    pub refresh: bool,
    /// `--no-cache`, or `watch`'s `r`.
    pub no_cache: bool,
}

impl Options {
    fn may_serve_cache(self) -> bool {
        !self.refresh && !self.no_cache
    }
}

/// Everything a pass's workers share. Captured by every job.
pub struct Shared {
    /// The store.
    pub paths: Arc<Paths>,
    /// The usage endpoint client, built through `UsageClient::from_env`.
    pub client: UsageClient,
    /// The read-only keychain listing, for homes in `auto` store mode.
    pub keyring: KeyringListing,
    /// Injected faults (empty in production).
    pub fault: Fault,
    /// The cache options.
    pub options: Options,
    /// Whether this command refreshes on the command thread (`status`), which
    /// only changes what a worker tells the user to run. A worker sends
    /// nothing either way.
    pub allow_post: bool,
}

/// The keychain listing a pass took, when one was needed.
#[derive(Debug, Clone)]
pub enum KeyringListing {
    /// No home in `auto` store mode, so nothing was listed.
    NotNeeded,
    /// The `Codex Auth` items, attributes only.
    Entries(Vec<ServiceEntry>),
    /// The listing could not be taken.
    Unavailable,
}

impl KeyringListing {
    /// Whether the listing names an item for `home` (fact F94). A listing with
    /// no account column matches by service alone (the coarse match `doctor`
    /// reports).
    ///
    /// `pub(super)` rather than private since S34 C2-a's sibling commit:
    /// `commands::codex::import` asks the same question of the same listing,
    /// so that one home gets one answer from both commands (plan AC95). The
    /// narrowest visibility that reaches it — nothing outside
    /// `commands::codex` can call it.
    pub(super) fn probe(&self, home: &Path) -> KeyringProbe {
        let Self::Entries(entries) = self else { return KeyringProbe::Unknown };
        let account = home::keyring_account(home);
        let listed = entries.iter().any(|entry| {
            entry.service == home::KEYRING_SERVICE
                && entry.account.as_deref().is_none_or(|listed| listed == account)
        });
        if listed { KeyringProbe::ItemPresent } else { KeyringProbe::NoItem }
    }
}

/// One row the pass will look at, owning what its job needs.
#[derive(Debug, Clone)]
pub struct RowPlan {
    /// Discovery order.
    pub index: usize,
    /// Where the credential is.
    pub source: PlanSource,
    /// What the pre-pass did, for an owned `auto` row under `status`.
    pub pre_pass: Option<RefreshReport>,
    /// Why this row is being read again after the 401 post-pass.
    pub retry: Option<Retry>,
}

impl RowPlan {
    /// Whether this row is one a refresh may be sent for.
    pub fn may_refresh(&self) -> bool {
        matches!(
            &self.source,
            PlanSource::Owned { record, .. } if matches!(
                record.kind,
                CodexKind::Owned { refresh: RefreshPolicy::Auto, .. }
            )
        )
    }
}

/// Where one row's credential is.
#[derive(Debug, Clone)]
pub enum PlanSource {
    /// The user's own Codex home.
    Live {
        /// The resolved home.
        home: PathBuf,
    },
    /// The live home could not be resolved.
    LiveUnreadable {
        /// Why, as `HomeError` says it.
        reason: String,
    },
    /// A home recorded by `import`.
    HomeReadOnly {
        /// The record.
        record: CodexAccountRecord,
        /// The recorded directory. Never a write target (invariant I27).
        dir: PathBuf,
    },
    /// An agctl-owned namespace.
    Owned {
        /// The record.
        record: CodexAccountRecord,
        /// Daemon evidence discovery took without a lock, for a note.
        evidence: DaemonEvidence,
    },
    /// An owned record whose ids cannot name a namespace.
    InvalidOwned {
        /// The record.
        record: CodexAccountRecord,
    },
}

/// Why a row is read a second time, after the 401 post-pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retry {
    /// A refresh was sent: the GET's answer is recorded (plan AC114).
    AfterSend,
    /// Another writer had already refreshed: nothing was sent.
    AfterAdopt,
    /// The token host called the grant sent dead while another writer's grant
    /// was in the file: one GET verifies that grant (plan AC124 (a)/(a′)).
    Verify,
}

/// What a worker produced for one row.
#[derive(Debug)]
pub struct RowPass {
    /// The row.
    pub outcome: CodexRowOutcome,
    /// The plan it came from, for the post-pass.
    pub plan: RowPlan,
    /// The access token's digest prefix, for the live/imported fold (D23).
    access_digest8: Option<String>,
    /// The digest prefix of the bearer a 401 rejected, when the post-pass
    /// should act on it.
    pub rejected: Option<String>,
    /// Whether the marker holds a raised floor or a did-not-help count that a
    /// successful GET after a sent refresh resets.
    pub floor_raised: bool,
    /// Whether a GET succeeded.
    pub fetched: bool,
}

/// Builds the plans from discovery.
pub fn plan_rows(
    paths: &Paths,
    accounts: &[CodexAccountRecord],
    env: &CodexEnv,
    cancel: &Cancel,
) -> Vec<RowPlan> {
    let (sources, live_error) = discovery::sources(paths, accounts, env, cancel);
    let mut plans = Vec::new();
    if let Some(err) = live_error {
        plans.push(PlanSource::LiveUnreadable { reason: err.to_string() });
    }
    for source in sources {
        let planned = match source {
            CodexSource::Live { home } => {
                if !live_home_exists(&home) {
                    // A machine that has never run Codex has no live row at
                    // all, rather than a `needs login` one that forces exit 2
                    // beside healthy owned rows (review S33-C2 B3).
                    continue;
                }
                PlanSource::Live { home }
            }
            CodexSource::HomeReadOnly { record, dir } => {
                PlanSource::HomeReadOnly { record: record.clone(), dir: dir.to_path_buf() }
            }
            CodexSource::Owned { record, evidence, .. } => {
                PlanSource::Owned { record: record.clone(), evidence }
            }
            CodexSource::InvalidOwned { record } => {
                PlanSource::InvalidOwned { record: record.clone() }
            }
        };
        plans.push(planned);
    }
    plans
        .into_iter()
        .enumerate()
        .map(|(index, source)| RowPlan { index, source, pre_pass: None, retry: None })
        .collect()
}

/// Whether the resolved live Codex home is on disk at all.
///
/// Only the `CODEX_HOME`-unset path can reach here with a missing directory:
/// `home::codex_home` stats and canonicalizes an explicit `CODEX_HOME` and
/// turns a missing one into `HomeError::Missing`, which is already its own
/// row. So "not there" here means "this machine has never run Codex", and the
/// honest report is no live row rather than one that says `needs login`
/// (review S33-C2 B3).
///
/// A dangling `~/.codex` symlink is **not** missing: `symlink_metadata` reads
/// the link itself, so something is there, it is broken, and the row says so
/// instead of vanishing. A home that cannot be stat'ed for any other reason
/// (a permission on its parent) also keeps its row.
fn live_home_exists(home: &Path) -> bool {
    !std::fs::symlink_metadata(home).is_err_and(|err| err.kind() == io::ErrorKind::NotFound)
}

/// Narrows the plans to `--account`: a user id, `<user>/<account>`, an email
/// the registry records, or `live` for the live home.
///
/// # Errors
///
/// [`AppError::Config`] when a selector matches nothing.
pub fn select(plans: Vec<RowPlan>, selectors: &[String]) -> Result<Vec<RowPlan>, AppError> {
    if selectors.is_empty() {
        return Ok(plans);
    }
    for selector in selectors {
        if !plans.iter().any(|plan| matches_selector(plan, selector)) {
            let known: Vec<String> = plans.iter().map(selector_name).collect();
            return Err(AppError::Config(format!(
                "no Codex account matches `{selector}`; known accounts: {}",
                known.join(", ")
            )));
        }
    }
    Ok(plans
        .into_iter()
        .filter(|plan| selectors.iter().any(|selector| matches_selector(plan, selector)))
        .collect())
}

fn record_of(plan: &RowPlan) -> Option<&CodexAccountRecord> {
    match &plan.source {
        PlanSource::HomeReadOnly { record, .. }
        | PlanSource::Owned { record, .. }
        | PlanSource::InvalidOwned { record } => Some(record),
        PlanSource::Live { .. } | PlanSource::LiveUnreadable { .. } => None,
    }
}

fn matches_selector(plan: &RowPlan, selector: &str) -> bool {
    match record_of(plan) {
        Some(record) => {
            record.chatgpt_user_id == selector
                || format!("{}/{}", record.chatgpt_user_id, record.chatgpt_account_id) == selector
                || record.email.as_deref() == Some(selector)
        }
        None => selector == "live",
    }
}

fn selector_name(plan: &RowPlan) -> String {
    record_of(plan).map_or_else(
        || "live".to_owned(),
        |record| format!("{}/{}", record.chatgpt_user_id, record.chatgpt_account_id),
    )
}

/// Takes the keychain listing when a home in `auto` store mode needs it
/// (plan section 3.3 step 1, AC109 amended): attributes only.
pub fn keyring_listing(plans: &[RowPlan], cancel: &Cancel, deadline: Instant) -> KeyringListing {
    let needed = plans.iter().any(|plan| {
        let home = match &plan.source {
            PlanSource::Live { home } => home,
            PlanSource::HomeReadOnly { dir, .. } => dir,
            _ => return false,
        };
        home::store_mode(home).0 == StoreMode::Auto
    });
    if !needed {
        return KeyringListing::NotNeeded;
    }
    let ctx = PassCtx::standalone(cancel.clone(), deadline);
    let reader = crate::secret::default_reader(&ctx);
    list_keyring(reader.as_ref())
}

/// The listing, through a reader a test can replace.
pub fn list_keyring(reader: &dyn KeychainReader) -> KeyringListing {
    match reader.list_services(home::KEYRING_SERVICE) {
        Ok(entries) => KeyringListing::Entries(entries),
        Err(err) => {
            tracing::warn!(error = %err, "the keychain listing for Codex homes failed");
            KeyringListing::Unavailable
        }
    }
}

/// Runs the read-only pass: one job per plan, results in discovery order.
///
/// Shared by `watch`, which never runs the pre-pass or the post-pass around
/// it: nothing reachable from here sends a refresh.
pub fn collect(
    plans: Vec<RowPlan>,
    shared: &Arc<Shared>,
    cancel: &Cancel,
    deadline: Instant,
) -> Vec<RowPass> {
    let jobs: Vec<Job<RowPass>> = plans
        .into_iter()
        .map(|plan| {
            let shared = Arc::clone(shared);
            let job: Job<RowPass> = Box::new(move |ctx| run_row(ctx.cancel(), plan, &shared));
            job
        })
        .collect();
    let mut passes: Vec<RowPass> =
        run_pass(jobs, cancel.clone(), deadline, DEFAULT_MAX_WORKERS).into_iter().collect();
    passes.sort_by_key(|pass| pass.outcome.index);
    passes
}

/// The state a refresh step leaves a row in when no GET follows it; `None`
/// for a step after which the row is read normally.
pub fn step_state(step: &RefreshStep) -> Option<(CodexState, Option<String>)> {
    Some(match step {
        RefreshStep::NeedsLogin(reason) => {
            (CodexState::NeedsLogin, Some(needs_login_note(*reason)))
        }
        RefreshStep::OutcomeUnknown { since, class, resend_eligible_at } => {
            unknown_state(*since, *class, *resend_eligible_at)
        }
        RefreshStep::StateUnavailable(reason) => {
            (CodexState::RefreshStateUnavailable { reason: reason.clone() }, None)
        }
        RefreshStep::SessionDetected(pid) => {
            (CodexState::CodexSessionDetected { evidence: format!("pid {pid} alive") }, None)
        }
        RefreshStep::Busy => (CodexState::Busy, None),
        RefreshStep::UnauthorizedTerminal => (CodexState::UnauthorizedTerminal, None),
        RefreshStep::Failed(message) => (CodexState::Error(message.clone()), None),
        _ => return None,
    })
}

/// A short note for a refresh step that did not change the row's state.
pub fn step_note(step: &RefreshStep) -> Option<String> {
    match step {
        RefreshStep::Stale(reason) => Some(format!("no refresh sent: {}", stale_reason(reason))),
        // The token host's own floor is not lifted by `--reset-floor`, only by
        // a new grant (review S32-C2 I2).
        RefreshStep::NotBefore(at) => {
            Some(format!("the token host allows no refresh before {at}; run agctl codex login"))
        }
        RefreshStep::Disabled => Some("refresh policy is never".to_owned()),
        _ => None,
    }
}

fn stale_reason(reason: &StaleReason) -> String {
    match reason {
        StaleReason::NotEnoughTime => "not enough time left in this pass".to_owned(),
        StaleReason::Cancelled => "cancelled".to_owned(),
        StaleReason::Torn => format!("{} was being rewritten", auth_store::shown_name()),
        StaleReason::DaemonRecordUnreadable => "a Codex daemon record is unreadable".to_owned(),
        StaleReason::ChangedBeforePost => "the file changed before the send".to_owned(),
        StaleReason::PreSend(why) => format!("not sent ({why}); retried next pass"),
        StaleReason::Rejected(status) => format!("the token host answered {status}"),
    }
}

fn needs_login_note(reason: NeedsLoginReason) -> String {
    match reason {
        NeedsLoginReason::Absent => "no credential; run agctl codex login".to_owned(),
        NeedsLoginReason::NoRefreshToken => "no refresh token; run agctl codex login".to_owned(),
        NeedsLoginReason::Dead => {
            "the token host rejected this grant; run agctl codex login".to_owned()
        }
        NeedsLoginReason::ResendRejected(_) => format!("refresh outcome unknown; {RESEND_SPENT}"),
    }
}

/// `refresh outcome unknown (<class>)` with its `--resend` hint.
fn unknown_state(
    since: Timestamp,
    class: UnknownClass,
    resend_eligible_at: Option<Timestamp>,
) -> (CodexState, Option<String>) {
    let now = Timestamp::now();
    let note = match resend_eligible_at {
        None => RESEND_SPENT.to_owned(),
        Some(at) if at <= now => {
            "agctl codex accounts refresh --resend is available (read the risk it names first)"
                .to_owned()
        }
        Some(at) => format!("--resend is available after {at}"),
    };
    (
        CodexState::RefreshOutcomeUnknown {
            since,
            class,
            resend_eligible: resend_eligible_at.is_some_and(|at| at <= now),
        },
        Some(note),
    )
}

/// The notes a refresh report carries onto the row.
pub fn push_report_notes(note: &mut Option<String>, report: &RefreshReport) {
    for item in &report.notes {
        push_note(
            note,
            Some(match item {
                RefreshNote::AuditLogRefused => "audit log refused".to_owned(),
                RefreshNote::CodexSession(evidence) => {
                    format!("codex session detected ({})", evidence_label(*evidence))
                }
                RefreshNote::IdentityDrift => "identity drift".to_owned(),
                RefreshNote::IdTokenUnreadable => "the new id token did not decode".to_owned(),
                RefreshNote::PendingReplayed => "pending replayed".to_owned(),
                RefreshNote::PendingDiscarded => "pending discarded".to_owned(),
                RefreshNote::StaleMarkerCleared => continue,
            }),
        );
    }
    match &report.step {
        RefreshStep::Refreshed { parked: false } => push_note(note, Some("refreshed".to_owned())),
        RefreshStep::Refreshed { parked: true } => {
            push_note(note, Some("refreshed (saved as pending)".to_owned()));
        }
        RefreshStep::RacedExternal => {
            push_note(note, Some("refresh raced an external writer".to_owned()));
        }
        RefreshStep::DiscardedExternal => {
            push_note(note, Some("refresh discarded (external writer)".to_owned()));
        }
        _ => {}
    }
}

fn evidence_label(evidence: DaemonEvidence) -> String {
    match evidence {
        DaemonEvidence::None => "none".to_owned(),
        DaemonEvidence::PidAlive(pid) => format!("pid {pid} alive"),
        DaemonEvidence::Recycled(pid) => format!("pid {pid} recycled"),
        DaemonEvidence::ArtefactOnly => "artefact only".to_owned(),
        DaemonEvidence::RecordUnreadable => "record unreadable".to_owned(),
    }
}

pub fn push_note(note: &mut Option<String>, more: Option<String>) {
    let Some(more) = more.filter(|more| !more.is_empty()) else { return };
    *note = Some(match note.take() {
        Some(existing) if !existing.is_empty() => format!("{existing}; {more}"),
        _ => more,
    });
}

/// What reading one row's credential found.
enum Read {
    /// A usable credential, and a note about how it was found.
    Credentials { credentials: Box<Credentials>, note: Option<String> },
    /// No credential to use; the row's state says why.
    State(CodexState, Option<String>),
}

/// What an owned namespace's refresh marker says about the grant in the file.
#[derive(Debug, Clone, PartialEq, Eq)]
enum MarkerView {
    /// Nothing outstanding.
    Clear,
    /// A send of this grant has no known outcome.
    Unknown { since: Timestamp, class: UnknownClass, resend_eligible_at: Option<Timestamp> },
    /// The token host called this grant dead.
    Dead,
    /// The marker cannot be read.
    Unavailable(String),
}

/// Produces one row: read, gate, fetch, normalize. Sends no refresh.
#[expect(
    clippy::too_many_lines,
    reason = "plan section 3.3 step 3 is one decision procedure; its order is the invariant"
)]
pub fn run_row(cancel: &Cancel, plan: RowPlan, shared: &Shared) -> RowPass {
    let (kind, record) = match &plan.source {
        PlanSource::Live { .. } | PlanSource::LiveUnreadable { .. } => (CodexRowKind::Live, None),
        PlanSource::HomeReadOnly { record, .. } => (CodexRowKind::HomeReadOnly, Some(record)),
        PlanSource::Owned { record, .. } | PlanSource::InvalidOwned { record } => {
            (CodexRowKind::Owned, Some(record))
        }
    };
    let span = tracing::info_span!(
        "codex_account",
        account.id = %record.map_or("live", |record| record.chatgpt_user_id.as_str()),
        kind = kind.name(),
    );
    let _entered = span.enter();

    let mut outcome = CodexRowOutcome {
        index: plan.index,
        id: String::new(),
        user_id: record.map(|record| record.chatgpt_user_id.clone()).unwrap_or_default(),
        account_id: record.map(|record| record.chatgpt_account_id.clone()).unwrap_or_default(),
        email: record.and_then(|record| record.email.clone()),
        plan: record.and_then(|record| record.plan_type.clone()),
        kind,
        state: CodexState::Ok,
        lock_state: "none",
        note: None,
        usage: None,
        visible_by_default: true,
    };
    let mut pass = RowPass {
        outcome: CodexRowOutcome { ..outcome.clone() },
        plan: plan.clone(),
        access_digest8: None,
        rejected: None,
        floor_raised: false,
        fetched: false,
    };

    if let Some(report) = &plan.pre_pass
        && plan.retry.is_none()
    {
        push_report_notes(&mut outcome.note, report);
    }

    let mut marker = MarkerView::Clear;
    let read = match &plan.source {
        PlanSource::LiveUnreadable { reason } => {
            Read::State(CodexState::HomeUnreadable { reason: reason.clone() }, None)
        }
        PlanSource::Live { home } | PlanSource::HomeReadOnly { dir: home, .. } => {
            read_home(home, &shared.keyring)
        }
        PlanSource::InvalidOwned { .. } => Read::State(
            CodexState::Error("the record's ids cannot name a namespace".to_owned()),
            None,
        ),
        PlanSource::Owned { record, evidence } => {
            if !matches!(evidence, DaemonEvidence::None) {
                push_note(
                    &mut outcome.note,
                    Some(format!("codex session detected ({})", evidence_label(*evidence))),
                );
            }
            match proof::owned(record) {
                Some(owned) => {
                    let (read, lock_state, view, floor_raised) = read_owned(owned, shared, cancel);
                    outcome.lock_state = lock_state;
                    pass.floor_raised = floor_raised;
                    marker = view;
                    read
                }
                None => Read::State(
                    CodexState::Error("the record's ids cannot name a namespace".to_owned()),
                    None,
                ),
            }
        }
    };

    let credentials = match read {
        Read::State(state, note) => {
            outcome.state = state;
            push_note(&mut outcome.note, note);
            pass.outcome = outcome;
            return pass;
        }
        Read::Credentials { credentials, note } => {
            push_note(&mut outcome.note, note);
            credentials
        }
    };

    if let Some(identity) = credentials.identity() {
        outcome.user_id = identity.user_id;
        outcome.account_id = identity.account_id;
        if identity.email.is_some() {
            outcome.email = identity.email;
        }
        if identity.plan.is_some() {
            outcome.plan = identity.plan;
        }
    }
    pass.access_digest8 = credentials.access_digest8();

    if !credentials.has_usage_source() {
        outcome.state =
            CodexState::NoUsageSource { mode: credentials.auth_mode().label().to_owned() };
        pass.outcome = outcome;
        return pass;
    }

    let now = Timestamp::now();
    // The state a fetched row keeps instead of `ok`, when the marker says the
    // grant's fate is unknown or cannot be read.
    let mut kept_state: Option<CodexState> = None;
    match &marker {
        MarkerView::Dead => {
            outcome.state = CodexState::NeedsLogin;
            push_note(&mut outcome.note, Some(needs_login_note(NeedsLoginReason::Dead)));
            pass.outcome = outcome;
            return pass;
        }
        MarkerView::Unknown { since, class, resend_eligible_at } => {
            let (state, note) = unknown_state(*since, *class, *resend_eligible_at);
            push_note(&mut outcome.note, note);
            // The old access token is probed only while its own `exp` is in
            // the future (fact F88, plan AC123); after that, no request.
            if credentials.access_expired(now, Duration::ZERO) {
                outcome.state = CodexState::NeedsLogin;
                push_note(&mut outcome.note, Some("refresh outcome unknown".to_owned()));
                pass.outcome = outcome;
                return pass;
            }
            kept_state = Some(state);
        }
        MarkerView::Unavailable(reason) => {
            kept_state = Some(CodexState::RefreshStateUnavailable { reason: reason.clone() });
        }
        MarkerView::Clear => {}
    }

    if kept_state.is_none() && credentials.access_expired(now, ACCESS_REFRESH_MARGIN) {
        let (state, note) = expired_state(kind, record, shared.allow_post, plan.pre_pass.as_ref());
        outcome.state = state;
        push_note(&mut outcome.note, note);
        pass.outcome = outcome;
        return pass;
    }

    // The fetch, or the cache.
    let cache_path = cache_path(&shared.paths, &outcome);
    let cached = cache_path.as_deref().and_then(cache::load);
    let now_ms = now.as_millisecond();
    let may_serve = shared.options.may_serve_cache() && plan.retry.is_none();
    if let Some(entry) = cached.as_ref().filter(|entry| {
        may_serve && entry.is_fresh(now_ms, cache::TTL) && entry.rate_limited_until_ms.is_none()
    }) && let Some(usage) = usage_from_cache(entry)
    {
        outcome.state = kept_state.unwrap_or_else(|| usage.state());
        apply_usage(&mut outcome, usage);
        pass.fetched = true;
        pass.outcome = outcome;
        return pass;
    }
    if let Some(entry) = cached.as_ref()
        && let Some(seconds) = entry.rate_limited_for(now_ms)
    {
        // No request inside the server's window, whichever process set it
        // (plan AC101).
        outcome.state = CodexState::RateLimited { retry_after: Some(seconds) };
        if let Some(usage) = usage_from_cache(entry) {
            apply_usage(&mut outcome, usage);
        }
        pass.outcome = outcome;
        return pass;
    }

    let id = outcome.user_id.clone();
    let account = AccountRef { id: &id, auth: credentials.as_ref() };
    let fetched = shared.client.fetch(&account, cancel);
    match fetched {
        Ok(usage) => {
            if let (Some(path), Some(raw)) = (cache_path.as_deref(), usage.raw.as_ref()) {
                // `raw` is the body less its top-level `email` (fact F78-a);
                // it keeps the top-level `user_id` and `account_id`, which are
                // the identifiers this file is already named by, never a
                // token (review S31 F7).
                let entry = CacheEntry::new(usage.fetched_at.as_millisecond(), raw.clone());
                if let Err(err) = cache::store(path, &entry) {
                    tracing::warn!(error = %err, "the Codex usage cache could not be written");
                }
            }
            outcome.state = kept_state.take().unwrap_or_else(|| usage.state());
            apply_usage(&mut outcome, usage);
            pass.fetched = true;
        }
        Err(FetchError::Unauthorized) => {
            let owned_auto = record.is_some_and(|record| {
                matches!(record.kind, CodexKind::Owned { refresh: RefreshPolicy::Auto, .. })
            });
            outcome.state = match plan.retry {
                Some(Retry::Verify) => CodexState::AdoptedGrantDead,
                Some(Retry::AfterSend) => CodexState::Unauthorized { refreshed_recently: true },
                Some(Retry::AfterAdopt) => CodexState::Unauthorized { refreshed_recently: false },
                None if matches!(
                    plan.pre_pass.as_ref().map(|report| &report.step),
                    Some(RefreshStep::RacedExternal)
                ) =>
                {
                    CodexState::AdoptedGrantDead
                }
                // The old token of a grant whose refresh has no known outcome
                // was rejected: nothing may be sent for it, so the row needs a
                // login (plan section 3.3, fact F88).
                None if matches!(kept_state, Some(CodexState::RefreshOutcomeUnknown { .. })) => {
                    push_note(&mut outcome.note, Some("refresh outcome unknown".to_owned()));
                    kept_state = None;
                    CodexState::NeedsLogin
                }
                None => {
                    if owned_auto && shared.allow_post && kept_state.is_none() {
                        pass.rejected = credentials.access_digest8();
                    } else if owned_auto && !shared.allow_post {
                        push_note(&mut outcome.note, Some(EXPIRED_IN_WATCH.to_owned()));
                    }
                    CodexState::Unauthorized { refreshed_recently: false }
                }
            };
            if let Some(usage) = cached.as_ref().and_then(usage_from_cache) {
                apply_usage(&mut outcome, usage);
            }
        }
        Err(FetchError::RateLimited { retry_after }) => {
            let seconds = retry_after.map(|wait| wait.as_secs());
            outcome.state = CodexState::RateLimited { retry_after: seconds };
            if let (Some(path), Some(wait)) = (cache_path.as_deref(), retry_after) {
                store_rate_limit(path, cached.clone(), now_ms, wait);
            }
            if let Some(usage) = cached.as_ref().and_then(usage_from_cache) {
                apply_usage(&mut outcome, usage);
            }
        }
        Err(err @ (FetchError::Transport(_) | FetchError::Cancelled)) => {
            outcome.state = CodexState::Stale;
            push_note(&mut outcome.note, Some(err.to_string()));
            if let Some(usage) = cached.as_ref().and_then(usage_from_cache) {
                apply_usage(&mut outcome, usage);
            }
        }
        Err(err @ (FetchError::Http { .. } | FetchError::Parse(_))) => {
            outcome.state = CodexState::Error(err.to_string());
            if let Some(usage) = cached.as_ref().and_then(usage_from_cache) {
                apply_usage(&mut outcome, usage);
            }
        }
    }
    // A marker that says the grant's fate is unknown, or cannot be read,
    // outranks a transient fetch failure: the failure is kept as a note.
    if let Some(kept) = kept_state {
        push_note(&mut outcome.note, Some(outcome.state.label()));
        outcome.state = kept;
    }
    pass.outcome = outcome;
    pass
}

/// The state of an expired row that is not fetched.
fn expired_state(
    kind: CodexRowKind,
    record: Option<&CodexAccountRecord>,
    allow_post: bool,
    pre_pass: Option<&RefreshReport>,
) -> (CodexState, Option<String>) {
    let expired = |reason: &str| CodexState::Expired { reason: reason.to_owned() };
    let policy = record.and_then(|record| match record.kind {
        CodexKind::Owned { refresh, .. } => Some(refresh),
        CodexKind::Live | CodexKind::HomeReadOnly { .. } => None,
    });
    match (kind, policy) {
        (CodexRowKind::Live | CodexRowKind::HomeReadOnly, _) => (expired(EXPIRED_READ_ONLY), None),
        (CodexRowKind::Owned, Some(RefreshPolicy::Never)) => (expired(EXPIRED_NEVER), None),
        (CodexRowKind::Owned, _) if !allow_post => (expired(EXPIRED_IN_WATCH), None),
        (CodexRowKind::Owned, _) => match pre_pass.map(|report| &report.step) {
            Some(step) => step_state(step).unwrap_or_else(|| (CodexState::Stale, step_note(step))),
            None => (CodexState::Stale, None),
        },
    }
}

/// Reads a live or imported home's `auth.json`, read-only.
fn read_home(home: &Path, keyring: &KeyringListing) -> Read {
    let (mode, config_note) = home::store_mode(home);
    let mut note =
        config_note.map(|_| "config.toml could not be read; file store assumed".to_owned());
    match home::file_in_effect(&mode, || keyring.probe(home)) {
        FileInEffect::NotRead(mode) => {
            return Read::State(CodexState::StoreModeUnsupported { mode }, note);
        }
        FileInEffect::Read { note: Some(mode_note) } => {
            push_note(&mut note, Some(mode_note.to_owned()))
        }
        FileInEffect::Read { note: None } => {}
    }
    let resolved = match auth_store::read_live(home) {
        CodexResolved::Torn => {
            thread::sleep(TORN_RETRY);
            auth_store::read_live(home)
        }
        other => other,
    };
    match resolved {
        CodexResolved::Credentials(credentials) => Read::Credentials { credentials, note },
        CodexResolved::Absent => {
            push_note(&mut note, Some("no credential in this Codex home".to_owned()));
            Read::State(CodexState::NeedsLogin, note)
        }
        CodexResolved::Transient(reason) => Read::State(CodexState::Error(reason), note),
        CodexResolved::Torn => Read::State(CodexState::TornRead, note),
    }
}

/// Reads an owned namespace under its lock, then lets the lock go.
///
/// Returns the read, the lock state, the marker's view of the grant, and
/// whether the marker holds a raised floor.
fn read_owned(
    owned: proof::OwnedRecord<'_>,
    shared: &Shared,
    cancel: &Cancel,
) -> (Read, &'static str, MarkerView, bool) {
    let guard = match lock::acquire_codex(
        &shared.paths,
        owned,
        LockBudget::Pass(PASS_LOCK_BUDGET),
        cancel,
        &shared.fault,
    ) {
        Ok(guard) => guard,
        Err(LockError::Busy) => {
            return (Read::State(CodexState::Busy, None), "busy", MarkerView::Clear, false);
        }
        Err(LockError::Cancelled) => {
            return (Read::State(CodexState::Stale, None), "none", MarkerView::Clear, false);
        }
        Err(err) => {
            return (
                Read::State(CodexState::LockUnavailable, Some(err.to_string())),
                "unavailable",
                MarkerView::Clear,
                false,
            );
        }
    };
    let ns = match OwnedNamespace::open(&shared.paths, owned, &guard) {
        Ok(ns) => ns,
        Err(err) => {
            return (
                Read::State(CodexState::Error(err.to_string()), None),
                "acquired",
                MarkerView::Clear,
                false,
            );
        }
    };
    let read = match ns.read() {
        Ok(NamespaceRead::Torn) => {
            thread::sleep(TORN_RETRY);
            ns.read()
        }
        other => other,
    };
    let credentials: LockedCredentials<'_> = match read {
        Ok(NamespaceRead::Credentials(credentials)) => *credentials,
        Ok(NamespaceRead::Absent) => {
            return (
                Read::State(
                    CodexState::NeedsLogin,
                    Some(needs_login_note(NeedsLoginReason::Absent)),
                ),
                "acquired",
                MarkerView::Clear,
                false,
            );
        }
        Ok(NamespaceRead::Torn) => {
            return (Read::State(CodexState::TornRead, None), "acquired", MarkerView::Clear, false);
        }
        Err(err) => {
            return (
                Read::State(CodexState::Error(err.to_string()), None),
                "acquired",
                MarkerView::Clear,
                false,
            );
        }
    };
    let (view, floor_raised) =
        marker_view(ns.refresh_state().load(), credentials.refresh_digest8());
    // The lock ends with this function: a usage request reads a token and
    // writes nothing, and must not make another process's refresh `busy`.
    let credentials = Box::new(credentials.into_credentials());
    (Read::Credentials { credentials, note: None }, "acquired", view, floor_raised)
}

/// What a marker says about the grant whose refresh digest prefix is `grant`,
/// and whether its floor was raised. Reads only.
fn marker_view(read: RefreshStateRead, grant: Option<String>) -> (MarkerView, bool) {
    let state: RefreshState = match read {
        RefreshStateRead::Present(state) => state,
        RefreshStateRead::Absent => return (MarkerView::Clear, false),
        RefreshStateRead::Unavailable(reason) => return (MarkerView::Unavailable(reason), false),
    };
    let floor_raised = state.did_not_help > 0 || state.floor_min != auth_store::DEFAULT_FLOOR_MIN;
    let Some(grant) = grant else { return (MarkerView::Clear, floor_raised) };
    if state.dead_digest8.as_deref() == Some(grant.as_str()) {
        return (MarkerView::Dead, floor_raised);
    }
    match &state.inflight {
        Some(inflight) if inflight.sent_digest8 == grant => {
            let since = state.ambiguous_since.unwrap_or(inflight.sent_at);
            let class = state.class.unwrap_or(UnknownClass::Interrupted);
            let resend_eligible_at = (!state.resent)
                .then(|| refresh::resend_eligible_at(since, class, state.retry_after));
            (MarkerView::Unknown { since, class, resend_eligible_at }, floor_raised)
        }
        _ => (MarkerView::Clear, floor_raised),
    }
}

/// The row's cache file, keyed by its identity; `None` when it has none.
fn cache_path(paths: &Paths, outcome: &CodexRowOutcome) -> Option<PathBuf> {
    (!outcome.user_id.is_empty() && !outcome.account_id.is_empty())
        .then(|| cache::path_for(paths, Provider::Codex, &outcome.user_id, &outcome.account_id))
}

/// A cached body, normalized as a fresh one would be.
fn usage_from_cache(entry: &CacheEntry) -> Option<CodexUsage> {
    let fetched_at = Timestamp::from_millisecond(entry.fetched_at_ms).ok()?;
    usage::normalize(&entry.body, fetched_at, true).ok()
}

/// Records a server's `retry-after` beside the cached body, so a second run
/// inside the window declines to call too.
fn store_rate_limit(path: &Path, cached: Option<CacheEntry>, now_ms: i64, wait: Duration) {
    let Ok(wait_ms) = i64::try_from(wait.as_millis()) else { return };
    let Some(until) = now_ms.checked_add(wait_ms) else { return };
    let mut entry = cached.unwrap_or_else(|| CacheEntry::new(0, Value::Object(Map::new())));
    entry.rate_limited_until_ms = Some(until);
    if let Err(err) = cache::store(path, &entry) {
        tracing::warn!(error = %err, "the Codex rate-limit window could not be cached");
    }
}

/// Puts a usage onto a row: the plan it names, its note, its figures.
fn apply_usage(outcome: &mut CodexRowOutcome, usage: CodexUsage) {
    if usage.plan_type.is_some() {
        outcome.plan.clone_from(&usage.plan_type);
    }
    push_note(&mut outcome.note, usage.note.clone());
    outcome.usage = Some(usage);
}

/// Finishes a pass: display ids, the live/imported fold, and a note for a
/// row a successful refresh left.
pub fn finish(passes: Vec<RowPass>) -> Vec<CodexRowOutcome> {
    let users: Vec<String> = passes.iter().map(|pass| pass.outcome.user_id.clone()).collect();
    let live_digest = passes
        .iter()
        .find(|pass| pass.outcome.kind == CodexRowKind::Live)
        .and_then(|pass| pass.access_digest8.clone());
    let live_home = passes.iter().find_map(|pass| match &pass.plan.source {
        PlanSource::Live { home } => home.canonicalize().ok(),
        _ => None,
    });

    passes
        .into_iter()
        .map(|pass| {
            let mut outcome = pass.outcome;
            outcome.id = display_id(&outcome, &users);
            if let PlanSource::HomeReadOnly { dir, record } = &pass.plan.source {
                let same_home = live_home.is_some() && dir.canonicalize().ok() == live_home;
                let same_grant = live_digest.is_some() && pass.access_digest8 == live_digest;
                let names_record = outcome.user_id == record.chatgpt_user_id
                    && outcome.account_id == record.chatgpt_account_id;
                if same_home && !names_record && !outcome.user_id.is_empty() {
                    // The import recorded an account this home no longer holds:
                    // the live row shows what it holds now (plan section 3.3).
                    outcome.state = CodexState::StaleSiblingOfLive;
                    outcome.usage = None;
                    outcome.visible_by_default = false;
                } else if same_grant {
                    // Folded into the live row (D23): the same grant read twice
                    // is one account, not two.
                    outcome.visible_by_default = false;
                    push_note(&mut outcome.note, Some("same credential as live".to_owned()));
                }
            }
            outcome
        })
        .collect()
}

/// The display id (decision D-039): the user id when unique in the pass, else
/// `<user>/<account>`; `live` for a live row that named nobody.
fn display_id(outcome: &CodexRowOutcome, users: &[String]) -> String {
    if outcome.user_id.is_empty() {
        return "live".to_owned();
    }
    let count = users.iter().filter(|user| **user == outcome.user_id).count();
    if count <= 1 {
        outcome.user_id.clone()
    } else {
        format!("{}/{}", outcome.user_id, outcome.account_id)
    }
}
#[cfg(test)]
#[path = "pass_tests.rs"]
mod tests;
