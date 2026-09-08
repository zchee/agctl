//! `agentctl claude status` — the pass that produces the table.
//!
//! The shape is plan section 3.3, and its five steps are the five stages
//! below: load and preflight, discover, fan out, normalize, render and exit.
//! Three of its rules are the reason this file is as long as it is.
//!
//! # Refusing is the default
//!
//! agentctl writes exactly one file per account it owns, and only when it is
//! certain nothing else is using that namespace. Before a refresh POST is
//! sent the pass checks the write target, takes a lock that lives *outside*
//! the namespace, re-checks for a Claude Code session under that lock, and
//! re-checks again immediately before the rename (invariant I3, plan AC21).
//! Any surprise at any of those points ends in a refusal, not a write. A row
//! that says `claude session detected` is the system working.
//!
//! Rows agentctl does *not* own — the live credential, a foreign
//! configuration directory, a namespace whose credentials a session has
//! migrated into the keychain — are never refreshed and, when expired, are
//! not even fetched (decision D-001, plan AC5). Their owner refreshes them;
//! agentctl reports.
//!
//! # A failed fetch shows the last good numbers
//!
//! A 429, a dropped connection or a keychain that went away renders the
//! cached value with the row marked `rate-limited` or `stale`, rather than a
//! blank cell (plan principle P4, AC8). The exit status still reports the
//! degradation, so a script can tell.
//!
//! # The exit status is about *shown* rows
//!
//! Exit 2 means "you asked for numbers and at least one row you can see did
//! not have them". A row hidden by default — a stale sibling, a foreign
//! keychain item — cannot change the exit status, because the user did not
//! ask about it (plan section 3.2).

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use jiff::Timestamp;
use serde_json::Map;
use serde_json::Value;
use tracing::field::Empty;

use crate::cli::Cli;
use crate::cli::StatusArgs;
use crate::config::AccountKind;
use crate::config::AccountRecord;
use crate::config::AgentctlConfig;
use crate::config::paths::Paths;
use crate::error::AppError;
use crate::provider::AccountRef;
use crate::provider::FetchError;
use crate::provider::UsageProvider;
use crate::provider::claude::account::AccountRow;
use crate::provider::claude::account::AccountState;
use crate::provider::claude::account::Source;
use crate::provider::claude::credentials::Credentials;
use crate::provider::claude::credentials::Digests;
use crate::provider::claude::credentials::REFRESH_MARGIN_MS;
use crate::provider::claude::discovery;
use crate::provider::claude::namespace;
use crate::provider::claude::namespace::EnvView;
use crate::provider::claude::oauth::OauthClient;
use crate::provider::claude::usage::RefreshError;
use crate::provider::claude::usage::TokenRefresher;
use crate::provider::claude::usage::UsageClient;
use crate::provider::claude::usage::parse_usage;
use crate::render::Report;
use crate::render::StatusRow;
use crate::render::json;
use crate::render::json::JsonRow;
use crate::render::json::StatusReport;
use crate::render::table;
use crate::runtime::coordinator::Cancel;
use crate::runtime::coordinator::DEFAULT_MAX_WORKERS;
use crate::runtime::coordinator::Job;
use crate::runtime::coordinator::PassCtx;
use crate::runtime::coordinator::run_pass;
use crate::runtime::fault::Fault;
use crate::secret::KeychainReader;
use crate::secret::ServiceEntry;
use crate::secret::file_store;
use crate::secret::file_store::CREDENTIALS_FILE;
use crate::secret::file_store::FileSnapshot;
use crate::secret::file_store::FileStoreError;
use crate::secret::file_store::PENDING_FILE;
use crate::secret::file_store::PendingDecision;
use crate::secret::file_store::PendingDiscardReason;
use crate::secret::file_store::WriteOutcome;
use crate::secret::file_store::WriteRequest;
use crate::secret::foreign_activity;
use crate::secret::foreign_activity::ForeignActivity;
use crate::secret::foreign_activity::OwnedMeta;
use crate::secret::location;
use crate::secret::location::Resolved;
use crate::secret::namespace_lock;
use crate::secret::namespace_lock::LockError;
use crate::usage::cache;
use crate::usage::model::UsageSnapshot;

/// How much longer than one request the whole pass may take.
///
/// Three requests' worth: a refresh POST, a usage GET, and one retry of the
/// GET after a 401. A worker that has not finished by then is holding the
/// pass open past anything the user asked for.
pub const PASS_TIMEOUT_MULTIPLIER: u32 = 3;

/// Runs `agentctl claude status`.
///
/// # Errors
///
/// [`AppError::Partial`] when a shown row is degraded — the table is still on
/// stdout, and this only sets the exit status. Anything else is fatal and
/// means nothing was rendered.
pub fn run(cli: &Cli, args: &StatusArgs, cancel: &Cancel) -> Result<(), AppError> {
    // Step 1: load. `ensure_dirs` is what makes a first run work at all — the
    // cache write later would otherwise fail on a store that does not exist.
    let paths = Arc::new(Paths::resolve(cli.config_dir.as_deref())?);
    paths.ensure_dirs()?;
    let config = AgentctlConfig::load(&paths)?;
    let env = EnvView::from_process();

    let deadline = pass_deadline(args.timeout);
    let discovery_ctx = PassCtx::standalone(cancel.clone(), deadline);

    // Step 2: discover. The preflight and the `dump-keychain` listing happen
    // once per pass, not once per row: they are the same answer for every
    // account, and asking twelve times would mean twelve subprocesses.
    let reader = crate::secret::default_reader(&discovery_ctx);
    let found = discovery::discover(&config, &paths, reader.as_ref(), &env, &discovery_ctx);
    tracing::debug!(
        rows = found.rows.len(),
        keychain = ?found.preflight,
        services = found.listing.len(),
        "discovery finished"
    );

    // Step 3: fan out. Each worker owns its row outright; nothing is shared
    // but immutable configuration, so a stuck account cannot block another.
    let shared = Shared {
        paths: Arc::clone(&paths),
        client: UsageClient::from_env(args.timeout),
        refresher: default_refresher()?,
        reader_factory: production_readers(),
        listing: found.listing,
        fault: current_fault(),
        options: Options { refresh: args.refresh, no_cache: args.no_cache },
    };

    let outcomes = collect(found.rows, &args.account, shared, cancel, deadline)?;

    // Steps 4 and 5: render, then map the shown rows onto the exit status.
    let failed = outcomes
        .iter()
        .filter(|outcome| (args.all || outcome.visible_by_default) && outcome.state.is_failure())
        .count();

    let report = Report {
        rows: outcomes.iter().map(RowOutcome::to_status_row).collect(),
        now: Timestamp::now(),
        show_all: args.all,
    };

    // `--json` replaces the table rather than accompanying it: the document is
    // the whole of stdout, so a caller can pipe it straight into a parser.
    // Log lines are on stderr already (see `main::init_tracing`), which is what
    // makes that safe.
    if args.json {
        let document = json_report(&outcomes, &report, args.raw);
        let text = serde_json::to_string_pretty(&document).map_err(|err| {
            AppError::Config(format!("the JSON report could not be serialized: {err}"))
        })?;
        println!("{text}");
    } else {
        println!("{}", table::render(&report));
        if args.raw {
            print_raw(&outcomes, args.all);
        }
    }

    if failed > 0 { Err(AppError::Partial { failed }) } else { Ok(()) }
}

/// Runs the fan-out and returns one outcome per selected row, in discovery
/// order.
///
/// Split out of [`run`] so a test can drive the whole decision procedure —
/// cache, lock, pending resolution, refresh, fetch — against an `httpmock`
/// server and a temporary store, without going near the process environment.
/// Everything ambient (which endpoint, which keychain, which faults) arrives
/// inside [`Shared`].
///
/// # Errors
///
/// Returns [`AppError::Config`] when an `--account` selector matches nothing.
pub fn collect(
    rows: Vec<AccountRow>,
    selectors: &[String],
    shared: Shared,
    cancel: &Cancel,
    deadline: Instant,
) -> Result<Vec<RowOutcome>, AppError> {
    let selected = select(rows, selectors)?;
    let shared = Arc::new(shared);

    let jobs: Vec<Job<RowOutcome>> = selected
        .into_iter()
        .enumerate()
        .map(|(index, row)| {
            let shared = Arc::clone(&shared);
            let job: Job<RowOutcome> = Box::new(move |ctx| run_account(ctx, index, row, &shared));
            job
        })
        .collect();

    let mut outcomes: Vec<RowOutcome> =
        run_pass(jobs, cancel.clone(), deadline, DEFAULT_MAX_WORKERS).into_iter().collect();
    // Results arrive in completion order; the table is in discovery order, so
    // that two runs of `status` on an unchanged machine look the same.
    outcomes.sort_by_key(|outcome| outcome.index);
    Ok(outcomes)
}

/// Builds the `StatusReport v1` document from a finished pass.
///
/// The rows are the ones the table would have shown, in the same order, so the
/// two renderings of one pass never disagree about what exists. `hidden` is
/// the same count the table's footer prints.
///
/// `raw` carries the untouched usage bodies, keyed by row id, and only when
/// `--raw` was given. Those bodies are usage figures — the `spend` object this
/// build deliberately never parses among them (plan AC23) — and carry no token
/// material (invariant I4).
fn json_report(outcomes: &[RowOutcome], report: &Report, raw: bool) -> StatusReport {
    let mut document = StatusReport::new(report.now, report.hidden_count());
    let shown = outcomes.iter().filter(|outcome| report.show_all || outcome.visible_by_default);

    let mut bodies = Map::new();
    for outcome in shown {
        document.rows.push(outcome.to_json_row());
        if raw && let Some(body) = outcome.usage.as_ref().and_then(|usage| usage.raw.as_ref()) {
            bodies.insert(outcome.id.clone(), body.clone());
        }
    }
    if raw {
        document.raw = Some(bodies);
    }
    document
}

/// Prints each shown row's untouched response body after the table.
///
/// Separate from the table rather than inside it because a usage body is a
/// couple of kilobytes of JSON and a table cell is not where anyone would
/// read it. In S6 the same bodies become the `raw` member of the JSON report;
/// until then this is what makes `--raw` observable.
///
/// The bodies carry usage figures and no token material (invariant I4).
fn print_raw(outcomes: &[RowOutcome], show_all: bool) {
    for outcome in outcomes {
        if !show_all && !outcome.visible_by_default {
            continue;
        }
        let Some(raw) = outcome.usage.as_ref().and_then(|usage| usage.raw.as_ref()) else {
            continue;
        };
        println!("\n--- raw: {} ---", outcome.account);
        match serde_json::to_string_pretty(raw) {
            Ok(text) => println!("{text}"),
            Err(err) => tracing::warn!(error = %err, "the raw body could not be re-serialized"),
        }
    }
}

/// The instant after which the pass stops starting new work.
///
/// Saturates rather than wrapping on an absurd `--timeout` (constraint
/// C-006): a wrapped deadline would land in the past and abort the pass
/// before it began.
fn pass_deadline(timeout: Duration) -> Instant {
    let now = Instant::now();
    timeout
        .checked_mul(PASS_TIMEOUT_MULTIPLIER)
        .and_then(|budget| now.checked_add(budget))
        .unwrap_or(now)
}

/// The fault set this process was asked to inject.
///
/// Always empty without the `testing` feature: fault injection is a test
/// seam, and a production build has no way to switch it on (plan section
/// 3.9).
pub fn current_fault() -> Fault {
    #[cfg(feature = "testing")]
    {
        Fault::from_env()
    }
    #[cfg(not(feature = "testing"))]
    {
        Fault::none()
    }
}

/// Narrows the discovered rows to the ones `--account` asked for.
///
/// # Errors
///
/// Returns [`AppError::Config`] when a selector matches nothing, naming what
/// was available — silently rendering an empty table would look like "you
/// have no accounts" rather than "that is not one of them".
fn select(rows: Vec<AccountRow>, selectors: &[String]) -> Result<Vec<AccountRow>, AppError> {
    if selectors.is_empty() {
        return Ok(rows);
    }

    for selector in selectors {
        if !rows.iter().any(|row| matches_selector(row, selector)) {
            let known: Vec<&str> = rows.iter().map(|row| row.id.as_str()).collect();
            return Err(AppError::Config(format!(
                "no account matches `{selector}`; known accounts: {}",
                known.join(", ")
            )));
        }
    }

    Ok(rows
        .into_iter()
        .filter(|row| selectors.iter().any(|selector| matches_selector(row, selector)))
        .collect())
}

/// Whether one `--account` selector names this row.
///
/// The accepted spellings are the ones plan section 3.2 lists: the account
/// UUID, `<acct>/<org>` when the UUID is ambiguous, and the email address.
fn matches_selector(row: &AccountRow, selector: &str) -> bool {
    let record = &row.record;
    row.id == selector
        || record.account_uuid == selector
        || record.email.as_deref() == Some(selector)
        || format!("{}/{}", record.account_uuid, record.organization_uuid) == selector
}

/// The `--refresh` / `--no-cache` pair, which both bypass the cache.
#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Refresh expired credentials even when a cached value would do.
    pub refresh: bool,
    /// Ignore the on-disk usage cache for this pass.
    pub no_cache: bool,
}

impl Options {
    /// Whether a cached value may be served instead of fetching.
    fn may_serve_cache(self) -> bool {
        !self.refresh && !self.no_cache
    }
}

/// Builds the keychain reader a worker should use.
///
/// A factory rather than a shared reader because a reader spawns
/// `security(1)`, and a child has to be registered with the *worker's*
/// [`PassCtx`] for the coordinator to be able to kill it when the pass is
/// cancelled (plan AC43). It is also the seam a test replaces with a scripted
/// double, which is what keeps the pass tests off the real keychain.
pub type ReaderFactory =
    Arc<dyn Fn(&PassCtx) -> Box<dyn KeychainReader + Send + Sync> + Send + Sync>;

/// The reader factory a real run uses.
pub fn production_readers() -> ReaderFactory {
    Arc::new(crate::secret::default_reader)
}

/// Everything the workers share, built once per pass.
pub struct Shared {
    /// The store the pass reads and writes.
    pub paths: Arc<Paths>,
    /// The usage endpoint client.
    pub client: UsageClient,
    /// What mints a new access token from a stored refresh token.
    pub refresher: Arc<dyn TokenRefresher>,
    /// How a worker builds its own keychain reader.
    pub reader_factory: ReaderFactory,
    /// The `dump-keychain` listing this pass took, attributes only.
    pub listing: Vec<ServiceEntry>,
    /// The faults injected into this pass.
    pub fault: Fault,
    /// The cache options this pass runs under.
    pub options: Options,
}

/// One finished row.
#[derive(Debug)]
pub struct RowOutcome {
    /// The row's position in discovery order, which is the order the table
    /// and the watch display put it back into.
    pub index: usize,
    /// The identifier `--account` accepts, and the key `--raw` files this
    /// row's body under in the JSON report.
    pub id: String,
    /// What the registry knows: the identifiers, the labels, and the kind.
    /// Kept whole rather than copied field by field, because the JSON report
    /// publishes most of it and a copy would be one more place to forget.
    pub record: AccountRecord,
    /// Where the credentials behind this row came from.
    pub source: Source,
    /// The first column: the email when known, else the row id.
    pub account: String,
    /// The organization's display name, or its UUID when unnamed.
    pub org: String,
    /// The subscription tier, as the credential recorded it.
    pub plan: String,
    /// What the pass concluded about this row.
    pub state: AccountState,
    /// What the namespace lock did on this pass, from [`LockedResult`]. Only
    /// the JSON report shows it — the table has no column for it — and plan
    /// AC7 pins the `busy` case.
    pub lock_state: &'static str,
    /// A short explanation appended to the state, when there is one.
    pub note: Option<String>,
    /// The numbers, when this row has any.
    pub usage: Option<UsageSnapshot>,
    /// Whether the row appears without `--all`.
    pub visible_by_default: bool,
}

impl RowOutcome {
    fn to_status_row(&self) -> StatusRow {
        StatusRow {
            account: self.account.clone(),
            org: self.org.clone(),
            plan: self.plan.clone(),
            state: self.state.label(),
            note: self.note.clone(),
            usage: self.usage.clone(),
            visible_by_default: self.visible_by_default,
        }
    }

    fn to_json_row(&self) -> JsonRow {
        let usage = self.usage.as_ref();
        JsonRow {
            id: self.id.clone(),
            account_uuid: self.record.account_uuid.clone(),
            organization_uuid: self.record.organization_uuid.clone(),
            email: self.record.email.clone(),
            org_name: self.record.org_name.clone(),
            kind: self.record.kind.name(),
            source: self.source.name(),
            state: self.state.name(),
            state_label: self.state.label(),
            lock_state: self.lock_state,
            windows: json::windows_of(usage),
            credits: json::credits_of(usage),
            next_reset: json::next_reset_of(usage),
            note: self.note.clone(),
        }
    }
}

/// Produces one row: cache, refresh, fetch, normalize.
#[expect(
    clippy::too_many_lines,
    reason = "plan section 3.3 step 3 is one decision procedure, and the order \
              of its checks is the invariant; splitting it would let a later \
              edit reorder them without noticing"
)]
fn run_account(ctx: &PassCtx, index: usize, row: AccountRow, shared: &Shared) -> RowOutcome {
    let span = tracing::info_span!(
        "account",
        account.id = %row.id,
        kind = row.record.kind.name(),
        source = ?row.source,
        cache.hit = Empty,
        http.status = Empty,
        retry_after = Empty,
        lock_state = "none",
        lock.age_ms = Empty,
        keychain.avail = matches!(row.source, Source::Keychain),
        pending.decision = Empty,
    );
    let _entered = span.enter();

    let AccountRow { id, record, state, credentials, visible_by_default, note, source } = row;
    let mut outcome = RowOutcome {
        index,
        id: id.clone(),
        record: record.clone(),
        source,
        account: record.email.clone().unwrap_or_else(|| id.clone()),
        org: record.org_name.clone().unwrap_or_else(|| record.organization_uuid.clone()),
        plan: credentials.as_ref().and_then(|c| c.subscription_type.clone()).unwrap_or_default(),
        state,
        lock_state: "none",
        note,
        usage: None,
        visible_by_default,
    };

    let now_ms = now_ms();
    // Every row gets a cache entry, including one keyed by a keychain service
    // name: `cache::path` names a file for any identifier at all, so a row
    // agentctl cannot refresh is still not made to re-fetch on every pass.
    let cache_path = cache::path(&shared.paths, &record.account_uuid, &record.organization_uuid);
    let entry = cache::load(&cache_path);
    let cached_usage = || {
        entry.as_ref().and_then(|entry| {
            let fetched_at = Timestamp::from_millisecond(entry.fetched_at_ms).ok()?;
            parse_usage(&entry.body, fetched_at, true).ok()
        })
    };

    let owns = matches!(record.kind, AccountKind::Owned { .. });
    // Both questions are asked of the state *discovery* produced, before the
    // pending resolution below can change it. A discarded pending is not a
    // reason to stop fetching (plan AC33 (b) expects a POST after one), and
    // an unreadable row is not made readable by one.
    let mut network_allowed = outcome.state.allows_network();
    // Discovery has already looked for a session or a migration; a row it
    // flagged is one agentctl must not write, whoever owns the record.
    let refreshable = owns
        && !matches!(
            outcome.state,
            AccountState::ClaudeSessionDetected { .. } | AccountState::MigratedToKeychain { .. }
        );

    // A pending write from an earlier run is resolved before anything else —
    // before the cache is even consulted. It holds a second copy of a refresh
    // token, and a user who runs `status` inside the cache TTL would
    // otherwise leave that copy on disk indefinitely (invariant I5, risk
    // R24). The common case costs one `lstat`; only a namespace that really
    // has a pending file pays for the lock.
    //
    // It runs for *every* owned row — including one that will never be
    // refreshed and one whose credential file is gone — and the decision it
    // produces is what the row reports (plan AC33 (f), (g), (h)).
    // `symlink_metadata` rather than `exists`, so a dangling symlink planted
    // at that path counts as present and is destroyed rather than ignored.
    let ns_dir = shared.paths.namespace_dir(&record.account_uuid, &record.organization_uuid);
    let mut credentials = credentials;
    if owns && std::fs::symlink_metadata(ns_dir.join(PENDING_FILE)).is_ok() {
        let result = under_namespace_lock(ctx, shared, &record, &ns_dir, false);
        apply(&span, &mut outcome, &result);
        match result.credentials {
            Some(resolved) => {
                // The resolution handed back a credential read from the file
                // under the lock, so the row has one whatever discovery
                // thought. A first-write replay turns `needs login` into a
                // fetchable row (plan AC33 (f)), and a discard does not stop
                // the refresh the file still needs (plan AC33 (b)) — which is
                // why neither the old state nor the new one can be the gate.
                credentials = Some(resolved);
                network_allowed = true;
            }
            None => {
                outcome.usage = cached_usage();
                return outcome;
            }
        }
    }

    // A server-imposed wait outlives the process that was told about it
    // (plan AC8): a second `status` inside the window must not call either.
    if let Some(seconds) = entry.as_ref().and_then(|entry| entry.rate_limited_for(now_ms)) {
        span.record("retry_after", seconds);
        outcome.state = AccountState::RateLimited { retry_after_s: Some(seconds) };
        outcome.usage = cached_usage();
        if outcome.usage.is_some() {
            outcome.note = Some("showing the cached value".to_owned());
        }
        return outcome;
    }

    if credentials.is_some()
        && shared.options.may_serve_cache()
        && let Some(fresh) = entry.as_ref().filter(|entry| entry.is_fresh(now_ms, cache::TTL))
        && let Ok(fetched_at) = Timestamp::from_millisecond(fresh.fetched_at_ms)
        && let Ok(usage) = parse_usage(&fresh.body, fetched_at, true)
    {
        span.record("cache.hit", true);
        outcome.state = classify(&usage, &outcome.state);
        outcome.usage = Some(usage);
        return outcome;
    }
    span.record("cache.hit", false);

    // Rows that cannot make a request at all: no credential, a locked
    // keychain, a hidden sibling. Discovery already said so; the pass only
    // has to not undo it.
    if !network_allowed {
        return outcome;
    }
    let Some(mut current) = credentials else {
        outcome.state = AccountState::NeedsLogin;
        return outcome;
    };
    outcome.plan = current.subscription_type.clone().unwrap_or_else(|| outcome.plan.clone());

    let expired = current.access_expired(now_ms, REFRESH_MARGIN_MS);
    if expired && refreshable {
        let result = under_namespace_lock(ctx, shared, &record, &ns_dir, true);
        apply(&span, &mut outcome, &result);
        match result.credentials {
            Some(refreshed) => {
                outcome.plan =
                    refreshed.subscription_type.clone().unwrap_or_else(|| outcome.plan.clone());
                current = refreshed;
            }
            None => {
                outcome.usage = cached_usage();
                return outcome;
            }
        }
    } else if expired {
        // Not ours to refresh: report it and spend no request on it
        // (decision D-001, plan AC5). An owned row that is expired *and*
        // unrefreshable keeps the state that made it unrefreshable.
        if !owns {
            outcome.state = AccountState::Expired { read_only: true };
        }
        outcome.usage = cached_usage();
        return outcome;
    }

    // The fetch, with at most one refresh in the middle of it.
    let carried = outcome.state.clone();
    let mut refreshed_once = false;
    loop {
        // The borrow of `current` ends with this statement, so the 401 arm
        // below can move it into the refresh.
        let fetched =
            shared.client.fetch(&AccountRef { id: &id, credentials: &current }, ctx.cancel());

        match fetched {
            Ok(usage) => {
                span.record("http.status", 200);
                if let Some(body) = usage.raw.as_ref() {
                    store_cache(&cache_path, body, usage.fetched_at.as_millisecond(), None);
                }
                outcome.state = merge_states(carried.clone(), classify(&usage, &AccountState::Ok));
                outcome.usage = Some(usage);
                return outcome;
            }
            Err(FetchError::Unauthorized) if refreshable && !refreshed_once => {
                // The token expired between the expiry check and the request.
                // Routine: the two use different clocks.
                span.record("http.status", 401);
                refreshed_once = true;
                let result = under_namespace_lock(ctx, shared, &record, &ns_dir, true);
                apply(&span, &mut outcome, &result);
                match result.credentials {
                    Some(refreshed) => current = refreshed,
                    None => {
                        if outcome.state == carried {
                            outcome.state = AccountState::NeedsLogin;
                        }
                        outcome.usage = cached_usage();
                        return outcome;
                    }
                }
            }
            Err(FetchError::Unauthorized) => {
                span.record("http.status", 401);
                outcome.state = AccountState::NeedsLogin;
                outcome.usage = cached_usage();
                return outcome;
            }
            Err(FetchError::RateLimited { retry_after }) => {
                span.record("http.status", 429);
                let seconds = retry_after.map(|after| after.as_secs());
                if let Some(seconds) = seconds {
                    span.record("retry_after", seconds);
                }
                // Persist the window so the *next* invocation also declines
                // to call, not merely the rest of this pass (plan AC8).
                if let Some(entry) = entry.as_ref() {
                    let until = retry_after
                        .and_then(|after| i64::try_from(after.as_millis()).ok())
                        .and_then(|millis| now_ms.checked_add(millis));
                    store_cache(&cache_path, &entry.body, entry.fetched_at_ms, until);
                }
                outcome.state = AccountState::RateLimited { retry_after_s: seconds };
                outcome.usage = cached_usage();
                if outcome.usage.is_some() {
                    outcome.note = Some("showing the cached value".to_owned());
                }
                return outcome;
            }
            Err(err) => {
                if let FetchError::Http { status } = err {
                    span.record("http.status", status);
                }
                // A cached value is only worth showing behind `stale` when
                // another pass could replace it. A permanent failure gets
                // the error, so the row says what to fix rather than what to
                // wait for.
                outcome.usage = cached_usage();
                outcome.state = if err.is_transient() && outcome.usage.is_some() {
                    AccountState::Stale
                } else {
                    AccountState::Error(err.to_string())
                };
                outcome.note = Some(err.to_string());
                return outcome;
            }
        }
    }
}

/// Folds one [`LockedResult`] into the row and its span.
fn apply(span: &tracing::Span, outcome: &mut RowOutcome, result: &LockedResult) {
    span.record("lock_state", result.lock_state);
    outcome.lock_state = result.lock_state;
    if let Some(age_ms) = result.lock_age_ms {
        span.record("lock.age_ms", age_ms);
    }
    if let Some(decision) = &result.pending_decision {
        span.record("pending.decision", decision.as_str());
    }
    if let Some(note) = &result.note {
        outcome.note = Some(note.clone());
    }
    if let Some(state) = &result.state {
        outcome.state = state.clone();
    }
}

/// What one trip through the namespace lock produced.
#[derive(Debug)]
struct LockedResult {
    /// The credentials to carry on with, or `None` when the row is finished.
    credentials: Option<Credentials>,
    /// A state that replaces whatever the row had.
    state: Option<AccountState>,
    note: Option<String>,
    pending_decision: Option<String>,
    lock_age_ms: Option<i64>,
    lock_state: &'static str,
}

impl Default for LockedResult {
    /// Spelled out rather than derived so `lock_state` starts at `none` and
    /// not at the empty string: it reaches the JSON report, whose schema lists
    /// the six words this vocabulary has, and `""` is not one of them.
    fn default() -> Self {
        Self {
            credentials: None,
            state: None,
            note: None,
            pending_decision: None,
            lock_age_ms: None,
            lock_state: "none",
        }
    }
}

/// The write path of plan section 3.3 step 3, from the target check to the
/// rename.
///
/// Every early return is a refusal, and every one of them releases the lock
/// by dropping the guard. `may_refresh` is `false` when the caller only needs
/// a pending file resolved — the lock is still taken, because moving a
/// pending file into place is a namespace mutation like any other
/// (invariant I3).
///
/// # Where the pre-rename re-check sits
///
/// Plan section 3.3 puts it between writing the temporary file and renaming
/// it. Here it is immediately *before* [`file_store::write_credentials`], for
/// one reason: the temporary file contains the new refresh token, and a
/// namespace that has been taken over is a namespace that should never have
/// had that token written into it at all. The observable outcome is the one
/// AC21 asks for — no temporary file, no pending file, the credential file
/// untouched — and the fault pause point that lets a test occupy the window
/// is honoured here as well as inside the writer, so the interleaving the
/// test needs still happens.
#[expect(
    clippy::too_many_lines,
    reason = "the ordering of these checks is the invariant; a split would let \
              a later edit reorder them without noticing"
)]
fn under_namespace_lock(
    ctx: &PassCtx,
    shared: &Shared,
    record: &AccountRecord,
    ns_dir: &Path,
    may_refresh: bool,
) -> LockedResult {
    let target = ns_dir.join(CREDENTIALS_FILE);

    // The write-target check comes before the lock and before any network: a
    // path that is not ours, or is not a plain file, is a refusal reachable
    // without touching anything.
    if !shared.paths.is_under_namespace_root(&target) {
        return refused(
            AccountState::Error(
                "refresh refused: the credential path is outside the store".to_owned(),
            ),
            "unavailable",
        );
    }
    if let Err(err) = file_store::snapshot(&target) {
        return refused(AccountState::Error(format!("refresh refused: {err}")), "unavailable");
    }

    let guard = match namespace_lock::acquire(
        &shared.paths,
        &record.account_uuid,
        &record.organization_uuid,
        ctx.deadline(),
        ctx.cancel(),
        shared.fault.clone(),
    ) {
        Ok(guard) => guard,
        Err(LockError::Busy) => {
            // Somebody else is refreshing this namespace. Re-read: if they
            // finished, their result is as good as ours (plan AC7).
            let lock_age_ms = lock_age_ms(shared, record);
            return match reread(ns_dir) {
                Some(fresh) if !fresh.access_expired(now_ms(), REFRESH_MARGIN_MS) => LockedResult {
                    credentials: Some(fresh),
                    note: Some("another process refreshed this account".to_owned()),
                    lock_age_ms,
                    lock_state: "adopted",
                    ..LockedResult::default()
                },
                _ => LockedResult {
                    state: Some(AccountState::Busy),
                    lock_age_ms,
                    lock_state: "busy",
                    ..LockedResult::default()
                },
            };
        }
        Err(LockError::Cancelled) => {
            return refused(
                AccountState::Error("cancelled while waiting for the namespace lock".to_owned()),
                "unavailable",
            );
        }
        Err(err) => {
            // Fail closed: a lock error that is not contention means the
            // guarantee is gone, and refreshing without it could race a
            // second holder (invariant I12).
            return LockedResult {
                state: Some(AccountState::LockUnavailable),
                note: Some(err.to_string()),
                lock_state: "unavailable",
                ..LockedResult::default()
            };
        }
    };

    // Under the lock, ask again. Between discovery and here a session may
    // have started, and discovery's answer is now only a hint.
    let reader = (shared.reader_factory)(ctx);
    let activity = detect(ns_dir, record, &shared.listing, reader.as_ref());

    let decision = match file_store::resolve_pending(ns_dir, &activity) {
        Ok(decision) => decision,
        Err(err) => {
            drop(guard);
            return refused(
                AccountState::Error(format!(
                    "refresh refused: the pending write could not be resolved: {err}"
                )),
                "unavailable",
            );
        }
    };
    let pending_state = pending_state(&decision);
    let pending_decision = Some(format!("{decision:?}"));

    match &activity {
        ForeignActivity::ClaudeLock { name, age_ms } => {
            drop(guard);
            return LockedResult {
                state: Some(pending_state.unwrap_or(AccountState::ClaudeSessionDetected {
                    lock: name.clone(),
                    age_ms: *age_ms,
                })),
                pending_decision,
                lock_age_ms: i64::try_from(*age_ms).ok(),
                lock_state: "claude_detected",
                ..LockedResult::default()
            };
        }
        ForeignActivity::MigratedToKeychain { service } => {
            drop(guard);
            return LockedResult {
                state: Some(
                    pending_state
                        .unwrap_or(AccountState::MigratedToKeychain { service: service.clone() }),
                ),
                pending_decision,
                lock_state: "migrated",
                ..LockedResult::default()
            };
        }
        ForeignActivity::None => {}
    }

    // Re-read after the pending resolution: a replayed file is the newest
    // truth, and an absent one means the account went away under us.
    let Some(mut current) = reread(ns_dir) else {
        drop(guard);
        return LockedResult {
            state: Some(AccountState::NeedsLogin),
            note: Some("the stored credential is gone".to_owned()),
            pending_decision,
            lock_state: "none",
            ..LockedResult::default()
        };
    };

    if !current.access_expired(now_ms(), REFRESH_MARGIN_MS) {
        // Fresh already — a replay, or another process that finished between
        // the expiry check and the lock. Either way there is nothing to do,
        // and no POST is made (plan AC7, AC33 (a)).
        drop(guard);
        return LockedResult {
            credentials: Some(current),
            state: pending_state,
            pending_decision,
            lock_state: "adopted",
            ..LockedResult::default()
        };
    }

    if !may_refresh {
        // Called only to resolve a pending file. The credentials the caller
        // continues with are the file's, not the ones it arrived holding:
        // a replay may have just replaced them.
        drop(guard);
        return LockedResult {
            credentials: Some(current),
            state: pending_state,
            pending_decision,
            lock_state: "none",
            ..LockedResult::default()
        };
    }

    let prior: Digests = current.digests();
    let post_lock: Option<FileSnapshot> = match file_store::snapshot(&target) {
        Ok(snapshot) => snapshot,
        Err(err) => {
            drop(guard);
            return refused(AccountState::Error(format!("refresh refused: {err}")), "unavailable");
        }
    };

    let token = match shared.refresher.refresh(&current, ctx.cancel()) {
        Ok(token) => token,
        Err(err) => {
            drop(guard);
            return LockedResult {
                state: Some(refresh_failure_state(&err)),
                note: Some(err.to_string()),
                pending_decision,
                lock_state: "none",
                ..LockedResult::default()
            };
        }
    };
    if let Err(err) = current.merge_refresh(token, now_ms()) {
        drop(guard);
        return refused(
            AccountState::Error(format!("the refresh response was unusable: {err}")),
            "none",
        );
    }

    // The last look before anything is written. The pause point is what lets
    // a test occupy this window, which is otherwise microseconds wide (plan
    // AC21, third clause).
    shared.fault.pause_point("before_rename");
    let moved = match file_store::snapshot(&target) {
        Ok(now) => now != post_lock,
        Err(_) => true,
    };
    if moved || detect(ns_dir, record, &shared.listing, reader.as_ref()) != ForeignActivity::None {
        drop(guard);
        return LockedResult {
            state: Some(AccountState::RefreshDiscarded),
            pending_decision,
            lock_state: "claude_detected",
            ..LockedResult::default()
        };
    }

    let blob = current.to_blob_json();
    let request = WriteRequest {
        paths: &shared.paths,
        ns_dir,
        blob_json: &blob,
        prior: Some(&prior),
        new_expires_at_ms: current.expires_at_ms,
        fault: shared.fault.clone(),
    };
    let write = file_store::write_credentials(&request, ctx);
    drop(guard);

    match write {
        Ok(WriteOutcome::Written { .. }) => LockedResult {
            credentials: Some(current),
            state: pending_state,
            pending_decision,
            lock_state: "none",
            ..LockedResult::default()
        },
        // The token is good; only the file is not. Fetching with it still
        // answers the user's question, and the next run replays the pending.
        Ok(WriteOutcome::SavedToPending { error }) => LockedResult {
            credentials: Some(current),
            state: Some(AccountState::Error(format!(
                "refresh saved to pending; write failed ({error})"
            ))),
            pending_decision,
            lock_state: "none",
            ..LockedResult::default()
        },
        Err(err) => LockedResult {
            state: Some(write_failure_state(&err)),
            note: Some(err.to_string()),
            pending_decision,
            lock_state: "unavailable",
            ..LockedResult::default()
        },
    }
}

/// The row state a failed credential write deserves.
///
/// # `FileStoreError::Cancelled`
///
/// The fix lane on `main` adds that variant, returned when the pass is
/// cancelled immediately before the rename — the temporary file is already
/// unlinked and no pending file was written, which is exactly the shape of a
/// discarded refresh, so it maps to [`AccountState::RefreshDiscarded`].
fn write_failure_state(err: &FileStoreError) -> AccountState {
    match err {
        // A namespace that is not ours, or is not a plain file, is a refusal
        // rather than a fault: saying so names something the user can fix.
        FileStoreError::OutsideNamespaceRoot(_)
        | FileStoreError::RefusedSymlink(_)
        | FileStoreError::NotRegular(_) => AccountState::Error(format!("refresh refused: {err}")),
        // The pass was cancelled immediately before the rename: the temporary
        // file is already unlinked and nothing was parked as pending, which
        // is exactly the shape of a discarded refresh.
        FileStoreError::Cancelled(_) => AccountState::RefreshDiscarded,
        _ => AccountState::Error(format!("the refresh could not be stored: {err}")),
    }
}

/// A refusal carrying no credentials.
fn refused(state: AccountState, lock_state: &'static str) -> LockedResult {
    LockedResult { state: Some(state), lock_state, ..LockedResult::default() }
}

/// How long ago the current holder took the lock, when it recorded that.
fn lock_age_ms(shared: &Shared, record: &AccountRecord) -> Option<i64> {
    let path = shared.paths.lock_path(&record.account_uuid, &record.organization_uuid);
    let body = namespace_lock::read_body(&path)?;
    let acquired = body.acquired_at.parse::<Timestamp>().ok()?;
    now_ms().checked_sub(acquired.as_millisecond())
}

/// The row state a pending decision deserves, or `None` when there was none.
fn pending_state(decision: &PendingDecision) -> Option<AccountState> {
    match decision {
        PendingDecision::NoPending => None,
        PendingDecision::Replayed { .. } => Some(AccountState::PendingReplayed),
        // A pending derived from a file that has since been removed means the
        // account was deleted under us; replaying it would resurrect a
        // credential the user got rid of (plan AC33 (g)).
        PendingDecision::Discarded(PendingDiscardReason::FileRemoved) => {
            Some(AccountState::NeedsLogin)
        }
        PendingDecision::Discarded(reason) => {
            Some(AccountState::PendingDiscarded { reason: reason.label().to_owned() })
        }
    }
}

/// Maps a refresh failure onto a row state.
fn refresh_failure_state(err: &RefreshError) -> AccountState {
    match err {
        RefreshError::InvalidGrant => AccountState::NeedsLogin,
        // Never `needs login`: the grant was not consumed and the next pass
        // may well succeed (fact R26, S3 probe).
        RefreshError::RateLimited { retry_after_s } => {
            AccountState::RateLimited { retry_after_s: *retry_after_s }
        }
        RefreshError::Transient(reason) => AccountState::Error(reason.clone()),
        RefreshError::Cancelled => AccountState::Error("cancelled mid-refresh".to_owned()),
    }
}

/// Looks for another owner of this namespace, under both spellings (AC20).
fn detect(
    ns_dir: &Path,
    record: &AccountRecord,
    listing: &[ServiceEntry],
    reader: &dyn KeychainReader,
) -> ForeignActivity {
    let AccountKind::Owned { export_sha8, .. } = &record.kind else {
        return ForeignActivity::None;
    };
    let canonical = canonical_sha8(ns_dir);
    let owned = OwnedMeta {
        export_sha8,
        canonical_sha8: canonical.as_deref().filter(|sha| *sha != export_sha8.as_str()),
    };
    foreign_activity::detect(ns_dir, &owned, listing, reader)
}

/// `sha8` of a directory's canonical spelling, when it resolves.
fn canonical_sha8(dir: &Path) -> Option<String> {
    let canonical = namespace::canonical(dir).ok()?;
    Some(namespace::sha8(&namespace::export_spelling(&canonical)))
}

/// Re-reads a namespace's credentials, discarding the failure reason.
fn reread(ns_dir: &Path) -> Option<Credentials> {
    match location::from_file(ns_dir) {
        Resolved::Credentials(credentials) => Some(*credentials),
        _ => None,
    }
}

/// Now, in milliseconds since the epoch.
fn now_ms() -> i64 {
    Timestamp::now().as_millisecond()
}

/// The state a successfully parsed snapshot deserves.
///
/// A response that described no window at all is what an API or console
/// account looks like; saying `ok` next to an empty row would be a lie
/// (plan AC49).
fn classify(usage: &UsageSnapshot, fallback: &AccountState) -> AccountState {
    if usage.windows.is_empty() {
        return AccountState::NoSubscriptionLimits;
    }
    fallback.clone()
}

/// Keeps the more informative of the state a row carried in and the state its
/// fetch produced.
///
/// A row that replayed a pending write and then fetched cleanly should say
/// `pending replayed`, not `ok`: the replay is the thing the user might need
/// to know about (plan AC33 (a)).
fn merge_states(carried: AccountState, fetched: AccountState) -> AccountState {
    match (&carried, &fetched) {
        (AccountState::Ok, _) | (_, AccountState::NoSubscriptionLimits) => fetched,
        _ => carried,
    }
}

/// Writes a cache entry, reporting a failure as a trace line and nothing more.
///
/// A cache that cannot be written is not a reason to fail a run that already
/// has its numbers.
fn store_cache(path: &Path, body: &Value, fetched_at_ms: i64, until_ms: Option<i64>) {
    let mut entry = cache::CacheEntry::new(fetched_at_ms, body.clone());
    entry.rate_limited_until_ms = until_ms;
    if let Err(err) = cache::store(path, &entry) {
        tracing::debug!(path = %path.display(), error = %err, "could not write the usage cache");
    }
}

/// The refresher this process should use: the real OAuth client, built from
/// the environment (honest User-Agent, production endpoints unless a
/// `testing`-only override is set).
///
/// # Errors
///
/// Returns [`AppError`] when the client cannot be built.
pub fn default_refresher() -> Result<Arc<dyn TokenRefresher>, AppError> {
    Ok(Arc::new(OauthClient::from_env(&crate::provider::claude::user_agent())?))
}

#[cfg(test)]
#[path = "status_tests.rs"]
mod tests;
