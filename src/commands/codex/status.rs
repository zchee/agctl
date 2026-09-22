//! `agctl codex status` — one pass over every Codex account, rendered as a
//! table or as a version-2 document.
//!
//! The shape is plan section 3.3: load, discover, fan out, normalize, render.
//! The pass itself is [`pass`](super::pass); what this file adds is where a
//! refresh is allowed to happen, and that is the first thing to read.
//!
//! # A refresh never runs inside a pass worker (U44 = option 5)
//!
//! Every refresh defect the plan's five review rounds found came from POSTing
//! inside a pass tuned for read-only work — its deadline, its cancel key, its
//! emergency cleanup (decision D-035's root cause). So the pass workers only
//! *read*: a credential file, a refresh marker, the usage endpoint. The two
//! places a refresh token can be sent both run **on the command thread**, one
//! namespace at a time, around the pass rather than inside it (ledger #233):
//!
//! 1. the **pre-pass** ([`refresh_pre_pass`]) runs [`refresh::run`] with
//!    [`SendMode::Proactive`] for every owned `auto` row before the pass
//!    starts, and the workers then read what it left;
//! 2. the **401 post-pass** ([`after_unauthorized`]) runs it with
//!    [`SendMode::AfterUnauthorized`], built from the digest of the bearer the
//!    usage GET just sent, for each row the pass saw rejected, and then
//!    retries that row's GET — still on the command thread.
//!
//! # Why `watch` cannot POST, as a property of the program
//!
//! [`refresh::run`] and [`refresh::record_retry_get`] take a [`PostPermit`],
//! whose field is private to `provider::codex::permit` and whose only
//! command-side constructor is [`PostPermit::from_env`], called here in
//! [`run`]. A caller holding no permit cannot POST — the call does not
//! type-check, whatever it imports the driver under (review S33-C2 F1).
//! `agctl codex watch` builds no permit, and the pass it shares lives in
//! [`pass`](super::pass), which names neither the permit nor the driver
//! (`scripts/phase3-structural.sh` clauses 12 and 13,
//! `scripts/phase3-greps.sh`). The captured per-job flag
//! [`Shared::allow_post`] only changes what a worker *says* about a row it
//! could not read — `run agctl codex status` under `watch` — never whether
//! anything is sent; it is deliberately not a `PassCtx` field (ledger #238).
//!
//! # The deadline (decision D-035, review S31 F9)
//!
//! `--timeout` is one usage request's per-phase budget, and one request can
//! spend four short phases (resolve, connect, send request, send body — each
//! `min(--timeout, 5s)`) and two long ones (response, body — each
//! `--timeout`). When an owned `auto` account is present the pass must still
//! leave a refresh its lock budget, POST budget and write allowance after a
//! first GET, and room for the retry GET after it, so the deadline is
//! `1s + 19s + 1s + 2 × (4 × min(--timeout, 5s) + 2 × --timeout)`. With no
//! account that can be refreshed it is one request's budget.

use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use jiff::Timestamp;
use jiff::tz::TimeZone;
use serde_json::Map;
use serde_json::Value;

use crate::cli::Cli;
use crate::cli::CodexStatusArgs;
use crate::commands::codex::codex_env_from_process;
use crate::commands::codex::pass::Options;
use crate::commands::codex::pass::PlanSource;
use crate::commands::codex::pass::Retry;
use crate::commands::codex::pass::RowPass;
use crate::commands::codex::pass::RowPlan;
use crate::commands::codex::pass::Shared;
use crate::commands::codex::pass::collect;
use crate::commands::codex::pass::finish;
use crate::commands::codex::pass::keyring_listing;
use crate::commands::codex::pass::plan_rows;
use crate::commands::codex::pass::push_note;
use crate::commands::codex::pass::push_report_notes;
use crate::commands::codex::pass::run_row;
use crate::commands::codex::pass::select;
use crate::commands::codex::pass::step_note;
use crate::commands::codex::pass::step_state;
use crate::commands::status::current_fault;
use crate::config::AgctlConfig;
use crate::config::paths::Paths;
use crate::error::AppError;
use crate::provider::codex::account::CodexRowOutcome;
use crate::provider::codex::account::CodexState;
use crate::provider::codex::lock::LockBudget;
use crate::provider::codex::permit::PostPermit;
use crate::provider::codex::proof;
use crate::provider::codex::refresh;
use crate::provider::codex::refresh::PASS_LOCK_BUDGET;
use crate::provider::codex::refresh::REFRESH_POST_BUDGET;
use crate::provider::codex::refresh::RefreshCtx;
use crate::provider::codex::refresh::RefreshReport;
use crate::provider::codex::refresh::RefreshStep;
use crate::provider::codex::refresh::RetryGet;
use crate::provider::codex::refresh::SendMode;
use crate::provider::codex::refresh::WRITE_ALLOWANCE;
use crate::provider::codex::usage;
use crate::provider::codex::usage::UsageClient;
use crate::render::json_v2::StatusReportV2;
use crate::render::table;
use crate::render::table::CodexReport;
use crate::runtime::coordinator::Cancel;
use crate::runtime::fault::Fault;

/// The short phases one usage request can spend: resolve, connect, send the
/// request, send the body (`usage::UsageClient::new`).
const SHORT_PHASES: u32 = 4;

/// The long phases one usage request can spend: the response and its body.
const LONG_PHASES: u32 = 2;

/// Runs `agctl codex status`.
///
/// # Errors
///
/// [`AppError::Partial`] when a shown row is degraded (the report is still on
/// stdout); [`AppError::Config`] for an `--account` that matches nothing;
/// anything else is fatal and nothing was rendered.
pub fn run(cli: &Cli, args: &CodexStatusArgs, cancel: &Cancel) -> Result<(), AppError> {
    // Step 1: load. `ensure_dirs` creates Claude's empty store too (plan AC97,
    // accepted); `ensure_codex_dirs` creates the lock, marker and cache roots
    // the pass writes under.
    let paths = Arc::new(Paths::resolve(cli.config_dir.as_deref())?);
    paths.ensure_dirs()?;
    paths.ensure_codex_dirs()?;
    let config = AgctlConfig::load(&paths)?;
    let env = codex_env_from_process();

    // Step 2: discover, and narrow to `--account`.
    let plans = select(plan_rows(&paths, &config.codex_accounts, &env, cancel), &args.account)?;
    let deadline = pass_deadline(args.timeout, plans.iter().any(RowPlan::may_refresh));
    let fault = current_fault();

    // The pre-pass: the only proactive refresh, on this thread (U44 = 5).
    let permit = PostPermit::from_env();
    let plans = refresh_pre_pass(&permit, plans, &paths, &fault, cancel, deadline);

    // Step 3: fan out the read-only pass.
    let listing = keyring_listing(&plans, cancel, deadline);
    let shared = Arc::new(Shared {
        paths: Arc::clone(&paths),
        client: UsageClient::from_env(args.timeout),
        keyring: listing,
        fault: fault.clone(),
        options: Options { refresh: args.refresh, no_cache: args.no_cache },
        allow_post: true,
    });
    let passes = collect(plans, &shared, cancel, deadline);

    // The 401 post-pass: the only refresh after a rejection, on this thread.
    let passes = after_unauthorized(&permit, passes, &shared, cancel, deadline);
    let outcomes = finish(passes);

    // Steps 4 and 5: render, then the exit status from the shown rows.
    let shown: Vec<&CodexRowOutcome> =
        outcomes.iter().filter(|row| args.all || row.visible_by_default).collect();
    let hidden = outcomes.len().saturating_sub(shown.len());
    let failed = shown.iter().filter(|row| !row.state.is_exit_neutral()).count();
    let now = Timestamp::now();

    if args.json {
        let rows: Vec<CodexRowOutcome> = shown.iter().map(|row| (*row).clone()).collect();
        let mut document = StatusReportV2::from_rows(&rows, now, hidden);
        if args.raw {
            // Keyed by row id, as version 1 is. Each body is the response less
            // its `email` member; the `user_id`/`account_id` it keeps are the
            // row's own identifiers (review S31 F7).
            let bodies: Map<String, Value> = shown
                .iter()
                .filter_map(|row| {
                    let raw = row.usage.as_ref()?.raw.as_ref()?;
                    Some((row.id.clone(), raw.clone()))
                })
                .collect();
            document.raw = Some(bodies);
        }
        let text = serde_json::to_string_pretty(&document).map_err(|err| {
            AppError::Config(format!("the JSON report could not be serialized: {err}"))
        })?;
        println!("{text}");
    } else {
        let report = CodexReport {
            rows: outcomes.iter().map(CodexRowOutcome::to_table_row).collect(),
            now,
            tz: TimeZone::system(),
            show_all: args.all,
        };
        println!("{}", table::render_codex(&report));
        if args.raw {
            print_raw(&shown);
        }
    }

    if failed > 0 { Err(AppError::Partial { failed }) } else { Ok(()) }
}

/// The budget one usage request can spend at `timeout` (review S31 F9):
/// `4 × min(timeout, 5s) + 2 × timeout`, saturating.
pub fn usage_request_budget(timeout: Duration) -> Duration {
    let short = timeout.min(usage::CONNECT_TIMEOUT).checked_mul(SHORT_PHASES);
    let long = timeout.checked_mul(LONG_PHASES);
    short.zip(long).and_then(|(short, long)| short.checked_add(long)).unwrap_or(Duration::MAX)
}

/// The pass budget at `timeout`: one request's, or, when a refresh is
/// possible, the lock budget + POST budget + write allowance + two requests'
/// (decision D-035 with review S31 F9). Saturating.
pub fn pass_budget(timeout: Duration, refresh_possible: bool) -> Duration {
    let request = usage_request_budget(timeout);
    if !refresh_possible {
        return request;
    }
    request
        .checked_mul(2)
        .and_then(|gets| gets.checked_add(PASS_LOCK_BUDGET))
        .and_then(|budget| budget.checked_add(REFRESH_POST_BUDGET))
        .and_then(|budget| budget.checked_add(WRITE_ALLOWANCE))
        .unwrap_or(Duration::MAX)
}

/// The instant after which the pass stops starting new work, never in the
/// past on an absurd `--timeout` (constraint C-006).
fn pass_deadline(timeout: Duration, refresh_possible: bool) -> Instant {
    let now = Instant::now();
    now.checked_add(pass_budget(timeout, refresh_possible)).unwrap_or(now)
}

/// The proactive refresh pre-pass: [`SendMode::Proactive`] for every owned
/// `auto` row, one at a time, on the caller's thread.
///
/// [`refresh::run`] decides everything — the time check before the lock, the
/// pending replay, the marker, the daemon evidence, whether the token is due —
/// and a row that is not due costs a lock and a read, no request.
pub fn refresh_pre_pass(
    permit: &PostPermit,
    plans: Vec<RowPlan>,
    paths: &Paths,
    fault: &Fault,
    cancel: &Cancel,
    deadline: Instant,
) -> Vec<RowPlan> {
    let ctx = RefreshCtx {
        paths,
        deadline,
        lock_budget: LockBudget::Pass(PASS_LOCK_BUDGET),
        cancel,
        fault,
    };
    plans
        .into_iter()
        .map(|mut plan| {
            if plan.may_refresh()
                && let PlanSource::Owned { record, .. } = &plan.source
                && let Some(owned) = proof::owned(record)
            {
                let report = refresh::run(permit, owned, SendMode::Proactive, &ctx);
                tracing::debug!(step = ?report.step, "codex refresh pre-pass");
                plan.pre_pass = Some(report);
            }
            plan
        })
        .collect()
}

/// The 401 post-pass: for each row the pass saw rejected, one
/// [`SendMode::AfterUnauthorized`] refresh and one retried GET, on the
/// caller's thread.
pub fn after_unauthorized(
    permit: &PostPermit,
    passes: Vec<RowPass>,
    shared: &Shared,
    cancel: &Cancel,
    deadline: Instant,
) -> Vec<RowPass> {
    let ctx = RefreshCtx {
        paths: &shared.paths,
        deadline,
        lock_budget: LockBudget::Pass(PASS_LOCK_BUDGET),
        cancel,
        fault: &shared.fault,
    };
    passes
        .into_iter()
        .map(|pass| {
            let Some(rejected) = pass.rejected.clone() else {
                return settle_retry(permit, pass, &ctx);
            };
            let PlanSource::Owned { record, .. } = &pass.plan.source else { return pass };
            let Some(owned) = proof::owned(record) else { return pass };
            let report = refresh::run(
                permit,
                owned,
                SendMode::AfterUnauthorized { rejected_access_digest8: rejected },
                &ctx,
            );
            tracing::debug!(step = ?report.step, "codex refresh after a 401");
            let retry = match report.step {
                RefreshStep::Refreshed { .. } => Some(Retry::AfterSend),
                RefreshStep::Adopted(_) | RefreshStep::DiscardedExternal => Some(Retry::AfterAdopt),
                RefreshStep::RacedExternal => Some(Retry::Verify),
                _ => None,
            };
            match retry {
                Some(retry) => {
                    let plan = RowPlan { retry: Some(retry), pre_pass: Some(report), ..pass.plan };
                    let again = run_row(cancel, plan, shared);
                    settle_retry(permit, again, &ctx)
                }
                None => unrefreshed_401(pass, &report),
            }
        })
        .collect()
}

/// Records a retried GET's answer after a sent refresh, and resets a raised
/// floor after any GET that followed one (plan AC114). A marker that cannot
/// be written is logged; the row keeps what the GET said.
fn settle_retry(permit: &PostPermit, pass: RowPass, ctx: &RefreshCtx<'_>) -> RowPass {
    let sent = matches!(pass.plan.retry, Some(Retry::AfterSend))
        || matches!(
            pass.plan.pre_pass.as_ref().map(|report| &report.step),
            Some(RefreshStep::Refreshed { .. })
        );
    let answer = match (pass.plan.retry, pass.fetched) {
        (Some(Retry::AfterSend), true) => Some(RetryGet::Succeeded),
        (Some(Retry::AfterSend), false)
            if matches!(pass.outcome.state, CodexState::Unauthorized { .. }) =>
        {
            Some(RetryGet::Unauthorized)
        }
        (_, true) if sent && pass.floor_raised => Some(RetryGet::Succeeded),
        _ => None,
    };
    if let Some(answer) = answer
        && let PlanSource::Owned { record, .. } = &pass.plan.source
        && let Some(owned) = proof::owned(record)
        && let Err(err) = refresh::record_retry_get(permit, owned, answer, ctx)
    {
        tracing::warn!(error = %err, "the answer to a retried Codex usage request was not recorded");
    }
    pass
}

/// A 401 the post-pass did not refresh: the row says why.
fn unrefreshed_401(mut pass: RowPass, report: &RefreshReport) -> RowPass {
    let (state, note) = match &report.step {
        RefreshStep::UnauthorizedFloor { until } => {
            (CodexState::UnauthorizedFloor, Some(format!("no refresh before {until}")))
        }
        RefreshStep::UnauthorizedTerminal => (
            CodexState::UnauthorizedTerminal,
            Some(format!(
                "run agctl codex login, or agctl codex accounts refresh {} --reset-floor",
                pass.outcome.id
            )),
        ),
        other => step_state(other)
            .unwrap_or((CodexState::Unauthorized { refreshed_recently: false }, step_note(other))),
    };
    pass.outcome.state = state;
    push_note(&mut pass.outcome.note, note);
    push_report_notes(&mut pass.outcome.note, report);
    pass
}

/// Prints each shown row's kept response body after the table. The bodies
/// are usage figures less the account's email, never a token.
fn print_raw(rows: &[&CodexRowOutcome]) {
    for row in rows {
        let Some(raw) = row.usage.as_ref().and_then(|usage| usage.raw.as_ref()) else { continue };
        println!("\n--- raw: {} ---", row.id);
        match serde_json::to_string_pretty(raw) {
            Ok(text) => println!("{text}"),
            Err(err) => tracing::warn!(error = %err, "the raw body could not be re-serialized"),
        }
    }
}
#[cfg(test)]
#[path = "status_tests.rs"]
mod tests;
