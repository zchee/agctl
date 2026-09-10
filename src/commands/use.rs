//! `agentctl claude use` — an isolated session, or a hot-swap of a live one.
//!
//! Bare `use <id>` is exactly `isolate::ensure_session` followed by
//! `export::exec_command` against `claude` on `PATH`, with the same
//! environment delta `exec`/`env` compute. `--forget` resolves the account
//! and hands off to `isolate::forget_session` (plan AC79).
//!
//! # `--live`: plan section 3.4's hot-swap (W4a)
//!
//! One procedure in three phases, and the phases are the safety argument.
//! [`swap`] states the shape and pins the order; [`run_live`] executes it.
//!
//! - **Phase A** reads. The registry, the environment, and exactly **one**
//!   read of the keychain item. Nothing is held and nothing is written, so
//!   every refusal decidable from what is already on the machine is decided
//!   before the swap has cost anybody anything.
//! - **Phase B** prepares. The adoption is decided, the operator is asked,
//!   the refresh POST is made and the adoption is written — in that order,
//!   because both the POST and the write are irreversible and neither may
//!   happen in front of the consent gate — under agentctl's **own**
//!   namespace locks —
//!   never Claude Code's. That is invariant I17's whole content: the things
//!   that block are done before the things Claude Code is waiting for are
//!   taken.
//! - **Phase C** writes. Claude Code's three locks in its own nesting, a
//!   drift check, a re-read, one write, release. Bounded by
//!   [`claude_lock::HOLD_BUDGET`], and a write that cannot finish inside what
//!   is left of the budget is not started at all.
//!
//! ## The two things this file must never do
//!
//! It never constructs [`WriteTarget::live`] — the live `~/.claude` store is
//! W4b's, and the scope gate in Phase A turns that case into
//! `not_implemented` before anything is read. And it never writes the
//! displaced credential to `.credentials.json`: decision D-024 puts it in the
//! adopted copy, because fact F35's composed read falls through to that file
//! on any keychain hiccup and would serve the credential the user just
//! swapped *away* from.

use std::ffi::OsString;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

use crate::cli::UseArgs;
use crate::commands::Prompt;
use crate::commands::Tty;
use crate::commands::export;
use crate::commands::isolate;
use crate::commands::status;
use crate::config::AccountKind;
use crate::config::AccountRecord;
use crate::config::AgentctlConfig;
use crate::config::paths::Paths;
use crate::error::AppError;
use crate::error::EXIT_OK;
use crate::provider::claude::adopt;
use crate::provider::claude::credentials::Credentials;
use crate::provider::claude::credentials::Digests;
use crate::provider::claude::credentials::KeychainStdinLine;
use crate::provider::claude::credentials::REFRESH_MARGIN_MS;
use crate::provider::claude::namespace::EnvView;
use crate::provider::claude::swap;
use crate::provider::claude::swap::Outcome;
use crate::provider::claude::swap::Refusal;
use crate::provider::claude::usage::RefreshError;
use crate::runtime::coordinator::Cancel;
use crate::runtime::coordinator::PassCtx;
use crate::runtime::fault::Fault;
use crate::secret::audit;
use crate::secret::audit::AuditEntry;
use crate::secret::audit::AuditEvent;
use crate::secret::audit::Target;
use crate::secret::claude_lock;
use crate::secret::claude_lock::AcquireOutcome;
use crate::secret::claude_lock::Clock;
use crate::secret::claude_lock::HeldLocks;
use crate::secret::claude_lock::LockSubject;
use crate::secret::claude_lock::Tree;
use crate::secret::default_reader;
use crate::secret::file_store;
use crate::secret::keychain_write;
use crate::secret::keychain_write::KeychainWriteError;
use crate::secret::keychain_write::OwnedSha8;
use crate::secret::keychain_write::WriteTarget;
use crate::secret::location;
use crate::secret::location::Resolved;
use crate::secret::namespace_lock;

/// How long the whole swap may take before its own deadline fires.
///
/// Generous, because Phase B contains a network round trip and possibly a
/// person reading a prompt. Phase C has its own, much tighter budget.
const SWAP_DEADLINE: Duration = Duration::from_secs(120);

/// `agentctl claude use [<id>] [--live] [--claude-config-dir <PATH>]
/// [--fresh-context] [--no-mcp] [--yes] [--json]` · `use --undo [--yes]` ·
/// `use --forget <id> [--yes]`.
///
/// Returns the launched `claude`'s own exit code for the bare-`use` shape
/// (plan AC52's contract, shared with `exec`), which is why `main`'s
/// dispatch treats this arm like `exec` rather than like every other
/// command. `--live` returns one of `cli::swap_exit`'s codes.
///
/// # Errors
///
/// Returns [`AppError::not_implemented`] for `--live` against the live store
/// (W4b) and for `--undo`; [`AppError::Config`] when no id was given and none
/// of `--undo`/`--forget` was either, or when the account cannot be resolved;
/// and whatever [`export::prepare`], [`export::exec_command`] or
/// [`isolate::forget_session`] return otherwise.
pub fn run(config_dir: Option<&Path>, args: &UseArgs, cancel: &Cancel) -> Result<i32, AppError> {
    if args.live {
        return run_live(config_dir, args, cancel);
    }
    if args.undo {
        return run_undo(config_dir, args, cancel);
    }
    if let Some(id) = &args.forget {
        return run_forget(config_dir, id, args.yes);
    }
    // `--new-only` is accepted as a synonym naming the default behaviour it
    // already asks for; there is nothing else for it to select.
    let _ = args.new_only;

    let Some(id) = &args.id else {
        return Err(AppError::Config(
            "an account id is required unless one of --undo or --forget is given".to_owned(),
        ));
    };

    let (session, spec, ctx) = export::prepare(
        config_dir,
        id,
        args.claude_config_dir.clone(),
        args.fresh_context,
        args.no_mcp,
        cancel,
    )?;

    if args.json {
        print_session_json(&session, &spec)?;
    }
    let _ = args.yes;

    let argv = vec![OsString::from("claude")];
    let status = export::exec_command(&spec, &argv, &ctx, cancel)?;
    Ok(export::exit_code_of(status))
}

// ---------------------------------------------------------------------------
// `--live`
// ---------------------------------------------------------------------------

/// What the swap decided, and everything the report needs to say it.
#[derive(Debug)]
struct Report {
    outcome: Outcome,
    /// Which keychain item the swap was for, spelled as the audit log spells
    /// it (`namespace:<sha8>`) so the two can be matched by eye.
    target: Option<String>,
    /// The service name the write targeted.
    service: String,
    /// Digest prefixes only — never a token, never the full hex.
    from_digest8: Option<String>,
    to_digest8: Option<String>,
    /// The audit entry the write produced, for `--undo` and the completion
    /// line.
    audit_id: Option<String>,
    /// Where the displaced credential went, when it went anywhere.
    adopted_to: Option<String>,
    /// What the hold cost and what it broke, for `--json`.
    lock: LockReport,
    /// Facts the pass wants the caller to know that are not refusals —
    /// today, refusal **B**'s degraded warning (decision D-020).
    ///
    /// Carried rather than only printed, because the warning goes to
    /// **stderr**: a machine reading `--json` would otherwise lose a fact a
    /// person at a terminal is told.
    warnings: Vec<String>,
    /// A sentence for the terminal.
    note: Option<String>,
}

impl Report {
    fn refused(refusal: Refusal, service: &str, note: String) -> Self {
        Self {
            outcome: Outcome::Refused(refusal),
            target: None,
            service: service.to_owned(),
            from_digest8: None,
            to_digest8: None,
            audit_id: None,
            adopted_to: None,
            lock: LockReport::default(),
            warnings: Vec::new(),
            note: Some(note),
        }
    }

    /// Refusal **F** with the adoption's own reason, which is the only
    /// refusal that has one.
    fn cannot_adopt(reason: adopt::Refusal, service: &str) -> Self {
        Self::refused(Refusal::CannotAdopt(reason), service, reason.message().to_owned())
    }

    /// The incoming credential is stale and this swap will not spend a
    /// refresh it cannot save (finding N-8).
    ///
    /// Not a lettered refusal: nothing about the store is wrong and nothing
    /// was written, so `--json` carries `refusal: null` and the note names
    /// the one command that fixes it.
    fn needs_refresh(service: &str, note: String) -> Self {
        Self {
            outcome: Outcome::NeedsRefresh,
            target: None,
            service: service.to_owned(),
            from_digest8: None,
            to_digest8: None,
            audit_id: None,
            adopted_to: None,
            lock: LockReport::default(),
            warnings: Vec::new(),
            note: Some(note),
        }
    }
}

/// What Phase C's hold cost, and what it had to break to take it.
///
/// The contract's `--json` clause in one place: "target, both digest
/// prefixes, outcome, **lock timings, any break**, and no token material".
/// A credential-store write is the highest-value thing this binary does, and
/// a caller that automated it could previously see only whether it worked.
#[derive(Debug, Default, Clone)]
struct LockReport {
    /// How long the three Claude Code locks were held, in milliseconds.
    /// Absent when no hold was taken.
    hold_ms: Option<u64>,
    /// The budget that hold was measured against.
    budget_ms: Option<u64>,
    /// The break the acquire performed, reduced to what may be said aloud:
    /// whether the artefact was removed, why not when it was not, and the
    /// three-value holder vocabulary. **Never a pid** and never a path
    /// (plan AC80).
    broke: Option<serde_json::Value>,
}

/// A break record reduced to the summary `--json` may carry.
fn break_summary(record: &audit::LockBreakRecord) -> serde_json::Value {
    serde_json::json!({
        "broke": matches!(record.outcome, audit::BreakOutcome::Broken),
        "outcome": serde_json::to_value(record.outcome).unwrap_or(serde_json::Value::Null),
        "reason": serde_json::to_value(record.reason).unwrap_or(serde_json::Value::Null),
        "holder_evidence": serde_json::to_value(record.holder_evidence)
            .unwrap_or(serde_json::Value::Null),
    })
}

/// Refusal **B**'s degraded warning (decision D-020).
///
/// It is not a refusal — no storage-V5 backend exists in this build, so
/// refusing on one would be refusing on a hypothesis — but it is still a fact
/// about what agentctl could and could not see, and it says whose environment
/// was inspected (plan AC67, critic M4).
const BACKEND_NOTE: &str = "agentctl inspected its own environment for a secure-storage backend \
                            and found none; it cannot inspect the target session's";

/// `claude use --live <id>`: plan section 3.4 against a store agentctl owns.
fn run_live(config_dir: Option<&Path>, args: &UseArgs, cancel: &Cancel) -> Result<i32, AppError> {
    // Before `Paths::resolve`, deliberately: a usage error must not create a
    // config directory on the way to being reported.
    let Some(id) = &args.id else {
        return Err(AppError::Config(
            "`--live` needs the account to swap in; give it an id".to_owned(),
        ));
    };

    let paths = Paths::resolve(config_dir)?;
    paths.ensure_dirs()?;
    let config = AgentctlConfig::load(&paths)?;
    let incoming = config.resolve_id(id)?.clone();

    // Phase A step 1: only an account agentctl owns can be swapped in — the
    // same fact `export::spec_for` states, in the same words.
    if !matches!(incoming.kind, AccountKind::Owned { .. }) {
        return Err(AppError::Config(format!(
            "only an account agentctl owns can be swapped into a live store; `{}` is `{}`, whose \
             credentials live outside agentctl's own store",
            incoming.account_uuid,
            incoming.kind.name()
        )));
    }

    // Step 2: ONE environment view. Every later derivation takes this one, so
    // the store directory and the service name cannot come from two different
    // readings of a variable that changed in between (risk R42).
    let env = EnvView::from_process();

    // Step 3: the scope gate. An unset or empty variable means the target is
    // the live Claude Code store, which is W4b's — refused before anything is
    // read, and never through `WriteTarget::live`, which this lane does not
    // construct at all.
    let inherited = match env.securestorage_dir.as_deref() {
        Some(value) if !value.is_empty() => value.to_owned(),
        _ => {
            return Err(AppError::not_implemented(
                "claude use --live against the live Claude Code store",
            ));
        }
    };

    // Step 4: the precondition (ruling OQ1). The inherited spelling is matched
    // **byte for byte** against an owned record's `export_spelling` — not
    // canonicalized, not resolved — because that string is what Claude Code
    // hashes into a service name (fact F14), and two spellings of one
    // directory name two different items.
    let Some(store) = owned_by_spelling(&config, &inherited).cloned() else {
        // Through `emit` like every other refusal, so `--json` gets the
        // document the contract specifies (`outcome: "refused"` with
        // `reason: "not_owned"`) rather than a sentence it cannot parse.
        let report = Report::refused(
            Refusal::NotOwned,
            "",
            format!(
                "`{inherited}` is not a store agentctl owns, so there is no record saying whose \
                 credentials are in it or where the displaced one should go"
            ),
        );
        emit(&report, args.json)?;
        return Ok(report.outcome.exit_code());
    };

    let ctx = PassCtx::standalone(cancel.clone(), Instant::now() + SWAP_DEADLINE);
    let fault = fault_from_env();
    let swap = Swap {
        paths: &paths,
        config: &config,
        env: &env,
        inherited: &inherited,
        ctx: &ctx,
        fault: &fault,
    };
    let incoming =
        Incoming { record: &incoming, direction: Direction::Forward, source: Source::OwnStore };
    let report = swap_in(&swap, &incoming, &store, args);
    emit(&report, args.json)?;
    Ok(report.outcome.exit_code())
}

/// The active fault set, which is empty in every build without the `testing`
/// feature.
fn fault_from_env() -> Fault {
    #[cfg(feature = "testing")]
    {
        Fault::from_env()
    }
    #[cfg(not(feature = "testing"))]
    {
        Fault::none()
    }
}

/// The spelling an `Owned` record recorded for its namespace.
///
/// The empty string for every other kind, which no derived directory can
/// equal, so a record that is not `Owned` fails the store-moved guard rather
/// than skipping it.
fn recorded_spelling(record: &AccountRecord) -> &str {
    match &record.kind {
        AccountKind::Owned { export_spelling, .. } => export_spelling,
        _ => "",
    }
}

/// The `Owned` record whose `export_spelling` is exactly `inherited`.
fn owned_by_spelling<'a>(config: &'a AgentctlConfig, inherited: &str) -> Option<&'a AccountRecord> {
    config.accounts.iter().find(|record| match &record.kind {
        AccountKind::Owned { export_spelling, .. } => export_spelling == inherited,
        _ => false,
    })
}

/// Phase A steps 5–9, then Phase B, then Phase C, with the two things every
/// exit owes stamped on afterwards.
///
/// The pass-wide members of the report — which item this was for, and the
/// warnings the pass collected — are the same whichever of the twenty-odd
/// exits inside [`swap_phases`] was taken, so they are filled in here rather
/// than at each of them, where the next one added would forget.
fn swap_in(
    swap: &Swap<'_>,
    incoming: &Incoming<'_>,
    store: &AccountRecord,
    args: &UseArgs,
) -> Report {
    let mut pass = Pass::default();
    let mut report = swap_phases(swap, incoming, store, args, &mut pass);
    report.target = pass.target;
    report.warnings = pass.warnings;
    report
}

/// What the pass learns on the way through that every exit owes the report.
///
/// Both members are the same whichever of the twenty-odd exits inside
/// [`swap_phases`] is taken, and filling them in at each of them is how the
/// next exit added would come to forget one. `target` is set once, where the
/// item is derived; the warnings are pushed where they are discovered.
#[derive(Default)]
struct Pass {
    /// Which keychain item this was for, spelled as the audit log spells it.
    target: Option<String>,
    /// Facts that are not refusals — today, refusal **B**'s degraded warning.
    warnings: Vec<String>,
}

/// Phase A steps 5–9, then Phase B, then Phase C.
#[expect(
    clippy::too_many_lines,
    reason = "plan section 3.4 is one procedure and the order of its refusals is the \
              invariant; splitting it would let a later edit move one inside the hold \
              without noticing, which is what swap::DECISION_ORDER exists to stop"
)]
fn swap_phases(
    env: &Swap<'_>,
    incoming: &Incoming<'_>,
    store: &AccountRecord,
    args: &UseArgs,
    pass: &mut Pass,
) -> Report {
    let Swap { paths, config, env, inherited, ctx, fault } = env;
    let (paths, config, env, inherited, ctx, fault) =
        (*paths, *config, *env, *inherited, *ctx, *fault);
    let direction = incoming.direction;
    // Step 5: derive the store directory and the service name **together**,
    // through the registry. `from_record` refuses a store outside the
    // namespace root, which is half of AC81's containment and is structural
    // rather than a check written here.
    let Some(sha8) = OwnedSha8::from_record(paths, store) else {
        return Report::refused(
            Refusal::NotOwned,
            "",
            "the store's recorded export spelling does not name a namespace agentctl owns"
                .to_owned(),
        );
    };
    let target = WriteTarget::migrated(sha8.clone());
    let store_dir = target.store_dir().to_path_buf();
    let service = target.service().to_owned();
    pass.target = Some(Target::Namespace(sha8.sha8().to_owned()).to_string());

    // The precondition's other half, and the one the OQ1 match alone does not
    // give: the item and the directory must name the *same* store.
    //
    // The service comes from the record's **stored** `export_sha8`, which is
    // what Claude Code hashed when the session started; the store directory
    // comes from the registry as it stands **now**. When the namespace has
    // moved, those disagree — the item is still the one the session reads,
    // but `store_dir` names somewhere else, so the three Claude Code locks,
    // the adopted copy and the containment walk would all be about a
    // directory whose `.oauth_refresh.lock` the peer never takes. Invariant
    // I3' would be defeated for exactly the one command that writes under the
    // peer's locks. `doctor` already reports this state (risk R25) and
    // `export` already refuses it; so does this.
    let spelled = crate::provider::claude::namespace::export_spelling(&store_dir);
    if spelled != inherited {
        return Report::refused(
            Refusal::NotOwned,
            &service,
            format!(
                "this store is named `{inherited}`, but `{}`'s namespace now spells `{spelled}`; \
                 the store moved, so agentctl would take the Claude Code locks in a different \
                 directory than the session reads — see `agentctl claude doctor`",
                store.account_uuid
            ),
        );
    }

    // Step 6, refusal C: agentctl's **own** environment only (decision
    // D-020). agentctl cannot read another process's environment and will not
    // guess at one, so the message says whose was inspected.
    if env.oauth_token_set {
        return Report::refused(
            Refusal::EnvToken,
            &service,
            "`CLAUDE_CODE_OAUTH_TOKEN` is set in agentctl's own environment, which short-circuits \
             every credential store; unset it and run this again"
                .to_owned(),
        );
    }
    // Refusal B degrades to a warning line and exit 0 (decision D-020): no
    // storage-V5 backend exists in this build, so refusing would be refusing
    // on a hypothesis. It still says whose environment was inspected.
    //
    // On **stderr**, and carried in the report besides. It used to go to
    // stdout, which put a prose line in front of the `--json` document and
    // made `use --live --json` unparseable — the one output shape whose
    // whole purpose is being parsed.
    pass.warnings.push(BACKEND_NOTE.to_owned());
    eprintln!("note: {BACKEND_NOTE}");

    let reader = default_reader(ctx);

    // Step 7: **one** read of the item. Everything Phase A knows about the
    // outgoing credential comes from here.
    let (displaced, item_present) = match location::from_keychain(reader.as_ref(), &service) {
        Resolved::Credentials(credentials) => (Some(*credentials), true),
        // The store has not migrated yet: the plaintext file is the
        // authoritative source, and the item write below is a first write.
        Resolved::Absent => match location::from_file(&store_dir) {
            Resolved::Credentials(credentials) => (Some(*credentials), false),
            Resolved::Absent => (None, false),
            _ => return Report::cannot_adopt(adopt::Refusal::Unreadable, &service),
        },
        // Locked or transient. Refusal F by subsumption: what cannot be read
        // cannot be put back, and a swap that cannot put the outgoing
        // credential back is a swap that loses it (decision D-017).
        _ => return Report::cannot_adopt(adopt::Refusal::Unreadable, &service),
    };

    // The baseline is the **item**, not the credential being adopted, and on
    // a first write those are different things: the store has not migrated,
    // so the item is absent and the credential to adopt came out of the
    // plaintext file. Using the file's digests here would compare a file
    // against a re-read of an item — which never matches, so every first
    // write would be discarded — and would record `from_digest8` for a
    // credential the item never held, which is precisely the field
    // `use --undo` reads as "this swap displaced something" (plan AC72).
    let before = if item_present { displaced.as_ref().map(Credentials::digests) } else { None };
    let from_digest8 = before.as_ref().and_then(|d| audit::digest8(&d.access_sha256));

    let mut incoming_credentials = match incoming.credentials(paths, ctx) {
        Ok(credentials) => credentials,
        Err(report) => return *report,
    };

    // Step 8: the incoming credential is already there. Adopt nothing, write
    // nothing, touch nothing (plan AC72).
    //
    // The question is about what the **store** currently serves, which is not
    // the same thing as what the item holds: before a migration the item is
    // absent and the plaintext file is authoritative. `before` is `None` in
    // exactly that case, so asking it here — as this briefly did — made the
    // comparison `None == Some(..)`, which can never hold. Re-swapping the
    // credential an unmigrated store already held then performed a real
    // keychain write, migrated a store nobody had asked to migrate, left a
    // duplicate credential at rest, and reported a swap that changed nothing
    // (finding N-3). `displaced` is already "the item if there is one, else
    // the plaintext file", which is the store's current credential by
    // definition.
    let current = displaced.as_ref().map(Credentials::digests);
    if current.as_ref() == Some(&incoming_credentials.digests()) {
        // `from_digest8` stays the **item**'s (AC72's audit baseline, `None`
        // on an unmigrated store); `to_digest8` names what is actually
        // active, which is the thing the caller asked about.
        let active = current.as_ref().and_then(|d| audit::digest8(&d.access_sha256));
        return Report {
            outcome: Outcome::AlreadyActive,
            target: None,
            service,
            from_digest8,
            to_digest8: active,
            audit_id: None,
            adopted_to: None,
            lock: LockReport::default(),
            warnings: Vec::new(),
            note: Some("that account's credential is already the one this store holds".to_owned()),
        };
    }

    // Step 9, refusal D's first check: on the **stored** blob, outside every
    // lock and before any child exists (invariant I15).
    let account = crate::secret::current_account();
    if matches!(
        incoming_credentials.to_keychain_stdin_line(&account, &service),
        Err(KeychainWriteError::LineTooLong { .. })
    ) {
        return Report::refused(Refusal::LineTooLong, &service, line_too_long_note());
    }

    // --- Phase B ---------------------------------------------------------
    // The **third** namespace, resolved here in Phase A's reading rather than
    // where it is used. A forward swap whose displaced credential belongs to
    // somebody else — the ordinary state of the second and every later swap
    // of one store — adopts it into *that* account's `.credentials.json`, and
    // ruling OQ11 ordered only two locks. A write agentctl does not hold the
    // namespace lock for is a blind overwrite of a namespace a concurrent
    // `status` may be refreshing, against invariant I3'. Resolving it before
    // the first lock is taken is what keeps the whole set sorted, so three
    // locks cannot be taken in two different orders.
    //
    // A reversal never reaches it: `adopt::decide_undo` parks the occupant in
    // this store's own adopted copy whoever it belongs to, so there is no
    // third namespace to write and none to lock.
    let third = match direction {
        Direction::Forward => displaced.as_ref().and_then(|p| third_namespace(config, store, p)),
        Direction::Reverse => None,
    };

    // Step 10: the namespace locks, in ascending namespace-key order so two
    // concurrent swaps cannot take each other's locks in opposite orders and
    // deadlock (ruling OQ11, extended to the third namespace above). Held
    // across Phase B *and* Phase C. These are agentctl's own locks; Claude
    // Code neither takes nor waits for them.
    let deadline = Instant::now() + SWAP_DEADLINE;
    let mut locked: Vec<&AccountRecord> = vec![incoming.record, store];
    locked.extend(third.as_ref());
    let mut guards = Vec::new();
    for (acct, org) in lock_order(&locked) {
        match namespace_lock::acquire(paths, &acct, &org, deadline, ctx.cancel(), fault.clone()) {
            Ok(guard) => guards.push(guard),
            Err(err) => {
                return Report::refused(
                    Refusal::CannotAdopt(adopt::Refusal::Unreadable),
                    &service,
                    format!("the namespace lock could not be taken: {err}"),
                );
            }
        }
    }

    // Step 11: **decide** what becomes of the displaced credential, or refuse
    // (decision D-017). Under D's namespace lock, which is ruling OQ2's
    // condition (c).
    //
    // Deciding and writing are two steps with the prompt between them, and
    // that separation is the whole of finding N-1. This used to write the
    // copy here, before step 12 printed the plan and asked — so the order was
    // *write the credential, describe the write, ask whether to do it,
    // refuse*. Every run that declined, and every non-interactive
    // `--json` inspection (which `Tty::confirm` fails closed), left a new
    // 0600 file holding a live access **and** refresh token in a directory
    // that had none — and in the third-account shape created or overwrote a
    // **different** account's `.credentials.json`. Refusal **F** still has to
    // be decided in front of the prompt, because a swap that cannot adopt is
    // not a swap worth asking about; only the write moves.
    let plan = match displaced.as_ref() {
        Some(displaced) => {
            match decide_adoption(
                paths,
                store,
                &store_dir,
                displaced,
                third.as_ref(),
                ctx,
                direction,
            ) {
                Ok(plan) => plan,
                Err(reason) => return Report::cannot_adopt(reason, &service),
            }
        }
        None => AdoptionPlan::Nothing,
    };

    // Step 12: the plan, then the prompt. Digest prefixes only — both name
    // what is being replaced without showing any of it.
    //
    // `--json` prints the plan and **still asks**. It used to imply `--yes`,
    // which inverted the flag's meaning: the machine-readable form is what an
    // operator reaches for to see what a swap *would* do, and it performed
    // one instead. `--yes` is the only thing that skips the question, and a
    // piped run without it refuses at `Tty::confirm`'s closed door rather
    // than proceeding.
    //
    // The prompt is in front of the **refresh**, and that is finding N-8. A
    // refresh is not a read: the server rotates the refresh token away from
    // whatever held the old one, so a refresh the run then discards costs the
    // incoming account an interactive `login`. Refreshing first meant every
    // declined prompt — and every scripted `--json` inspection, which
    // `Tty::confirm` fails closed — destroyed the grant of the account the
    // operator had just declined to move. Nothing irreversible may happen in
    // front of the consent gate, on the server any more than on the disk.
    //
    // The digest named here is therefore the credential as it stands **now**.
    // When it is stale, the refresh below mints a rotation of it and the
    // outcome document's `to.digest8` names that instead — the same
    // credential, one rotation on.
    let planned_digest8 = audit::digest8(&incoming_credentials.digests().access_sha256)
        .unwrap_or_else(|| "unknown".to_owned());
    if args.json {
        emit_plan(
            &store_dir,
            incoming.record,
            &from_digest8,
            &planned_digest8,
            &service,
            direction,
        );
    }
    if !args.yes
        && let Some(report) = confirm(
            &mut Tty,
            &store_dir,
            incoming.record,
            &from_digest8,
            &planned_digest8,
            &service,
            direction,
        )
    {
        return report;
    }

    // Step 13: refresh the incoming credential if it has expired or is about
    // to. Under the namespace locks, outside Claude Code's, and now behind
    // the consent gate.
    let now = now_ms();
    if incoming_credentials.access_expired(now, REFRESH_MARGIN_MS) {
        // Every other refresh in this crate saves its result where it read it
        // (`status::under_namespace_lock`, `status::refresh_in_place`), and
        // this one must too or the incoming account is left holding a refresh
        // token the server has rotated away. Which it can do depends on where
        // the credential came from:
        //
        // - a plaintext `.credentials.json` is written back below, under the
        //   namespace lock step 10 already took for that record;
        // - a **migrated** store would need a second keychain item written
        //   inside this pass, which no ruling has authorised and which would
        //   need a hold of its own. So it is refused before the POST instead,
        //   pointing at the one command that does refresh such an item in
        //   place and persist it. A migrated store whose credential is still
        //   fresh needs no refresh and is not affected.
        if matches!(incoming.source, Source::OwnStore)
            && migrated(paths, Some(incoming.record), ctx)
        {
            return Report::needs_refresh(
                &service,
                format!(
                    "`{}`'s credential has expired and its store has migrated into the keychain, \
                     so this swap cannot refresh it without discarding the result; run `agentctl \
                     claude status` to refresh that item in place and run this again",
                    incoming.record.email.as_deref().unwrap_or(&incoming.record.account_uuid)
                ),
            );
        }
        let derived_from = incoming_credentials.digests();
        if let Err(report) = refresh_incoming(&mut incoming_credentials, ctx, &service, now) {
            return *report;
        }
        write_back_refreshed(paths, incoming, &incoming_credentials, &derived_from, ctx);
    }
    let after = incoming_credentials.digests();

    // Step 14: refusal D's second check, on the refreshed blob, and then the
    // audit entry's own precondition. A write that could not be recorded must
    // not happen (invariant I16), and `to_digest8` is a required field of the
    // entry — so a credential with no usable digest is refused here, before
    // anything is held.
    //
    // This refusal sits **outside** the audit guard, and that is the W3
    // re-review's finding N5, inherited deliberately rather than papered over
    // with a sentinel: a minted credential is discarded without an audit
    // line, because there is no entry that could be written without the field
    // the entry requires.
    let line = match incoming_credentials.to_keychain_stdin_line(&account, &service) {
        Ok(line) => line,
        Err(KeychainWriteError::LineTooLong { .. }) => {
            return Report::refused(Refusal::LineTooLong, &service, line_too_long_note());
        }
        Err(err) => {
            return Report::refused(
                Refusal::CannotAdopt(adopt::Refusal::Unreadable),
                &service,
                err.to_string(),
            );
        }
    };
    let Some(to_digest8) = audit::digest8(&after.access_sha256) else {
        return Report::refused(
            Refusal::CannotAdopt(adopt::Refusal::Unreadable),
            &service,
            "the credential to be written has no usable digest".to_owned(),
        );
    };

    // Step 15: the adoption, now that somebody has agreed to it. Still Phase
    // B, still under every namespace lock step 10 took — including the third
    // one, when the displaced credential belongs to a third account — and
    // still before the hold. Nothing above this line has put a credential on
    // disk that was not already there (finding N-1).
    let Adopted { to: adopted_to, staged } =
        match perform_adoption(paths, plan, displaced.as_ref(), ctx) {
            Ok(adopted) => adopted,
            Err(reason) => return Report::cannot_adopt(reason, &service),
        };

    // Step 16: `acquire` creates nothing, so a namespace directory that does
    // not exist yet is `Unreachable` rather than a lock. Opening it the way
    // the file writer does is what makes a first swap work.
    if let Err(err) = file_store::open_namespace_dir(paths, &store_dir) {
        return Report::refused(
            Refusal::CannotAdopt(adopt::Refusal::Unreadable),
            &service,
            format!("the store directory could not be opened: {err}"),
        );
    }

    // The window AC71 occupies to change the item under us, **outside** the
    // hold: a pause inside one would break invariant I17 even under a fault.
    fault.pause_point("before_swap_write");

    phase_c(
        paths,
        PhaseC {
            target: &target,
            sha8: sha8.sha8(),
            service: &service,
            account: &account,
            store_dir: &store_dir,
            before: before.as_ref(),
            after: &after,
            from_digest8,
            to_digest8,
            adopted_to,
            staged,
            direction,
            // A first write, and the displaced credential came out of the
            // plaintext file rather than out of an item — so that file is
            // about to become a second copy of a credential the adoption has
            // already parked elsewhere (finding N-2). Both halves matter: an
            // absent item with no file at all displaces nothing and leaves
            // nothing to remove.
            shadowing_store: !item_present && displaced.is_some(),
        },
        line,
        env,
        ctx,
        fault,
    )
}

/// The registry record the displaced credential belongs to, when that is
/// somebody other than the store's own account.
///
/// `None` when the credential is the store's own — including the case where
/// it names no identity at all, which fact F4 says is an older blob rather
/// than a different account — and `None` when it names one agentctl has no
/// record for, which [`adopt_displaced`] turns into a refusal rather than
/// manufacturing a namespace for it.
fn third_namespace(
    config: &AgentctlConfig,
    store: &AccountRecord,
    displaced: &Credentials,
) -> Option<AccountRecord> {
    if swap::same_identity(displaced, store) {
        return None;
    }
    displaced
        .identity()
        .and_then(|id| config.accounts.iter().find(|r| r.account_uuid == id.account_uuid))
        .cloned()
}

/// Which way round the swap is running.
///
/// The procedure is the same in both directions — plan section 3.4's Phase
/// A/B/C, the same two namespace locks, the same hold, the same audit shape —
/// and exactly two things differ, both in Phase B:
///
/// | | `Forward` | `Reverse` |
/// |---|---|---|
/// | where the incoming credential is read | the incoming account's own namespace store | the store's adopted copy, which is where the swap being undone parked it |
/// | where the displaced credential is parked | decision D-017's matrix (`adopt::decide`) | always the store's adopted copy (`adopt::decide_undo`) |
///
/// Nothing else branches on this, which is the point: a rollback that took a
/// different path through the locks would be a second protocol to get right.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    /// `use --live <id>`.
    Forward,
    /// `use --undo`.
    Reverse,
}

/// The pass-wide values every phase needs, gathered so no signature has to
/// list them again.
///
/// One `EnvView` travels here on purpose: the store directory and the service
/// name must derive from a single reading of the environment, or a variable
/// that changed between two readings could make them disagree (risk R42).
struct Swap<'a> {
    paths: &'a Paths,
    config: &'a AgentctlConfig,
    env: &'a EnvView,
    /// The spelling the store is named by: the inherited
    /// `CLAUDE_SECURESTORAGE_CONFIG_DIR` on the forward path, and the same
    /// string as the record recorded it on a reversal, which has no session
    /// to inherit from. The derived store directory must still spell this,
    /// or the item and the locks are about different directories.
    inherited: &'a str,
    ctx: &'a PassCtx,
    fault: &'a Fault,
}

/// Everything Phase C needs, gathered so the signature stays readable.
struct PhaseC<'a> {
    target: &'a WriteTarget,
    sha8: &'a str,
    service: &'a str,
    account: &'a str,
    store_dir: &'a Path,
    before: Option<&'a Digests>,
    after: &'a Digests,
    from_digest8: Option<String>,
    to_digest8: String,
    adopted_to: Option<String>,
    /// A reversal's adopted copy, written but not yet renamed into place.
    ///
    /// The whole of finding P1-1's fix. On a reversal the copy is the **only**
    /// remaining home of the credential being restored — the store has
    /// migrated, so `.credentials.json` does not exist — so committing the
    /// occupant over it before the item write has landed destroys it on every
    /// exit that is not a write. Dropping this value removes the temporary
    /// and leaves the copy holding what it held.
    staged: Option<file_store::StagedAdoption>,
    /// Which way round the swap is running, for the sentence a failed write
    /// prints: the forward direction's "recoverable with `use --undo`" is
    /// false in reverse, where `--undo` is what is already running.
    direction: Direction,
    /// Whether the store's plaintext `.credentials.json` still holds the
    /// credential this swap is displacing.
    ///
    /// True only on a **first** write: the store had not migrated, so the
    /// item was absent and the displaced credential was read out of that
    /// file. Once the write applies, the item holds the incoming credential
    /// and the adoption has parked the displaced one elsewhere — so the file
    /// is a duplicate under the one name fact F35's composed read falls
    /// through to on *no item, a read failure or a throttle*. Leaving it
    /// would serve the peer session the account the user just swapped away
    /// from (finding N-2), which is the exposure decision D-024 exists to
    /// prevent.
    shadowing_store: bool,
}

/// Phase C: under Claude Code's three locks, inside the hold budget.
///
/// `line` is a parameter rather than a [`PhaseC`] field because it **moves**
/// into the write, and every path after the write still needs the rest.
#[expect(
    clippy::too_many_lines,
    reason = "the hold is one region and every exit from it owes the same release; \
              splitting it would put the drop between two functions"
)]
fn phase_c(
    paths: &Paths,
    c: PhaseC<'_>,
    line: KeychainStdinLine,
    env: &EnvView,
    ctx: &PassCtx,
    fault: &Fault,
) -> Report {
    // The budget is a constant of the protocol, so it is reported whether or
    // not a hold was ever taken; `hold_ms` is filled in only where there was
    // one to measure.
    let mut lock = LockReport {
        hold_ms: None,
        budget_ms: Some(millis(claude_lock::HOLD_BUDGET)),
        broke: None,
    };
    let ended = |outcome: Outcome, note: String, lock: LockReport| Report {
        outcome,
        target: None,
        service: c.service.to_owned(),
        from_digest8: c.from_digest8.clone(),
        to_digest8: Some(c.to_digest8.clone()),
        audit_id: None,
        adopted_to: c.adopted_to.clone(),
        lock,
        warnings: Vec::new(),
        note: Some(note),
    };

    let clock = Clock::system();
    let subject = LockSubject { store_dir: c.store_dir, tree: Tree::Agentctl };

    // Split the acquire into the draft and the rest **before** either is
    // looked at, so the append below is one unconditional statement. An
    // acquire that failed may already have removed a peer's stale lock, and
    // that removal is exactly what invariant I16 wants recorded
    // (`agentctl-nq3` — a completed break's draft was dropped on every Err).
    let (break_record, resolved) =
        match claude_lock::acquire(subject, paths, env, &clock, ctx, fault) {
            Ok(acquisition) => (acquisition.break_record, Ok(acquisition.outcome)),
            Err(failure) => (failure.break_record, Err(failure.error)),
        };

    // ONE append, unconditional, before the error mapping and before the
    // held/busy split — so a state added to either cannot be added without it.
    if let Some(draft) = break_record {
        let record = draft.complete(c.service.to_owned(), Target::Namespace(c.sha8.to_owned()));
        lock.broke = Some(break_summary(&record));
        audit_append(paths, AuditEvent::LockBreak(record));
    }

    let outcome = match resolved {
        Ok(outcome) => outcome,
        Err(err) => {
            return ended(
                Outcome::Refused(Refusal::CompromisedHold),
                format!("the Claude Code locks could not be taken: {err}"),
                lock,
            );
        }
    };

    let hold = match outcome {
        AcquireOutcome::Held(hold) => hold,
        AcquireOutcome::Busy { holder_alive, stopped_pids } => {
            return ended(Outcome::Busy, swap::busy_note(holder_alive, &stopped_pids), lock);
        }
    };

    // Refusal A: the lock agentctl holds moved under it, so the protocol was
    // violated before anything was written.
    if let Err(err) = hold.drift_check() {
        return ended(
            Outcome::Refused(Refusal::CompromisedHold),
            format!("the lock agentctl holds is compromised: {err}"),
            held(&lock, &hold),
        );
    }

    // The item as it is *now*, against what Phase A read (invariant I2′).
    let reader = default_reader(ctx);
    let observed = match location::from_keychain(reader.as_ref(), c.service) {
        Resolved::Credentials(credentials) => Some(credentials.digests()),
        Resolved::Absent => None,
        Resolved::Locked => {
            return ended(
                Outcome::Discarded,
                "the keychain locked before the item could be re-read under the hold".to_owned(),
                held(&lock, &hold),
            );
        }
        Resolved::Transient(detail) => {
            return ended(
                Outcome::Discarded,
                format!("the item could not be re-read under the hold ({detail})"),
                held(&lock, &hold),
            );
        }
    };
    if observed.as_ref() != c.before {
        return ended(
            Outcome::Discarded,
            "the item changed under the hold, so the swap was thrown away rather than written \
             over a newer credential"
                .to_owned(),
            held(&lock, &hold),
        );
    }

    // The deliberate I17 violation, under `testing` only and bounded by
    // `PAUSE_BUDGET`: the one fault that waits inside the hold, so a test can
    // watch the window from outside and move an artefact's mtime under it.
    //
    // **Above** the second drift check, and that position is the whole point.
    // Below it the pause was unobservable: an artefact moved during it was
    // never looked at again, so the one seam the contract designated for
    // producing refusal **A** could not produce it.
    fault.wait_if("swap_pause_in_locks");

    // Checked a second time, then the budget: a hold is never *started* down a
    // path that cannot finish inside it, because a hold past fact F53's
    // give-up floor makes the peer's own refresh throw rather than merely
    // making it late.
    if let Err(err) = hold.drift_check() {
        return ended(
            Outcome::Refused(Refusal::CompromisedHold),
            format!("the lock agentctl holds is compromised: {err}"),
            held(&lock, &hold),
        );
    }
    if hold.hold_elapsed().saturating_add(keychain_write::WRITE_TIMEOUT) > claude_lock::HOLD_BUDGET
    {
        return ended(
            Outcome::Discarded,
            "the hold ran out of budget before the write".to_owned(),
            held(&lock, &hold),
        );
    }

    // `swap_write_fail` models the child running and exiting non-zero — the
    // `failed` half of ruling OQ6, where `security(1)` reports a refused write
    // and the item is demonstrably untouched. Injected here rather than in the
    // fake, so the fake stays a faithful `security(1)` and this stays one
    // named branch.
    let write = if fault.is("swap_write_fail") {
        Err(KeychainWriteError::Failed {
            class: crate::secret::StderrClass::Other,
            stderr: "the write was refused by the test fault switch".to_owned(),
        })
    } else {
        keychain_write::write_item(c.target, c.account, line, ctx)
    };
    let elapsed = hold.hold_elapsed();
    lock.hold_ms = Some(millis(elapsed));
    drop(hold);
    if elapsed > claude_lock::HOLD_BUDGET {
        tracing::warn!(
            hold_ms = millis(elapsed),
            budget_ms = millis(claude_lock::HOLD_BUDGET),
            "the credential-store hold outlasted its budget"
        );
    } else {
        tracing::debug!(
            hold_ms = millis(elapsed),
            budget_ms = millis(claude_lock::HOLD_BUDGET),
            "released the credential-store hold"
        );
    }

    // `failed` = the child ran and exited non-zero, or the error was decided
    // before a child existed: the item demonstrably was not touched, and **no
    // verify read is issued** (ruling OQ6). Only a timeout leaves the question
    // open, and that one falls through to the read below.
    if let Err(err) = &write
        && !status::left_unknown(err)
    {
        let id = audit_write(paths, &c, audit::WriteOutcome::Failed);
        // Its **own** outcome and its own exit code. It used to report
        // refusal **A**, which made the exit code contradict the audit line
        // this call just wrote (`"outcome":"failed"`) and filled the one
        // signal that means *somebody moved a lock agentctl was holding* with
        // ordinary write failures.
        return Report {
            outcome: Outcome::Failed,
            target: None,
            service: c.service.to_owned(),
            from_digest8: c.from_digest8,
            to_digest8: Some(c.to_digest8),
            audit_id: id,
            adopted_to: c.adopted_to,
            lock,
            warnings: Vec::new(),
            note: Some(format!(
                "the credential could not be stored: {err}. {}",
                match c.direction {
                    // Forward: P sits in the adopted copy, written in Phase B and
                    // committed there, and the item still holds it too.
                    Direction::Forward => {
                        "The outgoing credential is still recoverable with `agentctl claude use \
                     --undo`"
                    }
                    // Reverse: the staged copy was never committed, so the copy
                    // still holds the credential this rollback was putting back.
                    // Saying "recoverable with `--undo`" here would be advising
                    // the user to re-run the command that just failed.
                    Direction::Reverse => {
                        "The credential this rollback was restoring is untouched in the adopted \
                     copy; nothing was lost and the rollback can be run again"
                    }
                }
            )),
        };
    }

    // The verifying read is deliberately outside the hold, so a legitimate
    // peer write landing in the gap reports `unknown` for a write that did
    // apply — which is why `unknown` means "re-run `status`", not "failed".
    let applied = match location::from_keychain(reader.as_ref(), c.service) {
        Resolved::Credentials(credentials) => credentials.digests() == *c.after,
        _ => false,
    };
    let id = audit_write(
        paths,
        &c,
        if applied { audit::WriteOutcome::Applied } else { audit::WriteOutcome::Unknown },
    );

    // The reversal's adoption, committed at last — and **only** on `applied`
    // (finding P1-1, narrowed by the lead's ruling on the `unknown` arm).
    //
    // `applied` is the one outcome in which the item demonstrably holds what
    // the copy held, so replacing the copy's contents cannot leave that
    // credential with nowhere to be. `unknown` says the write's outcome is
    // *undetermined*: if it did not land, the item still holds the occupant,
    // and committing would put the occupant over the only remaining home of
    // the credential this rollback was restoring. Dropping the staging
    // instead costs nothing — the occupant that goes unparked is still in its
    // own namespace store, where the forward swap read it and left it — and
    // it costs only the ability to undo *this* undo, which the note says.
    // Every refusing exit above dropped `c.staged` for the same reason.
    let mut adopted_to = c.adopted_to;
    let mut note = None;
    match c.staged {
        Some(staged) if applied => match file_store::commit_staged(paths, staged) {
            Ok(_) => adopted_to = Some(file_store::ADOPTED_FILE.to_owned()),
            Err(err) => {
                // The item write landed, so the reversal itself stands. What
                // did not happen is the parking of the credential it
                // displaced — which is still in its own namespace store.
                tracing::error!(error = %err, "the displaced credential could not be parked");
                note = Some(format!(
                    "the swap applied, but the credential it displaced could not be parked in \
                     the adopted copy ({err}); it is still in its own namespace store"
                ));
            }
        },
        Some(staged) => {
            // Explicit, because the whole ruling is in this line: the
            // temporary is removed and the copy keeps the restored credential.
            drop(staged);
            note = Some(
                "the write could not be confirmed; re-run `agentctl claude status`. The \
                 credential this rollback was restoring is untouched in the adopted copy, and \
                 the one it displaced was deliberately not parked there — so this reversal \
                 cannot itself be undone; that credential is still in its own namespace store"
                    .to_owned(),
            );
        }
        None => {}
    }
    // Finding N-2, and the D-024 exposure it reintroduced. On a **first**
    // write the displaced credential came out of `<D>/.credentials.json`, and
    // once the item demonstrably holds the incoming one that file is a second
    // copy rather than a home: the adoption has already parked the displaced
    // credential in `.credentials.adopted.json`. Fact F35's composed read
    // falls through to `.credentials.json` on *no item, a read failure or a
    // throttle* — not only on an absent item — so leaving it would serve the
    // peer session the account the user just swapped away from, on nothing
    // worse than a keychain hiccup, while the item says otherwise.
    //
    // Removed under D's namespace lock, which is still held (ruling OQ11),
    // through the same `O_NOFOLLOW` walk every other write to this directory
    // goes through. Only on `applied`: `unknown` leaves the question of what
    // the item holds open, and a file that may still be the credential's only
    // readable home is not one to remove on a guess.
    if c.shadowing_store {
        let removed = if applied {
            match file_store::remove_credentials_file(paths, c.store_dir) {
                Ok(_) => None,
                Err(err) => {
                    tracing::error!(
                        error = %err,
                        "the migrated store's plaintext credentials file could not be removed"
                    );
                    Some(format!(
                        "the swap applied, but `{}` still holds the credential it displaced and \
                         Claude Code reads that file whenever the keychain is unavailable; \
                         remove it by hand ({err})",
                        file_store::CREDENTIALS_FILE
                    ))
                }
            }
        } else {
            // Finding N-9: this used to say "re-run `agentctl claude
            // status`", which cannot do anything about the file — nothing in
            // `status`, `doctor` or `accounts` removes a `.credentials.json`
            // — so the sentence sent the operator to a command that would
            // report success and leave the shadow in place. What `status`
            // can answer is the question the removal turns on: what the item
            // holds. `unknown` is *undetermined*, not *failed*: the write may
            // well have landed and only the verifying read have missed it.
            Some(format!(
                "the write could not be confirmed, so `{}` was kept and still holds the \
                 credential this swap displaced. The item may already hold the incoming one: run \
                 `agentctl claude status` to see which, and if it does, remove that file by hand \
                 — Claude Code reads it whenever the keychain is unavailable. `agentctl claude \
                 doctor` reports it until then",
                file_store::CREDENTIALS_FILE
            ))
        };
        if let Some(sentence) = removed {
            note = Some(match note {
                Some(existing) => format!("{existing}. {sentence}"),
                None => sentence,
            });
        }
    }
    if note.is_none() && !applied {
        note = Some("the write could not be confirmed; re-run `agentctl claude status`".to_owned());
    }

    Report {
        outcome: if applied { Outcome::Applied } else { Outcome::Unknown },
        target: None,
        service: c.service.to_owned(),
        from_digest8: c.from_digest8,
        to_digest8: Some(c.to_digest8),
        audit_id: id,
        adopted_to,
        lock,
        warnings: Vec::new(),
        note,
    }
}

/// The lock report as it stands with a hold open.
fn held(base: &LockReport, hold: &HeldLocks) -> LockReport {
    LockReport { hold_ms: Some(millis(hold.hold_elapsed())), ..base.clone() }
}

/// Step 13's refresh, folded out so the phase reads as one sequence.
fn refresh_incoming(
    credentials: &mut Credentials,
    ctx: &PassCtx,
    service: &str,
    now: i64,
) -> Result<(), Box<Report>> {
    let refresher = match status::default_refresher() {
        Ok(refresher) => refresher,
        Err(err) => {
            return Err(Box::new(Report::refused(
                Refusal::CannotAdopt(adopt::Refusal::Unreadable),
                service,
                err.to_string(),
            )));
        }
    };
    match refresher.refresh(credentials, ctx.cancel()) {
        Ok(token) => credentials.merge_refresh(token, now).map_err(|err| {
            Box::new(Report::refused(
                Refusal::CannotAdopt(adopt::Refusal::Unreadable),
                service,
                format!("the refresh response was unusable: {err}"),
            ))
        }),
        Err(RefreshError::InvalidGrant) => Err(Box::new(Report::refused(
            Refusal::CannotAdopt(adopt::Refusal::Unreadable),
            service,
            "the incoming account's refresh token has been rotated away; run `agentctl claude \
             login` for it first"
                .to_owned(),
        ))),
        Err(err) => Err(Box::new(Report::refused(
            Refusal::CannotAdopt(adopt::Refusal::Unreadable),
            service,
            err.to_string(),
        ))),
    }
}

/// Saves a refreshed incoming credential back where it was read from.
///
/// Finding N-8's other half. The refresh POST rotates the server's refresh
/// token away from the copy in the incoming account's own store, so that copy
/// is dead the moment the POST returns — on the applied path as much as on
/// every exit that follows (busy, discarded, a compromised hold, a failed
/// write). Every other refresh in this crate persists immediately for exactly
/// that reason; this one does too, through the same tmp-fsync-rename writer,
/// under the namespace lock step 10 already holds for this record.
///
/// Only for [`Source::OwnStore`] — the forward direction, whose source is a
/// plaintext `.credentials.json`. A reversal reads the store's adopted copy,
/// which is the file the staging protocol protects and whose contents a later
/// `--undo`'s digest guard compares against; writing a refreshed credential
/// there needs its own ruling and is filed as `agentctl-bk5`.
///
/// A failure here does not fail the swap: the item write is what the operator
/// asked for, and a saved refresh is a repair, not a precondition. It is
/// logged, because the consequence — the incoming account needing a `login` —
/// is worth a line.
fn write_back_refreshed(
    paths: &Paths,
    incoming: &Incoming<'_>,
    refreshed: &Credentials,
    derived_from: &Digests,
    ctx: &PassCtx,
) {
    if !matches!(incoming.source, Source::OwnStore) {
        return;
    }
    let ns_dir =
        paths.namespace_dir(&incoming.record.account_uuid, &incoming.record.organization_uuid);
    let request = file_store::WriteRequest {
        paths,
        ns_dir: &ns_dir,
        blob_json: &refreshed.to_blob_json(),
        prior: Some(derived_from),
        new_expires_at_ms: refreshed.expires_at_ms,
        fault: Fault::none(),
    };
    if let Err(err) = file_store::write_credentials(&request, ctx) {
        tracing::error!(
            error = %err,
            "the refreshed incoming credential could not be saved to its own store"
        );
    }
}

/// Step 12's plan, for `--json`.
///
/// The contract's "`--json` prints the plan **before** prompting". It is a
/// separate document from the outcome and says so, so a consumer reading the
/// stream can tell the two apart: this one describes a swap that has not
/// happened yet and may still be refused at the prompt.
///
/// A render failure is not a reason to refuse a swap the user asked for, so
/// it is logged and the pass goes on to the prompt.
fn emit_plan(
    store_dir: &Path,
    incoming: &AccountRecord,
    from_digest8: &Option<String>,
    to_digest8: &str,
    service: &str,
    direction: Direction,
) {
    let doc = serde_json::json!({
        "kind": "plan",
        "direction": match direction {
            Direction::Forward => "forward",
            Direction::Reverse => "reverse",
        },
        "store_dir": store_dir.display().to_string(),
        "service": service,
        "account": incoming.email.as_deref().unwrap_or(&incoming.account_uuid),
        "from": { "digest8": from_digest8 },
        "to": { "digest8": to_digest8 },
    });
    match serde_json::to_string_pretty(&doc) {
        Ok(text) => println!("{text}"),
        Err(err) => tracing::error!(error = %err, "the swap plan could not be rendered"),
    }
}

/// Step 12's prompt. `None` means the user said yes.
///
/// Both refusing answers — "no", and "there is nobody to ask" — are
/// [`Outcome::Cancelled`] rather than refusal **F** (finding N-6). **F** is
/// `CannotAdopt`: *the outgoing credential cannot be adopted, so the swap
/// would lose it*, a fact about the store that no answer at the prompt can
/// change. Reporting a declined confirmation under the same letter and the
/// same exit code left a script unable to distinguish the two — and since
/// `--json` stopped implying `--yes`, declining became the common path rather
/// than a corner.
///
/// The [`Prompt`] arrives as a parameter so the decision can be tested with a
/// scripted answer: `Tty::confirm` needs a terminal on standard input, which
/// no test in this repository has, so a hard-wired `Tty` here would make the
/// "answered no" arm reachable only by a person.
fn confirm(
    prompt: &mut dyn Prompt,
    store_dir: &Path,
    incoming: &AccountRecord,
    from_digest8: &Option<String>,
    to_digest8: &str,
    service: &str,
    direction: Direction,
) -> Option<Report> {
    let verb = match direction {
        Direction::Forward => "replace",
        Direction::Reverse => "put back",
    };
    let question = format!(
        "{verb} the credential in `{}` (digest {}) with `{}`'s (digest {})? It takes effect on \
         your next message, within 30 s; run `/model` once afterwards to refresh model access",
        store_dir.display(),
        from_digest8.as_deref().unwrap_or("none"),
        incoming.email.as_deref().unwrap_or(&incoming.account_uuid),
        to_digest8,
    );
    match prompt.confirm(&question) {
        Ok(true) => None,
        Ok(false) => Some(cancelled(service, "cancelled at the confirmation prompt".to_owned())),
        Err(err) => Some(cancelled(service, err.to_string())),
    }
}

/// A swap nobody agreed to.
fn cancelled(service: &str, note: String) -> Report {
    Report {
        outcome: Outcome::Cancelled,
        target: None,
        service: service.to_owned(),
        from_digest8: None,
        to_digest8: None,
        audit_id: None,
        adopted_to: None,
        lock: LockReport::default(),
        warnings: Vec::new(),
        note: Some(note),
    }
}

/// The credential going **into** the item, and where it comes from.
///
/// A forward swap reads the incoming account's own namespace store. A
/// reversal cannot: the credential it is putting back is the one the swap
/// displaced, which by decision D-024 lives in the store's adopted copy and
/// nowhere else. So the caller supplies it and this carries it, rather than
/// `swap_in` growing a second read path it would have to choose between.
struct Incoming<'a> {
    /// The account the credential belongs to, for the locks and the prompt.
    record: &'a AccountRecord,
    /// Which way round the swap is running.
    direction: Direction,
    /// Which file holds it.
    ///
    /// A path rather than the value, because [`Credentials`] is deliberately
    /// not `Clone` — the type makes copying token material an explicit act —
    /// and `swap_in` takes this by reference. Naming the source instead keeps
    /// the read inside the phase that uses it.
    source: Source,
}

/// Where the incoming credential is read from.
enum Source {
    /// The incoming account's own namespace store, `.credentials.json`.
    OwnStore,
    /// The store's adopted copy, where the swap being undone parked the
    /// credential now being put back (decision D-024).
    AdoptedCopy(std::path::PathBuf),
}

impl Incoming<'_> {
    /// The credential to write.
    ///
    /// W4a reads the incoming credential from a **plaintext** store and only
    /// from there. A namespace whose credentials have migrated into the
    /// keychain therefore cannot be swapped *in* yet — reading its item would
    /// be a second read path with its own protocol, which no ruling has asked
    /// for — so this refuses. What it must not do is misdescribe why, which
    /// is what [`Incoming::unreadable`] is for.
    fn credentials(&self, paths: &Paths, ctx: &PassCtx) -> Result<Credentials, Box<Report>> {
        let read = match &self.source {
            Source::OwnStore => {
                let ns_dir =
                    paths.namespace_dir(&self.record.account_uuid, &self.record.organization_uuid);
                location::from_file(&ns_dir)
            }
            Source::AdoptedCopy(dir) => location::from_adopted(dir),
        };
        match read {
            Resolved::Credentials(credentials) => Ok(*credentials),
            read => Err(Box::new(Report::refused(
                Refusal::CannotAdopt(adopt::Refusal::Unreadable),
                "",
                self.unreadable(&read, paths, ctx),
            ))),
        }
    }

    /// Why the incoming credential could not be read, in the words that fit
    /// the state actually found.
    ///
    /// The forward direction has two ways to have no plaintext store, and
    /// they call for opposite responses. An account that has never logged in
    /// needs a `login`. An account whose namespace has **migrated** has a
    /// perfectly good credential sitting in its keychain item — telling its
    /// owner to log in again would spend a round trip and rotate a working
    /// refresh token away to fix nothing. So the migrated case says what is
    /// true: the credential is there, and swapping it in is not supported
    /// yet.
    ///
    /// The keychain read that separates the two is paid for only here, on a
    /// path that is already refusing, so no successful swap costs anything
    /// for it.
    fn unreadable(&self, read: &Resolved, paths: &Paths, ctx: &PassCtx) -> String {
        let Source::OwnStore = &self.source else {
            return "the adopted copy that swap displaced is gone or unreadable, so there is \
                    nothing to put back"
                .to_owned();
        };
        let who = self.record.email.as_deref().unwrap_or(&self.record.account_uuid);
        if matches!(read, Resolved::Absent) && migrated(paths, Some(self.record), ctx) {
            return format!(
                "`{who}`'s credential lives in its keychain item; swapping it in is not supported \
                 yet"
            );
        }
        format!("`{who}` has no readable credential to swap in; run `agentctl claude login` for it")
    }
}

/// Where decision D-017's adoption will put the displaced credential.
///
/// The output of [`decide_adoption`] and the input to [`perform_adoption`],
/// and the reason the two are separate: everything that can refuse an
/// adoption is settled while this value is being built, and nothing reaches
/// the disk until it is handed on — with the confirmation prompt in between
/// (finding N-1). It names places, never credentials: the blob is derived
/// from the caller's `displaced` at write time, so no second copy of the
/// token material exists while the operator is being asked.
#[derive(Debug, PartialEq, Eq)]
enum AdoptionPlan {
    /// Nothing to write: there is no displaced credential, or the target
    /// already holds exactly it.
    Nothing,
    /// Decision D-024's copy, renamed into place as soon as it is written.
    ///
    /// The forward direction. The item still holds the displaced credential
    /// at this point, so the copy *adds* a home rather than replacing one.
    AdoptedCopy(PathBuf),
    /// The same copy, written under a temporary name for Phase C to commit.
    ///
    /// A reversal. The copy is the only remaining home of the credential
    /// being restored, so the occupant may not be renamed over it until the
    /// item demonstrably holds what the copy held.
    StagedCopy(PathBuf),
    /// A third account's own `.credentials.json`, compare-and-swapped against
    /// what the decision was taken from.
    ThirdStore {
        /// That account's namespace directory.
        ns_dir: PathBuf,
        /// The digests read there when the decision was taken, or `None` for
        /// an absent file.
        prior: Option<Digests>,
    },
}

/// Decision D-017's adoption, **decided**: every read, every refusal, no write.
///
/// The matrix itself is [`adopt::decide`], which is pure; this reads what that
/// needs and turns its answer into an [`AdoptionPlan`]. It runs in Phase B
/// under the namespace lock (ruling OQ2, condition (c)) and **before** the
/// confirmation prompt, so refusal **F** keeps the position plan section
/// 3.4 gives it: a swap that cannot adopt is refused without asking about it.
fn decide_adoption(
    paths: &Paths,
    store: &AccountRecord,
    store_dir: &Path,
    displaced: &Credentials,
    third: Option<&AccountRecord>,
    ctx: &PassCtx,
    direction: Direction,
) -> Result<AdoptionPlan, adopt::Refusal> {
    // A reversal parks the occupant in the store's own adopted copy, whoever
    // it belongs to: see `adopt::decide_undo` for why the identity condition
    // and the matrix's namespace choice both fall away in that direction.
    //
    // It **stages** rather than writes. The copy is the only remaining home
    // of the credential this reversal is restoring — the store has migrated,
    // so `.credentials.json` does not exist, which is the premise of the
    // whole D-024 carve-out — so committing the occupant over it here would
    // destroy that credential on every Phase C exit that is not a write: a
    // peer refresh during the prompt, a busy store, a compromised hold, a
    // budget refusal, a `security(1)` that exits non-zero. Phase C commits it
    // once the item may hold what the copy held.
    if direction == Direction::Reverse {
        let existing = classify(location::from_adopted(store_dir), displaced);
        let decision = adopt::decide_undo(&adopt::Input {
            same_namespace: true,
            identity_matches: true,
            pending_present: pending_present(store_dir),
            target_migrated: false,
            existing,
            displaced_expires_at_ms: displaced.expires_at_ms,
        });
        return match decision {
            adopt::Adoption::AlreadyPresent => Ok(AdoptionPlan::Nothing),
            adopt::Adoption::Refused(refusal) => Err(refusal),
            _ => Ok(AdoptionPlan::StagedCopy(store_dir.to_path_buf())),
        };
    }

    // Condition (a): whether the item's identity is the record's. An absent
    // `tokenAccount` is an older blob (fact F4), not a different identity, so
    // `same_identity` passes it — and a credential agentctl cannot identify
    // belongs to the store it was found in, which is the same conclusion.
    let identity_matches = swap::same_identity(displaced, store);
    let same_namespace = identity_matches;

    let (ns_dir, existing, prior) = if same_namespace {
        // Decision D-024: the adopted copy, never `.credentials.json`.
        let read = location::from_adopted(store_dir);
        (store_dir.to_path_buf(), classify(read, displaced), None)
    } else {
        // Somebody else's credential is in this store's item. It belongs in
        // *their* namespace, if agentctl has one for them — and `third` is
        // that record, resolved in Phase A so its namespace lock is in the
        // set taken at step 10. Resolving it here instead would write a
        // namespace whose lock nobody took.
        let Some(record) = third else {
            return Err(adopt::Refusal::IdentityMismatch);
        };
        let dir = paths.namespace_dir(&record.account_uuid, &record.organization_uuid);
        // The digests are kept as well as the classification: they are what
        // the compare-and-swap below compares, because the classification
        // cannot (finding N-4).
        let (existing, prior) = inspect(location::from_file(&dir), displaced);
        (dir, existing, prior)
    };

    // The matrix's last row, and it costs a keychain read — but only on the
    // path that needs it. When the namespaces are the same the store has
    // migrated by construction (that is *why* there is a swap) and ruling
    // OQ2's carve-out is the exception that covers it, so `adopt::decide`
    // does not consult this flag there and nothing is read.
    let target_migrated = !same_namespace && migrated(paths, third, ctx);

    let decision = adopt::decide(&adopt::Input {
        same_namespace,
        identity_matches,
        pending_present: pending_present(&ns_dir),
        target_migrated,
        existing,
        displaced_expires_at_ms: displaced.expires_at_ms,
    });

    match decision {
        adopt::Adoption::AlreadyPresent => Ok(AdoptionPlan::Nothing),
        adopt::Adoption::Refused(refusal) => Err(refusal),
        adopt::Adoption::ToAdoptedCopy => Ok(AdoptionPlan::AdoptedCopy(ns_dir)),
        adopt::Adoption::ToStore => Ok(AdoptionPlan::ThirdStore { ns_dir, prior }),
    }
}

/// Decision D-017's adoption, **performed**: the write and nothing else.
///
/// Called once the operator has agreed to the swap, still in Phase B and
/// still under every namespace lock step 10 took. Everything that can refuse
/// an adoption refused in [`decide_adoption`], with the single exception of
/// the third namespace's compare-and-swap, which by definition can only be
/// answered against the file as it is at the moment of writing.
fn perform_adoption(
    paths: &Paths,
    plan: AdoptionPlan,
    displaced: Option<&Credentials>,
    ctx: &PassCtx,
) -> Result<Adopted, adopt::Refusal> {
    // The blob is derived here, from the caller's own value, rather than
    // carried on the plan: the plan outlives the confirmation prompt, and a
    // second copy of the access and refresh tokens has no business sitting in
    // memory while a person is being asked a question.
    let Some(displaced) = displaced else { return Ok(Adopted::default()) };
    match plan {
        AdoptionPlan::Nothing => Ok(Adopted::default()),
        AdoptionPlan::AdoptedCopy(ns_dir) => {
            file_store::write_adopted(paths, &ns_dir, &displaced.to_blob_json(), ctx)
                .map_err(|_| adopt::Refusal::Unreadable)?;
            Ok(Adopted { to: Some(file_store::ADOPTED_FILE.to_owned()), staged: None })
        }
        AdoptionPlan::StagedCopy(ns_dir) => {
            let staged = file_store::stage_adopted(paths, &ns_dir, &displaced.to_blob_json(), ctx)
                .map_err(|_| adopt::Refusal::Unreadable)?;
            Ok(Adopted { to: None, staged: Some(staged) })
        }
        AdoptionPlan::ThirdStore { ns_dir, prior } => {
            // The compare-and-swap the third namespace owes. `prior` on a
            // `WriteRequest` is recorded in the pending metadata; it is not a
            // check, so without this the write is a blind overwrite of a file
            // the decision was taken from a *read* of.
            //
            // Both reads sit inside this pass's own namespace locks, so
            // against a writer that respects the lock there is no window at
            // all; what this catches is one that does not — which is exactly
            // the case a coarse comparison serves worst, and why it compares
            // the **digests** rather than `adopt::Existing`. That
            // classification carries only `expiresAt` in its `Different`
            // variant, so a replacement whose expiry happened to match
            // compared equal and was overwritten (finding N-4).
            unchanged(location::from_file(&ns_dir), prior.as_ref())?;
            let request = file_store::WriteRequest {
                paths,
                ns_dir: &ns_dir,
                blob_json: &displaced.to_blob_json(),
                prior: None,
                new_expires_at_ms: displaced.expires_at_ms,
                fault: Fault::none(),
            };
            file_store::write_credentials(&request, ctx).map_err(|_| adopt::Refusal::Unreadable)?;
            Ok(Adopted { to: Some(file_store::CREDENTIALS_FILE.to_owned()), staged: None })
        }
    }
}

/// The compare-and-swap [`perform_adoption`] owes the third namespace.
///
/// `prior` is what the decision was taken from; `read` is the target as it is
/// now. Anything but the same answer refuses, because the credential now
/// there was never weighed against the one being adopted and may hold a
/// refresh token the server has already rotated away from it.
///
/// A target that has become unreadable refuses too, and under its own reason:
/// what cannot be read cannot be confirmed to be worthless.
fn unchanged(read: Resolved, prior: Option<&Digests>) -> Result<(), adopt::Refusal> {
    let now = match read {
        Resolved::Absent => None,
        Resolved::Credentials(found) => Some(found.digests()),
        _ => return Err(adopt::Refusal::Unreadable),
    };
    if now.as_ref() == prior { Ok(()) } else { Err(adopt::Refusal::Changed) }
}

/// What step 15 did, and what it still owes.
#[derive(Default)]
struct Adopted {
    /// The file the displaced credential is in, when it is already in one.
    to: Option<String>,
    /// A reversal's copy, written under a temporary name and not yet renamed
    /// into place. Committed by Phase C on the two outcomes in which the item
    /// may hold what the copy held, and dropped — which removes it — on every
    /// other.
    staged: Option<file_store::StagedAdoption>,
}

/// Whether a pending write from an earlier run is parked in a namespace
/// (ruling OQ2, condition (b)).
///
/// One spelling for the two callers that ask it. It is still `Path::exists`,
/// which follows symlinks and so answers "no" for a dangling one, where
/// `doctor` asks the same question with `symlink_metadata` — a divergence the
/// W4a review filed as a P3 and the lead left to the backlog, so it is
/// recorded here rather than changed under a fix lane that was not asked to.
fn pending_present(ns_dir: &Path) -> bool {
    ns_dir.join(file_store::PENDING_FILE).exists()
}

/// Whether an owned namespace's credentials have migrated into the keychain
/// (fact F35) — the matrix's last row.
///
/// One keychain read, and only on the path that needs it: restoring a
/// plaintext store beside an item that shadows it would put the credential
/// where nobody reads it (invariant I5').
fn migrated(paths: &Paths, record: Option<&AccountRecord>, ctx: &PassCtx) -> bool {
    let Some(record) = record else { return false };
    let Some(sha8) = OwnedSha8::from_record(paths, record) else { return false };
    let service = WriteTarget::migrated(sha8).service().to_owned();
    matches!(
        location::from_keychain(default_reader(ctx).as_ref(), &service),
        Resolved::Credentials(_)
    )
}

/// Turns one read of the adoption target into the classification the matrix
/// consumes, and the digests the compare-and-swap compares.
///
/// Both come out of the **same** read on purpose. Reading twice — once to
/// classify and once to remember — would leave the two describing different
/// moments, which is the very confusion the compare-and-swap exists to catch.
fn inspect(read: Resolved, displaced: &Credentials) -> (adopt::Existing, Option<Digests>) {
    match read {
        Resolved::Absent => (adopt::Existing::Absent, None),
        Resolved::Credentials(found) => {
            let digests = found.digests();
            let existing =
                adopt::existing_from(Some((&digests, found.expires_at_ms)), &displaced.digests());
            (existing, Some(digests))
        }
        _ => (adopt::Existing::Unreadable, None),
    }
}

/// [`inspect`]'s classification alone, for the callers with nothing to
/// compare against later.
fn classify(read: Resolved, displaced: &Credentials) -> adopt::Existing {
    inspect(read, displaced).0
}

/// The namespace keys a swap must hold, in ascending order (ruling OQ11).
///
/// A fixed order is what stops two concurrent swaps from taking each other's
/// locks in opposite orders and deadlocking, and sorting a set of any size
/// preserves that argument exactly — which is why the third namespace an
/// adoption may write can join the set rather than needing a second rule.
/// Equal keys collapse to one, so a swap of a store into itself takes one
/// lock and not two.
fn lock_order(records: &[&AccountRecord]) -> Vec<(String, String)> {
    let mut keys: Vec<(String, String)> = records
        .iter()
        .map(|record| (record.account_uuid.clone(), record.organization_uuid.clone()))
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

/// Refusal D's sentence, in one place so both checks say the same thing.
fn line_too_long_note() -> String {
    format!(
        "the credential does not fit the {}-byte keychain line the transport allows (fact F42), \
         so it cannot be written at all",
        keychain_write::SECURITY_STDIN_LIMIT
    )
}

/// Appends one audit entry, reporting a failure rather than failing the swap.
fn audit_append(paths: &Paths, event: AuditEvent) -> Option<String> {
    match audit::append(paths, &AuditEntry::new(event)) {
        Ok(id) => Some(id.to_string()),
        Err(err) => {
            tracing::error!(error = %err, "an audit entry could not be appended");
            None
        }
    }
}

/// Appends the audit entry for one write of a namespaced item.
fn audit_write(paths: &Paths, c: &PhaseC<'_>, outcome: audit::WriteOutcome) -> Option<String> {
    audit_append(
        paths,
        AuditEvent::Write {
            target: Target::Namespace(c.sha8.to_owned()),
            from_digest8: c.from_digest8.clone(),
            to_digest8: c.to_digest8.clone(),
            outcome,
        },
    )
}

/// A `Duration` in whole milliseconds, saturating rather than wrapping —
/// overflow checks are compiled out in every profile (constraint C-006).
fn millis(of: Duration) -> u64 {
    u64::try_from(of.as_millis()).unwrap_or(u64::MAX)
}

/// Milliseconds since the epoch.
fn now_ms() -> i64 {
    jiff::Timestamp::now().as_millisecond()
}

/// Prints the report, as a sentence or as JSON.
///
/// Neither form carries token material: the digests are eight-character
/// prefixes, and nothing here reproduces a blob (plan AC74).
fn emit(report: &Report, as_json: bool) -> Result<(), AppError> {
    if as_json {
        let mut doc = serde_json::json!({
            "outcome": report.outcome.word(),
            "target": report.target,
            "service": report.service,
            "from": { "digest8": report.from_digest8 },
            "to": { "digest8": report.to_digest8 },
            "audit": { "id": report.audit_id },
            "adopted_to": report.adopted_to,
            // The contract's "lock timings, any break". No pid, no path, no
            // sample — the break summary is the three-value holder
            // vocabulary and whether the artefact was removed (plan AC80).
            "lock": {
                "hold_ms": report.lock.hold_ms,
                "budget_ms": report.lock.budget_ms,
                "break": report.lock.broke,
            },
            "warnings": report.warnings,
            "note": report.note,
            // Present on every document, so a consumer can test the member
            // rather than test for it. A non-refusal failure — an outcome of
            // its own, such as `failed` — carries `null` here: a refusal
            // letter is a security signal and must not be produced by an
            // ordinary write failure.
            "refusal": serde_json::Value::Null,
        });
        match &report.outcome {
            // The OQ1 precondition is not lettered: it carries a reason
            // instead, because it is decided before Phase A begins.
            Outcome::Refused(Refusal::NotOwned) => doc["reason"] = serde_json::json!("not_owned"),
            Outcome::Refused(refusal) => doc["refusal"] = serde_json::json!(refusal.letter()),
            _ => {}
        }
        let text = serde_json::to_string_pretty(&doc)
            .map_err(|err| AppError::Config(format!("could not render the swap as JSON: {err}")))?;
        println!("{text}");
        return Ok(());
    }

    let mut out = Tty;
    if matches!(report.outcome, Outcome::Applied) {
        out.tell(&format!(
            "swapped: `{}` now holds the incoming credential (digest {}). It takes effect on your \
             next message, within 30 s; run `/model` once to refresh model access.",
            report.service,
            report.to_digest8.as_deref().unwrap_or("unknown"),
        ));
        // Finding N-7. The two notes an applied swap can carry are both
        // failures of a credential-at-rest cleanup — the shadowing
        // `.credentials.json` could not be removed, or the displaced
        // credential could not be parked — and each leaves something the
        // operator has to act on by hand. Printing the success line and
        // dropping the note, as this used to, meant the one outcome those
        // sentences exist for was the one outcome that discarded them: exit
        // 0, "swapped", and a live credential still readable under the name
        // fact F35's composed read falls through to. On **stderr**, so
        // stdout stays a stream of JSON documents, the same place refusal
        // **B**'s warning already goes.
        if let Some(note) = &report.note {
            eprintln!("warning: {note}");
        }
    } else if let Some(note) = &report.note {
        out.tell(&format!("{}: {note}", report.outcome.word()));
    } else {
        out.tell(report.outcome.word());
    }
    if let Some(adopted) = &report.adopted_to {
        out.tell(&format!("the displaced credential was adopted into `{adopted}`"));
    }
    if let Some(id) = &report.audit_id {
        out.tell(&format!("audit: {id}"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `--undo`
// ---------------------------------------------------------------------------

/// Which swap `--undo` would reverse, or why it will not guess.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Undoable {
    /// The `sha8` of the namespaced item to put back, and the digest prefixes
    /// the entry recorded.
    Found {
        /// The item's suffix.
        sha8: String,
        /// The digest prefix of the credential that was displaced, or `None`
        /// for a **first** write — one whose store had not migrated, so no
        /// item existed to displace.
        ///
        /// A first write used to be skipped here, on the reading that it
        /// "displaced nothing". That was true of the *item* and false of the
        /// store: the credential came out of `.credentials.json`, the
        /// adoption parked it in the adopted copy, and since finding N-2 the
        /// swap removes the plaintext file — so the copy is that credential's
        /// only home and a reversal is exactly what puts it back.
        from_digest8: Option<String>,
        /// The digest prefix of the credential the swap wrote, which is what
        /// a first write is matched against instead.
        to_digest8: String,
    },
    /// The newest reversible write targets the **live** item, which is S23's
    /// (W4b). Reported rather than skipped: `--undo` reverses the most recent
    /// swap, so silently reaching past a live-store swap to an older
    /// namespaced one would reverse a swap the user did not mean.
    Live,
    /// There is no write to undo.
    Nothing,
    /// A line between the tail's end and the entry could not be read, so the
    /// entry `--undo` needs may be the one that is unreadable.
    Unreadable(usize),
}

/// Picks the swap to reverse out of the audit log's tail.
///
/// Walks **backwards** for the newest `Write` naming a namespaced item whose
/// outcome was `Applied` or `Unknown`. `Discarded` and `Failed` wrote nothing,
/// so there is nothing of theirs to undo.
///
/// # Why an unreadable line refuses rather than being skipped
///
/// A crash part-way through an append truncates the **last** line — which is
/// exactly the entry `--undo` wants. Skipping it would silently reverse the
/// swap *before* the one the user meant, putting a credential back into an
/// item that a later swap has since changed. So any unreadable line at or
/// after the newest candidate refuses, and names the line number.
pub(crate) fn select_undo(tail: &audit::Tail) -> Undoable {
    let newest = tail.entries.iter().enumerate().rev().find_map(|(index, entry)| {
        let AuditEvent::Write { target, from_digest8, to_digest8, outcome } = &entry.event else {
            return None;
        };
        if !matches!(outcome, audit::WriteOutcome::Applied | audit::WriteOutcome::Unknown) {
            // `Discarded` and `Failed` wrote nothing, so there is nothing of
            // theirs to put back.
            return None;
        }
        // A first write — `from_digest8` null — is **not** skipped. It
        // displaced no *item*, but it displaced the credential that was in
        // the store's plaintext file, and since finding N-2 that file is
        // removed once the write applies, so the adopted copy is where that
        // credential now lives and a reversal is what returns it.
        //
        // The target is examined **after** the entry has been chosen, not as
        // part of choosing it: `--undo` reverses the most recent reversible
        // swap, whatever it targeted, and a live one is refused rather than
        // stepped over.
        Some(match target {
            Target::Namespace(sha8) => (
                index,
                Undoable::Found {
                    sha8: sha8.clone(),
                    from_digest8: from_digest8.clone(),
                    to_digest8: to_digest8.clone(),
                },
            ),
            Target::Live => (index, Undoable::Live),
        })
    });

    let Some((index, found)) = newest else {
        // Even with no candidate, an unreadable line means the log is not a
        // complete account of what happened.
        return match tail.unreadable.first() {
            Some((line, _)) => Undoable::Unreadable(*line),
            None => Undoable::Nothing,
        };
    };

    // `unreadable` is keyed by line number within the window and `entries` by
    // position among the lines that parsed, so the conservative comparison is
    // "is there any unreadable line at all at or after this entry's
    // position". Refusing on an earlier one too would be safe but useless;
    // refusing on a later one is the case that matters.
    if let Some((line, _)) = tail.unreadable.iter().find(|(line, _)| *line >= index) {
        return Undoable::Unreadable(*line);
    }
    found
}

/// `claude use --undo` — plan section 3.4's rollback.
///
/// Selects the swap to reverse ([`select_undo`]), then **re-runs Phase A–C
/// with P and T exchanged** against the same owned store. The adopted copy
/// supplies the credential to put back; the credential currently in the item
/// becomes the new displaced one and is parked in that same copy in turn, so
/// the operation is its own inverse.
///
/// Refusal **E** does not arise: the store is one agentctl owns and sits
/// inside `namespace_root()`, and nothing on this path touches the live
/// store. A reversal of a **live** swap is S23's, and is the one case that
/// still reports `not_implemented`.
///
/// # Errors
///
/// Returns [`AppError::Config`] when the audit log's tail is not a complete
/// account of what happened, when the entry names a store no record claims,
/// or when the adopted copy does not hold the credential the entry says was
/// displaced; and [`AppError::not_implemented`] for a live-target entry.
fn run_undo(config_dir: Option<&Path>, args: &UseArgs, cancel: &Cancel) -> Result<i32, AppError> {
    let paths = Paths::resolve(config_dir)?;
    paths.ensure_dirs()?;
    let tail = audit::tail(&paths, UNDO_TAIL)?;
    let (sha8, from_digest8, to_digest8) = match select_undo(&tail) {
        Undoable::Unreadable(line) => {
            return Err(AppError::Config(format!(
                "the audit log's line {line} could not be read, and it may be the entry \
                 `--undo` needs; agentctl will not guess which swap to reverse"
            )));
        }
        Undoable::Nothing => {
            Tty.tell("there is no swap to undo: the audit log records no reversible write");
            return Ok(EXIT_OK);
        }
        Undoable::Live => {
            return Err(AppError::not_implemented(
                "claude use --undo of a swap against the live Claude Code store",
            ));
        }
        Undoable::Found { sha8, from_digest8, to_digest8 } => (sha8, from_digest8, to_digest8),
    };

    let config = AgentctlConfig::load(&paths)?;
    // The entry names the item by its suffix; the store is whichever owned
    // record still derives that suffix. "Still" is the operative word — a
    // record that has been removed or relocated since the swap leaves an
    // entry nothing can act on, and guessing would write a credential into a
    // namespace the user no longer believes in.
    let Some(store) = config
        .accounts
        .iter()
        .find(|record| {
            OwnedSha8::from_record(&paths, record).is_some_and(|owned| owned.sha8() == sha8)
        })
        .cloned()
    else {
        return Err(AppError::Config(format!(
            "the swap to undo named the keychain item `{sha8}`, which no account agentctl \
             currently owns still derives; there is nothing to put it back into"
        )));
    };
    let store_dir = paths.namespace_dir(&store.account_uuid, &store.organization_uuid);

    // The adopted copy is where decision D-024 parked the displaced
    // credential. Its digest has to be the one the entry recorded: anything
    // else means the copy is not from the swap being undone, and putting it
    // back would restore a credential the user did not ask for.
    let displaced = match location::from_adopted(&store_dir) {
        Resolved::Credentials(credentials) => *credentials,
        _ => {
            return Err(AppError::Config(format!(
                "the credential that swap displaced is no longer in `{}`, so there is nothing \
                 to put back",
                store_dir.join(file_store::ADOPTED_FILE).display()
            )));
        }
    };
    let found8 = audit::digest8(&displaced.digests().access_sha256);
    match &from_digest8 {
        Some(from_digest8) => {
            if found8.as_deref() != Some(from_digest8.as_str()) {
                return Err(AppError::Config(format!(
                    "the adopted copy in `{}` holds `{}`, but the swap being undone displaced \
                     `{}`; agentctl will not put back a credential it cannot match to that swap",
                    store_dir.display(),
                    found8.as_deref().unwrap_or("an unreadable digest"),
                    from_digest8
                )));
            }
        }
        // A first write recorded no `from_digest8`, so there is no prefix to
        // match the copy against. What can still be checked is the other
        // direction, and it is the one that matters: the copy must **not**
        // hold what that swap wrote. A copy holding `to_digest8` is the copy
        // some *later* operation left — a reversal of this very swap, most
        // likely — and putting it back would reinstate the credential the
        // user swapped in while claiming to undo the swap that brought it.
        None => {
            if found8.as_deref() == Some(to_digest8.as_str()) {
                return Err(AppError::Config(format!(
                    "the adopted copy in `{}` holds `{}`, which is the credential that swap \
                     wrote rather than the one it displaced; agentctl will not put back a \
                     credential it cannot match to that swap",
                    store_dir.display(),
                    to_digest8
                )));
            }
        }
    }

    // Whose credential it is, so the reversal takes the right namespace lock
    // and names the right account at the prompt. An unidentifiable blob
    // belongs to the store it was displaced from, which is the same
    // conclusion `swap::same_identity` reaches.
    let owner = displaced
        .identity()
        .and_then(|id| config.accounts.iter().find(|r| r.account_uuid == id.account_uuid).cloned())
        .unwrap_or_else(|| store.clone());

    let env = EnvView::from_process();
    let ctx = PassCtx::standalone(cancel.clone(), Instant::now() + SWAP_DEADLINE);
    let fault = fault_from_env();
    // A reversal has no session to inherit a spelling from, so it uses the one
    // the record itself carries — which is byte-for-byte the string the
    // forward swap matched against, because that is how the record was chosen
    // in the first place. The guard it feeds is the same one: the namespace
    // agentctl derives now must be the namespace the item was made for.
    let inherited = recorded_spelling(&store).to_owned();
    let swap = Swap {
        paths: &paths,
        config: &config,
        env: &env,
        inherited: &inherited,
        ctx: &ctx,
        fault: &fault,
    };
    let incoming = Incoming {
        record: &owner,
        direction: Direction::Reverse,
        source: Source::AdoptedCopy(store_dir),
    };
    let report = swap_in(&swap, &incoming, &store, args);
    emit(&report, args.json)?;
    Ok(report.outcome.exit_code())
}

/// How many audit entries `--undo` looks back through.
///
/// Deep enough that a busy machine's lock-break lines cannot push the newest
/// write out of the window, and shallow enough that the read stays cheap.
const UNDO_TAIL: usize = 256;

// ---------------------------------------------------------------------------
// The other arms
// ---------------------------------------------------------------------------

/// `use --forget <id> [--yes]` (plan AC79).
///
/// Resolves the account the same way every other `claude` subcommand does,
/// then hands off to [`isolate::forget_session`], which does the removal and
/// its own confirmation.
///
/// # Errors
///
/// Returns [`AppError`] when the account cannot be resolved, or whatever
/// [`isolate::forget_session`] returns.
fn run_forget(config_dir: Option<&Path>, id: &str, yes: bool) -> Result<i32, AppError> {
    let paths = Paths::resolve(config_dir)?;
    paths.ensure_dirs()?;
    let config = AgentctlConfig::load(&paths)?;
    let record = config.resolve_id(id)?.clone();
    let prompt = &mut Tty;
    isolate::forget_session(&paths, &record, prompt, yes)?;
    Ok(EXIT_OK)
}

/// `--json`: the session's details, printed before `claude` launches.
fn print_session_json(
    session: &isolate::SessionDir,
    spec: &export::ExportSpec,
) -> Result<(), AppError> {
    let doc = serde_json::json!({
        "securestorage_dir": spec.securestorage_dir,
        "config_dir": spec.config_dir,
        "session_path": session.path,
        "mcp_config": session.mcp_config,
    });
    let text = serde_json::to_string_pretty(&doc)
        .map_err(|err| AppError::Config(format!("could not render the session as JSON: {err}")))?;
    println!("{text}");
    Ok(())
}

#[cfg(test)]
#[path = "use_tests.rs"]
mod tests;
