//! `agctl claude use` — an isolated session, or a hot-swap of a live one.
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
//!   happen in front of the consent gate — under agctl's **own**
//!   namespace locks —
//!   never Claude Code's. That is invariant I17's whole content: the things
//!   that block are done before the things Claude Code is waiting for are
//!   taken.
//! - **Phase C** writes. Claude Code's three locks in its own nesting, a
//!   drift check, a re-read, one write, release. Bounded by
//!   [`claude_lock::HOLD_BUDGET`], and a write that cannot finish inside what
//!   is left of the budget is not started at all.
//!
//! # `--live` against the live `~/.claude` (W4b)
//!
//! Phase A's scope gate **partitions** the two stores on one variable: a
//! non-empty `CLAUDE_SECURESTORAGE_CONFIG_DIR` selects a namespace agctl
//! owns (W4a's path), an unset or empty one selects the live store. Both arms
//! read the **same** [`EnvView`], which is why refusal **E** — the pass was
//! asked for the live item but the shell names a namespace — cannot arise on
//! the forward path at all, and arises only in `use --undo`, whose target
//! comes from the audit log rather than from the environment.
//!
//! The live target is the same procedure with four extra refusals and one
//! narrower containment rule. **Nothing under the live store is ever written
//! or removed**: invariant I11′'s W4b relaxation is exactly *the three lock
//! artefacts plus the keychain item*, so
//!
//! - an absent live item ([`Refusal::LiveItemAbsent`]) refuses rather than
//!   taking W4a's first-write path, which would remove
//!   `~/.claude/.credentials.json`;
//! - the displaced credential goes to **its own account's namespace** under
//!   `namespace_root()`, never to a `.credentials.adopted.json` beside the
//!   live store;
//! - a refused audit log ([`Refusal::AuditRefused`]) refuses the swap, because
//!   the log is the only durable evidence a live-store lock break leaves.
//!
//! ## The one thing this file must never do
//!
//! It never writes the displaced credential to a `.credentials.json` it did
//! not compare against first: decision D-024 puts a same-namespace copy in
//! the adopted sibling, because fact F35's composed read falls through to
//! `.credentials.json` on any keychain hiccup and would serve the credential
//! the user just swapped *away* from.

use std::ffi::OsString;
use std::fs::File;
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
use crate::config::AgctlConfig;
use crate::config::paths::Paths;
use crate::config::paths::UNKNOWN_ORG;
use crate::error::AppError;
use crate::error::EXIT_OK;
use crate::provider::claude::adopt;
use crate::provider::claude::credentials::Credentials;
use crate::provider::claude::credentials::Digests;
use crate::provider::claude::credentials::Identity;
use crate::provider::claude::credentials::KeychainStdinLine;
use crate::provider::claude::credentials::REFRESH_MARGIN_MS;
use crate::provider::claude::discovery;
use crate::provider::claude::namespace;
use crate::provider::claude::namespace::EnvView;
use crate::provider::claude::swap;
use crate::provider::claude::swap::ItemChange;
use crate::provider::claude::swap::Outcome;
use crate::provider::claude::swap::Refusal;
use crate::provider::claude::usage::RefreshError;
use crate::runtime::coordinator::Cancel;
use crate::runtime::coordinator::PassCtx;
use crate::runtime::fault::Fault;
use crate::secret::KeychainReader;
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
use crate::secret::foreign_activity::ForeignActivity;
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

/// `agctl claude use [<id>] [--live] [--claude-config-dir <PATH>]
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
/// Returns [`AppError::Config`] when no id was given and none of
/// `--undo`/`--forget` was either, or when the account cannot be resolved; and
/// whatever [`export::prepare`], [`export::exec_command`], [`run_undo`] or
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
/// about what agctl could and could not see, and it says whose environment
/// was inspected (plan AC67, critic M4).
const BACKEND_NOTE: &str = "agctl inspected its own environment for a secure-storage backend \
                            and found none; it cannot inspect the target session's";

/// `claude use --live <id>`: plan section 3.4 against a store agctl owns.
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
    let config = AgctlConfig::load(&paths)?;
    let incoming = config.resolve_id(id)?.clone();

    // Phase A step 1: only an account agctl owns can be swapped in — the
    // same fact `export::spec_for` states, in the same words.
    if !matches!(incoming.kind, AccountKind::Owned { .. }) {
        return Err(AppError::Config(format!(
            "only an account agctl owns can be swapped into a live store; `{}` is `{}`, whose \
             credentials live outside agctl's own store",
            incoming.account_uuid,
            incoming.kind.name()
        )));
    }

    // Step 2: ONE environment view. Every later derivation takes this one, so
    // the store directory and the service name cannot come from two different
    // readings of a variable that changed in between (risk R42).
    let env = EnvView::from_process();

    // Step 3: the scope gate, and it **partitions** rather than filters. One
    // reading of one variable decides which of the two stores this pass is
    // about, so the store directory, the service name, the lock tree and the
    // audit target cannot come from two different answers to that question
    // (risk R42). A truthy value names a namespace; an unset or empty one is
    // falsy to Claude Code (fact F14) and names the live store.
    //
    // Because both arms read this same `EnvView`, refusal **E** — "the live
    // item is not what this environment names" — is unreachable from here by
    // construction: the live arm is the arm in which the variable is falsy.
    // `use --undo` is where the two can disagree, because its target comes
    // from the audit log.
    let (which, inherited, store) = match namespace::securestorage_namespace(&env) {
        Some(value) => {
            let inherited = value.to_owned();
            // Step 4: the precondition (ruling OQ1). The inherited spelling is
            // matched **byte for byte** against an owned record's
            // `export_spelling` — not canonicalized, not resolved — because
            // that string is what Claude Code hashes into a service name
            // (fact F14), and two spellings of one directory name two
            // different items.
            let Some(store) = owned_by_spelling(&config, &inherited).cloned() else {
                // Through `emit` like every other refusal, so `--json` gets
                // the document the contract specifies (`outcome: "refused"`
                // with `reason: "not_owned"`) rather than a sentence it cannot
                // parse.
                let report = Report::refused(
                    Refusal::NotOwned,
                    "",
                    format!(
                        "`{inherited}` is not a store agctl owns, so there is no record saying \
                         whose credentials are in it or where the displaced one should go"
                    ),
                );
                emit(&report, args.json)?;
                return Ok(report.outcome.exit_code());
            };
            (Which::Namespace, inherited, Some(store))
        }
        // The live store is not a registry row, so there is no record to
        // resolve and no spelling to match: `WriteTarget::live` derives both
        // halves of the target from the view above, and whose the displaced
        // credential is, is a question about the credential rather than about
        // a record (see `decide_adoption`).
        None => (Which::Live, String::new(), None),
    };

    let ctx = PassCtx::standalone(cancel.clone(), Instant::now() + SWAP_DEADLINE);
    let fault = fault_from_env();
    let swap = Swap {
        paths: &paths,
        config: &config,
        env: &env,
        which,
        inherited: &inherited,
        ctx: &ctx,
        fault: &fault,
    };
    let incoming = Incoming {
        record: &incoming,
        direction: Direction::Forward,
        source: Source::OwnStore,
        undone: None,
    };
    let report = swap_in(&swap, &incoming, store.as_ref(), args);
    emit(&report, args.json)?;
    // Decision D-027's mitigation for what no guard can see yet: a Claude Code
    // `/login` as the displaced account while this swap is outstanding looks
    // exactly like the swapped-in account's own refresh until S24. On stderr,
    // beside refusal B's note, so `--json`'s stdout stays a stream of
    // documents.
    if which == Which::Live && matches!(report.outcome, Outcome::Applied) {
        eprintln!("note: {OUTSTANDING_REMINDER}");
    }
    Ok(report.outcome.exit_code())
}

/// What a live swap tells its operator on the way out, and what the
/// outstanding-live-swap refusal repeats (decision D-027).
const OUTSTANDING_REMINDER: &str = "while a live swap is outstanding, return with `agctl claude \
                                    use --undo`, never `/login` in Claude Code";

/// Which of the two credential stores a pass is about.
///
/// The scope gate's partition as a value, carried rather than re-derived: the
/// write target, the lock tree, the audit target, the adoption's destination
/// and four of the nine refusals all turn on it, and asking the environment
/// again at each of them is how two halves of one swap come to disagree about
/// what "live" means (risk R42).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Which {
    /// A namespace agctl owns, named by the inherited
    /// `CLAUDE_SECURESTORAGE_CONFIG_DIR` and backed by an `Owned` record.
    Namespace,
    /// The live Claude Code store — `~/.claude`, or `CLAUDE_CONFIG_DIR` — and
    /// the unsuffixed `Claude Code-credentials` item.
    Live,
}

/// The item a swap writes, the tree whose locks guard it, and how the audit
/// log names it — all derived from **one** [`EnvView`].
///
/// Plan AC82 in one value. [`WriteTarget`] is the only derivation of the pair
/// *(store directory, service name)*, and the lock subject is built from that
/// same value rather than from a second reading, so the hold cannot be taken
/// in one directory while the write names the item of another.
///
/// `Debug` is safe and is what lets a test say which subject it got: a service
/// name, a directory and a tree token are not secrets.
#[derive(Debug)]
struct Subject {
    /// The directory and the service, derived together.
    target: WriteTarget,
    /// Which tree the store directory is in, for `LockSubject` and for the
    /// held-lock record `doctor --remove-stale` reads.
    tree: Tree,
    /// How the audit log and `--json`'s `target` member name the item.
    audit: Target,
}

impl Subject {
    /// The directory whose lock artefacts guard the item.
    ///
    /// The **unresolved** spelling for the live tree, deliberately: invariant
    /// I13 keeps identity out of path resolution, so `WriteTarget::live`
    /// derives the directory from the environment's characters and the service
    /// from the same characters. `LockAnchor::open` resolves it itself and
    /// accepts this spelling by identity, which is what makes the two name one
    /// directory without either having to be the other's string.
    fn store_dir(&self) -> &Path {
        self.target.store_dir()
    }

    /// The keychain service name.
    fn service(&self) -> &str {
        self.target.service()
    }
}

/// Derives the subject, or the Phase A refusal that says why it cannot be.
///
/// The **single** statement that constructs [`WriteTarget::live`], which is
/// where refusal **E** is decided (W4b §D1). Deciding it anywhere else — in
/// particular at `LockAnchor::open`, which refuses the same environment — would
/// decide it with the locks being taken, breaking the property
/// [`swap::DECISION_ORDER`] asserts.
///
/// `WriteTarget::live`'s own `AppError::Refused` and `LockAnchor::open`'s
/// `Tree::Live` arm are **backstops**, documented as such: they exist so no
/// other caller can reach the case by accident, and neither is the
/// user-facing gate.
fn build_subject(
    paths: &Paths,
    env: &EnvView,
    which: Which,
    store: Option<&AccountRecord>,
    inherited: &str,
) -> Result<Subject, Box<Report>> {
    match which {
        Which::Namespace => {
            // `from_record` refuses a store outside the namespace root, which
            // is half of AC81's containment and is structural rather than a
            // check written here.
            let Some(record) = store else {
                return Err(Box::new(Report::refused(
                    Refusal::NotOwned,
                    "",
                    "a namespaced swap needs the record that owns the store".to_owned(),
                )));
            };
            let Some(sha8) = OwnedSha8::from_record(paths, record) else {
                return Err(Box::new(Report::refused(
                    Refusal::NotOwned,
                    "",
                    "the store's recorded export spelling does not name a namespace agctl owns"
                        .to_owned(),
                )));
            };
            let audit = Target::Namespace(sha8.sha8().to_owned());
            let target = WriteTarget::migrated(sha8);

            // The precondition's other half, and the one the OQ1 match alone
            // does not give: the item and the directory must name the *same*
            // store.
            //
            // The service comes from the record's **stored** `export_sha8`,
            // which is what Claude Code hashed when the session started; the
            // store directory comes from the registry as it stands **now**.
            // When the namespace has moved, those disagree — the item is still
            // the one the session reads, but `store_dir` names somewhere else,
            // so the three Claude Code locks, the adopted copy and the
            // containment walk would all be about a directory whose
            // `.oauth_refresh.lock` the peer never takes. Invariant I3' would
            // be defeated for exactly the one command that writes under the
            // peer's locks. `doctor` already reports this state (risk R25) and
            // `export` already refuses it; so does this.
            let spelled = namespace::export_spelling(target.store_dir());
            if spelled != inherited {
                return Err(Box::new(Report::refused(
                    Refusal::NotOwned,
                    target.service(),
                    format!(
                        "this store is named `{inherited}`, but `{}`'s namespace now spells \
                         `{spelled}`; the store moved, so agctl would take the Claude Code \
                         locks in a different directory than the session reads — see `agctl \
                         claude doctor`",
                        record.account_uuid
                    ),
                )));
            }
            Ok(Subject { target, tree: Tree::Agctl, audit })
        }
        Which::Live => {
            // Refusal **E**, decided here and nowhere else. The value is
            // escaped before it is printed: it comes from the environment, and
            // a refusal that reproduces control characters verbatim lets
            // whoever set the variable rewrite the line that reports it.
            let target = WriteTarget::live(env).map_err(|_| {
                let value = namespace::securestorage_namespace(env).unwrap_or_default();
                Box::new(Report::refused(
                    Refusal::LiveNamespaceEnv,
                    "",
                    format!(
                        "`{}` is set to `{}` in this shell, so this environment names a \
                         namespace rather than the live store; run without it, or target that \
                         namespace instead",
                        namespace::SECURESTORAGE_ENV,
                        printable(value)
                    ),
                ))
            })?;

            // The Phase A resolution, and it is a **diagnosis rather than a
            // guard**. `LockAnchor::open` resolves the live store again in
            // Phase C and that resolution stays authoritative, so this one
            // widens no window and may never be relied on for safety. Its only
            // job is to produce the right refusal, with the right exit code,
            // before anything is held — rather than letting a dangling
            // `~/.claude` arrive at the acquire and be reported as refusal
            // **A**, which means *somebody moved a lock agctl was holding*.
            if let Err(err) = namespace::canonical(target.store_dir()) {
                return Err(Box::new(Report::refused(
                    Refusal::LiveUnreachable,
                    target.service(),
                    format!(
                        "the live store `{}` could not be resolved: {err}",
                        target.store_dir().display()
                    ),
                )));
            }
            Ok(Subject { target, tree: Tree::Live, audit: Target::Live })
        }
    }
}

/// A value out of the environment, rendered safe to print.
///
/// Control characters become their escaped spelling, so a crafted
/// `CLAUDE_SECURESTORAGE_CONFIG_DIR` cannot rewrite the terminal line that
/// reports it, move the cursor, or hide the rest of the refusal (r4v F8). The
/// landed messages elsewhere interpolate such values verbatim; S23's own do
/// not, and this is the one spelling of the escape.
fn printable(value: &str) -> String {
    value.chars().flat_map(char::escape_debug).collect()
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
fn owned_by_spelling<'a>(config: &'a AgctlConfig, inherited: &str) -> Option<&'a AccountRecord> {
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
    store: Option<&AccountRecord>,
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
    store: Option<&AccountRecord>,
    args: &UseArgs,
    pass: &mut Pass,
) -> Report {
    let Swap { paths, config, env, which, inherited, ctx, fault } = env;
    let (paths, config, env, which, inherited, ctx, fault) =
        (*paths, *config, *env, *which, *inherited, *ctx, *fault);
    let direction = incoming.direction;
    // Step 5: derive the store directory and the service name **together**
    // from the one `EnvView` above — and, for a namespace, through the
    // registry. Refusals **E** and `LiveUnreachable` are decided in here; see
    // `build_subject`.
    let subject = match build_subject(paths, env, which, store, inherited) {
        Ok(subject) => subject,
        Err(report) => return *report,
    };
    let store_dir = subject.store_dir().to_path_buf();
    let service = subject.service().to_owned();
    pass.target = Some(subject.audit.to_string());

    // Step 6, refusal C: agctl's **own** environment only (decision
    // D-020). agctl cannot read another process's environment and will not
    // guess at one, so the message says whose was inspected.
    if env.oauth_token_set {
        return Report::refused(
            Refusal::EnvToken,
            &service,
            "`CLAUDE_CODE_OAUTH_TOKEN` is set in agctl's own environment, which short-circuits \
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
        // An absent **live** item means the live store has not migrated, so
        // its credential is in `~/.claude/.credentials.json` and W4a's
        // first-write path would *remove* that file once the write applied
        // (finding N-2) — a deletion inside the user's own live store, which
        // invariant I11′ does not price. Refused instead (ruling G4), so no
        // file under the live store is ever written or removed and the
        // relaxation stays exactly "three lock artefacts plus the item". The
        // condition is transient and self-healing: one `claude` session
        // migrates the store.
        Resolved::Absent if which == Which::Live => {
            return Report::refused(
                Refusal::LiveItemAbsent,
                &service,
                format!(
                    "the live store `{}` has not migrated into the keychain, so there is no \
                     `{service}` item to swap and its credential is still in the plaintext \
                     store; run `claude` once to migrate it, then run this again",
                    store_dir.display()
                ),
            );
        }
        // A namespace that has not migrated yet: the plaintext file is the
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

    // The two decision D-027 checks that need the item and nothing more,
    // decided here: after step 7's single read and `LiveItemAbsent`, before the
    // incoming read, the locks, the log, the prompt and the POST.
    //
    // Forward, the outstanding-live-swap guard (`live_swap_outstanding`,
    // temporary until S24). In reverse, the item must still be what the swap
    // being undone left there (`item_changed`); its `.claude.json` read is a
    // tripwire, and never where an identity comes from.
    if which == Which::Live
        && direction == Direction::Forward
        && let Some((refusal, note)) = live_swap_outstanding(paths, from_digest8.as_deref())
    {
        return Report::refused(refusal, &service, note);
    }
    if which == Which::Live
        && let Some(undone) = incoming.undone
    {
        let claimed = discovery::live_identity(env);
        if let Some(refusal) =
            item_changed(undone, incoming.record, from_digest8.as_deref(), claimed.as_ref())
        {
            // The `unknown` write the item is checked against: a later undo's
            // when there is one, else the swap's own.
            let (checked_from, checked_to) = match &undone.later_unknown_undo {
                Some(later) => {
                    (later.from_digest8.as_deref().unwrap_or("none"), later.to_digest8.as_str())
                }
                None => (undone.from_digest8.as_str(), undone.to_digest8.as_str()),
            };
            let note = match refusal {
                Refusal::LiveUndoItemChanged(ItemChange::ForeignLogin) => format!(
                    "the live session has logged in as `{}` since that swap, which is neither the \
                     account being put back nor the one the swap installed; run `agctl claude \
                     use --live` to adopt it, or resolve it by hand",
                    claimed.as_ref().map_or_else(String::new, display_of)
                ),
                Refusal::LiveUndoOfUndo => format!(
                    "the live swap `--undo` would reverse was already put back: a later undo \
                     ended `unknown`, and the live item holds what that undo wrote \
                     (`{checked_to}`); run `agctl claude use --live <id>` for the account you want \
                     instead"
                ),
                // The diverged item: the only other refusal `item_changed`
                // returns.
                _ => format!(
                    "a live write ended `unknown`, and the live item now holds neither the \
                     credential it displaced (`{checked_from}`) nor the one it wrote \
                     (`{checked_to}`); agctl will not guess what is there"
                ),
            };
            return Report::refused(refusal, &service, note);
        }
    }

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

    // Whose the displaced credential is (decision D-027). Decided here, after
    // Phase A's reads and before the first lock, because both of its refusals
    // are about what those reads found and neither needs anything held.
    //
    // A credential **Claude Code** wrote into the live item carries no
    // `tokenAccount`, so on a real machine the blob alone never names P and no
    // live swap could pass. For the live target the identity is the
    // credential's own when it names one, and otherwise comes from the one
    // other source each direction may trust (`attribute`):
    //
    // - forward, `.claude.json`'s `oauthAccount`, through discovery's own
    //   reader — the source the live row already uses (fact F33);
    // - in reverse, the account the swap being undone installed, as its audit
    //   entry records it (`incoming_identity`) — and **never** `oauthAccount`,
    //   which agctl does not write until S24 and which after a live swap still
    //   names the account that swap displaced.
    //
    // It is carried beside the credential rather than written into it, so
    // nothing agctl files on disk claims a `tokenAccount` the server did not
    // issue (invariant I13). The namespace target keeps the credential's own
    // identity, exactly as W4a does.
    let identity = match (displaced.as_ref(), which) {
        (None, _) => None,
        (Some(p), Which::Namespace) => p.identity(),
        (Some(p), Which::Live) => {
            let witness = match direction {
                Direction::Forward => Witness::LoginRecord(discovery::live_identity(env)),
                Direction::Reverse => {
                    Witness::UndoneSwap(incoming.undone.map(|undone| &undone.installed))
                }
            };
            match attribute(p.identity(), witness) {
                Attribution::Known(Some(identity)) => Some(identity),
                // An unidentified credential in the **live** item is refused
                // rather than attributed. Everywhere there is a record to
                // attribute it to, fact F4's identity-less blob passes the
                // guard: it is an older blob, not evidence of a different
                // account. Here there is no such record and no witness named
                // one either. Attributing it to the incoming account would let
                // task 4's row discard what may be somebody's only copy;
                // attributing it to nobody would lose it outright. Decision
                // D-017 is categorical, so this refuses — under refusal **F**'s
                // `Unreadable` reason, with a sentence of its own, because
                // `Unreadable`'s speaks of "the copy already stored".
                Attribution::Known(None) => {
                    return Report::refused(
                        Refusal::CannotAdopt(adopt::Refusal::Unreadable),
                        &service,
                        "the outgoing credential cannot be adopted: the credential in the live \
                         item does not say which account it belongs to, and the live store is no \
                         account's own, so there is no namespace agctl could file it in without \
                         guessing"
                            .to_owned(),
                    );
                }
                // The credential names one account and the witness another:
                // one of the two is stale, and nothing here says which.
                Attribution::Mismatch { item, witness } => {
                    let named = match direction {
                        Direction::Forward => format!(
                            "the live `.claude.json` says this session is logged in as \
                             `{witness}`"
                        ),
                        Direction::Reverse => {
                            format!("the swap being undone installed `{witness}`'s credential")
                        }
                    };
                    return Report::refused(
                        Refusal::CannotAdopt(adopt::Refusal::IdentityMismatch),
                        &service,
                        format!(
                            "the outgoing credential cannot be adopted: the credential in the \
                             live item belongs to `{item}`, but {named}; agctl will not guess \
                             which account it is"
                        ),
                    );
                }
            }
        }
    };

    // --- Phase B ---------------------------------------------------------
    // The **third** namespace, resolved here in Phase A's reading rather than
    // where it is used. A forward swap whose displaced credential belongs to
    // somebody else — the ordinary state of the second and every later swap
    // of one store — adopts it into *that* account's `.credentials.json`, and
    // ruling OQ11 ordered only two locks. A write agctl does not hold the
    // namespace lock for is a blind overwrite of a namespace a concurrent
    // `status` may be refreshing, against invariant I3'. Resolving it before
    // the first lock is taken is what keeps the whole set sorted, so three
    // locks cannot be taken in two different orders.
    //
    // A reversal never reaches it: `adopt::decide_undo` parks the occupant in
    // this store's own adopted copy whoever it belongs to, so there is no
    // third namespace to write and none to lock.
    //
    // The **live** target resolves it in both directions, and that is §D5's
    // re-cut rather than an oversight. `decide_undo`'s fixed destination is the
    // store's own `.credentials.adopted.json`, which for a live target is
    // `~/.claude/.credentials.adopted.json` — outside `namespace_root()` and
    // forbidden by I11′. So a live reversal parks what the item holds in *that
    // credential's* own namespace too, exactly as the forward direction does,
    // and the operation stays its own inverse because each credential goes
    // home rather than into a shared sibling.
    //
    // For the live target only an **`Owned`** record's namespace can receive
    // the displaced credential (§D5). Any other kind — an imported
    // `CLAUDE_CONFIG_DIR` item, a read-only live row — keeps its credentials
    // outside agctl's store, so a `.credentials.json` under `namespace_root()`
    // for it would be a namespace nobody created, and `use --undo`, which looks
    // for the displaced credential only in owned namespaces, could never read it
    // back. So `third_namespace` selects among `Owned` records only, by account
    // **and** organisation, and exactly one (review F1): none is the no-record
    // case `decide_adoption` refuses, and two refuse at step 11. The namespace
    // target keeps W4a's account-only selection (`agctl-m08`).
    let third = match displaced.as_ref() {
        Some(_) if which == Which::Live || direction == Direction::Forward => {
            third_namespace(config, store, incoming.record, identity.as_ref(), which)
        }
        _ => Ok(None),
    };

    // Step 10: the namespace locks, in ascending namespace-key order so two
    // concurrent swaps cannot take each other's locks in opposite orders and
    // deadlock (ruling OQ11, extended to the third namespace above). Held
    // across Phase B *and* Phase C. These are agctl's own locks; Claude
    // Code neither takes nor waits for them.
    let deadline = Instant::now() + SWAP_DEADLINE;
    let mut locked: Vec<&AccountRecord> = vec![incoming.record];
    locked.extend(store);
    locked.extend(third.as_ref().ok().and_then(Option::as_ref));
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

    // Step 10b, the live store only: the audit log, proved appendable by a
    // **held descriptor** and held from here through Phase C (ruling G2).
    //
    // Invariant I16 makes the audit line the only durable evidence that agctl
    // broke a lock in the user's own `~/.claude`, and the failure is
    // attacker-selectable: one `ln -s` at the log's name, or one `chmod 0644`.
    // A control whose only failure mode is *the adversary switches it off and
    // the privileged action proceeds* is not a control, so the swap stops.
    //
    // Gated on the descriptor rather than on `audit::log_state`, which is a
    // report: a report leaves the whole width between the look and the write
    // to whoever can plant a name in that directory. Taken **here** — before
    // the live store is touched, before the adoption write, before the POST
    // and before the prompt, with nothing of Claude Code's held — so a refusal
    // costs nobody anything.
    //
    // The *message* is the refusal `open_log` itself returned, which names the
    // log and carries `LogState::note()`'s sentence verbatim for a wrong mode
    // or a link at its name — the one sentence `doctor`'s `audit log` row
    // prints. Not a second look through `audit::log_state`: that would be a
    // second walk after the one that refused, and could describe a state other
    // than the one the gate actually met.
    //
    // A namespace swap keeps W4a's behaviour: `audit::append` returns an
    // error, the append is logged, and the swap carries on.
    let log_path = audit::log_path(paths);
    let live_log = match which {
        Which::Live => match audit::open_log(paths, &log_path) {
            Ok(file) => Some(file),
            Err(err) => {
                return Report::refused(
                    Refusal::AuditRefused,
                    &service,
                    format!("a swap of the live store will not proceed unrecorded: {err}"),
                );
            }
        },
        Which::Namespace => None,
    };

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
    // Two `Owned` records are the displaced credential's account (review F1):
    // which namespace is its own cannot be told without guessing, so this
    // refuses beside the no-record case — under the same reason, in the same
    // phase, and after the audit gate, as `DECISION_ORDER` lists them.
    let third = match third {
        Ok(third) => third,
        Err(pair) => {
            let [first, second] = *pair;
            return Report::refused(
                Refusal::CannotAdopt(adopt::Refusal::IdentityMismatch),
                &service,
                format!(
                    "the outgoing credential cannot be adopted: its account is both `{}` and `{}` \
                     in agctl's registry, and nothing says which of the two namespaces is its \
                     own; agctl will not guess",
                    first.display_id(&config.accounts),
                    second.display_id(&config.accounts)
                ),
            );
        }
    };
    let plan = match displaced.as_ref() {
        Some(displaced) => {
            let parties = Parties {
                store,
                store_dir: &store_dir,
                incoming: incoming.record,
                incoming_credentials: &incoming_credentials,
                third: third.as_ref(),
                identity: identity.as_ref(),
            };
            match decide_adoption(paths, &parties, displaced, ctx, direction, which, &service) {
                Ok(plan) => plan,
                Err(report) => return *report,
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
                     so this swap cannot refresh it without discarding the result; run `agctl \
                     claude status` to refresh that item in place and run this again",
                    incoming.record.email.as_deref().unwrap_or(&incoming.record.account_uuid)
                ),
            );
        }
        let derived_from = incoming_credentials.digests();
        if let Err(report) = refresh_incoming(&mut incoming_credentials, ctx, &service, now) {
            return *report;
        }
        write_back_refreshed(
            paths,
            incoming,
            &incoming_credentials,
            &derived_from,
            reader.as_ref(),
            ctx,
            pass,
        );
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
    //
    // **Only for a namespace.** `open_namespace_dir` creates what is missing
    // under `namespace_root()`, and for the live target the store directory is
    // outside it — so this would both refuse (it is not agctl's to create)
    // and, if it did not, be a write into the user's own `~/.claude` that
    // invariant I11′ does not price. The live store needs no such step: Phase A
    // already resolved it, so it exists, and `LiveUnreachable` is what says so
    // when it does not.
    if which == Which::Namespace
        && let Err(err) = file_store::open_namespace_dir(paths, &store_dir)
    {
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
            target: &subject.target,
            tree: subject.tree,
            audit: &subject.audit,
            log: live_log.as_ref(),
            log_path: &log_path,
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
            //
            // Always `false` for the live target: an absent live item refuses
            // in Phase A (`LiveItemAbsent`), so `item_present` is true by the
            // time this is reached — which is what makes "no file under the
            // live store is ever written or removed" structural rather than a
            // promise.
            shadowing_store: !item_present && displaced.is_some(),
            incoming_identity: (which == Which::Live && direction == Direction::Forward)
                .then(|| incoming_identity_of(incoming.record)),
        },
        line,
        env,
        ctx,
        fault,
    )
}

/// The registry record the displaced credential belongs to, when that is
/// somebody other than the store's own account **and** other than the account
/// being swapped in.
///
/// `None` when the credential is the store's own — including the case where
/// it names no identity at all, which fact F4 says is an older blob rather
/// than a different account — `None` when it belongs to the incoming account
/// (see below), and `None` when it names one agctl has no record for, which
/// [`decide_adoption`] turns into a refusal rather than manufacturing a
/// namespace for it.
///
/// **The incoming exclusion is not a special case; it is the absence of a
/// third party** (`agctl-5gs`, review4 N-14). A displaced credential that
/// belongs to the account being swapped *in* is an older copy of the very
/// grant this pass is about to write into the item — and, when it refreshed,
/// into that account's own store. Resolving it here made the "third"
/// namespace the incoming one, so step 13's write-back mutated the file step
/// 15's compare-and-swap had been taken from: run 1 refused `Changed` against
/// agctl's own write, blaming a concurrent writer that did not exist, and
/// every later run refused `NewerCopy`, wedging the store. What becomes of
/// that copy is [`adopt::Adoption::Discarded`]'s row, not this function's.
/// `store` is `None` for the **live** target, which is not a registry row:
/// there is no account the live item's credential belongs to *by default*, so
/// every identified credential in it is a third party's and the store-identity
/// test simply does not apply.
///
/// `identity` is whose the displaced credential is **as Phase A attributed
/// it**, which for the live target need not be the credential's own
/// `tokenAccount` (decision D-027). An unattributed live credential never gets
/// here: Phase A refuses it.
///
/// # Selecting the third party, and why the two targets differ (review F1)
///
/// For the **live** target the record is chosen the way §D5 names the
/// destination — `namespace(P.identity)`, account **and** organisation — with
/// the crate's one identity predicate, among `Owned` records only, and it must
/// be the only one ([`exactly_one`]). One account registered in two
/// organisations is a supported shape, and choosing by account alone found the
/// *incoming* organisation's record and filed the other organisation's
/// credential over its store. Two candidates — an organisation-less credential,
/// or a record whose organisation is unknown — come back as `Err`, and the swap
/// refuses at step 11 rather than guessing between them.
///
/// The **namespace** target keeps W4a's selection, the first record naming the
/// account, which the frozen W4b contract may not change. The same mistake is
/// reachable there and is `agctl-m08`'s follow-up.
fn third_namespace(
    config: &AgctlConfig,
    store: Option<&AccountRecord>,
    incoming: &AccountRecord,
    identity: Option<&Identity>,
    which: Which,
) -> Result<Option<AccountRecord>, Box<[AccountRecord; 2]>> {
    if store.is_some_and(|store| swap::identity_is(identity, store))
        || swap::identity_is(identity, incoming)
    {
        return Ok(None);
    }
    let Some(identity) = identity else { return Ok(None) };
    match which {
        Which::Namespace => Ok(config
            .accounts
            .iter()
            .find(|record| record.account_uuid == identity.account_uuid)
            .cloned()),
        Which::Live => exactly_one(config.accounts.iter().filter(|record| {
            matches!(record.kind, AccountKind::Owned { .. })
                && swap::identity_is(Some(identity), record)
        }))
        .map(|found| found.cloned())
        .map_err(|[first, second]| Box::new([first.clone(), second.clone()])),
    }
}

/// The one item `items` yields: `Ok(None)` when there is none, `Ok(Some(_))`
/// when there is exactly one, and the first two when there are more.
///
/// The live target's "exactly one or refuse" rule, written once for its two
/// selections — which owned namespace holds the credential an undo puts back
/// ([`live_reversal`]), and which owned record a displaced credential belongs
/// to ([`third_namespace`]). Both refuse on two rather than taking the first,
/// because the order of the registry is not evidence of anything.
fn exactly_one<T>(items: impl IntoIterator<Item = T>) -> Result<Option<T>, [T; 2]> {
    let mut items = items.into_iter();
    let Some(first) = items.next() else { return Ok(None) };
    match items.next() {
        Some(second) => Err([first, second]),
        None => Ok(Some(first)),
    }
}

/// Where the identity of the credential in the live item may come from when
/// that credential does not carry one (decision D-027).
///
/// One variant per direction, because the two may not trust the same source.
#[derive(Debug)]
enum Witness<'a> {
    /// A forward live swap: `.claude.json`'s `oauthAccount`, when it could be
    /// read — the last login through this configuration directory, which is
    /// what the live item holds when no live swap is outstanding.
    LoginRecord(Option<Identity>),
    /// A reversal of a live swap: the account that swap installed in the item,
    /// as its audit entry records it (`incoming_identity`). Never
    /// `oauthAccount`, which agctl does not write until S24 and which after a
    /// live swap still names the account that swap displaced.
    UndoneSwap(Option<&'a Identity>),
}

/// Whose the credential in the live item is, as [`attribute`] decided it.
#[derive(Debug, PartialEq, Eq)]
enum Attribution {
    /// That account, or `None` when neither the credential nor the witness
    /// names one.
    Known(Option<Identity>),
    /// The credential names one account and the witness another. Display ids
    /// only, escaped for printing — never token material.
    Mismatch {
        /// The account the credential's own `tokenAccount` names.
        item: String,
        /// The account the witness names.
        witness: String,
    },
}

/// Decision D-027's precedence for the identity of the credential in the live
/// item.
///
/// - The credential names an account: that account — unless the witness names
///   a **different** one ([`swap::identities_agree`]), which refuses, because
///   one of the two is stale and nothing here says which.
/// - It names none: the witness's account, or `None` when the witness has
///   none either, which the caller refuses rather than attributing the
///   credential to anybody.
fn attribute(item: Option<Identity>, witness: Witness<'_>) -> Attribution {
    let witnessed = match witness {
        Witness::LoginRecord(claimed) => claimed,
        Witness::UndoneSwap(installed) => installed.cloned(),
    };
    match (item, witnessed) {
        (Some(item), Some(witnessed)) if !swap::identities_agree(&item, &witnessed) => {
            Attribution::Mismatch { item: display_of(&item), witness: display_of(&witnessed) }
        }
        (Some(item), _) => Attribution::Known(Some(item)),
        (None, witnessed) => Attribution::Known(witnessed),
    }
}

/// The account a live forward swap installs, as its audit entry records it
/// (decision D-027): ids only, and the organization only when the record knows
/// one — [`UNKNOWN_ORG`] is a placeholder, and recording it would make the
/// undo's comparison report a disagreement that is not there.
fn incoming_identity_of(record: &AccountRecord) -> audit::IncomingIdentity {
    audit::IncomingIdentity {
        account_uuid: record.account_uuid.clone(),
        organization_uuid: (record.organization_uuid != UNKNOWN_ORG)
            .then(|| record.organization_uuid.clone()),
    }
}

/// An identity as a refusal names it: the account, and its organization when
/// known, escaped — both came from outside agctl.
fn display_of(identity: &Identity) -> String {
    match &identity.organization_uuid {
        Some(org) => format!("{}/{}", printable(&identity.account_uuid), printable(org)),
        None => printable(&identity.account_uuid),
    }
}

/// Which way round the swap is running.
///
/// The procedure is the same in both directions — plan section 3.4's Phase
/// A/B/C, the same two namespace locks, the same hold, the same audit shape —
/// and exactly two things differ, both in Phase B:
///
/// | | `Forward` | `Reverse` |
/// |---|---|---|
/// | where the incoming credential is read | the incoming account's own namespace store | where the swap being undone parked it: the store's adopted copy for a namespace, and for the live store whichever owned namespace holds the digest the entry names ([`live_reversal`]) |
/// | where the displaced credential is parked | decision D-017's matrix (`adopt::decide`) | the store's adopted copy for a namespace (`adopt::decide_undo`); the matrix again for the live store, whose adopted copy would be inside `~/.claude` (W4b §D5) |
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
    config: &'a AgctlConfig,
    env: &'a EnvView,
    /// Which of the two stores this pass is about, as the scope gate decided
    /// it (forward) or as the audit entry named it (a reversal).
    which: Which,
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
    /// Which tree the hold is in, so the live pass supplies [`Tree::Live`] and
    /// the namespace pass keeps [`Tree::Agctl`].
    ///
    /// A field rather than a constant because the two trees are **not**
    /// unified: `Tree::Agctl` stays strict, since below `namespace_root()`
    /// agctl owns every component and a symbolic link at one of them is an
    /// attack rather than a configuration. `Tree::Live` resolves the store
    /// once, because on a normal machine `~/.claude` *is* a symbolic link
    /// (fact F41).
    tree: Tree,
    /// How the audit log names the item: `live`, or `namespace:<sha8>`.
    audit: &'a Target,
    /// The audit log descriptor a **live** pass is holding, opened in Phase B
    /// before anything was touched (ruling G2).
    ///
    /// Every append this phase makes — the lock-break record as much as the
    /// write entry — goes through it, so neither can be redirected by a name
    /// planted after the gate proved the log appendable. `None` for a
    /// namespace pass, which keeps W4a's behaviour of logging a refused append
    /// and carrying on.
    log: Option<&'a File>,
    /// Where that log is, for the sentences an append failure produces.
    log_path: &'a Path,
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
    /// On a live forward swap, the account being swapped in, by id alone — the
    /// entry's `incoming_identity`, which `use --undo` reads back (decision
    /// D-027). `None` on every other pass.
    incoming_identity: Option<audit::IncomingIdentity>,
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
    // The one production site of `Tree::Live`. The subject's store directory is
    // the **same value** `WriteTarget` derived the service name from (plan
    // AC82), and `acquire` is handed the **same** `EnvView` — so the hold and
    // the write cannot be about two different readings of the environment
    // (risk R42).
    let subject = LockSubject { store_dir: c.store_dir, tree: c.tree };

    // Split the acquire into the draft and the rest **before** either is
    // looked at, so the append below is one unconditional statement. An
    // acquire that failed may already have removed a peer's stale lock, and
    // that removal is exactly what invariant I16 wants recorded
    // (`agctl-nq3` — a completed break's draft was dropped on every Err).
    let (break_record, resolved) =
        match claude_lock::acquire(subject, paths, env, &clock, ctx, fault) {
            Ok(acquisition) => (acquisition.break_record, Ok(acquisition.outcome)),
            Err(failure) => (failure.break_record, Err(failure.error)),
        };

    // ONE append, unconditional, before the error mapping and before the
    // held/busy split — so a state added to either cannot be added without it.
    if let Some(draft) = break_record {
        let record = draft.complete(c.service.to_owned(), c.audit.clone());
        lock.broke = Some(break_summary(&record));
        // Through the held descriptor for a live break, because this line is
        // the **only** durable evidence that agctl removed a lock in the
        // user's own `~/.claude` (invariant I16).
        audit_append_through(paths, c.log, c.log_path, AuditEvent::LockBreak(record));
    }

    let outcome = match resolved {
        Ok(outcome) => outcome,
        // Ruling G3: `LockError::Unreachable` against the **live** tree is not
        // refusal **A**. **A** means *somebody moved a lock agctl was
        // holding* — a security signal — and a `~/.claude` that is not there,
        // or whose final component was swapped for a link, is a configuration
        // fact. Collapsing both into one letter is `agctl-git`; this closes its
        // live half and leaves the rest open.
        //
        // Reaching here at all means the Phase A resolution succeeded and the
        // store went away during the window, so this is the race's backstop
        // rather than the decision site — and the acquire failed, so nothing is
        // held when it fires and `DECISION_ORDER`'s "decided before the locks
        // are held" property holds as written.
        Err(claude_lock::LockError::Unreachable { path, message }) if c.tree == Tree::Live => {
            return ended(
                Outcome::Refused(Refusal::LiveUnreachable),
                format!("the live store `{}` could not be resolved: {message}", path.display()),
                lock,
            );
        }
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

    // Refusal A: the lock agctl holds moved under it, so the protocol was
    // violated before anything was written.
    if let Err(err) = hold.drift_check() {
        return ended(
            Outcome::Refused(Refusal::CompromisedHold),
            format!("the lock agctl holds is compromised: {err}"),
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
            format!("the lock agctl holds is compromised: {err}"),
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
        // signal that means *somebody moved a lock agctl was holding* with
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
                match (c.direction, c.tree) {
                    // Forward: P sits where the adoption filed it in Phase B,
                    // and the item still holds it too.
                    (Direction::Forward, _) => {
                        "The outgoing credential is still recoverable with `agctl claude use \
                         --undo`"
                    }
                    // Reverse: the staged copy was never committed, so the copy
                    // still holds the credential this rollback was putting back.
                    // Saying "recoverable with `--undo`" here would be advising
                    // the user to re-run the command that just failed.
                    (Direction::Reverse, Tree::Agctl) => {
                        "The credential this rollback was restoring is untouched in the adopted \
                         copy; nothing was lost and the rollback can be run again"
                    }
                    // A live reversal stages nothing and has no adopted copy of
                    // the store's own: the credential it was restoring was read
                    // from where the forward pass filed it, inside agctl's own
                    // namespaces, and a write that did not happen moved nothing.
                    (Direction::Reverse, Tree::Live) => {
                        "The credential this rollback was restoring is untouched where the swap \
                         being undone filed it, inside agctl's own namespaces; nothing was lost \
                         and the rollback can be run again"
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
    // instead costs little — the occupant that goes unparked came from its own
    // namespace store, where the forward swap read it and left it, and that
    // store *may* still hold a usable copy; "may", because a peer that has
    // since refreshed that namespace's item has rotated the copy's refresh
    // token away (`agctl-npu`) — and it costs the ability to undo *this* undo,
    // which the note says without promising more.
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
                "the write could not be confirmed; re-run `agctl claude status`. The \
                 credential this rollback was restoring is untouched in the adopted copy, and \
                 the one it displaced was deliberately not parked there — so this reversal \
                 cannot itself be undone; that credential was not parked; its own store may still \
                 hold a usable copy"
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
            // Finding N-9: this used to say "re-run `agctl claude
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
                 `agctl claude status` to see which, and if it does, remove that file by hand \
                 — Claude Code reads it whenever the keychain is unavailable. `agctl claude \
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
        note = Some("the write could not be confirmed; re-run `agctl claude status`".to_owned());
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
            "the incoming account's refresh token has been rotated away; run `agctl claude \
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
/// Only for [`Source::OwnStore`], whose source is a plaintext
/// `.credentials.json`: the forward direction, and a **live** reversal whose
/// credential the forward pass filed in its own namespace's store (W4b §D5,
/// ruling G9 — `agctl-bk5`'s live half, a change of target rather than a new
/// path). A namespaced reversal reads the store's adopted copy, which is the
/// file the staging protocol protects and whose contents a later `--undo`'s
/// digest guard compares against, and a live reversal of task 4's keep arm
/// reads the incoming namespace's adopted copy; writing a refreshed credential
/// to either still needs its own ruling.
///
/// A failure here does not fail the swap: the item write is what the operator
/// asked for, and a saved refresh is a repair, not a precondition. It is
/// logged **and carried as a warning**, because the consequence — the incoming
/// account needing a `login` — is worth telling the operator about rather than
/// leaving in a log line nobody reads (`agctl-r9w`, review4 N-15).
fn write_back_refreshed(
    paths: &Paths,
    incoming: &Incoming<'_>,
    refreshed: &Credentials,
    derived_from: &Digests,
    reader: &dyn KeychainReader,
    ctx: &PassCtx,
    pass: &mut Pass,
) {
    if !matches!(incoming.source, Source::OwnStore) {
        return;
    }
    let ns_dir =
        paths.namespace_dir(&incoming.record.account_uuid, &incoming.record.organization_uuid);
    if let Err(refusal) =
        guarded_write_back(paths, incoming.record, &ns_dir, refreshed, derived_from, reader, ctx)
    {
        tracing::warn!(
            refusal = %refusal,
            "the refreshed incoming credential was not saved to its own store"
        );
        let warning = format!(
            "the incoming account's refreshed credential was not saved back to its own store: \
             {refusal}; that account may need `agctl claude login`"
        );
        // Both, for the reason refusal B's warning is both: on **stderr** so a
        // person at a terminal is told, and in the report so a consumer of
        // `--json` does not lose a fact the terminal shows.
        eprintln!("note: {warning}");
        pass.warnings.push(warning);
    }
}

/// The guards [`status::under_namespace_lock`] applies to this same file, in
/// its order, for the one other writer of it.
///
/// Review4 N-15: `status` guards this write five ways and the swap applied
/// **one** of them — the namespace lock, which excludes another agctl pass
/// and excludes nothing else. The other four are here, and each is the
/// *same function* `status` calls rather than a second spelling of it:
///
/// 1. **the namespace lock** — already held, taken at step 10 for this exact
///    record, which is why this is not `status`'s whole function: that one
///    acquires the lock itself (`flock`, and `flock` conflicts with a second
///    descriptor in the same process, so a nested call would wait out the
///    deadline and then report `busy`) and performs its own refresh POST. The
///    two cannot be one call; the drift-guard test in `use_tests.rs` is what
///    keeps them one decision.
/// 2. **[`status::detect_unlisted`] under the lock** — a Claude Code lock
///    artefact in the *incoming* namespace means a live session holds this
///    file, and the lock does not exclude it; a keychain item under this
///    namespace's name means the namespace has migrated and a plaintext write
///    would land where nobody reads it (invariant I5'). `status` refuses
///    outright in both states and so does this. The *unlisted* spelling is the
///    one that matters: the swap takes no `dump-keychain`, and an empty
///    listing would mean "nothing has migrated" rather than "I did not look",
///    which is what made the migrated arm unreachable here (review F1). It
///    costs one `find-generic-password` per candidate service name, on this
///    path only.
/// 3. **[`file_store::resolve_pending`] first** — a pending file left by an
///    interrupted write is somebody's newer credential; resolving it before
///    reading is what makes the read below the newest truth. Its *outcome* is
///    kept, because a replay is this store healing itself rather than a second
///    writer: see guard 4.
/// 4. **[`status::reread`] under the lock, and a compare** — the credential
///    this refresh was derived from was read in Phase A, *before* the locks,
///    and the whole lock wait is the window. If what is on disk now is not
///    what the refresh was derived from, another writer has been here and the
///    pair in hand is a lost update waiting to happen. `status` spells this
///    compare as a [`file_store::FileSnapshot`] identity check because its
///    "before" is a `stat`; here the "before" is a *read*, so the compare is
///    over [`Digests`] — the same question about the same window, asked of
///    the contents rather than of the inode.
///
///    **Except after a replay.** When guard 3 moved a pending file into place,
///    the file legitimately differs from what Phase A read and no second
///    writer exists to blame — so the baseline is the re-read that *follows*
///    the replay, which is where `status` takes its own. The refreshed pair is
///    then written over the replayed content, and that is the safe direction:
///    a pending file is only replayed when its metadata still matches the
///    credentials file Phase A read (`resolve_pending` discards it as
///    `FileChanged` otherwise), so both derive from that same file — and of
///    the two, only the pair this pass just minted holds a refresh token the
///    server has not rotated away. Refusing here would leave the account
///    holding the token the POST spent, which is finding N-8 again.
///
///    The same holds for the other replay, `Replayed { first_write: true }`,
///    which `resolve_pending` reaches only when the credentials file is
///    **absent** and the pending metadata records no `derived_from` — that is,
///    the pending was parked when nothing was at that name. Phase A read this
///    namespace's file, so at that moment it existed: a pending parked before
///    any file existed is therefore provably older than what Phase A read, and
///    the refreshed pair is at least as new as either. Same outcome, same
///    reason.
/// 5. **`SavedToPending` is a refusal** — the rename failed and a live refresh
///    token is parked under a different name. `resolve_pending` will replay it
///    and `doctor` knows the name, so nothing is lost; but it is not the write
///    that was asked for and reporting it as success is how the operator finds
///    out from the next `login` prompt instead.
///
/// Returns the sentence the warning carries, which is why it is a `String`
/// rather than a typed error: every arm is terminal for this repair and none
/// of them is actionable by the caller.
fn guarded_write_back(
    paths: &Paths,
    record: &AccountRecord,
    ns_dir: &Path,
    refreshed: &Credentials,
    derived_from: &Digests,
    reader: &dyn KeychainReader,
    ctx: &PassCtx,
) -> Result<(), String> {
    let activity = status::detect_unlisted(ns_dir, record, reader);

    // Before anything is decided, in `status`'s order: what a pending file
    // means depends on what else is in the namespace, which is why `activity`
    // is computed first and passed in.
    let decision = file_store::resolve_pending(ns_dir, &activity)
        .map_err(|err| format!("the pending write could not be resolved: {err}"))?;

    match &activity {
        ForeignActivity::ClaudeLock { name, age_ms } => {
            return Err(format!(
                "a Claude Code session holds `{name}` there ({age_ms} ms old), and the namespace \
                 lock does not exclude it"
            ));
        }
        ForeignActivity::MigratedToKeychain { service } => {
            return Err(format!("that namespace has migrated into the keychain item `{service}`"));
        }
        ForeignActivity::None => {}
    }

    let Some(current) = status::reread(ns_dir) else {
        return Err("the credential this refresh was derived from is gone".to_owned());
    };
    // A replay is not a second writer, so it is not a change to refuse over:
    // the baseline moves to the file the replay produced (guard 4).
    let replayed = matches!(decision, file_store::PendingDecision::Replayed { .. });
    if !replayed && current.digests() != *derived_from {
        return Err(
            "it changed while this swap was preparing, so the refreshed pair was derived from a \
             credential that is no longer there"
                .to_owned(),
        );
    }

    let request = file_store::WriteRequest {
        paths,
        ns_dir,
        blob_json: &refreshed.to_blob_json(),
        prior: Some(derived_from),
        new_expires_at_ms: refreshed.expires_at_ms,
        fault: Fault::none(),
    };
    match file_store::write_credentials(&request, ctx) {
        Ok(file_store::WriteOutcome::Written { .. }) => Ok(()),
        Ok(file_store::WriteOutcome::SavedToPending { error }) => Err(format!(
            "the replacement could not be renamed into place and is parked in `{}` ({error})",
            file_store::PENDING_FILE
        )),
        Err(err) => Err(err.to_string()),
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
/// displaced, which by decision D-024 lives in the store's adopted copy — or,
/// for the live store, wherever §D5 filed it inside agctl's own namespaces.
/// So the caller supplies it and this carries it, rather than
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
    /// For a reversal of a **live** swap, that swap as its audit entry records
    /// it: the account it installed — whose the credential the item holds now
    /// is, when that credential no longer says — and the outcome and digests
    /// the item is checked against (decision D-027). `None` on every other
    /// pass.
    undone: Option<&'a UndoneEntry>,
}

/// Where the incoming credential is read from.
enum Source {
    /// The record's own namespace store, `.credentials.json`: the incoming
    /// account's on the forward path, and on a live reversal the displaced
    /// credential's own account's, where §D5's ordinary row filed it.
    OwnStore,
    /// An adopted copy in the directory given: the store's own for a
    /// namespaced reversal (decision D-024), and the incoming namespace's for a
    /// live reversal of task 4's keep arm (§D5's re-cut of `agctl-r3h`).
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
        format!("`{who}` has no readable credential to swap in; run `agctl claude login` for it")
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

/// Who one adoption is between, and where the store it displaces from is.
///
/// Grouped rather than passed one by one because the three records have to
/// describe **one** swap: the account that owns the store being written, the
/// account being swapped in, and — when the displaced credential belongs to
/// neither of them — the third account whose namespace lock step 10 took for
/// it. Since `agctl-5gs` the second of those is not decoration: whose the
/// displaced credential is decides whether there is an adoption target at all.
struct Parties<'a> {
    /// The account that owns the store being swapped, or `None` for the
    /// **live** store, which is not a registry row.
    ///
    /// Its absence is the whole of §D5's reduction: with no account the store
    /// belongs to, `same_namespace` is false by construction, so decision
    /// D-024's sibling file — whose destination is `<D>/…`, and for the live
    /// target `~/.claude/…` — is unreachable, and every identified credential
    /// in the live item is a third party's to be filed in its own namespace
    /// under `namespace_root()`.
    store: Option<&'a AccountRecord>,
    /// That store's namespace directory.
    store_dir: &'a Path,
    /// The account being swapped in.
    incoming: &'a AccountRecord,
    /// The credential this pass read from that account's own store in Phase A
    /// and is about to install. Carried rather than re-read: a second read of
    /// the same file can see a different credential (a concurrent `login`,
    /// `import` or `status` that ignores the namespace lock), and the row's
    /// question is about the credential actually being written
    /// (`agctl-5gs` review F4).
    incoming_credentials: &'a Credentials,
    /// The account the displaced credential belongs to, when it is neither of
    /// the two above and agctl has a record for it — see [`third_namespace`].
    third: Option<&'a AccountRecord>,
    /// Whose the displaced credential is, as Phase A attributed it: its own
    /// `tokenAccount`, or for the live target the witness decision D-027 names
    /// when it carries none. Every identity question the adoption asks, asks
    /// this rather than the blob.
    identity: Option<&'a Identity>,
}

/// Decision D-017's adoption, **decided**: every read, every refusal, no write.
///
/// The matrix itself is [`adopt::decide`], which is pure; this reads what that
/// needs and turns its answer into an [`AdoptionPlan`]. It runs in Phase B
/// under the namespace lock (ruling OQ2, condition (c)) and **before** the
/// confirmation prompt, so refusal **F** keeps the position plan section
/// 3.4 gives it: a swap that cannot adopt is refused without asking about it.
///
/// A refusal comes back as the whole [`Report`] rather than as the matrix's
/// reason alone, because the live target has a refusal of its own whose matrix
/// reason carries a sentence that would be false for it (W4b §D5): the live
/// item's credential names an account no `Owned` record claims. It is still
/// refusal **F** with the matrix's reason — only the sentence is its own. A
/// live credential nothing attributes never gets here: Phase A refuses it where
/// it is attributed (decision D-027).
fn decide_adoption(
    paths: &Paths,
    parties: &Parties<'_>,
    displaced: &Credentials,
    ctx: &PassCtx,
    direction: Direction,
    which: Which,
    service: &str,
) -> Result<AdoptionPlan, Box<Report>> {
    let Parties { store, store_dir, incoming, incoming_credentials, third, identity } = *parties;
    let refused = |reason: adopt::Refusal| Box::new(Report::cannot_adopt(reason, service));
    // A **live** reversal does not take the staging path at all, and that is
    // §D5's re-cut rather than an omission: `adopt::decide_undo`'s destination
    // is fixed at `<D>/.credentials.adopted.json`, and for a live target `D` is
    // `~/.claude` — outside `namespace_root()`, forbidden by invariant I11′, and
    // the one write that would make AC81's live containment assertion false. So
    // both live directions take the reduction below, which sends each credential
    // to its **own** namespace: forward, the displaced live credential to
    // `namespace(P)`; in reverse, what the item holds to `namespace(T)`. Each
    // goes home, so the operation is still its own inverse, and both
    // destinations are inside `namespace_root()`.
    //
    // A namespace reversal parks the occupant in the store's own adopted copy, whoever
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
    if direction == Direction::Reverse && which == Which::Namespace {
        let existing = classify(location::from_adopted(store_dir), displaced);
        let decision = adopt::decide_undo(&adopt::Input {
            // A reversal reads the store's own adopted copy, never the
            // incoming account's namespace, so the row these fields select
            // cannot arise here — and `decide_undo` does not consult them.
            displaced_is_incoming: false,
            incoming_expires_at_ms: displaced.expires_at_ms,
            displaced_is_duplicate: false,
            existing_is_another_account: false,
            same_namespace: true,
            identity_matches: true,
            pending_present: pending_present(store_dir),
            target_migrated: false,
            existing,
            displaced_expires_at_ms: displaced.expires_at_ms,
        });
        return match decision {
            adopt::Adoption::AlreadyPresent => Ok(AdoptionPlan::Nothing),
            adopt::Adoption::Refused(refusal) => Err(refused(refusal)),
            _ => Ok(AdoptionPlan::StagedCopy(store_dir.to_path_buf())),
        };
    }

    // Condition (a): whether the item's identity is the record's. An absent
    // `tokenAccount` is an older blob (fact F4), not a different identity, so
    // `same_identity` passes it — and a credential agctl cannot identify
    // belongs to the store it was found in, which is the same conclusion.
    //
    // **The live target has no such record, and that is §D5's whole
    // reduction.** Refusal **E** guarantees `CLAUDE_SECURESTORAGE_CONFIG_DIR`
    // is falsy, so `D` is `~/.claude` (or `CLAUDE_CONFIG_DIR`) — and
    // `Paths::is_under_namespace_root` refuses every agctl namespace outside
    // `namespace_root()`, so no agctl namespace can *be* the live store.
    // `same_namespace` is therefore false by construction, decision D-024's
    // sibling row is unreachable, and `identity_matches` — which
    // `adopt::decide` consults only under `same_namespace` — is never asked.
    let (identity_matches, same_namespace) = match store {
        Some(store) => {
            let matches = swap::identity_is(identity, store);
            (matches, matches)
        }
        None => (false, false),
    };
    // `agctl-5gs`: whose the displaced credential is, asked of the incoming
    // record as well as of the store's. It selects the row that decides
    // whether that copy is worth keeping at all — see [`third_namespace`] for
    // what the third-namespace row did with it instead.
    let displaced_is_incoming = !same_namespace && swap::identity_is(identity, incoming);
    let mut occupied_by_another = false;

    let (ns_dir, existing, prior) = if displaced_is_incoming {
        // When this row keeps the copy it writes the **store's** D-024
        // sibling — the file `use --undo` reads back, and never the incoming
        // namespace, which is what the write-back writes. So it is read like
        // the sibling it is: a blind rename over that name destroys whatever
        // the previous swap adopted there (review F1). No keychain probe: the
        // row's own question is answered from Phase A's credential.
        //
        // For the **live** target the sibling is the **incoming namespace's**,
        // and the substitution is §D5's live re-cut of `agctl-r3h`. `<D>` is
        // `~/.claude`: a `.credentials.adopted.json` there is outside
        // `namespace_root()`, is the write invariant I11′ forbids, and is what
        // would make AC81's live containment assertion false. The incoming
        // namespace's sibling is inside `namespace_root()` and is still **not**
        // a `.credentials.json`, so neither the write-back's compare-and-swap
        // nor the incoming store is touched — which is the property the row
        // exists to preserve. The live `--undo` reads it back from there,
        // through the `PathBuf` `Source::AdoptedCopy` already carries.
        let sibling = match which {
            Which::Namespace => store_dir.to_path_buf(),
            Which::Live => paths.namespace_dir(&incoming.account_uuid, &incoming.organization_uuid),
        };
        let read = location::from_adopted(&sibling);
        // Condition (a) for that file: whose credential is already there. The
        // crate's one identity predicate, against the incoming record —
        // which is the displaced credential's own account by this row's
        // construction, so this is "the sibling's occupant against the
        // credential being adopted" (review F1's residual). Fact F4's
        // identity-less blob passes, as it does everywhere else.
        occupied_by_another = match &read {
            Resolved::Credentials(found) => !swap::same_identity(found, incoming),
            _ => false,
        };
        (sibling, classify(read, displaced), None)
    } else if same_namespace {
        // Decision D-024: the adopted copy, never `.credentials.json`.
        let read = location::from_adopted(store_dir);
        (store_dir.to_path_buf(), classify(read, displaced), None)
    } else {
        // Somebody else's credential is in this store's item. It belongs in
        // *their* namespace, if agctl has one for them — and `third` is
        // that record, resolved in Phase A so its namespace lock is in the
        // set taken at step 10. Resolving it here instead would write a
        // namespace whose lock nobody took.
        //
        // For the live target a missing `third` is §D5's **no-record** case:
        // the credential names an account and no `Owned` record is that
        // account (`swap_phases` drops a record of any other kind). Refused
        // rather than filed, because filing it would mean manufacturing a
        // namespace — under condition (a)'s reason, but not its sentence, which
        // speaks of "the account that owns this store" and the live store has
        // none. The uuid comes out of the item, so it is escaped like every
        // other value this file prints from outside.
        let Some(record) = third else {
            return Err(match (which, identity) {
                (Which::Live, Some(identity)) => Box::new(Report::refused(
                    Refusal::CannotAdopt(adopt::Refusal::IdentityMismatch),
                    service,
                    format!(
                        "the outgoing credential cannot be adopted: the live item holds a \
                         credential of `{}`, and no account agctl owns is that one, so there is \
                         no namespace to file it in; log that account in with `agctl claude \
                         login` first",
                        printable(&identity.account_uuid)
                    ),
                )),
                _ => refused(adopt::Refusal::IdentityMismatch),
            });
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
    let target_migrated = !same_namespace && !displaced_is_incoming && migrated(paths, third, ctx);

    let decision = adopt::decide(&adopt::Input {
        displaced_is_incoming,
        incoming_expires_at_ms: incoming_credentials.expires_at_ms,
        displaced_is_duplicate: displaced.digests() == incoming_credentials.digests(),
        existing_is_another_account: occupied_by_another,
        same_namespace,
        identity_matches,
        pending_present: pending_present(&ns_dir),
        target_migrated,
        existing,
        displaced_expires_at_ms: displaced.expires_at_ms,
    });

    match decision {
        // Both write nothing, and the difference between them is what they
        // say about *why*: the target already held it, or the credential was
        // a duplicate of — or older than — the one being installed.
        adopt::Adoption::AlreadyPresent | adopt::Adoption::Discarded => Ok(AdoptionPlan::Nothing),
        adopt::Adoption::Refused(refusal) => Err(refused(refusal)),
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

/// Appends one audit entry, through a descriptor the pass is already holding
/// when it has one.
///
/// The live-store half of ruling G2. A live swap proved the log appendable in
/// Phase B by **opening** it, and keeps that descriptor across Phase C — so
/// every entry this phase writes goes to the file the gate checked, and a name
/// replaced in between changes nothing. A namespace pass passes `None` and
/// keeps W4a's behaviour: `append` resolves the name itself, and a refused log
/// is logged and survived rather than fatal.
///
/// Either way a failure does not fail the swap. The entry is the record of a
/// write, not a precondition for one — invariant I16's precondition is checked
/// before the write, which for the live target is exactly what the Phase B gate
/// is.
fn audit_append_through(
    paths: &Paths,
    log: Option<&File>,
    log_path: &Path,
    event: AuditEvent,
) -> Option<String> {
    let entry = AuditEntry::new(event);
    let appended = match log {
        Some(file) => audit::append_through(file, log_path, &entry),
        None => audit::append(paths, &entry),
    };
    match appended {
        Ok(id) => Some(id.to_string()),
        Err(err) => {
            tracing::error!(error = %err, "an audit entry could not be appended");
            None
        }
    }
}

/// Appends the audit entry for one write of the item this pass is about.
fn audit_write(paths: &Paths, c: &PhaseC<'_>, outcome: audit::WriteOutcome) -> Option<String> {
    audit_append_through(
        paths,
        c.log,
        c.log_path,
        AuditEvent::Write {
            target: c.audit.clone(),
            from_digest8: c.from_digest8.clone(),
            to_digest8: c.to_digest8.clone(),
            outcome,
            direction: match c.direction {
                Direction::Forward => audit::WriteDirection::Forward,
                Direction::Reverse => audit::WriteDirection::Undo,
            },
            incoming_identity: c.incoming_identity.clone(),
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
            // Beside `emit_plan`'s `"kind": "plan"`, so a consumer reading the
            // stream can tell the two documents apart by a member rather than
            // by counting them (`agctl-npu`). A run that reaches the prompt
            // prints both; one refused before it prints only this. Read the
            // stream with a streaming parser and take the **last** document
            // rather than indexing `[1]`.
            "kind": "outcome",
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
        // A refusal carries a **letter** or a **reason**, never both and never
        // neither: `Refusal::reason` is the exact complement of
        // `Refusal::letter`, and `swap_tests.rs` pins that. The unlettered four
        // are the OQ1 precondition, which is decided before Phase A's work
        // begins, and W4b's three, which sit outside plan section 3.4's
        // canonical **A**–**F** because those letters were already spoken for.
        if let Outcome::Refused(refusal) = &report.outcome {
            match refusal.reason() {
                Some(reason) => doc["reason"] = serde_json::json!(reason),
                None => doc["refusal"] = serde_json::json!(refusal.letter()),
            }
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
    /// The swap to reverse targets the **live** item: an outstanding live
    /// forward swap, or — when none is outstanding — the newest reversible
    /// write, which is then a live undo that [`run_undo`] refuses to reverse.
    ///
    /// Carried rather than skipped, and that is load-bearing: stepping past a
    /// live-store entry to reach an older namespaced one would reverse a swap
    /// the user did not mean.
    Live {
        /// The digest prefix of the credential that was displaced.
        ///
        /// Never `None` for a live entry in practice: an absent live item
        /// refuses in Phase A ([`Refusal::LiveItemAbsent`]), so a live write
        /// always displaced something. A `None` here means a hand-edited log,
        /// and [`run_undo`] refuses rather than guessing.
        from_digest8: Option<String>,
        /// The digest prefix of the credential the swap wrote.
        to_digest8: String,
        /// How the swap ended — what [`item_changed`]'s diverged check keys
        /// on (decision D-027).
        outcome: audit::WriteOutcome,
        /// Which way round it ran: a live **undo** is refused rather than
        /// reversed ([`Refusal::LiveUndoOfUndo`]).
        direction: audit::WriteDirection,
        /// The account a live forward swap installed, which the reversal takes
        /// as the identity of the credential the item holds.
        incoming_identity: Option<audit::IncomingIdentity>,
        /// A live undo that ended `unknown` after this swap, when there is one
        /// (decision D-027): the item is checked against its digests before
        /// this swap is reversed again.
        later_unknown_undo: Option<UnknownUndo>,
    },
    /// There is no write to undo.
    Nothing,
    /// A line between the tail's end and the entry could not be read, so the
    /// entry `--undo` needs may be the one that is unreadable.
    Unreadable(usize),
}

/// Picks the swap to reverse out of the audit log — the whole log, not a tail
/// (decision D-027).
///
/// **An outstanding live swap first.** The newest live forward swap that no
/// later live undo applied over is what `--undo` means, whatever is newer than
/// it. `status` and `watch` record a migrated namespace's in-place refresh as a
/// reversible namespace write, and reaching for that instead would leave the
/// live swap unreachable while the outstanding-live-swap guard refuses every
/// forward swap until it is undone. An undo that did not apply does not clear
/// the swap, so undoing again reverses it again.
///
/// **Otherwise the newest reversible write**, W4a's rule: the newest `Write`
/// whose outcome was `Applied` or `Unknown`, whatever it targeted. `Discarded`
/// and `Failed` wrote nothing, so there is nothing of theirs to undo. A live
/// entry found this way is an undo, which [`run_undo`] refuses to reverse
/// ([`Refusal::LiveUndoOfUndo`]).
///
/// # Why an unreadable line refuses rather than being skipped
///
/// A crash part-way through an append truncates the **last** line — which is
/// exactly the entry `--undo` wants. Skipping it would silently reverse the
/// swap *before* the one the user meant, putting a credential back into an
/// item that a later swap has since changed. Read over the whole log the line
/// may equally be the live swap the first rule looks for, so any unreadable
/// line refuses, and names the line number.
pub(crate) fn select_undo(tail: &audit::Tail) -> Undoable {
    if let Some((line, _)) = tail.unreadable.first() {
        return Undoable::Unreadable(*line);
    }
    let reversible: Vec<Undoable> = tail.entries.iter().rev().filter_map(undoable).collect();
    let mut undone_later = false;
    let mut later_unknown = None;
    let mut outstanding = None;
    for (index, candidate) in reversible.iter().enumerate() {
        let Undoable::Live { direction, outcome, from_digest8, to_digest8, .. } = candidate else {
            continue;
        };
        match direction {
            audit::WriteDirection::Undo if *outcome == audit::WriteOutcome::Applied => {
                undone_later = true;
            }
            // An undo that ended `unknown` does not clear the swap, but it may
            // have landed: its digests go with the swap, for the item to say.
            audit::WriteDirection::Undo => {
                if later_unknown.is_none() {
                    later_unknown = Some(UnknownUndo {
                        from_digest8: from_digest8.clone(),
                        to_digest8: to_digest8.clone(),
                    });
                }
            }
            audit::WriteDirection::Forward => {
                if !undone_later {
                    outstanding = Some(index);
                }
                break;
            }
        }
    }
    let Some(index) = outstanding else {
        return reversible.into_iter().next().unwrap_or(Undoable::Nothing);
    };
    let mut picked = reversible.into_iter().nth(index).unwrap_or(Undoable::Nothing);
    if let Undoable::Live { later_unknown_undo, .. } = &mut picked {
        *later_unknown_undo = later_unknown;
    }
    picked
}

/// A live undo that ended `unknown` after the swap `--undo` is about to
/// reverse again (decision D-027). The item says whether it landed: holding
/// what it wrote means it did, and the swap is already reversed; holding what
/// it displaced means it did not; holding neither says nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnknownUndo {
    /// The digest prefix of what that undo displaced.
    pub(crate) from_digest8: Option<String>,
    /// The digest prefix of what that undo wrote.
    pub(crate) to_digest8: String,
}

/// One audit entry as a candidate for `--undo`, or `None` when it is not a
/// write that may have written something.
fn undoable(entry: &AuditEntry) -> Option<Undoable> {
    let AuditEvent::Write {
        target,
        from_digest8,
        to_digest8,
        outcome,
        direction,
        incoming_identity,
    } = &entry.event
    else {
        return None;
    };
    if !matches!(outcome, audit::WriteOutcome::Applied | audit::WriteOutcome::Unknown) {
        // `Discarded` and `Failed` wrote nothing, so there is nothing of
        // theirs to put back.
        return None;
    }
    // A first write — `from_digest8` null — is **not** skipped. It displaced
    // no *item*, but it displaced the credential that was in the store's
    // plaintext file, and since finding N-2 that file is removed once the write
    // applies, so the adopted copy is where that credential now lives and a
    // reversal is what returns it.
    Some(match target {
        Target::Namespace(sha8) => Undoable::Found {
            sha8: sha8.clone(),
            from_digest8: from_digest8.clone(),
            to_digest8: to_digest8.clone(),
        },
        Target::Live => Undoable::Live {
            from_digest8: from_digest8.clone(),
            to_digest8: to_digest8.clone(),
            outcome: *outcome,
            direction: *direction,
            incoming_identity: incoming_identity.clone(),
            later_unknown_undo: None,
        },
    })
}

/// Why a forward live swap refuses while a live swap agctl made is still
/// outstanding (decision D-027) — the refusal to give and its sentence — or
/// `None` when none is.
///
/// **Temporary, lifted by S24.** A credential Claude Code wrote into the live
/// item names no account, so a forward live swap takes its identity from
/// `.claude.json`'s `oauthAccount` — a record agctl does not write until S24.
/// Between a live swap and its `use --undo` that record therefore still names
/// the account the swap **displaced**, and a second live swap would attribute
/// the credential the first one installed to that account and file it in that
/// account's namespace, over the copy the first swap parked there. Once S24's
/// profile client names the item's account itself and agctl writes
/// `oauthAccount` on every live swap, the record is never stale and this guard
/// goes with it.
///
/// Decided after step 7's item read, because the `unknown` branch compares the
/// entry with the item's digest (`item8`). The **whole** log is read, not a
/// tail: `status` and `watch` record every in-place namespace refresh, so a
/// window short enough to push the live swap out of it is a window in which
/// this guard silently stands down. It never passes unread either — a
/// **refused** log (a link or a FIFO at its name, a link on the way to it) is
/// refusal `audit_refused`, in the words step 10b's gate uses for the same log,
/// and any other failure to read it, or an unreadable line, refuses: what could
/// not be read may be the swap this guard exists for.
fn live_swap_outstanding(paths: &Paths, item8: Option<&str>) -> Option<(Refusal, String)> {
    let tail = match audit::tail(paths, usize::MAX) {
        Ok(tail) => tail,
        Err(AppError::Config(refused)) => {
            return Some((
                Refusal::AuditRefused,
                format!("a swap of the live store will not proceed unrecorded: {refused}"),
            ));
        }
        Err(err) => {
            return Some((
                Refusal::LiveSwapOutstanding,
                format!(
                    "the audit log could not be read ({err}), so agctl cannot tell whether a \
                     live swap it made is still outstanding; see `agctl claude doctor`"
                ),
            ));
        }
    };
    Some(match outstanding_live_swap(&tail, item8)? {
        Outstanding::Swap(id) => (
            Refusal::LiveSwapOutstanding,
            format!(
                "a previous live swap (audit {id}) is still outstanding; run `agctl claude use \
                 --undo` first; {OUTSTANDING_REMINDER}"
            ),
        ),
        Outstanding::Unknown(id) => (
            Refusal::LiveWriteUnknown,
            format!(
                "the last live write (`{id}`) ended `unknown` and the live item has changed \
                 since, so nothing says which account it holds; run `agctl claude status` to see \
                 which account is live (`agctl claude doctor` names the entry)"
            ),
        ),
        Outstanding::Unreadable(line) => (
            Refusal::LiveSwapOutstanding,
            format!(
                "the audit log's line {line} could not be read, and it may record a live swap \
                 that has not been undone; agctl will not guess whose credential the live item \
                 holds (`agctl claude doctor` names the line)"
            ),
        ),
    })
}

/// What [`outstanding_live_swap`] found in the log.
#[derive(Debug, PartialEq, Eq)]
enum Outstanding {
    /// The outstanding live swap, by its audit id.
    Swap(String),
    /// The newest live write ended `unknown` and the item holds neither end of
    /// it, so nothing says whose credential is in it.
    Unknown(String),
    /// A line of the log could not be read, and it may be a live write.
    Unreadable(usize),
}

/// Whether the log leaves a live swap outstanding (decision D-027).
///
/// Keyed on the **newest live write**, read from the entries' `direction`
/// rather than inferred. A namespace swap is another item: one made after a
/// live swap does not clear the guard, and one alone does not arm it. A
/// discarded or failed write changed nothing and is skipped. An entry written
/// before `direction` existed reads as a forward swap, which arms rather than
/// disarms.
///
/// That newest live write settles the question, and an `unknown` outcome is
/// settled against the item:
///
/// - **forward, `applied`**: outstanding.
/// - **forward, `unknown`**: the item still holding what it displaced says the
///   write never landed, so not outstanding; otherwise it may have landed, so
///   outstanding.
/// - **undo, `applied`**: it put the swap back, so not outstanding.
/// - **undo, `unknown`**: the item holding what it wrote says it landed, so not
///   outstanding; the item still holding what it displaced leaves the swap it
///   was reversing standing, and that swap is what is named.
/// - **either, `unknown`, and the item holds neither end**: nothing says what is
///   in the item at all — [`Outstanding::Unknown`], which refuses a forward
///   swap under its own code and never blocks `use --undo`.
///
/// Any unreadable line refuses, wherever it is: it may be the newest live write.
fn outstanding_live_swap(tail: &audit::Tail, item8: Option<&str>) -> Option<Outstanding> {
    if let Some((line, _)) = tail.unreadable.first() {
        return Some(Outstanding::Unreadable(*line));
    }
    let mut live = tail.entries.iter().filter_map(live_write).rev();
    let newest = live.next()?;
    let holds_from = newest.from_digest8.is_some() && item8 == newest.from_digest8;
    let holds_to = item8 == Some(newest.to_digest8);
    if newest.outcome == audit::WriteOutcome::Unknown && !holds_from && !holds_to {
        return Some(Outstanding::Unknown(newest.entry.id().to_string()));
    }
    match newest.direction {
        audit::WriteDirection::Forward => (newest.outcome == audit::WriteOutcome::Applied
            || !holds_from)
            .then(|| Outstanding::Swap(newest.entry.id().to_string())),
        audit::WriteDirection::Undo => {
            if newest.outcome == audit::WriteOutcome::Applied || holds_to {
                return None;
            }
            // The undo did not land, so the swap it was reversing stands — and
            // that swap, not the undo, is what the refusal names.
            let standing = live
                .find(|write| write.direction == audit::WriteDirection::Forward)
                .unwrap_or(newest);
            Some(Outstanding::Swap(standing.entry.id().to_string()))
        }
    }
}

/// One live write that may have written something, as the guard reads it.
struct LiveWrite<'a> {
    /// The entry itself, for its audit id.
    entry: &'a AuditEntry,
    /// Which way round that swap ran.
    direction: audit::WriteDirection,
    /// How it ended — `Applied` or `Unknown`; the rest are not writes.
    outcome: audit::WriteOutcome,
    /// The digest prefix of what it displaced.
    from_digest8: Option<&'a str>,
    /// The digest prefix of what it wrote.
    to_digest8: &'a str,
}

/// One entry as a live write, or `None` when it is neither live nor a write
/// that may have landed.
fn live_write(entry: &AuditEntry) -> Option<LiveWrite<'_>> {
    let AuditEvent::Write {
        target: Target::Live,
        from_digest8,
        to_digest8,
        outcome,
        direction,
        ..
    } = &entry.event
    else {
        return None;
    };
    matches!(outcome, audit::WriteOutcome::Applied | audit::WriteOutcome::Unknown).then(|| {
        LiveWrite {
            entry,
            direction: *direction,
            outcome: *outcome,
            from_digest8: from_digest8.as_deref(),
            to_digest8,
        }
    })
}

/// Whether the live item is still what the swap `use --undo` reverses left
/// there (decision D-027), or why not.
///
/// Two checks on what Phase A has already read — the item's digest and one read
/// of `.claude.json` — and both refuse rather than attribute:
///
/// - **a foreign login.** `.claude.json`'s `oauthAccount` is a **tripwire**
///   here, never a source. After a live swap it normally still names the
///   account being put back (`owner`, P), and it names the account the swap
///   installed (T) if the session logged in as that one. Any other account
///   means the session logged in as somebody else since, the item holds *that*
///   account's credential, and the entry would misname it as T's.
/// - **a later undo that ended `unknown`**, when the swap has one: the item
///   holding what that undo wrote says it landed, so the swap is already
///   reversed and reversing it again is an undo of an undo
///   ([`Refusal::LiveUndoOfUndo`]); holding what it displaced says it did not,
///   and the reversal proceeds; holding neither says nothing.
/// - **a diverged item**, for an `unknown` swap only: the item holds neither
///   the credential the swap displaced nor the one it wrote, so nothing says
///   what is there. An `applied` swap is exempt, because a digest change there
///   is T's ordinary refresh.
///
/// Residual, recorded rather than guarded: a login as P itself while the swap
/// is outstanding passes the tripwire, and is indistinguishable from T's
/// refresh until S24's profile client.
fn item_changed(
    undone: &UndoneEntry,
    owner: &AccountRecord,
    item8: Option<&str>,
    claimed: Option<&Identity>,
) -> Option<Refusal> {
    if let Some(claimed) = claimed
        && !swap::identity_is(Some(claimed), owner)
        && !swap::identities_agree(claimed, &undone.installed)
    {
        return Some(Refusal::LiveUndoItemChanged(ItemChange::ForeignLogin));
    }
    let diverged = Refusal::LiveUndoItemChanged(ItemChange::Diverged);
    if let Some(later) = &undone.later_unknown_undo {
        if item8 == Some(later.to_digest8.as_str()) {
            return Some(Refusal::LiveUndoOfUndo);
        }
        let did_not_land = item8.is_some() && item8 == later.from_digest8.as_deref();
        return (!did_not_land).then_some(diverged);
    }
    let unknown_and_neither = matches!(undone.outcome, audit::WriteOutcome::Unknown)
        && item8 != Some(undone.from_digest8.as_str())
        && item8 != Some(undone.to_digest8.as_str());
    unknown_and_neither.then_some(diverged)
}

/// `claude use --undo` — plan section 3.4's rollback.
///
/// Selects the swap to reverse ([`select_undo`]), then **re-runs Phase A–C
/// with P and T exchanged** against the same owned store. The adopted copy
/// supplies the credential to put back; the credential currently in the item
/// becomes the new displaced one and is parked in that same copy in turn, so
/// the operation is its own inverse.
///
/// **An outstanding live swap takes precedence** over newer namespace swaps
/// (decision D-027): while one is outstanding it is what `--undo` reverses, and
/// a namespace swap made after it cannot be undone until it has been.
///
/// A reversal of a **live** swap runs the same way, against `Tree::Live` and
/// with §D5's live adoption rules. It is the one path on which refusal **E**
/// is reachable: the target comes from the **audit log**, not from
/// `CLAUDE_SECURESTORAGE_CONFIG_DIR`, so the two can disagree — and a run whose
/// shell names a namespace while the entry names the live item would take the
/// locks in one place and write the other, which is what **E** refuses.
///
/// # Errors
///
/// Returns [`AppError::Config`] when the audit log's tail is not a complete
/// account of what happened, when the entry names a store no record claims, and
/// when the credential the entry says was displaced cannot be found, cannot be
/// matched to that entry, or is found in more than one place.
fn run_undo(config_dir: Option<&Path>, args: &UseArgs, cancel: &Cancel) -> Result<i32, AppError> {
    let paths = Paths::resolve(config_dir)?;
    paths.ensure_dirs()?;
    // The whole log (decision D-027): namespace refresh lines accumulate, and a
    // window short enough to push the live swap out of it is a window in which
    // the outstanding-live-swap guard can never be cleared.
    let tail = audit::tail(&paths, usize::MAX)?;
    // The registry is loaded before the match so each arm can build its
    // reversal in place. Splitting the match in two — choose, then resolve —
    // would leave the two exhausted arms to be spelled again, and the only
    // honest way to spell them in the second match is a panic; this crate has
    // no `unreachable!` in production and is not getting its first one on the
    // credential path.
    let config = AgctlConfig::load(&paths)?;
    let reversal = match select_undo(&tail) {
        Undoable::Unreadable(line) => {
            return Err(AppError::Config(format!(
                "the audit log's line {line} could not be read, and it may be the entry \
                 `--undo` needs; agctl will not guess which swap to reverse (`agctl claude \
                 doctor` names the line)"
            )));
        }
        Undoable::Nothing => {
            Tty.tell("there is no swap to undo: the audit log records no reversible write");
            return Ok(EXIT_OK);
        }
        Undoable::Found { sha8, from_digest8, to_digest8 } => {
            namespaced_reversal(&paths, &config, &sha8, from_digest8.as_deref(), &to_digest8)?
        }
        Undoable::Live {
            from_digest8,
            to_digest8,
            outcome,
            direction,
            incoming_identity,
            later_unknown_undo,
        } => {
            // Decision D-027: the newest swap is itself the undo of a live
            // swap. Reversing it would put the swapped-in credential back while
            // `.claude.json` still names the account it displaced, and would
            // leave the outstanding-live-swap guard reading that reversal as the
            // newest word. Decided from the entry alone, before `live_reversal`
            // reads any owned namespace; temporary, lifted by S24.
            if direction == audit::WriteDirection::Undo {
                let mut report = Report::refused(
                    Refusal::LiveUndoOfUndo,
                    "",
                    "the newest swap in the audit log is the undo of a live swap, and undoing \
                     that undo is not supported yet; run `agctl claude use --live <id>` for the \
                     account you want instead"
                        .to_owned(),
                );
                report.target = Some(Target::Live.to_string());
                emit(&report, args.json)?;
                return Ok(report.outcome.exit_code());
            }
            live_reversal(
                &paths,
                &config,
                from_digest8.as_deref(),
                &to_digest8,
                outcome,
                incoming_identity.as_ref(),
                later_unknown_undo,
            )?
        }
    };

    let env = EnvView::from_process();
    let ctx = PassCtx::standalone(cancel.clone(), Instant::now() + SWAP_DEADLINE);
    let fault = fault_from_env();
    let swap = Swap {
        paths: &paths,
        config: &config,
        env: &env,
        which: reversal.which,
        inherited: &reversal.inherited,
        ctx: &ctx,
        fault: &fault,
    };
    let incoming = Incoming {
        record: &reversal.owner,
        direction: Direction::Reverse,
        source: reversal.source,
        undone: reversal.undone.as_ref(),
    };
    let report = swap_in(&swap, &incoming, reversal.store.as_ref(), args);
    emit(&report, args.json)?;
    Ok(report.outcome.exit_code())
}

/// One audit entry resolved to the places on disk a reversal needs.
///
/// Built by one function per target class so the two differ in exactly the
/// things that differ — which store, and where the credential being put back
/// was parked — and share the Phase A–C run that follows.
struct Reversal {
    /// Which of the two stores the item is in.
    which: Which,
    /// The record that owns the store, or `None` for the live store, which is
    /// not a registry row.
    store: Option<AccountRecord>,
    /// The spelling the store is named by; empty for the live store, which has
    /// no recorded spelling to check a derived directory against.
    inherited: String,
    /// The account the credential being put back belongs to, for the namespace
    /// lock and the prompt.
    owner: AccountRecord,
    /// Where that credential is read from.
    source: Source,
    /// For a live reversal, the swap being undone ([`Incoming::undone`]);
    /// `None` for a namespaced one.
    undone: Option<UndoneEntry>,
}

/// The live swap `use --undo` reverses, as the reversal needs it (decision
/// D-027).
#[derive(Debug)]
struct UndoneEntry {
    /// The account that swap installed in the item — the entry's
    /// `incoming_identity`, ids only.
    installed: Identity,
    /// How that swap ended.
    outcome: audit::WriteOutcome,
    /// The digest prefix of the credential it displaced.
    from_digest8: String,
    /// The digest prefix of the credential it wrote.
    to_digest8: String,
    /// A live undo that ended `unknown` after that swap, when there is one.
    later_unknown_undo: Option<UnknownUndo>,
}

/// A reversal of a swap against a namespace agctl owns (W4a's path,
/// unchanged).
fn namespaced_reversal(
    paths: &Paths,
    config: &AgctlConfig,
    sha8: &str,
    from_digest8: Option<&str>,
    to_digest8: &str,
) -> Result<Reversal, AppError> {
    // The entry names the item by its suffix; the store is whichever owned
    // record still derives that suffix. "Still" is the operative word — a
    // record that has been removed or relocated since the swap leaves an
    // entry nothing can act on, and guessing would write a credential into a
    // namespace the user no longer believes in.
    let Some(store) = config
        .accounts
        .iter()
        .find(|record| {
            OwnedSha8::from_record(paths, record).is_some_and(|owned| owned.sha8() == sha8)
        })
        .cloned()
    else {
        return Err(AppError::Config(format!(
            "the swap to undo named the keychain item `{sha8}`, which no account agctl \
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
    match from_digest8 {
        Some(from_digest8) => {
            if found8.as_deref() != Some(from_digest8) {
                return Err(AppError::Config(format!(
                    "the adopted copy in `{}` holds `{}`, but the swap being undone displaced \
                     `{}`; agctl will not put back a credential it cannot match to that swap",
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
            if found8.as_deref() == Some(to_digest8) {
                return Err(AppError::Config(format!(
                    "the adopted copy in `{}` holds `{}`, which is the credential that swap \
                     wrote rather than the one it displaced; agctl will not put back a \
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

    // A reversal has no session to inherit a spelling from, so it uses the one
    // the record itself carries — which is byte-for-byte the string the
    // forward swap matched against, because that is how the record was chosen
    // in the first place. The guard it feeds is the same one: the namespace
    // agctl derives now must be the namespace the item was made for.
    let inherited = recorded_spelling(&store).to_owned();
    Ok(Reversal {
        which: Which::Namespace,
        store: Some(store),
        inherited,
        owner,
        source: Source::AdoptedCopy(store_dir),
        undone: None,
    })
}

/// A reversal of a swap against the **live** store (W4b §D4, §D5).
///
/// # Where the credential to put back is, and why it is found by digest
///
/// A live swap files the credential it displaces in **that credential's own
/// account's** namespace and nowhere else (§D5):
/// `<namespace(P)>/.credentials.json` for the ordinary row, and
/// `<namespace(T)>/.credentials.adopted.json` for task 4's keep arm, whose
/// displaced credential *is* the incoming account T's. The contract names the
/// second as `Source::AdoptedCopy(namespace(T))`; this finds both, because
/// neither account can be derived from the entry:
///
/// - `AuditEvent::Write` names the account a live forward swap *installed*
///   (`incoming_identity`, decision D-027) but not the one it displaced, and
///   the displaced credential is the one being put back;
/// - the only other witness, the live item (which holds T), would have to be
///   read **before** Phase A — a `security` child spawned ahead of refusal
///   **E**, which §D1 says spawns none, and a second item read ahead of Phase
///   A's single one.
///
/// So it looks for the credential by the one key the entry does carry, the
/// displaced digest prefix, in exactly the places §D5 can have filed it: the
/// `.credentials.json` and the adopted copy of every namespace an `Owned`
/// record claims, **counting a copy only when the credential belongs to that
/// record** (`swap::same_identity`). That condition is what "its own account's
/// namespace" means, and it keeps a copy parked anywhere else — a namespace
/// swap's D-024 sibling holding somebody else's credential — from being taken
/// for this swap's. Exactly one match proceeds, with that record as the owner;
/// none refuses, because there is nothing to put back; two refuse and name
/// both, because agctl will not guess which of them to write into the live
/// item. For task 4's keep arm the one match *is* the contract's
/// `Source::AdoptedCopy(namespace(T))`.
///
/// The namespaced path's `to_digest8` guard is subsumed rather than dropped:
/// matching `from_digest8` exactly is a stronger statement than "not
/// `to_digest8`".
///
/// # Whose credential the item holds (decision D-027)
///
/// The entry's `incoming_identity` — the account the swap installed — is carried
/// out as [`Reversal::undone`] with the outcome and both digests, for Phase A's
/// attribution and [`item_changed`]'s checks. An entry without it refuses here,
/// before any owned namespace is read: nothing else may say whose the item's
/// credential is, and `oauthAccount` in particular may not.
fn live_reversal(
    paths: &Paths,
    config: &AgctlConfig,
    from_digest8: Option<&str>,
    to_digest8: &str,
    outcome: audit::WriteOutcome,
    incoming_identity: Option<&audit::IncomingIdentity>,
    later_unknown_undo: Option<UnknownUndo>,
) -> Result<Reversal, AppError> {
    let Some(from_digest8) = from_digest8 else {
        // Unreachable through agctl's own writes: an absent live item refuses
        // in Phase A, so a live write always displaced something and always
        // records its prefix. A log that says otherwise has been edited, and
        // there is nothing to match a candidate against.
        return Err(AppError::Config(format!(
            "the live swap to undo recorded no displaced credential (it wrote `{to_digest8}`), \
             so agctl cannot tell which credential to put back"
        )));
    };

    let Some(installed) = incoming_identity else {
        return Err(AppError::Config(format!(
            "the live swap to undo does not record which account it installed (it wrote \
             `{to_digest8}`), so agctl cannot tell whose credential the live item holds and will \
             not guess"
        )));
    };

    let mut found: Vec<(AccountRecord, Source, PathBuf)> = Vec::new();
    for record in &config.accounts {
        if !matches!(record.kind, AccountKind::Owned { .. }) {
            continue;
        }
        let ns_dir = paths.namespace_dir(&record.account_uuid, &record.organization_uuid);
        let candidates = [
            (location::from_file(&ns_dir), Source::OwnStore, file_store::CREDENTIALS_FILE),
            (
                location::from_adopted(&ns_dir),
                Source::AdoptedCopy(ns_dir.clone()),
                file_store::ADOPTED_FILE,
            ),
        ];
        for (read, source, name) in candidates {
            let Resolved::Credentials(credentials) = read else { continue };
            let digest8 = audit::digest8(&credentials.digests().access_sha256);
            // Its own account's namespace and only that — see above.
            if digest8.as_deref() == Some(from_digest8) && swap::same_identity(&credentials, record)
            {
                found.push((record.clone(), source, ns_dir.join(name)));
            }
        }
    }

    let (owner, source) = match exactly_one(found) {
        Ok(Some((owner, source, _))) => (owner, source),
        Ok(None) => {
            return Err(AppError::Config(format!(
                "the credential that live swap displaced (`{from_digest8}`) is not in its own \
                 account's namespace in any store agctl owns, so there is nothing to put back; \
                 `agctl claude doctor` reports what each namespace holds"
            )));
        }
        Err([(_, _, where_it_is), (_, _, also)]) => {
            return Err(AppError::Config(format!(
                "the credential that live swap displaced (`{from_digest8}`) is in both `{}` and \
                 `{}`; agctl will not guess which of them to put back into the live item",
                where_it_is.display(),
                also.display()
            )));
        }
    };

    Ok(Reversal {
        which: Which::Live,
        store: None,
        inherited: String::new(),
        owner,
        source,
        undone: Some(UndoneEntry {
            installed: Identity {
                account_uuid: installed.account_uuid.clone(),
                organization_uuid: installed.organization_uuid.clone(),
                email: None,
                org_name: None,
            },
            outcome,
            from_digest8: from_digest8.to_owned(),
            to_digest8: to_digest8.to_owned(),
            later_unknown_undo,
        }),
    })
}

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
    let config = AgctlConfig::load(&paths)?;
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
