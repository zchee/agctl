//! `agentctl claude doctor` — what is actually on this machine, and one
//! carefully fenced way to clean up after Claude Code.
//!
//! The report is a read of the whole store: the keychain preflight, every
//! discovered row with its token expiries, the credentials on this machine
//! that belong to something else and are never read, the namespace locks and
//! who holds them, the artefacts a Claude Code session leaves behind, the
//! files a failed write leaves behind, and the four situations that are not
//! failures but are worth knowing about — a stale sibling, a forgotten
//! service, two rows holding the same credential, and a namespace still
//! called `_unknown-org`.
//!
//! # `--remove-stale` is the only thing in agentctl that deletes a lock
//!
//! Invariant I11 says agentctl never removes a lock artefact. This command is
//! the single exception, and it is fenced so tightly that it is easier to
//! state what it *will* do than what it will not:
//!
//! 1. the path must spell a location under
//!    [`Paths::namespace_root`](crate::config::paths::Paths::namespace_root),
//!    *or* be named by a held-lock record whose process is dead — see below;
//! 2. it must not be in `.locks` — those are agentctl's own locks, which are
//!    never unlinked by anything (plan section 3.5);
//! 3. its file name must be `.oauth_refresh.lock`, `.storage-write`, or a
//!    legacy `<namespace>.lock`;
//! 4. it must be a **directory**, reached without following a symbolic link:
//!    every Claude Code lock artefact is one, made by `mkdir` (fact F45). A
//!    regular file at one of those names was made by something else, and is
//!    reported as anomalous rather than removed;
//! 5. it must be older than [`STALE_MIN_AGE`];
//! 6. two samples [`STALE_SAMPLE_INTERVAL`] apart must show the same
//!    modification time — Claude Code's holders heartbeat every five seconds
//!    and derive `holderAlive` from exactly that comparison (fact F36), so an
//!    unchanged mtime across twelve seconds is the evidence that nobody is
//!    holding it;
//! 7. the risk must have been printed, and `--yes` given.
//!
//! Anything else is refused, including a path that satisfies six of the seven.
//!
//! # The one path outside the namespace root
//!
//! Rule 1 has an exception, and it is the only relaxation in this command:
//! when agentctl itself holds Claude Code's locks it writes a held-lock record
//! before the first `mkdir` (plan section 3.4 step 6), and a crash leaves that
//! record behind naming directories nothing will ever remove. Those
//! directories can be in the live `~/.claude` by construction, so refusing
//! every outside path would leave premortem PM9 — "every refresh said
//! `lock_busy` for an hour" — with no recovery command at all (architect N-2,
//! critic M1).
//!
//! So an outside path is accepted when, and only when, a record in
//! [`held_locks::dir`] names **that exact path** and the process that wrote it
//! is gone: [`proc::exists`] says no, or it is a zombie that
//! [`proc::holder`] calls [`Holder::Dead`](proc::Holder::Dead). A live pid, a
//! record naming a different path, and no record at all are each refused with
//! the same sentence phase 1 used. Rules 2 to 7 still apply, and the walk to
//! the artefact is anchored at the record's store directory's parent so every
//! component below it is still refused if it is a symbolic link.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;

use serde_json::Value;

use crate::cli::DoctorArgs;
use crate::commands::Prompt;
use crate::commands::Tty;
use crate::commands::isolate;
use crate::config::AccountKind;
use crate::config::AccountRecord;
use crate::config::AgentctlConfig;
use crate::config::paths::Paths;
use crate::config::paths::UNKNOWN_ORG;
use crate::error::AppError;
use crate::provider::claude::account::AccountState;
use crate::provider::claude::credentials::Credentials;
use crate::provider::claude::discovery;
use crate::provider::claude::namespace;
use crate::provider::claude::namespace::EnvView;
use crate::render::json;
use crate::runtime::coordinator::Cancel;
use crate::runtime::coordinator::PassCtx;
use crate::runtime::proc;
use crate::secret::KeychainReader;
use crate::secret::KeychainStatus;
use crate::secret::ServiceEntry;
use crate::secret::file_store;
use crate::secret::foreign_activity::REFRESH_LOCK;
use crate::secret::foreign_activity::STORAGE_WRITE_LOCK;
use crate::secret::held_locks;
use crate::secret::namespace_lock;
use crate::secret::namespace_lock::COMMAND_LOCK_TIMEOUT;

/// How old a lock artefact must be before `--remove-stale` will consider it.
///
/// Claude Code's own `proper-lockfile` staleness threshold (fact F36), so this
/// command is no more aggressive than the tool that wrote the file.
pub const STALE_MIN_AGE: Duration = Duration::from_secs(60);

/// How far apart the two staleness samples must be.
///
/// Holders heartbeat every five seconds (fact F31), so twelve seconds spans at
/// least two missed beats — enough that an unchanged modification time is
/// evidence rather than timing luck.
pub const STALE_SAMPLE_INTERVAL: Duration = Duration::from_secs(12);

/// The legacy lock's suffix: `<realpath(namespace)>.lock`, beside the
/// directory rather than inside it (fact F17).
pub const LEGACY_LOCK_SUFFIX: &str = ".lock";

/// Runs `agentctl claude doctor`.
///
/// # Errors
///
/// Returns [`AppError::Config`] when `--remove-stale` names something this
/// command will not remove, and [`AppError`] for a store that cannot be read.
pub fn run(config_dir: Option<&Path>, args: &DoctorArgs, cancel: &Cancel) -> Result<(), AppError> {
    let paths = Paths::resolve(config_dir)?;
    paths.ensure_dirs()?;
    let env = EnvView::from_process();
    let doctor =
        Doctor { paths: &paths, env: &env, cancel, sample_interval: STALE_SAMPLE_INTERVAL };
    let io = &mut Tty;

    if let Some(path) = args.remove_stale.as_deref() {
        return remove_stale(&doctor, path, args.yes, io);
    }

    let ctx = doctor.ctx();
    let reader = crate::secret::default_reader(&ctx);
    report(&doctor, reader.as_ref(), &ctx, io)
}

/// One `doctor` invocation.
pub struct Doctor<'a> {
    /// The store to examine.
    pub paths: &'a Paths,
    /// The environment the live entry's name comes from.
    pub env: &'a EnvView,
    /// The process-wide cancellation flag.
    pub cancel: &'a Cancel,
    /// How long to wait between the two staleness samples.
    ///
    /// [`STALE_SAMPLE_INTERVAL`] in production. Injectable because the rule it
    /// implements is a *twelve second* wait, and a test that proved it by
    /// waiting twelve seconds would be a test nobody runs.
    pub sample_interval: Duration,
}

impl Doctor<'_> {
    /// A context bounding the keychain reads this command spawns.
    fn ctx(&self) -> PassCtx {
        let now = Instant::now();
        PassCtx::standalone(
            self.cancel.clone(),
            now.checked_add(COMMAND_LOCK_TIMEOUT).unwrap_or(now),
        )
    }
}

// ---------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------

/// Builds and prints the whole report (plan AC45).
///
/// # Errors
///
/// Returns [`AppError`] when the registry cannot be read. Everything else is
/// reported as a line rather than raised: a `doctor` that refuses to run
/// because one thing is wrong is a `doctor` that cannot diagnose it.
pub fn report(
    doctor: &Doctor<'_>,
    reader: &dyn KeychainReader,
    ctx: &PassCtx,
    io: &mut dyn Prompt,
) -> Result<(), AppError> {
    let config = AgentctlConfig::load(doctor.paths)?;
    let found = discovery::discover(&config, doctor.paths, reader, doctor.env, ctx);

    let mut out = Vec::new();
    out.push("store".to_owned());
    out.push(format!("  config dir       {}", doctor.paths.config_dir().display()));
    out.push(format!("  namespace root   {}", doctor.paths.namespace_root().display()));
    out.push(format!("  registry         {}", state_of(&doctor.paths.config_file())));
    out.push(format!("  accounts         {} recorded", config.accounts.len()));

    out.push(String::new());
    out.push("keychain".to_owned());
    out.push(format!("  preflight        {}", preflight(&found.preflight)));
    out.push(format!("  live service     {}", namespace::service_name(doctor.env)));
    out.push(format!("  services listed  {}", found.listing.len()));

    out.push(String::new());
    out.push("accounts".to_owned());
    let mut forgotten = 0usize;
    for row in &found.rows {
        // Plan AC47: `accounts forget` means `status` and `doctor` stop
        // reporting the service, and this is `doctor`'s half of that. Counted
        // rather than silently dropped, so a user who forgot something and
        // then wondered where it went is told it is hidden and how to see it
        // — one line, naming nothing.
        if matches!(row.state, AccountState::Forgotten) {
            forgotten = forgotten.saturating_add(1);
            continue;
        }
        out.push(format!(
            "  {}  {}  kind={} source={} state={}",
            row.id,
            row.record.email.as_deref().unwrap_or("(no email)"),
            row.record.kind.name(),
            row.source.name(),
            row.state.label()
        ));
        if let Some(credentials) = row.credentials.as_ref() {
            out.push(format!("      {}", expiries(credentials)));
        }
    }
    if forgotten > 0 {
        out.push(format!(
            "  {forgotten} forgotten service(s) hidden; `accounts list --all` shows them"
        ));
    }

    out.push(String::new());
    out.extend(foreign_section(doctor.env, &found));

    out.push(String::new());
    out.extend(lock_section(doctor.paths, doctor.cancel));

    out.push(String::new());
    out.extend(held_locks_section(doctor));

    out.push(String::new());
    out.extend(namespace_section(doctor, &config, io));

    out.push(String::new());
    out.extend(attention_section(doctor, &config, &found));

    out.push(String::new());
    let isolation = collect_isolation(doctor, &config, &found.listing);
    out.extend(isolation_section(&isolation, &doctor.paths.session_root()));

    io.tell(&out.join("\n"));
    Ok(())
}

/// The credentials on this machine that belong to something else.
///
/// Listed because they are there and a user comparing `security dump-keychain`
/// against this report should not have to wonder whether agentctl is quietly
/// using them; named "never read" because that is the invariant. A
/// `claude-switcher:*` item is a third-party tool's (fact F10) and is not
/// opened even to learn whose it is — the address in the service name is the
/// only thing this section knows about it — and `CLAUDE_CODE_OAUTH_TOKEN`
/// short-circuits every credential store in Claude Code itself (fact F19),
/// which is worth saying out loud when a row elsewhere in this report looks
/// unaccountably healthy.
fn foreign_section(env: &EnvView, found: &discovery::Discovery) -> Vec<String> {
    let mut out = vec!["foreign items (never read)".to_owned()];
    let mut empty = true;

    for entry in &found.listing {
        if !entry.service.starts_with(crate::secret::SWITCHER_SERVICE_PREFIX) {
            continue;
        }
        empty = false;
        out.push(format!(
            "  {}  belongs to claude-switcher; agentctl never reads or writes it",
            entry.service
        ));
    }

    if env.oauth_token_set {
        empty = false;
        out.push(format!(
            "  {}  is set in the environment and short-circuits every credential store; \
             agentctl reports it and never reads its value",
            namespace::OAUTH_TOKEN_ENV
        ));
    }

    if empty {
        out.push("  none".to_owned());
    }
    out
}

/// What the keychain preflight found, as a sentence.
///
/// Written out rather than derived from `Debug`, because this line is the
/// first thing a user reads when a row says `keychain locked` and
/// `Unavailable("…")` is a Rust value, not an explanation.
fn preflight(status: &KeychainStatus) -> String {
    match status {
        KeychainStatus::Unlocked => "unlocked".to_owned(),
        KeychainStatus::Locked => {
            "locked — unlock the login keychain and run this again".to_owned()
        }
        KeychainStatus::Timeout => {
            "timed out — `security(1)` did not answer inside its budget".to_owned()
        }
        KeychainStatus::Unavailable(detail) => format!("unavailable ({detail})"),
    }
}

/// The two token expiries, with no token anywhere near them.
fn expiries(credentials: &Credentials) -> String {
    let now = jiff::Timestamp::now().as_millisecond();
    let access = relative(credentials.expires_at_ms, now);
    let refresh = credentials
        .refresh_token_expires_at_ms
        .map_or_else(|| "not recorded".to_owned(), |at| relative(at, now));
    format!("access {access}, refresh {refresh}")
}

/// A millisecond timestamp as "expired 3m ago" or "in 2h13m".
fn relative(at_ms: i64, now_ms: i64) -> String {
    let (Ok(at), Ok(now)) =
        (jiff::Timestamp::from_millisecond(at_ms), jiff::Timestamp::from_millisecond(now_ms))
    else {
        return format!("{at_ms} (not a usable timestamp)");
    };
    if at <= now {
        format!("expired {} ago", crate::usage::model::render_countdown(at, now))
    } else {
        format!("in {}", crate::usage::model::render_countdown(now, at))
    }
}

/// agentctl's own namespace locks, and who holds them.
fn lock_section(paths: &Paths, cancel: &Cancel) -> Vec<String> {
    let mut out = vec!["namespace locks".to_owned()];
    let locks_dir = paths.locks_dir();
    let Ok(entries) = fs::read_dir(&locks_dir) else {
        out.push(format!("  {} is not readable", locks_dir.display()));
        return out;
    };

    let mut paths_found: Vec<PathBuf> =
        entries.filter_map(Result::ok).map(|entry| entry.path()).collect();
    paths_found.sort();
    if paths_found.is_empty() {
        out.push("  none".to_owned());
        return out;
    }

    for path in paths_found {
        let name = path.file_name().map(|name| name.to_string_lossy().into_owned());
        let name = name.unwrap_or_else(|| path.display().to_string());
        match namespace_lock::read_body(&path) {
            Some(body) => {
                // A recycled process id is the failure this comparison exists
                // for: the pid may well be in use again by something entirely
                // unrelated, and reporting that as the lock holder would send
                // a user after the wrong process.
                let recycled = body.pid_start_time.as_ref().is_some_and(|recorded| {
                    proc::start_time(body.pid, cancel).as_ref() != Some(recorded)
                });
                let state = if recycled {
                    "dead (pid recycled)"
                } else {
                    proc::holder(body.pid, cancel).label()
                };
                out.push(format!(
                    "  {name}  pid {} ({state}), taken {}",
                    body.pid, body.acquired_at
                ));
            }
            None => out.push(format!(
                "  {name}  no readable body (never held, or held by an older build)"
            )),
        }
    }
    out
}

/// The locks agentctl itself took inside a Claude Code store, and whether the
/// process that took them is still there (plan section 3.9).
///
/// Claude Code's locks are directories, and nothing releases a directory when
/// a process dies — so the record agentctl writes before its first `mkdir` is
/// the only evidence a crash leaves. Two of the partial states in the plan's
/// contract are visible here and nowhere else: a record whose directories are
/// gone is stale and holds nothing, and a record whose directories are still
/// there with a dead pid is a leak this command can name a removal for, even
/// when the leak is outside the namespace root.
fn held_locks_section(doctor: &Doctor<'_>) -> Vec<String> {
    let mut out = vec!["held locks".to_owned()];
    let records = held_locks::read_all(doctor.paths);
    if records.is_empty() {
        out.push("  none".to_owned());
        return out;
    }

    for held in &records {
        let pid = held.record.agentctl_pid;
        let state = proc::holder(pid, doctor.cancel);
        // The same question `--remove-stale` asks, so the report cannot offer a
        // removal the command would refuse — or withhold one it would allow: a
        // recycled process id is alive without being the writer.
        let gone = held.record.writer_is_gone(doctor.cancel);
        out.push(format!(
            "  {}  pid {pid} ({}), {}, taken {}",
            held.file.display(),
            state.label(),
            held.record.tree.label(),
            held.record.taken_at
        ));

        let present: Vec<&PathBuf> =
            held.record.paths.iter().filter(|path| fs::symlink_metadata(path).is_ok()).collect();
        if present.is_empty() {
            out.push(
                "    the directories it names are gone: a stale record, holding nothing".to_owned(),
            );
            continue;
        }
        for path in present {
            if gone {
                out.push(format!(
                    "    {}  leaked — `doctor --remove-stale {} --yes` removes it",
                    path.display(),
                    path.display()
                ));
            } else {
                out.push(format!("    {}  held by pid {pid}", path.display()));
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Namespace artefacts, pending writes and stray temporaries
// ---------------------------------------------------------------------------

/// One Claude Code lock artefact found in or beside a namespace.
#[derive(Debug, Clone)]
pub struct Artefact {
    /// Where it is.
    pub path: PathBuf,
    /// How long ago it was last written.
    pub age: Duration,
    /// Its modification time, which is the heartbeat (fact F36).
    pub mtime: SystemTime,
    /// What is actually at that name.
    pub kind: ArtefactKind,
}

/// What is at an artefact's name, which decides whether it can be removed.
///
/// Claude Code acquires every one of its locks with `mkdir` and releases it
/// with `rmdir` (fact F45), so the only shape that can be a lapsed lock is a
/// directory. The other three are reported and left alone — and the regular
/// file is the interesting one, because phase 1 believed it was the *only*
/// removable shape and therefore removed nothing at all (`agentctl-nz5`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtefactKind {
    /// A directory: what Claude Code's `mkdir` makes.
    Directory,
    /// A regular file, which Claude Code never leaves at one of these names.
    RegularFile,
    /// A symbolic link, whatever it points at.
    Symlink,
    /// Something else again: a socket, a device, a fifo.
    Other,
}

impl ArtefactKind {
    /// How the report describes this shape.
    ///
    /// Only [`Self::Directory`] is a candidate; the rest say why they are not,
    /// because "agentctl found something here and said nothing about it" is
    /// how `agentctl-nz5` survived a whole phase.
    fn note(self) -> &'static str {
        match self {
            Self::Directory => "",
            Self::RegularFile => ANOMALOUS_REGULAR_FILE,
            Self::Symlink => "anomalous (a symbolic link — refused)",
            Self::Other => "anomalous (neither a directory nor a regular file — refused)",
        }
    }
}

/// What `doctor` says, in the report and in the refusal, about a regular file
/// sitting at an artefact's name.
///
/// One string in one place: the report line and `--remove-stale`'s refusal are
/// the same claim about the same file, and a user comparing them should not
/// have to wonder whether they mean the same thing.
pub const ANOMALOUS_REGULAR_FILE: &str =
    "anomalous (regular file; Claude Code makes lock directories)";

/// Everything owned namespaces have to say about themselves.
///
/// The two-sample pass runs only when at least one artefact was found, so the
/// common case — a machine with no Claude Code session in an agentctl
/// namespace — costs nothing. When one *is* found, the wait is announced
/// first, because twelve silent seconds look like a hang.
fn namespace_section(
    doctor: &Doctor<'_>,
    config: &AgentctlConfig,
    io: &mut dyn Prompt,
) -> Vec<String> {
    let owned: Vec<&AccountRecord> = config
        .accounts
        .iter()
        .filter(|rec| matches!(rec.kind, AccountKind::Owned { .. }))
        .collect();

    let mut out = vec!["namespaces".to_owned()];
    if owned.is_empty() {
        out.push("  none created by agentctl".to_owned());
        return out;
    }

    let mut artefacts: Vec<Artefact> = Vec::new();
    for record in &owned {
        let ns_dir = doctor.paths.namespace_dir(&record.account_uuid, &record.organization_uuid);
        out.push(format!("  {}", ns_dir.display()));
        out.push(format!(
            "    credentials    {}",
            state_of(&ns_dir.join(file_store::CREDENTIALS_FILE))
        ));

        let pending = ns_dir.join(file_store::PENDING_FILE);
        if fs::symlink_metadata(&pending).is_ok() {
            out.push(format!(
                "    pending write  {} — a refresh that could not be renamed into place; \
                 the next `status` resolves it",
                state_of(&pending)
            ));
            out.push(format!(
                "    pending meta   {}",
                state_of(&ns_dir.join(file_store::PENDING_META))
            ));
        }

        match file_store::list_stray_tmp(&ns_dir) {
            Ok(stray) if stray.is_empty() => {}
            Ok(stray) => {
                for path in stray {
                    out.push(format!(
                        "    stray tmp      {} — a crashed write; it holds token material at \
                         rest and `login` or `accounts remove` clears it",
                        path.display()
                    ));
                }
            }
            Err(err) => out.push(format!("    stray tmp      could not be listed: {err}")),
        }

        artefacts.extend(claude_artefacts(&ns_dir));
    }

    if artefacts.is_empty() {
        out.push("  no Claude Code lock artefacts".to_owned());
        return out;
    }

    // A lapsed lock is a directory, because that is the only thing Claude
    // Code's `mkdir`/`rmdir` protocol can leave (fact F45). Anything else at
    // one of those names is reported where it stands and never sampled: the
    // two-sample rule looks for a heartbeat, and nothing is beating here.
    let (candidates, anomalies): (Vec<Artefact>, Vec<Artefact>) =
        artefacts.into_iter().partition(|artefact| artefact.kind == ArtefactKind::Directory);
    for artefact in &anomalies {
        out.push(format!(
            "  {}  {} — agentctl refuses to refresh this namespace and will not remove it",
            artefact.path.display(),
            artefact.kind.note()
        ));
    }
    if candidates.is_empty() {
        return out;
    }

    io.tell(&format!(
        "Found {} Claude Code lock artefact(s); sampling again in {}s to tell a live holder \
         from a lapsed one…",
        candidates.len(),
        doctor.sample_interval.as_secs()
    ));
    let alive = second_sample(&candidates, doctor.sample_interval, doctor.cancel);

    for (artefact, holder_alive) in candidates.iter().zip(alive) {
        out.push(format!(
            "  {}  age {}s, holder {} — agentctl refuses to refresh this namespace{}",
            artefact.path.display(),
            artefact.age.as_secs(),
            if holder_alive { "alive (heartbeat seen)" } else { "not beating" },
            if holder_alive {
                String::new()
            } else {
                format!("; `doctor --remove-stale {} --yes` removes it", artefact.path.display())
            }
        ));
    }
    out
}

/// The three artefacts a Claude Code session leaves for one namespace.
///
/// Two inside it and one beside it, named after the resolved directory with
/// `.lock` appended (fact F17) — which is why the legacy one is looked for
/// under the canonical spelling rather than the one agentctl uses.
fn claude_artefacts(ns_dir: &Path) -> Vec<Artefact> {
    let mut out: Vec<Artefact> = [ns_dir.join(REFRESH_LOCK), ns_dir.join(STORAGE_WRITE_LOCK)]
        .iter()
        .filter_map(|path| sample(path))
        .collect();
    out.extend(legacy_lock(ns_dir));
    out
}

/// The legacy `<namespace>.lock`, found by its canonical spelling and reported
/// under its lexical one.
///
/// Those two differ whenever the store is reached through a symbolic link, and
/// on macOS that is the common case rather than the exotic one: `$TMPDIR`
/// lives under `/var`, which is a link to `/private/var`, and a `~/.config`
/// moved onto another volume behaves the same way. Reporting the canonical
/// spelling printed a `--remove-stale <path>` command that this very build
/// then refused, because [`remove_stale`]'s root check compares spellings and
/// the canonical one does not begin with the root as [`Paths`] spells it.
///
/// So: look under the canonical spelling, because that is where Claude Code
/// writes it (fact F17), and report the lexical one, because that is the
/// spelling a user can paste back. Both name the same file — only components
/// above the leaf are resolved, and a symbolic link at `<acct>` or `<org>` is
/// refused by everything that would act on the result.
fn legacy_lock(ns_dir: &Path) -> Option<Artefact> {
    let lexical = with_lock_suffix(ns_dir);
    let found = sample(&lexical).or_else(|| {
        let canonical = namespace::canonical(ns_dir).ok()?;
        sample(&with_lock_suffix(&canonical))
    })?;
    Some(Artefact { path: lexical, ..found })
}

/// `<path>.lock` — the legacy lock sits beside the directory, not inside it.
fn with_lock_suffix(dir: &Path) -> PathBuf {
    let mut name = dir.to_path_buf().into_os_string();
    name.push(LEGACY_LOCK_SUFFIX);
    PathBuf::from(name)
}

/// Reads one artefact's modification time and age.
///
/// A clock that has gone backwards saturates to a zero age rather than
/// wrapping: overflow checks are off in every profile (constraint C-006), and
/// a wrapped age would read as older than any threshold — which for
/// `--remove-stale` would mean deleting a file that was written a moment ago.
fn sample(path: &Path) -> Option<Artefact> {
    let meta = fs::symlink_metadata(path).ok()?;
    let mtime = meta.modified().ok()?;
    let age = SystemTime::now().duration_since(mtime).unwrap_or_default();
    let kind = if meta.file_type().is_symlink() {
        ArtefactKind::Symlink
    } else if meta.is_dir() {
        ArtefactKind::Directory
    } else if meta.is_file() {
        ArtefactKind::RegularFile
    } else {
        ArtefactKind::Other
    };
    Some(Artefact { path: path.to_path_buf(), age, mtime, kind })
}

/// Waits `interval`, re-samples, and reports which holders are still beating.
///
/// `holder_alive == mtime changed` is Claude Code's own rule (fact F36),
/// reproduced rather than invented: a holder that is running rewrites its lock
/// every five seconds, so a modification time that has not moved across this
/// interval means nothing is holding it.
fn second_sample(artefacts: &[Artefact], interval: Duration, cancel: &Cancel) -> Vec<bool> {
    // Waiting on the cancellation condvar rather than sleeping, so Ctrl-C ends
    // the wait at once instead of up to twelve seconds later.
    cancel.wait_timeout(interval);
    artefacts
        .iter()
        .map(|artefact| match sample(&artefact.path) {
            Some(now) => now.mtime != artefact.mtime,
            // Gone between the samples: whatever held it has finished with it,
            // which is the opposite of a live holder.
            None => false,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The four things that are not failures but are worth knowing
// ---------------------------------------------------------------------------

/// Stale siblings, forgotten services, duplicate credentials, `_unknown-org`
/// namespaces, and evidence of a second store (risks R20 and R25).
fn attention_section(
    doctor: &Doctor<'_>,
    config: &AgentctlConfig,
    found: &discovery::Discovery,
) -> Vec<String> {
    let mut out = vec!["worth knowing".to_owned()];
    let mut empty = true;

    for row in &found.rows {
        // Only the stale sibling is listed here. There is deliberately no
        // `Forgotten` arm: naming a hidden service in the one report a user
        // runs to find out what is on the machine would undo `accounts
        // forget`, so the accounts block above counts them instead.
        if matches!(row.state, AccountState::StaleSiblingOfLive) {
            empty = false;
            out.push(format!(
                "  {}  names the same directory as the live credential but holds different \
                 tokens; hidden by default, never merged",
                row.id
            ));
        }
    }
    for service in &config.forgotten_services {
        if !found.listing.iter().any(|entry| &entry.service == service) {
            empty = false;
            out.push(format!(
                "  {service}  is on the forgotten list but is not in the keychain any more; \
                 `accounts unforget` clears the entry"
            ));
        }
    }

    // Duplicates: the same access token under two names. Digests, never paths
    // — two names for one directory is normal on this machine (fact F41), and
    // two names for one *credential* is what actually matters.
    let mut by_digest: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for row in &found.rows {
        if let Some(credentials) = row.credentials.as_ref() {
            by_digest.entry(credentials.digests().access_sha256).or_default().push(row.id.clone());
        }
    }
    for (digest, ids) in by_digest.iter().filter(|(_, ids)| ids.len() > 1) {
        empty = false;
        let short: String = digest.chars().take(8).collect();
        out.push(format!(
            "  {}  hold the same access token (digest {short}…): one refresh rotates it out from \
             under the others",
            ids.join(", ")
        ));
    }

    for record in &config.accounts {
        // Only an owned namespace can be relocated, so only an owned one gets
        // the suggestion. A read-only keychain row is keyed
        // `<service>/_unknown-org` precisely because the item named nobody,
        // and `relocate` refuses it — advice that cannot be taken is worse
        // than none.
        if record.organization_uuid == UNKNOWN_ORG
            && matches!(record.kind, AccountKind::Owned { .. })
        {
            empty = false;
            out.push(format!(
                "  {}/{UNKNOWN_ORG}  the login could not name an organization; \
                 `accounts relocate {}` moves it once one is known",
                record.account_uuid, record.account_uuid
            ));
        }

        // Risk R20/R25: the spelling recorded at login is the string a Claude
        // Code session would hash into a keychain service name. If it is not
        // the spelling this store produces now, either the store moved or the
        // record was written by a *different* store — and two stores holding
        // one refresh chain are two holders (invariant I14).
        let AccountKind::Owned { export_spelling, export_sha8 } = &record.kind else { continue };
        let current = namespace::export_spelling(
            &doctor.paths.namespace_dir(&record.account_uuid, &record.organization_uuid),
        );
        if export_spelling != &current {
            empty = false;
            out.push(format!(
                "  {}/{}  was created as `{export_spelling}` but this store spells it \
                 `{current}`: the store moved, or another agentctl store holds the same account \
                 (risk R25)",
                record.account_uuid, record.organization_uuid
            ));
        }
        let migrated = format!("{}-{export_sha8}", namespace::LIVE_SERVICE);
        if found.listing.iter().any(|entry| entry.service == migrated) {
            empty = false;
            out.push(format!(
                "  {migrated}  a keychain item exists for this namespace: a Claude Code session \
                 has migrated it, and agentctl will not write the file again"
            ));
        }
    }

    if empty {
        out.push("  nothing".to_owned());
    }
    out
}

/// Whether a path is there, and what it is, without following a link.
fn state_of(path: &Path) -> String {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            format!("{} (a symbolic link — refused)", path.display())
        }
        Ok(meta) if meta.is_file() => format!("{} (present)", path.display()),
        Ok(_) => format!("{} (present, but not a regular file)", path.display()),
        Err(_) => format!("{} (absent)", path.display()),
    }
}

// ---------------------------------------------------------------------------
// --remove-stale
// ---------------------------------------------------------------------------

/// `doctor --remove-stale <path> --yes` (invariant I11, plan AC45).
///
/// # Errors
///
/// Returns [`AppError::Config`] for every path this command will not remove
/// and for a run without `--yes` — each of those exits 1, because the run
/// rendered nothing — and [`AppError::Io`] when the removal itself fails.
pub fn remove_stale(
    doctor: &Doctor<'_>,
    path: &Path,
    yes: bool,
    io: &mut dyn Prompt,
) -> Result<(), AppError> {
    // `Config`, not `Refused`: a refusal here renders no table, and the exit
    // contract reserves 2 for a run that produced output with a degraded row
    // in it. A `--remove-stale` that removed nothing produced nothing, so it
    // exits 1.
    let refuse = AppError::Config;

    let permit = permit_for(doctor, path)?;
    if path.parent() == Some(doctor.paths.locks_dir().as_path()) {
        return Err(refuse(format!(
            "`{}` is one of agentctl's own namespace locks. Those are never unlinked: `flock` \
             locks an inode, and a recreated lock file is a second inode two processes could \
             hold at once",
            path.display()
        )));
    }
    if !is_artefact_name(path) {
        return Err(refuse(format!(
            "`{}` is not a Claude Code lock artefact; only `{REFRESH_LOCK}`, \
             `{STORAGE_WRITE_LOCK}` and a legacy `<namespace>{LEGACY_LOCK_SUFFIX}` can be removed",
            path.display()
        )));
    }

    let meta = fs::symlink_metadata(path)
        .map_err(|err| refuse(format!("`{}` cannot be examined: {err}", path.display())))?;
    if meta.file_type().is_symlink() {
        return Err(refuse(format!(
            "`{}` is a symbolic link; agentctl will not delete through one",
            path.display()
        )));
    }
    if !meta.is_dir() {
        // `agentctl-nz5`: phase 1 had this the other way round, so it refused
        // every real artefact — and could not have removed one anyway, since
        // `unlinkat` without `AT_REMOVEDIR` does not remove directories.
        return Err(refuse(if meta.is_file() {
            format!(
                "`{}` is {ANOMALOUS_REGULAR_FILE}: every Claude Code lock artefact is a directory \
                 made by `mkdir` (fact F45), so a regular file at that name was written by \
                 something else and agentctl will not remove it",
                path.display()
            )
        } else {
            format!(
                "`{}` is not a directory, and every Claude Code lock artefact is one",
                path.display()
            )
        }));
    }

    let Some(first) = sample(path) else {
        return Err(refuse(format!("`{}` went away while it was being examined", path.display())));
    };
    if first.age < STALE_MIN_AGE {
        return Err(refuse(format!(
            "`{}` was written {}s ago, less than the {}s staleness threshold: a session that is \
             starting up looks exactly like this",
            path.display(),
            first.age.as_secs(),
            STALE_MIN_AGE.as_secs()
        )));
    }

    if let Permit::Attested { record, .. } = &permit {
        io.tell(&format!(
            "`{}` is outside `{}`. The held-lock record `{}` names it and the agentctl process \
             that wrote it is gone — that record is the only reason this removal is allowed.",
            path.display(),
            doctor.paths.namespace_root().display(),
            record.display()
        ));
    }

    io.tell(&format!(
        "About to remove `{}`.\n\
         This is Claude Code's lock, not agentctl's. If a session is holding it and its \
         heartbeat is merely slow, removing it lets two processes write that store at once, \
         which ends with one of them holding a refresh token the server has already rotated \
         — and a login lost.\n\
         Checking for a heartbeat: two samples {}s apart.",
        path.display(),
        doctor.sample_interval.as_secs()
    ));

    if !yes {
        return Err(refuse(format!(
            "`--yes` is required to remove `{}`; nothing was removed",
            path.display()
        )));
    }

    let holder_alive =
        second_sample(std::slice::from_ref(&first), doctor.sample_interval, doctor.cancel)
            .first()
            .copied()
            .unwrap_or(true);
    if holder_alive {
        return Err(refuse(format!(
            "`{}` was rewritten between the two samples, so something is holding it",
            path.display()
        )));
    }

    // Not `fs::remove_dir`. Every check above is lexical or an `lstat` of the
    // final component; none of them can see a symbolic link planted at
    // `<acct>` or `<org>`, and `remove_dir` would resolve the path afresh —
    // turning the one deletion agentctl is allowed to make into a deletion
    // somewhere else entirely, the live `~/.claude/.oauth_refresh.lock` being
    // the obvious target. This walks down from the permitted root with
    // `O_NOFOLLOW` and removes relative to the directory that walk produced,
    // with `AT_REMOVEDIR`, which refuses both a non-empty directory and
    // anything that is not a directory at all.
    let removal = match &permit {
        Permit::NamespaceRoot => file_store::remove_dir_under_root(doctor.paths, path),
        Permit::Attested { anchor, .. } => file_store::remove_dir_under(anchor, path),
    };
    removal.map_err(|err| match err {
        file_store::FileStoreError::RefusedSymlink(shown) => refuse(format!(
            "`{}` is reached through a symbolic link; agentctl will not delete through one",
            shown.display()
        )),
        file_store::FileStoreError::OutsideNamespaceRoot(shown) => refuse(format!(
            "`{}` does not resolve to a location inside `{}`",
            shown.display(),
            permit.walk_root(doctor.paths).display()
        )),
        file_store::FileStoreError::NotEmpty(shown) => refuse(format!(
            "`{}` has something in it, so it is not the empty directory a lapsed lock leaves \
             behind; agentctl removes one directory and never a tree",
            shown.display()
        )),
        file_store::FileStoreError::NotRegular(shown) => {
            refuse(format!("`{}` is no longer the directory it was a moment ago", shown.display()))
        }
        other => AppError::Io {
            context: format!("could not remove `{}`", path.display()),
            source: std::io::Error::other(other.to_string()),
        },
    })?;
    io.tell(&format!("Removed `{}`.", path.display()));
    Ok(())
}

/// Where a removal's `O_NOFOLLOW` walk starts, and why it is allowed at all.
enum Permit {
    /// The path is under [`Paths::namespace_root`]: phase 1's rule, and still
    /// the only one that needs no evidence beyond the path itself.
    NamespaceRoot,
    /// The path is outside it and a held-lock record whose process is dead
    /// names it (plan section 3.9, architect N-2).
    Attested {
        /// The record's store directory's parent, which is as far up as the
        /// record's evidence reaches.
        anchor: PathBuf,
        /// The record file, named in refusals so the evidence is inspectable.
        record: PathBuf,
    },
}

impl Permit {
    /// The directory the walk starts from, for the one error that names it.
    fn walk_root(&self, paths: &Paths) -> PathBuf {
        match self {
            Self::NamespaceRoot => paths.namespace_root(),
            Self::Attested { anchor, .. } => anchor.clone(),
        }
    }
}

/// Decides whether this path may be removed at all.
///
/// Runs before anything about the artefact itself is examined, because the
/// question it answers — *is this store's, or somebody else's?* — is the one
/// invariant I11′ is about.
///
/// # Errors
///
/// [`AppError::Config`] with phase 1's sentence for a path outside the
/// namespace root that no held-lock record vouches for, and a sentence naming
/// the live process for one that a record names while its process is still
/// running.
fn permit_for(doctor: &Doctor<'_>, path: &Path) -> Result<Permit, AppError> {
    if doctor.paths.is_under_namespace_root(path) {
        return Ok(Permit::NamespaceRoot);
    }

    let outside = || {
        AppError::Config(format!(
            "`{}` is not inside `{}`; agentctl removes lock artefacts only inside its own \
             namespace root",
            path.display(),
            doctor.paths.namespace_root().display()
        ))
    };

    // Every record naming this exact path, not just the first: a store can
    // hold a stale record beside a current one, and it is the *dead* pid that
    // makes a leak recoverable.
    let attesting: Vec<held_locks::HeldLockFile> = held_locks::read_all(doctor.paths)
        .into_iter()
        .filter(|held| held.record.attests(path))
        .collect();
    if attesting.is_empty() {
        return Err(outside());
    }

    for held in &attesting {
        // `writer_is_gone` answers yes for a pid that is gone, for a zombie —
        // which has already exited, so it is holding nothing and never will
        // again — and for a pid the kernel has since handed to a different
        // process, which the recorded start time is what detects.
        if !held.record.writer_is_gone(doctor.cancel) {
            continue;
        }
        let Some(anchor) = held.record.anchor() else { continue };
        return Ok(Permit::Attested { anchor: anchor.to_path_buf(), record: held.file.clone() });
    }

    let held = attesting.first().ok_or_else(outside)?;
    Err(AppError::Config(format!(
        "`{}` is named by the held-lock record `{}`, but agentctl process {} is {} — that lock \
         is being held, not leaked",
        path.display(),
        held.file.display(),
        held.record.agentctl_pid,
        proc::holder(held.record.agentctl_pid, doctor.cancel).label()
    )))
}

/// Whether a path's file name is one of the three artefacts (fact F17, F37).
fn is_artefact_name(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else { return false };
    if name == REFRESH_LOCK || name == STORAGE_WRITE_LOCK {
        return true;
    }
    // The legacy lock is `<namespace directory>.lock`, so a bare `.lock` with
    // nothing in front of it is not one.
    name.len() > LEGACY_LOCK_SUFFIX.len() && name.ends_with(LEGACY_LOCK_SUFFIX)
}

// ---------------------------------------------------------------------------
// Isolation (plan AC58)
// ---------------------------------------------------------------------------

/// Where a macOS device profile can force Claude Code settings machine-wide
/// (fact from `.omc/handoffs/w0-s11.md` item 2).
pub const MANAGED_SETTINGS_PATH: &str =
    "/Library/Application Support/ClaudeCode/managed-settings.json";

/// Everything the isolation section reports, collected once and rendered
/// twice: as the lines [`isolation_section`] prints, and as the
/// [`json::IsolationRow`]/[`json::IsolationPolicy`] values a future
/// `doctor --json` would serialize verbatim.
struct IsolationData {
    rows: Vec<json::IsolationRow>,
    policy: json::IsolationPolicy,
}

/// The two facts about the wider store every session's row needs beyond its
/// own identity, grouped so [`isolation_row`] stays under clippy's
/// argument-count limit.
struct IsolationContext<'a> {
    /// Top-level entries of the live config directory that are on neither
    /// allowlist, sorted.
    unexposed: &'a [String],
    /// This pass's keychain listing, for the migration probe — the same one
    /// `attention_section` already has from discovery, passed in rather
    /// than re-fetched.
    listing: &'a [ServiceEntry],
}

/// Builds [`IsolationData`] for every session directory under
/// `session_root()`.
fn collect_isolation(
    doctor: &Doctor<'_>,
    config: &AgentctlConfig,
    listing: &[ServiceEntry],
) -> IsolationData {
    let paths = doctor.paths;
    let env = doctor.env;

    let live_dir = namespace::live_store_dir(env);
    let unexposed = unexposed_entries(&live_dir);
    let ctx = IsolationContext { unexposed: &unexposed, listing };

    let rows = discover_sessions(&paths.session_root())
        .into_iter()
        .map(|(acct, org, dir)| isolation_row(paths, config, env, &acct, &org, &dir, &ctx))
        .collect();

    let policy = isolation_policy(env);
    IsolationData { rows, policy }
}

/// Every `<acct>/<org>` directory under `session_root()`, sorted.
///
/// Nothing else is discoverable: a `--claude-config-dir` override lands
/// wherever the caller pointed it, and this command has no way to enumerate
/// those.
fn discover_sessions(session_root: &Path) -> Vec<(String, String, PathBuf)> {
    let mut found = Vec::new();
    let Ok(acct_entries) = fs::read_dir(session_root) else {
        return found;
    };

    let mut acct_dirs: Vec<PathBuf> = acct_entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|p| p.is_dir())
        .collect();
    acct_dirs.sort();

    for acct_dir in acct_dirs {
        let Some(acct) = acct_dir.file_name().and_then(|name| name.to_str()) else { continue };
        let Ok(org_entries) = fs::read_dir(&acct_dir) else { continue };
        let mut org_dirs: Vec<PathBuf> = org_entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|p| p.is_dir())
            .collect();
        org_dirs.sort();

        for org_dir in org_dirs {
            let Some(org) = org_dir.file_name().and_then(|name| name.to_str()) else { continue };
            found.push((acct.to_owned(), org.to_owned(), org_dir));
        }
    }
    found
}

/// One session directory's row.
fn isolation_row(
    paths: &Paths,
    config: &AgentctlConfig,
    env: &EnvView,
    acct: &str,
    org: &str,
    session_dir: &Path,
    ctx: &IsolationContext<'_>,
) -> json::IsolationRow {
    let registered = config.get(acct, org);
    let id = registered
        .map(|rec| rec.display_id(&config.accounts))
        .unwrap_or_else(|| "unregistered".to_owned());
    let forget_target =
        if registered.is_some() { id.clone() } else { session_dir.display().to_string() };

    // Plan AC58's "migration state" clause: the same probe
    // `attention_section` runs for a registered `Owned` account — a
    // `claude-code-<sha8>` keychain item existing for the namespace means a
    // session has migrated it — computed alongside `sha8_match` since both
    // read the same `export_sha8`.
    let (securestorage_dir, sha8_match, migrated) = match registered.map(|rec| &rec.kind) {
        Some(AccountKind::Owned { export_spelling, export_sha8 }) => {
            let migrated_service = format!("{}-{export_sha8}", namespace::LIVE_SERVICE);
            (
                export_spelling.clone(),
                &namespace::sha8(export_spelling) == export_sha8,
                ctx.listing.iter().any(|entry| entry.service == migrated_service),
            )
        }
        _ => (namespace::export_spelling(&paths.namespace_dir(acct, org)), false, false),
    };

    let live_dir = namespace::live_store_dir(env);
    let live_claude_json = namespace::claude_json_path(env);

    let mut links = Vec::with_capacity(isolate::TIER1.len() + isolate::TIER2_DIRS.len() + 2);
    for name in isolate::TIER1 {
        links.push(link_entry(session_dir, name, "tier1", &live_dir.join(name)));
    }
    for name in isolate::TIER2_DIRS {
        links.push(link_entry(session_dir, name, "tier2", &live_dir.join(name)));
    }
    let mcp_link = link_entry(session_dir, isolate::MCP_LINK, "mcp", &live_claude_json);
    let mcp = mcp_details(session_dir, &mcp_link);
    links.push(mcp_link);
    links.push(seed_link_entry(session_dir));

    let (seeded_keys, leaked_keys) = seed_keys(session_dir);
    let drift = drift_of(&live_claude_json, session_dir);

    json::IsolationRow {
        id,
        path: session_dir.display().to_string(),
        exports: json::IsolationExports {
            securestorage_dir,
            config_dir: session_dir.display().to_string(),
            sha8_match,
        },
        links,
        seeded_keys,
        leaked_keys,
        unexposed: ctx.unexposed.to_vec(),
        mcp,
        drift,
        migrated,
        forget_command: format!("agentctl claude use --forget {forget_target}"),
    }
}

/// One allowlisted entry's symlink state, at `session_dir/name`.
///
/// `linked` requires the entry to be a symlink whose fully resolved target
/// equals `canonical(expected_live_path)` — not merely *a* symlink, which is
/// what makes an entry someone else placed there `occupied` rather than
/// `linked`.
fn link_entry(
    session_dir: &Path,
    name: &str,
    tier: &'static str,
    expected_live_path: &Path,
) -> json::IsolationLink {
    let entry_path = session_dir.join(name);
    let expected_canonical = namespace::canonical(expected_live_path).ok();

    let (state, target) = match fs::symlink_metadata(&entry_path) {
        Err(_) => ("absent", None),
        Ok(meta) if meta.file_type().is_symlink() => {
            let raw_target = fs::read_link(&entry_path).ok().map(|t| t.display().to_string());
            let resolved = namespace::canonical(&entry_path).ok();
            let state = match (&resolved, &expected_canonical) {
                (None, _) => "missing-target",
                (Some(resolved), Some(expected)) if resolved == expected => "linked",
                _ => "occupied",
            };
            (state, raw_target)
        }
        Ok(_) => ("occupied", None),
    };

    json::IsolationLink { name: name.to_owned(), tier, state, target }
}

/// The seeded `.claude.json`'s own row: `seeded` | `occupied` | `absent`.
///
/// A sibling of [`link_entry`] rather than a call to it: the seed is never
/// expected to be a symlink at all (invariant I18, and P1-1's tightening of
/// `write_seed_file`), so this reports whether a plain file is there rather
/// than whether a symlink resolves correctly. `target` is always `None`.
fn seed_link_entry(session_dir: &Path) -> json::IsolationLink {
    let seed_path = session_dir.join(isolate::SEED_FILE);
    let state = match fs::symlink_metadata(&seed_path) {
        Err(_) => "absent",
        Ok(meta) if meta.is_file() => "seeded",
        Ok(_) => "occupied",
    };
    json::IsolationLink { name: isolate::SEED_FILE.to_owned(), tier: "seed", state, target: None }
}

/// The D-019 MCP symlink's credential count, reusing the state
/// [`link_entry`] already computed for it.
fn mcp_details(session_dir: &Path, mcp_link: &json::IsolationLink) -> json::IsolationMcp {
    let mcp_path = session_dir.join(isolate::MCP_LINK);
    let linked =
        matches!(fs::symlink_metadata(&mcp_path), Ok(meta) if meta.file_type().is_symlink());

    let credential_entries = if linked {
        match file_store::read_file_following(&mcp_path, discovery::MAX_CLAUDE_JSON_BYTES) {
            Ok(file_store::ReadOutcome::Present { bytes, .. }) => count_mcp_credentials(&bytes),
            _ => None,
        }
    } else {
        None
    };

    json::IsolationMcp { linked, target: mcp_link.target.clone(), credential_entries }
}

/// How many `mcpServers` entries carry a non-empty `env` or `headers` object.
///
/// `None` only on a JSON parse failure — an absent or malformed `mcpServers`
/// key in an otherwise valid document is zero servers, not an error (D-019
/// exposure 3: a count, never a key name or a value).
fn count_mcp_credentials(bytes: &[u8]) -> Option<u32> {
    let value: Value = serde_json::from_slice(bytes).ok()?;
    let count = value
        .get("mcpServers")
        .and_then(Value::as_object)
        .map(|servers| servers.values().filter(|entry| has_credential_fields(entry)).count())
        .unwrap_or(0);
    u32::try_from(count).ok()
}

/// Whether one `mcpServers` entry carries a non-empty `env` or `headers`
/// object.
fn has_credential_fields(entry: &Value) -> bool {
    let Some(obj) = entry.as_object() else { return false };
    ["env", "headers"]
        .iter()
        .any(|key| obj.get(*key).and_then(Value::as_object).is_some_and(|map| !map.is_empty()))
}

/// The seeded `.claude.json`'s key set, and which of those keys leaked from
/// [`isolate::NEVER_SEED`].
fn seed_keys(session_dir: &Path) -> (Vec<String>, Vec<String>) {
    let seed_path = session_dir.join(".claude.json");
    let bytes = match file_store::read_file(&seed_path, discovery::MAX_CLAUDE_JSON_BYTES) {
        Ok(file_store::ReadOutcome::Present { bytes, .. }) => bytes,
        _ => return (Vec::new(), Vec::new()),
    };
    let Ok(Value::Object(map)) = serde_json::from_slice::<Value>(&bytes) else {
        return (Vec::new(), Vec::new());
    };

    let mut seeded: Vec<String> = map.keys().cloned().collect();
    seeded.sort();
    let leaked: Vec<String> =
        seeded.iter().filter(|key| isolate::NEVER_SEED.contains(&key.as_str())).cloned().collect();
    (seeded, leaked)
}

/// Top-level entries of the live config directory that are on neither
/// allowlist (plan section 3.3's tier rule; tier 3 is "everything else").
fn unexposed_entries(live_dir: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(live_dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
        .filter(|name| {
            !isolate::TIER1.contains(&name.as_str())
                && !isolate::TIER2_DIRS.contains(&name.as_str())
                && !isolate::NEVER_LINKED.contains(&name.as_str())
        })
        .collect();
    names.sort();
    names
}

/// The live `.claude.json`'s modification time against the seed's.
fn drift_of(live_claude_json: &Path, session_dir: &Path) -> json::IsolationDrift {
    let seed_path = session_dir.join(".claude.json");
    let live_mtime_ms = mtime_ms(live_claude_json);
    let seed_mtime_ms = mtime_ms(&seed_path);
    let changed_since_seed = matches!(
        (live_mtime_ms, seed_mtime_ms),
        (Some(live), Some(seed)) if live > seed
    );
    json::IsolationDrift { live_mtime_ms, seed_mtime_ms, changed_since_seed }
}

/// A path's modification time, milliseconds since the epoch.
fn mtime_ms(path: &Path) -> Option<i64> {
    let meta = fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    let since_epoch = modified.duration_since(std::time::UNIX_EPOCH).ok()?;
    i64::try_from(since_epoch.as_millis()).ok()
}

/// The two D-019/D-020 machine-wide facts.
fn isolation_policy(env: &EnvView) -> json::IsolationPolicy {
    let live_settings = namespace::live_store_dir(env).join("settings.json");
    let managed_settings = PathBuf::from(MANAGED_SETTINGS_PATH);
    json::IsolationPolicy {
        disable_sideload_flags: disable_sideload_flags(&live_settings, &managed_settings),
        backend_observable: false,
    }
}

/// Reads `policySettings.disableSideloadFlags` out of both files, `true` from
/// either winning over `false`, and both absent or silent yielding `None`.
///
/// A pure function of two paths rather than one reading
/// [`MANAGED_SETTINGS_PATH`] itself, so a unit test can point both arguments
/// at fixtures instead of the real machine's profile location.
fn disable_sideload_flags(live_settings: &Path, managed_settings: &Path) -> Option<bool> {
    let live = read_disable_flag(live_settings);
    let managed = read_disable_flag(managed_settings);
    match (live, managed) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (Some(false), _) | (_, Some(false)) => Some(false),
        _ => None,
    }
}

/// `policySettings.disableSideloadFlags` out of one settings file, if it
/// exists, parses, and sets it.
fn read_disable_flag(path: &Path) -> Option<bool> {
    let bytes = fs::read(path).ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    value.get("policySettings")?.get("disableSideloadFlags")?.as_bool()
}

/// Renders [`IsolationData`] as the lines `doctor`'s report prints.
///
/// Always printed — `DoctorArgs` has no flag gating this section, so a run
/// with no isolated sessions still states that plainly, and the two
/// machine-wide facts print regardless of how many sessions exist.
fn isolation_section(data: &IsolationData, session_root: &Path) -> Vec<String> {
    let mut out = vec!["isolation".to_owned()];

    if data.rows.is_empty() {
        out.push(format!("  {} has no isolated sessions", session_root.display()));
    }

    for row in &data.rows {
        out.push(format!("  {}  id={}", row.path, row.id));
        out.push(format!(
            "    exports          CLAUDE_SECURESTORAGE_CONFIG_DIR={} CLAUDE_CONFIG_DIR={} \
             sha8_match={} migrated={}",
            row.exports.securestorage_dir,
            row.exports.config_dir,
            row.exports.sha8_match,
            row.migrated
        ));
        for link in &row.links {
            match &link.target {
                Some(target) => out.push(format!(
                    "    {:<14} {:<5} {:<14} -> {target}",
                    link.name, link.tier, link.state
                )),
                None => {
                    out.push(format!("    {:<14} {:<5} {}", link.name, link.tier, link.state));
                }
            }
        }
        out.push(format!(
            "    unexposed        {}",
            if row.unexposed.is_empty() { "none".to_owned() } else { row.unexposed.join(", ") }
        ));
        out.push(format!(
            "    seeded keys      {}",
            if row.seeded_keys.is_empty() {
                "not seeded".to_owned()
            } else {
                row.seeded_keys.join(", ")
            }
        ));
        if row.leaked_keys.is_empty() {
            out.push("    leaked keys      none".to_owned());
        } else {
            out.push(format!(
                "    leaked keys      {}  — must never appear in a seeded `.claude.json`",
                row.leaked_keys.join(", ")
            ));
        }
        out.push(format!(
            "    mcp              linked={} target={} credential_entries={}",
            row.mcp.linked,
            row.mcp.target.as_deref().unwrap_or("(none)"),
            row.mcp.credential_entries.map_or_else(|| "unreadable".to_owned(), |n| n.to_string()),
        ));
        out.push(format!(
            "    drift            live_mtime_ms={:?} seed_mtime_ms={:?} changed_since_seed={}",
            row.drift.live_mtime_ms, row.drift.seed_mtime_ms, row.drift.changed_since_seed
        ));
        out.push(format!("    forget           {}", row.forget_command));
    }

    out.push(format!(
        "  policySettings.disableSideloadFlags   {}",
        match data.policy.disable_sideload_flags {
            Some(true) => "true — `--mcp-config` is refused by managed settings; isolated \
                           sessions will start without MCP"
                .to_owned(),
            Some(false) => "false".to_owned(),
            None => "not set".to_owned(),
        }
    ));
    out.push(
        "  secure-storage backend: not independently observable from outside a session \
         (environment-only); as verified, this build's backend factory is a stub, so none is \
         active — see docs/re-verify.md"
            .to_owned(),
    );

    out
}

#[cfg(test)]
#[path = "doctor_tests.rs"]
mod tests;
