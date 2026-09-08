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
//!    [`Paths::namespace_root`](crate::config::paths::Paths::namespace_root);
//! 2. it must not be in `.locks` — those are agentctl's own locks, which are
//!    never unlinked by anything (plan section 3.5);
//! 3. its file name must be `.oauth_refresh.lock`, `.storage-write`, or a
//!    legacy `<namespace>.lock`;
//! 4. it must be a regular file, reached without following a symbolic link;
//! 5. it must be older than [`STALE_MIN_AGE`];
//! 6. two samples [`STALE_SAMPLE_INTERVAL`] apart must show the same
//!    modification time — Claude Code's holders heartbeat every five seconds
//!    and derive `holderAlive` from exactly that comparison (fact F36), so an
//!    unchanged mtime across twelve seconds is the evidence that nobody is
//!    holding it;
//! 7. the risk must have been printed, and `--yes` given.
//!
//! Anything else is refused, including a path that satisfies six of the seven.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;

use crate::cli::DoctorArgs;
use crate::commands::Prompt;
use crate::commands::Tty;
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
use crate::runtime::coordinator::Cancel;
use crate::runtime::coordinator::PassCtx;
use crate::runtime::proc;
use crate::secret::KeychainReader;
use crate::secret::KeychainStatus;
use crate::secret::file_store;
use crate::secret::foreign_activity::REFRESH_LOCK;
use crate::secret::foreign_activity::STORAGE_WRITE_LOCK;
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
    out.extend(namespace_section(doctor, &config, io));

    out.push(String::new());
    out.extend(attention_section(doctor, &config, &found));

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
}

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

    io.tell(&format!(
        "Found {} Claude Code lock artefact(s); sampling again in {}s to tell a live holder \
         from a lapsed one…",
        artefacts.len(),
        doctor.sample_interval.as_secs()
    ));
    let alive = second_sample(&artefacts, doctor.sample_interval, doctor.cancel);

    for (artefact, holder_alive) in artefacts.iter().zip(alive) {
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
    Some(Artefact { path: path.to_path_buf(), age, mtime })
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

    if !doctor.paths.is_under_namespace_root(path) {
        return Err(refuse(format!(
            "`{}` is not inside `{}`; agentctl removes lock artefacts only inside its own \
             namespace root",
            path.display(),
            doctor.paths.namespace_root().display()
        )));
    }
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
    if !meta.is_file() {
        return Err(refuse(format!("`{}` is not a regular file", path.display())));
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

    // Not `fs::remove_file`. Every check above is lexical or an `lstat` of the
    // final component; none of them can see a symbolic link planted at
    // `<acct>` or `<org>`, and `remove_file` would follow it — turning the one
    // deletion agentctl is allowed to make into a deletion of whatever the
    // link points at, the live `~/.claude/.oauth_refresh.lock` being the
    // obvious target. This walks down from the namespace root with
    // `O_NOFOLLOW` and unlinks relative to the directory that walk produced.
    file_store::remove_file_under_root(doctor.paths, path).map_err(|err| match err {
        file_store::FileStoreError::RefusedSymlink(shown) => refuse(format!(
            "`{}` is reached through a symbolic link; agentctl will not delete through one",
            shown.display()
        )),
        file_store::FileStoreError::OutsideNamespaceRoot(shown) => refuse(format!(
            "`{}` does not resolve to a location inside `{}`",
            shown.display(),
            doctor.paths.namespace_root().display()
        )),
        other => AppError::Io {
            context: format!("could not remove `{}`", path.display()),
            source: std::io::Error::other(other.to_string()),
        },
    })?;
    io.tell(&format!("Removed `{}`.", path.display()));
    Ok(())
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

#[cfg(test)]
#[path = "doctor_tests.rs"]
mod tests;
