//! The live `~/.claude.json`'s one value-level read-modify-write: after an
//! applied live swap or undo, `oauthAccount` is replaced with the installed
//! account's profile and five stale caches are deleted (decision D-021, plan
//! AC75, spike S13's V8 and V14).
//!
//! # Why this is safe to do to a file Claude Code owns
//!
//! agctl writes it as a **peer** of the running sessions, under their own
//! configuration lock ([`config_lock`]), and every one of V8's five rules is a
//! structural property of this file rather than a promise:
//!
//! 1. **The lock** is `${configPath}.lock` beside the literal path, taken with
//!    nothing else held, and never broken.
//! 2. **A backup** in the peer's own name shape is written under the lock,
//!    before the temporary file, and never pruned (ruling G7).
//! 3. **The read is from disk, under the lock**, and the write refuses unless
//!    re-serialising the unmodified document reproduces its bytes exactly
//!    ([`reproduce`]). That one comparison is exposure 4′'s whole safety
//!    argument: `serde_json`'s `preserve_order` pretty writer reproduces
//!    `JSON.stringify(_, null, 2)` byte for byte (V14 (b)), so a document it
//!    reproduces is one in which every byte outside the allowlist is carried
//!    over unchanged — and a document it does not reproduce is left alone.
//! 4. **The link is followed and the target replaced**, by descriptor: a
//!    temporary file in the target's directory, the target's mode, `fsync`,
//!    `renameat`. `~/.claude.json` itself — a symbolic link on the reference
//!    machine — is never opened for writing, renamed or removed.
//! 5. **The hold is budgeted**: [`CONFIG_HOLD_BUDGET`] split into seven
//!    cumulative deadlines, and a term that cannot finish inside its deadline is
//!    not started.
//!
//! The allowlist is exactly one replacement and five deletions. Everything
//! else — `userID`, `mcpServers`, `projects`, every setting — is carried over
//! as the bytes it was.
//!
//! # What never leaves this file
//!
//! A document value. `serde_json`'s errors quote their input, so every
//! sentence here names a reason and a path, and every `tracing` field carries
//! a reason word; the profile's email and names reach the one `oauthAccount`
//! object and nothing else (S24a-R2(5)).

use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustix::fs::AtFlags;
use rustix::fs::FileType;
use rustix::fs::Mode;
use rustix::fs::OFlags;
use rustix::io::Errno;
use serde_json::Map;
use serde_json::Value;
use sha2::Digest;
use sha2::Sha256;

use crate::provider::claude::discovery::MAX_CLAUDE_JSON_BYTES;
use crate::provider::claude::namespace;
use crate::provider::claude::namespace::EnvView;
use crate::provider::claude::oauth::Profile;
use crate::runtime::coordinator::PassCtx;
use crate::secret::audit;
use crate::secret::audit::ConfigOutcome;
use crate::secret::audit::ConfigReason;
use crate::secret::audit::ConfigWriteRecord;
use crate::secret::audit::IncomingIdentity;
use crate::secret::claude_lock::CONFIG_HOLD_BUDGET;
use crate::secret::claude_lock::Clock;
use crate::secret::claude_lock::LockFs;
use crate::secret::claude_lock::RealFs;
use crate::secret::config_lock;
use crate::secret::config_lock::ConfigHold;
use crate::secret::config_lock::ConfigLockError;
use crate::secret::file_store;
use crate::secret::file_store::ReadOutcome;

/// The one key the rewrite replaces.
const OAUTH_ACCOUNT: &str = "oauthAccount";

/// The caches the rewrite deletes, because each was derived from the previous
/// account and every reader treats an absent one as "fetch" (spike S13, V9).
pub const STALE_CACHES: [&str; 5] = [
    "modelAccessCache",
    "orgModelDefaultCache",
    "cachedExtraUsageDisabledReason",
    "cachedUsageUtilization",
    "passesEligibilityCache",
];

/// What one config step did, in the audit log's vocabulary.
///
/// Ids, digest prefixes and a file name only: no path, no email, no document
/// value — which is what lets the whole value reach `--json` and the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigReport {
    /// How the step ended.
    pub outcome: ConfigOutcome,
    /// Why, when it did not apply.
    pub reason: Option<ConfigReason>,
    /// The ids written into `oauthAccount`, when a profile was in hand.
    pub account: Option<IncomingIdentity>,
    /// The first eight hex digits of the file's SHA-256 as it was read.
    pub from_sha8: Option<String>,
    /// The same, of the file as it was written; only on `applied`.
    pub to_sha8: Option<String>,
    /// The backup's file name, once one was written.
    pub backup: Option<String>,
    /// How long the configuration lock was held, when it was taken.
    pub hold_ms: Option<u64>,
}

impl ConfigReport {
    /// A step that deliberately did not run.
    pub fn not_attempted(reason: ConfigReason) -> Self {
        Self::ended(ConfigOutcome::NotAttempted, reason)
    }

    fn ended(outcome: ConfigOutcome, reason: ConfigReason) -> Self {
        Self { reason: Some(reason), ..Self::about(None, outcome) }
    }

    /// A report about `account` whose outcome is not decided yet.
    fn about(account: Option<IncomingIdentity>, outcome: ConfigOutcome) -> Self {
        Self {
            outcome,
            reason: None,
            account,
            from_sha8: None,
            to_sha8: None,
            backup: None,
            hold_ms: None,
        }
    }

    /// The reason the file was **not** updated, or `None` when it was.
    pub fn not_updated(&self) -> Option<ConfigReason> {
        if self.outcome == ConfigOutcome::Applied { None } else { self.reason }
    }

    /// The audit record, naming the `write` entry this step followed.
    pub fn record(&self, after: Option<String>) -> ConfigWriteRecord {
        ConfigWriteRecord {
            after,
            outcome: self.outcome,
            reason: self.reason,
            account: self.account.clone(),
            from_sha8: self.from_sha8.clone(),
            to_sha8: self.to_sha8.clone(),
            backup: self.backup.clone(),
            hold_ms: self.hold_ms,
        }
    }

    /// The `--json` member: `outcome`, `reason`, `backup`, `hold_ms` and
    /// `budget_ms`. No path, no account id, no email (§D14).
    pub fn json(&self) -> Value {
        serde_json::json!({
            "outcome": self.outcome,
            "reason": self.reason,
            "backup": self.backup,
            "hold_ms": self.hold_ms,
            "budget_ms": millis(CONFIG_HOLD_BUDGET),
        })
    }
}

/// Why the rewrite stopped, with the path it was about.
///
/// The sentence names the reason and the path and never a value from the
/// document.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("`{}` was not rewritten: {}", .path.display(), reason_phrase(.reason))]
pub struct ClaudeJsonError {
    outcome: ConfigOutcome,
    reason: ConfigReason,
    path: PathBuf,
}

/// Rewrites the live configuration file's `oauthAccount` from `profile` — the
/// only public writer of `.claude.json`, called only by `use`'s config step.
///
/// Step P (reads only, nothing held) and then the locked write; see the module
/// documentation for the rules and [`ConfigReport`] for what comes back. It
/// never fails: every way it can end is an outcome the caller records.
pub fn rmw(env: &EnvView, profile: &Profile, ctx: &PassCtx) -> ConfigReport {
    let report = match prepare(env, profile, jiff::Timestamp::now().as_millisecond()) {
        Ok(prepared) => {
            write_with(prepared, ctx, &Clock::system(), Arc::new(RealFs), &HoldHooks::default())
        }
        Err(stopped) => *stopped,
    };
    tracing::debug!(
        outcome = ?report.outcome,
        reason = ?report.reason,
        hold_ms = ?report.hold_ms,
        "the live configuration step ended"
    );
    report
}

/// The guard: the document as a key-ordered map, if and only if
/// `to_string_pretty` of the **unmodified** document reproduces `bytes`.
///
/// One comparison catches every shape `serde_json` and `JSON.stringify` would
/// disagree on — a trailing newline, CRLF, another indent, a `\uXXXX` or `\/`
/// escape, a number spelled other than `serde_json` writes it (`1e21`, which it
/// writes `1e+21` as JS does; `0.000001`, which it writes `1e-6`), a duplicate
/// key — and a lone surrogate or a BOM does not parse at all.
///
/// # Errors
///
/// [`ConfigReason::Unparseable`], [`ConfigReason::NotAnObject`] or
/// [`ConfigReason::NotReproducible`].
pub fn reproduce(bytes: &[u8]) -> Result<Map<String, Value>, ConfigReason> {
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return Err(ConfigReason::Unparseable);
    };
    let Value::Object(map) = value else { return Err(ConfigReason::NotAnObject) };
    match serde_json::to_string_pretty(&map) {
        Ok(text) if text.as_bytes() == bytes => Ok(map),
        _ => Err(ConfigReason::NotReproducible),
    }
}

/// The `oauthAccount` object Claude Code's start-up refresh builds from a
/// profile document (V14 (a), `$0n`/`Btt`): exactly these keys, in this order,
/// **replacing** the previous object rather than merging over it (S13-2).
///
/// A value whose JavaScript form would be `undefined` is omitted, as
/// `JSON.stringify` omits it; values are cloned, never re-typed.
pub fn build_oauth_account(profile: &Profile, now_ms: i64) -> Value {
    let block = |name: &str| profile.document.get(name);
    let (account, organization) = (block("account"), block("organization"));
    let member = |from: Option<&Value>, key: &str| from.and_then(|found| found.get(key)).cloned();
    // `x ?? fallback`: absent and `null` both fall back.
    let present =
        |from: Option<&Value>, key: &str| member(from, key).filter(|value| !value.is_null());

    let mut object = Map::new();
    object.insert("accountUuid".to_owned(), Value::from(profile.account_uuid.clone()));
    object.insert("emailAddress".to_owned(), Value::from(profile.email.clone()));
    object.insert("organizationUuid".to_owned(), Value::from(profile.organization_uuid.clone()));
    object.insert(
        "hasExtraUsageEnabled".to_owned(),
        present(organization, "has_extra_usage_enabled").unwrap_or(Value::Bool(false)),
    );
    if let Some(value) = present(organization, "billing_type") {
        object.insert("billingType".to_owned(), value);
    }
    // No `??` in the peer: an explicit `null` is written as `null`.
    if let Some(value) = member(account, "created_at") {
        object.insert("accountCreatedAt".to_owned(), value);
    }
    if let Some(value) = present(organization, "subscription_created_at") {
        object.insert("subscriptionCreatedAt".to_owned(), value);
    }
    object.insert(
        "ccOnboardingFlags".to_owned(),
        present(organization, "cc_onboarding_flags").unwrap_or_else(|| Value::Object(Map::new())),
    );
    for (key, source) in [
        ("claudeCodeTrialEndsAt", "claude_code_trial_ends_at"),
        ("claudeCodeTrialDurationDays", "claude_code_trial_duration_days"),
        ("seatTier", "seat_tier"),
    ] {
        object.insert(key.to_owned(), present(organization, source).unwrap_or(Value::Null));
    }
    // `...(x && { key: x })`: only a JavaScript-truthy value is written.
    for (key, source) in [("displayName", "display_name"), ("fullName", "full_name")] {
        if let Some(value) = member(account, source).filter(is_truthy) {
            object.insert(key.to_owned(), value);
        }
    }
    object.insert("profileFetchedAt".to_owned(), Value::from(now_ms));
    Value::Object(object)
}

/// JavaScript truthiness for a JSON value: `false`, `0`, `""` and `null` are
/// falsy; everything else, empty arrays and objects included, is truthy.
fn is_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|n| n != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

// ---------------------------------------------------------------------------
// The sentences (every sentence that names the file lives here, ruling N12)
// ---------------------------------------------------------------------------

/// The clause Phase B's question gains on the live target, so the one
/// confirmation covers both writes (decision D-026).
pub fn plan_line(shown: &str) -> String {
    format!(", and rewrite the account `{shown}` names")
}

/// What the completion line adds when the configuration file was rewritten:
/// running sessions reload it within a second (V13).
pub fn completion_clause() -> &'static str {
    "running sessions show the new account within a second; "
}

/// Decision D-030's sentence for an applied swap or undo whose config step did
/// not apply, without the `warning: ` prefix the terminal adds.
///
/// It names no command and promises no re-run: S24b-1 has no catch-up, so the
/// file stays as it is until something else rewrites it.
pub fn not_updated_warning(reason: ConfigReason, config_path: &Path, home: &Path) -> String {
    format!(
        "`{}` was not updated ({}); running sessions keep showing the previous account until the \
         next swap or undo, or a Claude Code `/login`",
        shown_path(config_path, home),
        reason_phrase(&reason)
    )
}

/// `path` with a leading `$HOME/` shown as `~/`, and control characters
/// escaped — the path comes from the environment.
pub fn shown_path(path: &Path, home: &Path) -> String {
    let text = match path.strip_prefix(home) {
        Ok(rest) if !home.as_os_str().is_empty() => format!("~/{}", rest.display()),
        _ => path.display().to_string(),
    };
    let mut shown = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() {
            shown.extend(c.escape_default());
        } else {
            shown.push(c);
        }
    }
    shown
}

/// One fixed phrase per reason (§D9).
fn reason_phrase(reason: &ConfigReason) -> &'static str {
    match reason {
        ConfigReason::Absent => "there is no such file",
        ConfigReason::Unreadable => "it could not be read as a regular file",
        ConfigReason::Unparseable => "it is not valid JSON",
        ConfigReason::NotAnObject => "its top level is not a JSON object",
        ConfigReason::NotReproducible => {
            "agctl could not reproduce its bytes exactly, so it did not rewrite it"
        }
        ConfigReason::BackupUnwritable => "agctl could not write a backup of it first",
        ConfigReason::LockBusy => "a Claude Code session held its config lock",
        ConfigReason::LockStale => "its config lock was left behind by a session that stopped",
        ConfigReason::Cancelled => "the run was cancelled before it could take the config lock",
        ConfigReason::ChangedUnderLock => "it changed while agctl held its config lock",
        ConfigReason::Compromised => "agctl's config lock was broken while it held it",
        ConfigReason::Budget => "the rewrite could not finish inside the config lock's time budget",
        ConfigReason::Io => "the rewrite could not be written",
        ConfigReason::ProfileUnavailable => {
            "the server could not be asked for that account's profile"
        }
        ConfigReason::SwapUnknown => "the swap's own outcome could not be confirmed",
        ConfigReason::Unrecognized => "for a reason this build does not know",
    }
}

// ---------------------------------------------------------------------------
// Step P: the pre-flight, outside every hold
// ---------------------------------------------------------------------------

/// Everything the locked write needs, resolved before the lock is taken.
struct Prepared {
    /// `Lt()`'s path, literal: the lock is beside it and the backup is named
    /// after its file name.
    config_path: PathBuf,
    /// The target's directory — `canonical(config_path)`'s parent, resolved
    /// once — which every later operation on the file is relative to.
    target_dir: Arc<OwnedFd>,
    /// The target's own file name inside `target_dir`.
    target_name: OsString,
    /// The peer's `backups/`, opened.
    backups: OwnedFd,
    /// The new `oauthAccount` object.
    account: Value,
    /// The step's report so far: the ids, and the digest of step P's read.
    report: ConfigReport,
}

/// Step P1–P6: read, guard, resolve, open, build. A document the guard cannot
/// reproduce is refused here, before any lock, so it costs a peer nothing.
fn prepare(env: &EnvView, profile: &Profile, now_ms: i64) -> Result<Prepared, Box<ConfigReport>> {
    let ids = IncomingIdentity {
        account_uuid: profile.account_uuid.clone(),
        organization_uuid: Some(profile.organization_uuid.clone()),
    };
    // `Applied` is a placeholder every path below overwrites: step P and L set
    // their own outcome, and the hold sets `Applied` only after the rename.
    let mut report = ConfigReport::about(Some(ids), ConfigOutcome::Applied);
    let stop = |mut report: ConfigReport, outcome, reason| {
        report.outcome = outcome;
        report.reason = Some(reason);
        Box::new(report)
    };

    let config_path = namespace::global_config_path(env);
    let bytes = match file_store::read_file_following(&config_path, MAX_CLAUDE_JSON_BYTES) {
        Ok(ReadOutcome::Absent) => {
            return Err(stop(report, ConfigOutcome::Skipped, ConfigReason::Absent));
        }
        Ok(ReadOutcome::Present { bytes, .. }) => bytes,
        Err(_) => return Err(stop(report, ConfigOutcome::Refused, ConfigReason::Unreadable)),
    };
    report.from_sha8 = sha8(&bytes);
    if let Err(reason) = reproduce(&bytes) {
        return Err(stop(report, ConfigOutcome::Refused, reason));
    }

    let target = namespace::canonical(&config_path).ok();
    let target_parts = target.as_deref().and_then(|target| {
        let dir = open_dir(target.parent()?).ok()?;
        Some((Arc::new(dir), target.file_name()?.to_os_string()))
    });
    let Some((target_dir, target_name)) = target_parts else {
        return Err(stop(report, ConfigOutcome::Refused, ConfigReason::Unreadable));
    };
    let Ok(backups) = open_backups(&namespace::backups_dir(env)) else {
        return Err(stop(report, ConfigOutcome::Refused, ConfigReason::BackupUnwritable));
    };
    Ok(Prepared {
        config_path,
        target_dir,
        target_name,
        backups,
        account: build_oauth_account(profile, now_ms),
        report,
    })
}

/// A directory, opened following links: the live layout reaches both the
/// target and `backups/` through a link by design.
fn open_dir(path: &Path) -> rustix::io::Result<OwnedFd> {
    rustix::fs::open(path, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty())
}

/// `backups/`, opened `O_NOFOLLOW` on its own name and created at 0700 when it
/// is absent.
fn open_backups(backups: &Path) -> rustix::io::Result<OwnedFd> {
    let (Some(home), Some(leaf)) = (backups.parent(), backups.file_name()) else {
        return Err(Errno::INVAL);
    };
    let home = open_dir(home)?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    match rustix::fs::openat(&home, leaf, flags, Mode::empty()) {
        Err(Errno::NOENT) => {
            rustix::fs::mkdirat(&home, leaf, Mode::RWXU)?;
            rustix::fs::openat(&home, leaf, flags, Mode::empty())
        }
        opened => opened,
    }
}

// ---------------------------------------------------------------------------
// L and H1–H7: the locked write
// ---------------------------------------------------------------------------

/// One term of the hold, with its share of [`CONFIG_HOLD_BUDGET`] (§D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Term {
    /// `mkdirat` of the lock and the `statat` of its mtime.
    Lock,
    /// H1: open, `fstat` and read the target.
    Read,
    /// H2 and H3: the guard, the transform and the serialisation.
    Transform,
    /// H4: the backup.
    Backup,
    /// H5: the temporary file.
    Temp,
    /// H6: the re-read, its digest and the drift check.
    Recheck,
    /// H7: the rename, the directory `fsync` and the release.
    Rename,
}

impl Term {
    /// This term's own budget.
    const fn budget(self) -> Duration {
        Duration::from_millis(match self {
            Self::Lock => 50,
            Self::Read | Self::Recheck => 150,
            Self::Transform => 200,
            Self::Backup => 250,
            Self::Temp => 300,
            Self::Rename => 100,
        })
    }

    /// The cumulative deadline this term must finish by.
    const fn deadline(self) -> Duration {
        Duration::from_millis(match self {
            Self::Lock => 50,
            Self::Read => 200,
            Self::Transform => 400,
            Self::Backup => 650,
            Self::Temp => 950,
            Self::Recheck => 1100,
            Self::Rename => 1200,
        })
    }
}

/// In-hold test hooks: closures private to this file, compiled only under
/// `cfg(test)` and zero-sized otherwise (ruling R-D). No fault or pause name
/// can reach the hold in any build.
#[derive(Default)]
struct HoldHooks {
    /// Runs after H5's temporary file is written, before H6's re-read.
    #[cfg(test)]
    after_temp: Option<Box<dyn Fn()>>,
    /// Runs before each term's budget gate.
    #[cfg(test)]
    before_term: Option<Box<dyn Fn(Term)>>,
}

impl HoldHooks {
    fn after_temp(&self) {
        #[cfg(test)]
        if let Some(hook) = &self.after_temp {
            hook();
        }
    }

    fn before_term(&self, term: Term) {
        #[cfg(test)]
        if let Some(hook) = &self.before_term {
            hook(term);
        }
        let _ = term;
    }
}

/// Takes the lock (L) and runs the hold. Production passes the system clock,
/// the real directory operations and no hooks; the unit tests pass their own.
fn write_with(
    prepared: Prepared,
    ctx: &PassCtx,
    clock: &Clock,
    fs: Arc<dyn LockFs>,
    hooks: &HoldHooks,
) -> ConfigReport {
    let lock = match config_lock::acquire(&prepared.config_path, clock, fs, ctx) {
        Ok(lock) => lock,
        Err(err) => {
            let (outcome, reason) = match err {
                ConfigLockError::Busy => (ConfigOutcome::Skipped, ConfigReason::LockBusy),
                ConfigLockError::Stale { .. } => (ConfigOutcome::Skipped, ConfigReason::LockStale),
                ConfigLockError::Cancelled => (ConfigOutcome::Skipped, ConfigReason::Cancelled),
                ConfigLockError::Compromised(_) => {
                    (ConfigOutcome::Aborted, ConfigReason::Compromised)
                }
                ConfigLockError::Unreachable { .. } | ConfigLockError::Io { .. } => {
                    (ConfigOutcome::Failed, ConfigReason::Io)
                }
            };
            return ConfigReport { outcome, reason: Some(reason), ..prepared.report };
        }
    };
    hold(prepared, lock, hooks)
}

/// Everything under the configuration lock, then the release.
///
/// Its parameters are the whole of what the hold can reach: the prepared
/// write, the lock, and the test hooks. No profile source, no cancellation and
/// no prompt — so nothing under the hold can wait on the network or a person.
fn hold(prepared: Prepared, lock: ConfigHold, hooks: &HoldHooks) -> ConfigReport {
    let mut report = prepared.report.clone();
    let ended = under_lock(&prepared, &lock, hooks, &mut report);
    let elapsed = lock.elapsed();
    lock.release();
    report.hold_ms = Some(millis(elapsed));
    match ended {
        Ok(()) => {
            report.outcome = ConfigOutcome::Applied;
            report.reason = None;
            if elapsed > CONFIG_HOLD_BUDGET {
                tracing::warn!(
                    hold_ms = millis(elapsed),
                    budget_ms = millis(CONFIG_HOLD_BUDGET),
                    "the configuration hold outlasted its budget after the rename"
                );
            }
        }
        Err(err) => {
            tracing::debug!(outcome = ?err.outcome, reason = ?err.reason, "the configuration rewrite stopped");
            report.outcome = err.outcome;
            report.reason = Some(err.reason);
        }
    }
    report
}

/// H1–H7, each behind its budget gate. Every exit after H5 has unlinked the
/// temporary file before it returns.
fn under_lock(
    p: &Prepared,
    lock: &ConfigHold,
    hooks: &HoldHooks,
    report: &mut ConfigReport,
) -> Result<(), ClaudeJsonError> {
    let stop = |outcome, reason| ClaudeJsonError { outcome, reason, path: p.config_path.clone() };

    // L cannot be gated before it starts — the hold begins with it — so it is
    // checked on completion, against the same cumulative deadline.
    gate(p, lock, hooks, Term::Lock)?;

    // H1: the file as it is under the lock, and its mode, from one descriptor.
    gate(p, lock, hooks, Term::Read)?;
    let Some((before, mode)) = read_target(p) else {
        return Err(stop(ConfigOutcome::Refused, ConfigReason::Unreadable));
    };
    let before_sha = Sha256::digest(&before);
    report.from_sha8 = sha8(&before);

    // H2 and H3: the guard again, then one replacement and five deletions.
    // `shift_remove` and never `remove`: under `preserve_order` the latter is
    // `swap_remove`, which moves the last top-level key into the hole (drift 9).
    gate(p, lock, hooks, Term::Transform)?;
    let mut document = reproduce(&before).map_err(|reason| stop(ConfigOutcome::Refused, reason))?;
    document.insert(OAUTH_ACCOUNT.to_owned(), p.account.clone());
    for key in STALE_CACHES {
        document.shift_remove(key);
    }
    let Ok(after) = serde_json::to_string_pretty(&document) else {
        return Err(stop(ConfigOutcome::Failed, ConfigReason::Io));
    };

    // H4: the backup, a byte copy of H1's read, before any temporary file.
    gate(p, lock, hooks, Term::Backup)?;
    report.backup = Some(
        write_backup(p, &before)
            .ok_or_else(|| stop(ConfigOutcome::Refused, ConfigReason::BackupUnwritable))?,
    );

    // H5: the temporary file, registered with the hold before it exists.
    gate(p, lock, hooks, Term::Temp)?;
    let temp = temp_name(&p.target_name);
    lock.track_temp(Arc::clone(&p.target_dir), temp.clone());
    match write_temp(p, &temp, after.as_bytes(), mode) {
        Ok(()) => {}
        Err(created) => {
            if created {
                remove_temp(p, lock, &temp);
            } else {
                lock.untrack_temp();
            }
            return Err(stop(ConfigOutcome::Failed, ConfigReason::Io));
        }
    }
    hooks.after_temp();

    // H6: only a lock-free writer can have changed the file; then the drift
    // check, immediately before the rename.
    let recheck = gate(p, lock, hooks, Term::Recheck)
        .and_then(|()| match read_target(p) {
            Some((now, _)) if Sha256::digest(&now) == before_sha => Ok(()),
            _ => Err(stop(ConfigOutcome::Aborted, ConfigReason::ChangedUnderLock)),
        })
        .and_then(|()| {
            lock.drift_check().map_err(|_| stop(ConfigOutcome::Aborted, ConfigReason::Compromised))
        })
        .and_then(|()| gate(p, lock, hooks, Term::Rename));
    if let Err(err) = recheck {
        remove_temp(p, lock, &temp);
        return Err(err);
    }

    // H7: the rename onto the target, relative to its directory. The link is
    // never an operand.
    if rustix::fs::renameat(&*p.target_dir, &temp, &*p.target_dir, &p.target_name).is_err() {
        remove_temp(p, lock, &temp);
        return Err(stop(ConfigOutcome::Failed, ConfigReason::Io));
    }
    lock.untrack_temp();
    if rustix::fs::fsync(&*p.target_dir).is_err() {
        // The rename has happened; nothing can be abandoned now.
        tracing::warn!("the configuration file's directory could not be flushed after the rename");
    }
    report.to_sha8 = sha8(after.as_bytes());
    Ok(())
}

/// A term is not started when the hold's elapsed time plus its budget would
/// pass its cumulative deadline; [`Term::Lock`] is checked on completion.
fn gate(
    p: &Prepared,
    lock: &ConfigHold,
    hooks: &HoldHooks,
    term: Term,
) -> Result<(), ClaudeJsonError> {
    hooks.before_term(term);
    let elapsed = lock.elapsed();
    let late = match term {
        Term::Lock => elapsed > term.deadline(),
        _ => elapsed.saturating_add(term.budget()) > term.deadline(),
    };
    if late {
        return Err(ClaudeJsonError {
            outcome: ConfigOutcome::Aborted,
            reason: ConfigReason::Budget,
            path: p.config_path.clone(),
        });
    }
    Ok(())
}

/// The target's bytes and permission bits, read through one `O_NOFOLLOW`
/// descriptor; `None` for anything but a regular file inside the size limit.
fn read_target(p: &Prepared) -> Option<(Vec<u8>, Mode)> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let fd = rustix::fs::openat(&*p.target_dir, &p.target_name, flags, Mode::empty()).ok()?;
    let stat = rustix::fs::fstat(&fd).ok()?;
    let size = u64::try_from(stat.st_size).ok()?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || size > MAX_CLAUDE_JSON_BYTES
    {
        return None;
    }
    let mut bytes = Vec::with_capacity(usize::try_from(size).ok()?);
    File::from(fd).take(MAX_CLAUDE_JSON_BYTES.saturating_add(1)).read_to_end(&mut bytes).ok()?;
    let within = u64::try_from(bytes.len()).is_ok_and(|len| len <= MAX_CLAUDE_JSON_BYTES);
    within.then(|| (bytes, Mode::from_bits_truncate(stat.st_mode)))
}

/// H4: `backups/<literal basename>.backup.<epoch ms>`, 0600, `O_EXCL`,
/// `fsync`ed; one retry at `ms + 1`. Returns the file name.
fn write_backup(p: &Prepared, before: &[u8]) -> Option<String> {
    let literal = p.config_path.file_name()?;
    let stamp = jiff::Timestamp::now().as_millisecond();
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    for ms in [stamp, stamp.saturating_add(1)] {
        let mut name = literal.to_os_string();
        name.push(format!(".backup.{ms}"));
        match rustix::fs::openat(&p.backups, &name, flags, Mode::RUSR | Mode::WUSR) {
            Ok(fd) => {
                let mut file = File::from(fd);
                file.write_all(before).ok()?;
                file.sync_all().ok()?;
                return name.into_string().ok();
            }
            Err(Errno::EXIST) => {}
            Err(_) => return None,
        }
    }
    None
}

/// The peer's temporary name: `<target>.tmp.<pid>.<12 lowercase hex>`.
fn temp_name(target_name: &OsString) -> OsString {
    let mut name = target_name.clone();
    name.push(format!(".tmp.{}.{}", std::process::id(), hex::encode(rand::random::<[u8; 6]>())));
    name
}

/// H5: create, write, take the target's mode, `fsync`. `Err(true)` when the
/// file was created and must be removed, `Err(false)` when it never existed.
fn write_temp(p: &Prepared, temp: &OsString, after: &[u8], mode: Mode) -> Result<(), bool> {
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let fd = rustix::fs::openat(&*p.target_dir, temp, flags, Mode::RUSR | Mode::WUSR)
        .map_err(|_| false)?;
    let mut file = File::from(fd);
    file.write_all(after).map_err(|_| true)?;
    rustix::fs::fchmod(&file, mode).map_err(|_| true)?;
    file.sync_all().map_err(|_| true)
}

/// Unlinks the temporary file — the only name this module ever unlinks — and
/// withdraws it from the hold.
fn remove_temp(p: &Prepared, lock: &ConfigHold, temp: &OsString) {
    let _ = rustix::fs::unlinkat(&*p.target_dir, temp, AtFlags::empty());
    lock.untrack_temp();
}

/// The first eight hex digits of `bytes`' SHA-256.
fn sha8(bytes: &[u8]) -> Option<String> {
    audit::digest8(&hex::encode(Sha256::digest(bytes)))
}

/// A `Duration` in whole milliseconds, saturating.
fn millis(of: Duration) -> u64 {
    u64::try_from(of.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
#[path = "claude_json_tests.rs"]
mod tests;
