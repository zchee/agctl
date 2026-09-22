//! The append-only audit log: every keychain write, every lock break, every
//! *abandoned* lock break.
//!
//! Invariant I16 asks for two things this module provides and nothing else
//! does: that every dangerous act phase 2 performs leaves a record, and that
//! the record is explainable afterwards by `doctor` and reversible by
//! `use --undo`. Fact F45's lock artefacts are directories the kernel releases
//! nothing on death, and a keychain write has no rename to undo — so a line in
//! this file is, quite literally, the only evidence a crashed swap leaves
//! behind.
//!
//! # What it is not
//!
//! It is **not** a place secrets live (risk R34). An entry carries digest
//! *prefixes* — eight hex digits of a SHA-256 — and [`append`] refuses an
//! entry whose digest fields are anything else, so a caller that passed a
//! whole digest, or a token, is a failed write rather than a leak. Nothing
//! here holds a token, a hex-encoded blob, or an environment value.
//!
//! # Shape
//!
//! One JSON object per line, `O_APPEND`, mode 0600, `fsync` per entry, at
//! `<config_dir>/claude/keychain-writes.jsonl`. One `write` syscall per entry
//! keeps two agctl processes from interleaving half-lines. The log is
//! reached through the same `O_NOFOLLOW` walk the held-lock records are
//! ([`open_log_dir`], `agctl-9je`): it sits in `held-locks`' own directory, so
//! whoever could plant that name could otherwise redirect the record of the
//! break — and a mode that is not 0600 is refused rather than repaired, and
//! named by `doctor` through [`log_state`].
//!
//! The provenance fields — `ts`, `monotonic_ms`, `agctl_pid` — come first and
//! belong to *this* process; the plan moved `agctl_pid` up here precisely
//! so it cannot be read as the pid of somebody else's lock holder (ledger
//! #70), which the vocabulary in [`HolderEvidence`] never names.

#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the audit log lands in W2 with no caller; W3 and W4 append, doctor and `use --undo` read"
    )
)]

use std::fmt;
use std::fs::File;
use std::io;
use std::io::Write;
use std::os::fd::AsFd;
use std::os::fd::BorrowedFd;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::LazyLock;
use std::time::Instant;

use jiff::Timestamp;
use rustix::fs::AtFlags;
use rustix::fs::FileType;
use rustix::fs::Mode;
use rustix::fs::OFlags;
use rustix::io::Errno;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;

use crate::config::paths::FILE_MODE;
use crate::config::paths::Paths;
use crate::config::paths::is_single_component;
use crate::error::AppError;
use crate::secret::file_store;
use crate::secret::file_store::FileStoreError;

/// The log's file name, under [`Paths::namespace_root`].
pub const LOG_FILE: &str = "keychain-writes.jsonl";

/// How many hex digits of a digest an entry may carry (risk R34).
pub const DIGEST_PREFIX_LEN: usize = 8;

/// The permission bits [`append`] creates the log with, and the only ones it
/// will write through.
///
/// The same 0600 [`FILE_MODE`] spells for the rest of the store, in the form
/// `openat` takes.
const LOG_MODE: Mode = Mode::RUSR.union(Mode::WUSR);

/// When this process started, for [`AuditEntry::monotonic_ms`].
///
/// A monotonic clock has no epoch, so the number is meaningless on its own and
/// deliberately so: what it is *for* is comparing two entries' spacing against
/// their wall-clock spacing, which is how a clock step shows up in the record
/// of a break that spanned one.
static PROCESS_START: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Where the log lives for one agctl store.
pub fn log_path(paths: &Paths) -> PathBuf {
    paths.namespace_root().join(LOG_FILE)
}

/// One line of the log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// When this process wrote the entry, RFC 3339 in UTC.
    #[serde(with = "timestamp_as_string")]
    pub ts: Timestamp,
    /// Milliseconds on this process's monotonic clock, for the reason
    /// [`PROCESS_START`] gives.
    pub monotonic_ms: u64,
    /// **agctl's own** process id — never a holder's (plan AC80).
    pub agctl_pid: u32,
    /// What happened.
    #[serde(flatten)]
    pub event: AuditEvent,
}

impl AuditEntry {
    /// An entry stamped with now, this process's monotonic reading, and this
    /// process's id.
    pub fn new(event: AuditEvent) -> Self {
        let elapsed = PROCESS_START.elapsed();
        Self {
            ts: Timestamp::now(),
            monotonic_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            agctl_pid: std::process::id(),
            event,
        }
    }

    /// This entry's identity: its timestamp and the process that wrote it.
    pub fn id(&self) -> AuditId {
        AuditId { ts: self.ts, agctl_pid: self.agctl_pid }
    }
}

/// The events the log records.
///
/// Internally tagged, so the `event` member sits beside the provenance fields
/// and the event's own fields are flat — the shape plan section 3.8 fixes for
/// a break, and the same shape for a write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEvent {
    /// One keychain write.
    Write {
        /// Which item was written.
        target: Target,
        /// The first eight hex digits of the outgoing credential's access
        /// token digest, or `None` when the item did not exist — which is what
        /// records a first write *as* a first write.
        from_digest8: Option<String>,
        /// The first eight hex digits of the incoming credential's access
        /// token digest.
        to_digest8: String,
        /// How it ended.
        outcome: WriteOutcome,
        /// Which way round the swap ran (decision D-027).
        ///
        /// Additive: an entry written before the field existed reads as
        /// [`WriteDirection::Forward`], which is the conservative reading for
        /// the live-swap guard that consults it — it arms rather than disarms.
        #[serde(default)]
        direction: WriteDirection,
        /// The account a **live** write installed in the item, by id alone —
        /// never a token and never an email (decision D-027).
        ///
        /// Written on every live write, forward **and** undo (S24): for an
        /// undo it is the account put back. `use --undo` reads it as the
        /// account the write it reverses installed — which is what lets an
        /// undo itself be undone — and a live swap whose item token has
        /// expired takes it as the identity of the bytes that write put there.
        /// Compared against
        /// registry records only, never used to build a path. Absent on
        /// namespace entries, and on live entries written before S24 — which
        /// is why an entry without it refuses rather than being guessed at.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        incoming_identity: Option<IncomingIdentity>,
    },
    /// One lock break, or one break the rule abandoned.
    ///
    /// The record is written **after** the decision, never inside the Sample C
    /// gap: plan section 3.8 forbids any I/O between the last sample and the
    /// `rmdir`, and an audit append is I/O.
    LockBreak(LockBreakRecord),
    /// One config step of a live pass: the `.claude.json` rewrite that follows
    /// an applied live write, or the record that it was not attempted (S24b,
    /// ruling G14).
    ///
    /// One line per step even when nothing was written, so the log says why a
    /// file was left as it was.
    ConfigWrite(ConfigWriteRecord),
    /// An event kind this build does not know: a later agctl's additive kind,
    /// read rather than refused (principle P3, ruling Q8 (b)).
    ///
    /// **Read-only.** [`append`] and [`append_through`] refuse to write it, so a
    /// line can only ever arrive here from a newer build. Every reader that
    /// matches [`AuditEvent::Write`] treats it as it treats any other
    /// non-write event.
    #[serde(other)]
    Unrecognized,
}

/// What one config step of a live pass did (S24b, ruling Q7).
///
/// Ids and digest prefixes only: `account` is the pair of ids written into
/// `oauthAccount`, never an email, and `backup` is a file **name**, never a
/// path — [`append`] refuses an entry that carries anything else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigWriteRecord {
    /// The [`AuditId`] of the `write` entry this pass appended, as its
    /// `Display` renders it; `None` on a catch-up, which follows no write of
    /// its own (S24b-2, ruling Q7).
    #[serde(default)]
    pub after: Option<String>,
    /// How the step ended.
    pub outcome: ConfigOutcome,
    /// Why, when it did not apply.
    #[serde(default)]
    pub reason: Option<ConfigReason>,
    /// The account written into `oauthAccount`, by id alone.
    #[serde(default)]
    pub account: Option<IncomingIdentity>,
    /// The first eight hex digits of the SHA-256 of the file as it was read.
    #[serde(default)]
    pub from_sha8: Option<String>,
    /// The first eight hex digits of the SHA-256 of the file as it was
    /// written; only on `applied`.
    #[serde(default)]
    pub to_sha8: Option<String>,
    /// The backup's file name, under the peer's `backups/`.
    #[serde(default)]
    pub backup: Option<String>,
    /// How long the configuration lock was held, in whole milliseconds, when
    /// one was taken.
    #[serde(default)]
    pub hold_ms: Option<u64>,
}

/// How a config step ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigOutcome {
    /// The file was rewritten.
    Applied,
    /// Nothing was there to rewrite, or the lock could not be taken.
    Skipped,
    /// The file could not be rewritten safely, decided before anything was
    /// written.
    Refused,
    /// A check under the lock failed and nothing was renamed.
    Aborted,
    /// A write or a rename failed.
    Failed,
    /// The step deliberately did not run.
    NotAttempted,
    /// A word a later build writes; read-only.
    #[serde(other)]
    Unrecognized,
}

/// Why a config step did not apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigReason {
    /// There is no configuration file.
    Absent,
    /// It is not a regular file, or it is too large, or it could not be read.
    Unreadable,
    /// It is not JSON.
    Unparseable,
    /// Its top level is not an object.
    NotAnObject,
    /// Re-serialising it did not reproduce its bytes.
    NotReproducible,
    /// Its backup could not be written first.
    BackupUnwritable,
    /// A Claude Code session held the configuration lock throughout the ladder.
    LockBusy,
    /// The configuration lock was stale; agctl never breaks it.
    LockStale,
    /// The run was cancelled while waiting for the lock.
    Cancelled,
    /// The file changed while agctl held the lock.
    ChangedUnderLock,
    /// agctl's lock was broken while it held it.
    Compromised,
    /// A term could not finish inside the lock's budget.
    Budget,
    /// A write or a rename failed.
    Io,
    /// The installed account's profile could not be read.
    ProfileUnavailable,
    /// The swap's own outcome is `unknown`.
    SwapUnknown,
    /// A catch-up found the file already naming the live item's account, by
    /// its two ids (S24b-2, ruling Q4).
    AlreadyCurrent,
    /// A catch-up's rewrite was not confirmed, or there was nobody to ask.
    /// Never written: a declined catch-up appends no line (ruling Q3).
    Declined,
    /// A catch-up met an audit log agctl refuses, so nothing was read or
    /// locked. Never written: there is no log to write it to.
    AuditRefused,
    /// A word a later build writes; read-only.
    #[serde(other)]
    Unrecognized,
}

/// Which keychain item an event is about.
///
/// `live` for the unsuffixed item, `namespace:<sha8>` for one of agctl's
/// own. Rendered as one string rather than an object so a `doctor` line, a
/// `jq` filter and a human reading the file all see the same token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// `Claude Code-credentials` — whatever Claude Code is using now.
    Live,
    /// A namespaced item, by the eight hex digits of its suffix.
    Namespace(String),
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Live => f.write_str("live"),
            Self::Namespace(sha8) => write!(f, "namespace:{sha8}"),
        }
    }
}

impl Serialize for Target {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Target {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        match text.as_str() {
            "live" => Ok(Self::Live),
            other => match other.strip_prefix("namespace:") {
                Some(sha8) => Ok(Self::Namespace(sha8.to_owned())),
                None => Err(serde::de::Error::custom(format!("unknown audit target `{other}`"))),
            },
        }
    }
}

/// How a write ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteOutcome {
    /// The item was re-read after the locks were released and holds the
    /// incoming credential.
    Applied,
    /// The write returned, but the verifying re-read did not agree — which
    /// includes a legitimate peer write landing in the gap. It means "re-run
    /// `status`", not "failed" (plan section 3.4 step 12).
    Unknown,
    /// The write itself failed and the item was left as it was.
    Failed,
    /// The refresh was performed and never written: a refusal after the POST
    /// (a busy store, a drifted lock, an item that changed under us, a hold
    /// out of budget) threw away a credential the server had already minted.
    ///
    /// Worth its own entry rather than silence, because the discard is
    /// invisible afterwards: the item still holds the *old* refresh token,
    /// which the server has usually just rotated away, so the next pass may
    /// report `needs login` for reasons this pass created.
    Discarded,
}

/// Which way round a swap ran (decision D-027).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteDirection {
    /// `use --live <id>` — and any write that is not a reversal, such as a
    /// refresh saved in place.
    #[default]
    Forward,
    /// `use --undo`.
    Undo,
}

/// The account a live write installed in the item, by id alone (decision
/// D-027; on undo entries too since S24).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncomingIdentity {
    /// The account UUID.
    pub account_uuid: String,
    /// The organization UUID, when the registry knows one; `None` for a record
    /// still carrying the unknown-organization placeholder.
    #[serde(default)]
    pub organization_uuid: Option<String>,
}

/// Which tree a lock artefact belongs to (invariant I11′ containment).
///
/// The crate's one spelling of the distinction: the lock protocol
/// ([`claude_lock`](crate::secret::claude_lock)) records it, the held-lock
/// records ([`held_locks`](crate::secret::held_locks)) carry it, and `doctor`
/// prints it. It lives here because this is the module both of the others
/// depend on, and because two enums that agreed only for today's two variants
/// would diverge the moment a third arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tree {
    /// Under `<config_dir>/claude/` — a store agctl owns.
    Agctl,
    /// The live Claude Code store. Only W4b can break a lock here.
    Live,
}

impl Tree {
    /// The words `doctor` prints for this tree.
    pub fn label(self) -> &'static str {
        match self {
            Self::Agctl => "agctl's own tree",
            Self::Live => "the live store",
        }
    }
}

/// One `stat` of a lock directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockSample {
    /// When the sample was taken.
    #[serde(with = "timestamp_as_string")]
    pub at: Timestamp,
    /// The directory's modification time in nanoseconds since the epoch.
    ///
    /// `i64` rather than the plan's `i128`: nanoseconds since 1970 fit in an
    /// `i64` until the year 2262, and 128-bit integers do not survive serde's
    /// flattened-field buffering, which this record reaches through
    /// [`AuditEntry`]'s `#[serde(flatten)]`.
    pub mtime_ns: i64,
    /// How old the directory was at that moment.
    pub age_ms: u64,
}

/// What the holder check could see (plan AC80).
///
/// Three values, and **no value names a pid or claims a store was
/// identified** — the vocabulary itself is the assertion, so a later edit
/// cannot reintroduce attribution through the log. Partial evidence — any pid
/// whose state could not be read — is [`HolderEvidence::None`], never
/// [`HolderEvidence::NoStoppedClaude`] (decision D-022).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HolderEvidence {
    /// Some same-user `claude` process is stopped or traced.
    StoppedClaudePresent,
    /// Every same-user `claude` process was readable and none was stopped.
    NoStoppedClaude,
    /// The check could not be made, or could not be made completely.
    None,
}

/// Whether the artefact was removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BreakOutcome {
    /// The directory was removed and re-created by agctl.
    Broken,
    /// The rule refused; the directory was left exactly as it was.
    Abandoned,
}

/// Why a break did not happen — or, for `retaken`, what happened to the
/// artefact after one did.
///
/// Every member is a reason **not** to have broken a lock, which is why a
/// clean break carries no reason at all
/// ([`LockBreakRecord::reason`] is an `Option`). Plan section 3.8 fixes the
/// six words; there is deliberately no seventh meaning "it was stale", because
/// staleness is the precondition of the whole rule rather than an outcome of
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BreakReason {
    /// A sample's mtime differed from the one before it: somebody is alive in
    /// there.
    HeartbeatObserved,
    /// The artefact was not yet stale.
    TooYoung,
    /// The artefact disappeared between samples.
    Vanished,
    /// Wall clock and monotonic clock disagreed by more than a second.
    ClockJump,
    /// The post-`rmdir` `mkdir` found the artefact back: a peer re-took it,
    /// and there is no second break.
    Retaken,
    /// A same-user `claude` process is stopped, so the break was abandoned
    /// whether or not that process is the holder.
    HolderStopped,
}

/// The record of one break decision (plan section 3.8).
///
/// Defined here rather than beside the lock protocol so the two lanes that
/// need it — the module that decides, and the module that writes the line —
/// share one field list and one JSON shape. It is **the** shape: nested in
/// [`AuditEvent::LockBreak`], serde's internal tag and
/// [`AuditEntry`]'s `flatten` reproduce section 3.8's object exactly, and a
/// second declaration of these fields anywhere else would duplicate the
/// provenance members the moment it reached [`append`].
///
/// Only [`claude_lock`](crate::secret::claude_lock) builds one, and it cannot
/// build one in halves: the rule fills everything it can observe and the
/// caller supplies `service` and `target` through
/// `BreakDraft::complete`, so no field arrives at the log empty because
/// somebody forgot it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockBreakRecord {
    /// The lock directory itself.
    pub path: PathBuf,
    /// The credential store directory it guards.
    pub store_dir: PathBuf,
    /// Which tree that store is in.
    pub tree: Tree,
    /// The keychain service name of the item the store holds.
    pub service: String,
    /// Which item the swap was for.
    pub target: Target,
    /// The first `stat`.
    pub sample_a: LockSample,
    /// The second `stat`, after the sampling interval. Absent when the rule
    /// abandoned before it.
    pub sample_b: Option<LockSample>,
    /// The third `stat`, immediately before the `rmdir`, with no I/O between.
    pub sample_c: Option<LockSample>,
    /// Wall-clock milliseconds between samples A and B.
    pub interval_wall_ms: u64,
    /// Monotonic milliseconds between the same two samples. A divergence from
    /// `interval_wall_ms` over a second is a clock step in either direction.
    pub interval_monotonic_ms: u64,
    /// What the holder check saw.
    pub holder_evidence: HolderEvidence,
    /// Whether the artefact was removed.
    pub outcome: BreakOutcome,
    /// Why not, when it was not — and `retaken` when it was removed and a peer
    /// took it back before agctl could.
    ///
    /// Absent for a clean break: every member of [`BreakReason`] is a reason
    /// *not* to have broken a lock, so a break with nothing to explain records
    /// no reason rather than inventing a word for success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<BreakReason>,
}

/// One entry's identity: the timestamp it carries and the process that wrote
/// it.
///
/// Returned by [`append`] so a command can print "audit id X" and a later
/// `doctor` or `use --undo` can find the same line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditId {
    /// The entry's timestamp.
    pub ts: Timestamp,
    /// The process that wrote it.
    pub agctl_pid: u32,
}

impl fmt::Display for AuditId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}#{}", self.ts, self.agctl_pid)
    }
}

/// Appends one entry and returns its identity.
///
/// The file is created 0600 if it is absent, opened `O_APPEND` through
/// [`open_log`]'s walk, written with a single `write` and `fsync`ed before
/// this returns — because the whole point of the record is to survive the
/// crash that happens next.
///
/// # Errors
///
/// Returns [`AppError::Config`] when the entry carries a digest field that is
/// not exactly [`DIGEST_PREFIX_LEN`] lowercase hex digits — the guard that
/// keeps risk R34 from arriving through a caller — when the entry cannot be
/// serialized, and when the log itself is refused: a symbolic link at its
/// name, a link on the way to it, something that is not a regular file, or a
/// mode that is not 0600 ([`LogState`]). [`AppError::Io`] is the remaining
/// arm, for a log that cannot be written or flushed.
///
/// Both arms are the ones this function already had, and both callers —
/// `commands::use`'s `audit_append` and
/// [`status`](crate::commands::status)'s — treat any `Err` the same way: the
/// entry is not written, the failure is logged, and the swap or the row
/// carries on. A refused log therefore means the `broken` line
/// [`AuditEvent::LockBreak`] exists to produce is absent — fail-closed, and
/// the same shape as every other unwritable log.
pub fn append(paths: &Paths, entry: &AuditEntry) -> Result<AuditId, AppError> {
    // Serialized and checked before any I/O, so a malformed entry cannot
    // create the log on its way to being refused.
    let line = entry_line(entry)?;

    paths.ensure_dirs()?;
    let path = log_path(paths);
    let file = open_log(paths, &path)?;
    write_line(&file, &path, &line)?;
    Ok(entry.id())
}

/// Appends one entry through a descriptor the caller is **already holding**.
///
/// The live-store half of invariant I16 (W4b §D6, ruling G2). A live swap
/// gates on [`open_log`] in Phase B — a held descriptor, not a report — and
/// keeps it across Phase C, so the entry that records the write is appended
/// through the same file the gate proved appendable. Nothing between the two
/// can redirect the log: an `ln -s` or a `chmod` after the open changes the
/// *name*, and this writes to the descriptor.
///
/// Serialization and the digest checks are [`append`]'s own, shared rather
/// than repeated, so the two entry points cannot disagree about what a valid
/// entry is or about how it is spelled.
///
/// `path` is for the error sentences only; nothing is resolved through it.
///
/// # Errors
///
/// The same arms as [`append`] minus the ones about reaching the log:
/// [`AppError::Config`] for a bad digest field or an entry that cannot be
/// serialized, and [`AppError::Io`] when the write or the flush fails.
pub(crate) fn append_through(
    file: &File,
    path: &Path,
    entry: &AuditEntry,
) -> Result<AuditId, AppError> {
    let line = entry_line(entry)?;
    write_line(file, path, &line)?;
    Ok(entry.id())
}

/// One entry as the line the log holds, with risk R34's guard applied.
///
/// Both entry points go through this, which is what keeps one serialisation
/// and one digest check: a second spelling of either would let an entry that
/// [`append`] refuses reach the log through [`append_through`].
fn entry_line(entry: &AuditEntry) -> Result<String, AppError> {
    match &entry.event {
        AuditEvent::Write { from_digest8, to_digest8, .. } => {
            if let Some(from) = from_digest8 {
                check_digest8("from_digest8", from)?;
            }
            check_digest8("to_digest8", to_digest8)?;
        }
        // Risk R34 for the config step (ruling Q7, finding N11): the same
        // prefix rule for both digests, and a backup that is a bare file name in
        // the peer's shape — a caller that passed a whole digest or a path fails
        // the append rather than leaking it.
        AuditEvent::ConfigWrite(record) => {
            if let Some(from) = &record.from_sha8 {
                check_digest8("from_sha8", from)?;
            }
            if let Some(to) = &record.to_sha8 {
                check_digest8("to_sha8", to)?;
            }
            if let Some(backup) = &record.backup
                && !is_backup_name(backup)
            {
                return Err(AppError::Config(format!(
                    "an audit entry's `backup` must be a `.claude.json.backup.<ms>` file name, not \
                     {} characters; the audit log holds no paths",
                    backup.len()
                )));
            }
            if record.outcome == ConfigOutcome::Unrecognized
                || record.reason == Some(ConfigReason::Unrecognized)
            {
                return Err(AppError::Config(
                    "an audit entry's config outcome or reason is a word this build only reads; it \
                     is never written"
                        .to_owned(),
                ));
            }
        }
        // Read-only (ruling Q8 (b)): writing it would record an event nobody
        // performed under a name that means "a later build wrote this".
        AuditEvent::Unrecognized => {
            return Err(AppError::Config(
                "an unrecognised audit event is read from a later build's log, never written"
                    .to_owned(),
            ));
        }
        AuditEvent::LockBreak(_) => {}
    }

    let mut line = serde_json::to_string(entry).map_err(|err| {
        AppError::Config(format!("an audit entry could not be serialized: {err}"))
    })?;
    line.push('\n');
    Ok(line)
}

/// One `write` and one `fsync`, because the point of the record is to survive
/// the crash that happens next.
///
/// `pub(crate)` so phase 3's Codex log (`<config_dir>/codex/writes.jsonl`)
/// appends its own entry type through the same one-write-one-flush rule rather
/// than a copy of it. `path` is for the error sentences only.
///
/// # Errors
///
/// Returns [`AppError::Io`] when the write or the flush fails.
pub(crate) fn write_line(mut file: &File, path: &Path, line: &str) -> Result<(), AppError> {
    file.write_all(line.as_bytes()).map_err(|err| AppError::Io {
        context: format!("could not append to the audit log `{}`", path.display()),
        source: err,
    })?;
    file.sync_all().map_err(|err| AppError::Io {
        context: format!("could not flush the audit log `{}`", path.display()),
        source: err,
    })
}

// ---------------------------------------------------------------------------
// Reaching the log: one walk, and no name resolved by path
// ---------------------------------------------------------------------------

/// What is at the log's name, seen through the same walk [`append`] writes
/// through.
///
/// The vocabulary exists so the refusal and the report cannot drift: `append`
/// hands [`LogState::note`]'s sentence to its caller, and `doctor` prints the
/// same sentence in its `audit log` row. A wrong mode is a *state*, never a
/// repair — the file belongs to whoever set it that way, and agctl saying so
/// is worth more than agctl quietly making it look right.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogState {
    /// Nothing is there: a store that has never appended.
    Absent,
    /// A regular file at mode 0600 — the one shape [`append`] writes to.
    Present,
    /// A regular file whose permission bits are something else, carrying them.
    WrongMode(u32),
    /// A symbolic link at the log's name, a link on the way to it, or
    /// something that is not a regular file at all.
    Refused(String),
}

impl LogState {
    /// The sentence `doctor` prints, and the reason [`append`]'s refusal
    /// carries.
    pub fn note(&self) -> String {
        match self {
            Self::Absent => "absent".to_owned(),
            Self::Present => "present".to_owned(),
            Self::WrongMode(mode) => format!(
                "present, but its mode is {mode:04o} and not {FILE_MODE:04o}: agctl refuses \
                 the log and will not change it"
            ),
            Self::Refused(why) => why.clone(),
        }
    }

    /// Whether [`append`] will write to what is at that name.
    pub fn is_appendable(&self) -> bool {
        matches!(self, Self::Absent | Self::Present)
    }
}

/// What is at the audit log's name, for `doctor`'s report.
///
/// Reads through [`open_log_dir`]'s walk, so what it reports is what [`append`]
/// would meet rather than what a second path resolution would find. A store
/// with no namespace root at all reads as [`LogState::Absent`]: it has never
/// appended.
pub fn log_state(paths: &Paths) -> LogState {
    match open_log_dir(paths) {
        Ok(dir) => state_at(dir.as_fd(), LOG_FILE),
        Err(err) if is_absent(&err) => LogState::Absent,
        Err(err) => LogState::Refused(format!("unreachable: {err}")),
    }
}

/// Opens the log for one append, refusing a link at its name and a mode that
/// is not 0600.
///
/// The log lives in [`Paths::namespace_root`], the directory
/// [`held_locks`](crate::secret::held_locks) keeps its records in, so the
/// attacker who could plant `held-locks` as a symbolic link could plant this
/// name too — and this file is the only durable evidence a broken lock leaves
/// (`agctl-9je`, from the T6 security review). The directory is therefore
/// resolved once, one `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` component at a
/// time from [`Paths::config_dir`] down, and the log is opened relative to the
/// descriptor that walk produced with `O_NOFOLLOW` on its own name. Nothing is
/// resolved by path twice.
///
/// The mode is checked on the open descriptor, not on the name, so there is no
/// window between the check and the write. It is **refused, never repaired**:
/// a `chmod` here would erase the evidence that somebody else can read this
/// machine's swap history.
///
/// `pub(crate)` because a **live**-store swap gates on this descriptor rather
/// than on [`log_state`] (W4b §D6, ruling G2). `log_state` is a report, and a
/// report leaves the whole width between the look and the write to whoever can
/// plant a name in this directory; a descriptor held from Phase B through
/// Phase C leaves none. The write then goes through [`append_through`].
///
/// # Errors
///
/// Returns [`AppError::Config`] when the log is refused — a symbolic link or a
/// FIFO at its name, a link on the way to it, something that is not a regular
/// file, or a mode that is not 0600 — and [`AppError::Io`] when the opened
/// descriptor cannot be `stat`ed.
pub(crate) fn open_log(paths: &Paths, path: &Path) -> Result<File, AppError> {
    let dir = open_log_dir(paths)
        .map_err(|err| refused(path, &format!("its directory is unreachable: {err}")))?;
    open_log_at(dir.as_fd(), LOG_FILE, path)
}

/// [`open_log`]'s open, relative to a directory the caller's own `O_NOFOLLOW`
/// walk produced, for a log with any name.
///
/// Every rule is [`open_log`]'s — `O_APPEND | O_CREAT | O_NOFOLLOW |
/// O_NONBLOCK`, a regular file, mode 0600 checked on the descriptor and refused
/// rather than repaired — because it *is* that function's body: `open_log` is
/// this plus the walk to [`Paths::namespace_root`]. Phase 3's Codex log reaches
/// its own directory and opens its own name through here.
///
/// `name` must be one plain path component; `path` is the log as the user
/// would recognise it, used only in the error sentences.
///
/// # Errors
///
/// As [`open_log`], plus [`AppError::Config`] for a `name` that is not one
/// plain component.
pub(crate) fn open_log_at(dir: BorrowedFd<'_>, name: &str, path: &Path) -> Result<File, AppError> {
    if !is_single_component(name) {
        return Err(refused(path, "its name is not a single path component"));
    }

    // `O_NONBLOCK` is not decoration: without it a FIFO planted at this name
    // — one `mkfifo`, the same precondition as the symbolic link — blocks the
    // `openat` until a reader arrives, and `append` runs with the namespace
    // lock held, so the whole store wedges instead of one entry failing. With
    // it the open returns `ENXIO` at once and the FIFO is refused as what it
    // is. It changes nothing for a regular file, which is why `read_file_at`
    // has carried it all along.
    let flags = OFlags::WRONLY
        | OFlags::APPEND
        | OFlags::CREATE
        | OFlags::NOFOLLOW
        | OFlags::NONBLOCK
        | OFlags::CLOEXEC;
    let fd = match rustix::fs::openat(dir, name, flags, LOG_MODE) {
        Ok(fd) => fd,
        // The open has already refused: `O_NOFOLLOW` followed nothing and
        // `O_CREAT` without `O_TRUNC` wrote nothing. All this second look
        // decides is which sentence the caller is handed — the reasoning
        // `file_store::open_dir_at` gives for its own `lstat`.
        Err(errno) => return Err(refused(path, &why_open_failed(dir, name, errno))),
    };

    let file = File::from(fd);
    let meta = file.metadata().map_err(|err| AppError::Io {
        context: format!("could not stat the audit log `{}`", path.display()),
        source: err,
    })?;
    if !meta.is_file() {
        return Err(refused(path, "it is not a regular file"));
    }
    let mode = meta.mode() & 0o7777;
    if mode != FILE_MODE {
        return Err(refused(path, &LogState::WrongMode(mode).note()));
    }
    Ok(file)
}

/// The log's whole text, or `None` when there is nothing there to read.
///
/// [`tail`]'s half of the same walk. The reader must refuse what the writer
/// refuses — `use --undo` acts on what this returns, so a log somebody else
/// could redirect would be an undo somebody else could direct — but it does
/// **not** apply the mode rule: a log at 0644 is one `doctor` must still be
/// able to report, and reading it discloses nothing that its mode has not
/// already disclosed.
fn read_log(paths: &Paths, path: &Path) -> Result<Option<String>, AppError> {
    let dir = match open_log_dir(paths) {
        Ok(dir) => dir,
        // A store with no namespace root has never appended.
        Err(err) if is_absent(&err) => return Ok(None),
        Err(err) => return Err(refused(path, &format!("its directory is unreachable: {err}"))),
    };
    read_log_at(dir.as_fd(), LOG_FILE, path)
}

/// [`read_log`]'s read, relative to a directory the caller's own `O_NOFOLLOW`
/// walk produced, for a log with any name.
///
/// The same rules: a link at the name is refused, an absent file is `None`,
/// and the mode is **not** checked, because a reader must still be able to
/// report a log whose mode is wrong. Phase 3's `codex doctor` tails the Codex
/// log through here.
///
/// # Errors
///
/// As [`read_log`], plus [`AppError::Config`] for a `name` that is not one
/// plain component.
pub(crate) fn read_log_at(
    dir: BorrowedFd<'_>,
    name: &str,
    path: &Path,
) -> Result<Option<String>, AppError> {
    if !is_single_component(name) {
        return Err(refused(path, "its name is not a single path component"));
    }

    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let fd = match rustix::fs::openat(dir, name, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(errno) if errno == Errno::NOENT => return Ok(None),
        Err(errno) => return Err(refused(path, &why_open_failed(dir, name, errno))),
    };

    let mut file = File::from(fd);
    io::read_to_string(&mut file).map(Some).map_err(|err| AppError::Io {
        context: format!("could not read the audit log `{}`", path.display()),
        source: err,
    })
}

/// [`read_log_at`]'s open, but handing the caller one line at a time instead
/// of the whole file.
///
/// Returns whether a log was there at all: `Ok(false)` for an absent one, the
/// same as `read_log_at`'s `None`.
///
/// # Why a second reader
///
/// `read_log_at` answers "show me the tail", which is a bounded question, and
/// it holds the file in memory to answer it. A caller that must consult
/// **every** line — `codex doctor` asking which keychain items a refused
/// login left behind, where the answer can be a thousand writes back — would
/// turn an append-only log into a whole-file allocation that grows with the
/// user's history. This reads through a buffer instead, so the memory it
/// needs is `max_line_bytes` plus the buffer, whatever the log's size.
///
/// A line longer than `max_line_bytes`, and a line that is not UTF-8, is
/// skipped rather than refused: neither is a line agctl wrote, and a reader
/// asked to find agctl's own entries must not be stopped by somebody else's.
/// The bound is the caller's, because only the caller knows how long its own
/// entries are.
///
/// # Errors
///
/// As [`read_log_at`], apart from the absent case.
pub(crate) fn for_each_line_at(
    dir: BorrowedFd<'_>,
    name: &str,
    path: &Path,
    max_line_bytes: usize,
    mut visit: impl FnMut(&str),
) -> Result<bool, AppError> {
    if !is_single_component(name) {
        return Err(refused(path, "its name is not a single path component"));
    }

    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let fd = match rustix::fs::openat(dir, name, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(errno) if errno == Errno::NOENT => return Ok(false),
        Err(errno) => return Err(refused(path, &why_open_failed(dir, name, errno))),
    };

    let failed = |err: io::Error| AppError::Io {
        context: format!("could not read the audit log `{}`", path.display()),
        source: err,
    };
    let mut reader = io::BufReader::new(File::from(fd));
    let mut line: Vec<u8> = Vec::new();
    // Set when the current line has already passed the bound: its remaining
    // bytes are consumed and dropped rather than collected, so one enormous
    // line costs time and not memory.
    let mut over_bound = false;
    loop {
        let (consumed, complete) = {
            let available = io::BufRead::fill_buf(&mut reader).map_err(failed)?;
            if available.is_empty() {
                break;
            }
            match available.iter().position(|&byte| byte == b'\n') {
                Some(end) => {
                    over_bound |= line.len().saturating_add(end) > max_line_bytes;
                    if !over_bound {
                        line.extend_from_slice(&available[..end]);
                    }
                    (end.saturating_add(1), true)
                }
                None => {
                    over_bound |= line.len().saturating_add(available.len()) > max_line_bytes;
                    if !over_bound {
                        line.extend_from_slice(available);
                    }
                    (available.len(), false)
                }
            }
        };
        io::BufRead::consume(&mut reader, consumed);
        if complete {
            if !over_bound && let Ok(text) = str::from_utf8(&line) {
                visit(text);
            }
            line.clear();
            over_bound = false;
        }
    }
    // A final line with no terminating newline is still a line: a writer that
    // was interrupted between the bytes and the `\n` leaves one.
    if !over_bound
        && !line.is_empty()
        && let Ok(text) = str::from_utf8(&line)
    {
        visit(text);
    }
    Ok(true)
}

/// The directory the log lives in, opened without following a link.
///
/// Anchored at [`Paths::config_dir`] and walked down to
/// [`Paths::namespace_root`], so the `claude` component itself — the one a
/// planter would swap — is opened `O_NOFOLLOW` like every other.
fn open_log_dir(paths: &Paths) -> Result<OwnedFd, FileStoreError> {
    file_store::open_dir_under(paths.config_dir(), &paths.namespace_root())
}

/// What is at `name` — [`LOG_FILE`], for Claude's log — inside an
/// already-opened directory.
fn state_at(dir: BorrowedFd<'_>, name: &str) -> LogState {
    match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => match FileType::from_raw_mode(stat.st_mode) {
            FileType::Symlink => {
                LogState::Refused("a symbolic link, which agctl will not append through".to_owned())
            }
            FileType::RegularFile => match u32::from(stat.st_mode) & 0o7777 {
                FILE_MODE => LogState::Present,
                other => LogState::WrongMode(other),
            },
            _ => LogState::Refused("not a regular file".to_owned()),
        },
        Err(errno) if errno == Errno::NOENT => LogState::Absent,
        Err(errno) => LogState::Refused(format!("could not be examined: {errno}")),
    }
}

/// Why an open of the log failed, in the user's terms.
///
/// [`state_at`] first, because "a symbolic link" is a better answer than
/// `ELOOP`; the errno when the name says nothing useful — the open failed for
/// a reason that is not about the shape of what is there, or lost a race with
/// somebody changing it.
fn why_open_failed(dir: BorrowedFd<'_>, name: &str, errno: Errno) -> String {
    let state = state_at(dir, name);
    if state.is_appendable() { format!("it could not be opened: {errno}") } else { state.note() }
}

/// Whether a walk failed because the directory is simply not there.
fn is_absent(err: &FileStoreError) -> bool {
    matches!(err, FileStoreError::Io { source, .. } if source.kind() == io::ErrorKind::NotFound)
}

/// The refusal both halves of this module hand back.
fn refused(path: &Path, why: &str) -> AppError {
    AppError::Config(format!("the audit log `{}` is refused: {why}", path.display()))
}

/// What one [`tail`] read found: the entries it could parse, and the lines it
/// could not.
///
/// Two lists rather than a `Result`, because the caller's job is to *report*
/// this file and one damaged line must not take the report down with it. The
/// damaged line is not exotic: [`append`] is one `write` plus an `fsync`, so a
/// process killed between them — or a short write at `ENOSPC` — leaves a
/// truncated final line, which is by construction inside the last `n`. Failing
/// the whole read for it would mean `doctor` could explain no entry at all, and
/// `use --undo` could not run, exactly after the crash they are the recovery
/// for.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Tail {
    /// The entries that parsed, oldest first.
    pub entries: Vec<AuditEntry>,
    /// One `(line number, reason)` pair per line that did not, so `doctor` can
    /// name it instead of hiding it.
    pub unreadable: Vec<(usize, String)>,
}

/// The last `n` entries, oldest first, plus the lines in that window that could
/// not be read.
///
/// An absent log is no entries rather than an error: a store that has never
/// written a keychain item has nothing to explain. A line carrying *unknown
/// members* is not unreadable either — serde ignores them, so a log written by
/// a later agctl still reads here (principle P3). Nor is a line whose `event`
/// is a kind this build does not know: it reads as [`AuditEvent::Unrecognized`]
/// rather than landing in [`Tail::unreadable`], where `use --undo` would refuse
/// on it (ruling Q8 (b)).
///
/// The read goes through [`read_log`]'s `O_NOFOLLOW` walk, the same one
/// [`append`] writes through.
///
/// # Errors
///
/// Returns [`AppError::Config`] when the log is refused — a symbolic link at
/// its name or on the way to it — and [`AppError::Io`] when it exists but
/// cannot be opened or read at all. Both are a different failure from a line
/// this build cannot parse, and both leave the caller with nothing to report.
pub fn tail(paths: &Paths, n: usize) -> Result<Tail, AppError> {
    let path = log_path(paths);
    let Some(text) = read_log(paths, &path)? else { return Ok(Tail::default()) };

    let numbered: Vec<(usize, &str)> = text
        .lines()
        .enumerate()
        .map(|(index, line)| (index.saturating_add(1), line.trim()))
        .filter(|(_, line)| !line.is_empty())
        .collect();

    let start = numbered.len().saturating_sub(n);
    let mut tail = Tail::default();
    for (number, line) in numbered.get(start..).unwrap_or_default() {
        match serde_json::from_str::<AuditEntry>(line) {
            Ok(entry) => tail.entries.push(entry),
            Err(err) => tail.unreadable.push((*number, err.to_string())),
        }
    }
    Ok(tail)
}

/// The first [`DIGEST_PREFIX_LEN`] hex digits of a digest, for an entry.
///
/// `None` when `digest` is shorter than that, or when its prefix is not
/// lowercase hex — which means the caller has something other than a digest in
/// its hand and should not be writing it to a file either way.
pub fn digest8(digest: &str) -> Option<String> {
    let prefix = digest.get(..DIGEST_PREFIX_LEN)?;
    is_digest8(prefix).then(|| prefix.to_owned())
}

/// Refuses a digest field that is anything but eight lowercase hex digits.
fn check_digest8(field: &'static str, value: &str) -> Result<(), AppError> {
    if is_digest8(value) {
        return Ok(());
    }
    Err(AppError::Config(format!(
        "an audit entry's `{field}` must be {DIGEST_PREFIX_LEN} lowercase hex digits, not \
         {} characters; the audit log holds digest prefixes only",
        value.len()
    )))
}

/// Whether `value` is exactly eight lowercase hex digits.
fn is_digest8(value: &str) -> bool {
    value.len() == DIGEST_PREFIX_LEN
        && value.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Whether `value` is a backup file name in the peer's shape:
/// `.claude.json.backup.<digits>` or `.config.json.backup.<digits>`, and so
/// carries no `/`.
fn is_backup_name(value: &str) -> bool {
    [".claude.json.backup.", ".config.json.backup."].iter().any(|prefix| {
        value
            .strip_prefix(prefix)
            .is_some_and(|stamp| !stamp.is_empty() && stamp.bytes().all(|b| b.is_ascii_digit()))
    })
}

/// `jiff::Timestamp` as an RFC 3339 string.
///
/// Hand-written because this crate does not enable `jiff`'s `serde` feature,
/// and enabling a feature is a `Cargo.toml` edit another lane owns.
mod timestamp_as_string {
    use jiff::Timestamp;
    use serde::Deserialize;
    use serde::Deserializer;
    use serde::Serializer;

    /// Writes the timestamp as its RFC 3339 rendering.
    pub fn serialize<S: Serializer>(ts: &Timestamp, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&ts.to_string())
    }

    /// Reads an RFC 3339 rendering back.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Timestamp, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
#[path = "audit_tests.rs"]
mod tests;
