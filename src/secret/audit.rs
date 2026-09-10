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
//! keeps two agctl processes from interleaving half-lines. The
//! provenance fields — `ts`, `monotonic_ms`, `agctl_pid` — come first and
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
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::LazyLock;
use std::time::Instant;

use jiff::Timestamp;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;

use crate::config::paths::FILE_MODE;
use crate::config::paths::Paths;
use crate::error::AppError;

/// The log's file name, under [`Paths::namespace_root`].
pub const LOG_FILE: &str = "keychain-writes.jsonl";

/// How many hex digits of a digest an entry may carry (risk R34).
pub const DIGEST_PREFIX_LEN: usize = 8;

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
    },
    /// One lock break, or one break the rule abandoned.
    ///
    /// The record is written **after** the decision, never inside the Sample C
    /// gap: plan section 3.8 forbids any I/O between the last sample and the
    /// `rmdir`, and an audit append is I/O.
    LockBreak(LockBreakRecord),
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
/// The file is created 0600 if it is absent, opened `O_APPEND`, written with a
/// single `write` and `fsync`ed before this returns — because the whole point
/// of the record is to survive the crash that happens next.
///
/// # Errors
///
/// Returns [`AppError::Config`] when the entry carries a digest field that is
/// not exactly [`DIGEST_PREFIX_LEN`] lowercase hex digits — the guard that
/// keeps risk R34 from arriving through a caller — or when the entry cannot be
/// serialized, and [`AppError::Io`] when the log cannot be created or written.
pub fn append(paths: &Paths, entry: &AuditEntry) -> Result<AuditId, AppError> {
    if let AuditEvent::Write { from_digest8, to_digest8, .. } = &entry.event {
        if let Some(from) = from_digest8 {
            check_digest8("from_digest8", from)?;
        }
        check_digest8("to_digest8", to_digest8)?;
    }

    let mut line = serde_json::to_string(entry).map_err(|err| {
        AppError::Config(format!("an audit entry could not be serialized: {err}"))
    })?;
    line.push('\n');

    paths.ensure_dirs()?;
    let path = log_path(paths);
    let mut file =
        fs::OpenOptions::new().append(true).create(true).mode(FILE_MODE).open(&path).map_err(
            |err| AppError::Io {
                context: format!("could not open the audit log `{}`", path.display()),
                source: err,
            },
        )?;
    file.write_all(line.as_bytes()).map_err(|err| AppError::Io {
        context: format!("could not append to the audit log `{}`", path.display()),
        source: err,
    })?;
    file.sync_all().map_err(|err| AppError::Io {
        context: format!("could not flush the audit log `{}`", path.display()),
        source: err,
    })?;

    Ok(entry.id())
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
/// a later agctl still reads here (principle P3).
///
/// # Errors
///
/// Returns [`AppError::Io`] when the log exists but cannot be opened or read at
/// all. That is a different failure from a line this build cannot parse, and it
/// is the only one that leaves the caller with nothing to report.
pub fn tail(paths: &Paths, n: usize) -> Result<Tail, AppError> {
    let path = log_path(paths);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Tail::default()),
        Err(err) => {
            return Err(AppError::Io {
                context: format!("could not read the audit log `{}`", path.display()),
                source: err,
            });
        }
    };

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
