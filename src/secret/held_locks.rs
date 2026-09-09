//! The records agentctl leaves behind while it holds a Claude Code lock.
//!
//! Claude Code's lock artefacts are directories made by `mkdir` (fact F45),
//! and the kernel releases nothing when the process holding one dies. So the
//! only evidence a crash leaves is a record agentctl writes *before* the first
//! `mkdir`: which store it is locking, which directories it made, and the
//! process id that made them (plan section 3.4 step 6).
//!
//! This module is the read side. It exists so `doctor` can answer the two
//! states in the partial-state contract that nothing else can (plan section
//! 3.9):
//!
//! - a record whose directories are gone is a stale record and nothing more;
//! - a record whose directories are still there and whose process is dead is a
//!   leak, and it is the *only* thing that lets `--remove-stale` act on a path
//!   outside [`Paths::namespace_root`] — a `--live` swap's leaked locks are in
//!   `~/.claude` by construction, so without this the recovery command for
//!   premortem PM9 would not exist (architect N-2, critic M1).
//!
//! The write side is [`crate::secret::claude_lock`]'s, and it writes
//! [`HeldLockRecord`] itself rather than a second declaration of the same
//! fields — two types that were wire-compatible only by inspection is how a
//! reader and a writer in different lanes end up disagreeing about a spelling.

use std::fs;
use std::path::Path;
use std::path::PathBuf;

use serde::Deserialize;
use serde::Serialize;

use crate::config::paths::Paths;
use crate::runtime::coordinator::Cancel;
use crate::runtime::proc;
use crate::secret::file_store;
use crate::secret::file_store::ReadOutcome;

/// Where the records live, under [`Paths::namespace_root`].
pub const DIR_NAME: &str = "held-locks";

/// The extension every record file carries.
pub const RECORD_EXTENSION: &str = "json";

/// The largest record that will be parsed.
///
/// A record names one store and at most three directories, so anything larger
/// is not one — and a `doctor` run must not be turned into an unbounded read
/// by a file somebody dropped in this directory.
pub const MAX_RECORD_BYTES: u64 = 4096;

/// The directory holding one store's records.
pub fn dir(paths: &Paths) -> PathBuf {
    paths.namespace_root().join(DIR_NAME)
}

/// Which credential store's locks a record describes.
///
/// Named in the record rather than inferred from the path, because the whole
/// point of invariant I11′'s containment is being able to tell a lock agentctl
/// took inside its own tree from one it took in the live `~/.claude`.
///
/// Re-exported rather than declared: [`crate::secret::audit`] holds the crate's
/// one spelling, so the writer's `tree` and the reader's cannot drift apart.
pub use crate::secret::audit::Tree;

/// One held-lock record, as it is written before the first `mkdir`.
///
/// This is the shape [`claude_lock`](crate::secret::claude_lock) writes — it
/// serializes *this* type — so the reader and the writer cannot disagree about
/// a field name or a `tree` spelling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldLockRecord {
    /// The agentctl process that took the locks.
    pub agentctl_pid: u32,
    /// When that process started, so a recycled process id cannot pass for the
    /// one that wrote the record.
    ///
    /// `None` when it could not be read, and `None` in a record written by a
    /// build that predates the field: both mean "unknown", and an unknown start
    /// time falls back to the process id alone, which is weaker but is what
    /// phase 1 had. Filled from [`proc::self_start_time`].
    #[serde(default)]
    pub agentctl_start_time: Option<String>,
    /// Which tree they are in.
    pub tree: Tree,
    /// The credential store directory being locked.
    pub store_dir: PathBuf,
    /// Every directory that was created, in the order they were taken.
    pub paths: Vec<PathBuf>,
    /// When they were taken, RFC 3339.
    pub taken_at: String,
}

impl HeldLockRecord {
    /// Whether the process that wrote this record is gone, so the directories
    /// it names are a leak rather than a live hold.
    ///
    /// Two ways to be gone, and the second is why the start time is recorded at
    /// all: the process id no longer exists (or is a zombie, which has already
    /// exited), **or** it exists and started at a different moment, which means
    /// the kernel handed the id to somebody else. Without the second test an
    /// unrelated long-lived process inheriting the id would block recovery from
    /// a real leak for as long as it ran.
    ///
    /// Both start times must be readable for a mismatch to count. An unknown
    /// one is not evidence of anything, and reading it as one would turn every
    /// record written by an older build into a permitted removal.
    pub fn writer_is_gone(&self, cancel: &Cancel) -> bool {
        if proc::holder(self.agentctl_pid, cancel) == proc::Holder::Dead {
            return true;
        }
        let Some(recorded) = self.agentctl_start_time.as_deref() else { return false };
        match proc::start_time(self.agentctl_pid, cancel) {
            Some(now) => now != recorded,
            None => false,
        }
    }

    /// Whether this record vouches for `path`.
    ///
    /// Exact paths, compared component by component: this is the check that
    /// decides whether `--remove-stale` may leave the namespace root, so a
    /// prefix or a parent is not enough.
    pub fn attests(&self, path: &Path) -> bool {
        self.paths.iter().any(|held| held == path)
    }

    /// Where an `O_NOFOLLOW` walk to one of these paths may start.
    ///
    /// The store directory's parent, not the store directory: the legacy lock
    /// is `<realpath(store_dir)>.lock`, which sits *beside* the store rather
    /// than inside it (fact F17), so an anchor at the store itself could not
    /// reach it. Everything below the anchor — the store directory included —
    /// is still walked one `O_NOFOLLOW` component at a time.
    pub fn anchor(&self) -> Option<&Path> {
        self.store_dir.parent()
    }
}

/// One record and the file it was read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldLockFile {
    /// The record file itself.
    pub file: PathBuf,
    /// What it said.
    pub record: HeldLockRecord,
}

/// Every readable record in this store, ordered by file name.
///
/// Anything that is not a readable, parseable record is skipped rather than
/// raised: this is called from `doctor`, and a `doctor` that refuses to report
/// because one file in a directory is malformed is a `doctor` that cannot
/// diagnose the machine it was run on. The read itself refuses symbolic links
/// and stops at [`MAX_RECORD_BYTES`].
pub fn read_all(paths: &Paths) -> Vec<HeldLockFile> {
    let dir = dir(paths);
    let Ok(entries) = fs::read_dir(&dir) else { return Vec::new() };

    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == RECORD_EXTENSION))
        .collect();
    files.sort();

    files
        .into_iter()
        .filter_map(|file| {
            let record = read_one(&file)?;
            Some(HeldLockFile { file, record })
        })
        .collect()
}

/// One record, or nothing if it cannot be read or parsed.
fn read_one(file: &Path) -> Option<HeldLockRecord> {
    match file_store::read_file(file, MAX_RECORD_BYTES) {
        Ok(ReadOutcome::Present { bytes, .. }) => serde_json::from_slice(&bytes).ok(),
        _ => None,
    }
}

#[cfg(test)]
#[path = "held_locks_tests.rs"]
mod tests;
