//! A process-wide registry of things that must be undone if the process stops
//! abruptly.
//!
//! Two kinds of entry live here:
//!
//! - **In-flight temporary paths.** A credential write lands in
//!   `<path>.tmp.<8 hex>` before it is renamed into place. If the process dies
//!   between the two, that file holds token material at rest that nothing will
//!   ever claim. Registering the path means a signal handler can unlink it.
//! - **Terminal-restore callbacks.** The TUI puts the terminal into raw mode
//!   and the alternate screen. Dying without restoring it leaves the user with
//!   an unusable shell.
//! - **Registered child processes.** `agctl claude exec` runs `claude` as a
//!   child that holds a live grant in memory, and `security(1)` children can
//!   be mid-write to the keychain. A child registered with a pass is meant to
//!   die with its parent, and a signal thread about to call `process::exit`
//!   has no pass to reach it through — so each one is recorded here as a
//!   process id **and its start time**, the pair that tells the original
//!   process apart from an unrelated one that has since been given the same
//!   id. This module only keeps the list; the signal path does the killing.
//!
//! [`emergency`] acts on the first two kinds and [`take_children`] hands out
//! the third. Both are idempotent: each takes ownership of every entry it
//! processes, so a second call — a signal arriving while the first is still
//! unwinding, say — does nothing rather than unlinking a path some other run
//! has since recreated.
//!
//! A child cannot be registered before it exists, so there is a window between
//! `spawn` and registration that the list alone cannot cover.
//! [`begin_spawn_unless_cancelled`] covers it: a spawner holds its guard across that window, and the signal
//! path waits for [`spawns_in_flight`] to reach zero before it stops looking
//! for children.
//!
//! Failures during [`emergency`] are deliberately swallowed. It runs on the
//! way out of the process, frequently from a signal-handling thread, and there
//! is no caller left to handle an error; a path that is already gone is the
//! outcome we wanted anyway.

use std::path::Path;
use std::path::PathBuf;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use crate::runtime::coordinator::Cancel;

/// Identifies one registered entry so it can be withdrawn again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CleanupToken(u64);

/// A callback that restores some global state, run at most once.
type RestoreFn = Box<dyn FnOnce() + Send>;

/// A child process a terminating signal must take down with the process.
///
/// `start_time` is [`crate::runtime::proc::start_time`]'s spelling, read
/// right after the child was spawned. It is compared, never parsed: a process
/// id whose start time no longer matches belongs to some other process now,
/// and must not be signalled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildEntry {
    /// The child's process id.
    pub pid: u32,
    /// When the child started, as read at registration.
    pub start_time: String,
}

/// The registry contents.
///
/// Every critical section on this lock is a push, a `retain` or a
/// `mem::take`: nothing blocks, nothing runs a callback and nothing takes a
/// second lock while it is held, so a thread waiting on it — the signal
/// thread included — waits at most for one of those to finish.
struct Registry {
    next_id: u64,
    tmp_paths: Vec<(CleanupToken, PathBuf)>,
    restores: Vec<(CleanupToken, RestoreFn)>,
    children: Vec<(CleanupToken, ChildEntry)>,
}

impl Registry {
    const fn new() -> Self {
        Self { next_id: 0, tmp_paths: Vec::new(), restores: Vec::new(), children: Vec::new() }
    }

    fn len(&self) -> usize {
        self.tmp_paths.len() + self.restores.len() + self.children.len()
    }

    fn next_token(&mut self) -> CleanupToken {
        // Wrapping is unreachable in practice and harmless if reached: tokens
        // are only ever compared for equality against live entries. It is
        // spelled explicitly because overflow checks are off in every profile.
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        CleanupToken(id)
    }
}

static REGISTRY: LazyLock<Mutex<Registry>> = LazyLock::new(|| Mutex::new(Registry::new()));

/// Locks the registry, recovering from a poisoned mutex.
///
/// A panic in another thread must not disable cleanup — that is exactly when
/// cleanup matters most — so a poisoned lock is taken anyway.
fn registry() -> MutexGuard<'static, Registry> {
    match REGISTRY.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Registers a temporary path to unlink if the process stops abruptly.
///
/// Withdraw it with [`unregister`] as soon as the path has been renamed into
/// place or removed, so a later [`emergency`] cannot unlink an unrelated file
/// that has taken the same name.
pub fn register_tmp_path(path: PathBuf) -> CleanupToken {
    let mut reg = registry();
    let token = reg.next_token();
    reg.tmp_paths.push((token, path));
    token
}

/// Registers a callback that restores global state, such as the terminal.
///
/// The callback runs at most once, on the first [`emergency`] after
/// registration.
pub fn register_restore(restore: RestoreFn) -> CleanupToken {
    let mut reg = registry();
    let token = reg.next_token();
    reg.restores.push((token, restore));
    token
}

/// Registers a child process a terminating signal must kill.
///
/// Withdraw it with [`unregister`] once the child has been reaped. Until then
/// its process id cannot be reused, because an unreaped child still occupies
/// it; after that the start time is what keeps a recycled id safe.
pub fn register_child(pid: u32, start_time: String) -> CleanupToken {
    let mut reg = registry();
    let token = reg.next_token();
    reg.children.push((token, ChildEntry { pid, start_time }));
    token
}

/// Withdraws a previously registered entry.
///
/// Returns whether an entry was actually removed, which lets a caller notice
/// a double-withdrawal in tests.
pub fn unregister(token: CleanupToken) -> bool {
    let mut reg = registry();
    let before = reg.len();
    reg.tmp_paths.retain(|(entry, _)| *entry != token);
    reg.restores.retain(|(entry, _)| *entry != token);
    reg.children.retain(|(entry, _)| *entry != token);
    before != reg.len()
}

/// How many spawns are between their cancellation check and their child's
/// registration.
static SPAWNS_IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);

/// Held by a spawner from before its cancellation check until the child it
/// spawned is registered with [`register_child`]; dropping it ends the window.
#[derive(Debug)]
#[must_use = "the spawn window closes as soon as the guard is dropped"]
pub struct SpawnGuard(());

impl Drop for SpawnGuard {
    fn drop(&mut self) {
        SPAWNS_IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Opens a spawn window unless the run is already cancelled, closing the gap
/// between `spawn` and registration in which a terminating signal would
/// otherwise find no child to kill.
///
/// `None` means "do not spawn". `Some` is held until the child is registered
/// with the pass, then dropped. Every spawner that registers a child which
/// must die with agctl goes through this one call, so no call site can put
/// the cancellation check before the increment.
///
/// Why that order matters: the signal thread sets cancellation and then reads
/// [`spawns_in_flight`], and this increments the counter and then reads
/// cancellation. Both sides use `SeqCst`, so at least one of them sees the
/// other. Either the spawner finds the run cancelled and does not spawn, or
/// the signal thread finds the window open and keeps looking until the child
/// is registered. Checking first would reopen a window between the check and
/// the increment in which neither side sees the other.
pub fn begin_spawn_unless_cancelled(cancel: &Cancel) -> Option<SpawnGuard> {
    begin_spawn_unless(|| cancel.is_cancelled())
}

/// [`begin_spawn_unless_cancelled`] with the cancellation read passed in, so
/// a test can observe the counter at the moment it is read.
fn begin_spawn_unless(cancelled: impl FnOnce() -> bool) -> Option<SpawnGuard> {
    let guard = begin_spawn();
    if cancelled() {
        return None;
    }
    Some(guard)
}

/// Opens a spawn window unconditionally.
fn begin_spawn() -> SpawnGuard {
    SPAWNS_IN_FLIGHT.fetch_add(1, Ordering::SeqCst);
    SpawnGuard(())
}

/// Whether any [`SpawnGuard`] is currently held.
pub fn spawns_in_flight() -> bool {
    SPAWNS_IN_FLIGHT.load(Ordering::SeqCst) != 0
}

/// Takes every registered child out of the registry.
///
/// Draining rather than copying, for the reason [`emergency`] drains: a
/// second caller finds nothing left, so no child is signalled twice by two
/// overlapping exits. A child registered after this returns is picked up by
/// the next call, which is why the signal path calls it again while it waits.
pub fn take_children() -> Vec<ChildEntry> {
    let taken = std::mem::take(&mut registry().children);
    taken.into_iter().map(|(_, entry)| entry).collect()
}

/// Unlinks every registered temporary path and runs every registered restore
/// callback, then empties those two lists.
///
/// Registered children are left alone: this also runs when a pass merely hits
/// its deadline or `watch` quits, and neither may kill a child some other
/// context is still waiting on. Only the signal path, on its way to
/// `process::exit`, takes them — through [`take_children`].
///
/// Safe to call more than once and from more than one thread: entries are
/// taken out of the registry under the lock before any of them is acted on, so
/// a concurrent or subsequent call finds nothing left to do.
pub fn emergency() {
    let (tmp_paths, restores) = {
        let mut reg = registry();
        (std::mem::take(&mut reg.tmp_paths), std::mem::take(&mut reg.restores))
    };

    for (_, path) in tmp_paths {
        remove_quietly(&path);
    }

    // Restores run last: unlinking a temporary file does not depend on the
    // terminal, and a restore callback that blocks should not delay removing
    // token material from disk.
    for (_, restore) in restores {
        restore();
    }
}

/// Removes a path, ignoring the failure.
fn remove_quietly(path: &Path) {
    if let Err(err) = std::fs::remove_file(path) {
        // Not `warn!`: this runs on the way out, often from a signal thread,
        // and a missing file is the desired end state.
        tracing::debug!(path = %path.display(), error = %err, "emergency cleanup could not remove a temporary file");
    }
}

#[cfg(test)]
#[path = "cleanup_tests.rs"]
mod tests;
