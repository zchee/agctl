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
//!
//! [`emergency`] is the one entry point that acts on the registry, and it is
//! idempotent: it takes ownership of every entry it processes, so a second
//! call — a signal arriving while the first is still unwinding, say — does
//! nothing rather than unlinking a path some other run has since recreated.
//!
//! Failures during [`emergency`] are deliberately swallowed. It runs on the
//! way out of the process, frequently from a signal-handling thread, and there
//! is no caller left to handle an error; a path that is already gone is the
//! outcome we wanted anyway.

// `emergency`, `register_tmp_path` and `unregister` are all live now — the
// credential writer and the registry writer both bracket their temporary
// files with them. What is left is `register_restore` and the `RestoreFn` it
// takes, which exist for W3's TUI: the terminal has to be put back whatever
// ends the process. Scoped to the non-test build because the tests below
// exercise all of it, and spelled `expect` so it starts warning the moment
// W3 makes it stale.
#![cfg_attr(not(test), expect(dead_code, reason = "register_restore awaits W3's TUI"))]

use std::path::Path;
use std::path::PathBuf;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::MutexGuard;

/// Identifies one registered entry so it can be withdrawn again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CleanupToken(u64);

/// A callback that restores some global state, run at most once.
type RestoreFn = Box<dyn FnOnce() + Send>;

/// The registry contents.
struct Registry {
    next_id: u64,
    tmp_paths: Vec<(CleanupToken, PathBuf)>,
    restores: Vec<(CleanupToken, RestoreFn)>,
}

impl Registry {
    const fn new() -> Self {
        Self { next_id: 0, tmp_paths: Vec::new(), restores: Vec::new() }
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

/// Withdraws a previously registered entry.
///
/// Returns whether an entry was actually removed, which lets a caller notice
/// a double-withdrawal in tests.
pub fn unregister(token: CleanupToken) -> bool {
    let mut reg = registry();
    let before = reg.tmp_paths.len() + reg.restores.len();
    reg.tmp_paths.retain(|(entry, _)| *entry != token);
    reg.restores.retain(|(entry, _)| *entry != token);
    before != reg.tmp_paths.len() + reg.restores.len()
}

/// Unlinks every registered temporary path and runs every registered restore
/// callback, then empties the registry.
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
