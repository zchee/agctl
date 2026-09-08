//! Asking the operating system about a process that is not this one.
//!
//! `doctor` reports who holds a namespace lock and whether that process is
//! still there (plan AC45), and the lock body records a start time so a
//! recycled process id cannot be mistaken for the original holder (plan
//! AC48(c)). Both questions need facts the standard library does not offer.
//!
//! # Two sources, because neither is enough alone
//!
//! `kill(pid, 0)` answers "does a process with this id exist", cheaply and
//! without a subprocess — including the `EPERM` case, which means the process
//! exists and belongs to somebody else. What it cannot say is whether that
//! process is *running*: a `SIGSTOP`ed holder looks exactly like a healthy
//! one, and a lock held by a stopped process is a lock that will not be
//! released by waiting. So the state comes from `ps -o stat=`, and the start
//! time — the only thing that distinguishes a recycled id — from
//! `ps -o lstart=`.
//!
//! Reading those out of `sysctl(KERN_PROC_PID)` would avoid the subprocess,
//! but only through a raw FFI struct whose layout is a Darwin implementation
//! detail; `ps(1)` is a documented interface with a stable output contract.
//! The cost is one short-lived child, bounded by [`PS_TIMEOUT`] and reaped
//! through the coordinator's child table, and the process's own start time is
//! read at most once per process ([`self_start_time`]).

use std::process::Command;
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::Duration;
use std::time::Instant;

use rustix::process::Pid;

use crate::runtime::coordinator::Cancel;
use crate::runtime::coordinator::PassCtx;

/// Where `ps(1)` lives on macOS and on every Linux this could run on.
pub const PS_BIN: &str = "/bin/ps";

/// How long a `ps` child may run before it is killed and its answer given up
/// on.
///
/// Generous for a program that prints one line about one process id, and short
/// enough that a wedged `ps` cannot hold a `doctor` run open.
pub const PS_TIMEOUT: Duration = Duration::from_millis(2000);

/// What is known about a process another file claims to be held by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Holder {
    /// The process exists and is runnable.
    Alive,
    /// The process exists but is stopped, so waiting for it to release
    /// anything is waiting forever.
    Stopped,
    /// There is no such process, or it is a zombie waiting to be reaped.
    Dead,
}

impl Holder {
    /// The word `doctor` prints for this state.
    pub fn label(self) -> &'static str {
        match self {
            Self::Alive => "alive",
            Self::Stopped => "stopped",
            Self::Dead => "dead",
        }
    }
}

/// Whether a process with this id exists.
///
/// `EPERM` counts as existing: the process is there and owned by somebody
/// else, which for a lock holder is the answer that matters.
pub fn exists(pid: u32) -> bool {
    let Ok(raw) = i32::try_from(pid) else { return false };
    let Some(pid) = Pid::from_raw(raw) else { return false };
    match rustix::process::test_kill_process(pid) {
        Ok(()) => true,
        Err(errno) => errno == rustix::io::Errno::PERM,
    }
}

/// Classifies the process holding a lock.
///
/// The `kill(pid, 0)` probe comes first so the common case — a lock left
/// behind by a process that is long gone — costs no subprocess at all.
pub fn holder(pid: u32) -> Holder {
    if !exists(pid) {
        return Holder::Dead;
    }
    match field("stat", pid) {
        // `ps` reports the state as a leading letter followed by flags:
        // `T` is stopped or traced, `Z` a zombie whose exit status nobody has
        // collected. Both mean the holder will not release anything.
        Some(stat) if stat.starts_with('T') => Holder::Stopped,
        Some(stat) if stat.starts_with('Z') => Holder::Dead,
        // `ps` printed a state, or could not be run at all. The `kill` probe
        // already established that the process is there, so the honest answer
        // is that it is alive; refusing to answer would make every machine
        // without `/bin/ps` report a dead holder for a live one.
        _ => Holder::Alive,
    }
}

/// When a process started, as `ps` spells it (`Tue  9 Sep 12:00:00 2026`).
///
/// The string is compared, never parsed: its only job is to differ when a
/// process id has been recycled, and `ps`'s own formatting is stable enough
/// for that within one machine's uptime.
pub fn start_time(pid: u32) -> Option<String> {
    field("lstart", pid)
}

/// This process's start time, read once and remembered.
///
/// Called from [`crate::secret::namespace_lock::acquire`], which runs on every
/// refresh: a fresh `ps` per lock acquisition would be a subprocess in the hot
/// path for a value that cannot change while this process is alive.
pub fn self_start_time() -> Option<String> {
    static SELF_START: OnceLock<Option<String>> = OnceLock::new();
    SELF_START.get_or_init(|| start_time(std::process::id())).clone()
}

/// Runs `ps -o <name>= -p <pid>` and returns the single trimmed line it prints.
///
/// `None` covers every uninteresting outcome at once: `ps` could not be
/// spawned, it exceeded [`PS_TIMEOUT`], it exited non-zero because the process
/// had already gone, or it printed nothing. Every caller treats those the same
/// way, so distinguishing them would only add branches nobody reads.
fn field(name: &str, pid: u32) -> Option<String> {
    let mut child = Command::new(PS_BIN)
        .arg("-o")
        .arg(format!("{name}="))
        .arg("-p")
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    // Taken before the handle is registered: from that point the child table
    // owns the process and may kill it, and a half-taken pipe would be a
    // use-after-kill hazard.
    let stdout = child.stdout.take();

    let now = Instant::now();
    let ctx = PassCtx::standalone(Cancel::new(), now.checked_add(PS_TIMEOUT).unwrap_or(now));
    let token = ctx.register_child(child);
    let status = ctx.wait_child_timeout(token, PS_TIMEOUT).ok()??;
    if !status.success() {
        return None;
    }

    // Read after the child has exited: one line about one process id is orders
    // of magnitude below a pipe buffer, so there is no writer left to deadlock
    // against.
    let mut text = String::new();
    std::io::Read::read_to_string(&mut stdout?, &mut text).ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() { None } else { Some(trimmed.to_owned()) }
}

#[cfg(test)]
#[path = "proc_tests.rs"]
mod tests;
