//! Termination-signal handling.
//!
//! `agctl` can be holding a namespace lock and a half-written credential
//! temporary file when the user hits Ctrl-C, and can have the terminal in raw
//! mode and on the alternate screen when `watch` is killed. Dying on the
//! default disposition would leave both behind. So TERM, HUP and INT are
//! handled: each sets the pass-wide [`Cancel`], runs [`cleanup::emergency`],
//! and exits with the conventional `128 + signo` status.
//!
//! The work happens on a dedicated thread draining `signal_hook`'s iterator,
//! not in a signal handler. That matters: unlinking files and restoring the
//! terminal are not async-signal-safe, and doing them from a real handler
//! would risk deadlocking against whatever the interrupted thread was holding.
//! `signal_hook` registers a handler that does nothing but wake this thread.
//!
//! # Registered children die with the process
//!
//! A child handed to [`PassCtx::register_child`] — the `claude` that `agctl
//! claude exec` runs, a `security(1)` read or write — is meant to die with
//! agctl. The waits that own those children do kill them on cancellation, but
//! only on their next poll, and `process::exit` below would win that race
//! every time, leaving a `claude` with a live grant in memory reparented to
//! `launchd`. So before exiting this thread takes every child out of the
//! [`cleanup`] registry and ends it itself: `SIGTERM` first, a wait of at most
//! [`WORKER_JOIN_BUDGET`], then `SIGKILL` for whatever is still there.
//!
//! That grace period is honoured only for a child nobody is waiting on.
//! Cancellation is set before this thread signals anything, and a child's own
//! waiter also observes it and `SIGKILL`s the child within one poll interval —
//! possibly before this thread's `SIGTERM` has been sent. The `claude` under
//! `agctl claude exec` always has such a waiter, so in practice it receives
//! `SIGTERM` and then `SIGKILL` within about 10 ms, not 500 ms.
//!
//! A signal can also land between a child's `spawn` and its registration.
//! [`cleanup::begin_spawn_unless_cancelled`] closes that window: while a spawn is in flight this
//! thread keeps looking for newly registered children, within the same budget.
//!
//! Every signal is sent only after checking that the process id still has the
//! start time recorded when the child was registered. A child that has
//! already exited, or whose id now names some other process, is skipped. The
//! residual window is the one any `kill(2)` by process id has — between the
//! check and the send — and Darwin allocates process ids in increasing order,
//! so reusing one inside it would take the whole id space wrapping round.
//!
//! A Ctrl-C at the terminal reaches the child directly as well, because it is
//! in agctl's foreground process group, so such a child can receive `SIGINT`
//! and then this thread's `SIGTERM`. That is harmless: both ask it to stop.
//! A terminal in raw mode delivers Ctrl-C as a keystroke rather than a signal,
//! so a full-screen child that reads it that way never triggers this path.
//!
//! [`PassCtx::register_child`]: crate::runtime::coordinator::PassCtx::register_child

use std::io;
use std::process;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use rustix::process::Pid;
use rustix::process::Signal;
use signal_hook::consts::SIGHUP;
use signal_hook::consts::SIGINT;
use signal_hook::consts::SIGTERM;
use signal_hook::iterator::Signals;

use crate::runtime::cleanup;
use crate::runtime::cleanup::ChildEntry;
use crate::runtime::coordinator::Cancel;
use crate::runtime::coordinator::WORKER_JOIN_BUDGET;
use crate::runtime::proc;

/// The signals `agctl` handles.
const HANDLED: [i32; 3] = [SIGTERM, SIGHUP, SIGINT];

/// How often the signal thread re-checks the children it has signalled.
const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// How long the signal thread waits for a `SIGKILL` it sent to land.
///
/// Short, because nothing can block `SIGKILL`; it exists so emergency cleanup
/// — which releases Claude Code's lock directories — does not run while a
/// `security(1)` writer this process started is still being torn down.
const KILL_SETTLE: Duration = Duration::from_millis(50);

/// How long another thread defers to an exit already in progress before
/// giving up and carrying on.
///
/// Well above everything the signal thread does before it exits — the
/// children's budget, the kill settle and emergency cleanup — so reaching it
/// means that thread is stuck, and exiting on this one is the better outcome.
const EXIT_DEFERRAL_LIMIT: Duration = Duration::from_secs(10);

/// Set by the signal thread before it does anything else.
static EXITING: AtomicBool = AtomicBool::new(false);

/// The conventional exit status for a process killed by `signal`.
///
/// Uses checked arithmetic rather than `128 + signal` because overflow checks
/// are compiled out in every profile of this project, so a nonsensical signal
/// number would otherwise wrap into a plausible status.
fn exit_status_for(signal: i32) -> i32 {
    signal.checked_add(128).unwrap_or(128)
}

/// Installs the termination-signal handler thread.
///
/// On any of TERM, HUP or INT the handler sets `cancel`, runs emergency
/// cleanup, and terminates the process with `128 + signo` — 143, 129 and 130
/// respectively.
///
/// # Errors
///
/// Returns the underlying [`io::Error`] if the signals cannot be registered or
/// the handler thread cannot be started.
pub fn install(cancel: Cancel) -> io::Result<()> {
    let mut signals = Signals::new(HANDLED)?;
    thread::Builder::new().name("agctl-signals".to_owned()).spawn(move || {
        // Only the first signal is ever acted on: handling it ends the
        // process, so there is no second iteration to write.
        if let Some(signal) = signals.forever().next() {
            // Before `cancel`, so a thread that wakes on the cancellation
            // already sees an exit in progress (see [`defer_to_exit`]).
            EXITING.store(true, Ordering::SeqCst);
            cancel.cancel();
            // Before emergency cleanup, not after: cleanup releases lock
            // directories, and a `security(1)` child still writing under
            // one of them must be gone first.
            terminate_children(&cancel);
            cleanup::emergency();
            process::exit(exit_status_for(signal));
        }
    })?;
    Ok(())
}

/// Parks the calling thread while a signal-driven exit is in progress.
///
/// Returns at once when there is none. Otherwise it waits — up to
/// [`EXIT_DEFERRAL_LIMIT`] — for the signal thread's `process::exit`, which
/// ends the process from under it. This is what keeps the exit status
/// `128 + signo`: a command that saw its child killed by that thread would
/// otherwise race back to `main` and exit with the child's status or its own
/// error code first.
pub fn defer_to_exit() {
    if !EXITING.load(Ordering::SeqCst) {
        return;
    }
    let started = Instant::now();
    while started.elapsed() < EXIT_DEFERRAL_LIMIT {
        thread::park_timeout(EXIT_DEFERRAL_LIMIT.saturating_sub(started.elapsed()));
    }
}

/// Ends every registered child: `SIGTERM`, a wait bounded by
/// [`WORKER_JOIN_BUDGET`], then `SIGKILL`.
fn terminate_children(cancel: &Cancel) {
    terminate_with(
        WORKER_JOIN_BUDGET,
        cleanup::take_children,
        cleanup::spawns_in_flight,
        |entry| still_ours(entry, cancel),
        |pid, signal| {
            if let Ok(raw) = i32::try_from(pid)
                && let Some(pid) = Pid::from_raw(raw)
            {
                // A failure means the process is already gone, which is the
                // state this was trying to reach.
                let _ = rustix::process::kill_process(pid, signal);
            }
        },
    );
}

/// Whether `entry`'s process id still names the child that was registered,
/// and that child has not yet exited.
///
/// Both halves read the process table afresh. An unreadable start time counts
/// as "not ours": it is what a reaped child looks like, and a process this one
/// cannot identify is not one it may signal.
fn still_ours(entry: &ChildEntry, cancel: &Cancel) -> bool {
    proc::start_time(entry.pid, cancel).as_deref() == Some(entry.start_time.as_str())
        && proc::holder(entry.pid, cancel) != proc::Holder::Dead
}

/// The escalation behind [`terminate_children`], with the process table and
/// `kill(2)` passed in so the recycled-id and dead-entry rules can be tested
/// without signalling real processes.
///
/// `take` is polled again while waiting, and the wait does not end while
/// `in_flight` reports an open spawn window, so a child registered after the
/// first sweep — a spawn that was already under way when the signal arrived —
/// is still signalled rather than left behind.
///
/// `in_flight` is read **before** `take` on every round. A spawner registers
/// its child and only then closes its window, so a window seen closed before
/// the take means that child is already in what the take returns — and a
/// window opened after the read belongs to a spawner that will see the
/// cancellation and not spawn. Reading it after the take would miss a child
/// registered between the two calls.
fn terminate_with(
    budget: Duration,
    mut take: impl FnMut() -> Vec<ChildEntry>,
    in_flight: impl Fn() -> bool,
    is_ours: impl Fn(&ChildEntry) -> bool,
    mut send: impl FnMut(u32, Signal),
) {
    let mut pending: Vec<ChildEntry> = Vec::new();
    let now = Instant::now();
    let deadline = now.checked_add(budget).unwrap_or(now);
    loop {
        let spawning = in_flight();
        for entry in take() {
            if is_ours(&entry) {
                send(entry.pid, Signal::TERM);
                pending.push(entry);
            }
        }
        pending.retain(|entry| is_ours(entry));
        if (pending.is_empty() && !spawning) || Instant::now() >= deadline {
            break;
        }
        thread::sleep(CHILD_POLL_INTERVAL);
    }

    if pending.is_empty() {
        return;
    }
    for entry in &pending {
        if is_ours(entry) {
            send(entry.pid, Signal::KILL);
        }
    }
    let now = Instant::now();
    let settle = now.checked_add(KILL_SETTLE).unwrap_or(now);
    while Instant::now() < settle {
        pending.retain(|entry| is_ours(entry));
        if pending.is_empty() {
            break;
        }
        thread::sleep(CHILD_POLL_INTERVAL);
    }
}

#[cfg(test)]
#[path = "signals_tests.rs"]
mod tests;
