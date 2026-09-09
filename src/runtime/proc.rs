//! Asking the operating system about a process that is not this one.
//!
//! `doctor` reports who holds a namespace lock and whether that process is
//! still there (plan AC45), the lock body records a start time so a recycled
//! process id cannot be mistaken for the original holder (plan AC48(c)), and
//! the Claude Code lock protocol asks whether any same-user `claude` is
//! *stopped* before it will break a lock (plan section 3.8 condition 2). All
//! three need facts the standard library does not offer.
//!
//! # Why this module holds the crate's only `unsafe`
//!
//! Phase 1 answered the state and start-time questions by running the
//! system's process lister and parsing one line. Decision **D-022** retires
//! that: on Darwin that binary is **setuid root**, and a sandboxed process
//! may not exec a setuid binary at all — under the phase-2 manual-check
//! sandbox `execvp()` fails with `Operation not permitted` (spike S12, V12).
//! The consequence was not a missing diagnostic but a *wrong* one: the holder
//! check would have got process ids with no states, a shape the audit
//! vocabulary cannot express, and the tempting reading of "no state" is
//! `no_stopped_claude` — a false negative that licenses a lock break.
//!
//! So the three questions are answered in-process through Darwin's `libproc`
//! interface: [`ffi::all_pids`] (`proc_listpids`), [`ffi::bsd_info`]
//! (`proc_pidinfo` with `PROC_PIDTBSDINFO`) and [`ffi::name`] (`proc_name`).
//! No child process, no argv, and — the part that matters for ruling 4 — no
//! call on this path can return another process's environment. The kernel's
//! process-argument interface is named nowhere in this crate, and neither is
//! the C symbol for a process's environment block; plan AC80 asserts both by
//! grep as well as by construction.
//!
//! The alternatives were weighed and rejected in D-022: the `libproc` crate
//! needs `bindgen` and `libclang` at build time, and `sysinfo` pulls in the
//! `objc2-*` tree and offers an environment accessor on the very type this
//! module would hand around. `libc` was already in the dependency graph.
//!
//! # Two sources, because neither is enough alone
//!
//! `kill(pid, 0)` answers "does a process with this id exist", cheaply and
//! including the `EPERM` case, which means the process exists and belongs to
//! somebody else. What it cannot say is whether that process is *running*: a
//! `SIGSTOP`ed holder looks exactly like a healthy one, and a lock held by a
//! stopped process is a lock that will not be released by waiting. That comes
//! from `proc_bsdinfo::pbi_status`.

use std::sync::OnceLock;

use rustix::process::Pid;

use crate::runtime::coordinator::Cancel;

/// The process name a Claude Code session runs under.
///
/// Compared with `==` against `proc_name`, never as a substring and never
/// case-insensitively: `Claude.app`'s helpers (`Claude Helper`,
/// `Claude Helper (Renderer)`, …) all contain "Claude" and none of them holds
/// a credential-store lock (fact F57).
pub const CLAUDE_PROCESS_NAME: &str = "claude";

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

/// Why the process table could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProcError {
    /// `proc_listpids` failed, so there is no candidate list at all.
    #[error("the process list could not be read: {0}")]
    Listing(String),
    /// At least one process that still exists could not be classified.
    ///
    /// Reported as an error rather than as a shorter list on purpose: a
    /// caller that took the shorter list would record "no stopped `claude`"
    /// having failed to look at every process, which is the false negative
    /// V12 identified and section 3.8 forbids.
    #[error("{unreadable} process(es) exist but could not be classified")]
    Incomplete {
        /// How many process ids existed and could not be read.
        unreadable: usize,
    },
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
/// The `kill(pid, 0)` probe comes first because it is the cheaper call and
/// because it is the one that reports another user's process honestly.
///
/// `cancel` is retained so every caller keeps compiling unchanged across
/// D-022; nothing here can block any more, so there is nothing left to
/// interrupt.
pub fn holder(pid: u32, _cancel: &Cancel) -> Holder {
    if !exists(pid) {
        return Holder::Dead;
    }
    match ffi::bsd_info(pid) {
        Ok(info) => holder_from_status(info.pbi_status),
        // The `kill` probe already established that the process is there, so
        // the honest answer is that it is alive; refusing to answer would
        // make every unreadable process report a dead holder for a live one.
        // The break rule does **not** reuse this default — see
        // [`claude_processes`](crate::runtime::proc::claude_processes).
        Err(_) => Holder::Alive,
    }
}

/// Maps `proc_bsdinfo::pbi_status` onto the three states callers care about.
///
/// `SSTOP` covers `SIGSTOP`, a tty stop (`SIGTTIN`/`SIGTTOU` from a
/// backgrounded pane) and `Ctrl-Z` alike, and `SZOMB` is a process whose exit
/// status nobody has collected. Both mean the holder will not release
/// anything. `SIDL`, `SRUN` and `SSLEEP` are all "alive" for this purpose.
fn holder_from_status(status: u32) -> Holder {
    match status {
        libc::SSTOP => Holder::Stopped,
        libc::SZOMB => Holder::Dead,
        _ => Holder::Alive,
    }
}

/// When a process started, to microsecond resolution.
///
/// The string is **compared, never parsed**: its only job is to differ when a
/// process id has been recycled. D-022 changes its spelling from `ps -o
/// lstart=`'s one-second `ctime` format to an RFC 3339 timestamp carrying the
/// microseconds `proc_bsdinfo` reports, which makes a recycled id detectable
/// inside the same second as well as across seconds.
///
/// One consequence, deliberate and self-clearing: a lock body written by a
/// phase-1 build carries the old spelling, so a phase-2 `doctor` comparing it
/// against a fresh read sees a mismatch and prints `dead (pid recycled)` for
/// a holder that may well be alive. That errs towards suspicion rather than
/// towards trusting a stale claim, `doctor` never removes an agentctl
/// namespace lock, and the next acquire rewrites the body.
pub fn start_time(pid: u32, _cancel: &Cancel) -> Option<String> {
    let info = ffi::bsd_info(pid).ok()?;
    render_start_time(info.pbi_start_tvsec, info.pbi_start_tvusec)
}

/// Renders `pbi_start_tvsec`/`pbi_start_tvusec` as one comparable string.
///
/// Checked arithmetic throughout: overflow checks are compiled out in every
/// profile of this project (constraint C-006), so a nonsensical value from
/// the kernel must not be allowed to wrap into a plausible timestamp.
fn render_start_time(tvsec: u64, tvusec: u64) -> Option<String> {
    let secs = i64::try_from(tvsec).ok()?;
    let usecs = i64::try_from(tvusec).ok()?;
    let total = secs.checked_mul(1_000_000)?.checked_add(usecs)?;
    jiff::Timestamp::from_microsecond(total).ok().map(|at| at.to_string())
}

/// This process's start time, read once and remembered.
///
/// Called from [`crate::secret::namespace_lock::acquire`], which runs on
/// every refresh. Memoized because the value cannot change while this process
/// is alive, not because reading it is expensive any more.
pub fn self_start_time(cancel: &Cancel) -> Option<String> {
    static SELF_START: OnceLock<Option<String>> = OnceLock::new();
    SELF_START.get_or_init(|| start_time(std::process::id(), cancel)).clone()
}

/// Every same-user process whose name is exactly [`CLAUDE_PROCESS_NAME`],
/// with its state.
///
/// This is the evidence half of section 3.8's break rule, and its contract is
/// the opposite of [`holder`]'s: **an unreadable process is an error, not an
/// "alive"**. A caller that received a shorter list would conclude
/// `no_stopped_claude` without having looked at every process, and that
/// conclusion licenses removing a directory a live session may be holding
/// (V12). An `Err` maps to `holder_evidence: "none"` — "I do not know" — and
/// the rule then rests on the mtime samples alone.
///
/// Two kinds of "could not read" are **not** unreadable, and both matter for
/// the answer to be useful at all. A process id that has gone between the
/// listing and the classification no longer exists, so it cannot be a stopped
/// holder. And a process the kernel refuses to describe *and that this process
/// may not signal* belongs to another user, so it cannot be a *same-user*
/// `claude`; on this machine that is 313 of about 700 processes, so counting
/// those as unreadable would make the evidence permanently inconclusive.
///
/// The second half of that sentence is load-bearing. `EPERM` alone does not
/// mean "somebody else's": a sandbox profile carrying `(deny process-info*)`
/// — and the manual checks for decisions D-016/D-023 run under
/// `sandbox-exec` — makes `proc_pidinfo` answer `EPERM` for **every** process,
/// this user's included. Reading that as "not ours" would return an empty list
/// from a sweep that classified nothing, `no_stopped_claude` would follow, and
/// a `SIGSTOP`ped session's lock would be broken on modification times alone:
/// the exact false negative spike V12 identified. So the two are told apart by
/// `kill(pid, 0)`, which succeeds only for a process this one may signal.
///
/// # Errors
///
/// [`ProcError::Listing`] when the process list itself could not be read, and
/// [`ProcError::Incomplete`] when a process of ours could not be classified
/// **and** no stopped `claude` was found anyway — see [`sweep`] for why the
/// second half of that condition is there.
pub fn claude_processes() -> Result<Vec<(u32, Holder)>, ProcError> {
    let uid = rustix::process::getuid().as_raw();
    sweep(ffi::all_pids()?.into_iter().map(|pid| (pid, look(uid, pid))))
}

/// What one process looked like to the sweep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seen {
    /// A same-user `claude`, in this state.
    Claude(Holder),
    /// Readable, and not a same-user `claude`.
    Other,
    /// Gone between the listing and the classification.
    Gone,
    /// Still there, ours, and **not classified** — the one shape a stopped
    /// `claude` can hide in.
    Unclassified,
}

/// Turns per-process observations into the evidence the break rule asks for.
///
/// Separated from the syscalls so the aggregation — "one unclassified process
/// of ours makes the whole sweep incomplete" — is checkable without a sandbox.
///
/// One asymmetry, and it is deliberate: a **stopped** `claude` that was found
/// is returned even when some other process could not be classified. The
/// question section 3.8 asks is "is any same-user `claude` stopped?", and a
/// `yes` does not become less true for having stopped looking. Discarding it
/// would turn a positive into `none` and let the break proceed on modification
/// times alone — the very outcome the incompleteness check exists to prevent.
/// Incompleteness only ever suppresses a **negative**.
fn sweep(seen: impl IntoIterator<Item = (u32, Seen)>) -> Result<Vec<(u32, Holder)>, ProcError> {
    let mut found = Vec::new();
    let mut unreadable = 0_usize;
    let mut stopped = false;
    for (pid, seen) in seen {
        match seen {
            Seen::Claude(state) => {
                stopped = stopped || state == Holder::Stopped;
                found.push((pid, state));
            }
            Seen::Other | Seen::Gone => {}
            Seen::Unclassified => unreadable = unreadable.saturating_add(1),
        }
    }

    if unreadable > 0 && !stopped {
        return Err(ProcError::Incomplete { unreadable });
    }
    Ok(found)
}

/// Classifies one process id, asking the kernel only what it needs.
fn look(uid: u32, pid: u32) -> Seen {
    classify(
        uid,
        ffi::bsd_info(pid).map(|info| (info.pbi_uid, info.pbi_status)),
        || ffi::name(pid),
        || signalable(pid),
    )
}

/// [`look`]'s decision, with every kernel answer already in hand.
///
/// `name` and `signalable` are taken as closures because each costs a syscall
/// and most processes need neither; they are *parameters* rather than calls so
/// that the `EPERM` row — a process the kernel describes to nobody yet this
/// process may signal — is reachable in a test.
fn classify(
    uid: u32,
    info: Result<(u32, u32), ffi::InfoError>,
    name: impl FnOnce() -> Option<String>,
    signalable: impl Fn() -> bool,
) -> Seen {
    match info {
        Ok((owner, status)) => {
            if owner != uid {
                return Seen::Other;
            }
            match name() {
                Some(name) if name == CLAUDE_PROCESS_NAME => {
                    Seen::Claude(holder_from_status(status))
                }
                Some(_) => Seen::Other,
                // Ours, still there, and unnameable: the one case that could
                // hide a stopped `claude`.
                None if signalable() => Seen::Unclassified,
                None => Seen::Gone,
            }
        }
        // `EPERM` means "another user's" only when we also cannot signal it.
        Err(ffi::InfoError::Refused) if signalable() => Seen::Unclassified,
        Err(ffi::InfoError::Refused) => Seen::Other,
        Err(ffi::InfoError::Gone) => Seen::Gone,
        // A short answer from a mismatched kernel struct would come back for
        // every process alike, so one that cannot be signalled either is not
        // ours and cannot hide a same-user holder.
        Err(ffi::InfoError::Unreadable) if signalable() => Seen::Unclassified,
        Err(ffi::InfoError::Unreadable) => Seen::Other,
    }
}

/// Whether this process may signal `pid`, which is what makes it **ours**.
///
/// Distinct from [`exists`], which counts `EPERM` as existing: here `EPERM` is
/// the answer that means "not ours", and conflating the two is what let an
/// unreadable same-user process table pass for an empty one.
fn signalable(pid: u32) -> bool {
    let Ok(raw) = i32::try_from(pid) else { return false };
    let Some(pid) = Pid::from_raw(raw) else { return false };
    matches!(rustix::process::test_kill_process(pid), Ok(()))
}

/// The three `libproc` calls, and the only `unsafe` in the crate.
///
/// Every function here is a safe wrapper that owns its buffer, passes that
/// buffer's own length as the size argument, and turns every failure into
/// `None` or a [`ProcError`]. Nothing `unsafe` escapes: no raw pointer, no
/// partially-initialised struct and no unbounded length crosses the module
/// boundary.
mod ffi {
    use std::mem;

    use super::ProcError;

    /// `PROC_ALL_PIDS` from `<sys/proc_info.h>`.
    ///
    /// Spelled here because the `libc` crate exports `PROC_PIDTBSDINFO` but
    /// not the `proc_listpids` type selectors.
    const PROC_ALL_PIDS: u32 = 1;

    /// How many extra slots are asked for beyond the size the kernel reports.
    ///
    /// The count can grow between the sizing call and the filling call, and a
    /// buffer filled exactly to its limit is indistinguishable from one that
    /// was truncated. Slack makes the common case a single pair of calls.
    const PID_SLACK: usize = 128;

    /// How many times the buffer is grown before giving up.
    const SIZING_ATTEMPTS: u32 = 4;

    /// Every process id on the machine.
    pub(super) fn all_pids() -> Result<Vec<u32>, ProcError> {
        let mut slots = sizing_hint()?.saturating_add(PID_SLACK);

        for _ in 0..SIZING_ATTEMPTS {
            let mut buffer = vec![0_i32; slots];
            let bytes = i32::try_from(std::mem::size_of_val(buffer.as_slice())).map_err(|_| {
                ProcError::Listing("the process list is implausibly large".to_owned())
            })?;

            // SAFETY: `buffer` owns `slots` initialised `i32`s and `bytes` is
            // exactly that many bytes, so `proc_listpids` cannot write past
            // the allocation. The pointer is valid for the duration of the
            // call because `buffer` outlives it.
            let filled =
                unsafe { libc::proc_listpids(PROC_ALL_PIDS, 0, buffer.as_mut_ptr().cast(), bytes) };
            if filled <= 0 {
                return Err(ProcError::Listing(last_os_error()));
            }

            let filled = usize::try_from(filled)
                .map_err(|_| ProcError::Listing("a negative byte count".to_owned()))?;
            let count = filled / size_of::<i32>();
            if count >= slots {
                // The buffer may have been truncated; ask for a bigger one.
                slots = slots.saturating_mul(2);
                continue;
            }

            // Zero and negative entries are padding, never process ids: the
            // kernel writes the array without compacting it.
            return Ok(buffer
                .into_iter()
                .take(count)
                .filter(|raw| *raw > 0)
                .filter_map(|raw| u32::try_from(raw).ok())
                .collect());
        }

        Err(ProcError::Listing("the process list kept outgrowing the buffer".to_owned()))
    }

    /// How many process-id slots the kernel says it needs.
    fn sizing_hint() -> Result<usize, ProcError> {
        // SAFETY: a null buffer with a zero size is the documented way to ask
        // `proc_listpids` for the size it would need; it writes nothing at
        // all through the pointer.
        let bytes = unsafe { libc::proc_listpids(PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0) };
        if bytes <= 0 {
            return Err(ProcError::Listing(last_os_error()));
        }
        let bytes =
            usize::try_from(bytes).map_err(|_| ProcError::Listing("a negative size".to_owned()))?;
        Ok(bytes / size_of::<i32>())
    }

    /// Why one process's BSD info could not be read.
    ///
    /// The distinction is load-bearing rather than diagnostic.
    /// [`Refused`](InfoError::Refused) is what the kernel answers for a
    /// process belonging to **another user**, and a process that is not ours
    /// cannot be a same-user `claude` — so it is irrelevant to the break
    /// rule rather than evidence the rule is missing. Measured on this
    /// machine: 313 of about 700 processes answer `EPERM`, so treating that
    /// as "unreadable" would make the holder check permanently
    /// inconclusive.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum InfoError {
        /// `EPERM`: the process exists and belongs to somebody else.
        Refused,
        /// `ESRCH`: there is no such process any more.
        Gone,
        /// Anything else, including a short answer.
        Unreadable,
    }

    /// One process's BSD info.
    ///
    /// # Errors
    ///
    /// See [`InfoError`].
    pub(super) fn bsd_info(pid: u32) -> Result<libc::proc_bsdinfo, InfoError> {
        let raw = i32::try_from(pid).map_err(|_| InfoError::Gone)?;
        let size =
            i32::try_from(size_of::<libc::proc_bsdinfo>()).map_err(|_| InfoError::Unreadable)?;

        // SAFETY: `proc_bsdinfo` is a `repr(C)` aggregate of integers and
        // `c_char` arrays, so an all-zero value is a valid inhabitant of the
        // type; the kernel overwrites it wholesale on success and the return
        // value below is what decides whether it did.
        let mut info: libc::proc_bsdinfo = unsafe { mem::zeroed() };

        // SAFETY: the pointer addresses one live, fully initialised
        // `proc_bsdinfo` and `size` is exactly that type's size, so the
        // kernel cannot write past it. `info` outlives the call.
        let filled = unsafe {
            libc::proc_pidinfo(raw, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size)
        };
        if filled == size {
            return Ok(info);
        }

        // A short answer means the running kernel's struct is not the one
        // this build was compiled against, which is a reason to know nothing
        // rather than to trust half a struct.
        if filled > 0 {
            return Err(InfoError::Unreadable);
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EPERM) => Err(InfoError::Refused),
            Some(libc::ESRCH) => Err(InfoError::Gone),
            _ => Err(InfoError::Unreadable),
        }
    }

    /// One process's name, exactly as the kernel accounts for it.
    pub(super) fn name(pid: u32) -> Option<String> {
        let raw = i32::try_from(pid).ok()?;

        // `proc_name` copies `pbi_name` — 2 × `MAXCOMLEN` bytes — when the
        // buffer is at least that large, and `pbi_comm` otherwise. Sized for
        // the longer of the two plus room for a terminator.
        let mut buffer = [0_u8; 64];
        let size = u32::try_from(buffer.len()).ok()?;

        // SAFETY: `buffer` is `size` writable bytes and `size` is its own
        // length, so `proc_name` cannot write past it. It returns the number
        // of bytes it wrote, which is what bounds the slice below.
        let written = unsafe { libc::proc_name(raw, buffer.as_mut_ptr().cast(), size) };
        if written <= 0 {
            return None;
        }

        let len = usize::try_from(written).ok()?.min(buffer.len());
        // Trailing NULs are trimmed as well as bounded: the implementation
        // copies a fixed-width field and reports `strlen`, and being wrong
        // about either would turn `claude` into `claude\0…` and never match.
        let name = &buffer[..len];
        let name = name.split(|byte| *byte == 0).next().unwrap_or(name);
        std::str::from_utf8(name).ok().map(str::to_owned)
    }

    /// The current `errno`, rendered.
    fn last_os_error() -> String {
        std::io::Error::last_os_error().to_string()
    }
}

#[cfg(test)]
#[path = "proc_tests.rs"]
mod tests;
