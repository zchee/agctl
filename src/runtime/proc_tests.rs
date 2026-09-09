//! Tests for the process probes `doctor`, the lock body and the Claude Code
//! break rule rely on.
//!
//! Every test that needs a *stopped* process makes one of its own: a copy of
//! `/bin/sleep` under a temporary directory, named `claude` so the kernel
//! accounts for it under that name exactly as a real session's launcher does
//! (spike S12, V12). **No real `claude` process is ever signalled**, and the
//! only process id any test here passes to `kill` is one it spawned itself.

use std::path::Path;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

use super::*;

/// A process id no running process can have.
///
/// `kill(0, 0)` addresses the caller's whole process group and `kill(-n, …)`
/// addresses another group, so zero and negatives are not usable as "surely
/// absent"; `u32::MAX` is above every `pid_max` any of these platforms
/// supports and does not even convert to the `i32` the syscall takes.
const IMPOSSIBLE_PID: u32 = u32::MAX;

/// How long a state transition is waited for before the test gives up.
const SETTLE: Duration = Duration::from_secs(5);

/// A child process this test spawned, killed and reaped on drop.
///
/// Owning the handle is what keeps the promise in the module documentation
/// mechanical rather than aspirational: the only pid these tests can signal
/// is one held by this guard.
struct OwnChild {
    child: Child,
    #[expect(dead_code, reason = "held so the copied binary outlives the process")]
    dir: tempfile::TempDir,
}

impl OwnChild {
    /// Spawns a copy of `/bin/sleep` under `name` and waits until it runs.
    fn spawn_named(name: &str) -> Self {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let binary = dir.path().join(name);
        std::fs::copy("/bin/sleep", &binary).expect("`/bin/sleep` is copyable");
        make_executable(&binary);

        let child = Command::new(&binary)
            .arg("600")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("the copied binary should be spawnable");
        let own = Self { child, dir };
        own.wait_for(Holder::Alive);
        own
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Sends `SIGSTOP` to **this** child and waits for the state to show it.
    fn stop(&self) {
        self.signal(rustix::process::Signal::STOP).expect("signalling our own child");
        self.wait_for(Holder::Stopped);
    }

    /// Signals **this** child, and nothing else: the pid comes from the
    /// handle this guard owns.
    fn signal(&self, signal: rustix::process::Signal) -> Option<()> {
        let raw = i32::try_from(self.pid()).ok()?;
        let pid = Pid::from_raw(raw)?;
        rustix::process::kill_process(pid, signal).ok()
    }

    /// Polls until the child reports `want`, because "spawned" and "has run
    /// its first instruction" are different moments.
    fn wait_for(&self, want: Holder) {
        let deadline = Instant::now() + SETTLE;
        while Instant::now() < deadline {
            if holder(self.pid(), &Cancel::new()) == want {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("child {} never reached {want:?}", self.pid());
    }
}

impl Drop for OwnChild {
    fn drop(&mut self) {
        // A stopped child stays stopped until it is continued, so it is
        // continued first and then killed; both signals go to our own pid.
        let _ = self.signal(rustix::process::Signal::CONT);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, PermissionsExt::from_mode(0o755)).expect("mode 0755");
}

#[test]
fn this_process_exists_and_is_alive() {
    let pid = std::process::id();
    assert!(exists(pid), "the running test process exists");
    assert_eq!(holder(pid, &Cancel::new()), Holder::Alive);
}

#[test]
fn an_impossible_pid_is_dead() {
    assert!(!exists(IMPOSSIBLE_PID));
    assert_eq!(
        holder(IMPOSSIBLE_PID, &Cancel::new()),
        Holder::Dead,
        "no subprocess is needed to say so"
    );
}

#[test]
fn pid_one_exists_even_though_it_is_not_ours() {
    // `launchd` and `init` both run as root, so `kill(1, 0)` returns `EPERM`
    // rather than succeeding. That is the case this probe must not read as
    // "gone" (plan AC45: a lock held by another user's process is still held).
    assert!(exists(1), "pid 1 exists even when signalling it is refused");
}

#[test]
fn a_start_time_is_readable_and_stable() {
    // Plan AC48(c): the value the lock body records.
    let first = self_start_time(&Cancel::new()).expect("libproc answers for this process");
    assert!(!first.is_empty());
    assert_eq!(
        first,
        self_start_time(&Cancel::new()).expect("memoized"),
        "memoized, so it cannot drift"
    );
    assert_eq!(
        Some(first),
        start_time(std::process::id(), &Cancel::new()),
        "the memo answers what a fresh read would"
    );
}

#[test]
fn a_start_time_for_an_impossible_pid_is_unavailable() {
    assert_eq!(start_time(IMPOSSIBLE_PID, &Cancel::new()), None);
}

#[test]
fn a_start_time_carries_microseconds() {
    // The whole point of D-022's change of spelling: `ps -o lstart=` had
    // one-second resolution, so a pid recycled inside the same second was
    // indistinguishable from its predecessor.
    let rendered = render_start_time(1_757_400_000, 123_456).expect("a valid instant");
    assert_eq!(rendered, "2025-09-09T06:40:00.123456Z", "rendered, not parsed, but exact");
    assert_ne!(
        rendered,
        render_start_time(1_757_400_000, 123_457).expect("a valid instant"),
        "one microsecond apart is still two different holders"
    );
}

#[test]
fn an_implausible_start_time_is_unavailable_rather_than_wrapped() {
    // Overflow checks are compiled out in every profile, so the checked
    // arithmetic is the only thing between a nonsensical kernel value and a
    // plausible-looking timestamp.
    assert_eq!(render_start_time(u64::MAX, 0), None);
    assert_eq!(render_start_time(u64::MAX / 2, u64::MAX), None);
}

#[test]
fn holder_labels_are_the_words_doctor_prints() {
    assert_eq!(Holder::Alive.label(), "alive");
    assert_eq!(Holder::Stopped.label(), "stopped");
    assert_eq!(Holder::Dead.label(), "dead");
}

#[test]
fn every_bsd_status_maps_to_one_of_the_three_states() {
    assert_eq!(holder_from_status(libc::SSTOP), Holder::Stopped);
    assert_eq!(holder_from_status(libc::SZOMB), Holder::Dead);
    for alive in [libc::SIDL, libc::SRUN, libc::SSLEEP] {
        assert_eq!(holder_from_status(alive), Holder::Alive, "status {alive}");
    }
}

#[test]
fn a_stopped_child_is_reported_as_stopped() {
    // The whole reason `kill(pid, 0)` is not enough: a stopped process answers
    // the probe exactly as a running one does, and a lock it holds will never
    // be released by waiting.
    let child = OwnChild::spawn_named("sleeper");
    child.stop();
    assert_eq!(holder(child.pid(), &Cancel::new()), Holder::Stopped);
}

#[test]
fn a_reaped_child_is_reported_as_dead() {
    let mut child = OwnChild::spawn_named("sleeper");
    let pid = child.pid();
    child.child.kill().expect("killing our own child");
    child.child.wait().expect("reaping our own child");
    assert_eq!(holder(pid, &Cancel::new()), Holder::Dead, "reaped, so nothing is there");
}

// ---------------------------------------------------------------------------
// AC80 — the holder check reads process state and nothing else
// ---------------------------------------------------------------------------

/// This process's user id, for the per-process classification assertions.
fn our_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

#[test]
fn claude_processes_finds_a_stopped_same_user_claude() {
    // Plan AC80's live half. The child is a copy of `/bin/sleep` named
    // `claude`, which is what makes the kernel account for it under that
    // name; the real Claude Code binary is never run and never signalled.
    //
    // The running half is asserted per process rather than through the whole
    // sweep, because the sweep's verdict legitimately depends on every other
    // process on the machine: one of ours that the kernel will not describe
    // makes it `Incomplete`, which is the honest answer and not this test's
    // subject.
    let child = OwnChild::spawn_named("claude");
    assert_eq!(
        look(our_uid(), child.pid()),
        Seen::Claude(Holder::Alive),
        "a running same-user `claude` is seen, and seen as alive"
    );

    child.stop();
    assert_eq!(look(our_uid(), child.pid()), Seen::Claude(Holder::Stopped));
    // And through the sweep, which reports a stopped `claude` it found even if
    // it could not classify everything else — the asymmetry `sweep` documents.
    let found = claude_processes().expect("a stopped `claude` is an answer, not an incomplete one");
    assert!(
        found.iter().any(|(pid, state)| *pid == child.pid() && *state == Holder::Stopped),
        "a stopped same-user `claude` is listed as stopped: {found:?}"
    );
}

#[test]
fn a_name_that_merely_contains_claude_is_not_a_match() {
    // Fact F57's two banned matchers in one assertion: `Claude.app`'s helpers
    // contain "Claude" and a match on the full command line would sweep in
    // arguments as well as names.
    //
    // Per process for the reason above: what is under test is the matcher, not
    // whether every other process on a busy machine happened to be readable.
    let helper = OwnChild::spawn_named("Claude Helper");
    let prefixed = OwnChild::spawn_named("claude-code");
    for other in [&helper, &prefixed] {
        assert_eq!(
            look(our_uid(), other.pid()),
            Seen::Other,
            "only an exact, case-sensitive `claude` matches: `{:?}`",
            ffi::name(other.pid())
        );
    }
}

#[test]
fn another_users_process_is_refused_rather_than_unreadable() {
    // The measurement that makes `claude_processes` usable at all: the kernel
    // answers `EPERM` for a process belonging to somebody else, and a process
    // that is not ours cannot be a same-user `claude`. If this ever became
    // `Unreadable`, the holder evidence would go permanently inconclusive
    // rather than silently wrong — but it would still be a regression.
    assert!(exists(1), "pid 1 is there");
    assert_eq!(ffi::bsd_info(1).err(), Some(ffi::InfoError::Refused), "launchd runs as root");
    assert_eq!(
        ffi::bsd_info(IMPOSSIBLE_PID).err(),
        Some(ffi::InfoError::Gone),
        "a pid that cannot exist is gone, not unreadable"
    );
    assert!(ffi::bsd_info(std::process::id()).is_ok(), "our own process is readable");
}

#[test]
fn the_process_name_is_read_exactly() {
    let child = OwnChild::spawn_named("claude");
    assert_eq!(ffi::name(child.pid()).as_deref(), Some(CLAUDE_PROCESS_NAME));
    assert_eq!(ffi::name(IMPOSSIBLE_PID), None, "no name for a pid that cannot exist");
}

#[test]
fn the_process_list_is_readable_and_holds_this_process() {
    let pids = ffi::all_pids().expect("`proc_listpids` answers on this machine");
    assert!(pids.contains(&std::process::id()), "the list includes the reader");
    assert!(pids.iter().all(|pid| *pid > 0), "padding entries are dropped: {pids:?}");
    assert!(pids.len() > 1, "a machine running this test runs more than one process");
}

#[test]
fn partial_evidence_is_an_error_rather_than_a_shorter_list() {
    // V12's one substantive requirement, asserted on the type rather than on
    // a machine state the test cannot create: the only non-error answer is a
    // complete list, so a caller cannot mistake "could not read one process"
    // for "no stopped `claude`". The error's own text says so.
    let incomplete = ProcError::Incomplete { unreadable: 3 };
    assert_eq!(incomplete.to_string(), "3 process(es) exist but could not be classified");
    assert!(matches!(claude_processes(), Ok(_) | Err(ProcError::Incomplete { .. })));
}

#[test]
fn a_refused_process_we_can_still_signal_is_unclassified_not_absent() {
    // Review P1-4. `EPERM` from `proc_pidinfo` means "another user's" only
    // when this process also cannot signal it. Under a sandbox profile
    // carrying `(deny process-info*)` — and the manual checks for D-016/D-023
    // run under `sandbox-exec` — **every** process answers `EPERM`, our own
    // included, and reading that as "not ours" would make the sweep return an
    // empty list having classified nothing: `no_stopped_claude`, and a
    // `SIGSTOP`ped session's lock broken on modification times alone.
    //
    // The sandbox cannot be entered from inside a test, so the two answers are
    // driven directly: same `EPERM`, opposite `kill(pid, 0)`.
    let ours = classify(0, Err(ffi::InfoError::Refused), || None, || true);
    assert_eq!(ours, Seen::Unclassified, "a process we may signal is ours and was not classified");

    let theirs = classify(0, Err(ffi::InfoError::Refused), || None, || false);
    assert_eq!(theirs, Seen::Other, "and one we may not signal is somebody else's");

    // Which is what makes the difference between the two verdicts the break
    // rule keys on.
    assert_eq!(
        sweep([(4242, ours)]).err(),
        Some(ProcError::Incomplete { unreadable: 1 }),
        "an unclassified process of ours makes the whole sweep incomplete"
    );
    assert_eq!(sweep([(4242, theirs)]).ok(), Some(Vec::new()), "somebody else's is skipped");
}

#[test]
fn one_unreadable_process_of_ours_is_enough_to_make_the_sweep_incomplete() {
    // The aggregation on its own, including the shape that hid the false
    // negative: a sweep that found a `claude` **and** failed to read one
    // process of ours is still incomplete, because the one it could not read
    // may be another, stopped, `claude`.
    let seen = [
        (1, Seen::Other),
        (2, Seen::Claude(Holder::Alive)),
        (3, Seen::Gone),
        (4, Seen::Unclassified),
    ];
    assert_eq!(sweep(seen).err(), Some(ProcError::Incomplete { unreadable: 1 }));

    let complete = [(1, Seen::Other), (2, Seen::Claude(Holder::Stopped)), (3, Seen::Gone)];
    assert_eq!(sweep(complete).ok(), Some(vec![(2, Holder::Stopped)]));
}

#[test]
fn a_stopped_claude_that_was_found_survives_an_incomplete_sweep() {
    // The asymmetry, stated as a test because getting it wrong is a
    // credential: incompleteness must suppress a *negative* — "no stopped
    // `claude`", which would license a break — and never a positive. A `yes`
    // does not become less true for having stopped looking, and discarding it
    // would map a found stopped holder to `none` and let the break proceed on
    // modification times alone.
    let masked = [(7, Seen::Claude(Holder::Stopped)), (8, Seen::Unclassified)];
    assert_eq!(
        sweep(masked).ok(),
        Some(vec![(7, Holder::Stopped)]),
        "an unreadable process cannot hide a stopped `claude` that was found"
    );

    let alive_only = [(7, Seen::Claude(Holder::Alive)), (8, Seen::Unclassified)];
    assert_eq!(
        sweep(alive_only).err(),
        Some(ProcError::Incomplete { unreadable: 1 }),
        "a running one is not an answer to the question the rule asks"
    );
}

#[test]
fn the_signal_probe_tells_our_own_process_from_another_users() {
    // The distinguishing call, against the two processes every machine has:
    // this one, and `launchd`.
    assert!(signalable(std::process::id()), "we may signal ourselves");
    assert!(!signalable(1), "and not `launchd`, which runs as root");
    assert!(exists(1), "even though it plainly exists — which is the distinction");
    assert!(!signalable(IMPOSSIBLE_PID));
}

#[test]
fn this_module_names_no_process_argument_or_environment_api() {
    // Plan AC80, ruling 4: the grep that keeps the retired mechanism retired.
    // Held here as well as over the whole tree (tests/e2e_lock.rs) because
    // this is the one module that could plausibly reintroduce it.
    let source = include_str!("proc.rs");
    // Spelled by concatenation so this assertion is not itself the match its
    // sibling grep over `src/` would find (tests/e2e_lock.rs).
    let procargs = format!("KERN_{}", "PROCARGS");
    for banned in [procargs.as_str(), "proc_pidpath", "Command::new", "PS_BIN"] {
        assert!(!source.contains(banned), "`{banned}` must not appear in runtime/proc.rs");
    }
}
