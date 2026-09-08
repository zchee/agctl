//! Tests for the pass coordinator.
//!
//! The load-bearing ones are AC43: on cancellation or deadline a child process
//! a worker spawned must be dead and the workers joined, both inside 500 ms.
//! Every timing assertion measures a real [`Instant`] and asserts on the
//! measured value -- `debug_assert!` is compiled out in every profile of this
//! project, so it could not catch a regression here.

use std::process::Command;
use std::process::Stdio;
use std::sync::atomic::AtomicUsize;
use std::sync::mpsc::RecvTimeoutError;
use std::time::Instant;

use super::*;

/// The budget every abnormal-termination assertion in this file is held to.
const BUDGET: Duration = Duration::from_millis(500);

/// How long the sleeping child would live if nobody killed it. Long enough
/// that a passing test cannot be an accident of the child exiting on its own.
const SLEEP_SECONDS: &str = "30";

/// What a spawn-and-wait job reports back.
#[derive(Debug)]
struct ChildOutcome {
    pid: u32,
    /// Whether `wait_child` reported that the coordinator killed the child,
    /// rather than the child exiting on its own.
    killed_by_coordinator: bool,
}

/// Asks the operating system whether `pid` still exists.
///
/// Shells out to `ps` rather than calling `kill(pid, 0)` so this stays inside
/// the standard library: `libc` is only a transitive dependency here and
/// nothing in agentctl uses it directly.
fn pid_is_alive(pid: u32) -> bool {
    let output = Command::new("/bin/ps")
        .arg("-p")
        .arg(pid.to_string())
        .arg("-o")
        .arg("pid=")
        .output()
        .expect("running `ps` should succeed");
    !String::from_utf8_lossy(&output.stdout).trim().is_empty()
}

/// Builds a job that spawns a long `sleep`, registers it with the pass, and
/// reports its pid over `pid_tx` before waiting on it.
///
/// The handshake matters: without it a test could cancel the pass before the
/// child was ever registered and then assert on a coordinator that had nothing
/// to kill.
fn sleeping_child_job(pid_tx: Sender<u32>) -> Job<ChildOutcome> {
    Box::new(move |ctx: &PassCtx| {
        let child = Command::new("/bin/sleep")
            .arg(SLEEP_SECONDS)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawning `sleep` should succeed");
        let pid = child.id();
        let token = ctx.register_child(child);
        pid_tx.send(pid).expect("the test should still be listening for the pid");

        let killed_by_coordinator = match ctx.wait_child(token) {
            Ok(_status) => false,
            Err(err) => err.kind() == io::ErrorKind::Interrupted,
        };
        ChildOutcome { pid, killed_by_coordinator }
    })
}

/// Drains the pass channel until it disconnects, which happens exactly when
/// the last worker has been joined.
///
/// Returns the collected results and how long the drain took, or the receive
/// error if the channel went quiet without disconnecting.
fn drain_until_joined<T>(
    rx: &Receiver<T>,
    budget: Duration,
) -> Result<(Vec<T>, Duration), RecvTimeoutError> {
    let started = Instant::now();
    let mut collected = Vec::new();
    loop {
        let remaining = budget.saturating_sub(started.elapsed());
        match rx.recv_timeout(remaining) {
            Ok(value) => collected.push(value),
            Err(RecvTimeoutError::Disconnected) => return Ok((collected, started.elapsed())),
            Err(RecvTimeoutError::Timeout) => return Err(RecvTimeoutError::Timeout),
        }
    }
}

#[test]
fn cancel_kills_live_children_and_joins_workers_within_the_budget() {
    // AC43, cancellation half.
    let (pid_tx, pid_rx) = mpsc::channel();
    let cancel = Cancel::new();
    let deadline = Instant::now() + Duration::from_secs(60);

    let rx =
        run_pass(vec![sleeping_child_job(pid_tx)], cancel.clone(), deadline, DEFAULT_MAX_WORKERS);

    let pid = pid_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the job should register its child and report the pid");
    assert!(pid_is_alive(pid), "the child should be running before the pass is cancelled");

    let cancelled_at = Instant::now();
    cancel.cancel();

    let (results, drained_in) =
        drain_until_joined(&rx, BUDGET).expect("workers must be joined within the budget");
    let elapsed = cancelled_at.elapsed();

    assert!(
        elapsed <= BUDGET,
        "workers must join within {BUDGET:?} of cancellation, took {elapsed:?} (drain {drained_in:?})"
    );
    assert_eq!(results.len(), 1, "the job should still have reported its outcome");
    assert!(
        results[0].killed_by_coordinator,
        "the job should learn the coordinator killed its child, got {:?}",
        results[0]
    );
    assert!(!pid_is_alive(results[0].pid), "the child process must be dead and reaped");
}

#[test]
fn deadline_kills_live_children_and_joins_workers_within_the_budget() {
    // AC43, deadline half: the same guarantee with no cancellation, reached
    // by letting the pass deadline pass while a child is still running.
    let (pid_tx, pid_rx) = mpsc::channel();
    let cancel = Cancel::new();
    let deadline = Instant::now() + Duration::from_millis(300);

    let rx = run_pass(vec![sleeping_child_job(pid_tx)], cancel, deadline, DEFAULT_MAX_WORKERS);

    let pid = pid_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the job should register its child and report the pid");

    let (results, _) = drain_until_joined(&rx, Duration::from_millis(300) + BUDGET + BUDGET)
        .expect("workers must be joined after the deadline");
    let elapsed_past_deadline = Instant::now().saturating_duration_since(deadline);

    assert!(
        elapsed_past_deadline <= BUDGET,
        "workers must join within {BUDGET:?} of the deadline, overran by {elapsed_past_deadline:?}"
    );
    assert_eq!(results.len(), 1, "the job should still have reported its outcome");
    assert!(results[0].killed_by_coordinator, "the deadline should kill the child too");
    assert!(!pid_is_alive(pid), "the child process must be dead and reaped");
}

#[test]
fn a_normal_pass_streams_every_result_and_then_disconnects() {
    let jobs: Vec<Job<usize>> =
        (0..8_usize).map(|n| Box::new(move |_: &PassCtx| n * 2) as Job<usize>).collect();
    let deadline = Instant::now() + Duration::from_secs(30);

    let rx = run_pass(jobs, Cancel::new(), deadline, DEFAULT_MAX_WORKERS);
    let (mut results, _) =
        drain_until_joined(&rx, Duration::from_secs(10)).expect("a normal pass should finish");

    results.sort_unstable();
    assert_eq!(results, vec![0, 2, 4, 6, 8, 10, 12, 14], "every job's result should arrive");
}

#[test]
fn concurrency_never_exceeds_max_workers() {
    let live = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let max_workers = 4;

    let jobs: Vec<Job<usize>> = (0..24)
        .map(|_| {
            let live = Arc::clone(&live);
            let peak = Arc::clone(&peak);
            Box::new(move |_: &PassCtx| {
                let now = live.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(20));
                live.fetch_sub(1, Ordering::SeqCst);
                now
            }) as Job<usize>
        })
        .collect();

    let rx = run_pass(jobs, Cancel::new(), Instant::now() + Duration::from_secs(30), max_workers);
    let (results, _) =
        drain_until_joined(&rx, Duration::from_secs(20)).expect("the pass should finish");

    assert_eq!(results.len(), 24, "every job should run");
    let observed_peak = peak.load(Ordering::SeqCst);
    assert!(
        observed_peak <= max_workers,
        "at most {max_workers} jobs may run at once, saw {observed_peak}"
    );
}

#[test]
fn max_workers_is_clamped_to_at_least_one() {
    let rx = run_pass(
        vec![Box::new(|_: &PassCtx| 7_usize) as Job<usize>],
        Cancel::new(),
        Instant::now() + Duration::from_secs(30),
        0,
    );
    let (results, _) = drain_until_joined(&rx, Duration::from_secs(10))
        .expect("a zero worker count must not deadlock the pass");
    assert_eq!(results, vec![7]);
}

#[test]
fn an_empty_pass_disconnects_immediately() {
    let rx: Receiver<usize> = run_pass(
        Vec::new(),
        Cancel::new(),
        Instant::now() + Duration::from_secs(30),
        DEFAULT_MAX_WORKERS,
    );
    let (results, _) = drain_until_joined(&rx, Duration::from_secs(5))
        .expect("a pass with no jobs should disconnect rather than hang");
    assert!(results.is_empty());
}

#[test]
fn jobs_queued_behind_a_cancellation_do_not_run() {
    let ran = Arc::new(AtomicUsize::new(0));
    let cancel = Cancel::new();

    let mut jobs: Vec<Job<()>> = Vec::new();
    // One job that cancels the pass from the inside, then many that must not run.
    {
        let cancel = cancel.clone();
        let ran = Arc::clone(&ran);
        jobs.push(Box::new(move |_: &PassCtx| {
            ran.fetch_add(1, Ordering::SeqCst);
            cancel.cancel();
        }));
    }
    for _ in 0..32 {
        let ran = Arc::clone(&ran);
        jobs.push(Box::new(move |_: &PassCtx| {
            thread::sleep(Duration::from_millis(5));
            ran.fetch_add(1, Ordering::SeqCst);
        }));
    }
    let total = jobs.len();

    let rx = run_pass(jobs, cancel, Instant::now() + Duration::from_secs(30), 1);
    let (_results, _) =
        drain_until_joined(&rx, Duration::from_secs(10)).expect("the pass should finish");

    let executed = ran.load(Ordering::SeqCst);
    assert!(
        executed < total,
        "cancellation should stop the queue draining, {executed} of {total} ran"
    );
}

#[test]
fn cancel_is_shared_across_clones_and_is_idempotent() {
    let cancel = Cancel::new();
    let clone = cancel.clone();
    assert!(!cancel.is_cancelled());
    assert!(!clone.is_cancelled());

    clone.cancel();
    assert!(cancel.is_cancelled(), "cancellation must be visible through every clone");

    clone.cancel();
    assert!(cancel.is_cancelled(), "cancelling twice must stay cancelled");
}

#[test]
fn wait_timeout_returns_at_once_when_already_cancelled() {
    let cancel = Cancel::new();
    cancel.cancel();

    let started = Instant::now();
    let cancelled = cancel.wait_timeout(Duration::from_secs(5));
    let elapsed = started.elapsed();

    assert!(cancelled, "an already-cancelled flag should report so");
    assert!(
        elapsed < Duration::from_millis(100),
        "it should not wait out the timeout, took {elapsed:?}"
    );
}

#[test]
fn wait_timeout_wakes_promptly_when_another_thread_cancels() {
    let cancel = Cancel::new();
    let waker = cancel.clone();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(50));
        waker.cancel();
    });

    let started = Instant::now();
    let cancelled = cancel.wait_timeout(Duration::from_secs(10));
    let elapsed = started.elapsed();

    assert!(cancelled, "the waiter should observe the cancellation");
    assert!(
        elapsed < Duration::from_millis(500),
        "the condvar should wake the waiter, not the timeout; took {elapsed:?}"
    );
}

#[test]
fn wait_timeout_returns_false_when_it_times_out() {
    let cancel = Cancel::new();
    assert!(!cancel.wait_timeout(Duration::from_millis(20)), "no cancellation should be reported");
}

#[test]
fn pass_ctx_reports_remaining_time_and_stop_state() {
    let (pid_tx, _pid_rx) = mpsc::channel::<u32>();
    drop(pid_tx);

    let cancel = Cancel::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    let observed = Arc::new(Mutex::new(Vec::<(bool, bool)>::new()));

    let job = {
        let observed = Arc::clone(&observed);
        let cancel = cancel.clone();
        Box::new(move |ctx: &PassCtx| {
            // The context must hand a job the same deadline and the same
            // cancellation flag the caller passed in, or a job cannot make its
            // own budgeting decisions.
            assert_eq!(ctx.deadline(), deadline, "the context should carry the pass deadline");
            assert!(!ctx.cancel().is_cancelled(), "the shared flag starts uncancelled");

            let before = (ctx.should_stop(), ctx.remaining() > Duration::ZERO);
            cancel.cancel();
            let after = (ctx.should_stop(), ctx.remaining() > Duration::ZERO);

            assert!(
                ctx.cancel().is_cancelled(),
                "the context's flag is the caller's flag, not a copy"
            );

            lock_recovering(&observed).push(before);
            lock_recovering(&observed).push(after);
        }) as Job<()>
    };

    let rx = run_pass(vec![job], cancel, deadline, DEFAULT_MAX_WORKERS);
    let _ = drain_until_joined(&rx, Duration::from_secs(10)).expect("the pass should finish");

    let seen = lock_recovering(&observed).clone();
    assert_eq!(seen[0], (false, true), "before cancellation: not stopping, time remaining");
    assert_eq!(seen[1], (true, true), "after cancellation: stopping, deadline still in the future");
}

#[test]
fn a_deadline_already_past_stops_the_pass_without_running_jobs() {
    let ran = Arc::new(AtomicUsize::new(0));
    let jobs: Vec<Job<()>> = (0..4)
        .map(|_| {
            let ran = Arc::clone(&ran);
            Box::new(move |_: &PassCtx| {
                ran.fetch_add(1, Ordering::SeqCst);
            }) as Job<()>
        })
        .collect();

    let past = Instant::now() - Duration::from_secs(1);
    let rx = run_pass(jobs, Cancel::new(), past, DEFAULT_MAX_WORKERS);
    let _ = drain_until_joined(&rx, Duration::from_secs(10)).expect("the pass should finish");

    assert_eq!(ran.load(Ordering::SeqCst), 0, "no job should start after the deadline has passed");
}

#[test]
fn a_standalone_context_owns_its_own_child_table() {
    // `login` and the unit tests need a context outside a pass. Nothing
    // watches it, so the caller must reap what it registers -- which is what
    // `wait_child_timeout` does on both of its paths.
    let ctx = PassCtx::standalone(Cancel::new(), Instant::now() + Duration::from_secs(30));
    assert!(!ctx.should_stop());
    assert!(ctx.remaining() > Duration::from_secs(25));

    let child = Command::new("/bin/sh")
        .arg("-c")
        .arg("exit 7")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("a shell should be spawnable");
    let token = ctx.register_child(child);

    let status = ctx
        .wait_child_timeout(token, Duration::from_secs(10))
        .expect("waiting should succeed")
        .expect("the child exits well inside its budget");
    assert_eq!(status.code(), Some(7));
}

#[test]
fn wait_child_timeout_kills_and_reaps_a_child_that_overruns() {
    // The mechanism behind the 2 000 ms and 10 000 ms `security` budgets: a
    // keychain prompt nobody answers must not hold a pass open.
    let ctx = PassCtx::standalone(Cancel::new(), Instant::now() + Duration::from_secs(30));
    let child = Command::new("/bin/sleep")
        .arg(SLEEP_SECONDS)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("sleep should be spawnable");
    let pid = child.id();
    let token = ctx.register_child(child);

    let start = Instant::now();
    let outcome = ctx
        .wait_child_timeout(token, Duration::from_millis(200))
        .expect("a timeout is not an error");
    let elapsed = start.elapsed();

    assert!(outcome.is_none(), "the child should have been killed, not reaped normally");
    assert!(elapsed >= Duration::from_millis(200), "returned early: {elapsed:?}");
    assert!(elapsed < Duration::from_secs(5), "overran its budget: {elapsed:?}");
    assert!(!pid_is_alive(pid), "the child should be dead and reaped");

    // The token is gone from the table, so a second wait reports the same
    // thing a coordinator kill does rather than blocking forever.
    let err = ctx
        .wait_child_timeout(token, Duration::from_millis(50))
        .expect_err("the child is no longer registered");
    assert_eq!(err.kind(), io::ErrorKind::Interrupted);
}

#[test]
fn wait_child_timeout_reports_a_coordinator_kill_as_interrupted() {
    let ctx = PassCtx::standalone(Cancel::new(), Instant::now() + Duration::from_secs(30));
    let err = ctx
        .wait_child_timeout(ChildToken(9999), Duration::from_millis(50))
        .expect_err("an unregistered token means the coordinator took the child");
    assert_eq!(err.kind(), io::ErrorKind::Interrupted);
}

#[test]
fn a_cloned_context_shares_the_child_table() {
    // What lets the `security` reader hold a context of its own and still
    // have its children killed by the pass watchdog.
    let ctx = PassCtx::standalone(Cancel::new(), Instant::now() + Duration::from_secs(30));
    let clone = ctx.clone();

    let child = Command::new("/bin/sleep")
        .arg(SLEEP_SECONDS)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("sleep should be spawnable");
    let pid = child.id();
    let token = clone.register_child(child);

    // Registered through the clone, waited through the original.
    assert!(
        ctx.wait_child_timeout(token, Duration::from_millis(150)).expect("not an error").is_none()
    );
    assert!(!pid_is_alive(pid));

    ctx.cancel().cancel();
    assert!(clone.cancel().is_cancelled(), "cancellation is shared too");
}
