//! Tests for signal handling.
//!
//! The end-to-end behaviour -- SIGTERM during a held refresh exits 143 with
//! the lock released and the temporary file removed -- is AC27, and lands with
//! the e2e suite once there is a command to interrupt. What is testable here
//! is the exit-status mapping, that installation succeeds, and the escalation
//! that ends registered children before the exit (plan AC52).

use std::cell::Cell;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::Command;
use std::process::Stdio;
use std::rc::Rc;

use super::*;
use crate::runtime::coordinator::ChildToken;
use crate::runtime::coordinator::PassCtx;

#[test]
fn exit_status_follows_the_128_plus_signo_convention() {
    let tests = [
        ("SIGHUP exits 129", SIGHUP, 129),
        ("SIGINT exits 130", SIGINT, 130),
        ("SIGTERM exits 143", SIGTERM, 143),
    ];

    for (name, signal, expected) in tests {
        assert_eq!(exit_status_for(signal), expected, "{name}");
    }
}

#[test]
fn exit_status_does_not_wrap_on_an_absurd_signal_number() {
    // Overflow checks are compiled out in every profile, so `128 + signal`
    // would wrap silently into a plausible status. The checked form falls back
    // to a fixed value instead.
    assert_eq!(exit_status_for(i32::MAX), 128, "an unrepresentable status must not wrap");
}

#[test]
fn the_handled_set_is_exactly_term_hup_and_int() {
    assert_eq!(HANDLED.len(), 3);
    for signal in [SIGTERM, SIGHUP, SIGINT] {
        assert!(HANDLED.contains(&signal), "signal {signal} should be handled");
    }
}

#[test]
fn install_succeeds_and_leaves_the_cancel_flag_untouched() {
    let cancel = Cancel::new();
    install(cancel.clone()).expect("installing signal handling should succeed");
    assert!(!cancel.is_cancelled(), "installing must not itself request cancellation");
}

// ---------------------------------------------------------------------------
// Registered children die with the process (plan AC52)
// ---------------------------------------------------------------------------

/// A short budget, so the escalation tests do not each take half a second.
const TEST_BUDGET: Duration = Duration::from_millis(40);

/// The budget for the tests that hand a child out on a later poll. They check
/// what the signal path does with that child, so the budget has to outlast
/// the polls before it: on a loaded CI runner each 5ms poll sleep overshot
/// enough that three of them outlasted `TEST_BUDGET`, and the wait ended
/// before the child was ever handed out.
const LATE_CHILD_BUDGET: Duration = Duration::from_secs(1);

/// A fake process table: which process id currently carries which start time.
/// A missing id is a process that has exited and been reaped.
type Table = Rc<RefCell<BTreeMap<u32, String>>>;

fn table(rows: &[(u32, &str)]) -> Table {
    Rc::new(RefCell::new(rows.iter().map(|(pid, start)| (*pid, (*start).to_owned())).collect()))
}

fn child(pid: u32, start: &str) -> ChildEntry {
    ChildEntry { pid, start_time: start.to_owned() }
}

/// Runs [`terminate_with`] against `table` with the short [`TEST_BUDGET`],
/// handing out `batches` one per `take`, and returns every `(pid, signal)`
/// sent. `on_send` lets a test make the fake process react to a signal.
fn run(
    table: &Table,
    batches: Vec<Vec<ChildEntry>>,
    on_send: impl Fn(&Table, u32, Signal),
) -> Vec<(u32, i32)> {
    run_with(TEST_BUDGET, table, batches, on_send)
}

/// [`run`] with the budget chosen by the test.
fn run_with(
    budget: Duration,
    table: &Table,
    batches: Vec<Vec<ChildEntry>>,
    on_send: impl Fn(&Table, u32, Signal),
) -> Vec<(u32, i32)> {
    let batches = RefCell::new(batches.into_iter());
    let sent = RefCell::new(Vec::new());
    terminate_with(
        budget,
        || batches.borrow_mut().next().unwrap_or_default(),
        || false,
        |entry| table.borrow().get(&entry.pid) == Some(&entry.start_time),
        |pid, signal| {
            sent.borrow_mut().push((pid, signal.as_raw()));
            on_send(table, pid, signal);
        },
    );
    sent.into_inner()
}

/// The fake child exits on the first signal it receives.
fn dies_on_any_signal(table: &Table, pid: u32, _signal: Signal) {
    table.borrow_mut().remove(&pid);
}

/// The fake child ignores `SIGTERM`; only `SIGKILL` ends it.
fn ignores_term(table: &Table, pid: u32, signal: Signal) {
    if signal == Signal::KILL {
        table.borrow_mut().remove(&pid);
    }
}

#[test]
fn a_live_child_gets_sigterm_and_no_sigkill_once_it_has_exited() {
    let processes = table(&[(100, "A")]);
    let started = Instant::now();
    let sent = run(&processes, vec![vec![child(100, "A")]], dies_on_any_signal);
    assert_eq!(sent, [(100, SIGTERM)]);
    assert!(started.elapsed() < TEST_BUDGET, "a child that died must not wait out the budget");
}

#[test]
fn a_recycled_pid_is_never_signalled() {
    // Same id, different start time: the child is gone and something else
    // has its number now.
    let processes = table(&[(100, "B")]);
    let sent = run(&processes, vec![vec![child(100, "A")]], dies_on_any_signal);
    assert!(sent.is_empty(), "a recycled pid was signalled: {sent:?}");
    assert_eq!(processes.borrow().get(&100).map(String::as_str), Some("B"), "and it still runs");
}

#[test]
fn a_dead_entry_is_skipped() {
    let processes = table(&[]);
    let sent = run(&processes, vec![vec![child(100, "A")]], dies_on_any_signal);
    assert!(sent.is_empty(), "a child that already exited was signalled: {sent:?}");
}

#[test]
fn a_child_that_ignores_sigterm_is_sigkilled_after_the_budget() {
    let processes = table(&[(100, "A")]);
    let started = Instant::now();
    let sent = run(&processes, vec![vec![child(100, "A")]], ignores_term);
    assert_eq!(sent, [(100, SIGTERM), (100, Signal::KILL.as_raw())]);
    assert!(started.elapsed() >= TEST_BUDGET, "SIGKILL came before the budget ran out");
    assert!(processes.borrow().is_empty(), "and the SIGKILL ended it");
}

#[test]
fn a_pid_recycled_during_the_wait_is_not_sigkilled() {
    // The child dies of the SIGTERM and its id is handed to a new process
    // before the escalation: the SIGKILL must not follow the number.
    let processes = table(&[(100, "A")]);
    let sent = run(&processes, vec![vec![child(100, "A")]], |table, pid, signal| {
        if signal == Signal::TERM {
            table.borrow_mut().insert(pid, "B".to_owned());
        }
    });
    assert_eq!(sent, [(100, SIGTERM)], "only the SIGTERM may reach pid 100");
}

#[test]
fn a_child_registered_while_waiting_is_signalled_too() {
    // The second child arrives on the second poll, and both ignore SIGTERM,
    // so the budget has to run out for the SIGKILL sweep — but not before
    // that second poll.
    let processes = table(&[(100, "A"), (200, "C")]);
    let batches = vec![vec![child(100, "A")], vec![child(200, "C")]];
    let sent = run_with(LATE_CHILD_BUDGET, &processes, batches, ignores_term);
    let kill = Signal::KILL.as_raw();
    assert_eq!(sent, [(100, SIGTERM), (200, SIGTERM), (100, kill), (200, kill)]);
}

#[test]
fn the_signal_path_waits_no_longer_than_the_drain_budget_for_a_stubborn_child() {
    let polls = Cell::new(0_u32);
    let started = Instant::now();
    terminate_with(
        TEST_BUDGET,
        || if polls.replace(polls.get() + 1) == 0 { vec![child(100, "A")] } else { Vec::new() },
        || false,
        |_| true,
        |_, _| {},
    );
    let elapsed = started.elapsed();
    assert!(
        elapsed < TEST_BUDGET + KILL_SETTLE + Duration::from_millis(200),
        "a child that never dies must not hold the exit open: {elapsed:?}"
    );
}

// ---------------------------------------------------------------------------
// The spawn window (review finding F1)
// ---------------------------------------------------------------------------

#[test]
fn a_child_registered_while_its_spawn_was_in_flight_is_signalled() {
    // `exec` has exactly one child. When the signal lands between its `spawn`
    // and its registration, the first take is empty and nothing is pending;
    // only the open spawn window keeps the signal path looking.
    let processes = table(&[(100, "A")]);
    let takes = Cell::new(0_u32);
    let sent = RefCell::new(Vec::new());
    terminate_with(
        LATE_CHILD_BUDGET,
        || {
            let round = takes.replace(takes.get() + 1);
            if round == 3 { vec![child(100, "A")] } else { Vec::new() }
        },
        // Open until the round that hands the child out, as a spawner's guard
        // is dropped only after `register_child`.
        || takes.get() <= 3,
        |entry| processes.borrow().get(&entry.pid) == Some(&entry.start_time),
        |pid, signal| {
            sent.borrow_mut().push((pid, signal.as_raw()));
            dies_on_any_signal(&processes, pid, signal);
        },
    );
    assert_eq!(sent.into_inner(), [(100, SIGTERM)], "the late child must not be orphaned");
}

#[test]
fn the_spawn_window_is_read_before_the_registry_is_taken() {
    // The interleaving that ordering exists for: the spawner registers its
    // child and closes its window between the signal path's two reads. Here
    // that happens *inside* the window read, which is the latest moment it can
    // happen if the window is read first — so the take that follows must see
    // the child. Reading the window after the take would find it closed with
    // the child still in the registry, stop, and orphan it.
    let processes = table(&[(100, "A")]);
    let registry: RefCell<Vec<ChildEntry>> = RefCell::new(Vec::new());
    let window_open = Cell::new(true);
    let sent = RefCell::new(Vec::new());
    terminate_with(
        TEST_BUDGET,
        || std::mem::take(&mut *registry.borrow_mut()),
        || {
            let was_open = window_open.replace(false);
            if was_open {
                registry.borrow_mut().push(child(100, "A"));
            }
            false
        },
        |entry| processes.borrow().get(&entry.pid) == Some(&entry.start_time),
        |pid, signal| {
            sent.borrow_mut().push((pid, signal.as_raw()));
            dies_on_any_signal(&processes, pid, signal);
        },
    );
    assert_eq!(
        sent.into_inner(),
        [(100, SIGTERM)],
        "a child registered before the take was missed"
    );
}

#[test]
fn a_spawn_window_that_never_closes_holds_the_exit_no_longer_than_the_budget() {
    let started = Instant::now();
    let sent = RefCell::new(Vec::new());
    terminate_with(
        TEST_BUDGET,
        Vec::new,
        || true,
        |_| true,
        |pid, signal| {
            sent.borrow_mut().push((pid, signal.as_raw()));
        },
    );
    let elapsed = started.elapsed();
    assert!(sent.into_inner().is_empty(), "nothing was ever registered, so nothing is signalled");
    assert!(elapsed >= TEST_BUDGET, "gave up on the open window early: {elapsed:?}");
    assert!(
        elapsed < TEST_BUDGET + Duration::from_millis(200),
        "a stuck spawner must not hold the exit open: {elapsed:?}"
    );
}

#[test]
fn defer_to_exit_returns_at_once_when_no_signal_arrived() {
    let started = Instant::now();
    defer_to_exit();
    assert!(started.elapsed() < Duration::from_millis(100));
}

/// Spawns `script` under `sh`, registers it with `ctx`, and waits for it to
/// create `ready` so the test signals the process it means to.
fn spawn_registered(ctx: &PassCtx, script: &str, ready: &Path) -> (u32, ChildToken) {
    let child = Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("sh should be spawnable");
    let pid = child.id();
    let token = ctx.register_child(child);
    let started = Instant::now();
    while !ready.exists() {
        assert!(started.elapsed() < Duration::from_secs(10), "the child never became ready");
        thread::sleep(Duration::from_millis(5));
    }
    (pid, token)
}

// Needs nextest's process-per-test isolation: the cleanup registry is
// process-wide, so under a shared-process `cargo test` this would drain, and
// signal, other tests' registered children.
#[test]
fn terminate_children_sigterms_a_real_registered_child() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let ready = dir.path().join("ready");
    let cancel = Cancel::new();
    let ctx = PassCtx::standalone(cancel.clone(), Instant::now() + Duration::from_secs(60));
    let script = format!(": > '{}'; exec /bin/sleep 300", ready.display());
    let (pid, token) = spawn_registered(&ctx, &script, &ready);

    let started = Instant::now();
    terminate_children(&cancel);
    let elapsed = started.elapsed();

    let status = ctx.wait_child(token).expect("the killed child is still reapable");
    assert_eq!(status.signal(), Some(SIGTERM), "pid {pid} should have died of the SIGTERM");
    assert!(elapsed < WORKER_JOIN_BUDGET, "a child that obeys SIGTERM ends early: {elapsed:?}");
}

// Needs nextest's process-per-test isolation: the cleanup registry is
// process-wide, so under a shared-process `cargo test` this would drain, and
// signal, other tests' registered children.
#[test]
fn terminate_children_sigkills_a_real_child_that_ignores_sigterm() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let ready = dir.path().join("ready");
    let cancel = Cancel::new();
    let ctx = PassCtx::standalone(cancel.clone(), Instant::now() + Duration::from_secs(60));
    // An ignored disposition survives `exec`, so the `sleep` ignores it too.
    let script = format!("trap '' TERM; : > '{}'; exec /bin/sleep 300", ready.display());
    let (pid, token) = spawn_registered(&ctx, &script, &ready);

    let started = Instant::now();
    terminate_children(&cancel);
    let elapsed = started.elapsed();

    let status = ctx.wait_child(token).expect("the killed child is still reapable");
    assert_eq!(
        status.signal(),
        Some(Signal::KILL.as_raw()),
        "pid {pid} ignored SIGTERM and should have been SIGKILLed"
    );
    assert!(elapsed >= WORKER_JOIN_BUDGET, "SIGKILL came before the budget: {elapsed:?}");
    assert!(
        elapsed < WORKER_JOIN_BUDGET + KILL_SETTLE + Duration::from_millis(500),
        "the signal path overran its budget: {elapsed:?}"
    );
}
