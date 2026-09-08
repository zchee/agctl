//! The fetch-pass coordinator: bounded fan-out that owns every child process.
//!
//! A *pass* is one sweep over the accounts. [`run_pass`] hands the jobs to a
//! detached coordinator thread, which fans them out across at most
//! [`DEFAULT_MAX_WORKERS`] workers and streams each result back over an
//! [`mpsc`] channel as it lands, so a caller can render early rows while later
//! ones are still in flight.
//!
//! The reason this is a module rather than a handful of `thread::spawn` calls
//! is ownership of child processes. Workers shell out to `security(1)`, which
//! can block indefinitely on a locked keychain. If each worker owned its own
//! child, a cancelled pass would have no way to reach in and kill it, and the
//! process would hang on exit holding a keychain prompt open. So the split is:
//!
//! - the **child table** owns every [`Child`] handle, and is reachable from
//!   the coordinator's watchdog;
//! - the **worker** owns the child's pipes, taken before registration, and
//!   waits through [`PassCtx::wait_child`], which polls rather than blocking
//!   so the watchdog can always take the lock.
//!
//! On cancellation or deadline the watchdog kills and reaps every live child,
//! which unblocks the workers within one poll interval; the workers then
//! finish, the scope joins them, and [`cleanup::emergency`] runs. Not every
//! child has a watchdog behind it, though — [`PassCtx::standalone`] has none,
//! and that is what a `watch` pass discovers under and what `login`, `import`,
//! `doctor` and `accounts` read the keychain through — so both waits treat
//! cancellation as their own deadline and reap what they were waiting on
//! themselves. Because the
//! coordinator thread is detached, a caller that has given up never blocks on
//! it: the pass is observed entirely through the channel, and the channel
//! disconnects exactly when the last worker has been joined.

// `run_pass` is wired: `status` and `watch` both call it on every pass. What
// is left is `PassCtx::remaining` and `wait_child`. W3 turned out not to need
// either in production code — a watch pass reads its budget from the `Instant`
// the loop already holds, and the only caller that waits on a child without a
// timeout of its own is the AC43 test — so they are kept as part of the
// context's contract and exercised by the tests below rather than deleted.
// Scoped to the non-test build for that reason, and `expect` rather than
// `allow` so it starts warning the moment a production caller appears.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "remaining and wait_child are exercised only by tests")
)]

use std::collections::BTreeMap;
use std::io;
use std::process::Child;
use std::process::ExitStatus;
use std::sync::Arc;
use std::sync::Condvar;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use crate::runtime::cleanup;

/// The most workers a single pass will run concurrently (plan section 2, S1').
pub const DEFAULT_MAX_WORKERS: usize = 4;

/// How long the coordinator waits for workers to drain after killing their
/// children before it stops waiting and runs emergency cleanup anyway.
pub const WORKER_JOIN_BUDGET: Duration = Duration::from_millis(500);

/// How often a worker re-checks a child it is waiting on.
const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// How often the watchdog re-checks the deadline. Cancellation does not wait
/// for this: it wakes the watchdog through the condvar immediately.
const WATCHDOG_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// One unit of work in a pass.
pub type Job<T> = Box<dyn FnOnce(&PassCtx) -> T + Send>;

/// A cancellation flag that waiters can block on.
///
/// Cloning shares the underlying flag, so every holder observes a single
/// cancellation. The condvar exists so a waiter reacts to cancellation at once
/// instead of at the end of its next poll interval, which is what keeps the
/// `q`-to-exit and signal-to-exit paths inside their latency budgets.
#[derive(Clone, Debug)]
pub struct Cancel {
    inner: Arc<CancelInner>,
}

#[derive(Debug)]
struct CancelInner {
    flag: AtomicBool,
    mutex: Mutex<()>,
    changed: Condvar,
}

impl Cancel {
    /// Creates a fresh, uncancelled flag.
    pub fn new() -> Self {
        let inner = CancelInner {
            flag: AtomicBool::new(false),
            mutex: Mutex::new(()),
            changed: Condvar::new(),
        };
        Self { inner: Arc::new(inner) }
    }

    /// Requests cancellation and wakes every waiter.
    ///
    /// Idempotent: cancelling an already-cancelled flag is a no-op beyond the
    /// redundant wake.
    pub fn cancel(&self) {
        self.inner.flag.store(true, Ordering::SeqCst);
        // The lock is taken so a waiter cannot miss the notification between
        // testing the flag and blocking on the condvar.
        let _guard = lock_recovering(&self.inner.mutex);
        self.inner.changed.notify_all();
    }

    /// Whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.inner.flag.load(Ordering::SeqCst)
    }

    /// Blocks until cancellation is requested or `timeout` elapses, and
    /// returns whether cancellation is now set.
    pub fn wait_timeout(&self, timeout: Duration) -> bool {
        let guard = lock_recovering(&self.inner.mutex);
        if self.is_cancelled() {
            return true;
        }
        let (_guard, _timeout_result) = match self.inner.changed.wait_timeout(guard, timeout) {
            Ok(pair) => pair,
            Err(poisoned) => poisoned.into_inner(),
        };
        self.is_cancelled()
    }
}

impl Default for Cancel {
    fn default() -> Self {
        Self::new()
    }
}

/// Locks a mutex, recovering from poisoning.
///
/// The runtime's mutexes guard plain data with no invariant a panic could
/// break, and refusing to cancel or clean up because an unrelated thread
/// panicked would be strictly worse than proceeding.
fn lock_recovering<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Identifies a child process registered with the pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChildToken(u64);

/// Every child process the pass has spawned and not yet reaped.
#[derive(Debug, Default)]
struct ChildTable {
    next_id: u64,
    live: BTreeMap<ChildToken, Child>,
}

impl ChildTable {
    fn insert(&mut self, child: Child) -> ChildToken {
        let token = ChildToken(self.next_id);
        self.next_id = self.next_id.wrapping_add(1);
        self.live.insert(token, child);
        token
    }

    /// Kills and reaps every live child.
    ///
    /// Both calls are allowed to fail: a child that exited on its own between
    /// the deadline firing and this call is already gone, which is the state
    /// we were trying to reach.
    fn kill_all(&mut self) {
        for (_, mut child) in std::mem::take(&mut self.live) {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// What a job is given so it can cooperate with cancellation and hand its
/// child processes to the coordinator.
///
/// Cloning is shallow and deliberate: every clone observes the same
/// cancellation flag and shares the same child table, so a long-lived helper
/// that a job builds for itself — the `security(1)` reader, say — can hold a
/// context of its own and still have its children killed by the watchdog.
#[derive(Debug, Clone)]
pub struct PassCtx {
    cancel: Cancel,
    deadline: Instant,
    children: Arc<Mutex<ChildTable>>,
}

impl PassCtx {
    /// Builds a context that belongs to no pass.
    ///
    /// `login` and the unit tests need a context to spawn `security(1)`
    /// through, but they are not running inside [`run_pass`] and so have no
    /// coordinator thread behind them. The child table is owned by the
    /// returned value and **nothing watches it**: dropping this context kills
    /// nothing, so a caller must reach every child it registers through
    /// [`PassCtx::wait_child`] or [`PassCtx::wait_child_timeout`], both of
    /// which reap what they wait on — and both of which treat cancellation as
    /// a deadline, so a context with no watchdog behind it still lets go of
    /// its children when the pass is cancelled.
    pub fn standalone(cancel: Cancel, deadline: Instant) -> Self {
        Self { cancel, deadline, children: Arc::new(Mutex::new(ChildTable::default())) }
    }

    /// The pass-wide cancellation flag.
    pub fn cancel(&self) -> &Cancel {
        &self.cancel
    }

    /// The instant after which the pass must stop doing new work.
    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    /// How long is left before the deadline, saturating at zero.
    pub fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    /// Whether the job should stop, because the pass was cancelled or the
    /// deadline has passed.
    pub fn should_stop(&self) -> bool {
        self.cancel.is_cancelled() || Instant::now() >= self.deadline
    }

    /// Hands a freshly spawned child process to the coordinator.
    ///
    /// Take any pipe the job needs (`child.stdout.take()` and friends) *before*
    /// calling this: from here on the coordinator owns the handle and may kill
    /// the process at any moment, and the job's only sanctioned interaction is
    /// [`PassCtx::wait_child`].
    pub fn register_child(&self, child: Child) -> ChildToken {
        lock_recovering(&self.children).insert(child)
    }

    /// Waits for a registered child to exit, polling so the coordinator can
    /// still take the child table and kill it.
    ///
    /// Cancellation ends the wait: this has no budget of its own, so without
    /// that clause a job waiting here would hold a child open for as long as
    /// the child felt like living, watchdog or no watchdog. The child is
    /// killed and reaped before returning, exactly as the coordinator would
    /// have done, so the caller sees the same outcome either way.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::Interrupted`] when the child was killed out
    /// from under the job — by the coordinator, or by this call because the
    /// pass was cancelled — which is how a job learns the pass is over. Any
    /// other error is the underlying `wait` failure.
    pub fn wait_child(&self, token: ChildToken) -> io::Result<ExitStatus> {
        loop {
            {
                let mut table = lock_recovering(&self.children);
                match table.live.get_mut(&token) {
                    Some(child) => {
                        if let Some(status) = child.try_wait()? {
                            table.live.remove(&token);
                            return Ok(status);
                        }
                    }
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "the pass coordinator killed this child process",
                        ));
                    }
                }

                // After the harvest above, so a child that exited on its own
                // in the same instant is still reported as having exited
                // rather than as having been killed.
                if self.cancel.is_cancelled() {
                    // Still holding the table, so nothing can register a child
                    // under this token between the check and the kill.
                    if let Some(mut child) = table.live.remove(&token) {
                        let _ = child.kill();
                        let _ = child.wait();
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "the pass was cancelled while this child process was running",
                    ));
                }
            }
            thread::sleep(CHILD_POLL_INTERVAL);
        }
    }

    /// Waits for a registered child to exit, giving up after `timeout` — or
    /// as soon as the pass is cancelled, whichever comes first.
    ///
    /// Polls exactly as [`PassCtx::wait_child`] does, so the watchdog can
    /// always take the child table. On either kind of giving up the child is
    /// killed and reaped through that table and `Ok(None)` is returned, which
    /// is what bounds the 2 000 ms and 10 000 ms `security(1)` budgets: a
    /// keychain prompt that never gets an answer cannot hold the pass open.
    ///
    /// **Cancellation counts as the deadline arriving**, which is what makes
    /// the guarantee hold where there is no watchdog at all: a `watch` pass
    /// runs its discovery under [`PassCtx::standalone`], and `login`, `import`,
    /// `doctor` and `accounts` do all of their `security(1)` reads there. Before
    /// this clause a Ctrl-C or a `q` during a `dump-keychain` left the child
    /// running for the rest of its budget with nothing left to reap it.
    ///
    /// `Ok(None)` does not distinguish the two reasons, deliberately: every
    /// caller already treats "no answer" the same way, and
    /// [`security_cli`](crate::secret::security_cli) collapses it with the
    /// error case into one timeout. The only visible consequence is that a
    /// cancelled read is reported as having used its whole budget rather than
    /// the time it actually took — a number nothing renders on the way out.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::Interrupted`] when the coordinator killed the
    /// child first. Any other error is the underlying `wait` failure.
    pub fn wait_child_timeout(
        &self,
        token: ChildToken,
        timeout: Duration,
    ) -> io::Result<Option<ExitStatus>> {
        // `Instant + Duration` panics on overflow and overflow checks are off
        // in every profile here, so the addition is spelled out: an absurd
        // timeout degrades to "already expired" rather than wrapping.
        let now = Instant::now();
        let deadline = now.checked_add(timeout).unwrap_or(now);
        loop {
            {
                let mut table = lock_recovering(&self.children);
                match table.live.get_mut(&token) {
                    Some(child) => {
                        if let Some(status) = child.try_wait()? {
                            table.live.remove(&token);
                            return Ok(Some(status));
                        }
                    }
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "the pass coordinator killed this child process",
                        ));
                    }
                }

                // After the harvest above, so a child that exited on its own
                // in the same instant is still reported as having exited
                // rather than as having been killed.
                if self.cancel.is_cancelled() || Instant::now() >= deadline {
                    // Still holding the table, so nothing can register a child
                    // under this token between the check and the kill.
                    if let Some(mut child) = table.live.remove(&token) {
                        let _ = child.kill();
                        let _ = child.wait();
                    }
                    return Ok(None);
                }
            }
            thread::sleep(CHILD_POLL_INTERVAL);
        }
    }
}

/// Runs `jobs` on a detached coordinator thread and streams their results.
///
/// At most `max_workers` jobs run at once (clamped to at least one). Results
/// arrive on the returned channel in completion order, not submission order.
/// The channel disconnects when the last worker has been joined, which is the
/// caller's signal that the pass is over — successfully or not.
///
/// The caller must never block on the channel without a timeout of its own:
/// the coordinator bounds how long it waits for a *cooperative* worker, but a
/// job that ignores [`PassCtx::should_stop`] and blocks forever cannot be
/// forced to return.
///
/// # Panics
///
/// Panics only if the operating system refuses to start the coordinator
/// thread, which the process has no way to continue past.
pub fn run_pass<T>(
    jobs: Vec<Job<T>>,
    cancel: Cancel,
    deadline: Instant,
    max_workers: usize,
) -> Receiver<T>
where
    T: Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    thread::Builder::new()
        .name("agentctl-pass".to_owned())
        .spawn(move || coordinate(jobs, cancel, deadline, max_workers, tx))
        .expect("the operating system refused to start the pass coordinator thread");
    rx
}

/// The body of the coordinator thread.
fn coordinate<T>(
    jobs: Vec<Job<T>>,
    cancel: Cancel,
    deadline: Instant,
    max_workers: usize,
    tx: Sender<T>,
) where
    T: Send,
{
    let job_count = jobs.len();
    if job_count == 0 {
        return;
    }

    let children: Arc<Mutex<ChildTable>> = Arc::new(Mutex::new(ChildTable::default()));
    let ctx = PassCtx { cancel: cancel.clone(), deadline, children: Arc::clone(&children) };
    let queue = Mutex::new(jobs.into_iter());
    let worker_count = max_workers.clamp(1, job_count);
    let workers_running = AtomicBool::new(true);

    // One sender per worker, so the channel disconnects precisely when the
    // last worker has finished. `Sender` is not `Sync`, so each must be moved
    // into its worker rather than shared by reference.
    let mut senders: Vec<Sender<T>> = Vec::with_capacity(worker_count);
    for _ in 0..worker_count {
        senders.push(tx.clone());
    }
    drop(tx);

    thread::scope(|scope| {
        scope.spawn(|| {
            watchdog(&cancel, deadline, &children, &workers_running);
        });

        for sender in senders {
            let ctx = &ctx;
            let queue = &queue;
            scope.spawn(move || {
                loop {
                    let job = { lock_recovering(queue).next() };
                    let Some(job) = job else { break };
                    if ctx.should_stop() {
                        break;
                    }
                    if sender.send(job(ctx)).is_err() {
                        // The caller dropped the receiver; nothing downstream
                        // will read further results, so stop early.
                        break;
                    }
                }
            });
        }
    });

    workers_running.store(false, Ordering::SeqCst);

    // The watchdog only kills children on the abnormal path, so a pass that
    // finished normally can still be holding a child whose job leaked it.
    lock_recovering(&children).kill_all();

    if cancel.is_cancelled() || Instant::now() >= deadline {
        cleanup::emergency();
    }
}

/// Watches for cancellation or the deadline and kills every live child when
/// either fires.
///
/// Returns as soon as the workers are done on the normal path, so the
/// enclosing scope is not held open by the watchdog itself.
fn watchdog(
    cancel: &Cancel,
    deadline: Instant,
    children: &Arc<Mutex<ChildTable>>,
    workers_running: &AtomicBool,
) {
    let kill_deadline = loop {
        if !workers_running.load(Ordering::SeqCst) {
            return;
        }
        if cancel.is_cancelled() || Instant::now() >= deadline {
            let now = Instant::now();
            break now.checked_add(WORKER_JOIN_BUDGET).unwrap_or(now);
        }
        cancel.wait_timeout(WATCHDOG_POLL_INTERVAL);
    };

    lock_recovering(children).kill_all();

    // Give the workers their bounded window to notice their children are gone
    // and return. Anything still running after this is a job that ignored
    // `should_stop`; the scope join will wait for it, but nothing further is
    // gained by this thread staying to watch.
    while workers_running.load(Ordering::SeqCst) && Instant::now() < kill_deadline {
        thread::sleep(CHILD_POLL_INTERVAL);
        // A job may have spawned another child after the first sweep.
        lock_recovering(children).kill_all();
    }
}

#[cfg(test)]
#[path = "coordinator_tests.rs"]
mod tests;
