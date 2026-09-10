//! The watch loop, driven in this process with no terminal anywhere.
//!
//! Two seams make that possible and they are the reason this file can assert
//! the timing claims plan AC35 and AC43 make at all:
//!
//! - the frames go to a [`TestBackend`], which is a buffer with a `Backend`
//!   implementation, so no test opens `/dev/tty` or puts a terminal into raw
//!   mode;
//! - the key presses come from an [`EventSource`] the test scripts, which
//!   also records *when* the loop asked for one. Since the loop draws exactly
//!   once before each ask, the gap between two asks is the redraw period, and
//!   the gap between the ask that answered `q` and the loop's return is the
//!   quit latency. Both are then ordinary assertions rather than a stopwatch
//!   held against a real terminal.
//!
//! The passes those tests run are real: [`HeldPass`] blocks on
//! [`namespace_lock::acquire`] under the genuine `hold_lock` fault, and
//! [`ChildPass`] registers a real `sleep 30` with a real [`run_pass`]
//! coordinator. What is faked is only what the loop is given, never the
//! machinery underneath it.

use std::fs;
use std::os::unix::fs::PermissionsExt;
// Only the staged-credential test walks a namespace by path, and it is behind
// the feature that makes `Fault::pause_point` pause.
#[cfg(feature = "testing")]
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use clap::Parser;
use httpmock::Method::GET;
use httpmock::MockServer;
use ratatui::backend::TestBackend;
use serde_json::json;

use super::*;
use crate::config::AccountKind;
use crate::config::new_record;
use crate::provider::claude::account::AccountState;
use crate::provider::claude::credentials::Credentials;
use crate::provider::claude::namespace::export_spelling;
use crate::provider::claude::namespace::sha8;
use crate::provider::claude::oauth::TokenResponse;
use crate::provider::claude::usage::RefreshError;
use crate::provider::claude::usage::USAGE_PATH;
use crate::runtime::coordinator::DEFAULT_MAX_WORKERS;
use crate::runtime::coordinator::Job;
use crate::runtime::coordinator::run_pass;
use crate::secret::KeychainReader;
use crate::secret::KeychainStatus;
use crate::secret::fake_reader::FakeReader;
use crate::secret::file_store::CREDENTIALS_FILE;
#[cfg(feature = "testing")]
use crate::secret::file_store::WriteRequest;
#[cfg(feature = "testing")]
use crate::secret::file_store::write_credentials;
use crate::secret::namespace_lock;
use crate::tui::fixtures;

const ACCT: &str = "11111111-2222-3333-4444-555555555555";
const ORG: &str = "66666666-7777-8888-9999-000000000000";
const LIVE_ACCT: &str = "99999999-8888-7777-6666-555555555555";
const LIVE_SERVICE: &str = "Claude Code-credentials";

/// The captured live body every successful fetch answers with.
const USAGE_BODY: &str = include_str!("../../fixtures/claude/usage-2026-09-08.json");

/// The one interval the parser accepts at its lowest setting (AC13).
const FLOOR: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// A temporary store plus the paths that address it.
struct Store {
    _dir: tempfile::TempDir,
    home: PathBuf,
    paths: Arc<Paths>,
}

fn store() -> Store {
    let dir = tempfile::TempDir::new().expect("a temporary directory should be creatable");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("the fake home should be creatable");
    let paths = Arc::new(Paths::with_config_dir(dir.path().join("config")));
    paths.ensure_dirs().expect("the store directories should be creatable");
    Store { _dir: dir, home, paths }
}

/// A credential blob in Claude Code's shape (fact F40), fresh for an hour.
fn blob(account: &str, access: &str, email: &str) -> String {
    json!({
        "claudeAiOauth": {
            "accessToken": access,
            "refreshToken": format!("{access}-refresh"),
            "expiresAt": Timestamp::now().as_millisecond() + 3_600_000,
            "scopes": ["user:inference", "user:profile"],
            "subscriptionType": "max",
            "tokenAccount": {
                "uuid": account,
                "emailAddress": email,
                "organizationUuid": ORG,
                "organizationName": "Acme",
            },
        }
    })
    .to_string()
}

/// Persists a registry holding one account this store owns.
fn write_owned_registry(store: &Store) {
    let ns_dir = store.paths.namespace_dir(ACCT, ORG);
    let spelling = export_spelling(&ns_dir);
    let mut record = new_record(
        ACCT.to_owned(),
        ORG.to_owned(),
        AccountKind::Owned { export_sha8: sha8(&spelling), export_spelling: spelling },
    )
    .expect("the fixture identifiers are valid path segments");
    record.email = Some("owner@example.com".to_owned());
    record.org_name = Some("Acme".to_owned());

    AgctlConfig::update(&store.paths, |config| config.upsert(record))
        .expect("the registry should be writable");
}

/// Writes `.credentials.json` into the owned namespace.
fn write_credential_file(store: &Store, blob: &str) {
    let ns_dir = store.paths.namespace_dir(ACCT, ORG);
    fs::create_dir_all(&ns_dir).expect("the namespace directory should be creatable");
    let path = ns_dir.join(CREDENTIALS_FILE);
    fs::write(&path, blob).expect("the credential file should be writable");
    fs::set_permissions(&path, PermissionsExt::from_mode(0o600)).expect("mode 0600");
}

/// A refresher that must never be reached: every fixture credential is fresh.
struct NeverRefresher;

impl TokenRefresher for NeverRefresher {
    fn refresh(&self, _: &Credentials, _: &Cancel) -> Result<TokenResponse, RefreshError> {
        panic!("a fresh credential must not be refreshed")
    }
}

/// A scripted [`EventSource`] that also records when it was asked.
///
/// A `None` entry sleeps for the whole timeout, the way `crossterm::poll`
/// does, so the loop's timing under this double is the timing it has against
/// a real terminal that nobody is typing at.
struct ScriptedEvents {
    script: Vec<Option<Key>>,
    asked_at: Vec<Instant>,
    answered_quit_at: Option<Instant>,
}

impl ScriptedEvents {
    /// `quiet` polls that time out, then `q`.
    fn quiet_then_quit(quiet: usize) -> Self {
        let mut script = vec![None; quiet];
        script.push(Some(Key::Quit));
        Self { script, asked_at: Vec::new(), answered_quit_at: None }
    }

    fn scripted(script: Vec<Option<Key>>) -> Self {
        Self { script, asked_at: Vec::new(), answered_quit_at: None }
    }

    /// The longest gap between two successive asks, which is the longest a
    /// frame stayed on screen.
    fn longest_redraw_gap(&self) -> Duration {
        self.asked_at
            .windows(2)
            .map(|pair| pair[1].duration_since(pair[0]))
            .max()
            .unwrap_or_default()
    }
}

impl EventSource for ScriptedEvents {
    fn next_key(&mut self, timeout: Duration) -> io::Result<Option<Key>> {
        let index = self.asked_at.len();
        self.asked_at.push(Instant::now());

        match self.script.get(index).copied().flatten() {
            Some(key) => {
                if key == Key::Quit {
                    self.answered_quit_at = Some(Instant::now());
                }
                Ok(Some(key))
            }
            None => {
                // Past the end of the script the terminal simply stays quiet.
                thread::sleep(timeout);
                Ok(None)
            }
        }
    }
}

/// A pass that blocks the way a real one blocks when another process is
/// holding the namespace lock (`AGCTL_FAULT=hold_lock`).
struct HeldPass {
    paths: Arc<Paths>,
    hold: Duration,
    entered: Arc<AtomicBool>,
    left: Arc<AtomicBool>,
}

impl Pass for HeldPass {
    fn run(&self, _forced: bool, cancel: &Cancel, _deadline: Instant) -> Option<Vec<RowOutcome>> {
        let paths = Arc::clone(&self.paths);
        let entered = Arc::clone(&self.entered);
        let left = Arc::clone(&self.left);
        let now = Instant::now();
        let hold_until = now.checked_add(self.hold).unwrap_or(now);

        let job: Job<()> = Box::new(move |ctx| {
            entered.store(true, Ordering::SeqCst);
            // `hold_lock` takes the lock and then stalls until cancellation or
            // the deadline, which is exactly the shape of losing a race with a
            // process that is refreshing this namespace.
            let guard = namespace_lock::acquire(
                &paths,
                ACCT,
                ORG,
                hold_until,
                ctx.cancel(),
                Fault::from_list("hold_lock"),
            );
            drop(guard);
            left.store(true, Ordering::SeqCst);
        });

        let rx = run_pass(vec![job], cancel.clone(), hold_until, DEFAULT_MAX_WORKERS);
        let _drained: Vec<()> = rx.into_iter().collect();
        Some(Vec::new())
    }
}

/// What a registered child did.
#[derive(Debug, Default)]
struct ChildReport {
    spawned_at: Option<Instant>,
    reaped_at: Option<Instant>,
    interrupted: bool,
    /// Whether the wait gave up and killed the child rather than reporting an
    /// exit status — [`PassCtx::wait_child_timeout`]'s `Ok(None)`.
    gave_up: bool,
}

/// A pass that registers a real `sleep 30` with the coordinator and waits on
/// it, which is what a `security(1)` read looks like from the outside.
struct ChildPass {
    report: Arc<Mutex<ChildReport>>,
}

impl Pass for ChildPass {
    fn run(&self, _forced: bool, cancel: &Cancel, deadline: Instant) -> Option<Vec<RowOutcome>> {
        let report = Arc::clone(&self.report);
        let job: Job<()> = Box::new(move |ctx| {
            let Ok(child) = Command::new("/bin/sleep").arg("30").spawn() else {
                return;
            };
            let token = ctx.register_child(child);
            lock(&report).spawned_at = Some(Instant::now());

            let outcome = ctx.wait_child(token);
            let mut report = lock(&report);
            report.reaped_at = Some(Instant::now());
            report.interrupted = outcome.is_err_and(|err| err.kind() == io::ErrorKind::Interrupted);
        });

        let rx = run_pass(vec![job], cancel.clone(), deadline, DEFAULT_MAX_WORKERS);
        let _drained: Vec<()> = rx.into_iter().collect();
        Some(Vec::new())
    }
}

/// A pass that waits on a real child through a context with **no coordinator
/// behind it**, which is the shape of a watch pass's discovery phase and of
/// every `security(1)` read `login`, `import`, `doctor` and `accounts` make.
///
/// Nothing watches this child table. If cancellation were not a deadline
/// inside [`PassCtx::wait_child_timeout`] there would be nothing left to reap
/// the child after `q`, and a `dump-keychain` would outlive the display by the
/// whole of its budget.
struct StandaloneChildPass {
    report: Arc<Mutex<ChildReport>>,
    /// Far longer than the test runs, so a passing run cannot be the budget
    /// expiring on its own.
    budget: Duration,
}

impl Pass for StandaloneChildPass {
    fn run(&self, _forced: bool, cancel: &Cancel, deadline: Instant) -> Option<Vec<RowOutcome>> {
        let ctx = PassCtx::standalone(cancel.clone(), deadline);
        let Ok(child) = Command::new("/bin/sleep").arg("30").spawn() else {
            return Some(Vec::new());
        };
        let token = ctx.register_child(child);
        lock(&self.report).spawned_at = Some(Instant::now());

        let outcome = ctx.wait_child_timeout(token, self.budget);

        let mut report = lock(&self.report);
        report.reaped_at = Some(Instant::now());
        report.gave_up = matches!(outcome, Ok(None));
        Some(Vec::new())
    }
}

/// A pass whose thread dies without answering.
struct PanickingPass {
    calls: Arc<AtomicUsize>,
}

impl Pass for PanickingPass {
    fn run(&self, _forced: bool, _cancel: &Cancel, _deadline: Instant) -> Option<Vec<RowOutcome>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        panic!("the pass fell over")
    }
}

/// A pass that records the `forced` flag it was called with and returns at
/// once.
struct RecordingPass {
    calls: Arc<Mutex<Vec<bool>>>,
}

impl Pass for RecordingPass {
    fn run(&self, forced: bool, _cancel: &Cancel, _deadline: Instant) -> Option<Vec<RowOutcome>> {
        lock(&self.calls).push(forced);
        Some(vec![fixtures::row_with_usage(0, "owner@example.com")])
    }
}

/// A pass that answers with rows once and then reports nothing, the way a
/// [`Session`] does when the registry cannot be read.
struct FailsAfterFirstPass {
    calls: Arc<AtomicUsize>,
}

impl Pass for FailsAfterFirstPass {
    fn run(&self, _forced: bool, _cancel: &Cancel, _deadline: Instant) -> Option<Vec<RowOutcome>> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            Some(vec![fixtures::row_with_usage(0, "owner@example.com")])
        } else {
            None
        }
    }
}

/// A pass caught in the window the credential writer opens between staging
/// `.credentials.json.tmp.<hex>` and renaming it into place.
///
/// The write is the real one, through
/// [`write_credentials`](crate::secret::file_store::write_credentials), so
/// what the loop has to clean up is a genuinely registered temporary file
/// holding genuine token material — not a fixture standing in for one.
#[cfg(feature = "testing")]
struct StagingPass {
    paths: Arc<Paths>,
    blob: String,
}

#[cfg(feature = "testing")]
impl Pass for StagingPass {
    fn run(&self, _forced: bool, cancel: &Cancel, deadline: Instant) -> Option<Vec<RowOutcome>> {
        let ns_dir = self.paths.namespace_dir(ACCT, ORG);
        let request = WriteRequest {
            paths: &self.paths,
            ns_dir: &ns_dir,
            blob_json: &self.blob,
            prior: None,
            new_expires_at_ms: Timestamp::now().as_millisecond() + 3_600_000,
            fault: Fault::from_list("pause_before_rename"),
        };

        let ctx = PassCtx::standalone(cancel.clone(), deadline);
        // The outcome is not this pass's business: the test is about what is
        // left on disk when the loop returns, and every outcome here — the
        // rename, the refusal, the cancellation — is one the writer handles.
        let _ = write_credentials(&request, &ctx);
        Some(Vec::new())
    }
}

/// Every staged-but-unrenamed credential file in a namespace.
#[cfg(feature = "testing")]
fn staged_tmps(ns_dir: &Path) -> Vec<String> {
    let prefix = format!("{CREDENTIALS_FILE}.tmp.");
    let Ok(dir) = fs::read_dir(ns_dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = dir
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(&prefix))
        .collect();
    names.sort();
    names
}

/// Locks a test mutex, recovering from poisoning so one failed assertion does
/// not cascade into a second, unrelated failure.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// A terminal that draws into a buffer.
fn terminal() -> Terminal<TestBackend> {
    Terminal::new(TestBackend::new(80, 24)).expect("a test backend always reports its size")
}

/// Blocks until `ready` answers true, or `budget` runs out.
fn wait_until(budget: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < budget {
        if ready() {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    ready()
}

// ---------------------------------------------------------------------------
// AC13 — the interval floor
// ---------------------------------------------------------------------------

#[test]
fn an_interval_below_the_floor_is_refused_naming_the_floor() {
    // The parser rejects it too (`cli_tests.rs`), but `WatchArgs` is an
    // ordinary struct: the floor is a promise to the usage API, not a nicety
    // of the command line, so the command refuses one as well.
    let cli = Cli::parse_from(["agctl", "claude", "watch"]);
    let args = WatchArgs { interval: Duration::from_secs(30) };

    let err = run(&cli, &args, &Cancel::new()).expect_err("30s is below the 60s floor");

    let message = err.to_string();
    assert!(message.contains("60"), "the refusal must name the floor: {message}");
    assert_eq!(err.exit_code(), crate::error::EXIT_FATAL);
}

#[test]
fn the_floor_itself_is_accepted() {
    let args = WatchArgs { interval: FLOOR };

    // Not run to completion — that would enter a terminal — but the floor
    // check is the first thing `run` does, and the deadline it derives is the
    // observable half of accepting the value.
    assert!(args.interval >= WATCH_INTERVAL_FLOOR);
    assert!(pass_deadline(args.interval) > Instant::now());
}

// ---------------------------------------------------------------------------
// The pass deadline
// ---------------------------------------------------------------------------

#[test]
fn the_pass_deadline_is_the_interval_less_five_seconds() {
    let before = Instant::now();

    let deadline = pass_deadline(FLOOR);

    let budget = deadline.saturating_duration_since(before);
    assert!(
        budget >= Duration::from_secs(55) && budget <= Duration::from_millis(55_500),
        "the 60s floor must leave at least 55s of pass budget, got {budget:?}"
    );
}

#[test]
fn an_interval_shorter_than_the_margin_yields_no_budget_rather_than_too_much() {
    // Unreachable behind the floor check; asserted so that a later edit
    // cannot turn it into a deadline *longer* than the interval, which would
    // let two passes overlap.
    let deadline = pass_deadline(Duration::from_secs(1));

    assert!(deadline <= Instant::now(), "a budget that does not exist must be already spent");
}

// ---------------------------------------------------------------------------
// Key binding
// ---------------------------------------------------------------------------

/// A key press, as the terminal reports one.
fn press(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
    KeyEvent::new(code, modifiers)
}

#[test]
fn the_quit_keys_are_bound() {
    assert_eq!(bind(press(KeyCode::Char('q'), KeyModifiers::NONE)), Some(Key::Quit));
    assert_eq!(bind(press(KeyCode::Esc, KeyModifiers::NONE)), Some(Key::Quit));
    // Raw mode swallows the terminal driver's SIGINT, so Ctrl-C has to be
    // bound explicitly or the first key everyone reaches for does nothing.
    assert_eq!(bind(press(KeyCode::Char('c'), KeyModifiers::CONTROL)), Some(Key::Quit));
    assert_eq!(bind(press(KeyCode::Char('d'), KeyModifiers::CONTROL)), Some(Key::Quit));
}

#[test]
fn the_refresh_and_selection_keys_are_bound() {
    assert_eq!(bind(press(KeyCode::Char('r'), KeyModifiers::NONE)), Some(Key::Refresh));
    assert_eq!(bind(press(KeyCode::Up, KeyModifiers::NONE)), Some(Key::Up));
    assert_eq!(bind(press(KeyCode::Char('k'), KeyModifiers::NONE)), Some(Key::Up));
    assert_eq!(bind(press(KeyCode::Down, KeyModifiers::NONE)), Some(Key::Down));
    assert_eq!(bind(press(KeyCode::Char('j'), KeyModifiers::NONE)), Some(Key::Down));
}

#[test]
fn unbound_keys_and_key_releases_are_ignored() {
    assert_eq!(bind(press(KeyCode::Char('x'), KeyModifiers::NONE)), None);

    let mut release = press(KeyCode::Char('q'), KeyModifiers::NONE);
    release.kind = KeyEventKind::Release;
    assert_eq!(bind(release), None, "letting go of `q` must not quit a second time");
}

// ---------------------------------------------------------------------------
// AC35 — a stuck worker stops neither the frames nor `q`
// ---------------------------------------------------------------------------

#[test]
fn frames_keep_coming_and_quit_is_answered_while_a_worker_is_held() {
    let store = store();
    let entered = Arc::new(AtomicBool::new(false));
    let left = Arc::new(AtomicBool::new(false));
    let pass: Arc<dyn Pass> = Arc::new(HeldPass {
        paths: Arc::clone(&store.paths),
        // Far longer than this test runs: the point is that the loop leaves
        // while the worker is still in there.
        hold: Duration::from_secs(10),
        entered: Arc::clone(&entered),
        left: Arc::clone(&left),
    });

    let mut events = ScriptedEvents::quiet_then_quit(5);
    let cancel = Cancel::new();
    let mut terminal = terminal();

    let started = Instant::now();
    run_loop(&mut terminal, &mut events, &pass, &cancel, FLOOR)
        .expect("a test backend never fails to draw");
    let ran_for = started.elapsed();

    let quit_at = events.answered_quit_at.expect("the script answered `q`");
    assert!(
        quit_at.elapsed() < Duration::from_millis(500),
        "`q` must return without joining the worker, took {:?}",
        quit_at.elapsed()
    );
    assert!(
        ran_for < Duration::from_secs(5),
        "the loop left while the worker was still inside its 10s hold, after {ran_for:?}"
    );
    assert!(entered.load(Ordering::SeqCst), "the worker really did reach the lock");
    // `q` cancels and then drains for at most `QUIT_DRAIN_BUDGET`, so a
    // cooperative worker is out by the time the loop returns. What proves the
    // loop did not *wait out the hold* is the clock: 10 s of hold against a
    // run that lasted less than five.
    assert!(
        left.load(Ordering::SeqCst),
        "the held worker came out because it was cancelled, not because its 10s hold expired"
    );

    assert!(events.asked_at.len() >= 6, "a frame was drawn before each of these asks");
    assert!(
        events.longest_redraw_gap() <= Duration::from_millis(500),
        "frames must keep coming while a worker is stuck, longest gap {:?}",
        events.longest_redraw_gap()
    );
    assert!(cancel.is_cancelled(), "`q` sets the pass-wide cancellation flag");
}

// ---------------------------------------------------------------------------
// AC43 — a registered child dies with the pass
// ---------------------------------------------------------------------------

#[test]
fn a_registered_child_is_dead_by_the_time_quit_returns() {
    let report = Arc::new(Mutex::new(ChildReport::default()));
    let pass: Arc<dyn Pass> = Arc::new(ChildPass { report: Arc::clone(&report) });

    let mut events = ScriptedEvents::quiet_then_quit(3);
    let cancel = Cancel::new();
    let mut terminal = terminal();

    run_loop(&mut terminal, &mut events, &pass, &cancel, FLOOR)
        .expect("a test backend never fails to draw");
    let returned_at = Instant::now();
    let quit_at = events.answered_quit_at.expect("the script answered `q`");

    // No polling for the child to die: `q` kills every registered child itself
    // rather than leaving it to the coordinator's watchdog, so the `sleep 30`
    // is already gone at this line. A `wait_until` here would pass even if the
    // loop had left the job to a thread, which is the thing being ruled out.
    let report = lock(&report);
    let spawned_at = report.spawned_at.expect("the child was spawned");
    let reaped_at = report
        .reaped_at
        .expect("the `sleep 30` must be dead before `run_loop` returns, not shortly after");
    assert!(spawned_at < quit_at, "the child was already running when `q` was pressed");
    assert!(reaped_at <= returned_at, "and was reaped before the loop returned");
    assert!(
        report.interrupted,
        "the worker learns the pass was cancelled from its wait, not from a timeout"
    );

    // AC35's budget, measured with the bounded drain in place.
    let latency = returned_at.duration_since(quit_at);
    assert!(latency < Duration::from_millis(500), "`q` must return within 500ms, took {latency:?}");
}

#[test]
fn a_child_registered_with_no_watchdog_is_dead_by_the_time_quit_returns() {
    // The same guarantee as the test above, on the path that has no watchdog
    // at all. The 30 s budget is what makes it non-vacuous: without the
    // cancellation clause in `wait_child_timeout` the wait would still be
    // running when `run_loop` returned and `reaped_at` would be unset.
    let report = Arc::new(Mutex::new(ChildReport::default()));
    let pass: Arc<dyn Pass> = Arc::new(StandaloneChildPass {
        report: Arc::clone(&report),
        budget: Duration::from_secs(30),
    });

    let mut events = ScriptedEvents::quiet_then_quit(3);
    let cancel = Cancel::new();
    let mut terminal = terminal();

    run_loop(&mut terminal, &mut events, &pass, &cancel, FLOOR)
        .expect("a test backend never fails to draw");
    let returned_at = Instant::now();
    let quit_at = events.answered_quit_at.expect("the script answered `q`");

    let report = lock(&report);
    let spawned_at = report.spawned_at.expect("the child was spawned");
    let reaped_at = report
        .reaped_at
        .expect("the `sleep 30` must be dead before `run_loop` returns, not 30 seconds later");
    assert!(spawned_at < quit_at, "the child was already running when `q` was pressed");
    assert!(reaped_at <= returned_at, "and was reaped before the loop returned");
    assert!(
        report.gave_up,
        "the wait gave up and killed the child — `Ok(None)` is only returned after the \
         kill and the reap"
    );

    let latency = returned_at.duration_since(quit_at);
    assert!(latency < Duration::from_millis(500), "`q` must return within 500ms, took {latency:?}");
}

// ---------------------------------------------------------------------------
// `q` leaves no token material staged
// ---------------------------------------------------------------------------

#[cfg(feature = "testing")]
#[test]
fn quitting_while_a_pass_holds_a_staged_credential_file_leaves_none_behind() {
    // Gated on `testing` because that is the feature under which
    // `Fault::pause_point` actually pauses; without it the writer would run
    // straight through and there would be no staged file to observe, which
    // would make the first assertion below vacuous rather than failing.
    let store = store();
    let ns_dir = store.paths.namespace_dir(ACCT, ORG);
    fs::create_dir_all(&ns_dir).expect("the namespace directory should be creatable");

    let pass: Arc<dyn Pass> = Arc::new(StagingPass {
        paths: Arc::clone(&store.paths),
        blob: blob(ACCT, "staged-access", "owner@example.com"),
    });

    // The staged file exists only between the write and the rename, so it is
    // watched for rather than looked for once.
    let seen_staged = Arc::new(AtomicBool::new(false));
    let stop_watching = Arc::new(AtomicBool::new(false));
    let watcher = {
        let ns_dir = ns_dir.clone();
        let seen = Arc::clone(&seen_staged);
        let stop = Arc::clone(&stop_watching);
        thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                if !staged_tmps(&ns_dir).is_empty() {
                    seen.store(true, Ordering::SeqCst);
                }
                thread::sleep(Duration::from_millis(5));
            }
        })
    };

    let mut events = ScriptedEvents::quiet_then_quit(3);
    let cancel = Cancel::new();
    let mut terminal = terminal();

    run_loop(&mut terminal, &mut events, &pass, &cancel, FLOOR)
        .expect("a test backend never fails to draw");
    let returned_at = Instant::now();
    let quit_at = events.answered_quit_at.expect("the script answered `q`");

    stop_watching.store(true, Ordering::SeqCst);
    let _ = watcher.join();

    assert!(
        seen_staged.load(Ordering::SeqCst),
        "the pass really did stage a temporary credential file, so this test is about \
         removing one rather than about there never having been one"
    );
    assert!(
        staged_tmps(&ns_dir).is_empty(),
        "`q` must not leave token material staged in the namespace: {:?}",
        staged_tmps(&ns_dir)
    );
    assert!(
        !ns_dir.join(CREDENTIALS_FILE).exists(),
        "and a write the pass never finished must not have landed either"
    );

    let latency = returned_at.duration_since(quit_at);
    assert!(latency < Duration::from_millis(500), "`q` must return within 500ms, took {latency:?}");
}

// ---------------------------------------------------------------------------
// `r` forces a pass
// ---------------------------------------------------------------------------

#[test]
fn the_refresh_key_starts_a_pass_that_bypasses_the_cache() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let pass: Arc<dyn Pass> = Arc::new(RecordingPass { calls: Arc::clone(&calls) });

    // The interval is a minute away, so nothing but `r` can start a second
    // pass inside this test.
    let mut events =
        ScriptedEvents::scripted(vec![None, Some(Key::Refresh), None, None, Some(Key::Quit)]);
    let mut terminal = terminal();

    run_loop(&mut terminal, &mut events, &pass, &Cancel::new(), FLOOR)
        .expect("a test backend never fails to draw");

    assert!(
        wait_until(Duration::from_secs(2), || lock(&calls).len() >= 2),
        "`r` should have started a second pass: {:?}",
        lock(&calls)
    );
    let calls = lock(&calls);
    assert!(!calls[0], "a scheduled pass may serve the 300s cache");
    assert!(calls[1], "a pass the user asked for goes to the wire");
}

#[test]
fn a_pass_that_falls_over_does_not_wedge_the_display() {
    let calls = Arc::new(AtomicUsize::new(0));
    let pass: Arc<dyn Pass> = Arc::new(PanickingPass { calls: Arc::clone(&calls) });

    // The pass thread's own panic message is not this test's output. Restored
    // below so a later assertion still reports normally.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_info| {}));

    // A pass that ends without answering must leave the display schedulable
    // again rather than stuck in `fetching` for the rest of the run; `r` is
    // what makes that observable inside a test rather than a minute later.
    let mut events =
        ScriptedEvents::scripted(vec![None, None, Some(Key::Refresh), None, None, Some(Key::Quit)]);
    let mut terminal = terminal();
    let cancel = Cancel::new();

    let outcome = run_loop(&mut terminal, &mut events, &pass, &cancel, FLOOR);
    std::panic::set_hook(previous);
    outcome.expect("a test backend never fails to draw");

    assert!(
        calls.load(Ordering::SeqCst) >= 2,
        "one pass falling over must not stop the next one; ran {} time(s)",
        calls.load(Ordering::SeqCst)
    );
}

#[test]
fn a_cancelled_run_leaves_without_drawing_again() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let pass: Arc<dyn Pass> = Arc::new(RecordingPass { calls: Arc::clone(&calls) });
    let cancel = Cancel::new();
    // What the signal thread does on TERM, HUP or INT before this loop even
    // starts (plan AC27's `watch` clause: the terminal is restored by the
    // registry, and the loop must not fight it by drawing again).
    cancel.cancel();

    let mut events = ScriptedEvents::scripted(Vec::new());
    let mut terminal = terminal();

    run_loop(&mut terminal, &mut events, &pass, &cancel, FLOOR)
        .expect("a cancelled loop returns cleanly");

    assert!(events.asked_at.is_empty(), "a cancelled loop asks for no keys");
    assert!(lock(&calls).is_empty(), "and starts no pass");
}

// ---------------------------------------------------------------------------
// A pass that could not look keeps the numbers that are on screen
// ---------------------------------------------------------------------------

#[test]
fn a_pass_whose_registry_cannot_be_read_reports_nothing_rather_than_no_accounts() {
    let store = store();
    write_owned_registry(&store);
    // What another terminal's `login` looks like if this pass reads the
    // registry halfway through it being saved.
    fs::write(store.paths.config_file(), "{\"version\": 1, \"accounts\": [")
        .expect("the registry should be writable");

    let session = Session {
        paths: Arc::clone(&store.paths),
        env: EnvView::with_home(store.home.clone()),
        reader_factory: Arc::new(|_ctx| {
            let reader: Box<dyn KeychainReader + Send + Sync> = Box::new(FakeReader::unlocked());
            reader
        }),
        // Unroutable: this pass must fail long before anything is fetched.
        client_factory: Arc::new(|| {
            UsageClient::new("http://127.0.0.1:1", "agctl/test", Duration::from_secs(1))
        }),
        refresher: Arc::new(NeverRefresher),
        fault: Fault::none(),
    };

    let rows = session.run(false, &Cancel::new(), pass_deadline(FLOOR));

    assert!(
        rows.is_none(),
        "an unreadable registry says nothing about the accounts; an empty list would say \
         there are none and blank the display: {rows:?}"
    );
}

#[test]
fn a_pass_that_reports_nothing_leaves_the_previous_rows_on_screen() {
    let calls = Arc::new(AtomicUsize::new(0));
    let pass: Arc<dyn Pass> = Arc::new(FailsAfterFirstPass { calls: Arc::clone(&calls) });

    // `r` is what makes the second pass happen inside this test rather than a
    // minute later.
    let mut events =
        ScriptedEvents::scripted(vec![None, Some(Key::Refresh), None, None, Some(Key::Quit)]);
    let mut terminal = terminal();

    run_loop(&mut terminal, &mut events, &pass, &Cancel::new(), FLOOR)
        .expect("a test backend never fails to draw");

    assert_eq!(calls.load(Ordering::SeqCst), 2, "`r` should have started a second pass");
    let frame = terminal.backend().to_string();
    assert!(
        frame.contains("owner@example.com"),
        "the second pass reported nothing, so the first pass's row must still be on \
         screen:\n{frame}"
    );
}

// ---------------------------------------------------------------------------
// AC44 — the keychain preflight is re-run every pass
// ---------------------------------------------------------------------------

/// The live keychain row.
///
/// Found by kind rather than by name: a locked keychain leaves the live row
/// with no identity at all, which is half of what this test is about.
fn live_row(rows: &[RowOutcome]) -> &RowOutcome {
    rows.iter()
        .find(|row| matches!(row.record.kind, AccountKind::Live))
        .unwrap_or_else(|| panic!("no live row in {rows:?}"))
}

/// The row for the account this store owns.
fn owned_row(rows: &[RowOutcome]) -> &RowOutcome {
    rows.iter()
        .find(|row| matches!(row.record.kind, AccountKind::Owned { .. }))
        .unwrap_or_else(|| panic!("no owned row in {rows:?}"))
}

#[test]
fn a_keychain_that_locks_between_passes_is_reported_on_the_next_one() {
    let store = store();
    write_owned_registry(&store);
    write_credential_file(&store, &blob(ACCT, "owned-access", "owner@example.com"));

    let server = MockServer::start();
    let usage = server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(200).body(USAGE_BODY);
    });

    // The fake keychain answers for the live service until the test flips it
    // to locked — which is what `security` exiting 36 looks like to the
    // reader (fact F34, `KeychainStatus::Locked`).
    let locked = Arc::new(AtomicBool::new(false));
    let built = Arc::new(AtomicUsize::new(0));
    let live_blob = blob(LIVE_ACCT, "live-access", "live@example.com");
    let readers: ReaderFactory = {
        let locked = Arc::clone(&locked);
        let built = Arc::clone(&built);
        Arc::new(move |_ctx| {
            built.fetch_add(1, Ordering::SeqCst);
            let mut reader = FakeReader::unlocked().with_item(LIVE_SERVICE, live_blob.as_bytes());
            if locked.load(Ordering::SeqCst) {
                reader.preflight = KeychainStatus::Locked;
            }
            let reader: Box<dyn KeychainReader + Send + Sync> = Box::new(reader);
            reader
        })
    };

    let base_url = server.base_url();
    let session = Session {
        paths: Arc::clone(&store.paths),
        env: EnvView::with_home(store.home.clone()),
        reader_factory: readers,
        client_factory: Arc::new(move || {
            UsageClient::new(&base_url, "agctl/test", Duration::from_secs(5))
        }),
        refresher: Arc::new(NeverRefresher),
        fault: Fault::none(),
    };

    let cancel = Cancel::new();
    let first =
        session.run(false, &cancel, pass_deadline(FLOOR)).expect("the registry is readable");
    assert_eq!(
        live_row(&first).state,
        AccountState::Ok,
        "the keychain was readable on the first pass"
    );
    assert_eq!(owned_row(&first).state, AccountState::Ok);
    let after_first = built.load(Ordering::SeqCst);
    assert!(after_first >= 1, "the first pass built a reader");

    // The user's keychain locks between the two passes.
    locked.store(true, Ordering::SeqCst);

    let second =
        session.run(false, &cancel, pass_deadline(FLOOR)).expect("the registry is readable");

    let live = live_row(&second);
    assert_eq!(
        live.state,
        AccountState::KeychainLocked { detail: String::new() },
        "a preflight remembered from the first pass would still say `ok` here"
    );
    assert_eq!(live.state.label(), "keychain locked");

    let owned = owned_row(&second);
    assert_eq!(owned.state, AccountState::Ok, "an owned row reads its own file, not the keychain");
    assert_ne!(
        owned.state,
        AccountState::NeedsLogin,
        "a locked keychain must never be reported as a missing login (plan AC44)"
    );
    assert_eq!(
        owned.note.as_deref(),
        Some("keychain locked — migration probe skipped"),
        "the row says what could not be checked rather than pretending it was"
    );

    assert!(
        built.load(Ordering::SeqCst) > after_first,
        "every pass builds its own reader, so nothing about the keychain is memoized"
    );
    usage.assert_calls(2);
}
