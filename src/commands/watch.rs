//! `agentctl claude watch` — the same pass as `status`, on a loop, in a TUI.
//!
//! The command adds no data flow of its own. Every pass goes through
//! [`status::collect`](crate::commands::status::collect), so the refusals, the
//! namespace lock, the pending resolution and the cache all behave exactly as
//! they do for `status`; what is new here is when a pass runs and what happens
//! to the terminal while one is running.
//!
//! # The UI thread never waits on a worker
//!
//! A pass runs on its own thread and reports back over an [`mpsc`] channel.
//! The loop only ever `try_recv`s, and its one blocking call is a bounded wait
//! for a key press ([`POLL_INTERVAL`]). So a worker stuck on a namespace lock
//! another process is holding cannot stop the frames from being drawn, and `q`
//! is answered at the next poll boundary rather than when the worker finishes
//! (plan section 2 S1', AC35).
//!
//! `q` never *joins* the worker: joining is exactly the thing that would make
//! the exit take as long as the stuck worker does. What it does instead, in
//! this order, is [`quit`]: cancel, wait [`QUIT_DRAIN_BUDGET`] for the pass in
//! flight to come back, and run emergency cleanup. The bounded wait is not a
//! join — it is the window in which cancellation does its work. Every child
//! process the pass registered dies inside it, because
//! [`wait_child_timeout`](PassCtx::wait_child_timeout) and
//! [`wait_child`](PassCtx::wait_child) both treat cancellation as their
//! deadline and reap what they were waiting on (AC43), and a pass caught
//! between staging a credential file and renaming it into place gets the same
//! window to put its own temporary away. What does not fit in it,
//! [`cleanup::emergency`] unlinks. The terminal is restored by
//! [`Tui`](crate::tui::Tui)'s destructor on the way out regardless.
//!
//! # The pass deadline is the interval less five seconds
//!
//! A pass that ran until the next one was due would overlap itself. Five
//! seconds of headroom, checked, and the 60 s floor on `--interval` (AC13)
//! guarantees at least 55 s of budget.
//!
//! # The keychain preflight is re-run every pass
//!
//! Each pass builds a fresh reader and runs discovery from scratch, so a
//! keychain that locks between two passes is reported as locked on the next
//! one rather than being remembered as unlocked from the first (plan section
//! 3.3 step 1, AC44). Nothing about the keychain is memoized across passes.

use std::fmt;
use std::io;
use std::sync::Arc;
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use crossterm::event;
use crossterm::event::Event as TerminalEvent;
use crossterm::event::KeyCode;
use crossterm::event::KeyEvent;
use crossterm::event::KeyEventKind;
use crossterm::event::KeyModifiers;
use jiff::Timestamp;
use ratatui::Terminal;
use ratatui::backend::Backend;

use crate::cli::Cli;
use crate::cli::WATCH_INTERVAL_FLOOR;
use crate::cli::WatchArgs;
use crate::commands::status::Options;
use crate::commands::status::ReaderFactory;
use crate::commands::status::RowOutcome;
use crate::commands::status::Shared;
use crate::commands::status::collect;
use crate::commands::status::current_fault;
use crate::commands::status::default_refresher;
use crate::commands::status::production_readers;
use crate::config::AgentctlConfig;
use crate::config::paths::Paths;
use crate::error::AppError;
use crate::provider::claude::discovery;
use crate::provider::claude::namespace::EnvView;
use crate::provider::claude::usage::TokenRefresher;
use crate::provider::claude::usage::UsageClient;
use crate::runtime::cleanup;
use crate::runtime::coordinator::Cancel;
use crate::runtime::coordinator::PassCtx;
use crate::runtime::fault::Fault;
use crate::tui;
use crate::tui::app::App;
use crate::tui::app::Effect;
use crate::tui::app::Event;
use crate::tui::app::Key;
use crate::tui::ui;

/// The per-request HTTP timeout a watch pass uses.
///
/// `watch` has no `--timeout` of its own (plan section 3.2); this is the
/// default `status` takes for the same requests.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// How much of the interval a pass must leave unspent, so one pass has ended
/// before the next is due (plan section 3.3 step 3).
pub const DEADLINE_MARGIN: Duration = Duration::from_secs(5);

/// How long the loop waits for a key press before drawing again.
///
/// Also the bound on how late `q` can be answered, and — with the draw that
/// precedes it — what keeps the redraw period inside the 500 ms plan AC35
/// asks for.
pub const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// How long `q` waits for the pass in flight to come back before it stops
/// waiting and cleans up on the pass's behalf.
///
/// Sized against the two windows worth waiting out, both of which are one
/// poll interval wide rather than anything like this long: a child process
/// being killed and reaped by the cancellation clause in
/// [`wait_child_timeout`](PassCtx::wait_child_timeout), and a pass between
/// `create_new_file_at` and `renameat` in
/// [`write_credentials`](crate::secret::file_store::write_credentials), which
/// re-checks [`should_stop`](PassCtx::should_stop) immediately after the
/// staging write. Half the 500 ms plan AC35 gives the whole exit, so the
/// budget can be spent in full and still leave room.
pub const QUIT_DRAIN_BUDGET: Duration = Duration::from_millis(250);

/// Runs `agentctl claude watch`.
///
/// # Errors
///
/// Returns [`AppError::Config`] when `--interval` is below the floor,
/// [`AppError::Io`] when the terminal cannot be entered or drawn, and
/// whatever resolving the store failed with.
pub fn run(cli: &Cli, args: &WatchArgs, cancel: &Cancel) -> Result<(), AppError> {
    // The parser enforces the floor too (AC13), but `WatchArgs` is an ordinary
    // struct that any caller can build, and the floor is a promise to the
    // usage API rather than a nicety of the command line (plan principle P4).
    if args.interval < WATCH_INTERVAL_FLOOR {
        return Err(AppError::Config(format!(
            "`--interval {}s` is below the {}s floor; agentctl will not poll the usage API more \
             often than once every {} seconds",
            args.interval.as_secs(),
            WATCH_INTERVAL_FLOOR.as_secs(),
            WATCH_INTERVAL_FLOOR.as_secs()
        )));
    }

    let paths = Arc::new(Paths::resolve(cli.config_dir.as_deref())?);
    paths.ensure_dirs()?;
    let session: Arc<dyn Pass> = Arc::new(Session::production(paths)?);

    let mut terminal = tui::enter()?;
    let mut events = CrosstermEvents;
    let result = run_loop(terminal.terminal_mut(), &mut events, &session, cancel, args.interval);
    // Explicit rather than left to the end of the function so the terminal is
    // back before `main` prints anything about `result`.
    drop(terminal);
    result
}

/// One fetch pass, run on a worker thread.
///
/// A trait rather than a function so the loop's timing behaviour can be
/// tested against a pass that blocks, that registers a child process, or that
/// answers instantly — none of which the production pass can be made to do on
/// demand without a machine to break.
pub trait Pass: Send + Sync {
    /// Produces one pass's rows, in discovery order, or `None` when this pass
    /// has nothing to say about the accounts.
    ///
    /// `None` is not "no accounts" — that is `Some(vec![])`. It is "this pass
    /// failed before it could look", which the loop answers by keeping the
    /// numbers already on screen rather than blanking them over a transient
    /// failure to read the registry.
    ///
    /// Must respect `cancel` and `deadline`: the loop does not join the
    /// thread this runs on.
    fn run(&self, forced: bool, cancel: &Cancel, deadline: Instant) -> Option<Vec<RowOutcome>>;
}

/// Builds a [`UsageClient`] for one pass.
///
/// A factory rather than a client because [`Shared`] takes one by value and a
/// pass happens every interval; it is also the seam a test points at its own
/// server.
pub type ClientFactory = Arc<dyn Fn() -> UsageClient + Send + Sync>;

/// Everything a watch pass needs, built once for the whole run.
pub struct Session {
    paths: Arc<Paths>,
    env: EnvView,
    reader_factory: ReaderFactory,
    client_factory: ClientFactory,
    refresher: Arc<dyn TokenRefresher>,
    fault: Fault,
}

impl fmt::Debug for Session {
    /// The factories and the refresher are trait objects with nothing to
    /// print; what identifies a session is the store it watches.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("config_dir", &self.paths.config_dir())
            .finish_non_exhaustive()
    }
}

impl Session {
    /// The session a real run uses: the production keychain reader, the real
    /// OAuth client, and the usage endpoint from the environment.
    ///
    /// # Errors
    ///
    /// Returns whatever building the OAuth client failed with.
    pub fn production(paths: Arc<Paths>) -> Result<Self, AppError> {
        Ok(Self {
            paths,
            env: EnvView::from_process(),
            reader_factory: production_readers(),
            client_factory: Arc::new(|| UsageClient::from_env(REQUEST_TIMEOUT)),
            refresher: default_refresher()?,
            fault: current_fault(),
        })
    }
}

impl Pass for Session {
    fn run(&self, forced: bool, cancel: &Cancel, deadline: Instant) -> Option<Vec<RowOutcome>> {
        // The registry is re-read every pass: `login`, `accounts remove` or
        // `import` may have run in another terminal since the last one.
        let config = match AgentctlConfig::load(&self.paths) {
            Ok(config) => config,
            Err(err) => {
                tracing::warn!(error = %err, "the account registry could not be read this pass");
                // `None`, not an empty list: a registry that could not be read
                // says nothing about the accounts, and a half-written file
                // another terminal is in the middle of saving would otherwise
                // blank the display for a whole interval.
                return None;
            }
        };

        // A fresh reader, and therefore a fresh preflight and a fresh
        // `dump-keychain` listing, on every pass (plan AC44).
        let discovery_ctx = PassCtx::standalone(cancel.clone(), deadline);
        let reader = (self.reader_factory)(&discovery_ctx);
        let found =
            discovery::discover(&config, &self.paths, reader.as_ref(), &self.env, &discovery_ctx);

        let shared = Shared {
            paths: Arc::clone(&self.paths),
            client: (self.client_factory)(),
            refresher: Arc::clone(&self.refresher),
            reader_factory: Arc::clone(&self.reader_factory),
            listing: found.listing,
            fault: self.fault.clone(),
            // A scheduled pass may serve the 300 s cache; only `r` insists on
            // the wire.
            options: Options { refresh: false, no_cache: forced },
        };

        match collect(found.rows, &[], shared, cancel, deadline) {
            Ok(rows) => Some(rows),
            Err(err) => {
                // Unreachable with no `--account` selectors, which is the only
                // failure `collect` has; reported rather than swallowed so a
                // later widening of that contract is visible, and `None` so a
                // widened contract cannot silently blank the display either.
                tracing::warn!(error = %err, "the watch pass produced no rows");
                None
            }
        }
    }
}

/// Where the loop's key presses come from.
///
/// The seam that keeps every test off a real terminal: a test drives the loop
/// with a scripted source and never opens `/dev/tty`.
pub trait EventSource {
    /// Waits up to `timeout` for a key the loop binds, returning `None` when
    /// the wait expired or the event was one the loop ignores.
    ///
    /// # Errors
    ///
    /// The underlying terminal read failure.
    fn next_key(&mut self, timeout: Duration) -> io::Result<Option<Key>>;
}

/// The real terminal's key presses.
#[derive(Debug, Clone, Copy)]
pub struct CrosstermEvents;

impl EventSource for CrosstermEvents {
    fn next_key(&mut self, timeout: Duration) -> io::Result<Option<Key>> {
        if !event::poll(timeout)? {
            return Ok(None);
        }
        match event::read()? {
            TerminalEvent::Key(key) => Ok(bind(key)),
            // A resize or a mouse event is not a key, but it is a reason to
            // come back round the loop and draw at the new size, which
            // returning here does.
            _ => Ok(None),
        }
    }
}

/// Maps a terminal key event onto the loop's vocabulary.
///
/// Ctrl-C is bound because raw mode swallows it: with the line discipline off
/// the terminal driver no longer raises SIGINT, so without this the one key
/// every user reaches for first would do nothing.
pub fn bind(key: KeyEvent) -> Option<Key> {
    if key.kind != KeyEventKind::Press {
        return None;
    }
    match key.code {
        KeyCode::Char('c' | 'd') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            Some(Key::Quit)
        }
        KeyCode::Char('q') | KeyCode::Esc => Some(Key::Quit),
        KeyCode::Char('r') => Some(Key::Refresh),
        KeyCode::Up | KeyCode::Char('k') => Some(Key::Up),
        KeyCode::Down | KeyCode::Char('j') => Some(Key::Down),
        _ => None,
    }
}

/// The watch loop.
///
/// Returns when `q` is pressed, when `cancel` is set from elsewhere — a
/// signal, say — or when the terminal cannot be drawn.
///
/// # Errors
///
/// Returns [`AppError::Io`] when a draw or a key read fails.
pub fn run_loop<B, S>(
    terminal: &mut Terminal<B>,
    events: &mut S,
    pass: &Arc<dyn Pass>,
    cancel: &Cancel,
    interval: Duration,
) -> Result<(), AppError>
where
    B: Backend,
    B::Error: fmt::Display,
    S: EventSource,
{
    let mut app = App::new(Timestamp::now());

    // The channel the running pass will answer on, or `None` when none is
    // running. Holding the receiver *is* how the loop knows a pass is in
    // flight, so the two cannot get out of step.
    let mut in_flight: Option<Receiver<Option<Vec<RowOutcome>>>> = None;

    // `Some(instant)` is when the next pass is due; `None` means no pass is
    // scheduled, which happens only for an interval too large to add to the
    // clock. `r` still works in that case, which is why it is not an error.
    let mut due_at: Option<Instant> = Some(Instant::now());
    let mut force_next = false;

    loop {
        if cancel.is_cancelled() {
            return Ok(());
        }

        if in_flight.is_none() && due_at.is_some_and(|due| Instant::now() >= due) {
            let forced = std::mem::take(&mut force_next);
            match start_pass(pass, forced, cancel, pass_deadline(interval)) {
                Some(receiver) => {
                    in_flight = Some(receiver);
                    due_at = None;
                    app.reduce(Event::PassStarted);
                }
                None => {
                    // The operating system refused the thread. Try again at
                    // the next interval rather than leaving the display in
                    // `fetching` for a pass that never started.
                    force_next = forced;
                    due_at = schedule(interval);
                }
            }
        }

        app.reduce(Event::Tick(Timestamp::now()));
        draw(terminal, &app)?;

        // Never `recv`: the whole point of the worker thread is that the
        // frames keep coming while it is stuck (plan AC35). The outer option
        // is "a pass ended"; the inner one is what it had to show. A
        // disconnect is a pass whose thread ended without answering — it
        // panicked — and reads as the same "nothing to show" a pass that could
        // not read the registry reports, so that neither can wedge the display
        // into `fetching` for the rest of the run.
        let finished: Option<Option<Vec<RowOutcome>>> =
            match in_flight.as_ref().map(Receiver::try_recv) {
                Some(Ok(rows)) => Some(rows),
                Some(Err(mpsc::TryRecvError::Disconnected)) => Some(None),
                Some(Err(mpsc::TryRecvError::Empty)) | None => None,
            };
        if let Some(rows) = finished {
            in_flight = None;
            let at = Timestamp::now();
            if let Some(rows) = rows {
                app.reduce(Event::Rows(rows));
            } else {
                tracing::warn!("a watch pass ended without producing rows");
            }
            app.reduce(Event::PassFinished { at, next: schedule_display(at, interval) });
            due_at = if force_next { Some(Instant::now()) } else { schedule(interval) };
        }

        let key = events.next_key(POLL_INTERVAL).map_err(|err| AppError::Io {
            context: "the watch keyboard could not be read".to_owned(),
            source: err,
        })?;
        let Some(key) = key else { continue };

        match app.reduce(Event::Key(key)) {
            Effect::Quit => {
                quit(cancel, in_flight.take());
                return Ok(());
            }
            Effect::Refresh => {
                force_next = true;
                if in_flight.is_none() {
                    due_at = Some(Instant::now());
                }
            }
            Effect::None => {}
        }
    }
}

/// Leaves the watch loop on `q`, in the order the guarantees need.
///
/// 1. **Cancel.** Every cooperative waiter is watching this flag — a namespace
///    lock, the pause between two steps of a credential write, and, since it
///    is a deadline there too, every wait on a `security(1)` child. Setting it
///    first is what makes the rest short.
/// 2. **Drain, bounded.** This is not a join; it is the window in which the
///    cancellation just set does its work, and it is bounded so that a pass
///    which ignores it cannot hold the exit open. A registered child is killed
///    and reaped within one poll of the child table by
///    [`wait_child_timeout`](PassCtx::wait_child_timeout) or
///    [`wait_child`](PassCtx::wait_child) — whether or not a watchdog is
///    behind it (plan AC43) — and a pass that has staged
///    `.credentials.json.tmp.<hex>` and not yet renamed it re-checks
///    [`should_stop`](PassCtx::should_stop) immediately afterwards, so it
///    either completes the rename or takes the staged file away itself.
///    Waiting is worth it: the pass removing its own temporary is tidier than
///    the registry removing it.
/// 3. **Emergency cleanup**, for the pass that did not make it: any temporary
///    still registered is unlinked — token material must not be left at rest —
///    and the terminal restore runs. It is idempotent, so the destructor
///    running it again on the way out costs nothing.
///
/// The whole route is bounded by [`QUIT_DRAIN_BUDGET`], which is what keeps
/// `q` inside the 500 ms plan AC35 asks for.
fn quit(cancel: &Cancel, in_flight: Option<Receiver<Option<Vec<RowOutcome>>>>) {
    cancel.cancel();

    if let Some(receiver) = in_flight {
        // Whatever it answers is discarded: the display is going away, and a
        // disconnect — the pass thread ending — ends the wait just as an
        // answer does.
        let _ = receiver.recv_timeout(QUIT_DRAIN_BUDGET);
    }

    cleanup::emergency();
}

/// Starts one pass on its own thread, returning the channel it will answer
/// on, or `None` when the thread could not be started.
///
/// The thread is detached on purpose. Nothing joins it, so a pass that is
/// stuck cannot delay the loop's exit; cancellation is what winds it down.
///
/// One channel per pass rather than one for the whole run, so that the loop
/// can tell a pass that finished from a pass whose thread ended without
/// answering: the second disconnects the receiver.
fn start_pass(
    pass: &Arc<dyn Pass>,
    forced: bool,
    cancel: &Cancel,
    deadline: Instant,
) -> Option<Receiver<Option<Vec<RowOutcome>>>> {
    type Rows = Option<Vec<RowOutcome>>;
    let (tx, rx): (Sender<Rows>, Receiver<Rows>) = mpsc::channel();
    let pass = Arc::clone(pass);
    let cancel = cancel.clone();

    match thread::Builder::new().name("agentctl-watch-pass".to_owned()).spawn(move || {
        let rows = pass.run(forced, &cancel, deadline);
        // The receiver is gone when the loop has already left; there is
        // nobody to tell and nothing to do about it.
        let _ = tx.send(rows);
    }) {
        Ok(_handle) => Some(rx),
        Err(err) => {
            tracing::warn!(error = %err, "a watch pass could not be started");
            None
        }
    }
}

/// Draws one frame.
fn draw<B>(terminal: &mut Terminal<B>, app: &App) -> Result<(), AppError>
where
    B: Backend,
    B::Error: fmt::Display,
{
    terminal.draw(|frame| ui::draw(frame, app)).map(|_frame| ()).map_err(|err| AppError::Io {
        context: "the watch display could not be drawn".to_owned(),
        source: io::Error::other(err.to_string()),
    })
}

/// When a pass started now must stop (plan section 3.3 step 3).
///
/// Checked throughout: `--interval` is a user-supplied duration, and this
/// project compiles with `-C overflow-checks=off`, so a wrapped deadline
/// would land in the past and abort the pass before it began.
///
/// An interval below the margin cannot reach here — [`run`] refuses one, and
/// the parser refuses one — and if it did, it would yield a budget of zero
/// rather than one longer than the interval itself.
pub fn pass_deadline(interval: Duration) -> Instant {
    let now = Instant::now();
    let budget = interval.checked_sub(DEADLINE_MARGIN).unwrap_or(Duration::ZERO);
    now.checked_add(budget).unwrap_or(now)
}

/// When the next pass is due, or `None` for an interval that does not fit the
/// clock.
fn schedule(interval: Duration) -> Option<Instant> {
    Instant::now().checked_add(interval)
}

/// The same schedule as a wall-clock timestamp, for the header's countdown.
fn schedule_display(at: Timestamp, interval: Duration) -> Option<Timestamp> {
    i64::try_from(interval.as_millis())
        .ok()
        .and_then(|millis| at.as_millisecond().checked_add(millis))
        .and_then(|millis| Timestamp::from_millisecond(millis).ok())
}

#[cfg(test)]
#[path = "watch_tests.rs"]
mod tests;
