//! `agctl codex watch` — the Codex pass on a loop, in the shared TUI.
//!
//! The loop, the terminal handling, `q` and `r` are `claude watch`'s own
//! ([`commands::watch::run_loop`](crate::commands::watch::run_loop)), generic
//! over the row: what this file adds is the pass, and the pass is
//! [`pass::collect`] — the same read-only workers `agctl codex status` fans
//! out.
//!
//! # `watch` never sends a refresh (U44 = option 5)
//!
//! The refresh driver takes a capability value that only a command building
//! one can hold, and this file builds none: the unattended loop therefore has
//! no path to a POST that type-checks, whatever it were to import the driver
//! under (review S33-C2 F1). The module it shares the pass with,
//! [`pass`](super::pass), holds no such value either, and the greps and
//! structural clauses in `scripts/` keep both statements true as the code
//! moves. An owned row that is due says `expired (run agctl codex status)`
//! instead, and a 401 on one carries the same instruction.

use std::fmt;
use std::sync::Arc;
use std::time::Instant;

use crate::cli::Cli;
use crate::cli::CodexWatchArgs;
use crate::cli::WATCH_INTERVAL_FLOOR;
use crate::commands::codex::codex_env_from_process;
use crate::commands::codex::pass;
use crate::commands::codex::pass::Options;
use crate::commands::codex::pass::Shared;
use crate::commands::status::current_fault;
use crate::commands::watch::CrosstermEvents;
use crate::commands::watch::Pass;
use crate::commands::watch::REQUEST_TIMEOUT;
use crate::commands::watch::run_loop;
use crate::config::AgctlConfig;
use crate::config::paths::Paths;
use crate::error::AppError;
use crate::provider::codex::account::CodexRowOutcome;
use crate::provider::codex::home::CodexEnv;
use crate::provider::codex::usage::UsageClient;
use crate::render::row::RowSource;
use crate::runtime::coordinator::Cancel;
use crate::runtime::coordinator::PassCtx;
use crate::runtime::fault::Fault;
use crate::tui;

/// Runs `agctl codex watch`.
///
/// # Errors
///
/// [`AppError::Config`] when `--interval` is below the floor, [`AppError::Io`]
/// when the terminal cannot be entered or drawn, and whatever resolving the
/// store failed with.
pub fn run(cli: &Cli, args: &CodexWatchArgs, cancel: &Cancel) -> Result<(), AppError> {
    if args.interval < WATCH_INTERVAL_FLOOR {
        return Err(AppError::Config(format!(
            "`--interval {}s` is below the {}s floor; agctl will not poll the usage API more \
             often than once every {} seconds",
            args.interval.as_secs(),
            WATCH_INTERVAL_FLOOR.as_secs(),
            WATCH_INTERVAL_FLOOR.as_secs()
        )));
    }

    let paths = Arc::new(Paths::resolve(cli.config_dir.as_deref())?);
    paths.ensure_dirs()?;
    paths.ensure_codex_dirs()?;
    let session: Arc<dyn Pass<CodexRowOutcome>> = Arc::new(Session::production(paths));

    let mut terminal = tui::enter()?;
    let mut events = CrosstermEvents;
    let result = run_loop(terminal.terminal_mut(), &mut events, &session, cancel, args.interval);
    drop(terminal);
    result
}

/// Builds a usage client for one pass; the seam a test points at its own
/// server.
pub type ClientFactory = Arc<dyn Fn() -> UsageClient + Send + Sync>;

/// Everything a Codex watch pass needs, built once for the run.
pub struct Session {
    paths: Arc<Paths>,
    env: CodexEnv,
    client_factory: ClientFactory,
    fault: Fault,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("config_dir", &self.paths.config_dir())
            .finish_non_exhaustive()
    }
}

impl Session {
    /// The session a real run uses.
    pub fn production(paths: Arc<Paths>) -> Self {
        Self {
            paths,
            env: codex_env_from_process(),
            client_factory: Arc::new(|| UsageClient::from_env(REQUEST_TIMEOUT)),
            fault: current_fault(),
        }
    }

    /// A session over an explicit environment and client, for tests.
    #[cfg(test)]
    pub fn new(paths: Arc<Paths>, env: CodexEnv, client_factory: ClientFactory) -> Self {
        Self { paths, env, client_factory, fault: Fault::none() }
    }

    /// One pass: the registry re-read, a fresh keychain listing when a home
    /// needs one, and the read-only workers. Never a refresh.
    fn pass(
        &self,
        forced: bool,
        cancel: &Cancel,
        deadline: Instant,
    ) -> Option<Vec<CodexRowOutcome>> {
        let config = match AgctlConfig::load(&self.paths) {
            Ok(config) => config,
            Err(err) => {
                tracing::warn!(error = %err, "the account registry could not be read this pass");
                return None;
            }
        };
        let plans = pass::plan_rows(&self.paths, &config.codex_accounts, &self.env, cancel);
        let shared = Arc::new(Shared {
            paths: Arc::clone(&self.paths),
            client: (self.client_factory)(),
            keyring: pass::keyring_listing(&plans, cancel, deadline),
            fault: self.fault.clone(),
            options: Options { refresh: false, no_cache: forced },
            allow_post: false,
        });
        Some(pass::finish(pass::collect(plans, &shared, cancel, deadline)))
    }
}

impl RowSource for Session {
    type Row = CodexRowOutcome;

    /// A scheduled pass: the cache may be served.
    fn rows(&self, ctx: &PassCtx) -> Option<Vec<CodexRowOutcome>> {
        self.pass(false, ctx.cancel(), ctx.deadline())
    }
}

impl Pass<CodexRowOutcome> for Session {
    fn run(
        &self,
        forced: bool,
        cancel: &Cancel,
        deadline: Instant,
    ) -> Option<Vec<CodexRowOutcome>> {
        if forced {
            // `r`: the wire, never the cache — and still never a refresh.
            self.pass(true, cancel, deadline)
        } else {
            self.rows(&PassCtx::standalone(cancel.clone(), deadline))
        }
    }
}

#[cfg(test)]
#[path = "watch_tests.rs"]
mod tests;
