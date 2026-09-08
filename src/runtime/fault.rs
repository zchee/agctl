//! Fault injection, compiled in only under the `testing` feature.
//!
//! Several behaviours this crate must get right are unreachable from a test
//! that only drives the public surface: a `rename` that fails, a namespace
//! lock that another process is holding past the deadline, a `security(1)`
//! child that never answers, an `flock` the filesystem does not support. Each
//! of those is a real failure mode with a real branch, and each is otherwise
//! only reproducible by breaking the machine.
//!
//! So the branches are reachable through one environment variable,
//! `AGENTCTL_FAULT`, holding a comma-separated list of names:
//!
//! | name | effect |
//! |------|--------|
//! | `security_hang` | the fake `security` script sleeps past its budget |
//! | `rename_fail` | [`crate::secret::file_store::write_credentials`] takes the pending path |
//! | `hold_lock` | [`crate::secret::namespace_lock::acquire`] holds the lock until cancel or deadline |
//! | `pause_before_rename` | the credential writer waits at `before_rename` (see [`Fault::pause_point`]) |
//! | `flock_enotsup` | the namespace lock reports `Unavailable` instead of locking |
//!
//! Without the `testing` feature [`Fault::from_env`] does not exist, the set
//! is always empty, [`Fault::is`] is always false and [`Fault::pause_point`]
//! returns at once — so a release build has no way to reach any of it. That
//! is the point: `cfg(debug_assertions)` cannot serve as the gate because
//! this project builds with `-C debug-assertions=off` everywhere (plan
//! section 3.9, constraint C-006).

#![cfg_attr(not(test), expect(dead_code, reason = "consumed by lane D and lane C"))]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

/// The environment variable that carries the active fault names.
#[cfg(feature = "testing")]
pub const FAULT_ENV: &str = "AGENTCTL_FAULT";

/// The environment variable naming the file whose appearance releases a
/// [`Fault::pause_point`].
#[cfg(feature = "testing")]
pub const FAULT_RESUME_ENV: &str = "AGENTCTL_FAULT_RESUME";

/// How long a [`Fault::pause_point`] waits before giving up on its resume
/// file, so a test that crashes without writing one cannot wedge a run.
#[cfg(feature = "testing")]
pub const PAUSE_BUDGET: Duration = Duration::from_secs(10);

/// How often a [`Fault::pause_point`] re-checks for its resume file.
#[cfg(feature = "testing")]
const PAUSE_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// The set of faults active in this process.
///
/// Cheap to clone — the names sit behind an [`Arc`] — because the value is
/// carried by structs that cross thread boundaries, such as
/// [`crate::secret::file_store::WriteRequest`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fault {
    names: Arc<BTreeSet<String>>,
}

impl Fault {
    /// The empty fault set: nothing is injected.
    ///
    /// This is what production code gets, and it is the only constructor that
    /// exists without the `testing` feature.
    pub fn none() -> Self {
        Self::default()
    }

    /// Reads the active fault set from `AGENTCTL_FAULT`.
    ///
    /// Names are separated by commas; surrounding whitespace is trimmed and
    /// empty entries are dropped, so `"rename_fail, hold_lock"` and
    /// `"rename_fail,hold_lock"` mean the same thing. An unset or empty
    /// variable yields the same value as [`Fault::none`].
    #[cfg(feature = "testing")]
    pub fn from_env() -> Self {
        match std::env::var(FAULT_ENV) {
            Ok(raw) => Self::from_list(&raw),
            Err(_) => Self::none(),
        }
    }

    /// Parses a comma-separated fault list.
    #[cfg(feature = "testing")]
    pub fn from_list(raw: &str) -> Self {
        let names: BTreeSet<String> =
            raw.split(',').map(str::trim).filter(|n| !n.is_empty()).map(str::to_owned).collect();
        Self { names: Arc::new(names) }
    }

    /// Whether `name` is active.
    pub fn is(&self, name: &str) -> bool {
        self.names.contains(name)
    }

    /// Blocks at a named pause point when `pause_<name>` is active.
    ///
    /// The wait ends when the file named by `AGENTCTL_FAULT_RESUME` exists, or
    /// after [`PAUSE_BUDGET`]. It exists so a test can interleave with a
    /// window that is otherwise a few microseconds wide — the moment between
    /// a refresh POST returning and the new credentials being renamed into
    /// place, where a Claude Code session may take the namespace over (plan
    /// AC21, third clause).
    ///
    /// Without the `testing` feature this returns immediately and the
    /// parameter is unused.
    #[cfg(feature = "testing")]
    pub fn pause_point(&self, name: &str) {
        if !self.is(&format!("pause_{name}")) {
            return;
        }

        let resume = std::env::var_os(FAULT_RESUME_ENV).map(std::path::PathBuf::from);
        let start = Instant::now();
        loop {
            if let Some(path) = resume.as_ref()
                && path.exists()
            {
                return;
            }
            if start.elapsed() >= PAUSE_BUDGET {
                return;
            }
            std::thread::sleep(PAUSE_POLL_INTERVAL);
        }
    }

    /// Blocks at a named pause point. Inert without the `testing` feature.
    #[cfg(not(feature = "testing"))]
    pub fn pause_point(&self, _name: &str) {}

    /// Sleeps until `deadline` or cancellation, whichever comes first.
    ///
    /// Shared by the `hold_lock` and `security_hang` injections so both wait
    /// the same cooperative way rather than blocking a worker that the
    /// coordinator is trying to wind down.
    pub fn stall_until(cancel: &crate::runtime::coordinator::Cancel, deadline: Instant) {
        while !cancel.is_cancelled() && Instant::now() < deadline {
            let left = deadline.saturating_duration_since(Instant::now());
            cancel.wait_timeout(left.min(Duration::from_millis(50)));
        }
    }
}

#[cfg(test)]
#[path = "fault_tests.rs"]
mod tests;
