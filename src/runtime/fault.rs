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
//! `AGCTL_FAULT`, holding a comma-separated list of names:
//!
//! | name | effect |
//! |------|--------|
//! | `security_hang` | the fake `security` script sleeps past its budget |
//! | `rename_fail` | [`crate::secret::file_store::write_credentials`] takes the pending path |
//! | `hold_lock` | [`crate::secret::namespace_lock::acquire`] holds the lock until cancel or deadline |
//! | `pause_before_rename` | the credential writer waits at `before_rename` (see [`Fault::pause_point`]) |
//! | `pause_before_migrated_reread` | the refresh-in-place path waits **before** the read that precedes its POST |
//! | `pause_before_invalid_grant_reread` | the refresh-in-place path waits before the read that follows an `invalid_grant` |
//! | `pause_before_migrated_write` | the refresh-in-place path waits after its POST and **before** it takes any lock |
//! | `pause_before_swap_write` | the swap waits after its POST and **before** it takes any lock (plan AC71) |
//! | `flock_enotsup` | the namespace lock reports `Unavailable` instead of locking |
//! | `lock_contended` | [`crate::secret::claude_lock::acquire`] sees `EEXIST` on the primary lock |
//! | `lock_stale` | every existing Claude Code lock is treated as stale, whatever its age |
//! | `lock_resume_after_sample_b` | a wedged holder heartbeats between Sample B and Sample C |
//! | `swap_lock_leak` | a [`crate::secret::claude_lock::HeldLocks`] leaves its directories and its record behind |
//! | `swap_pause_in_locks` | (W4a) the swap waits inside the hold |
//! | `swap_write_fail` | (W4a) the keychain write fails after adoption |
//! | `keychain_write_hang` | (W4a) the `security` write child never answers |
//!
//! The last three were **declared by W2 and implemented by W4a**, which is
//! the step that gave them something to act on: W2 landed the lock protocol
//! and the keychain transport with no caller, and adding a
//! sleep-inside-the-hold branch to unreachable code would have been exactly
//! the kind of dangerous dead weight section 3.8 exists to keep out.
//! Declaring the names then meant W4a did not have to invent them.
//!
//! **`swap_pause_in_locks` is the one fault that waits inside a hold**, which
//! invariant I17 otherwise forbids outright. It exists so a test can observe
//! the hold from outside — `utimes` an artefact to force refusal A, watch the
//! window open and close — and it is why it cannot ride [`Fault::pause_point`]:
//! that helper matches `pause_{name}`, and this name is not spelled that way.
//! It goes through [`Fault::wait_if`] instead, which takes the whole name.
//! Both are `testing`-only and bounded by [`PAUSE_BUDGET`], so a release
//! build cannot wait anywhere, ever.
//!
//! Without the `testing` feature [`Fault::from_env`] does not exist, the set
//! is always empty, [`Fault::is`] is always false and [`Fault::pause_point`]
//! returns at once — so a release build has no way to reach any of it. That
//! is the point: `cfg(debug_assertions)` cannot serve as the gate because
//! this project builds with `-C debug-assertions=off` everywhere (plan
//! section 3.9, constraint C-006).

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

/// The environment variable that carries the active fault names.
#[cfg(any(test, feature = "testing"))]
pub const FAULT_ENV: &str = "AGCTL_FAULT";

/// The environment variable naming the file whose appearance releases a
/// [`Fault::pause_point`].
#[cfg(any(test, feature = "testing"))]
pub const FAULT_RESUME_ENV: &str = "AGCTL_FAULT_RESUME";

/// How long a [`Fault::pause_point`] waits before giving up on its resume
/// file, so a test that crashes without writing one cannot wedge a run.
#[cfg(any(test, feature = "testing"))]
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
    /// exists in a build without the `testing` feature (the unit-test target
    /// also sees the parsers, so a plain `cargo check --tests` compiles).
    pub fn none() -> Self {
        Self::default()
    }

    /// Reads the active fault set from `AGCTL_FAULT`.
    ///
    /// Names are separated by commas; surrounding whitespace is trimmed and
    /// empty entries are dropped, so `"rename_fail, hold_lock"` and
    /// `"rename_fail,hold_lock"` mean the same thing. An unset or empty
    /// variable yields the same value as [`Fault::none`].
    #[cfg(any(test, feature = "testing"))]
    pub fn from_env() -> Self {
        match std::env::var(FAULT_ENV) {
            Ok(raw) => Self::from_list(&raw),
            Err(_) => Self::none(),
        }
    }

    /// Parses a comma-separated fault list.
    #[cfg(any(test, feature = "testing"))]
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
    /// The wait ends when the file named by `AGCTL_FAULT_RESUME` exists, or
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
        self.wait_if(&format!("pause_{name}"));
    }

    /// Blocks at a named pause point. Inert without the `testing` feature.
    #[cfg(not(feature = "testing"))]
    pub fn pause_point(&self, _name: &str) {}

    /// Blocks while `name` — the **whole** fault name, not a `pause_` stem —
    /// is active.
    ///
    /// [`Fault::pause_point`] is this function with the `pause_` prefix
    /// applied, and is what almost every waiting injection should use: the
    /// prefix is what makes a fault list readable as "these ones stop, those
    /// ones break". This is the escape hatch for a declared name that does
    /// not carry it, which today is `swap_pause_in_locks` — a name W2 fixed
    /// before the helper's convention existed, and one this crate would
    /// rather honour than quietly rename in a released fault table.
    ///
    /// The wait ends when the file named by `AGCTL_FAULT_RESUME` exists,
    /// or after [`PAUSE_BUDGET`], so a test that dies without writing one
    /// cannot wedge a run. Without the `testing` feature it returns at once.
    #[cfg(feature = "testing")]
    pub fn wait_if(&self, name: &str) {
        if !self.is(name) {
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

    /// Blocks while a whole-named fault is active. Inert without the
    /// `testing` feature.
    #[cfg(not(feature = "testing"))]
    pub fn wait_if(&self, _name: &str) {}

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
