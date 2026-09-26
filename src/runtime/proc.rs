//! Target-selected process observations, without process arguments or environment reads.
//!
//! Liveness is not authority to remove a peer lock. In particular, Linux process
//! visibility is namespace-local and a negative sweep cannot certify an absent peer.

use std::ffi::CStr;
use std::os::fd::OwnedFd;

use crate::runtime::coordinator::Cancel;

#[cfg(any(test, target_os = "linux"))]
mod classification;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("agctl supports only macOS and Linux");

#[cfg(target_os = "linux")]
use linux as platform;
#[cfg(target_os = "macos")]
use macos as platform;

/// The exact, case-sensitive process name of a matching Claude peer.
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
    /// The process list could not be read.
    #[error("the process list could not be read: {0}")]
    Listing(String),
    /// At least one process that still exists could not be classified.
    #[error("{unreadable} process(es) exist but could not be classified")]
    Incomplete {
        /// How many process ids existed and could not be read.
        unreadable: usize,
    },
}

/// Whether a process with this id exists; EPERM counts as existing.
pub fn exists(pid: u32) -> bool {
    platform::exists(pid)
}

/// Classifies a lock holder; an unreadable existing process stays alive.
pub fn holder(pid: u32, cancel: &Cancel) -> Holder {
    platform::holder(pid, cancel)
}

/// The platform's start identity, or unknown when required data is unreadable.
///
/// macOS retains its RFC3339 spelling. Linux identities include a version,
/// boot UUID, PID namespace, start ticks and real UID, not a wall timestamp.
pub fn start_time(pid: u32, cancel: &Cancel) -> Option<String> {
    platform::start_time(pid, cancel)
}

/// The process's wall-clock start, for presentation rather than recovery evidence.
pub fn start_timestamp(pid: u32, cancel: &Cancel) -> Option<jiff::Timestamp> {
    platform::start_timestamp(pid, cancel)
}

/// This process's start identity.
pub fn self_start_time(cancel: &Cancel) -> Option<String> {
    platform::self_start_time(cancel)
}

/// Every visible same-real-UID process whose name is exactly `claude`.
///
/// # Errors
///
/// Returns a listing or incomplete error rather than unclassified negative evidence.
pub fn claude_processes() -> Result<Vec<(u32, Holder)>, ProcError> {
    platform::claude_processes()
}

/// Restores owner-only directory access without changing a symlink target.
///
/// # Errors
///
/// Returns the platform error if the entry cannot safely be made searchable.
pub(crate) fn make_dir_searchable(dir: &OwnedFd, name: &CStr) -> rustix::io::Result<()> {
    platform::make_dir_searchable(dir, name)
}

/// Whether a persisted identity supplies evidence that its writer is gone.
pub(crate) fn writer_is_gone(pid: u32, recorded: Option<&str>, cancel: &Cancel) -> bool {
    #[cfg(target_os = "linux")]
    {
        !cancel.is_cancelled() && linux::writer_is_gone(pid, recorded)
    }
    #[cfg(target_os = "macos")]
    {
        if holder(pid, cancel) == Holder::Dead {
            return true;
        }
        let Some(recorded) = recorded else { return false };
        start_time(pid, cancel).is_some_and(|current| current != recorded)
    }
}

/// What a saved identity establishes about the current holder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordHolder {
    /// The identity or its domain cannot be compared.
    Unknown,
    /// The platform can establish that the PID has been recycled.
    Recycled,
    /// A comparable observation of the recorded process.
    Known(Holder),
}

impl RecordHolder {
    /// The Claude doctor's redacted holder label.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Unknown => "unknown holder identity",
            Self::Recycled => "dead (pid recycled)",
            Self::Known(holder) => holder.label(),
        }
    }
}

/// Diagnoses a record only within its platform identity domain.
pub(crate) fn record_holder(pid: u32, recorded: Option<&str>, cancel: &Cancel) -> RecordHolder {
    #[cfg(target_os = "linux")]
    let (state, recycled) = (linux::record_state(pid, recorded, cancel), false);
    #[cfg(target_os = "macos")]
    let (state, recycled) = {
        let recycled =
            recorded.is_some_and(|value| start_time(pid, cancel).as_deref() != Some(value));
        (if recycled { None } else { Some(holder(pid, cancel)) }, recycled)
    };
    if recycled {
        RecordHolder::Recycled
    } else {
        state.map_or(RecordHolder::Unknown, RecordHolder::Known)
    }
}

/// What one process looked like to the sweep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seen {
    Claude(Holder),
    Other,
    Gone,
    Unclassified,
}

/// Positive stopped evidence survives incompleteness; negative evidence does not.
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

// Keep the existing macOS test identities at runtime::proc::tests.
#[cfg(all(test, target_os = "macos"))]
use macos::classify;
#[cfg(all(test, target_os = "macos"))]
use macos::ffi;
#[cfg(all(test, target_os = "macos"))]
use macos::holder_from_status;
#[cfg(all(test, target_os = "macos"))]
use macos::look;
#[cfg(all(test, target_os = "macos"))]
use macos::render_start_time;
#[cfg(all(test, target_os = "macos"))]
use macos::signalable;
#[cfg(all(test, target_os = "macos"))]
use macos::start_instant;
#[cfg(all(test, target_os = "macos"))]
use rustix::process::Pid;

#[cfg(all(test, target_os = "macos"))]
#[path = "proc_tests.rs"]
mod tests;
