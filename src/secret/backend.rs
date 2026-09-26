//! Platform capabilities shared by lock consumers, never runtime selectors.

use crate::runtime::proc::Holder;
use crate::runtime::proc::ProcError;
use crate::secret::audit::HolderEvidence;

/// Whether this platform supports the macOS keychain transport.
pub const KEYCHAIN_TRANSPORT: bool = cfg!(target_os = "macos");

/// The fixed refusal for a transport this platform does not provide.
pub const UNSUPPORTED: &str = "unsupported on this platform";

/// Whether process visibility permits attempting to reclaim a peer directory.
pub const PEER_LOCK_REMOVAL: bool = cfg!(target_os = "macos");

/// The fixed refusal for Linux's unproved store-sharing peer visibility.
pub const STALE_REMOVAL_UNSUPPORTED: &str =
    "stale lock removal unsupported on this platform: peer visibility is unproved";

/// Converts a process sweep into the platform's recovery evidence.
pub fn holder_evidence(sweep: Result<Vec<(u32, Holder)>, ProcError>) -> HolderEvidence {
    match sweep {
        Ok(found) if found.iter().any(|(_, state)| *state == Holder::Stopped) => {
            HolderEvidence::StoppedClaudePresent
        }
        #[cfg(target_os = "macos")]
        Err(_) => HolderEvidence::None,
        #[cfg(target_os = "macos")]
        Ok(_) => HolderEvidence::NoStoppedClaude,
        #[cfg(target_os = "linux")]
        Err(_) | Ok(_) => HolderEvidence::Unreadable,
    }
}
