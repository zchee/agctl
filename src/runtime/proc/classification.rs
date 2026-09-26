//! Process classification rules that require no operating-system observations.

use super::CLAUDE_PROCESS_NAME;
use super::Holder;

/// Maps recognized Linux state letters, refusing unknown states.
pub(super) fn state_holder(state: u8) -> Option<Holder> {
    match state {
        b'T' | b't' => Some(Holder::Stopped),
        b'Z' | b'X' => Some(Holder::Dead),
        b'R' | b'S' | b'D' | b'I' | b'W' | b'K' | b'P' => Some(Holder::Alive),
        _ => None,
    }
}

/// Matches only the real owner and the exact, case-sensitive process name.
pub(super) fn is_claude(uid: u32, owner: u32, name: &str) -> bool {
    owner == uid && name == CLAUDE_PROCESS_NAME
}

#[cfg(test)]
#[path = "classification_tests.rs"]
mod tests;
