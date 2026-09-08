//! Turning a finished pass into something a person reads.
//!
//! [`StatusRow`] is the boundary. Everything above it — the keychain, the
//! namespace lock, the HTTP client — has finished by the time a row exists,
//! and everything below it is presentation. That split is why the table can
//! be snapshot-tested without standing up a pass, and why the JSON report
//! (W2) can be added without touching the pass at all.
//!
//! A row carries a *rendered* state string rather than an
//! [`AccountState`](crate::provider::claude::account::AccountState), so that
//! the renderer cannot accidentally make a policy decision — such as deciding
//! that some state or other should be hidden. Visibility and the exit status
//! are settled before a row is built.

pub mod table;

use jiff::Timestamp;

use crate::usage::model::UsageSnapshot;

/// One account, ready to render.
#[derive(Debug, Clone)]
pub struct StatusRow {
    /// How the account is named in the first column: its email when known,
    /// otherwise the id `--account` accepts.
    pub account: String,
    /// The organization's display name, or its UUID when unnamed.
    pub org: String,
    /// The subscription tier, as the credential recorded it.
    pub plan: String,
    /// The state column's text, from
    /// [`AccountState::label`](crate::provider::claude::account::AccountState::label).
    pub state: String,
    /// A short explanation appended to the state, when there is one.
    pub note: Option<String>,
    /// The numbers, when this row has any.
    pub usage: Option<UsageSnapshot>,
    /// Whether the row appears without `--all`.
    pub visible_by_default: bool,
}

impl StatusRow {
    /// The state column's full text: the state, then the note in parentheses.
    pub fn state_cell(&self) -> String {
        match &self.note {
            Some(note) if !note.is_empty() => format!("{} ({note})", self.state),
            _ => self.state.clone(),
        }
    }
}

/// A whole pass, ready to render.
#[derive(Debug, Clone)]
pub struct Report {
    /// Every row the pass produced, hidden ones included.
    pub rows: Vec<StatusRow>,
    /// The moment the report was built; every countdown is relative to it, so
    /// a table cannot show two cells computed against different clocks.
    pub now: Timestamp,
    /// Whether `--all` was given.
    pub show_all: bool,
}

impl Report {
    /// The rows that will actually be printed.
    pub fn shown(&self) -> Vec<&StatusRow> {
        self.rows.iter().filter(|row| self.show_all || row.visible_by_default).collect()
    }

    /// How many rows `--all` would add.
    pub fn hidden_count(&self) -> usize {
        if self.show_all {
            return 0;
        }
        self.rows.iter().filter(|row| !row.visible_by_default).count()
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
