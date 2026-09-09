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

pub mod json;
pub mod reset;
pub mod table;

use jiff::Timestamp;
use jiff::tz::TimeZone;

use crate::usage::model::UsageSnapshot;

/// What the `State` column appends to a row whose account and organization
/// UUIDs are the live credential's.
///
/// A note rather than a state, because it is not a problem: two independent
/// token pairs for one account are a legitimate `use --new-only` setup
/// (decision D-011), and both sessions stay valid. What the reader needs is
/// the reason the same address appears twice.
pub const SAME_IDENTITY_NOTE: &str = "same identity as live";

/// The `Kind` cell of a row `--by-identity` folded two rows into.
///
/// A composition of two [`AccountKind::name`](crate::config::AccountKind::name)
/// values, in the order the reader meets them: the live credential first,
/// because that is the one already in use, then the store agentctl owns.
pub const LIVE_AND_OWNED_KIND: &str = "live+owned";

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
    /// Whether this row's `(account, organization)` pair is the live
    /// credential's, which is what puts [`SAME_IDENTITY_NOTE`] in the state
    /// cell.
    pub same_identity_as_live: bool,
    /// The `Kind` cell: an
    /// [`AccountKind::name`](crate::config::AccountKind::name), or
    /// [`LIVE_AND_OWNED_KIND`] for a row two were folded into.
    ///
    /// Carried on every row but printed only under `--by-identity`, so the
    /// default table keeps the ten columns plan section 3.1 fixed. `Kind` and
    /// not `Source`: the vocabulary here is `owned`/`live`/`config_dir`/
    /// `foreign`, which is what `accounts list`'s `Kind` column and the JSON
    /// report's `kind` member already spell, while `source` in both of those
    /// means `keychain`/`file`/`env`/`none` — where the bytes were read from,
    /// a different question with a different answer.
    pub kind: &'static str,
}

impl StatusRow {
    /// The state column's full text: the state, then its notes in parentheses.
    ///
    /// Two notes are joined with a semicolon rather than one replacing the
    /// other: a row can be both `expired` for a stated reason and the live
    /// account's twin, and dropping either would answer half the reader's
    /// question.
    pub fn state_cell(&self) -> String {
        let mut notes: Vec<&str> = Vec::new();
        if let Some(note) = self.note.as_deref().filter(|note| !note.is_empty()) {
            notes.push(note);
        }
        if self.same_identity_as_live {
            notes.push(SAME_IDENTITY_NOTE);
        }
        if notes.is_empty() {
            self.state.clone()
        } else {
            format!("{} ({})", self.state, notes.join("; "))
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
    /// The zone the reset columns are printed in, for the same reason [`Report::now`]
    /// is carried: one report, one zone, so two cells cannot disagree about
    /// what "Sunday" means. `commands::status` fills it from
    /// [`TimeZone::system`]; a test injects a fixed one.
    pub tz: TimeZone,
    /// Whether `--all` was given.
    pub show_all: bool,
    /// Whether `--by-identity` was given, which is the only thing that puts
    /// the `Kind` column on the table.
    ///
    /// The folding itself has already happened by the time a report exists —
    /// which rows survive is a decision about accounts, and
    /// `commands::status` makes it (see this module's opening note on why a
    /// renderer is given no room to decide what to hide).
    pub by_identity: bool,
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
