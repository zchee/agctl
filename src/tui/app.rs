//! The watch loop's state, and the only place it changes.
//!
//! [`App`] holds no handles — no terminal, no channel, no clock. Everything
//! that reaches it arrives as an [`Event`], and every event that asks for
//! something to happen outside the state leaves as an [`Effect`]. That split
//! is what makes the whole of the loop's behaviour — what `q` does, when the
//! numbers count as stale, where the selection goes when rows disappear —
//! testable by calling one function, and it is why nothing in this file
//! reads the clock: `now` arrives on [`Event::Tick`] so that a frame drawn
//! from this state is a frame the test can reproduce exactly.
//!
//! # Why the rows are [`RowOutcome`]s
//!
//! `watch` runs the same pass `status` runs, through
//! [`collect`](crate::commands::status::collect), and shows what it produced.
//! Keeping the pass's own row type means the TUI branches on
//! [`AccountState`](crate::provider::claude::account::AccountState) — which is
//! what the badges are — rather than on a rendered string, and it means there
//! is exactly one definition of what a row is. A second view type would be a
//! second place for the two renderings of one pass to drift apart.

use jiff::Timestamp;

use crate::commands::status::RowOutcome;

/// A key the watch loop binds.
///
/// Deliberately not `crossterm`'s `KeyEvent`: the loop's reducer should not
/// know about key modifiers or repeat kinds, and a test that drives it should
/// not have to build terminal events. The translation lives at the edge, in
/// [`bind`](crate::commands::watch::bind).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    /// Leave the watch loop.
    Quit,
    /// Fetch now, ignoring the cache.
    Refresh,
    /// Move the selection towards the first row.
    Up,
    /// Move the selection towards the last row.
    Down,
}

/// Everything that can change the watch state.
#[derive(Debug)]
pub enum Event {
    /// A pass finished and produced these rows, in discovery order.
    Rows(Vec<RowOutcome>),
    /// The clock advanced; every countdown in the next frame is relative to
    /// this moment.
    Tick(Timestamp),
    /// The user pressed a bound key.
    Key(Key),
    /// A pass has just been started.
    PassStarted,
    /// A pass has just ended.
    PassFinished {
        /// When it ended.
        at: Timestamp,
        /// When the next one is due, or `None` when no further pass is
        /// scheduled — an interval so large that the schedule does not fit
        /// the clock, where only `r` will fetch again.
        next: Option<Timestamp>,
    },
}

/// What the loop must do about an event, beyond updating the state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Nothing; the state change was the whole of it.
    None,
    /// Set the pass-wide cancellation flag and leave.
    Quit,
    /// Start a pass now, bypassing the cache.
    Refresh,
}

/// The watch loop's whole state.
#[derive(Debug)]
pub struct App {
    /// The rows the frame shows, in discovery order. Rows that `status`
    /// hides without `--all` — a stale sibling of the live credential, a
    /// foreign keychain item, a forgotten service — are not here; they are
    /// counted in [`App::hidden`].
    pub rows: Vec<RowOutcome>,
    /// When the last pass finished, if one has.
    pub last_fetch: Option<Timestamp>,
    /// When the next pass is due, if one is scheduled.
    pub next_fetch: Option<Timestamp>,
    /// Whether the numbers on screen predate the pass now in flight.
    pub stale: bool,
    /// Which row the selection is on. Always a valid index into
    /// [`App::rows`], or `0` when there are none.
    pub selected: usize,
    /// How many rows the pass produced that this display does not show.
    pub hidden: usize,
    /// Whether a pass is running right now.
    pub fetching: bool,
    /// The moment the next frame is drawn against.
    pub now: Timestamp,
}

impl App {
    /// An empty display, before the first pass has produced anything.
    pub fn new(now: Timestamp) -> Self {
        Self {
            rows: Vec::new(),
            last_fetch: None,
            next_fetch: None,
            stale: false,
            selected: 0,
            hidden: 0,
            fetching: false,
            now,
        }
    }

    /// Folds one event into the state and says what the loop must do about
    /// it.
    pub fn reduce(&mut self, event: Event) -> Effect {
        match event {
            Event::Rows(rows) => {
                self.take_rows(rows);
                // The numbers on screen are now this pass's own, whatever
                // they were a moment ago.
                self.stale = false;
                Effect::None
            }
            Event::Tick(now) => {
                self.now = now;
                Effect::None
            }
            Event::Key(key) => self.press(key),
            Event::PassStarted => {
                self.fetching = true;
                // Only meaningful once something is on screen: the very first
                // pass has nothing to be stale relative to.
                self.stale = !self.rows.is_empty();
                Effect::None
            }
            Event::PassFinished { at, next } => {
                self.fetching = false;
                self.last_fetch = Some(at);
                self.next_fetch = next;
                Effect::None
            }
        }
    }

    /// Replaces the rows, keeping the selection inside the new list.
    ///
    /// A pass can return fewer rows than the last one did — an account
    /// removed in another terminal, a keychain that went away — and a
    /// selection left pointing past the end would blank the highlight until
    /// the user pressed a key.
    fn take_rows(&mut self, rows: Vec<RowOutcome>) {
        let (shown, hidden): (Vec<RowOutcome>, Vec<RowOutcome>) =
            rows.into_iter().partition(|row| row.visible_by_default);
        self.rows = shown;
        self.hidden = hidden.len();
        self.selected = self.selected.min(self.last_index());
    }

    /// Handles one key press.
    fn press(&mut self, key: Key) -> Effect {
        match key {
            Key::Quit => Effect::Quit,
            Key::Refresh => Effect::Refresh,
            Key::Up => {
                self.selected = self.selected.saturating_sub(1);
                Effect::None
            }
            Key::Down => {
                // Saturating rather than `+ 1`: overflow checks are compiled
                // out in every profile of this project (constraint C-006), so
                // a wrapped index would land on row zero rather than failing.
                self.selected = self.selected.saturating_add(1).min(self.last_index());
                Effect::None
            }
        }
    }

    /// The last valid selection index, which is `0` for an empty display.
    fn last_index(&self) -> usize {
        self.rows.len().saturating_sub(1)
    }
}

#[cfg(test)]
#[path = "app_tests.rs"]
mod tests;
