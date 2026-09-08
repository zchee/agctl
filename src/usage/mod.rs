//! What "usage" is, once a provider's response has been normalized, and where
//! a normalized answer is kept between runs.
//!
//! The split is between meaning and storage:
//!
//! - [`model`] — the vocabulary the renderer and the JSON report share. It is
//!   provider-neutral on purpose: `session` and `weekly_all` are Claude's
//!   spellings, and translating them here keeps the table from having to know
//!   which vendor produced a row.
//! - [`cache`] — a per-account copy of the last successful response, so a
//!   429 or a dead network still renders numbers (marked stale) instead of a
//!   blank row, and so repeated `status` calls inside the TTL do not hit the
//!   API at all (plan principle P4).

pub mod cache;
pub mod model;
