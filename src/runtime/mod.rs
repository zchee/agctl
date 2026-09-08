//! Process-lifetime concerns: cancellation, bounded fan-out, child-process
//! ownership, signal handling, and emergency cleanup.
//!
//! These three modules are deliberately coupled in one direction only.
//! [`cleanup`] knows about nothing; [`coordinator`] calls into [`cleanup`]
//! when a pass ends abnormally; [`signals`] calls into both. Nothing here
//! knows anything about accounts, credentials or HTTP, which is what lets the
//! provider modules be tested without standing up a pass.

pub mod cleanup;
pub mod coordinator;
pub mod signals;
