//! Process-lifetime concerns: cancellation, bounded fan-out, child-process
//! ownership, signal handling, and emergency cleanup.
//!
//! These modules are deliberately coupled in one direction, with one
//! exception. [`log_writer`] knows about nothing; [`coordinator`] calls into
//! [`cleanup`] when a pass ends abnormally, and [`cleanup`] reads the
//! [`coordinator::Cancel`] flag only to refuse a spawn once cancellation has
//! begun; [`signals`] calls into both.
//! Nothing here knows anything about accounts, credentials or HTTP, which is
//! what lets the provider modules be tested without standing up a pass.

pub mod cleanup;
pub mod coordinator;
pub mod fault;
#[cfg(feature = "testing")]
pub mod lock_order;
pub mod log_writer;
pub mod proc;
pub mod signals;
