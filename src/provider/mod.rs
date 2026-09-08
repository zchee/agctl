//! Usage providers. Claude first, others later (constraint C-001).
//!
//! The `UsageProvider` trait — one `fetch` per account, returning a
//! `UsageSnapshot` — belongs to lane C, alongside the model it returns. It is
//! deliberately not declared here yet: a trait with one implementation and no
//! caller is a guess about the second provider, and phase 2 is where the
//! second one arrives to correct that guess.

pub mod claude;
