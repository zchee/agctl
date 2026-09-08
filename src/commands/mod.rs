//! The subcommand implementations.
//!
//! One module per command, each exposing a `run` that `main`'s dispatch calls
//! with the parsed arguments and the process-wide cancellation flag. Keeping
//! them here rather than in `main.rs` is what lets the dispatch stay a table
//! of one-line arms, and what lets each command's real work be exercised by a
//! unit test that never spawns a process.

pub mod login;
