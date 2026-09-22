//! A `testing`-only witness for one lock-order rule: a thread never takes
//! `.config.lock` while it holds a Codex namespace guard (numbered deviation
//! 13, plan E15).
//!
//! `agctl codex login` releases the namespace lock before it records the
//! account, and C2's `import` will do the same. Before this module that order
//! was pinned by a comment only: moving `record_account` inside the guarded
//! block passed every suite. Now every [`CodexNamespaceGuard`] carries a
//! [`HeldCodexGuard`] token, the token counts itself on the thread that made
//! it, and [`AgctlConfig::update`] asserts the count is zero right before it
//! takes the lock — so any test that reaches the registry update under a
//! guard panics, with no new pause point.
//!
//! **Why per thread.** The rule is about what *this* thread holds when it
//! blocks on `.config.lock`; a guard another thread holds is not an ordering
//! fault here, and a process-wide count would fire on it (the same reason a
//! lock-order checker keeps a per-task held-lock stack). A thread-local count
//! is only sound while every guard is dropped on the thread that created it.
//! Today that holds by construction: `lock.rs` is the only function that
//! returns a guard by value, every caller binds it to a local and lends it as
//! `&guard`, and no guard is moved into a `thread::spawn`/`scope` closure.
//! A guard dropped on another thread would underflow that thread's count;
//! with `overflow-checks=off` a bare `- 1` would wrap silently, so both
//! directions use checked arithmetic and panic with a message instead.
//!
//! Compiled only under the `testing` feature. All three of its messages
//! start with the one prefix `agctl lock order violated: `, inside a single
//! literal, and `scripts/release-gate.sh` proves that prefix absent from a
//! release artifact — so no message escapes the gate if one of them moves.
//!
//! [`CodexNamespaceGuard`]: crate::provider::codex::proof::CodexNamespaceGuard
//! [`AgctlConfig::update`]: crate::config::AgctlConfig::update

use std::cell::Cell;

thread_local! {
    /// Codex namespace guards alive on this thread.
    static HELD_CODEX_GUARDS: Cell<usize> = const { Cell::new(0) };
}

/// Proof that one Codex namespace guard is alive on this thread.
///
/// A field of `CodexNamespaceGuard` rather than a `Drop` impl on the guard:
/// every constructor of the guard must build one (a struct literal needs all
/// its fields), and the guard itself keeps its release-build borrow rules.
#[derive(Debug)]
pub struct HeldCodexGuard(());

impl HeldCodexGuard {
    /// Counts one more guard on this thread.
    ///
    /// # Panics
    ///
    /// When the count would overflow, which no real program reaches.
    pub fn take() -> Self {
        HELD_CODEX_GUARDS.with(|held| {
            let Some(next) = held.get().checked_add(1) else {
                panic!("agctl lock order violated: Codex namespace guard count overflowed on this thread");
            };
            held.set(next);
        });
        Self(())
    }
}

impl Drop for HeldCodexGuard {
    fn drop(&mut self) {
        HELD_CODEX_GUARDS.with(|held| {
            let Some(next) = held.get().checked_sub(1) else {
                panic!(
                    "agctl lock order violated: a Codex namespace guard was dropped on a thread that did not create it"
                );
            };
            held.set(next);
        });
    }
}

/// Codex namespace guards alive on this thread.
pub fn held_codex_guards() -> usize {
    HELD_CODEX_GUARDS.with(Cell::get)
}

/// Asserts this thread holds no Codex namespace guard; called right before
/// `.config.lock` is taken.
///
/// # Panics
///
/// When this thread holds one. The message is one literal with nothing
/// interpolated into it, so `strings` finds it whole in a `testing` binary
/// and the release gate can prove it absent from a shipped one.
pub fn assert_no_codex_guard_before_config_lock() {
    assert_eq!(
        held_codex_guards(),
        0,
        "agctl lock order violated: .config.lock requested while this thread holds a Codex namespace guard"
    );
}
