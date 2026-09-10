//! What `claude use --live` decides, and in what order (plan section 3.4).
//!
//! A hot-swap is one procedure with a fixed shape, and the shape is the
//! safety argument:
//!
//! - **Phase A** — read-only, nothing held. Everything that can be known from
//!   the environment, the registry and one read of the item.
//! - **Phase B** — prepare. Nothing Claude Code wants is held. **All** network,
//!   **all** prompting, **all** sampling happens here and nowhere else.
//! - **Phase C** — under Claude Code's own three locks, inside
//!   [`HOLD_BUDGET`](crate::secret::claude_lock::HOLD_BUDGET). No network, no
//!   prompt, no sampling (invariant I17), and no write is *started* down a
//!   path that cannot finish inside the budget.
//!
//! This module holds the part of that shape which is a pure decision: which
//! refusals exist, what each one costs the caller, and — the load-bearing
//! bit — **which phase each is decided in**. It performs no I/O. The driver
//! in [`commands::use`](crate::commands::r#use) executes the steps; it maps
//! every refusal through the types here to get its message and its exit code,
//! so a refusal cannot acquire a second spelling by being raised somewhere
//! new.
//!
//! # Why the order is written down rather than merely obeyed
//!
//! Two of the refusals are only correct where they are. Refusal **D** — the
//! credential does not fit fact F42's line — is decided **before any child
//! process exists** (invariant I15), because discovering it later means
//! discovering it with the locks held and a `security` child already spawned.
//! Refusal **A** — the hold's mtime moved — can only be decided *inside* the
//! hold, because that is the only place there is a hold to check. An edit
//! that moved either would still compile and would still pass a test that
//! only checked the outcome, so [`DECISION_ORDER`] pins the positions
//! themselves and `swap_tests.rs` asserts them as a table.

#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "`Phase` and `Refusal::decided_in` are the specification `swap_tests.rs` \
                  checks the driver against: they state which phase each refusal is decided \
                  in, which is a constraint on the code rather than something the code calls. \
                  The remaining items are consumed by S23 (W4b) and S25 (docs)."
    )
)]

use crate::cli::swap_exit;
use crate::config::AccountRecord;
use crate::config::paths;
use crate::provider::claude::adopt;
use crate::provider::claude::credentials::Credentials;

/// Which phase of plan section 3.4 a decision belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    /// Read-only, nothing held.
    A,
    /// Prepare: the network, the prompt, the adoption. Nothing held that
    /// Claude Code wants.
    B,
    /// Under the three Claude Code locks, inside the hold budget.
    C,
}

impl Phase {
    /// Whether the three Claude Code locks are held during this phase.
    ///
    /// The whole of invariant I17 in one predicate: anything that blocks —
    /// a POST, a prompt, a sampling wait — must be decided where this is
    /// `false`.
    pub fn holds_locks(self) -> bool {
        matches!(self, Self::C)
    }

    /// A stable token for the tracing span and `--json`.
    pub fn name(self) -> &'static str {
        match self {
            Self::A => "a",
            Self::B => "b",
            Self::C => "c",
        }
    }
}

/// The lettered refusals of plan section 3.4, plus the precondition ruling
/// OQ1 added in front of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// **A** — the lock agctl holds is compromised: its mtime moved under
    /// us, so the protocol was violated before anything was written.
    CompromisedHold,
    /// **C** — `CLAUDE_CODE_OAUTH_TOKEN` is set in agctl's **own**
    /// environment, which short-circuits every store (fact F19).
    ///
    /// Decision D-020 narrowed this to agctl's own environment: agctl
    /// cannot read another process's environment and will not guess at one.
    EnvToken,
    /// **D** — the credential does not fit fact F42's 4 032-byte keychain
    /// stdin line, newline included.
    LineTooLong,
    /// **F** — the outgoing credential cannot be adopted, so the swap would
    /// lose it (decision D-017).
    CannotAdopt(adopt::Refusal),
    /// The inherited `CLAUDE_SECURESTORAGE_CONFIG_DIR` names no store
    /// agctl owns (ruling OQ1).
    ///
    /// Deliberately **not** lettered: it is decided before Phase A's work
    /// begins, and `--json` gives it `reason: "not_owned"` rather than a
    /// `refusal` member.
    NotOwned,
}

impl Refusal {
    /// The letter `--json`'s `refusal` member carries, or `None` for the
    /// unlettered precondition.
    pub fn letter(self) -> Option<&'static str> {
        match self {
            Self::CompromisedHold => Some("A"),
            Self::EnvToken => Some("C"),
            Self::LineTooLong => Some("D"),
            Self::CannotAdopt(_) => Some("F"),
            Self::NotOwned => None,
        }
    }

    /// The process exit code, from `cli`'s single table (ruling OQ4).
    pub fn exit_code(self) -> i32 {
        match self {
            Self::CompromisedHold => swap_exit::REFUSED_A,
            Self::EnvToken => swap_exit::REFUSED_C,
            Self::LineTooLong => swap_exit::REFUSED_D,
            Self::CannotAdopt(_) => swap_exit::REFUSED_F,
            Self::NotOwned => swap_exit::PRECONDITION,
        }
    }

    /// Which phase decides this refusal.
    ///
    /// Not a description of the current code — a constraint on it. See the
    /// module documentation for why refusals **D** and **A** are the two that
    /// matter.
    pub fn decided_in(self) -> Phase {
        match self {
            // Before anything is read from the store at all.
            Self::NotOwned | Self::EnvToken => Phase::A,
            // First checked in Phase A against the stored blob, and again in
            // Phase B against the refreshed one — both before any child
            // exists (invariant I15). The later of the two is what this
            // names, because that is the constraint worth holding.
            Self::LineTooLong => Phase::B,
            // The adoption runs under the namespace locks in Phase B, which
            // is where its refusal is decided (ruling OQ2, condition (c)).
            Self::CannotAdopt(_) => Phase::B,
            // Only decidable inside the hold: there is no hold to check
            // anywhere else.
            Self::CompromisedHold => Phase::C,
        }
    }
}

/// Every refusal in the order it is decided, with the phase that decides it.
///
/// The specification `swap_tests.rs` checks the implementation against. Two
/// properties are asserted from it and neither is cosmetic: the sequence is
/// **non-decreasing** in phase, so no refusal is decided earlier in the list
/// than one that runs before it; and everything except
/// [`Refusal::CompromisedHold`] is decided **before** the locks are held, so
/// a swap that is going to be refused has not taken anything Claude Code
/// wants in order to find out.
pub const DECISION_ORDER: [Refusal; 5] = [
    Refusal::NotOwned,
    Refusal::EnvToken,
    Refusal::LineTooLong,
    Refusal::CannotAdopt(adopt::Refusal::NewerCopy),
    Refusal::CompromisedHold,
];

/// How a swap ended, as the word `--json` and the terminal both use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The item now holds the incoming credential, confirmed by the verifying
    /// read after the release.
    Applied,
    /// The item already held it. Nothing was adopted and nothing was written
    /// (plan AC72).
    AlreadyActive,
    /// The write child was killed on a timeout and the verifying read did not
    /// settle it. Means "re-run `status`", **not** "failed".
    Unknown,
    /// The write child ran and exited non-zero, or the error was decided
    /// before a child existed: the item was demonstrably not touched
    /// (ruling OQ6's `failed` half).
    ///
    /// It is an outcome and **not** a lettered refusal. Reporting it as
    /// refusal **A** — as this used to — made the exit code contradict the
    /// audit line, which records `"outcome":"failed"`, and it filled the one
    /// signal that means *somebody moved a lock agctl was holding* with
    /// ordinary write failures.
    Failed,
    /// Nobody agreed to the swap: the confirmation was declined, or there was
    /// no terminal to ask at and `--yes` was not given.
    ///
    /// An outcome and **not** refusal **F**, which it used to be reported as.
    /// **F** is `CannotAdopt`: *the outgoing credential cannot be adopted, so
    /// the swap would lose it*. That is a fact about the store, and a script
    /// that saw its exit code could not tell it from an operator answering
    /// "no" — two states that call for opposite responses. Since `--json` no
    /// longer implies `--yes`, declining is the common path rather than a
    /// corner, so it gets its own word and its own code.
    Cancelled,
    /// The incoming credential has expired and the swap will not refresh it,
    /// because it could not save the result.
    ///
    /// A refresh is not a read: the server rotates the refresh token away
    /// from whatever held the old one, so a refresh whose result is discarded
    /// costs the incoming account a `login`. The swap can write a refreshed
    /// credential back into a plaintext `.credentials.json` under the
    /// namespace lock it already holds; it cannot write a **second** keychain
    /// item inside one Claude Code hold, so a migrated incoming store is
    /// refused here rather than refreshed and forgotten (finding N-8).
    ///
    /// An outcome and **not** a lettered refusal: nothing about the store is
    /// wrong, nothing was written, and the remedy is one command
    /// (`agctl claude status`, which refreshes that item in place and
    /// persists the result) rather than an investigation.
    NeedsRefresh,
    /// A refresh completed and was thrown away rather than written over a
    /// newer credential.
    Discarded,
    /// Another process holds the store's locks and agctl did not break
    /// them.
    Busy,
    /// One of plan section 3.4's refusals.
    Refused(Refusal),
}

impl Outcome {
    /// The stable token for `--json`'s `outcome` member.
    pub fn word(&self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::AlreadyActive => "already_active",
            Self::Unknown => "unknown",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::NeedsRefresh => "needs_refresh",
            Self::Discarded => "discarded",
            Self::Busy => "busy",
            Self::Refused(_) => "refused",
        }
    }

    /// The process exit code.
    ///
    /// [`Outcome::Applied`] and [`Outcome::AlreadyActive`] are the only zeros;
    /// refusal **B** also exits zero but is a warning line rather than an
    /// outcome, so it never reaches here (decision D-020).
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Applied | Self::AlreadyActive => crate::error::EXIT_OK,
            Self::Unknown => swap_exit::UNKNOWN,
            Self::Failed => swap_exit::WRITE_FAILED,
            Self::Cancelled => swap_exit::CANCELLED,
            Self::NeedsRefresh => swap_exit::NEEDS_REFRESH,
            Self::Discarded => swap_exit::DISCARDED,
            Self::Busy => swap_exit::BUSY,
            Self::Refused(refusal) => refusal.exit_code(),
        }
    }
}

/// Whether a credential belongs to the account a record names.
///
/// The identity guard of invariant I1′ and the W3 re-review's **N1**, in one
/// place because it has three callers in the status pass and one in the swap,
/// and four copies of a security predicate is four chances to write it
/// differently. An item whose identity is not the record's is an **occupant**:
/// it is never read for that row, never refreshed for it, and never adopted
/// into it (ruling OQ2(d)).
///
/// # An absent `tokenAccount` is not a mismatch
///
/// Older blobs carry no `tokenAccount` at all (fact F4), and a credential
/// that does not say who it belongs to is not thereby evidence that it
/// belongs to somebody else. Refusing those would break every account that
/// has not logged in since the field appeared, so absence passes. Only a
/// **present** identity that **disagrees** refuses — which is the fail-closed
/// direction that matters, because the case this exists to stop is a swap
/// having put a different account's credential in the item.
///
/// The organization is compared only when both sides name one: a blob that
/// omits it is missing information rather than contradicting the record, and
/// a record still carrying the
/// [`UNKNOWN_ORG`](crate::config::paths::UNKNOWN_ORG) placeholder (decision
/// D-008) never learned one to compare against. The account UUID is the
/// identity that decides.
pub fn same_identity(credentials: &Credentials, record: &AccountRecord) -> bool {
    let Some(identity) = credentials.identity() else { return true };
    if identity.account_uuid != record.account_uuid {
        return false;
    }
    match identity.organization_uuid.as_deref() {
        Some(org) if record.organization_uuid != paths::UNKNOWN_ORG => {
            org == record.organization_uuid
        }
        _ => true,
    }
}

/// Who holds an item, for
/// [`AccountState::Adopted`](crate::provider::claude::account::AccountState::Adopted)
/// and for `--json`'s `occupied_by`.
///
/// An email address when the blob named one, the account UUID otherwise, and
/// a fixed sentence when it named neither. **Never token material** and never
/// the raw blob: this string is printed and logged.
pub fn occupant_of(credentials: &Credentials) -> String {
    match credentials.identity() {
        Some(identity) => identity.email.unwrap_or(identity.account_uuid),
        None => "an unidentified credential".to_owned(),
    }
}

/// Plan section 3.4's `busy` wording.
///
/// Lives here rather than in `status.rs` because both the status pass and the
/// swap reach `AcquireOutcome::Busy` and must say the same thing: this is
/// verbatim user-facing wording that names the stopped process ids and the
/// `doctor --remove-stale` remedy, and two copies of it would drift on the
/// first edit to either.
///
/// The stopped process ids are named because a bare `busy` is a dead end for
/// a user whose `Ctrl-Z`'d pane is blocking every break, and the disclaimer
/// is in the same breath because that is what makes naming them honest: a
/// process id is not attribution to a store. Nothing here reaches the audit
/// log, whose vocabulary names no pid at all (plan AC80).
pub(crate) fn busy_note(holder_alive: bool, stopped_pids: &[u32]) -> String {
    if !stopped_pids.is_empty() {
        let pids: Vec<String> = stopped_pids.iter().map(u32::to_string).collect();
        return format!(
            "a stopped claude process is present (pid {}). agctl will not break this lock \
             while one is, because it cannot tell whether that process is the holder. Resume or \
             end it, or run `agctl claude doctor --remove-stale <path> --yes`",
            pids.join(", ")
        );
    }
    if holder_alive {
        "another process is refreshing this store's credentials".to_owned()
    } else {
        "this store's refresh lock is held; agctl did not break it".to_owned()
    }
}

#[cfg(test)]
#[path = "swap_tests.rs"]
mod tests;
