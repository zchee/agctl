//! What to do with the credential a hot-swap displaces (decision D-017).
//!
//! A swap overwrites one keychain item, and the credential that was in it —
//! **P**, in plan section 3.4's notation — has nowhere else to be. Losing it
//! costs the user a login and makes `use --undo` a lie, so D-017 is
//! categorical: **adopt the displaced credential or refuse the swap.** There
//! is no third answer where the swap proceeds and P is dropped.
//!
//! Everything here is a pure decision over values the caller has already
//! read. It performs no I/O, opens no file and takes no lock, which is what
//! makes the order of its refusals testable as a table rather than as a
//! sequence of mocks.
//!
//! # Where the copy goes, and why there are two answers
//!
//! | case | target |
//! |---|---|
//! | P's namespace is **not** the store being swapped | `<namespace(P)>/.credentials.json` — P's own store, which is where P belongs |
//! | P's namespace **is** the store being swapped | `<D>/.credentials.adopted.json` (decision D-024) |
//!
//! The second row is the ordinary first swap of an `agctl claude exec`
//! session, and it is the case the plan's own matrix used to refuse outright:
//! a store whose credentials have migrated into the keychain has no plaintext
//! file, and writing one back resurrects a store fact F35's composed read
//! will shadow. Ruling OQ2 permitted it narrowly and D-024 settled where:
//! **not** `.credentials.json`, because F35 falls through to that name on any
//! keychain hiccup and deletes it only when the keychain was previously empty
//! — which after a swap it never is. A name Claude Code does not read is the
//! only place a displaced credential can sit without either being served in
//! place of the one the user asked for or being destroyed by the peer's next
//! write.
//!
//! # The five states, and the two conditions on top of them
//!
//! Plan section 3.4's matrix, unchanged in substance:
//!
//! | what is already at the target | action |
//! |---|---|
//! | nothing | write it |
//! | the same credential | nothing to do |
//! | a different one, **older** by `expiresAt` | overwrite it |
//! | a different one, **newer or equal** by `expiresAt` | refuse (**F**) |
//! | unreadable, or the namespace has migrated, or a pending write is parked | refuse (**F**) |
//!
//! The "newer or equal" refusal is the one worth restating: a newer copy may
//! hold a refresh token the server has already rotated away from the older P,
//! so overwriting it would replace a working credential with a dead one.
//! Equal expiries refuse for the same reason — nothing distinguishes them, and
//! the safe direction is to keep what is there.
//!
//! Ruling OQ2 adds two conditions to the same-namespace row, both refusals
//! before the matrix is consulted at all: the identity in the item must match
//! the record's (condition (a), invariant I1′ in both directions), and a
//! pending write must still refuse (condition (b)).

#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "`Refusal::name` and `Adoption::writes` are consumed by `adopt_tests.rs` and \
                  by S25's documentation of the `--json` vocabulary"
    )
)]

use crate::provider::claude::credentials::Digests;

/// What the adoption found at the place it would write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Existing {
    /// Nothing is there. The ordinary case for a first adoption.
    Absent,
    /// A copy of exactly the credential being adopted.
    Same,
    /// A different credential, and when its access token expires.
    Different {
        /// The stored copy's `expiresAt`, in milliseconds.
        expires_at_ms: i64,
    },
    /// Something is there but could not be read or parsed. Refused rather
    /// than overwritten: what cannot be read cannot be confirmed to be
    /// worthless.
    Unreadable,
}

/// Why an adoption cannot proceed. Every variant is plan section 3.4's
/// refusal **F**; they differ only in what the message says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The copy already there is newer than, or as new as, the credential
    /// being adopted.
    NewerCopy,
    /// A pending write from an earlier run is parked in the namespace
    /// (condition (b)). An unresolved phase-1 write means the namespace's
    /// state is not settled, and adopting into it would race the replay.
    PendingPresent,
    /// P's own namespace has migrated into the keychain, so writing a
    /// plaintext store there would resurrect one the composed read shadows
    /// (fact F35, invariant I5′).
    Migrated,
    /// The credential in the item is not the record's (condition (a)). It is
    /// an occupant, not this row's credential, and adopting it would file one
    /// account's token under another's name.
    IdentityMismatch,
    /// The existing copy could not be read.
    Unreadable,
    /// The adopted copy beside the store already holds a **different
    /// account's** credential.
    ///
    /// Condition (a) for the one row that writes that file without owning it:
    /// `agctl-r3h`'s keep arm parks the incoming account's displaced copy in
    /// `<D>/.credentials.adopted.json`, and `write_adopted` renames over that
    /// name. If what is there belongs to somebody else, replacing it destroys
    /// a credential whose store may have migrated and whose item this very
    /// swap is overwriting — so the expiry comparison never gets to run.
    OccupiedByAnother,
    /// What was at the target when the adoption was decided is not what is
    /// there now.
    ///
    /// The compare-and-swap the third-namespace adoption owes: the decision
    /// is taken from a read, and between that read and the rename another
    /// pass may have written the same file. Refusing is the only safe answer
    /// — the credential now there was not weighed against this one, and it
    /// may hold a refresh token the server has already rotated away from it.
    Changed,
}

impl Refusal {
    /// The sentence `use --live` prints, and the reason the audit entry
    /// carries.
    pub fn message(self) -> &'static str {
        match self {
            Self::NewerCopy => {
                "the outgoing credential cannot be adopted: the copy already stored is newer, \
                 and may hold a refresh token the server has rotated away from this one"
            }
            Self::PendingPresent => {
                "the outgoing credential cannot be adopted: an unresolved pending write is \
                 parked in that namespace; run `agctl claude status` to settle it first"
            }
            Self::Migrated => {
                "the outgoing credential cannot be adopted: that namespace has migrated into \
                 the keychain, and restoring a plaintext store there would be shadowed by it"
            }
            Self::IdentityMismatch => {
                "the outgoing credential cannot be adopted: the keychain item belongs to a \
                 different identity than the account that owns this store"
            }
            Self::Unreadable => {
                "the outgoing credential cannot be adopted: the copy already stored could not \
                 be read"
            }
            Self::OccupiedByAnother => {
                "the outgoing credential cannot be adopted: the adopted copy beside the store \
                 belongs to another account, and replacing it would destroy that account's \
                 only copy"
            }
            Self::Changed => {
                "the outgoing credential cannot be adopted: the copy already stored changed \
                 while this swap was preparing, so it was never weighed against the one being \
                 adopted"
            }
        }
    }

    /// A stable token for `--json` and the audit entry.
    pub fn name(self) -> &'static str {
        match self {
            Self::NewerCopy => "newer_copy",
            Self::PendingPresent => "pending_present",
            Self::Migrated => "migrated",
            Self::IdentityMismatch => "identity_mismatch",
            Self::Unreadable => "unreadable",
            Self::OccupiedByAnother => "occupied_by_another",
            Self::Changed => "changed",
        }
    }
}

/// Where the displaced credential is to be written, or why it cannot be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Adoption {
    /// The target already holds this exact credential. Write nothing; the
    /// swap proceeds.
    AlreadyPresent,
    /// Write it to P's own namespace store, `<namespace(P)>/.credentials.json`.
    ToStore,
    /// Write it to the adopted copy beside the store it was displaced from,
    /// `<D>/.credentials.adopted.json` (decision D-024).
    ToAdoptedCopy,
    /// The displaced credential is the incoming account's own, and it is a
    /// **proven duplicate or strictly older** copy of the one this pass is
    /// installing: write nothing, adopt nowhere, and let the swap proceed.
    ///
    /// Not [`Self::AlreadyPresent`], which says the *target* already holds
    /// this credential; this says the credential is not worth a target,
    /// because the account whose it is, is the one being swapped in — and the
    /// pass is about to put a newer copy of that same grant into the item and
    /// (when it refreshed) into that account's own store. The other half of
    /// the row — a copy that is *not* older — is kept, and takes
    /// [`Self::ToAdoptedCopy`]'s guards to keep it (`agctl-5gs`,
    /// `agctl-r3h`).
    Discarded,
    /// Refusal **F**: the swap does not happen and nothing is written.
    Refused(Refusal),
}

impl Adoption {
    /// Whether this decision writes a file.
    pub fn writes(self) -> bool {
        matches!(self, Self::ToStore | Self::ToAdoptedCopy)
    }
}

/// Everything [`decide`] needs, all of it already read by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Input {
    /// Whether the displaced credential belongs to the account being swapped
    /// **in**, rather than to the store's own account or to a third party
    /// (`agctl-5gs`).
    ///
    /// The caller
    /// signals it rather than the matrix deriving it, for the same reason
    /// `same_namespace` is a field — deciding whose a credential is means
    /// comparing identities, which is [`swap::same_identity`](crate::provider::claude::swap::same_identity)'s
    /// job and not this function's.
    ///
    /// It selects a row, it does not skip the others' conditions: when the
    /// row **keeps** the copy it writes the store's own D-024 sibling, so
    /// [`Self::pending_present`] and [`Self::existing`] are consulted for that
    /// file exactly as the `same_namespace` row consults them. What it does
    /// skip is condition (a): the credential is the incoming account's by
    /// construction, which is precisely what [`Self::identity_matches`]
    /// denies.
    pub displaced_is_incoming: bool,
    /// When [`Self::displaced_is_incoming`] is set: the `expiresAt` of the
    /// credential the incoming account's **own store** holds — the one this
    /// pass read in Phase A and is about to install — so the row can ask
    /// whether the displaced copy is the live one.
    ///
    /// Not an `Option`: the caller has that credential in its hand (it is
    /// what the swap is installing) and `expiresAt` is a required field of
    /// the blob, so "nothing to compare against" is not a state this row can
    /// be in. Not consulted by any other row.
    pub incoming_expires_at_ms: i64,
    /// When [`Self::displaced_is_incoming`] is set: whether the displaced
    /// credential and that stored one are the **same** credential, by digest.
    ///
    /// Expiry alone cannot answer it. Two credentials of one account can
    /// carry the same `expiresAt` and different refresh tokens — a refresh
    /// inside the same expiry window — and dropping one of those on an equal
    /// expiry can kill the live chain. A proven duplicate is the only thing
    /// this row drops without weighing it. Not consulted by any other row.
    pub displaced_is_duplicate: bool,
    /// When [`Self::displaced_is_incoming`] is set: whether what is already at
    /// the target — the store's D-024 sibling — belongs to a **different
    /// account** than the credential being adopted.
    ///
    /// The caller answers it with the crate's one identity predicate
    /// (`swap::same_identity`) against the incoming record, which is the
    /// displaced credential's own account by this row's construction. A
    /// sibling that names no identity at all is **not** a different account
    /// (fact F4). Not consulted by any other row.
    pub existing_is_another_account: bool,
    /// Whether P's namespace **is** the store being swapped — the ordinary
    /// first swap of an `exec`-started session, and the case ruling OQ2
    /// permits narrowly.
    pub same_namespace: bool,
    /// Whether the identity in the item matches the record that owns the
    /// store (condition (a)). Only consulted when `same_namespace`, because
    /// that is the only case in which the item and the record are claimed to
    /// describe one account.
    ///
    /// An **absent** `tokenAccount` is an older blob (fact F4), not evidence
    /// of a different identity, so the caller passes `true` for it.
    pub identity_matches: bool,
    /// Whether a pending write is parked in the namespace (condition (b)).
    pub pending_present: bool,
    /// Whether P's own namespace has migrated into the keychain. Meaningful
    /// only when `!same_namespace`: when the namespaces are the same, the
    /// store has migrated by construction — that is *why* there is a swap —
    /// and ruling OQ2 is the exception that covers it.
    pub target_migrated: bool,
    /// What is already at the target.
    pub existing: Existing,
    /// The displaced credential's own `expiresAt`, in milliseconds.
    pub displaced_expires_at_ms: i64,
}

/// Decides what becomes of the displaced credential.
///
/// The order of the checks is the invariant, not an implementation detail: a
/// later edit that moves the pending check below the matrix would let an
/// adoption race a replay, and one that moves the identity check below it
/// would file one account's credential under another's name. `adopt_tests.rs`
/// pins the order as a table for exactly that reason.
pub fn decide(input: &Input) -> Adoption {
    // `agctl-5gs`'s row, first because its first half — a duplicate, or a
    // copy older than the one being installed — needs no target at all. Its
    // other half does write, and takes the store sibling's own conditions
    // below. Routing this credential through the third-namespace row instead
    // sent it to the incoming account's own `.credentials.json` — the file
    // step 13's write-back writes — so the swap refused `Changed` against its
    // own write and `NewerCopy` for ever afterwards (review4 N-14).
    if input.displaced_is_incoming {
        // Nothing to keep: the same credential the pass is installing, or a
        // strictly older copy of that grant. Equal expiries with different
        // digests are **not** this case — see `displaced_is_duplicate`.
        if input.displaced_is_duplicate
            || input.incoming_expires_at_ms > input.displaced_expires_at_ms
        {
            return Adoption::Discarded;
        }

        // Keeping it writes the store's own D-024 sibling, so it takes that
        // file's conditions — every one of them, because a blind rename over
        // that name destroys whatever the previous swap adopted there
        // (`agctl-5gs` review F1). Condition (a) is the exception: this
        // credential is the incoming account's by construction.
        if input.pending_present {
            return Adoption::Refused(Refusal::PendingPresent);
        }
        // Condition (a) for this file, and it outranks the expiry comparison:
        // `place` asks whether what is there is worth keeping *as a copy of
        // the same credential*, which is a question that means nothing across
        // two accounts. An older credential of somebody else is not a worse
        // copy of this one — it is somebody else's only one.
        if input.existing_is_another_account {
            return Adoption::Refused(Refusal::OccupiedByAnother);
        }
        return place(input, Adoption::ToAdoptedCopy);
    }

    // Condition (b), first for both paths that do have a target: an
    // unresolved phase-1 write means the namespace has not settled, and
    // nothing may be added to it.
    if input.pending_present {
        return Adoption::Refused(Refusal::PendingPresent);
    }

    if input.same_namespace {
        // Condition (a), invariant I1′ in both directions. Before the matrix,
        // because an occupant's credential is not this record's to file
        // anywhere at all.
        if !input.identity_matches {
            return Adoption::Refused(Refusal::IdentityMismatch);
        }
        return place(input, Adoption::ToAdoptedCopy);
    }

    // The matrix's last row for a namespace that is not the swap's target: a
    // migrated store's plaintext file is shadowed by its own keychain item.
    if input.target_migrated {
        return Adoption::Refused(Refusal::Migrated);
    }
    place(input, Adoption::ToStore)
}

/// The adoption a `use --undo` performs.
///
/// A reversal always parks what the item currently holds in **the store's own
/// adopted copy** — `<D>/.credentials.adopted.json` — whoever that credential
/// belongs to. Two differences from [`decide`], both deliberate:
///
/// - **The identity condition does not apply.** In a reversal the occupant's
///   identity is *expected* to differ from the record's; that is what makes it
///   an occupant, and parking it is the whole point. Refusing on the mismatch
///   would make every undo of a real swap impossible.
/// - **The target is fixed**, rather than being P's own namespace. Writing the
///   occupant back to *its* namespace store would mutate a third namespace
///   during a rollback, and would refuse outright whenever that namespace had
///   since migrated (fact F35) — which would block a legitimate rollback for a
///   reason that has nothing to do with the store being rolled back. Keeping
///   the occupant at D also makes the operation its own inverse: undoing an
///   undo is a swap.
/// - **The `expiresAt` comparison does not apply.** This is the subtle one.
///   [`Existing::Different`] normally refuses when the stored copy is newer,
///   because overwriting it could destroy a credential holding a refresh token
///   the server has since rotated away — and nobody has read it. In a reversal
///   that reasoning is inverted: the copy's contents are precisely what this
///   operation *just read* and is putting back into the item. Nothing is being
///   destroyed; the two credentials are changing places. Applying the
///   comparison here would refuse every rollback whose two credentials happen
///   to expire at the same moment, which is the common case.
///
/// The pending refusal still outranks everything, for the reason it does in
/// [`decide`]: an unresolved phase-1 write means the namespace has not settled.
pub fn decide_undo(input: &Input) -> Adoption {
    if input.pending_present {
        return Adoption::Refused(Refusal::PendingPresent);
    }
    match input.existing {
        // Degenerate but harmless: the item already held what the copy holds,
        // so the exchange has nothing to move.
        Existing::Same => Adoption::AlreadyPresent,
        _ => Adoption::ToAdoptedCopy,
    }
}

/// The four matrix rows that depend only on what is already at the target.
///
/// Shared by both paths so the comparison cannot drift between them: the
/// question "is what is already there worth keeping" has one answer whichever
/// file is being written.
fn place(input: &Input, write: Adoption) -> Adoption {
    match input.existing {
        Existing::Absent => write,
        Existing::Same => Adoption::AlreadyPresent,
        // Strictly older, so strictly worth replacing. Equal expiries take
        // the refusal below: nothing distinguishes them, and keeping what is
        // there cannot lose a credential the server still honours.
        Existing::Different { expires_at_ms } if expires_at_ms < input.displaced_expires_at_ms => {
            write
        }
        Existing::Different { .. } => Adoption::Refused(Refusal::NewerCopy),
        Existing::Unreadable => Adoption::Refused(Refusal::Unreadable),
    }
}

/// Classifies what was read at the adoption target against the credential
/// being adopted.
///
/// A convenience for the caller so the mapping from "what the file said" to
/// [`Existing`] is written once, next to the rules that consume it.
pub fn existing_from(read: Option<(&Digests, i64)>, displaced: &Digests) -> Existing {
    match read {
        None => Existing::Absent,
        Some((digests, _)) if digests == displaced => Existing::Same,
        Some((_, expires_at_ms)) => Existing::Different { expires_at_ms },
    }
}

#[cfg(test)]
#[path = "adopt_tests.rs"]
mod tests;
