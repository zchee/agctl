//! Tests for decision D-017's adoption matrix.
//!
//! Plan AC69 asks for the five matrix rows as a table against the pure
//! decision function, plus ruling OQ2's same-namespace rows with all of their
//! conditions. Both are here; the e2e half lives in `tests/e2e_swap.rs`.
//!
//! The tables assert **which** decision comes out *and* — for the refusals —
//! which reason, because "refused" alone would pass even if the code refused
//! for the wrong reason, and the reason is what the user is told to act on.

use super::*;

/// A credential expiring an hour from an arbitrary fixed instant.
const NOW: i64 = 1_757_000_000_000;
const HOUR: i64 = 3_600_000;

/// The displaced credential in every case below expires at `NOW + HOUR`.
fn input(existing: Existing) -> Input {
    Input {
        displaced_is_incoming: false,
        // Only the `displaced_is_incoming` row reads these two; the value is
        // the displaced credential's own, so nothing is "newer" by default.
        incoming_expires_at_ms: NOW + HOUR,
        displaced_is_duplicate: false,
        existing_is_another_account: false,
        same_namespace: false,
        identity_matches: true,
        pending_present: false,
        target_migrated: false,
        existing,
        displaced_expires_at_ms: NOW + HOUR,
    }
}

#[test]
fn the_five_matrix_rows_of_decision_d_017() {
    // (name, input, expected)
    let cases: Vec<(&str, Input, Adoption)> = vec![
        ("absent: write it", input(Existing::Absent), Adoption::ToStore),
        ("the same credential: nothing to do", input(Existing::Same), Adoption::AlreadyPresent),
        (
            "older by expiresAt: overwrite it",
            input(Existing::Different { expires_at_ms: NOW }),
            Adoption::ToStore,
        ),
        (
            "newer by expiresAt: refuse (F)",
            input(Existing::Different { expires_at_ms: NOW + 2 * HOUR }),
            Adoption::Refused(Refusal::NewerCopy),
        ),
        (
            "migrated into the keychain: refuse (F)",
            Input { target_migrated: true, ..input(Existing::Absent) },
            Adoption::Refused(Refusal::Migrated),
        ),
    ];

    for (name, input, expected) in cases {
        assert_eq!(decide(&input), expected, "matrix row: {name}");
    }
}

#[test]
fn the_incoming_accounts_own_copy_is_dropped_only_when_it_is_a_duplicate_or_older() {
    // `agctl-5gs`'s row, split by `agctl-r3h` and guarded by review F1/F3.
    // The question is not "what is at the target" but "is this copy of that
    // account's grant worth keeping": a proven duplicate or a strictly older
    // copy is not, and everything else is. Equal expiries with **different**
    // digests are kept, because two credentials of one account can share an
    // `expiresAt` and differ in their refresh token, and dropping the live
    // one costs that account a `login`.
    let row = |stored: i64, duplicate: bool| Input {
        displaced_is_incoming: true,
        incoming_expires_at_ms: stored,
        displaced_is_duplicate: duplicate,
        ..input(Existing::Absent)
    };

    // The displaced copy expires at NOW + HOUR throughout.
    let cases: Vec<(&str, Input, Adoption)> = vec![
        ("newer than the store's copy: keep it", row(NOW, false), Adoption::ToAdoptedCopy),
        (
            "the same expiry but a different credential: keep it",
            row(NOW + HOUR, false),
            Adoption::ToAdoptedCopy,
        ),
        ("the same credential: drop it", row(NOW + HOUR, true), Adoption::Discarded),
        ("older than the store's copy: drop it", row(NOW + 2 * HOUR, false), Adoption::Discarded),
    ];
    for (name, input, expected) in cases {
        assert_eq!(decide(&input), expected, "{name}");
        assert_eq!(decide(&input).writes(), expected == Adoption::ToAdoptedCopy, "{name}");
    }
}

#[test]
fn the_kept_half_of_the_row_takes_the_adopted_copys_own_guards() {
    // Review F1/F2: keeping writes `<D>/.credentials.adopted.json`, which
    // `write_adopted` renames over blind. Every condition the
    // `same_namespace` row puts on that file applies here too, or the row
    // destroys whatever the previous swap adopted there — a credential whose
    // store has migrated and whose item this swap is overwriting has no other
    // home.
    let keep = |existing: Existing| Input {
        displaced_is_incoming: true,
        incoming_expires_at_ms: NOW,
        displaced_is_duplicate: false,
        ..input(existing)
    };

    assert_eq!(decide(&keep(Existing::Absent)), Adoption::ToAdoptedCopy, "nothing there: write it");
    assert_eq!(
        decide(&keep(Existing::Same)),
        Adoption::AlreadyPresent,
        "already the same credential: nothing to do"
    );
    assert_eq!(
        decide(&keep(Existing::Different { expires_at_ms: NOW - HOUR })),
        Adoption::ToAdoptedCopy,
        "strictly older: worth replacing"
    );
    assert_eq!(
        decide(&keep(Existing::Different { expires_at_ms: NOW + 2 * HOUR })),
        Adoption::Refused(Refusal::NewerCopy),
        "a newer copy is refused, not overwritten and not silently dropped"
    );
    assert_eq!(
        decide(&keep(Existing::Unreadable)),
        Adoption::Refused(Refusal::Unreadable),
        "what cannot be read cannot be confirmed worthless"
    );
    assert_eq!(
        decide(&Input { pending_present: true, ..keep(Existing::Absent) }),
        Adoption::Refused(Refusal::PendingPresent),
        "condition (b) applies to the file this row writes"
    );

    // Condition (a) for that file, and it outranks the expiry comparison: an
    // **older** credential of another account is not a worse copy of this one,
    // it is somebody else's only one. Without this the sibling is renamed
    // over and that account owes an interactive `login`.
    assert_eq!(
        decide(&Input {
            existing_is_another_account: true,
            ..keep(Existing::Different { expires_at_ms: NOW - HOUR })
        }),
        Adoption::Refused(Refusal::OccupiedByAnother),
        "another account's copy is refused whatever its expiry says"
    );
    assert_eq!(
        decide(&Input { existing_is_another_account: true, ..keep(Existing::Absent) }),
        Adoption::Refused(Refusal::OccupiedByAnother),
        "and the flag decides on its own"
    );
}

#[test]
fn the_row_changes_nothing_when_the_displaced_credential_is_a_third_partys() {
    // The other half of the same claim: the flag is the whole of the new
    // row's reach, so with it clear every case above answers exactly as it
    // did before it existed.
    assert_eq!(decide(&input(Existing::Absent)), Adoption::ToStore);
    assert_eq!(decide(&input(Existing::Same)), Adoption::AlreadyPresent);
    assert_eq!(
        decide(&input(Existing::Different { expires_at_ms: NOW + 2 * HOUR })),
        Adoption::Refused(Refusal::NewerCopy)
    );
    assert_eq!(
        decide(&Input { pending_present: true, ..input(Existing::Absent) }),
        Adoption::Refused(Refusal::PendingPresent)
    );
}

#[test]
fn a_reversal_ignores_the_row_because_it_has_a_target_of_its_own() {
    // The `--undo` direction parks the occupant in the store's own adopted
    // copy whoever it belongs to, which is a target that always exists — so
    // `decide_undo` never consults the flag, and a reversal of a swap whose
    // occupant happens to be the incoming account's is still a staged copy
    // rather than a discard.
    let row = Input { displaced_is_incoming: true, ..input(Existing::Absent) };
    assert_eq!(decide_undo(&row), Adoption::ToAdoptedCopy);
    assert_eq!(
        decide_undo(&Input { displaced_is_incoming: true, ..input(Existing::Same) }),
        Adoption::AlreadyPresent
    );
}

#[test]
fn an_equal_expiry_refuses_because_nothing_distinguishes_the_two() {
    // The matrix says "newer **or equal**", and the reason is worth pinning:
    // with identical expiries there is no evidence which copy the server
    // still honours, and keeping what is already stored cannot lose one.
    let equal = input(Existing::Different { expires_at_ms: NOW + HOUR });
    assert_eq!(decide(&equal), Adoption::Refused(Refusal::NewerCopy));

    // One millisecond older is strictly older, and is taken.
    let older = input(Existing::Different { expires_at_ms: NOW + HOUR - 1 });
    assert_eq!(decide(&older), Adoption::ToStore);
}

#[test]
fn a_pending_write_refuses_before_anything_else_is_considered() {
    // Condition (b), and it must outrank every other row: a namespace with an
    // unresolved phase-1 write has not settled, so even the cases that would
    // otherwise be a plain write refuse.
    for existing in [Existing::Absent, Existing::Same, Existing::Different { expires_at_ms: NOW }] {
        let pending = Input { pending_present: true, ..input(existing.clone()) };
        assert_eq!(
            decide(&pending),
            Adoption::Refused(Refusal::PendingPresent),
            "a pending write outranks {existing:?}"
        );

        // And in the same-namespace case too, ahead of the identity check.
        let both_wrong = Input {
            pending_present: true,
            same_namespace: true,
            identity_matches: false,
            ..input(existing.clone())
        };
        assert_eq!(
            decide(&both_wrong),
            Adoption::Refused(Refusal::PendingPresent),
            "the pending refusal is decided first, before the identity guard"
        );
    }
}

#[test]
fn an_unreadable_copy_is_refused_rather_than_overwritten() {
    assert_eq!(
        decide(&input(Existing::Unreadable)),
        Adoption::Refused(Refusal::Unreadable),
        "what cannot be read cannot be shown to be worthless"
    );
}

/// Ruling OQ2: `namespace(P) == D`, the ordinary first swap of an
/// `exec`-started session. Permitted narrowly, and the conditions are the
/// permission.
mod same_namespace {
    use super::*;

    fn same(existing: Existing) -> Input {
        Input { same_namespace: true, ..input(existing) }
    }

    #[test]
    fn a_matching_identity_adopts_into_the_adopted_copy_never_the_store() {
        // Decision D-024: the target is `.credentials.adopted.json`, because
        // fact F35's composed read falls through to `.credentials.json` on any
        // keychain hiccup and would serve the displaced credential in place of
        // the one the user asked for.
        assert_eq!(decide(&same(Existing::Absent)), Adoption::ToAdoptedCopy);
        assert_eq!(
            decide(&same(Existing::Different { expires_at_ms: NOW })),
            Adoption::ToAdoptedCopy,
            "an older adopted copy is replaced, like any other older copy"
        );
    }

    #[test]
    fn a_different_identity_in_the_item_refuses() {
        // Condition (a), invariant I1' in both directions. An occupant's
        // credential is not this record's to file anywhere.
        for existing in [Existing::Absent, Existing::Same] {
            let mismatched = Input { identity_matches: false, ..same(existing.clone()) };
            assert_eq!(
                decide(&mismatched),
                Adoption::Refused(Refusal::IdentityMismatch),
                "identity mismatch outranks {existing:?}"
            );
        }
    }

    #[test]
    fn a_pending_file_still_refuses() {
        // Condition (b) again, stated for the carve-out because that is where
        // the ruling wrote it down.
        let pending = Input { pending_present: true, ..same(Existing::Absent) };
        assert_eq!(decide(&pending), Adoption::Refused(Refusal::PendingPresent));
    }

    #[test]
    fn the_migrated_refusal_does_not_apply_here_which_is_the_whole_carve_out() {
        // The store has migrated by construction — that is *why* there is a
        // swap — so applying the matrix's last row would refuse W4a's
        // headline case every time. Ruling OQ2 is exactly the exception, and
        // `target_migrated` is therefore not consulted on this path.
        let migrated = Input { target_migrated: true, ..same(Existing::Absent) };
        assert_eq!(
            decide(&migrated),
            Adoption::ToAdoptedCopy,
            "the same-namespace path does not consult the migrated flag"
        );
    }

    #[test]
    fn a_newer_adopted_copy_still_refuses() {
        let newer = same(Existing::Different { expires_at_ms: NOW + 2 * HOUR });
        assert_eq!(decide(&newer), Adoption::Refused(Refusal::NewerCopy));
    }
}

#[test]
fn only_the_two_writing_decisions_write() {
    assert!(Adoption::ToStore.writes());
    assert!(Adoption::ToAdoptedCopy.writes());
    assert!(!Adoption::AlreadyPresent.writes());
    assert!(!Adoption::Discarded.writes(), "the row that has no target writes nothing");
    for refusal in every_refusal() {
        assert!(!Adoption::Refused(refusal).writes(), "{refusal:?} must not write");
    }
}

#[test]
fn every_refusal_has_a_distinct_token_and_a_message_that_names_refusal_f() {
    let mut seen: Vec<&str> = Vec::new();
    for refusal in every_refusal() {
        let name = refusal.name();
        assert!(!seen.contains(&name), "duplicate token {name}");
        seen.push(name);

        let message = refusal.message();
        assert!(
            message.starts_with("the outgoing credential cannot be adopted"),
            "every adoption refusal is plan section 3.4's refusal F and says so: {message}"
        );
        assert!(!message.is_empty());
    }
    assert_eq!(seen.len(), 7, "every variant is covered by this test");
}

fn every_refusal() -> Vec<Refusal> {
    vec![
        Refusal::NewerCopy,
        Refusal::PendingPresent,
        Refusal::Migrated,
        Refusal::IdentityMismatch,
        Refusal::Unreadable,
        Refusal::Changed,
        Refusal::OccupiedByAnother,
    ]
}

#[test]
fn existing_from_classifies_what_the_target_held() {
    let displaced = Digests { access_sha256: "aaaa".to_owned(), refresh_sha256: None };
    let other = Digests { access_sha256: "bbbb".to_owned(), refresh_sha256: None };

    assert_eq!(existing_from(None, &displaced), Existing::Absent);
    assert_eq!(existing_from(Some((&displaced, NOW)), &displaced), Existing::Same);
    assert_eq!(
        existing_from(Some((&other, NOW)), &displaced),
        Existing::Different { expires_at_ms: NOW }
    );
}

/// The rollback's adoption: the occupant is parked in the store's own copy,
/// and the rules that protect an *unread* credential fall away.
mod undo {
    use super::*;

    fn reversal(existing: Existing) -> Input {
        Input { same_namespace: true, ..input(existing) }
    }

    #[test]
    fn the_expiry_comparison_does_not_apply_to_the_copy_being_consumed() {
        // The case that matters, and the one a naive reuse of `decide` gets
        // wrong: the copy holds the credential this operation just read and is
        // restoring to the item. Refusing because it is "newer" would refuse
        // every rollback whose two credentials share an expiry — the common
        // case, since a swap that did not refresh leaves both untouched.
        for existing in [
            Existing::Absent,
            Existing::Different { expires_at_ms: NOW + 10 * HOUR },
            Existing::Different { expires_at_ms: NOW + HOUR },
            Existing::Different { expires_at_ms: NOW },
            Existing::Unreadable,
        ] {
            assert_eq!(
                decide_undo(&reversal(existing.clone())),
                Adoption::ToAdoptedCopy,
                "a reversal parks the occupant whatever the copy held: {existing:?}"
            );
        }
    }

    #[test]
    fn the_identity_condition_does_not_apply_either() {
        // In a reversal the occupant's identity is *expected* to differ from
        // the record's — that is what makes it an occupant, and parking it is
        // the point.
        let mismatched = Input { identity_matches: false, ..reversal(Existing::Absent) };
        assert_eq!(decide_undo(&mismatched), Adoption::ToAdoptedCopy);
    }

    #[test]
    fn a_pending_write_still_refuses() {
        let pending = Input { pending_present: true, ..reversal(Existing::Absent) };
        assert_eq!(decide_undo(&pending), Adoption::Refused(Refusal::PendingPresent));
    }

    #[test]
    fn an_identical_copy_has_nothing_to_exchange() {
        assert_eq!(decide_undo(&reversal(Existing::Same)), Adoption::AlreadyPresent);
    }

    #[test]
    fn a_reversal_never_writes_the_store() {
        // `ToStore` would put the occupant in `.credentials.json`, which is
        // the one place decision D-024 forbids.
        for existing in [Existing::Absent, Existing::Same, Existing::Unreadable] {
            assert_ne!(decide_undo(&reversal(existing)), Adoption::ToStore);
        }
    }
}
