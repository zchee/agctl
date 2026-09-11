//! Tests for the swap's decision order and its outcome vocabulary.
//!
//! The point of this file is the **order**, not the outcomes. Plan section
//! 3.4's safety argument is that a refusal which can be decided outside the
//! hold *is*, and the two invariants that depend on it — I15 (refusal D
//! before any child exists) and I17 (no network, prompt or sampling inside
//! the hold) — are properties of position rather than of return values. A
//! test that only checked what came back would pass on a build that had moved
//! a refusal into Phase C.

use super::*;
use crate::cli::swap_exit;
use crate::config::AccountKind;
use crate::config::AccountRecord;
use crate::provider::claude::credentials::Credentials;

#[test]
fn the_decision_order_never_goes_backwards_through_the_phases() {
    let phases: Vec<Phase> = DECISION_ORDER.iter().map(|r| r.decided_in()).collect();
    for pair in phases.windows(2) {
        assert!(
            pair[0] <= pair[1],
            "the refusals are listed in the order they are decided, so their phases cannot \
             decrease: {pair:?} in {phases:?}"
        );
    }
}

#[test]
fn every_refusal_but_the_compromised_hold_is_decided_before_anything_is_held() {
    // The load-bearing assertion of this file. A swap that is going to be
    // refused must not have taken Claude Code's locks in order to find out —
    // taking them costs the peer session a refresh window, and holding them
    // while deciding something that needed no hold is invariant I17's
    // violation in its plainest form.
    for refusal in DECISION_ORDER {
        let phase = refusal.decided_in();
        if matches!(refusal, Refusal::CompromisedHold) {
            assert!(
                phase.holds_locks(),
                "refusal A is the one refusal that can only be decided inside the hold, \
                 because that is the only place there is a hold to check"
            );
            continue;
        }
        assert!(
            !phase.holds_locks(),
            "{refusal:?} is decided in phase {} — with the locks held — but nothing about it \
             requires a hold",
            phase.name()
        );
    }
}

#[test]
fn refusal_d_is_decided_before_any_child_process_can_exist() {
    // Invariant I15. `LineTooLong` is settled from the blob and the service
    // name alone, so discovering it inside the hold would mean discovering it
    // with a `security` child already spawned and the peer's locks taken.
    let phase = Refusal::LineTooLong.decided_in();
    assert!(!phase.holds_locks(), "refusal D must be decided outside the hold");
    assert!(
        phase < Phase::C,
        "refusal D is decided in phase A against the stored blob and again in phase B against \
         the refreshed one, never in phase C"
    );
}

#[test]
fn the_adoption_refusal_is_decided_in_phase_b_under_the_namespace_locks() {
    // Ruling OQ2 condition (c): the adoption write runs in Phase B, under D's
    // namespace lock — which is agctl's own lock, not one Claude Code
    // wants — and its refusal is decided there with it.
    assert_eq!(Refusal::CannotAdopt(adopt::Refusal::NewerCopy).decided_in(), Phase::B);
}

#[test]
fn only_phase_c_holds_the_locks() {
    assert!(!Phase::A.holds_locks());
    assert!(!Phase::B.holds_locks());
    assert!(Phase::C.holds_locks());
}

#[test]
fn every_refusal_carries_its_own_exit_code_and_no_two_share_one() {
    // Plan AC67 is literal: "their own message and exit code". A duplicate
    // would make two different refusals indistinguishable to a script.
    let mut seen: Vec<i32> = Vec::new();
    for refusal in DECISION_ORDER {
        let code = refusal.exit_code();
        assert!(code >= 3, "{refusal:?} exits {code}, which collides with 0, 1 or clap's 2");
        assert!(!seen.contains(&code), "{refusal:?} reuses exit code {code}");
        seen.push(code);
    }
}

#[test]
fn the_cli_exit_table_is_total_and_has_no_duplicate_or_reserved_value() {
    use crate::cli::swap_exit;

    let mut seen: Vec<i32> = Vec::new();
    for (name, code) in swap_exit::ALL {
        assert!(
            code >= 3,
            "{name} exits {code}: 0, 1 and 2 are taken by EXIT_OK, EXIT_FATAL/EXIT_PARTIAL and \
             clap's own usage error"
        );
        assert!(!seen.contains(&code), "{name} reuses exit code {code}");
        seen.push(code);
    }
    assert_eq!(seen.len(), 19, "every code in the block is listed in ALL");

    // The table itself, spelled out. Counting the entries proved only that
    // there were as many of them as expected: a renumbering, or a name moved onto another
    // account's code, left the count untouched and the test green. What a
    // caller acts on is the *pairing* — `cancelled` means 20 and nothing else
    // — so the pairing is what is pinned.
    assert_eq!(
        swap_exit::ALL,
        [
            ("refused_a", 10),
            ("refused_c", 11),
            ("refused_d", 12),
            ("refused_e", 13),
            ("refused_f", 14),
            ("precondition", 15),
            ("busy", 16),
            ("discarded", 17),
            ("unknown", 18),
            ("write_failed", 19),
            ("cancelled", 20),
            ("needs_refresh", 21),
            ("audit_refused", 22),
            ("live_unreachable", 23),
            ("live_item_absent", 24),
            ("live_swap_outstanding", 25),
            ("live_undo_of_undo", 26),
            ("live_undo_item_changed", 27),
            ("live_write_unknown", 28),
        ],
        "the block is contiguous from 10 and each name keeps its own number"
    );
}

/// Every [`Outcome`] the driver can report.
///
/// Listed rather than derived, and kept honest by
/// [`every_code_the_swap_can_exit_with_is_named_in_the_cli_table`]: a variant
/// added with a fresh exit code and forgotten here — or forgotten in
/// [`swap_exit::ALL`] — fails that test.
fn all_outcomes() -> Vec<Outcome> {
    vec![
        Outcome::Applied,
        Outcome::AlreadyActive,
        Outcome::Unknown,
        Outcome::Failed,
        Outcome::Cancelled,
        Outcome::NeedsRefresh,
        Outcome::Discarded,
        Outcome::Busy,
        Outcome::Refused(Refusal::CompromisedHold),
        Outcome::Refused(Refusal::EnvToken),
        Outcome::Refused(Refusal::LineTooLong),
        Outcome::Refused(Refusal::CannotAdopt(adopt::Refusal::NewerCopy)),
        Outcome::Refused(Refusal::NotOwned),
        Outcome::Refused(Refusal::LiveNamespaceEnv),
        Outcome::Refused(Refusal::LiveUnreachable),
        Outcome::Refused(Refusal::LiveItemAbsent),
        Outcome::Refused(Refusal::AuditRefused),
        Outcome::Refused(Refusal::LiveSwapOutstanding),
        Outcome::Refused(Refusal::LiveUndoOfUndo),
        Outcome::Refused(Refusal::LiveUndoItemChanged(ItemChange::ForeignLogin)),
        Outcome::Refused(Refusal::LiveWriteUnknown),
    ]
}

#[test]
fn every_code_the_swap_can_exit_with_is_named_in_the_cli_table() {
    use crate::cli::swap_exit;

    // Totality in the direction the count could not reach. A code the driver
    // emits that the table does not name is a code nothing documents and
    // nothing enumerates — and the table is what `--json`'s consumers are
    // told to switch on.
    let emitted: Vec<i32> = all_outcomes()
        .iter()
        .map(Outcome::exit_code)
        .filter(|code| *code != crate::error::EXIT_OK)
        .collect();
    for code in &emitted {
        assert!(
            swap_exit::ALL.iter().any(|(_, listed)| listed == code),
            "exit code {code} is reachable but is not named in `swap_exit::ALL`"
        );
    }
    // And the other way: nothing sits in the table that the driver cannot
    // produce — with no exemption any more. W4a carved `REFUSED_E` out of this
    // loop because the code existed only to keep the block contiguous; W4b
    // emits it, so every name in the table is reachable and the totality is
    // total in both directions.
    for (name, code) in swap_exit::ALL {
        assert!(
            emitted.contains(&code),
            "`{name}` ({code}) is in the table but no outcome or refusal emits it"
        );
    }
}

#[test]
fn refusal_e_is_emitted_by_exactly_one_refusal_and_keeps_its_reserved_code() {
    use crate::cli::swap_exit;

    // The W4a form of this test asserted the **opposite** — that nothing could
    // produce code 13, because refusal E lived only inside `WriteTarget::live`
    // and that lane never constructed it. W4b constructs it, so the claim
    // inverts: exactly one refusal carries the reserved code, and it is the one
    // that carries the letter.
    assert_eq!(swap_exit::REFUSED_E, 13, "the number it was reserved as");
    let carriers: Vec<Refusal> =
        DECISION_ORDER.iter().copied().filter(|r| r.exit_code() == swap_exit::REFUSED_E).collect();
    assert_eq!(carriers, vec![Refusal::LiveNamespaceEnv], "one refusal, and only one, exits 13");
    assert_eq!(Refusal::LiveNamespaceEnv.letter(), Some("E"));
}

#[test]
fn the_lettered_refusals_are_lettered_and_the_precondition_is_not() {
    assert_eq!(Refusal::CompromisedHold.letter(), Some("A"));
    assert_eq!(Refusal::EnvToken.letter(), Some("C"));
    assert_eq!(Refusal::LineTooLong.letter(), Some("D"));
    assert_eq!(Refusal::CannotAdopt(adopt::Refusal::Migrated).letter(), Some("F"));
    assert_eq!(
        Refusal::NotOwned.letter(),
        None,
        "the OQ1 precondition is decided before Phase A and carries `reason: not_owned` instead"
    );
}

#[test]
fn the_outcome_words_are_distinct_and_only_the_two_successes_exit_zero() {
    let outcomes = all_outcomes();
    for outcome in &outcomes {
        let zero = outcome.exit_code() == crate::error::EXIT_OK;
        let success = matches!(outcome, Outcome::Applied | Outcome::AlreadyActive);
        assert_eq!(zero, success, "{outcome:?} exits {} ", outcome.exit_code());
        assert!(!outcome.word().is_empty());
    }
    // `unknown` is not `failed`: it has its own code so a script can tell
    // "re-run status" from "nothing was written" (ruling OQ6).
    assert_ne!(Outcome::Unknown.exit_code(), Outcome::Discarded.exit_code());
    assert_ne!(Outcome::Unknown.exit_code(), Outcome::Failed.exit_code());
    // And `cancelled` is not refusal **F**: nobody agreeing to a swap is not
    // the same fact as a store whose credential cannot be adopted, and the
    // two call for opposite responses (finding N-6).
    assert_eq!(Outcome::Cancelled.word(), "cancelled");
    assert_ne!(
        Outcome::Cancelled.exit_code(),
        Refusal::CannotAdopt(adopt::Refusal::Unreadable).exit_code(),
        "a declined confirmation must be distinguishable from refusal F"
    );
    assert!(
        !DECISION_ORDER.iter().any(|r| r.exit_code() == Outcome::Cancelled.exit_code()),
        "and no lettered refusal may reuse its code"
    );
}

#[test]
fn a_failed_write_is_an_outcome_of_its_own_and_never_a_refusal_letter() {
    // A refusal letter is a security signal: **A** means somebody moved a
    // lock agctl was holding. An ordinary `security(1)` refusal is not
    // that, and while the two shared a code the exit status contradicted the
    // audit line the same pass had written (`"outcome":"failed"`).
    assert_eq!(Outcome::Failed.word(), "failed");
    assert_eq!(Outcome::Failed.exit_code(), swap_exit::WRITE_FAILED);
    assert_ne!(
        Outcome::Failed.exit_code(),
        Refusal::CompromisedHold.exit_code(),
        "a write that failed must be distinguishable from a compromised hold"
    );
    assert!(
        !DECISION_ORDER.iter().any(|r| r.exit_code() == swap_exit::WRITE_FAILED),
        "and no lettered refusal may reuse its code"
    );
}

// ---------------------------------------------------------------------------
// The identity guard (W3 re-review N1, ruling OQ2(d))
// ---------------------------------------------------------------------------

fn record(account: &str, org: &str) -> AccountRecord {
    AccountRecord {
        account_uuid: account.to_owned(),
        organization_uuid: org.to_owned(),
        email: None,
        org_name: None,
        kind: AccountKind::Owned {
            export_spelling: "/tmp/ns".to_owned(),
            export_sha8: "00000000".to_owned(),
        },
        label: None,
        forgotten: false,
        created_at: String::new(),
    }
}

/// A credential whose `tokenAccount` names `account`/`org`, or none at all.
fn credential(identity: Option<(&str, Option<&str>)>) -> Credentials {
    let token_account = identity.map(|(uuid, org)| {
        serde_json::json!({
            "uuid": uuid,
            "organizationUuid": org,
            "emailAddress": "someone@example.com",
        })
    });
    let mut blob = serde_json::json!({
        "claudeAiOauth": {
            "accessToken": "sk-ant-test-access",
            "refreshToken": "sk-ant-test-refresh",
            "expiresAt": 4_000_000_000_000i64,
        }
    });
    if let Some(account) = token_account {
        blob["claudeAiOauth"]["tokenAccount"] = account;
    }
    Credentials::parse_blob(blob.to_string().as_bytes()).expect("the fixture blob parses")
}

#[test]
fn an_absent_token_account_is_not_evidence_of_a_different_identity() {
    // Fact F4: older blobs carry no `tokenAccount`. Refusing them would break
    // every account that has not logged in since the field appeared, and
    // silence is not disagreement.
    let older = credential(None);
    assert!(same_identity(&older, &record("acct-1", "org-1")));
    assert!(same_identity(&older, &record("acct-2", "org-2")));
}

#[test]
fn a_present_identity_must_agree_on_the_account_uuid() {
    let owner = record("acct-1", "org-1");
    assert!(same_identity(&credential(Some(("acct-1", Some("org-1")))), &owner));
    assert!(
        !same_identity(&credential(Some(("acct-2", Some("org-1")))), &owner),
        "a different account uuid is an occupant, whatever the organization says"
    );
}

#[test]
fn the_organization_is_compared_only_when_both_sides_name_one() {
    let owner = record("acct-1", "org-1");
    assert!(
        same_identity(&credential(Some(("acct-1", None))), &owner),
        "a blob that omits the organization is missing information, not contradicting the record"
    );
    assert!(
        !same_identity(&credential(Some(("acct-1", Some("org-2")))), &owner),
        "two named organizations that disagree is a disagreement"
    );

    let unknown_org = record("acct-1", crate::config::paths::UNKNOWN_ORG);
    assert!(
        same_identity(&credential(Some(("acct-1", Some("org-9")))), &unknown_org),
        "a record still carrying the D-008 placeholder never learned an organization to compare"
    );
}

#[test]
fn the_occupant_is_named_without_any_token_material() {
    let named = credential(Some(("acct-2", Some("org-2"))));
    let occupant = occupant_of(&named);
    assert_eq!(occupant, "someone@example.com", "an email address when the blob named one");

    let anonymous = credential(None);
    assert_eq!(occupant_of(&anonymous), "an unidentified credential");

    for occupant in [occupant_of(&named), occupant_of(&anonymous)] {
        assert!(!occupant.contains("sk-ant-"), "the occupant string is never token material");
    }
}

#[test]
fn an_account_uuid_stands_in_when_the_blob_named_no_email() {
    let blob = serde_json::json!({
        "claudeAiOauth": {
            "accessToken": "sk-ant-test-access",
            "refreshToken": "sk-ant-test-refresh",
            "expiresAt": 4_000_000_000_000i64,
            "tokenAccount": { "uuid": "acct-7" },
        }
    });
    let credentials =
        Credentials::parse_blob(blob.to_string().as_bytes()).expect("the fixture blob parses");
    assert_eq!(occupant_of(&credentials), "acct-7");
}

// ---------------------------------------------------------------------------
// `busy_note` — one wording, two callers
// ---------------------------------------------------------------------------

#[test]
fn busy_note_names_the_stopped_pids_and_the_remedy_in_the_same_breath() {
    let note = busy_note(false, &[41207]);
    assert!(note.contains("pid 41207"), "the pid is named: {note}");
    assert!(
        note.contains("cannot tell whether that process is the holder"),
        "and the disclaimer is what makes naming it honest: {note}"
    );
    assert!(note.contains("doctor --remove-stale"), "the remedy is named: {note}");
}

#[test]
fn busy_note_distinguishes_a_live_holder_from_a_lock_it_would_not_break() {
    let alive = busy_note(true, &[]);
    let not_broken = busy_note(false, &[]);
    assert_ne!(alive, not_broken);
    assert!(alive.contains("another process is refreshing"));
    assert!(not_broken.contains("did not break it"));
    for note in [&alive, &not_broken] {
        assert!(!note.contains("pid"), "no pid is invented when none was stopped: {note}");
    }
}

#[test]
fn busy_note_lists_every_stopped_pid() {
    let note = busy_note(false, &[41207, 41208]);
    assert!(note.contains("41207, 41208"), "{note}");
}

// ---------------------------------------------------------------------------
// W4b's four refusals (the live store)
// ---------------------------------------------------------------------------

#[test]
fn the_live_refusals_carry_the_letter_code_and_phase_w4b_fixed_for_each() {
    // The contract's §D9 table, asserted rather than described. Each of the
    // three numbers is load-bearing for a different reason: the **letter** is
    // what `--json` consumers switch on and AC67 wants one message per letter;
    // the **code** is what a script sees; and the **phase** is the safety
    // claim — a refusal decided a phase later than this says has taken
    // something it did not need in order to find out.
    let rows = [
        (Refusal::LiveNamespaceEnv, Some("E"), None, swap_exit::REFUSED_E, Phase::A),
        (
            Refusal::LiveUnreachable,
            None,
            Some("live_unreachable"),
            swap_exit::LIVE_UNREACHABLE,
            Phase::A,
        ),
        (
            Refusal::LiveItemAbsent,
            None,
            Some("live_item_absent"),
            swap_exit::LIVE_ITEM_ABSENT,
            Phase::A,
        ),
        (Refusal::AuditRefused, None, Some("audit_refused"), swap_exit::AUDIT_REFUSED, Phase::B),
        // S23b (decision D-027): all three are decided in Phase A, and the
        // item-changed refusal carries one of two reasons under one code.
        (
            Refusal::LiveSwapOutstanding,
            None,
            Some("live_swap_outstanding"),
            swap_exit::LIVE_SWAP_OUTSTANDING,
            Phase::A,
        ),
        (
            Refusal::LiveUndoOfUndo,
            None,
            Some("live_undo_of_undo"),
            swap_exit::LIVE_UNDO_OF_UNDO,
            Phase::A,
        ),
        (
            Refusal::LiveUndoItemChanged(ItemChange::ForeignLogin),
            None,
            Some("live_undo_foreign_login"),
            swap_exit::LIVE_UNDO_ITEM_CHANGED,
            Phase::A,
        ),
        (
            Refusal::LiveUndoItemChanged(ItemChange::Diverged),
            None,
            Some("live_undo_item_diverged"),
            swap_exit::LIVE_UNDO_ITEM_CHANGED,
            Phase::A,
        ),
        (
            Refusal::LiveWriteUnknown,
            None,
            Some("live_write_unknown"),
            swap_exit::LIVE_WRITE_UNKNOWN,
            Phase::A,
        ),
    ];
    for (refusal, letter, reason, code, phase) in rows {
        assert_eq!(refusal.letter(), letter, "{refusal:?}'s `--json` letter");
        assert_eq!(refusal.reason(), reason, "{refusal:?}'s `--json` reason");
        assert_eq!(refusal.exit_code(), code, "{refusal:?}'s exit code");
        assert_eq!(refusal.decided_in(), phase, "{refusal:?} is decided in phase {}", phase.name());
        assert!(
            DECISION_ORDER
                .iter()
                .any(|listed| std::mem::discriminant(listed) == std::mem::discriminant(&refusal)),
            "{refusal:?} is missing from DECISION_ORDER"
        );
    }
}

#[test]
fn every_refusal_carries_a_letter_or_a_reason_and_never_both() {
    // `Refusal::reason` is the exact complement of `Refusal::letter`, which is
    // what lets `emit` branch on the pair instead of listing the unlettered
    // ones by name — and what stops a refusal added later from reaching
    // `--json` with neither member set, which would leave a consumer unable to
    // tell *which* refusal it was looking at. Both directions are asserted,
    // because the interesting failure is a new variant that answers `None` to
    // both.
    for refusal in DECISION_ORDER {
        match (refusal.letter(), refusal.reason()) {
            (Some(_), None) | (None, Some(_)) => {}
            (letter, reason) => panic!(
                "{refusal:?} carries letter {letter:?} and reason {reason:?}: exactly one of \
                 the two is required"
            ),
        }
    }
}

#[test]
fn the_live_refusals_are_decided_before_the_locks_and_in_the_contracts_order() {
    // A narrower restatement of the file's load-bearing property, aimed at the
    // four W4b refusals specifically: every one of them is outside the hold.
    // `LiveNamespaceEnv` is the one worth naming — `LockAnchor::open`'s
    // `Tree::Live` arm refuses the very same environment, so deciding it there
    // instead of at the `WriteTarget::live` call would still compile, still
    // refuse, and still pass a test that only looked at the outcome.
    for refusal in [
        Refusal::LiveNamespaceEnv,
        Refusal::LiveUnreachable,
        Refusal::LiveItemAbsent,
        Refusal::AuditRefused,
        Refusal::LiveSwapOutstanding,
        Refusal::LiveUndoOfUndo,
        Refusal::LiveUndoItemChanged(ItemChange::ForeignLogin),
        Refusal::LiveUndoItemChanged(ItemChange::Diverged),
        Refusal::LiveWriteUnknown,
    ] {
        assert!(!refusal.decided_in().holds_locks(), "{refusal:?} must not need a hold");
    }
    // And their positions in the table, which is the order the driver is
    // checked against. `NotOwned` is listed **before** `LiveNamespaceEnv`
    // (r4v ruling 7 item 5): they are both Phase A preconditions but sit on
    // different branches of the scope gate's partition, so they never compete
    // and this is the documented order rather than a precedence claim.
    let at = |refusal: Refusal| {
        DECISION_ORDER
            .iter()
            .position(|listed| *listed == refusal)
            .unwrap_or_else(|| panic!("{refusal:?} is missing from DECISION_ORDER"))
    };
    assert!(at(Refusal::NotOwned) < at(Refusal::LiveNamespaceEnv));
    assert!(at(Refusal::LiveNamespaceEnv) < at(Refusal::LiveUnreachable));
    assert!(at(Refusal::LiveUnreachable) < at(Refusal::EnvToken));
    assert!(at(Refusal::EnvToken) < at(Refusal::LiveItemAbsent));
    // Decision D-027. The undo-of-undo refusal is decided from the entry alone,
    // before a reversal's subject is built; the guard and the item-changed
    // refusal both need the item, so both follow `LiveItemAbsent`.
    assert!(at(Refusal::NotOwned) < at(Refusal::LiveUndoOfUndo));
    assert!(at(Refusal::LiveUndoOfUndo) < at(Refusal::LiveNamespaceEnv));
    assert!(at(Refusal::LiveItemAbsent) < at(Refusal::LiveSwapOutstanding));
    assert!(at(Refusal::LiveSwapOutstanding) < at(Refusal::LiveWriteUnknown));
    assert!(at(Refusal::LiveWriteUnknown) < at(Refusal::LineTooLong));
    assert!(
        at(Refusal::LiveSwapOutstanding)
            < at(Refusal::LiveUndoItemChanged(ItemChange::ForeignLogin))
    );
    assert!(at(Refusal::LiveUndoItemChanged(ItemChange::ForeignLogin)) < at(Refusal::LineTooLong));
    assert!(at(Refusal::LiveItemAbsent) < at(Refusal::LineTooLong));
    assert!(at(Refusal::LineTooLong) < at(Refusal::AuditRefused));
    assert!(at(Refusal::AuditRefused) < at(Refusal::CannotAdopt(adopt::Refusal::NewerCopy)));
    assert!(at(Refusal::CannotAdopt(adopt::Refusal::NewerCopy)) < at(Refusal::CompromisedHold));
    assert_eq!(DECISION_ORDER.len(), 13, "every refusal the driver can raise is in the table");
}
