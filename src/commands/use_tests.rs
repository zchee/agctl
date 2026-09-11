//! Tests for the `use` dispatch: the S22 refusals and the id requirement.
//! The successful launch path is exercised at the `export` unit-test and
//! e2e layers, which is where a controllable `PATH` lives — `run` resolves
//! `claude` through the *process's own* `PATH`, which a unit test cannot
//! safely override (`std::env::set_var` is `unsafe` in this edition and
//! would race every other test in the binary).
//!
//! `--forget` is not exercised here for the same reason `run_forget` is not:
//! it calls [`crate::config::paths::Paths::resolve`] with no override, which
//! in this in-process unit-test binary would resolve to whatever
//! `AGCTL_CONFIG_DIR`/XDG names on the machine actually running the
//! tests — never a directory a test controls. `isolate::forget_session`
//! itself is exercised directly, with a `Paths::with_config_dir` fixture, in
//! `isolate_tests.rs`; the dispatch wiring is exercised end-to-end, with the
//! `Fixture` harness's `--config-dir` isolation, in
//! `tests/e2e_isolate.rs`'s `ac79_*` tests.

use super::*;
use crate::runtime::coordinator::Cancel;

fn args(id: Option<&str>) -> UseArgs {
    UseArgs {
        id: id.map(str::to_owned),
        live: false,
        new_only: false,
        undo: false,
        forget: None,
        claude_config_dir: None,
        fresh_context: false,
        no_mcp: false,
        yes: false,
        json: false,
    }
}

#[test]
fn live_without_an_id_is_refused_before_any_directory_is_touched() {
    // The ordering matters and is asserted rather than assumed: `run_live`
    // checks the id *before* `Paths::resolve`, so a usage error cannot create
    // a config directory on the way to being reported — which in this
    // in-process test binary would be the developer's real one.
    let mut a = args(None);
    a.live = true;
    let err = run(None, &a, &Cancel::new()).expect_err("--live needs an id");
    assert!(matches!(err, AppError::Config(_)), "{err}");
    assert!(err.to_string().contains("id"), "{err}");
}

#[test]
fn requires_an_id_without_undo_or_forget() {
    let a = args(None);
    let err = run(None, &a, &Cancel::new())
        .expect_err("no id and neither --undo nor --forget is refused");
    assert!(matches!(err, AppError::Config(_)));
}

#[test]
fn accepts_new_only_as_an_inert_synonym() {
    // `--new-only` alone still requires an id (it changes nothing about the
    // id requirement); this proves the field is read rather than rejected by
    // some accidental exhaustiveness check, without needing a `claude` on
    // `PATH`.
    let mut a = args(None);
    a.new_only = true;
    let err = run(None, &a, &Cancel::new()).expect_err("an id is still required");
    assert!(matches!(err, AppError::Config(_)));
}

// ---------------------------------------------------------------------------
// The `--undo` selection rule
// ---------------------------------------------------------------------------

use crate::secret::audit::AuditEntry;
use crate::secret::audit::AuditEvent;
use crate::secret::audit::IncomingIdentity;
use crate::secret::audit::Tail;
use crate::secret::audit::Target;
use crate::secret::audit::WriteDirection;
use crate::secret::audit::WriteOutcome;

fn write(sha8: &str, from: Option<&str>, outcome: WriteOutcome) -> AuditEntry {
    AuditEntry::new(AuditEvent::Write {
        target: Target::Namespace(sha8.to_owned()),
        from_digest8: from.map(str::to_owned),
        to_digest8: "cafebabe".to_owned(),
        outcome,
        direction: WriteDirection::Forward,
        incoming_identity: None,
    })
}

/// The account every hand-built live forward entry installed.
fn installed_t() -> IncomingIdentity {
    IncomingIdentity {
        account_uuid: "acct-t".to_owned(),
        organization_uuid: Some("org-t".to_owned()),
    }
}

#[test]
fn undo_picks_the_newest_applied_namespace_write() {
    let tail = Tail {
        entries: vec![
            write("11111111", Some("aaaaaaaa"), WriteOutcome::Applied),
            write("22222222", Some("bbbbbbbb"), WriteOutcome::Applied),
        ],
        unreadable: Vec::new(),
    };
    assert_eq!(
        select_undo(&tail),
        Undoable::Found {
            sha8: "22222222".to_owned(),
            from_digest8: Some("bbbbbbbb".to_owned()),
            to_digest8: "cafebabe".to_owned(),
        },
        "the walk is backwards: the newest applied write is the one to reverse"
    );
}

#[test]
fn undo_accepts_an_unknown_outcome_because_the_write_may_have_landed() {
    let tail = Tail {
        entries: vec![write("33333333", Some("cccccccc"), WriteOutcome::Unknown)],
        unreadable: Vec::new(),
    };
    assert!(matches!(select_undo(&tail), Undoable::Found { .. }));
}

#[test]
fn undo_skips_the_outcomes_that_wrote_nothing() {
    for outcome in [WriteOutcome::Discarded, WriteOutcome::Failed] {
        let tail = Tail {
            entries: vec![write("44444444", Some("dddddddd"), outcome)],
            unreadable: Vec::new(),
        };
        assert_eq!(
            select_undo(&tail),
            Undoable::Nothing,
            "{outcome:?} wrote nothing, so there is nothing of its to undo"
        );
    }
}

#[test]
fn undo_selects_a_first_write_because_the_adopted_copy_is_what_it_displaced() {
    // A first write used to be skipped here, on the reading that a null
    // `from_digest8` means "displaced nothing". That is true of the *item*
    // and false of the store: the credential came out of the plaintext
    // `.credentials.json`, the adoption parked it in the adopted copy, and
    // since finding N-2 the swap removes that file once the write applies —
    // so the copy is the credential's only home and a reversal is exactly
    // what returns it. Skipping the entry left the user's own credential
    // parked with no supported way to get it back.
    let tail = Tail {
        entries: vec![write("55555555", None, WriteOutcome::Applied)],
        unreadable: Vec::new(),
    };
    assert_eq!(
        select_undo(&tail),
        Undoable::Found {
            sha8: "55555555".to_owned(),
            from_digest8: None,
            to_digest8: "cafebabe".to_owned(),
        },
        "a null `from_digest8` records a first write, which is reversible through the copy"
    );
}

#[test]
fn undo_refuses_rather_than_skipping_an_unreadable_line() {
    // The case the refusal exists for: a crash part-way through an append
    // truncates the *last* line, which is exactly the entry `--undo` wants.
    // Skipping it would reverse the swap before the one the user meant,
    // putting a credential back into an item a later swap has since changed.
    let tail = Tail {
        entries: vec![write("66666666", Some("eeeeeeee"), WriteOutcome::Applied)],
        unreadable: vec![(7, "unexpected end of input".to_owned())],
    };
    assert_eq!(select_undo(&tail), Undoable::Unreadable(7));
}

#[test]
fn undo_refuses_on_an_unreadable_line_even_with_no_candidate_at_all() {
    let tail = Tail { entries: Vec::new(), unreadable: vec![(2, "trailing garbage".to_owned())] };
    assert_eq!(
        select_undo(&tail),
        Undoable::Unreadable(2),
        "an unreadable line means the log is not a complete account of what happened"
    );
}

#[test]
fn undo_says_nothing_to_do_on_an_empty_log() {
    assert_eq!(select_undo(&Tail::default()), Undoable::Nothing);
}

fn live_write(from: &str) -> AuditEntry {
    AuditEntry::new(AuditEvent::Write {
        target: Target::Live,
        from_digest8: Some(from.to_owned()),
        to_digest8: "cafebabe".to_owned(),
        outcome: WriteOutcome::Applied,
        direction: WriteDirection::Forward,
        incoming_identity: Some(installed_t()),
    })
}

/// The [`Undoable::Live`] [`live_write`] produces.
fn live_undoable(from: &str) -> Undoable {
    Undoable::Live {
        from_digest8: Some(from.to_owned()),
        to_digest8: "cafebabe".to_owned(),
        outcome: WriteOutcome::Applied,
        direction: WriteDirection::Forward,
        incoming_identity: Some(installed_t()),
        later_unknown_undo: None,
    }
}

#[test]
fn undo_reports_a_live_target_rather_than_reaching_past_it() {
    // The newest reversible swap is the one `--undo` means, whatever it
    // targeted. Stepping over a live-store swap to reverse an older
    // namespaced one would undo a swap the user did not ask about — so a live
    // target is named, and carries the digests the reversal matches the
    // displaced credential against, rather than being skipped.
    let tail = Tail { entries: vec![live_write("ffffffff")], unreadable: Vec::new() };
    assert_eq!(select_undo(&tail), live_undoable("ffffffff"));
}

#[test]
fn undo_reaches_past_a_live_entry_that_was_not_itself_reversible() {
    // An entry that wrote nothing is not a swap to reverse in any direction,
    // so it does not shadow the namespaced one behind it.
    let discarded = AuditEntry::new(AuditEvent::Write {
        target: Target::Live,
        from_digest8: Some("ffffffff".to_owned()),
        to_digest8: "cafebabe".to_owned(),
        outcome: WriteOutcome::Discarded,
        direction: WriteDirection::Forward,
        incoming_identity: Some(installed_t()),
    });
    let tail = Tail {
        entries: vec![write("77777777", Some("11112222"), WriteOutcome::Applied), discarded],
        unreadable: Vec::new(),
    };
    assert_eq!(
        select_undo(&tail),
        Undoable::Found {
            sha8: "77777777".to_owned(),
            from_digest8: Some("11112222".to_owned()),
            to_digest8: "cafebabe".to_owned(),
        }
    );
}

#[test]
fn undo_picks_the_newest_even_when_an_older_namespaced_swap_exists() {
    let tail = Tail {
        entries: vec![
            write("88888888", Some("33334444"), WriteOutcome::Applied),
            live_write("aaaabbbb"),
        ],
        unreadable: Vec::new(),
    };
    assert_eq!(select_undo(&tail), live_undoable("aaaabbbb"), "the live swap is the newer one");
}

// ---------------------------------------------------------------------------
// The namespace-lock order (ruling OQ11)
// ---------------------------------------------------------------------------

/// A registry record keyed by the pair `lock_order` sorts on.
fn keyed(acct: &str, org: &str) -> AccountRecord {
    AccountRecord {
        account_uuid: acct.to_owned(),
        organization_uuid: org.to_owned(),
        email: None,
        org_name: None,
        label: None,
        kind: AccountKind::Owned { export_spelling: String::new(), export_sha8: String::new() },
        forgotten: false,
        created_at: "2026-09-10T00:00:00Z".to_owned(),
    }
}

#[test]
fn lock_order_sorts_ascending_and_collapses_equal_keys() {
    // Ruling OQ11's whole argument is the *order*, not the set: two swaps of
    // overlapping namespaces that took each other's locks in opposite orders
    // would deadlock, and sorting is what makes one global order out of any
    // number of them. The property had no test at any level — reversing the
    // sort left the entire suite green — so it is a table here, over an input
    // that is unsorted and carries a duplicate.
    let records = [
        keyed("cccccccc", "1111"),
        keyed("aaaaaaaa", "2222"),
        keyed("cccccccc", "1111"),
        keyed("aaaaaaaa", "1111"),
        keyed("bbbbbbbb", "9999"),
    ];
    let refs: Vec<&AccountRecord> = records.iter().collect();

    assert_eq!(
        lock_order(&refs),
        vec![
            ("aaaaaaaa".to_owned(), "1111".to_owned()),
            ("aaaaaaaa".to_owned(), "2222".to_owned()),
            ("bbbbbbbb".to_owned(), "9999".to_owned()),
            ("cccccccc".to_owned(), "1111".to_owned()),
        ],
        "ascending on the whole key, and each key once"
    );
}

#[test]
fn lock_order_is_the_same_whichever_way_round_the_swap_is() {
    // The deadlock the order prevents needs two passes with the *same* pair
    // in different orders — a forward swap and its reversal being the pair
    // this command actually produces. `locked` is built as
    // `[incoming, store]`, so the two directions hand this function the same
    // two records the other way round, and the output must not notice.
    let p = keyed("11111111", "aaaa");
    let t = keyed("99999999", "bbbb");

    let forward = lock_order(&[&t, &p]);
    let reverse = lock_order(&[&p, &t]);
    assert_eq!(forward, reverse, "a swap and its undo take the locks in one order");
    assert_eq!(
        forward,
        vec![
            ("11111111".to_owned(), "aaaa".to_owned()),
            ("99999999".to_owned(), "bbbb".to_owned())
        ],
        "and that order is ascending"
    );
}

#[test]
fn lock_order_of_a_store_into_itself_takes_one_lock() {
    let one = keyed("11111111", "aaaa");
    assert_eq!(lock_order(&[&one, &one]).len(), 1, "equal keys collapse to a single acquire");
}

// ---------------------------------------------------------------------------
// The third namespace's compare-and-swap (finding N-4)
// ---------------------------------------------------------------------------

/// A credential blob with an identity, an expiry and a chosen access token.
fn cas_blob(access: &str, expires_at_ms: i64) -> String {
    serde_json::json!({
        "claudeAiOauth": {
            "accessToken": access,
            "refreshToken": "sk-ant-ort01-cas",
            "expiresAt": expires_at_ms,
            "scopes": ["user:inference"],
            "subscriptionType": "max",
        }
    })
    .to_string()
}

fn cas_credentials(access: &str, expires_at_ms: i64) -> Credentials {
    Credentials::parse_blob(cas_blob(access, expires_at_ms).as_bytes())
        .expect("the fixture blob parses")
}

#[test]
fn the_cas_refuses_a_replacement_that_kept_the_same_expiry() {
    // The finding, exactly: the compare-and-swap used to compare
    // `adopt::Existing`, whose `Different` variant carries only
    // `expires_at_ms`. Two *different* credentials sharing an `expiresAt`
    // therefore compared equal, and the third account's store was overwritten
    // with a credential that had never been weighed against it — the case
    // `Refusal::Changed`'s own documentation says must refuse.
    let expiry = 1_800_000_000_000;
    let prior = cas_credentials("sk-ant-oat01-first", expiry).digests();
    let now = cas_credentials("sk-ant-oat01-second", expiry);
    assert_eq!(
        now.expires_at_ms, expiry,
        "the two differ only in the token, which is what makes this the finding's case"
    );

    assert_eq!(
        unchanged(Resolved::Credentials(Box::new(now)), Some(&prior)),
        Err(adopt::Refusal::Changed),
        "a different credential is a change even when its expiry is identical"
    );
}

#[test]
fn the_cas_accepts_the_credential_the_decision_was_taken_from() {
    let expiry = 1_800_000_000_000;
    let prior = cas_credentials("sk-ant-oat01-first", expiry).digests();
    let same = cas_credentials("sk-ant-oat01-first", expiry);
    assert_eq!(unchanged(Resolved::Credentials(Box::new(same)), Some(&prior)), Ok(()));
}

#[test]
fn the_cas_answers_each_way_a_target_can_have_moved() {
    let prior = cas_credentials("sk-ant-oat01-first", 1_800_000_000_000).digests();
    let arrived = cas_credentials("sk-ant-oat01-arrived", 1_900_000_000_000);

    /// One row: what the decision read, what is there now, and the answer.
    type Case<'a> = (&'a str, Resolved, Option<&'a Digests>, Result<(), adopt::Refusal>);

    let cases: Vec<Case<'_>> = vec![
        ("absent then, absent now", Resolved::Absent, None, Ok(())),
        (
            "absent then, written since",
            Resolved::Credentials(Box::new(arrived)),
            None,
            Err(adopt::Refusal::Changed),
        ),
        (
            "present then, removed since",
            Resolved::Absent,
            Some(&prior),
            Err(adopt::Refusal::Changed),
        ),
        (
            "unreadable now",
            Resolved::Transient("the file could not be read".to_owned()),
            Some(&prior),
            Err(adopt::Refusal::Unreadable),
        ),
        ("keychain locked", Resolved::Locked, None, Err(adopt::Refusal::Unreadable)),
    ];
    for (name, read, prior, want) in cases {
        assert_eq!(unchanged(read, prior), want, "{name}");
    }
}

// ---------------------------------------------------------------------------
// The confirmation prompt (finding N-6)
// ---------------------------------------------------------------------------

/// A [`Prompt`] that answers whatever it was built with.
///
/// `Tty::confirm` refuses without a terminal on standard input, which no test
/// in this repository has, so the "answered no" arm is reachable only through
/// a seam like this one.
struct Answers(Result<bool, ()>);

impl Prompt for Answers {
    fn tell(&mut self, _message: &str) {}

    fn confirm(&mut self, _question: &str) -> Result<bool, AppError> {
        match self.0 {
            Ok(answer) => Ok(answer),
            Err(()) => Err(AppError::Refused { reason: "no terminal to ask at".to_owned() }),
        }
    }
}

fn confirm_with(answer: Result<bool, ()>) -> Option<Report> {
    confirm(
        &mut Answers(answer),
        Path::new("/tmp/store"),
        &keyed("99999999", "bbbb"),
        &Some("aaaaaaaa".to_owned()),
        "bbbbbbbb",
        "Claude Code-credentials-cafebabe",
        Direction::Forward,
    )
}

#[test]
fn a_declined_confirmation_is_cancelled_and_not_refusal_f() {
    // Refusal **F** is `CannotAdopt`: *the outgoing credential cannot be
    // adopted, so the swap would lose it* — a fact about the store that no
    // answer at the prompt can change. While declining shared that letter and
    // that exit code, a script could not tell an operator saying "no" from a
    // swap that would have destroyed a credential, and since `--json` stopped
    // implying `--yes` declining is the common path.
    let report = confirm_with(Ok(false)).expect("a declined prompt reports");
    assert_eq!(report.outcome, Outcome::Cancelled);
    assert_eq!(report.outcome.exit_code(), crate::cli::swap_exit::CANCELLED);
    assert_ne!(
        report.outcome.exit_code(),
        Refusal::CannotAdopt(adopt::Refusal::Unreadable).exit_code(),
        "and it is distinguishable from refusal F"
    );
    assert!(!matches!(report.outcome, Outcome::Refused(_)), "so `--json` carries no letter");
    assert_eq!(report.adopted_to, None, "nothing was adopted");
    assert_eq!(report.audit_id, None, "and nothing was written to record");
}

#[test]
fn a_prompt_with_nobody_to_ask_is_cancelled_too() {
    // The same class: nobody agreed. A piped `--json` inspection run reaches
    // this arm, and it must not be reported as a store that cannot be swapped.
    let report = confirm_with(Err(())).expect("an unaskable prompt reports");
    assert_eq!(report.outcome, Outcome::Cancelled);
    assert!(report.note.is_some_and(|note| note.contains("no terminal")), "and it says why");
}

#[test]
fn a_confirmed_prompt_reports_nothing_and_lets_the_swap_proceed() {
    assert!(confirm_with(Ok(true)).is_none(), "`None` is what carries on to the adoption");
}

// ---------------------------------------------------------------------------
// The write-back's guards (`agctl-r9w`, review4 N-15)
// ---------------------------------------------------------------------------

/// A store with one owned namespace, holding `access` as its credential.
///
/// The record is [`keyed`]'s, whose `Owned` kind is what makes
/// [`status::detect`] look at the namespace at all — a record of any other
/// kind short-circuits to [`ForeignActivity::None`] and would test nothing.
fn write_back_store(access: &str) -> (tempfile::TempDir, Paths, AccountRecord, PathBuf) {
    let dir = tempfile::TempDir::new().expect("a temporary directory");
    let paths = Paths::with_config_dir(dir.path().to_path_buf());
    paths.ensure_dirs().expect("the store directories are creatable");
    let mut record = keyed("acct-write-back", "org-write-back");
    // A real export `sha8`, because the migrated arm of the gate asks the
    // keychain about the service name this spells.
    record.kind = AccountKind::Owned {
        export_spelling: String::new(),
        export_sha8: WRITE_BACK_SHA8.to_owned(),
    };
    let ns_dir = paths.namespace_dir(&record.account_uuid, &record.organization_uuid);
    std::fs::create_dir_all(&ns_dir).expect("the namespace is creatable");
    std::fs::write(ns_dir.join(file_store::CREDENTIALS_FILE), cas_blob(access, 1_800_000_000_000))
        .expect("the credential fixture is writable");
    (dir, paths, record, ns_dir)
}

/// The export `sha8` [`write_back_store`]'s record carries.
const WRITE_BACK_SHA8: &str = "0123abcd";

/// The keychain item that namespace would have migrated into.
fn migrated_service() -> String {
    crate::secret::foreign_activity::service_name(WRITE_BACK_SHA8)
}

/// A scripted keychain, holding the migrated item when `migrated` is set.
///
/// The item's bytes are never parsed — [`crate::secret::foreign_activity`]
/// asks only whether the read answers — so an opaque marker is honest about
/// what the gate turns on.
fn write_back_reader(migrated: bool) -> crate::secret::fake_reader::FakeReader {
    let reader = crate::secret::fake_reader::FakeReader::unlocked();
    if !migrated {
        return reader;
    }
    let service = migrated_service();
    reader.with_entry(&service).with_item(&service, b"{}")
}

/// The context the guard's write runs under.
fn write_back_ctx() -> PassCtx {
    PassCtx::standalone(Cancel::new(), std::time::Instant::now() + Duration::from_secs(30))
}

/// Runs the guard with a refreshed pair derived from `derived_from`.
fn guard(
    paths: &Paths,
    record: &AccountRecord,
    ns_dir: &Path,
    derived_from: &Digests,
) -> Result<(), String> {
    guard_with(&write_back_reader(false), paths, record, ns_dir, derived_from)
}

/// [`guard`], against a keychain of the caller's choosing.
fn guard_with(
    reader: &dyn crate::secret::KeychainReader,
    paths: &Paths,
    record: &AccountRecord,
    ns_dir: &Path,
    derived_from: &Digests,
) -> Result<(), String> {
    let refreshed = cas_credentials("sk-ant-oat01-rotated", 1_900_000_000_000);
    guarded_write_back(paths, record, ns_dir, &refreshed, derived_from, reader, &write_back_ctx())
}

/// Plants a `.pending` + `.pending.meta` derived from the namespace's current
/// credential, in the shape `file_store::save_to_pending` writes.
///
/// The metadata names the digests of the file that is there, which is what
/// makes `resolve_pending` **replay** it rather than discard it as
/// `FileChanged`.
fn plant_pending(ns_dir: &Path, replacement: &str, expires_at_ms: i64) {
    let current = status::reread(ns_dir).expect("the namespace has a credential to derive from");
    let digests = current.digests();
    let meta = file_store::PendingMeta {
        derived_from_access_sha256: Some(digests.access_sha256.clone()),
        derived_from_refresh_sha256: digests.refresh_sha256.clone(),
        created_at: "2026-09-11T00:00:00Z".to_owned(),
        new_expires_at: expires_at_ms,
    };
    std::fs::write(
        ns_dir.join(file_store::PENDING_META),
        serde_json::to_string(&meta).expect("the metadata serializes"),
    )
    .expect("the pending metadata is writable");
    std::fs::write(ns_dir.join(file_store::PENDING_FILE), replacement)
        .expect("the pending file is writable");
}

fn stored(ns_dir: &Path) -> String {
    std::fs::read_to_string(ns_dir.join(file_store::CREDENTIALS_FILE)).expect("readable")
}

#[test]
fn the_write_back_writes_when_every_guard_passes() {
    let (_dir, paths, record, ns_dir) = write_back_store("sk-ant-oat01-before");
    let derived_from = cas_credentials("sk-ant-oat01-before", 1_800_000_000_000).digests();

    guard(&paths, &record, &ns_dir, &derived_from).expect("an undisturbed namespace is written");

    let saved = stored(&ns_dir);
    assert!(saved.contains("sk-ant-oat01-rotated"), "the refreshed pair landed: {saved}");
    assert!(
        paths.is_under_namespace_root(&ns_dir.join(file_store::CREDENTIALS_FILE)),
        "and the only path written is inside the namespace root"
    );
}

#[test]
fn the_write_back_refuses_a_credential_that_changed_under_the_lock() {
    // Review4 N-15 (a): the credential was read in Phase A, *before* the
    // locks, and the whole lock wait plus the refresh POST is the window. A
    // second writer in that window means the pair in hand was derived from a
    // credential that is no longer there, and writing it is a lost update
    // that kills the other writer's refresh token.
    let (_dir, paths, record, ns_dir) = write_back_store("sk-ant-oat01-before");
    let derived_from = cas_credentials("sk-ant-oat01-before", 1_800_000_000_000).digests();

    // Somebody else refreshed this namespace while the POST was in flight.
    std::fs::write(
        ns_dir.join(file_store::CREDENTIALS_FILE),
        cas_blob("sk-ant-oat01-somebody-else", 1_850_000_000_000),
    )
    .expect("the racing write lands");

    let refusal = guard(&paths, &record, &ns_dir, &derived_from).expect_err("refused");

    assert!(refusal.contains("changed while this swap was preparing"), "{refusal}");
    assert_eq!(
        stored(&ns_dir),
        cas_blob("sk-ant-oat01-somebody-else", 1_850_000_000_000),
        "the other writer's credential is still there, byte for byte: nothing was overwritten"
    );
    assert!(
        !ns_dir.join(file_store::PENDING_FILE).exists(),
        "and nothing was parked beside it either"
    );
}

#[test]
fn the_write_back_refuses_a_namespace_a_claude_session_holds() {
    // Review4 N-15 (b): the namespace lock excludes another agctl pass and
    // excludes nothing else. Claude Code writes this same file under its own
    // protocol, and its lock artefact is the only sign of it.
    let (_dir, paths, record, ns_dir) = write_back_store("sk-ant-oat01-before");
    let derived_from = cas_credentials("sk-ant-oat01-before", 1_800_000_000_000).digests();
    std::fs::create_dir(ns_dir.join(crate::secret::foreign_activity::REFRESH_LOCK))
        .expect("the artefact is plantable");

    let refusal = guard(&paths, &record, &ns_dir, &derived_from).expect_err("refused");

    assert!(refusal.contains("Claude Code session"), "{refusal}");
    assert!(refusal.contains(crate::secret::foreign_activity::REFRESH_LOCK), "{refusal}");
    assert_eq!(
        stored(&ns_dir),
        cas_blob("sk-ant-oat01-before", 1_800_000_000_000),
        "the session's file is untouched"
    );
}

#[test]
fn the_write_back_refuses_a_credential_that_is_gone() {
    let (_dir, paths, record, ns_dir) = write_back_store("sk-ant-oat01-before");
    let derived_from = cas_credentials("sk-ant-oat01-before", 1_800_000_000_000).digests();
    std::fs::remove_file(ns_dir.join(file_store::CREDENTIALS_FILE)).expect("removable");

    let refusal = guard(&paths, &record, &ns_dir, &derived_from).expect_err("refused");

    assert!(refusal.contains("is gone"), "{refusal}");
    assert!(
        !ns_dir.join(file_store::CREDENTIALS_FILE).exists(),
        "a namespace whose credential was removed does not get one back from a swap"
    );
}

/// A refresher that cannot be called, for the drift guard's `Shared`.
///
/// [`status::under_namespace_lock`] is driven with `may_refresh: false`, which
/// returns before the POST, so a refresher that panics is the assertion that
/// the comparison is over the *guards* and not over a network round trip.
struct NeverRefreshes;

impl crate::provider::claude::usage::TokenRefresher for NeverRefreshes {
    fn refresh(
        &self,
        _credentials: &Credentials,
        _cancel: &Cancel,
    ) -> Result<
        crate::provider::claude::oauth::TokenResponse,
        crate::provider::claude::usage::RefreshError,
    > {
        panic!("the drift guard compares guards, not refreshes")
    }
}

#[test]
fn the_write_back_refuses_a_namespace_that_has_migrated_into_the_keychain() {
    // Invariant I5': a plaintext credential written beside an item that
    // shadows it lands where nobody reads it. `status` refuses such a
    // namespace; before review F1 the write-back could not see the state at
    // all, because it passed an empty listing and an empty listing read as
    // "nothing has migrated" rather than "I did not look".
    let (_dir, paths, record, ns_dir) = write_back_store("sk-ant-oat01-before");
    let derived_from = cas_credentials("sk-ant-oat01-before", 1_800_000_000_000).digests();
    let reader = write_back_reader(true);

    let refusal =
        guard_with(&reader, &paths, &record, &ns_dir, &derived_from).expect_err("refused");

    assert!(refusal.contains("migrated into the keychain item"), "{refusal}");
    assert!(refusal.contains(&migrated_service()), "the refusal names the item: {refusal}");
    assert_eq!(
        reader.reads(),
        vec![migrated_service()],
        "one `find-generic-password`, for the one service name this namespace could have \
         migrated under"
    );
    assert_eq!(
        stored(&ns_dir),
        cas_blob("sk-ant-oat01-before", 1_800_000_000_000),
        "and the shadowed file is left exactly as it was"
    );
}

#[test]
fn a_replayed_pending_file_is_not_reported_as_another_writer() {
    // `resolve_pending` moves a pending file into place *inside* the guard,
    // so the file legitimately differs from what Phase A read — but there is
    // no second writer to blame, and blaming one would refuse a write-back
    // that must happen (the POST has already spent the old refresh token).
    // The baseline moves to the read that follows the replay.
    let (_dir, paths, record, ns_dir) = write_back_store("sk-ant-oat01-before");
    let derived_from = cas_credentials("sk-ant-oat01-before", 1_800_000_000_000).digests();
    plant_pending(
        &ns_dir,
        &cas_blob("sk-ant-oat01-replayed", 1_850_000_000_000),
        1_850_000_000_000,
    );

    guard(&paths, &record, &ns_dir, &derived_from).expect("a replay is not a refusal");

    let saved = stored(&ns_dir);
    assert!(
        saved.contains("sk-ant-oat01-rotated"),
        "the refreshed pair — the only one holding a live refresh token — is what is left: {saved}"
    );
    assert!(
        !ns_dir.join(file_store::PENDING_FILE).exists()
            && !ns_dir.join(file_store::PENDING_META).exists(),
        "and the pending pair was consumed rather than left behind"
    );
}

#[test]
fn a_replayed_pending_file_does_not_blame_a_writer_that_does_not_exist() {
    // The same state, asserted on the *sentence*: before this fix the compare
    // ran against Phase A's digests, necessarily failed, and told the
    // operator the store had changed under the swap.
    let (_dir, paths, record, ns_dir) = write_back_store("sk-ant-oat01-before");
    let derived_from = cas_credentials("sk-ant-oat01-before", 1_800_000_000_000).digests();
    plant_pending(
        &ns_dir,
        &cas_blob("sk-ant-oat01-replayed", 1_850_000_000_000),
        1_850_000_000_000,
    );

    let outcome = guard(&paths, &record, &ns_dir, &derived_from);

    assert!(
        !format!("{outcome:?}").contains("changed while this swap was preparing"),
        "a replay is this store healing itself, not a racing writer: {outcome:?}"
    );
}

#[test]
fn the_write_back_refuses_exactly_what_status_refuses_at_the_same_write_site() {
    // The drift guard the ruling asks for. `status::under_namespace_lock` and
    // `guarded_write_back` write the same file by the same writer, and they
    // cannot be one call: `status`'s acquires the namespace lock itself
    // (`flock`, which a second descriptor in this same process conflicts
    // with, so a nested call would wait out the deadline and report `busy`)
    // and performs its own refresh POST, both of which the swap has already
    // done by the time it reaches its write-back. So the two orderings are
    // written twice and compared here, state by state.
    //
    // Each side gets its **own store, built from the same recipe**, rather
    // than literally one directory: `resolve_pending` mutates, so whichever
    // side ran first would heal the pending plant for the second and the
    // comparison would be over two different states.
    //
    // `may_refresh: false` is `status`'s "resolve the pending file and tell
    // me what is there" mode: it takes the lock, detects, resolves, re-reads,
    // and returns — which is guards 1, 2, 3 and 5 and no network. Guard 4,
    // the compare, has no counterpart reachable that way (`status`'s is a
    // `FileSnapshot` identity check across its own POST, behind the
    // `before_rename` fault seam), and is pinned by
    // `the_write_back_refuses_a_credential_that_changed_under_the_lock`.
    //
    // `status` is given a **real listing** for the migrated plant, as a real
    // pass would have; the swap is given none, which is the asymmetry review
    // F1 is about and `detect_unlisted` closes.
    struct Plant {
        name: &'static str,
        setup: fn(&Path),
        migrated: bool,
        proceeds: bool,
    }
    let plants = [
        Plant { name: "an undisturbed namespace", setup: |_| {}, migrated: false, proceeds: true },
        Plant {
            name: "a live Claude Code session",
            setup: |ns_dir| {
                std::fs::create_dir(ns_dir.join(crate::secret::foreign_activity::REFRESH_LOCK))
                    .expect("plantable");
            },
            migrated: false,
            proceeds: false,
        },
        Plant {
            name: "a credential that is gone",
            setup: |ns_dir| {
                std::fs::remove_file(ns_dir.join(file_store::CREDENTIALS_FILE)).expect("removable");
            },
            migrated: false,
            proceeds: false,
        },
        Plant {
            name: "a namespace that has migrated into the keychain",
            setup: |_| {},
            migrated: true,
            proceeds: false,
        },
        Plant {
            name: "a pending write left by an interrupted run",
            setup: |ns_dir| {
                plant_pending(
                    ns_dir,
                    &cas_blob("sk-ant-oat01-replayed", 1_850_000_000_000),
                    1_850_000_000_000,
                );
            },
            migrated: false,
            proceeds: true,
        },
    ];

    let mut proceeded = 0usize;
    let mut refused = 0usize;
    for plant in plants {
        let derived_from = cas_credentials("sk-ant-oat01-before", 1_800_000_000_000).digests();

        // `status`'s side, on its own copy of the state.
        let (_dir, paths, record, ns_dir) = write_back_store("sk-ant-oat01-before");
        (plant.setup)(&ns_dir);
        let listing = if plant.migrated {
            vec![crate::secret::ServiceEntry {
                service: migrated_service(),
                account: None,
                cdat: None,
                mdat: None,
            }]
        } else {
            Vec::new()
        };
        let migrated = plant.migrated;
        let shared = status::Shared {
            paths: std::sync::Arc::new(paths.clone()),
            env: crate::provider::claude::namespace::EnvView::with_home(
                paths.config_dir().to_path_buf(),
            ),
            client: crate::provider::claude::usage::UsageClient::new(
                "http://127.0.0.1:1",
                "agctl/test",
                Duration::from_secs(1),
            ),
            refresher: std::sync::Arc::new(NeverRefreshes),
            reader_factory: std::sync::Arc::new(move |_ctx| Box::new(write_back_reader(migrated))),
            listing,
            fault: Fault::none(),
            options: status::Options { refresh: false, no_cache: false },
        };
        let by_status =
            status::under_namespace_lock(&write_back_ctx(), &shared, &record, &ns_dir, false)
                .credentials;

        // The swap's side, on an identically built one.
        let (_dir, paths, record, ns_dir) = write_back_store("sk-ant-oat01-before");
        (plant.setup)(&ns_dir);
        let by_swap =
            guard_with(&write_back_reader(plant.migrated), &paths, &record, &ns_dir, &derived_from);

        assert_eq!(
            by_status.is_some(),
            by_swap.is_ok(),
            "{}: `status` {} and the swap {}",
            plant.name,
            if by_status.is_some() { "proceeded" } else { "refused" },
            if by_swap.is_ok() { "wrote" } else { "refused" }
        );
        assert_eq!(by_swap.is_ok(), plant.proceeds, "{}: {by_swap:?}", plant.name);
        if plant.migrated {
            let refusal = by_swap.as_ref().expect_err("refused");
            assert!(
                refusal.contains("migrated into the keychain item"),
                "{}: the refusal names the state it found: {refusal}",
                plant.name
            );
        }
        if by_swap.is_ok() {
            proceeded = proceeded.saturating_add(1);
        } else {
            refused = refused.saturating_add(1);
        }
    }
    assert_eq!(proceeded, 2, "two states both sides write");
    assert_eq!(refused, 3, "and three both sides refuse");
}

// ---------------------------------------------------------------------------
// W4b: the live store's subject (plan AC82) and the scope gate's partition
// ---------------------------------------------------------------------------

/// A store tree and an `EnvView` whose live store is inside it.
///
/// The live store is created as a real directory here rather than planted as a
/// link: what these tests are about is the **derivation** of the pair, and the
/// link shape is what `tests/e2e_swap.rs` and `claude_lock_tests.rs` exercise.
fn live_env() -> (tempfile::TempDir, Paths, EnvView) {
    let dir = tempfile::TempDir::new().expect("a temporary directory");
    let paths = Paths::with_config_dir(dir.path().join("config"));
    paths.ensure_dirs().expect("the agctl store should be creatable");
    let home = dir.path().join("home");
    std::fs::create_dir_all(home.join(".claude")).expect("the live store should be creatable");
    let env = EnvView::with_home(home);
    (dir, paths, env)
}

#[test]
fn ac82_the_live_store_directory_and_its_service_come_from_one_env_view() {
    // Plan AC82 asks for "a test in which the two would otherwise disagree",
    // and the last assertion is what makes this one that rather than a
    // tautology: a **second** `EnvView`, read from the process, names a
    // different directory entirely. A build that derived the store directory
    // from one reading of the environment and the service name from another
    // would pass every other assertion here.
    let (_dir, paths, env) = live_env();

    let subject =
        build_subject(&paths, &env, Which::Live, None, "").expect("the live store resolves");
    assert_eq!(subject.tree, Tree::Live, "the live store is locked as the live tree");
    assert_eq!(subject.audit, Target::Live, "and the audit log names it `live`");

    // The lock subject is built from the write target's own value, which is
    // the whole of AC82: one derivation, consumed twice.
    let lock = LockSubject { store_dir: subject.store_dir(), tree: subject.tree };
    assert_eq!(lock.store_dir, env.home.join(".claude"));
    assert_eq!(
        subject.service(),
        crate::provider::claude::namespace::LIVE_SERVICE,
        "an unset CLAUDE_SECURESTORAGE_CONFIG_DIR and an unset CLAUDE_CONFIG_DIR name the \
         unsuffixed live item"
    );

    // The row that makes the test load-bearing.
    let second = EnvView::from_process();
    assert_ne!(
        namespace::live_store_dir(&second),
        lock.store_dir.to_path_buf(),
        "a second EnvView WOULD name a different store, so deriving the two halves from two \
         readings is a reachable mistake rather than a hypothetical one"
    );
}

#[test]
fn ac82_a_config_dir_moves_the_store_and_the_service_together() {
    // The second row: `CLAUDE_CONFIG_DIR` is both the store and the hash
    // input, so the suffixed service and the moved directory have to arrive
    // together. They are allowed to differ **as strings** — the lock resolves
    // its store and the service name never does (invariant I13) — and are
    // required to name **one directory**, which is the last assertion.
    let (dir, paths, base) = live_env();
    let elsewhere = dir.path().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).expect("the config dir should be creatable");
    let spelling = elsewhere.to_string_lossy().into_owned();
    let env = EnvView { config_dir: Some(spelling.clone()), ..base };

    let subject =
        build_subject(&paths, &env, Which::Live, None, "").expect("the live store resolves");
    assert_eq!(subject.store_dir(), elsewhere, "the store moved with the variable");
    assert_eq!(
        subject.service(),
        format!("{}-{}", namespace::LIVE_SERVICE, namespace::sha8(&spelling)),
        "and so did the service, hashed from the same characters"
    );
    assert_eq!(
        namespace::canonical(subject.store_dir()).expect("the store resolves"),
        namespace::canonical(&elsewhere).expect("the store resolves"),
        "the lock's resolved store and the service's spelling name one directory"
    );
}

#[test]
fn the_scope_gate_partitions_the_two_targets_in_both_directions() {
    // Ruling G1's proof that refusal **E** is unreachable on the forward path,
    // and it is a proof rather than a gap: the gate and the live subject build
    // ask the **same function** — `namespace::securestorage_namespace` — of the
    // **same** `EnvView`, so "the variable is truthy" and "the live arm was
    // taken" cannot both hold.
    //
    // Both directions are asserted, because each is half of the partition: a
    // truthy value must never reach the live subject build, and a falsy one
    // must never be treated as naming a namespace.
    let (dir, paths, base) = live_env();

    for value in ["/tmp/some-namespace", dir.path().to_string_lossy().as_ref()] {
        let env = EnvView { securestorage_dir: Some(value.to_owned()), ..base.clone() };
        assert_eq!(
            namespace::securestorage_namespace(&env),
            Some(value),
            "a truthy value selects the namespace arm, so the live subject is never built"
        );
        // And if it somehow were, it refuses **E** rather than naming the live
        // item: the backstop, asserted as a backstop.
        let report = *build_subject(&paths, &env, Which::Live, None, value)
            .expect_err("a shell pointed at a namespace has no live store to name");
        assert_eq!(report.outcome, Outcome::Refused(Refusal::LiveNamespaceEnv));
        assert_eq!(report.outcome.exit_code(), 13);
        let note = report.note.expect("refusal E says why");
        assert!(note.contains(namespace::SECURESTORAGE_ENV), "it names the variable: {note}");
        assert!(note.contains(value), "and its value: {note}");
    }

    for falsy in [None, Some(String::new())] {
        let env = EnvView { securestorage_dir: falsy.clone(), ..base.clone() };
        assert_eq!(
            namespace::securestorage_namespace(&env),
            None,
            "unset and empty are both falsy (fact F14), so both select the live arm"
        );
        let subject = build_subject(&paths, &env, Which::Live, None, "")
            .unwrap_or_else(|_| panic!("the live arm builds for {falsy:?}"));
        assert_eq!(subject.audit, Target::Live, "and `NotOwned` cannot fire on it");
        assert_eq!(subject.service(), namespace::LIVE_SERVICE);
    }
}

#[test]
fn a_live_store_that_does_not_resolve_is_unreachable_rather_than_refusal_a() {
    // Ruling G3, at its decision site. A dangling `~/.claude` is a
    // configuration fact, and reporting it as refusal **A** — *somebody moved
    // a lock agctl was holding* — spends a security signal on it and sends
    // the user looking for an attacker. Decided in Phase A, before anything is
    // locked, so it is also not the acquire's error to map.
    let dir = tempfile::TempDir::new().expect("a temporary directory");
    let paths = Paths::with_config_dir(dir.path().join("config"));
    paths.ensure_dirs().expect("the agctl store should be creatable");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).expect("the home should be creatable");
    // A link to nothing, which is what a store whose target was removed looks
    // like — and which `canonicalize` refuses rather than following.
    std::os::unix::fs::symlink(home.join("gone"), home.join(".claude"))
        .expect("the dangling link should be plantable");
    let env = EnvView::with_home(home.clone());

    let report = *build_subject(&paths, &env, Which::Live, None, "")
        .expect_err("a dangling live store cannot be locked");
    assert_eq!(report.outcome, Outcome::Refused(Refusal::LiveUnreachable));
    assert_eq!(report.outcome.exit_code(), 23, "its own code, not refusal A's 10");
    let note = report.note.expect("it says why");
    assert!(
        note.contains(&home.join(".claude").display().to_string()),
        "the message names the spelling the environment gave: {note}"
    );
    assert!(note.contains("could not be resolved"), "and the failure: {note}");
    assert!(!note.contains("compromised"), "and never the compromised-hold sentence: {note}");
}

#[test]
fn undo_refuses_an_unreadable_line_after_a_live_entry_too() {
    // The unreadable-line refusal is about *which* entry is newest, so it must
    // not depend on what that entry targets. A live entry followed by a
    // truncated line is exactly the crash-mid-append shape, and reversing the
    // live swap before the one the user meant would put a credential back into
    // the user's own live item.
    let tail = Tail {
        entries: vec![live_write("ffffffff")],
        unreadable: vec![(3, "unexpected end of input".to_owned())],
    };
    assert_eq!(select_undo(&tail), Undoable::Unreadable(3));
}

// ---------------------------------------------------------------------------
// W4b: where a live `--undo` finds the credential to put back
// ---------------------------------------------------------------------------

/// A store with P's and T's owned namespaces, both empty.
fn reversal_store() -> (tempfile::TempDir, Paths, AgctlConfig) {
    let dir = tempfile::TempDir::new().expect("a temporary directory");
    let paths = Paths::with_config_dir(dir.path().to_path_buf());
    paths.ensure_dirs().expect("the store directories are creatable");
    let config = AgctlConfig {
        accounts: vec![keyed("acct-p", "org-p"), keyed("acct-t", "org-t")],
        ..AgctlConfig::default()
    };
    (dir, paths, config)
}

/// A credential of `acct`/`org` whose access token is `access`.
fn owned_by(access: &str, acct: &str, org: &str) -> String {
    serde_json::json!({
        "claudeAiOauth": {
            "accessToken": access,
            "refreshToken": "sk-ant-ort01-reversal",
            "expiresAt": 1_800_000_000_000_i64,
            "scopes": ["user:inference"],
            "subscriptionType": "max",
            "tokenAccount": { "uuid": acct, "organizationUuid": org },
        }
    })
    .to_string()
}

/// Writes `blob` as `name` in the namespace `acct`/`org`, at the modes agctl's
/// own writer leaves.
fn park(paths: &Paths, (acct, org): (&str, &str), name: &str, blob: &str) {
    use std::os::unix::fs::PermissionsExt;

    let ns_dir = paths.namespace_dir(acct, org);
    std::fs::create_dir_all(&ns_dir).expect("the namespace is creatable");
    std::fs::set_permissions(&ns_dir, std::fs::Permissions::from_mode(0o700)).expect("0700");
    let path = ns_dir.join(name);
    std::fs::write(&path, blob).expect("the fixture is writable");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("0600");
}

/// The digest prefix an audit entry records for the credential `blob` holds.
fn recorded(blob: &str) -> String {
    let credentials = Credentials::parse_blob(blob.as_bytes()).expect("the fixture parses");
    audit::digest8(&credentials.digests().access_sha256).expect("a digest prefix")
}

/// [`live_reversal`] for a row that must resolve.
fn resolves(paths: &Paths, config: &AgctlConfig, from: &str) -> Reversal {
    match live_reversal(
        paths,
        config,
        Some(from),
        "cafebabe",
        WriteOutcome::Applied,
        Some(&installed_t()),
        None,
    ) {
        Ok(reversal) => reversal,
        Err(err) => panic!("the live reversal should resolve: {err}"),
    }
}

/// [`live_reversal`] for a row that must refuse, and what it said.
fn refuses(paths: &Paths, config: &AgctlConfig, from: Option<&str>) -> String {
    match live_reversal(
        paths,
        config,
        from,
        "cafebabe",
        WriteOutcome::Applied,
        Some(&installed_t()),
        None,
    ) {
        Ok(found) => {
            panic!("expected a refusal, got a reversal owned by `{}`", found.owner.account_uuid)
        }
        Err(err) => err.to_string(),
    }
}

const P: (&str, &str) = ("acct-p", "org-p");
const T: (&str, &str) = ("acct-t", "org-t");

#[test]
fn a_live_undo_puts_back_the_credential_its_own_accounts_store_holds() {
    // §D5's ordinary row: the forward pass filed P in
    // `namespace(P)/.credentials.json`. The entry names P only by digest, so
    // that is how it is found — and the owner, the source and the target class
    // all follow from where it was found.
    let (_dir, paths, config) = reversal_store();
    let p = owned_by("sk-ant-oat01-p", P.0, P.1);
    park(&paths, P, file_store::CREDENTIALS_FILE, &p);
    park(&paths, T, file_store::CREDENTIALS_FILE, &owned_by("sk-ant-oat01-t", T.0, T.1));

    let found = resolves(&paths, &config, &recorded(&p));
    assert_eq!(found.owner.account_uuid, P.0, "P's own record owns the reversal");
    assert!(matches!(found.source, Source::OwnStore), "read from P's own store");
    assert_eq!(found.which, Which::Live, "against the live target");
    assert!(found.store.is_none(), "which is not a registry row");
    assert!(found.inherited.is_empty(), "and has no recorded spelling to check");
}

#[test]
fn a_live_undo_reads_task_fours_kept_copy_from_the_incoming_namespace() {
    // §D5's re-cut of `agctl-r3h`, which is the contract's
    // `Source::AdoptedCopy(namespace(T))`: T's own store holds the copy the
    // forward swap installed, and the newer copy of T it displaced is parked
    // beside it — never beside the live store.
    let (_dir, paths, config) = reversal_store();
    let kept = owned_by("sk-ant-oat01-t-newer", T.0, T.1);
    park(&paths, T, file_store::CREDENTIALS_FILE, &owned_by("sk-ant-oat01-t", T.0, T.1));
    park(&paths, T, file_store::ADOPTED_FILE, &kept);

    let found = resolves(&paths, &config, &recorded(&kept));
    assert_eq!(found.owner.account_uuid, T.0, "T's own record owns the reversal");
    match &found.source {
        Source::AdoptedCopy(dir) => {
            assert_eq!(
                dir,
                &paths.namespace_dir(T.0, T.1),
                "the incoming namespace's adopted copy"
            );
        }
        Source::OwnStore => panic!("the kept copy is the adopted one, not T's store"),
    }
}

#[test]
fn a_live_third_party_is_the_one_owned_record_of_the_credentials_account_and_organisation() {
    // Review F1. One account in two organisations is a supported registry
    // shape, so the live target's third party is chosen by account **and**
    // organisation (`swap::same_identity`), among `Owned` records, and only when
    // it is the one match — never by account alone, which met the incoming
    // record listed first.
    let org1 = keyed("acct-a", "org-1");
    let org2 = keyed("acct-a", "org-2");
    let config =
        AgctlConfig { accounts: vec![org1.clone(), org2.clone()], ..AgctlConfig::default() };
    let displaced =
        Credentials::parse_blob(owned_by("sk-ant-oat01-org2", "acct-a", "org-2").as_bytes())
            .expect("the fixture parses");

    // `use --live acct-a/org-1` with org2's credential in the live item.
    match third_namespace(&config, None, &org1, displaced.identity().as_ref(), Which::Live) {
        Ok(Some(third)) => assert_eq!(third.organization_uuid, "org-2", "the credential's own org"),
        Ok(None) => panic!("org2's own record is a third party, not the no-record case"),
        Err(_) => panic!("one exact match is not two candidates"),
    }

    // An organisation-less credential of that account matches both records:
    // two candidates, which the swap refuses rather than picking the first.
    let orgless = serde_json::json!({
        "claudeAiOauth": {
            "accessToken": "sk-ant-oat01-orgless",
            "refreshToken": "sk-ant-ort01-orgless",
            "expiresAt": 1_800_000_000_000_i64,
            "scopes": ["user:inference"],
            "subscriptionType": "max",
            "tokenAccount": { "uuid": "acct-a" },
        }
    })
    .to_string();
    let orgless = Credentials::parse_blob(orgless.as_bytes()).expect("the fixture parses");
    let elsewhere = keyed("acct-b", "org-b");
    match third_namespace(&config, None, &elsewhere, orgless.identity().as_ref(), Which::Live) {
        Err(pair) => assert_eq!(
            (pair[0].organization_uuid.as_str(), pair[1].organization_uuid.as_str()),
            ("org-1", "org-2"),
            "both candidates come back, for the refusal to name"
        ),
        Ok(found) => panic!(
            "two candidates must refuse, got {:?}",
            found.map(|record| record.organization_uuid)
        ),
    }

    // The exact identity under a record agctl does not own is no third party:
    // that is the no-record case, which `decide_adoption` refuses.
    let mut read_only = org2;
    read_only.kind = AccountKind::ConfigDirReadOnly {
        dir: PathBuf::new(),
        service: "Claude Code-credentials-0badc0de".to_owned(),
        shares_live_dir: false,
    };
    let config = AgctlConfig { accounts: vec![org1.clone(), read_only], ..AgctlConfig::default() };
    assert!(
        matches!(
            third_namespace(&config, None, &org1, displaced.identity().as_ref(), Which::Live),
            Ok(None)
        ),
        "only an `Owned` record can receive the displaced credential"
    );
}

// ---------------------------------------------------------------------------
// Decision D-027: whose the live item's credential is, and the guard
// ---------------------------------------------------------------------------

/// An identity naming `acct`, and `org` when given.
fn named(acct: &str, org: Option<&str>) -> Identity {
    Identity {
        account_uuid: acct.to_owned(),
        organization_uuid: org.map(str::to_owned),
        email: None,
        org_name: None,
    }
}

/// An [`Attribution::Mismatch`] between two display ids.
fn mismatch(item: &str, witness: &str) -> Attribution {
    Attribution::Mismatch { item: item.to_owned(), witness: witness.to_owned() }
}

#[test]
fn d027_the_live_credentials_identity_follows_the_precedence_and_refuses_a_disagreement() {
    // The precedence, by row: the credential's own identity first, the
    // witness when it has none, a refusal when the two disagree. The witness
    // differs by direction and that is the rule's point — `.claude.json` for a
    // forward swap, the account the undone entry installed for a reversal.
    let p = named("acct-p", Some("org-p"));
    let t = named("acct-t", Some("org-t"));
    let t_orgless = named("acct-t", None);
    let rows: Vec<(&str, Option<Identity>, Witness<'_>, Attribution)> = vec![
        (
            "forward: the credential names P and `.claude.json` agrees",
            Some(p.clone()),
            Witness::LoginRecord(Some(p.clone())),
            Attribution::Known(Some(p.clone())),
        ),
        (
            "forward: the credential names P and `.claude.json` names nobody",
            Some(p.clone()),
            Witness::LoginRecord(None),
            Attribution::Known(Some(p.clone())),
        ),
        (
            "forward: Claude Code's identity-less credential, `.claude.json` naming P",
            None,
            Witness::LoginRecord(Some(p.clone())),
            Attribution::Known(Some(p.clone())),
        ),
        (
            "forward: nothing names anybody",
            None,
            Witness::LoginRecord(None),
            Attribution::Known(None),
        ),
        (
            "forward: the credential names P and `.claude.json` names T",
            Some(p.clone()),
            Witness::LoginRecord(Some(t.clone())),
            mismatch("acct-p/org-p", "acct-t/org-t"),
        ),
        (
            "forward: one account in two organisations disagrees",
            Some(named("acct-p", Some("org-1"))),
            Witness::LoginRecord(Some(named("acct-p", Some("org-2")))),
            mismatch("acct-p/org-1", "acct-p/org-2"),
        ),
        (
            "forward: an organisation named on one side only is no disagreement",
            Some(named("acct-p", None)),
            Witness::LoginRecord(Some(p.clone())),
            Attribution::Known(Some(named("acct-p", None))),
        ),
        (
            "reverse: Claude Code's refreshed credential, the entry installed T",
            None,
            Witness::UndoneSwap(Some(&t)),
            Attribution::Known(Some(t.clone())),
        ),
        (
            "reverse: the credential names T and the entry agrees",
            Some(t.clone()),
            Witness::UndoneSwap(Some(&t)),
            Attribution::Known(Some(t.clone())),
        ),
        (
            "reverse: the credential names P but the entry installed T",
            Some(p.clone()),
            Witness::UndoneSwap(Some(&t)),
            mismatch("acct-p/org-p", "acct-t/org-t"),
        ),
        (
            "reverse: no installed account to witness, the credential decides",
            Some(t.clone()),
            Witness::UndoneSwap(None),
            Attribution::Known(Some(t.clone())),
        ),
        (
            "reverse: nothing names anybody",
            None,
            Witness::UndoneSwap(None),
            Attribution::Known(None),
        ),
        (
            "reverse: an installed account with no organisation names only its account",
            None,
            Witness::UndoneSwap(Some(&t_orgless)),
            Attribution::Known(Some(named("acct-t", None))),
        ),
    ];
    for (row, item, witness, expected) in rows {
        assert_eq!(attribute(item, witness), expected, "{row}");
    }
}

/// A live-store write, stamped `second` seconds past a fixed instant so that
/// every entry in a row has an id of its own. Every one displaced `ffffffff`
/// and wrote `cafebabe`.
fn live_at(second: i64, direction: WriteDirection, outcome: WriteOutcome) -> AuditEntry {
    let mut entry = AuditEntry::new(AuditEvent::Write {
        target: Target::Live,
        from_digest8: Some("ffffffff".to_owned()),
        to_digest8: "cafebabe".to_owned(),
        outcome,
        direction,
        incoming_identity: (direction == WriteDirection::Forward).then(installed_t),
    });
    entry.ts = jiff::Timestamp::from_second(1_800_000_000 + second).expect("a valid instant");
    entry
}

#[test]
fn d027_a_live_swap_is_outstanding_until_an_applied_undo_reverses_it() {
    // Keyed on the newest live forward swap, read from `direction` rather than
    // inferred. The item's digest matters only to an `unknown` swap: an item
    // still holding what the swap displaced (`ffffffff`) says the write did not
    // land.
    const STILL_P: Option<&str> = Some("ffffffff");
    const NOT_P: Option<&str> = Some("cafebabe");
    let swap = live_at(1, WriteDirection::Forward, WriteOutcome::Applied);
    let undo = live_at(2, WriteDirection::Undo, WriteOutcome::Applied);
    let again = live_at(3, WriteDirection::Forward, WriteOutcome::Applied);
    let unknown = live_at(4, WriteDirection::Forward, WriteOutcome::Unknown);
    let namespaced = write("77777777", Some("11112222"), WriteOutcome::Applied);
    let id = |entry: &AuditEntry| Some(Outstanding::Swap(entry.id().to_string()));
    let rows = vec![
        ("an empty log", Vec::new(), NOT_P, None),
        ("one live swap, not undone", vec![swap.clone()], NOT_P, id(&swap)),
        ("a live swap and its applied undo", vec![swap.clone(), undo.clone()], NOT_P, None),
        (
            "a later live swap after that undo",
            vec![swap.clone(), undo.clone(), again.clone()],
            NOT_P,
            id(&again),
        ),
        (
            "a failed undo, and an unknown one whose item still holds what it displaced, \
             reversed nothing",
            vec![
                swap.clone(),
                live_at(5, WriteDirection::Undo, WriteOutcome::Failed),
                live_at(6, WriteDirection::Undo, WriteOutcome::Unknown),
            ],
            // The undo displaced `ffffffff`: an item still holding it says the
            // undo never landed, so the swap it was reversing stands.
            Some("ffffffff"),
            id(&swap),
        ),
        (
            "a discarded or a failed live swap changed nothing",
            vec![
                live_at(7, WriteDirection::Forward, WriteOutcome::Discarded),
                live_at(8, WriteDirection::Forward, WriteOutcome::Failed),
            ],
            NOT_P,
            None,
        ),
        (
            "an unknown swap whose item no longer holds what it displaced may have landed",
            vec![unknown.clone()],
            NOT_P,
            id(&unknown),
        ),
        (
            "an unknown swap whose item still holds what it displaced did not apply",
            vec![unknown],
            STILL_P,
            None,
        ),
        (
            "a namespaced swap after a live one does not clear it",
            vec![swap.clone(), namespaced.clone()],
            NOT_P,
            id(&swap),
        ),
        ("namespaced swaps alone do not arm it", vec![namespaced.clone(), namespaced], NOT_P, None),
    ];
    for (row, entries, item8, expected) in rows {
        let tail = Tail { entries, unreadable: Vec::new() };
        assert_eq!(outstanding_live_swap(&tail, item8), expected, "{row}");
    }

    // An unreadable line refuses whatever the parsed entries say.
    let tail = Tail { entries: vec![swap, undo], unreadable: vec![(1, "truncated".to_owned())] };
    assert_eq!(
        outstanding_live_swap(&tail, NOT_P),
        Some(Outstanding::Unreadable(1)),
        "an unreadable line never passes"
    );
}

#[test]
fn d027_a_live_undo_takes_the_installed_account_from_the_entry_and_refuses_without_it() {
    // Whose credential the live item holds comes from the entry's
    // `incoming_identity` and from nowhere else. An entry without one refuses
    // before any owned namespace is searched: a parked P that would resolve
    // does not change the answer.
    let (_dir, paths, config) = reversal_store();
    let p = owned_by("sk-ant-oat01-p", P.0, P.1);
    park(&paths, P, file_store::CREDENTIALS_FILE, &p);
    let from = recorded(&p);

    let refused = match live_reversal(
        &paths,
        &config,
        Some(&from),
        "cafebabe",
        WriteOutcome::Applied,
        None,
        None,
    ) {
        Ok(found) => panic!(
            "an entry naming no installed account must refuse, got `{}`",
            found.owner.account_uuid
        ),
        Err(err) => err.to_string(),
    };
    assert!(refused.contains("does not record which account it installed"), "{refused}");

    let installed = IncomingIdentity { account_uuid: T.0.to_owned(), organization_uuid: None };
    let found = match live_reversal(
        &paths,
        &config,
        Some(&from),
        "cafebabe",
        WriteOutcome::Unknown,
        Some(&installed),
        None,
    ) {
        Ok(found) => found,
        Err(err) => panic!("the live reversal should resolve: {err}"),
    };
    assert_eq!(found.owner.account_uuid, P.0, "P's parked copy is still found by its digest");
    let Some(undone) = found.undone else { panic!("a live reversal carries the swap it undoes") };
    assert_eq!(undone.installed, named(T.0, None), "the entry's account, by id alone");
    assert_eq!(
        undone.outcome,
        WriteOutcome::Unknown,
        "and the outcome the item is checked against"
    );
    assert_eq!(
        (undone.from_digest8.as_str(), undone.to_digest8.as_str()),
        (from.as_str(), "cafebabe"),
        "and both of its digests"
    );
}

/// The swap a live undo reverses, as [`item_changed`] sees it: it displaced
/// `ffffffff` and wrote `cafebabe`, installing `acct-t`/`org-t`.
fn undone_entry(outcome: WriteOutcome) -> UndoneEntry {
    UndoneEntry {
        installed: named("acct-t", Some("org-t")),
        outcome,
        from_digest8: "ffffffff".to_owned(),
        to_digest8: "cafebabe".to_owned(),
        later_unknown_undo: None,
    }
}

#[test]
fn d027_a_live_undo_refuses_an_item_that_changed_hands_or_diverged() {
    // `.claude.json` is a tripwire here and never a source: P (being put back)
    // and T (installed) pass, anybody else is a foreign login. The diverged
    // check applies to an `unknown` swap only; an `applied` one's digest change
    // is T's ordinary refresh.
    let owner = keyed("acct-p", "org-p");
    let p = named("acct-p", Some("org-p"));
    let t = named("acct-t", Some("org-t"));
    let q = named("acct-q", Some("org-q"));
    let p_elsewhere = named("acct-p", Some("org-x"));
    let rows = [
        (
            "applied, `.claude.json` still names P",
            WriteOutcome::Applied,
            Some("cafebabe"),
            Some(&p),
            None,
        ),
        (
            "applied, the session logged in as T",
            WriteOutcome::Applied,
            Some("cafebabe"),
            Some(&t),
            None,
        ),
        ("applied, `.claude.json` unreadable", WriteOutcome::Applied, Some("cafebabe"), None, None),
        (
            "applied, T refreshed in the item: exempt",
            WriteOutcome::Applied,
            Some("12345678"),
            Some(&p),
            None,
        ),
        (
            "applied, the session logged in as a third account",
            WriteOutcome::Applied,
            Some("12345678"),
            Some(&q),
            Some(Refusal::LiveUndoItemChanged(ItemChange::ForeignLogin)),
        ),
        (
            "P's account in another organisation is somebody else",
            WriteOutcome::Applied,
            Some("cafebabe"),
            Some(&p_elsewhere),
            Some(Refusal::LiveUndoItemChanged(ItemChange::ForeignLogin)),
        ),
        (
            "unknown, the item still holds P",
            WriteOutcome::Unknown,
            Some("ffffffff"),
            Some(&p),
            None,
        ),
        ("unknown, the item holds T", WriteOutcome::Unknown, Some("cafebabe"), Some(&p), None),
        (
            "unknown, the item holds neither end",
            WriteOutcome::Unknown,
            Some("12345678"),
            Some(&p),
            Some(Refusal::LiveUndoItemChanged(ItemChange::Diverged)),
        ),
        (
            "unknown and a foreign login: the login is what is named",
            WriteOutcome::Unknown,
            Some("12345678"),
            Some(&q),
            Some(Refusal::LiveUndoItemChanged(ItemChange::ForeignLogin)),
        ),
    ];
    for (row, outcome, item8, claimed, expected) in rows {
        assert_eq!(item_changed(&undone_entry(outcome), &owner, item8, claimed), expected, "{row}");
    }
}

#[test]
fn d027_a_live_forward_entry_records_the_incoming_account_without_the_placeholder_org() {
    // The registry's unknown-organization placeholder is not an organization:
    // recording it would make the undo's comparison report a disagreement that
    // is not there.
    assert_eq!(
        incoming_identity_of(&keyed("acct-t", "org-t")),
        IncomingIdentity {
            account_uuid: "acct-t".to_owned(),
            organization_uuid: Some("org-t".to_owned())
        }
    );
    assert_eq!(
        incoming_identity_of(&keyed("acct-t", UNKNOWN_ORG)),
        IncomingIdentity { account_uuid: "acct-t".to_owned(), organization_uuid: None },
        "the placeholder maps to no organization"
    );
}

#[test]
fn d027_an_unknown_live_write_is_read_against_the_item_or_refused_as_unknown() {
    // Ruling R16. The newest live entry's `unknown` outcome is settled by the
    // item: every `live_at` entry displaced `ffffffff` and wrote `cafebabe`. An
    // item holding neither end says nothing, and refuses as unknown (exit 28).
    let swap = live_at(1, WriteDirection::Forward, WriteOutcome::Applied);
    let unknown_undo = live_at(2, WriteDirection::Undo, WriteOutcome::Unknown);
    let unknown_swap = live_at(3, WriteDirection::Forward, WriteOutcome::Unknown);
    let as_swap = |entry: &AuditEntry| Some(Outstanding::Swap(entry.id().to_string()));
    let as_unknown = |entry: &AuditEntry| Some(Outstanding::Unknown(entry.id().to_string()));
    let rows = vec![
        (
            "an unknown swap whose item holds what it wrote landed",
            vec![unknown_swap.clone()],
            Some("cafebabe"),
            as_swap(&unknown_swap),
        ),
        (
            "an unknown swap whose item holds neither end",
            vec![unknown_swap.clone()],
            Some("12345678"),
            as_unknown(&unknown_swap),
        ),
        (
            "an unknown undo whose item holds what it wrote reversed the swap",
            vec![swap.clone(), unknown_undo.clone()],
            Some("cafebabe"),
            None,
        ),
        (
            "an unknown undo whose item still holds what it displaced left the swap standing",
            vec![swap.clone(), unknown_undo.clone()],
            Some("ffffffff"),
            as_swap(&swap),
        ),
        (
            "an unknown undo whose item holds neither end",
            vec![swap, unknown_undo.clone()],
            Some("12345678"),
            as_unknown(&unknown_undo),
        ),
    ];
    for (row, entries, item8, expected) in rows {
        let tail = Tail { entries, unreadable: Vec::new() };
        assert_eq!(outstanding_live_swap(&tail, item8), expected, "{row}");
    }
}

#[test]
fn d027_undo_reverses_an_outstanding_live_swap_before_anything_newer() {
    // Ruling R16. An in-place namespace refresh written after a live swap must
    // not become what `--undo` reverses, or the live swap becomes unreachable
    // while the guard refuses every forward swap. With no live swap outstanding,
    // W4a's newest-reversible rule stands, and a live undo it finds is refused
    // by `run_undo` rather than reversed.
    let swap = live_at(1, WriteDirection::Forward, WriteOutcome::Applied);
    let undo = live_at(2, WriteDirection::Undo, WriteOutcome::Applied);
    let unknown_undo = live_at(3, WriteDirection::Undo, WriteOutcome::Unknown);
    let refresh = write("77777777", Some("11112222"), WriteOutcome::Applied);
    let pick = |entries: Vec<AuditEntry>| select_undo(&Tail { entries, unreadable: Vec::new() });

    assert!(
        matches!(
            pick(vec![swap.clone(), refresh.clone()]),
            Undoable::Live { direction: WriteDirection::Forward, .. }
        ),
        "an outstanding live swap is reversed before a newer namespace refresh"
    );
    assert!(
        matches!(
            pick(vec![swap.clone(), undo.clone()]),
            Undoable::Live { direction: WriteDirection::Undo, .. }
        ),
        "nothing outstanding: the newest reversible entry is the live undo, for `run_undo` to refuse"
    );
    assert!(
        matches!(
            pick(vec![swap.clone(), undo, refresh.clone()]),
            Undoable::Found { ref sha8, .. } if sha8 == "77777777"
        ),
        "nothing outstanding: W4a's rule picks the newest reversible write"
    );
    // Ruling R17(3): an undo that ended `unknown` leaves the swap outstanding,
    // so it is reversed again — and its digests go with it, for the item to say
    // whether that undo landed after all.
    match pick(vec![swap, unknown_undo, refresh]) {
        Undoable::Live { direction: WriteDirection::Forward, later_unknown_undo, .. } => {
            assert_eq!(
                later_unknown_undo,
                Some(UnknownUndo {
                    from_digest8: Some("ffffffff".to_owned()),
                    to_digest8: "cafebabe".to_owned(),
                }),
                "the unknown undo's digests travel with the swap"
            );
        }
        other => panic!("the outstanding swap is reversed again, not {other:?}"),
    }
}

#[test]
fn d027_a_live_undo_after_an_unknown_undo_asks_the_item_whether_it_landed() {
    // Ruling R17(3), as `item_changed` decides it. The swap displaced
    // `ffffffff` and wrote `cafebabe`; a later undo that ended `unknown`
    // displaced `cafebabe` and wrote `ffffffff`. Holding what that undo wrote,
    // the item says it landed and the swap is already reversed; holding what it
    // displaced, it did not land; holding neither says nothing.
    let owner = keyed("acct-p", "org-p");
    let p = named("acct-p", Some("org-p"));
    let mut undone = undone_entry(WriteOutcome::Applied);
    undone.later_unknown_undo = Some(UnknownUndo {
        from_digest8: Some("cafebabe".to_owned()),
        to_digest8: "ffffffff".to_owned(),
    });
    let rows = [
        (
            "the item holds what the unknown undo wrote",
            Some("ffffffff"),
            Some(Refusal::LiveUndoOfUndo),
        ),
        ("the item holds what the unknown undo displaced", Some("cafebabe"), None),
        (
            "the item holds neither end",
            Some("12345678"),
            Some(Refusal::LiveUndoItemChanged(ItemChange::Diverged)),
        ),
    ];
    for (row, item8, expected) in rows {
        assert_eq!(item_changed(&undone, &owner, item8, Some(&p)), expected, "{row}");
    }
}

#[test]
fn a_live_undo_refuses_a_digest_that_matches_in_two_accounts_namespaces() {
    // The planted collision the "exactly one match" rule exists for, across two
    // namespaces. An old-format credential names no account (fact F4), so
    // `same_identity` lets it belong to either record: found in both P's and
    // T's store it is two candidates, and nothing in an 8-hex prefix says which
    // one the swap being undone parked.
    let (_dir, paths, config) = reversal_store();
    let old_format = cas_blob("sk-ant-oat01-old-format", 1_800_000_000_000);
    park(&paths, P, file_store::CREDENTIALS_FILE, &old_format);
    park(&paths, T, file_store::CREDENTIALS_FILE, &old_format);

    let said = refuses(&paths, &config, Some(&recorded(&old_format)));
    assert!(said.contains("in both"), "a cross-namespace match is ambiguous: {said}");
    assert!(
        said.contains(&paths.namespace_dir(P.0, P.1).display().to_string())
            && said.contains(&paths.namespace_dir(T.0, T.1).display().to_string()),
        "and both namespaces are named: {said}"
    );
}

#[test]
fn a_live_undo_refuses_to_guess_between_two_homes_of_one_credential() {
    // Exactly one match or refuse. Two copies carrying the digest the entry
    // names are two candidates for the live item, and nothing in the entry says
    // which one the swap being undone produced.
    let (_dir, paths, config) = reversal_store();
    let p = owned_by("sk-ant-oat01-p", P.0, P.1);
    park(&paths, P, file_store::CREDENTIALS_FILE, &p);
    park(&paths, P, file_store::ADOPTED_FILE, &p);

    let said = refuses(&paths, &config, Some(&recorded(&p)));
    assert!(said.contains("in both"), "it names the ambiguity: {said}");
    assert!(
        said.contains(file_store::CREDENTIALS_FILE) && said.contains(file_store::ADOPTED_FILE),
        "and both places: {said}"
    );
}

#[test]
fn a_live_undo_looks_only_in_the_credentials_own_accounts_namespace() {
    // A copy of P parked in **T's** namespace — the shape a namespace swap's
    // D-024 sibling can leave — is not where §D5 files a live swap's displaced
    // credential. Alone it is not found; beside P's own copy it is not a second
    // candidate, so it cannot turn a clean match into an ambiguity either.
    let (_dir, paths, config) = reversal_store();
    let p = owned_by("sk-ant-oat01-p", P.0, P.1);
    park(&paths, T, file_store::ADOPTED_FILE, &p);

    let said = refuses(&paths, &config, Some(&recorded(&p)));
    assert!(
        said.contains("nothing to put back"),
        "a copy in another namespace is no match: {said}"
    );

    park(&paths, P, file_store::CREDENTIALS_FILE, &p);
    let found = resolves(&paths, &config, &recorded(&p));
    assert_eq!(found.owner.account_uuid, P.0, "P's own copy is the one match");
    assert!(matches!(found.source, Source::OwnStore));
}

#[test]
fn a_live_undo_skips_namespaces_no_owned_record_claims_and_entries_with_no_digest() {
    // A read-only row whose namespace directory happens to hold the credential
    // is not a place agctl filed anything: only `Owned` records are searched.
    let (_dir, paths, mut config) = reversal_store();
    let mut read_only = keyed("acct-x", "org-x");
    read_only.kind = AccountKind::ConfigDirReadOnly {
        dir: PathBuf::new(),
        service: "Claude Code-credentials-0badc0de".to_owned(),
        shares_live_dir: false,
    };
    config.accounts.push(read_only);
    let x = owned_by("sk-ant-oat01-x", "acct-x", "org-x");
    park(&paths, ("acct-x", "org-x"), file_store::CREDENTIALS_FILE, &x);
    let said = refuses(&paths, &config, Some(&recorded(&x)));
    assert!(said.contains("nothing to put back"), "{said}");

    // A live entry recording no displaced digest can only be a hand-edited log:
    // an absent live item refuses before any write, so there is nothing to
    // match a candidate against.
    let said = refuses(&paths, &config, None);
    assert!(said.contains("recorded no displaced credential"), "{said}");
    assert!(said.contains("cafebabe"), "and it names what the entry did record: {said}");
}
