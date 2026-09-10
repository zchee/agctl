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
use crate::secret::audit::Tail;
use crate::secret::audit::Target;
use crate::secret::audit::WriteOutcome;

fn write(sha8: &str, from: Option<&str>, outcome: WriteOutcome) -> AuditEntry {
    AuditEntry::new(AuditEvent::Write {
        target: Target::Namespace(sha8.to_owned()),
        from_digest8: from.map(str::to_owned),
        to_digest8: "cafebabe".to_owned(),
        outcome,
    })
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
    })
}

#[test]
fn undo_reports_a_live_target_rather_than_reaching_past_it() {
    // The newest reversible swap is the one `--undo` means, whatever it
    // targeted. Stepping over a live-store swap to reverse an older
    // namespaced one would undo a swap the user did not ask about — so a live
    // target is named (and refused as S23's) rather than skipped.
    let tail = Tail { entries: vec![live_write("ffffffff")], unreadable: Vec::new() };
    assert_eq!(select_undo(&tail), Undoable::Live);
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
    assert_eq!(select_undo(&tail), Undoable::Live, "the live swap is the newer one");
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
