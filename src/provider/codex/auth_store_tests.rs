use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;

use jiff::Timestamp;
use serde_json::json;

use super::*;
use crate::config::codex::CodexAccountRecord;
use crate::provider::codex::lock;
use crate::provider::codex::lock::LockBudget;
use crate::provider::codex::proof;
use crate::provider::codex::testkit;
use crate::provider::codex::testkit::IdClaims;
use crate::secret::pending::PendingDiscardReason;

const OTHER_ACCT: &str = "99999999-2222-4333-8444-555555555555";

fn clean_report() -> PostExitReport {
    PostExitReport::from_child(Vec::new(), Vec::new(), false, Vec::new(), testkit::exit_status(0))
}

fn record() -> CodexAccountRecord {
    testkit::owned_record(testkit::USER, testkit::ACCT)
}

fn ns_dir(paths: &Paths) -> PathBuf {
    paths.codex_namespace_dir(testkit::USER, testkit::ACCT).expect("valid ids")
}

fn auth_path(paths: &Paths) -> PathBuf {
    ns_dir(paths).join(AUTH_FILE)
}

fn expired_doc_bytes() -> Vec<u8> {
    testkit::pretty(&testkit::chatgpt_doc(Some(1_000), Some("2026-09-06T21:40:50Z")))
}

fn scratch_with(bytes: &[u8]) -> tempfile::TempDir {
    let scratch = tempfile::tempdir().expect("tempdir");
    testkit::write_0600(&scratch.path().join(AUTH_FILE), bytes);
    scratch
}

fn verified(bytes: &[u8]) -> VerifiedLogin {
    let scratch = scratch_with(bytes);
    verify_login(scratch.path(), &clean_report()).expect("a clean login verifies")
}

fn locked_owned<'g>(ns: &OwnedNamespace<'g>) -> LockedCredentials<'g> {
    match ns.read().expect("reads") {
        NamespaceRead::Credentials(credentials) => *credentials,
        other => panic!("expected credentials, got {other:?}"),
    }
}

#[test]
fn read_live_outcomes() {
    // Plan AC94 and section 3.7 #1.
    let home = tempfile::tempdir().expect("tempdir");
    let path = home.path().join(AUTH_FILE);
    assert!(matches!(read_live(home.path()), CodexResolved::Absent));

    testkit::write_0600(&path, &testkit::fresh_auth_bytes());
    assert!(matches!(read_live(home.path()), CodexResolved::Credentials(_)));

    for torn in [&b""[..], &testkit::fresh_auth_bytes()[..40]] {
        fs::write(&path, torn).expect("write");
        assert!(
            matches!(read_live(home.path()), CodexResolved::Torn),
            "empty or cut off is torn, never absent"
        );
    }

    fs::write(&path, br#"{"tokens": "agctl-test-codex-at-oops"}"#).expect("write");
    let CodexResolved::Transient(reason) = read_live(home.path()) else {
        panic!("not a credential")
    };
    testkit::assert_no_needles(&reason, "transient reason");

    fs::remove_file(&path).expect("rm");
    let elsewhere = tempfile::tempdir().expect("tempdir");
    testkit::write_0600(&elsewhere.path().join("x.json"), &testkit::fresh_auth_bytes());
    std::os::unix::fs::symlink(elsewhere.path().join("x.json"), &path).expect("symlink");
    let CodexResolved::Transient(reason) = read_live(home.path()) else {
        panic!("a link is refused")
    };
    assert!(reason.contains("symbolic link"), "{reason}");

    fs::remove_file(&path).expect("rm");
    fs::create_dir(&path).expect("mkdir");
    assert!(matches!(read_live(home.path()), CodexResolved::Transient(_)), "a directory");
    fs::remove_dir(&path).expect("rmdir");

    fs::write(&path, vec![b' '; (MAX_CREDENTIALS_BYTES + 1) as usize]).expect("write");
    let CodexResolved::Transient(reason) = read_live(home.path()) else { panic!("oversized") };
    assert!(reason.contains("limit"), "{reason}");

    // Fact F60: the directory chain may be a link; only the file may not.
    fs::remove_file(&path).expect("rm");
    testkit::write_0600(&path, &testkit::fresh_auth_bytes());
    let linked_home = elsewhere.path().join("linked-home");
    std::os::unix::fs::symlink(home.path(), &linked_home).expect("symlink");
    assert!(matches!(read_live(&linked_home), CodexResolved::Credentials(_)));
}

#[test]
fn verify_login_accepts_a_clean_chatgpt_login() {
    let login = verified(&testkit::fresh_auth_bytes());
    assert_eq!(login.ids(), (testkit::USER, testkit::ACCT));
    let identity = login.identity();
    assert_eq!(identity.user_id, testkit::USER);
    assert_eq!(identity.account_id, testkit::ACCT);
    assert_eq!(identity.plan.as_deref(), Some("pro"));
    testkit::assert_no_needles(&format!("{login:?} {identity:?}"), "VerifiedLogin Debug");
}

#[test]
fn verify_login_refusals() {
    let unclean = PostExitReport::from_child(
        vec!["cli|0123456789abcdef".to_owned()],
        vec![PathBuf::from("/proc/1")],
        true,
        vec![PathBuf::from("x.lock")],
        testkit::exit_status(1),
    );
    let empty = tempfile::tempdir().expect("tempdir");
    let err = verify_login(empty.path(), &unclean).expect_err("an unclean child is refused");
    let LoginRefusal::ChildAnomalies(found) = &err else { panic!("{err:?}") };
    assert_eq!(found.len(), 5, "every anomaly is named: {found:?}");

    assert_eq!(verify_login(empty.path(), &clean_report()).err(), Some(LoginRefusal::NoCredential));

    let apikey = scratch_with(&testkit::fixture("auth-apikey.json"));
    assert_eq!(
        verify_login(apikey.path(), &clean_report()).err(),
        Some(LoginRefusal::NotChatGpt("apikey".to_owned()))
    );

    let torn = scratch_with(b"{\"auth_mode\": \"chat");
    assert!(matches!(verify_login(torn.path(), &clean_report()), Err(LoginRefusal::Unreadable(_))));

    let mut no_acct = testkit::chatgpt_doc(Some(4_102_444_800), None);
    no_acct["tokens"]["id_token"] =
        json!(testkit::id_token(&IdClaims { acct: None, ..IdClaims::default() }));
    if let Some(tokens) = no_acct["tokens"].as_object_mut() {
        tokens.remove("account_id");
    }
    let no_acct = scratch_with(&testkit::pretty(&no_acct));
    assert_eq!(verify_login(no_acct.path(), &clean_report()).err(), Some(LoginRefusal::NoIdentity));

    let mut dotted = testkit::chatgpt_doc(Some(4_102_444_800), None);
    dotted["tokens"]["account_id"] = json!(".locks");
    let dotted = scratch_with(&testkit::pretty(&dotted));
    assert!(matches!(
        verify_login(dotted.path(), &clean_report()),
        Err(LoginRefusal::InvalidId(_))
    ));
}

#[test]
fn a_guard_for_another_namespace_is_refused_by_both_handles() {
    // Plan AC119: the guard-path equality is a real `if`/`Err`, tested.
    let (_dir, paths) = testkit::store();
    let other = testkit::owned_record(testkit::USER, OTHER_ACCT);
    let other_guard = testkit::lock_for(&paths, &other);
    let this = record();
    let owned = proof::owned(&this).expect("owned");
    let err = OwnedNamespace::open(&paths, owned, &other_guard).err().expect("refused");
    assert!(err.to_string().contains("refusing to open that namespace"), "{err}");

    let login = verified(&testkit::fresh_auth_bytes());
    let err =
        InstallNamespace::open_for_install(&paths, login, &other_guard).err().expect("refused");
    assert!(err.to_string().contains("refusing to open that namespace"), "{err}");
    assert!(!ns_dir(&paths).exists(), "nothing was created for the refused namespace");
}

#[test]
fn the_namespace_is_derived_from_the_ids_never_from_export_spelling() {
    // Invariant I27: the record's export spelling points elsewhere; the handle
    // still opens `codex/<user>/<acct>`.
    let (dir, paths) = testkit::store();
    let this = record();
    let guard = testkit::lock_for(&paths, &this);
    let ns =
        OwnedNamespace::open(&paths, proof::owned(&this).expect("owned"), &guard).expect("opens");
    assert!(matches!(ns.read().expect("reads"), NamespaceRead::Absent));
    assert!(ns_dir(&paths).is_dir());
    assert!(!dir.path().join("somewhere").exists() && !Path::new("/somewhere/else").exists());
    assert_eq!(fs::metadata(ns_dir(&paths)).expect("stat").permissions().mode() & 0o777, 0o700);
}

#[test]
fn a_torn_owned_file_is_torn_and_nothing_is_written() {
    // Plan AC94: never `needs login`, no write.
    let (_dir, paths) = testkit::store();
    let this = record();
    let guard = testkit::lock_for(&paths, &this);
    let ns =
        OwnedNamespace::open(&paths, proof::owned(&this).expect("owned"), &guard).expect("opens");
    testkit::write_0600(&auth_path(&paths), b"{\"tokens\": {");
    let before = fs::metadata(auth_path(&paths)).expect("stat");
    assert!(matches!(ns.read().expect("reads"), NamespaceRead::Torn));
    assert_eq!(ns.snapshot_for_post().expect("snapshot"), None);
    let after = fs::metadata(auth_path(&paths)).expect("stat");
    assert_eq!(
        (before.ino(), before.mtime_nsec(), before.len()),
        (after.ino(), after.mtime_nsec(), after.len())
    );
}

#[test]
fn writer_one_replaces_atomically_after_the_snapshot_check() {
    let (_dir, paths) = testkit::store();
    let this = record();
    let guard = testkit::lock_for(&paths, &this);
    let ns =
        OwnedNamespace::open(&paths, proof::owned(&this).expect("owned"), &guard).expect("opens");
    testkit::write_0600(&auth_path(&paths), &expired_doc_bytes());
    let inode_before = fs::metadata(auth_path(&paths)).expect("stat").ino();

    let credentials = locked_owned(&ns);
    let response = crate::provider::codex::credentials::RefreshResponse::parse(
        br#"{"access_token":"agctl-test-codex-at-new.x.y","refresh_token":"agctl-test-codex-rt-0002"}"#,
    )
    .expect("parses");
    let prior = ns.snapshot_for_post().expect("snapshot").expect("present");
    assert_eq!(prior.refresh_digest8(), credentials.refresh_digest8());
    testkit::assert_no_needles(&format!("{prior:?}"), "PostSnapshot Debug");
    assert!(
        !format!("{prior:?}").contains(&sha256_hex_of_rt()),
        "a digest prefix, not the full digest"
    );
    let (merged, _) = credentials.merge_refresh(response, Timestamp::now()).expect("merges");

    let CodexWrite::Landed { outcome, receipt } =
        ns.write(&merged, &Fault::none()).expect("writes")
    else {
        panic!("expected a landed write")
    };
    assert!(matches!(outcome, WriteOutcome::Written { .. }));
    assert_eq!(receipt.kind(), WriteKind::RefreshApplied);
    assert_eq!(receipt.digest8_before(), prior.refresh_digest8().as_deref());
    assert_eq!(receipt.digest8_after(), merged.refresh_digest8().as_deref());
    assert_ne!(receipt.digest8_before(), receipt.digest8_after());
    assert_eq!(receipt.ids(), (testkit::USER, testkit::ACCT));

    let meta = fs::metadata(auth_path(&paths)).expect("stat");
    assert_ne!(meta.ino(), inode_before, "a rename, never an in-place write");
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    let mut expected = Vec::new();
    merged.credentials().write_json_to(&mut expected).expect("serializes");
    assert_eq!(fs::read(auth_path(&paths)).expect("read"), expected);
    let leftovers: Vec<_> =
        fs::read_dir(ns_dir(&paths)).expect("list").flatten().map(|e| e.file_name()).collect();
    assert_eq!(leftovers, [AUTH_FILE], "no tmp, no pending");
}

#[test]
fn writer_one_discards_when_another_writer_refreshed_first() {
    // Plan AC124: the file's grant changed after the read → discard, audit
    // `discarded_external`, file untouched.
    let (_dir, paths) = testkit::store();
    let this = record();
    let guard = testkit::lock_for(&paths, &this);
    let ns =
        OwnedNamespace::open(&paths, proof::owned(&this).expect("owned"), &guard).expect("opens");
    testkit::write_0600(&auth_path(&paths), &expired_doc_bytes());
    let credentials = locked_owned(&ns);

    let mut external = testkit::chatgpt_doc(Some(4_102_444_800), None);
    external["tokens"]["refresh_token"] = json!("agctl-test-codex-rt-external");
    let external = testkit::pretty(&external);
    fs::write(auth_path(&paths), &external).expect("an in-place external writer");

    let CodexWrite::ChangedSinceRead { receipt } =
        ns.write(&credentials, &Fault::none()).expect("checks")
    else {
        panic!("expected a discard")
    };
    assert_eq!(receipt.kind(), WriteKind::DiscardedExternal);
    assert_eq!(fs::read(auth_path(&paths)).expect("read"), external, "the newer grant stands");

    fs::write(auth_path(&paths), b"{").expect("torn");
    assert!(matches!(ns.write(&credentials, &Fault::none()).expect("checks"), CodexWrite::Torn));
}

#[test]
fn a_failed_rename_parks_the_grant_and_the_next_pass_replays_it() {
    // Plan AC113 (a) on the Codex writer: `codex_rename_fail` → pending with a
    // meta derived from the snapshot → writer 3 replays it, and the replayed
    // file's refresh digest is the merged one.
    let (_dir, paths) = testkit::store();
    let this = record();
    let guard = testkit::lock_for(&paths, &this);
    let ns =
        OwnedNamespace::open(&paths, proof::owned(&this).expect("owned"), &guard).expect("opens");
    testkit::write_0600(&auth_path(&paths), &expired_doc_bytes());
    let credentials = locked_owned(&ns);
    let response = crate::provider::codex::credentials::RefreshResponse::parse(
        br#"{"refresh_token":"agctl-test-codex-rt-0003"}"#,
    )
    .expect("parses");
    let (merged, _) = credentials.merge_refresh(response, Timestamp::now()).expect("merges");

    let fault = Fault::from_list("codex_rename_fail");
    let CodexWrite::Landed { outcome, receipt } = ns.write(&merged, &fault).expect("parks") else {
        panic!("expected a parked write")
    };
    assert!(matches!(outcome, WriteOutcome::SavedToPending { .. }));
    assert_eq!(receipt.kind(), WriteKind::RefreshSavedToPending);
    assert!(
        ns_dir(&paths).join(PENDING_FILE).is_file() && ns_dir(&paths).join(PENDING_META).is_file()
    );
    assert_eq!(
        fs::read(auth_path(&paths)).expect("read"),
        expired_doc_bytes(),
        "the old file is unchanged"
    );

    let (decision, receipt, _evidence) = ns.resolve_pending(&Cancel::new()).expect("resolves");
    assert_eq!(decision, PendingDecision::Replayed { first_write: false });
    let receipt = receipt.expect("a replay is a write");
    assert_eq!(receipt.kind(), WriteKind::PendingReplayed);
    assert_eq!(receipt.digest8_after(), merged.refresh_digest8().as_deref());
    let replayed = Credentials::parse(&fs::read(auth_path(&paths)).expect("read")).expect("parses");
    assert_eq!(
        replayed.refresh_digest8(),
        merged.refresh_digest8(),
        "the rotated token was not lost"
    );

    let (decision, receipt, _evidence) = ns.resolve_pending(&Cancel::new()).expect("resolves");
    assert_eq!((decision, receipt), (PendingDecision::NoPending, None));
}

#[test]
fn a_torn_target_keeps_the_pending_grant() {
    // Review F8: a present, unparseable `auth.json` is not absent for Codex.
    let (_dir, paths) = testkit::store();
    let this = record();
    let guard = testkit::lock_for(&paths, &this);
    let ns =
        OwnedNamespace::open(&paths, proof::owned(&this).expect("owned"), &guard).expect("opens");
    testkit::write_0600(&auth_path(&paths), &expired_doc_bytes());
    let credentials = locked_owned(&ns);
    let CodexWrite::Landed { .. } =
        ns.write(&credentials, &Fault::from_list("codex_rename_fail")).expect("parks")
    else {
        panic!("expected a parked write")
    };
    fs::write(auth_path(&paths), b"{\"auth_mode\":").expect("torn by an in-place writer");
    let err = ns.resolve_pending(&Cancel::new()).expect_err("an error, not a discard");
    assert!(err.to_string().contains("does not parse"), "{err}");
    assert!(ns_dir(&paths).join(PENDING_FILE).is_file(), "the pending grant is kept");
    assert!(ns_dir(&paths).join(PENDING_META).is_file());

    fs::write(auth_path(&paths), expired_doc_bytes()).expect("the writer finished");
    let (decision, _receipt, _evidence) = ns.resolve_pending(&Cancel::new()).expect("resolves");
    assert_eq!(decision, PendingDecision::Replayed { first_write: false });
}

#[test]
fn a_pending_grant_derived_from_another_file_is_discarded_with_a_receipt() {
    let (_dir, paths) = testkit::store();
    let this = record();
    let guard = testkit::lock_for(&paths, &this);
    let ns =
        OwnedNamespace::open(&paths, proof::owned(&this).expect("owned"), &guard).expect("opens");
    testkit::write_0600(&auth_path(&paths), &expired_doc_bytes());
    let credentials = locked_owned(&ns);
    let CodexWrite::Landed { .. } =
        ns.write(&credentials, &Fault::from_list("codex_rename_fail")).expect("parks")
    else {
        panic!("expected a parked write")
    };
    let mut changed = testkit::chatgpt_doc(Some(4_102_444_800), None);
    changed["tokens"]["refresh_token"] = json!("agctl-test-codex-rt-changed");
    fs::write(auth_path(&paths), testkit::pretty(&changed)).expect("write");
    let (decision, receipt, _evidence) = ns.resolve_pending(&Cancel::new()).expect("resolves");
    assert_eq!(decision, PendingDecision::Discarded(PendingDiscardReason::FileChanged));
    assert_eq!(receipt.map(|r| r.kind()), Some(WriteKind::PendingDiscarded));
}

#[test]
fn the_login_tail_installs_a_copy_and_resets_the_marker() {
    // Plan section 3.3 (L2′ tail) and AC105's install clauses, AC114's
    // "login lifts it", compile check #230: verify → identity → lock → open
    // (login by value) → install(self) → (receipt, identity).
    let (_dir, paths) = testkit::store();
    let bytes = testkit::fresh_auth_bytes();
    let scratch = scratch_with(&bytes);
    let login = verify_login(scratch.path(), &clean_report()).expect("verifies");
    let identity = login.identity();
    let guard = lock::acquire_codex_for_install(
        &paths,
        &login,
        LockBudget::Command(Duration::from_secs(2)),
        &Cancel::new(),
        &Fault::none(),
    )
    .expect("locks");

    // A marker in the terminal 401 state with a stale in-flight entry.
    let state = RefreshStateFile::new(&paths, testkit::USER, testkit::ACCT).expect("marker");
    let terminal = RefreshState {
        inflight: Some(Inflight { sent_digest8: "deadbeef".to_owned(), sent_at: Timestamp::now() }),
        did_not_help: 3,
        floor_min: 240,
        resent: true,
        class: Some(UnknownClass::Ambiguous),
        ..RefreshState::default()
    };
    state.store(&terminal).expect("seeds");

    let install = InstallNamespace::open_for_install(&paths, login, &guard).expect("opens");
    let (receipt, installed) = install.install(&Fault::none()).expect("installs");
    assert_eq!(installed, identity);
    assert_eq!(receipt.kind(), WriteKind::LoginInstall { overwrote: false });
    assert_eq!(receipt.digest8_before(), None);

    let meta = fs::metadata(auth_path(&paths)).expect("stat");
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    assert_ne!(
        meta.ino(),
        fs::metadata(scratch.path().join(AUTH_FILE)).expect("stat").ino(),
        "a copy, not a link"
    );
    assert_eq!(
        fs::read(auth_path(&paths)).expect("read"),
        bytes,
        "byte-identical to the child's document"
    );
    assert_eq!(
        state.load(),
        RefreshStateRead::Present(RefreshState::default()),
        "the login reset the marker"
    );

    // A second login of the same identity overwrites, under the same rules.
    let again = verified(&testkit::fresh_auth_bytes());
    let (receipt, _) = InstallNamespace::open_for_install(&paths, again, &guard)
        .expect("opens")
        .install(&Fault::none())
        .expect("installs");
    assert_eq!(receipt.kind(), WriteKind::LoginInstall { overwrote: true });
    assert!(receipt.digest8_before().is_some());
}

#[test]
fn a_failed_install_rename_leaves_the_previous_grant_and_no_pending() {
    // Ledger #237 / review ruling 3: install has no pending fallback.
    let (_dir, paths) = testkit::store();
    let login = verified(&testkit::fresh_auth_bytes());
    let guard = lock::acquire_codex_for_install(
        &paths,
        &login,
        LockBudget::Command(Duration::from_secs(2)),
        &Cancel::new(),
        &Fault::none(),
    )
    .expect("locks");
    testkit::write_0600(&auth_path(&paths), &expired_doc_bytes());
    let install = InstallNamespace::open_for_install(&paths, login, &guard).expect("opens");
    let err = install
        .install(&Fault::from_list("codex_install_rename_fail"))
        .expect_err("the rename fails");
    assert!(err.to_string().contains("could not rename"), "{err}");
    assert_eq!(fs::read(auth_path(&paths)).expect("read"), expired_doc_bytes());
    let names: Vec<_> =
        fs::read_dir(ns_dir(&paths)).expect("list").flatten().map(|e| e.file_name()).collect();
    assert_eq!(names, [AUTH_FILE], "no tmp, no pending, no meta");

    // The refresh writer's fault name does not fail the install's rename.
    let login = verified(&testkit::fresh_auth_bytes());
    let install = InstallNamespace::open_for_install(&paths, login, &guard).expect("opens");
    let (receipt, _) = install.install(&Fault::from_list("codex_rename_fail")).expect("installs");
    assert_eq!(receipt.kind(), WriteKind::LoginInstall { overwrote: true });
}

#[test]
fn the_marker_lifecycle() {
    // Invariant I26 / plan section 3.3: token only after the durable marker;
    // no second send while one is in flight; one resend per marker.
    let (_dir, paths) = testkit::store();
    let this = record();
    let guard = testkit::lock_for(&paths, &this);
    let ns =
        OwnedNamespace::open(&paths, proof::owned(&this).expect("owned"), &guard).expect("opens");
    testkit::write_0600(&auth_path(&paths), &expired_doc_bytes());
    let credentials = locked_owned(&ns);
    let state = ns.refresh_state();
    assert_eq!(state.load(), RefreshStateRead::Absent);

    let token = state.write_inflight(&credentials).expect("records");
    assert_eq!(Some(token.digest8().to_owned()), credentials.refresh_digest8());
    let RefreshStateRead::Present(written) = state.load() else { panic!("present") };
    let inflight = written.inflight.clone().expect("in flight");
    assert_eq!(inflight.sent_digest8, token.digest8());
    assert_eq!(written.last_sent_at, Some(inflight.sent_at));
    let marker = paths.codex_refresh_state_path(testkit::USER, testkit::ACCT).expect("path");
    assert_eq!(fs::metadata(&marker).expect("stat").permissions().mode() & 0o777, 0o600);
    testkit::assert_no_needles(&fs::read_to_string(&marker).expect("read"), "marker");

    assert!(
        state.write_inflight(&credentials).is_err(),
        "never a second send while one is in flight"
    );
    assert!(
        state.write_resend(&credentials).is_err(),
        "a send whose outcome is not yet classified unknown cannot be re-sent"
    );
}

#[test]
fn interrupted_unknown_resend_and_clear() {
    let (_dir, paths) = testkit::store();
    let this = record();
    let guard = testkit::lock_for(&paths, &this);
    let ns =
        OwnedNamespace::open(&paths, proof::owned(&this).expect("owned"), &guard).expect("opens");
    testkit::write_0600(&auth_path(&paths), &expired_doc_bytes());
    let credentials = locked_owned(&ns);
    let state = ns.refresh_state();

    assert!(state.write_resend(&credentials).is_err(), "nothing to re-send");
    let first = state.write_inflight(&credentials).expect("records");
    let RefreshStateRead::Present(sent) = state.load() else { panic!("present") };
    let sent_at = sent.inflight.as_ref().map(|i| i.sent_at).expect("sent_at");

    state.mark_interrupted(Timestamp::now()).expect("classifies");
    let RefreshStateRead::Present(interrupted) = state.load() else { panic!("present") };
    assert_eq!(interrupted.class, Some(UnknownClass::Interrupted));
    assert_eq!(interrupted.ambiguous_since, Some(sent_at), "since = sent_at");

    let resend = state.write_resend(&credentials).expect("the one resend");
    assert_eq!(resend.digest8(), first.digest8(), "the same grant");
    let RefreshStateRead::Present(resent) = state.load() else { panic!("present") };
    assert!(resent.resent);
    assert_eq!(resent.ambiguous_since, Some(sent_at), "kept");
    assert_eq!(resent.class, Some(UnknownClass::Interrupted), "kept");
    assert!(state.write_resend(&credentials).is_err(), "once per marker");

    state
        .mark_unknown(UnknownClass::RateLimited, Timestamp::now(), Some(Duration::from_secs(30)))
        .expect("marks");
    let RefreshStateRead::Present(limited) = state.load() else { panic!("present") };
    assert_eq!(
        (limited.class, limited.retry_after),
        (Some(UnknownClass::RateLimited), Some(Duration::from_secs(30)))
    );
    assert_eq!(limited.ambiguous_since, Some(sent_at), "the first unknown instant is kept");

    state.clear_inflight(DefiniteOutcome::Applied).expect("clears");
    let RefreshStateRead::Present(cleared) = state.load() else { panic!("present") };
    assert_eq!((&cleared.inflight, cleared.class, cleared.resent), (&None, None, false));
    assert!(
        state.mark_unknown(UnknownClass::Tls, Timestamp::now(), None).is_err(),
        "nothing in flight"
    );

    state.store(&RefreshState { did_not_help: 2, floor_min: 240, ..cleared }).expect("seeds");
    state.reset_floor().expect("resets");
    let RefreshStateRead::Present(reset) = state.load() else { panic!("present") };
    assert_eq!((reset.did_not_help, reset.floor_min), (0, DEFAULT_FLOOR_MIN));
}

#[test]
fn an_unreadable_marker_fails_closed() {
    // `RefreshStateUnavailable`: never "unknown", and no token.
    let (_dir, paths) = testkit::store();
    let this = record();
    let guard = testkit::lock_for(&paths, &this);
    let ns =
        OwnedNamespace::open(&paths, proof::owned(&this).expect("owned"), &guard).expect("opens");
    testkit::write_0600(&auth_path(&paths), &expired_doc_bytes());
    let credentials = locked_owned(&ns);
    let marker = paths.codex_refresh_state_path(testkit::USER, testkit::ACCT).expect("path");

    for (name, body) in [("garbage", &b"not json"[..]), ("future schema", br#"{"schema": 99}"#)] {
        testkit::write_0600(&marker, body);
        assert!(matches!(ns.refresh_state().load(), RefreshStateRead::Unavailable(_)), "{name}");
        assert!(ns.refresh_state().write_inflight(&credentials).is_err(), "{name}: no token");
        assert_eq!(fs::read(&marker).expect("read"), body, "{name}: untouched");
    }
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o000)).expect("chmod");
    let unreadable = ns.refresh_state().load();
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).expect("chmod");
    assert!(matches!(unreadable, RefreshStateRead::Unavailable(_)), "{unreadable:?}");
}

#[test]
fn remove_named_files_removes_exactly_its_own_files() {
    let (_dir, paths) = testkit::store();
    let this = record();
    let guard = testkit::lock_for(&paths, &this);
    let ns =
        OwnedNamespace::open(&paths, proof::owned(&this).expect("owned"), &guard).expect("opens");
    testkit::write_0600(&auth_path(&paths), &expired_doc_bytes());
    for name in [PENDING_FILE, PENDING_META, "auth.json.tmp.0badc0de"] {
        testkit::write_0600(&ns_dir(&paths).join(name), b"x");
    }
    let credentials = locked_owned(&ns);
    let _token = ns.refresh_state().write_inflight(&credentials).expect("marker");

    // A foreign entry refuses the whole removal.
    fs::create_dir(ns_dir(&paths).join("sessions")).expect("mkdir");
    let err = ns.remove_named_files().expect_err("refused");
    assert!(
        err.to_string().contains("sessions") && err.to_string().contains("nothing was removed"),
        "{err}"
    );
    assert!(auth_path(&paths).is_file());
    fs::remove_dir(ns_dir(&paths).join("sessions")).expect("rmdir");

    let receipt = ns.remove_named_files().expect("removes");
    assert_eq!(receipt.kind(), WriteKind::Delete);
    assert_eq!(receipt.digest8_before(), credentials.refresh_digest8().as_deref());
    assert!(!ns_dir(&paths).exists(), "the namespace directory is gone");
    assert!(!paths.codex_root().join(testkit::USER).exists(), "and its empty user directory");
    assert_eq!(ns.refresh_state().load(), RefreshStateRead::Absent, "the marker went with it");
    assert!(
        paths.codex_locks_dir().is_dir() && paths.codex_state_dir().is_dir(),
        "shared dirs stay"
    );
}

#[test]
fn receipts_and_handles_render_no_secret() {
    let (_dir, paths) = testkit::store();
    let this = record();
    let guard = testkit::lock_for(&paths, &this);
    let ns =
        OwnedNamespace::open(&paths, proof::owned(&this).expect("owned"), &guard).expect("opens");
    testkit::write_0600(&auth_path(&paths), &expired_doc_bytes());
    let read = ns.read().expect("reads");
    let snapshot = ns.snapshot_for_post().expect("snapshot");
    testkit::assert_no_needles(&format!("{read:?} {read:#?} {snapshot:?}"), "namespace read");
    let NamespaceRead::Credentials(credentials) = read else { panic!("credentials") };
    let token = ns.refresh_state().write_inflight(&credentials).expect("marker");
    testkit::assert_no_needles(&format!("{token:?}"), "InflightToken");
    assert_eq!(shown_name(), "auth.json");
}

#[test]
fn accessors_and_every_definite_outcome_clear_the_marker() {
    let (_dir, paths) = testkit::store();
    let this = record();
    let guard = testkit::lock_for(&paths, &this);
    let ns =
        OwnedNamespace::open(&paths, proof::owned(&this).expect("owned"), &guard).expect("opens");
    assert_eq!((ns.owned().user(), ns.owned().acct()), (testkit::USER, testkit::ACCT));
    testkit::write_0600(&auth_path(&paths), &expired_doc_bytes());
    let snapshot = ns.snapshot_for_post().expect("snapshot").expect("present");
    let meta = fs::metadata(auth_path(&paths)).expect("stat");
    assert_eq!(snapshot.size_and_mtime_ns().0, meta.len());
    assert_eq!(
        snapshot.size_and_mtime_ns().1,
        i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec())
    );

    let CodexResolved::Credentials(live) = read_live(&ns_dir(&paths)) else {
        panic!("credentials")
    };
    assert_eq!(live.last_refresh(), "2026-09-06T21:40:50Z".parse().ok());

    let credentials = locked_owned(&ns);
    for outcome in [
        DefiniteOutcome::Applied,
        DefiniteOutcome::Permanent,
        DefiniteOutcome::PreSend,
        DefiniteOutcome::Rejected,
        DefiniteOutcome::External,
    ] {
        let _token = ns.refresh_state().write_inflight(&credentials).expect("records");
        ns.refresh_state().clear_inflight(outcome).expect("clears");
        let RefreshStateRead::Present(state) = ns.refresh_state().load() else { panic!("present") };
        assert_eq!(state.inflight, None, "{outcome:?}");
    }
}

fn sha256_hex_of_rt() -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(testkit::RT_SENTINEL.as_bytes()))
}

fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .unwrap_or_else(|err| panic!("chmod {}: {err}", path.display()));
}

#[test]
fn an_unopenable_auth_json_is_an_error_never_needs_login_and_never_a_discard() {
    // Review S30 F1 (a): a mode-0000 owned `auth.json` is not absent.
    let (_dir, paths) = testkit::store();
    let this = record();
    let guard = testkit::lock_for(&paths, &this);
    let ns =
        OwnedNamespace::open(&paths, proof::owned(&this).expect("owned"), &guard).expect("opens");
    testkit::write_0600(&auth_path(&paths), &expired_doc_bytes());
    let credentials = locked_owned(&ns);
    // Park a pending grant derived from this file.
    let CodexWrite::Landed { .. } =
        ns.write(&credentials, &Fault::from_list("codex_rename_fail")).expect("parks")
    else {
        panic!("expected a parked write")
    };

    chmod(&auth_path(&paths), 0o000);
    let read = ns.read();
    let write = ns.write(&credentials, &Fault::none());
    let resolve = ns.resolve_pending(&Cancel::new());
    let snapshot = ns.snapshot_for_post();
    chmod(&auth_path(&paths), 0o600);

    assert!(read.is_err(), "read() is an error, never `Absent`/needs login: {read:?}");
    assert!(write.is_err(), "write() is an error, not a discard: {write:?}");
    assert!(resolve.is_err(), "resolve_pending() is an error, not a discard");
    assert!(snapshot.is_err());
    assert!(ns_dir(&paths).join(PENDING_FILE).is_file(), "the pending grant is kept");
    assert!(ns_dir(&paths).join(PENDING_META).is_file(), "and its meta");
    assert_eq!(fs::read(auth_path(&paths)).expect("read"), expired_doc_bytes());
}

#[test]
fn an_unopenable_pending_file_keeps_both_files() {
    // Review S30 F1 (b).
    let (_dir, paths) = testkit::store();
    let this = record();
    let guard = testkit::lock_for(&paths, &this);
    let ns =
        OwnedNamespace::open(&paths, proof::owned(&this).expect("owned"), &guard).expect("opens");
    testkit::write_0600(&auth_path(&paths), &expired_doc_bytes());
    let credentials = locked_owned(&ns);
    let CodexWrite::Landed { .. } =
        ns.write(&credentials, &Fault::from_list("codex_rename_fail")).expect("parks")
    else {
        panic!("expected a parked write")
    };
    let pending = ns_dir(&paths).join(PENDING_FILE);
    chmod(&pending, 0o000);
    let resolve = ns.resolve_pending(&Cancel::new());
    chmod(&pending, 0o600);
    assert!(resolve.is_err(), "an error, not an `invalid` discard");
    assert!(pending.is_file() && ns_dir(&paths).join(PENDING_META).is_file());

    let (decision, _receipt, _evidence) = ns.resolve_pending(&Cancel::new()).expect("resolves");
    assert_eq!(
        decision,
        PendingDecision::Replayed { first_write: false },
        "readable again → replayed"
    );
}

#[test]
fn a_live_codex_daemon_does_not_discard_a_parked_grant() {
    // Review S30 F2: a live pid record is a note, not "taken over".
    let (_dir, paths) = testkit::store();
    let this = record();
    let guard = testkit::lock_for(&paths, &this);
    let ns =
        OwnedNamespace::open(&paths, proof::owned(&this).expect("owned"), &guard).expect("opens");
    testkit::write_0600(&auth_path(&paths), &expired_doc_bytes());
    let credentials = locked_owned(&ns);
    let response = crate::provider::codex::credentials::RefreshResponse::parse(
        br#"{"refresh_token":"agctl-test-codex-rt-under-daemon"}"#,
    )
    .expect("parses");
    let (merged, _) = credentials.merge_refresh(response, Timestamp::now()).expect("merges");
    let CodexWrite::Landed { .. } =
        ns.write(&merged, &Fault::from_list("codex_rename_fail")).expect("parks")
    else {
        panic!("expected a parked write")
    };

    // This process as the daemon, its record written after it started.
    let daemon = ns_dir(&paths).join("app-server-daemon");
    fs::create_dir(&daemon).expect("mkdir");
    fs::write(daemon.join("app-server.pid"), format!(r#"{{"pid":{}}}"#, std::process::id()))
        .expect("write");

    let (decision, receipt, evidence) = ns.resolve_pending(&Cancel::new()).expect("resolves");
    assert_eq!(evidence, DaemonEvidence::PidAlive(std::process::id()), "surfaced as a note");
    assert_eq!(decision, PendingDecision::Replayed { first_write: false });
    assert_eq!(receipt.map(|r| r.kind()), Some(WriteKind::PendingReplayed));
    let now = Credentials::parse(&fs::read(auth_path(&paths)).expect("read")).expect("parses");
    assert_eq!(now.refresh_digest8(), merged.refresh_digest8(), "the rotated grant is on disk");
}

#[test]
fn a_write_compares_with_the_read_it_came_from() {
    // Review S30 F4: read → an in-place external writer → merge → write must
    // discard; no snapshot taken by a separate read can defeat it.
    let (_dir, paths) = testkit::store();
    let this = record();
    let guard = testkit::lock_for(&paths, &this);
    let ns =
        OwnedNamespace::open(&paths, proof::owned(&this).expect("owned"), &guard).expect("opens");
    testkit::write_0600(&auth_path(&paths), &expired_doc_bytes());
    let credentials = locked_owned(&ns);

    let mut external = testkit::chatgpt_doc(Some(4_102_444_800), None);
    external["tokens"]["refresh_token"] = json!("agctl-test-codex-rt-external-newer");
    let external = testkit::pretty(&external);
    fs::write(auth_path(&paths), &external).expect("an in-place external writer");
    // A snapshot taken now would match the newer file; `write` does not use one.
    let _late_snapshot = ns.snapshot_for_post().expect("snapshot");

    let response = crate::provider::codex::credentials::RefreshResponse::parse(
        br#"{"refresh_token":"agctl-test-codex-rt-merged-on-old"}"#,
    )
    .expect("parses");
    let (merged, _) = credentials.merge_refresh(response, Timestamp::now()).expect("merges");
    let CodexWrite::ChangedSinceRead { receipt } =
        ns.write(&merged, &Fault::none()).expect("checks")
    else {
        panic!("a merge built on the older read must not overwrite the newer grant")
    };
    assert_eq!(receipt.kind(), WriteKind::DiscardedExternal);
    assert_eq!(fs::read(auth_path(&paths)).expect("read"), external);
}

#[test]
fn credentials_from_another_namespace_are_refused_by_the_writer_and_the_marker() {
    // Review S30 F7.
    let (_dir, paths) = testkit::store();
    let a = record();
    let b = testkit::owned_record(testkit::USER, OTHER_ACCT);
    let guard_a = testkit::lock_for(&paths, &a);
    let guard_b = testkit::lock_for(&paths, &b);
    let ns_a = OwnedNamespace::open(&paths, proof::owned(&a).expect("owned"), &guard_a).expect("a");
    let ns_b = OwnedNamespace::open(&paths, proof::owned(&b).expect("owned"), &guard_b).expect("b");
    testkit::write_0600(&auth_path(&paths), &expired_doc_bytes());
    let b_path = paths.codex_namespace_dir(testkit::USER, OTHER_ACCT).expect("dir").join(AUTH_FILE);
    testkit::write_0600(&b_path, &expired_doc_bytes());

    let from_a = locked_owned(&ns_a);
    assert_eq!(from_a.ids(), (testkit::USER, testkit::ACCT));
    let err = ns_b.write(&from_a, &Fault::none()).expect_err("another namespace's credentials");
    assert!(err.to_string().contains("another namespace"), "{err}");
    assert!(ns_b.refresh_state().write_inflight(&from_a).is_err(), "B's marker is not armed");
    assert_eq!(ns_b.refresh_state().load(), RefreshStateRead::Absent);
    assert_eq!(fs::read(&b_path).expect("read"), expired_doc_bytes(), "B's file is untouched");
}

#[test]
fn foreign_entry_names_are_escaped_in_the_refusal() {
    // Review S30 F11: a name a foreign process chose may carry control bytes.
    let (_dir, paths) = testkit::store();
    let this = record();
    let guard = testkit::lock_for(&paths, &this);
    let ns =
        OwnedNamespace::open(&paths, proof::owned(&this).expect("owned"), &guard).expect("opens");
    fs::write(ns_dir(&paths).join("evil\u{1b}[2Jname"), b"x").expect("write");
    let err = ns.remove_named_files().expect_err("refused");
    let text = err.to_string();
    assert!(!text.contains('\u{1b}'), "no raw escape byte: {text:?}");
    assert!(text.contains("\\u{1b}"), "the name is shown escaped: {text}");
}
