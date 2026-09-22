use std::path::PathBuf;

use super::*;
use crate::provider::codex::auth_store;
use crate::provider::codex::testkit;

#[test]
fn owned_is_some_only_for_owned_records_with_valid_ids() {
    let owned_row = testkit::owned_record(testkit::USER, testkit::ACCT);
    let proof = owned(&owned_row).expect("an owned row with valid ids");
    assert_eq!((proof.user(), proof.acct()), (testkit::USER, testkit::ACCT));
    assert_eq!(proof.export_spelling(), Some("/somewhere/else"));
    assert_eq!(proof.refresh(), RefreshPolicy::Auto);

    let mut never = owned_row.clone();
    never.kind =
        CodexKind::Owned { export_spelling: "x".to_owned(), refresh: RefreshPolicy::Never };
    assert_eq!(owned(&never).map(|p| p.refresh()), Some(RefreshPolicy::Never));

    let mut live = owned_row.clone();
    live.kind = CodexKind::Live;
    assert_eq!(owned(&live), None, "a live row has no path to a write (I27)");
    let mut imported = owned_row.clone();
    imported.kind = CodexKind::HomeReadOnly { dir: PathBuf::from("/tmp/elsewhere") };
    assert_eq!(owned(&imported), None);

    // The registry is user-editable: ids are validated again, not trusted.
    for (user, acct) in [
        ("../x", testkit::ACCT),
        (testkit::USER, "b/c"),
        (".locks", testkit::ACCT),
        (testkit::USER, ""),
    ] {
        assert_eq!(owned(&testkit::owned_record(user, acct)), None, "{user:?} {acct:?}");
    }
}

#[test]
fn a_verified_login_proves_itself_as_an_unregistered_owned_record() {
    let scratch = tempfile::tempdir().expect("tempdir");
    testkit::write_0600(
        &scratch.path().join(auth_store::shown_name()),
        &testkit::fresh_auth_bytes(),
    );
    let report = PostExitReport::from_child(
        Vec::new(),
        Vec::new(),
        testkit::clean_survey(),
        testkit::exit_status(0),
    );
    let login = auth_store::verify_login(scratch.path(), &report).expect("verifies");
    let record = login.owned_record();
    assert_eq!(
        (record.user(), record.acct(), record.export_spelling()),
        (testkit::USER, testkit::ACCT, None)
    );
    assert_eq!(record.refresh(), RefreshPolicy::Auto);
    assert_eq!(login.doc().identity().map(|i| i.user_id).as_deref(), Some(testkit::USER));
    let rendered = format!("{login:?} {login:#?}");
    testkit::assert_no_needles(&rendered, "VerifiedLogin Debug");
}

#[test]
fn a_post_exit_report_is_clean_only_when_nothing_was_left_behind() {
    let ok = testkit::exit_status(0);
    assert!(
        PostExitReport::from_child(Vec::new(), Vec::new(), testkit::clean_survey(), ok).clean()
    );
    assert!(
        PostExitReport::from_child(Vec::new(), Vec::new(), testkit::clean_survey(), ok)
            .anomalies()
            .is_empty()
    );
    let cases: [(&str, PostExitReport); 7] = [
        (
            "exit",
            PostExitReport::from_child(
                Vec::new(),
                Vec::new(),
                testkit::clean_survey(),
                testkit::exit_status(2),
            ),
        ),
        (
            "keychain",
            PostExitReport::from_child(
                vec!["cli|0000".to_owned()],
                Vec::new(),
                testkit::clean_survey(),
                ok,
            ),
        ),
        (
            "survivor",
            PostExitReport::from_child(
                Vec::new(),
                vec![PathBuf::from("/x")],
                testkit::clean_survey(),
                ok,
            ),
        ),
        (
            "daemon",
            PostExitReport::from_child(
                Vec::new(),
                Vec::new(),
                testkit::survey_where(|s| {
                    s.daemon_dir = true;
                }),
                ok,
            ),
        ),
        (
            "lock",
            PostExitReport::from_child(
                Vec::new(),
                Vec::new(),
                testkit::survey_where(|s| {
                    s.held_locks = vec![PathBuf::from("a.lock")];
                }),
                ok,
            ),
        ),
        (
            "odd lock",
            PostExitReport::from_child(
                Vec::new(),
                Vec::new(),
                testkit::survey_where(|s| {
                    s.odd_locks = vec![PathBuf::from("wedge.lock")];
                }),
                ok,
            ),
        ),
        (
            "truncated survey",
            PostExitReport::from_child(
                Vec::new(),
                Vec::new(),
                testkit::survey_where(|s| {
                    s.truncated = true;
                }),
                ok,
            ),
        ),
    ];
    for (name, report) in cases {
        assert!(!report.clean(), "{name}");
        assert_eq!(report.anomalies().len(), 1, "{name}: {:?}", report.anomalies());
    }
}

#[test]
fn the_guard_reports_the_lock_it_holds() {
    let (_dir, paths) = testkit::store();
    let guard = testkit::lock_for(&paths, &testkit::owned_record(testkit::USER, testkit::ACCT));
    assert_eq!(guard.path(), paths.codex_lock_path(testkit::USER, testkit::ACCT).expect("path"));
}

#[test]
fn an_odd_lock_is_named_only_by_a_final_component_agctl_would_have_written() {
    // Review S37-b1b F2, the unit half. `anomalies()` is printed to the
    // user's terminal, and these paths carry a name the login CHILD chose:
    // `is_lock_name` is only `ends_with(".lock")`.
    let mut survey = testkit::clean_survey();
    survey.odd_locks = vec![
        // Hostile: an escape byte, a command substitution and a needle, under
        // a directory whose own path must not be printed either.
        PathBuf::from("/tmp/scratch-0001")
            .join(format!("a\u{1b}]0;pwned\u{7}$(id){}.lock", testkit::AK_SENTINEL)),
        // Well spelled: still named, so the guard is a filter, not a switch.
        PathBuf::from("/tmp/scratch-0001").join("codex.lock"),
    ];
    let report =
        PostExitReport::from_child(Vec::new(), Vec::new(), survey, testkit::exit_status(0));

    let text = report.anomalies().join("\n");

    // Each value guard runs BEFORE the shape assertions, whose failure would
    // print the text.
    for shape in ["\u{1b}]0;", "$(id)", testkit::AK_SENTINEL, "/tmp/scratch-0001"] {
        assert!(!text.contains(shape), "an odd-lock name or path reached the refusal");
    }
    testkit::assert_no_needles(&text, "the refusal");
    assert!(text.contains("are not regular files"), "{text}");
    assert!(text.contains("codex.lock"), "a name agctl would write is still shown: {text}");
    assert!(text.contains("1 unnameable lock file(s)"), "the other is counted: {text}");
    assert!(text.contains("2 entr(y/ies)"), "and the total is still the truth: {text}");
}
