use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use super::*;
use crate::provider::codex::auth_store;
use crate::provider::codex::auth_store::InstallNamespace;
use crate::provider::codex::auth_store::UnknownClass;
use crate::provider::codex::lock;
use crate::provider::codex::lock::LockBudget;
use crate::provider::codex::oauth::PermanentClass;
use crate::provider::codex::proof::PostExitReport;
use crate::provider::codex::testkit;
use crate::runtime::coordinator::Cancel;
use crate::runtime::fault::Fault;

/// A real receipt: a verified login installed into an empty namespace.
fn install_receipt(paths: &Paths) -> WriteReceipt {
    let scratch = tempfile::tempdir().expect("tempdir");
    testkit::write_0600(&scratch.path().join("auth.json"), &testkit::fresh_auth_bytes());
    let report = PostExitReport::from_child(
        Vec::new(),
        Vec::new(),
        testkit::clean_survey(),
        testkit::exit_status(0),
    );
    let login = auth_store::verify_login(scratch.path(), &report).expect("a clean login verifies");
    let guard = lock::acquire_codex_for_install(
        paths,
        &login,
        LockBudget::Command(Duration::from_secs(2)),
        &Cancel::new(),
        &Fault::none(),
    )
    .expect("lock");
    let install = InstallNamespace::open_for_install(paths, login, &guard).expect("opens");
    let (receipt, _identity) = install.install(&Fault::none()).expect("installs");
    receipt
}

fn lines(paths: &Paths) -> Vec<CodexAuditEntry> {
    read(paths)
        .expect("the log reads")
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).expect("every line is an entry"))
        .collect()
}

#[test]
fn a_receipt_becomes_one_line_in_a_0600_log() {
    let (_dir, paths) = testkit::store();
    assert_eq!(read(&paths).expect("reads"), None, "no log before the first write");

    append(&paths, install_receipt(&paths)).expect("appends");

    let entries = lines(&paths);
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry.provider, "codex");
    assert_eq!((entry.user_id.as_str(), entry.account_id.as_str()), (testkit::USER, testkit::ACCT));
    assert_eq!(entry.outcome, CodexOutcome::LoginInstall);
    assert_eq!(entry.digest8_before, None);
    assert!(entry.digest8_after.as_deref().is_some_and(is_digest8), "{entry:?}");
    assert_eq!(entry.agctl_pid, std::process::id());

    let mode = fs::metadata(log_path(&paths)).expect("stat").permissions().mode() & 0o7777;
    assert_eq!(mode, 0o600);
    let text = fs::read_to_string(log_path(&paths)).expect("read");
    testkit::assert_no_needles(&text, "the Codex audit log");
    assert!(!text.contains('@'), "{text}");
}

#[test]
fn every_event_is_one_parseable_line() {
    let (_dir, paths) = testkit::store();
    let ids = (testkit::USER, testkit::ACCT);
    let events = [
        (
            CodexEvent::Ambiguous { class: UnknownClass::Interrupted, sent_digest8: "0123abcd" },
            CodexOutcome::Ambiguous,
        ),
        (CodexEvent::Resend { sent_digest8: "0123abcd" }, CodexOutcome::Resend),
        (
            CodexEvent::AdoptedExternal {
                sent_digest8: "0123abcd",
                kept_digest8: Some("fedc9876"),
            },
            CodexOutcome::AdoptedExternal,
        ),
        (
            CodexEvent::NeedsLogin { class: PermanentClass::Reused, sent_digest8: "0123abcd" },
            CodexOutcome::NeedsLogin,
        ),
        (CodexEvent::FloorReset, CodexOutcome::FloorReset),
    ];
    for (event, _) in events {
        append_event(&paths, ids, event).expect("appends");
    }
    let entries = lines(&paths);
    assert_eq!(
        entries.iter().map(|entry| entry.outcome).collect::<Vec<_>>(),
        events.map(|(_, outcome)| outcome).to_vec()
    );
    assert_eq!(entries[0].class.as_deref(), Some("interrupted"));
    assert_eq!(entries[0].digest8_before.as_deref(), Some("0123abcd"));
    assert_eq!(entries[2].digest8_after.as_deref(), Some("fedc9876"));
    assert_eq!(entries[4].class, None);
}

#[test]
fn the_field_guard_refuses_before_any_io() {
    let (_dir, paths) = testkit::store();
    let tests: [(&str, (&str, &str), CodexEvent<'_>); 5] = [
        ("an email as an id", ("someone@example.invalid", testkit::ACCT), CodexEvent::FloorReset),
        ("a path as an id", ("../x", testkit::ACCT), CodexEvent::FloorReset),
        (
            "a whole digest",
            (testkit::USER, testkit::ACCT),
            CodexEvent::Resend { sent_digest8: "0123abcd0123abcd0123abcd0123abcd" },
        ),
        (
            "uppercase hex",
            (testkit::USER, testkit::ACCT),
            CodexEvent::Resend { sent_digest8: "0123ABCD" },
        ),
        (
            "a whole digest as the written grant",
            (testkit::USER, testkit::ACCT),
            CodexEvent::AppliedAfterError {
                sent_digest8: "0123abcd",
                written_digest8: Some("agctl-test-codex-rt-0001"),
            },
        ),
    ];
    for (name, ids, event) in tests {
        let err = append_event(&paths, ids, event).expect_err(name);
        let text = err.to_string();
        assert!(
            !text.contains("example.invalid") && !text.contains("agctl-test-codex-rt"),
            "{name}: {text}"
        );
    }
    assert!(!log_path(&paths).exists(), "a refused entry created no log");
}

#[test]
fn a_refused_log_is_an_error_and_names_no_secret() {
    let (_dir, paths) = testkit::store();
    let other = paths.codex_root().join("elsewhere.jsonl");
    fs::write(&other, b"").expect("write");
    std::os::unix::fs::symlink(&other, log_path(&paths)).expect("symlink");
    let err = append_event(&paths, (testkit::USER, testkit::ACCT), CodexEvent::FloorReset)
        .expect_err("a link at the log's name is refused");
    assert!(err.to_string().contains("refused"), "{err}");
    assert_eq!(fs::read(&other).expect("read"), b"", "nothing was written through the link");

    fs::remove_file(log_path(&paths)).expect("unlink");
    testkit::write_0600(&log_path(&paths), b"");
    fs::set_permissions(log_path(&paths), fs::Permissions::from_mode(0o644)).expect("chmod");
    append_event(&paths, (testkit::USER, testkit::ACCT), CodexEvent::FloorReset)
        .expect_err("a log that is not 0600 is refused");
}

#[test]
fn a_gained_keychain_item_is_recorded_and_read_back() {
    // The one ground on which `doctor` may offer to remove a keychain item:
    // agctl's own log saying agctl's own login child caused it.
    let (_dir, paths) = testkit::store();
    let account = "cli|00112233abcdefff";

    append_event(
        &paths,
        (testkit::USER, testkit::ACCT),
        CodexEvent::LoginKeychainGained { keychain_account: account },
    )
    .expect("the event is recorded");

    let entries = lines(&paths);
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry.outcome, CodexOutcome::LoginKeychainGained);
    assert_eq!(entry.keychain_account.as_deref(), Some(account));
    // The ids the caller passed are NOT used: a refused login has no verified
    // identity, and the line must not claim one.
    assert_eq!(entry.user_id, NO_NAMESPACE);
    assert_eq!(entry.account_id, NO_NAMESPACE);

    assert_eq!(gained_keychain_accounts(&paths).expect("reads"), vec![account.to_owned()]);

    let text = fs::read_to_string(log_path(&paths)).expect("read");
    testkit::assert_no_needles(&text, "the Codex audit log");
    assert!(!text.contains('@'), "{text}");
}

#[test]
fn a_gained_account_agctl_would_not_have_written_is_refused_on_write() {
    let (_dir, paths) = testkit::store();
    let hostile = [
        "cli|00112233ABCDEFFF",
        "cli|00112233abcdeff",
        "cli|00112233abcdefff0",
        "cli|",
        "00112233abcdefff",
        "cli|00112233abcdefff\"; id; \"",
        "cli|00112233abcdefff\u{1b}[2J",
        testkit::RT_SENTINEL,
        "",
    ];

    for account in hostile {
        let err = append_event(
            &paths,
            (testkit::USER, testkit::ACCT),
            CodexEvent::LoginKeychainGained { keychain_account: account },
        )
        .expect_err("a spelling agctl would not have written is refused");
        let shown = err.to_string();
        assert!(shown.contains("sixteen lowercase hex"), "{shown}");
        testkit::assert_no_needles(&shown, "the refusal");
    }
    assert_eq!(read(&paths).expect("reads"), None, "nothing was written");
}

#[test]
fn a_keychain_account_on_any_other_outcome_is_refused_on_write() {
    // The other half of the two-sided guard: the field belongs to that one
    // outcome, so a line cannot carry it under cover of another.
    let mut entry =
        entry((testkit::USER, testkit::ACCT), CodexOutcome::Applied, None, None, Some("0123abcd"));
    entry.keychain_account = Some("cli|00112233abcdefff".to_owned());

    let err = entry_line(&entry).expect_err("refused");
    assert!(err.to_string().contains("outcome that has none"), "{err}");
}

#[test]
fn a_gained_outcome_without_an_account_is_refused_on_write() {
    let entry =
        entry((NO_NAMESPACE, NO_NAMESPACE), CodexOutcome::LoginKeychainGained, None, None, None);

    let err = entry_line(&entry).expect_err("refused");
    assert!(err.to_string().contains("sixteen lowercase hex"), "{err}");
}

#[test]
fn a_log_written_before_this_field_existed_still_parses() {
    // An agctl that predates the field wrote lines without it, and a reader
    // that refused them would refuse the whole history.
    let (_dir, paths) = testkit::store();
    append(&paths, install_receipt(&paths)).expect("appends");

    let text = fs::read_to_string(log_path(&paths)).expect("read");
    assert!(!text.contains("keychain_account"), "the field is absent when there is none: {text}");
    let entry: CodexAuditEntry = serde_json::from_str(text.lines().next().expect("a line"))
        .expect("an old-shaped line still parses");
    assert_eq!(entry.keychain_account, None);
    assert!(gained_keychain_accounts(&paths).expect("reads").is_empty());
}

#[test]
fn a_gained_line_the_log_holds_is_read_only_when_its_account_is_agctls_spelling() {
    // The read side is as strict as the write side: a line planted in the
    // file, rather than written through `append_event`, explains nothing.
    let (_dir, paths) = testkit::store();
    let hostile = "cli|00112233abcdefff\"; id; \"";
    let planted = format!(
        "{}\n{}\n",
        serde_json::json!({
            "ts": "2026-09-22T00:00:00Z",
            "agctl_pid": 1,
            "provider": "codex",
            "user_id": NO_NAMESPACE,
            "account_id": NO_NAMESPACE,
            "outcome": "login_keychain_gained",
            "keychain_account": hostile,
        }),
        serde_json::json!({
            "ts": "2026-09-22T00:00:00Z",
            "agctl_pid": 1,
            "provider": "codex",
            "user_id": NO_NAMESPACE,
            "account_id": NO_NAMESPACE,
            "outcome": "login_keychain_gained",
            "keychain_account": "cli|00112233abcdefff",
        }),
    );
    fs::create_dir_all(paths.codex_root()).expect("the codex root");
    testkit::write_0600(&log_path(&paths), planted.as_bytes());

    let found = gained_keychain_accounts(&paths).expect("reads");

    assert_eq!(found, vec!["cli|00112233abcdefff".to_owned()]);
}

#[test]
fn a_line_past_the_entry_bound_is_passed_over_and_the_next_one_is_not() {
    // The reader walks the whole history, so it walks it a line at a time and
    // one absurd line costs time rather than memory. The line after it is
    // still read, which is what proves the reader resynchronised.
    let (_dir, paths) = testkit::store();
    let good = serde_json::json!({
        "ts": "2026-09-22T00:00:00Z",
        "agctl_pid": 1,
        "provider": "codex",
        "user_id": NO_NAMESPACE,
        "account_id": NO_NAMESPACE,
        "outcome": "login_keychain_gained",
        "keychain_account": "cli|00112233abcdefff",
    })
    .to_string();
    let planted = format!("{}\n{good}\n", "x".repeat(MAX_ENTRY_BYTES + 1));
    fs::create_dir_all(paths.codex_root()).expect("the codex root");
    testkit::write_0600(&log_path(&paths), planted.as_bytes());

    assert_eq!(
        gained_keychain_accounts(&paths).expect("reads"),
        vec!["cli|00112233abcdefff".to_owned()]
    );
}

#[test]
fn a_provider_that_is_not_this_ones_is_refused_on_write_and_never_quoted() {
    // Review S37-b1b F1. `provider` was the one field `entry_line` did not
    // check, and `shown_line` re-serializes a line parsed from a FILE — so
    // whatever the file spelled reached the table and `--json`.
    let mut entry =
        entry((testkit::USER, testkit::ACCT), CodexOutcome::Applied, None, None, Some("0123abcd"));
    for hostile in [
        "$(id)",
        "`id`",
        "codex\u{1b}[2J",
        "codex\u{2028}",
        "codex\u{9b}0m",
        "claude",
        "",
        testkit::AK_SENTINEL,
    ] {
        entry.provider = hostile.to_owned();
        let err = entry_line(&entry).expect_err("a foreign provider is refused");
        let shown = err.to_string();
        // The refusal names the LENGTH, never the bytes: this message is
        // printed, and the value is the thing that must not be.
        assert!(shown.contains(&format!("({} characters)", hostile.len())), "{shown}");
        assert!(!shown.contains(hostile) || hostile.is_empty(), "the refusal quoted the value");
        testkit::assert_no_needles(&shown, "the refusal");
    }
}

#[test]
fn a_planted_line_is_shown_only_when_every_field_would_have_been_written() {
    // The read side of the same rule: `shown_line` is what `doctor` renders
    // through, so a line the guard would refuse must come back `None`.
    let good = serde_json::json!({
        "ts": "2026-09-22T00:00:00Z",
        "agctl_pid": 1,
        "provider": "codex",
        "user_id": testkit::USER,
        "account_id": testkit::ACCT,
        "outcome": "applied",
    });
    assert!(shown_line(&good.to_string()).is_some(), "a well-formed line is shown");

    for (field, value) in [
        ("provider", serde_json::json!("$(id)")),
        ("user_id", serde_json::json!("user\u{1b}[2J")),
        ("account_id", serde_json::json!("acct|1")),
        ("digest8_before", serde_json::json!("nothex!!")),
        ("class", serde_json::json!("made up")),
        ("keychain_account", serde_json::json!("cli|00112233abcdefff")),
    ] {
        let mut planted = good.clone();
        planted[field] = value;
        assert!(
            shown_line(&planted.to_string()).is_none(),
            "a line whose `{field}` the guard refuses was shown"
        );
    }
}
