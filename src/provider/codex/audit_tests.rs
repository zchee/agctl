use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use super::*;
use crate::provider::codex::auth_store;
use crate::provider::codex::auth_store::InstallNamespace;
use crate::provider::codex::lock;
use crate::provider::codex::lock::LockBudget;
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
        false,
        Vec::new(),
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
            CodexEvent::Ambiguous { class: "interrupted", sent_digest8: "0123abcd" },
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
            CodexEvent::NeedsLogin { class: "refresh_token_reused", sent_digest8: "0123abcd" },
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
            "a free-form class",
            (testkit::USER, testkit::ACCT),
            CodexEvent::Ambiguous { class: "agctl-test-codex-rt-0001", sent_digest8: "0123abcd" },
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
