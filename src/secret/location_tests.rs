//! Tests for the read rule (plan AC34's unit half, invariant I10).

use std::path::PathBuf;

use tempfile::TempDir;

use super::*;
use crate::config::AccountKind;
use crate::config::paths::UNKNOWN_ORG;
use crate::secret::KeychainError;
use crate::secret::fake_reader::FakeReader;

const BLOB: &[u8] = br#"{"claudeAiOauth":{"accessToken":"a","refreshToken":"r","expiresAt":9}}"#;

fn record(kind: AccountKind) -> AccountRecord {
    AccountRecord {
        account_uuid: "acct".to_owned(),
        organization_uuid: "org".to_owned(),
        email: None,
        org_name: None,
        label: None,
        kind,
        forgotten: false,
        created_at: "2026-09-09T00:00:00Z".to_owned(),
    }
}

fn env() -> EnvView {
    EnvView::with_home(PathBuf::from("/Users/example"))
}

fn paths() -> (TempDir, Paths) {
    let dir = TempDir::new().expect("a temporary directory should be available");
    let paths = Paths::with_config_dir(dir.path().join("agctl"));
    (dir, paths)
}

#[test]
fn the_live_row_reads_the_environment_s_service_name() {
    let (_dir, paths) = paths();
    let env = env();
    let service = namespace::service_name(&env);
    let reader = FakeReader::unlocked().with_item(&service, BLOB);

    let resolved = resolve(&AccountKind::Live, &record(AccountKind::Live), &paths, &reader, &env);
    assert!(matches!(resolved, Resolved::Credentials(_)), "got {resolved:?}");
    assert_eq!(reader.reads(), vec![service]);
}

#[test]
fn a_locked_keychain_never_falls_through_to_the_file() {
    // Invariant I10, the documented divergence from Claude Code's composed
    // store (fact F35). A file left behind by an earlier configuration can
    // hold a *different* account's credentials.
    let (_dir, paths) = paths();
    let env = env();
    let ns_dir = paths.namespace_dir("acct", "org");
    std::fs::create_dir_all(&ns_dir).expect("directories should be creatable");
    std::fs::write(ns_dir.join(file_store::CREDENTIALS_FILE), BLOB).expect("writable");

    let service = namespace::service_name(&env);
    let reader = FakeReader::unlocked().with_failure(&service, KeychainError::Locked);
    let resolved = resolve(&AccountKind::Live, &record(AccountKind::Live), &paths, &reader, &env);
    assert!(matches!(resolved, Resolved::Locked), "got {resolved:?}");
}

#[test]
fn a_keychain_timeout_is_transient_not_absent() {
    let (_dir, paths) = paths();
    let env = env();
    let service = namespace::service_name(&env);
    let reader = FakeReader::unlocked().with_failure(&service, KeychainError::Timeout(2000));

    let resolved = resolve(&AccountKind::Live, &record(AccountKind::Live), &paths, &reader, &env);
    let Resolved::Transient(detail) = resolved else { panic!("expected a transient failure") };
    assert!(detail.contains("2000"), "the row says how long it waited: {detail}");
}

#[test]
fn a_missing_keychain_item_is_absent() {
    let (_dir, paths) = paths();
    let env = env();
    let resolved = resolve(
        &AccountKind::Live,
        &record(AccountKind::Live),
        &paths,
        &FakeReader::unlocked(),
        &env,
    );
    assert!(matches!(resolved, Resolved::Absent), "got {resolved:?}");
}

#[test]
fn a_config_dir_row_reads_its_recorded_service_not_the_live_one() {
    let (_dir, paths) = paths();
    let env = env();
    let kind = AccountKind::ConfigDirReadOnly {
        dir: PathBuf::from("/elsewhere"),
        service: "Claude Code-credentials-5cdc535f".to_owned(),
        shares_live_dir: false,
    };
    let reader = FakeReader::unlocked().with_item("Claude Code-credentials-5cdc535f", BLOB);

    let resolved = resolve(&kind, &record(kind.clone()), &paths, &reader, &env);
    assert!(matches!(resolved, Resolved::Credentials(_)), "got {resolved:?}");
    assert_eq!(reader.reads(), vec!["Claude Code-credentials-5cdc535f"]);
}

#[test]
fn an_owned_row_reads_its_namespace_file_and_never_the_keychain() {
    let (_dir, paths) = paths();
    let env = env();
    let ns_dir = paths.namespace_dir("acct", "org");
    std::fs::create_dir_all(&ns_dir).expect("directories should be creatable");
    std::fs::write(ns_dir.join(file_store::CREDENTIALS_FILE), BLOB).expect("writable");

    let kind = AccountKind::Owned {
        export_spelling: ns_dir.to_string_lossy().into_owned(),
        export_sha8: "aaaaaaaa".to_owned(),
    };
    let reader = FakeReader::unlocked();
    let resolved = resolve(&kind, &record(kind.clone()), &paths, &reader, &env);
    assert!(matches!(resolved, Resolved::Credentials(_)), "got {resolved:?}");
    assert!(reader.reads().is_empty(), "an owned row does not touch the keychain");
}

#[test]
fn an_owned_row_with_no_file_is_absent() {
    let (_dir, paths) = paths();
    let kind = AccountKind::Owned {
        export_spelling: "/nowhere".to_owned(),
        export_sha8: "aaaaaaaa".to_owned(),
    };
    let resolved = resolve(&kind, &record(kind.clone()), &paths, &FakeReader::unlocked(), &env());
    assert!(matches!(resolved, Resolved::Absent), "got {resolved:?}");
}

#[test]
fn a_corrupt_blob_is_transient_rather_than_absent() {
    // Absent would lead to writing over the corrupt file. Transient leaves it
    // for the user, or `doctor`, to look at.
    let (_dir, paths) = paths();
    let env = env();
    let service = namespace::service_name(&env);
    let reader = FakeReader::unlocked().with_item(&service, b"{not json");

    let resolved = resolve(&AccountKind::Live, &record(AccountKind::Live), &paths, &reader, &env);
    assert!(matches!(resolved, Resolved::Transient(_)), "got {resolved:?}");
}

#[test]
fn a_foreign_record_has_nothing_to_read() {
    // Invariant I1: another tool's keychain item is never read, so resolving
    // one asks no store anything at all.
    let (_dir, paths) = paths();
    let kind = AccountKind::Foreign { source: "claude-switcher".to_owned() };
    let mut rec = record(kind.clone());
    rec.organization_uuid = UNKNOWN_ORG.to_owned();
    let reader = FakeReader::unlocked();

    let resolved = resolve(&kind, &rec, &paths, &reader, &env());
    assert!(matches!(resolved, Resolved::Absent), "got {resolved:?}");
    assert!(reader.reads().is_empty());
}
