//! Tests for foreign-activity detection (plan AC20, section 3.5).

use tempfile::TempDir;

use super::*;
use crate::secret::KeychainError;
use crate::secret::fake_reader::FakeReader;

fn namespace() -> (TempDir, std::path::PathBuf) {
    let dir = TempDir::new().expect("a temporary directory should be available");
    let ns_dir = dir.path().join("claude").join("acct").join("org");
    std::fs::create_dir_all(&ns_dir).expect("directories should be creatable");
    (dir, ns_dir)
}

fn owned<'a>(export: &'a str, canonical: Option<&'a str>) -> OwnedMeta<'a> {
    OwnedMeta { export_sha8: export, canonical_sha8: canonical }
}

#[test]
fn a_clean_namespace_has_no_activity() {
    let (_dir, ns_dir) = namespace();
    let reader = FakeReader::unlocked();
    assert_eq!(detect(&ns_dir, &owned("aaaaaaaa", None), &[], &reader), ForeignActivity::None);
    assert!(reader.reads().is_empty(), "an empty listing means no keychain read at all");
}

#[test]
fn each_lock_artefact_is_detected_by_name() {
    for artefact in [REFRESH_LOCK, STORAGE_WRITE_LOCK] {
        let (_dir, ns_dir) = namespace();
        std::fs::write(ns_dir.join(artefact), b"").expect("the artefact should be writable");

        let activity = detect(&ns_dir, &owned("aaaaaaaa", None), &[], &FakeReader::unlocked());
        let ForeignActivity::ClaudeLock { name, age_ms } = activity else {
            panic!("`{artefact}` should be detected, got {activity:?}")
        };
        assert_eq!(name, artefact);
        assert!(age_ms < 60_000, "a just-created artefact is young, got {age_ms}ms");
    }
}

#[test]
fn the_legacy_lock_beside_the_namespace_is_detected() {
    // Fact F17: the older lock is `<realpath(ns)>.lock`, a sibling of the
    // directory rather than a file inside it.
    let (_dir, ns_dir) = namespace();
    let mut legacy = ns_dir.clone().into_os_string();
    legacy.push(".lock");
    let legacy = std::path::PathBuf::from(legacy);
    std::fs::write(&legacy, b"").expect("the artefact should be writable");

    let activity = detect(&ns_dir, &owned("aaaaaaaa", None), &[], &FakeReader::unlocked());
    let ForeignActivity::ClaudeLock { name, .. } = activity else {
        panic!("the legacy lock should be detected, got {activity:?}")
    };
    assert_eq!(name, "org.lock");
}

#[test]
fn a_lock_wins_over_a_migration() {
    let (_dir, ns_dir) = namespace();
    std::fs::write(ns_dir.join(REFRESH_LOCK), b"").expect("writable");
    let service = format!("{}-aaaaaaaa", namespace::LIVE_SERVICE);
    let reader = FakeReader::unlocked().with_item(&service, b"{}");
    let listing = reader.list_services("").expect("the fake lists");

    let activity = detect(&ns_dir, &owned("aaaaaaaa", None), &listing, &reader);
    assert!(matches!(activity, ForeignActivity::ClaudeLock { .. }), "got {activity:?}");
}

#[test]
fn a_migrated_namespace_is_detected_under_either_spelling() {
    for (export, canonical, expected_sha) in
        [("aaaaaaaa", None, "aaaaaaaa"), ("aaaaaaaa", Some("bbbbbbbb"), "bbbbbbbb")]
    {
        let (_dir, ns_dir) = namespace();
        let service = format!("{}-{expected_sha}", namespace::LIVE_SERVICE);
        let reader = FakeReader::unlocked().with_item(&service, b"{}");
        let listing = reader.list_services("").expect("the fake lists");

        let activity = detect(&ns_dir, &owned(export, canonical), &listing, &reader);
        assert_eq!(activity, ForeignActivity::MigratedToKeychain { service: service.clone() });
        assert_eq!(reader.reads(), vec![service], "only the listed service was read");
    }
}

#[test]
fn no_read_is_issued_when_the_listing_does_not_carry_the_service() {
    // Plan AC20: the dump listing gates the read, so a namespace that has not
    // migrated costs no `find-generic-password` at all.
    let (_dir, ns_dir) = namespace();
    let reader = FakeReader::unlocked().with_entry("Claude Code-credentials-99999999");
    let listing = reader.list_services("").expect("the fake lists");

    assert_eq!(
        detect(&ns_dir, &owned("aaaaaaaa", Some("bbbbbbbb")), &listing, &reader),
        ForeignActivity::None
    );
    assert!(reader.reads().is_empty(), "reads issued: {:?}", reader.reads());
}

#[test]
fn a_listed_item_that_has_since_vanished_is_not_a_migration() {
    let (_dir, ns_dir) = namespace();
    let service = format!("{}-aaaaaaaa", namespace::LIVE_SERVICE);
    let reader = FakeReader::unlocked().with_deleted_item(&service);

    let listing = reader.list_services("").expect("the fake lists");
    assert_eq!(detect(&ns_dir, &owned("aaaaaaaa", None), &listing, &reader), ForeignActivity::None);
    assert_eq!(reader.reads(), vec![service]);
}

#[test]
fn a_listed_item_that_cannot_be_read_fails_closed() {
    // Failing open here would mean writing into a namespace a Claude Code
    // session has migrated, which costs the user their session (invariant I2).
    let (_dir, ns_dir) = namespace();
    let service = format!("{}-aaaaaaaa", namespace::LIVE_SERVICE);
    let reader = FakeReader::unlocked().with_failure(&service, KeychainError::Locked);
    let listing = reader.list_services("").expect("the fake lists");

    assert_eq!(
        detect(&ns_dir, &owned("aaaaaaaa", None), &listing, &reader),
        ForeignActivity::MigratedToKeychain { service }
    );
}

#[test]
fn detection_survives_a_namespace_that_does_not_exist_yet() {
    // The legacy lock check canonicalizes the namespace, which fails before
    // the first login. That must not stop the other checks.
    let dir = TempDir::new().expect("a temporary directory");
    let ns_dir = dir.path().join("never-created");
    assert_eq!(
        detect(&ns_dir, &owned("aaaaaaaa", None), &[], &FakeReader::unlocked()),
        ForeignActivity::None
    );
}
