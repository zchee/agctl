//! Tests for the account registry (plan AC28's config half).

use std::os::unix::fs::PermissionsExt;

use tempfile::TempDir;

use super::*;

fn store() -> (TempDir, Paths) {
    let dir = TempDir::new().expect("a temporary directory should be available");
    let paths = Paths::with_config_dir(dir.path().join("agctl"));
    (dir, paths)
}

fn owned(acct: &str, org: &str) -> AccountRecord {
    let mut record = new_record(
        acct.to_owned(),
        org.to_owned(),
        AccountKind::Owned {
            export_spelling: format!("/store/claude/{acct}/{org}"),
            export_sha8: "aaaaaaaa".to_owned(),
        },
    )
    .expect("the identifiers should be valid");
    record.email = Some(format!("{acct}@example.com"));
    record
}

#[test]
fn an_absent_file_loads_as_an_empty_registry() {
    let (_dir, paths) = store();
    let config = AgctlConfig::load(&paths).expect("an absent file is not an error");
    assert_eq!(config, AgctlConfig::default());
    assert_eq!(config.version, CONFIG_VERSION);
    assert!(config.accounts.is_empty());
}

#[test]
fn saving_and_loading_round_trips_every_kind() {
    let (_dir, paths) = store();
    let mut config = AgctlConfig::default();
    config.upsert(owned("acct-1", "org-1"));
    config.upsert(
        new_record("acct-2".to_owned(), paths::UNKNOWN_ORG.to_owned(), AccountKind::Live)
            .expect("valid"),
    );
    config.upsert(
        new_record(
            "acct-3".to_owned(),
            "org-3".to_owned(),
            AccountKind::ConfigDirReadOnly {
                dir: PathBuf::from("/elsewhere"),
                service: "Claude Code-credentials-5cdc535f".to_owned(),
                shares_live_dir: true,
            },
        )
        .expect("valid"),
    );
    config.upsert(
        new_record(
            "acct-4".to_owned(),
            "org-4".to_owned(),
            AccountKind::Foreign { source: "claude-switcher".to_owned() },
        )
        .expect("valid"),
    );

    let saved = config.clone();
    AgctlConfig::update(&paths, |registry| *registry = config).expect("the registry should save");
    let loaded = AgctlConfig::load(&paths).expect("the registry should load");
    assert_eq!(loaded, saved);
}

#[test]
fn the_saved_file_is_0600_and_the_lock_file_stays() {
    let (_dir, paths) = store();
    AgctlConfig::update(&paths, |_| ()).expect("the registry should save");

    let mode =
        std::fs::metadata(paths.config_file()).expect("the file exists").permissions().mode();
    assert_eq!(mode & 0o777, paths::FILE_MODE);
    assert!(paths.config_lock().exists(), "the lock file is created once and never unlinked");
}

#[test]
fn saving_twice_leaves_no_temporary_file() {
    let (_dir, paths) = store();
    AgctlConfig::update(&paths, |_| ()).expect("the first save should succeed");
    AgctlConfig::update(&paths, |registry| registry.upsert(owned("acct-1", "org-1")))
        .expect("the second save should succeed");

    let strays: Vec<_> = std::fs::read_dir(paths.config_dir())
        .expect("the store should be listable")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains(".tmp."))
        .collect();
    assert!(strays.is_empty(), "left behind: {strays:?}");
}

#[test]
fn a_future_version_is_refused_rather_than_misread() {
    let (_dir, paths) = store();
    paths.ensure_dirs().expect("directories should be creatable");
    std::fs::write(paths.config_file(), br#"{"version": 99, "accounts": []}"#)
        .expect("the file should be writable");

    let err = AgctlConfig::load(&paths).expect_err("a newer schema should not be guessed at");
    assert!(err.to_string().contains("version 99"), "{err}");
}

#[test]
fn a_corrupt_file_is_refused() {
    let (_dir, paths) = store();
    paths.ensure_dirs().expect("directories should be creatable");
    std::fs::write(paths.config_file(), b"{not json").expect("the file should be writable");
    assert!(AgctlConfig::load(&paths).is_err());
}

#[test]
fn upsert_replaces_by_account_and_organization() {
    let mut config = AgctlConfig::default();
    config.upsert(owned("acct-1", "org-1"));
    config.upsert(owned("acct-1", "org-2"));
    assert_eq!(config.accounts.len(), 2, "a second organization is a second namespace (D-008)");

    let mut replacement = owned("acct-1", "org-1");
    replacement.label = Some("work".to_owned());
    config.upsert(replacement);
    assert_eq!(config.accounts.len(), 2, "the same key replaces rather than duplicating");
    assert_eq!(config.get("acct-1", "org-1").and_then(|rec| rec.label.as_deref()), Some("work"));
}

#[test]
fn resolve_id_accepts_a_uuid_a_pair_a_label_and_an_email() {
    let mut config = AgctlConfig::default();
    config.upsert(owned("acct-1", "org-1"));
    let mut labelled = owned("acct-2", "org-2");
    labelled.label = Some("work".to_owned());
    config.upsert(labelled);

    for id in ["acct-1", "acct-1/org-1", "acct-1@example.com"] {
        let record = config.resolve_id(id).unwrap_or_else(|err| panic!("`{id}`: {err}"));
        assert_eq!(record.key(), ("acct-1", "org-1"));
    }
    assert_eq!(config.resolve_id("work").expect("a label resolves").key(), ("acct-2", "org-2"));
}

#[test]
fn resolve_id_reports_an_ambiguous_account_with_its_candidates() {
    let mut config = AgctlConfig::default();
    config.upsert(owned("acct-1", "org-1"));
    config.upsert(owned("acct-1", "org-2"));

    let err = config.resolve_id("acct-1").expect_err("two organizations are ambiguous");
    let message = err.to_string();
    assert!(message.contains("acct-1/org-1"), "{message}");
    assert!(message.contains("acct-1/org-2"), "{message}");

    // The unambiguous spelling still works.
    assert_eq!(
        config.resolve_id("acct-1/org-2").expect("the pair resolves").key(),
        ("acct-1", "org-2")
    );
}

#[test]
fn resolve_id_reports_an_unknown_id() {
    let config = AgctlConfig::default();
    assert!(config.resolve_id("nobody").is_err());
}

#[test]
fn display_id_shortens_to_the_uuid_only_when_it_is_unique() {
    let unique = vec![owned("acct-1", "org-1"), owned("acct-2", "org-2")];
    assert_eq!(unique[0].display_id(&unique), "acct-1");

    let duplicated = vec![owned("acct-1", "org-1"), owned("acct-1", "org-2")];
    assert_eq!(duplicated[0].display_id(&duplicated), "acct-1/org-1");
}

#[test]
fn new_record_refuses_an_identifier_that_would_escape_the_namespace_root() {
    for (acct, org) in [("..", "org"), ("acct", "../.."), ("a/b", "org")] {
        assert!(
            new_record(acct.to_owned(), org.to_owned(), AccountKind::Live).is_err(),
            "({acct}, {org}) should be refused"
        );
    }
}

#[test]
fn new_record_stamps_an_rfc3339_creation_time() {
    let record = owned("acct-1", "org-1");
    assert!(record.created_at.ends_with('Z'), "{}", record.created_at);
    assert!(record.created_at.contains('T'), "{}", record.created_at);
    assert!(!record.forgotten);
}

#[test]
fn the_serialized_shape_tags_the_kind() {
    let record = owned("acct-1", "org-1");
    let json = serde_json::to_value(&record).expect("the record should serialize");
    assert_eq!(json["kind"]["kind"], "owned");
    assert_eq!(json["kind"]["export_sha8"], "aaaaaaaa");
    assert_eq!(json["forgotten"], false);

    let live = serde_json::to_value(AccountKind::Live).expect("the kind should serialize");
    assert_eq!(live, serde_json::json!({"kind": "live"}));
    let config_dir = serde_json::to_value(AccountKind::ConfigDirReadOnly {
        dir: PathBuf::from("/x"),
        service: "svc".to_owned(),
        shares_live_dir: false,
    })
    .expect("the kind should serialize");
    assert_eq!(config_dir["kind"], "config_dir_read_only");
}

#[test]
fn two_concurrent_updates_both_land() {
    // The reason `save` is not public. `flock` is per open file description,
    // so a load-outside/save-inside pair would let each thread write a
    // registry it read before the other thread's record existed, and the
    // later write would erase the earlier one. `update` re-reads inside the
    // lock, so the second thread sees the first thread's record and adds to
    // it.
    let (_dir, paths) = store();
    paths.ensure_dirs().expect("directories should be creatable");

    std::thread::scope(|scope| {
        for acct in ["acct-1", "acct-2"] {
            let paths = &paths;
            scope.spawn(move || {
                AgctlConfig::update(paths, |registry| registry.upsert(owned(acct, "org")))
                    .unwrap_or_else(|err| panic!("`{acct}` should have been written: {err}"));
            });
        }
    });

    let loaded = AgctlConfig::load(&paths).expect("the registry should load");
    let mut accounts: Vec<&str> =
        loaded.accounts.iter().map(|record| record.account_uuid.as_str()).collect();
    accounts.sort_unstable();
    assert_eq!(accounts, ["acct-1", "acct-2"], "one update overwrote the other");
}

#[test]
fn update_returns_the_closure_s_value_and_persists_the_change() {
    let (_dir, paths) = store();
    let key = AgctlConfig::update(&paths, |registry| {
        registry.upsert(owned("acct-1", "org-1"));
        registry.accounts.len()
    })
    .expect("the registry should save");
    assert_eq!(key, 1, "the closure's value is handed back once the write succeeded");

    let loaded = AgctlConfig::load(&paths).expect("the registry should load");
    assert_eq!(loaded.get("acct-1", "org-1").map(AccountRecord::key), Some(("acct-1", "org-1")));
}
