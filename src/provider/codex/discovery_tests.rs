use std::ffi::OsString;

use super::*;
use crate::provider::codex::testkit;

const OTHER_ACCT: &str = "99999999-2222-4333-8444-555555555555";

fn read_only(dir: &Path) -> CodexAccountRecord {
    let mut record = testkit::owned_record("user-0002", OTHER_ACCT);
    record.kind = CodexKind::HomeReadOnly { dir: dir.to_path_buf() };
    record
}

#[test]
fn sources_list_the_live_home_then_registry_rows_and_skip_forgotten_ones() {
    let (dir, paths) = testkit::store();
    let live = dir.path().join("live-codex");
    fs::create_dir(&live).expect("mkdir");
    let env = CodexEnv::new(Some(OsString::from(&live)), Some(dir.path().to_path_buf()));

    let owned = testkit::owned_record(testkit::USER, testkit::ACCT);
    let elsewhere = read_only(&dir.path().join("elsewhere"));
    let mut forgotten = testkit::owned_record("user-0003", testkit::ACCT);
    forgotten.forgotten = true;
    let mut invalid = testkit::owned_record(".locks", testkit::ACCT);
    invalid.chatgpt_user_id = ".locks".to_owned();
    let mut live_record = testkit::owned_record("user-0004", testkit::ACCT);
    live_record.kind = CodexKind::Live;
    let accounts = [owned, elsewhere, forgotten, invalid, live_record];

    let (rows, live_error) = sources(&paths, &accounts, &env, &Cancel::new());
    assert!(live_error.is_none(), "{live_error:?}");
    assert_eq!(rows.len(), 4, "{rows:?}");
    assert!(matches!(&rows[0], CodexSource::Live { home } if home.ends_with("live-codex")));
    assert!(matches!(
        &rows[1],
        CodexSource::Owned { owned, evidence: DaemonEvidence::None, .. }
            if owned.user() == testkit::USER
    ));
    assert!(
        matches!(&rows[2], CodexSource::HomeReadOnly { dir, .. } if dir.ends_with("elsewhere"))
    );
    assert!(matches!(&rows[3], CodexSource::InvalidOwned { .. }));
    assert_eq!(rows[0].record(), None);
    assert_eq!(rows[1].record().map(|r| r.chatgpt_user_id.as_str()), Some(testkit::USER));
    assert_eq!(rows[3].record().map(|r| r.chatgpt_user_id.as_str()), Some(".locks"));
}

#[test]
fn an_owned_row_carries_daemon_evidence_taken_without_a_lock() {
    let (dir, paths) = testkit::store();
    let record = testkit::owned_record(testkit::USER, testkit::ACCT);
    let daemon = paths
        .codex_namespace_dir(testkit::USER, testkit::ACCT)
        .expect("ids")
        .join("app-server-daemon");
    fs::create_dir_all(&daemon).expect("mkdir");
    fs::write(daemon.join("daemon.lock"), b"").expect("write");
    let env = CodexEnv::new(None, Some(dir.path().to_path_buf()));
    let accounts = [record];
    let (rows, _) = sources(&paths, &accounts, &env, &Cancel::new());
    assert!(
        rows.iter().any(|row| matches!(
            row,
            CodexSource::Owned { evidence: DaemonEvidence::ArtefactOnly, .. }
        )),
        "{rows:?}"
    );
}

#[test]
fn orphans_are_namespaces_without_records_records_without_credentials_and_stale_scratch() {
    let (_dir, paths) = testkit::store();
    let with_credentials = testkit::owned_record(testkit::USER, testkit::ACCT);
    testkit::write_0600(
        &paths.codex_namespace_dir(testkit::USER, testkit::ACCT).expect("ids").join("auth.json"),
        &testkit::fresh_auth_bytes(),
    );
    let without_credentials = testkit::owned_record("user-0005", testkit::ACCT);
    fs::create_dir_all(paths.codex_namespace_dir("user-0005", testkit::ACCT).expect("ids"))
        .expect("mkdir");
    fs::create_dir_all(paths.codex_namespace_dir("user-0009", OTHER_ACCT).expect("ids"))
        .expect("mkdir");

    let scratch_old = paths.codex_scratch_root().join("agctl-codex-login-old");
    let scratch_new = paths.codex_scratch_root().join("agctl-codex-login-new");
    fs::create_dir_all(&scratch_old).expect("mkdir");
    fs::create_dir_all(&scratch_new).expect("mkdir");
    fs::create_dir_all(paths.codex_scratch_root().join("not-a-login")).expect("mkdir");

    let accounts = [with_credentials, without_credentials];
    let now = SystemTime::now() + Duration::from_secs(10);
    assert_eq!(
        orphans(&paths, &accounts, now).expect("lists"),
        vec![
            Orphan::NamespaceWithoutRecord {
                user: "user-0009".to_owned(),
                acct: OTHER_ACCT.to_owned()
            },
            Orphan::RecordWithoutCredentials {
                user: "user-0005".to_owned(),
                acct: testkit::ACCT.to_owned()
            },
        ],
        "a fresh scratch home is a login in progress"
    );

    let later = SystemTime::now() + SCRATCH_STALE_AFTER + Duration::from_secs(60);
    let found = orphans(&paths, &accounts, later).expect("lists");
    let stale: Vec<&str> = found
        .iter()
        .filter_map(|orphan| match orphan {
            Orphan::StaleScratch { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(stale, ["agctl-codex-login-new", "agctl-codex-login-old"]);
}

#[test]
fn an_absent_codex_tree_has_no_orphans() {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = Paths::with_config_dir(dir.path().join("agctl"));
    assert_eq!(orphans(&paths, &[], SystemTime::now()).expect("lists"), Vec::new());
}
