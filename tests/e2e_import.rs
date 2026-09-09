#![cfg(feature = "testing")]

//! `agentctl claude import --from keychain`, driven through the real binary.
//!
//! Decision D-010 removed the `claude-switcher` importer, so the keychain is
//! the only source left and plan AC10 keeps its dry-run and idempotency
//! halves. What both halves are really about is decision D-009: an import
//! *records* accounts. It never copies a credential, never writes a keychain
//! item, and never turns an account the user has logged into back into a
//! read-only row.

mod common;

use std::fs;

use common::Fixture;
use common::LIVE_SERVICE;
use predicates::str::contains;
use serde_json::Value;

/// Two per-configuration-directory items, under distinct accounts.
const FIRST_SERVICE: &str = "Claude Code-credentials-11112222";
const SECOND_SERVICE: &str = "Claude Code-credentials-33334444";
const FIRST_ACCT: &str = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
const SECOND_ACCT: &str = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb";
const ORG_A: &str = "cccccccc-3333-4333-8333-cccccccccccc";
const ORG_B: &str = "dddddddd-4444-4444-8444-dddddddddddd";

/// A keychain holding the live item and two importable ones.
fn keychain_store() -> Fixture {
    let mut fixture = Fixture::new();
    fixture.with_keychain();
    fixture.dump(&[LIVE_SERVICE, FIRST_SERVICE, SECOND_SERVICE]);
    fixture.keychain_item(
        LIVE_SERVICE,
        &common::blob("sk-ant-oat01-live", "sk-ant-ort01-live", common::fresh_at()),
    );
    fixture.keychain_item(
        FIRST_SERVICE,
        &common::identified_blob(
            "sk-ant-oat01-first",
            "sk-ant-ort01-first",
            common::fresh_at(),
            FIRST_ACCT,
            Some(ORG_A),
        ),
    );
    fixture.keychain_item(
        SECOND_SERVICE,
        &common::identified_blob(
            "sk-ant-oat01-second",
            "sk-ant-ort01-second",
            common::fresh_at(),
            SECOND_ACCT,
            Some(ORG_B),
        ),
    );
    fixture
}

#[test]
fn ac10_a_dry_run_reports_the_plan_and_writes_nothing() {
    // Plan AC10: `--dry-run` reaches neither the registry nor anything else,
    // which is why it leaves a store that did not exist still not existing.
    let fixture = keychain_store();

    fixture
        .cmd()
        .args(["claude", "import", "--from", "keychain", "--dry-run"])
        .assert()
        .success()
        .stdout(contains("import config-dir-read-only"))
        .stdout(contains(FIRST_ACCT))
        .stdout(contains(SECOND_ACCT))
        .stdout(contains("imported 2"))
        .stdout(contains("--dry-run: nothing was written"));

    assert!(!fixture.config_file().exists(), "a dry run writes no registry");
    fixture.assert_keychain_read_only();
}

#[test]
fn ac10_a_second_import_is_a_no_op() {
    // Decision D-007, carried over to the keychain source: an account already
    // in the registry is reported and left alone, whatever kind it is. That is
    // what makes re-running this safe rather than a way to downgrade a
    // logged-in account to a read-only row.
    let fixture = keychain_store();

    fixture
        .cmd()
        .args(["claude", "import", "--from", "keychain"])
        .assert()
        .success()
        .stdout(contains("imported 2"));
    let first = fs::read(fixture.config_file()).expect("the registry should exist");

    // The two services are claimed by the records the first run wrote, so the
    // second run considers nothing at all — which is the strongest form of
    // "no-op" available: not "decided to change nothing" but "had nothing to
    // decide about".
    fixture
        .cmd()
        .args(["claude", "import", "--from", "keychain"])
        .assert()
        .success()
        .stdout(contains("imported 0, skipped 0, already known 0"));

    assert_eq!(
        fs::read(fixture.config_file()).expect("readable"),
        first,
        "a second import produces a byte-identical registry"
    );
    fixture.assert_keychain_read_only();
}

#[test]
fn ac10_an_import_never_downgrades_a_logged_in_account() {
    // Decision D-007's real point. The item in the keychain and the account
    // agentctl owns are the same account, reached two ways. Recording the
    // keychain one would turn a refreshable account into a read-only row, so
    // the import reports it and stops.
    let mut fixture = Fixture::new();
    fixture.with_keychain();

    let foreign_dir = fixture.home().join("other-claude");
    fs::create_dir_all(&foreign_dir).expect("the directory should be creatable");
    let spelling = common::export_spelling(&foreign_dir);
    let service = format!("{LIVE_SERVICE}-{}", common::sha8(&spelling));
    fixture.dump(&[&service]);
    fixture.keychain_item(
        &service,
        &common::identified_blob(
            "sk-ant-oat01-same",
            "sk-ant-ort01-same",
            common::fresh_at(),
            FIRST_ACCT,
            Some(ORG_A),
        ),
    );
    fixture.write_registry(vec![fixture.owned_record(FIRST_ACCT, ORG_A)]);

    fixture
        .cmd()
        .args(["claude", "import", "--from", "keychain", "--claude-config-dir", &spelling])
        .assert()
        .success()
        .stdout(contains("already known as owned"))
        .stdout(contains("imported 0"));

    let config: Value =
        serde_json::from_str(&fs::read_to_string(fixture.config_file()).expect("readable"))
            .expect("the registry is JSON");
    assert_eq!(config["accounts"].as_array().expect("an array").len(), 1);
    assert_eq!(
        config["accounts"][0]["kind"]["kind"],
        serde_json::json!("owned"),
        "the logged-in account kept its kind"
    );
    fixture.assert_keychain_read_only();
}

#[test]
fn ac19_an_import_records_in_place_and_writes_nothing_else() {
    // Plan AC19, decision D-009 and invariant I1: the credentials stay exactly
    // where they were — in the login keychain, which phase 1 never writes —
    // and the only thing that changes on disk is agentctl's own registry.
    let fixture = keychain_store();
    let before = fixture.keychain_items();

    fixture.cmd().args(["claude", "import", "--from", "keychain"]).assert().success();

    let config: Value =
        serde_json::from_str(&fs::read_to_string(fixture.config_file()).expect("readable"))
            .expect("the registry is JSON");
    let accounts = config["accounts"].as_array().expect("an array");
    assert_eq!(accounts.len(), 2);
    for record in accounts {
        assert_eq!(record["kind"]["kind"], serde_json::json!("config_dir_read_only"));
        assert!(
            record["kind"]["service"].as_str().is_some_and(|s| s.starts_with(LIVE_SERVICE)),
            "the record points at the keychain item rather than copying it: {record}"
        );
    }

    let after = fixture.keychain_items();
    assert_eq!(after, before, "no keychain item was added, changed or removed");
    assert!(
        !fixture.config_dir().join("claude").join(FIRST_ACCT).exists(),
        "no credential was copied into the store"
    );
    fixture.assert_keychain_read_only();
}

#[test]
fn ac19_an_alias_of_the_live_directory_is_warned_about() {
    // Plan AC19's last clause, and fact F41: on the reference machine
    // `~/.claude` is a symlink, so a directory the user names on the command
    // line can turn out to be the live store under another spelling. It is
    // recorded — under the name it was given, because that spelling is what
    // the keychain item is named after — but flagged, because its credentials
    // are the live account's and refreshing it is not agentctl's business.
    let mut fixture = Fixture::new();
    fixture.with_keychain();

    let real = fixture.home().join("real-claude");
    fs::create_dir_all(&real).expect("the real store directory should be creatable");
    std::os::unix::fs::symlink(&real, fixture.live_store_dir())
        .expect("`~/.claude` should be linkable");

    let spelling = common::export_spelling(&real);
    let service = format!("{LIVE_SERVICE}-{}", common::sha8(&spelling));
    fixture.dump(&[LIVE_SERVICE, &service]);
    fixture.keychain_item(
        LIVE_SERVICE,
        &common::blob("sk-ant-oat01-live", "sk-ant-ort01-live", common::fresh_at()),
    );
    fixture.keychain_item(
        &service,
        &common::identified_blob(
            "sk-ant-oat01-alias",
            "sk-ant-ort01-alias",
            common::fresh_at(),
            FIRST_ACCT,
            Some(ORG_A),
        ),
    );

    fixture
        .cmd()
        .args(["claude", "import", "--from", "keychain", "--claude-config-dir", &spelling])
        .assert()
        .success()
        .stdout(contains("warning:"))
        .stdout(contains("alias of the live config dir"))
        .stdout(contains("stale sibling"));

    let config: Value =
        serde_json::from_str(&fs::read_to_string(fixture.config_file()).expect("readable"))
            .expect("the registry is JSON");
    assert_eq!(config["accounts"][0]["kind"]["shares_live_dir"], serde_json::json!(true));
    assert_eq!(
        config["accounts"][0]["kind"]["dir"],
        serde_json::json!(spelling),
        "the spelling as given is recorded, not where it resolves to (fact F14, risk R20)"
    );
    fixture.assert_keychain_read_only();
}
