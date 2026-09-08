//! The import parsers and planners, driven without a store or a keychain.
//!
//! Everything here is a pure function of its arguments, which is the point:
//! the decisions an import makes — which entries are accounts, which are
//! already known, which directory hashes to which keychain item — are settled
//! before anything is written, so they can be asserted on without writing
//! anything. The end-to-end half lives in `commands/import_tests.rs`.

use std::path::PathBuf;

use serde_json::json;
use tempfile::TempDir;

use super::*;
use crate::config::AccountKind;
use crate::config::new_record;
use crate::provider::claude::namespace::LIVE_SERVICE;
use crate::provider::claude::namespace::sha8;
use crate::secret::KeychainStatus;
use crate::secret::fake_reader::FakeReader;

/// The synthetic switcher file from plan AC10.
const FIXTURE: &str = include_str!("../../fixtures/claude/claude-switcher-accounts.json");

/// The first fixture account's UUID pair.
const FIRST_ACCT: &str = "aaaaaaaa-1111-2222-3333-444444444444";
const FIRST_ORG: &str = "bbbbbbbb-5555-6666-7777-888888888888";

/// The second fixture account, which names no organization.
const SECOND_ACCT: &str = "cccccccc-9999-0000-1111-222222222222";

fn fixture_path() -> PathBuf {
    PathBuf::from("fixtures/claude/claude-switcher-accounts.json")
}

fn parse_fixture() -> Vec<SwitcherAccount> {
    parse_switcher(FIXTURE.as_bytes(), &fixture_path())
        .expect("the shipped fixture should parse as a v2 switcher file")
}

/// A credential blob in Claude Code's shape (fact F40), naming an account.
fn blob(acct: &str, org: Option<&str>, email: &str) -> String {
    let mut token_account = json!({ "uuid": acct, "emailAddress": email });
    if let Some(org) = org {
        token_account["organizationUuid"] = json!(org);
        token_account["organizationName"] = json!("Imported Org");
    }
    json!({
        "claudeAiOauth": {
            "accessToken": "access-token",
            "refreshToken": "refresh-token",
            "expiresAt": 4_102_444_800_000_i64,
            "scopes": ["user:inference"],
            "tokenAccount": token_account,
        }
    })
    .to_string()
}

/// A blob with no `tokenAccount` at all — an older login (fact F4).
fn anonymous_blob() -> String {
    json!({
        "claudeAiOauth": {
            "accessToken": "access-token",
            "refreshToken": "refresh-token",
            "expiresAt": 4_102_444_800_000_i64,
            "scopes": ["user:inference"],
        }
    })
    .to_string()
}

fn records_of(plan: &ImportPlan) -> Vec<AccountRecord> {
    plan.records()
}

fn skips_of(plan: &ImportPlan) -> Vec<(String, String)> {
    plan.decisions
        .iter()
        .filter_map(|decision| match decision {
            Decision::Skipped { what, reason } => Some((what.clone(), reason.clone())),
            _ => None,
        })
        .collect()
}

fn warnings_of(plan: &ImportPlan) -> Vec<String> {
    plan.decisions
        .iter()
        .filter_map(|decision| match decision {
            Decision::Warning(text) => Some(text.clone()),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The switcher file
// ---------------------------------------------------------------------------

#[test]
fn the_fixture_holds_two_claude_accounts_and_three_codex_ones() {
    let accounts = parse_fixture();
    assert_eq!(accounts.len(), 5, "the fixture should carry five entries");
    let claude =
        accounts.iter().filter(|account| account.provider.as_deref() == Some("claude")).count();
    let codex =
        accounts.iter().filter(|account| account.provider.as_deref() == Some("codex")).count();
    assert_eq!((claude, codex), (2, 3));
}

#[test]
fn a_v1_file_is_refused_by_version_rather_than_guessed_at() {
    let document = json!({ "version": 1, "accounts": [] }).to_string();
    let err = parse_switcher(document.as_bytes(), &fixture_path())
        .expect_err("a v1 file should not be read as if it were v2");
    let message = err.to_string();
    assert!(message.contains("version 1"), "{message}");
    assert!(message.contains("version 2"), "{message}");
}

#[test]
fn a_file_with_no_version_is_refused() {
    let document = json!({ "accounts": [] }).to_string();
    let err = parse_switcher(document.as_bytes(), &fixture_path())
        .expect_err("a file that does not say which schema it is should be refused");
    assert!(err.to_string().contains("version"), "{err}");
}

#[test]
fn a_malformed_file_names_the_first_error() {
    let err = parse_switcher(b"{not json", &fixture_path())
        .expect_err("unparseable bytes should not produce an empty import");
    let message = err.to_string();
    assert!(message.contains("claude-switcher account file"), "{message}");
    assert!(message.contains("accounts.json"), "{message}");
}

#[test]
fn an_entry_missing_every_optional_field_still_parses() {
    let document = json!({ "version": 2, "accounts": [{}] }).to_string();
    let accounts = parse_switcher(document.as_bytes(), &fixture_path())
        .expect("a sparse entry belongs to the planner, not to the parser");
    assert_eq!(accounts.len(), 1);
    assert_eq!(
        accounts[0],
        SwitcherAccount { email: None, org_name: None, provider: None, oauth_account: None }
    );
}

#[test]
fn ac10_the_fixture_plans_two_metadata_accounts_and_skips_three_codex_ones() {
    let plan = plan_switcher(&parse_fixture(), &AgentctlConfig::default());
    let records = records_of(&plan);

    assert_eq!(records.len(), 2, "both claude entries should be recorded");
    assert!(
        records.iter().all(|record| matches!(
            &record.kind,
            AccountKind::Metadata { source } if source == SWITCHER_SOURCE
        )),
        "an imported switcher account holds no credential, so it is metadata: {records:?}"
    );
    assert_eq!(records[0].key(), (FIRST_ACCT, FIRST_ORG));
    assert_eq!(records[0].email.as_deref(), Some("first@example.com"));
    assert_eq!(records[0].org_name.as_deref(), Some("First Org"));

    // The second entry names no organization, so it lands under the
    // placeholder rather than being dropped or given a made-up one.
    assert_eq!(records[1].key(), (SECOND_ACCT, UNKNOWN_ORG));
    assert_eq!(records[1].org_name, None, "an empty `org_name` is not a name");

    let skips = skips_of(&plan);
    assert_eq!(skips.len(), 3);
    assert!(skips.iter().all(|(_, reason)| reason == "codex"), "{skips:?}");
    assert_eq!(plan.summary(), "imported 2, skipped 3 (codex), already known 0");
}

#[test]
fn an_account_already_in_the_registry_is_never_downgraded_to_metadata() {
    let mut config = AgentctlConfig::default();
    config.upsert(
        new_record(
            FIRST_ACCT.to_owned(),
            FIRST_ORG.to_owned(),
            AccountKind::Owned {
                export_spelling: "/tmp/ns".to_owned(),
                export_sha8: sha8("/tmp/ns"),
            },
        )
        .expect("a uuid pair should be a usable key"),
    );

    let plan = plan_switcher(&parse_fixture(), &config);
    assert_eq!(records_of(&plan).len(), 1, "only the unknown account should be recorded");
    let known: Vec<&str> = plan
        .decisions
        .iter()
        .filter_map(|decision| match decision {
            Decision::AlreadyKnown { kind, .. } => Some(*kind),
            _ => None,
        })
        .collect();
    assert_eq!(known, vec!["owned"]);
    assert_eq!(plan.summary(), "imported 1, skipped 3 (codex), already known 1");
}

#[test]
fn a_claude_entry_with_no_account_uuid_is_skipped_rather_than_keyed_by_its_email() {
    let document = json!({
        "version": 2,
        "accounts": [{ "email": "nobody@example.com", "provider": "claude", "oauth_account": null }],
    })
    .to_string();
    let accounts =
        parse_switcher(document.as_bytes(), &fixture_path()).expect("the file itself is valid");

    let plan = plan_switcher(&accounts, &AgentctlConfig::default());
    assert!(records_of(&plan).is_empty(), "an email address is not an account identifier (I13)");
    assert_eq!(
        skips_of(&plan),
        vec![("nobody@example.com".to_owned(), "no account uuid".to_owned())]
    );
}

#[test]
fn an_unknown_provider_is_skipped_under_its_own_name() {
    let document = json!({
        "version": 2,
        "accounts": [
            { "email": "a@example.com", "provider": "gemini" },
            { "email": "b@example.com" },
        ],
    })
    .to_string();
    let accounts = parse_switcher(document.as_bytes(), &fixture_path()).expect("valid file");

    let plan = plan_switcher(&accounts, &AgentctlConfig::default());
    assert_eq!(
        skips_of(&plan),
        vec![
            ("a@example.com".to_owned(), "gemini".to_owned()),
            ("b@example.com".to_owned(), "no provider".to_owned()),
        ]
    );
    assert_eq!(plan.summary(), "imported 0, skipped 2 (1 gemini, 1 no provider), already known 0");
}

#[test]
fn two_entries_naming_one_account_are_recorded_once() {
    let entry = json!({
        "email": "first@example.com",
        "provider": "claude",
        "oauth_account": { "accountUuid": FIRST_ACCT, "organizationUuid": FIRST_ORG },
    });
    let document = json!({ "version": 2, "accounts": [entry, entry] }).to_string();
    let accounts = parse_switcher(document.as_bytes(), &fixture_path()).expect("valid file");

    let plan = plan_switcher(&accounts, &AgentctlConfig::default());
    assert_eq!(records_of(&plan).len(), 1);
    assert_eq!(
        skips_of(&plan),
        vec![(format!("{FIRST_ACCT}/{FIRST_ORG}"), "duplicate".to_owned())]
    );
}

#[test]
fn an_account_uuid_that_is_not_a_usable_key_is_skipped_with_the_reason() {
    let document = json!({
        "version": 2,
        "accounts": [{
            "email": "evil@example.com",
            "provider": "claude",
            "oauth_account": { "accountUuid": "../../etc" },
        }],
    })
    .to_string();
    let accounts = parse_switcher(document.as_bytes(), &fixture_path()).expect("valid file");

    let plan = plan_switcher(&accounts, &AgentctlConfig::default());
    assert!(records_of(&plan).is_empty());
    let skips = skips_of(&plan);
    assert_eq!(skips.len(), 1);
    assert_eq!(skips[0].1, "unusable ids");
    assert!(skips[0].0.contains("evil@example.com"), "{skips:?}");
}

#[test]
fn the_default_path_is_the_switchers_own_hard_coded_one() {
    assert_eq!(
        default_switcher_path(Path::new("/home/example")),
        PathBuf::from("/home/example/.config/claude-switcher/accounts.json")
    );
}

// ---------------------------------------------------------------------------
// The keychain
// ---------------------------------------------------------------------------

/// A store whose live configuration directory is a real, resolvable path.
struct Env {
    _dir: TempDir,
    home: PathBuf,
    live_dir: PathBuf,
}

fn env() -> Env {
    let dir = TempDir::new().expect("a temporary directory should be creatable");
    let home = dir.path().join("home");
    let live_dir = home.join(".claude");
    std::fs::create_dir_all(&live_dir).expect("the fake live config dir should be creatable");
    Env { _dir: dir, home, live_dir }
}

impl Env {
    /// The environment a session with `CLAUDE_CONFIG_DIR` unset would see.
    fn view(&self) -> EnvView {
        EnvView::with_home(self.home.clone())
    }

    /// The service name Claude Code would give a session pointed at `dir`.
    fn service_for(&self, dir: &Path) -> String {
        format!("{LIVE_SERVICE}-{}", sha8(&dir.to_string_lossy()))
    }
}

#[test]
fn a_listed_item_naming_the_live_directorys_other_spelling_is_a_stale_sibling() {
    // The live store is reached through one spelling and resolves to another
    // — the situation on the reference machine, where `~/.claude` is a
    // symlink (fact F41). An item named after either spelling is the live
    // row's sibling, not a second account.
    let env = env();
    let canonical = std::fs::canonicalize(&env.live_dir).expect("the live dir should resolve");
    assert_ne!(canonical, env.live_dir, "the temporary directory should be reached through a link");

    let service = env.service_for(&canonical);
    let reader = FakeReader::unlocked()
        .with_item(&service, blob(FIRST_ACCT, Some(FIRST_ORG), "sibling@example.com").as_bytes());

    let plan = plan_keychain(
        &[],
        &reader.entries.clone(),
        &reader,
        &env.view(),
        &AgentctlConfig::default(),
    );

    let records = records_of(&plan);
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].kind,
        AccountKind::ConfigDirReadOnly { dir: PathBuf::new(), service, shares_live_dir: true }
    );
}

#[test]
fn ac19_a_named_directory_is_recorded_from_its_keychain_item() {
    let env = env();
    let other = env.home.join("work");
    std::fs::create_dir_all(&other).expect("the other config dir should be creatable");
    let service = env.service_for(&other);
    let reader = FakeReader::unlocked()
        .with_item(&service, blob(FIRST_ACCT, Some(FIRST_ORG), "work@example.com").as_bytes());

    let plan = plan_keychain(
        std::slice::from_ref(&other),
        &reader.entries.clone(),
        &reader,
        &env.view(),
        &AgentctlConfig::default(),
    );

    let records = records_of(&plan);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].key(), (FIRST_ACCT, FIRST_ORG));
    assert_eq!(records[0].email.as_deref(), Some("work@example.com"));
    assert_eq!(
        records[0].kind,
        AccountKind::ConfigDirReadOnly {
            dir: other,
            service: service.clone(),
            shares_live_dir: false,
        }
    );
    assert_eq!(reader.reads(), vec![service], "the item is read once, for its identity");
    assert!(warnings_of(&plan).is_empty());
}

#[test]
fn ac19_a_directory_with_no_keychain_item_is_reported_and_not_recorded() {
    let env = env();
    let missing = env.home.join("nothing-here");
    let reader = FakeReader::unlocked();

    let plan = plan_keychain(
        std::slice::from_ref(&missing),
        &[],
        &reader,
        &env.view(),
        &AgentctlConfig::default(),
    );

    assert!(records_of(&plan).is_empty());
    let skips = skips_of(&plan);
    assert_eq!(skips.len(), 1);
    assert_eq!(skips[0].1, "no keychain item");
    assert!(skips[0].0.contains(&missing.display().to_string()), "{skips:?}");
    assert!(skips[0].0.contains(&env.service_for(&missing)), "{skips:?}");
    assert!(reader.reads().is_empty(), "an item that is not listed is never read");
}

#[test]
fn ac19_an_alias_of_the_live_directory_is_warned_about_and_recorded_as_a_sibling() {
    let env = env();
    let alias = env.home.join("alias");
    std::os::unix::fs::symlink(&env.live_dir, &alias).expect("a symlink should be creatable");
    let service = env.service_for(&alias);
    let reader = FakeReader::unlocked()
        .with_item(&service, blob(SECOND_ACCT, None, "alias@example.com").as_bytes());

    let plan = plan_keychain(
        std::slice::from_ref(&alias),
        &reader.entries.clone(),
        &reader,
        &env.view(),
        &AgentctlConfig::default(),
    );

    let warnings = warnings_of(&plan);
    assert_eq!(warnings.len(), 1, "the alias should be called out: {plan:?}");
    assert!(warnings[0].contains("alias of the live config dir"), "{warnings:?}");

    let records = records_of(&plan);
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].kind,
        AccountKind::ConfigDirReadOnly { dir: alias, service, shares_live_dir: true }
    );
    assert_eq!(records[0].key(), (SECOND_ACCT, UNKNOWN_ORG));
}

#[test]
fn an_item_that_names_nobody_is_keyed_by_its_service_and_reads_identity_unknown() {
    let env = env();
    let other = env.home.join("anonymous");
    let service = env.service_for(&other);
    let reader = FakeReader::unlocked().with_item(&service, anonymous_blob().as_bytes());

    let plan = plan_keychain(
        &[other],
        &reader.entries.clone(),
        &reader,
        &env.view(),
        &AgentctlConfig::default(),
    );

    let records = records_of(&plan);
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].key(),
        (service.as_str(), UNKNOWN_ORG),
        "a directory is not an identity (I13), so the service name is the key"
    );
    assert!(plan.lines().iter().any(|line| line.contains("identity unknown")), "{plan:?}");
}

#[test]
fn naming_the_directory_the_live_session_uses_reports_the_live_row() {
    // `CLAUDE_CONFIG_DIR` is set, so the live item is itself a hashed one.
    // A `--claude-config-dir` naming that same directory hashes to the same
    // item, which is the live row rather than a second account.
    let env = env();
    let live = env.home.join("configured");
    let view = EnvView {
        securestorage_dir: None,
        config_dir: Some(live.to_string_lossy().into_owned()),
        home: env.home.clone(),
        oauth_token_set: false,
    };
    let reader = FakeReader::unlocked();

    let plan =
        plan_keychain(std::slice::from_ref(&live), &[], &reader, &view, &AgentctlConfig::default());

    assert!(records_of(&plan).is_empty());
    assert_eq!(
        plan.decisions,
        vec![Decision::AlreadyKnown { id: "live".to_owned(), kind: "live" }]
    );
    assert!(reader.reads().is_empty());
}

#[test]
fn an_empty_directory_argument_names_the_live_item_and_is_refused() {
    let env = env();
    let reader = FakeReader::unlocked();

    let plan =
        plan_keychain(&[PathBuf::new()], &[], &reader, &env.view(), &AgentctlConfig::default());

    assert!(records_of(&plan).is_empty());
    assert_eq!(skips_of(&plan)[0].1, "names the live keychain item");
}

#[test]
fn without_any_directory_every_unclaimed_credential_item_is_imported() {
    let env = env();
    let first = env.service_for(Path::new("/one"));
    let second = env.service_for(Path::new("/two"));
    let reader = FakeReader::unlocked()
        .with_item(&first, blob(FIRST_ACCT, Some(FIRST_ORG), "one@example.com").as_bytes())
        .with_item(&second, anonymous_blob().as_bytes())
        // The live item, which has its own row and is never a per-directory
        // account.
        .with_item(LIVE_SERVICE, blob(SECOND_ACCT, None, "live@example.com").as_bytes())
        // A legacy API-key item (fact F5): listed, classified, and dropped.
        .with_entry("Claude Code-86c75be7");

    let plan = plan_keychain(
        &[],
        &reader.entries.clone(),
        &reader,
        &env.view(),
        &AgentctlConfig::default(),
    );

    let records = records_of(&plan);
    assert_eq!(records.len(), 2, "the live item and the legacy key are not imported: {records:?}");
    assert_eq!(records[0].key(), (FIRST_ACCT, FIRST_ORG));
    assert_eq!(records[1].key(), (second.as_str(), UNKNOWN_ORG));
    assert!(
        !reader.reads().contains(&LIVE_SERVICE.to_owned()),
        "the live item is claimed, so it is not read here: {:?}",
        reader.reads()
    );
    assert!(
        !reader.reads().iter().any(|service| service.starts_with("Claude Code-8")),
        "a legacy API-key item is never read: {:?}",
        reader.reads()
    );
}

#[test]
fn a_service_a_record_already_claims_is_reported_rather_than_imported_twice() {
    let env = env();
    let other = env.home.join("work");
    let service = env.service_for(&other);
    let mut config = AgentctlConfig::default();
    config.upsert(
        new_record(
            FIRST_ACCT.to_owned(),
            FIRST_ORG.to_owned(),
            AccountKind::ConfigDirReadOnly {
                dir: other.clone(),
                service: service.clone(),
                shares_live_dir: false,
            },
        )
        .expect("a uuid pair should be a usable key"),
    );
    let reader = FakeReader::unlocked()
        .with_item(&service, blob(FIRST_ACCT, Some(FIRST_ORG), "work@example.com").as_bytes());

    let plan = plan_keychain(&[other], &reader.entries.clone(), &reader, &env.view(), &config);

    assert!(records_of(&plan).is_empty());
    assert_eq!(plan.summary(), "imported 0, skipped 0, already known 1");
    assert!(reader.reads().is_empty(), "a claimed service is not even read");
}

#[test]
fn an_unreadable_item_still_records_the_service_it_could_not_identify() {
    let env = env();
    let other = env.home.join("gone");
    let service = env.service_for(&other);
    // Listed by the dump but deleted before the read: the snapshot went stale
    // mid-pass, which is a normal race, not a failure.
    let reader = FakeReader::unlocked().with_deleted_item(&service);

    let plan = plan_keychain(
        &[other],
        &reader.entries.clone(),
        &reader,
        &env.view(),
        &AgentctlConfig::default(),
    );

    let records = records_of(&plan);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].account_uuid, service);
}

#[test]
fn a_locked_keychain_is_the_callers_problem_not_the_planners() {
    // The planner has no preflight of its own; the command refuses before
    // calling it. Proven here by driving it with a reader that answers
    // nothing: no record, no panic, no invented identity.
    let env = env();
    let reader = FakeReader::unlocked().with_preflight(KeychainStatus::Locked);
    let plan = plan_keychain(&[], &[], &reader, &env.view(), &AgentctlConfig::default());
    assert_eq!(plan.summary(), "imported 0, skipped 0, already known 0");
}
