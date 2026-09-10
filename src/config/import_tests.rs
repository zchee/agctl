//! The import parsers and planners, driven without a store or a keychain.
//!
//! Everything here is a pure function of its arguments, which is the point:
//! the decisions an import makes — which items are accounts, which are
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

/// An account and organization UUID pair, in the shape Anthropic issues.
const FIRST_ACCT: &str = "aaaaaaaa-1111-2222-3333-444444444444";
const FIRST_ORG: &str = "bbbbbbbb-5555-6666-7777-888888888888";

/// A second account, used where the keychain item names no organization.
const SECOND_ACCT: &str = "cccccccc-9999-0000-1111-222222222222";

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

    let plan =
        plan_keychain(&[], &reader.entries.clone(), &reader, &env.view(), &AgctlConfig::default());

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
        &AgctlConfig::default(),
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
        &AgctlConfig::default(),
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
        &AgctlConfig::default(),
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
        &AgctlConfig::default(),
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
        plan_keychain(std::slice::from_ref(&live), &[], &reader, &view, &AgctlConfig::default());

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

    let plan = plan_keychain(&[PathBuf::new()], &[], &reader, &env.view(), &AgctlConfig::default());

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

    let plan =
        plan_keychain(&[], &reader.entries.clone(), &reader, &env.view(), &AgctlConfig::default());

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
    let mut config = AgctlConfig::default();
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
        &AgctlConfig::default(),
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
    let plan = plan_keychain(&[], &[], &reader, &env.view(), &AgctlConfig::default());
    assert_eq!(plan.summary(), "imported 0, skipped 0, already known 0");
}
