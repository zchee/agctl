//! Tests for discovery (plan AC18, AC39, AC42, AC34's discovery half).
//!
//! The scenario these are built around is the development machine, because it
//! is the one that breaks naive implementations: `~/.claude` is a symlink,
//! the live keychain item and the item named after the link's *target* both
//! exist, and they hold **different** credentials (facts F6, F41). Anything
//! that folds rows by path merges two accounts; anything that folds by
//! nothing at all shows a phantom second account.

use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

use tempfile::TempDir;

use super::*;
use crate::config::new_record;
use crate::runtime::coordinator::Cancel;
use crate::secret::KeychainError;
use crate::secret::fake_reader::FakeReader;

const LIVE_BLOB: &[u8] = br#"{"claudeAiOauth":{"accessToken":"live-access","refreshToken":"live-refresh","expiresAt":9999999999999,"tokenAccount":{"uuid":"11111111-1111-4111-8111-111111111111","emailAddress":"live@example.com","organizationUuid":"22222222-2222-4222-8222-222222222222"}}}"#;

const OTHER_BLOB: &[u8] = br#"{"claudeAiOauth":{"accessToken":"other-access","refreshToken":"other-refresh","expiresAt":9999999999999,"tokenAccount":{"uuid":"33333333-3333-4333-8333-333333333333","emailAddress":"other@example.com","organizationUuid":"44444444-4444-4444-8444-444444444444"}}}"#;

/// A blob with no `tokenAccount`, which is what an older Claude Code wrote.
const OLD_BLOB: &[u8] =
    br#"{"claudeAiOauth":{"accessToken":"old-access","refreshToken":"old-refresh","expiresAt":9999999999999}}"#;

fn ctx() -> PassCtx {
    PassCtx::standalone(Cancel::new(), Instant::now() + Duration::from_secs(30))
}

fn store() -> (TempDir, Paths) {
    let dir = TempDir::new().expect("a temporary directory should be available");
    let paths = Paths::with_config_dir(dir.path().join("agentctl"));
    (dir, paths)
}

fn env_in(home: &std::path::Path) -> EnvView {
    EnvView::with_home(home.to_path_buf())
}

fn row<'a>(discovery: &'a Discovery, id: &str) -> &'a AccountRow {
    discovery
        .rows
        .iter()
        .find(|row| row.id == id)
        .unwrap_or_else(|| panic!("no row `{id}` in {:?}", ids(discovery)))
}

fn ids(discovery: &Discovery) -> Vec<&str> {
    discovery.rows.iter().map(|row| row.id.as_str()).collect()
}

#[test]
fn a_live_item_becomes_one_row_with_its_identity() {
    let (dir, paths) = store();
    let env = env_in(dir.path());
    let reader = FakeReader::unlocked().with_item(namespace::LIVE_SERVICE, LIVE_BLOB);

    let discovery = discover(&AgentctlConfig::default(), &paths, &reader, &env, &ctx());
    assert_eq!(discovery.preflight, KeychainStatus::Unlocked);
    assert_eq!(discovery.rows.len(), 1, "{:?}", ids(&discovery));

    let live = &discovery.rows[0];
    assert_eq!(live.id, "11111111-1111-4111-8111-111111111111");
    assert_eq!(live.state, AccountState::Ok);
    assert_eq!(live.source, Source::Keychain);
    assert!(live.visible_by_default);
    assert!(live.credentials.is_some());
    assert_eq!(live.record.email.as_deref(), Some("live@example.com"));
    assert_eq!(live.record.organization_uuid, "22222222-2222-4222-8222-222222222222");
    assert!(live.note.as_deref().is_some_and(|note| note.contains(namespace::LIVE_SERVICE)));
}

#[test]
fn the_sibling_of_the_live_directory_is_hidden_and_never_folded() {
    // Plan AC18 and AC42: `~/.claude` is a symlink, so the item named after
    // the resolved directory shares the live directory. Different digests,
    // so it is a stale sibling — hidden, and counted in the footer.
    let (dir, paths) = store();
    let real = dir.path().join("agent-claude");
    std::fs::create_dir_all(&real).expect("directories should be creatable");
    std::os::unix::fs::symlink(&real, dir.path().join(".claude"))
        .expect("the symlink should be creatable");

    let env = env_in(dir.path());
    // Named after the *resolved* directory, which is how the machine this was
    // developed against looks: `~/.claude` is a link and `…-5cdc535f` is the
    // hash of the target's own spelling (fact F41). A temporary directory adds
    // one more link — `/var` to `/private/var` on macOS — so the spelling is
    // taken after resolution rather than assumed.
    let resolved = namespace::canonical(&real).expect("the target resolves");
    let sibling_sha8 = namespace::sha8(&namespace::export_spelling(&resolved));
    let sibling_service = format!("{}-{sibling_sha8}", namespace::LIVE_SERVICE);
    let reader = FakeReader::unlocked()
        .with_item(namespace::LIVE_SERVICE, LIVE_BLOB)
        .with_item(&sibling_service, OTHER_BLOB);

    let discovery = discover(&AgentctlConfig::default(), &paths, &reader, &env, &ctx());
    assert_eq!(discovery.rows.len(), 2, "{:?}", ids(&discovery));

    let sibling = row(&discovery, "33333333-3333-4333-8333-333333333333");
    assert_eq!(sibling.state, AccountState::StaleSiblingOfLive);
    assert!(!sibling.visible_by_default, "hidden without --all");
}

#[test]
fn an_identical_blob_under_a_second_name_folds_into_the_live_row() {
    // The other half of plan AC42: same digests means the same account, and
    // one row is the honest answer.
    let (dir, paths) = store();
    let real = dir.path().join("agent-claude");
    std::fs::create_dir_all(&real).expect("directories should be creatable");
    std::os::unix::fs::symlink(&real, dir.path().join(".claude"))
        .expect("the symlink should be creatable");

    let env = env_in(dir.path());
    let resolved = namespace::canonical(&real).expect("the target resolves");
    let sibling_sha8 = namespace::sha8(&namespace::export_spelling(&resolved));
    let reader = FakeReader::unlocked()
        .with_item(namespace::LIVE_SERVICE, LIVE_BLOB)
        .with_item(&format!("{}-{sibling_sha8}", namespace::LIVE_SERVICE), LIVE_BLOB);

    let discovery = discover(&AgentctlConfig::default(), &paths, &reader, &env, &ctx());
    assert_eq!(discovery.rows.len(), 1, "{:?}", ids(&discovery));
}

#[test]
fn an_unclaimed_item_is_shown_and_a_legacy_key_is_ignored() {
    // Plan AC18: `6cdd6b98` is unclaimed and visible; the legacy
    // `Claude Code-<sha8>` API-key item classifies as nothing at all.
    let (dir, paths) = store();
    let env = env_in(dir.path());
    let reader = FakeReader::unlocked()
        .with_item(namespace::LIVE_SERVICE, LIVE_BLOB)
        .with_item("Claude Code-credentials-6cdd6b98", OTHER_BLOB)
        .with_entry("Claude Code-86c75be7");

    let discovery = discover(&AgentctlConfig::default(), &paths, &reader, &env, &ctx());
    assert_eq!(discovery.rows.len(), 2, "{:?}", ids(&discovery));

    let unclaimed = row(&discovery, "33333333-3333-4333-8333-333333333333");
    assert_eq!(unclaimed.state, AccountState::Unclaimed);
    assert!(unclaimed.visible_by_default);
    assert!(!discovery.rows.iter().any(|row| row.id.contains("86c75be7")));
    assert!(
        !reader.reads().iter().any(|service| service == "Claude Code-86c75be7"),
        "the legacy item is never read: {:?}",
        reader.reads()
    );
}

#[test]
fn an_old_blob_in_a_foreign_directory_is_identity_unknown_and_shown() {
    // Plan AC39: no `tokenAccount`, and a path is not identity (I13). The
    // row stays visible because the fix — log in — is actionable.
    let (dir, paths) = store();
    let env = env_in(dir.path());
    let reader = FakeReader::unlocked()
        .with_item(namespace::LIVE_SERVICE, LIVE_BLOB)
        .with_item("Claude Code-credentials-6cdd6b98", OLD_BLOB);

    let discovery = discover(&AgentctlConfig::default(), &paths, &reader, &env, &ctx());
    let unknown = row(&discovery, "Claude Code-credentials-6cdd6b98");
    assert_eq!(unknown.state, AccountState::IdentityUnknown);
    assert!(unknown.visible_by_default);
    assert_eq!(unknown.record.account_uuid, "", "no identity was invented from the path");
}

#[test]
fn a_switcher_item_is_listed_hidden_and_never_read() {
    // Fact F10: `claude-account-switcher` rewrites the live item on every
    // switch. agentctl reports its items exist and touches nothing.
    let (dir, paths) = store();
    let env = env_in(dir.path());
    let reader = FakeReader::unlocked()
        .with_item(namespace::LIVE_SERVICE, LIVE_BLOB)
        .with_entry("claude-switcher:alice@example.com");

    let discovery = discover(&AgentctlConfig::default(), &paths, &reader, &env, &ctx());
    let foreign = row(&discovery, "claude-switcher:alice@example.com");
    assert!(!foreign.visible_by_default);
    assert_eq!(foreign.source, Source::None);
    assert_eq!(foreign.record.email.as_deref(), Some("alice@example.com"));
    assert!(foreign.note.as_deref().is_some_and(|note| note.contains("claude-account-switcher")));
    assert!(
        !reader.reads().iter().any(|service| service.starts_with("claude-switcher:")),
        "reads: {:?}",
        reader.reads()
    );
}

#[test]
fn the_live_row_falls_back_to_claude_json_for_its_identity() {
    // Fact F33: `.claude.json` records the last login through this config
    // directory, which is evidence about the live row and nothing else.
    let (dir, paths) = store();
    let env = env_in(dir.path());
    std::fs::write(
        dir.path().join(".claude.json"),
        br#"{"oauthAccount":{"accountUuid":"55555555-5555-4555-8555-555555555555","emailAddress":"from-json@example.com","organizationUuid":"66666666-6666-4666-8666-666666666666","organizationName":"JSON Org"}}"#,
    )
    .expect("the file should be writable");

    let reader = FakeReader::unlocked().with_item(namespace::LIVE_SERVICE, OLD_BLOB);
    let discovery = discover(&AgentctlConfig::default(), &paths, &reader, &env, &ctx());

    let live = &discovery.rows[0];
    assert_eq!(live.id, "55555555-5555-4555-8555-555555555555");
    assert_eq!(live.record.email.as_deref(), Some("from-json@example.com"));
    assert_eq!(live.record.org_name.as_deref(), Some("JSON Org"));
    assert_eq!(live.state, AccountState::Ok, "the identity was found, so the row is fine");
}

#[test]
fn claude_json_is_not_consulted_for_any_other_row() {
    // Invariant I13. The same `.claude.json` is present, and the foreign
    // item must still be `identity unknown`.
    let (dir, paths) = store();
    let env = env_in(dir.path());
    std::fs::write(
        dir.path().join(".claude.json"),
        br#"{"oauthAccount":{"accountUuid":"55555555-5555-4555-8555-555555555555"}}"#,
    )
    .expect("the file should be writable");

    let reader = FakeReader::unlocked()
        .with_item(namespace::LIVE_SERVICE, LIVE_BLOB)
        .with_item("Claude Code-credentials-6cdd6b98", OLD_BLOB);
    let discovery = discover(&AgentctlConfig::default(), &paths, &reader, &env, &ctx());

    let foreign = row(&discovery, "Claude Code-credentials-6cdd6b98");
    assert_eq!(foreign.state, AccountState::IdentityUnknown);
    assert_ne!(foreign.record.account_uuid, "55555555-5555-4555-8555-555555555555");
}

#[test]
fn a_locked_keychain_locks_the_keychain_backed_rows_and_reads_nothing() {
    // Plan AC32 and AC44's unit half.
    let (dir, paths) = store();
    let env = env_in(dir.path());
    let reader = FakeReader::unlocked()
        .with_preflight(KeychainStatus::Locked)
        .with_item(namespace::LIVE_SERVICE, LIVE_BLOB);

    let discovery = discover(&AgentctlConfig::default(), &paths, &reader, &env, &ctx());
    assert_eq!(discovery.preflight, KeychainStatus::Locked);
    assert_eq!(discovery.rows[0].state, AccountState::KeychainLocked { detail: String::new() });
    assert!(discovery.rows[0].state.is_failure(), "exit 2");
    assert!(!discovery.rows[0].state.allows_network(), "no request for a row with no token");
    assert!(reader.reads().is_empty(), "a locked keychain is not prodded item by item");
    assert!(discovery.listing.is_empty());
}

#[test]
fn a_timed_out_keychain_is_transient_not_needs_login() {
    // Plan AC31: a slow keychain must never be reported as "log in again".
    let (dir, paths) = store();
    let env = env_in(dir.path());
    let reader = FakeReader::unlocked().with_preflight(KeychainStatus::Timeout);

    let discovery = discover(&AgentctlConfig::default(), &paths, &reader, &env, &ctx());
    assert_eq!(discovery.rows[0].state, AccountState::KeychainTimeout);
}

#[test]
fn an_owned_row_reads_its_file() {
    let (dir, paths) = store();
    let env = env_in(dir.path());
    let ns_dir = paths.namespace_dir("acct-1", "org-1");
    std::fs::create_dir_all(&ns_dir).expect("directories should be creatable");
    std::fs::write(ns_dir.join(crate::secret::file_store::CREDENTIALS_FILE), OTHER_BLOB)
        .expect("writable");

    let mut config = AgentctlConfig::default();
    config.upsert(
        new_record(
            "acct-1".to_owned(),
            "org-1".to_owned(),
            AccountKind::Owned {
                export_spelling: ns_dir.to_string_lossy().into_owned(),
                export_sha8: namespace::sha8(&namespace::export_spelling(&ns_dir)),
            },
        )
        .expect("valid"),
    );

    let reader = FakeReader::unlocked();
    let discovery = discover(&config, &paths, &reader, &env, &ctx());
    let owned = row(&discovery, "acct-1");
    assert_eq!(owned.state, AccountState::Ok);
    assert_eq!(owned.source, Source::File);
    assert!(owned.credentials.is_some());
    assert_eq!(owned.note, None);
}

#[test]
fn an_owned_row_with_no_file_needs_a_login() {
    let (dir, paths) = store();
    let env = env_in(dir.path());
    let mut config = AgentctlConfig::default();
    config.upsert(
        new_record(
            "acct-1".to_owned(),
            "org-1".to_owned(),
            AccountKind::Owned {
                export_spelling: "/store/claude/acct-1/org-1".to_owned(),
                export_sha8: "aaaaaaaa".to_owned(),
            },
        )
        .expect("valid"),
    );

    let discovery = discover(&config, &paths, &FakeReader::unlocked(), &env, &ctx());
    assert_eq!(row(&discovery, "acct-1").state, AccountState::NeedsLogin);
}

#[test]
fn an_owned_namespace_with_a_claude_lock_reports_the_session() {
    // Plan AC21's unit half: the row still shows numbers from the file, but
    // it is degraded and the refresh path will refuse.
    let (dir, paths) = store();
    let env = env_in(dir.path());
    let ns_dir = paths.namespace_dir("acct-1", "org-1");
    std::fs::create_dir_all(&ns_dir).expect("directories should be creatable");
    std::fs::write(ns_dir.join(crate::secret::file_store::CREDENTIALS_FILE), OTHER_BLOB)
        .expect("writable");
    std::fs::write(ns_dir.join(crate::secret::foreign_activity::REFRESH_LOCK), b"")
        .expect("writable");

    let mut config = AgentctlConfig::default();
    config.upsert(
        new_record(
            "acct-1".to_owned(),
            "org-1".to_owned(),
            AccountKind::Owned {
                export_spelling: ns_dir.to_string_lossy().into_owned(),
                export_sha8: "aaaaaaaa".to_owned(),
            },
        )
        .expect("valid"),
    );

    let discovery = discover(&config, &paths, &FakeReader::unlocked(), &env, &ctx());
    let owned = row(&discovery, "acct-1");
    let AccountState::ClaudeSessionDetected { lock, .. } = &owned.state else {
        panic!("expected a detected session, got {:?}", owned.state)
    };
    assert_eq!(lock, ".oauth_refresh.lock");
    assert!(owned.credentials.is_some(), "the file is still readable");
    assert_eq!(owned.source, Source::File);
}

#[test]
fn a_migrated_owned_namespace_is_displayed_from_the_keychain() {
    // Plan AC34: a keychain item under this namespace's name means a Claude
    // Code session has taken it over (fact F35). Read, never written.
    let (dir, paths) = store();
    let env = env_in(dir.path());
    let ns_dir = paths.namespace_dir("acct-1", "org-1");
    std::fs::create_dir_all(&ns_dir).expect("directories should be creatable");
    std::fs::write(ns_dir.join(crate::secret::file_store::CREDENTIALS_FILE), OLD_BLOB)
        .expect("writable");

    let export_sha8 = namespace::sha8(&namespace::export_spelling(&ns_dir));
    let service = format!("{}-{export_sha8}", namespace::LIVE_SERVICE);
    let mut config = AgentctlConfig::default();
    config.upsert(
        new_record(
            "acct-1".to_owned(),
            "org-1".to_owned(),
            AccountKind::Owned {
                export_spelling: ns_dir.to_string_lossy().into_owned(),
                export_sha8,
            },
        )
        .expect("valid"),
    );

    let reader = FakeReader::unlocked()
        .with_item(namespace::LIVE_SERVICE, LIVE_BLOB)
        .with_item(&service, OTHER_BLOB);
    let discovery = discover(&config, &paths, &reader, &env, &ctx());

    let owned = row(&discovery, "acct-1");
    assert_eq!(owned.state, AccountState::MigratedToKeychain { service });
    assert_eq!(owned.source, Source::Keychain);
    assert!(!owned.state.is_failure(), "the row still shows numbers");
    let credentials = owned.credentials.as_ref().expect("the keychain item was read");
    assert_eq!(
        credentials.identity().map(|identity| identity.account_uuid),
        Some("33333333-3333-4333-8333-333333333333".to_owned()),
        "the displayed credentials came from the keychain, not the file"
    );
}

#[test]
fn an_owned_row_says_when_the_migration_probe_could_not_run() {
    // Plan section 3.3 step 1: an unreadable keychain must not turn an owned
    // account into `needs login`.
    let (dir, paths) = store();
    let env = env_in(dir.path());
    let ns_dir = paths.namespace_dir("acct-1", "org-1");
    std::fs::create_dir_all(&ns_dir).expect("directories should be creatable");
    std::fs::write(ns_dir.join(crate::secret::file_store::CREDENTIALS_FILE), OTHER_BLOB)
        .expect("writable");

    let mut config = AgentctlConfig::default();
    config.upsert(
        new_record(
            "acct-1".to_owned(),
            "org-1".to_owned(),
            AccountKind::Owned {
                export_spelling: ns_dir.to_string_lossy().into_owned(),
                export_sha8: "aaaaaaaa".to_owned(),
            },
        )
        .expect("valid"),
    );

    let reader = FakeReader::unlocked().with_preflight(KeychainStatus::Locked);
    let discovery = discover(&config, &paths, &reader, &env, &ctx());
    let owned = row(&discovery, "acct-1");
    assert_eq!(owned.state, AccountState::Ok, "the file is still authoritative for an owned row");
    assert!(
        owned.note.as_deref().is_some_and(|note| note.contains("migration probe skipped")),
        "note: {:?}",
        owned.note
    );
    assert!(reader.reads().is_empty(), "no item was read while the keychain was locked");
}

#[test]
fn a_forgotten_record_is_hidden() {
    let (dir, paths) = store();
    let env = env_in(dir.path());
    let mut record = new_record(
        "acct-1".to_owned(),
        "org-1".to_owned(),
        AccountKind::Metadata { source: "claude-switcher".to_owned() },
    )
    .expect("valid");
    record.forgotten = true;
    let mut config = AgentctlConfig::default();
    config.upsert(record);

    let discovery = discover(&config, &paths, &FakeReader::unlocked(), &env, &ctx());
    let hidden = row(&discovery, "acct-1");
    assert_eq!(hidden.state, AccountState::Forgotten);
    assert!(!hidden.visible_by_default);
    assert!(!hidden.state.is_failure(), "a hidden row never drives the exit status");
}

#[test]
fn a_metadata_record_asks_for_a_login() {
    // Decision D-007: an import is non-destructive and carries no secret.
    let (dir, paths) = store();
    let env = env_in(dir.path());
    let mut config = AgentctlConfig::default();
    config.upsert(
        new_record(
            "acct-1".to_owned(),
            "org-1".to_owned(),
            AccountKind::Metadata { source: "claude-switcher".to_owned() },
        )
        .expect("valid"),
    );

    let discovery = discover(&config, &paths, &FakeReader::unlocked(), &env, &ctx());
    let imported = row(&discovery, "acct-1");
    assert_eq!(imported.state, AccountState::NeedsLogin);
    assert_eq!(imported.source, Source::None);
    assert!(imported.note.as_deref().is_some_and(|note| note.contains("claude-switcher")));
}

#[test]
fn a_config_dir_record_claims_its_service_so_it_is_not_also_unclaimed() {
    let (dir, paths) = store();
    let env = env_in(dir.path());
    let mut config = AgentctlConfig::default();
    config.upsert(
        new_record(
            "acct-9".to_owned(),
            "org-9".to_owned(),
            AccountKind::ConfigDirReadOnly {
                dir: PathBuf::from("/elsewhere"),
                service: "Claude Code-credentials-6cdd6b98".to_owned(),
                shares_live_dir: false,
            },
        )
        .expect("valid"),
    );

    let reader = FakeReader::unlocked()
        .with_item(namespace::LIVE_SERVICE, LIVE_BLOB)
        .with_item("Claude Code-credentials-6cdd6b98", OTHER_BLOB);
    let discovery = discover(&config, &paths, &reader, &env, &ctx());

    assert_eq!(discovery.rows.len(), 2, "{:?}", ids(&discovery));
    let claimed = row(&discovery, "acct-9");
    assert_eq!(claimed.state, AccountState::Ok);
    assert_eq!(claimed.source, Source::Keychain);
}

#[test]
fn a_config_dir_record_that_shares_the_live_directory_is_a_stale_sibling() {
    let (dir, paths) = store();
    let env = env_in(dir.path());
    let mut config = AgentctlConfig::default();
    config.upsert(
        new_record(
            "acct-9".to_owned(),
            "org-9".to_owned(),
            AccountKind::ConfigDirReadOnly {
                dir: PathBuf::from("/elsewhere"),
                service: "Claude Code-credentials-6cdd6b98".to_owned(),
                shares_live_dir: true,
            },
        )
        .expect("valid"),
    );

    let reader = FakeReader::unlocked()
        .with_item(namespace::LIVE_SERVICE, LIVE_BLOB)
        .with_item("Claude Code-credentials-6cdd6b98", OTHER_BLOB);
    let discovery = discover(&config, &paths, &reader, &env, &ctx());

    let sibling = row(&discovery, "acct-9");
    assert_eq!(sibling.state, AccountState::StaleSiblingOfLive);
    assert!(!sibling.visible_by_default);
}

#[test]
fn a_config_dir_record_with_a_failed_read_is_not_needs_login() {
    let (dir, paths) = store();
    let env = env_in(dir.path());
    let mut config = AgentctlConfig::default();
    config.upsert(
        new_record(
            "acct-9".to_owned(),
            "org-9".to_owned(),
            AccountKind::ConfigDirReadOnly {
                dir: PathBuf::from("/elsewhere"),
                service: "Claude Code-credentials-6cdd6b98".to_owned(),
                shares_live_dir: false,
            },
        )
        .expect("valid"),
    );

    let reader = FakeReader::unlocked()
        .with_item(namespace::LIVE_SERVICE, LIVE_BLOB)
        .with_failure("Claude Code-credentials-6cdd6b98", KeychainError::Locked);
    let discovery = discover(&config, &paths, &reader, &env, &ctx());
    assert_eq!(row(&discovery, "acct-9").state, AccountState::NeedsLogin);
}

#[test]
fn an_env_token_adds_its_own_row() {
    // Fact F19: the variable short-circuits every store, so the row exists to
    // tell the user why the numbers may not match the account they expect.
    let (dir, paths) = store();
    let mut env = env_in(dir.path());
    env.oauth_token_set = true;

    let discovery =
        discover(&AgentctlConfig::default(), &paths, &FakeReader::unlocked(), &env, &ctx());
    let env_row = row(&discovery, "env");
    assert_eq!(env_row.state, AccountState::EnvToken);
    assert_eq!(env_row.source, Source::Env);
    assert!(env_row.visible_by_default);
    assert!(!env_row.state.is_failure());
    assert!(env_row.credentials.is_none());
}

#[test]
fn a_cancelled_pass_returns_what_it_has_so_far() {
    let (dir, paths) = store();
    let env = env_in(dir.path());
    let mut config = AgentctlConfig::default();
    config.upsert(
        new_record(
            "acct-1".to_owned(),
            "org-1".to_owned(),
            AccountKind::Metadata { source: "x".to_owned() },
        )
        .expect("valid"),
    );

    let cancel = Cancel::new();
    cancel.cancel();
    let ctx = PassCtx::standalone(cancel, Instant::now() + Duration::from_secs(30));
    let discovery = discover(&config, &paths, &FakeReader::unlocked(), &env, &ctx);
    assert_eq!(discovery.rows.len(), 1, "only the live row was built before the stop");
}

#[test]
fn an_oversized_claude_json_leaves_the_live_row_visible_without_an_identity() {
    // `.claude.json` belongs to Claude Code and grows without a documented
    // bound, so the read is capped. Past the cap the row must still render —
    // an unreadable identity file is not a reason to hide an account that
    // plainly exists.
    let (dir, paths) = store();
    let env = env_in(dir.path());
    let path = dir.path().join(".claude.json");
    let padding = " ".repeat(usize::try_from(MAX_CLAUDE_JSON_BYTES).expect("a 64-bit host") + 1);
    std::fs::write(&path, format!("{{\"oauthAccount\":{{}}}}{padding}"))
        .expect("the file should be writable");
    assert!(
        std::fs::metadata(&path).expect("the file exists").len() > MAX_CLAUDE_JSON_BYTES,
        "the fixture has to break the cap for this test to mean anything"
    );

    let reader = FakeReader::unlocked().with_item(namespace::LIVE_SERVICE, OLD_BLOB);
    let discovery = discover(&AgentctlConfig::default(), &paths, &reader, &env, &ctx());

    let live = &discovery.rows[0];
    assert_eq!(live.id, "live", "no identity was found");
    assert_eq!(live.state, AccountState::IdentityUnknown);
    assert!(live.visible_by_default, "the row is still shown");
}

#[test]
fn a_symlinked_claude_json_is_followed_for_the_live_row() {
    // Fact F41: on the reference machine `~/.claude.json` is a symbolic link
    // into the real configuration directory. The live row's identity comes
    // from that file when the keychain blob carries no `tokenAccount`, so the
    // link has to be followed — refusing it blinds the live row.
    let (dir, paths) = store();
    let env = env_in(dir.path());
    let elsewhere = dir.path().join("real-config").join(".claude.json");
    std::fs::create_dir_all(elsewhere.parent().expect("the file has a parent"))
        .expect("the real config dir should be creatable");
    std::fs::write(
        &elsewhere,
        br#"{"oauthAccount":{"accountUuid":"99999999-9999-4999-8999-999999999999","emailAddress":"live@example.com"}}"#,
    )
    .expect("the file should be writable");
    std::os::unix::fs::symlink(&elsewhere, dir.path().join(".claude.json"))
        .expect("the symlink should be creatable");

    let reader = FakeReader::unlocked().with_item(namespace::LIVE_SERVICE, OLD_BLOB);
    let discovery = discover(&AgentctlConfig::default(), &paths, &reader, &env, &ctx());

    let live = &discovery.rows[0];
    assert_eq!(live.id, "99999999-9999-4999-8999-999999999999", "the identity behind the link");
    assert_eq!(live.state, AccountState::Ok);
    assert_eq!(live.record.email.as_deref(), Some("live@example.com"));
}

#[test]
fn an_unchanged_claude_json_is_not_parsed_twice() {
    // `watch` re-runs discovery every few seconds against a file that is
    // hundreds of kilobytes and changes its `oauthAccount` only at a login,
    // so the `(dev, ino, size, mtime)` fingerprint decides whether the parse
    // runs at all. Observed by poisoning the memo with an answer the file
    // does not contain: getting it back proves the bytes were not re-read.
    let dir = TempDir::new().expect("a temporary directory should be available");
    let path = dir.path().join(".claude.json");
    std::fs::write(
        &path,
        br#"{"oauthAccount":{"accountUuid":"55555555-5555-4555-8555-555555555555"}}"#,
    )
    .expect("the file should be writable");

    let first = claude_json_identity(&path).expect("the identity should parse");
    assert_eq!(first.account_uuid, "55555555-5555-4555-8555-555555555555");

    let sentinel = Identity {
        account_uuid: "memo-hit".to_owned(),
        organization_uuid: None,
        email: None,
        org_name: None,
    };
    {
        let mut memo = memo();
        let (cached_path, snap, _) = memo.take().expect("the first read populated the memo");
        assert_eq!(cached_path, path);
        *memo = Some((cached_path, snap, Some(sentinel.clone())));
    }
    assert_eq!(claude_json_identity(&path), Some(sentinel), "the file was parsed again");

    // And a change to the file invalidates it: same length, new mtime and a
    // new inode, which is what a rewrite by Claude Code looks like.
    std::fs::remove_file(&path).expect("the file should be removable");
    std::fs::write(
        &path,
        br#"{"oauthAccount":{"accountUuid":"77777777-7777-4777-8777-777777777777"}}"#,
    )
    .expect("the file should be writable");
    assert_eq!(
        claude_json_identity(&path).map(|identity| identity.account_uuid),
        Some("77777777-7777-4777-8777-777777777777".to_owned()),
        "a changed file must be re-read"
    );
}

#[test]
fn claude_json_keys_outside_oauth_account_are_ignored_rather_than_parsed() {
    // The typed shape is the point: everything else in `.claude.json` —
    // project lists, session history, MCP configuration — is skipped by
    // `serde` without being materialised, including values that no
    // `serde_json::Value` tree would survive being asked about.
    let dir = TempDir::new().expect("a temporary directory should be available");
    let path = dir.path().join(".claude.json");
    std::fs::write(
        &path,
        br#"{"projects":{"/a":{"history":[1,2,3]}},"oauthAccount":{"accountUuid":"55555555-5555-4555-8555-555555555555","emailAddress":"json@example.com","unexpected":{"nested":true}},"tipsHistory":{}}"#,
    )
    .expect("the file should be writable");

    let identity = claude_json_identity(&path).expect("the identity should parse");
    assert_eq!(identity.account_uuid, "55555555-5555-4555-8555-555555555555");
    assert_eq!(identity.email.as_deref(), Some("json@example.com"));
    assert_eq!(identity.organization_uuid, None, "an absent field is absent, not an error");
}

#[test]
fn an_oauth_account_without_a_uuid_is_no_identity() {
    let dir = TempDir::new().expect("a temporary directory should be available");
    let path = dir.path().join(".claude.json");
    std::fs::write(&path, br#"{"oauthAccount":{"emailAddress":"nameless@example.com"}}"#)
        .expect("the file should be writable");
    assert_eq!(claude_json_identity(&path), None);
}
