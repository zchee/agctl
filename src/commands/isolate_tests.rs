//! Tests for the S15 isolation skeleton: directory creation, the D-019
//! symlink, idempotence and the I19 refusal.

use std::os::unix::fs::PermissionsExt;
use std::time::Instant;

use tempfile::TempDir;

use super::*;
use crate::config::AccountRecord;
use crate::runtime::coordinator::Cancel;

const ACCT: &str = "11111111-2222-3333-4444-555555555555";
const ORG: &str = "66666666-7777-8888-9999-000000000000";

struct Fixture {
    root: TempDir,
    paths: Paths,
    env: EnvView,
}

fn fixture() -> Fixture {
    let root = TempDir::new().expect("a temporary directory should be available");
    let home = root.path().join("home");
    std::fs::create_dir_all(&home).expect("the fake home should be creatable");
    std::fs::write(home.join(".claude.json"), "{}\n").expect("the live file should be writable");

    let paths = Paths::with_config_dir(root.path().join("config"));
    let env = EnvView::with_home(home);
    Fixture { root, paths, env }
}

fn owned_record() -> AccountRecord {
    crate::config::new_record(
        ACCT.to_owned(),
        ORG.to_owned(),
        AccountKind::Owned {
            export_spelling: "/does/not/matter".to_owned(),
            export_sha8: "deadbeef".to_owned(),
        },
    )
    .expect("the fixture identifiers are valid")
}

fn ctx() -> PassCtx {
    PassCtx::standalone(Cancel::new(), Instant::now())
}

#[test]
fn creates_the_session_directory_at_0700_with_parents() {
    let fx = fixture();
    let opts = SessionOptions::default();
    let session =
        ensure_session(&fx.paths, &owned_record(), &opts, &fx.env, &ctx()).expect("should succeed");

    assert_eq!(session.path, fx.paths.session_dir(ACCT, ORG));
    let meta = std::fs::metadata(&session.path).expect("the session directory should exist");
    assert!(meta.is_dir());
    assert_eq!(meta.permissions().mode() & 0o777, DIR_MODE);
    drop(fx.root);
}

#[test]
fn symlinks_mcp_json_to_the_canonical_live_claude_json() {
    let fx = fixture();
    let opts = SessionOptions::default();
    let session =
        ensure_session(&fx.paths, &owned_record(), &opts, &fx.env, &ctx()).expect("should succeed");

    let link = session.mcp_config.expect("mcp_config should be set without --no-mcp");
    assert_eq!(link, session.path.join(MCP_LINK));

    let meta = std::fs::symlink_metadata(&link).expect("the symlink should exist");
    assert!(meta.file_type().is_symlink());

    let target = std::fs::read_link(&link).expect("the symlink target should be readable");
    let expected = namespace::canonical(&fx.env.home.join(".claude.json"))
        .expect("the fixture's live file should canonicalize");
    assert_eq!(target, expected);
}

#[test]
fn omits_the_symlink_when_no_mcp_is_set() {
    let fx = fixture();
    let opts = SessionOptions { no_mcp: true, ..SessionOptions::default() };
    let session =
        ensure_session(&fx.paths, &owned_record(), &opts, &fx.env, &ctx()).expect("should succeed");

    assert_eq!(session.mcp_config, None);
    assert!(!session.path.join(MCP_LINK).exists());
}

#[test]
fn is_idempotent() {
    let fx = fixture();
    let opts = SessionOptions::default();
    let first =
        ensure_session(&fx.paths, &owned_record(), &opts, &fx.env, &ctx()).expect("first run");
    let second =
        ensure_session(&fx.paths, &owned_record(), &opts, &fx.env, &ctx()).expect("second run");
    assert_eq!(first, second);
}

#[test]
fn refuses_when_mcp_json_is_occupied_by_a_regular_file() {
    let fx = fixture();
    let opts = SessionOptions::default();
    let session_dir = fx.paths.session_dir(ACCT, ORG);
    std::fs::create_dir_all(&session_dir).expect("the session directory should be creatable");
    std::fs::write(session_dir.join(MCP_LINK), "not a symlink")
        .expect("the file should be writable");

    let err = ensure_session(&fx.paths, &owned_record(), &opts, &fx.env, &ctx())
        .expect_err("an occupied mcp.json should be refused");
    let message = err.to_string();
    assert!(message.contains(MCP_LINK), "message should name the path: {message}");
}

#[test]
fn refuses_when_mcp_json_is_a_symlink_to_something_else() {
    let fx = fixture();
    let opts = SessionOptions::default();
    let session_dir = fx.paths.session_dir(ACCT, ORG);
    std::fs::create_dir_all(&session_dir).expect("the session directory should be creatable");
    let elsewhere = fx.root.path().join("elsewhere.json");
    std::fs::write(&elsewhere, "{}").expect("the decoy file should be writable");
    std::os::unix::fs::symlink(&elsewhere, session_dir.join(MCP_LINK))
        .expect("the decoy symlink should be creatable");

    let err = ensure_session(&fx.paths, &owned_record(), &opts, &fx.env, &ctx())
        .expect_err("a symlink to the wrong target should be refused");
    let message = err.to_string();
    assert!(message.contains(MCP_LINK), "message should name the path: {message}");
}

#[test]
fn refuses_a_relative_claude_config_dir_override() {
    let fx = fixture();
    let opts = SessionOptions {
        claude_config_dir: Some(PathBuf::from("relative/dir")),
        ..SessionOptions::default()
    };
    let err = ensure_session(&fx.paths, &owned_record(), &opts, &fx.env, &ctx())
        .expect_err("a relative override should be refused");
    assert!(err.to_string().contains("absolute"));
}

#[test]
fn refuses_non_owned_accounts() {
    let fx = fixture();
    let opts = SessionOptions::default();
    let live = crate::config::new_record(ACCT.to_owned(), ORG.to_owned(), AccountKind::Live)
        .expect("the fixture identifiers are valid");
    let err = ensure_session(&fx.paths, &live, &opts, &fx.env, &ctx())
        .expect_err("a Live account has nothing to isolate");
    assert!(err.to_string().contains("live"));
}

#[test]
fn session_options_carries_fresh_context_through() {
    // S16 is the first production reader of `fresh_context`; this pins the
    // round trip so the field cannot silently stop being threaded through
    // once it does.
    let opts = SessionOptions { fresh_context: true, ..SessionOptions::default() };
    assert!(opts.fresh_context);
    assert!(!SessionOptions::default().fresh_context);
}

#[test]
fn the_seeding_allowlists_are_exactly_the_contract_lists() {
    // Plan section 3.3 / the phase-2 W1 contract fix these lists verbatim;
    // S16 relies on them being exactly this, so a drift here is a defect in
    // this module, not in S16.
    assert_eq!(TIER1, ["settings.json", "CLAUDE.md", "skills"]);
    assert_eq!(
        TIER2_DIRS,
        ["projects", "shell-snapshots", "file-history", "sessions", "session-env"]
    );
    assert_eq!(NEVER_LINKED, ["history.jsonl"]);
    assert_eq!(SEED_KEYS.len(), 15);
    assert!(SEED_KEYS.contains(&"hasCompletedOnboarding"));
    assert!(SEED_KEYS.contains(&"verbose"));
    assert_eq!(NEVER_SEED.len(), 19);
    assert!(NEVER_SEED.contains(&"oauthAccount"));
    assert!(NEVER_SEED.contains(&"mcpServers"));
    assert!(NEVER_SEED.contains(&"clientDataCacheSlots"));

    // The F52 leak test's other half: nothing seeded may also be forbidden.
    for key in SEED_KEYS {
        assert!(!NEVER_SEED.contains(key), "`{key}` is on both lists");
    }
}

#[test]
fn seed_floor_sets_onboarding_true() {
    let floor = seed_floor();
    assert_eq!(floor, vec![("hasCompletedOnboarding", serde_json::Value::Bool(true))]);
}

#[test]
fn honours_an_absolute_claude_config_dir_override() {
    let fx = fixture();
    let overridden = fx.root.path().join("elsewhere").join("session");
    let opts =
        SessionOptions { claude_config_dir: Some(overridden.clone()), ..SessionOptions::default() };
    let session =
        ensure_session(&fx.paths, &owned_record(), &opts, &fx.env, &ctx()).expect("should succeed");
    assert_eq!(session.path, overridden);
}
