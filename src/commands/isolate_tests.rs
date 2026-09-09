//! Tests for the S15 isolation skeleton: directory creation, the D-019
//! symlink, idempotence and the I19 refusal.

use std::os::unix::fs::PermissionsExt;
use std::time::Duration;
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

/// A [`PassCtx`] with a deadline far enough in the future that
/// [`PassCtx::should_stop`] answers only to cancellation, never to the
/// deadline — for the M6 retry tests, which need more than one attempt to
/// run before the loop returns and would otherwise see [`ctx`]'s
/// already-past deadline as a spurious stop request.
fn ctx_with_deadline() -> PassCtx {
    PassCtx::standalone(Cancel::new(), Instant::now() + Duration::from_secs(60))
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

#[test]
fn refuses_a_claude_config_dir_override_equal_to_the_live_store_dir() {
    // A `--claude-config-dir` naming the live directory would symlink and
    // seed on top of the very store a session exists to isolate from.
    let fx = fixture();
    let live = live_dir(&fx);
    std::fs::create_dir_all(&live).expect("the live config dir should be creatable");

    let opts =
        SessionOptions { claude_config_dir: Some(live.clone()), ..SessionOptions::default() };
    let err = ensure_session(&fx.paths, &owned_record(), &opts, &fx.env, &ctx())
        .expect_err("the live store dir cannot be the isolated one");
    assert!(err.to_string().contains("live Claude Code configuration directory"), "{err}");
    assert!(
        std::fs::read_dir(&live).expect("readable").next().is_none(),
        "nothing was created inside the live directory"
    );
}

#[test]
fn refuses_a_claude_config_dir_override_reaching_the_live_store_dir_through_a_symlink() {
    // The same refusal, spelled differently: a symlink resolving to the live
    // directory is caught by the canonicalized comparison.
    let fx = fixture();
    let live = live_dir(&fx);
    std::fs::create_dir_all(&live).expect("the live config dir should be creatable");
    let via_link = fx.root.path().join("live-via-link");
    std::os::unix::fs::symlink(&live, &via_link).expect("the symlink should be creatable");

    let opts =
        SessionOptions { claude_config_dir: Some(via_link.clone()), ..SessionOptions::default() };
    let err = ensure_session(&fx.paths, &owned_record(), &opts, &fx.env, &ctx())
        .expect_err("a symlinked spelling of the live store dir is still refused");
    assert!(err.to_string().contains("live Claude Code configuration directory"), "{err}");
}

// ---------------------------------------------------------------------------
// `..`/`.` spellings in a `--claude-config-dir` override (N-2)
// ---------------------------------------------------------------------------

#[test]
fn refuses_a_claude_config_dir_override_with_a_dotdot_segment_even_when_it_would_resolve_onto_the_live_dir()
 {
    // Before N-2, `canonical` fails because `does-not-exist` was never
    // created, and the export-spelling fallback does not fold `..`, so this
    // spelling read as a different path from `live` and dodged the
    // live-store-dir refusal even though it resolves onto it.
    let fx = fixture();
    let live = live_dir(&fx);
    let overridden = live.join("does-not-exist").join("..");
    let opts =
        SessionOptions { claude_config_dir: Some(overridden.clone()), ..SessionOptions::default() };
    let err = ensure_session(&fx.paths, &owned_record(), &opts, &fx.env, &ctx())
        .expect_err("a `..` segment should be refused before anything else");
    assert!(err.to_string().contains("normalized"), "{err}");
    assert!(
        !live.join("does-not-exist").exists(),
        "the missing component should never have been created"
    );
}

#[test]
fn refuses_a_claude_config_dir_override_with_a_curdir_segment() {
    let fx = fixture();
    let live = live_dir(&fx);
    let overridden = live.join(".");
    let opts =
        SessionOptions { claude_config_dir: Some(overridden.clone()), ..SessionOptions::default() };
    let err = ensure_session(&fx.paths, &owned_record(), &opts, &fx.env, &ctx())
        .expect_err("a `.` segment should be refused before anything else");
    assert!(err.to_string().contains("normalized"), "{err}");
}

#[test]
fn honours_a_genuinely_different_sibling_of_the_live_dir() {
    // The dot-segment refusal must not overreach: a plain, normalized path
    // that merely sits next to the live directory is still accepted.
    let fx = fixture();
    let live = live_dir(&fx);
    let sibling = live.parent().expect("the live dir has a parent").join("sibling-session");
    let opts =
        SessionOptions { claude_config_dir: Some(sibling.clone()), ..SessionOptions::default() };
    let session =
        ensure_session(&fx.paths, &owned_record(), &opts, &fx.env, &ctx()).expect("should succeed");
    assert_eq!(session.path, sibling);
}

#[test]
fn is_live_store_dir_folds_a_dotdot_spelling_before_comparing() {
    // Exercises the helper directly, independent of `ensure_session`'s own
    // front-door refusal of any override carrying a `.`/`..` segment: even a
    // caller that bypassed the front door must still get the right answer.
    let fx = fixture();
    let live = live_dir(&fx);

    let dotdot_spelling = live.join("does-not-exist").join("..");
    assert!(is_live_store_dir(&dotdot_spelling, &fx.env));

    let sibling = live.parent().expect("the live dir has a parent").join("sibling-session");
    assert!(!is_live_store_dir(&sibling, &fx.env));
}

// ---------------------------------------------------------------------------
// Tier 1 / tier 2 symlinks (AC53)
// ---------------------------------------------------------------------------

/// The live config directory (`$HOME/.claude`) a [`fixture`] never creates on
/// its own — tests that exercise tier 1/tier 2 build it themselves.
fn live_dir(fx: &Fixture) -> std::path::PathBuf {
    namespace::live_store_dir(&fx.env)
}

#[test]
fn links_every_tier_1_and_tier_2_entry_the_live_dir_has_and_reports_the_rest_missing() {
    let fx = fixture();
    let live = live_dir(&fx);
    std::fs::create_dir_all(&live).expect("the live config dir should be creatable");
    std::fs::write(live.join("settings.json"), "{}").expect("writable");
    std::fs::create_dir_all(live.join("projects")).expect("writable");
    // "CLAUDE.md", "skills", and the other four tier 2 directories are left
    // absent from the live dir on purpose.

    let opts = SessionOptions::default();
    let session =
        ensure_session(&fx.paths, &owned_record(), &opts, &fx.env, &ctx()).expect("should succeed");

    assert_eq!(session.linked, vec!["settings.json".to_owned(), "projects".to_owned()]);
    assert_eq!(
        session.missing,
        vec![
            "CLAUDE.md".to_owned(),
            "skills".to_owned(),
            "shell-snapshots".to_owned(),
            "file-history".to_owned(),
            "sessions".to_owned(),
            "session-env".to_owned(),
        ]
    );
    assert!(session.already_linked.is_empty());

    for name in ["settings.json", "projects"] {
        let link = session.path.join(name);
        let meta = std::fs::symlink_metadata(&link).expect("the symlink should exist");
        assert!(meta.file_type().is_symlink(), "`{name}` should be a symlink");
        let target = std::fs::read_link(&link).expect("readable");
        let expected = namespace::canonical(&live.join(name)).expect("canonicalizable");
        assert_eq!(target, expected, "`{name}`'s target");
    }
    for name in ["CLAUDE.md", "skills", "shell-snapshots"] {
        assert!(!session.path.join(name).exists(), "`{name}` should not be created");
    }
}

#[test]
fn fresh_context_omits_tier_2_entirely_even_when_the_live_dir_has_it() {
    let fx = fixture();
    let live = live_dir(&fx);
    std::fs::create_dir_all(&live).expect("writable");
    std::fs::write(live.join("settings.json"), "{}").expect("writable");
    std::fs::create_dir_all(live.join("projects")).expect("writable");

    let opts = SessionOptions { fresh_context: true, ..SessionOptions::default() };
    let session =
        ensure_session(&fx.paths, &owned_record(), &opts, &fx.env, &ctx()).expect("should succeed");

    assert_eq!(session.linked, vec!["settings.json".to_owned()]);
    assert!(
        !session.missing.iter().any(|name| name == "projects"),
        "an omitted tier 2 entry is neither linked nor reported missing: {:?}",
        session.missing
    );
    assert!(!session.path.join("projects").exists());
}

#[test]
fn a_tier_2_name_that_resolves_to_a_file_is_reported_missing_not_symlinked() {
    // AC53: tier 2 is directories only. A file living under a tier-2 name in
    // the live config directory must not be symlinked in.
    let fx = fixture();
    let live = live_dir(&fx);
    std::fs::create_dir_all(&live).expect("writable");
    std::fs::write(live.join("projects"), "not a directory").expect("writable");

    let opts = SessionOptions::default();
    let session =
        ensure_session(&fx.paths, &owned_record(), &opts, &fx.env, &ctx()).expect("should succeed");

    assert!(
        session.missing.contains(&"projects".to_owned()),
        "a tier-2 file is reported missing: {:?}",
        session.missing
    );
    assert!(!session.linked.contains(&"projects".to_owned()));
    assert!(!session.path.join("projects").exists(), "a tier-2 file must not be symlinked");
}

#[test]
fn idempotent_repair_links_a_missing_symlink_and_leaves_correct_ones_alone() {
    let fx = fixture();
    let live = live_dir(&fx);
    std::fs::create_dir_all(&live).expect("writable");
    std::fs::write(live.join("settings.json"), "{}").expect("writable");
    std::fs::write(live.join("CLAUDE.md"), "# hi").expect("writable");

    let opts = SessionOptions::default();
    let first =
        ensure_session(&fx.paths, &owned_record(), &opts, &fx.env, &ctx()).expect("first run");
    assert_eq!(first.linked, vec!["settings.json".to_owned(), "CLAUDE.md".to_owned()]);
    assert!(first.already_linked.is_empty());

    // Simulate the symlink going missing between runs.
    std::fs::remove_file(first.path.join("CLAUDE.md")).expect("the symlink should be removable");

    let second =
        ensure_session(&fx.paths, &owned_record(), &opts, &fx.env, &ctx()).expect("second run");
    assert_eq!(second.linked, vec!["CLAUDE.md".to_owned()], "only the missing one is repaired");
    assert_eq!(
        second.already_linked,
        vec![second.path.join("settings.json")],
        "the correct one is left alone"
    );
    assert!(
        std::fs::symlink_metadata(second.path.join("CLAUDE.md"))
            .expect("readable")
            .file_type()
            .is_symlink()
    );
}

#[test]
fn refuses_when_a_tier_1_path_is_occupied_by_a_regular_file() {
    let fx = fixture();
    let live = live_dir(&fx);
    std::fs::create_dir_all(&live).expect("writable");
    std::fs::write(live.join("settings.json"), "{}").expect("writable");

    let session_dir = fx.paths.session_dir(ACCT, ORG);
    std::fs::create_dir_all(&session_dir).expect("writable");
    std::fs::write(session_dir.join("settings.json"), "not a symlink").expect("writable");

    let opts = SessionOptions::default();
    let err = ensure_session(&fx.paths, &owned_record(), &opts, &fx.env, &ctx())
        .expect_err("an occupied tier 1 path should be refused");
    assert!(err.to_string().contains("settings.json"), "{err}");
    assert_eq!(
        std::fs::read_to_string(session_dir.join("settings.json")).expect("readable"),
        "not a symlink",
        "the foreign occupant is left untouched"
    );
}

#[test]
fn refuses_when_a_tier_1_path_is_a_symlink_to_something_else() {
    let fx = fixture();
    let live = live_dir(&fx);
    std::fs::create_dir_all(&live).expect("writable");
    std::fs::write(live.join("settings.json"), "{}").expect("writable");

    let session_dir = fx.paths.session_dir(ACCT, ORG);
    std::fs::create_dir_all(&session_dir).expect("writable");
    let elsewhere = fx.root.path().join("elsewhere-settings.json");
    std::fs::write(&elsewhere, "{}").expect("writable");
    std::os::unix::fs::symlink(&elsewhere, session_dir.join("settings.json")).expect("writable");

    let opts = SessionOptions::default();
    let err = ensure_session(&fx.paths, &owned_record(), &opts, &fx.env, &ctx())
        .expect_err("a foreign symlink should be refused");
    assert!(err.to_string().contains("settings.json"), "{err}");
}

#[test]
fn refuses_when_a_tier_1_path_is_occupied_by_a_directory() {
    let fx = fixture();
    let live = live_dir(&fx);
    std::fs::create_dir_all(&live).expect("writable");
    std::fs::create_dir_all(live.join("skills")).expect("writable");

    let session_dir = fx.paths.session_dir(ACCT, ORG);
    std::fs::create_dir_all(session_dir.join("skills")).expect("writable");

    let opts = SessionOptions::default();
    let err = ensure_session(&fx.paths, &owned_record(), &opts, &fx.env, &ctx())
        .expect_err("an occupying directory should be refused");
    assert!(err.to_string().contains("skills"), "{err}");
}

// ---------------------------------------------------------------------------
// Symlink hazards at the session directory itself, and at the seed path
// (P1-1 / invariant I19, plan AC56)
// ---------------------------------------------------------------------------

#[test]
fn refuses_when_the_session_directory_itself_is_a_symlink_to_a_live_directory() {
    // Scenario A: `<session_root>/<acct>/<org>` is a symlink to some other
    // "live" directory left by an earlier experiment or any same-user
    // actor. Before this fix `is_dir()` follows the link and every
    // placement this call makes lands inside the link's target instead of
    // being refused.
    let fx = fixture();
    let live_elsewhere = fx.root.path().join("live-elsewhere");
    std::fs::create_dir_all(&live_elsewhere).expect("the decoy live directory should be creatable");

    let session_dir = fx.paths.session_dir(ACCT, ORG);
    std::fs::create_dir_all(session_dir.parent().expect("the session dir has a parent"))
        .expect("the session directory's parent should be creatable");
    std::os::unix::fs::symlink(&live_elsewhere, &session_dir)
        .expect("the decoy symlink should be creatable");

    let opts = SessionOptions::default();
    let err = ensure_session(&fx.paths, &owned_record(), &opts, &fx.env, &ctx())
        .expect_err("a symlinked session directory should be refused");
    assert!(err.to_string().contains(&session_dir.display().to_string()), "{err}");
    assert_eq!(
        std::fs::read_dir(&live_elsewhere).expect("readable").count(),
        0,
        "nothing was created inside the symlink's target"
    );
    assert!(
        std::fs::symlink_metadata(&session_dir)
            .expect("the symlink itself is untouched")
            .file_type()
            .is_symlink(),
        "the decoy symlink itself is left exactly as it was"
    );
}

#[test]
fn create_session_dir_fails_closed_when_a_symlink_is_planted_in_the_check_create_window() {
    // N-1: the original shape — `symlink_metadata` finds nothing, then a
    // single `DirBuilder::recursive(true)` over the whole path — has a
    // TOCTOU window, because std's `create_dir_all` maps `mkdir`'s `EEXIST`
    // to `Ok(())` whenever `path.is_dir()`, which *follows* a symlink.
    // Anything planted at `path` in that window that resolves to a
    // directory was silently accepted. `before_create` stands in for a
    // same-user actor winning that race.
    let root = TempDir::new().expect("a temporary directory should be available");
    let live_elsewhere = root.path().join("live-elsewhere");
    std::fs::create_dir_all(&live_elsewhere).expect("the decoy live directory should be creatable");
    let path = root.path().join("session");

    let err = create_session_dir_seamed(&path, || {
        std::os::unix::fs::symlink(&live_elsewhere, &path)
            .expect("the decoy symlink should be creatable in the check-create window");
    })
    .expect_err("a symlink planted in the window should be refused, not silently accepted");
    assert!(err.to_string().contains(&path.display().to_string()), "{err}");

    assert!(
        std::fs::symlink_metadata(&path)
            .expect("the decoy symlink is untouched")
            .file_type()
            .is_symlink(),
        "the decoy symlink itself is left exactly as it was"
    );
    assert_eq!(
        std::fs::read_dir(&live_elsewhere).expect("readable").count(),
        0,
        "nothing was created inside the symlink's target"
    );
}

#[test]
fn refuses_when_the_seed_path_is_a_dangling_symlink() {
    // Scenario B: `<session>/.claude.json` is a dangling symlink. Before
    // this fix `exists()` is false, `create_new` then fails with
    // `AlreadyExists` (the entry itself is there, even though its target is
    // not), and the old `write_seed_file` mapped that straight to `Ok(())`
    // — no seed, no error, no report.
    let fx = fixture();
    let opts = SessionOptions::default();
    let session_dir = fx.paths.session_dir(ACCT, ORG);
    std::fs::create_dir_all(&session_dir).expect("the session directory should be creatable");
    let nowhere = fx.root.path().join("nowhere.json");
    std::os::unix::fs::symlink(&nowhere, session_dir.join(SEED_FILE))
        .expect("the dangling symlink should be creatable");

    let err = ensure_session(&fx.paths, &owned_record(), &opts, &fx.env, &ctx())
        .expect_err("a dangling symlink at the seed path should be refused, not silently skipped");
    assert!(err.to_string().contains(SEED_FILE), "{err}");
    assert!(
        std::fs::symlink_metadata(session_dir.join(SEED_FILE))
            .expect("the symlink itself is untouched")
            .file_type()
            .is_symlink(),
        "the dangling symlink itself is left exactly as it was"
    );
}

// ---------------------------------------------------------------------------
// `.claude.json` seeding (AC54)
// ---------------------------------------------------------------------------

#[test]
fn seeds_only_the_present_seed_keys_and_the_floor() {
    let fx = fixture();
    std::fs::write(
        fx.env.home.join(".claude.json"),
        serde_json::json!({"theme": "dark", "verbose": true}).to_string(),
    )
    .expect("writable");

    let opts = SessionOptions::default();
    let session =
        ensure_session(&fx.paths, &owned_record(), &opts, &fx.env, &ctx()).expect("should succeed");

    let seed_path = session.path.join(SEED_FILE);
    let seed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&seed_path).expect("readable"))
            .expect("valid JSON");
    let object = seed.as_object().expect("an object");
    assert_eq!(object.get("theme"), Some(&serde_json::json!("dark")));
    assert_eq!(object.get("verbose"), Some(&serde_json::json!(true)));
    // The live file lacked it, so the floor fills it in.
    assert_eq!(object.get("hasCompletedOnboarding"), Some(&serde_json::json!(true)));
    assert_eq!(object.len(), 3, "only what was present, plus the floor: {object:?}");

    let mode = std::fs::metadata(&seed_path).expect("readable").permissions().mode() & 0o777;
    assert_eq!(mode, FILE_MODE);
}

#[test]
fn f52_leak_test_the_seed_never_carries_a_never_seed_key() {
    let fx = fixture();
    std::fs::write(
        fx.env.home.join(".claude.json"),
        serde_json::json!({
            "oauthAccount": {"uuid": "leak-me-not"},
            "userID": "u-1",
            "machineID": "m-1",
            "cachedUsageUtilization": 0.5,
            "overageCreditGrantCache": {},
            "passesEligibilityCache": {},
            "s1mAccessCache": {},
            "modelAccessCache": {},
            "projects": {"/tmp": {}},
            "mcpServers": {"server-a": {"command": "foo"}},
            "hasCompletedOnboarding": true,
            "theme": "dark",
        })
        .to_string(),
    )
    .expect("writable");

    let opts = SessionOptions::default();
    let session =
        ensure_session(&fx.paths, &owned_record(), &opts, &fx.env, &ctx()).expect("should succeed");

    let seed_text = std::fs::read_to_string(session.path.join(SEED_FILE)).expect("readable");
    for key in NEVER_SEED {
        assert!(!seed_text.contains(key), "`{key}` must not appear in the seed: {seed_text}");
    }
    assert!(seed_text.contains("theme"), "an allowlisted key must still be seeded");
}

#[test]
fn seeding_is_skipped_once_the_seed_file_exists() {
    let fx = fixture();
    std::fs::write(
        fx.env.home.join(".claude.json"),
        serde_json::json!({"theme": "dark"}).to_string(),
    )
    .expect("writable");

    let opts = SessionOptions::default();
    let session =
        ensure_session(&fx.paths, &owned_record(), &opts, &fx.env, &ctx()).expect("first run");
    let seed_path = session.path.join(SEED_FILE);

    // A later Claude Code run would extend the file; simulate that directly.
    std::fs::write(&seed_path, serde_json::json!({"theme": "dark", "extra": true}).to_string())
        .expect("writable");

    ensure_session(&fx.paths, &owned_record(), &opts, &fx.env, &ctx()).expect("second run");

    let after: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&seed_path).expect("readable"))
            .expect("valid JSON");
    assert_eq!(
        after,
        serde_json::json!({"theme": "dark", "extra": true}),
        "a re-run must not touch an already-seeded file"
    );
}

// ---------------------------------------------------------------------------
// The torn-read guard (M6)
// ---------------------------------------------------------------------------

#[test]
fn read_twice_and_compare_returns_immediately_when_the_first_pair_agrees() {
    let mut calls = 0u32;
    let result =
        read_twice_and_compare(std::path::Path::new("/fixture/.claude.json"), &ctx(), |_| {
            calls += 1;
            Ok(Some(vec![7]))
        })
        .expect("a stable reader should succeed on the first attempt");
    assert_eq!(result, Some(vec![7]));
    assert_eq!(calls, 2, "only the first attempt's pair of reads should run");
}

#[test]
fn read_twice_and_compare_retries_and_succeeds_once_the_writer_settles() {
    let mut calls = 0u32;
    let result = read_twice_and_compare(
        std::path::Path::new("/fixture/.claude.json"),
        &ctx_with_deadline(),
        |_| {
            calls += 1;
            // Tears on the first attempt's pair, then settles.
            if calls <= 2 { Ok(Some(vec![calls as u8])) } else { Ok(Some(vec![9])) }
        },
    )
    .expect("a writer that settles within the retry budget should succeed");
    assert_eq!(result, Some(vec![9]));
    assert_eq!(calls, 4, "one torn attempt plus one settled attempt, two reads each");
}

#[test]
fn read_twice_and_compare_refuses_after_persistent_tearing() {
    let mut calls = 0u32;
    let err = read_twice_and_compare(
        std::path::Path::new("/fixture/.claude.json"),
        &ctx_with_deadline(),
        |_| {
            calls += 1;
            // Alternates every single call, so no pair ever agrees.
            Ok(Some(vec![u8::try_from(calls % 2).unwrap_or(0)]))
        },
    )
    .expect_err("persistent tearing across every attempt should refuse rather than seed it");
    assert!(err.to_string().contains(".claude.json"), "{err}");
    assert_eq!(calls, LIVE_READ_ATTEMPTS * 2);
}

#[test]
fn read_twice_and_compare_stops_retrying_once_cancelled() {
    let cancel = Cancel::new();
    cancel.cancel();
    let cancelled_ctx = PassCtx::standalone(cancel, Instant::now());

    let mut calls = 0u32;
    let err = read_twice_and_compare(
        std::path::Path::new("/fixture/.claude.json"),
        &cancelled_ctx,
        |_| {
            calls += 1;
            // Always disagree, so an uncancelled run would exhaust every retry.
            Ok(Some(vec![u8::try_from(calls % 2).unwrap_or(0)]))
        },
    )
    .expect_err("a cancelled context should stop retrying rather than exhaust every attempt");
    assert!(matches!(err, AppError::Refused { .. }), "{err:?}");
    assert_eq!(
        calls, 2,
        "only the first attempt's two reads should run before cancellation is checked"
    );
}

// ---------------------------------------------------------------------------
// `forget_session` (AC79)
// ---------------------------------------------------------------------------

/// A [`Prompt`] double that answers a scripted confirmation and records what
/// it was told.
struct ScriptedPrompt {
    answer: bool,
    told: Vec<String>,
    confirmed: u32,
}

impl ScriptedPrompt {
    fn answering(answer: bool) -> Self {
        Self { answer, told: Vec::new(), confirmed: 0 }
    }
}

impl Prompt for ScriptedPrompt {
    fn tell(&mut self, message: &str) {
        self.told.push(message.to_owned());
    }

    fn confirm(&mut self, _question: &str) -> Result<bool, AppError> {
        self.confirmed += 1;
        Ok(self.answer)
    }
}

/// A [`Prompt`] double that panics if ever asked anything, for proving
/// `--yes` skips the prompt entirely.
struct PanicsIfAsked;

impl Prompt for PanicsIfAsked {
    fn tell(&mut self, _message: &str) {}

    fn confirm(&mut self, _question: &str) -> Result<bool, AppError> {
        panic!("forget_session must not confirm when `yes` is true");
    }
}

#[test]
fn forget_session_removes_the_directory_when_confirmed() {
    let fx = fixture();
    let opts = SessionOptions::default();
    let session =
        ensure_session(&fx.paths, &owned_record(), &opts, &fx.env, &ctx()).expect("should succeed");
    assert!(session.path.exists());

    let mut prompt = ScriptedPrompt::answering(true);
    forget_session(&fx.paths, &owned_record(), &mut prompt, false).expect("should succeed");

    assert!(!session.path.exists(), "the session directory is gone");
    assert_eq!(prompt.confirmed, 1);
    assert!(prompt.told.iter().any(|line| line.contains(&session.path.display().to_string())));
}

#[test]
fn forget_session_with_yes_never_asks() {
    let fx = fixture();
    let opts = SessionOptions::default();
    let session =
        ensure_session(&fx.paths, &owned_record(), &opts, &fx.env, &ctx()).expect("should succeed");

    forget_session(&fx.paths, &owned_record(), &mut PanicsIfAsked, true).expect("should succeed");
    assert!(!session.path.exists());
}

#[test]
fn forget_session_declined_removes_nothing() {
    let fx = fixture();
    let opts = SessionOptions::default();
    let session =
        ensure_session(&fx.paths, &owned_record(), &opts, &fx.env, &ctx()).expect("should succeed");

    let mut prompt = ScriptedPrompt::answering(false);
    let err = forget_session(&fx.paths, &owned_record(), &mut prompt, false)
        .expect_err("a decline should refuse");
    assert!(matches!(err, AppError::Refused { .. }), "{err:?}");
    assert!(session.path.exists(), "nothing was removed");
}

#[test]
fn forget_session_with_nothing_to_forget_is_a_no_op() {
    let fx = fixture();
    let mut prompt = ScriptedPrompt::answering(true);
    forget_session(&fx.paths, &owned_record(), &mut prompt, false).expect("should succeed");
    assert_eq!(prompt.confirmed, 0, "there was nothing to confirm");
    assert!(!fx.paths.session_dir(ACCT, ORG).exists());
}

#[test]
fn forget_session_refuses_non_owned_accounts() {
    let fx = fixture();
    let live = crate::config::new_record(ACCT.to_owned(), ORG.to_owned(), AccountKind::Live)
        .expect("the fixture identifiers are valid");
    let mut prompt = ScriptedPrompt::answering(true);
    let err = forget_session(&fx.paths, &live, &mut prompt, true)
        .expect_err("a Live account has no session to forget");
    assert!(err.to_string().contains("live"), "{err}");
}

#[test]
fn forget_session_leaves_the_namespace_and_lock_untouched() {
    let fx = fixture();
    let opts = SessionOptions::default();
    ensure_session(&fx.paths, &owned_record(), &opts, &fx.env, &ctx()).expect("should succeed");

    let ns_dir = fx.paths.namespace_dir(ACCT, ORG);
    std::fs::create_dir_all(&ns_dir).expect("writable");
    std::fs::write(ns_dir.join(".credentials.json"), "{}").expect("writable");
    std::fs::create_dir_all(fx.paths.locks_dir()).expect("writable");
    let lock_path = fx.paths.lock_path(ACCT, ORG);
    std::fs::write(&lock_path, "{}").expect("writable");

    let mut prompt = ScriptedPrompt::answering(true);
    forget_session(&fx.paths, &owned_record(), &mut prompt, true).expect("should succeed");

    assert!(ns_dir.join(".credentials.json").exists(), "the namespace is untouched");
    assert!(lock_path.exists(), "the lock file is untouched");
}
