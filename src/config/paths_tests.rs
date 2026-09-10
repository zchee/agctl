//! Tests for path derivation, directory modes and the namespace-root check
//! (plan AC28, AC15's path half).

use std::os::unix::fs::PermissionsExt;

use tempfile::TempDir;

use super::*;

fn temp() -> TempDir {
    TempDir::new().expect("a temporary directory should be available")
}

#[test]
fn resolve_precedence_prefers_the_cli_override() {
    let tests = map_cases();
    for (name, case) in tests {
        let resolved = Paths::resolve_from(case.cli.as_deref(), case.env.as_deref(), || {
            Ok(PathBuf::from("/xdg/config"))
        })
        .expect("resolution should succeed when a fallback is available");
        assert_eq!(resolved.config_dir(), Path::new(case.expected), "{name}");
    }
}

struct Case {
    cli: Option<PathBuf>,
    env: Option<PathBuf>,
    expected: &'static str,
}

fn map_cases() -> std::collections::BTreeMap<&'static str, Case> {
    let mut tests = std::collections::BTreeMap::new();
    tests.insert(
        "success: cli wins over env and xdg",
        Case {
            cli: Some(PathBuf::from("/from/cli")),
            env: Some(PathBuf::from("/from/env")),
            expected: "/from/cli",
        },
    );
    tests.insert(
        "success: env wins over xdg",
        Case { cli: None, env: Some(PathBuf::from("/from/env")), expected: "/from/env" },
    );
    tests.insert(
        "success: xdg fallback appends agctl",
        Case { cli: None, env: None, expected: "/xdg/config/agctl" },
    );
    tests
}

#[test]
fn resolve_reports_a_missing_home_only_when_it_is_needed() {
    let failing = || Err(AppError::Config("no home".to_owned()));
    assert!(Paths::resolve_from(None, None, failing).is_err());

    let failing = || Err(AppError::Config("no home".to_owned()));
    let resolved = Paths::resolve_from(Some(Path::new("/store")), None, failing)
        .expect("an override must not consult the base directory");
    assert_eq!(resolved.config_dir(), Path::new("/store"));
}

#[test]
fn derived_paths_follow_the_documented_layout() {
    let paths = Paths::with_config_dir(PathBuf::from("/store"));
    assert_eq!(paths.config_file(), Path::new("/store/config.json"));
    assert_eq!(paths.config_lock(), Path::new("/store/.config.lock"));
    assert_eq!(paths.namespace_root(), Path::new("/store/claude"));
    assert_eq!(paths.namespace_dir("acct", "org"), Path::new("/store/claude/acct/org"));
    assert_eq!(paths.locks_dir(), Path::new("/store/claude/.locks"));
    assert_eq!(paths.lock_path("acct", "org"), Path::new("/store/claude/.locks/acct.org.lock"));
    assert_eq!(paths.cache_dir(), Path::new("/store/cache/claude"));
}

#[test]
fn ensure_dirs_creates_every_level_at_0700() {
    let dir = temp();
    let paths = Paths::with_config_dir(dir.path().join("nested").join("store"));
    paths.ensure_dirs().expect("directory creation should succeed in a temporary directory");

    for created in [
        paths.config_dir().to_path_buf(),
        paths.namespace_root(),
        paths.locks_dir(),
        paths.cache_dir(),
    ] {
        let meta = std::fs::metadata(&created).expect("the directory should exist");
        assert!(meta.is_dir(), "{} should be a directory", created.display());
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, DIR_MODE, "{} has mode {mode:o}", created.display());
    }
}

#[test]
fn ensure_dirs_is_idempotent() {
    let dir = temp();
    let paths = Paths::with_config_dir(dir.path().join("store"));
    paths.ensure_dirs().expect("first call should succeed");
    paths.ensure_dirs().expect("second call should succeed");
}

#[test]
fn session_paths_follow_the_documented_layout() {
    let paths = Paths::with_config_dir(PathBuf::from("/store"));
    assert_eq!(paths.session_root(), Path::new("/store/claude-sessions"));
    assert_eq!(paths.session_dir("acct", "org"), Path::new("/store/claude-sessions/acct/org"));
}

#[test]
fn session_root_is_outside_namespace_root() {
    let paths = Paths::with_config_dir(PathBuf::from("/store"));
    assert!(!paths.session_root().starts_with(paths.namespace_root()));
    assert!(!paths.namespace_root().starts_with(paths.session_root()));
}

#[test]
fn is_under_session_root_rejects_escapes() {
    let paths = Paths::with_config_dir(PathBuf::from("/store"));
    let root = paths.session_root();

    let accepted = [
        root.join("acct").join("org").join("mcp.json"),
        root.join("acct"),
        PathBuf::from("/store/claude-sessions/./acct/../acct/org/mcp.json"),
    ];
    for path in accepted {
        assert!(paths.is_under_session_root(&path), "{} should be accepted", path.display());
    }

    let refused = [
        root.clone(),
        PathBuf::from("/store/config.json"),
        PathBuf::from("/store/claude-sessions/../config.json"),
        PathBuf::from("/store/claude-sessions/acct/../../../etc/passwd"),
        PathBuf::from("/etc/passwd"),
        paths.namespace_root().join("acct").join("org"),
        PathBuf::from("claude-sessions/acct/org/mcp.json"),
        PathBuf::from("/store/claude-sessionsx/acct"),
    ];
    for path in refused {
        assert!(!paths.is_under_session_root(&path), "{} should be refused", path.display());
    }
}

#[test]
fn is_under_namespace_root_rejects_escapes() {
    let paths = Paths::with_config_dir(PathBuf::from("/store"));
    let root = paths.namespace_root();

    let accepted = [
        root.join("acct").join("org").join(".credentials.json"),
        root.join("acct"),
        PathBuf::from("/store/claude/./acct/../acct/org/.credentials.json"),
    ];
    for path in accepted {
        assert!(paths.is_under_namespace_root(&path), "{} should be accepted", path.display());
    }

    let refused = [
        root.clone(),
        PathBuf::from("/store/config.json"),
        PathBuf::from("/store/claude/../config.json"),
        PathBuf::from("/store/claude/acct/../../../etc/passwd"),
        PathBuf::from("/etc/passwd"),
        PathBuf::from("claude/acct/org/.credentials.json"),
        PathBuf::from("/store/claudex/acct"),
    ];
    for path in refused {
        assert!(!paths.is_under_namespace_root(&path), "{} should be refused", path.display());
    }
}

#[test]
fn lexical_normalize_keeps_leading_parent_components() {
    assert_eq!(lexical_normalize(Path::new("../x")), PathBuf::from("../x"));
    assert_eq!(lexical_normalize(Path::new("a/./b/../c")), PathBuf::from("a/c"));
    assert_eq!(lexical_normalize(Path::new("/a/b/../..")), PathBuf::from("/"));
}

#[test]
fn validate_segment_accepts_uuids_and_the_unknown_org() {
    for good in ["11111111-1111-4111-8111-111111111111", UNKNOWN_ORG, "a.b_c-1"] {
        validate_segment(good).unwrap_or_else(|err| panic!("`{good}` should be valid: {err}"));
    }
}

#[test]
fn validate_segment_rejects_separators_and_dots() {
    for bad in ["", ".", "..", "a/b", "a\\b", "a b", "a\u{0}b", "../x", "café"] {
        assert!(validate_segment(bad).is_err(), "`{bad}` should be rejected");
    }
}

#[test]
fn resolve_reads_the_documented_environment_variable_name() {
    assert_eq!(CONFIG_DIR_ENV, "AGCTL_CONFIG_DIR");
}

#[test]
fn resolve_honours_a_cli_override_without_touching_the_environment() {
    // The full `resolve`, not the injectable half: an override must win over
    // both `AGCTL_CONFIG_DIR` and the XDG base directory, whatever this
    // test runner's environment happens to hold.
    let dir = temp();
    let resolved = Paths::resolve(Some(dir.path())).expect("an override always resolves");
    assert_eq!(resolved.config_dir(), dir.path());
}
