//! Tests for Claude Code's keychain naming rule (plan AC11, facts F14, F30,
//! F41).
//!
//! The three `sha8` vectors are literal absolute paths, re-verified against
//! `shasum -a 256` on 2026-09-08. They are the load-bearing assertion in this
//! file: a naming rule that is subtly wrong produces plausible service names
//! that name nothing, and every downstream test would still pass.

use std::path::PathBuf;

use super::*;

fn env(securestorage: Option<&str>, config: Option<&str>) -> EnvView {
    EnvView {
        securestorage_dir: securestorage.map(str::to_owned),
        config_dir: config.map(str::to_owned),
        home: PathBuf::from("/Users/zchee"),
        oauth_token_set: false,
    }
}

#[test]
fn sha8_matches_the_verified_vectors() {
    let vectors = [
        ("/Users/zchee/.claude", "95313c21"),
        ("/Users/zchee/src/github.com/zchee/agent/claude", "5cdc535f"),
        ("/Users/zchee/.config/claude-code", "86c75be7"),
    ];
    for (raw, expected) in vectors {
        assert_eq!(sha8(raw), expected, "sha8({raw})");
    }
}

#[test]
fn sha8_normalizes_to_nfc() {
    // "café" composed and decomposed must hash alike: the shell hands over
    // decomposed paths on macOS while a config file usually carries composed
    // ones, and they name the same directory.
    let composed = "/Users/zchee/caf\u{e9}";
    let decomposed = "/Users/zchee/cafe\u{301}";
    assert_ne!(composed, decomposed, "the two spellings must differ as bytes");
    assert_eq!(sha8(composed), sha8(decomposed));
}

#[test]
fn service_name_gate_is_truthiness_not_presence() {
    let tests: Vec<(&str, EnvView, String)> = vec![
        ("nothing set: the live name", env(None, None), LIVE_SERVICE.to_owned()),
        (
            "empty securestorage wins over a set config dir",
            env(Some(""), Some("/x")),
            LIVE_SERVICE.to_owned(),
        ),
        ("empty config dir alone", env(None, Some("")), LIVE_SERVICE.to_owned()),
        (
            "securestorage set: it is hashed",
            env(Some("/Users/zchee/.config/claude-code"), Some("/x")),
            format!("{LIVE_SERVICE}-86c75be7"),
        ),
        (
            "config dir set, securestorage absent: config dir is hashed",
            env(None, Some("/Users/zchee/src/github.com/zchee/agent/claude")),
            format!("{LIVE_SERVICE}-5cdc535f"),
        ),
    ];
    for (name, view, expected) in tests {
        assert_eq!(service_name(&view), expected, "{name}");
    }
}

#[test]
fn service_name_hashes_the_raw_string_not_the_resolved_path() {
    let dir = tempfile::TempDir::new().expect("a temporary directory");
    let real = dir.path().join("real");
    std::fs::create_dir(&real).expect("the target directory should be creatable");
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).expect("the symlink should be creatable");

    let through_link = env(None, Some(&link.to_string_lossy()));
    let through_real = env(None, Some(&real.to_string_lossy()));
    assert_ne!(
        service_name(&through_link),
        service_name(&through_real),
        "two spellings of one directory are two different keychain items (fact F41)"
    );
    assert_eq!(
        canonical(&link).expect("the link resolves"),
        canonical(&real).expect("the target resolves"),
        "but they canonicalize to the same physical directory"
    );
}

#[test]
fn service_name_applies_nfc_on_both_branches() {
    let decomposed = "/Users/zchee/cafe\u{301}";
    let composed = "/Users/zchee/caf\u{e9}";
    assert_eq!(
        service_name(&env(Some(decomposed), None)),
        service_name(&env(Some(composed), None))
    );
    assert_eq!(
        service_name(&env(None, Some(decomposed))),
        service_name(&env(None, Some(composed)))
    );
}

#[test]
fn classify_recognises_only_credential_items() {
    let tests = [
        ("Claude Code-credentials", Some(ServiceKind::Live)),
        ("Claude Code-credentials-5cdc535f", Some(ServiceKind::ConfigDir("5cdc535f".to_owned()))),
        // The legacy API-key item (fact F5): same product, not a credential.
        ("Claude Code-86c75be7", None),
        ("claude-switcher:user@example.com", None),
        ("Claude Code-credentials-", None),
        ("Claude Code-credentials-5CDC535F", None),
        ("Claude Code-credentials-5cdc535", None),
        ("Claude Code-credentials-5cdc535ff", None),
        ("Claude Code-credentials-zzzzzzzz", None),
        ("Chrome Safe Storage", None),
    ];
    for (service, expected) in tests {
        assert_eq!(classify(service), expected, "classify({service})");
    }
}

#[test]
fn live_store_dir_follows_a_underscore() {
    let home = PathBuf::from("/Users/zchee");
    let tests: Vec<(&str, EnvView, PathBuf)> = vec![
        ("nothing set", env(None, None), home.join(".claude")),
        ("securestorage set", env(Some("/store"), Some("/config")), PathBuf::from("/store")),
        // Truthiness again: an empty securestorage falls back to ~/.claude,
        // not to CLAUDE_CONFIG_DIR (plan AC11).
        ("empty securestorage", env(Some(""), Some("/config")), home.join(".claude")),
        ("config dir only", env(None, Some("/config")), PathBuf::from("/config")),
        ("empty config dir", env(None, Some("")), home.join(".claude")),
    ];
    for (name, view, expected) in tests {
        assert_eq!(live_store_dir(&view), expected, "{name}");
    }
}

#[test]
fn claude_json_is_keyed_on_the_config_dir_not_the_store_dir() {
    let view = env(Some("/store"), Some("/config"));
    assert_eq!(live_store_dir(&view), PathBuf::from("/store"));
    assert_eq!(claude_json_path(&view), PathBuf::from("/config/.claude.json"));

    let no_config = env(Some("/store"), None);
    assert_eq!(claude_json_path(&no_config), PathBuf::from("/Users/zchee/.claude.json"));
}

#[test]
fn global_config_path_prefers_config_json_under_the_config_dir() {
    // Claude Code's `Lt()`: `<be()>/.config.json` when it exists, else `OQt()`.
    // Every row runs against a temporary home, so the one existence check this
    // function makes never looks at the developer's own `~/.claude`.
    let home = tempfile::TempDir::new().expect("a temporary home");
    let other = tempfile::TempDir::new().expect("a temporary config dir");
    let home_path = home.path().to_path_buf();
    let other_path = other.path().to_path_buf();
    let at_home = |config_dir: Option<&str>| EnvView {
        securestorage_dir: None,
        config_dir: config_dir.map(str::to_owned),
        home: home_path.clone(),
        oauth_token_set: false,
    };
    let other_text = other_path.to_string_lossy().into_owned();

    // Neither `.config.json` exists yet: `claude_json_path`'s answer.
    let tests: Vec<(&str, EnvView, PathBuf)> = vec![
        ("nothing set, no .config.json", at_home(None), home_path.join(".claude.json")),
        (
            "CLAUDE_CONFIG_DIR set, no .config.json",
            at_home(Some(&other_text)),
            other_path.join(".claude.json"),
        ),
        (
            "CLAUDE_CONFIG_DIR empty, no .config.json",
            at_home(Some("")),
            home_path.join(".claude.json"),
        ),
    ];
    for (name, view, expected) in tests {
        assert_eq!(global_config_path(&view), expected, "{name}");
        assert_eq!(
            global_config_path(&view),
            claude_json_path(&view),
            "{name}: falls back to OQt()"
        );
    }

    // `$HOME/.claude/.config.json` present: it wins for an unset and for an
    // empty `CLAUDE_CONFIG_DIR` — the empty value is never a relative path.
    std::fs::create_dir_all(home_path.join(".claude")).expect("the config home is creatable");
    std::fs::write(home_path.join(".claude").join(".config.json"), "{}").expect("a .config.json");
    let preferred = home_path.join(".claude").join(".config.json");
    assert_eq!(global_config_path(&at_home(None)), preferred, "$HOME/.claude/.config.json present");
    assert_eq!(
        global_config_path(&at_home(Some(""))),
        preferred,
        "CLAUDE_CONFIG_DIR=\"\" takes the $HOME/.claude rule, never a relative path"
    );
    assert!(global_config_path(&at_home(Some(""))).is_absolute(), "never a relative path");
    // …but not for a `CLAUDE_CONFIG_DIR` naming somewhere else, whose own
    // `.config.json` is absent.
    assert_eq!(
        global_config_path(&at_home(Some(&other_text))),
        other_path.join(".claude.json"),
        "a set CLAUDE_CONFIG_DIR looks only under itself"
    );

    // `CLAUDE_CONFIG_DIR=/x` with `/x/.config.json` present: it.
    std::fs::write(other_path.join(".config.json"), "{}").expect("a .config.json under /x");
    assert_eq!(
        global_config_path(&at_home(Some(&other_text))),
        other_path.join(".config.json"),
        "CLAUDE_CONFIG_DIR=/x and /x/.config.json present"
    );

    // Followed like `existsSync`: a link named `.config.json` counts when its
    // target exists, and a dangling one does not.
    let linked = tempfile::TempDir::new().expect("a third directory");
    let dangling = linked.path().join(".config.json");
    std::os::unix::fs::symlink(linked.path().join("missing"), &dangling).expect("a dangling link");
    let linked_view = at_home(Some(&linked.path().to_string_lossy()));
    assert_eq!(
        global_config_path(&linked_view),
        linked.path().join(".claude.json"),
        "a dangling .config.json link does not exist to existsSync"
    );
}

#[test]
fn backups_dir_is_under_the_config_home_not_beside_the_config_file() {
    let view = env(None, None);
    assert_eq!(backups_dir(&view), PathBuf::from("/Users/zchee/.claude/backups"));
    assert_ne!(
        backups_dir(&view).parent(),
        claude_json_path(&view).parent(),
        "the backups are not beside `~/.claude.json`"
    );
    assert_eq!(backups_dir(&env(None, Some("/x"))), PathBuf::from("/x/backups"));
    assert_eq!(
        backups_dir(&env(None, Some(""))),
        PathBuf::from("/Users/zchee/.claude/backups"),
        "an empty CLAUDE_CONFIG_DIR is $HOME/.claude, never relative"
    );
    // CLAUDE_SECURESTORAGE_CONFIG_DIR names a credential namespace, not the
    // configuration home.
    assert_eq!(
        backups_dir(&env(Some("/store"), None)),
        PathBuf::from("/Users/zchee/.claude/backups")
    );

    // The lock name is the literal file name plus `.lock`.
    assert_eq!(
        config_lock_name(std::path::Path::new("/Users/zchee/.claude.json")),
        Some(std::ffi::OsString::from(".claude.json.lock"))
    );
    assert_eq!(
        config_lock_name(std::path::Path::new("/x/.config.json")),
        Some(std::ffi::OsString::from(".config.json.lock"))
    );
    assert_eq!(config_lock_name(std::path::Path::new("/")), None);
}

#[test]
fn export_spelling_trims_one_trailing_slash_and_normalizes() {
    assert_eq!(export_spelling(std::path::Path::new("/a/b/")), "/a/b");
    assert_eq!(export_spelling(std::path::Path::new("/a/b")), "/a/b");
    assert_eq!(export_spelling(std::path::Path::new("/")), "/");
    assert_eq!(
        export_spelling(std::path::Path::new("/cafe\u{301}")),
        export_spelling(std::path::Path::new("/caf\u{e9}"))
    );
}

#[test]
fn the_environment_variable_names_are_the_ones_claude_code_reads() {
    assert_eq!(SECURESTORAGE_ENV, "CLAUDE_SECURESTORAGE_CONFIG_DIR");
    assert_eq!(CONFIG_DIR_ENV, "CLAUDE_CONFIG_DIR");
    assert_eq!(OAUTH_TOKEN_ENV, "CLAUDE_CODE_OAUTH_TOKEN");
}

#[test]
fn from_process_reads_the_environment_without_mutating_it() {
    // Only structural assertions: the values belong to whatever environment
    // the test runner was started in, and this process must never change
    // them (`set_var` is `unsafe` in edition 2024 and would race every other
    // test in this binary).
    let view = EnvView::from_process();
    let service = service_name(&view);
    assert!(service.starts_with(LIVE_SERVICE), "{service}");
    assert!(
        service.len() == LIVE_SERVICE.len() || service.len() == LIVE_SERVICE.len() + 9,
        "a service name is either unsuffixed or carries a nine-character suffix: {service}"
    );
    let _ = live_store_dir(&view);
    let _ = claude_json_path(&view);
}
