//! `agentctl claude import`, run end to end in this process.
//!
//! Each test stands up a temporary store and a scripted keychain, runs
//! [`run_with`] — the same code path the command runs — and then asserts on
//! the two things that matter about an import: what the registry says
//! afterwards, and everything that did *not* happen. The negative claims are
//! the point. Plan AC19 asks for zero writes of any kind — no keychain write,
//! no file under the namespace root — which is an assertion about absence, so
//! it is made against a real temporary directory and a reader that records
//! every call.
//!
//! Nothing here reads or writes the process environment: `std::env::set_var`
//! is `unsafe` in edition 2024 and would race every other test in the binary,
//! so the home directory, the keychain and the store all arrive inside
//! [`Import`].

use std::fs;
use std::path::PathBuf;

use clap::Parser;
use serde_json::json;
use tempfile::TempDir;

use super::*;
use crate::cli::ClaudeCommand;
use crate::cli::Cli;
use crate::cli::Command;
use crate::config::AccountKind;
use crate::provider::claude::namespace::LIVE_SERVICE;
use crate::provider::claude::namespace::sha8;
use crate::secret::KeychainStatus;
use crate::secret::fake_reader::FakeReader;

const FIRST_ACCT: &str = "aaaaaaaa-1111-2222-3333-444444444444";
const FIRST_ORG: &str = "bbbbbbbb-5555-6666-7777-888888888888";
const SECOND_ACCT: &str = "cccccccc-9999-0000-1111-222222222222";

/// A temporary store, a fake home, and the paths that address them.
struct Store {
    _dir: TempDir,
    home: PathBuf,
    paths: Paths,
}

fn store() -> Store {
    let dir = TempDir::new().expect("a temporary directory should be creatable");
    let home = dir.path().join("home");
    fs::create_dir_all(home.join(".claude")).expect("the fake home should be creatable");
    let paths = Paths::with_config_dir(dir.path().join("config"));
    Store { _dir: dir, home, paths }
}

impl Store {
    fn env(&self) -> EnvView {
        EnvView::with_home(self.home.clone())
    }

    /// The service name Claude Code would give a session pointed at `dir`.
    fn service_for(&self, dir: &Path) -> String {
        format!("{LIVE_SERVICE}-{}", sha8(&dir.to_string_lossy()))
    }

    /// Every regular file anywhere under this store, as a sorted list of
    /// paths relative to the configuration directory.
    fn files(&self) -> Vec<String> {
        let mut found = Vec::new();
        collect_files(self.paths.config_dir(), self.paths.config_dir(), &mut found);
        found.sort();
        found
    }

    /// Every regular file under `claude/`, where credentials would live.
    ///
    /// Always empty after an import: an import records what another
    /// configuration directory holds and never materializes a credential of
    /// its own (decision D-007).
    fn namespace_files(&self) -> Vec<String> {
        let root = self.paths.namespace_root();
        let mut found = Vec::new();
        collect_files(&root, &root, &mut found);
        found.sort();
        found
    }

    fn config(&self) -> AgentctlConfig {
        AgentctlConfig::load(&self.paths).expect("the registry should be readable")
    }

    fn registry_bytes(&self) -> Vec<u8> {
        fs::read(self.paths.config_file()).expect("the registry should exist")
    }
}

fn collect_files(root: &Path, dir: &Path, found: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(root, &path, found);
        } else {
            let shown = path.strip_prefix(root).unwrap_or(&path);
            found.push(shown.display().to_string());
        }
    }
}

/// Parses a command line into the arguments the command actually receives.
///
/// Going through `clap` rather than building the struct pins the spellings
/// down too: `--claude-config-dir` is deliberately not `--config-dir`, which
/// is the global option naming agentctl's own store.
fn args(argv: &[&str]) -> ImportArgs {
    let mut full = vec!["agentctl", "claude", "import"];
    full.extend_from_slice(argv);
    let cli = Cli::try_parse_from(full).expect("the argument list should parse");
    let Command::Claude { command: ClaudeCommand::Import(args) } = cli.command else {
        panic!("the parsed command should be `claude import`");
    };
    args
}

/// A credential blob in Claude Code's shape (fact F40), naming an account.
fn blob(acct: &str, org: Option<&str>, email: &str) -> String {
    let mut token_account = json!({ "uuid": acct, "emailAddress": email });
    if let Some(org) = org {
        token_account["organizationUuid"] = json!(org);
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

fn import(store: &Store, args: &ImportArgs, reader: &dyn KeychainReader) -> Vec<String> {
    let env = store.env();
    let import = Import { paths: &store.paths, args, reader, env: &env };
    run_with(&import).expect("the import should succeed")
}

// ---------------------------------------------------------------------------
// AC19 — keychain
// ---------------------------------------------------------------------------

#[test]
fn ac19_a_named_directory_lands_in_the_registry_and_nothing_is_written_to_the_keychain() {
    let store = store();
    let other = store.home.join("work");
    fs::create_dir_all(&other).expect("the other config dir should be creatable");
    let service = store.service_for(&other);
    let reader = FakeReader::unlocked()
        .with_item(&service, blob(FIRST_ACCT, Some(FIRST_ORG), "work@example.com").as_bytes());

    let lines = import(
        &store,
        &args(&["--from", "keychain", "--claude-config-dir", &other.display().to_string()]),
        &reader,
    );
    assert!(lines.contains(&"imported 1, skipped 0, already known 0".to_owned()), "{lines:#?}");

    let config = store.config();
    assert_eq!(config.accounts.len(), 1);
    assert_eq!(config.accounts[0].key(), (FIRST_ACCT, FIRST_ORG));
    assert_eq!(
        config.accounts[0].kind,
        AccountKind::ConfigDirReadOnly {
            dir: other,
            service: service.clone(),
            shares_live_dir: false,
        }
    );

    // One read, for the identity, and no other keychain traffic. `FakeReader`
    // has no write side to call: the trait does not have one (invariant I1).
    assert_eq!(reader.reads(), vec![service]);
    assert_eq!(store.files(), vec![".config.lock".to_owned(), "config.json".to_owned()]);
    assert!(store.namespace_files().is_empty(), "{:?}", store.namespace_files());
}

#[test]
fn ac19_an_alias_of_the_live_config_dir_is_warned_about_and_recorded_as_a_sibling() {
    let store = store();
    let alias = store.home.join("alias");
    std::os::unix::fs::symlink(store.home.join(".claude"), &alias)
        .expect("a symlink should be creatable");
    let service = store.service_for(&alias);
    let reader = FakeReader::unlocked()
        .with_item(&service, blob(SECOND_ACCT, None, "alias@example.com").as_bytes());

    let lines = import(
        &store,
        &args(&["--from", "keychain", "--claude-config-dir", &alias.display().to_string()]),
        &reader,
    );

    assert!(lines.iter().any(|line| line.contains("alias of the live config dir")), "{lines:#?}");
    let config = store.config();
    assert_eq!(config.accounts.len(), 1);
    let AccountKind::ConfigDirReadOnly { shares_live_dir, .. } = config.accounts[0].kind else {
        panic!("the record should be a read-only config-dir account");
    };
    assert!(shares_live_dir, "an alias of the live directory is a stale sibling (F41)");
}

#[test]
fn ac19_a_directory_with_no_item_is_reported_and_leaves_the_registry_empty() {
    let store = store();
    let missing = store.home.join("nothing-here");
    let reader = FakeReader::unlocked();

    let lines = import(
        &store,
        &args(&["--from", "keychain", "--claude-config-dir", &missing.display().to_string()]),
        &reader,
    );

    assert!(
        lines.iter().any(|line| line.contains("no keychain item for")
            && line.contains(&missing.display().to_string())),
        "{lines:#?}"
    );
    assert!(!store.paths.config_file().exists(), "nothing was imported, so nothing was written");
    assert!(reader.reads().is_empty());
}

#[test]
fn a_second_import_leaves_the_registry_byte_identical() {
    // Decision D-007: an import records what is already true, so running it
    // again has nothing left to record and nothing to overwrite.
    let store = store();
    let other = store.home.join("work");
    fs::create_dir_all(&other).expect("the other config dir should be creatable");
    let service = store.service_for(&other);
    let reader = FakeReader::unlocked()
        .with_item(&service, blob(FIRST_ACCT, Some(FIRST_ORG), "work@example.com").as_bytes());
    let argv = args(&["--from", "keychain", "--claude-config-dir", &other.display().to_string()]);

    import(&store, &argv, &reader);
    let first = store.registry_bytes();

    let lines = import(&store, &argv, &reader);
    assert!(lines.contains(&"imported 0, skipped 0, already known 1".to_owned()), "{lines:#?}");
    assert_eq!(store.registry_bytes(), first, "a second import must change nothing");
}

#[test]
fn a_dry_run_prints_the_plan_and_writes_nothing_at_all() {
    let store = store();
    let other = store.home.join("work");
    fs::create_dir_all(&other).expect("the other config dir should be creatable");
    let service = store.service_for(&other);
    let reader = FakeReader::unlocked()
        .with_item(&service, blob(FIRST_ACCT, Some(FIRST_ORG), "work@example.com").as_bytes());

    let lines = import(
        &store,
        &args(&[
            "--from",
            "keychain",
            "--claude-config-dir",
            &other.display().to_string(),
            "--dry-run",
        ]),
        &reader,
    );

    assert!(lines.iter().any(|line| line.contains("import config-dir-read-only")), "{lines:#?}");
    assert!(lines.contains(&"--dry-run: nothing was written".to_owned()), "{lines:#?}");
    assert!(
        !store.paths.config_dir().exists(),
        "a dry run must not even bring the store into existence"
    );
}

#[test]
fn a_locked_keychain_refuses_the_import_instead_of_reporting_an_empty_one() {
    let store = store();
    let reader = FakeReader::unlocked().with_preflight(KeychainStatus::Locked);
    let env = store.env();
    let args = args(&["--from", "keychain"]);
    let import = Import { paths: &store.paths, args: &args, reader: &reader, env: &env };

    let err = run_with(&import).expect_err("an unreadable keychain has nothing to import from");
    assert!(err.to_string().contains("locked"), "{err}");
    assert_eq!(err.exit_code(), crate::error::EXIT_FATAL);
}

#[test]
fn a_keychain_import_never_asks_about_the_switchers_own_items() {
    let store = store();
    let service = store.service_for(Path::new("/somewhere"));
    let reader = FakeReader::unlocked()
        .with_item(&service, blob(FIRST_ACCT, Some(FIRST_ORG), "one@example.com").as_bytes())
        .with_item("claude-switcher:someone@example.com", b"never read");

    import(&store, &args(&["--from", "keychain"]), &reader);

    assert_eq!(
        reader.reads(),
        vec![service],
        "the listing prefix excludes `claude-switcher:*`, so it is never even considered"
    );
}
