#![cfg(feature = "testing")]
#![allow(
    dead_code,
    reason = "each end-to-end file uses a different subset of this harness, and \
              `mod common` is compiled once per file"
)]

//! The end-to-end harness: one isolated `agentctl` per test.
//!
//! Everything here exists to make one promise cheap to keep — **no test ever
//! reaches the developer's real home directory, keychain or Anthropic
//! account**. W1 recorded an incident where a bare smoke test issued a live
//! usage GET the moment `status` started working, so every command this
//! harness builds is cut off from all three at once:
//!
//! - `--config-dir` and `HOME` point into a temporary directory;
//! - `CLAUDE_CONFIG_DIR`, `CLAUDE_SECURESTORAGE_CONFIG_DIR`,
//!   `CLAUDE_CODE_OAUTH_TOKEN` and `AGENTCTL_CONFIG_DIR` are removed, so an
//!   inherited value cannot point the binary back at the real machine;
//! - the three endpoint overrides default to `127.0.0.1:1`, which nothing
//!   listens on, so a regression that fetched anyway fails loudly here rather
//!   than quietly reaching Anthropic;
//! - the keychain is either disabled outright or replaced by the fake
//!   `security` script, never `/usr/bin/security`.
//!
//! # The fake `security` is one script, shared with the unit tests
//!
//! [`FAKE_SECURITY`] is the same `fixtures/fake-security.sh` that
//! `src/secret/fake_security.rs` compiles in, because `agentctl` is a binary
//! with no library target and `tests/` cannot call into it. One script means
//! one behaviour and, more to the point, one argv log: plan AC25 requires that
//! across the whole suite the only subcommands agentctl ever issues are
//! `show-keychain-info`, `find-generic-password` and `dump-keychain`, and
//! [`Fixture::assert_keychain_read_only`] turns that into an assertion every
//! keychain-using test makes for itself.
//!
//! # What is asserted about the wire
//!
//! `httpmock` servers are per test and bound to loopback. The mocks are not
//! stand-ins for a client: the binary under test really does POST to them, so
//! "exactly one refresh" is a statement about hit counts rather than about a
//! counter a double incremented.

use std::fs;
use std::io::Read;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command as StdCommand;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

use assert_cmd::Command;
use rustix::fs::FlockOperation;
use serde_json::Value;
use serde_json::json;
use sha2::Digest;
use sha2::Sha256;
use tempfile::TempDir;
use unicode_normalization::UnicodeNormalization;

/// The fake `security(1)`, shared verbatim with `src/secret/fake_security.rs`.
pub const FAKE_SECURITY: &str = include_str!("../../fixtures/fake-security.sh");

/// A credential blob with no `tokenAccount`, so no identity (fact F4).
pub const OLD_BLOB: &str = include_str!("../../fixtures/claude/credentials-old-blob.json");

/// The captured usage body every successful fetch answers with.
pub const USAGE_BODY: &str = include_str!("../../fixtures/claude/usage-2026-09-08.json");

/// The keychain service Claude Code uses when no configuration directory is
/// set (fact F14).
pub const LIVE_SERVICE: &str = "Claude Code-credentials";

/// The account uuid every fixture account uses.
pub const ACCT: &str = "11111111-2222-3333-4444-555555555555";

/// The organization uuid every fixture account uses.
pub const ORG: &str = "66666666-7777-8888-9999-000000000000";

/// The email the fixture account is addressed by.
pub const EMAIL: &str = "owner@example.com";

/// The path the mock OAuth token endpoint is served under.
pub const TOKEN_PATH: &str = "/v1/oauth/token";

/// The usage endpoint's path under the base URL (fact F1).
pub const USAGE_PATH: &str = "/api/oauth/usage";

/// The organization directory name a login uses when the exchange named none.
pub const UNKNOWN_ORG: &str = "_unknown-org";

/// The account attribute the fake keychain items carry.
const KEYCHAIN_ACCOUNT: &str = "example";

// ---------------------------------------------------------------------------
// One isolated agentctl
// ---------------------------------------------------------------------------

/// A temporary store, a fake home, and the environment that points one
/// `agentctl` process at both and at nothing else.
pub struct Fixture {
    root: TempDir,
    env: Vec<(String, String)>,
}

impl Fixture {
    /// Builds an isolated store with the keychain disabled outright.
    ///
    /// # Panics
    ///
    /// Panics when the temporary directory cannot be created, which means the
    /// test cannot run at all.
    #[must_use]
    pub fn new() -> Self {
        let root = TempDir::new().expect("a temporary directory should be creatable");
        for relative in ["config", "home", "bin", "keychain-items"] {
            fs::create_dir_all(root.path().join(relative))
                .expect("the fixture directories should be creatable");
        }

        let mut fixture = Self { root, env: Vec::new() };
        // Unroutable by default. A test that means to talk to a server
        // overrides these; a test that does not, cannot reach anything.
        fixture.set("AGENTCTL_CLAUDE_USAGE_URL", "http://127.0.0.1:1");
        fixture.set("AGENTCTL_CLAUDE_TOKEN_URL", "http://127.0.0.1:1/token");
        fixture.set("AGENTCTL_CLAUDE_AUTHORIZE_URL", "http://127.0.0.1:1/authorize");
        // `login` prints the URL either way; opening a window on the
        // developer's desktop from a test run is not acceptable.
        fixture.set("AGENTCTL_NO_BROWSER", "1");
        fixture.set("AGENTCTL_KEYCHAIN_BACKEND", "none");
        fixture
    }

    /// The agentctl configuration directory (`--config-dir`).
    #[must_use]
    pub fn config_dir(&self) -> PathBuf {
        self.root.path().join("config")
    }

    /// The fake `$HOME`.
    #[must_use]
    pub fn home(&self) -> PathBuf {
        self.root.path().join("home")
    }

    /// A scratch path inside the fixture, for resume files and the like.
    #[must_use]
    pub fn scratch(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    /// The registry file.
    #[must_use]
    pub fn config_file(&self) -> PathBuf {
        self.config_dir().join("config.json")
    }

    /// One account's namespace directory.
    #[must_use]
    pub fn ns_dir(&self, acct: &str, org: &str) -> PathBuf {
        self.config_dir().join("claude").join(acct).join(org)
    }

    /// One account's credential file.
    #[must_use]
    pub fn credentials_path(&self, acct: &str, org: &str) -> PathBuf {
        self.ns_dir(acct, org).join(".credentials.json")
    }

    /// One account's namespace lock file.
    #[must_use]
    pub fn lock_path(&self, acct: &str, org: &str) -> PathBuf {
        self.config_dir().join("claude").join(".locks").join(format!("{acct}.{org}.lock"))
    }

    /// The live store directory Claude Code would read (`$HOME/.claude`).
    #[must_use]
    pub fn live_store_dir(&self) -> PathBuf {
        self.home().join(".claude")
    }

    /// Sets one environment variable for every command this fixture builds.
    pub fn set(&mut self, key: &str, value: &str) -> &mut Self {
        self.env.retain(|(existing, _)| existing != key);
        self.env.push((key.to_owned(), value.to_owned()));
        self
    }

    /// Points the usage and token endpoints at a mock server.
    pub fn endpoints(&mut self, base_url: &str) -> &mut Self {
        self.set("AGENTCTL_CLAUDE_USAGE_URL", base_url);
        self.set("AGENTCTL_CLAUDE_TOKEN_URL", &format!("{base_url}{TOKEN_PATH}"));
        self.set("AGENTCTL_CLAUDE_AUTHORIZE_URL", &format!("{base_url}/oauth/authorize"));
        self
    }

    /// Turns on fault injection.
    pub fn fault(&mut self, names: &str) -> &mut Self {
        self.set("AGENTCTL_FAULT", names)
    }

    // -----------------------------------------------------------------------
    // The store
    // -----------------------------------------------------------------------

    /// Writes a registry holding exactly these accounts.
    ///
    /// # Panics
    ///
    /// Panics when the registry cannot be written.
    pub fn write_registry(&self, accounts: Vec<Value>) -> &Self {
        self.write_registry_document(&json!({
            "version": 1,
            "accounts": accounts,
            "forgotten_services": [],
        }))
    }

    /// Writes a whole registry document, for the cases that need a field the
    /// helpers above do not set.
    ///
    /// # Panics
    ///
    /// Panics when the registry cannot be written.
    pub fn write_registry_document(&self, document: &Value) -> &Self {
        let text = serde_json::to_string_pretty(document).expect("the registry is serializable");
        fs::write(self.config_file(), text).expect("the registry should be writable");
        self
    }

    /// An `Owned` registry record for a namespace this store holds.
    #[must_use]
    pub fn owned_record(&self, acct: &str, org: &str) -> Value {
        let spelling = export_spelling(&self.ns_dir(acct, org));
        json!({
            "account_uuid": acct,
            "organization_uuid": org,
            "email": EMAIL,
            "org_name": "Acme",
            "label": null,
            "kind": {
                "kind": "owned",
                "export_spelling": spelling,
                "export_sha8": sha8(&spelling),
            },
            "forgotten": false,
            "created_at": "2026-09-08T00:00:00Z",
        })
    }

    /// A `ConfigDirReadOnly` registry record naming one keychain service.
    #[must_use]
    pub fn config_dir_record(&self, acct: &str, org: &str, service: &str) -> Value {
        json!({
            "account_uuid": acct,
            "organization_uuid": org,
            "email": "read-only@example.com",
            "org_name": null,
            "label": null,
            "kind": {
                "kind": "config_dir_read_only",
                "dir": "",
                "service": service,
                "shares_live_dir": false,
            },
            "forgotten": false,
            "created_at": "2026-09-08T00:00:00Z",
        })
    }

    /// Writes `.credentials.json` into a namespace, 0600 inside 0700 dirs.
    ///
    /// # Panics
    ///
    /// Panics when the namespace cannot be created or written.
    pub fn write_credentials(&self, acct: &str, org: &str, blob: &str) -> PathBuf {
        let ns_dir = self.ns_dir(acct, org);
        fs::create_dir_all(&ns_dir).expect("the namespace should be creatable");
        fs::set_permissions(&ns_dir, PermissionsExt::from_mode(0o700)).expect("mode 0700");
        let path = ns_dir.join(".credentials.json");
        fs::write(&path, blob).expect("the credential file should be writable");
        fs::set_permissions(&path, PermissionsExt::from_mode(0o600)).expect("mode 0600");
        path
    }

    /// Everything in a namespace directory, sorted by name.
    ///
    /// # Panics
    ///
    /// Never: an unreadable namespace is reported as empty, which is what a
    /// caller asserting "nothing was left behind" wants anyway.
    #[must_use]
    pub fn namespace_entries(&self, acct: &str, org: &str) -> Vec<String> {
        let Ok(dir) = fs::read_dir(self.ns_dir(acct, org)) else {
            return Vec::new();
        };
        let mut names: Vec<String> = dir
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    // -----------------------------------------------------------------------
    // The fake keychain
    // -----------------------------------------------------------------------

    /// Installs the fake `security(1)` and switches the keychain on.
    ///
    /// # Panics
    ///
    /// Panics when the script cannot be written.
    pub fn with_keychain(&mut self) -> &mut Self {
        let path = self.root.path().join("bin").join("security");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o755)
            .open(&path)
            .expect("the fake `security` should be creatable");
        file.write_all(FAKE_SECURITY.as_bytes()).expect("the fake `security` should be writable");
        file.sync_all().expect("the fake `security` should be flushed");
        drop(file);

        self.env.retain(|(key, _)| key != "AGENTCTL_KEYCHAIN_BACKEND");
        self.set("AGENTCTL_SECURITY_BIN", &path.to_string_lossy());
        self.set("AGENTCTL_FAKE_SECURITY_LOG", &self.security_log_path().to_string_lossy());
        self.set("AGENTCTL_FAKE_SECURITY_ITEMS", &self.items_dir().to_string_lossy());
        self.set("AGENTCTL_FAKE_SECURITY_DUMP", &self.dump_path().to_string_lossy());
        self.dump(&[]);
        self
    }

    /// Where the fake `security` logs one line per invocation.
    #[must_use]
    pub fn security_log_path(&self) -> PathBuf {
        self.root.path().join("security-argv.log")
    }

    /// Where the fake keychain items live.
    #[must_use]
    fn items_dir(&self) -> PathBuf {
        self.root.path().join("keychain-items")
    }

    /// Where the fake `dump-keychain` output lives.
    #[must_use]
    fn dump_path(&self) -> PathBuf {
        self.root.path().join("keychain-dump.txt")
    }

    /// Gives the fake keychain one readable item.
    ///
    /// # Panics
    ///
    /// Panics when the item cannot be written.
    pub fn keychain_item(&self, service: &str, blob: &str) -> &Self {
        let path = self.items_dir().join(item_file_name(service));
        fs::write(path, blob).expect("the keychain item should be writable");
        self
    }

    /// Sets what `dump-keychain` lists, in `security(1)`'s own format.
    ///
    /// # Panics
    ///
    /// Panics when the listing cannot be written.
    pub fn dump(&self, services: &[&str]) -> &Self {
        let mut text = String::from(
            "keychain: \"/Users/example/Library/Keychains/login.keychain-db\"\nversion: 512\n",
        );
        for service in services {
            text.push_str("class: \"genp\"\nattributes:\n");
            text.push_str(&format!("    0x00000007 <blob>=\"{service}\"\n"));
            text.push_str(&format!("    \"acct\"<blob>=\"{KEYCHAIN_ACCOUNT}\"\n"));
            text.push_str(
                "    \"cdat\"<timedate>=0x32303236303930383031323030355A00  \"20260908012005Z\\000\"\n",
            );
            text.push_str(
                "    \"mdat\"<timedate>=0x32303236303930383031323030355A00  \"20260908012005Z\\000\"\n",
            );
            text.push_str(&format!("    \"svce\"<blob>=\"{service}\"\n"));
            text.push_str("    \"type\"<uint32>=<NULL>\n");
        }
        fs::write(self.dump_path(), text).expect("the keychain listing should be writable");
        self
    }

    /// Every argv line the fake `security` has recorded so far.
    #[must_use]
    pub fn security_log(&self) -> Vec<String> {
        fs::read_to_string(self.security_log_path())
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// Asserts plan invariant I1 over this fixture's keychain calls, and
    /// records them in the suite-wide aggregate plan AC25 asks about.
    ///
    /// # Panics
    ///
    /// Panics when agentctl issued any `security` subcommand other than the
    /// three read-only ones — which would mean a keychain write path exists.
    pub fn assert_keychain_read_only(&self) {
        let lines = self.security_log();
        for line in &lines {
            let subcommand = line.split_whitespace().next().unwrap_or_default();
            assert!(
                matches!(
                    subcommand,
                    "show-keychain-info" | "find-generic-password" | "dump-keychain"
                ),
                "agentctl issued a `security {subcommand}`, which phase 1 has no code path for \
                 (plan invariant I1, AC25); full argv: {line}"
            );
        }
        append_to_aggregate_log(&lines);
    }

    // -----------------------------------------------------------------------
    // Running the binary
    // -----------------------------------------------------------------------

    /// An `assert_cmd` handle to the binary, isolated.
    #[must_use]
    pub fn cmd(&self) -> Command {
        // `CARGO_BIN_EXE_agentctl` rather than `assert_cmd`'s `cargo_bin`,
        // which guesses `target/debug/agentctl` relative to the manifest. This
        // project builds into a tmpfs target directory, so that guess can find
        // a stale binary from some earlier build and silently test it.
        let mut command = Command::new(env!("CARGO_BIN_EXE_agentctl"));
        command.args(["--config-dir", &self.config_dir().to_string_lossy()]);
        command.env("HOME", self.home());
        // Removals first: several of these are also things a test sets, and an
        // inherited value must lose to the fixture rather than to the list.
        for key in REMOVED_ENV {
            command.env_remove(key);
        }
        for (key, value) in &self.env {
            command.env(key, value);
        }
        command
    }

    /// A `std::process::Command` handle to the binary, isolated, with every
    /// standard stream piped.
    ///
    /// Used where a test has to interleave with a *running* agentctl — send it
    /// a signal, read the authorize URL it prints, start a second process
    /// while the first holds a lock — which `assert_cmd` cannot express
    /// because it runs a command to completion.
    #[must_use]
    pub fn raw(&self) -> StdCommand {
        let mut command = StdCommand::new(env!("CARGO_BIN_EXE_agentctl"));
        command.args(["--config-dir", &self.config_dir().to_string_lossy()]);
        command.env("HOME", self.home());
        for key in REMOVED_ENV {
            command.env_remove(key);
        }
        for (key, value) in &self.env {
            command.env(key, value);
        }
        command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        command
    }
}

impl Default for Fixture {
    fn default() -> Self {
        Self::new()
    }
}

/// Environment every command starts without.
///
/// An inherited value for any of these would either point the binary back at
/// the real machine — the Claude Code store, the developer's own agentctl
/// store — or quietly change what a test is measuring: a fault switch, a scope
/// set, a keychain backend, or one of the fake `security` script's own
/// scripting variables. Removed *before* the fixture's own settings are
/// applied, so an inherited value loses to the fixture rather than to the
/// list.
const REMOVED_ENV: [&str; 14] = [
    "CLAUDE_CONFIG_DIR",
    "CLAUDE_SECURESTORAGE_CONFIG_DIR",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "AGENTCTL_CONFIG_DIR",
    "AGENTCTL_FAULT",
    "AGENTCTL_FAULT_RESUME",
    "AGENTCTL_CLAUDE_OAUTH_SCOPES",
    "AGENTCTL_CLAUDE_USER_AGENT",
    "AGENTCTL_KEYCHAIN_BACKEND",
    "AGENTCTL_SECURITY_BIN",
    "AGENTCTL_FAKE_SECURITY_SLEEP",
    "AGENTCTL_FAKE_SECURITY_PREFLIGHT_EXIT",
    "AGENTCTL_FAKE_SECURITY_FIND_EXIT",
    "AGENTCTL_FAKE_SECURITY_DUMP_EXIT",
];

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

/// Now, in milliseconds since the epoch.
///
/// # Panics
///
/// Panics when the clock is before the epoch.
#[must_use]
pub fn now_ms() -> i64 {
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is after 1970");
    i64::try_from(since.as_millis()).expect("the epoch milliseconds fit in an i64")
}

/// An expiry far enough in the past to be expired under any margin.
#[must_use]
pub fn expired_at() -> i64 {
    now_ms() - 60_000
}

/// An expiry far enough ahead to be fresh under the five-minute margin.
#[must_use]
pub fn fresh_at() -> i64 {
    now_ms() + 3_600_000
}

/// A credential blob in Claude Code's shape (fact F40), with an identity.
#[must_use]
pub fn blob(access: &str, refresh: &str, expires_at_ms: i64) -> String {
    identified_blob(access, refresh, expires_at_ms, ACCT, Some(ORG))
}

/// A credential blob naming a specific account and organization.
#[must_use]
pub fn identified_blob(
    access: &str,
    refresh: &str,
    expires_at_ms: i64,
    acct: &str,
    org: Option<&str>,
) -> String {
    json!({
        "claudeAiOauth": {
            "accessToken": access,
            "refreshToken": refresh,
            "expiresAt": expires_at_ms,
            "scopes": ["user:inference", "user:profile"],
            "subscriptionType": "max",
            "tokenAccount": {
                "uuid": acct,
                "emailAddress": EMAIL,
                "organizationUuid": org,
                "organizationName": "Acme",
            },
        }
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// Naming (facts F14, N4')
// ---------------------------------------------------------------------------

/// `hex(sha256(nfc(raw)))[0..8]`, the way Claude Code names a keychain item.
///
/// A second implementation of `provider::claude::namespace::sha8` rather than a
/// call to it, because `agentctl` has no library target for `tests/` to link
/// against. Plan AC11 pins the same function's vectors inside the crate, so a
/// divergence between the two would fail there.
#[must_use]
pub fn sha8(raw: &str) -> String {
    let normalized: String = raw.nfc().collect();
    let digest = Sha256::digest(normalized.as_bytes());
    let hex = hex::encode(digest);
    hex.get(..8).unwrap_or(hex.as_str()).to_owned()
}

/// How a directory is spelled for naming purposes: NFC, no trailing slash.
#[must_use]
pub fn export_spelling(dir: &Path) -> String {
    let text: String = dir.to_string_lossy().nfc().collect();
    let trimmed = text.trim_end_matches('/');
    if trimmed.is_empty() { text } else { trimmed.to_owned() }
}

/// The file name the fake `security` reads one service's password from.
///
/// The fold has to match the `tr -c 'A-Za-z0-9._-' '_'` inside
/// `fixtures/fake-security.sh`, and the twin of this function in
/// `src/secret/fake_security.rs`. All three change together.
#[must_use]
pub fn item_file_name(service: &str) -> String {
    service
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '_' })
        .collect()
}

/// The keychain service a Claude Code session would migrate `ns_dir` to
/// (fact F35).
#[must_use]
pub fn migration_service(ns_dir: &Path) -> String {
    format!("{LIVE_SERVICE}-{}", sha8(&export_spelling(ns_dir)))
}

// ---------------------------------------------------------------------------
// Filesystem facts
// ---------------------------------------------------------------------------

/// A file's `(device, inode)` pair, for proving a replacement was atomic.
///
/// # Panics
///
/// Panics when the file cannot be stat'ed.
#[must_use]
pub fn inode_of(path: &Path) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::metadata(path)
        .unwrap_or_else(|err| panic!("`{}` should be stat-able: {err}", path.display()));
    (meta.dev(), meta.ino())
}

/// A file's permission bits.
///
/// # Panics
///
/// Panics when the file cannot be stat'ed.
#[must_use]
pub fn mode_of(path: &Path) -> u32 {
    let meta = fs::metadata(path)
        .unwrap_or_else(|err| panic!("`{}` should be stat-able: {err}", path.display()));
    meta.permissions().mode() & 0o7777
}

/// Whether some *other* process holds the exclusive lock on `path`.
///
/// Opens the file and tries a non-blocking `flock`, which is exactly what
/// agentctl does. `false` when the file does not exist yet, so a caller can
/// poll this from the moment it starts a child.
#[must_use]
pub fn lock_is_held(path: &Path) -> bool {
    let Ok(file) = fs::File::open(path) else {
        return false;
    };
    match rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {
            let _ = rustix::fs::flock(&file, FlockOperation::Unlock);
            false
        }
        Err(_) => true,
    }
}

/// Takes the exclusive lock on `path` and holds it until the guard drops.
///
/// The test process is a different process from the binary under test, so this
/// is a genuine second holder — which is what makes "the second waits" and
/// "the kernel released it on death" assertions mean anything.
///
/// # Panics
///
/// Panics when the lock cannot be created or is already held.
#[must_use]
pub fn hold_lock(path: &Path) -> fs::File {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("the locks directory should be creatable");
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .expect("the lock file should be creatable");
    rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive)
        .expect("the test should be able to take an unheld lock");
    file
}

// ---------------------------------------------------------------------------
// Driving a running process
// ---------------------------------------------------------------------------

/// Polls `ready` every 20 ms until it returns true or `budget` elapses.
///
/// Returns whether the condition was ever observed, so the caller decides what
/// a timeout means. Polling rather than sleeping a fixed interval is what
/// keeps these tests fast in the common case and honest in the slow one.
pub fn wait_until(budget: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    loop {
        if ready() {
            return true;
        }
        if start.elapsed() >= budget {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Sends `SIGTERM` to one process id.
///
/// Through `/bin/kill` rather than a signal crate: this is a test asking the
/// operating system to do what a user's `kill` would, and going through the
/// same program removes any doubt about which signal was delivered.
///
/// # Panics
///
/// Panics when `kill(1)` cannot be run.
pub fn send_sigterm(pid: u32) {
    let status = StdCommand::new("/bin/kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .expect("`/bin/kill` should be runnable");
    assert!(status.success(), "`kill -TERM {pid}` failed: {status}");
}

/// Everything a finished child said.
pub struct Output {
    /// The exit status code, or `None` when a signal ended it.
    pub code: Option<i32>,
    /// Standard output, as text.
    pub stdout: String,
    /// Standard error, as text.
    pub stderr: String,
}

impl Output {
    /// The exit code, insisting there was one.
    ///
    /// # Panics
    ///
    /// Panics when the process was killed by a signal instead of exiting,
    /// which for this binary means signal handling did not run.
    #[must_use]
    pub fn code(&self) -> i32 {
        self.code.unwrap_or_else(|| {
            panic!(
                "the process was terminated by a signal rather than exiting; \
                 stdout:\n{}\nstderr:\n{}",
                self.stdout, self.stderr
            )
        })
    }
}

/// Waits for a child and drains both its pipes.
///
/// # Panics
///
/// Panics when the child cannot be waited for.
#[must_use]
pub fn finish(mut child: Child) -> Output {
    let mut stdout = String::new();
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stdout.take() {
        let _ = pipe.read_to_string(&mut stdout);
    }
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    let status = child.wait().expect("the child should be waitable");
    Output { code: status.code(), stdout, stderr }
}

// ---------------------------------------------------------------------------
// The suite-wide keychain log (plan AC25)
// ---------------------------------------------------------------------------

/// Where every test's keychain calls are accumulated.
///
/// `CARGO_TARGET_TMPDIR` is one directory shared by every process `nextest`
/// starts for this test binary, which is what lets a per-test assertion also
/// contribute to a suite-wide one. Removing the file resets the aggregate.
#[must_use]
pub fn aggregate_log_path() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fake-security-argv.log")
}

/// Appends one test's keychain calls to the suite-wide log.
///
/// `O_APPEND` with one `write` per call: several test processes run at once,
/// and this is what keeps their lines whole rather than interleaved.
fn append_to_aggregate_log(lines: &[String]) {
    if lines.is_empty() {
        return;
    }
    let mut text = lines.join("\n");
    text.push('\n');
    if let Ok(mut file) =
        fs::OpenOptions::new().append(true).create(true).open(aggregate_log_path())
    {
        let _ = file.write_all(text.as_bytes());
    }
}

// ---------------------------------------------------------------------------
// Driving `login --manual`
// ---------------------------------------------------------------------------

/// A `login --manual` that has printed its authorize URL and is waiting for a
/// pasted `code#state`.
///
/// The `state` is generated inside the process, so a test cannot know it in
/// advance — but the command prints it, in the URL it asks the user to open.
/// Reading it back off stdout is what lets the suite drive a *complete* login
/// through the real binary rather than only its failure paths.
pub struct LoginSession {
    child: Child,
    reader: std::io::BufReader<std::process::ChildStdout>,
    /// The `state` parameter the process minted for this login.
    pub state: String,
    /// The whole authorize URL it printed.
    pub url: String,
}

impl LoginSession {
    /// The process id, for signalling.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Sends one line to the waiting prompt.
    ///
    /// # Panics
    ///
    /// Panics when the child's standard input has already been closed.
    pub fn paste(&mut self, line: &str) {
        let stdin = self.child.stdin.as_mut().expect("the login should still be reading stdin");
        writeln!(stdin, "{line}").expect("the pasted code should be writable");
        stdin.flush().expect("the pasted code should reach the child");
    }

    /// Closes standard input without answering, so the prompt sees end of file.
    pub fn close_stdin(&mut self) {
        drop(self.child.stdin.take());
    }

    /// Waits for the login to finish and returns everything it said.
    ///
    /// # Panics
    ///
    /// Panics when the child cannot be waited for.
    #[must_use]
    pub fn finish(mut self) -> Output {
        drop(self.child.stdin.take());
        let mut rest = String::new();
        let _ = self.reader.read_to_string(&mut rest);
        let mut stderr = String::new();
        if let Some(mut pipe) = self.child.stderr.take() {
            let _ = pipe.read_to_string(&mut stderr);
        }
        let status = self.child.wait().expect("the child should be waitable");
        let mut stdout = self.url.clone();
        stdout.push('\n');
        stdout.push_str(&rest);
        Output { code: status.code(), stdout, stderr }
    }

    /// Kills the login and reaps it.
    pub fn kill(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Starts `agentctl claude login --manual` and reads back its authorize URL.
///
/// `env` carries anything the individual test needs on top of the fixture's
/// own isolation, such as a fault switch.
///
/// # Panics
///
/// Panics when the binary cannot be started, or when it exits before printing
/// an authorize URL — in which case the panic carries what it did print, since
/// that is the whole of the diagnosis.
#[must_use]
pub fn start_login(fixture: &Fixture, args: &[&str], env: &[(&str, &str)]) -> LoginSession {
    use std::io::BufRead;

    let mut command = fixture.raw();
    command.args(["claude", "login", "--manual"]);
    command.args(args);
    for (key, value) in env {
        command.env(key, value);
    }
    let mut child = command.spawn().expect("`agentctl claude login` should start");
    let stdout = child.stdout.take().expect("stdout was piped");
    let mut reader = std::io::BufReader::new(stdout);

    let mut seen = String::new();
    let url;
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => {
                let _ = child.kill();
                panic!("`login` never printed an authorize URL; it said:\n{seen}");
            }
            Ok(_) => {}
        }
        seen.push_str(&line);
        if line.contains("state=") {
            url = line.trim().to_owned();
            break;
        }
    }

    let state = url
        .split_once("state=")
        .map(|(_, rest)| rest.split(['&', ' ']).next().unwrap_or_default().to_owned())
        .filter(|state| !state.is_empty())
        .unwrap_or_else(|| panic!("the authorize URL should carry a state: {url}"));

    LoginSession { child, reader, state, url }
}
