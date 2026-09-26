//! The Codex half of the e2e harness: a fixture that cannot reach a real
//! Codex home.
//!
//! # How to use it
//!
//! This file is **not** a submodule of `common`. A test crate declares both:
//!
//! ```ignore
//! mod common;
//! #[path = "common/codex.rs"]
//! mod codex;
//! ```
//!
//! which is what keeps `tests/common/mod.rs` — a file every phase-2 e2e test
//! shares — out of phase 3's diff entirely (plan §3.1, L7).
//!
//! # What it is for (invariant I25)
//!
//! A Codex test must never read the developer's own `~/.codex`. Three things
//! keep it away from one, and the first two are asserted rather than assumed:
//!
//! 1. the variable naming a Codex home is **removed** from every spawned
//!    environment (it is in `common`'s own removal list, ledger #171), and
//!    [`CodexFixture::cmd`] asserts that it is not there;
//! 2. `HOME` points inside the fixture's temporary directory, so the
//!    fallback path — `$HOME/.codex` — resolves under the fixture too, and
//!    [`CodexFixture::cmd`] asserts that as well;
//! 3. [`CodexFixture::set`] **panics** if a test tries to put that variable
//!    back. A test that needs a Codex home names one with `--codex-home`, or
//!    creates it under [`CodexFixture::codex_home`], which is inside the
//!    temporary directory by construction.
//!
//! The `codex` binary is faked the way `security(1)` is: `AGCTL_CODEX_BIN`
//! points at a copy of `fixtures/fake-codex.sh` written inside the fixture,
//! and the fixture asserts the resolved path really is under its own root —
//! a stale absolute path from another run would spawn something this test did
//! not write.

#![allow(dead_code, reason = "each e2e crate uses the part of the harness it needs")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Output;

use assert_cmd::Command;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;

use crate::common::Fixture;

/// The environment variable that names a Codex home.
///
/// Spelled here so the assertions below can name it; the crate under test
/// spells it in exactly one place of its own (`provider::codex::home`).
pub const CODEX_HOME_ENV: &str = "CODEX_HOME";

/// The test-only override that replaces the `codex` binary.
pub const CODEX_BIN_ENV: &str = "AGCTL_CODEX_BIN";

/// `fixtures/fake-codex.sh`, compiled into the test binary the way
/// `common::FAKE_SECURITY` is, so the fixture writes its own copy rather than
/// pointing at a path in the source tree.
pub const FAKE_CODEX: &str = include_str!("../../fixtures/fake-codex.sh");

/// A [`Fixture`] that also cannot reach a real Codex home.
pub struct CodexFixture {
    inner: Fixture,
    codex_bin: PathBuf,
}

impl CodexFixture {
    /// Builds an isolated store with the fake `codex` wired and every route
    /// to a real Codex home closed.
    ///
    /// # Panics
    ///
    /// Panics when the fake cannot be written, and when the fake it wired
    /// does not resolve inside the fixture.
    #[must_use]
    pub fn new() -> Self {
        let mut inner = Fixture::new();

        let codex_bin = inner.scratch("bin").join("fake-codex.sh");
        fs::write(&codex_bin, FAKE_CODEX).expect("the fake codex should be writable");
        fs::set_permissions(&codex_bin, fs::Permissions::from_mode(0o755))
            .expect("the fake codex should be executable");
        inner.set(CODEX_BIN_ENV, &codex_bin.to_string_lossy());

        let fixture = Self { inner, codex_bin };
        fixture.assert_fake_is_ours();
        fixture.assert_no_real_codex_home();
        fixture
    }

    /// The fixture's own root, which everything it creates lives under.
    #[must_use]
    pub fn root(&self) -> PathBuf {
        self.inner
            .config_dir()
            .parent()
            .expect("the config directory has a parent inside the fixture")
            .to_path_buf()
    }

    /// The Claude-side fixture, for everything this one does not add.
    #[must_use]
    pub fn inner(&self) -> &Fixture {
        &self.inner
    }

    /// A Codex home *inside the fixture*, created on demand.
    ///
    /// The only Codex home a test may name. It is not the fallback path the
    /// binary would resolve on its own; a test that wants the fallback puts
    /// its file at `home()/.codex`, which is inside the fixture too.
    ///
    /// # Panics
    ///
    /// Panics when the directory cannot be created.
    #[must_use]
    pub fn codex_home(&self, name: &str) -> PathBuf {
        let dir = self.root().join("codex-homes").join(name);
        fs::create_dir_all(&dir).expect("a fixture Codex home should be creatable");
        dir
    }

    /// Wires the fake `security` into every spawn, the way the Claude suite
    /// does, so a Codex login takes real keychain listings instead of the
    /// empty ones a disabled backend returns.
    ///
    /// `Fixture::new` disables the keychain for every test; a login test that
    /// does not call this runs keychain-less, and says so.
    pub fn with_keychain(&mut self) -> &mut Self {
        self.inner.with_keychain();
        self
    }

    /// The fake `security`'s `dump-keychain` output, once [`Self::with_keychain`]
    /// has run.
    ///
    /// `Fixture::dump_path` is private to the phase-2 harness, so the path is
    /// derived here the same way and asserted to exist: a rename there fails
    /// loudly here instead of pointing a test at a file nobody reads.
    ///
    /// # Panics
    ///
    /// Panics when the keychain is not wired.
    #[must_use]
    pub fn keychain_dump_path(&self) -> PathBuf {
        let path = self.root().join("keychain-dump.txt");
        assert!(
            path.exists(),
            "call `with_keychain` first; there is no dump at {}",
            path.display()
        );
        path
    }

    /// The fake `security`'s argv log, once [`Self::with_keychain`] has run.
    #[must_use]
    pub fn security_log_path(&self) -> PathBuf {
        self.inner.security_log_path()
    }

    /// Where the fake `codex` was written.
    #[must_use]
    pub fn codex_bin(&self) -> &Path {
        &self.codex_bin
    }

    /// The fake `codex`'s argv/env/cwd log, wired on first use.
    #[must_use]
    pub fn codex_log_path(&self) -> PathBuf {
        self.root().join("fake-codex.log")
    }

    /// Sets an environment variable for every command this fixture spawns.
    ///
    /// # Panics
    ///
    /// Panics when asked to set the Codex home variable. A test that needs a
    /// Codex home passes `--codex-home`; putting the variable back would put
    /// every *other* test on this fixture one inherited value away from the
    /// developer's own home (invariant I25).
    pub fn set(&mut self, key: &str, value: &str) -> &mut Self {
        assert_ne!(
            key, CODEX_HOME_ENV,
            "a test must not set `{CODEX_HOME_ENV}` in a spawned environment: name a home with \
             `--codex-home` instead, or create one under `CodexFixture::codex_home`"
        );
        self.inner.set(key, value);
        self
    }

    /// An `assert_cmd` handle to the binary, isolated from any real Codex
    /// home.
    ///
    /// # Panics
    ///
    /// Panics when the Codex home variable reached the child's environment,
    /// or when `HOME` is not inside the fixture.
    #[must_use]
    pub fn cmd(&self) -> Command {
        let command = self.inner.cmd();
        self.assert_isolated(command.get_envs());
        command
    }

    /// A `std::process::Command` to the binary, for the few tests that must
    /// control a stream `assert_cmd` cannot (a stdout whose reader is closed).
    ///
    /// Never call `self.inner().raw()` bare: that keeps phase 2's isolation but
    /// skips this fixture's own [`Self::assert_isolated`]. This runs the same
    /// check [`Self::cmd`] runs, over the same environment.
    ///
    /// # Panics
    ///
    /// Panics when the Codex home variable reached the child's environment,
    /// or when `HOME` is not inside the fixture.
    #[must_use]
    pub fn raw(&self) -> std::process::Command {
        let command = self.inner.raw();
        self.assert_isolated(command.get_envs());
        command
    }

    /// Asserts that the wired fake is the copy this fixture wrote.
    ///
    /// # Panics
    ///
    /// Panics when it is not.
    fn assert_fake_is_ours(&self) {
        let resolved = self.codex_bin.canonicalize().expect("the fake codex exists");
        let root = self.root().canonicalize().expect("the fixture root exists");
        assert!(
            resolved.starts_with(&root),
            "the fake codex at {} is not inside the fixture at {}",
            resolved.display(),
            root.display()
        );
        assert!(resolved.is_file(), "{} is not a file", resolved.display());
    }

    /// Asserts that no real Codex home is reachable from this fixture.
    ///
    /// # Panics
    ///
    /// Panics when `HOME` is outside the fixture, or when the fallback path
    /// under it already holds a credential — which would mean the fixture is
    /// pointed at something it did not create.
    pub fn assert_no_real_codex_home(&self) {
        let home = self.inner.home();
        let root = self.root();
        assert!(
            home.starts_with(&root),
            "HOME ({}) is outside the fixture ({})",
            home.display(),
            root.display()
        );
        let fallback = home.join(".codex");
        assert!(
            !fallback.join("auth.json").exists(),
            "{} already exists; this fixture did not create it",
            fallback.join("auth.json").display()
        );
    }

    /// Asserts that a built command carries no route to a real Codex home.
    ///
    /// # Panics
    ///
    /// Panics when the Codex home variable is set in the child's environment,
    /// or when `HOME` is not the fixture's.
    fn assert_isolated<'a>(
        &self,
        envs: impl Iterator<Item = (&'a std::ffi::OsStr, Option<&'a std::ffi::OsStr>)>,
    ) {
        let home = self.inner.home();
        let mut security_bin: Option<PathBuf> = None;
        let mut backend_none = false;
        for (key, value) in envs {
            if key == CODEX_HOME_ENV {
                assert!(
                    value.is_none(),
                    "`{CODEX_HOME_ENV}` reached a spawned environment as {:?}",
                    value.unwrap_or_default()
                );
            }
            if key == "HOME" {
                assert_eq!(
                    value.map(PathBuf::from),
                    Some(home.clone()),
                    "HOME must point inside the fixture"
                );
            }
            if key == "AGCTL_SECURITY_BIN" {
                security_bin = value.map(PathBuf::from);
            }
            if key == "AGCTL_KEYCHAIN_BACKEND" {
                backend_none = value == Some(std::ffi::OsStr::new("none"));
            }
        }
        // AC109's anti-vacuity arm (fix loop 1, F2): a log check alone is
        // vacuous for a fixture that never calls `with_keychain()` — no fake
        // `security` runs, so no log is ever written, and "zero
        // `find-generic-password` lines" would be trivially true. This proves
        // the OTHER half instead, on the same route every `cmd()`/`raw()`
        // already takes: every launch either wires a fake `security` INSIDE
        // the fixture root (so `checked`'s log check means something) or has
        // the keychain backend disabled outright, which fails closed before
        // any keychain call (`secret::default_reader`) — never neither, which
        // would leave a real `security(1)` reachable.
        match (backend_none, &security_bin) {
            (false, None) if cfg!(target_os = "linux") => {}
            (true, None) => {}
            (false, Some(bin)) => assert!(
                bin.starts_with(self.root()),
                "AGCTL_SECURITY_BIN ({}) is not inside the fixture root ({})",
                bin.display(),
                self.root().display()
            ),
            _ => panic!(
                "this fixture wires neither the fake `security` (`AGCTL_SECURITY_BIN`) nor the \
                 disabled backend (`AGCTL_KEYCHAIN_BACKEND=none`), so a keychain call here could \
                 reach the real one; call `with_keychain()` if the test needs a keychain"
            ),
        }
    }
}

impl Default for CodexFixture {
    fn default() -> Self {
        Self::new()
    }
}

/// A string a test's output must not carry: the NAME a failure reports, and
/// the value searched for. A hit reports the name and the byte offset only —
/// never the value, and never the text around it, because a value may be a
/// credential and the text a stream that holds one.
pub type Needle = (&'static str, &'static str);

/// A captured stream that [`checked`] copies to `AGCTL_E2E_TRACE_DIR`.
#[derive(Clone, Copy)]
pub enum Stream {
    Stdout,
    Stderr,
}

/// The first needle `text` carries, as its name and byte offset.
pub fn find_needle(text: &[u8], needles: &[Needle]) -> Option<(&'static str, usize)> {
    needles.iter().find_map(|(name, value)| {
        text.windows(value.len())
            .position(|window| window == value.as_bytes())
            .map(|at| (*name, at))
    })
}

/// Panics if `text` carries a needle, naming `test`, `what` was searched, the
/// needle's name and its byte offset.
pub fn assert_no_needle(test: &str, what: &str, text: &[u8], needles: &[Needle]) {
    if let Some((name, at)) = find_needle(text, needles) {
        panic!("{test}: {what} carries the needle `{name}` at byte {at}");
    }
}

/// The unaudited-receipt drop check's panic prefix, as the binary prints it.
///
/// Spelled here a second time on purpose: `tests/` is not compiled into the
/// crate, so it cannot reach `UNAUDITED_RECEIPT` in `auth_store.rs`. The two
/// spellings are held together by `scripts/release-gate.sh`, whose absent-seam
/// entry is this same string — a drift in the source spelling makes the gate
/// look for a string no build carries, and the gate's own plant-and-prove
/// half reports it.
const UNAUDITED_RECEIPT: &str = "agctl unaudited write receipt";

/// Panics if `stderr` carries the unaudited-receipt line.
///
/// The dev profile is `panic = "abort"`, so a receipt the real binary drops
/// before `codex::audit::append` shows up as this line plus exit 134. A test
/// asserting a successful run already fails on the status; one asserting a
/// refusal would not, and would report a wrong exit code rather than the
/// invariant that broke. This names it instead.
///
/// [`checked`] calls it, and so must every Codex e2e launch that does not go
/// through `checked` — a test that reads only an exit status would otherwise
/// be a hole in the one guard this invariant has left. The C2-a request
/// carries the table of every launch and which of the two routes it takes.
pub fn assert_receipts_were_audited(test: &str, stderr: &[u8]) {
    let hit = stderr
        .windows(UNAUDITED_RECEIPT.len())
        .position(|window| window == UNAUDITED_RECEIPT.as_bytes());
    if let Some(at) = hit {
        let tail = String::from_utf8_lossy(&stderr[at..]);
        let line = tail.lines().next().unwrap_or_default();
        panic!("{test}: the binary dropped a Codex write receipt before the audit log: {line}");
    }
}

/// Plan AC109's per-account lookup clause, enforced on the fake `security`
/// log itself rather than on the Rust source (fix loop 1, F1): a Codex
/// command never needs one account's password, only a listing
/// (`dump-keychain`), and a source-string grep cannot see a call that
/// reaches `KeychainReader::read` (`src/secret/mod.rs:130`) without spelling
/// `find-generic-password` anywhere in Codex's own modules — as a planted
/// `reader.read(KEYRING_SERVICE)` in `login.rs`/`pass.rs` proved.
///
/// Non-vacuous by construction, not by assumption: every fixture is in
/// exactly one of two states — the fake `security` wired
/// (`CodexFixture::with_keychain`), whose log this reads, or the keychain
/// backend disabled outright (`Fixture::new`'s default), which fails closed
/// before any lookup could happen (`secret::default_reader`,
/// `keychain_write::security_bin`) and asserted on every launch by
/// `Fixture::assert_keychain_seam` (`cmd()`/`raw()`, `tests/common/mod.rs:815,839`).
/// So a missing log is never "the check didn't run" — it is either "the
/// keychain is off" (proven elsewhere) or "this launch never touched a fake
/// `security` that exists" (nothing to find). A `with_keychain()` fixture's
/// own `dumps == N` assertions (`e2e_codex_login.rs`,
/// `e2e_codex_import.rs`) already prove the log is live when one is wired.
fn assert_no_keychain_lookup(test: &str, security_log: Option<&Path>) {
    let Some(path) = security_log else { return };
    let Ok(text) = fs::read_to_string(path) else { return };
    let lookups: Vec<&str> =
        text.lines().filter(|line| line.starts_with("find-generic-password")).collect();
    assert!(
        lookups.is_empty(),
        "{test}: a Codex launch issued a per-account keychain lookup, which no Codex command \
         needs:\n{}",
        lookups.join("\n")
    );
}

/// Asserts neither stream of `output` carries a needle, that the fake
/// `security` log — when `security_log` names one that exists — carries no
/// per-account lookup, then copies the `keep` streams to
/// `AGCTL_E2E_TRACE_DIR/<prefix>-<test>.<stream>` when that directory is
/// named. Every e2e crate's `checked` is this one: the one route every
/// Codex launch already goes through.
pub fn checked(
    prefix: &str,
    test: &str,
    output: Output,
    needles: &[Needle],
    keep: &[Stream],
    security_log: Option<&Path>,
) -> Output {
    assert_no_needle(test, "stdout", &output.stdout, needles);
    assert_no_needle(test, "stderr", &output.stderr, needles);
    assert_receipts_were_audited(test, &output.stderr);
    assert_no_keychain_lookup(test, security_log);
    if let Some(dir) = std::env::var_os("AGCTL_E2E_TRACE_DIR") {
        let dir = PathBuf::from(dir);
        for stream in keep {
            let (suffix, bytes) = match stream {
                Stream::Stdout => ("stdout", &output.stdout),
                Stream::Stderr => ("stderr", &output.stderr),
            };
            fs::write(dir.join(format!("{prefix}-{test}.{suffix}")), bytes)
                .expect("the trace directory is writable");
        }
    }
    output
}

// ---------------------------------------------------------------------------
// Helpers each `e2e_codex*.rs` used to define for itself. Every one below had
// an identical body in two or more of them. A helper whose body read a
// per-file constant (`USER`, `ACCT`, `JWT_SIGNATURE` — all different per file)
// takes that value as an argument here, and the caller keeps a one-line
// binding rather than a copy of the body.
// ---------------------------------------------------------------------------

/// The current second.
pub fn now_s() -> i64 {
    jiff::Timestamp::now().as_second()
}

/// A JWT with the usual header, `payload` as its body and `signature` verbatim.
pub fn jwt(payload: &Value, signature: &str) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).expect("serializes"));
    format!("{header}.{body}.{signature}")
}

/// Writes `bytes` to `path`, creating its parent, at mode 0600.
pub fn write_0600(path: &Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
    fs::write(path, bytes).expect("write");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("chmod");
}

/// A run's stdout, lossily decoded.
pub fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// A run's stderr, lossily decoded.
pub fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The Codex write log, `<store>/codex/writes.jsonl` (`audit::LOG_FILE`).
pub fn audit_log(fixture: &CodexFixture) -> PathBuf {
    fixture.inner().config_dir().join("codex").join("writes.jsonl")
}

/// The `outcome` of every line in the Codex audit log, oldest first.
pub fn audit_outcomes(fixture: &CodexFixture) -> Vec<String> {
    let log = audit_log(fixture);
    let Ok(text) = fs::read_to_string(&log) else { return Vec::new() };
    text.lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter_map(|value| value.get("outcome")?.as_str().map(str::to_owned))
        .collect()
}

/// The keychain account name agctl derives for the Codex home at `home`.
pub fn keyring_account(home: &Path) -> String {
    let canonical = home.canonicalize().unwrap_or_else(|_| home.to_path_buf());
    let digest =
        hex::encode(<sha2::Sha256 as sha2::Digest>::digest(canonical.to_string_lossy().as_bytes()));
    format!("cli|{}", &digest[..16])
}

/// The namespace directory `<store>/codex/<user>/<acct>`.
pub fn namespace(fixture: &CodexFixture, user: &str, acct: &str) -> PathBuf {
    fixture.inner().config_dir().join("codex").join(user).join(acct)
}

/// The refresh marker for `<user>/<acct>`.
pub fn marker_path(fixture: &CodexFixture, user: &str, acct: &str) -> PathBuf {
    fixture.inner().config_dir().join("codex").join(".state").join(format!("{user}+{acct}.refresh"))
}
