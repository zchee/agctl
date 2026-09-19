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

use assert_cmd::Command;

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
        }
    }
}

impl Default for CodexFixture {
    fn default() -> Self {
        Self::new()
    }
}
