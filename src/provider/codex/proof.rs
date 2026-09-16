//! The values that prove a Codex namespace write is allowed.
//!
//! Every proof type lives in this one module (plan H2), with private fields
//! and `pub(super)` constructors, so:
//!
//! - **Outside `provider::codex`** a proof cannot be built at all — a struct
//!   literal is E0451, a tuple constructor E0603, a constructor call E0624
//!   (plan AC122, `scripts/phase3-structural.sh`). A command can only *receive*
//!   one, from [`owned`], from the login verification, or from the lock.
//! - **Inside `provider::codex`** the `pub(super)` constructors are visible to
//!   every sibling, so which sibling calls each one is pinned by a
//!   source-reading test instead (plan AC119). That boundary is partial, and
//!   is stated as such (invariant I22).
//!
//! What each proof guarantees, and where:
//!
//! | proof | produced by | guarantees |
//! |-------|-------------|------------|
//! | [`OwnedRecord`] | [`owned`], [`VerifiedLogin::owned_record`] | the ids come from an `Owned` registry row (or a verified login) and pass `validate_codex_segment` |
//! | [`VerifiedLogin`] | `auth_store::verify_login` | a login child's `auth.json` was parsed once, is a ChatGPT login, names two valid ids, and the child left nothing behind |
//! | [`CodexNamespaceGuard`] | `lock::acquire_codex*` | this process holds the `flock` on `codex/.locks/<user>+<acct>.lock` |
//! | [`PostExitReport`] | `login_child::run` (S34) | what the login child's run left behind, from two fresh keychain listings and the scratch home |
//!
//! The namespace a guard is for is re-checked at run time where it is used
//! (`auth_store`), with a real `if` and an `Err`: debug assertions are off in
//! every build of this project (AGENTS.md).

use std::fmt;
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitStatus;

use crate::config::codex::CodexAccountRecord;
use crate::config::codex::CodexKind;
use crate::config::codex::RefreshPolicy;
use crate::config::paths::validate_codex_segment;
use crate::provider::codex::credentials::CodexIdentity;
use crate::provider::codex::credentials::Credentials;
use crate::secret::namespace_lock::NamespaceLockGuard;

/// A registry record agctl owns, with ids fit to name a directory.
///
/// `Copy`: a pass uses it twice, for the lock and for the namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnedRecord<'a> {
    user: &'a str,
    acct: &'a str,
    export_spelling: Option<&'a str>,
    refresh: RefreshPolicy,
}

impl<'a> OwnedRecord<'a> {
    /// The ChatGPT user id.
    pub fn user(&self) -> &'a str {
        self.user
    }

    /// The ChatGPT account id.
    pub fn acct(&self) -> &'a str {
        self.acct
    }

    /// The namespace directory as recorded at login, for display only.
    ///
    /// Never a path agctl writes through: every write derives its directory
    /// from [`OwnedRecord::user`] and [`OwnedRecord::acct`] under `codex_root()`
    /// (invariant I27, plan AC119).
    pub fn export_spelling(&self) -> Option<&'a str> {
        self.export_spelling
    }

    /// Whether agctl may refresh this grant.
    pub fn refresh(&self) -> RefreshPolicy {
        self.refresh
    }
}

/// The owned-record proof for a registry row: `Some` only for
/// [`CodexKind::Owned`] with two ids that pass
/// [`validate_codex_segment`].
///
/// The ids are validated again here, not trusted from the file: the registry
/// is a document the user can edit, and these ids become directory names.
pub fn owned(record: &CodexAccountRecord) -> Option<OwnedRecord<'_>> {
    let CodexKind::Owned { export_spelling, refresh } = &record.kind else { return None };
    validate_codex_segment(&record.chatgpt_user_id).ok()?;
    validate_codex_segment(&record.chatgpt_account_id).ok()?;
    Some(OwnedRecord {
        user: &record.chatgpt_user_id,
        acct: &record.chatgpt_account_id,
        export_spelling: Some(export_spelling),
        refresh: *refresh,
    })
}

/// A login child's `auth.json`, verified and parsed exactly once.
///
/// Owned by the install that consumes it, so a verified login installs at most
/// once.
pub struct VerifiedLogin {
    doc: Credentials,
    user: String,
    acct: String,
}

impl VerifiedLogin {
    /// Wraps a verified document. The only caller is
    /// `auth_store::verify_login` (plan AC119).
    pub(super) fn from_verified(doc: Credentials, user: String, acct: String) -> Self {
        Self { doc, user, acct }
    }

    /// The `(user, account)` ids the login named.
    pub(super) fn ids(&self) -> (&str, &str) {
        (&self.user, &self.acct)
    }

    /// The verified document.
    pub(super) fn doc(&self) -> &Credentials {
        &self.doc
    }

    /// The owned-record proof for a login not yet in the registry.
    pub(super) fn owned_record(&self) -> OwnedRecord<'_> {
        OwnedRecord {
            user: &self.user,
            acct: &self.acct,
            export_spelling: None,
            refresh: RefreshPolicy::default(),
        }
    }

    /// Who logged in. No secret: `commands/codex/login.rs` needs this for its
    /// same-identity notice and its registry record (plan section 3.3).
    pub fn identity(&self) -> CodexIdentity {
        let from_doc = self.doc.identity();
        CodexIdentity {
            user_id: self.user.clone(),
            account_id: self.acct.clone(),
            email: from_doc.as_ref().and_then(|identity| identity.email.clone()),
            plan: from_doc.and_then(|identity| identity.plan),
        }
    }
}

impl fmt::Debug for VerifiedLogin {
    /// The ids and the document's own redacted render.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedLogin")
            .field("user", &self.user)
            .field("acct", &self.acct)
            .field("doc", &self.doc)
            .finish()
    }
}

/// A held Codex namespace lock.
#[derive(Debug)]
pub struct CodexNamespaceGuard(NamespaceLockGuard);

impl CodexNamespaceGuard {
    /// Wraps an acquired lock. The only caller is `lock.rs` (plan AC119).
    pub(super) fn wrap(guard: NamespaceLockGuard) -> Self {
        Self(guard)
    }

    /// The lock file held.
    pub fn path(&self) -> &Path {
        self.0.path()
    }
}

/// What a login child left behind (plan section 3.3, L2′).
#[derive(Debug)]
pub struct PostExitReport {
    gained_codex_auth: Vec<String>,
    survivors: Vec<PathBuf>,
    daemon_dir: bool,
    lock_files: Vec<PathBuf>,
    exit: ExitStatus,
}

impl PostExitReport {
    /// Records one child run. The only caller is `login_child.rs` (S34,
    /// plan AC119).
    ///
    /// `gained_codex_auth` holds the `Codex Auth` item accounts present in the
    /// second listing and not the first — `cli|<hash>` names, never emails.
    pub(super) fn from_child(
        gained_codex_auth: Vec<String>,
        survivors: Vec<PathBuf>,
        daemon_dir: bool,
        lock_files: Vec<PathBuf>,
        exit: ExitStatus,
    ) -> Self {
        Self { gained_codex_auth, survivors, daemon_dir, lock_files, exit }
    }

    /// Whether the child exited successfully and left nothing behind.
    pub(super) fn clean(&self) -> bool {
        self.exit.success()
            && self.gained_codex_auth.is_empty()
            && self.survivors.is_empty()
            && !self.daemon_dir
            && self.lock_files.is_empty()
    }

    /// The reasons [`PostExitReport::clean`] is false, as refusal fragments.
    pub(super) fn anomalies(&self) -> Vec<String> {
        let mut found = Vec::new();
        if !self.exit.success() {
            found.push(format!("the login exited with {}", self.exit));
        }
        if !self.gained_codex_auth.is_empty() {
            found.push(format!(
                "the login created {} `Codex Auth` keychain item(s): {}",
                self.gained_codex_auth.len(),
                self.gained_codex_auth.join(", ")
            ));
        }
        if !self.survivors.is_empty() {
            found.push(format!("{} process(es) still use the scratch home", self.survivors.len()));
        }
        if self.daemon_dir {
            found.push("the login started a Codex daemon in the scratch home".to_owned());
        }
        if !self.lock_files.is_empty() {
            found
                .push(format!("{} lock file(s) remain in the scratch home", self.lock_files.len()));
        }
        found
    }
}

#[cfg(test)]
#[path = "proof_tests.rs"]
mod tests;
