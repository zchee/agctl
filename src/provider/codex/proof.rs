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
use crate::provider::codex::home::is_home_account;
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
///
/// Under the `testing` feature it also carries a
/// [`HeldCodexGuard`](crate::runtime::lock_order::HeldCodexGuard), so a test
/// that takes `.config.lock` while one is alive panics (numbered deviation 13).
#[derive(Debug)]
pub struct CodexNamespaceGuard(
    NamespaceLockGuard,
    #[cfg(feature = "testing")] crate::runtime::lock_order::HeldCodexGuard,
);

impl CodexNamespaceGuard {
    /// Wraps an acquired lock. The only caller is `lock.rs` (plan AC119).
    pub(super) fn wrap(guard: NamespaceLockGuard) -> Self {
        #[cfg(feature = "testing")]
        {
            Self(guard, crate::runtime::lock_order::HeldCodexGuard::take())
        }
        #[cfg(not(feature = "testing"))]
        {
            Self(guard)
        }
    }

    /// The lock file held.
    pub fn path(&self) -> &Path {
        self.0.path()
    }
}

/// What the scratch home looked like after the login child exited.
///
/// Produced by `login_child::survey` and consumed by
/// [`PostExitReport::from_child`]. It exists so that the report is built from
/// one named value rather than from a row of positional `Vec`s and `bool`s
/// that a caller could silently transpose.
/// **Deliberately no `Default`, and no `new`/`empty`/`clean` constructor.** A
/// default survey is the claim "we looked and found nothing", which is the
/// silent-clean failure `truncated` exists to remove; handing callers a cheap
/// way to make that claim would put it straight back. The only production
/// producer is `login_child::survey`, and every value is built by a named
/// struct literal so a transposed field cannot compile quietly. A test that
/// wants a clean value builds one in its own `*_tests.rs`.
///
/// The fields are `pub(super)`, so `commands/` cannot write the literal
/// either (E0451) — the same boundary AC122 clause 7 puts around
/// [`PostExitReport`].
#[derive(Debug)]
pub struct ScratchSurvey {
    /// Whether a Codex daemon directory appeared.
    pub(super) daemon_dir: bool,
    /// `*.lock` files something still holds, proved by a non-blocking probe.
    pub(super) held_locks: Vec<PathBuf>,
    /// Entries named `*.lock` that are not regular files.
    pub(super) odd_locks: Vec<PathBuf>,
    /// Whether a depth or entry bound stopped the walk short.
    pub(super) truncated: bool,
}

/// What a login child left behind (plan section 3.3, L2′).
#[derive(Debug)]
pub struct PostExitReport {
    gained_codex_auth: Vec<String>,
    survivors: Vec<PathBuf>,
    survey: ScratchSurvey,
    exit: ExitStatus,
}

impl PostExitReport {
    /// Records one child run. The only caller is `login_child.rs` (S34,
    /// plan AC119).
    ///
    /// `gained_codex_auth` holds the `Codex Auth` item accounts present in the
    /// second listing and not the first — `cli|<hash>` names, never emails.
    ///
    /// `survivors` is **always empty today**. Plan section 3.3's "refuse if a
    /// process still holds the scratch" is replaced entirely by the held-lock
    /// evidence in `survey` (ledger #310, #323, #325): there is no process
    /// scan in the login path, so a survivor holding an ordinary descriptor,
    /// rather than a lock, is not detected. That is harmless only because the
    /// install copies the bytes `verify_login` parsed — nothing a survivor
    /// writes to the scratch afterwards can reach the namespace. The field
    /// stays so a future process scan has somewhere to report.
    ///
    /// `survey` is what the scratch home looked like: see [`ScratchSurvey`].
    /// Its `held_locks` are lock files something still **holds**, never lock
    /// files that merely exist — a normal `codex login` leaves an unheld
    /// `tmp/arg0/…/.lock` behind (fact F81, measured at S28), so refusing on
    /// existence would refuse every real login. Its `odd_locks` are entries
    /// named `*.lock` that are not regular files; S28's residue has none, so
    /// one is an anomaly, and `flock` is never called on it. Its `truncated`
    /// says the walk could not look everywhere — a bound, an unreadable
    /// directory, a lock whose state could not be asked — and a home that was
    /// not walked completely has not been shown clean.
    pub(super) fn from_child(
        gained_codex_auth: Vec<String>,
        survivors: Vec<PathBuf>,
        survey: ScratchSurvey,
        exit: ExitStatus,
    ) -> Self {
        Self { gained_codex_auth, survivors, survey, exit }
    }

    /// The `Codex Auth` item accounts the second listing gained.
    ///
    /// Read-only, and the one reader outside this module is
    /// `commands::codex::login`, which records them in the write log when the
    /// login is refused: an item nothing recorded is an item `doctor` can
    /// never offer to remove, because nothing says agctl caused it.
    pub fn gained_codex_auth(&self) -> &[String] {
        &self.gained_codex_auth
    }

    /// Whether the child exited successfully and left nothing behind.
    pub(super) fn clean(&self) -> bool {
        // Destructured exhaustively, with no `..`: a field added to either
        // struct is a compile error here until somebody has decided what it
        // means for cleanliness. The mutant "add a field, forget `clean()`"
        // is caught by the compiler rather than by a reviewer's attention.
        let Self { gained_codex_auth, survivors, survey, exit } = self;
        let ScratchSurvey { daemon_dir, held_locks, odd_locks, truncated } = survey;
        exit.success()
            && gained_codex_auth.is_empty()
            && survivors.is_empty()
            && !daemon_dir
            && held_locks.is_empty()
            && odd_locks.is_empty()
            && !truncated
    }

    /// The reasons [`PostExitReport::clean`] is false, as refusal fragments.
    pub(super) fn anomalies(&self) -> Vec<String> {
        let mut found = Vec::new();
        if !self.exit.success() {
            found.push(format!("the login exited with {}", self.exit));
        }
        if !self.gained_codex_auth.is_empty() {
            // A keychain `acct` is an attribute any application on this
            // machine can set, and this sentence is printed to the user's
            // terminal. So the same rule `doctor` applies before it names one
            // applies here: a spelling agctl itself could have written is
            // shown, and anything else is counted (review S37-b1, carry 3).
            // Without this, a quote, a `$(…)`, a backtick or an escape byte
            // in that attribute rode into stderr on the refusal path.
            let (named, unnameable): (Vec<&String>, Vec<&String>) =
                self.gained_codex_auth.iter().partition(|account| is_home_account(account));
            let which = if named.is_empty() {
                String::new()
            } else {
                format!(
                    ": {}",
                    named.iter().map(|account| account.as_str()).collect::<Vec<_>>().join(", ")
                )
            };
            let rest = if unnameable.is_empty() {
                String::new()
            } else {
                format!(
                    " ({} of them under an account agctl would not have written, so it is not \
                     printed; look in Keychain Access)",
                    unnameable.len()
                )
            };
            found.push(format!(
                "the login created {} `Codex Auth` keychain item(s){which}{rest}",
                self.gained_codex_auth.len()
            ));
        }
        if !self.survivors.is_empty() {
            found.push(format!("{} process(es) still use the scratch home", self.survivors.len()));
        }
        if self.survey.daemon_dir {
            found.push("the login started a Codex daemon in the scratch home".to_owned());
        }
        if !self.survey.odd_locks.is_empty() {
            // The twin of the keychain join above, and the same rule. These
            // are names the login CHILD chose inside the scratch home, and
            // `is_lock_name` is only `ends_with(".lock")`, so a directory it
            // creates carries whatever bytes it likes into this sentence —
            // which is printed to the user's terminal (review S37-b1b, F2).
            // Only the final component is ever shown, and only when it is
            // spelled the way agctl spells a name: the leading directories
            // are agctl's own derived path and say nothing a reader needs.
            let mut named: Vec<&str> = Vec::new();
            let mut unnameable = 0usize;
            for path in &self.survey.odd_locks {
                match path.file_name().and_then(|name| name.to_str()) {
                    Some(name) if validate_codex_segment(name).is_ok() => named.push(name),
                    _ => unnameable = unnameable.saturating_add(1),
                }
            }
            let which =
                if named.is_empty() { String::new() } else { format!(": {}", named.join(", ")) };
            let rest = if unnameable == 0 {
                String::new()
            } else {
                format!(" ({unnameable} unnameable lock file(s), not printed)")
            };
            found.push(format!(
                "{} entr(y/ies) named `*.lock` in the scratch home are not regular \
                 files{which}{rest}",
                self.survey.odd_locks.len()
            ));
        }
        if self.survey.truncated {
            found
                .push("the scratch home was too large or too deep to survey completely".to_owned());
        }
        if !self.survey.held_locks.is_empty() {
            found.push(format!(
                "{} lock file(s) are still held in the scratch home",
                self.survey.held_locks.len()
            ));
        }
        found
    }
}

#[cfg(test)]
#[path = "proof_tests.rs"]
mod tests;
