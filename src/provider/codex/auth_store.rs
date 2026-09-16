//! Every read and write of a Codex `auth.json`, and the refresh marker beside
//! each owned one.
//!
//! # One opener
//!
//! This is the only module that opens an `auth.json` (invariant I23), and the
//! file name itself is private to it. Three kinds of file are opened here:
//!
//! - **a live or read-only home's**, by [`read_live`]: read-only, the final
//!   component never a symbolic link (the directories above may be, fact
//!   F60), a regular file of at most 1 MiB, parsed once. Codex rewrites that
//!   file in place without a lock (fact F66), so an empty or cut-off read is
//!   [`CodexResolved::Torn`] — a retry, never `needs login` (plan AC94) — and
//!   under `auto` its next keychain save can delete the file between a `stat`
//!   and the open (fact F94), which is simply [`CodexResolved::Absent`].
//! - **a login child's**, by [`verify_login`]: the same read, then the checks
//!   that make it a [`VerifiedLogin`].
//! - **an owned namespace's**, through [`OwnedNamespace`] and
//!   [`InstallNamespace`], under a held [`CodexNamespaceGuard`].
//!
//! # Three writers
//!
//! Every Codex namespace write is one of (invariant I22):
//!
//! 1. [`OwnedNamespace::write`] — a merged refresh, always with a pending
//!    fallback and [`StopPolicy::Complete`], so a rotated grant is never
//!    dropped at a deadline and never lost to a failed rename;
//! 2. [`InstallNamespace::install`] — a verified login, copied in, consuming
//!    the handle, with **no** pending fallback (its bytes still exist where
//!    they came from; plan ledger #237) and the refresh marker reset;
//! 3. [`OwnedNamespace::resolve_pending`] — replay or discard.
//!
//! plus [`OwnedNamespace::remove_named_files`]. Each returns a
//! [`WriteReceipt`], which the Codex audit log consumes (invariant I30). The
//! stop policy and the pending spec are fixed inside each writer rather than
//! passed in, so "no pending fallback" is reachable from the install and
//! nowhere else (review ruling 3).
//!
//! # One directory binding
//!
//! A handle derives its directory descriptor and the path it shows from one
//! `codex_namespace_dir(user, acct)` value, in one function, and
//! [`SecretFile::open`] is called in exactly one place here (review F7, plan
//! AC119): a descriptor from one namespace cannot be paired with another's
//! path.
//!
//! # The refresh marker
//!
//! [`RefreshStateFile`] is the write-ahead marker that binds a refresh POST
//! to a durable record of it (invariant I26, plan section 3.3): the
//! [`InflightToken`] the POST consumes exists only after the marker file and
//! its directory have been `fsync`ed. Reading it is public — `doctor` shows it
//! — and every mutator is `pub(super)`, so no command can clear a marker and
//! re-arm a send (plan AC122 clause 11).

use std::fmt;
use std::fs::File;
use std::io;
use std::io::Read;
use std::marker::PhantomData;
use std::os::fd::AsFd;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use jiff::Timestamp;
use rustix::fs::AtFlags;
use rustix::io::Errno;
use serde::Deserialize;
use serde::Serialize;

use crate::config::paths::Paths;
use crate::config::paths::validate_codex_segment;
use crate::provider::codex::credentials::AuthMode;
use crate::provider::codex::credentials::CodexIdentity;
use crate::provider::codex::credentials::Credentials;
use crate::provider::codex::credentials::CredentialsError;
use crate::provider::codex::credentials::LockedCredentials;
use crate::provider::codex::home;
use crate::provider::codex::home::DaemonEvidence;
use crate::provider::codex::proof::CodexNamespaceGuard;
use crate::provider::codex::proof::OwnedRecord;
use crate::provider::codex::proof::PostExitReport;
use crate::provider::codex::proof::VerifiedLogin;
use crate::runtime::coordinator::Cancel;
use crate::runtime::fault::Fault;
use crate::secret::audit;
use crate::secret::file_store;
use crate::secret::file_store::FileStoreError;
use crate::secret::file_store::MAX_CREDENTIALS_BYTES;
use crate::secret::file_store::ReadOutcome;
use crate::secret::file_store::WriteOutcome;
use crate::secret::pending;
use crate::secret::pending::Digests;
use crate::secret::pending::PendingDecision;
use crate::secret::pending::PendingSpec;
use crate::secret::secret_file::SecretFile;
use crate::secret::secret_file::StopPolicy;
use crate::secret::secret_file::WriteFaults;

/// The credential file's name in every Codex home and namespace (fact F61).
/// Private: nothing outside this module may name it (plan AC119).
const AUTH_FILE: &str = "auth.json";

/// Where a merged refresh waits after a failed rename.
const PENDING_FILE: &str = "auth.json.pending";

/// What the pending credential was derived from.
const PENDING_META: &str = "auth.pending.meta";

/// The prefix of a staged write's temporary file (`SecretFile::write`).
const TMP_PREFIX: &str = "auth.json.tmp.";

/// The largest refresh marker this module will read.
const MAX_STATE_BYTES: u64 = 64 * 1024;

/// The refresh marker's schema version.
const STATE_SCHEMA: u32 = 1;

/// The 401 floor a fresh marker starts at (decision D-035).
pub const DEFAULT_FLOOR_MIN: u32 = 60;

/// The write faults the refresh writer honours.
const REFRESH_FAULTS: (&str, &str) = ("codex_before_rename", "codex_rename_fail");

/// The write faults the install honours (plan AC126 (d)).
const INSTALL_FAULTS: (&str, &str) = ("codex_before_rename", "codex_install_rename_fail");

/// The credential file's name, for messages outside this module.
pub fn shown_name() -> &'static str {
    AUTH_FILE
}

/// What reading a Codex home's credential file found.
#[derive(Debug)]
pub enum CodexResolved {
    /// A parsed credential.
    Credentials(Box<Credentials>),
    /// No file: never logged in, logged out, or migrated into the keychain
    /// (fact F94).
    Absent,
    /// The file is there and cannot be used now: a link, not a regular file,
    /// too large, unreadable, or not a Codex credential. The reason names the
    /// path and never the content.
    Transient(String),
    /// The file is empty or cut off: Codex's in-place writer is mid-write
    /// (fact F66). Retry; never `needs login`.
    Torn,
}

/// Reads `<home>/auth.json` read-only (plan section 3.7 #1).
pub fn read_live(home: &Path) -> CodexResolved {
    let path = home.join(AUTH_FILE);
    let bytes = match read_regular_nofollow(&path) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return CodexResolved::Absent,
        Err(reason) => return CodexResolved::Transient(reason),
    };
    match Credentials::parse(&bytes) {
        Ok(credentials) => CodexResolved::Credentials(Box::new(credentials)),
        Err(CredentialsError::Truncated) => CodexResolved::Torn,
        Err(err) => CodexResolved::Transient(format!("`{}`: {err}", path.display())),
    }
}

/// Reads a file whose final component must not be a link: `Ok(None)` when
/// absent, the reason when unusable.
fn read_regular_nofollow(path: &Path) -> Result<Option<Vec<u8>>, String> {
    let file = match home::open_readonly_nofollow(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err)
            if err.raw_os_error() == Some(Errno::LOOP.raw_os_error())
                || err.raw_os_error() == Some(Errno::MLINK.raw_os_error()) =>
        {
            return Err(format!(
                "`{}` is a symbolic link; agctl will not read through one",
                path.display()
            ));
        }
        Err(err) => return Err(format!("could not open `{}`: {}", path.display(), err.kind())),
    };
    read_opened(file, path).map(Some)
}

/// Reads an opened file under the regular-file and size rules.
fn read_opened(mut file: File, path: &Path) -> Result<Vec<u8>, String> {
    let meta = file
        .metadata()
        .map_err(|err| format!("could not stat `{}`: {}", path.display(), err.kind()))?;
    if !meta.is_file() {
        return Err(format!("`{}` is not a regular file", path.display()));
    }
    if meta.len() > MAX_CREDENTIALS_BYTES {
        return Err(format!(
            "`{}` is {} bytes, larger than the {MAX_CREDENTIALS_BYTES}-byte limit",
            path.display(),
            meta.len()
        ));
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_CREDENTIALS_BYTES)
        .read_to_end(&mut bytes)
        .map_err(|err| format!("could not read `{}`: {}", path.display(), err.kind()))?;
    Ok(bytes)
}

/// Why a login child's credential was not accepted (plan AC105).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LoginRefusal {
    /// The child's run left something behind or failed.
    #[error("the Codex login was refused: {}", .0.join("; "))]
    ChildAnomalies(Vec<String>),
    /// The child wrote no credential.
    #[error("the Codex login wrote no credential file into its scratch home")]
    NoCredential,
    /// The credential could not be read or parsed.
    #[error("the Codex login's credential could not be used: {0}")]
    Unreadable(String),
    /// The login is not a ChatGPT login, so it has no usage to read.
    #[error("the Codex login is in `{0}` mode; only a ChatGPT login has a usage source")]
    NotChatGpt(String),
    /// The id token names no user or no account (decision D-039).
    #[error(
        "the Codex login's id token names no ChatGPT user or account; choose one workspace and log in again"
    )]
    NoIdentity,
    /// An id is not fit to name a directory.
    #[error("the Codex login's ids cannot name a namespace: {0}")]
    InvalidId(String),
}

/// Verifies a login child's `<scratch>/auth.json` and parses it exactly once
/// (plan section 3.3, L2′).
///
/// The child's report is checked first, so a run that left a process, a
/// daemon directory, a lock file or a new keychain item behind is refused
/// without reading its credential at all.
///
/// # Errors
///
/// [`LoginRefusal`], naming the first rule the login broke.
pub fn verify_login(
    scratch: &Path,
    report: &PostExitReport,
) -> Result<VerifiedLogin, LoginRefusal> {
    if !report.clean() {
        return Err(LoginRefusal::ChildAnomalies(report.anomalies()));
    }
    let path = scratch.join(AUTH_FILE);
    let bytes = match read_regular_nofollow(&path) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Err(LoginRefusal::NoCredential),
        Err(reason) => return Err(LoginRefusal::Unreadable(reason)),
    };
    let doc =
        Credentials::parse(&bytes).map_err(|err| LoginRefusal::Unreadable(err.to_string()))?;
    if *doc.auth_mode() != AuthMode::ChatGpt {
        return Err(LoginRefusal::NotChatGpt(doc.auth_mode().label().to_owned()));
    }
    if doc.digests().is_none() {
        return Err(LoginRefusal::Unreadable("the credential has no access token".to_owned()));
    }
    let identity = doc.identity().ok_or(LoginRefusal::NoIdentity)?;
    validate_codex_segment(&identity.user_id)
        .map_err(|err| LoginRefusal::InvalidId(err.to_string()))?;
    validate_codex_segment(&identity.account_id)
        .map_err(|err| LoginRefusal::InvalidId(err.to_string()))?;
    Ok(VerifiedLogin::from_verified(doc, identity.user_id, identity.account_id))
}

/// What a write did, for the audit log (invariant I30).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteKind {
    /// A merged refresh was renamed into place.
    RefreshApplied,
    /// A merged refresh was parked as pending after a failed rename.
    RefreshSavedToPending,
    /// A merged refresh was discarded: the file's grant changed since the
    /// post-refresh snapshot (another writer holds a newer one).
    DiscardedExternal,
    /// A pending credential was replayed.
    PendingReplayed,
    /// A pending credential was deleted unused.
    PendingDiscarded,
    /// A verified login was installed; `overwrote` when a credential was there.
    LoginInstall {
        /// Whether an existing credential was replaced.
        overwrote: bool,
    },
    /// The namespace's named files were removed.
    Delete,
}

/// The record of one namespace write. Consumed by the Codex audit log and
/// nothing else (invariant I30, plan AC117).
#[must_use = "every Codex namespace write is audited: hand the receipt to the audit log"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteReceipt {
    kind: WriteKind,
    digest8_before: Option<String>,
    digest8_after: Option<String>,
    ids: (String, String),
}

impl WriteReceipt {
    /// What the write did.
    pub fn kind(&self) -> WriteKind {
        self.kind
    }

    /// The refresh digest prefix of the credential before the write.
    pub fn digest8_before(&self) -> Option<&str> {
        self.digest8_before.as_deref()
    }

    /// The refresh digest prefix of the credential the write concerned.
    pub fn digest8_after(&self) -> Option<&str> {
        self.digest8_after.as_deref()
    }

    /// The `(user, account)` ids of the namespace.
    pub fn ids(&self) -> (&str, &str) {
        (&self.ids.0, &self.ids.1)
    }
}

/// The refresh digest prefix (or, without a refresh token, the access one).
fn digest8_of(digests: Option<&Digests>) -> Option<String> {
    let digests = digests?;
    digests
        .refresh_sha256
        .as_deref()
        .or(Some(digests.access_sha256.as_str()))
        .and_then(audit::digest8)
}

/// One namespace directory, bound once.
struct NamespaceDir {
    /// `codex_root()`, the root every file here must spell a path below.
    root: PathBuf,
    /// `codex_namespace_dir(user, acct)`.
    dir_shown: PathBuf,
    /// `<dir_shown>/auth.json`.
    shown: PathBuf,
    /// The directory, from an `O_NOFOLLOW` walk down from `root`.
    fd: OwnedFd,
    user: String,
    acct: String,
}

impl NamespaceDir {
    /// Derives the directory and its displayed path from one value, and
    /// checks the guard is this namespace's (review F7, plan AC119).
    fn open(
        paths: &Paths,
        user: &str,
        acct: &str,
        guard: &CodexNamespaceGuard,
    ) -> Result<Self, FileStoreError> {
        let expected = paths.codex_lock_path(user, acct).map_err(refused)?;
        if guard.path() != expected {
            return Err(FileStoreError::io(
                format!(
                    "the lock held is `{}`, not `{}`; refusing to open that namespace",
                    guard.path().display(),
                    expected.display()
                ),
                io::Error::from(io::ErrorKind::PermissionDenied),
            ));
        }
        let root = paths.codex_root();
        let dir_shown = paths.codex_namespace_dir(user, acct).map_err(refused)?;
        let fd = file_store::create_dir_under(&root, &dir_shown)?;
        let shown = dir_shown.join(AUTH_FILE);
        Ok(Self { root, dir_shown, shown, fd, user: user.to_owned(), acct: acct.to_owned() })
    }

    /// The named file in this directory. The one `SecretFile::open` call in
    /// this module (review F7).
    fn file<'a>(&'a self, name: &'a str, shown: &'a Path) -> SecretFile<'a> {
        SecretFile::open(&self.root, self.fd.as_fd(), name, shown)
    }

    /// `auth.json`.
    fn auth_file(&self) -> SecretFile<'_> {
        self.file(AUTH_FILE, &self.shown)
    }

    /// Reads `auth.json`'s digests, with whether it is torn.
    fn current(&self) -> Result<Current, FileStoreError> {
        match self.auth_file().read_strict(MAX_CREDENTIALS_BYTES)? {
            ReadOutcome::Absent => Ok(Current::Absent),
            ReadOutcome::Present { bytes, snap } => match Credentials::parse(&bytes) {
                Ok(credentials) => {
                    Ok(Current::Present { credentials: Box::new(credentials), snap })
                }
                Err(CredentialsError::Truncated) => Ok(Current::Torn),
                Err(err) => Err(FileStoreError::Json(format!("`{}`: {err}", self.shown.display()))),
            },
        }
    }

    fn ids(&self) -> (String, String) {
        (self.user.clone(), self.acct.clone())
    }
}

/// What an owned namespace's `auth.json` is right now.
enum Current {
    Absent,
    Torn,
    Present { credentials: Box<Credentials>, snap: file_store::FileSnapshot },
}

/// An id that `Paths` refused, as the store error the handles speak.
fn refused(err: crate::error::AppError) -> FileStoreError {
    FileStoreError::io(err.to_string(), io::Error::from(io::ErrorKind::InvalidInput))
}

/// What reading an owned namespace found.
pub enum NamespaceRead<'g> {
    /// Credentials, bound to the held lock.
    Credentials(Box<LockedCredentials<'g>>),
    /// No `auth.json`: `needs login`.
    Absent,
    /// Empty or cut off: retry after 50 ms, never `needs login` (plan AC94).
    Torn,
}

impl fmt::Debug for NamespaceRead<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Credentials(credentials) => {
                f.debug_tuple("Credentials").field(credentials).finish()
            }
            Self::Absent => f.write_str("Absent"),
            Self::Torn => f.write_str("Torn"),
        }
    }
}

/// The file identity and grant right before a refresh is sent (plan section
/// 3.3), for a caller that wants to know whether the file moved during the
/// POST. [`OwnedNamespace::write`] does not take one: it compares the file with
/// the read its credentials came from (review S30 F4).
#[derive(Clone, PartialEq, Eq)]
pub struct PostSnapshot {
    snap: file_store::FileSnapshot,
    digests: Option<Digests>,
}

impl PostSnapshot {
    /// The refresh digest prefix the snapshot saw.
    pub fn refresh_digest8(&self) -> Option<String> {
        digest8_of(self.digests.as_ref())
    }

    /// The file size and modification time the snapshot saw.
    pub fn size_and_mtime_ns(&self) -> (u64, i128) {
        (self.snap.size, self.snap.mtime_ns)
    }
}

impl fmt::Debug for PostSnapshot {
    /// Digest prefixes, as every other render here: a full digest is a stable
    /// identifier across logs (review S30 F10).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostSnapshot")
            .field("size", &self.snap.size)
            .field("mtime_ns", &self.snap.mtime_ns)
            .field("refresh_digest8", &self.refresh_digest8())
            .finish_non_exhaustive()
    }
}

/// What [`OwnedNamespace::write`] did.
#[must_use = "a landed write or a discard carries a receipt the audit log must consume"]
#[derive(Debug)]
pub enum CodexWrite {
    /// The merged credential was renamed into place or parked as pending.
    Landed {
        /// Which of the two.
        outcome: WriteOutcome,
        /// The audit record.
        receipt: WriteReceipt,
    },
    /// The file's grant changed since the read the credentials came from:
    /// another writer holds a newer one, and the merged response was not
    /// written (plan AC124).
    ChangedSinceRead {
        /// The audit record (`discarded_external`).
        receipt: WriteReceipt,
    },
    /// The file was torn at the pre-write check; nothing was written. The
    /// caller retries the re-read.
    Torn,
}

/// An owned namespace, opened under its lock. Writers 1 and 3 live here.
pub struct OwnedNamespace<'g> {
    owned: OwnedRecord<'g>,
    guard: &'g CodexNamespaceGuard,
    ns: NamespaceDir,
    state: RefreshStateFile,
}

impl<'g> OwnedNamespace<'g> {
    /// Opens the namespace an owned record names, creating its directory at
    /// 0700 when missing.
    ///
    /// # Errors
    ///
    /// [`FileStoreError`] when `guard` is not this namespace's lock — a real
    /// check, not an assertion (plan AC119) — when a component is a link or
    /// not a directory, or when `codex_root()` does not exist yet.
    pub fn open(
        paths: &Paths,
        owned: OwnedRecord<'g>,
        guard: &'g CodexNamespaceGuard,
    ) -> Result<Self, FileStoreError> {
        let ns = NamespaceDir::open(paths, owned.user(), owned.acct(), guard)?;
        let state = RefreshStateFile::new(paths, owned.user(), owned.acct())?;
        Ok(Self { owned, guard, ns, state })
    }

    /// The record this handle was opened for.
    pub fn owned(&self) -> OwnedRecord<'g> {
        self.owned
    }

    /// The namespace's refresh marker.
    pub fn refresh_state(&self) -> &RefreshStateFile {
        &self.state
    }

    /// Writer 3: replays or discards a pending credential. Runs first in every
    /// pass, before the read and the marker compare (plan section 3.3).
    ///
    /// A live Codex daemon in the namespace is **not** "taken over" (review S30
    /// F2): a pending file is a rotated grant whose rename failed, the refresh
    /// token in `auth.json` is already spent, and discarding the pending file
    /// guarantees `needs login`. Whether another writer holds a newer grant is
    /// the resolver's digest compare, which discards as `file changed`. The
    /// daemon evidence is returned for the row's `codex session detected` note.
    /// A present but unusable `auth.json`, pending file or meta keeps every file
    /// and is an error (reviews S29a F8, S30 F1).
    ///
    /// # Errors
    ///
    /// [`FileStoreError`] from the resolver.
    pub fn resolve_pending(
        &self,
        cancel: &Cancel,
    ) -> Result<(PendingDecision, Option<WriteReceipt>, DaemonEvidence), FileStoreError> {
        let evidence = home::daemon_evidence(&self.ns.dir_shown, cancel);
        let spec = PendingSpec {
            target_name: AUTH_FILE,
            pending_name: PENDING_FILE,
            meta_name: PENDING_META,
            prior: None,
            expires_at_ms: None,
        };
        let (decision, write) = pending::resolve_pending_with::<Credentials>(
            self.ns.fd.as_fd(),
            &self.ns.dir_shown,
            &spec,
            false,
        )?;
        let receipt = write.map(|write| {
            let kind = match decision {
                PendingDecision::Replayed { .. } => WriteKind::PendingReplayed,
                PendingDecision::Discarded(_) | PendingDecision::NoPending => {
                    WriteKind::PendingDiscarded
                }
            };
            WriteReceipt {
                kind,
                digest8_before: digest8_of(write.before.as_ref()),
                digest8_after: digest8_of(write.pending.as_ref()),
                ids: self.ns.ids(),
            }
        });
        Ok((decision, receipt, evidence))
    }

    /// Reads `auth.json` under the lock.
    ///
    /// # Errors
    ///
    /// [`FileStoreError`] for a link, a non-regular file, an oversized one, or
    /// a document that is complete and still not a Codex credential.
    pub fn read(&self) -> Result<NamespaceRead<'g>, FileStoreError> {
        Ok(match self.ns.current()? {
            Current::Absent => NamespaceRead::Absent,
            Current::Torn => NamespaceRead::Torn,
            Current::Present { credentials, .. } => {
                NamespaceRead::Credentials(Box::new(LockedCredentials::from_locked_read(
                    *credentials,
                    (&self.ns.user, &self.ns.acct),
                    self.guard,
                )))
            }
        })
    }

    /// The file identity and grant right now. `Ok(None)` when absent or torn.
    ///
    /// # Errors
    ///
    /// As [`OwnedNamespace::read`].
    pub fn snapshot_for_post(&self) -> Result<Option<PostSnapshot>, FileStoreError> {
        Ok(match self.ns.current()? {
            Current::Present { credentials, snap } => {
                Some(PostSnapshot { snap, digests: credentials.digests() })
            }
            Current::Absent | Current::Torn => None,
        })
    }

    /// Writer 1: writes a merged refresh.
    ///
    /// `credentials` must have been read from this namespace (review S30 F7).
    /// The file's grant is compared with the one that read saw — which a merge
    /// carries — immediately before staging, so the comparison cannot be
    /// defeated by a snapshot taken in a separate read (review S30 F4); a
    /// different grant means another writer refreshed, and the merge is
    /// discarded rather than written over it ([`CodexWrite::ChangedSinceRead`]).
    /// Otherwise the bytes go through [`SecretFile::write`] with a pending
    /// fallback derived from that read and [`StopPolicy::Complete`] — both fixed
    /// here, not chosen by the caller.
    ///
    /// # Errors
    ///
    /// [`FileStoreError`] for credentials from another namespace, from the
    /// check, or from the write. A failed rename is not an error: it is
    /// [`WriteOutcome::SavedToPending`].
    pub fn write(
        &self,
        credentials: &LockedCredentials<'g>,
        fault: &Fault,
    ) -> Result<CodexWrite, FileStoreError> {
        check_ids(credentials, &self.ns.user, &self.ns.acct, &self.ns.shown)?;
        let before = match self.ns.current()? {
            Current::Torn => return Ok(CodexWrite::Torn),
            Current::Absent => None,
            Current::Present { credentials, .. } => credentials.digests(),
        };
        let base = credentials.base_digests();
        let after = credentials.credentials().digests();
        if before.as_ref().and_then(|d| d.refresh_sha256.as_ref())
            != base.and_then(|d| d.refresh_sha256.as_ref())
        {
            return Ok(CodexWrite::ChangedSinceRead {
                receipt: WriteReceipt {
                    kind: WriteKind::DiscardedExternal,
                    digest8_before: digest8_of(before.as_ref()),
                    digest8_after: digest8_of(after.as_ref()),
                    ids: self.ns.ids(),
                },
            });
        }

        let mut bytes = Vec::new();
        credentials.credentials().write_json_to(&mut bytes).map_err(|err| {
            FileStoreError::io(format!("could not serialize `{}`", self.ns.shown.display()), err)
        })?;
        let spec = PendingSpec {
            target_name: AUTH_FILE,
            pending_name: PENDING_FILE,
            meta_name: PENDING_META,
            prior: base,
            expires_at_ms: credentials
                .credentials()
                .access_expires_at()
                .and_then(|exp| exp.checked_mul(1000)),
        };
        let faults =
            WriteFaults { fault, before_rename: REFRESH_FAULTS.0, rename_fail: REFRESH_FAULTS.1 };
        let outcome =
            self.ns.auth_file().write(&bytes, Some(spec), StopPolicy::Complete, &faults)?;
        let kind = match outcome {
            WriteOutcome::Written { .. } => WriteKind::RefreshApplied,
            WriteOutcome::SavedToPending { .. } => WriteKind::RefreshSavedToPending,
        };
        Ok(CodexWrite::Landed {
            outcome,
            receipt: WriteReceipt {
                kind,
                digest8_before: digest8_of(before.as_ref()),
                digest8_after: digest8_of(after.as_ref()),
                ids: self.ns.ids(),
            },
        })
    }

    /// Removes `auth.json`, the pending pair, staged temporaries and the
    /// refresh marker, then the namespace directory if it is empty
    /// (plan section 3.3, `accounts remove --delete-secret`).
    ///
    /// Anything else in the directory — a Codex session's `sessions/`, a
    /// database, a `config.toml` — refuses the whole removal before anything
    /// is deleted, naming what it found.
    ///
    /// # Errors
    ///
    /// [`FileStoreError::NotEmpty`]-shaped refusal naming the foreign entries,
    /// and [`FileStoreError`] for a failed unlink.
    pub fn remove_named_files(&self) -> Result<WriteReceipt, FileStoreError> {
        let mut named = Vec::new();
        let mut foreign = Vec::new();
        let dir = rustix::fs::Dir::read_from(&self.ns.fd).map_err(|errno| {
            FileStoreError::errno(
                format!("could not list `{}`", self.ns.dir_shown.display()),
                errno,
            )
        })?;
        for entry in dir {
            let entry = entry.map_err(|errno| {
                FileStoreError::errno(
                    format!("could not list `{}`", self.ns.dir_shown.display()),
                    errno,
                )
            })?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == "." || name == ".." {
                continue;
            }
            if is_named_file(&name) {
                named.push(name);
            } else {
                foreign.push(name);
            }
        }
        if !foreign.is_empty() {
            foreign.sort();
            return Err(FileStoreError::io(
                format!(
                    "`{}` holds entries agctl did not create ({}); nothing was removed",
                    self.ns.dir_shown.display(),
                    foreign.iter().map(|name| format!("{name:?}")).collect::<Vec<_>>().join(", ")
                ),
                io::Error::from(io::ErrorKind::DirectoryNotEmpty),
            ));
        }

        let before = match self.ns.current() {
            Ok(Current::Present { credentials, .. }) => credentials.digests(),
            _ => None,
        };
        for name in &named {
            let shown = self.ns.dir_shown.join(name);
            self.ns.file(name, &shown).remove()?;
        }
        self.state.remove()?;

        // The namespace directory, then its user directory when that is
        // empty too — both relative to descriptors from an `O_NOFOLLOW` walk,
        // never by path.
        let user_dir = self.ns.root.join(&self.ns.user);
        let user_fd = file_store::open_dir_under(&self.ns.root, &user_dir)?;
        rustix::fs::unlinkat(&user_fd, self.ns.acct.as_str(), AtFlags::REMOVEDIR).map_err(
            |errno| {
                FileStoreError::errno(
                    format!("could not remove `{}`", self.ns.dir_shown.display()),
                    errno,
                )
            },
        )?;
        if let Some(parent) = self.ns.root.parent()
            && let Ok(root_fd) = file_store::open_dir_under(parent, &self.ns.root)
        {
            // Another account of the same user keeps it: `ENOTEMPTY` is the
            // expected answer then, and nothing else here is worth a failure.
            let _ = rustix::fs::unlinkat(&root_fd, self.ns.user.as_str(), AtFlags::REMOVEDIR);
        }
        Ok(WriteReceipt {
            kind: WriteKind::Delete,
            digest8_before: digest8_of(before.as_ref()),
            digest8_after: None,
            ids: self.ns.ids(),
        })
    }
}

/// Whether `name` is one of the files a namespace write can leave.
fn is_named_file(name: &str) -> bool {
    matches!(name, AUTH_FILE | PENDING_FILE | PENDING_META)
        || name
            .strip_prefix(TMP_PREFIX)
            .is_some_and(|hex| hex.len() == 8 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// A namespace a verified login is about to be installed into. Writer 2.
pub struct InstallNamespace<'g> {
    login: VerifiedLogin,
    guard: PhantomData<&'g CodexNamespaceGuard>,
    ns: NamespaceDir,
    state: RefreshStateFile,
}

impl<'g> InstallNamespace<'g> {
    /// Opens (creating at 0700) the namespace a verified login names, taking
    /// the login by value.
    ///
    /// # Errors
    ///
    /// As [`OwnedNamespace::open`], including a guard for another namespace.
    pub fn open_for_install(
        paths: &Paths,
        login: VerifiedLogin,
        guard: &'g CodexNamespaceGuard,
    ) -> Result<Self, FileStoreError> {
        let (user, acct) = login.ids();
        let ns = NamespaceDir::open(paths, user, acct, guard)?;
        let state = RefreshStateFile::new(paths, user, acct)?;
        Ok(Self { login, guard: PhantomData, ns, state })
    }

    /// Writer 2: copies the verified document into the namespace, consuming
    /// the handle, so a verified login installs at most once.
    ///
    /// `O_EXCL` temporary → `fsync` → rename → directory `fsync`, with no
    /// pending fallback: on a failed rename the temporary is removed and the
    /// previous grant stays (plan ledger #237). Then the refresh marker is
    /// reset — floor, did-not-help count, `resent`, any stale in-flight entry —
    /// which is how a login lifts the terminal 401 state (plan AC114). A reset
    /// that fails after the install landed is logged and does not undo the
    /// install: the stale in-flight digest cannot match the new grant.
    ///
    /// Removing `<scratch>/auth.json` is the login driver's (S34), which
    /// registered it with cleanup before the child ran.
    ///
    /// # Errors
    ///
    /// [`FileStoreError`] from the write.
    pub fn install(self, fault: &Fault) -> Result<(WriteReceipt, CodexIdentity), FileStoreError> {
        let before = match self.ns.current() {
            Ok(Current::Present { credentials, .. }) => Some(credentials.digests()),
            Ok(Current::Absent) => None,
            // Torn or unparseable: there was something, and it is replaced.
            Ok(Current::Torn) | Err(_) => Some(None),
        };
        let mut bytes = Vec::new();
        self.login.doc().write_json_to(&mut bytes).map_err(|err| {
            FileStoreError::io(format!("could not serialize `{}`", self.ns.shown.display()), err)
        })?;
        let faults =
            WriteFaults { fault, before_rename: INSTALL_FAULTS.0, rename_fail: INSTALL_FAULTS.1 };
        match self.ns.auth_file().write(&bytes, None, StopPolicy::Complete, &faults)? {
            WriteOutcome::Written { .. } => {}
            WriteOutcome::SavedToPending { error } => {
                // Unreachable with no pending spec; stated rather than assumed.
                return Err(FileStoreError::io(
                    format!(
                        "`{}` was parked instead of installed: {error}",
                        self.ns.shown.display()
                    ),
                    io::Error::other("unexpected pending outcome"),
                ));
            }
        }
        if let Err(err) = self.state.reset_for_login() {
            tracing::warn!(error = %err, "the refresh marker could not be reset after a login install");
        }
        let receipt = WriteReceipt {
            kind: WriteKind::LoginInstall { overwrote: before.is_some() },
            digest8_before: before.flatten().as_ref().and_then(|d| digest8_of(Some(d))),
            digest8_after: digest8_of(self.login.doc().digests().as_ref()),
            ids: self.ns.ids(),
        };
        Ok((receipt, self.login.identity()))
    }
}

/// Why a refresh outcome is unknown (plan section 3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownClass {
    /// The request may have reached the server; no answer was read.
    Ambiguous,
    /// A 5xx.
    ServerError,
    /// A 429.
    RateLimited,
    /// The process died with the marker set (classified by the next pass).
    Interrupted,
    /// A TLS failure during or before the send.
    Tls,
}

/// How a sent refresh definitely ended, for clearing its marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefiniteOutcome {
    /// The response was applied (or parked as pending).
    Applied,
    /// A permanent failure: the grant is dead or was adopted from elsewhere.
    Permanent,
    /// Proven never sent.
    PreSend,
    /// A non-429 4xx answered before processing.
    Rejected,
    /// Another writer's newer grant replaced the one sent.
    External,
}

/// A refresh that was sent and has no definite outcome yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inflight {
    /// The refresh digest prefix of the grant sent.
    pub sent_digest8: String,
    /// When it was sent.
    #[serde(with = "ts")]
    pub sent_at: Timestamp,
}

/// One namespace's refresh marker (decision D-035).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshState {
    /// The marker's schema version.
    pub schema: u32,
    /// The refresh in flight, if any.
    #[serde(default)]
    pub inflight: Option<Inflight>,
    /// The current 401 floor in minutes (60 → 120 → 240).
    #[serde(default = "default_floor")]
    pub floor_min: u32,
    /// Sent refreshes followed by a 401.
    #[serde(default)]
    pub did_not_help: u8,
    /// Since when the in-flight outcome has been unknown.
    #[serde(default, with = "ts_opt")]
    pub ambiguous_since: Option<Timestamp>,
    /// Why it is unknown.
    #[serde(default)]
    pub class: Option<UnknownClass>,
    /// Whether the user's one `--resend` has been spent on this marker.
    #[serde(default)]
    pub resent: bool,
    /// A server's `retry-after`, for `rate_limited`.
    #[serde(default, with = "secs_opt")]
    pub retry_after: Option<Duration>,
    /// When a refresh was last sent, for the floor.
    #[serde(default, with = "ts_opt")]
    pub last_sent_at: Option<Timestamp>,
}

fn default_floor() -> u32 {
    DEFAULT_FLOOR_MIN
}

impl Default for RefreshState {
    fn default() -> Self {
        Self {
            schema: STATE_SCHEMA,
            inflight: None,
            floor_min: DEFAULT_FLOOR_MIN,
            did_not_help: 0,
            ambiguous_since: None,
            class: None,
            resent: false,
            retry_after: None,
            last_sent_at: None,
        }
    }
}

/// What reading a marker found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshStateRead {
    /// A marker.
    Present(RefreshState),
    /// No marker: nothing was ever sent, or it was reset.
    Absent,
    /// The marker exists and cannot be read. Never "unknown": the row is
    /// `refresh state unavailable`, and no POST is made (fail closed).
    Unavailable(String),
}

/// The value a refresh POST consumes: it exists only after the marker that
/// records the send is on disk (invariant I26).
pub struct InflightToken<'g> {
    digest8: String,
    _guard: PhantomData<&'g CodexNamespaceGuard>,
}

impl InflightToken<'_> {
    /// The refresh digest prefix the marker recorded.
    pub fn digest8(&self) -> &str {
        &self.digest8
    }
}

impl fmt::Debug for InflightToken<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InflightToken").field("digest8", &self.digest8).finish()
    }
}

/// `<config_dir>/codex/.state/<user>+<acct>.refresh`: 0600, replaced by
/// temporary + rename with the file **and** the directory `fsync`ed, always
/// under the namespace lock.
///
/// Neither `Clone` nor `Copy` (review S30 F6): a handle is only ever borrowed
/// from the namespace that holds the lock, so a mutator cannot outlive it.
#[derive(Debug)]
pub struct RefreshStateFile {
    root: PathBuf,
    dir: PathBuf,
    name: String,
    shown: PathBuf,
    user: String,
    acct: String,
}

impl RefreshStateFile {
    /// The marker for one namespace.
    fn new(paths: &Paths, user: &str, acct: &str) -> Result<Self, FileStoreError> {
        let shown = paths.codex_refresh_state_path(user, acct).map_err(refused)?;
        let name = shown
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned)
            .ok_or_else(|| FileStoreError::OutsideNamespaceRoot(shown.clone()))?;
        Ok(Self {
            root: paths.codex_root(),
            dir: paths.codex_state_dir(),
            name,
            shown,
            user: user.to_owned(),
            acct: acct.to_owned(),
        })
    }

    /// Reads the marker. Public: `doctor` shows it.
    pub fn load(&self) -> RefreshStateRead {
        let dir = match file_store::open_dir_under(&self.root, &self.dir) {
            Ok(dir) => dir,
            Err(FileStoreError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                return RefreshStateRead::Absent;
            }
            Err(err) => return RefreshStateRead::Unavailable(err.to_string()),
        };
        let bytes = match self.read_bytes(&dir) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return RefreshStateRead::Absent,
            Err(reason) => return RefreshStateRead::Unavailable(reason),
        };
        match serde_json::from_slice::<RefreshState>(&bytes) {
            Ok(state) if state.schema == STATE_SCHEMA => RefreshStateRead::Present(state),
            Ok(state) => RefreshStateRead::Unavailable(format!(
                "`{}` has schema {}, which this build does not read",
                self.shown.display(),
                state.schema
            )),
            Err(err) => RefreshStateRead::Unavailable(format!(
                "`{}` does not parse (line {}, column {})",
                self.shown.display(),
                err.line(),
                err.column()
            )),
        }
    }

    /// Reads the marker's bytes: `Ok(None)` only when there is no file.
    ///
    /// Not `file_store::read_file_at`, whose phase-1 rule reads an unreadable
    /// credential file as absent. For this file "absent" means "nothing was
    /// sent", so a marker that exists and cannot be read must fail closed
    /// (plan AC128's mode-0000 case), and only `ENOENT` is absence.
    fn read_bytes(&self, dir: &OwnedFd) -> Result<Option<Vec<u8>>, String> {
        let flags = rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC;
        let fd = match rustix::fs::openat(dir, self.name.as_str(), flags, rustix::fs::Mode::empty())
        {
            Ok(fd) => fd,
            Err(errno) if errno == Errno::NOENT => return Ok(None),
            Err(errno) => {
                return Err(format!("could not open `{}`: {}", self.shown.display(), errno));
            }
        };
        let file = File::from(fd);
        let meta = file
            .metadata()
            .map_err(|err| format!("could not stat `{}`: {}", self.shown.display(), err.kind()))?;
        if !meta.is_file() || meta.len() > MAX_STATE_BYTES {
            return Err(format!("`{}` is not a small regular file", self.shown.display()));
        }
        let mut bytes = Vec::new();
        file.take(MAX_STATE_BYTES)
            .read_to_end(&mut bytes)
            .map_err(|err| format!("could not read `{}`: {}", self.shown.display(), err.kind()))?;
        Ok(Some(bytes))
    }

    /// The marker to update: absent is a fresh one, unavailable refuses.
    fn load_for_update(&self) -> Result<RefreshState, FileStoreError> {
        match self.load() {
            RefreshStateRead::Present(state) => Ok(state),
            RefreshStateRead::Absent => Ok(RefreshState::default()),
            RefreshStateRead::Unavailable(reason) => Err(FileStoreError::Json(reason)),
        }
    }

    /// Replaces the marker durably: temporary, `fsync`, rename, directory
    /// `fsync`. A failed directory `fsync` is an error here — unlike a
    /// credential write, whose rename is what matters — because the token a
    /// POST consumes must not exist before its record is durable.
    fn store(&self, state: &RefreshState) -> Result<(), FileStoreError> {
        let dir = file_store::create_dir_under(&self.root, &self.dir)?;
        let bytes = serde_json::to_vec(state).map_err(|err| {
            FileStoreError::Json(format!("could not serialize `{}`: {err}", self.shown.display()))
        })?;
        let tmp = format!("{}.tmp.{}", self.name, file_store::hex8());
        if let Err(err) = file_store::create_new_file_at(dir.as_fd(), &tmp, &bytes) {
            // A write or `fsync` failure after the `O_EXCL` create leaves a
            // partial temporary; an `EEXIST` means the name was never ours.
            if err.kind() != io::ErrorKind::AlreadyExists {
                let _ = rustix::fs::unlinkat(&dir, tmp.as_str(), AtFlags::empty());
            }
            return Err(FileStoreError::io(
                format!("could not write `{}`", self.dir.join(&tmp).display()),
                err,
            ));
        }
        if let Err(errno) = rustix::fs::renameat(&dir, tmp.as_str(), &dir, self.name.as_str()) {
            let _ = rustix::fs::unlinkat(&dir, tmp.as_str(), AtFlags::empty());
            return Err(FileStoreError::errno(
                format!("could not replace `{}`", self.shown.display()),
                errno,
            ));
        }
        rustix::fs::fsync(&dir).map_err(|errno| {
            FileStoreError::errno(format!("could not flush `{}`", self.dir.display()), errno)
        })
    }

    /// Records a refresh about to be sent, and returns the token the POST
    /// consumes.
    ///
    /// Refuses when a send is already in flight: the caller clears a marker
    /// whose digest no longer matches the file before it gets here, and one
    /// that does match is `refresh outcome unknown` — never a second send
    /// (invariant I26).
    pub(super) fn write_inflight<'g>(
        &self,
        credentials: &LockedCredentials<'g>,
    ) -> Result<InflightToken<'g>, FileStoreError> {
        check_ids(credentials, &self.user, &self.acct, &self.shown)?;
        let digest8 = sent_digest(credentials, &self.shown)?;
        let mut state = self.load_for_update()?;
        if state.inflight.is_some() {
            return Err(FileStoreError::Json(format!(
                "`{}` already records a refresh in flight; refusing to send another",
                self.shown.display()
            )));
        }
        let now = Timestamp::now();
        state.inflight = Some(Inflight { sent_digest8: digest8.clone(), sent_at: now });
        state.ambiguous_since = None;
        state.class = None;
        state.resent = false;
        state.retry_after = None;
        state.last_sent_at = Some(now);
        self.store(&state)?;
        Ok(InflightToken { digest8, _guard: PhantomData })
    }

    /// Records the user's one re-send of an unknown refresh: the same digest,
    /// a new `sent_at`, `resent = true`, the unknown-since and class kept — in
    /// one durable write.
    ///
    /// Refuses unless the marker's in-flight digest is this grant's, its
    /// outcome has been classified unknown, and it has not been re-sent
    /// before. The time rule (`since + 1 h`) is the caller's (plan section 3.3).
    pub(super) fn write_resend<'g>(
        &self,
        credentials: &LockedCredentials<'g>,
    ) -> Result<InflightToken<'g>, FileStoreError> {
        check_ids(credentials, &self.user, &self.acct, &self.shown)?;
        let digest8 = sent_digest(credentials, &self.shown)?;
        let mut state = self.load_for_update()?;
        match &state.inflight {
            Some(inflight)
                if inflight.sent_digest8 == digest8 && !state.resent && state.class.is_some() => {}
            Some(_) if state.resent => {
                return Err(FileStoreError::Json(format!(
                    "`{}` has already been re-sent once; run `agctl codex login`",
                    self.shown.display()
                )));
            }
            _ => {
                return Err(FileStoreError::Json(format!(
                    "`{}` records no unknown refresh for this grant",
                    self.shown.display()
                )));
            }
        }
        let now = Timestamp::now();
        state.inflight = Some(Inflight { sent_digest8: digest8.clone(), sent_at: now });
        state.resent = true;
        state.last_sent_at = Some(now);
        self.store(&state)?;
        Ok(InflightToken { digest8, _guard: PhantomData })
    }

    /// Classifies a marker a dead process left behind: `interrupted`, unknown
    /// since it was sent (plan section 3.3).
    pub(super) fn mark_interrupted(&self, _now: Timestamp) -> Result<(), FileStoreError> {
        let mut state = self.load_for_update()?;
        let Some(inflight) = &state.inflight else { return Ok(()) };
        if state.class.is_none() {
            state.ambiguous_since = Some(inflight.sent_at);
            state.class = Some(UnknownClass::Interrupted);
            self.store(&state)?;
        }
        Ok(())
    }

    /// Keeps the in-flight marker and records why its outcome is unknown.
    pub(super) fn mark_unknown(
        &self,
        class: UnknownClass,
        now: Timestamp,
        retry_after: Option<Duration>,
    ) -> Result<(), FileStoreError> {
        let mut state = self.load_for_update()?;
        if state.inflight.is_none() {
            return Err(FileStoreError::Json(format!(
                "`{}` records no refresh in flight to mark unknown",
                self.shown.display()
            )));
        }
        state.ambiguous_since = Some(state.ambiguous_since.unwrap_or(now));
        state.class = Some(class);
        state.retry_after = retry_after;
        self.store(&state)
    }

    /// Clears the in-flight marker after a definite outcome.
    pub(super) fn clear_inflight(&self, _outcome: DefiniteOutcome) -> Result<(), FileStoreError> {
        let mut state = self.load_for_update()?;
        state.inflight = None;
        state.ambiguous_since = None;
        state.class = None;
        state.resent = false;
        state.retry_after = None;
        self.store(&state)
    }

    /// Lifts the 401 floor: count to 0, floor to 60 minutes.
    pub(super) fn reset_floor(&self) -> Result<(), FileStoreError> {
        let mut state = self.load_for_update()?;
        state.did_not_help = 0;
        state.floor_min = DEFAULT_FLOOR_MIN;
        self.store(&state)
    }

    /// A login's reset: everything back to a fresh marker. Called only by
    /// [`InstallNamespace::install`].
    fn reset_for_login(&self) -> Result<(), FileStoreError> {
        self.store(&RefreshState::default())
    }

    /// Removes the marker; `false` when there was none.
    fn remove(&self) -> Result<bool, FileStoreError> {
        let dir = match file_store::open_dir_under(&self.root, &self.dir) {
            Ok(dir) => dir,
            Err(FileStoreError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                return Ok(false);
            }
            Err(err) => return Err(err),
        };
        match rustix::fs::unlinkat(&dir, self.name.as_str(), AtFlags::empty()) {
            Ok(()) => Ok(true),
            Err(errno) if errno == Errno::NOENT => Ok(false),
            Err(errno) => Err(FileStoreError::errno(
                format!("could not remove `{}`", self.shown.display()),
                errno,
            )),
        }
    }
}

/// Refuses credentials read from a namespace other than `(user, acct)` (review
/// S30 F7). The ids are the ones the read was made under, never the claims,
/// which a refresh can legitimately change (fact F92).
fn check_ids(
    credentials: &LockedCredentials<'_>,
    user: &str,
    acct: &str,
    shown: &Path,
) -> Result<(), FileStoreError> {
    if credentials.ids() == (user, acct) {
        return Ok(());
    }
    Err(FileStoreError::io(
        format!("credentials read from another namespace cannot be used for `{}`", shown.display()),
        io::Error::from(io::ErrorKind::PermissionDenied),
    ))
}

/// The refresh digest prefix a marker records for a send.
fn sent_digest(
    credentials: &LockedCredentials<'_>,
    shown: &Path,
) -> Result<String, FileStoreError> {
    credentials.refresh_digest8().ok_or_else(|| {
        FileStoreError::Json(format!("no refresh token to record in `{}`", shown.display()))
    })
}

/// A timestamp as an RFC 3339 string.
mod ts {
    use jiff::Timestamp;
    use serde::Deserialize;
    use serde::Deserializer;
    use serde::Serializer;

    pub fn serialize<S: Serializer>(at: &Timestamp, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(at)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Timestamp, D::Error> {
        String::deserialize(deserializer)?.parse().map_err(serde::de::Error::custom)
    }
}

/// An optional timestamp as an RFC 3339 string or `null`.
mod ts_opt {
    use jiff::Timestamp;
    use serde::Deserialize;
    use serde::Deserializer;
    use serde::Serializer;

    pub fn serialize<S: Serializer>(
        at: &Option<Timestamp>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match at {
            Some(at) => serializer.collect_str(at),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Timestamp>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|text| text.parse().map_err(serde::de::Error::custom))
            .transpose()
    }
}

/// An optional duration as whole seconds or `null`.
mod secs_opt {
    use std::time::Duration;

    use serde::Deserialize;
    use serde::Deserializer;
    use serde::Serializer;

    pub fn serialize<S: Serializer>(
        value: &Option<Duration>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => serializer.serialize_u64(value.as_secs()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Duration>, D::Error> {
        Ok(Option::<u64>::deserialize(deserializer)?.map(Duration::from_secs))
    }
}

#[cfg(test)]
#[path = "auth_store_tests.rs"]
mod tests;
