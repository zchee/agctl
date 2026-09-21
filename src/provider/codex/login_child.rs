//! Runs the vendor's `codex login` in a scratch home and reports what it left
//! behind (plan section 3.3, decision D-037's L2′).
//!
//! The child is the one place agctl hands control to another program that
//! holds the user's browser session, so everything here is about bounding it:
//!
//! - **The environment is built, not inherited.** [`allowed_env`] is a pure
//!   function over the parent's variables, so the set the child sees is
//!   decided by a list this module owns rather than by whatever happens to be
//!   exported. A name outside D-037's allowlist cannot reach the child, and
//!   the unit tests prove it with decoys rather than with the real
//!   environment.
//! - **The home is a fresh directory agctl owns.** The leaf is created once,
//!   atomically, at 0700, relative to a descriptor for a root this module has
//!   already examined — see [`open_scratch_root`], which exists because
//!   creating a directory 0700 says nothing about one that was already there.
//! - **What the child leaves is evidence, not trust.** After it exits, the
//!   scratch is surveyed for a daemon directory and for lock files that are
//!   still *held*, and that evidence — with the two keychain listings and the
//!   exit status — becomes a [`PostExitReport`] which
//!   [`verify_login`](super::auth_store::verify_login) consumes.
//!
//! Nothing here reads or writes a credential: this module produces the report
//! and the scratch path, and `auth_store` decides what they mean.

use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;

use rustix::fs::AtFlags;
use rustix::fs::Dir;
use rustix::fs::FileType;
use rustix::fs::FlockOperation;
use rustix::fs::Mode;
use rustix::fs::OFlags;
use rustix::io::Errno;
use rustix::process::geteuid;

use crate::config::paths::Paths;
use crate::provider::codex::auth_store::shown_name;
use crate::provider::codex::home::CODEX_HOME_ENV;
use crate::provider::codex::home::open_readonly_nofollow;
use crate::provider::codex::proof::PostExitReport;
use crate::provider::codex::proof::ScratchSurvey;
use crate::runtime::cleanup;
use crate::runtime::coordinator::Cancel;
use crate::runtime::coordinator::PassCtx;
use crate::runtime::fault::Fault;
use crate::secret::file_store::hex8;
use crate::secret::namespace_lock;
use crate::secret::namespace_lock::NamespaceLockGuard;

/// The vendor binary agctl spawns.
pub const CODEX_BIN: &str = "codex";

/// The test-only override for [`CODEX_BIN`], compiled out of a release.
#[cfg(feature = "testing")]
pub const CODEX_BIN_ENV: &str = "AGCTL_CODEX_BIN";

/// How long the user has to finish the login before the child is killed.
///
/// Ten minutes is the plan's figure (section 3.3): long enough for a browser
/// round trip with a password manager and a second factor, short enough that
/// an abandoned login does not hold `scratch.lock` for an afternoon.
pub const LOGIN_DEADLINE: Duration = Duration::from_secs(600);

/// The name every scratch home starts with.
const SCRATCH_PREFIX: &str = "agctl-codex-login-";

/// How many times a colliding scratch name is retried before giving up.
///
/// A collision needs two logins to draw the same 32-bit suffix in the same
/// second; eight tries turn that into an impossibility rather than a retry
/// loop with no end.
const SCRATCH_TRIES: u32 = 8;

/// How deep the post-exit survey walks, and how many entries it will look at.
///
/// The scratch is agctl's own directory and the vendor's residue is shallow
/// (`tmp/arg0/codex-arg0<rand>/.lock`), so these bounds are generous. They
/// exist so that a child which fills the scratch with directories cannot turn
/// the survey into an unbounded walk.
const SURVEY_MAX_DEPTH: u32 = 8;
const SURVEY_MAX_ENTRIES: u32 = 4096;

/// Variables passed through to the child when the parent has them set.
///
/// Decision D-037, amended by architect L9 / critic m14 (ledger #171): the six
/// proxy and CA names are here because a user behind a proxy cannot reach the
/// authorization endpoint without them, and a login that cannot happen is not
/// a safer login.
///
/// `TERM` is a numbered deviation from the plan's list: it was in the
/// environment every S28 fact was measured with, and the vendor's prompts are
/// drawn with it.
const PASS_THROUGH: [&str; 11] = [
    "HOME",
    "PATH",
    "TMPDIR",
    "LANG",
    "TERM",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "ALL_PROXY",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
];

/// The prefix whose every variable is passed through (`LC_ALL`, `LC_CTYPE`, …).
const LOCALE_PREFIX: &str = "LC_";

/// The prefix that drives the stand-in binary, under `testing` only.
///
/// Compiled out of a release, and `scripts/release-gate.sh` proves the name is
/// absent from the artifact. Without it the fake would run with no knobs and
/// write nothing, which is how the e2e found this missing in the first place:
/// the allowlist's doc comment described a pass-through the code did not have.
#[cfg(feature = "testing")]
const FAKE_PREFIX: &str = "AGCTL_FAKE_CODEX_";

/// What went wrong before the child's own outcome could be judged.
#[derive(Debug, thiserror::Error)]
pub enum LoginChildError {
    /// The scratch root is not a directory agctl may create homes in.
    #[error("the Codex scratch root `{path}` {reason}; agctl will not create a login home there")]
    ScratchRoot {
        /// The root, as it was spelled.
        path: PathBuf,
        /// What is wrong with it, as a clause.
        reason: String,
    },
    /// Another login holds the lifecycle lock.
    #[error("another `agctl codex login` is in progress: {0}")]
    ScratchLock(String),
    /// A scratch home could not be created.
    #[error("could not create a Codex login home under `{path}`: {reason}")]
    Scratch {
        /// The root the leaf was to be created in.
        path: PathBuf,
        /// The failure, as a sentence.
        reason: String,
    },
    /// The vendor's binary is not on `PATH`.
    #[error("`{CODEX_BIN}` is not on PATH; install the Codex CLI, or run `agctl codex import`")]
    NotOnPath,
    /// The child could not be started.
    #[error("could not run `{bin}`: {reason}")]
    Spawn {
        /// The binary agctl tried to run.
        bin: String,
        /// The failure, as a sentence.
        reason: String,
    },
    /// The user did not finish the login in time.
    #[error("the Codex login did not finish within {}s; nothing was installed", .0.as_secs())]
    Deadline(Duration),
    /// The login was cancelled (a signal, or the command being wound down).
    #[error("the Codex login was cancelled; nothing was installed")]
    Cancelled,
    /// The keychain could not be read after the child exited.
    ///
    /// Never "nothing gained": the second listing is the check that catches a
    /// child that put its credential in the keychain despite being asked not
    /// to (fact F95), so a listing that could not be taken is a refusal.
    #[error("could not read the keychain after the login: {0}; nothing was installed")]
    KeychainAfter(String),
}

/// Builds the child's environment from the parent's.
///
/// Pure on purpose: the parent's variables arrive as an iterator, so the unit
/// tests feed it decoys — a `KACHE_`-prefixed name, `CODEX_API_KEY`, an
/// inherited `CODEX_HOME` pointing at the live home — and assert on the whole
/// result, rather than reaching for the real environment and asserting on the
/// names the test happened to think of.
///
/// `CODEX_HOME` is always the scratch. An inherited one is dropped on the way
/// past, which is the single most important line in this module: it is what
/// stops the child from writing into the home agctl is trying to protect.
pub fn allowed_env<'a>(
    inherited: impl Iterator<Item = (&'a OsStr, &'a OsStr)>,
    scratch: &Path,
) -> Vec<(OsString, OsString)> {
    let mut chosen: Vec<(OsString, OsString)> = Vec::new();
    for (name, value) in inherited {
        let Some(text) = name.to_str() else {
            // A name that is not UTF-8 cannot match the allowlist, and the
            // allowlist is the only way in.
            continue;
        };
        if text == CODEX_HOME_ENV {
            // Set below, from the scratch path, never from the parent.
            continue;
        }
        #[cfg(feature = "testing")]
        let test_seam = text.starts_with(FAKE_PREFIX) && text.len() > FAKE_PREFIX.len();
        #[cfg(not(feature = "testing"))]
        let test_seam = false;

        let allowed = PASS_THROUGH.contains(&text)
            || text.starts_with(LOCALE_PREFIX) && text.len() > LOCALE_PREFIX.len()
            || test_seam;
        if allowed {
            chosen.push((name.to_os_string(), value.to_os_string()));
        }
    }
    chosen.push((OsString::from(CODEX_HOME_ENV), scratch.as_os_str().to_os_string()));
    chosen
}

/// Takes the lock that serialises the whole `login` lifecycle.
///
/// The name is derived from [`Paths::codex_scratch_lock`] rather than spelled
/// again here, so the accessor and this call site cannot drift into two
/// spellings of one path; the lock itself is taken through the same
/// [`namespace_lock::acquire_at`] every namespace lock uses, in the same
/// directory.
///
/// The guard is a plain [`NamespaceLockGuard`], deliberately **not** wrapped
/// in a `CodexNamespaceGuard`: that type is the proof that a namespace may be
/// written, and holding `scratch.lock` proves only that a login is in
/// progress. The install takes its own namespace lock later, inside this one.
///
/// # Errors
///
/// Returns [`LoginChildError::ScratchLock`] when the lock cannot be taken
/// within `budget` — another `agctl codex login` is running.
pub fn acquire_scratch_lock(
    paths: &Paths,
    budget: Duration,
    cancel: &Cancel,
    fault: &Fault,
) -> Result<NamespaceLockGuard, LoginChildError> {
    let path = paths.codex_scratch_lock();
    let name = path.file_name().and_then(OsStr::to_str).ok_or_else(|| {
        LoginChildError::ScratchLock(format!("`{}` does not name a lock file", path.display()))
    })?;
    let now = Instant::now();
    let deadline = now.checked_add(budget).unwrap_or(now);
    namespace_lock::acquire_at(&paths.codex_locks_dir(), name, deadline, cancel, fault.clone())
        .map_err(|err| LoginChildError::ScratchLock(err.to_string()))
}

/// Judges a scratch root from its `stat`, with no I/O of its own.
///
/// Split out so the refusals can be unit-tested by *passing* a uid rather than
/// by *being* one: a test cannot make a directory another user owns without
/// privileges, and "every other test happens to pass through the comparison"
/// catches an inverted comparison but not a deleted one. Calling this with a
/// `expected_uid` that differs from `st_uid` exercises the branch directly, so
/// the mutant "delete the owner check" goes red.
///
/// # Errors
///
/// The clause naming what is wrong, ready to be read after the root's path.
fn root_verdict(st_uid: u32, st_mode: u32, expected_uid: u32) -> Result<(), String> {
    if st_uid != expected_uid {
        return Err("is owned by another user".to_owned());
    }
    let mode = st_mode & 0o777;
    if mode & 0o077 != 0 {
        return Err(format!("is mode {mode:04o}, which lets other users in (it must be 0700)"));
    }
    Ok(())
}

/// Opens the scratch root as a descriptor, refusing anything that is not the
/// 0700 directory this uid owns.
///
/// The scratch leaf's name carries only 32 bits of randomness ([`hex8`]), so
/// the property that keeps a login home private is not the name but the
/// parent: a directory another user cannot enter cannot be enumerated or
/// pre-populated. `Paths::ensure_codex_dirs` creates the root at 0700 when it
/// is absent and **trusts it when it is present**, so this is the check that
/// makes that argument true rather than assumed.
///
/// The check and the creation are bound to the **same inode**: the root is
/// opened once with `O_DIRECTORY | O_NOFOLLOW`, examined through `fstat` on
/// that descriptor, and the leaf is then created with `mkdirat` relative to
/// it. There is no window in which the path could be swapped between the
/// check and the `mkdir`, because after the open there is no path left to
/// re-resolve. The walk above the root may still be symlinked, which fact F60
/// allows; a link *at* the root is refused.
///
/// A permissive root is a refusal, not something to repair: silently
/// `chmod`-ing it would hide how it came to be 0755.
///
/// # Errors
///
/// Returns [`LoginChildError::ScratchRoot`] when the root is missing, is not a
/// directory, is a symbolic link, is owned by another user, or carries any
/// group or other bit.
pub fn open_scratch_root(root: &Path) -> Result<OwnedFd, LoginChildError> {
    let refuse = |reason: &str| LoginChildError::ScratchRoot {
        path: root.to_path_buf(),
        reason: reason.to_owned(),
    };

    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let dir = rustix::fs::open(root, flags, Mode::empty()).map_err(|errno| {
        // What the root *is* is read back from the path rather than inferred
        // from the errno: a symbolic link under `O_NOFOLLOW | O_DIRECTORY`
        // reports `ELOOP` on some systems and `ENOTDIR` on others, and a
        // refusal that names the wrong cause sends the user to the wrong
        // place. This stat runs only after the open has already failed, so it
        // decides nothing — it only words the refusal.
        match fs::symlink_metadata(root) {
            Ok(meta) if meta.file_type().is_symlink() => refuse("is a symbolic link"),
            Ok(meta) if !meta.is_dir() => refuse("is not a directory"),
            _ => LoginChildError::ScratchRoot {
                path: root.to_path_buf(),
                reason: format!("cannot be opened ({errno})"),
            },
        }
    })?;

    let stat = rustix::fs::fstat(&dir).map_err(|errno| LoginChildError::ScratchRoot {
        path: root.to_path_buf(),
        reason: format!("cannot be inspected ({errno})"),
    })?;

    if let Err(reason) = root_verdict(stat.st_uid, u32::from(stat.st_mode), geteuid().as_raw()) {
        return Err(LoginChildError::ScratchRoot { path: root.to_path_buf(), reason });
    }
    Ok(dir)
}

/// Creates the directory `name` inside the verified root, at 0700.
///
/// `mkdirat` relative to the root's descriptor, so an existing name is `EEXIST`
/// and never a silent reuse — the directory equivalent of the `O_EXCL` the
/// crate's file writers rely on. Split out so that property has a test of its
/// own: a builder that created parents or tolerated an existing directory
/// would reuse a leaf somebody else made, and nothing else would notice.
///
/// # Errors
///
/// The `Errno` from `mkdirat`, `EEXIST` included.
pub(crate) fn mkdir_leaf(root: &OwnedFd, name: &str) -> Result<(), Errno> {
    rustix::fs::mkdirat(root, name, Mode::RWXU)
}

/// Whether `name` is exactly the shape a scratch home is created with:
/// `agctl-codex-login-` followed by eight lowercase hex digits.
///
/// Exact, not a prefix: the sweep removes what this accepts, so it must accept
/// only what [`Scratch::create`] could have made, and nothing a user happened
/// to name similarly. `doctor` asks the same question for the other reason —
/// a name it did not write is a name it will not print (review S35 C3) — and
/// the two answers must not drift, so they are one predicate.
pub(crate) fn is_scratch_name(name: &str) -> bool {
    name.strip_prefix(SCRATCH_PREFIX).is_some_and(|suffix| {
        suffix.len() == 8
            && suffix.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// How deep [`remove_tree_at`] descends before it stops.
const REMOVE_MAX_DEPTH: u32 = 16;

/// Writes one line saying something agctl created could not be removed.
///
/// Never panics: a failed write is ignored. This runs inside `Drop`, and under
/// this crate's `panic = "abort"` a panicking write there would abort the very
/// cleanup it is reporting on. The line names the path and the errno — never a
/// byte of the file — and asks for a manual removal, because agctl has already
/// done everything it can.
fn report(out: &mut dyn Write, path: &Path, what: &str, errno: Errno) {
    let _ = writeln!(
        out,
        "agctl: could not remove {what} in the Codex login scratch home `{}` ({errno}); \
         remove it by hand",
        path.display()
    );
}

/// Opens the subdirectory `name` of `dir` without following a link, making it
/// searchable first if it has to.
///
/// A same-uid child can `chmod 000` a directory it created, which would leave
/// its contents behind. The owner may always change the mode, so on `EACCES`
/// the mode is reset with `fchmodat(AT_SYMLINK_NOFOLLOW)` — which acts on a
/// link itself rather than its target, so a swap between the `statat` and here
/// cannot redirect it — and the open is tried once more.
fn open_subdir(dir: &OwnedFd, name: &std::ffi::CStr) -> Option<OwnedFd> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    match rustix::fs::openat(dir, name, flags, Mode::empty()) {
        Ok(child) => Some(child),
        Err(Errno::ACCESS) => {
            rustix::fs::chmodat(dir, name, Mode::RWXU, AtFlags::SYMLINK_NOFOLLOW).ok()?;
            rustix::fs::openat(dir, name, flags, Mode::empty()).ok()
        }
        Err(_) => None,
    }
}

/// Removes everything inside the directory `dir`, then nothing else.
///
/// Every step is relative to a descriptor: each entry is examined with
/// `statat(AT_SYMLINK_NOFOLLOW)`, a subdirectory is entered only through
/// `openat(O_DIRECTORY | O_NOFOLLOW)`, and removal is `unlinkat`. So a link
/// planted anywhere in the tree — the child writes this tree, and F81's residue
/// already contains links — is removed as a link and never followed, which is
/// what stops a planted `<leaf>/x -> ~/.codex` from making agctl empty the live
/// home. Bounded by [`REMOVE_MAX_DEPTH`].
///
/// Silent by itself: what is left behind shows up as the caller's final
/// `unlinkat(AT_REMOVEDIR)` failing with `ENOTEMPTY`, which the caller reports.
fn remove_tree_at(dir: &OwnedFd, depth: u32) {
    if depth >= REMOVE_MAX_DEPTH {
        return;
    }
    let Ok(entries) = Dir::read_from(dir) else { return };
    let names: Vec<std::ffi::CString> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_owned())
        .filter(|name| name.as_bytes() != b"." && name.as_bytes() != b"..")
        .collect();
    for name in names {
        let Ok(stat) = rustix::fs::statat(dir, name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW) else {
            continue;
        };
        if FileType::from_raw_mode(stat.st_mode) == FileType::Directory {
            if let Some(child) = open_subdir(dir, name.as_c_str()) {
                remove_tree_at(&child, depth.saturating_add(1));
            }
            let _ = rustix::fs::unlinkat(dir, name.as_c_str(), AtFlags::REMOVEDIR);
        } else {
            let _ = rustix::fs::unlinkat(dir, name.as_c_str(), AtFlags::empty());
        }
    }
}

/// Removes the scratch homes a crashed or killed login left behind.
///
/// Only ever called with `scratch.lock` held and with a root that
/// [`open_scratch_root`] has already verified, so "old enough" is a safe
/// question: no login this process cannot see is running, and the root is the
/// 0700 directory this uid owns rather than whatever a link pointed at.
///
/// Everything goes through `root`: an entry is considered only when its name is
/// exactly [`is_scratch_name`], it is examined with `statat(AT_SYMLINK_NOFOLLOW)`
/// so a link is never a directory here, and it is removed with
/// [`remove_tree_at`] then `unlinkat(AT_REMOVEDIR)`. A directory the user made
/// that merely sits in the root is never touched. A home that still cannot be
/// removed is reported on `out` by path, never silently kept.
pub fn sweep_stale_at(root: &OwnedFd, root_path: &Path, max_age: Duration, out: &mut dyn Write) {
    let Ok(entries) = Dir::read_from(root) else { return };
    let names: Vec<std::ffi::CString> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_owned())
        .filter(|name| name.to_str().is_ok_and(is_scratch_name))
        .collect();
    let now = SystemTime::now();
    for name in names {
        let Ok(stat) = rustix::fs::statat(root, name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW) else {
            continue;
        };
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
            continue;
        }
        let Some(modified) = modified_at(&stat) else { continue };
        let aged = now.duration_since(modified).is_ok_and(|age| age >= max_age);
        if !aged {
            continue;
        }
        if let Some(leaf) = open_subdir(root, name.as_c_str()) {
            let _ = rustix::fs::fchmod(&leaf, Mode::RWXU);
            remove_tree_at(&leaf, 0);
        }
        match rustix::fs::unlinkat(root, name.as_c_str(), AtFlags::REMOVEDIR) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(errno) => {
                let path = root_path.join(name.to_string_lossy().as_ref());
                report(out, &path, "a stale login home", errno);
            }
        }
    }
}

/// A `stat`'s modification time, or `None` when it cannot be represented.
fn modified_at(stat: &rustix::fs::Stat) -> Option<SystemTime> {
    let secs = u64::try_from(stat.st_mtime).ok()?;
    SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(secs))
}

/// A scratch home, held by descriptor for the whole login.
///
/// **Dropping it discards it.** The credential inside is unlinked, the leaf is
/// emptied and removed, and the cleanup registration is withdrawn — on every
/// path out of the login, the error paths included. That is a property of the
/// type rather than of every caller remembering to call a cleanup function,
/// which is exactly how an early `?` once left a killed child's `auth.json` on
/// disk.
///
/// Every removal goes through the two descriptors taken at creation, never
/// through the path: if the leaf is replaced by a symbolic link to the live
/// Codex home while the login runs, the removal still acts on the directory
/// agctl created, and the live `auth.json` behind the link is untouched
/// (invariant I21). The child itself is still handed the PATH — that is how a
/// program is told its home — so the descriptor bounds agctl's own removals,
/// not what the child can reach.
///
/// **What this cannot promise.** This crate builds with `panic = "abort"`, and
/// an abort runs no destructor. A panic in the window from the child writing
/// `auth.json` to the unlink straight after the install would therefore leave
/// `<scratch>/auth.json` — 0600, inside agctl's 0700 tree — until a later
/// login's sweep removes homes older than fifteen minutes.
/// `runtime::cleanup::emergency` covers signals, not panics. agctl's own output
/// is not such a panic: the `login` command prints through a writer that drops
/// an undeliverable line, and the tracing subscriber is built with
/// `log_internal_errors(false)`, so neither a closed stdout nor a closed stderr
/// can abort this window. Any other panic still could, and would leave the file.
///
/// **What a failure looks like.** A removal that still fails after the leaf's
/// mode has been reset is reported on stderr by path and errno — never
/// silently kept.
pub struct Scratch {
    root: OwnedFd,
    leaf: OwnedFd,
    name: String,
    path: PathBuf,
    auth_cleanup: Option<cleanup::CleanupToken>,
    done: bool,
}

impl Scratch {
    /// Creates a fresh scratch home in a root [`open_scratch_root`] verified.
    ///
    /// The credential path is registered with `runtime::cleanup` here, before
    /// any child exists, so a terminating signal can take the credential away
    /// from the moment one could be written.
    ///
    /// # Errors
    ///
    /// [`LoginChildError::Scratch`] when no leaf could be created or opened.
    pub fn create(root_path: &Path, root: OwnedFd) -> Result<Self, LoginChildError> {
        let refuse =
            |reason: String| LoginChildError::Scratch { path: root_path.to_path_buf(), reason };

        let mut collisions = 0_u32;
        let name = loop {
            if collisions >= SCRATCH_TRIES {
                return Err(refuse(format!("{collisions} generated names were already taken")));
            }
            let name = format!("{SCRATCH_PREFIX}{}", hex8());
            match mkdir_leaf(&root, &name) {
                Ok(()) => break name,
                Err(Errno::EXIST) => collisions = collisions.saturating_add(1),
                Err(errno) => return Err(refuse(errno.to_string())),
            }
        };

        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let leaf = match rustix::fs::openat(&root, name.as_str(), flags, Mode::empty()) {
            Ok(leaf) => leaf,
            Err(errno) => {
                let _ = rustix::fs::unlinkat(&root, name.as_str(), AtFlags::REMOVEDIR);
                return Err(refuse(errno.to_string()));
            }
        };

        let path = root_path.join(&name);
        let auth_cleanup = Some(cleanup::register_tmp_path(path.join(shown_name())));
        Ok(Self { root, leaf, name, path, auth_cleanup, done: false })
    }

    /// The path the child is told to use as its home.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Unlinks the scratch credential now, through the leaf descriptor.
    ///
    /// Called as soon as the install has copied the bytes (and on a refusal),
    /// so two 0600 copies of the grant do not coexist across the wait for the
    /// configuration lock.
    pub fn unlink_credential(&self) {
        let _ = rustix::fs::unlinkat(&self.leaf, shown_name(), AtFlags::empty());
    }
}

impl Scratch {
    /// Removes the credential and the scratch home, reporting on `out` anything
    /// that could not be removed.
    ///
    /// The leaf's mode is reset first: a same-uid child can make its home
    /// read-only (`chmod 500`), which would otherwise make every later unlink
    /// fail with `EACCES`, silently, on this login and on every sweep after it.
    /// The owner may always change the mode of its own directory, and doing it
    /// on the descriptor means no path is re-resolved.
    pub(crate) fn discard(&mut self, out: &mut dyn Write) {
        if self.done {
            return;
        }
        self.done = true;
        let _ = rustix::fs::fchmod(&self.leaf, Mode::RWXU);
        let credential = match rustix::fs::unlinkat(&self.leaf, shown_name(), AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => None,
            Err(errno) => Some(errno),
        };
        remove_tree_at(&self.leaf, 0);
        // Reported only if the name is STILL there after the tree walk. An
        // `auth.json` a child made into a directory fails the plain unlink
        // (`EPERM` on Darwin) and is then removed by the walk; saying "remove
        // it by hand" about something already gone would send the user to
        // look for nothing.
        if let Some(errno) = credential
            && rustix::fs::statat(&self.leaf, shown_name(), AtFlags::SYMLINK_NOFOLLOW).is_ok()
        {
            report(out, &self.path, &format!("the credential `{}`", shown_name()), errno);
        }
        match rustix::fs::unlinkat(&self.root, self.name.as_str(), AtFlags::REMOVEDIR) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(errno) => report(out, &self.path, "the directory", errno),
        }
        if let Some(token) = self.auth_cleanup.take() {
            cleanup::unregister(token);
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        self.discard(&mut io::stderr().lock());
    }
}

/// Resolves the vendor binary.
///
/// Production walks `PATH`. Under the `testing` feature `AGCTL_CODEX_BIN`
/// replaces it, which is how every test runs a stand-in instead of the real
/// CLI; the name is absent from a release artifact and `scripts/release-gate.sh`
/// proves it.
///
/// # Errors
///
/// Returns [`LoginChildError::NotOnPath`] when no `codex` is found.
pub fn resolve_codex_bin() -> Result<PathBuf, LoginChildError> {
    #[cfg(feature = "testing")]
    if let Some(bin) = std::env::var_os(CODEX_BIN_ENV) {
        return Ok(PathBuf::from(bin));
    }

    let path = std::env::var_os("PATH").ok_or(LoginChildError::NotOnPath)?;
    for dir in std::env::split_paths(&path) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let candidate = dir.join(CODEX_BIN);
        if is_executable_file(&candidate) {
            return Ok(candidate);
        }
    }
    Err(LoginChildError::NotOnPath)
}

/// Whether `path` is a regular file this process could execute.
fn is_executable_file(path: &Path) -> bool {
    match fs::metadata(path) {
        Ok(meta) => meta.is_file() && meta.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

/// Whether `path` names a lock file.
///
/// The test is on the **name**, not on `Path::extension`: the file a real
/// `codex login` leaves is called `.lock`, and a leading dot makes the whole
/// name the file stem, so `extension()` returns `None` for it. Matching on the
/// extension would therefore have missed the one lock file this check exists
/// to see.
fn is_lock_name(path: &Path) -> bool {
    path.file_name().and_then(OsStr::to_str).is_some_and(|name| name.ends_with(".lock"))
}

/// What asking a lock file whether it is held can answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Probe {
    /// Something holds it.
    Held,
    /// Nobody holds it, or it cannot be held by anyone (see below).
    Free,
    /// The question could not be asked, so the answer is unknown.
    Unknown,
}

/// Whether a lock file is *held* by something other than this process.
///
/// Only ever called on an entry [`survey`] has already established is a
/// regular file.
///
/// The probe is non-blocking and non-contending: the file is opened read-only
/// through `home::open_readonly_nofollow`, whose flags carry **`O_NONBLOCK`**
/// as well as `O_NOFOLLOW` — so even a FIFO could not make this open wait; the
/// regular-file check in [`survey`] exists to keep `flock` off non-regular
/// descriptors and device nodes, not to prevent a hang. An exclusive `flock` is
/// attempted once and, whatever the answer, released before the descriptor
/// closes.
///
/// - acquired → nobody held it → [`Probe::Free`]. A normal `codex login` leaves
///   an unheld `tmp/arg0/codex-arg0<rand>/.lock` behind (fact F81, measured at
///   S28), so treating existence as evidence would refuse every real login.
/// - `EWOULDBLOCK` → [`Probe::Held`]. A shared (`LOCK_SH`) holder blocks an
///   exclusive probe too, so a reader-only survivor reads as held; deliberate,
///   and the conservative direction.
/// - `ENOTSUP` / `EOPNOTSUPP` on the `flock` → [`Probe::Free`]: the filesystem
///   has no advisory locks, so nobody can be holding one, and failing closed
///   would refuse every login there (every login leaves a lock file).
/// - the open fails with `ELOOP` or `ENOENT` → [`Probe::Free`]: a link at that
///   name (the survey never offers one, so only a race produces it) cannot be a
///   lock anyone holds for this home, and a file that vanished is held by
///   nobody.
/// - any other failure — `EACCES` on a 0000 lock file included → [`Probe::Unknown`],
///   which the survey records as incomplete. "Could not look" is not "free".
fn is_held(path: &Path) -> Probe {
    let file = match open_readonly_nofollow(path) {
        Ok(file) => file,
        Err(err) => {
            return match Errno::from_io_error(&err) {
                Some(Errno::LOOP | Errno::NOENT) => Probe::Free,
                _ => Probe::Unknown,
            };
        }
    };
    match rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {
            // Released at once, so nothing waiting on this file is delayed by
            // the question having been asked.
            let _ = rustix::fs::flock(&file, FlockOperation::Unlock);
            Probe::Free
        }
        Err(Errno::WOULDBLOCK) => Probe::Held,
        Err(errno) if errno == Errno::NOTSUP || errno == Errno::OPNOTSUPP => Probe::Free,
        Err(_) => Probe::Unknown,
    }
}

/// Surveys the scratch home after the child has exited.
///
/// Unheld lock files are normal residue and are reported nowhere: they leave
/// with the directory. Everything else the walk can tell apart is evidence.
///
/// Only regular files are probed; a `*.lock` that is a FIFO, socket, device
/// node or directory is recorded as an anomaly, because S28's measured residue
/// contains none and `flock` has no business on one.
///
/// **"Could not look" never reads as "found nothing".** Hitting a bound, a
/// directory that cannot be listed, an entry that cannot be examined, or a lock
/// whose state cannot be asked all set [`ScratchSurvey::truncated`], which
/// refuses: a home that was not walked completely has not been shown clean.
/// Only `NotFound` is forgiven — an entry that vanished between the listing and
/// the look is not evidence of anything.
fn survey(scratch: &Path) -> ScratchSurvey {
    // Every field named: `ScratchSurvey` has no `Default`, because a default
    // value would be the claim "we looked and found nothing".
    let mut found = ScratchSurvey {
        daemon_dir: matches!(
            fs::symlink_metadata(scratch.join("app-server-daemon")),
            Ok(meta) if meta.is_dir()
        ),
        held_locks: Vec::new(),
        odd_locks: Vec::new(),
        truncated: false,
    };

    let mut budget = SURVEY_MAX_ENTRIES;
    let mut queue = vec![(scratch.to_path_buf(), 0_u32)];
    while let Some((dir, depth)) = queue.pop() {
        if depth >= SURVEY_MAX_DEPTH {
            found.truncated = true;
            continue;
        }
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => {
                found.truncated = true;
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                Err(_) => {
                    found.truncated = true;
                    continue;
                }
            };
            if budget == 0 {
                found.truncated = true;
                return found;
            }
            budget = budget.saturating_sub(1);
            let path = entry.path();
            // `symlink_metadata` settles the type without following anything
            // and without opening anything.
            let meta = match fs::symlink_metadata(&path) {
                Ok(meta) => meta,
                Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                Err(_) => {
                    found.truncated = true;
                    continue;
                }
            };
            let kind = meta.file_type();
            if kind.is_symlink() {
                // Never followed, and never held: a planted link must not be
                // able to deny a login.
                continue;
            }
            if kind.is_dir() && !is_lock_name(&path) {
                queue.push((path, depth.saturating_add(1)));
            } else if is_lock_name(&path) {
                if kind.is_file() {
                    match is_held(&path) {
                        Probe::Held => found.held_locks.push(path),
                        Probe::Free => {}
                        Probe::Unknown => found.truncated = true,
                    }
                } else {
                    found.odd_locks.push(path);
                }
            }
        }
    }
    found
}

/// Runs `codex login` against `scratch` and reports what it left behind.
///
/// The caller owns the [`Scratch`] and therefore its removal: whatever this
/// returns — a report, a deadline, a cancel, a spawn failure, a keychain that
/// could not be read — the scratch is discarded when the caller drops it, so
/// no exit path can leave a credential behind.
///
/// `listing_after` is taken **after** the child has exited. An error from it
/// is a refusal ([`LoginChildError::KeychainAfter`]), never an empty listing.
///
/// # Errors
///
/// Returns [`LoginChildError`] when the child cannot be started, when it is
/// still running at the deadline or the login is cancelled, and when the
/// keychain cannot be read afterwards.
pub fn run(
    scratch: &Scratch,
    bin: &Path,
    ctx: &PassCtx,
    listing_before: &[String],
    listing_after: impl FnOnce() -> Result<Vec<String>, String>,
) -> Result<PostExitReport, LoginChildError> {
    let status = spawn_and_wait(bin, scratch.path(), ctx)?;
    let found = survey(scratch.path());
    let after = listing_after().map_err(LoginChildError::KeychainAfter)?;
    let gained = gained_entries(listing_before, &after);
    Ok(PostExitReport::from_child(gained, Vec::new(), found, status))
}

/// Starts the child and waits for it, killing it at the deadline.
fn spawn_and_wait(
    bin: &Path,
    scratch: &Path,
    ctx: &PassCtx,
) -> Result<ExitStatus, LoginChildError> {
    let inherited: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    let env = allowed_env(inherited.iter().map(|(k, v)| (k.as_os_str(), v.as_os_str())), scratch);

    let mut command = Command::new(bin);
    // The measured order (S28, fact F95): `codex -c '<override>' login`. The
    // override asks the child to keep its credential in a file rather than the
    // keychain. It is a request, not a guarantee — legacy-managed config layers
    // outrank it — which is why the caller compares keychain listings
    // afterwards instead of trusting it.
    command.arg("-c");
    command.arg("cli_auth_credentials_store=\"file\"");
    command.arg("login");
    command.env_clear();
    command.envs(env);
    // The child runs in its scratch home, not in agctl's working directory:
    // Codex resolves a `.codex/` Project config layer (fact F95, precedence 25)
    // from the directory it starts in, and a repository the user happens to be
    // standing in must not configure the login.
    command.current_dir(scratch);
    // The login is interactive: the vendor prints a URL and waits for the
    // browser to come back. Piping its output would hide the URL from the
    // user, so all three streams are the terminal's. Nothing the child writes
    // enters agctl's own output, which is also why it cannot leak through it.
    command.stdin(Stdio::inherit());
    command.stdout(Stdio::inherit());
    command.stderr(Stdio::inherit());

    let child = command.spawn().map_err(|err| LoginChildError::Spawn {
        bin: bin.display().to_string(),
        reason: err.to_string(),
    })?;
    let token = ctx.register_child(child);

    match ctx.wait_child_timeout(token, LOGIN_DEADLINE) {
        Ok(Some(status)) => Ok(status),
        // Nothing may be installed from a login that did not finish. On the
        // deadline (`Ok(None)`) and on a coordinator kill the child has been
        // killed and reaped. On `Err` — `try_wait` itself failing, a `waitpid`
        // error on our own child — it may be neither; that is theoretical, and
        // what matters here still holds: the caller's `Scratch` drop removes
        // the credential whatever the child is doing. The two wordings are
        // apart because they send the user to different places: a cancel was
        // their own, a deadline was the browser round trip taking too long.
        Ok(None) | Err(_) if ctx.cancel().is_cancelled() => Err(LoginChildError::Cancelled),
        Ok(None) | Err(_) => Err(LoginChildError::Deadline(LOGIN_DEADLINE)),
    }
}

/// The `Codex Auth` accounts present in the second listing and not the first.
///
/// These are `cli|<hash>` names, never emails.
fn gained_entries(before: &[String], after: &[String]) -> Vec<String> {
    after.iter().filter(|entry| !before.contains(entry)).cloned().collect()
}

#[cfg(test)]
#[path = "login_child_tests.rs"]
mod tests;
