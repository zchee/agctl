//! The keychain **write** transport: one argv shape, one line, on stdin.
//!
//! This is the only module in the crate that names `add-generic-password`, and
//! the only one that can make `security(1)` change anything. Invariant I1′ is
//! what shapes it, and it is arranged to hold at *compile* time rather than by
//! review:
//!
//! 1. **A write needs a [`WriteTarget`]**, whose fields are private and which
//!    has exactly two constructors — [`WriteTarget::live`], which derives the
//!    store directory and the service name **together from one
//!    [`EnvView`]**, and [`WriteTarget::migrated`], which takes an
//!    [`OwnedSha8`] that only an `Owned` registry record can produce. There is
//!    no `From<String>`, no public struct literal, and therefore no way to
//!    name an arbitrary keychain item from anywhere else in the crate.
//! 2. **The argv is the constant [`WRITE_ARGV`]** — `["-i"]`, fact F42 — and
//!    the payload goes on **stdin**. No secret ever reaches argv (invariant
//!    I15), which is the whole reason this transport exists rather than the
//!    argv form Claude Code falls back to for an over-long line.
//! 3. **There is no delete path.** `delete-generic-password` is issued
//!    nowhere in agentctl (fact F43, non-goal in plan section 1.2): a swap
//!    updates an item in place with `-U`, so a failed write leaves the
//!    previous credential intact and nothing agentctl does can make an item
//!    disappear. This comment is the only place in `src/` that names the
//!    subcommand, so the gate's grep has exactly one hit to expect.
//!
//! # What this module deliberately does not do
//!
//! It does not build the line — [`Credentials::to_keychain_stdin_line`] does,
//! inside the crate's single credential exposure site, and hands back a
//! [`KeychainStdinLine`] this module can hand to a pipe without ever holding
//! the plaintext itself. It does not take a lock: acquiring the peer's locks
//! around a write is `claude_lock`'s job and the caller's ordering problem. And
//! in W2 it has **no caller at all**, which is the point of landing it on its
//! own.
//!
//! [`Credentials::to_keychain_stdin_line`]: crate::provider::claude::credentials::Credentials::to_keychain_stdin_line
//! [`EnvView`]: crate::provider::claude::namespace::EnvView

#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the write path lands in W2 with no caller; W3 (refresh in place) and W4 (swap) call it"
    )
)]

use std::io;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;

use crate::config::AccountKind;
use crate::config::AccountRecord;
use crate::config::paths::Paths;
use crate::error::AppError;
use crate::provider::claude::credentials::KeychainStdinLine;
use crate::provider::claude::namespace::EnvView;
use crate::provider::claude::namespace::LIVE_SERVICE;
use crate::provider::claude::namespace::SECURESTORAGE_ENV;
use crate::provider::claude::namespace::live_store_dir;
use crate::provider::claude::namespace::service_name;
use crate::runtime::coordinator::PassCtx;
#[cfg(not(feature = "testing"))]
use crate::secret::SECURITY_BIN;
use crate::secret::StderrClass;
use crate::secret::classify_stderr;
use crate::secret::security_cli::EXIT_LOCKED;
use crate::secret::security_cli::EXIT_NOT_FOUND;

/// The longest line `security -i` accepts, **counting the trailing newline**
/// (fact F42).
///
/// Claude Code compares `<= 4032` against the whole line including the `\n`
/// and, when the line is longer, falls back to putting the hex in **argv**.
/// agentctl has no such fallback: a line one byte over the limit is
/// [`KeychainWriteError::LineTooLong`] and nothing is spawned (refusal D,
/// invariant I15).
pub const SECURITY_STDIN_LIMIT: usize = 4032;

/// The budget for the write itself (plan section 3.4's budget table).
///
/// Derived, not chosen: fact F53 says a peer's refresh acquire gives up after
/// 4 000 ms at the floor, so the whole hold is 3 000 ms, split 500 ms spawn
/// allowance + 800 ms re-read + 1 200 ms write + 500 ms lock syscalls. The
/// 1 500 ms that plan section 3.7 named predates the table; the table wins.
pub const WRITE_TIMEOUT: Duration = Duration::from_millis(1200);

/// The budget for the under-lock re-read that precedes a write (step 9).
///
/// Lives here rather than in [`crate::secret::security_cli`] because it is a
/// term of *this* transport's budget: the 2 000 ms read timeout that module
/// uses is the right number outside a hold and far too generous inside one.
pub const READ_TIMEOUT: Duration = Duration::from_millis(800);

/// The one argv `security` is ever given by this module (fact F42).
///
/// A constant rather than a literal at the call site so that
/// [`argv_shapes`] and the transport cannot drift apart — the gate's
/// argv-construction assertion (plan section 9.3) reads the former and the
/// child gets the latter.
const WRITE_ARGV: [&str; 1] = ["-i"];

/// The keychain item a write is allowed to change.
///
/// Private fields on purpose (invariant I1′): with no public constructor
/// taking a string, and no struct literal available outside this module, the
/// set of items agentctl can write is exactly the set the two constructors
/// below can name. `#[derive(Debug)]` is safe — a service name and a directory
/// are not secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteTarget {
    store_dir: PathBuf,
    service: String,
}

impl WriteTarget {
    /// The live item and the directory whose locks guard it, derived
    /// **together** from one [`EnvView`].
    ///
    /// One derivation for both halves is the whole point (risk R42, premortem
    /// PM17): reading the store directory from one environment view and the
    /// service name from another is how a swap ends up locking a namespace and
    /// writing the live item. [`live_store_dir`] and [`service_name`] are both
    /// applied to the value handed in here and nowhere else.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Refused`] when `CLAUDE_SECURESTORAGE_CONFIG_DIR`
    /// holds a non-empty value. That is refusal **E**: this shell has been
    /// pointed at a namespace, so "the live item" is not what the caller
    /// means. The refusal message belongs to W4b, but the derivation refuses
    /// from the day it lands so no earlier wave can reach the case by
    /// accident. An **empty** value is not refused: it is falsy to Claude
    /// Code, so it names the live item exactly as an unset variable would
    /// (fact F14).
    pub fn live(env: &EnvView) -> Result<Self, AppError> {
        if let Some(value) = env.securestorage_dir.as_deref()
            && !value.is_empty()
        {
            return Err(AppError::Refused {
                reason: format!(
                    "`{SECURESTORAGE_ENV}` is set to `{value}` in this shell, so the live keychain \
                     item is not the item this environment names; run without it, or target the \
                     namespace instead"
                ),
            });
        }
        Ok(Self { store_dir: live_store_dir(env), service: service_name(env) })
    }

    /// The namespaced item a Claude Code session migrated an agentctl
    /// namespace to (fact F35, decision D-015).
    pub fn migrated(sha8: OwnedSha8) -> Self {
        Self { store_dir: sha8.store_dir, service: format!("{LIVE_SERVICE}-{}", sha8.sha8) }
    }

    /// The directory whose lock artefacts guard this item.
    pub fn store_dir(&self) -> &Path {
        &self.store_dir
    }

    /// The keychain service name.
    pub fn service(&self) -> &str {
        &self.service
    }
}

/// The `sha8` of a namespace agentctl owns, and that namespace's directory.
///
/// One constructor, from a registry record, because an item agentctl did not
/// create must never be nameable as a write target (risk R40). Private fields
/// for the same reason [`WriteTarget`]'s are private.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedSha8 {
    sha8: String,
    store_dir: PathBuf,
}

impl OwnedSha8 {
    /// The `sha8` of an [`AccountKind::Owned`] record, or `None`.
    ///
    /// `None` for every other kind — `Live`, `ConfigDirReadOnly` and `Foreign`
    /// are read-only by decision D-001 and have no namespace agentctl
    /// refreshes — and also for a record whose stored `export_sha8` is not
    /// eight lowercase hex digits, or whose namespace directory does not spell
    /// a path under [`Paths::namespace_root`]. Both of those mean a registry
    /// that has been edited by hand or corrupted, and neither is a reason to
    /// go on and name some other keychain item.
    pub fn from_record(paths: &Paths, rec: &AccountRecord) -> Option<Self> {
        let AccountKind::Owned { export_sha8, .. } = &rec.kind else {
            return None;
        };
        if !is_sha8(export_sha8) {
            return None;
        }
        let store_dir = paths.namespace_dir(&rec.account_uuid, &rec.organization_uuid);
        if !paths.is_under_namespace_root(&store_dir) {
            return None;
        }
        Some(Self { sha8: export_sha8.clone(), store_dir })
    }

    /// The eight hex digits themselves.
    pub fn sha8(&self) -> &str {
        &self.sha8
    }
}

/// Whether `value` is the eight lowercase hex digits a service suffix is.
fn is_sha8(value: &str) -> bool {
    value.len() == 8 && value.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Why a keychain write did not happen.
///
/// The `security(1)` half mirrors [`KeychainError`](crate::secret::KeychainError)
/// so a write and a read classify a failure the same way — the ten classes of
/// fact F34 come through [`StderrClass`] unchanged. The three refusals above
/// them are this transport's own, and all three are decided **before** a child
/// exists.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeychainWriteError {
    /// The line exceeds [`SECURITY_STDIN_LIMIT`]. Nothing was spawned.
    #[error("the keychain line is {len} bytes, over the {limit}-byte `security -i` limit")]
    LineTooLong {
        /// The line's length, including its trailing newline.
        len: usize,
        /// [`SECURITY_STDIN_LIMIT`].
        limit: usize,
    },
    /// The line was built for a different item than the target being written.
    ///
    /// Not in the plan's enum, and added deliberately: the two parameters that
    /// name the item — `account` and the target's service — are otherwise
    /// unused by the transport, because the names travel *inside* the line. If
    /// they are allowed to disagree, agentctl writes one item and audits
    /// another, which is risk R42 arriving by a different road.
    #[error("this keychain line was built for `{found}`, not for `{expected}`")]
    TargetMismatch {
        /// The target's service name, or the account passed to the write.
        expected: String,
        /// What the line was built for.
        found: String,
    },
    /// An account or service name cannot be written into fact F42's quoted
    /// line without changing what the line means.
    #[error("the {field} name cannot be quoted into a `security -i` line")]
    Unquotable {
        /// `"account"` or `"service"`.
        field: &'static str,
    },
    /// `security(1)` could not be started at all.
    #[error("security could not be spawned: {0}")]
    Spawn(String),
    /// `security(1)` exceeded [`WRITE_TIMEOUT`] and was killed.
    #[error("security timed out after {0} ms")]
    Timeout(u64),
    /// The keychain is locked (exit status 36, fact F34).
    #[error("keychain locked")]
    Locked,
    /// `security(1)` exited non-zero with a classifiable message.
    #[error("security failed: {class:?}: {stderr}")]
    Failed {
        /// Which of the ten classes the message fell into.
        class: StderrClass,
        /// The message, trimmed.
        stderr: String,
    },
}

impl KeychainWriteError {
    /// Whether a later attempt might succeed where this one failed.
    ///
    /// The same rule [`KeychainError::is_transient`] applies — everything but
    /// a missing binary is transient — with the three pre-spawn refusals added
    /// as permanent, because an over-long line, a mismatched target and an
    /// unquotable name are all decisions about the request rather than about
    /// the machine, and none of them changes on a retry.
    ///
    /// Nothing in phase 2 retries a write automatically: this exists so the
    /// caller can say *whether* it is worth retrying, and so `doctor` can tell
    /// a locked keychain from a bug.
    ///
    /// [`KeychainError::is_transient`]: crate::secret::KeychainError::is_transient
    pub fn is_transient(&self) -> bool {
        match self {
            Self::LineTooLong { .. }
            | Self::TargetMismatch { .. }
            | Self::Unquotable { .. }
            | Self::Spawn(_) => false,
            Self::Timeout(_) | Self::Locked | Self::Failed { .. } => true,
        }
    }
}

/// Writes one keychain item through `security -i`.
///
/// `line` arrives already built and already newline-terminated, because the
/// only place it can be built is
/// [`Credentials::to_keychain_stdin_line`](crate::provider::claude::credentials::Credentials::to_keychain_stdin_line),
/// inside the crate's single credential exposure site. This function hands its
/// bytes to the child's stdin and drops it; it never sees the plaintext.
///
/// The child is registered with `ctx` before anything is written to it, so the
/// pass coordinator can kill it on `Ctrl-C` or at the deadline even while this
/// thread is blocked on a pipe — the same contract
/// [`security_cli`](crate::secret::security_cli) keeps.
///
/// # Errors
///
/// Returns [`KeychainWriteError`]. The three refusals — [`LineTooLong`],
/// [`TargetMismatch`] and [`Unquotable`] — are decided before a child exists,
/// so a caller that gets one of them knows the keychain was not touched.
///
/// [`LineTooLong`]: KeychainWriteError::LineTooLong
/// [`TargetMismatch`]: KeychainWriteError::TargetMismatch
/// [`Unquotable`]: KeychainWriteError::Unquotable
pub fn write_item(
    target: &WriteTarget,
    account: &str,
    line: KeychainStdinLine,
    ctx: &PassCtx,
) -> Result<(), KeychainWriteError> {
    write_item_through_inner(&security_bin()?, target, account, line, ctx)
}

/// [`write_item`] with the transport binary named — **a test seam, and
/// compiled only for tests.**
///
/// It exists so the unit tests can point the write at the fake `security`
/// without setting an environment variable: `std::env::set_var` is `unsafe` in
/// edition 2024 and would race every other test in this binary.
///
/// It is `cfg`-gated because in a release build it would be a way for any
/// future caller in this crate to hand fact F42's line — the hex-encoded blob,
/// which is to say both tokens — to the standard input of a program of its
/// choosing, bypassing [`security_bin`]'s "an absolute path, never resolved
/// through `PATH`" guarantee. Invariant I1′ is compile-time about *which item*
/// is written; this is what makes it compile-time about *which binary receives
/// the plaintext*.
///
/// # Errors
///
/// As [`write_item`].
#[cfg(any(test, feature = "testing"))]
pub fn write_item_through(
    bin: &Path,
    target: &WriteTarget,
    account: &str,
    line: KeychainStdinLine,
    ctx: &PassCtx,
) -> Result<(), KeychainWriteError> {
    write_item_through_inner(bin, target, account, line, ctx)
}

/// The whole write, with the binary already chosen.
///
/// Unexported: [`write_item`] is the only way in from production code, and it
/// resolves the binary itself.
///
/// # Errors
///
/// As [`write_item`].
fn write_item_through_inner(
    bin: &Path,
    target: &WriteTarget,
    account: &str,
    line: KeychainStdinLine,
    ctx: &PassCtx,
) -> Result<(), KeychainWriteError> {
    if line.account() != account {
        return Err(KeychainWriteError::TargetMismatch {
            expected: account.to_owned(),
            found: line.account().to_owned(),
        });
    }
    if line.service() != target.service() {
        return Err(KeychainWriteError::TargetMismatch {
            expected: target.service().to_owned(),
            found: line.service().to_owned(),
        });
    }
    // Checked again here, and not only where the line was built: this is the
    // last gate before a child exists, and plan AC59 asks for the guarantee
    // that an over-long line spawns nothing rather than for the guarantee that
    // one particular builder refuses first.
    let len = line.len();
    if len > SECURITY_STDIN_LIMIT {
        return Err(KeychainWriteError::LineTooLong { len, limit: SECURITY_STDIN_LIMIT });
    }

    let output = run_write(bin, &line, ctx)?;
    match output.code {
        Some(0) => Ok(()),
        Some(EXIT_LOCKED) => Err(KeychainWriteError::Locked),
        // For a *read*, status 44 means "no such item" and is a normal answer.
        // For a write it is a failure: `-U` creates an item that is not there,
        // so 44 means `security` refused to reach the item at all.
        Some(EXIT_NOT_FOUND) => Err(KeychainWriteError::Failed {
            class: StderrClass::ItemNotFound,
            stderr: output.stderr.trim().to_owned(),
        }),
        _ => Err(KeychainWriteError::Failed {
            class: classify_stderr(&output.stderr),
            stderr: output.stderr.trim().to_owned(),
        }),
    }
}

/// Fact F42's update line, with the three values filled in.
///
/// Built **here**, and called from the line builder in
/// [`credentials`](crate::provider::claude::credentials), for one reason that
/// is worth stating rather than rediscovering: the gate asserts that exactly
/// one non-test file under `src/` names the subcommand (plan section 9.3). The
/// secret half — turning the credential into `hex` — stays with the
/// credential, and the argv-shaped half stays with the transport.
///
/// `hex` is the lowercase hex of the blob. Nothing here is secret: this
/// function does not know what `hex` encodes, and the value it returns is
/// wrapped in a `SecretString` by its only caller.
///
/// `pub(crate)` rather than `pub`: it returns a bare `String` containing the
/// hex, and the crate has exactly one legitimate caller for it — the line
/// builder inside the single exposure site. It cannot reach [`write_item`],
/// which takes a `KeychainStdinLine`, but a caller could still build the string
/// and log it.
///
/// # Errors
///
/// Returns [`KeychainWriteError::Unquotable`] when a name would change what
/// the line means, and [`KeychainWriteError::LineTooLong`] when the finished
/// line — trailing newline included — exceeds [`SECURITY_STDIN_LIMIT`].
pub(crate) fn line_text(
    account: &str,
    service: &str,
    hex: &str,
) -> Result<String, KeychainWriteError> {
    quotable("account", account)?;
    quotable("service", service)?;
    let line = format!("add-generic-password -U -a \"{account}\" -s \"{service}\" -X \"{hex}\"\n");
    let len = line.len();
    if len > SECURITY_STDIN_LIMIT {
        return Err(KeychainWriteError::LineTooLong { len, limit: SECURITY_STDIN_LIMIT });
    }
    Ok(line)
}

/// Refuses a value that would change what fact F42's quoted line means.
///
/// `security -i` reads a *command line*, so a value carrying a quote, a
/// backslash or a newline could end the field early and append arguments of
/// its own — a second `-s`, or a second command. Neither name can carry one in
/// practice — the account is the `$USER` the matching read was issued with
/// (`crate::secret::current_account`, never an attribute read back out of a
/// `dump-keychain` listing, which any same-user process can choose), and the
/// service comes from a [`WriteTarget`], whose suffix is eight validated hex
/// digits — which is exactly why refusing costs nothing and closes the case
/// anyway.
fn quotable(field: &'static str, value: &str) -> Result<(), KeychainWriteError> {
    if value.chars().any(|c| c == '"' || c == '\\' || c.is_control()) {
        return Err(KeychainWriteError::Unquotable { field });
    }
    Ok(())
}

/// The argv arrays this module can hand to `security(1)`.
///
/// Read by the argv-construction assertion in plan section 9.3, which replaced
/// a text grep that tripped over the fake script. `security_cli` enumerates
/// its own three read shapes; between them the two lists are the complete set
/// of argv the crate builds.
///
/// `test` as well as `testing`, so the assertion runs in a plain unit-test
/// build too; neither spelling reaches a release artifact.
#[cfg(any(test, feature = "testing"))]
pub fn argv_shapes() -> Vec<Vec<&'static str>> {
    vec![WRITE_ARGV.to_vec()]
}

/// The `security(1)` binary this process should write through.
///
/// [`SECURITY_BIN`](crate::secret::SECURITY_BIN), an absolute path never
/// resolved through `PATH`. This is
/// the whole of the release build's answer; the `testing` build's is below and
/// is deliberately narrower, not wider.
#[cfg(not(feature = "testing"))]
fn security_bin() -> Result<PathBuf, KeychainWriteError> {
    Ok(PathBuf::from(SECURITY_BIN))
}

/// The `security(1)` a `testing` build may write through, or a refusal.
///
/// **Fails closed.** With `AGENTCTL_SECURITY_BIN` unset there is no stand-in
/// wired, and falling back to the real binary would let any test that reached
/// this path create an item in the developer's own login keychain — which is
/// exactly what happened once, from a unit test that made a migrated namespace
/// expired and had no idea it was one line away from a write. A `testing`
/// build has no business writing a real keychain under any circumstances, so
/// the absence of the seam is a refusal rather than a default.
///
/// The release build above has no such branch, and `scripts/release-gate.sh`
/// keeps the feature out of a shipped artifact.
#[cfg(feature = "testing")]
fn security_bin() -> Result<PathBuf, KeychainWriteError> {
    std::env::var_os(crate::secret::SECURITY_BIN_ENV).map(PathBuf::from).ok_or_else(|| {
        KeychainWriteError::Spawn(format!(
            "`{}` is unset in a `testing` build, so there is no write transport; \
             the real `security(1)` is deliberately not a fallback",
            crate::secret::SECURITY_BIN_ENV
        ))
    })
}

/// One completed `security -i` invocation.
struct RunOutput {
    /// The exit status, or `None` when the child died from a signal.
    code: Option<i32>,
    /// Standard error, as text.
    stderr: String,
}

/// Spawns `security -i`, hands it the line, and collects the result.
fn run_write(
    bin: &Path,
    line: &KeychainStdinLine,
    ctx: &PassCtx,
) -> Result<RunOutput, KeychainWriteError> {
    // `keychain_write_hang` (plan AC74): the write child never answers, so
    // the pass kills it at `WRITE_TIMEOUT` and the outcome of the write is
    // undetermined — the one path that produces `unknown` rather than
    // `failed`. Injected at the spawn site, before a child exists, rather
    // than by hanging a real one: a test that had to wait out the budget
    // would be waiting **inside a hold**, racing the very hold budget it is
    // there to observe, and the fake `security` is deliberately a faithful
    // `security(1)` with no stall knob. The caller sees exactly what a killed
    // child produces, which is what AC74 is about. Compiled out entirely
    // without the `testing` feature, so a release build has no such branch.
    #[cfg(feature = "testing")]
    if crate::runtime::fault::Fault::from_env().is("keychain_write_hang") {
        let budget_ms = u64::try_from(WRITE_TIMEOUT.as_millis()).unwrap_or(u64::MAX);
        return Err(KeychainWriteError::Timeout(budget_ms));
    }

    let mut child = Command::new(bin)
        .args(WRITE_ARGV)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| KeychainWriteError::Spawn(format!("{}: {err}", bin.display())))?;

    // Every pipe is taken before the handle is registered: from that moment
    // the coordinator may kill the process, and a half-taken pipe would be a
    // use-after-kill hazard.
    let mut stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let token = ctx.register_child(child);

    // Written on this thread rather than a helper thread, and safe to do so
    // for one measurable reason: the line is at most SECURITY_STDIN_LIMIT
    // bytes, which is under 4 KiB, and a pipe buffers at least 16 KiB before
    // it blocks a writer. A child that never reads its stdin therefore cannot
    // block this write. Dropping the pipe afterwards is what gives `security
    // -i` its end of input; without that it would wait for EOF until the
    // budget killed it.
    let handed = match stdin.as_mut() {
        Some(pipe) => line.write_to(pipe).and_then(|()| pipe.flush()),
        None => Err(io::Error::other("`security`'s standard input was not piped")),
    };
    drop(stdin);

    // Drained on threads because a child that fills one pipe while this side
    // reads the other deadlocks.
    let out_reader = std::thread::spawn(move || drain(stdout));
    let err_reader = std::thread::spawn(move || drain(stderr));

    let budget_ms = u64::try_from(WRITE_TIMEOUT.as_millis()).unwrap_or(u64::MAX);
    let status = match ctx.wait_child_timeout(token, WRITE_TIMEOUT) {
        Ok(Some(status)) => Some(status),
        // The budget expired, or the coordinator wound the pass down; either
        // way the child has been killed and reaped, and either way the write
        // may or may not have landed. The caller's audit entry says `unknown`.
        Ok(None) | Err(_) => None,
    };

    let Some(status) = status else {
        // The drain threads are deliberately not joined: killing a child does
        // not close a pipe a grandchild inherited, and waiting for that is the
        // unbounded wait this budget exists to prevent.
        return Err(KeychainWriteError::Timeout(budget_ms));
    };

    let _ = out_reader.join();
    let stderr = String::from_utf8_lossy(&err_reader.join().unwrap_or_default()).into_owned();

    // A child that never received its line can still exit 0 — `security -i`
    // reads commands until end of input and an empty input is not an error —
    // so a failed hand-off must not be reported as a successful write.
    if let Err(err) = handed {
        return Err(KeychainWriteError::Failed {
            class: StderrClass::Other,
            stderr: format!("the line could not be handed to `security`: {err}"),
        });
    }

    Ok(RunOutput { code: status.code(), stderr })
}

/// Reads a pipe to end-of-file, treating a read failure as no output.
fn drain<R: Read>(reader: Option<R>) -> Vec<u8> {
    let mut buffer = Vec::new();
    if let Some(mut reader) = reader {
        let _ = reader.read_to_end(&mut buffer);
    }
    buffer
}

#[cfg(test)]
#[path = "keychain_write_tests.rs"]
mod tests;
