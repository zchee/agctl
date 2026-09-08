//! The `security(1)` transport: bounded, read-only, and owned by the pass.
//!
//! Three rules shape this module, and all three come from the same worry —
//! that a keychain prompt nobody answers can hang a process forever:
//!
//! 1. **Every call is time-bounded.** 2 000 ms for a preflight or a read,
//!    10 000 ms for a dump (fact F34). A call that overruns is killed, and the
//!    result is [`KeychainError::Timeout`], which is transient. It is never a
//!    reason to fall back to the plaintext file (invariant I10): a keychain
//!    that is merely slow still holds the authoritative credentials, and
//!    reading the file instead is how two writers of one refresh chain
//!    happen.
//! 2. **Every child belongs to the pass.** The [`PassCtx`] owns the handle, so
//!    the coordinator's watchdog can kill it on `Ctrl-C` or at the deadline
//!    even while this module is blocked reading its pipes.
//! 3. **Only three subcommands are ever issued** — `show-keychain-info`,
//!    `find-generic-password` and `dump-keychain` — all of which read.
//!    Plan AC25 asserts exactly that over the whole end-to-end suite by
//!    logging the fake `security`'s argv.
//!
//! Secrets never appear in argv (invariant I8): the service *name* is an
//! argument, the password comes back on stdout.

#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "remaining items are consumed by W2 (accounts, import, doctor) and W3 (watch)"
    )
)]

use std::io::Read;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use crate::runtime::coordinator::PassCtx;
use crate::secret::KeychainError;
use crate::secret::KeychainReader;
use crate::secret::KeychainStatus;
use crate::secret::ServiceEntry;
use crate::secret::classify_stderr;

/// The budget for `show-keychain-info` and `find-generic-password`.
pub const READ_TIMEOUT: Duration = Duration::from_millis(2000);

/// The budget for `dump-keychain`, which walks every item.
pub const DUMP_TIMEOUT: Duration = Duration::from_millis(10_000);

/// `security(1)`'s exit status for a locked keychain (fact F34).
pub const EXIT_LOCKED: i32 = 36;

/// `security(1)`'s exit status for "no such item" (fact F34).
pub const EXIT_NOT_FOUND: i32 = 44;

/// A [`KeychainReader`] backed by the `security(1)` command-line tool.
#[derive(Debug)]
pub struct SecurityCli {
    bin: PathBuf,
    account: String,
    ctx: PassCtx,
    /// The parsed `dump-keychain` output, kept for this reader's lifetime.
    ///
    /// One pass builds one reader, and a pass asks for more than one service
    /// prefix — the Claude Code items and the `claude-switcher:` items are
    /// separate questions with the same answer source. Running a ten-second
    /// dump twice to answer them would be the only cost of not caching. The
    /// cache holds attributes only; no password material passes through it.
    dump: Mutex<Option<Arc<Vec<ServiceEntry>>>>,
}

impl SecurityCli {
    /// Builds a reader.
    ///
    /// `ctx` is cloned into the reader so every child it spawns is registered
    /// with the pass that created it. The contract sketch for this
    /// constructor took two arguments; a third is unavoidable, because
    /// [`KeychainReader`]'s methods take only `&self` and the child still has
    /// to reach the coordinator.
    pub fn new(bin: PathBuf, account: String, ctx: PassCtx) -> Self {
        Self { bin, account, ctx, dump: Mutex::new(None) }
    }

    /// Runs one `security` subcommand and collects its output.
    fn run(&self, args: &[&str], budget: Duration) -> Result<RunOutput, KeychainError> {
        let mut child = Command::new(&self.bin)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| KeychainError::Spawn(format!("{}: {err}", self.bin.display())))?;

        // Both pipes are taken before the handle is registered: from that
        // moment the coordinator may kill the process at any time, and a
        // half-taken pipe would be a use-after-kill hazard.
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let token = self.ctx.register_child(child);

        // Drained on threads because a child that fills one pipe while this
        // side reads the other deadlocks. When the coordinator or the budget
        // kills the child, both pipes reach EOF and both threads finish.
        let out_reader = std::thread::spawn(move || drain(stdout));
        let err_reader = std::thread::spawn(move || drain(stderr));

        let budget_ms = u64::try_from(budget.as_millis()).unwrap_or(u64::MAX);
        let status = match self.ctx.wait_child_timeout(token, budget) {
            Ok(Some(status)) => Some(status),
            // The budget expired and the child has been killed and reaped.
            Ok(None) => None,
            // The coordinator killed it first: the pass is being wound down.
            // Reported as a timeout because it is transient in exactly the
            // same way, and because `KeychainError` deliberately has no
            // cancellation variant to tempt a caller into retrying.
            Err(_) => None,
        };

        let Some(status) = status else {
            // Deliberately *not* joining the drain threads here. Killing a
            // child does not close a pipe its own children inherited, so a
            // process that forked before dying leaves the read end open until
            // the grandchild exits — and waiting for that is exactly the
            // unbounded wait this budget exists to prevent. (Measured: a
            // stand-in that shells out to `sleep 30` held the pipes for the
            // full thirty seconds after its shell was killed.) The threads
            // are detached; each ends when its pipe finally closes, and the
            // output is not wanted on this path anyway.
            return Err(KeychainError::Timeout(budget_ms));
        };

        // The child has exited, so its pipes are closed and these joins are
        // bounded by however long it takes to drain what is already buffered.
        let stdout = out_reader.join().unwrap_or_default();
        let stderr = err_reader.join().unwrap_or_default();

        Ok(RunOutput {
            code: status.code(),
            stdout,
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        })
    }
}

/// One completed `security` invocation.
struct RunOutput {
    /// The exit status, or `None` when the child died from a signal.
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: String,
}

impl RunOutput {
    /// Turns a non-zero exit into the classified error it stands for.
    fn failure(&self) -> KeychainError {
        if self.code == Some(EXIT_LOCKED) {
            return KeychainError::Locked;
        }
        let class = classify_stderr(&self.stderr);
        KeychainError::Failed { class, stderr: self.stderr.trim().to_owned() }
    }
}

/// Reads a pipe to end-of-file, treating a read failure as no output.
fn drain<R: Read>(reader: Option<R>) -> Vec<u8> {
    let mut buffer = Vec::new();
    if let Some(mut reader) = reader {
        let _ = reader.read_to_end(&mut buffer);
    }
    buffer
}

impl KeychainReader for SecurityCli {
    fn preflight(&self) -> KeychainStatus {
        match self.run(&["show-keychain-info"], READ_TIMEOUT) {
            Ok(output) if output.code == Some(0) => KeychainStatus::Unlocked,
            Ok(output) if output.code == Some(EXIT_LOCKED) => KeychainStatus::Locked,
            Ok(output) => match classify_stderr(&output.stderr) {
                crate::secret::StderrClass::KeychainLocked => KeychainStatus::Locked,
                other => {
                    KeychainStatus::Unavailable(format!("{other:?}: {}", output.stderr.trim()))
                }
            },
            Err(KeychainError::Timeout(_)) => KeychainStatus::Timeout,
            Err(err) => KeychainStatus::Unavailable(err.to_string()),
        }
    }

    fn list_services(&self, prefix: &str) -> Result<Vec<ServiceEntry>, KeychainError> {
        let cached = {
            let guard = lock(&self.dump);
            guard.clone()
        };
        let entries = match cached {
            Some(entries) => entries,
            None => {
                let output = self.run(&["dump-keychain"], DUMP_TIMEOUT)?;
                if output.code != Some(0) {
                    return Err(output.failure());
                }
                let parsed = Arc::new(parse_dump(&String::from_utf8_lossy(&output.stdout)));
                *lock(&self.dump) = Some(Arc::clone(&parsed));
                parsed
            }
        };

        Ok(entries.iter().filter(|entry| entry.service.starts_with(prefix)).cloned().collect())
    }

    fn read(&self, service: &str) -> Result<Option<Vec<u8>>, KeychainError> {
        let args = ["find-generic-password", "-a", self.account.as_str(), "-w", "-s", service];
        let output = self.run(&args, READ_TIMEOUT)?;
        match output.code {
            Some(0) => Ok(Some(trim_trailing_newline(output.stdout))),
            Some(EXIT_NOT_FOUND) => Ok(None),
            _ => Err(output.failure()),
        }
    }
}

/// Locks a mutex, recovering from poisoning.
///
/// The cache holds plain data with no invariant a panic could break, and
/// refusing to read the keychain because an unrelated thread panicked would
/// be strictly worse than proceeding.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Drops the single trailing newline `security -w` prints after a password.
fn trim_trailing_newline(mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    bytes
}

/// Parses `security dump-keychain` output into one entry per item.
///
/// The format is a run of records, each introduced by a `class:` line and
/// followed by an `attributes:` block of `"key"<type>=value` lines. Only four
/// attributes are kept — service, account and the two timestamps — and every
/// value is optional, because `security` prints `<NULL>` for anything unset.
///
/// Items without a service name are dropped: they cannot be Claude Code
/// credentials, and carrying them would mean holding every generic-password
/// label on the machine in memory for no reason.
pub fn parse_dump(text: &str) -> Vec<ServiceEntry> {
    let mut entries = Vec::new();
    let mut current = PartialEntry::default();

    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("class:") || trimmed.starts_with("keychain:") {
            current.flush_into(&mut entries);
            continue;
        }
        if let Some(value) = attribute(trimmed, "svce") {
            current.service = Some(value);
        } else if let Some(value) = attribute(trimmed, "acct") {
            current.account = Some(value);
        } else if let Some(value) = attribute(trimmed, "cdat") {
            current.cdat = Some(value);
        } else if let Some(value) = attribute(trimmed, "mdat") {
            current.mdat = Some(value);
        }
    }
    current.flush_into(&mut entries);
    entries
}

/// An item being assembled from consecutive attribute lines.
#[derive(Debug, Default)]
struct PartialEntry {
    service: Option<String>,
    account: Option<String>,
    cdat: Option<String>,
    mdat: Option<String>,
}

impl PartialEntry {
    fn flush_into(&mut self, entries: &mut Vec<ServiceEntry>) {
        let taken = std::mem::take(self);
        if let Some(service) = taken.service {
            entries.push(ServiceEntry {
                service,
                account: taken.account,
                cdat: taken.cdat,
                mdat: taken.mdat,
            });
        }
    }
}

/// Extracts the printable value of one attribute line.
///
/// `security` writes a value three ways: quoted (`"x"`), as `<NULL>`, or as
/// hex followed by the quoted printable form (`0x6162  "ab"`). Taking the
/// text between the first and last quote on the line handles all three,
/// because the hex form always ends with the quoted rendering.
fn attribute(line: &str, key: &str) -> Option<String> {
    let marker = format!("\"{key}\"<");
    let rest = line.strip_prefix(&marker)?;
    let value = rest.split_once('=').map(|(_, value)| value)?;
    let open = value.find('"')?;
    let close = value.rfind('"')?;
    if close <= open {
        return None;
    }
    let raw = value.get(open + 1..close)?;
    // `security` terminates C strings inside the quoted rendering.
    Some(raw.trim_end_matches("\\000").to_owned())
}

#[cfg(test)]
#[path = "security_cli_tests.rs"]
mod tests;
