//! A stand-in for `/usr/bin/security`, written to disk by tests.
//!
//! It lives in `src/` rather than in `tests/` because three different test
//! layers need the same script: this crate's unit tests, the end-to-end suite
//! in `tests/`, and the manual probes. One script means one behaviour to
//! reason about, and — more to the point — one argv log to assert against.
//! Plan AC25 requires that across the whole suite the only subcommands
//! agctl ever issues are `show-keychain-info`, `find-generic-password` and
//! `dump-keychain`; the script writes every invocation to
//! `AGCTL_FAKE_SECURITY_LOG`, which turns that requirement into a grep.
//!
//! The script is driven entirely by the environment, so one copy serves every
//! scenario:
//!
//! | variable | effect |
//! |----------|--------|
//! | `AGCTL_FAKE_SECURITY_LOG` | append one line per invocation |
//! | `AGCTL_FAKE_SECURITY_SLEEP` | sleep this many seconds first (the `security_hang` fault) |
//! | `AGCTL_FAKE_SECURITY_PREFLIGHT_EXIT` | exit status for `show-keychain-info` (36 = locked) |
//! | `AGCTL_FAKE_SECURITY_PREFLIGHT_STDERR` | stderr for `show-keychain-info` |
//! | `AGCTL_FAKE_SECURITY_DUMP` | file to print for `dump-keychain` |
//! | `AGCTL_FAKE_SECURITY_DUMP_EXIT` | exit status for `dump-keychain` |
//! | `AGCTL_FAKE_SECURITY_ITEMS` | directory of item files, laid out by [`item_path`] |
//! | `AGCTL_FAKE_SECURITY_FIND_EXIT` | force this exit status for `find-generic-password` |
//! | `AGCTL_FAKE_SECURITY_WRITE_EXIT` | force this exit status for the `-i` write path |
//! | `AGCTL_FAKE_SECURITY_STDERR` | stderr to print with a forced failure |
//!
//! Anything the script is not told about behaves like an empty keychain:
//! `find-generic-password` exits 44 with the real tool's not-found message.
//! Every subcommand it does not implement exits 1 — including, deliberately,
//! every mutating one but the single write transport below.
//!
//! # The write path (`-i`)
//!
//! Phase 2 gives the stand-in the one mutating transport agctl has: argv
//! `-i`, with the `add-generic-password -U` line on **stdin** (fact F42). It
//! reads exactly one line, refuses anything else without running it, and:
//!
//! - **logs the line with the hex redacted** — `-X <REDACTED:<digits>>` —
//!   because a stand-in that logged the payload would put a credential in
//!   every test's output (`agctl-pww`, closed here for the write path);
//! - **refuses a service the test did not register.** One service name per
//!   line in `<items>/.allowed-services` ([`ALLOWED_SERVICES`],
//!   [`allow_service`]); anything else exits 1 with a `security:`-shaped
//!   message. A write is the one operation where "the test forgot to say
//!   which item" must not silently succeed;
//! - **stores the decoded blob** at [`item_path`]`(<items>, <account>, <service>)`,
//!   the same file the read path serves, so a write followed by a read
//!   round-trips through the same bytes the transport put on the pipe — and a
//!   write whose `-a` names another account lands in a sibling file that no
//!   read of the original account will serve, which is what the shipped
//!   `security(1)` does with `-U` and a mismatched `-a`.
//!
//! The log line is written *before* the refusals, so an invocation counts as
//! an attempted write whether or not it landed — which is what plan AC61's
//! aggregate counts.

#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "remaining items are consumed by W2 (accounts, import, doctor) and W3 (watch)"
    )
)]

use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::path::PathBuf;

/// The script body. `sh`, not `bash`: nothing here needs more.
///
/// It lives in `fixtures/` rather than inline because the end-to-end suite
/// cannot reach into this crate — `agctl` is a binary with no library
/// target, so `tests/` has no way to call [`write_fake_security`]. A fixture
/// both sides `include_str!` keeps the argv log AC25 asserts against, and the
/// behaviour the unit tests assert against, one script rather than two.
const SCRIPT: &str = include_str!("../../fixtures/fake-security.sh");

/// Writes the stand-in into `dir` and returns its path.
///
/// The caller points `AGCTL_SECURITY_BIN` at the returned path.
///
/// # Errors
///
/// Returns the underlying [`io::Error`] when the script cannot be created.
pub fn write_fake_security(dir: &Path) -> io::Result<PathBuf> {
    use std::io::Write;

    let path = dir.join("security");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o755)
        .open(&path)?;
    file.write_all(SCRIPT.as_bytes())?;
    file.sync_all()?;
    Ok(path)
}

/// The file name the stand-in folds one account or service name to.
///
/// Both carry spaces, colons and `@` — `Claude Code-credentials`,
/// `claude-switcher:user@example.com` — so they are folded to a conservative
/// alphabet. The shell script performs the identical fold with `tr`, and the
/// two must be changed together.
pub fn item_file_name(service: &str) -> String {
    service
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '_' })
        .collect()
}

/// Where the stand-in keeps one item's password.
///
/// A generic password is identified by its **account and service together**,
/// which is what `find-generic-password -a … -s …` matches on and what
/// `add-generic-password -U` decides "already exists" by. Nesting the service
/// file under the account is the smallest layout that models that: a read with
/// the wrong `-a` finds nothing, and a write with the wrong `-a` creates a
/// sibling rather than updating the item that was read.
pub fn item_path(items_dir: &Path, account: &str, service: &str) -> PathBuf {
    items_dir.join(item_file_name(account)).join(item_file_name(service))
}

/// Writes one item's password into an items directory, under `account`.
///
/// # Errors
///
/// Returns the underlying [`io::Error`] when the file cannot be written.
pub fn write_item(
    items_dir: &Path,
    account: &str,
    service: &str,
    blob: &[u8],
) -> io::Result<PathBuf> {
    let path = item_path(items_dir, account, service);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, blob)?;
    Ok(path)
}

/// The file inside an items directory listing which services may be written.
pub const ALLOWED_SERVICES: &str = ".allowed-services";

/// Registers `service` as a legitimate write target for the stand-in.
///
/// Additive, one name per line: a test that means to write two items calls
/// this twice. Nothing else in the stand-in may be written, which is what
/// makes "agctl wrote an item nobody asked for" a failing test rather than
/// a silently created file.
///
/// # Errors
///
/// Returns the underlying [`io::Error`] when the list cannot be appended to.
pub fn allow_service(items_dir: &Path, service: &str) -> io::Result<PathBuf> {
    use std::io::Write;

    std::fs::create_dir_all(items_dir)?;
    let path = items_dir.join(ALLOWED_SERVICES);
    let mut file = std::fs::OpenOptions::new().append(true).create(true).open(&path)?;
    writeln!(file, "{service}")?;
    Ok(path)
}

#[cfg(test)]
#[path = "fake_security_tests.rs"]
mod tests;
