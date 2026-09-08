//! The per-account usage cache: `<cache_dir>/<acct>.<org>.<sha8>.json`.
//!
//! Two jobs, both from plan principle P4:
//!
//! - **Do not hammer an undocumented endpoint.** Inside [`TTL`] a repeated
//!   `status` answers from disk and makes no request at all.
//! - **Stale beats blank.** When a fetch fails — a 429, a dead network, a
//!   keychain that went away — the last good numbers are rendered with the
//!   row marked `stale` or `rate-limited`. A user who can see yesterday's 35 %
//!   next to a `rate-limited` badge is better served than one who sees an
//!   empty cell.
//!
//! # Why the *body* is cached, not the snapshot
//!
//! The entry stores the untouched response body and re-parses it on load,
//! rather than serializing [`UsageSnapshot`](crate::usage::model::UsageSnapshot).
//! That costs one JSON parse per cached row and buys three things: `--raw`
//! round-trips from the cache exactly as it does from the network; a build
//! that learns to read a new field (the `extra_usage` credits parser in W2)
//! immediately understands entries written by an older build; and the model
//! types need no `serde` derives, so nothing about the on-disk format leaks
//! into the vocabulary the renderer uses.
//!
//! The file is written the same way credentials are — a temporary file, then
//! a rename, mode 0600 — because it sits in the same store and a half-written
//! cache entry would be indistinguishable from a corrupt one. It holds no
//! token material (invariant I4); the mode is for consistency and because
//! usage figures are still the user's business alone.

use std::fs;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

use crate::config::paths::FILE_MODE;
use crate::config::paths::Paths;
use crate::secret::file_store::hex8;

/// How long a cached response is served without asking the API again.
pub const TTL: Duration = Duration::from_secs(300);

/// The format version of an entry. A file written by a future build with a
/// higher version is ignored rather than misread.
pub const ENTRY_VERSION: u32 = 1;

/// The largest cache file this build will read.
///
/// A usage body is a couple of kilobytes; the ceiling is here so a corrupt or
/// hostile file cannot make a `status` run allocate without bound.
pub const MAX_ENTRY_BYTES: u64 = 1 << 20;

/// One account's cached usage response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CacheEntry {
    /// The format version, [`ENTRY_VERSION`].
    pub version: u32,
    /// When the response was received, milliseconds since the epoch.
    pub fetched_at_ms: i64,
    /// When a `retry-after` the server sent expires, if it sent one.
    ///
    /// Persisted rather than kept in memory so that a *second* `status`
    /// invocation inside the window also declines to call (plan AC8: no retry
    /// within the window, not merely no retry within the pass).
    #[serde(default)]
    pub rate_limited_until_ms: Option<i64>,
    /// The untouched response body.
    pub body: Value,
}

impl CacheEntry {
    /// Builds an entry around a freshly received body.
    pub fn new(fetched_at_ms: i64, body: Value) -> Self {
        Self { version: ENTRY_VERSION, fetched_at_ms, rate_limited_until_ms: None, body }
    }

    /// Whether this entry may be served without asking the API.
    ///
    /// A clock that moved backwards makes the entry look like it was fetched
    /// in the future; that is treated as *not* fresh, so the run refetches
    /// rather than serving an entry it cannot date.
    pub fn is_fresh(&self, now_ms: i64, ttl: Duration) -> bool {
        let Ok(ttl_ms) = i64::try_from(ttl.as_millis()) else {
            return false;
        };
        let Some(age_ms) = now_ms.checked_sub(self.fetched_at_ms) else {
            return false;
        };
        (0..ttl_ms).contains(&age_ms)
    }

    /// How many seconds of a server-imposed rate limit are still to run.
    ///
    /// `None` means the account is free to call again.
    pub fn rate_limited_for(&self, now_ms: i64) -> Option<u64> {
        let until = self.rate_limited_until_ms?;
        let remaining_ms = until.checked_sub(now_ms)?;
        if remaining_ms <= 0 {
            return None;
        }
        // Round up, so a 500 ms remainder is reported as "1s to go" rather
        // than as "no wait left". `div_ceil` is stable for unsigned integers
        // only, which is why the conversion comes first — and it is
        // infallible here, the value having just been shown positive.
        u64::try_from(remaining_ms).ok().map(|millis| millis.div_ceil(1000))
    }
}

/// The cache file for one row.
///
/// `<acct>.<org>.<sha8>.json`, where the two identifiers are reduced to
/// characters that are safe in a file name and `sha8` is taken over the
/// untouched pair.
///
/// # Why this is not `validate_segment`
///
/// It used to be, and rows whose identifiers are not path segments therefore
/// had no cache at all: an `import --from keychain` record for an item that
/// named nobody is keyed by its *keychain service name*, which holds a space,
/// so every pass over such a row was a cache miss and a fresh request against
/// Anthropic — for a row agentctl cannot even refresh. Refusing to name a file
/// was the wrong answer to "this identifier has a space in it".
///
/// The digest is what makes the sanitized name safe rather than merely
/// pretty: two identifiers that sanitize to the same string still differ in
/// the digest, so no two rows can collide on one entry and read each other's
/// usage figures. The readable prefix is kept only so a human looking in the
/// cache directory can tell which file is whose.
pub fn path(paths: &Paths, acct: &str, org: &str) -> PathBuf {
    let digest = crate::provider::claude::namespace::sha8(&format!("{acct}/{org}"));
    paths.cache_dir().join(format!("{}.{}.{digest}.json", file_safe(acct), file_safe(org)))
}

/// The longest run of one identifier that reaches a cache file name.
///
/// Only the readable half is truncated; uniqueness lives in the digest. The
/// bound exists because two identifiers of unbounded length would otherwise
/// build a name longer than `NAME_MAX`, which is an error the caller could do
/// nothing about.
const MAX_NAME_PART: usize = 48;

/// One identifier, reduced to characters that are safe in a file name.
///
/// Anything outside `[A-Za-z0-9._-]` becomes `-`, which covers the separators
/// (`/`), the shell-significant characters, and the space a keychain service
/// name carries. An identifier that is empty, or that sanitizes to `.` or
/// `..`, becomes `_`: those three would otherwise build a name that either
/// hides the file or does not name a file at all.
fn file_safe(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .take(MAX_NAME_PART)
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '-' })
        .collect();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." { "_".to_owned() } else { cleaned }
}

/// Reads an entry, or `None` when there is nothing usable to read.
///
/// Every failure — absent, oversized, corrupt, a version from the future — is
/// `None`. A cache is an optimisation: refusing to run because one is
/// unreadable would turn a harmless stale file into an outage.
pub fn load(path: &Path) -> Option<CacheEntry> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_ENTRY_BYTES {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    let entry: CacheEntry = serde_json::from_slice(&bytes).ok()?;
    (entry.version == ENTRY_VERSION).then_some(entry)
}

/// Writes an entry atomically at mode 0600.
///
/// # Errors
///
/// Returns the underlying [`io::Error`]. Callers treat a cache write failure
/// as a warning: the numbers were still fetched and rendered.
pub fn store(path: &Path, entry: &CacheEntry) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "the cache path has no parent directory")
    })?;
    fs::create_dir_all(parent)?;

    let json = serde_json::to_vec(entry)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;

    let tmp = parent.join(format!(
        ".{}.tmp.{}",
        path.file_name().map_or_else(|| "usage".into(), |name| name.to_string_lossy()),
        hex8()
    ));

    // `create_new` so a stray temporary file from a crashed run is never
    // silently reused, and an explicit mode so the process umask cannot widen
    // it (the same rule the credential store follows).
    let write = (|| -> io::Result<()> {
        use std::io::Write;

        let mut file =
            fs::OpenOptions::new().write(true).create_new(true).mode(FILE_MODE).open(&tmp)?;
        file.write_all(&json)?;
        file.sync_all()
    })();

    if let Err(err) = write {
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }

    if let Err(err) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }

    // A pre-existing file keeps its own mode through a rename onto it only on
    // some filesystems, so the mode is asserted afterwards as well.
    fs::set_permissions(path, PermissionsExt::from_mode(FILE_MODE))
}

#[cfg(test)]
#[path = "cache_tests.rs"]
mod tests;
