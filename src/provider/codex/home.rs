//! Where a Codex home is, how it stores credentials, and whether a Codex
//! process is using it.
//!
//! # No process environment here
//!
//! [`codex_home`] resolves `CODEX_HOME` from a [`CodexEnv`] its caller built,
//! never from the process. The one constructor that reads the process lives
//! with command dispatch (plan section 3.1, invariant I25), so every rule in
//! this file is tested in-process with values the test chose, and no test can
//! end up reading the developer's own `~/.codex`. `scripts/phase3-greps.sh`
//! fails the build if this file ever names the environment module.
//!
//! # `config.toml` is a plaintext path
//!
//! A Codex `config.toml` routinely holds MCP server keys (fact F72), and a
//! TOML parser's error message quotes the line it stopped on. [`store_mode`]
//! and [`base_url`] therefore take the two keys they need out of the parsed
//! table, drop the table, and report a parse failure as
//! [`ConfigNote::Unparseable`] with a line number and nothing else — the
//! error's text is never formatted (invariant I31, plan AC116). This file is
//! the only one that names the parser.
//!
//! # A Codex session nearby
//!
//! [`daemon_evidence`] looks for Codex's shared app-server daemon in a home
//! (facts F72, F83) without taking part in any of its locks: it never opens
//! `daemon.lock`, and reads both spellings of the pid record through
//! [`open_readonly_nofollow`], whose flags cannot create or write.

use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::path::PathBuf;

use jiff::SignedDuration;
use jiff::Timestamp;
use rustix::fs::Mode;
use rustix::fs::OFlags;
use serde::Deserialize;
use sha2::Digest;
use sha2::Sha256;

use crate::runtime::coordinator::Cancel;
use crate::runtime::proc;

/// The environment variable Codex resolves its home from (fact F60).
///
/// The only spelling of the name in `src/`; `scripts/phase3-greps.sh` pins
/// that.
pub const CODEX_HOME_ENV: &str = "CODEX_HOME";

/// The configuration file inside a Codex home.
const CONFIG_FILE: &str = "config.toml";

/// The daemon directory inside a Codex home (fact F83).
const DAEMON_DIR: &str = "app-server-daemon";

/// The daemon's pid record, under either of the two names Codex gives it
/// (fact F83, re-checked at 0.155.0-alpha.12).
///
/// The name is conditional upstream: `app-server.pid` while the managed codex
/// binary lives under `<CODEX_HOME>/packages/standalone`, and `daemon.pid`
/// otherwise (`app-server-daemon/src/lib.rs:43-49`, selected at `:316-330` and
/// `:354-356`). agctl cannot see which branch a host is on without reading the
/// daemon's own state, and it does not need to: it reads both and takes the
/// strongest evidence, so a live daemon stops a refresh under either name.
/// Reading one name only was a **fail-open** gap — a live daemon writing the
/// other name read as `ArtefactOnly`, which the refresh gate passes with a note
/// (deviation D32).
const DAEMON_PID_FILES: [&str; 2] = ["app-server.pid", "daemon.pid"];

/// The largest `config.toml` this module will parse.
const MAX_CONFIG_BYTES: u64 = 1 << 20;

/// The largest pid record this module will read.
const MAX_PID_RECORD_BYTES: u64 = 64 * 1024;

/// How much later than its pid file a process may have started and still be
/// the process the file names (decision D-032).
const RECYCLE_TOLERANCE: SignedDuration = SignedDuration::from_secs(1);

/// The flags [`open_readonly_nofollow`] opens with.
///
/// Read-only, no link at the final component, closed on exec, and
/// non-blocking so a FIFO planted at the path cannot stall a pass. No create,
/// no write, no truncate: plan AC93 asserts that on this value.
pub const READONLY_NOFOLLOW: OFlags =
    OFlags::RDONLY.union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC).union(OFlags::NONBLOCK);

/// The two inputs a Codex home is resolved from.
///
/// Built by command dispatch from the process, and by tests from literals.
/// Deliberately has no constructor here that reads the environment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CodexEnv {
    /// `CODEX_HOME`, when set.
    codex_home: Option<OsString>,
    /// The user's home directory, when it could be determined.
    home: Option<PathBuf>,
}

impl CodexEnv {
    /// An environment with these two values.
    pub fn new(codex_home: Option<OsString>, home: Option<PathBuf>) -> Self {
        Self { codex_home, home }
    }
}

/// Why a Codex home could not be resolved (fact F86).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HomeError {
    /// `CODEX_HOME` names a path that does not exist.
    #[error(
        "codex home unreadable: {CODEX_HOME_ENV} points to `{0}`, but that path does not exist"
    )]
    Missing(PathBuf),
    /// `CODEX_HOME` names something that is not a directory.
    #[error(
        "codex home unreadable: {CODEX_HOME_ENV} points to `{0}`, but that path is not a directory"
    )]
    NotDirectory(PathBuf),
    /// Any other failure to stat or canonicalize it.
    #[error("codex home unreadable: could not read {CODEX_HOME_ENV} `{path}`: {reason}")]
    Unreadable {
        /// The path as set.
        path: PathBuf,
        /// The operating system's reason.
        reason: String,
    },
    /// `CODEX_HOME` is unset and there is no home directory to default under.
    #[error("codex home unreadable: {CODEX_HOME_ENV} is unset and the home directory is unknown")]
    NoHomeDirectory,
}

/// Resolves the Codex home the way Codex does (facts F60, F86).
///
/// A non-empty `CODEX_HOME` must exist and be a directory, and is
/// canonicalized. Unset or empty, the home is `$HOME/.codex`, **not**
/// canonicalized: Codex follows a symlinked `~/.codex` on every access, and so
/// does agctl.
///
/// # Errors
///
/// [`HomeError`], which a row shows as `codex home unreadable: …`.
pub fn codex_home(env: &CodexEnv) -> Result<PathBuf, HomeError> {
    match env.codex_home.as_ref().filter(|value| !value.is_empty()) {
        Some(value) => {
            let path = PathBuf::from(value);
            let meta = std::fs::metadata(&path).map_err(|err| match err.kind() {
                io::ErrorKind::NotFound => HomeError::Missing(path.clone()),
                _ => HomeError::Unreadable { path: path.clone(), reason: err.kind().to_string() },
            })?;
            if !meta.is_dir() {
                return Err(HomeError::NotDirectory(path));
            }
            path.canonicalize()
                .map_err(|err| HomeError::Unreadable { path, reason: err.kind().to_string() })
        }
        None => env.home.as_ref().map(|home| home.join(".codex")).ok_or(HomeError::NoHomeDirectory),
    }
}

/// Where a Codex home keeps its CLI credentials (fact F62).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreMode {
    /// `auth.json` — the default, and the mode when the key is absent.
    File,
    /// The OS keychain only.
    Keyring,
    /// The keychain when it has an item, otherwise `auth.json` (fact F94).
    Auto,
    /// In memory, in one process. Nothing on disk to read.
    Ephemeral,
    /// A value this build does not know, sanitized for display.
    Unknown(String),
}

impl StoreMode {
    /// The mode as the configuration spells it.
    pub fn label(&self) -> &str {
        match self {
            Self::File => "file",
            Self::Keyring => "keyring",
            Self::Auto => "auto",
            Self::Ephemeral => "ephemeral",
            Self::Unknown(value) => value,
        }
    }
}

/// Something `config.toml` said that is worth a note, without its text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigNote {
    /// The file is not TOML. `line` is where the parser stopped, when it said.
    ///
    /// Only a number: the parser's message can quote the offending line, and
    /// that line can hold a key (risk R61).
    Unparseable {
        /// 1-based line of the error, when the parser reported a position.
        line: Option<usize>,
    },
    /// The file exists and could not be read.
    Unreadable,
}

/// The two keys agctl reads from `config.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CodexConfig {
    store: StoreMode,
    base_url: Option<String>,
}

impl Default for CodexConfig {
    fn default() -> Self {
        Self { store: StoreMode::File, base_url: None }
    }
}

/// The credential store mode a home is configured with (fact F62).
///
/// Only the base `config.toml` is consulted: a profile cannot set this key
/// (fact F84), and the layers outside the home (fact F95) are `doctor`'s to
/// mention. A missing file or key is [`StoreMode::File`]. An unparseable or
/// unreadable file is also [`StoreMode::File`] with a note — Codex itself will
/// not start over such a file, and reading `auth.json` changes nothing.
pub fn store_mode(home: &Path) -> (StoreMode, Option<ConfigNote>) {
    let (config, note) = load_config(home);
    (config.store, note)
}

/// `chatgpt_base_url` from `config.toml`, when it is a plain `http(s)` URL.
///
/// A URL carrying a user name or password is not returned: it would put a
/// credential into every row that names the endpoint.
pub fn base_url(home: &Path) -> Option<String> {
    load_config(home).0.base_url
}

/// Reads and parses `config.toml`, keeping two keys.
fn load_config(home: &Path) -> (CodexConfig, Option<ConfigNote>) {
    let text = match read_config(&home.join(CONFIG_FILE)) {
        Ok(Some(text)) => text,
        Ok(None) => return (CodexConfig::default(), None),
        Err(note) => return (CodexConfig::default(), Some(note)),
    };
    parse_config(&text)
}

/// Extracts the two keys from a `config.toml` document.
///
/// The parsed table is dropped before this returns, and a parse error is
/// reduced to its line before anything else can see it.
fn parse_config(text: &str) -> (CodexConfig, Option<ConfigNote>) {
    let table = match toml::de::DeTable::parse(text) {
        Ok(table) => table,
        Err(err) => {
            let line = err.span().map(|span| line_of(text, span.start));
            return (CodexConfig::default(), Some(ConfigNote::Unparseable { line }));
        }
    };
    let mut config = CodexConfig::default();
    for (key, value) in table.get_ref().iter() {
        let toml::de::DeValue::String(value) = value.get_ref() else {
            if key.get_ref().as_ref() == "cli_auth_credentials_store" {
                config.store = StoreMode::Unknown(UNRECOGNISED.to_owned());
            }
            continue;
        };
        match key.get_ref().as_ref() {
            "cli_auth_credentials_store" => config.store = mode_from(value),
            "chatgpt_base_url" => config.base_url = plain_url(value),
            _ => {}
        }
    }
    (config, None)
}

/// How an unrecognised store value is shown when it is not safe to echo.
const UNRECOGNISED: &str = "<unrecognised>";

/// The store mode a configuration value names.
fn mode_from(value: &str) -> StoreMode {
    match value {
        "file" => StoreMode::File,
        "keyring" => StoreMode::Keyring,
        "auto" => StoreMode::Auto,
        "ephemeral" => StoreMode::Ephemeral,
        other => {
            let shown = other.len() <= 32
                && other.chars().all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_' | '-'));
            StoreMode::Unknown(if shown { other.to_owned() } else { UNRECOGNISED.to_owned() })
        }
    }
}

/// `value` when it is an `http(s)` URL without credentials in it.
fn plain_url(value: &str) -> Option<String> {
    let url = url::Url::parse(value).ok()?;
    let plain = matches!(url.scheme(), "https" | "http")
        && url.username().is_empty()
        && url.password().is_none();
    plain.then(|| url.as_str().to_owned())
}

/// The 1-based line containing byte `offset` of `text`.
fn line_of(text: &str, offset: usize) -> usize {
    let end = offset.min(text.len());
    text.as_bytes()[..end].iter().filter(|&&b| b == b'\n').count().saturating_add(1)
}

/// Reads `config.toml`: `Ok(None)` when absent, a note when unusable.
///
/// Follows a symlinked file — dotfile managers link it, and this is a read of
/// a file Codex itself follows — but opens non-blocking and refuses anything
/// that is not a regular file of a sane size.
fn read_config(path: &Path) -> Result<Option<String>, ConfigNote> {
    let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let fd = match rustix::fs::open(path, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(errno) if errno == rustix::io::Errno::NOENT => return Ok(None),
        Err(_) => return Err(ConfigNote::Unreadable),
    };
    let mut file = File::from(fd);
    let meta = file.metadata().map_err(|_| ConfigNote::Unreadable)?;
    if !meta.is_file() || meta.len() > MAX_CONFIG_BYTES {
        return Err(ConfigNote::Unreadable);
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_CONFIG_BYTES)
        .read_to_end(&mut bytes)
        .map_err(|_| ConfigNote::Unreadable)?;
    String::from_utf8(bytes).map(Some).map_err(|_| ConfigNote::Unparseable { line: None })
}

/// The keychain item service Codex stores a home's credentials under (fact
/// F94). Compared against a read-only listing, never passed to a writer.
pub const KEYRING_SERVICE: &str = "Codex Auth";

/// The keychain item account Codex uses for a home (fact F94):
/// `cli|<first 16 hex digits of sha256(canonical home)>`.
///
/// Canonicalized when the directory exists; the raw spelling otherwise. A
/// listing that has no account column cannot be matched against this, which
/// `doctor` reports as a coarse match (plan section 3.3).
pub fn keyring_account(home: &Path) -> String {
    let canonical = home.canonicalize().unwrap_or_else(|_| home.to_path_buf());
    let digest = hex::encode(Sha256::digest(canonical.to_string_lossy().as_bytes()));
    format!("cli|{}", &digest[..16])
}

/// What the read-only keychain listing said about a home's item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyringProbe {
    /// A `Codex Auth` item for this home is listed.
    ItemPresent,
    /// No such item is listed.
    NoItem,
    /// The listing could not be taken.
    Unknown,
}

/// Whether a home's `auth.json` is the credential Codex is using.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileInEffect {
    /// Read `auth.json`. `note` is `auto (file in effect)` under `auto`.
    Read {
        /// A note for the row, when the mode makes the answer worth stating.
        note: Option<&'static str>,
    },
    /// Do not read it: the credential is elsewhere, or nowhere on disk.
    NotRead(StoreMode),
}

/// Decides whether `auth.json` is read for a home in `mode`.
///
/// `probe` is the keychain listing and is consulted **only** under `auto`, the
/// one mode whose answer depends on it. Fact F94 inverts the plan's first
/// reading of `auto`: Codex loads the keychain first and falls back to the
/// file both when there is no item and when the keychain errors, so under
/// `auto` the file is in effect unless an item is listed. The same fact says
/// Codex's next keychain save deletes the file, so a caller must treat it as
/// able to vanish between this answer and the read.
pub fn file_in_effect(mode: &StoreMode, probe: impl FnOnce() -> KeyringProbe) -> FileInEffect {
    match mode {
        StoreMode::File => FileInEffect::Read { note: None },
        StoreMode::Auto => match probe() {
            KeyringProbe::ItemPresent => FileInEffect::NotRead(StoreMode::Auto),
            KeyringProbe::NoItem | KeyringProbe::Unknown => {
                FileInEffect::Read { note: Some("auto (file in effect)") }
            }
        },
        other @ (StoreMode::Keyring | StoreMode::Ephemeral | StoreMode::Unknown(_)) => {
            FileInEffect::NotRead(other.clone())
        }
    }
}

/// Opens `path` read-only, refusing a symbolic link at the final component.
///
/// The directories above may be links (fact F60); the file may not.
///
/// # Errors
///
/// The underlying [`io::Error`]; a link arrives as `ELOOP` (or `EMLINK`).
pub fn open_readonly_nofollow(path: &Path) -> io::Result<File> {
    rustix::fs::open(path, READONLY_NOFOLLOW, Mode::empty())
        .map(File::from)
        .map_err(|errno| io::Error::from_raw_os_error(errno.raw_os_error()))
}

/// What a home says about a Codex daemon using it (decision D-032).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonEvidence {
    /// No daemon directory.
    None,
    /// The pid record names a live process that started no later than the
    /// record was written.
    PidAlive(u32),
    /// The pid record names a live process that started after the record was
    /// written: a recycled id, not the daemon.
    Recycled(u32),
    /// A daemon directory, lock or record, with no live process behind it.
    ArtefactOnly,
    /// A pid record exists in the daemon directory and cannot be read, is not
    /// a regular file, or does not parse. Codex publishes the record under its
    /// own reservation lock (fact F83), so this is "a daemon may be starting",
    /// not "no daemon": a refresh sends nothing this pass (review S30 F8).
    RecordUnreadable,
}

/// Codex's daemon pid record (fact F83), under either spelling.
///
/// Only `pid` decides anything, and members this type does not name are
/// ignored: `serde` tolerates them by default, so upstream's `processIdentity`
/// (added at 0.155.0-alpha.12, and spelled `linuxProcessIdentity` on Linux)
/// needs no field here to keep the record parsing. Modelling a member nothing
/// compares would be dead code pretending to be a pin — review S33-C3b F1
/// showed the field survived being deleted with the suite still green. The start time Codex recorded is compared by
/// `mtime` instead, because its spelling is not settled (fact F83, open row);
/// the executable digest is not needed once a recycled id is caught by time.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PidRecord {
    pid: u32,
    #[cfg_attr(
        test,
        expect(dead_code, reason = "parsed to pin the record's shape (F83); never compared")
    )]
    process_start_time: Option<serde_json::Value>,
    #[cfg_attr(
        test,
        expect(dead_code, reason = "parsed to pin the record's shape (F83); never compared")
    )]
    executable_identity: Option<ExecutableIdentity>,
}

/// The executable fingerprint inside a [`PidRecord`].
#[derive(Debug, Deserialize)]
struct ExecutableIdentity {
    #[cfg_attr(
        test,
        expect(dead_code, reason = "parsed to pin the record's shape (F83); never compared")
    )]
    digest: String,
}

/// Looks for Codex's daemon in the home at `dir`, without contending for any
/// of its locks.
///
/// `daemon.lock` is never opened, `flock`ed or even named: the directory's
/// existence is established by `lstat` (invariant I21, plan AC93), and the pid
/// record is read through [`open_readonly_nofollow`]. A record whose process is
/// alive and started more than a second after the record was last modified is
/// [`DaemonEvidence::Recycled`]; alive otherwise is
/// [`DaemonEvidence::PidAlive`]. A process whose start time cannot be read
/// counts as alive — the conservative answer, since it stops a refresh. A
/// record that is there and cannot be used is
/// [`DaemonEvidence::RecordUnreadable`]; a dead process, or a daemon directory
/// with no record at all, is [`DaemonEvidence::ArtefactOnly`].
pub fn daemon_evidence(dir: &Path, cancel: &Cancel) -> DaemonEvidence {
    let daemon = dir.join(DAEMON_DIR);
    match std::fs::symlink_metadata(&daemon) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => return DaemonEvidence::ArtefactOnly,
        Err(_) => return DaemonEvidence::None,
    }
    DAEMON_PID_FILES
        .iter()
        .map(|name| one_record(&daemon.join(name), cancel))
        .reduce(stronger)
        .map_or(DaemonEvidence::ArtefactOnly, |(evidence, _)| evidence)
}

/// What one pid record says, whichever name it is under, and when that record
/// was last written — the tiebreak when both names name a live process.
fn one_record(record: &Path, cancel: &Cancel) -> (DaemonEvidence, Option<Timestamp>) {
    let Some((pid, written)) = read_pid_record(record) else {
        // `daemon.lock` alone is only an artefact; the lock itself is never
        // opened, so it is never named here either. A record that is there
        // and cannot be used may be one being published (review S30 F8).
        let evidence = match std::fs::symlink_metadata(record) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => DaemonEvidence::ArtefactOnly,
            _ => DaemonEvidence::RecordUnreadable,
        };
        return (evidence, None);
    };
    if pid == 0 || !proc::exists(pid) {
        return (DaemonEvidence::ArtefactOnly, Some(written));
    }
    (classify_live(pid, proc::start_timestamp(pid, cancel), written), Some(written))
}

/// The evidence that stops more: a live daemon outranks a record that cannot
/// be read, which outranks a recycled id, which outranks a bare artefact.
///
/// Both names can exist at once — an upgrade migrates a host from one to the
/// other (`migration.rs:35,85,140`), and nothing cleans the old record up — so
/// two answers have to become one, and the safe direction is the one that
/// sends less. **Equal verdicts are broken toward the record written last**,
/// so a migrated host naming two live pids reports the daemon whose record is
/// current rather than the leftover one (review S33-C3b F3). The array order
/// is not a tiebreak: which name is current depends on the host, and the mtime
/// does not.
fn stronger(
    left: (DaemonEvidence, Option<Timestamp>),
    right: (DaemonEvidence, Option<Timestamp>),
) -> (DaemonEvidence, Option<Timestamp>) {
    let rank = |evidence: &DaemonEvidence| match evidence {
        DaemonEvidence::PidAlive(_) => 4,
        DaemonEvidence::RecordUnreadable => 3,
        DaemonEvidence::Recycled(_) => 2,
        DaemonEvidence::ArtefactOnly => 1,
        DaemonEvidence::None => 0,
    };
    match rank(&right.0).cmp(&rank(&left.0)) {
        std::cmp::Ordering::Greater => right,
        std::cmp::Ordering::Less => left,
        std::cmp::Ordering::Equal if right.1 > left.1 => right,
        std::cmp::Ordering::Equal => left,
    }
}

/// Alive or recycled, from the process's start and the record's `mtime`.
fn classify_live(pid: u32, started: Option<Timestamp>, written: Timestamp) -> DaemonEvidence {
    match (started, written.checked_add(RECYCLE_TOLERANCE)) {
        (Some(started), Ok(limit)) if started > limit => DaemonEvidence::Recycled(pid),
        _ => DaemonEvidence::PidAlive(pid),
    }
}

/// The pid and modification time of a pid record, when it is a readable,
/// regular, parseable file.
fn read_pid_record(path: &Path) -> Option<(u32, Timestamp)> {
    let mut file = open_readonly_nofollow(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.size() > MAX_PID_RECORD_BYTES {
        return None;
    }
    let nanos = i128::from(meta.mtime())
        .checked_mul(1_000_000_000)?
        .checked_add(i128::from(meta.mtime_nsec()))?;
    let written = Timestamp::from_nanosecond(nanos).ok()?;
    let mut bytes = Vec::new();
    file.by_ref().take(MAX_PID_RECORD_BYTES).read_to_end(&mut bytes).ok()?;
    let record: PidRecord = serde_json::from_slice(&bytes).ok()?;
    Some((record.pid, written))
}

#[cfg(test)]
#[path = "home_tests.rs"]
mod tests;
