//! Bounded Linux process observations. Only this module addresses procfs.
//!
//! procfs-core supplies numeric parsing, but its unbounded, lossy reader and
//! unchecked stat envelope require validation before any bytes reach it (D-058).

use std::ffi::CStr;
use std::fs;
use std::fs::File;
use std::io;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use procfs_core::FromBufRead;
use procfs_core::FromRead;
use procfs_core::process::Stat;
use procfs_core::process::Status;
use rustix::io::Errno;
use rustix::process::Pid;

use super::Holder;
use super::ProcError;
use super::Seen;
use super::classification::is_claude;
use super::classification::state_holder;
use super::sweep;
use crate::runtime::coordinator::Cancel;

const STAT_LIMIT: u64 = 4096;
const STATUS_LIMIT: u64 = 65536;
const SYSTEM_STAT_LIMIT: u64 = 1024 * 1024;

/// Makes an unreadable directory searchable through a pinned no-follow descriptor.
///
/// rustix's Linux chmodat refuses SYMLINK_NOFOLLOW. Like glibc, use an O_PATH
/// directory handle and the procfs magic link to that handle, never the entry's
/// mutable pathname. Missing procfs remains an error, not a path-based fallback.
pub(super) fn make_dir_searchable(dir: &OwnedFd, name: &CStr) -> rustix::io::Result<()> {
    let flags = rustix::fs::OFlags::PATH
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::DIRECTORY
        | rustix::fs::OFlags::CLOEXEC;
    let child = rustix::fs::openat(dir, name, flags, rustix::fs::Mode::empty())?;
    let stat = rustix::fs::fstat(&child)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Directory {
        return Err(Errno::NOTDIR);
    }
    rustix::fs::chmod(format!("/proc/self/fd/{}", child.as_raw_fd()), rustix::fs::Mode::RWXU)
}

#[derive(Debug, thiserror::Error)]
enum ReadError {
    #[error("process data could not be read: {0}")]
    Io(#[from] io::Error),
    #[error("process data exceeds its read bound")]
    Oversized,
    #[error("invalid process data")]
    Invalid,
    #[error("process identity changed during observation")]
    Raced,
}

fn read_bounded(path: &Path, limit: u64) -> Result<String, ReadError> {
    let bytes = read_bytes(File::open(path)?, limit)?;
    let text = String::from_utf8(bytes).map_err(|_| ReadError::Invalid)?;
    if !text.ends_with('\n') {
        return Err(ReadError::Invalid);
    }
    Ok(text)
}

fn read_bytes(reader: impl Read, limit: u64) -> Result<Vec<u8>, ReadError> {
    let mut bytes = Vec::new();
    reader.take(limit.checked_add(1).ok_or(ReadError::Oversized)?).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_err(|_| ReadError::Oversized)? > limit {
        return Err(ReadError::Oversized);
    }
    Ok(bytes)
}

fn parse_stat(bytes: &[u8]) -> Result<Stat, ReadError> {
    if u64::try_from(bytes.len()).map_err(|_| ReadError::Oversized)? > STAT_LIMIT {
        return Err(ReadError::Oversized);
    }
    let line = std::str::from_utf8(bytes).map_err(|_| ReadError::Invalid)?;
    let line = line.strip_suffix('\n').ok_or(ReadError::Invalid)?;
    let open = line.find('(').ok_or(ReadError::Invalid)?;
    let close = line.rfind(')').ok_or(ReadError::Invalid)?;
    if open < 2 || close <= open || line.as_bytes()[open - 1] != b' ' {
        return Err(ReadError::Invalid);
    }
    let pid = decimal(&line[..open - 1]).ok_or(ReadError::Invalid)?;
    if pid == 0 || pid > i32::MAX as u64 {
        return Err(ReadError::Invalid);
    }
    let rest =
        line.get(close + 1..).and_then(|tail| tail.strip_prefix(' ')).ok_or(ReadError::Invalid)?;
    let mut fields = rest.split(' ');
    let state = fields.next().ok_or(ReadError::Invalid)?;
    if state.len() != 1 || state_holder(state.as_bytes()[0]).is_none() {
        return Err(ReadError::Invalid);
    }
    // Modern Linux emits all 52 fields. Do not let optional parser fields
    // disguise a truncated read, or accept a multi-byte state by its first byte.
    if fields.clone().count() != 49 || fields.clone().any(str::is_empty) {
        return Err(ReadError::Invalid);
    }
    let ticks = fields.nth(18).and_then(decimal).ok_or(ReadError::Invalid)?;
    let stat = Stat::from_read(bytes).map_err(|_| ReadError::Invalid)?;
    if stat.starttime != ticks {
        return Err(ReadError::Invalid);
    }
    Ok(stat)
}

fn parse_status(text: &str) -> Result<Status, ReadError> {
    let mut uids = text.lines().filter_map(|line| line.strip_prefix("Uid:"));
    let uid = uids.next().ok_or(ReadError::Invalid)?;
    if uids.next().is_some() {
        return Err(ReadError::Invalid);
    }
    let mut columns = uid.split_ascii_whitespace();
    for _ in 0..4 {
        let value = columns.next().and_then(decimal).ok_or(ReadError::Invalid)?;
        u32::try_from(value).map_err(|_| ReadError::Invalid)?;
    }
    if columns.next().is_some() {
        return Err(ReadError::Invalid);
    }
    Status::from_buf_read(text.as_bytes()).map_err(|_| ReadError::Invalid)
}

fn decimal(value: &str) -> Option<u64> {
    (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse().ok())
        .flatten()
}

#[derive(Debug)]
struct Observation {
    stat: Stat,
    uid: u32,
    name: String,
}

fn observe(pid: u32) -> Result<Observation, ReadError> {
    let root = Path::new("/proc").join(pid.to_string());
    let before = parse_stat(read_bounded(&root.join("stat"), STAT_LIMIT)?.as_bytes())?;
    let status = parse_status(&read_bounded(&root.join("status"), STATUS_LIMIT)?)?;
    let name = read_bounded(&root.join("comm"), 16)?;
    let name = name.strip_suffix('\n').ok_or(ReadError::Invalid)?.to_owned();
    let after_status = parse_status(&read_bounded(&root.join("status"), STATUS_LIMIT)?)?;
    let after = parse_stat(read_bounded(&root.join("stat"), STAT_LIMIT)?.as_bytes())?;
    let expected = i32::try_from(pid).map_err(|_| ReadError::Invalid)?;
    if before.pid != expected
        || status.pid != expected
        || after_status.pid != expected
        || after.pid != expected
        || before.starttime != after.starttime
        || status.ruid != after_status.ruid
    {
        return Err(ReadError::Raced);
    }
    Ok(Observation { stat: after, uid: status.ruid, name })
}

fn probe(pid: u32) -> Result<(), Errno> {
    let raw = i32::try_from(pid).map_err(|_| Errno::INVAL)?;
    let pid = Pid::from_raw(raw).ok_or(Errno::INVAL)?;
    rustix::process::test_kill_process(pid)
}

/// Whether kill-zero finds a visible PID, including permission refusal.
pub(super) fn exists(pid: u32) -> bool {
    matches!(probe(pid), Ok(()) | Err(Errno::PERM))
}

/// Classifies a PID conservatively, retaining unreadable processes as alive.
pub(super) fn holder(pid: u32, _cancel: &Cancel) -> Holder {
    if pid == 0 || pid > i32::MAX as u32 || probe(pid) == Err(Errno::SRCH) {
        return Holder::Dead;
    }
    observe(pid).ok().and_then(|seen| state_holder(seen.stat.state as u8)).unwrap_or(Holder::Alive)
}

fn classify(uid: u32, observed: Result<Observation, ReadError>, signal: Result<(), Errno>) -> Seen {
    match observed {
        Ok(seen) if !is_claude(uid, seen.uid, &seen.name) => Seen::Other,
        Ok(seen) => state_holder(seen.stat.state as u8).map_or(Seen::Unclassified, Seen::Claude),
        // A reused PID is inconclusive even if the replacement then exits.
        Err(ReadError::Raced) => Seen::Unclassified,
        Err(ReadError::Io(err))
            if err.kind() == io::ErrorKind::NotFound && signal == Err(Errno::SRCH) =>
        {
            Seen::Gone
        }
        Err(_) => Seen::Unclassified,
    }
}

/// Collects exact-name peers, returning an error for incomplete negative evidence.
pub(super) fn claude_processes() -> Result<Vec<(u32, Holder)>, ProcError> {
    let entries = fs::read_dir("/proc").map_err(|err| ProcError::Listing(err.to_string()))?;
    let uid = rustix::process::getuid().as_raw();
    let mut seen = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| ProcError::Listing(err.to_string()))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let pid = name.parse::<u32>().map_err(|_| ProcError::Incomplete { unreadable: 1 })?;
        if pid == 0 || pid > i32::MAX as u32 {
            return Err(ProcError::Incomplete { unreadable: 1 });
        }
        let observed = observe(pid);
        let signal = if observed.is_err() { probe(pid) } else { Ok(()) };
        seen.push((pid, classify(uid, observed, signal)));
    }
    sweep(seen)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Domain {
    boot: String,
    device: u64,
    inode: u64,
    uid: u32,
}

#[derive(Debug, PartialEq, Eq)]
struct Identity {
    domain: Domain,
    ticks: u64,
}

fn boot_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

fn current_domain() -> Option<Domain> {
    let boot = read_bounded(Path::new("/proc/sys/kernel/random/boot_id"), 37).ok()?;
    let boot = boot.strip_suffix('\n')?;
    if !boot_uuid(boot) {
        return None;
    }
    let namespace = fs::metadata("/proc/self/ns/pid").ok()?;
    Some(Domain {
        boot: boot.to_owned(),
        device: namespace.dev(),
        inode: namespace.ino(),
        uid: rustix::process::getuid().as_raw(),
    })
}

impl Identity {
    fn parse(value: &str) -> Option<Self> {
        let mut fields = value.split(':');
        if fields.next()? != "linux-v1" {
            return None;
        }
        let boot = fields.next()?;
        if !boot_uuid(boot) {
            return None;
        }
        let device = decimal(fields.next()?)?;
        let inode = decimal(fields.next()?)?;
        let ticks = decimal(fields.next()?)?;
        let uid = u32::try_from(decimal(fields.next()?)?).ok()?;
        if fields.next().is_some() {
            return None;
        }
        Some(Self { domain: Domain { boot: boot.to_owned(), device, inode, uid }, ticks })
    }

    fn render(&self) -> String {
        let Domain { boot, device, inode, uid } = &self.domain;
        format!("linux-v1:{boot}:{device}:{inode}:{}:{uid}", self.ticks)
    }
}

/// Returns the versioned boot/namespace/tick/real-UID identity when fully readable.
pub(super) fn start_time(pid: u32, _cancel: &Cancel) -> Option<String> {
    // Signal cleanup deliberately asks after cancellation; identity reads must
    // remain available so it can identify and terminate this invocation's child.
    let mut domain = current_domain()?;
    let seen = observe(pid).ok()?;
    domain.uid = seen.uid;
    Some(Identity { domain, ticks: seen.stat.starttime }.render())
}

/// Reads this invocation's own identity without caching process observations.
pub(super) fn self_start_time(cancel: &Cancel) -> Option<String> {
    start_time(std::process::id(), cancel)
}

fn start_instant(boot: u64, ticks: u64, rate: u64) -> Option<jiff::Timestamp> {
    let seconds = boot.checked_add(ticks.checked_div(rate)?)?;
    let nanos = ticks.checked_rem(rate)?.checked_mul(1_000_000_000)?.checked_div(rate)?;
    jiff::Timestamp::new(i64::try_from(seconds).ok()?, i32::try_from(nanos).ok()?).ok()
}

/// Converts boot time and ticks to a checked presentation timestamp.
pub(super) fn start_timestamp(pid: u32, cancel: &Cancel) -> Option<jiff::Timestamp> {
    if cancel.is_cancelled() {
        return None;
    }
    let seen = observe(pid).ok()?;
    let rate = rustix::param::clock_ticks_per_second();
    if rate == 0 {
        return None;
    }
    let system = read_bounded(Path::new("/proc/stat"), SYSTEM_STAT_LIMIT).ok()?;
    let mut times = system.lines().filter_map(|line| line.strip_prefix("btime "));
    let boot = decimal(times.next()?)?;
    if times.next().is_some() {
        return None;
    }
    start_instant(boot, seen.stat.starttime, rate)
}

fn same_domain(recorded: Option<&str>, domain: Option<Domain>) -> Option<Identity> {
    let identity = Identity::parse(recorded?)?;
    (identity.domain == domain?).then_some(identity)
}

fn writer_gone_with(
    recorded: Option<&str>,
    domain: Option<Domain>,
    probe: impl FnOnce() -> Result<(), Errno>,
) -> bool {
    same_domain(recorded, domain).is_some() && probe() == Err(Errno::SRCH)
}

/// Accepts only a same-domain record followed by a kill-zero ESRCH result.
pub(super) fn writer_is_gone(pid: u32, recorded: Option<&str>) -> bool {
    writer_gone_with(recorded, current_domain(), || probe(pid))
}

/// Diagnoses only comparable identities; a tick mismatch remains unknown.
pub(super) fn record_state(pid: u32, recorded: Option<&str>, cancel: &Cancel) -> Option<Holder> {
    let identity = same_domain(recorded, current_domain())?;
    match probe(pid) {
        Err(Errno::SRCH) => Some(Holder::Dead),
        Ok(()) if !cancel.is_cancelled() => match observe(pid) {
            Ok(seen)
                if seen.stat.starttime == identity.ticks && seen.uid == identity.domain.uid =>
            {
                state_holder(seen.stat.state as u8)
            }
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
#[path = "linux_tests.rs"]
mod tests;
