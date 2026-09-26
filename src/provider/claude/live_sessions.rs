//! Read-only Remote Control hints from Claude Code's session registry.
//!
//! The registry does not identify a session's credential store. These are
//! possibilities to disclose, never evidence for refusing or targeting a swap.

use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::io;
use std::io::Read;
use std::path::Path;

use serde::Deserialize;

use crate::runtime::coordinator::Cancel;
use crate::runtime::proc;
use crate::runtime::tmux::Pane;

const MAX_ENTRIES: usize = 512;
const MAX_BYTES: u64 = 64 * 1024;
const MAX_NAME_CHARS: usize = 48;

/// What Phase A learned from Claude Code's session registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scan {
    /// No registry exists under this config home.
    NoRegistry,
    /// Live Remote Control entries, and the number of entries skipped.
    Read { remote: Vec<RemoteSession>, skipped: usize },
    /// Listing failed; retaining only the kind keeps paths out of output.
    Unreadable(io::ErrorKind),
}

/// A live Remote Control session, reduced to its sanitized human-facing label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSession {
    /// Only human-readable sentences may show this label, never JSON warnings.
    pub name: Option<String>,
}

#[derive(Deserialize)]
struct Entry {
    pid: Option<u32>,
    name: Option<String>,
    #[serde(rename = "bridgeSessionId")]
    bridge_session_id: Option<String>,
}

/// Reads at most 512 JSON entries of less than 64 KiB each from `dir`.
///
/// `alive` supplies the process-liveness check, including stopped processes.
/// Missing directories and listing errors become [`Scan`] variants; individual
/// unreadable or invalid entries are counted, without exposing their filenames.
/// Standard filesystem reads and the existing serde parser suffice; the bounds
/// and hint selection are specific to this registry, not a general directory walker.
pub fn scan(dir: &Path, alive: impl Fn(u32) -> bool) -> Scan {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Scan::NoRegistry,
        Err(err) => return Scan::Unreadable(err.kind()),
    };
    let mut remote = Vec::new();
    let mut skipped = 0_usize;
    let mut reasons = BTreeMap::<String, usize>::new();
    let mut skip = |reason: String| {
        skipped = skipped.saturating_add(1);
        let count = reasons.entry(reason).or_default();
        *count = count.saturating_add(1);
    };
    let mut considered = 0;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                skip(err.kind().to_string());
                continue;
            }
        };
        if !entry.file_name().as_encoded_bytes().ends_with(b".json") {
            continue;
        }
        if considered == MAX_ENTRIES {
            skip("entry limit".to_owned());
            continue;
        }
        considered += 1;
        let path = entry.path();
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => {}
            Ok(_) => {
                skip("not a regular file".to_owned());
                continue;
            }
            Err(err) => {
                skip(err.kind().to_string());
                continue;
            }
        }
        let mut bytes = Vec::new();
        if let Err(err) =
            File::open(&path).and_then(|file| file.take(MAX_BYTES).read_to_end(&mut bytes))
        {
            skip(err.kind().to_string());
            continue;
        }
        if bytes.len() as u64 == MAX_BYTES {
            skip("oversized".to_owned());
            continue;
        }
        let Ok(entry) = serde_json::from_slice::<Entry>(&bytes) else {
            skip("unparseable".to_owned());
            continue;
        };
        let Some(pid) = entry.pid.or_else(|| path.file_stem()?.to_str()?.parse().ok()) else {
            skip("missing pid".to_owned());
            continue;
        };
        if pid != 0 && alive(pid) && entry.bridge_session_id.is_some_and(|id| !id.is_empty()) {
            remote.push(RemoteSession { name: entry.name.as_deref().and_then(sanitize_name) });
        }
    }
    tracing::debug!(skipped, ?reasons, "Claude Code session registry scan");
    Scan::Read { remote, skipped }
}

fn sanitize_name(name: &str) -> Option<String> {
    let clean: String = name
        .trim()
        .chars()
        .filter(|ch| !ch.is_control())
        .map(|ch| if ch == '`' { '\'' } else { ch })
        .collect();
    let clean = clean.trim();
    if clean.is_empty() {
        return None;
    }
    let mut chars = clean.chars();
    let mut result: String = chars.by_ref().take(MAX_NAME_CHARS).collect();
    if chars.next().is_some() {
        result.pop();
        result.push('…');
    }
    Some(result)
}

fn render_list(remote: &[RemoteSession]) -> String {
    let mut named: Vec<&str> =
        remote.iter().filter_map(|session| session.name.as_deref()).collect();
    named.sort_unstable();
    let unnamed = remote.len() - named.len();
    let mut parts: Vec<String> = named.iter().take(3).map(|name| format!("`{name}`")).collect();
    if unnamed != 0 {
        parts.push(format!("{unnamed} unnamed"));
    }
    if named.len() > 3 {
        parts.push(format!("{} more", named.len() - 3));
    }
    match parts.split_last() {
        None => String::new(),
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
    }
}

/// Returns the consent suffix for a non-empty scan, naming `deadline_secs`.
pub fn consent_clause(scan: &Scan, deadline_secs: u64) -> Option<String> {
    let Scan::Read { remote, .. } = scan else { return None };
    if remote.is_empty() {
        return None;
    }
    let n = remote.len();
    let s = if n == 1 { "" } else { "s" };
    let verb_have = if n == 1 { "has" } else { "have" };
    let list = render_list(remote);
    Some(format!(
        ". {n} running Claude Code session{s} ({list}) {verb_have} Remote Control on, and agctl cannot tell which \
         of them use this store. To keep a session's claude.ai history, answer n, run `/remote-control` in that \
         session and disconnect, then run this command again — do not leave this question open while you do it, \
         because it counts against this swap's {deadline_secs}-second limit. If you answer y, Remote Control stops in each \
         session that uses this store, and starting it again there begins a remote session without the earlier \
         conversation"
    ))
}

/// Returns the completion warning; `names` is false for machine-readable output.
pub fn completion_warning(scan: &Scan, names: bool) -> Option<String> {
    let Scan::Read { remote, .. } = scan else { return None };
    if remote.is_empty() {
        return None;
    }
    let n = remote.len();
    let s = if n == 1 { "" } else { "s" };
    let list = if names { format!(" ({})", render_list(remote)) } else { String::new() };
    Some(format!(
        "{n} Claude Code session{s}{list} had Remote Control on when this swap started, and agctl cannot tell \
         which of them use this store. In each one that does, Remote Control stops (now, or on its next account \
         check): run `/remote-control` there to start it again. Its earlier conversation reaches claude.ai only if \
         Remote Control was disconnected there before the swap"
    ))
}

/// Returns a path-free note for a registry listing failure, otherwise nothing.
pub fn unreadable_note(scan: &Scan) -> Option<String> {
    let Scan::Unreadable(kind) = scan else { return None };
    Some(format!(
        "agctl could not read Claude Code's session registry ({kind}), so it cannot say whether a running session \
         has Remote Control on. A session that does keeps its claude.ai history only if Remote Control is \
         disconnected there before the swap: decline this swap (answer n, or run without `--yes`), disconnect it \
         there, and run this command again"
    ))
}

/// Opaque registry identity. Process and bridge identifiers never enter output.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKey {
    pid: u32,
    session_id: Option<String>,
    bridge_session_id: String,
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionKey(..)")
    }
}

impl SessionKey {
    /// The kernel probe's argument, never a presentation field.
    pub fn pid(&self) -> u32 {
        self.pid
    }
}

/// The recognized registry fields used for rejecting stale input targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    /// Whether a nonempty bridge id is set.
    pub bridge_on: bool,
    /// Whether it is the bridge seen during the initial scan.
    pub same_bridge: bool,
    /// One of the four known lifecycle states.
    pub status: String,
    /// Absent means not waiting; explicit null is unrecognized.
    pub waiting_for: Option<String>,
    /// The producer's epoch-millisecond stamp, not a readiness guarantee.
    pub status_updated_at: i64,
    /// The registry's version, never an external version subprocess.
    pub version: String,
    /// The current validated pane, so a changed target invalidates an answer.
    pub pane: Pane,
}

/// One remote session with its opaque identity and sanitized human label.
#[derive(Debug, Clone)]
pub struct DetailedSession {
    /// Identity checked on every reread.
    pub key: SessionKey,
    /// The pane alone, excluding session/window syntax.
    pub pane: Option<Pane>,
    /// Human-only sanitized name.
    pub name: Option<String>,
    /// Recognized initial fields, or missing/unknown schema.
    pub state: Option<State>,
}

/// A detailed scan keeps the existing hint for sessions with no eligible pane.
#[derive(Debug)]
pub struct DetailedScan {
    /// The same human hint vocabulary as a plain scan.
    pub hint: Scan,
    /// Live bridged entries, including ones whose detailed schema is rejected.
    pub sessions: Vec<DetailedSession>,
}

/// Reads the same bounded registry without losing identities needed by the stages.
/// Invalid detailed fields remain candidates so the stage rejects rather than ignores them.
pub fn scan_detailed(dir: &Path, alive: impl Fn(u32) -> bool) -> DetailedScan {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) => {
            return DetailedScan {
                hint: if err.kind() == io::ErrorKind::NotFound {
                    Scan::NoRegistry
                } else {
                    Scan::Unreadable(err.kind())
                },
                sessions: Vec::new(),
            };
        }
    };
    let mut sessions = Vec::new();
    let mut skipped = 0_usize;
    let mut considered = 0_usize;
    for entry in entries {
        let Ok(entry) = entry else {
            skipped = skipped.saturating_add(1);
            continue;
        };
        if !entry.file_name().as_encoded_bytes().ends_with(b".json") {
            continue;
        }
        if considered >= MAX_ENTRIES {
            skipped = skipped.saturating_add(1);
            continue;
        }
        considered += 1;
        let path = entry.path();
        let Ok(document) = read_document(&path) else {
            skipped = skipped.saturating_add(1);
            continue;
        };
        let pid = document
            .get("pid")
            .and_then(serde_json::Value::as_u64)
            .and_then(|pid| u32::try_from(pid).ok())
            .or_else(|| path.file_stem()?.to_str()?.parse().ok());
        let Some(pid) = pid.filter(|pid| *pid != 0 && alive(*pid)) else { continue };
        let Some(bridge) = document
            .get("bridgeSessionId")
            .and_then(serde_json::Value::as_str)
            .filter(|id| !id.is_empty())
        else {
            continue;
        };
        let key = SessionKey {
            pid,
            session_id: document
                .get("sessionId")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            bridge_session_id: bridge.to_owned(),
        };
        let state = parse_state(&document, &key);
        sessions.push(DetailedSession {
            pane: document.get("tmux").and_then(serde_json::Value::as_str).and_then(Pane::parse),
            name: document.get("name").and_then(serde_json::Value::as_str).and_then(sanitize_name),
            key,
            state,
        });
    }
    let remote =
        sessions.iter().map(|session| RemoteSession { name: session.name.clone() }).collect();
    DetailedScan { hint: Scan::Read { remote, skipped }, sessions }
}

/// A targeted reread, carrying neither identifiers nor raw registry text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reread {
    /// The pid died or its registry entry was removed.
    Gone,
    /// This filename now names a different session.
    Replaced,
    /// Unknown, unreadable, or inconsistent schema.
    Unrecognized,
    /// Recognized fields for the original session.
    State(State),
}

/// Reopens only this session's numeric filename with the scan's file/size guards.
pub fn reread(dir: &Path, key: &SessionKey) -> Reread {
    if proc::holder(key.pid, &Cancel::new()) == proc::Holder::Dead {
        return Reread::Gone;
    }
    let document = match read_document(&dir.join(format!("{}.json", key.pid))) {
        Ok(document) => document,
        Err(io::ErrorKind::NotFound) => return Reread::Gone,
        Err(_) => return Reread::Unrecognized,
    };
    let Some(session) = document.get("sessionId").and_then(serde_json::Value::as_str) else {
        return Reread::Unrecognized;
    };
    if key.session_id.as_deref().is_some_and(|original| original != session) {
        return Reread::Replaced;
    }
    parse_state(&document, key).map_or(Reread::Unrecognized, Reread::State)
}

fn read_document(path: &Path) -> Result<serde_json::Value, io::ErrorKind> {
    if !fs::symlink_metadata(path).map_err(|err| err.kind())?.file_type().is_file() {
        return Err(io::ErrorKind::InvalidData);
    }
    // Nonblocking/no-follow prevents a replacement FIFO or symlink from making
    // a bounded registry read block or leave the selected entry.
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map_err(|err| io::Error::from(err).kind())?;
    let stat = rustix::fs::fstat(&fd).map_err(|err| io::Error::from(err).kind())?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile {
        return Err(io::ErrorKind::InvalidData);
    }
    let mut bytes = Vec::new();
    File::from(fd).take(MAX_BYTES).read_to_end(&mut bytes).map_err(|err| err.kind())?;
    if bytes.len() as u64 == MAX_BYTES {
        return Err(io::ErrorKind::InvalidData);
    }
    serde_json::from_slice(&bytes).map_err(|_| io::ErrorKind::InvalidData)
}

fn parse_state(document: &serde_json::Value, key: &SessionKey) -> Option<State> {
    if document.get("pid")?.as_u64()? != u64::from(key.pid)
        || document.get("sessionId")?.as_str()? != key.session_id.as_deref()?
    {
        return None;
    }
    let status = document.get("status")?.as_str()?;
    if !["busy", "shell", "idle", "waiting"].contains(&status) {
        return None;
    }
    let waiting_for = match document.get("waitingFor") {
        None => None,
        Some(value) => {
            let waiting = value.as_str()?;
            if ![
                "input needed",
                "permission prompt",
                "dialog open",
                "worker request",
                "sandbox request",
                "goal proposal",
            ]
            .contains(&waiting)
            {
                return None;
            }
            Some(waiting.to_owned())
        }
    };
    let bridge = match document.get("bridgeSessionId")? {
        serde_json::Value::Null => None,
        serde_json::Value::String(value) => Some(value.as_str()),
        _ => return None,
    };
    Some(State {
        bridge_on: bridge.is_some_and(|value| !value.is_empty()),
        same_bridge: bridge == Some(key.bridge_session_id.as_str()),
        status: status.to_owned(),
        waiting_for,
        status_updated_at: document.get("statusUpdatedAt")?.as_i64()?,
        version: document.get("version")?.as_str()?.to_owned(),
        pane: Pane::parse(document.get("tmux")?.as_str()?)?,
    })
}

#[cfg(test)]
#[path = "live_sessions_tests.rs"]
mod tests;
