//! Bounded tmux argv transport. Screens only reject; they never authorize input.
//!
//! The existing process coordinator and standard library supply child ownership
//! and bounded reads. Target validation and screen rejection are vendor-specific.

#![cfg_attr(
    not(test),
    expect(dead_code, reason = "Remote Control stages consume this transport in S10")
)]

use std::ffi::OsStr;
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::sync::mpsc;
use std::time::Duration;
use std::time::Instant;

use crate::runtime::coordinator::PassCtx;

/// A blocked server must not keep a namespace lock indefinitely.
pub const TMUX_CALL_TIMEOUT: Duration = Duration::from_secs(2);
const CAPTURE_LIMIT: usize = 64 * 1024;
const PANE_FORMAT: &str =
    "#{pane_pid} #{pane_tty} #{pane_in_mode} #{pane_dead} #{pane_synchronized}";
#[cfg(feature = "testing")]
const TMUX_BIN_ENV: &str = "AGCTL_TMUX_BIN";
#[cfg(feature = "testing")]
const FAKE_PREFIX: &str = "AGCTL_FAKE_TMUX_";

/// A validated pane id, never a tmux session/window target expression.
#[derive(Clone, PartialEq, Eq)]
pub struct Pane(String);

impl Pane {
    /// Extracts the last dot-separated suffix and accepts only `%` plus 1–9 ASCII digits.
    pub fn parse(value: &str) -> Option<Self> {
        let suffix = value.rsplit('.').next()?;
        let digits = suffix.strip_prefix('%')?;
        if !(1..=9).contains(&digits.len()) || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        Some(Self(suffix.to_owned()))
    }

    /// The validated id, for argv and an explicit human-only TTY question.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Pane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Pane(..)")
    }
}

/// The complete set of input groups; no variant can carry arbitrary text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keys {
    /// Open the status panel, or reconnect an unbridged session.
    RemoteControl,
    /// Navigate the verified default panel from Continue to Disconnect.
    Disconnect,
}

impl Keys {
    fn argv(self) -> &'static [&'static str] {
        match self {
            Self::RemoteControl => &["/remote-control", "Enter"],
            Self::Disconnect => &["Up", "Up", "Enter"],
        }
    }

    /// The fixed input-group description for the human-only question.
    pub fn description(self) -> &'static str {
        match self {
            Self::RemoteControl => "/remote-control Enter",
            Self::Disconnect => "Up Up Enter",
        }
    }
}

/// Closed transport failures; no child text or OS error can escape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Failure {
    /// No executable was found.
    #[error("tmux_unavailable")]
    Unavailable,
    /// The child could not be started.
    #[error("tmux_spawn_failed")]
    Spawn,
    /// The call exceeded its deadline or was cancelled.
    #[error("tmux_timeout")]
    Timeout,
    /// The child returned a nonzero status.
    #[error("tmux_nonzero")]
    Nonzero,
    /// The bounded reply could not be read or parsed.
    #[error("tmux_invalid_reply")]
    Invalid,
    /// The reply exceeded its byte limit.
    #[error("tmux_reply_too_large")]
    TooLarge,
}

/// A pane observation; the tty path never belongs in logs or JSON.
pub struct PaneState {
    /// The pane's terminal device path.
    pub tty: PathBuf,
    /// Whether tmux is in copy/other mode.
    pub in_mode: bool,
    /// Whether the pane's process has died.
    pub dead: bool,
    /// Whether input is synchronized to other panes.
    pub synchronized: bool,
}

/// Opaque transient bytes: deliberately no Debug, Display or Serialize.
pub(crate) struct Capture(Vec<u8>);

/// Closed rejecting categories. `NoRejection` is not authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureVerdict {
    /// The screen supplied no rejection clue; fresh attestation is still required.
    NoRejection,
    /// Visible input text, including a continuation.
    DraftVisible,
    /// A visible stash banner.
    StashVisible,
    /// Any visible vim mode footer, including INSERT.
    ModeVisible,
    /// The dialog's option labels disagree with the verified default panel.
    DialogConflict,
    /// The disconnect group has no visible expected panel.
    PanelAbsent,
    /// Missing or viewport-clipped input without a recognized dialog.
    Ambiguous,
    /// Spawn, timeout or nonzero exit.
    Failed,
    /// More than 64 KiB.
    TooLarge,
    /// Invalid UTF-8.
    Invalid,
}

impl CaptureVerdict {
    /// A path- and screen-free diagnostic token.
    pub fn reason(self) -> &'static str {
        match self {
            Self::NoRejection => "no_screen_rejection",
            Self::DraftVisible => "draft_visible",
            Self::StashVisible => "stash_visible",
            Self::ModeVisible => "mode_visible",
            Self::DialogConflict => "dialog_conflict",
            Self::PanelAbsent => "panel_absent",
            Self::Ambiguous => "capture_ambiguous",
            Self::Failed => "capture_failed",
            Self::TooLarge => "capture_too_large",
            Self::Invalid => "capture_invalid",
        }
    }
}

impl Capture {
    pub(super) fn classify(self) -> CaptureVerdict {
        let Ok(text) = std::str::from_utf8(&self.0) else { return CaptureVerdict::Invalid };
        let lines: Vec<&str> = text.lines().collect();
        let options: Vec<&str> = lines
            .iter()
            .filter_map(|line| {
                let line = line.trim().trim_start_matches(['❯', '›', '●', '○', ' ']);
                ["Disconnect this session", "Show QR code", "Hide QR code", "Continue"]
                    .into_iter()
                    .find(|label| line == *label)
            })
            .collect();
        let panel = options == ["Disconnect this session", "Show QR code", "Continue"]
            || options == ["Disconnect this session", "Hide QR code", "Continue"];
        let mut pointer = None;
        for (index, line) in lines.iter().enumerate() {
            if let Some(tail) = line.trim_start().strip_prefix('❯') {
                if panel && options.contains(&tail.trim()) {
                    continue;
                }
                if !tail.trim().is_empty() {
                    return CaptureVerdict::DraftVisible;
                }
                pointer = Some(index);
                // Continuations belong to the input until its closing border or
                // an unindented footer. Neither border nor footer is an accepting grammar.
                for continuation in lines.iter().skip(index + 1) {
                    let content = continuation.trim();
                    if content.is_empty() {
                        continue;
                    }
                    if is_border(content)
                        || !continuation.starts_with(' ')
                        || content.starts_with('?')
                        || content.contains(" shortcuts")
                    {
                        break;
                    }
                    return CaptureVerdict::DraftVisible;
                }
            }
        }
        if text.contains(" stashed") {
            return CaptureVerdict::StashVisible;
        }
        if lines.iter().any(|line| {
            line.trim()
                .strip_prefix("-- ")
                .and_then(|v| v.strip_suffix(" --"))
                .is_some_and(|mode| !mode.is_empty())
        }) {
            return CaptureVerdict::ModeVisible;
        }
        if !options.is_empty() && !panel {
            return CaptureVerdict::DialogConflict;
        }
        if !panel && pointer.is_none_or(|index| index == 0 || index + 1 == lines.len()) {
            return CaptureVerdict::Ambiguous;
        }
        CaptureVerdict::NoRejection
    }
}

fn is_border(line: &str) -> bool {
    !line.is_empty()
        && line.chars().all(|ch| matches!(ch, '─' | '━' | '│' | '╭' | '╮' | '╰' | '╯' | ' ' | '-'))
}

/// Finds an executable on agctl's own PATH; the test override is absent in production.
///
/// # Errors
/// Returns a closed unavailable category when no executable is found.
pub fn resolve_tmux_bin() -> Result<PathBuf, Failure> {
    #[cfg(feature = "testing")]
    if let Some(bin) = std::env::var_os(TMUX_BIN_ENV) {
        return Ok(PathBuf::from(bin));
    }
    resolve_on_path(std::env::var_os("PATH").as_deref().ok_or(Failure::Unavailable)?)
}

fn resolve_on_path(path: &OsStr) -> Result<PathBuf, Failure> {
    for dir in std::env::split_paths(path).filter(|dir| !dir.as_os_str().is_empty()) {
        let bin = dir.join("tmux");
        if fs::metadata(&bin)
            .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        {
            return Ok(bin);
        }
    }
    Err(Failure::Unavailable)
}

/// Reads the five tmux fields without exposing the raw reply.
///
/// # Errors
/// Rejects failed calls and malformed or oversized replies.
pub fn pane_state(
    bin: &Path,
    pane: &Pane,
    ctx: &PassCtx,
    deadline: Instant,
) -> Result<PaneState, Failure> {
    let bytes = run(
        bin,
        &["display-message", "-p", "-t", pane.as_str(), PANE_FORMAT],
        None,
        ctx,
        deadline,
    )?;
    parse_pane_state(&bytes)
}

fn parse_pane_state(bytes: &[u8]) -> Result<PaneState, Failure> {
    if bytes.len() > 256 {
        return Err(Failure::TooLarge);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| Failure::Invalid)?;
    let fields: Vec<&str> = text.split_whitespace().collect();
    if fields.len() != 5 || fields[0].parse::<u32>().ok().filter(|pid| *pid != 0).is_none() {
        return Err(Failure::Invalid);
    }
    let tty = PathBuf::from(fields[1]);
    if !tty.is_absolute()
        || !tty.starts_with("/dev")
        || tty.components().any(|part| matches!(part, std::path::Component::ParentDir))
        || tty == Path::new("/dev")
    {
        return Err(Failure::Invalid);
    }
    let flag = |value| match value {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(Failure::Invalid),
    };
    Ok(PaneState {
        tty,
        in_mode: flag(fields[2])?,
        dead: flag(fields[3])?,
        synchronized: flag(fields[4])?,
    })
}

/// Sends exactly one closed input group in one tmux invocation.
///
/// # Errors
/// Returns only the closed transport failure, never child output.
pub fn send(
    bin: &Path,
    pane: &Pane,
    keys: Keys,
    ctx: &PassCtx,
    deadline: Instant,
) -> Result<(), Failure> {
    let mut args = vec!["send-keys", "-t", pane.as_str()];
    args.extend_from_slice(keys.argv());
    run(bin, &args, Some(keys), ctx, deadline).map(|_| ())
}

/// Captures only the visible viewport, rejects bounded failures, and drops all bytes.
pub fn capture(
    bin: &Path,
    pane: &Pane,
    keys: Keys,
    ctx: &PassCtx,
    deadline: Instant,
) -> CaptureVerdict {
    match run(
        bin,
        &["capture-pane", "-p", "-t", pane.as_str(), "-S", "0", "-E", "-"],
        None,
        ctx,
        deadline,
    ) {
        Ok(bytes) => {
            if std::str::from_utf8(&bytes).is_err() {
                return CaptureVerdict::Invalid;
            }
            if keys == Keys::Disconnect
                && !bytes
                    .windows(b"Disconnect this session".len())
                    .any(|window| window == b"Disconnect this session")
            {
                return CaptureVerdict::PanelAbsent;
            }
            Capture(bytes).classify()
        }
        Err(Failure::TooLarge) => CaptureVerdict::TooLarge,
        Err(
            Failure::Unavailable
            | Failure::Spawn
            | Failure::Timeout
            | Failure::Nonzero
            | Failure::Invalid,
        ) => CaptureVerdict::Failed,
    }
}

fn run(
    bin: &Path,
    args: &[&str],
    keys: Option<Keys>,
    ctx: &PassCtx,
    deadline: Instant,
) -> Result<Vec<u8>, Failure> {
    let started = Instant::now();
    let deadline = deadline.min(started.checked_add(TMUX_CALL_TIMEOUT).unwrap_or(started));
    let subcommand = args[0];
    let mut exit_status = None;
    let result = (|| {
        if ctx.cancel().is_cancelled() || started >= deadline {
            return Err(Failure::Timeout);
        }
        let mut command = Command::new(bin);
        command.args(args).env_clear();
        for name in ["PATH", "HOME", "TMUX", "TMUX_TMPDIR"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        #[cfg(feature = "testing")]
        command.envs(
            std::env::vars_os()
                .filter(|(name, _)| name.as_encoded_bytes().starts_with(FAKE_PREFIX.as_bytes())),
        );
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| Failure::Spawn)?;
        let stdout = child.stdout.take().ok_or(Failure::Invalid)?;
        let token = ctx.register_child(child);
        let limit = if subcommand == "capture-pane" { CAPTURE_LIMIT } else { 256 };
        let (tx, rx) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = stdout.take((limit + 1) as u64).read_to_end(&mut bytes).map(|_| bytes);
            let _ = tx.send(result);
        });
        let status = ctx
            .wait_child_timeout(token, deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| Failure::Timeout)?
            .ok_or(Failure::Timeout)?;
        exit_status = status.code();
        let bytes = rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| Failure::Timeout)?
            .map_err(|_| Failure::Invalid)?;
        if bytes.len() > limit {
            return Err(Failure::TooLarge);
        }
        if !status.success() {
            return Err(Failure::Nonzero);
        }
        Ok(bytes)
    })();
    let failure = result.as_ref().err().copied();
    if matches!(failure, Some(Failure::Spawn | Failure::Timeout)) {
        tracing::warn!(?failure, "tmux call did not complete");
    }
    tracing::debug!(
        subcommand,
        ?keys,
        ?failure,
        ?exit_status,
        elapsed_ms = started.elapsed().as_millis(),
        "tmux call"
    );
    result
}

#[cfg(test)]
#[path = "tmux_tests.rs"]
mod tests;
