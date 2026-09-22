//! Codex's write log: `<config_dir>/codex/writes.jsonl` (invariant I30).
//!
//! Every Codex namespace write returns a [`WriteReceipt`], and [`append`] is
//! the one function that consumes one: it takes the receipt by value, so a
//! write that is audited cannot be audited twice, and
//! `scripts/phase3-greps.sh`'s `receipt_type` rule holds `WriteReceipt` to
//! `auth_store.rs` and this file, so no other module takes a receipt apart
//! (plan AC117, review S30 LOW-2). A refresh outcome that changes no
//! credential file — an adopted external grant, a dead grant, an ambiguous
//! send, a user's re-send, a floor reset — is recorded through
//! [`append_event`].
//!
//! The log's reach and its one-write-one-`fsync` rule are Claude's
//! (`secret::audit::{open_log_at, write_line}`): the file is created 0600
//! beside the Codex namespaces, opened `O_NOFOLLOW` relative to a directory
//! descriptor, refused when it is a link, not a regular file, or not 0600.
//!
//! # What a line may hold
//!
//! Ids, digest prefixes and fixed words — nothing else (invariant I24). Each
//! entry is checked before any I/O: both ids must be valid namespace segments,
//! each digest exactly eight lowercase hex digits, and the finished line must
//! contain no `@`, so an email address can never reach it through an id.

use std::os::fd::AsFd;
use std::path::PathBuf;

use jiff::Timestamp;
use serde::Deserialize;
use serde::Serialize;

use crate::config::paths::Paths;
use crate::config::paths::validate_codex_segment;
use crate::error::AppError;
use crate::provider::codex::auth_store::UnknownClass;
use crate::provider::codex::auth_store::WriteKind;
use crate::provider::codex::auth_store::WriteReceipt;
use crate::provider::codex::home;
use crate::provider::codex::oauth::PermanentClass;
use crate::secret::audit;
use crate::secret::file_store;

/// The log's file name under `codex_root()`.
pub const LOG_FILE: &str = "writes.jsonl";

/// The only value `provider` may hold, spelled once.
///
/// A field of a struct is not a validated field just because this crate is
/// the only thing that writes it: [`shown_line`] re-serializes a line parsed
/// from a FILE, so every field it renders needs a rule of its own. This one
/// had none, and a planted line's `provider` reached the table and `--json`
/// exactly as the file spelled it (review S37-b1b, F1).
const PROVIDER: &str = "codex";

/// The `user_id` and `account_id` of a line that belongs to no namespace.
///
/// A valid namespace segment, so the field guard is unchanged, and a word no
/// ChatGPT id is: the pair says "not a namespace" rather than leaving two
/// required fields to be guessed at.
const NO_NAMESPACE: &str = "none";

/// The longest line a reader will assemble before it gives up on it.
///
/// An entry agctl writes is a timestamp, a pid, two namespace segments, a
/// fixed word and up to three short hex strings — a few hundred bytes, and
/// bounded by the field guard that wrote it. Four kilobytes is far above
/// that and far below anything that would matter as an allocation, so a line
/// past it was not written by this crate and is no use to a reader looking
/// for this crate's own entries.
const MAX_ENTRY_BYTES: usize = 4096;

/// Where the Codex log lives for one agctl store.
pub fn log_path(paths: &Paths) -> PathBuf {
    paths.codex_root().join(LOG_FILE)
}

/// What one line records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodexOutcome {
    /// A refreshed grant was renamed into place.
    Applied,
    /// A refreshed grant was parked as pending.
    SavedToPending,
    /// A refreshed grant was not written: the file holds a newer one.
    DiscardedExternal,
    /// A parked grant was replayed.
    PendingReplayed,
    /// A parked grant was deleted unused.
    PendingDiscarded,
    /// A login was installed into an empty namespace.
    LoginInstall,
    /// A login replaced a credential.
    LoginOverwrite,
    /// A namespace's files were removed.
    Delete,
    /// A refresh was answered as dead while another writer's grant was in the
    /// file, and that grant was kept.
    AdoptedExternal,
    /// A refresh was answered as dead and the file still held the grant sent.
    NeedsLogin,
    /// A refresh's outcome is unknown; the marker is kept.
    Ambiguous,
    /// The user's one re-send of an unknown refresh.
    Resend,
    /// The user lifted the 401 floor.
    FloorReset,
    /// A login child agctl spawned left a `Codex Auth` keychain item behind,
    /// and the login was refused because of it.
    LoginKeychainGained,
}

/// One line of the Codex log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodexAuditEntry {
    /// When this process wrote the entry, RFC 3339 in UTC.
    #[serde(with = "rfc3339")]
    pub ts: Timestamp,
    /// agctl's own process id.
    pub agctl_pid: u32,
    /// Always `codex`, so a line read out of context says whose it is.
    pub provider: String,
    /// The namespace's ChatGPT user id.
    pub user_id: String,
    /// The namespace's ChatGPT account id.
    pub account_id: String,
    /// What happened.
    pub outcome: CodexOutcome,
    /// A fixed word qualifying the outcome: the unknown class or the
    /// permanent class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    /// The refresh digest prefix of the credential before.
    #[serde(default)]
    pub digest8_before: Option<String>,
    /// The refresh digest prefix of the credential the event concerned.
    #[serde(default)]
    pub digest8_after: Option<String>,
    /// The `Codex Auth` keychain account a refused login child gained, on a
    /// [`CodexOutcome::LoginKeychainGained`] line and on no other.
    ///
    /// Always `cli|` and sixteen lowercase hex digits ([`home::is_home_account`]),
    /// which is a digest prefix of a path and names no person — the same
    /// standing as the two `digest8_*` fields under invariant I24.
    ///
    /// [`home::is_home_account`]: crate::provider::codex::home::is_home_account
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keychain_account: Option<String>,
}

/// A refresh event that wrote no credential file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodexEvent<'a> {
    /// The server called the sent grant dead; the file held another writer's
    /// grant, which was kept.
    AdoptedExternal {
        /// The grant sent.
        sent_digest8: &'a str,
        /// The grant kept.
        kept_digest8: Option<&'a str>,
    },
    /// The server called the grant dead and it was still the file's.
    NeedsLogin {
        /// Which answer.
        class: PermanentClass,
        /// The grant sent.
        sent_digest8: &'a str,
    },
    /// The outcome of a send is unknown.
    Ambiguous {
        /// Why.
        class: UnknownClass,
        /// The grant sent.
        sent_digest8: &'a str,
    },
    /// A refreshed grant is on disk though its write reported an error after
    /// the rename, so no receipt came back; the file was re-read and holds it.
    AppliedAfterError {
        /// The grant sent.
        sent_digest8: &'a str,
        /// The grant now in the file.
        written_digest8: Option<&'a str>,
    },
    /// The user re-sent an unknown refresh.
    Resend {
        /// The grant re-sent.
        sent_digest8: &'a str,
    },
    /// The user lifted the 401 floor.
    FloorReset,
    /// A login child left a `Codex Auth` keychain item behind and the login
    /// was refused. Written by `commands::codex::login`, read back by
    /// `doctor`: it is the only evidence that an item in somebody's keychain
    /// is one agctl caused, and therefore the only ground on which `doctor`
    /// offers to remove it.
    LoginKeychainGained {
        /// The account of the item the second listing gained.
        keychain_account: &'a str,
    },
}

/// The classes an [`CodexEvent::Ambiguous`] or [`CodexEvent::NeedsLogin`] may
/// carry — fixed words, so a line cannot carry anything a caller formats.
const CLASSES: [&str; 11] = [
    "ambiguous",
    "server_error",
    "rate_limited",
    "interrupted",
    "tls",
    "write_failed",
    "unauthorized",
    "invalid_grant",
    "refresh_token_expired",
    "refresh_token_reused",
    "refresh_token_invalidated",
];

/// Records one namespace write, consuming its receipt.
///
/// # Errors
///
/// [`AppError::Config`] when the entry fails its field guard, and the log's own
/// refusals and I/O errors (`secret::audit::open_log_at`, `write_line`). A
/// caller whose write has already landed logs the failure at `warn` and marks
/// the row `audit log refused`; the write stands (plan AC117).
pub fn append(paths: &Paths, receipt: WriteReceipt) -> Result<(), AppError> {
    // First, before anything here can fail: the receipt has reached the log,
    // which is what the `testing`-only drop check asks. A refused entry below
    // leaves the write standing, so the receipt is audited either way.
    receipt.reached_audit();
    let outcome = match receipt.kind() {
        WriteKind::RefreshApplied => CodexOutcome::Applied,
        WriteKind::RefreshSavedToPending => CodexOutcome::SavedToPending,
        WriteKind::DiscardedExternal => CodexOutcome::DiscardedExternal,
        WriteKind::PendingReplayed => CodexOutcome::PendingReplayed,
        WriteKind::PendingDiscarded => CodexOutcome::PendingDiscarded,
        WriteKind::LoginInstall { overwrote: false } => CodexOutcome::LoginInstall,
        WriteKind::LoginInstall { overwrote: true } => CodexOutcome::LoginOverwrite,
        WriteKind::Delete => CodexOutcome::Delete,
    };
    let entry =
        entry(receipt.ids(), outcome, None, receipt.digest8_before(), receipt.digest8_after());
    write_entry(paths, &entry)
}

/// Records a refresh event that changed no credential file.
///
/// # Errors
///
/// As [`append`].
pub fn append_event(
    paths: &Paths,
    ids: (&str, &str),
    event: CodexEvent<'_>,
) -> Result<(), AppError> {
    let entry = match event {
        CodexEvent::AdoptedExternal { sent_digest8, kept_digest8 } => {
            entry(ids, CodexOutcome::AdoptedExternal, None, Some(sent_digest8), kept_digest8)
        }
        CodexEvent::NeedsLogin { class, sent_digest8 } => {
            entry(ids, CodexOutcome::NeedsLogin, Some(class.label()), Some(sent_digest8), None)
        }
        CodexEvent::Ambiguous { class, sent_digest8 } => {
            entry(ids, CodexOutcome::Ambiguous, Some(class.label()), Some(sent_digest8), None)
        }
        CodexEvent::AppliedAfterError { sent_digest8, written_digest8 } => {
            entry(ids, CodexOutcome::Applied, None, Some(sent_digest8), written_digest8)
        }
        CodexEvent::Resend { sent_digest8 } => {
            entry(ids, CodexOutcome::Resend, None, Some(sent_digest8), None)
        }
        CodexEvent::FloorReset => entry(ids, CodexOutcome::FloorReset, None, None, None),
        CodexEvent::LoginKeychainGained { keychain_account } => {
            // `ids` is deliberately ignored. A login is refused on the child's
            // evidence *before* its credential is parsed (`verify_login`:
            // evidence before trust), so at this point no identity has been
            // read and there is no namespace this line belongs to. The fixed
            // word says that, and saying it here rather than trusting the
            // caller keeps a real pair out of a line that did not earn one.
            let mut entry = entry(
                (NO_NAMESPACE, NO_NAMESPACE),
                CodexOutcome::LoginKeychainGained,
                None,
                None,
                None,
            );
            entry.keychain_account = Some(keychain_account.to_owned());
            entry
        }
    };
    write_entry(paths, &entry)
}

/// One log line as it may be shown, or `None` when it may not be.
///
/// # Why a line agctl wrote is re-checked before it is displayed
///
/// `doctor` prints the log's tail, and until S37 it printed whatever bytes
/// each line held. The log is agctl's own 0600 file, so every line agctl
/// wrote already passed [`entry_line`]'s guard — but "agctl wrote it" is an
/// assumption about a file on a disk, not a property of the bytes being
/// rendered, and a planted line's escape sequence would redraw the reader's
/// terminal (review S37-b1, carry 1).
///
/// So a line is shown only when it parses as an entry AND that entry would be
/// accepted by the same guard that writes one, and what is shown is this
/// crate's own re-serialization of the parsed fields rather than the bytes
/// from the file.
///
/// That claim is only worth as much as the guard's field coverage, so the
/// coverage is written down rather than asserted. Every field of
/// [`CodexAuditEntry`], and what constrains it:
///
/// | field | what makes it safe to render |
/// |-------|------------------------------|
/// | `ts` | a `jiff::Timestamp`; a value that is not RFC 3339 fails to parse, and what is rendered is jiff's own formatting, not the file's bytes |
/// | `agctl_pid` | a `u32` |
/// | `provider` | [`entry_line`]: equal to [`PROVIDER`], a word this build compiled in |
/// | `user_id`, `account_id` | [`entry_line`]: `validate_codex_segment` |
/// | `outcome` | a `CodexOutcome`; an unknown discriminant fails to parse |
/// | `class` | [`entry_line`]: one of [`CLASSES`] |
/// | `digest8_before`, `digest8_after` | [`entry_line`]: [`is_digest8`] |
/// | `keychain_account` | [`entry_line`]: [`home::is_home_account`], and only on one outcome |
///
/// plus the whole-line refusal of any `@`. Adding a field to
/// [`CodexAuditEntry`] without adding a row here and a rule to [`entry_line`]
/// re-opens exactly the hole `provider` was (review S37-b1b, F1): a field
/// nothing checks is a field the file controls.
pub fn shown_line(line: &str) -> Option<String> {
    let entry: CodexAuditEntry = serde_json::from_str(line).ok()?;
    entry_line(&entry).ok().map(|line| line.trim_end().to_owned())
}

/// The `Codex Auth` accounts this log records a refused login child as having
/// gained, oldest first and each named once.
///
/// `doctor` asks this before it offers to remove a keychain item: an item is
/// agctl's to name only when agctl's own log says agctl caused it (plan
/// section 3.3, "a `Codex Auth` keychain item agctl's login child caused and
/// refused (`listing gained` in the audit)"). The whole log is read, not the
/// tail `doctor` displays — a login refused a thousand writes ago still left
/// the item behind.
///
/// Every account is re-checked against [`home::is_home_account`] on the way
/// out, exactly as [`entry_line`] checked it on the way in. It was checked
/// when it was written, but a log is a file on a disk, and the caller puts
/// this string inside a command a person is invited to paste: a line whose
/// field has any other shape is not a gained item, it is a malformed line,
/// and it is passed over like any other.
///
/// The log is read a line at a time ([`audit::for_each_line_at`]), never as
/// one string: this asks a question about the whole history, and the history
/// only grows. [`MAX_ENTRY_BYTES`] bounds what one line may cost.
///
/// # Errors
///
/// As [`read`]. A log that cannot be read is not an empty log, and the caller
/// must not be left unable to tell the two apart; it is told.
///
/// [`home::is_home_account`]: crate::provider::codex::home::is_home_account
/// [`audit::for_each_line_at`]: crate::secret::audit::for_each_line_at
pub fn gained_keychain_accounts(paths: &Paths) -> Result<Vec<String>, AppError> {
    let shown = log_path(paths);
    let root = match file_store::open_dir_under(paths.config_dir(), &paths.codex_root()) {
        Ok(root) => root,
        Err(file_store::FileStoreError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(Vec::new());
        }
        Err(err) => return Err(AppError::Config(err.to_string())),
    };
    let mut found: Vec<String> = Vec::new();
    audit::for_each_line_at(root.as_fd(), LOG_FILE, &shown, MAX_ENTRY_BYTES, |line| {
        let Ok(entry) = serde_json::from_str::<CodexAuditEntry>(line) else { return };
        if entry.outcome != CodexOutcome::LoginKeychainGained {
            return;
        }
        let Some(account) = entry.keychain_account else { return };
        if home::is_home_account(&account) && !found.contains(&account) {
            found.push(account);
        }
    })?;
    Ok(found)
}

/// The whole log, or `None` when there is none (for `doctor`).
///
/// # Errors
///
/// The reader's refusals (`secret::audit::read_log_at`).
pub fn read(paths: &Paths) -> Result<Option<String>, AppError> {
    let root = match file_store::open_dir_under(paths.config_dir(), &paths.codex_root()) {
        Ok(root) => root,
        Err(file_store::FileStoreError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(None);
        }
        Err(err) => return Err(AppError::Config(err.to_string())),
    };
    audit::read_log_at(root.as_fd(), LOG_FILE, &log_path(paths))
}

fn entry(
    ids: (&str, &str),
    outcome: CodexOutcome,
    class: Option<&str>,
    digest8_before: Option<&str>,
    digest8_after: Option<&str>,
) -> CodexAuditEntry {
    CodexAuditEntry {
        ts: Timestamp::now(),
        agctl_pid: std::process::id(),
        provider: PROVIDER.to_owned(),
        user_id: ids.0.to_owned(),
        account_id: ids.1.to_owned(),
        outcome,
        class: class.map(str::to_owned),
        digest8_before: digest8_before.map(str::to_owned),
        digest8_after: digest8_after.map(str::to_owned),
        keychain_account: None,
    }
}

/// The entry as the line the log holds, after the field guard.
fn entry_line(entry: &CodexAuditEntry) -> Result<String, AppError> {
    for id in [&entry.user_id, &entry.account_id] {
        validate_codex_segment(id).map_err(|_| {
            AppError::Config(format!(
                "a Codex audit entry's id is not a namespace segment ({} characters); the log holds ids only",
                id.len()
            ))
        })?;
    }
    for (field, value) in
        [("digest8_before", &entry.digest8_before), ("digest8_after", &entry.digest8_after)]
    {
        if let Some(value) = value
            && !is_digest8(value)
        {
            return Err(AppError::Config(format!(
                "a Codex audit entry's `{field}` must be 8 lowercase hex digits, not {} characters",
                value.len()
            )));
        }
    }
    if entry.provider != PROVIDER {
        return Err(AppError::Config(format!(
            "a Codex audit entry's provider is not `{PROVIDER}` ({} characters); the log holds \
             this provider's lines only",
            entry.provider.len()
        )));
    }
    // Two-sided, so neither half can drift: the keychain account belongs to
    // that one outcome and to no other, that outcome is meaningless without
    // it, and its spelling is the one agctl itself writes. `doctor` puts this
    // value into a command a person pastes into a shell, so the line is
    // refused rather than written if any of the three fails.
    match (entry.outcome, &entry.keychain_account) {
        (CodexOutcome::LoginKeychainGained, Some(account)) if home::is_home_account(account) => {}
        (CodexOutcome::LoginKeychainGained, _) => {
            return Err(AppError::Config(
                "a Codex audit entry claims a gained keychain item without an account spelled \
                 `cli|` and sixteen lowercase hex digits"
                    .to_owned(),
            ));
        }
        (_, Some(_)) => {
            return Err(AppError::Config(
                "a Codex audit entry carries a keychain account on an outcome that has none"
                    .to_owned(),
            ));
        }
        (_, None) => {}
    }
    if let Some(class) = &entry.class
        && !CLASSES.contains(&class.as_str())
    {
        return Err(AppError::Config(format!(
            "a Codex audit entry's class is not one of the fixed words ({} characters)",
            class.len()
        )));
    }
    let mut line = serde_json::to_string(entry).map_err(|err| {
        AppError::Config(format!("a Codex audit entry could not be serialized: {err}"))
    })?;
    if line.contains('@') {
        return Err(AppError::Config(
            "a Codex audit entry would carry an `@`; the log holds no email address".to_owned(),
        ));
    }
    line.push('\n');
    Ok(line)
}

/// Opens the log under `codex_root()` and appends one checked line.
fn write_entry(paths: &Paths, entry: &CodexAuditEntry) -> Result<(), AppError> {
    let line = entry_line(entry)?;
    let shown = log_path(paths);
    let root = file_store::create_dir_under(paths.config_dir(), &paths.codex_root())
        .map_err(|err| AppError::Config(err.to_string()))?;
    let file = audit::open_log_at(root.as_fd(), LOG_FILE, &shown)?;
    audit::write_line(&file, &shown, &line)
}

fn is_digest8(value: &str) -> bool {
    value.len() == 8 && value.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A timestamp as an RFC 3339 string.
mod rfc3339 {
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

#[cfg(test)]
#[path = "audit_tests.rs"]
mod tests;
