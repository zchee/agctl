//! Which store holds one account's credentials, and what happens when it
//! cannot be read.
//!
//! # The divergence from Claude Code, stated plainly
//!
//! Claude Code's composed store is "keychain, and if that does not work, the
//! file" (fact F35). Its non-strict read treats *any* keychain failure — no
//! item, an error, a throttle — as a reason to fall through to
//! `.credentials.json`. That is right for Claude Code, which must start a
//! session somehow.
//!
//! agctl does not do that (invariant I10). For a keychain-backed row a
//! keychain failure is [`Resolved::Transient`], and the file is not consulted
//! at all. The reason is that the two stores can hold *different*
//! credentials: on the machine this was developed against, the live keychain
//! item and the item for the same directory's other spelling are different
//! accounts (facts F6, F41). Falling back would mean showing one account's
//! usage under another's row, and — worse — deciding a namespace was free to
//! write when a session owned it.
//!
//! So the rule is by kind:
//!
//! | kind | source | on failure |
//! |------|--------|------------|
//! | [`Live`](crate::config::AccountKind::Live) | keychain | transient; never the file |
//! | [`ConfigDirReadOnly`](crate::config::AccountKind::ConfigDirReadOnly) | keychain | transient; never the file |
//! | [`Owned`](crate::config::AccountKind::Owned) | file | transient |
//! | [`Foreign`](crate::config::AccountKind::Foreign) | nothing | absent |

#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "remaining items are consumed by W2 (accounts, import, doctor) and W3 (watch)"
    )
)]

use crate::config::AccountKind;
use crate::config::AccountRecord;
use crate::config::paths::Paths;
use crate::provider::claude::credentials::Credentials;
use crate::provider::claude::namespace;
use crate::provider::claude::namespace::EnvView;
use crate::secret::KeychainError;
use crate::secret::KeychainReader;
use crate::secret::file_store;
use crate::secret::file_store::ReadOutcome;

/// What resolving one account's credentials produced.
#[derive(Debug)]
pub enum Resolved {
    /// The credentials were read.
    Credentials(Box<Credentials>),
    /// There is no credential for this account. For an owned account this
    /// means `needs login`.
    Absent,
    /// The read failed in a way that might succeed next pass. Never a reason
    /// to consult another store.
    Transient(String),
    /// The keychain is locked. Split out from `Transient` because the row
    /// tells the user to unlock rather than to retry.
    Locked,
}

/// Reads one account's credentials from wherever they live.
pub fn resolve(
    kind: &AccountKind,
    record: &AccountRecord,
    paths: &Paths,
    reader: &dyn KeychainReader,
    env: &EnvView,
) -> Resolved {
    match kind {
        AccountKind::Live => from_keychain(reader, &namespace::service_name(env)),
        AccountKind::ConfigDirReadOnly { service, .. } => from_keychain(reader, service),
        AccountKind::Owned { .. } => {
            let ns_dir = paths.namespace_dir(&record.account_uuid, &record.organization_uuid);
            from_file(&ns_dir)
        }
        // Somebody else's credential: agctl never reads it, so as far as
        // this store is concerned there is nothing there.
        AccountKind::Foreign { .. } => Resolved::Absent,
    }
}

/// Reads one keychain item, without ever falling through to a file.
pub fn from_keychain(reader: &dyn KeychainReader, service: &str) -> Resolved {
    match reader.read(service) {
        Ok(Some(bytes)) => parse(&bytes),
        Ok(None) => Resolved::Absent,
        Err(KeychainError::Locked) => Resolved::Locked,
        Err(err) => Resolved::Transient(err.to_string()),
    }
}

/// Reads a namespace's `.credentials.json`.
pub fn from_file(ns_dir: &std::path::Path) -> Resolved {
    match file_store::read_credentials(ns_dir) {
        Ok(ReadOutcome::Present { bytes, .. }) => parse(&bytes),
        Ok(ReadOutcome::Absent) => Resolved::Absent,
        Err(err) => Resolved::Transient(err.to_string()),
    }
}

/// Reads a namespace's adopted copy —
/// [`ADOPTED_FILE`](file_store::ADOPTED_FILE), the credential a hot-swap
/// displaced (decision D-024).
///
/// This is the source for a row whose keychain item is held by another
/// identity: after a swap the item names the incoming account, so the item is
/// no longer the record's credential and reading it would show one account's
/// usage under another's row — the exact confusion the table at the top of
/// this module refuses to risk. The record's own credential is here instead
/// (ruling OQ2(d); rendered as
/// [`AccountState::Adopted`](crate::provider::claude::account::AccountState::Adopted)).
///
/// [`Resolved::Absent`] is a real answer and not an error: a row is only read
/// this way once something has been adopted into it.
pub fn from_adopted(ns_dir: &std::path::Path) -> Resolved {
    match file_store::read_adopted(ns_dir) {
        Ok(ReadOutcome::Present { bytes, .. }) => parse(&bytes),
        Ok(ReadOutcome::Absent) => Resolved::Absent,
        Err(err) => Resolved::Transient(err.to_string()),
    }
}

/// Parses a blob, reporting a corrupt one as transient rather than absent.
///
/// Absent would lead to writing a new file over the corrupt one; transient
/// leaves it alone for the user — or `doctor` — to look at.
fn parse(bytes: &[u8]) -> Resolved {
    match Credentials::parse_blob(bytes) {
        Ok(credentials) => Resolved::Credentials(Box::new(credentials)),
        Err(err) => Resolved::Transient(err.to_string()),
    }
}

#[cfg(test)]
#[path = "location_tests.rs"]
mod tests;
