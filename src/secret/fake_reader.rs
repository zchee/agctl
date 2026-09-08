//! A scripted [`KeychainReader`] for unit tests.
//!
//! Not a `*_tests.rs` file because it holds no tests: it is the double that
//! several modules' tests drive, and a `mod tests` cannot be reached from a
//! sibling module. Gated to `cfg(test)` so it never exists in a shipped
//! binary — the end-to-end suite drives the real reader against the fake
//! `security` script from [`crate::secret::fake_security`] instead.

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::secret::KeychainError;
use crate::secret::KeychainReader;
use crate::secret::KeychainStatus;
use crate::secret::ServiceEntry;

/// A reader that answers from a script and records what it was asked.
#[derive(Debug)]
pub struct FakeReader {
    /// What [`KeychainReader::preflight`] returns.
    pub preflight: KeychainStatus,
    /// What [`KeychainReader::list_services`] returns, before prefix
    /// filtering.
    pub entries: Vec<ServiceEntry>,
    /// Per-service answers. A service with no entry reads as `Ok(None)`.
    pub items: BTreeMap<String, ItemAnswer>,
    /// Every service `read` was called with, in order. Plan AC20 asserts that
    /// a namespace with no listed item issues no read at all.
    pub reads: Mutex<Vec<String>>,
}

/// One scripted answer to a `read`.
#[derive(Debug, Clone)]
pub enum ItemAnswer {
    /// The item is there, holding this blob.
    Blob(Vec<u8>),
    /// The item is not there.
    Missing,
    /// The read failed.
    Failed(KeychainError),
}

impl FakeReader {
    /// An unlocked, empty keychain.
    pub fn unlocked() -> Self {
        Self {
            preflight: KeychainStatus::Unlocked,
            entries: Vec::new(),
            items: BTreeMap::new(),
            reads: Mutex::new(Vec::new()),
        }
    }

    /// Adds a listing entry, as `dump-keychain` would report it.
    pub fn with_entry(mut self, service: &str) -> Self {
        self.entries.push(ServiceEntry {
            service: service.to_owned(),
            account: Some("example".to_owned()),
            cdat: None,
            mdat: None,
        });
        self
    }

    /// Adds a readable item, and its listing entry.
    pub fn with_item(mut self, service: &str, blob: &[u8]) -> Self {
        self.items.insert(service.to_owned(), ItemAnswer::Blob(blob.to_vec()));
        self = self.with_entry(service);
        self
    }

    /// Adds a listing entry whose item has since been deleted, which is what
    /// a `dump-keychain` snapshot going stale mid-pass looks like.
    pub fn with_deleted_item(mut self, service: &str) -> Self {
        self.items.insert(service.to_owned(), ItemAnswer::Missing);
        self = self.with_entry(service);
        self
    }

    /// Adds a listed item whose read fails.
    pub fn with_failure(mut self, service: &str, err: KeychainError) -> Self {
        self.items.insert(service.to_owned(), ItemAnswer::Failed(err));
        self = self.with_entry(service);
        self
    }

    /// Sets the preflight answer.
    pub fn with_preflight(mut self, status: KeychainStatus) -> Self {
        self.preflight = status;
        self
    }

    /// The services `read` has been called with.
    pub fn reads(&self) -> Vec<String> {
        match self.reads.lock() {
            Ok(reads) => reads.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

impl KeychainReader for FakeReader {
    fn preflight(&self) -> KeychainStatus {
        self.preflight.clone()
    }

    fn list_services(&self, prefix: &str) -> Result<Vec<ServiceEntry>, KeychainError> {
        Ok(self.entries.iter().filter(|e| e.service.starts_with(prefix)).cloned().collect())
    }

    fn read(&self, service: &str) -> Result<Option<Vec<u8>>, KeychainError> {
        match self.reads.lock() {
            Ok(mut reads) => reads.push(service.to_owned()),
            Err(poisoned) => poisoned.into_inner().push(service.to_owned()),
        }
        match self.items.get(service) {
            Some(ItemAnswer::Blob(blob)) => Ok(Some(blob.clone())),
            Some(ItemAnswer::Missing) | None => Ok(None),
            Some(ItemAnswer::Failed(err)) => Err(err.clone()),
        }
    }
}
