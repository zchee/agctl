#![cfg(feature = "testing")]

//! `doctor --remove-stale` outside agentctl's own namespace root (plan AC73,
//! section 3.9 row 2), driven through the real binary.
//!
//! Invariant I11′ confines every lock removal to
//! `<config-dir>/claude` — with exactly one exception, and this file is that
//! exception's test. When agentctl holds Claude Code's locks it writes a
//! held-lock record before its first `mkdir`, and a crash leaves the record
//! behind naming directories nothing else will ever remove. Those directories
//! can be in `~/.claude` by construction, so without this branch premortem PM9
//! — "every refresh said `lock_busy` for an hour" — would have no recovery
//! command at all (architect N-2, critic M1).
//!
//! The record's JSON is written literally here rather than through the crate's
//! own serializer: this binary has no library target, and a shape asserted
//! against itself would agree with itself whatever it spelled.

mod common;

use std::fs;
use std::path::Path;
use std::path::PathBuf;

use common::ACCT;
use common::Fixture;
use common::ORG;
use predicates::str::contains;
use serde_json::json;

/// A store with one owned account holding a fresh credential.
fn owned_store() -> Fixture {
    let fixture = Fixture::new();
    fixture.write_registry(vec![fixture.owned_record(ACCT, ORG)]);
    fixture.write_credentials(
        ACCT,
        ORG,
        &common::blob("sk-ant-oat01-owned", "sk-ant-ort01-owned", common::fresh_at()),
    );
    fixture
}

/// A process id that is certainly gone: a child that has run and been reaped.
fn dead_pid() -> u32 {
    let mut child =
        std::process::Command::new("/usr/bin/true").spawn().expect("`true` should be runnable");
    let pid = child.id();
    child.wait().expect("the child should be waitable");
    pid
}

/// Writes one held-lock record, in the shape `claude_lock` writes.
fn write_record(fixture: &Fixture, pid: u32, store_dir: &Path, held: &[&Path]) -> PathBuf {
    let dir = fixture.config_dir().join("claude").join("held-locks");
    fs::create_dir_all(&dir).expect("the held-locks directory should be creatable");
    let held: Vec<String> = held.iter().map(|path| path.to_string_lossy().into_owned()).collect();
    let record = json!({
        "agentctl_pid": pid,
        "tree": "live",
        "store_dir": store_dir.to_string_lossy(),
        "paths": held,
        "taken_at": "2026-09-09T12:00:00Z",
    });
    let file = dir.join(format!("{pid}.json"));
    fs::write(&file, record.to_string()).expect("the record should be writable");
    file
}

/// A lock directory in the live store, aged past the staleness threshold.
fn leak(fixture: &Fixture) -> PathBuf {
    let leaked = fixture.live_store_dir().join(".oauth_refresh.lock");
    fs::create_dir_all(&leaked).expect("the leaked lock directory should be creatable");
    age(&leaked);
    leaked
}

#[test]
fn ac73_remove_stale_clears_a_leak_a_dead_record_names() {
    // The whole recovery path, end to end: `doctor` names the leak, and the
    // command it prints removes it. The two-sample wait is real here for the
    // same reason it is real in AC45 — the interval is the safety property.
    let fixture = owned_store();
    let leaked = leak(&fixture);
    let record = write_record(&fixture, dead_pid(), &fixture.live_store_dir(), &[leaked.as_path()]);

    fixture
        .cmd()
        .args(["claude", "doctor"])
        .assert()
        .success()
        .stdout(contains("held locks"))
        .stdout(contains(record.to_string_lossy().into_owned()))
        .stdout(contains("the live store"))
        .stdout(contains(format!("--remove-stale {} --yes", leaked.display())));

    fixture
        .cmd()
        .args(["claude", "doctor", "--remove-stale", &leaked.to_string_lossy(), "--yes"])
        .assert()
        .success()
        .stdout(contains("is outside"))
        .stdout(contains(record.to_string_lossy().into_owned()))
        .stdout(contains("Removed"));

    assert!(!leaked.exists(), "the leaked lock directory is gone");
    assert!(fixture.live_store_dir().exists(), "and the store around it is untouched");
    assert!(fixture.credentials_path(ACCT, ORG).exists(), "as is everything agentctl owns");
}

#[test]
fn ac73_remove_stale_refuses_an_outside_path_without_a_dead_record() {
    // Three ways to be outside the namespace root and stay there: no record at
    // all, a record whose process is alive, and a record naming a different
    // path in the same store. None of them waits twelve seconds — the refusal
    // comes before anything is sampled.
    let fixture = owned_store();
    let leaked = leak(&fixture);

    fixture
        .cmd()
        .args(["claude", "doctor", "--remove-stale", &leaked.to_string_lossy(), "--yes"])
        .assert()
        .code(1)
        .stderr(contains("is not inside"));
    assert!(leaked.exists());

    // A live pid: the lock is held, not leaked.
    let live =
        write_record(&fixture, std::process::id(), &fixture.live_store_dir(), &[leaked.as_path()]);
    fixture
        .cmd()
        .args(["claude", "doctor", "--remove-stale", &leaked.to_string_lossy(), "--yes"])
        .assert()
        .code(1)
        .stderr(contains("is being held, not leaked"));
    assert!(leaked.exists());
    fs::remove_file(&live).expect("the record should be removable");

    // A dead pid, but the record names its sibling rather than this path.
    let sibling = fixture.live_store_dir().join(".storage-write");
    fs::create_dir_all(&sibling).expect("the sibling artefact should be creatable");
    age(&sibling);
    write_record(&fixture, dead_pid(), &fixture.live_store_dir(), &[sibling.as_path()]);
    fixture
        .cmd()
        .args(["claude", "doctor", "--remove-stale", &leaked.to_string_lossy(), "--yes"])
        .assert()
        .code(1)
        .stderr(contains("is not inside"));
    assert!(leaked.exists(), "the path no record names is still there");
    assert!(sibling.exists(), "and so is the one that was never asked about");
}

/// Backdates a path past the staleness threshold.
///
/// Through `touch(1)` rather than a crate: setting an mtime is the whole of
/// what is needed, and `/usr/bin/touch` is on every machine this runs on. It
/// sets a directory's timestamp as readily as a file's, which is what these
/// fixtures need.
fn age(path: &Path) {
    let status = std::process::Command::new("/usr/bin/touch")
        .args(["-t", "202601010000.00"])
        .arg(path)
        .status()
        .expect("`touch` should be runnable");
    assert!(status.success(), "`touch` failed: {status}");
}
