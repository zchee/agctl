#![cfg(feature = "testing")]

//! `doctor --remove-stale` outside agctl's own namespace root (plan AC73,
//! section 3.9 row 2), driven through the real binary.
//!
//! Invariant I11′ confines every lock removal to
//! `<config-dir>/claude` — with exactly one exception, and this file is that
//! exception's test. When agctl holds Claude Code's locks it writes a
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
    write_record_in(&fixture.held_locks_dir(), pid, store_dir, held)
}

/// [`write_record`], into a directory the caller names.
///
/// The planted-directory test needs a record that is *not* under the namespace
/// root, and a second spelling of the record's JSON is how a reader and a
/// writer end up disagreeing about a field name.
fn write_record_in(dir: &Path, pid: u32, store_dir: &Path, held: &[&Path]) -> PathBuf {
    fs::create_dir_all(dir).expect("the held-locks directory should be creatable");
    let held: Vec<String> = held.iter().map(|path| path.to_string_lossy().into_owned()).collect();
    let record = json!({
        "agctl_pid": pid,
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
    assert!(fixture.credentials_path(ACCT, ORG).exists(), "as is everything agctl owns");
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

#[test]
fn a_symlinked_held_locks_directory_authorises_no_removal() {
    // `agctl-dit`. After `1yj` the *writer* reaches `<namespace_root>/held-locks`
    // through an `O_NOFOLLOW` walk, and the reader still listed it by path — so
    // a same-uid planter chose the directory every record `doctor` reports came
    // from, and `Permit::Attested` is the only thing in agctl that lets a
    // removal leave the namespace root.
    //
    // Everything the permit asks for is true here: the record is in the shape
    // `claude_lock` writes, it names a real lock directory in the live store,
    // that directory is empty and aged past the threshold, and the process that
    // "wrote" the record is really dead. The one thing that is false is where
    // the directory holding it was found — which is now what decides it.
    let fixture = owned_store();
    let leaked = leak(&fixture);
    let pid = dead_pid();

    let planted = fixture.scratch("planted-held-locks");
    let record = write_record_in(&planted, pid, &fixture.live_store_dir(), &[leaked.as_path()]);
    std::os::unix::fs::symlink(&planted, fixture.held_locks_dir())
        .expect("the symlink should be creatable");

    // Nothing behind the link is reported. Pre-fix this section listed the
    // record under the name it would have had inside the root
    // (`held-locks/<pid>.json`) and offered the removal command for the leak.
    let output =
        fixture.cmd().args(["claude", "doctor"]).output().expect("`claude doctor` should run");
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("held locks"), "the section is still reported:\n{stdout}");
    assert!(
        !stdout.contains(&format!("{pid}.json")),
        "no record is read through the planted link:\n{stdout}"
    );
    assert!(
        !stdout.contains(&format!("--remove-stale {} --yes", leaked.display())),
        "and no removal outside the root is offered:\n{stdout}"
    );

    // And nothing behind it authorises one. The refusal is phase 1's sentence
    // for a path no record vouches for, which is what an unreadable
    // `held-locks` leaves true: it arrives before anything is sampled, so this
    // does not spend the two heartbeat intervals a permitted removal does.
    fixture
        .cmd()
        .args(["claude", "doctor", "--remove-stale", &leaked.to_string_lossy(), "--yes"])
        .assert()
        .code(1)
        .stderr(contains("is not inside"));

    assert!(leaked.exists(), "the leak the planted record named is still there");
    assert!(record.exists(), "and the planted record was neither read nor removed");
    assert!(
        fixture.held_locks_dir().symlink_metadata().is_ok_and(|meta| meta.is_symlink()),
        "the link itself is left exactly as it was found: agctl repairs nothing here"
    );
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
