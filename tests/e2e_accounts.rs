#![cfg(feature = "testing")]

//! `accounts` and `doctor`, driven through the real binary.
//!
//! These commands are the ones that *remove* things, so the tests are mostly
//! about what they refuse. Invariant I1 says phase 1 never writes or deletes a
//! keychain item; invariant I9 says a namespace is only ever deleted under its
//! own lock, and never the lock itself; invariant I11 says agentctl removes a
//! Claude Code lock artefact in exactly one circumstance and no other. Each of
//! those is a sentence about something that must *not* happen, which is what
//! makes it worth asserting from outside the process.

mod common;

use std::fs;
use std::time::Duration;
use std::time::Instant;

use common::ACCT;
use common::EMAIL;
use common::Fixture;
use common::LIVE_SERVICE;
use common::ORG;
use predicates::str::contains;
use serde_json::Value;
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

/// The registry, parsed.
fn registry(fixture: &Fixture) -> Value {
    let text = fs::read_to_string(fixture.config_file()).expect("the registry should exist");
    serde_json::from_str(&text).expect("the registry should be JSON")
}

// ---------------------------------------------------------------------------
// AC26 — remove
// ---------------------------------------------------------------------------

#[test]
fn ac26_remove_without_delete_secret_leaves_the_credential_on_disk() {
    // Plan AC26: forgetting an account and destroying its refresh token are
    // different requests, and only the second one is irreversible.
    let fixture = owned_store();
    let path = fixture.credentials_path(ACCT, ORG);

    fixture
        .cmd()
        .args(["claude", "accounts", "remove", EMAIL])
        .assert()
        .success()
        .stdout(contains("--delete-secret"));

    assert!(path.exists(), "the credential is still there");
    assert!(
        registry(&fixture)["accounts"].as_array().expect("an array").is_empty(),
        "but the record is gone"
    );
}

#[test]
fn ac26_remove_with_delete_secret_clears_the_namespace_and_keeps_the_lock() {
    // Plan AC26 and invariant I9: the namespace goes, including any pending
    // write; the lock file — which lives *outside* the namespace and is never
    // unlinked — stays. Recreating a lock file would create a second inode two
    // processes could hold at once (the v6 race, premortem PM7).
    let fixture = owned_store();
    let ns_dir = fixture.ns_dir(ACCT, ORG);
    fs::write(ns_dir.join(".credentials.json.pending"), "{}").expect("writable");
    fs::write(ns_dir.join(".pending.meta"), "{}").expect("writable");

    // Take the lock once so the file exists before the removal runs.
    drop(common::hold_lock(&fixture.lock_path(ACCT, ORG)));

    fixture
        .cmd()
        .args(["claude", "accounts", "remove", EMAIL, "--delete-secret", "--yes"])
        .assert()
        .success()
        .stdout(contains("deleted its stored credentials"));

    assert!(!ns_dir.exists(), "the namespace is gone, pending files and all");
    assert!(fixture.lock_path(ACCT, ORG).exists(), "the lock file is never unlinked");
    assert!(registry(&fixture)["accounts"].as_array().expect("an array").is_empty());
}

#[test]
fn ac26_remove_refuses_a_read_only_row() {
    // Invariant I9 and I1: the credentials behind a keychain-backed row are
    // not agentctl's to delete, and phase 1 has no code path that could.
    let mut fixture = Fixture::new();
    fixture.with_keychain();
    let service = format!("{LIVE_SERVICE}-deadbeef");
    fixture.dump(&[&service]);
    fixture.keychain_item(
        &service,
        &common::blob("sk-ant-oat01-foreign", "sk-ant-ort01-foreign", common::fresh_at()),
    );
    fixture.write_registry(vec![fixture.config_dir_record(
        "44444444-4444-4444-4444-444444444444",
        "55555555-5555-5555-5555-555555555555",
        &service,
    )]);

    fixture
        .cmd()
        .args([
            "claude",
            "accounts",
            "remove",
            "44444444-4444-4444-4444-444444444444",
            "--delete-secret",
            "--yes",
        ])
        .assert()
        .code(1)
        .stderr(contains("never writes or deletes"))
        .stderr(contains("accounts forget"));

    assert_eq!(
        registry(&fixture)["accounts"].as_array().expect("an array").len(),
        1,
        "a refusal changes nothing"
    );
    fixture.assert_keychain_read_only();
}

#[test]
fn ac26_remove_waits_for_the_namespace_lock_and_then_refuses() {
    // Plan AC26's last clause: a `status` mid-refresh holds this lock, and
    // deleting the namespace under it would pull the directory out from
    // beneath a rename. So the removal waits — bounded — and then declines,
    // rather than proceeding without the lock.
    let fixture = owned_store();
    let guard = common::hold_lock(&fixture.lock_path(ACCT, ORG));

    let started = Instant::now();
    fixture
        .cmd()
        .args(["claude", "accounts", "remove", EMAIL, "--delete-secret", "--yes"])
        .assert()
        .code(2)
        .stderr(contains("could not take the namespace lock"));
    let elapsed = started.elapsed();

    assert!(
        elapsed >= Duration::from_secs(4),
        "the removal should have waited out the command lock timeout, not given up at once \
         (took {elapsed:?})"
    );
    assert!(fixture.credentials_path(ACCT, ORG).exists(), "nothing was deleted");
    drop(guard);
}

// ---------------------------------------------------------------------------
// AC40 — relocate
// ---------------------------------------------------------------------------

#[test]
fn ac40_relocate_moves_an_unknown_org_namespace_and_clears_its_pending() {
    // Plan AC40, decision D-008: a login that could not name an organization
    // lands in `_unknown-org`, and this is how it gets its real name once the
    // credential carries one. Invariant I9: the pending write it supersedes is
    // deleted first.
    let fixture = Fixture::new();
    let mut record = fixture.owned_record(ACCT, common::UNKNOWN_ORG);
    record["organization_uuid"] = json!(common::UNKNOWN_ORG);
    fixture.write_registry(vec![record]);
    fixture.write_credentials(
        ACCT,
        common::UNKNOWN_ORG,
        &common::blob("sk-ant-oat01-owned", "sk-ant-ort01-owned", common::fresh_at()),
    );
    let source = fixture.ns_dir(ACCT, common::UNKNOWN_ORG);
    fs::write(source.join(".credentials.json.pending"), "{}").expect("writable");
    fs::write(source.join(".pending.meta"), "{}").expect("writable");

    fixture
        .cmd()
        .args(["claude", "accounts", "relocate", ACCT, "--yes"])
        .assert()
        .success()
        .stdout(contains("Relocated"));

    let target = fixture.ns_dir(ACCT, ORG);
    assert!(target.join(".credentials.json").exists(), "the credential moved to the real org");
    assert_eq!(common::mode_of(&target.join(".credentials.json")), 0o600);
    assert!(!source.exists(), "and the `_unknown-org` namespace is gone with its pending files");
    assert_eq!(registry(&fixture)["accounts"][0]["organization_uuid"], json!(ORG));
    assert_eq!(
        registry(&fixture)["accounts"][0]["kind"]["export_spelling"],
        json!(common::export_spelling(&target)),
        "the recorded spelling follows the namespace"
    );
}

#[test]
fn ac40_relocate_refuses_when_the_target_is_occupied() {
    // Plan AC40: a different credential already at the target is somebody
    // else's account. Overwriting it would destroy a refresh chain.
    let fixture = Fixture::new();
    let mut record = fixture.owned_record(ACCT, common::UNKNOWN_ORG);
    record["organization_uuid"] = json!(common::UNKNOWN_ORG);
    fixture.write_registry(vec![record]);
    fixture.write_credentials(
        ACCT,
        common::UNKNOWN_ORG,
        &common::blob("sk-ant-oat01-owned", "sk-ant-ort01-owned", common::fresh_at()),
    );
    let occupant = fixture.write_credentials(
        ACCT,
        ORG,
        &common::blob("sk-ant-oat01-other", "sk-ant-ort01-other", common::fresh_at()),
    );
    let before = fs::read(&occupant).expect("readable");

    fixture.cmd().args(["claude", "accounts", "relocate", ACCT, "--yes"]).assert().code(1);

    assert_eq!(fs::read(&occupant).expect("readable"), before, "the occupant is untouched");
    assert!(
        fixture.ns_dir(ACCT, common::UNKNOWN_ORG).join(".credentials.json").exists(),
        "and the source is still where it was"
    );
}

// ---------------------------------------------------------------------------
// AC47 — forget and unforget
// ---------------------------------------------------------------------------

#[test]
fn ac47_forget_hides_a_service_without_ever_reading_it_again() {
    // Plan AC47: `forget` is a display decision, recorded in agentctl's own
    // registry. The keychain item is not touched — not written, not deleted,
    // and after this, not even read (the check happens before the
    // `find-generic-password`, invariant I1).
    let mut fixture = Fixture::new();
    fixture.with_keychain();
    let service = format!("{LIVE_SERVICE}-deadbeef");
    fixture.dump(&[&service]);
    fixture.keychain_item(
        &service,
        &common::blob("sk-ant-oat01-unclaimed", "sk-ant-ort01-unclaimed", common::fresh_at()),
    );

    fixture.cmd().args(["claude", "status"]).assert().stdout(contains("unclaimed"));

    fixture
        .cmd()
        .args(["claude", "accounts", "forget", &service])
        .assert()
        .success()
        .stdout(contains("hidden"));

    let before = fixture.security_log().len();
    let assert = fixture.cmd().args(["claude", "status"]).assert();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).expect("stdout is UTF-8");
    assert!(!stdout.contains("unclaimed"), "the row is hidden from `status`:\n{stdout}");
    let after: Vec<String> = fixture.security_log().split_off(before);
    assert!(
        after.iter().all(|line| !line.contains(&service)),
        "a forgotten item costs no keychain read: {after:?}"
    );

    fixture
        .cmd()
        .args(["claude", "accounts", "list", "--all"])
        .assert()
        .success()
        .stdout(contains("forgotten"));

    fixture
        .cmd()
        .args(["claude", "accounts", "unforget", &service])
        .assert()
        .success()
        .stdout(contains("reported again"));
    fixture.cmd().args(["claude", "status"]).assert().stdout(contains("unclaimed"));

    assert!(
        fs::read_to_string(fixture.keychain_item_path(&service)).is_ok(),
        "the keychain item itself was never removed"
    );
    fixture.assert_keychain_read_only();
}

// ---------------------------------------------------------------------------
// AC45 — doctor
// ---------------------------------------------------------------------------

#[test]
fn ac45_doctor_reports_every_part_of_the_store() {
    // Plan AC45: one report that names what is on this machine — the
    // preflight, expiries, lock bodies, stray temporaries, pending writes,
    // hidden siblings, duplicates and `_unknown-org` namespaces — so a user
    // does not have to know which file to look in.
    let mut fixture = Fixture::new();
    fixture.with_keychain();
    let service = format!("{LIVE_SERVICE}-deadbeef");
    fixture.dump(&[LIVE_SERVICE, &service]);
    let same = common::blob("sk-ant-oat01-live", "sk-ant-ort01-live", common::fresh_at());
    fixture.keychain_item(LIVE_SERVICE, &same);
    fixture.keychain_item(&service, &same);

    let mut unknown = fixture.owned_record(ACCT, common::UNKNOWN_ORG);
    unknown["organization_uuid"] = json!(common::UNKNOWN_ORG);
    fixture.write_registry(vec![unknown]);
    let ns_dir = fixture.ns_dir(ACCT, common::UNKNOWN_ORG);
    fixture.write_credentials(
        ACCT,
        common::UNKNOWN_ORG,
        &common::blob("sk-ant-oat01-owned", "sk-ant-ort01-owned", common::fresh_at()),
    );
    fs::write(ns_dir.join(".credentials.json.pending"), "{}").expect("writable");
    fs::write(ns_dir.join(".pending.meta"), "{}").expect("writable");
    fs::write(ns_dir.join(".credentials.json.tmp.0123abcd"), "{}").expect("writable");

    // A held lock, so the report has a body to describe.
    let guard = common::hold_lock(&fixture.lock_path(ACCT, common::UNKNOWN_ORG));
    fs::write(
        fixture.lock_path(ACCT, common::UNKNOWN_ORG),
        json!({ "pid": std::process::id(), "pid_start_time": null, "acquired_at": "2026-09-08T00:00:00Z" })
            .to_string(),
    )
    .expect("the lock body should be writable");

    let assert = fixture
        .cmd()
        .args(["claude", "doctor"])
        .assert()
        .success()
        .stdout(contains("preflight        unlocked"))
        .stdout(contains("live service     Claude Code-credentials"))
        .stdout(contains("pending write"))
        .stdout(contains("pending meta"))
        .stdout(contains("stray tmp"))
        .stdout(contains("no Claude Code lock artefacts"))
        .stdout(contains("namespace locks"))
        .stdout(contains("held locks"))
        .stdout(contains(format!("{ACCT}/{}", common::UNKNOWN_ORG)))
        .stdout(contains("accounts relocate"));

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).expect("stdout is UTF-8");
    assert!(stdout.contains("access in "), "expiries are reported:\n{stdout}");
    assert!(
        stdout.contains(&format!("pid {}", std::process::id())),
        "the lock body names its holder:\n{stdout}"
    );
    drop(guard);
    fixture.assert_keychain_read_only();
}

#[test]
fn ac45_doctor_remove_stale_refuses_everything_it_should() {
    // Invariant I11, the four refusals. Each of them is a path somebody could
    // plausibly type, and each would do real damage if it were honoured.
    let fixture = owned_store();
    let ns_dir = fixture.ns_dir(ACCT, ORG);

    // Its own namespace lock: `flock` binds an inode, so unlinking one is how
    // two processes end up holding "the lock" at the same time.
    drop(common::hold_lock(&fixture.lock_path(ACCT, ORG)));
    fixture
        .cmd()
        .args([
            "claude",
            "doctor",
            "--remove-stale",
            &fixture.lock_path(ACCT, ORG).to_string_lossy(),
            "--yes",
        ])
        .assert()
        .code(1)
        .stderr(contains("never unlinked"));

    // Not an artefact name at all.
    fixture
        .cmd()
        .args([
            "claude",
            "doctor",
            "--remove-stale",
            &ns_dir.join(".credentials.json").to_string_lossy(),
            "--yes",
        ])
        .assert()
        .code(1)
        .stderr(contains("not a Claude Code lock artefact"));

    // A regular file at an artefact's name. Claude Code makes its locks with
    // `mkdir` (fact F45), so this was written by something else: it is
    // reported as anomalous and never removed (`agentctl-nz5`, AC73).
    let anomalous = ns_dir.join(".storage-write");
    fs::write(&anomalous, "{}").expect("writable");
    age(&anomalous);
    fixture
        .cmd()
        .args(["claude", "doctor", "--remove-stale", &anomalous.to_string_lossy(), "--yes"])
        .assert()
        .code(1)
        .stderr(contains("anomalous (regular file; Claude Code makes lock directories)"));
    assert!(anomalous.exists());

    // A real artefact — a directory, as Claude Code makes it — but younger
    // than the staleness threshold: a session that is starting up looks
    // exactly like this.
    let fresh = ns_dir.join(".oauth_refresh.lock");
    fs::create_dir(&fresh).expect("the lock directory should be creatable");
    fixture
        .cmd()
        .args(["claude", "doctor", "--remove-stale", &fresh.to_string_lossy(), "--yes"])
        .assert()
        .code(1)
        .stderr(contains("staleness threshold"));
    assert!(fresh.exists());

    // Old enough, but without `--yes`.
    age(&fresh);
    fixture
        .cmd()
        .args(["claude", "doctor", "--remove-stale", &fresh.to_string_lossy()])
        .assert()
        .code(1)
        .stderr(contains("`--yes` is required"))
        .stdout(contains("This is Claude Code's lock, not agentctl's"));
    assert!(fresh.exists(), "nothing was removed");
    assert!(fixture.credentials_path(ACCT, ORG).exists());
}

#[test]
fn ac45_doctor_remove_stale_removes_a_lapsed_artefact_after_two_samples() {
    // The one deletion invariant I11 allows, and the two-sample check that
    // gates it. Claude Code's holder heartbeats every five seconds (fact F31),
    // so twelve seconds of an unchanged mtime is the evidence that nothing is
    // holding this. The test really does wait for it: the interval is the
    // safety property, not an implementation detail to be stubbed out.
    let fixture = owned_store();
    let artefact = fixture.ns_dir(ACCT, ORG).join(".oauth_refresh.lock");
    // A directory, because that is what Claude Code's `mkdir` leaves (fact
    // F45). Phase 1's fixture wrote a regular file here, which is the whole of
    // why AC45 passed against a command that could not remove a real artefact
    // (`agentctl-nz5`, AC73).
    fs::create_dir(&artefact).expect("the lock directory should be creatable");
    age(&artefact);

    let started = Instant::now();
    fixture
        .cmd()
        .args(["claude", "doctor", "--remove-stale", &artefact.to_string_lossy(), "--yes"])
        .assert()
        .success()
        .stdout(contains("two samples 12s apart"))
        .stdout(contains("Removed"));
    let elapsed = started.elapsed();

    assert!(!artefact.exists(), "the lapsed artefact was removed");
    assert!(
        elapsed >= Duration::from_secs(11),
        "the second sample must actually be taken (took {elapsed:?})"
    );
    assert!(fixture.credentials_path(ACCT, ORG).exists(), "and nothing else was touched");
}

/// Backdates a file past the staleness threshold.
///
/// Through `touch(1)` rather than a crate: setting an mtime is the whole of
/// what is needed, and `/usr/bin/touch` is on every machine this runs on.
fn age(path: &std::path::Path) {
    let status = std::process::Command::new("/usr/bin/touch")
        .args(["-t", "202601010000.00"])
        .arg(path)
        .status()
        .expect("`touch` should be runnable");
    assert!(status.success(), "`touch` failed: {status}");
}
