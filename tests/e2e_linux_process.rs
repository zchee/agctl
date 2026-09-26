#![cfg(all(feature = "testing", target_os = "linux"))]

//! Linux process consumers, through the real binary and isolated stores only.

mod common;

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::time::SystemTime;

use common::Fixture;
use serde_json::Value;
use serde_json::json;

const REFUSAL: &str =
    "stale lock removal unsupported on this platform: peer visibility is unproved";
const CODEX_USER: &str = "user-linux-process-0001";
const CODEX_ACCT: &str = "11111111-2222-4333-8444-555555555555";

type Entry = (PathBuf, u32, u64, SystemTime, Vec<u8>);

fn manifest(root: &Path) -> Vec<Entry> {
    fn walk(root: &Path, at: &Path, rows: &mut Vec<Entry>) {
        for entry in fs::read_dir(at).expect("read fixture tree") {
            let path = entry.expect("entry").path();
            let meta = fs::symlink_metadata(&path).expect("metadata");
            let bytes =
                if meta.is_file() { fs::read(&path).expect("fixture bytes") } else { Vec::new() };
            rows.push((
                path.strip_prefix(root).expect("below fixture").to_owned(),
                meta.mode(),
                meta.len(),
                meta.modified().expect("mtime"),
                bytes,
            ));
            if meta.is_dir() {
                walk(root, &path, rows);
            }
        }
    }
    let mut rows = Vec::new();
    walk(root, root, &mut rows);
    rows.sort();
    rows
}

fn write_record(path: &Path, document: &Value) {
    fs::create_dir_all(path.parent().expect("record parent")).expect("record directory");
    fs::write(path, serde_json::to_vec(document).expect("fixture JSON")).expect("write record");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("record mode");
}

fn own_domain_identity(ticks: u64) -> String {
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").expect("boot UUID");
    let namespace = fs::metadata("/proc/self/ns/pid").expect("PID namespace");
    format!(
        "linux-v1:{}:{}:{}:{ticks}:{}",
        boot.trim(),
        namespace.dev(),
        namespace.ino(),
        rustix::process::getuid().as_raw()
    )
}

fn age(path: &Path) {
    let time = rustix::fs::Timespec { tv_sec: 1, tv_nsec: 0 };
    rustix::fs::utimensat(
        rustix::fs::CWD,
        path,
        &rustix::fs::Timestamps { last_access: time, last_modification: time },
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .expect("old lock");
}

#[test]
fn linux_doctor_stale_refuses() {
    let fixture = Fixture::new();
    let namespace = fixture.ns_dir(common::ACCT, common::ORG);
    fs::create_dir_all(&namespace).expect("owned namespace");
    let in_root = namespace.join(".oauth_refresh.lock");
    fs::create_dir(&in_root).expect("peer lock");
    age(&in_root);
    let outside = fixture.home().join("isolated-store");
    fs::create_dir(&outside).expect("scratch live-style store");
    let attested = outside.join(".oauth_refresh.lock");
    fs::create_dir(&attested).expect("attested peer lock");
    age(&attested);
    let mut child = Command::new("/bin/sleep").arg("600").spawn().expect("owned child");
    let pid = child.id();
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).expect("owned child's stat");
    let ticks = stat
        .rsplit_once(')')
        .expect("stat envelope")
        .1
        .split_ascii_whitespace()
        .nth(19)
        .expect("field 22")
        .parse::<u64>()
        .expect("ticks");
    let identity = own_domain_identity(ticks);
    child.kill().expect("terminate owned child");
    child.wait().expect("reap owned child");
    let record = fixture.config_dir().join("claude/held-locks/dead.json");
    write_record(
        &record,
        &json!({
            "agctl_pid": pid, "agctl_start_time": identity, "tree": "live",
            "store_dir": outside, "paths": [attested], "taken_at": "fixture"
        }),
    );
    let before = manifest(&fixture.config_dir());
    let home_before = manifest(&fixture.home());
    for path in [&in_root, &attested, &fixture.scratch("absent/.oauth_refresh.lock")] {
        for yes in [false, true] {
            let mut command = fixture.cmd();
            command.args(["claude", "doctor", "--remove-stale"]).arg(path);
            if yes {
                command.arg("--yes");
            }
            let output = command.output().expect("doctor removal refusal");
            assert_eq!(output.status.code(), Some(1), "{output:?}");
            assert!(output.stdout.is_empty(), "no prompt, samples or removal hint: {output:?}");
            assert_eq!(
                String::from_utf8(output.stderr).expect("stderr"),
                format!("agctl: {REFUSAL}\n")
            );
            assert_eq!(
                manifest(&fixture.config_dir()),
                before,
                "no record, directory or file mutation"
            );
            assert_eq!(manifest(&fixture.home()), home_before, "no attested removal");
        }
    }
    assert!(in_root.is_dir() && attested.is_dir());
    let output = fixture.cmd().args(["claude", "doctor"]).output().expect("held report");
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).expect("report");
    assert!(text.contains("writer gone"), "valid same-domain ESRCH is diagnosed: {text}");
    assert!(text.contains(REFUSAL));
    assert!(!text.contains("doctor --remove-stale"), "no usable removal hint: {text}");

    let lock_path = fixture.lock_path(common::ACCT, common::ORG);
    let first = common::hold_lock(&lock_path);
    let second =
        fs::OpenOptions::new().read(true).write(true).open(&lock_path).expect("same flock inode");
    assert!(
        rustix::fs::flock(&second, rustix::fs::FlockOperation::NonBlockingLockExclusive).is_err()
    );
    drop(first);
    rustix::fs::flock(&second, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .expect("kernel releases namespace lock");
}

#[test]
fn linux_record_identity_guard() {
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.ns_dir(common::ACCT, common::ORG)).expect("owned namespace");
    fixture.write_registry_document(&json!({
        "version": 2,
        "accounts": [fixture.owned_record(common::ACCT, common::ORG)],
        "forgotten_services": [],
        "codex_accounts": [{
            "chatgpt_user_id": CODEX_USER, "chatgpt_account_id": CODEX_ACCT,
            "email": null, "plan_type": null, "label": null,
            "kind": { "kind": "owned", "export_spelling": "/fixture", "refresh": "auto" },
            "forgotten": false, "created_at": "2026-09-22T00:00:00Z"
        }]
    }));
    let claude_lock = fixture.lock_path(common::ACCT, common::ORG);
    let codex_lock =
        fixture.config_dir().join(format!("codex/.locks/{CODEX_USER}+{CODEX_ACCT}.lock"));
    let held_record = fixture.config_dir().join("claude/held-locks/unknown.json");
    let values = [
        Value::Null,
        json!("2026-09-22T00:00:00Z"),
        json!("Tue Sep 22 00:00:00 2026"),
        json!("linux-v2:unknown"),
        json!("linux-v1:malformed"),
        json!(own_domain_identity(0).replace("linux-v1", "foreign-v1")),
    ];
    for identity in values {
        let body = json!({ "pid": u32::MAX, "pid_start_time": identity, "acquired_at": "fixture" });
        write_record(&claude_lock, &body);
        write_record(&codex_lock, &body);
        write_record(
            &held_record,
            &json!({
                "agctl_pid": u32::MAX, "agctl_start_time": identity, "tree": "agctl",
                "store_dir": fixture.ns_dir(common::ACCT, common::ORG), "paths": [], "taken_at": "fixture"
            }),
        );
        let saved = [&claude_lock, &codex_lock, &held_record]
            .map(|path| fs::read(path).expect("saved record"));
        let output = fixture.cmd().args(["claude", "doctor"]).output().expect("Claude doctor");
        assert!(output.status.success(), "{output:?}");
        let text = String::from_utf8(output.stdout).expect("doctor text");
        assert!(text.contains("unknown holder identity"), "{text}");
        assert!(!text.contains("pid recycled"), "incomparable is not recycled: {text}");
        let output =
            fixture.cmd().args(["codex", "doctor", "--json"]).output().expect("Codex doctor");
        assert!(output.status.success(), "{output:?}");
        let document: Value = serde_json::from_slice(&output.stdout).expect("doctor JSON");
        let schema: Value = serde_json::from_str(include_str!("../schemas/codex-doctor.v1.json"))
            .expect("unchanged schema");
        jsonschema::validator_for(&schema)
            .expect("schema compiles")
            .validate(&document)
            .expect("Linux fixture conforms to unchanged schema");
        let namespace = &document["namespaces"][0];
        assert!(namespace["lock"].is_null(), "unknown lock uses null: {document}");
        assert!(
            namespace["notes"].as_array().expect("notes").iter().any(|note| note
                .as_str()
                .is_some_and(|text| text.contains("unknown holder identity"))),
            "{document}"
        );
        for (path, before) in [&claude_lock, &codex_lock, &held_record].into_iter().zip(saved) {
            assert_eq!(fs::read(path).expect("record still readable"), before, "no read migration");
        }
    }
}

#[test]
fn linux_keychain_boundary_refuses_without_a_spawn() {
    let mut fixture = Fixture::new();
    fixture.with_keychain();
    for selector in ["none", "security", ""] {
        fixture.set("AGCTL_KEYCHAIN_BACKEND", selector);
        let before = manifest(&fixture.config_dir());
        let output = fixture
            .cmd()
            .args(["claude", "import", "--from", "keychain"])
            .output()
            .expect("unsupported import");
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let error = String::from_utf8(output.stderr).expect("error text");
        assert_eq!(error, "agctl: unsupported on this platform\n");
        assert_eq!(manifest(&fixture.config_dir()), before);
        let output = fixture
            .cmd()
            .args(["claude", "status", "--json"])
            .output()
            .expect("unsupported live status");
        let text = String::from_utf8(output.stdout).expect("status text");
        assert!(text.contains("unsupported on this platform"), "{text}");
        assert!(
            !text.contains("keychain unavailable") && !text.contains("keychain locked"),
            "{text}"
        );
        assert!(fixture.security_log().is_empty(), "neither seam enables Linux security");
    }
}
