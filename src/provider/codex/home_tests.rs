use std::cell::Cell;
use std::ffi::OsString;
use std::fs;
use std::path::Path;

use jiff::SignedDuration;
use jiff::Timestamp;

use super::*;
use crate::provider::codex::auth_store;
use crate::provider::codex::auth_store::CodexResolved;
use crate::provider::codex::testkit;

fn env(codex_home: Option<&str>, home: Option<&Path>) -> CodexEnv {
    CodexEnv::new(codex_home.map(OsString::from), home.map(Path::to_path_buf))
}

#[test]
fn codex_home_rules_through_an_injected_environment() {
    // Plan AC95 / facts F60, F86 — unit-only through `CodexEnv` (I25).
    let dir = tempfile::tempdir().expect("tempdir");
    let real = dir.path().join("real-home");
    fs::create_dir(&real).expect("mkdir");
    let link = dir.path().join("linked-home");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    let file = dir.path().join("a-file");
    fs::write(&file, b"x").expect("write");
    let user_home = dir.path().join("user");
    let canonical_real = real.canonicalize().expect("canonical");

    // unset → `$HOME/.codex`, not canonicalized even though it does not exist.
    assert_eq!(codex_home(&env(None, Some(&user_home))), Ok(user_home.join(".codex")));
    // empty → treated as unset (F86).
    assert_eq!(codex_home(&env(Some(""), Some(&user_home))), Ok(user_home.join(".codex")));
    // set + directory → canonical, through a link.
    assert_eq!(codex_home(&env(link.to_str(), Some(&user_home))), Ok(canonical_real.clone()));
    assert_eq!(codex_home(&env(real.to_str(), None)), Ok(canonical_real));
    // set + missing → unreadable, naming the path.
    let missing = dir.path().join("missing");
    let err = codex_home(&env(missing.to_str(), Some(&user_home))).expect_err("missing");
    assert_eq!(err, HomeError::Missing(missing.clone()));
    assert!(err.to_string().starts_with("codex home unreadable: CODEX_HOME points to"), "{err}");
    // set + not a directory.
    assert_eq!(codex_home(&env(file.to_str(), None)), Err(HomeError::NotDirectory(file)));
    // neither.
    assert_eq!(codex_home(&env(None, None)), Err(HomeError::NoHomeDirectory));
}

fn home_with_config(fixture: Option<&str>) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    if let Some(name) = fixture {
        fs::write(dir.path().join("config.toml"), testkit::fixture(name)).expect("write config");
    }
    dir
}

#[test]
fn store_mode_per_fixture() {
    // Plan AC95: 'file'/absent key/missing file → File; the other modes by name.
    let tests: [(&str, Option<&str>, StoreMode); 6] = [
        ("missing file", None, StoreMode::File),
        ("explicit file", Some("config-file.toml"), StoreMode::File),
        ("absent key", Some("config-mcp-key.toml"), StoreMode::File),
        ("keyring", Some("config-keyring.toml"), StoreMode::Keyring),
        ("auto", Some("config-auto.toml"), StoreMode::Auto),
        ("ephemeral", Some("config-ephemeral.toml"), StoreMode::Ephemeral),
    ];
    for (name, fixture, expected) in tests {
        let home = home_with_config(fixture);
        assert_eq!(store_mode(home.path()), (expected, None), "{name}");
    }
    let home = home_with_config(Some("config-auto.toml"));
    assert_eq!(
        base_url(home.path()).as_deref(),
        Some("https://chatgpt.example.invalid/backend-api/")
    );
}

#[test]
fn unusual_store_values_are_unknown_and_sanitized() {
    let tests: [(&str, StoreMode); 4] = [
        ("cli_auth_credentials_store = 'secrets'\n", StoreMode::Unknown("secrets".to_owned())),
        (
            "cli_auth_credentials_store = 'agctl-test-codex-ak-0009 with spaces'\n",
            StoreMode::Unknown("<unrecognised>".to_owned()),
        ),
        ("cli_auth_credentials_store = 7\n", StoreMode::Unknown("<unrecognised>".to_owned())),
        ("[profiles.x]\ncli_auth_credentials_store = 'keyring'\n", StoreMode::File),
    ];
    for (text, expected) in tests {
        assert_eq!(parse_config(text).0.store, expected, "{text}");
        testkit::assert_no_needles(&format!("{:?}", parse_config(text)), text);
    }
}

#[test]
fn base_url_refuses_credentials_in_the_url() {
    assert_eq!(
        parse_config("chatgpt_base_url = 'https://u:agctl-test-codex-ak-1@h.invalid/'\n")
            .0
            .base_url,
        None
    );
    assert_eq!(parse_config("chatgpt_base_url = 'file:///etc/passwd'\n").0.base_url, None);
    assert_eq!(parse_config("chatgpt_base_url = 'not a url'\n").0.base_url, None);
    assert_eq!(
        parse_config("chatgpt_base_url = 'http://127.0.0.1:9/x'\n").0.base_url.as_deref(),
        Some("http://127.0.0.1:9/x")
    );
}

#[test]
fn an_unparseable_config_is_a_line_number_and_nothing_else() {
    // Plan AC116 (unit half), invariant I31: the bad line carries a key
    // sentinel; the note carries a line number, and no rendering of the result
    // can carry the key.
    let home = home_with_config(Some("config-malformed.toml"));
    let (mode, note) = store_mode(home.path());
    assert_eq!(mode, StoreMode::File);
    assert_eq!(note, Some(ConfigNote::Unparseable { line: Some(4) }));
    for rendered in [format!("{mode:?} {note:?}"), format!("{:#?}", load_config(home.path()))] {
        testkit::assert_no_needles(&rendered, "config note");
    }

    // A well-formed file whose MCP env block holds a key: the parse keeps two
    // keys and drops the rest, so no render of the result can hold it.
    let home = home_with_config(Some("config-mcp-key.toml"));
    testkit::assert_no_needles(&format!("{:#?}", load_config(home.path())), "well-formed config");

    let binary = tempfile::tempdir().expect("tempdir");
    fs::write(binary.path().join("config.toml"), [0xff, 0xfe, b'\n']).expect("write");
    assert_eq!(
        store_mode(binary.path()),
        (StoreMode::File, Some(ConfigNote::Unparseable { line: None }))
    );

    let not_file = tempfile::tempdir().expect("tempdir");
    fs::create_dir(not_file.path().join("config.toml")).expect("mkdir");
    assert_eq!(store_mode(not_file.path()), (StoreMode::File, Some(ConfigNote::Unreadable)));
}

#[test]
fn the_toml_error_text_would_have_leaked_which_is_why_it_is_never_formatted() {
    // Proves the premise of the test above rather than assuming it: the
    // parser's own `Display` quotes the offending line.
    let text = String::from_utf8(testkit::fixture("config-malformed.toml")).expect("utf-8");
    let err = toml::de::DeTable::parse(&text).expect_err("malformed");
    assert!(
        err.to_string().contains("agctl-test-codex-ak-0002"),
        "premise: the Display quotes the line"
    );
}

#[test]
fn keyring_and_ephemeral_never_read_the_file_and_auto_reads_it_without_an_item() {
    // Plan AC95: a spy counts the `auth.json` reads and the keychain probes.
    let home = tempfile::tempdir().expect("tempdir");
    testkit::write_0600(&home.path().join(auth_store::shown_name()), &testkit::fresh_auth_bytes());
    let tests: [(StoreMode, KeyringProbe, usize, usize, Option<&str>); 6] = [
        (StoreMode::File, KeyringProbe::ItemPresent, 0, 1, None),
        (StoreMode::Keyring, KeyringProbe::NoItem, 0, 0, None),
        (StoreMode::Ephemeral, KeyringProbe::NoItem, 0, 0, None),
        (StoreMode::Unknown("x".to_owned()), KeyringProbe::NoItem, 0, 0, None),
        (StoreMode::Auto, KeyringProbe::ItemPresent, 1, 0, None),
        (StoreMode::Auto, KeyringProbe::NoItem, 1, 1, Some("auto (file in effect)")),
    ];
    for (mode, probe, probes, reads, note) in tests {
        let (probed, read) = (Cell::new(0), Cell::new(0));
        let decision = file_in_effect(&mode, || {
            probed.set(probed.get() + 1);
            probe
        });
        if let FileInEffect::Read { note: seen } = &decision {
            read.set(read.get() + 1);
            assert_eq!(*seen, note, "{mode:?}");
            assert!(matches!(auth_store::read_live(home.path()), CodexResolved::Credentials(_)));
        }
        assert_eq!((probed.get(), read.get()), (probes, reads), "{mode:?} with {probe:?}");
    }
    assert_eq!(
        file_in_effect(&StoreMode::Auto, || KeyringProbe::Unknown),
        FileInEffect::Read { note: Some("auto (file in effect)") },
        "F94: a keychain error also falls through to the file"
    );
}

#[test]
fn under_auto_a_file_that_vanishes_after_the_decision_is_absent() {
    // Fact F94: Codex's next keychain save deletes `auth.json`. The decision
    // said "read"; the file is gone by the read — that is `Absent`, not a panic
    // and not an error.
    let home = tempfile::tempdir().expect("tempdir");
    let path = home.path().join(auth_store::shown_name());
    testkit::write_0600(&path, &testkit::fresh_auth_bytes());
    let decision = file_in_effect(&StoreMode::Auto, || KeyringProbe::NoItem);
    assert!(matches!(decision, FileInEffect::Read { .. }));
    fs::remove_file(&path).expect("vanish");
    assert!(matches!(auth_store::read_live(home.path()), CodexResolved::Absent));
}

#[test]
fn keyring_account_is_cli_and_sixteen_hex() {
    let home = tempfile::tempdir().expect("tempdir");
    let account = keyring_account(home.path());
    let hex = account.strip_prefix("cli|").expect("prefix");
    assert_eq!(hex.len(), 16);
    assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()));
    let canonical = home.path().canonicalize().expect("canonical");
    assert_eq!(keyring_account(&canonical), account, "hashed after canonicalization");
}

#[test]
fn open_readonly_nofollow_flags_cannot_create_or_write() {
    // Plan AC93 (unit half, m6).
    assert!(READONLY_NOFOLLOW.contains(OFlags::NOFOLLOW));
    assert!(READONLY_NOFOLLOW.contains(OFlags::CLOEXEC));
    for forbidden in
        [OFlags::CREATE, OFlags::WRONLY, OFlags::RDWR, OFlags::TRUNC, OFlags::APPEND, OFlags::EXCL]
    {
        assert!(!READONLY_NOFOLLOW.intersects(forbidden), "{forbidden:?} must not be set");
    }
    assert_eq!(
        READONLY_NOFOLLOW & (OFlags::WRONLY | OFlags::RDWR),
        OFlags::RDONLY,
        "access mode is read-only"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("target");
    fs::write(&target, b"x").expect("write");
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    let err = open_readonly_nofollow(&link).expect_err("a link is refused");
    assert_eq!(err.raw_os_error(), Some(rustix::io::Errno::LOOP.raw_os_error()));
    assert!(open_readonly_nofollow(&dir.path().join("absent")).is_err());
    assert!(!dir.path().join("absent").exists(), "nothing was created");
}

fn write_pid_record(home: &Path, pid: u32, mtime: Option<Timestamp>) {
    write_named_pid_record(home, "app-server.pid", pid, mtime);
}

/// The same record under either of F83's two names.
fn write_named_pid_record(home: &Path, name: &str, pid: u32, mtime: Option<Timestamp>) {
    let daemon = home.join("app-server-daemon");
    fs::create_dir_all(&daemon).expect("mkdir");
    let path = daemon.join(name);
    let body = format!(
        r#"{{"pid":{pid},"processStartTime":"Wed Sep 16 21:40:50 2026","executableIdentity":{{"digest":"abc"}}}}"#
    );
    fs::write(&path, body).expect("write");
    if let Some(at) = mtime {
        let spec = rustix::fs::Timespec { tv_sec: at.as_second(), tv_nsec: 0 };
        let times = rustix::fs::Timestamps { last_access: spec, last_modification: spec };
        rustix::fs::utimensat(rustix::fs::CWD, &path, &times, rustix::fs::AtFlags::empty())
            .expect("utimensat");
    }
}

#[test]
fn daemon_evidence_classifies_the_pid_record() {
    // Plan AC93 / decision D-032.
    let cancel = Cancel::new();
    let home = tempfile::tempdir().expect("tempdir");
    assert_eq!(daemon_evidence(home.path(), &cancel), DaemonEvidence::None, "no daemon directory");

    fs::create_dir(home.path().join("app-server-daemon")).expect("mkdir");
    fs::write(home.path().join("app-server-daemon/daemon.lock"), b"").expect("write");
    assert_eq!(
        daemon_evidence(home.path(), &cancel),
        DaemonEvidence::ArtefactOnly,
        "a bare daemon.lock"
    );

    let me = std::process::id();
    write_pid_record(home.path(), me, None);
    assert_eq!(
        daemon_evidence(home.path(), &cancel),
        DaemonEvidence::PidAlive(me),
        "our own pid, written after we started"
    );

    // A record older than this process by far more than a second: the pid has
    // been reused by a process that started after the record was written.
    write_pid_record(
        home.path(),
        me,
        Some(Timestamp::now() - SignedDuration::from_hours(24 * 365)),
    );
    assert_eq!(daemon_evidence(home.path(), &cancel), DaemonEvidence::Recycled(me));

    write_pid_record(home.path(), u32::MAX - 1, None);
    assert_eq!(daemon_evidence(home.path(), &cancel), DaemonEvidence::ArtefactOnly, "a dead pid");
    write_pid_record(home.path(), 0, None);
    assert_eq!(
        daemon_evidence(home.path(), &cancel),
        DaemonEvidence::ArtefactOnly,
        "pid 0 is not a process"
    );

    fs::write(home.path().join("app-server-daemon/app-server.pid"), b"12").expect("write");
    assert_eq!(
        daemon_evidence(home.path(), &cancel),
        DaemonEvidence::RecordUnreadable,
        "not the F83 JSON shape: a record being published blocks a refresh (review S30 F8)"
    );
    fs::write(home.path().join("app-server-daemon/app-server.pid"), b"").expect("write");
    assert_eq!(
        daemon_evidence(home.path(), &cancel),
        DaemonEvidence::RecordUnreadable,
        "an empty, torn record"
    );

    // A link at the record is refused by the open, never followed.
    let elsewhere = tempfile::tempdir().expect("tempdir");
    write_pid_record(elsewhere.path(), me, None);
    fs::remove_file(home.path().join("app-server-daemon/app-server.pid")).expect("rm");
    std::os::unix::fs::symlink(
        elsewhere.path().join("app-server-daemon/app-server.pid"),
        home.path().join("app-server-daemon/app-server.pid"),
    )
    .expect("symlink");
    assert_eq!(
        daemon_evidence(home.path(), &cancel),
        DaemonEvidence::RecordUnreadable,
        "a link at the record is refused, and refusing it blocks a refresh"
    );
}

#[test]
fn the_recycle_rule_has_a_one_second_tolerance() {
    let written = Timestamp::from_second(1_800_000_000).expect("valid");
    let at = |ms: i64| Some(written + SignedDuration::from_millis(ms));
    assert_eq!(
        classify_live(7, at(1_000), written),
        DaemonEvidence::PidAlive(7),
        "exactly one second later"
    );
    assert_eq!(classify_live(7, at(1_001), written), DaemonEvidence::Recycled(7));
    assert_eq!(classify_live(7, at(-5_000), written), DaemonEvidence::PidAlive(7));
    assert_eq!(
        classify_live(7, None, written),
        DaemonEvidence::PidAlive(7),
        "unknown start is conservative"
    );
    assert_eq!(
        classify_live(7, Some(Timestamp::MAX), Timestamp::MAX),
        DaemonEvidence::PidAlive(7),
        "overflow"
    );
}

#[test]
fn this_file_names_no_process_environment() {
    // Invariant I25 in-process as well as by `scripts/phase3-greps.sh`.
    let source = include_str!("home.rs");
    let needle = format!("std::{}", "env");
    let code = source.lines().filter(|line| !line.trim_start().starts_with("//"));
    assert!(code.clone().all(|line| !line.contains(&needle)), "home.rs reads the environment");
    assert_eq!(source.matches(&format!("\"{}\"", CODEX_HOME_ENV)).count(), 1);
}

// --- F83's second pid-record name (deviation D32) ---------------------------

#[test]
fn d32_a_live_daemon_is_seen_under_either_pid_record_name() {
    // At 0.155.0-alpha.12 the name is `app-server.pid` only while the managed
    // codex binary is under `<CODEX_HOME>/packages/standalone`, and `daemon.pid`
    // otherwise. Reading one name let a live daemon read as `ArtefactOnly`,
    // which the refresh gate passes with a note — fail-open.
    let cancel = Cancel::new();
    let me = std::process::id();
    for name in ["app-server.pid", "daemon.pid"] {
        let home = tempfile::tempdir().expect("tempdir");
        write_named_pid_record(home.path(), name, me, None);
        assert_eq!(
            daemon_evidence(home.path(), &cancel),
            DaemonEvidence::PidAlive(me),
            "a live daemon under `{name}` was not seen"
        );
    }
}

#[test]
fn d32_a_torn_record_under_the_second_name_still_blocks() {
    let cancel = Cancel::new();
    let home = tempfile::tempdir().expect("tempdir");
    let daemon = home.path().join("app-server-daemon");
    fs::create_dir_all(&daemon).expect("mkdir");
    fs::write(daemon.join("daemon.pid"), b"{\"pid\":").expect("a torn record");

    assert_eq!(
        daemon_evidence(home.path(), &cancel),
        DaemonEvidence::RecordUnreadable,
        "a record being published under the new name must still stop a send (review S30 F8)"
    );
}

#[test]
fn d32_when_both_names_exist_the_stronger_evidence_wins() {
    // A migrated host can hold both: nothing cleans the legacy record up.
    let cancel = Cancel::new();
    let me = std::process::id();

    // Live under the new name, dead under the old one.
    let home = tempfile::tempdir().expect("tempdir");
    write_named_pid_record(home.path(), "app-server.pid", u32::MAX - 1, None);
    write_named_pid_record(home.path(), "daemon.pid", me, None);
    assert_eq!(daemon_evidence(home.path(), &cancel), DaemonEvidence::PidAlive(me));

    // Live under the old name, dead under the new one: the same answer.
    let home = tempfile::tempdir().expect("tempdir");
    write_named_pid_record(home.path(), "app-server.pid", me, None);
    write_named_pid_record(home.path(), "daemon.pid", u32::MAX - 1, None);
    assert_eq!(daemon_evidence(home.path(), &cancel), DaemonEvidence::PidAlive(me));

    // A torn record outranks a dead one: a daemon may be starting.
    let home = tempfile::tempdir().expect("tempdir");
    write_named_pid_record(home.path(), "app-server.pid", u32::MAX - 1, None);
    fs::write(home.path().join("app-server-daemon/daemon.pid"), b"{").expect("a torn record");
    assert_eq!(daemon_evidence(home.path(), &cancel), DaemonEvidence::RecordUnreadable);

    // …and a live pid outranks a torn record.
    write_named_pid_record(home.path(), "app-server.pid", me, None);
    assert_eq!(daemon_evidence(home.path(), &cancel), DaemonEvidence::PidAlive(me));
}

#[test]
fn d32_the_record_tolerates_members_this_crate_does_not_name() {
    // Upstream added `processIdentity` at alpha.12 (spelled
    // `linuxProcessIdentity` on Linux) and may add more. `PidRecord` models
    // none of them and must not have to: `serde` ignores unknown members
    // unless `deny_unknown_fields` is set, and the unknown-member case below is
    // what proves this type does not set it. Modelling a member nothing
    // compares would be dead code pretending to be a pin (review S33-C3b F1).
    let cancel = Cancel::new();
    let me = std::process::id();
    let three =
        format!(r#"{{"pid":{me},"processStartTime":"x","executableIdentity":{{"digest":"d"}}}}"#);
    let bodies = [
        // The shape on disk today, and the shape before `executableIdentity`.
        format!(r#"{{"pid":{me}}}"#),
        three.clone(),
        // The fourth member, under both spellings.
        format!(
            r#"{{"pid":{me},"processStartTime":"x","executableIdentity":{{"digest":"d"}},"processIdentity":{{"pidfdInode":7}}}}"#
        ),
        format!(
            r#"{{"pid":{me},"processStartTime":"x","executableIdentity":{{"digest":"d"}},"linuxProcessIdentity":{{"pidfdInode":7}}}}"#
        ),
        // A member no version of Codex has ever written: the general case.
        format!(
            r#"{{"pid":{me},"processStartTime":"x","executableIdentity":{{"digest":"d"}},"somethingCodexAddsLater":[1,2,3]}}"#
        ),
    ];

    let mut home = tempfile::tempdir().expect("tempdir");
    let daemon = home.path().join("app-server-daemon");
    fs::create_dir_all(&daemon).expect("mkdir");
    fs::write(daemon.join("daemon.pid"), &three).expect("write");
    let baseline = daemon_evidence(home.path(), &cancel);
    assert_eq!(baseline, DaemonEvidence::PidAlive(me), "the three-member record must parse");

    for body in bodies {
        home = tempfile::tempdir().expect("tempdir");
        let daemon = home.path().join("app-server-daemon");
        fs::create_dir_all(&daemon).expect("mkdir");
        fs::write(daemon.join("daemon.pid"), &body).expect("write");
        assert_eq!(
            daemon_evidence(home.path(), &cancel),
            baseline,
            "this record shape did not read the same as the three-member one: {body}"
        );
    }
}

#[test]
fn f3_two_live_records_report_the_one_written_last() {
    // A migrated host can hold both names with both processes alive; the
    // leftover record must not be the one the row names (review S33-C3b F3).
    // Two *different* live pids are needed for the assertion to distinguish
    // which record was read, so this test uses its own and its parent's, and
    // sets both mtimes after this process started so neither is `Recycled`.
    let cancel = Cancel::new();
    let me = std::process::id();
    let parent = std::os::unix::process::parent_id();
    assert_ne!(me, parent, "this test needs two live pids");
    let now = Timestamp::now();
    let later = now + SignedDuration::from_secs(5);

    let home = tempfile::tempdir().expect("tempdir");
    write_named_pid_record(home.path(), "app-server.pid", me, Some(now));
    write_named_pid_record(home.path(), "daemon.pid", parent, Some(later));
    assert_eq!(
        daemon_evidence(home.path(), &cancel),
        DaemonEvidence::PidAlive(parent),
        "the stale legacy record was reported over the current one"
    );

    // The same the other way round, so the answer is the mtime and not the
    // order of `DAEMON_PID_FILES`.
    let home = tempfile::tempdir().expect("tempdir");
    write_named_pid_record(home.path(), "app-server.pid", me, Some(later));
    write_named_pid_record(home.path(), "daemon.pid", parent, Some(now));
    assert_eq!(
        daemon_evidence(home.path(), &cancel),
        DaemonEvidence::PidAlive(me),
        "the tiebreak followed the file name rather than the write time"
    );

    // The tiebreak never weakens the verdict: a live record still beats a
    // newer artefact.
    let home = tempfile::tempdir().expect("tempdir");
    write_named_pid_record(home.path(), "app-server.pid", me, Some(now));
    write_named_pid_record(home.path(), "daemon.pid", u32::MAX - 1, Some(later));
    assert_eq!(daemon_evidence(home.path(), &cancel), DaemonEvidence::PidAlive(me));
}
