use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use serde_json::json;
use tempfile::TempDir;

use super::*;
use crate::runtime::coordinator::Cancel;
use crate::runtime::proc;

fn live_scan(dir: &Path) -> Scan {
    let cancel = Cancel::new();
    scan(dir, |pid| proc::holder(pid, &cancel) != proc::Holder::Dead)
}

#[test]
fn live_sessions_missing_empty_and_unreadable() {
    let root = TempDir::new().expect("fixture root");
    let dir = root.path().join("sessions");
    assert_eq!(live_scan(&dir), Scan::NoRegistry);
    fs::create_dir(&dir).expect("registry");
    assert_eq!(live_scan(&dir), Scan::Read { remote: vec![], skipped: 0 });
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o000)).expect("unreadable registry");
    let actual = live_scan(&dir);
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("restore cleanup access");
    assert_eq!(actual, Scan::Unreadable(io::ErrorKind::PermissionDenied));
}

#[test]
fn live_sessions_mixed_registry_reads_only_live_remote_regular_json() {
    let root = TempDir::new().expect("fixture root");
    let dir = root.path().join("sessions");
    fs::create_dir(&dir).expect("registry");
    let live = std::process::id();
    let mut child = Command::new("true").spawn().expect("short-lived child");
    let dead = child.id();
    child.wait().expect("reap dead pid");
    let entries = [
        ("malformed".to_owned(), "{".to_owned()),
        ("missing-bridge".to_owned(), json!({"pid": live}).to_string()),
        ("null-bridge".to_owned(), json!({"pid": live, "bridgeSessionId": null}).to_string()),
        ("empty-bridge".to_owned(), json!({"pid": live, "bridgeSessionId": ""}).to_string()),
        ("dead".to_owned(), json!({"pid": dead, "bridgeSessionId": "rc"}).to_string()),
        ("zero".to_owned(), json!({"pid": 0, "bridgeSessionId": "rc"}).to_string()),
        (
            "live".to_owned(),
            json!({"pid": live, "name": "live", "bridgeSessionId": "rc"}).to_string(),
        ),
        (live.to_string(), json!({"name": "stem", "bridgeSessionId": "rc"}).to_string()),
        ("oversized".to_owned(), " ".repeat(65 * 1024)),
    ];
    for (name, bytes) in entries {
        fs::write(dir.join(format!("{name}.json")), bytes).expect("entry");
    }
    let key = dir.join(format!("{live}.secret.key"));
    fs::write(&key, b"not json and must never be opened").expect("key fixture");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o000)).expect("unreadable key");
    fs::create_dir(dir.join("x.json")).expect("directory with json suffix");
    let target = root.path().join("valid.json");
    fs::write(&target, json!({"pid": live, "bridgeSessionId": "rc"}).to_string()).expect("target");
    std::os::unix::fs::symlink(&target, dir.join("y.json")).expect("symlink with json suffix");
    let Scan::Read { mut remote, skipped } = live_scan(&dir) else { panic!("read registry") };
    remote.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(
        remote,
        vec![
            RemoteSession { name: Some("live".into()) },
            RemoteSession { name: Some("stem".into()) }
        ]
    );
    assert_eq!(skipped, 4, "malformed, oversized, directory, symlink only");
    fs::set_permissions(key, fs::Permissions::from_mode(0o600)).expect("cleanup access");
}

#[test]
fn live_sessions_bounds_entries_and_bytes() {
    for (name, size, expected) in [("below", 64 * 1024 - 1, 0), ("at cap", 64 * 1024, 1)] {
        let root = TempDir::new().expect("fixture root");
        let mut bytes = json!({"pid": std::process::id(), "bridgeSessionId": "rc"}).to_string();
        bytes.extend(std::iter::repeat_n(' ', size - bytes.len()));
        fs::write(root.path().join("entry.json"), bytes).expect("bounded entry");
        let Scan::Read { remote, skipped } = live_scan(root.path()) else { panic!("read") };
        assert_eq!(skipped, expected, "{name}");
        assert_eq!(remote.len(), 1 - expected, "{name}");
    }
    let root = TempDir::new().expect("fixture root");
    let bytes = json!({"pid": std::process::id(), "bridgeSessionId": "rc"}).to_string();
    for index in 0..513 {
        fs::write(root.path().join(format!("{index}.json")), &bytes).expect("entry");
    }
    let Scan::Read { remote, skipped } = live_scan(root.path()) else { panic!("read") };
    assert_eq!(remote.len(), 512);
    assert_eq!(skipped, 1);
}

#[test]
fn live_sessions_names_are_sanitized_and_lists_are_bounded() {
    let long = "語".repeat(60);
    let tests = [
        ("trim", "  review  ", Some("review".to_owned())),
        ("controls", "a\n\r\t\u{1b}b", Some("ab".to_owned())),
        ("backtick", "a`b", Some("a'b".to_owned())),
        ("empty", "\n\t\u{1b}", None),
        ("cap", long.as_str(), Some(format!("{}…", "語".repeat(47)))),
    ];
    for (label, input, expected) in tests {
        assert_eq!(sanitize_name(input), expected, "{label}");
    }
    let tests = [
        (vec![Some("rif-review")], "`rif-review`"),
        (vec![Some("rif-review"), Some("agctl"), None], "`agctl`, `rif-review` and 1 unnamed"),
        (
            vec![Some("a"), Some("b"), Some("c"), Some("d"), Some("e"), Some("f"), Some("g")],
            "`a`, `b`, `c` and 4 more",
        ),
        (
            vec![Some("a"), Some("b"), Some("c"), Some("d"), None, None],
            "`a`, `b`, `c`, 2 unnamed and 1 more",
        ),
        (vec![None, None], "2 unnamed"),
    ];
    for (names, expected) in tests {
        let sessions: Vec<_> =
            names.into_iter().map(|name| RemoteSession { name: name.map(str::to_owned) }).collect();
        assert_eq!(render_list(&sessions), expected);
    }
}

#[test]
fn live_sessions_sentences_preserve_the_uncertainty_and_exact_wording() {
    for count in [1, 4] {
        let scan = Scan::Read {
            remote: vec![RemoteSession { name: Some("rc-e2e".into()) }; count],
            skipped: 0,
        };
        let consent = consent_clause(&scan, 120).expect("consent");
        let named = completion_warning(&scan, true).expect("named warning");
        let counted = completion_warning(&scan, false).expect("counted warning");
        let note =
            unreadable_note(&Scan::Unreadable(io::ErrorKind::PermissionDenied)).expect("note");
        for sentence in [&consent, &named, &counted, &note] {
            assert!(
                sentence.contains("cannot tell") || sentence.contains("cannot say"),
                "{sentence}"
            );
        }
        assert!(consent.contains("answer n, run `/remote-control`"));
        assert!(consent.contains("this swap's 120-second limit"));
        assert!(named.contains("rc-e2e"));
        assert!(!counted.contains("rc-e2e"));
        if count == 1 {
            assert_eq!(
                consent,
                ". 1 running Claude Code session (`rc-e2e`) has Remote Control on, and agctl cannot tell which of them use this store. To keep a session's claude.ai history, answer n, run `/remote-control` in that session and disconnect, then run this command again — do not leave this question open while you do it, because it counts against this swap's 120-second limit. If you answer y, Remote Control stops in each session that uses this store, and starting it again there begins a remote session without the earlier conversation"
            );
            assert_eq!(
                counted,
                "1 Claude Code session had Remote Control on when this swap started, and agctl cannot tell which of them use this store. In each one that does, Remote Control stops (now, or on its next account check): run `/remote-control` there to start it again. Its earlier conversation reaches claude.ai only if Remote Control was disconnected there before the swap"
            );
            assert_eq!(named, counted.replacen("session had", "session (`rc-e2e`) had", 1));
            assert_eq!(
                note,
                "agctl could not read Claude Code's session registry (permission denied), so it cannot say whether a running session has Remote Control on. A session that does keeps its claude.ai history only if Remote Control is disconnected there before the swap: decline this swap (answer n, or run without `--yes`), disconnect it there, and run this command again"
            );
        }
    }
    for scan in [Scan::NoRegistry, Scan::Read { remote: vec![], skipped: 2 }] {
        assert!(consent_clause(&scan, 120).is_none());
        assert!(completion_warning(&scan, true).is_none());
        assert!(completion_warning(&scan, false).is_none());
        assert!(unreadable_note(&scan).is_none());
    }
}

#[test]
fn live_sessions_output_and_tracing_never_disclose_registry_identifiers() {
    let root = TempDir::new().expect("fixture root");
    let entry = root.path().join("4242.json");
    fs::write(&entry, json!({
        "pid": 4242, "name": "safe\n`name", "cwd": "/tmp/secret-cwd",
        "tmux": "x:@1.%1", "sessionId": "local-secret-id", "bridgeSessionId": "session_01TESTSECRET"
    }).to_string()).expect("entry");
    let trace_path = root.path().join("trace.log");
    let trace = File::create(&trace_path).expect("trace capture");
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(trace)
        .finish();
    let scanned = tracing::subscriber::with_default(subscriber, || {
        let scanned = scan(root.path(), |_| true);
        fs::write(&entry, "{").expect("malformed entry exercises skipped trace");
        assert!(matches!(scan(root.path(), |_| true), Scan::Read { skipped: 1, .. }));
        scanned
    });
    let trace = fs::read_to_string(trace_path).expect("UTF-8 trace");
    assert!(trace.contains("unparseable"), "trace capture is not vacuous: {trace}");
    let output = format!(
        "{}\n{}\n{}\n{trace}",
        consent_clause(&scanned, 120).expect("consent"),
        completion_warning(&scanned, true).expect("warning"),
        completion_warning(&scanned, false).expect("count warning")
    );
    for forbidden in [
        "4242",
        "4242.json",
        "/tmp/secret-cwd",
        "x:@1.%1",
        "local-secret-id",
        "session_01TESTSECRET",
    ] {
        assert!(!output.contains(forbidden), "leaked {forbidden}: {output}");
    }
}
