#[cfg(target_os = "macos")]
use std::collections::VecDeque;
use std::fs;
use std::os::unix::fs::PermissionsExt;

use serde_json::json;

use super::*;
#[cfg(target_os = "macos")]
use crate::error::AppError;
use crate::runtime::coordinator::Cancel;
use crate::runtime::tmux::Pane;

fn state() -> State {
    State {
        bridge_on: true,
        same_bridge: true,
        status: "idle".to_owned(),
        waiting_for: None,
        status_updated_at: 1,
        version: "2.1.281".to_owned(),
        pane: Pane::parse("%7").unwrap(),
    }
}

#[test]
fn remote_control_no_pane_session_keeps_the_nonautomation_hint() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("entry.json"),
        json!({"pid":std::process::id(), "bridgeSessionId":"bridge", "name":"no pane"}).to_string(),
    )
    .unwrap();
    let scan = live_sessions::scan_detailed(dir.path(), |_| true);
    let ctx = PassCtx::standalone(Cancel::new(), Instant::now() + Duration::from_secs(120));
    let rc = RemoteControl::new(scan, dir.path().to_path_buf(), dir.path().join("config"), &ctx);
    assert_eq!(rc.counts.eligible, 0);
    assert!(rc.consent_clause(Instant::now()).is_none());
    assert!(live_sessions::consent_clause(&rc.hint, 120).unwrap().contains("`no pane`"));
}

#[test]
fn remote_control_versions_use_only_three_checked_ascii_components() {
    let cases: BTreeMap<_, _> = [
        ("2.1.280", Some((2, 1, 280))),
        ("2.1.281", Some(RC_MIN_VERSION)),
        ("2.1.999", Some((2, 1, 999))),
        ("2.1", None),
        ("2.1.281.0", None),
        ("", None),
        ("2..281", None),
        ("2.1.２８１", None),
        ("2.1.x", None),
        (" 2.1.281", None),
        ("2.1.281 ", None),
        ("2.1.281-beta", None),
        ("+2.1.281", None),
        ("2.1.4294967296", None),
    ]
    .into();
    for (text, expected) in cases {
        assert_eq!(parse_version(text), expected, "{text}");
    }
    assert_eq!(RC_MIN_VERSION, (2, 1, 281));
    assert!(RC_LAST_VERIFIED_VERSION >= RC_MIN_VERSION);
}

#[test]
fn remote_control_deadlines_recompute_reserve_and_never_subtract_unchecked() {
    let reserve = TOKEN_TIMEOUT
        + PROFILE_TIMEOUT
        + READ_TIMEOUT * 2
        + CONTENTION_LADDER.into_iter().sum::<Duration>() * 2
        + Duration::from_secs(5);
    assert_eq!(RC_STAGE_RESERVE, reserve);
    assert_eq!(reserve, Duration::from_millis(51_800));
    let now = Instant::now();
    let cases: BTreeMap<_, _> = [
        ("budget", (Some(now + Duration::from_secs(100)), Some(now + RC_DISCONNECT_BUDGET))),
        ("reserve", (Some(now + Duration::from_secs(10)), Some(now + Duration::from_secs(10)))),
        ("too short", (Some(now + Duration::from_secs(4)), None)),
        ("already past", (Some(now), None)),
        ("checked_sub underflow", (None, None)),
    ]
    .into();
    for (name, (limit, expected)) in cases {
        assert_eq!(stage_deadline(now, limit), expected, "{name}");
    }
    assert_eq!(stage_window(now, None), 0);
    assert_eq!(stage_window(now, Some(now + Duration::from_secs(18))), 18);
    assert_eq!(stage_window(now, Some(now + Duration::from_secs(100))), 30);
    for (n, seconds) in [(0, 60), (1, 90), (2, 120)] {
        assert_eq!(reconnect_budget(n), Duration::from_secs(seconds));
    }
}

#[test]
fn remote_control_quiet_time_is_local_resets_and_rejects_future_stamps() {
    let start = Instant::now();
    let mut quiet = Quiet::default();
    let mut current = state();
    assert!(!quiet.ready(&current, Group::Opening, start, 10_000));
    assert!(!quiet.ready(&current, Group::Opening, start + Duration::from_millis(999), 10_000));
    assert!(quiet.ready(&current, Group::Opening, start + RC_QUIET, 10_000));
    current.status_updated_at = 2;
    assert!(!quiet.ready(&current, Group::Opening, start + RC_QUIET, 10_000));
    assert!(quiet.ready(&current, Group::Opening, start + RC_QUIET * 2, 10_000));
    assert!(!quiet.ready(&current, Group::Opening, start + RC_QUIET * 3, 1));
    assert!(!quiet.ready(&current, Group::Disconnect, start + RC_QUIET * 3, 10_000));
    current.status = "waiting".to_owned();
    current.waiting_for = Some("dialog open".to_owned());
    assert!(!quiet.ready(&current, Group::Disconnect, start + RC_QUIET * 3, 10_000));
    assert!(quiet.ready(&current, Group::Disconnect, start + RC_QUIET * 4, 10_000));
    assert!(!quiet.ready(&current, Group::Reconnect, start + RC_QUIET * 4, 10_000));
    current.waiting_for = Some("input needed".to_owned());
    assert!(!quiet.ready(&current, Group::Disconnect, start + RC_QUIET * 5, 10_000));
}

#[test]
fn remote_control_foreground_comparison_fails_every_unsupported_part() {
    let proof = proc::TtyForeground { holder: proc::Holder::Alive, pgid: 7, tpgid: 7, tdev: 123 };
    let pane = || tmux::PaneState {
        tty: PathBuf::from("/dev/tty"),
        in_mode: false,
        dead: false,
        synchronized: false,
    };
    assert_eq!(foreground(Some(proof), &pane(), Some(123)), Ok(()));
    assert_eq!(foreground(None, &pane(), Some(123)), Err("foreground_unreadable"));
    let cases: BTreeMap<_, _> = [
        (
            "stopped",
            (proc::TtyForeground { holder: proc::Holder::Stopped, ..proof }, "stopped_or_dead"),
        ),
        ("dead", (proc::TtyForeground { holder: proc::Holder::Dead, ..proof }, "stopped_or_dead")),
        ("background", (proc::TtyForeground { tpgid: 8, ..proof }, "not_in_foreground")),
        ("other tty", (proc::TtyForeground { tdev: 124, ..proof }, "another_terminal")),
        ("NODEV", (proc::TtyForeground { tdev: u32::MAX, ..proof }, "another_terminal")),
    ]
    .into();
    for (name, (changed, reason)) in cases {
        assert_eq!(foreground(Some(changed), &pane(), Some(123)), Err(reason), "{name}");
    }
    for (index, expected) in ["copy_mode", "dead_pane", "synchronized"].into_iter().enumerate() {
        let mut bad = pane();
        match index {
            0 => bad.in_mode = true,
            1 => bad.dead = true,
            _ => bad.synchronized = true,
        }
        assert_eq!(foreground(Some(proof), &bad, Some(123)), Err(expected));
    }
    assert_eq!(
        foreground(Some(proc::TtyForeground { tdev: u32::MAX, ..proof }), &pane(), Some(u32::MAX)),
        Err("another_terminal")
    );
}

#[test]
fn remote_control_config_mode_read_is_bounded_and_rejecting_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config");
    let cases: BTreeMap<_, _> = [
        ("absent key", (json!({}), true)),
        ("normal", (json!({"editorMode":"normal"}), true)),
        ("vim", (json!({"editorMode":"vim"}), false)),
        ("legacy", (json!({"editorMode":"emacs"}), false)),
        ("unknown", (json!({"editorMode":"future"}), false)),
        ("null", (json!({"editorMode":null}), false)),
        ("numeric", (json!({"editorMode":7}), false)),
        ("not object", (json!([]), false)),
    ]
    .into();
    for (name, (document, expected)) in cases {
        fs::write(&path, document.to_string()).unwrap();
        assert_eq!(config_mode_permits(&path), expected, "{name}");
    }
    fs::write(&path, " ".repeat(MAX_CLAUDE_JSON_BYTES as usize + 1)).unwrap();
    assert!(!config_mode_permits(&path));
    fs::write(&path, "{}").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
    assert!(!config_mode_permits(&path));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::remove_file(&path).unwrap();
    assert!(!config_mode_permits(&path));
}

#[test]
fn remote_control_outcome_table_and_integer_warnings_cover_every_variant() {
    let applied = ConfigReport {
        outcome: ConfigOutcome::Applied,
        reason: None,
        account: None,
        from_sha8: None,
        to_sha8: None,
        backup: None,
        hold_ms: None,
    };
    assert_eq!(action(&Outcome::Applied, Some(&applied)), Action::Reconnect);
    assert_eq!(action(&Outcome::Applied, None), Action::ConfigRecovery);
    assert_eq!(action(&Outcome::Unknown, None), Action::StatusRecovery);
    assert_eq!(action(&Outcome::AlreadyActive, None), Action::None);
    for outcome in [
        Outcome::Refused(crate::provider::claude::swap::Refusal::RemoteControlNotDisconnected),
        Outcome::Cancelled,
        Outcome::Failed,
        Outcome::NeedsRefresh,
        Outcome::Discarded,
        Outcome::Busy,
    ] {
        assert_eq!(action(&outcome, None), Action::Restore, "{outcome:?}");
    }
    let counts = Counts {
        eligible: 2,
        disconnected: 1,
        not_disconnected: 1,
        not_confirmed: 1,
        skipped: 1,
        not_attested: 1,
        attestation_declined: 1,
        ..Counts::default()
    };
    let json = serde_json::to_value(&counts).unwrap();
    assert_eq!(json.as_object().unwrap().len(), 11);
    assert!(json.as_object().unwrap().values().all(serde_json::Value::is_u64));
    assert_eq!(warnings(&counts, Action::Restore).len(), 5);
    assert!(warnings(&counts, Action::ConfigRecovery).last().unwrap().contains("config recovery"));
    assert!(
        warnings(&counts, Action::StatusRecovery).last().unwrap().contains("agctl claude status")
    );
    assert!(warnings(&Counts::default(), Action::None).is_empty());
}

#[cfg(target_os = "macos")]
#[derive(Default)]
struct Script {
    answers: VecDeque<Attestation>,
    questions: Vec<String>,
    notes: Vec<String>,
    change: Option<Box<dyn FnMut()>>,
}
#[cfg(target_os = "macos")]
impl Script {
    fn yes(n: usize) -> Self {
        Self { answers: std::iter::repeat_n(Attestation::Yes, n).collect(), ..Self::default() }
    }
}
#[cfg(target_os = "macos")]
impl Prompt for Script {
    fn tell(&mut self, message: &str) {
        self.notes.push(message.to_owned());
    }
    fn confirm(&mut self, question: &str) -> Result<bool, AppError> {
        self.questions.push(question.to_owned());
        Ok(self.answers.pop_front() == Some(Attestation::Yes))
    }
    fn attest(&mut self, question: &str, deadline: Instant, cancel: &Cancel) -> Attestation {
        self.questions.push(question.to_owned());
        if let Some(change) = self.change.as_mut() {
            change();
        }
        if cancel.is_cancelled() || Instant::now() >= deadline {
            return Attestation::NotObtained;
        }
        self.answers.pop_front().unwrap_or(Attestation::NotObtained)
    }
}

#[cfg(target_os = "macos")]
mod stage_tests {
    use std::fs::File;
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    use std::process::Child;
    use std::process::Command;
    use std::process::Stdio;

    use super::*;

    struct Fixture {
        root: tempfile::TempDir,
        child: Child,
        _master: File,
        dir: PathBuf,
        config: PathBuf,
        bin: PathBuf,
        log: PathBuf,
        document: serde_json::Value,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let master = rustix::pty::openpt(
                rustix::pty::OpenptFlags::RDWR | rustix::pty::OpenptFlags::NOCTTY,
            )
            .unwrap();
            rustix::pty::grantpt(&master).unwrap();
            rustix::pty::unlockpt(&master).unwrap();
            let name = rustix::pty::ptsname(&master, Vec::new()).unwrap();
            let slave = File::from(
                rustix::fs::open(
                    name.as_c_str(),
                    rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOCTTY,
                    rustix::fs::Mode::empty(),
                )
                .unwrap(),
            );
            let mut command = Command::new("sleep");
            command
                .arg("300")
                .stdin(slave)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .env("HOME", root.path());
            // SAFETY: the child owns fd 0, only async-signal-safe syscalls occur before exec.
            unsafe {
                command.pre_exec(|| {
                    if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY.into(), 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let child = command.spawn().unwrap();
            let pid = child.id();
            let end = Instant::now() + Duration::from_secs(3);
            while proc::tty_foreground(pid)
                .is_none_or(|proof| proof.pgid != pid || proof.tdev == u32::MAX)
            {
                assert!(Instant::now() < end, "pty child did not become foreground");
                std::thread::yield_now();
            }
            let dir = root.path().join("sessions");
            fs::create_dir(&dir).unwrap();
            let states = root.path().join("states");
            fs::create_dir(&states).unwrap();
            let config = root.path().join("config.json");
            fs::write(&config, "{}").unwrap();
            let log = root.path().join("tmux.log");
            let panes = root.path().join("panes");
            fs::write(&panes, format!("%7 {pid} {} 0 0 0\n", name.to_str().unwrap())).unwrap();
            let document = json!({"pid":pid,"sessionId":"secret-session","name":"rc-test","tmux":"name:@0.%7",
                "version":"2.1.281","status":"idle","statusUpdatedAt":1,"bridgeSessionId":"secret-bridge"});
            fs::write(dir.join(format!("{pid}.json")), document.to_string()).unwrap();
            let mut panel = document.clone();
            panel["status"] = json!("waiting");
            panel["waitingFor"] = json!("dialog open");
            fs::write(states.join(format!("{pid}.panel.json")), panel.to_string()).unwrap();
            let mut off = document.clone();
            off["bridgeSessionId"] = serde_json::Value::Null;
            fs::write(states.join(format!("{pid}.disconnected.json")), off.to_string()).unwrap();
            fs::write(states.join(format!("{pid}.reconnected.json")), document.to_string())
                .unwrap();
            let bin = root.path().join("fake-tmux");
            let fake = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/fake-tmux.sh");
            let screens = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/rc-screens");
            fs::write(&bin, format!("#!/bin/sh\nexport HOME='{}'\nexport AGCTL_FAKE_TMUX_LOG='{}'\nexport AGCTL_FAKE_TMUX_PANES='{}'\nexport AGCTL_FAKE_TMUX_STATES='{}'\nexport AGCTL_FAKE_TMUX_REGISTRY='{}'\nexport AGCTL_FAKE_TMUX_NULL_AFTER_MS=300\nstatus=$(perl -MJSON::PP -e 'local $/; open my $f, \"<\", $ARGV[0] or die; print decode_json(<$f>)->{{status}}' '{}/{pid}.json')\nif [ \"$status\" = waiting ]; then export AGCTL_FAKE_TMUX_SCREEN='{}/c20-panel.txt'; else export AGCTL_FAKE_TMUX_SCREEN='{}/empty-prompt.txt'; fi\nexec '{}' \"$@\"\n", root.path().display(), log.display(), panes.display(), states.display(), dir.display(), dir.display(), screens.display(), screens.display(), fake.display())).unwrap();
            fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).unwrap();
            Self { root, child, _master: File::from(master), dir, config, bin, log, document }
        }
        fn path(&self) -> PathBuf {
            self.dir.join(format!("{}.json", self.child.id()))
        }
        fn save(&self, value: &serde_json::Value) {
            fs::write(self.path(), value.to_string()).unwrap();
        }
        fn plan(&self, ctx: &PassCtx) -> RemoteControl {
            let mut remote = RemoteControl::new(
                live_sessions::scan_detailed(&self.dir, |_| true),
                self.dir.clone(),
                self.config.clone(),
                ctx,
            );
            remote.bin = Some(self.bin.clone());
            remote
        }
        fn log(&self) -> String {
            fs::read_to_string(&self.log).unwrap_or_default()
        }
    }
    fn context() -> PassCtx {
        PassCtx::standalone(Cancel::new(), Instant::now() + Duration::from_secs(120))
    }

    #[test]
    fn remote_control_disconnects_once_and_restores_only_after_fresh_attestation() {
        let fixture = Fixture::new();
        let ctx = context();
        let mut rc = fixture.plan(&ctx);
        let mut prompt = Script::yes(2);
        assert!(rc.disconnect(&ctx, &mut prompt));
        assert_eq!(rc.counts.disconnected, 1);
        assert_eq!(fixture.log().matches("arg send-keys\n").count(), 2);
        rc.finish(&ctx, &mut prompt, Action::Restore);
        assert_eq!(rc.counts.not_confirmed, 1);
        assert_eq!(rc.counts.not_attested, 1);
        assert_eq!(fixture.log().matches("arg send-keys\n").count(), 2);
        assert_eq!(prompt.questions.len(), 3);
        for question in &prompt.questions {
            assert!(question.contains("uses the live store"));
            assert!(question.contains("complete input line is empty"));
            assert!(question.contains("not in vim mode"));
            assert!(question.contains("rc-test in %7"));
        }
    }

    #[test]
    fn remote_control_each_group_rejects_config_capture_schema_and_stale_answers() {
        for group in [Group::Opening, Group::Disconnect, Group::Reconnect, Group::Restore] {
            for failure in ["config", "capture", "schema", "stale", "decline", "eof", "cancel"] {
                let fixture = Fixture::new();
                let ctx = context();
                let rc = fixture.plan(&ctx);
                let session = &rc.sessions[0].session;
                let mut document = fixture.document.clone();
                if group == Group::Disconnect {
                    document["status"] = json!("waiting");
                    document["waitingFor"] = json!("dialog open");
                }
                if group.connecting() {
                    document["bridgeSessionId"] = serde_json::Value::Null;
                }
                fixture.save(&document);
                let mut prompt = Script::yes(1);
                match failure {
                    "config" => fs::write(&fixture.config, r#"{"editorMode":"vim"}"#).unwrap(),
                    "capture" => {
                        let script = fs::read_to_string(&fixture.bin)
                            .unwrap()
                            .replace("empty-prompt.txt", "draft_visible.txt")
                            .replace("c20-panel.txt", "dialog_conflict.txt");
                        fs::write(&fixture.bin, script).unwrap();
                    }
                    "schema" => {
                        document["status"] = json!("new-state");
                        fixture.save(&document);
                    }
                    "stale" => {
                        let path = fixture.path();
                        document["statusUpdatedAt"] = json!(2);
                        prompt.change =
                            Some(Box::new(move || fs::write(&path, document.to_string()).unwrap()));
                    }
                    "decline" => prompt.answers = [Attestation::Declined].into(),
                    "eof" => prompt.answers.clear(),
                    "cancel" => {
                        let cancel = ctx.cancel().clone();
                        prompt.change = Some(Box::new(move || cancel.cancel()));
                    }
                    _ => unreachable!(),
                }
                let stage = Stage {
                    dir: &fixture.dir,
                    config: &fixture.config,
                    bin: &fixture.bin,
                    ctx: &ctx,
                    end: Instant::now() + Duration::from_secs(5),
                    notice: &cleanup::register_exit_notice(0, not_confirmed_warning),
                };
                let result = stage.group(session, group, &mut prompt);
                assert_ne!(result, GroupResult::Sent, "{group:?} {failure}");
                assert!(!fixture.log().contains("arg send-keys"), "{group:?} {failure}");
            }
        }
    }

    #[test]
    fn remote_control_preflight_checks_every_pane_before_input_and_preserves_version_note() {
        let fixture = Fixture::new();
        let ctx = context();
        let mut document = fixture.document.clone();
        document["version"] = json!("2.1.999");
        fixture.save(&document);
        let mut rc = fixture.plan(&ctx);
        assert_eq!(
            rc.version_notes(),
            ["Remote Control automation was last verified on 2.1.281; this session runs 2.1.999"]
        );
        let clause = rc.consent_clause(Instant::now()).unwrap();
        assert!(clause.contains("`rc-test` in %7"));
        assert!(clause.contains("30 seconds"));
        assert!(clause.ends_with(RESIDUAL));
        let duplicate = rc.sessions[0].session.clone();
        rc.sessions.push(Progress {
            session: duplicate,
            opened: false,
            sent: false,
            disconnected: false,
            gone: false,
        });
        rc.counts.eligible = 2;
        assert!(!rc.disconnect(&ctx, &mut Script::yes(4)));
        assert_eq!(rc.counts.skipped, 2);
        assert!(!fixture.log().contains("arg send-keys"));
    }

    #[test]
    fn remote_control_static_refusals_do_not_type_and_dead_sessions_are_gone() {
        for version in ["2.1.280", "garbled"] {
            let fixture = Fixture::new();
            let ctx = context();
            let mut document = fixture.document.clone();
            document["version"] = json!(version);
            fixture.save(&document);
            let mut rc = fixture.plan(&ctx);
            assert!(!rc.disconnect(&ctx, &mut Script::yes(2)));
            assert_eq!(rc.counts.skipped, 1);
            assert!(!fixture.log().contains("arg send-keys"));
        }
        let mut fixture = Fixture::new();
        let ctx = context();
        let mut rc = fixture.plan(&ctx);
        fixture.child.kill().unwrap();
        fixture.child.wait().unwrap();
        assert!(rc.disconnect(&ctx, &mut Script::yes(2)));
        assert_eq!(rc.counts.gone, 1);
        assert!(fixture.log().is_empty());
    }

    #[test]
    fn remote_control_restore_observes_liveness_only_after_a_fresh_group() {
        let fixture = Fixture::new();
        let ctx = context();
        let mut rc = fixture.plan(&ctx);
        let mut prompt = Script::yes(3);
        assert!(rc.disconnect(&ctx, &mut prompt));
        let started = Instant::now();
        rc.finish(&ctx, &mut prompt, Action::Restore);
        assert_eq!(rc.counts.restored, 1);
        assert_eq!(rc.counts.not_confirmed, 0);
        assert!(started.elapsed() >= RC_RECONNECT_CONFIRM);
        assert_eq!(fixture.log().matches("arg send-keys\n").count(), 3);
        assert_eq!(prompt.questions.len(), 3);
    }

    #[test]
    fn remote_control_timeout_sends_one_sequence_and_never_toggles_a_live_bridge() {
        let fixture = Fixture::new();
        let ctx = context();
        let mut rc = fixture.plan(&ctx);
        rc.stage_limit = Some(Instant::now() + Duration::from_secs(6));
        let script = fs::read_to_string(&fixture.bin)
            .unwrap()
            .replace("NULL_AFTER_MS=300", "NULL_AFTER_MS=never");
        fs::write(&fixture.bin, script).unwrap();
        let mut prompt = Script::yes(3);
        assert!(!rc.disconnect(&ctx, &mut prompt));
        assert_eq!(rc.counts.not_disconnected, 1);
        assert_eq!(rc.counts.disconnected, 0);
        rc.finish(&ctx, &mut prompt, Action::Restore);
        assert_eq!(fixture.log().matches("arg send-keys\n").count(), 2);
        assert_eq!(prompt.questions.len(), 2);
    }

    #[test]
    fn remote_control_drop_after_reconnect_is_not_confirmed() {
        let fixture = Fixture::new();
        let ctx = context();
        let mut rc = fixture.plan(&ctx);
        let mut prompt = Script::yes(3);
        assert!(rc.disconnect(&ctx, &mut prompt));
        let script = fs::read_to_string(&fixture.bin)
            .unwrap()
            .replace("export HOME=", "export AGCTL_FAKE_TMUX_DROP_AFTER_MS=500\nexport HOME=");
        fs::write(&fixture.bin, script).unwrap();
        rc.finish(&ctx, &mut prompt, Action::Restore);
        assert_eq!(rc.counts.restored, 0);
        assert_eq!(rc.counts.not_confirmed, 1);
        assert_eq!(fixture.log().matches("arg send-keys\n").count(), 3);
    }

    #[test]
    fn remote_control_small_stage_reserve_makes_no_tmux_call() {
        let fixture = Fixture::new();
        let ctx = PassCtx::standalone(
            Cancel::new(),
            Instant::now() + RC_STAGE_RESERVE + Duration::from_secs(4),
        );
        let mut rc = fixture.plan(&ctx);
        assert!(!rc.disconnect(&ctx, &mut Script::yes(2)));
        assert!(fixture.log().is_empty());
    }

    #[test]
    fn remote_control_cancel_during_disconnect_poll_makes_no_restore_call() {
        let fixture = Fixture::new();
        let ctx = context();
        let mut rc = fixture.plan(&ctx);
        let script = fs::read_to_string(&fixture.bin)
            .unwrap()
            .replace("NULL_AFTER_MS=300", "NULL_AFTER_MS=never");
        fs::write(&fixture.bin, script).unwrap();
        let mut prompt = Script::yes(2);
        let cancel = ctx.cancel().clone();
        let log = fixture.log.clone();
        let watcher = std::thread::spawn(move || {
            let end = Instant::now() + Duration::from_secs(10);
            while Instant::now() < end {
                if fs::read_to_string(&log)
                    .unwrap_or_default()
                    .contains("arg Up\narg Up\narg Enter")
                {
                    cancel.cancel();
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            panic!("disconnect sequence never appeared");
        });
        assert!(!rc.disconnect(&ctx, &mut prompt));
        watcher.join().unwrap();
        let before = fixture.log();
        rc.finish(&ctx, &mut prompt, Action::Restore);
        assert_eq!(fixture.log(), before);
        assert_eq!(rc.counts.not_disconnected, 1);
    }

    #[test]
    fn remote_control_bridge_guard_never_toggles_an_already_connected_reconnect() {
        let fixture = Fixture::new();
        let ctx = context();
        let rc = fixture.plan(&ctx);
        let stage = Stage {
            dir: &fixture.dir,
            config: &fixture.config,
            bin: &fixture.bin,
            ctx: &ctx,
            end: ctx.deadline(),
            notice: &cleanup::register_exit_notice(0, not_confirmed_warning),
        };
        for group in [Group::Reconnect, Group::Restore] {
            assert_eq!(
                stage.group(&rc.sessions[0].session, group, &mut Script::yes(1)),
                GroupResult::AlreadyConnected
            );
        }
        assert!(fixture.log().is_empty());
        assert!(fixture.root.path().exists());
        assert!(fixture._master.as_raw_fd() >= 0);
    }
}
