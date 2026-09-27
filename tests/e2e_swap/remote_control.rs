//! The opt-in restart path uses two real PTYs: one foreground sleep process
//! per synthetic session, and a separate terminal for agctl's fresh answers.

use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;

use super::*;

#[path = "remote_control_more.rs"]
mod more;

fn normal_config() -> Value {
    let mut document = common::live_config_document();
    document["editorMode"] = json!("normal");
    document
}

fn pty() -> (File, File, PathBuf) {
    let master =
        rustix::pty::openpt(rustix::pty::OpenptFlags::RDWR | rustix::pty::OpenptFlags::NOCTTY)
            .unwrap();
    rustix::io::fcntl_setfd(&master, rustix::io::FdFlags::CLOEXEC).unwrap();
    rustix::pty::grantpt(&master).unwrap();
    rustix::pty::unlockpt(&master).unwrap();
    let name = rustix::pty::ptsname(&master, Vec::new()).unwrap();
    let slave = rustix::fs::open(
        name.as_c_str(),
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOCTTY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    let mut settings = rustix::termios::tcgetattr(&slave).unwrap();
    settings.local_modes.remove(rustix::termios::LocalModes::ECHO);
    rustix::termios::tcsetattr(&slave, rustix::termios::OptionalActions::Now, &settings).unwrap();
    (File::from(master), File::from(slave), PathBuf::from(name.to_str().unwrap()))
}

struct Session {
    child: Child,
    foreground: Option<rustix::process::Pid>,
    _master: File,
    tty: PathBuf,
    path: PathBuf,
    root: PathBuf,
    document: Value,
}
impl Drop for Session {
    fn drop(&mut self) {
        if let Some(foreground) = self.foreground
            && self.child.try_wait().is_ok_and(|status| status.is_none())
        {
            // The owned parent never reaps this child, so its pid cannot be
            // recycled while that parent is still running.
            let _ = rustix::process::kill_process(foreground, rustix::process::Signal::KILL);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Session {
    fn new(fixture: &Fixture, pane: u32) -> Self {
        Self::spawn(fixture, pane, false)
    }

    fn spawn(fixture: &Fixture, pane: u32, background: bool) -> Self {
        let (master, slave, tty) = pty();
        let (mut observed, writer) = UnixStream::pair().unwrap();
        let mut command = Command::new("sleep");
        command
            .arg("300")
            .stdin(slave)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env("HOME", fixture.home());
        // SAFETY: the child owns fd 0; only async-signal-safe syscalls precede exec.
        unsafe {
            command.pre_exec(move || {
                if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY.into(), 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if background {
                    let foreground = libc::fork();
                    if foreground < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if foreground == 0 {
                        if libc::setpgid(0, 0) < 0 {
                            libc::_exit(126);
                        }
                        let argv = [c"sleep".as_ptr(), c"300".as_ptr(), std::ptr::null()];
                        libc::execv(c"/bin/sleep".as_ptr(), argv.as_ptr());
                        libc::_exit(127);
                    }
                    if (libc::setpgid(foreground, foreground) < 0
                        && libc::getpgid(foreground) != foreground)
                        || libc::tcsetpgrp(0, foreground) < 0
                        || libc::write(
                            writer.as_raw_fd(),
                            (&raw const foreground).cast(),
                            size_of::<libc::pid_t>(),
                        ) != size_of::<libc::pid_t>() as isize
                    {
                        let error = std::io::Error::last_os_error();
                        libc::kill(foreground, libc::SIGKILL);
                        return Err(error);
                    }
                }
                Ok(())
            });
        }
        // spawn reports successful exec only after setsid/TIOCSCTTY completed.
        // tcgetpgrp from the parent would reject a tty outside its own session.
        let child = command.spawn().unwrap();
        let foreground = if background {
            let mut bytes = [0_u8; size_of::<libc::pid_t>()];
            observed.read_exact(&mut bytes).unwrap();
            Some(rustix::process::Pid::from_raw(libc::pid_t::from_ne_bytes(bytes)).unwrap())
        } else {
            None
        };
        let dir = fixture.home().join(".claude/sessions");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{}.json", child.id()));
        let key = dir.join(format!("{}.private.key", child.id()));
        fs::write(&key, b"unchanged key sentinel").unwrap();
        let document = json!({"pid":child.id(), "sessionId":format!("private-session-{pane}"), "name":format!("rc-e2e-{pane}"),
            "bridgeSessionId":format!("session_private_bridge_{pane}"), "tmux":format!("private-name:@0.%{pane}"), "cwd":fixture.home().join("private-cwd"),
            "version":"2.1.281", "status":"idle", "statusUpdatedAt":1});
        fs::write(&path, document.to_string()).unwrap();
        Self { child, foreground, _master: master, tty, path, root: fixture.scratch(""), document }
    }
    fn save(&self, document: &Value) {
        let states = self.root.join("tmux-states");
        fs::create_dir_all(&states).unwrap();
        let bytes = document.to_string();
        let source = states.join(format!("{}.fixture.json", self.child.id()));
        fs::write(&source, &bytes).unwrap();
        let state = format!("fixture-{}", file_hash(&source));
        fs::rename(&source, states.join(format!("{}.{state}.json", self.child.id()))).unwrap();
        let output =
            Command::new(Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/fake-tmux.sh"))
                .args(["fixture-state", &self.child.id().to_string(), &state])
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", self.root.join("home"))
                .env("AGCTL_FAKE_TMUX_LOG", self.root.join("tmux.log"))
                .env("AGCTL_FAKE_TMUX_REGISTRY", self.path.parent().unwrap())
                .env("AGCTL_FAKE_TMUX_STATES", states)
                .output()
                .unwrap();
        assert!(
            output.status.success(),
            "fixture move: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn setup(fixture: &mut Fixture, sessions: &[&Session], resolved: &Path) {
    let unrelated = fixture.home().join(".claude/sessions/unrelated");
    fs::create_dir_all(&unrelated).unwrap();
    fs::write(unrelated.join("preserved.key"), b"nested unchanged key sentinel").unwrap();
    fs::write(unrelated.join("preserved.txt"), b"unrelated registry sentinel").unwrap();
    let audit = fixture.audit_log_path();
    if !audit.exists() {
        fs::create_dir_all(audit.parent().unwrap()).unwrap();
        fs::write(&audit, "").unwrap();
        fs::set_permissions(&audit, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let states = fixture.scratch("tmux-states");
    fs::create_dir_all(&states).unwrap();
    let panes = fixture.scratch("tmux-panes");
    let mut rows = String::new();
    for session in sessions {
        let pid = session.child.id();
        let pane = session.document["tmux"].as_str().unwrap().rsplit('.').next().unwrap();
        rows.push_str(&format!("{pane} {pid} {} 0 0 0\n", session.tty.display()));
        let mut panel = session.document.clone();
        panel["status"] = json!("waiting");
        panel["waitingFor"] = json!("dialog open");
        let mut off = session.document.clone();
        off["bridgeSessionId"] = Value::Null;
        fs::write(states.join(format!("{pid}.panel.json")), panel.to_string()).unwrap();
        fs::write(states.join(format!("{pid}.disconnected.json")), off.to_string()).unwrap();
        fs::write(states.join(format!("{pid}.reconnected.json")), session.document.to_string())
            .unwrap();
    }
    fs::write(&panes, rows).unwrap();
    let bin = fixture.scratch("tmux-test");
    let fake = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/fake-tmux.sh");
    let screens = fixture.scratch("rc-screens");
    fs::create_dir_all(&screens).unwrap();
    for entry in
        fs::read_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/rc-screens")).unwrap()
    {
        let entry = entry.unwrap();
        let mut bytes = b"RC_SCREEN_SENTINEL\n".to_vec();
        bytes.extend(fs::read(entry.path()).unwrap());
        fs::write(screens.join(entry.file_name()), bytes).unwrap();
    }
    // The stand-in's SCREEN knob always names one file. This fixture wrapper
    // selects the synthetic panel/prompt by the registry state, never a real pane.
    let script = format!(
        "#!/bin/sh\npane=\nprev=\nfor arg in \"$@\"; do if [ \"$prev\" = -t ]; then pane=$arg; break; fi; prev=$arg; done\npid=$(awk -v pane=\"$pane\" '$1 == pane {{print $2; exit}}' \"$AGCTL_FAKE_TMUX_PANES\")\nif [ -z \"${{AGCTL_FAKE_TMUX_SCREEN:-}}\" ] && [ -n \"$pid\" ]; then\n status=$(perl -MJSON::PP -e 'local $/; open my $f, \"<\", $ARGV[0] or die; print decode_json(<$f>)->{{status}}' \"$AGCTL_FAKE_TMUX_REGISTRY/$pid.json\")\n if [ \"$status\" = waiting ]; then export AGCTL_FAKE_TMUX_SCREEN='{}/c20-panel.txt'; else export AGCTL_FAKE_TMUX_SCREEN='{}/empty-prompt.txt'; fi\nfi\nexec '{}' \"$@\"\n",
        screens.display(),
        screens.display(),
        fake.display()
    );
    fs::write(&bin, script).unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).unwrap();
    fixture.set("AGCTL_TMUX_BIN", bin.to_str().unwrap());
    fixture.set("AGCTL_FAKE_TMUX_LOG", fixture.scratch("tmux.log").to_str().unwrap());
    fixture.set("AGCTL_FAKE_TMUX_PANES", panes.to_str().unwrap());
    fixture
        .set("AGCTL_FAKE_TMUX_REGISTRY", fixture.home().join(".claude/sessions").to_str().unwrap());
    fixture.set("AGCTL_FAKE_TMUX_STATES", states.to_str().unwrap());
    fixture.set("AGCTL_FAKE_TMUX_NULL_AFTER_MS", "300");
    fixture.set(
        "AGCTL_FAKE_TMUX_WATCH",
        &format!(
            "{}:{}:{}",
            fixture.home().join(".claude.json").display(),
            fixture.scratch("keychain-dump.txt").display(),
            fixture.audit_log_path().display()
        ),
    );
    let mut locks = Fixture::live_hold_artefacts(resolved).to_vec();
    locks.push(fixture.home().join(".claude.json.lock"));
    locks.push(resolved.join(".claude.json.lock"));
    fixture.set(
        "AGCTL_FAKE_TMUX_LOCKS",
        &locks.iter().map(|path| path.display().to_string()).collect::<Vec<_>>().join(":"),
    );
    fixture.set(
        "AGCTL_FAKE_TMUX_FLOCKS",
        &format!(
            "{}:{}",
            fixture.lock_path(ACCT, ORG).display(),
            fixture.lock_path(ACCT_T, ORG_T).display()
        ),
    );
    fixture.set("TMUX", fixture.scratch("private-tmux-socket").to_str().unwrap());
}

#[derive(Clone, Copy)]
enum Reply {
    Yes,
    No,
    Eof,
    Partial,
    Wait,
    LoseTty,
    Interrupt,
    YesThenSignal,
}

struct Run {
    output: common::Output,
    questions: Vec<String>,
}

fn run(fixture: &Fixture, args: &[&str], answer: impl FnMut(usize, &str) -> Reply) -> Run {
    run_channel(fixture, args, false, answer)
}

fn run_channel(
    fixture: &Fixture,
    args: &[&str],
    stdout_terminal: bool,
    mut answer: impl FnMut(usize, &str) -> Reply,
) -> Run {
    let registry = fixture.home().join(".claude/sessions");
    let registry_before = session_tree(&registry);
    let keys_before: BTreeMap<_, _> = registry_before
        .keys()
        .filter(|path| path.extension().is_some_and(|extension| extension == "key"))
        .map(|path| (path.clone(), fs::read(registry.join(path)).unwrap()))
        .collect();
    let log_before = fs::read_to_string(fixture.scratch("tmux.log")).unwrap_or_default();
    let forbidden = forbidden_output(fixture, &registry_before);
    let (mut master, slave, _) = pty();
    let mut command = fixture.raw();
    command.args(args).stdin(slave.try_clone().unwrap());
    if stdout_terminal {
        command.stdout(slave.try_clone().unwrap());
    } else {
        command.stdout(Stdio::piped());
    }
    command.stderr(slave);
    let mut child = command.spawn().unwrap();
    let stdout = child.stdout.take();
    let out = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(mut stdout) = stdout {
            stdout.read_to_end(&mut bytes).unwrap();
        }
        bytes
    });
    let end = Instant::now() + Duration::from_secs(190);
    let mut bytes = Vec::new();
    let mut consumed = 0;
    let mut questions = Vec::new();
    let mut arm_signal = false;
    let mut signal_at = None;
    let mut signalled = false;
    let status = loop {
        if Instant::now() >= end {
            let _ = child.kill();
            let _ = child.wait();
            panic!("interactive child timed out: {}", String::from_utf8_lossy(&bytes));
        }
        let mut fds = [rustix::event::PollFd::new(&master, rustix::event::PollFlags::IN)];
        let timeout = rustix::event::Timespec::try_from(Duration::from_millis(20)).unwrap();
        if rustix::event::poll(&mut fds, Some(&timeout)).unwrap() > 0 {
            let mut chunk = [0; 8192];
            match master.read(&mut chunk) {
                Ok(n) => bytes.extend_from_slice(&chunk[..n]),
                Err(error) if error.raw_os_error() == Some(libc::EIO) => {}
                Err(error) => panic!("PTY read: {error}"),
            }
        }
        let text = String::from_utf8_lossy(&bytes);
        while let Some(at) = text[consumed..].find("[y/N]") {
            let stop = consumed + at + "[y/N]".len();
            let question = text[consumed..stop].to_owned();
            consumed = stop;
            let reply = answer(questions.len(), &question);
            questions.push(question);
            let response: &[u8] = match reply {
                Reply::Yes => b"y\n",
                Reply::No => b"n\n",
                Reply::Eof => b"\x04",
                Reply::Partial => b"y",
                Reply::Wait => b"",
                Reply::LoseTty => {
                    master = File::open("/dev/null").unwrap();
                    b""
                }
                Reply::Interrupt => {
                    rustix::process::kill_process(
                        rustix::process::Pid::from_raw(child.id() as i32).unwrap(),
                        rustix::process::Signal::INT,
                    )
                    .unwrap();
                    b""
                }
                Reply::YesThenSignal => {
                    arm_signal = true;
                    b"y\n"
                }
            };
            master.write_all(response).unwrap();
        }
        if arm_signal && !signalled {
            let log = fs::read_to_string(fixture.scratch("tmux.log")).unwrap_or_default();
            if signal_at.is_none() && log.contains("arg Up\narg Up\narg Enter\n") {
                signal_at = Some(Instant::now() + Duration::from_millis(300));
            }
            if signal_at.is_some_and(|at| Instant::now() >= at) {
                rustix::process::kill_process(
                    rustix::process::Pid::from_raw(child.id() as i32).unwrap(),
                    rustix::process::Signal::INT,
                )
                .unwrap();
                signalled = true;
            }
        }
        if let Some(status) = child.try_wait().unwrap() {
            // Drain the terminal after exit without waiting for inherited slave fds.
            rustix::fs::fcntl_setfl(&master, rustix::fs::OFlags::NONBLOCK).unwrap();
            let mut chunk = [0; 8192];
            while let Ok(n) = master.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                bytes.extend_from_slice(&chunk[..n]);
            }
            break status;
        }
    };
    let result = Run {
        output: common::Output {
            code: status.code(),
            stdout: String::from_utf8(out.join().unwrap()).unwrap(),
            stderr: String::from_utf8_lossy(&bytes).replace("\r\n", "\n"),
        },
        questions,
    };
    assert_registry_unchanged(fixture, &registry_before, &keys_before, &log_before);
    assert_output_hygiene(fixture, &result, &forbidden);
    result
}

fn assert_registry_unchanged(
    fixture: &Fixture,
    before: &BTreeMap<PathBuf, SessionSnapshot>,
    keys: &BTreeMap<PathBuf, Vec<u8>>,
    log_before: &str,
) {
    let registry = fixture.home().join(".claude/sessions");
    let after = session_tree(&registry);
    assert_eq!(
        before.keys().collect::<Vec<_>>(),
        after.keys().collect::<Vec<_>>(),
        "AC159: registry tree membership"
    );
    let log = fs::read_to_string(fixture.scratch("tmux.log")).unwrap_or_default();
    let delta = log.strip_prefix(log_before).expect("fake log is append-only during each run");
    let mut moved = BTreeMap::new();
    for line in delta.lines().filter_map(|line| line.strip_prefix("move ")) {
        let (pid, state) = line.split_once(' ').expect("logged fixture move");
        let path = PathBuf::from(format!("{pid}.json"));
        assert!(before.contains_key(&path), "fake may replace only an existing session");
        moved.insert(path, fixture.scratch("tmux-states").join(format!("{pid}.{state}.json")));
    }
    for (path, original) in before {
        if let Some(source) = moved.get(path) {
            assert_eq!(
                fs::read(registry.join(path)).unwrap(),
                fs::read(source).unwrap(),
                "AC159: only the final logged fixture state may replace {path:?}"
            );
        } else if path.as_os_str().is_empty() && !moved.is_empty() {
            // Atomic replacements change the parent directory's size/mtime,
            // never its mode or the membership checked above.
            assert_eq!(original.mode, after[path].mode);
            assert_eq!(original.sha256, after[path].sha256);
        } else {
            assert_eq!(original, &after[path], "AC159: unlogged registry change at {path:?}");
        }
    }
    for (path, bytes) in keys {
        assert_eq!(&fs::read(registry.join(path)).unwrap(), bytes, "AC159: key bytes at {path:?}");
    }
}

fn forbidden_output(fixture: &Fixture, tree: &BTreeMap<PathBuf, SessionSnapshot>) -> Vec<String> {
    let registry = fixture.home().join(".claude/sessions");
    let mut forbidden = vec![
        fixture.home().display().to_string(),
        fixture.home().join("private-cwd").display().to_string(),
        fixture.scratch("tmux-test").display().to_string(),
        Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/fake-tmux.sh").display().to_string(),
        fixture.scratch("private-tmux-socket").display().to_string(),
        registry.display().to_string(),
        "rc-screens".to_owned(),
        "RC_SCREEN_SENTINEL".to_owned(),
    ];
    let panes = fs::read_to_string(fixture.scratch("tmux-panes")).unwrap_or_default();
    for row in panes.lines() {
        forbidden.extend(row.split_whitespace().take(3).map(str::to_owned));
    }
    for path in
        tree.keys().filter(|path| path.extension().is_some_and(|extension| extension == "json"))
    {
        let path = registry.join(path);
        forbidden.push(path.display().to_string());
        let Ok(document) = serde_json::from_slice::<Value>(&fs::read(path).unwrap()) else {
            continue;
        };
        for key in ["sessionId", "bridgeSessionId", "name", "cwd", "tmux"] {
            if let Some(value) = document[key].as_str().filter(|value| !value.is_empty()) {
                forbidden.push(value.to_owned());
            }
        }
        if let Some(pid) = document["pid"].as_u64() {
            forbidden.push(pid.to_string());
        }
    }
    forbidden.sort();
    forbidden.dedup();
    forbidden
}

fn log_events(run: &Run) -> String {
    common::strip_ansi(&run.output.stderr)
        .lines()
        // Strip the human [y/N] prefix and tracing timestamp, never the
        // level, target, message or fields. Echo is disabled.
        .map(|line| line.rsplit("[y/N] ").next().unwrap_or(line))
        .map(|line| match line.split_once(' ') {
            Some((stamp, rest))
                if stamp.as_bytes().first().is_some_and(u8::is_ascii_digit)
                    && stamp.ends_with('Z') =>
            {
                rest
            }
            _ => line,
        })
        .filter(|line| {
            ["DEBUG", "INFO", "WARN", "ERROR", "TRACE"].iter().any(|level| line.contains(level))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn restart_log_hygiene_keeps_identity_fields_but_not_timestamps() {
    let stamp = "2026-09-26T22:39:14.317280Z";
    let clean =
        captured("", &format!("question [y/N] {stamp} DEBUG agctl::runtime::tmux: tmux call\n"));
    assert_eq!(log_events(&clean), "DEBUG agctl::runtime::tmux: tmux call");
    assert!(leaks(stamp, "2026"), "an unstripped stamp fails the check below");
    assert_output_hygiene(&Fixture::new(), &clean, &["2026".to_owned()]);
    for prefix in [format!("{stamp} "), String::new()] {
        let with_identity = captured("", &format!("{prefix}WARN agctl::runtime::tmux: pid=3172\n"));
        assert_eq!(log_events(&with_identity), "WARN agctl::runtime::tmux: pid=3172");
    }
}

// An all-digit value is a pid, which the OS picks per run. Its digits also
// occur inside unrelated hex digests, so it leaks only as a whole token.
fn leaks(text: &str, value: &str) -> bool {
    if value.bytes().all(|byte| byte.is_ascii_digit()) {
        text.split(|c: char| !c.is_ascii_alphanumeric()).any(|token| token == value)
    } else {
        text.contains(value)
    }
}

fn captured(stdout: &str, stderr: &str) -> Run {
    Run {
        output: common::Output {
            code: Some(0),
            stdout: stdout.to_owned(),
            stderr: stderr.to_owned(),
        },
        questions: Vec::new(),
    }
}

#[test]
fn restart_output_hygiene_compares_a_pid_as_a_whole_token() {
    // PR #6 run 36289983531: pid 31704 met the `from` digest of this plan.
    let plan = r#"{"kind":"plan","direction":"forward","to":{"digest8":"36f527ce"},"service":"Claude Code-credentials","account":"incoming@example.com","from":{"digest8":"a9231704"}}"#;
    for pid in ["31704", "9231704", "704", "527", "36"] {
        assert!(!leaks(plan, pid), "{pid} is part of a digest, never a pid");
    }
    for text in [
        r#"{"pid":31704}"#,
        r#"{"path":"sessions/31704.json"}"#,
        "WARN agctl::runtime::tmux: pid=31704",
        "pane %7 31704 /dev/ttys012",
        "session_31704",
        "31704",
    ] {
        assert!(leaks(text, "31704"), "{text}");
    }
    assert!(leaks("name=rc-e2e-71", "rc-e2e-7"), "every other value stays a substring");
    let digest_event = "DEBUG agctl::commands::use: digest8=a9231704";
    assert_output_hygiene(&Fixture::new(), &captured(plan, digest_event), &["31704".to_owned()]);
}

#[test]
#[should_panic(expected = "AC163: forbidden \"31704\" in JSON")]
fn restart_output_hygiene_rejects_a_pid_member_in_json() {
    let outcome = r#"{"kind":"outcome","remote_control":{"pid":31704}}"#;
    assert_output_hygiene(&Fixture::new(), &captured(outcome, ""), &["31704".to_owned()]);
}

#[test]
#[should_panic(expected = "AC163: forbidden \"31704\" in log events")]
fn restart_output_hygiene_rejects_a_pid_field_in_log_events() {
    let event = "WARN agctl::runtime::tmux: pid=31704\n";
    assert_output_hygiene(&Fixture::new(), &captured("", event), &["31704".to_owned()]);
}

fn assert_output_hygiene(fixture: &Fixture, run: &Run, forbidden: &[String]) {
    let events = log_events(run);
    for value in forbidden {
        assert!(!leaks(&events, value), "AC163: forbidden {value:?} in log events: {events}");
    }
    // Human-only stdout-terminal controls have no piped JSON. D7 exempts
    // exactly the pre-existing top-level plan paths, no other field.
    let documents: Vec<Value> = serde_json::Deserializer::from_str(&run.output.stdout)
        .into_iter()
        .map(Result::unwrap)
        .collect();
    let home = fixture.home().display().to_string();
    let allowed = documents
        .iter()
        .map(|value| {
            ["store_dir", "config_path"]
                .iter()
                .map(|key| value[*key].as_str().map_or(0, |path| path.matches(&home).count()))
                .sum::<usize>()
        })
        .sum::<usize>();
    assert_eq!(
        run.output.stdout.matches(&home).count(),
        allowed,
        "D7: only plan paths contain HOME"
    );
    for mut value in documents {
        value.as_object_mut().unwrap().remove("store_dir");
        value.as_object_mut().unwrap().remove("config_path");
        let text = value.to_string();
        for value in forbidden {
            assert!(!leaks(&text, value), "AC163: forbidden {value:?} in JSON: {text}");
        }
    }
}

fn forward() -> [&'static str; 6] {
    ["claude", "use", "--live", EMAIL_T, "--restart-remote-control", "--json"]
}
fn doc(run: &Run) -> Value {
    outcome_doc(&run.output.stdout)
}
fn calls(fixture: &Fixture) -> Vec<Vec<String>> {
    let log = fs::read_to_string(fixture.scratch("tmux.log")).unwrap_or_default();
    let mut result: Vec<Vec<String>> = Vec::new();
    for line in log.lines() {
        if line == "call" {
            result.push(Vec::new());
        }
        if let Some(arg) = line.strip_prefix("arg ") {
            result.last_mut().unwrap().push(arg.to_owned());
        }
    }
    result
}
fn sends(fixture: &Fixture) -> usize {
    calls(fixture).iter().filter(|call| call[0] == "send-keys").count()
}
fn file_hash(path: &Path) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(fs::read(path).unwrap()))
}

fn assert_counts(doc: &Value) {
    let expected = [
        "eligible",
        "disconnected",
        "reconnected",
        "restored",
        "not_disconnected",
        "not_confirmed",
        "skipped",
        "gone",
        "already_connected",
        "not_attested",
        "attestation_declined",
    ];
    let counts = doc["remote_control"].as_object().expect("flag always includes counts");
    assert_eq!(counts.len(), expected.len());
    for name in expected {
        assert!(counts[name].is_u64(), "integer {name}: {doc}");
    }
}
fn credential_files(fixture: &Fixture) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    [(ACCT, ORG), (ACCT_T, ORG_T)]
        .into_iter()
        .flat_map(|(acct, org)| {
            [fixture.credentials_path(acct, org), adopted_path(fixture, acct, org)]
        })
        .map(|path| {
            let bytes = match fs::read(&path) {
                Ok(bytes) => Some(bytes),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => panic!("snapshot {}: {error}", path.display()),
            };
            (path, bytes)
        })
        .collect()
}

fn assert_unchanged(
    fixture: &Fixture,
    before: &[(String, Vec<u8>)],
    config: &[u8],
    credentials: &BTreeMap<PathBuf, Option<Vec<u8>>>,
) {
    assert_eq!(&credential_files(fixture), credentials, "namespace credential presence and bytes");
    assert_eq!(fixture.keychain_items(), before);
    assert_eq!(fs::read(fixture.home().join(".claude.json")).unwrap(), config);
    assert!(config_steps(fixture).is_empty());
}
fn assert_released(fixture: &Fixture, resolved: &Path) {
    live_artefacts_released(fixture, resolved);
    for (acct, org) in [(ACCT, ORG), (ACCT_T, ORG_T)] {
        if let Ok(lock) = File::open(fixture.lock_path(acct, org)) {
            rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
        }
    }
}

#[test]
fn ac169_restart_preflight_requires_both_ttys_before_any_io() {
    let server = MockServer::start();
    let (p, t) = live_profiles(&server);
    let token = token_ok(&server);
    for piped in ["stdin", "stderr", "both"] {
        let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
        fixture.live_claude_json_js(&normal_config());
        let session = Session::new(&fixture, 7);
        setup(&mut fixture, &[&session], &resolved);
        let before = fixture.keychain_items();
        let credentials = credential_files(&fixture);
        let config = fs::read(fixture.home().join(".claude.json")).unwrap();
        let (_master, slave, _) = pty();
        let mut command = fixture.raw();
        command.args(forward());
        if piped == "stdin" {
            command.stderr(slave);
        } else if piped == "stderr" {
            command.stdin(slave);
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(30), "{piped}");
        let doc: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_counts(&doc);
        assert_eq!(doc["reason"], "remote_control_needs_tty");
        assert!(doc.get("refusal").is_none());
        assert!(doc["remote_control"].as_object().unwrap().values().all(|v| v == 0));
        assert!(calls(&fixture).is_empty());
        assert!(!fixture.security_log_path().exists());
        assert_unchanged(&fixture, &before, &config, &credentials);
    }
    assert_eq!(p.calls(), 0);
    assert_eq!(t.calls(), 0);
    assert_eq!(token.calls(), 0);
}

#[test]
fn ac149_restart_forward_and_undo_have_exact_groups_and_counts_only_output() {
    let server = MockServer::start();
    let (_p, _t) = live_profiles(&server);
    let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
    fixture.live_claude_json_js(&normal_config());
    let mut session = Session::new(&fixture, 7);
    session.document["version"] = json!("2.1.999");
    session.save(&session.document);
    setup(&mut fixture, &[&session], &resolved);
    let (baseline, _) = live_accounts(&server, common::fresh_at());
    baseline.live_claude_json_js(&normal_config());
    for reverse in [false, true] {
        if reverse {
            fs::write(fixture.scratch("tmux.log"), "").unwrap();
        }
        let args = if reverse {
            vec!["claude", "use", "--undo", "--restart-remote-control", "--json"]
        } else {
            forward().to_vec()
        };
        let baseline_before =
            fs::read_to_string(baseline.audit_log_path()).unwrap_or_default().lines().count();
        let plain_args = if reverse {
            vec!["claude", "use", "--undo", "--yes", "--json"]
        } else {
            vec!["claude", "use", "--live", EMAIL_T, "--yes", "--json"]
        };
        let plain = baseline.raw().args(plain_args).output().unwrap();
        assert!(plain.status.success(), "{}", String::from_utf8_lossy(&plain.stderr));
        let expected_receipts =
            fs::read_to_string(baseline.audit_log_path()).unwrap().lines().count()
                - baseline_before;
        let audit_before = fs::read_to_string(fixture.audit_log_path()).unwrap().lines().count();
        let watched = [
            fixture.home().join(".claude.json"),
            fixture.scratch("keychain-dump.txt"),
            fixture.audit_log_path(),
        ];
        let hashes = watched.iter().map(|path| file_hash(path)).collect::<Vec<_>>();
        let run = run(&fixture, &args, |_, _| Reply::Yes);
        assert_eq!(run.output.code(), 0, "{}{}", run.output.stdout, run.output.stderr);
        assert_eq!(run.output.stderr.matches("Remote Control automation was last verified on 2.1.281; this session runs 2.1.999").count(), 1);
        assert_eq!(
            fs::read_to_string(fixture.audit_log_path()).unwrap().lines().count() - audit_before,
            expected_receipts,
            "AC163: keystrokes add no audit receipts"
        );
        let transport_log = fs::read_to_string(fixture.scratch("tmux.log")).unwrap();
        let observations = transport_log.split("call\n").skip(1).collect::<Vec<_>>();
        assert_eq!(observations.len(), 10);
        for (index, observation) in observations.iter().enumerate() {
            for line in observation.lines().filter(|line| line.starts_with("lock ")) {
                assert!(line.ends_with(" absent"), "{line}");
            }
            for line in observation.lines().filter(|line| line.starts_with("flock ")) {
                assert!(
                    line.ends_with(if index < 7 { " held" } else { " free" }),
                    "call {index}: {line}"
                );
            }
            for (path, old_hash) in watched.iter().zip(&hashes) {
                let expected = if index < 7 { old_hash.clone() } else { file_hash(path) };
                assert!(
                    observation.contains(&format!("watch {} {expected}", path.display())),
                    "call {index}: wrong write ordering"
                );
            }
        }
        assert!(fs::read_to_string(fixture.audit_log_path()).unwrap().contains("config_write"));
        let outcome = doc(&run);
        assert_counts(&outcome);
        assert_eq!(outcome["remote_control"]["reconnected"], 1);
        assert_eq!(run.questions.len(), 4);
        assert!(run.questions[0].contains("`rc-e2e-7` in %7"));
        assert!(run.questions[0].contains("30 seconds"));
        assert!(run.questions[1].contains("for opening"));
        assert!(run.questions[2].contains("expected-panel disconnect"));
        assert!(run.questions[3].contains("for reconnect"));
        let state = vec![
            "display-message",
            "-p",
            "-t",
            "%7",
            "#{pane_pid} #{pane_tty} #{pane_in_mode} #{pane_dead} #{pane_synchronized}",
        ];
        let capture = vec!["capture-pane", "-p", "-t", "%7", "-S", "0", "-E", "-"];
        let slash = vec!["send-keys", "-t", "%7", "/remote-control", "Enter"];
        let disconnect = vec!["send-keys", "-t", "%7", "Up", "Up", "Enter"];
        assert_eq!(
            calls(&fixture),
            [
                state.clone(),
                state.clone(),
                capture.clone(),
                slash.clone(),
                state.clone(),
                capture.clone(),
                disconnect,
                state,
                capture,
                slash
            ]
        );
        assert_released(&fixture, &resolved);
        let events = log_events(&run);
        assert_eq!(events.matches("Remote Control stage").count(), 2);
    }
}

#[test]
fn ac170_restart_declines_eof_partial_and_deadlines_at_each_input_group() {
    for group in [1, 2] {
        for (label, reply, field) in [
            ("decline", Reply::No, "attestation_declined"),
            ("EOF", Reply::Eof, "not_attested"),
            ("partial", Reply::Partial, "not_attested"),
            ("expiry", Reply::Wait, "not_attested"),
        ] {
            let server = MockServer::start();
            let (_p, t) = live_profiles(&server);
            let token = token_ok(&server);
            let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
            fixture.live_claude_json_js(&normal_config());
            let session = Session::new(&fixture, 7);
            setup(&mut fixture, &[&session], &resolved);
            fixture.set("AGCTL_RC_BUDGET_MS", "6000");
            let before = fixture.keychain_items();
            let credentials = credential_files(&fixture);
            let config = fs::read(fixture.home().join(".claude.json")).unwrap();
            let run = run(
                &fixture,
                &forward(),
                |index, _| if index == group { reply } else { Reply::Yes },
            );
            assert_eq!(
                run.output.code(),
                30,
                "{group} {label}: {}{}",
                run.output.stdout,
                run.output.stderr
            );
            let outcome = doc(&run);
            assert_eq!(outcome["reason"], "remote_control_not_disconnected");
            assert!(outcome.get("refusal").is_none());
            assert_eq!(outcome["remote_control"][field], 1);
            assert_eq!(outcome["remote_control"]["not_disconnected"], 1);
            assert_eq!(sends(&fixture), group - 1);
            assert_unchanged(&fixture, &before, &config, &credentials);
            assert_eq!(token.calls(), 0);
            assert_eq!(t.calls(), 0);
            assert_released(&fixture, &resolved);
        }
    }
}

#[test]
fn ac152_restart_schema_versions_and_preflight_fail_before_input_or_post() {
    for (field, value) in [
        ("status", Value::Null),
        ("status", json!("new state")),
        ("waitingFor", Value::Null),
        ("waitingFor", json!("unknown")),
        ("version", json!("2.1.280")),
        ("version", json!("banner 2.1.281")),
        ("statusUpdatedAt", json!("invalid")),
        ("sessionId", Value::Null),
    ] {
        let server = MockServer::start();
        let (_p, t) = live_profiles(&server);
        let token = token_ok(&server);
        let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
        fixture.live_claude_json_js(&normal_config());
        let session = Session::new(&fixture, 7);
        setup(&mut fixture, &[&session], &resolved);
        let mut document = session.document.clone();
        document[field] = value.clone();
        session.save(&document);
        let before = fixture.keychain_items();
        let credentials = credential_files(&fixture);
        let config = fs::read(fixture.home().join(".claude.json")).unwrap();
        let run = run(&fixture, &forward(), |_, _| Reply::Yes);
        assert_eq!(
            run.output.code(),
            30,
            "{field}={value}: {}{}",
            run.output.stdout,
            run.output.stderr
        );
        assert_eq!(doc(&run)["remote_control"]["skipped"], 1);
        assert_eq!(sends(&fixture), 0);
        assert_unchanged(&fixture, &before, &config, &credentials);
        assert_eq!(token.calls(), 0);
        assert_eq!(t.calls(), 0);
    }
}

#[test]
fn ac153_restart_foreground_proof_rejects_stopped_other_tty_and_pane_modes() {
    for failure in ["stopped", "other tty", "copy", "dead", "synchronized", "short"] {
        let server = MockServer::start();
        let (_p, _t) = live_profiles(&server);
        let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
        fixture.live_claude_json_js(&normal_config());
        let session = Session::new(&fixture, 7);
        let other = Session::new(&fixture, 8);
        // The second process exists only to supply another real tty; it is not eligible.
        fs::remove_file(&other.path).unwrap();
        setup(&mut fixture, &[&session], &resolved);
        let pid = rustix::process::Pid::from_raw(session.child.id() as i32).unwrap();
        let row = match failure {
            "copy" => format!("%7 {} {} 1 0 0\n", session.child.id(), session.tty.display()),
            "dead" => format!("%7 {} {} 0 1 0\n", session.child.id(), session.tty.display()),
            "synchronized" => {
                format!("%7 {} {} 0 0 1\n", session.child.id(), session.tty.display())
            }
            "short" => format!("%7 {} {} 0 0\n", session.child.id(), session.tty.display()),
            "other tty" => format!("%7 {} {} 0 0 0\n", session.child.id(), other.tty.display()),
            "stopped" => {
                rustix::process::kill_process(pid, rustix::process::Signal::STOP).unwrap();
                fs::read_to_string(fixture.scratch("tmux-panes")).unwrap()
            }
            _ => unreachable!(),
        };
        fs::write(fixture.scratch("tmux-panes"), row).unwrap();
        let run = run(&fixture, &forward(), |_, _| Reply::Yes);
        assert_eq!(run.output.code(), 30, "{failure}: {}{}", run.output.stdout, run.output.stderr);
        assert_eq!(doc(&run)["remote_control"]["skipped"], 1);
        assert_eq!(doc(&run)["remote_control"]["restored"], 0);
        assert_eq!(sends(&fixture), 0);
    }
}

#[test]
fn ac155_restart_insufficient_stage_reserve_never_calls_tmux() {
    let server = MockServer::start();
    let (_p, _t) = live_profiles(&server);
    let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
    fixture.live_claude_json_js(&normal_config());
    let session = Session::new(&fixture, 7);
    setup(&mut fixture, &[&session], &resolved);
    fixture.set("AGCTL_SWAP_DEADLINE_MS", "55000");
    let before = fixture.keychain_items();
    let credentials = credential_files(&fixture);
    let config = fs::read(fixture.home().join(".claude.json")).unwrap();
    let run = run(&fixture, &forward(), |_, _| Reply::Yes);
    assert_eq!(run.output.code(), 30);
    assert!(calls(&fixture).is_empty());
    assert_unchanged(&fixture, &before, &config, &credentials);
}

#[test]
fn ac164_restart_sigint_in_disconnect_poll_exits_130_with_counts_notice() {
    let server = MockServer::start();
    let (_p, _t) = live_profiles(&server);
    let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
    fixture.live_claude_json_js(&normal_config());
    let session = Session::new(&fixture, 7);
    setup(&mut fixture, &[&session], &resolved);
    fixture.set("AGCTL_FAKE_TMUX_NULL_AFTER_MS", "never");
    let before = fixture.keychain_items();
    let credentials = credential_files(&fixture);
    let config = fs::read(fixture.home().join(".claude.json")).unwrap();
    let run = run(
        &fixture,
        &forward(),
        |index, _| if index == 2 { Reply::YesThenSignal } else { Reply::Yes },
    );
    assert_eq!(run.output.code(), 130, "{}{}", run.output.stdout, run.output.stderr);
    assert!(run.output.stderr.contains("Remote Control was not confirmed reconnected in 1 session(s); run /remote-control there manually."));
    assert_eq!(sends(&fixture), 2);
    let documents: Vec<Value> = serde_json::Deserializer::from_str(&run.output.stdout)
        .into_iter()
        .map(Result::unwrap)
        .collect();
    assert!(documents.iter().all(|value| value["kind"] != "outcome"));
    assert_unchanged(&fixture, &before, &config, &credentials);
    assert_released(&fixture, &resolved);
}
