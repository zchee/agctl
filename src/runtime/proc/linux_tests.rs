use std::cell::Cell;
use std::os::unix::fs::symlink;
use std::os::unix::process::CommandExt;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

use super::super::RecordHolder;
use super::super::record_holder;
use super::*;

fn stat_fixture(name: &str, state: char, ticks: &str) -> Vec<u8> {
    let mut fields = vec!["0"; 49];
    fields[18] = ticks;
    format!("42 ({name}) {state} {}\n", fields.join(" ")).into_bytes()
}

#[test]
fn linux_searchable_directory_contract() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().expect("isolated directories");
    let target = root.path().join("target");
    fs::create_dir(&target).expect("target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o500)).expect("target mode");
    symlink(&target, root.path().join("link")).expect("planted symlink");
    let dir = rustix::fs::open(
        root.path(),
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    )
    .expect("parent descriptor");
    assert!(make_dir_searchable(&dir, c"link").is_err(), "never follow a symlink");
    assert_eq!(fs::metadata(&target).expect("untouched target").mode() & 0o777, 0o500);
    let hidden = root.path().join("hidden");
    fs::create_dir(&hidden).expect("hidden directory");
    fs::write(hidden.join("entry"), b"retained").expect("contents");
    fs::set_permissions(&hidden, fs::Permissions::from_mode(0o000)).expect("seal directory");
    make_dir_searchable(&dir, c"hidden").expect("restore real directory access");
    assert_eq!(fs::metadata(&hidden).expect("searchable directory").mode() & 0o777, 0o700);
    assert_eq!(fs::read(hidden.join("entry")).expect("contents intact"), b"retained");
    assert!(make_dir_searchable(&dir, c"missing").is_err());
}

#[test]
fn linux_stat_parser_contract() {
    let valid = stat_fixture("a (name) with )", 'T', "18446744073709551615");
    let parsed = parse_stat(&valid).expect("last closing parenthesis bounds the name");
    assert_eq!(parsed.comm, "a (name) with )");
    assert_eq!(parsed.starttime, u64::MAX);
    assert_eq!(parsed.state, 'T');

    let malformed = [
        b"\xff\n".to_vec(),
        b"(x) S 1\n".to_vec(),
        b"42 ) x ( S 1\n".to_vec(),
        b"42 (x)\n".to_vec(),
        b"42 (x)S 1\n".to_vec(),
        b"42 (x) S\n".to_vec(),
        stat_fixture("x", '?', "1"),
        stat_fixture("x", 'S', "18446744073709551616"),
        stat_fixture("x", 'S', "-1"),
        stat_fixture("x", 'S', "+1"),
        stat_fixture("x", 'S', "1").strip_suffix(b"\n").expect("newline").to_vec(),
        String::from_utf8(stat_fixture("x", 'S', "1"))
            .expect("ASCII fixture")
            .replace(") S ", ") SS ")
            .into_bytes(),
        vec![b' '; usize::try_from(STAT_LIMIT + 1).expect("small bound")],
    ];
    for input in malformed {
        let result = std::panic::catch_unwind(|| parse_stat(&input));
        assert!(result.is_ok(), "malformed envelope must not panic: {input:?}");
        assert!(result.expect("no panic").is_err(), "malformed input was accepted: {input:?}");
    }
    assert_eq!(read_bytes(&b"abc"[..], 3).expect("exact bound"), b"abc");
    assert!(matches!(read_bytes(&b"abcd"[..], 3), Err(ReadError::Oversized)));
    let dir = tempfile::tempdir().expect("scratch proc files");
    let path = dir.path().join("stat");
    fs::write(&path, &valid).expect("write valid stat");
    assert!(read_bounded(&path, STAT_LIMIT).is_ok());
    fs::write(&path, b"\xff\n").expect("invalid UTF-8");
    assert!(matches!(read_bounded(&path, STAT_LIMIT), Err(ReadError::Invalid)));
    fs::write(&path, b"truncated").expect("missing newline");
    assert!(matches!(read_bounded(&path, STAT_LIMIT), Err(ReadError::Invalid)));
    assert!(
        matches!(read_bounded(&dir.path().join("missing"), STAT_LIMIT), Err(ReadError::Io(err)) if err.kind() == io::ErrorKind::NotFound)
    );
}

fn observation(uid: u32, name: &str, state: char) -> Observation {
    Observation {
        stat: parse_stat(&stat_fixture(name, state, "100")).expect("valid stat"),
        uid,
        name: name.to_owned(),
    }
}

#[test]
fn linux_proc_classification_contract() {
    for state in *b"Tt" {
        assert_eq!(state_holder(state), Some(Holder::Stopped));
    }
    for state in *b"ZX" {
        assert_eq!(state_holder(state), Some(Holder::Dead));
    }
    for state in b"RSDIWKP" {
        assert_eq!(state_holder(*state), Some(Holder::Alive));
    }
    for state in [b'?', b'x', 0, 255] {
        assert_eq!(state_holder(state), None);
    }
    for name in ["Claude", "claude-code", "Claude Helper", "2.1.282", "claude "] {
        assert_eq!(classify(42, Ok(observation(42, name, 'T')), Ok(())), Seen::Other);
    }
    assert_eq!(classify(42, Ok(observation(43, "claude", 'T')), Ok(())), Seen::Other);
    assert_eq!(
        classify(42, Ok(observation(42, "claude", 't')), Ok(())),
        Seen::Claude(Holder::Stopped)
    );
    for signal in [Ok(()), Err(Errno::PERM), Err(Errno::IO)] {
        assert_eq!(
            classify(42, Err(ReadError::Io(io::ErrorKind::PermissionDenied.into())), signal),
            Seen::Unclassified
        );
        assert_eq!(
            classify(42, Err(ReadError::Io(io::ErrorKind::NotFound.into())), signal),
            Seen::Unclassified
        );
    }
    assert_eq!(
        classify(42, Err(ReadError::Io(io::ErrorKind::NotFound.into())), Err(Errno::SRCH)),
        Seen::Gone
    );
    assert_eq!(classify(42, Err(ReadError::Raced), Err(Errno::SRCH)), Seen::Unclassified);
    assert!(matches!(
        sweep([(42, Seen::Unclassified)]),
        Err(ProcError::Incomplete { unreadable: 1 })
    ));
    assert_eq!(
        sweep([(42, Seen::Unclassified), (43, Seen::Claude(Holder::Stopped))])
            .expect("positive survives"),
        [(43, Holder::Stopped)]
    );
    let status = read_bounded(Path::new("/proc/self/status"), STATUS_LIMIT).expect("own status");
    let parsed = parse_status(&status).expect("real UID is readable");
    assert_eq!(parsed.ruid, rustix::process::getuid().as_raw());
    let old = status.lines().find(|line| line.starts_with("Uid:")).expect("Uid line");
    let different = status.replace(old, "Uid:\t42\t43\t44\t45");
    assert_eq!(parse_status(&different).expect("four UID columns").ruid, 42);
    for uid in ["Uid:\t42", "Uid:\t-1 0 0 0", "Uid:\t4294967296 0 0 0", "Uid:\t1 2 3 4 5"] {
        assert!(parse_status(&status.replace(old, uid)).is_err(), "{uid}");
    }
    assert!(parse_status(&format!("{status}Uid:\t1 2 3 4\n")).is_err());
}

#[test]
fn linux_start_identity_contract() {
    let cancel = Cancel::new();
    let pid = std::process::id();
    let text = start_time(pid, &cancel).expect("own identity");
    assert_eq!(start_time(pid, &cancel).as_deref(), Some(text.as_str()));
    assert_eq!(self_start_time(&cancel).as_deref(), Some(text.as_str()));
    let identity = Identity::parse(&text).expect("versioned identity");
    assert_eq!(identity.domain, current_domain().expect("own domain"));
    assert_eq!(text, identity.render());
    cancel.cancel();
    assert_eq!(
        start_time(pid, &cancel).as_deref(),
        Some(text.as_str()),
        "cleanup reads identity after cancellation"
    );
    assert_eq!(holder(pid, &cancel), Holder::Alive);
    let cancel = Cancel::new();
    assert!(boot_uuid(&identity.domain.boot));
    assert_eq!(
        start_instant(1000, 123, 100).expect("ticks").to_string(),
        "1970-01-01T00:16:41.23Z"
    );
    for (boot, ticks, rate) in [(1, 1, 0), (u64::MAX, 1, 1), (0, u64::MAX - 1, u64::MAX)] {
        assert!(start_instant(boot, ticks, rate).is_none());
    }
    assert!(start_time(u32::MAX, &cancel).is_none());
    assert!(start_timestamp(u32::MAX, &cancel).is_none());
    assert!(start_timestamp(pid, &cancel).expect("wall start") <= jiff::Timestamp::now());
}

#[test]
fn linux_record_identity_guard() {
    let domain = current_domain().expect("current identity domain");
    let valid = Identity { domain: domain.clone(), ticks: 1 }.render();
    let invalid = [
        None,
        Some("".to_owned()),
        Some("2026-09-26T00:00:00Z".to_owned()),
        Some("Sat Sep 26 00:00:00 2026".to_owned()),
        Some(valid.replace("linux-v1", "linux-v2")),
        Some(valid.replace("linux-v1", "foreign-v1")),
        Some(format!("{valid}:extra")),
        Some(valid.replace(&domain.boot, "00000000-0000-0000-0000-000000000000")),
        Some(
            Identity {
                domain: Domain {
                    inode: domain.inode.checked_add(1).expect("inode"),
                    ..domain.clone()
                },
                ticks: 1,
            }
            .render(),
        ),
        Some(
            Identity {
                domain: Domain {
                    device: domain.device.checked_add(1).expect("device"),
                    ..domain.clone()
                },
                ticks: 1,
            }
            .render(),
        ),
        Some(
            Identity {
                domain: Domain { uid: domain.uid.checked_add(1).expect("UID"), ..domain.clone() },
                ticks: 1,
            }
            .render(),
        ),
        Some(format!("linux-v1:{}:1:2:18446744073709551616:0", domain.boot)),
        Some(format!("linux-v1:{}:-1:2:3:0", domain.boot)),
        Some(format!("linux-v1:{}:1:2:3:4294967296", domain.boot)),
        Some(valid.to_uppercase()),
    ];
    for record in invalid {
        let called = Cell::new(false);
        assert!(!writer_gone_with(record.as_deref(), Some(domain.clone()), || {
            called.set(true);
            Err(Errno::SRCH)
        }));
        assert!(!called.get(), "invalid domain must fail before probing: {record:?}");
        assert_eq!(
            record_holder(std::process::id(), record.as_deref(), &Cancel::new()),
            RecordHolder::Unknown
        );
    }
    for signal in [Ok(()), Err(Errno::PERM), Err(Errno::IO), Err(Errno::INVAL)] {
        assert!(!writer_gone_with(Some(&valid), Some(domain.clone()), || signal));
    }
    assert!(writer_gone_with(Some(&valid), Some(domain.clone()), || Err(Errno::SRCH)));
    assert!(!writer_gone_with(Some(&valid), None, || panic!("no probe without domain")));
    assert!(!writer_is_gone(std::process::id(), Some(&valid)), "tick mismatch is not ESRCH");
    assert_eq!(
        record_holder(std::process::id(), Some(&valid), &Cancel::new()),
        RecordHolder::Unknown
    );
}

struct OwnChild(Child);

impl OwnChild {
    /// Spawns `path`, a copy of `/bin/sh`, parked in `read` on a pipe the
    /// parent never writes to, so it keeps whatever name it was started under
    /// until it is signalled.
    ///
    /// Not a copy of `/bin/sleep`: on Ubuntu 26.04 that is the uutils
    /// multi-call binary, which dispatches on `argv[0]` and exits with
    /// `unknown program 'claude'` when run under the launcher's name. dash,
    /// the `/bin/sh` of Debian and Ubuntu, behaves the same under any name.
    fn spawn(path: &Path, traced: bool) -> Self {
        let mut command = Command::new(path);
        command
            .args(["-c", "read _"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if traced {
            // SAFETY: the child callback calls only ptrace and errno; it neither
            // allocates nor takes locks between fork and exec.
            unsafe {
                command.pre_exec(|| {
                    if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == -1 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        Self(command.spawn().expect("scratch child"))
    }

    fn signal(&self, signal: rustix::process::Signal) {
        let pid =
            Pid::from_raw(i32::try_from(self.0.id()).expect("child PID")).expect("positive PID");
        rustix::process::kill_process(pid, signal).expect("signal owned child");
    }

    fn wait_state(&self, expected: Holder) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if holder(self.0.id(), &Cancel::new()) == expected {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("child {} never reached {expected:?}", self.0.id());
    }
}

impl Drop for OwnChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn linux_process_lifecycle() {
    let scratch = tempfile::tempdir().expect("isolated launchers");
    let version = scratch.path().join("2.1.282");
    let base = scratch.path().join("sh");
    fs::copy("/bin/sh", &base).expect("copy system sh");
    fs::hard_link(&base, &version).expect("same-inode version name");
    let launcher = scratch.path().join("claude");
    symlink(&version, &launcher).expect("same-inode claude launcher");
    assert_eq!(
        fs::metadata(&launcher).expect("launcher").ino(),
        fs::metadata(&version).expect("version").ino()
    );
    let mut claude = OwnChild::spawn(&launcher, false);
    let version_child = OwnChild::spawn(&version, false);
    claude.wait_state(Holder::Alive);
    version_child.wait_state(Holder::Alive);
    let cancel = Cancel::new();
    let identity = start_time(claude.0.id(), &cancel).expect("start identity");
    claude.signal(rustix::process::Signal::STOP);
    version_child.signal(rustix::process::Signal::STOP);
    claude.wait_state(Holder::Stopped);
    version_child.wait_state(Holder::Stopped);
    assert_eq!(observe(claude.0.id()).expect("comm").name, "claude");
    assert_eq!(observe(version_child.0.id()).expect("version comm").name, "2.1.282");
    let matches = claude_processes().expect("positive stopped peer");
    assert!(matches.contains(&(claude.0.id(), Holder::Stopped)));
    assert!(!matches.iter().any(|(pid, _)| *pid == version_child.0.id()));
    assert_eq!(start_time(claude.0.id(), &cancel), Some(identity.clone()));
    claude.signal(rustix::process::Signal::CONT);
    claude.wait_state(Holder::Alive);
    claude.signal(rustix::process::Signal::KILL);
    claude.wait_state(Holder::Dead);
    assert_eq!(observe(claude.0.id()).expect("unreaped child").stat.state, 'Z');
    assert!(exists(claude.0.id()), "zombies still answer kill-zero");
    assert!(!writer_is_gone(claude.0.id(), Some(&identity)), "zombie is not ESRCH");
    claude.0.wait().expect("reap child");
    assert!(!exists(claude.0.id()));
    assert!(writer_is_gone(claude.0.id(), Some(&identity)), "same-domain ESRCH");
    let traced = OwnChild::spawn(&version, true);
    traced.wait_state(Holder::Stopped);
    assert_eq!(observe(traced.0.id()).expect("traced child").stat.state, 't');
    assert!(exists(1));
    assert_eq!(holder(std::process::id(), &cancel), Holder::Alive);
    assert!(!exists(u32::MAX));
    assert_eq!(holder(u32::MAX, &cancel), Holder::Dead);
}
