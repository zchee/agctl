use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::runtime::coordinator::Cancel;

fn screens() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/rc-screens")
}

fn context() -> PassCtx {
    PassCtx::standalone(Cancel::new(), Instant::now() + Duration::from_secs(10))
}

fn fake(dir: &Path, knobs: &[(&str, String)]) -> PathBuf {
    let fake = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/fake-tmux.sh");
    let bin = dir.join("tmux-test");
    let mut script = format!("#!/bin/sh\nexport HOME='{}'\n", dir.display());
    for (name, value) in knobs {
        script.push_str(&format!("export {name}='{}'\n", value.replace('\'', "'\\''")));
    }
    script.push_str(&format!("exec '{}' \"$@\"\n", fake.display()));
    fs::write(&bin, script).unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).unwrap();
    bin
}

#[test]
fn pane_target_is_only_a_bounded_numeric_id() {
    let cases: BTreeMap<_, _> = [
        ("gaudiy:@10.%10", Some("%10")),
        ("%10", Some("%10")),
        ("a.b.%7", Some("%7")),
        ("%", None),
        ("%1a", None),
        ("%1234567890", None),
        ("x:@1.%1 ", None),
        ("", None),
        ("%１２", None),
        ("%1; send-keys", None),
    ]
    .into();
    for (input, expected) in cases {
        assert_eq!(Pane::parse(input).as_ref().map(Pane::as_str), expected, "{input}");
    }
    assert_eq!(format!("{:?}", Pane::parse("%7").unwrap()), "Pane(..)");
}

#[test]
fn closed_keys_are_exact_argv_not_tmux_key_names_or_literals() {
    assert_eq!(Keys::RemoteControl.argv(), ["/remote-control", "Enter"]);
    assert_eq!(Keys::Disconnect.argv(), ["Up", "Up", "Enter"]);
    assert_eq!(Keys::RemoteControl.description(), "/remote-control Enter");
    assert_eq!(Keys::Disconnect.description(), "Up Up Enter");
    assert!(Keys::RemoteControl.argv()[0].starts_with('/'));
}

#[test]
fn executable_resolution_skips_nonexecutables_and_directories() {
    let dir = tempfile::tempdir().unwrap();
    let paths: Vec<_> =
        ["plain", "directory", "executable"].map(|name| dir.path().join(name)).into();
    for path in &paths {
        fs::create_dir(path).unwrap();
    }
    fs::write(paths[0].join("tmux"), "unused").unwrap();
    fs::set_permissions(paths[0].join("tmux"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::create_dir(paths[1].join("tmux")).unwrap();
    fs::write(paths[2].join("tmux"), "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(paths[2].join("tmux"), fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        resolve_on_path(&std::env::join_paths(&paths[..2]).unwrap()),
        Err(Failure::Unavailable)
    );
    assert_eq!(
        resolve_on_path(&std::env::join_paths(&paths).unwrap()).unwrap(),
        paths[2].join("tmux")
    );
}

#[test]
fn resolve_obeys_feature_boundary_without_mutating_process_environment() {
    const CHILD: &str = "AGCTL_TMUX_RESOLVE_TEST_CHILD";
    if let Some(expected) = std::env::var_os(CHILD) {
        assert_eq!(resolve_tmux_bin().unwrap(), PathBuf::from(expected));
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("tmux");
    fs::write(&bin, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).unwrap();
    let override_bin = dir.path().join("override");
    let expected = if cfg!(feature = "testing") { &override_bin } else { &bin };
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "runtime::tmux::tests::resolve_obeys_feature_boundary_without_mutating_process_environment"])
        .env("PATH", dir.path()).env("HOME", dir.path())
        .env("AGCTL_TMUX_BIN", &override_bin).env(CHILD, expected).status().unwrap();
    assert!(status.success());
}

#[test]
fn pane_state_requires_five_bounded_fields_and_a_device_path() {
    let cases: BTreeMap<_, _> = [
        ("123 /dev/ttys001 0 0 0\n", true),
        ("123 /dev/ttys001 0 0\n", false),
        ("123 /tmp/not-a-tty 0 0 0\n", false),
        ("123 /dev/../tmp/tty 0 0 0\n", false),
        ("123 /dev 0 0 0\n", false),
        ("123 /dev/tty 2 0 0\n", false),
        ("0 /dev/tty 0 0 0\n", false),
    ]
    .into();
    for (text, valid) in cases {
        assert_eq!(parse_pane_state(text.as_bytes()).is_ok(), valid, "{text}");
    }
    assert!(matches!(parse_pane_state(&[b'x'; 257]), Err(Failure::TooLarge)));
    let state = parse_pane_state(b"123 /dev/tty 1 1 1").unwrap();
    assert_eq!(state.tty, Path::new("/dev/tty"));
    assert!(state.in_mode && state.dead && state.synchronized);
}

#[test]
fn synthetic_screen_rejections_never_supply_authorization() {
    let cases: BTreeMap<_, _> = [
        ("draft_visible.txt", CaptureVerdict::DraftVisible),
        ("stash_visible.txt", CaptureVerdict::StashVisible),
        ("mode_visible.txt", CaptureVerdict::ModeVisible),
        ("dialog_conflict.txt", CaptureVerdict::DialogConflict),
        ("capture_ambiguous.txt", CaptureVerdict::Ambiguous),
        ("capture_invalid.bin", CaptureVerdict::Invalid),
        ("empty-prompt.txt", CaptureVerdict::NoRejection),
        ("c20-panel.txt", CaptureVerdict::NoRejection),
    ]
    .into();
    for (file, expected) in cases {
        assert_eq!(Capture(fs::read(screens().join(file)).unwrap()).classify(), expected, "{file}");
        assert!(!expected.reason().is_empty());
    }
    for mode in ["INSERT", "NORMAL", "REPLACE", "other mode"] {
        let text = format!("transcript\n❯\n────────\n-- {mode} --\n");
        assert_eq!(Capture(text.into_bytes()).classify(), CaptureVerdict::ModeVisible);
    }
    assert_eq!(Capture(b"transcript\n".to_vec()).classify(), CaptureVerdict::Ambiguous);
    assert_eq!(Capture(Vec::new()).classify(), CaptureVerdict::Ambiguous);
    assert_eq!(
        Capture("transcript\n❯\n  continuation draft\n────\n".as_bytes().to_vec()).classify(),
        CaptureVerdict::DraftVisible
    );
    let text = fs::read_to_string(screens().join("c20-panel.txt"))
        .unwrap()
        .replace("Show QR code", "Hide QR code");
    assert_eq!(Capture(text.into_bytes()).classify(), CaptureVerdict::NoRejection);
}

#[test]
fn fake_transport_pins_argv_and_closed_capture_failures() {
    let dir = tempfile::tempdir().unwrap();
    let panes = dir.path().join("panes");
    let log = dir.path().join("log");
    fs::write(&panes, " %7 123 /dev/tty 0 0 0\n".trim_start()).unwrap();
    let base = [
        ("AGCTL_FAKE_TMUX_PANES", panes.display().to_string()),
        ("AGCTL_FAKE_TMUX_LOG", log.display().to_string()),
        ("AGCTL_FAKE_TMUX_SCREEN", screens().join("empty-prompt.txt").display().to_string()),
    ];
    let bin = fake(dir.path(), &base);
    let ctx = context();
    let pane = Pane::parse("%7").unwrap();
    let end = ctx.deadline();
    assert!(!pane_state(&bin, &pane, &ctx, end).unwrap().dead);
    assert_eq!(capture(&bin, &pane, Keys::RemoteControl, &ctx, end), CaptureVerdict::NoRejection);
    assert_eq!(capture(&bin, &pane, Keys::Disconnect, &ctx, end), CaptureVerdict::PanelAbsent);
    send(&bin, &pane, Keys::RemoteControl, &ctx, end).unwrap();
    send(&bin, &pane, Keys::Disconnect, &ctx, end).unwrap();
    let logged = fs::read_to_string(&log).unwrap();
    assert!(logged.contains("arg send-keys\narg -t\narg %7\narg /remote-control\narg Enter\n"));
    assert!(logged.contains("arg send-keys\narg -t\narg %7\narg Up\narg Up\narg Enter\n"));
    assert!(
        logged.contains("arg capture-pane\narg -p\narg -t\narg %7\narg -S\narg 0\narg -E\narg -\n")
    );
    assert!(!logged.contains("arg -l\n"));
    // POSIX sh may add PWD/SHLVL itself; neither was inherited from agctl.
    for name in logged.lines().filter_map(|line| line.strip_prefix("env ")) {
        assert!(
            ["PATH", "HOME", "TMUX", "TMUX_TMPDIR", "PWD", "SHLVL", "_"].contains(&name)
                || name.starts_with("AGCTL_FAKE_TMUX_"),
            "unexpected inherited variable: {name}"
        );
    }
    let cases: BTreeMap<_, _> = [
        ("AGCTL_FAKE_TMUX_CAPTURE_EXIT", ("9", CaptureVerdict::Failed)),
        ("AGCTL_FAKE_TMUX_CAPTURE_BYTES", ("65537", CaptureVerdict::TooLarge)),
        ("AGCTL_FAKE_TMUX_SLEEP", ("5", CaptureVerdict::Failed)),
    ]
    .into();
    for (name, (value, expected)) in cases {
        let mut knobs = base.to_vec();
        knobs.push((name, value.to_owned()));
        let bin = fake(dir.path(), &knobs);
        let ctx = context();
        let limit = Instant::now() + Duration::from_millis(250);
        assert_eq!(capture(&bin, &pane, Keys::RemoteControl, &ctx, limit), expected, "{name}");
    }
    let mut knobs = base.to_vec();
    knobs.push(("AGCTL_FAKE_TMUX_CAPTURE_BYTES", "65536".to_owned()));
    let bin = fake(dir.path(), &knobs);
    assert_eq!(run(&bin, &["capture-pane"], None, &ctx, ctx.deadline()).unwrap().len(), 65536);
    assert_eq!(
        capture(&dir.path().join("absent"), &pane, Keys::RemoteControl, &ctx, ctx.deadline()),
        CaptureVerdict::Failed
    );
}

#[test]
fn child_timeout_kills_and_reaps_even_after_the_pass_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("pid");
    let bin = dir.path().join("blocked");
    fs::write(&bin, format!("#!/bin/sh\nprintf '%s' $$ > '{}'\nexec sleep 30\n", marker.display()))
        .unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).unwrap();
    let ctx = PassCtx::standalone(Cancel::new(), Instant::now());
    let start = Instant::now();
    assert_eq!(
        run(&bin, &["display-message"], None, &ctx, start + Duration::from_millis(150)),
        Err(Failure::Timeout)
    );
    let pid: u32 = fs::read_to_string(marker).unwrap().parse().unwrap();
    assert!(!crate::runtime::proc::exists(pid), "timed-out child must be reaped");
    assert!(start.elapsed() < Duration::from_secs(2));
}
