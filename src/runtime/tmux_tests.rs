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
        ("echoed-prompts.txt", CaptureVerdict::NoRejection),
        ("echoed-prompts-draft.txt", CaptureVerdict::DraftVisible),
    ]
    .into();
    for (file, expected) in cases {
        assert_eq!(
            Capture(fs::read(screens().join(file)).unwrap()).classify(Keys::RemoteControl),
            expected,
            "{file}"
        );
        assert!(!expected.reason().is_empty());
    }
    for mode in ["INSERT", "NORMAL", "REPLACE", "other mode"] {
        let text = format!("transcript\n❯\u{a0}\n────────\n-- {mode} --\n");
        assert_eq!(
            Capture(text.into_bytes()).classify(Keys::RemoteControl),
            CaptureVerdict::ModeVisible
        );
    }
    assert_eq!(
        Capture(b"transcript\n".to_vec()).classify(Keys::RemoteControl),
        CaptureVerdict::Ambiguous
    );
    assert_eq!(Capture(Vec::new()).classify(Keys::RemoteControl), CaptureVerdict::Ambiguous);
    assert_eq!(
        Capture("transcript\n❯\u{a0}\n  continuation draft\n────\n".as_bytes().to_vec())
            .classify(Keys::RemoteControl),
        CaptureVerdict::DraftVisible
    );
    let text = fs::read_to_string(screens().join("c20-panel.txt"))
        .unwrap()
        .replace("Show QR code", "Hide QR code");
    assert_eq!(
        Capture(text.into_bytes()).classify(Keys::RemoteControl),
        CaptureVerdict::NoRejection
    );
}

#[test]
fn an_echoed_prompt_is_transcript_and_only_the_input_line_holds_a_draft() {
    let classify = |text: &str, keys| Capture(text.as_bytes().to_vec()).classify(keys);
    let echoed = fs::read_to_string(screens().join("echoed-prompts.txt")).unwrap();
    assert_eq!(echoed.matches("❯ ").count(), 3, "three echoed prompts, U+0020 after the pointer");
    assert_eq!(echoed.matches("❯\u{a0}").count(), 1, "one input line, U+00A0 after the pointer");
    let input = "❯\u{a0}\n";

    let cases: BTreeMap<_, _> = [
        ("echoes above an empty input line", echoed.clone(), CaptureVerdict::NoRejection),
        (
            "echoes above a continuation draft",
            echoed.replace(input, "❯\u{a0}\n  second line\n"),
            CaptureVerdict::DraftVisible,
        ),
        (
            "echoes and no input line, as under a covering panel",
            echoed.replace(input, "   Settings  Status   Config\n"),
            CaptureVerdict::Ambiguous,
        ),
        (
            "an input line spelled with U+0020 is not recognized, so nothing is accepted",
            echoed.replace(input, "❯ \n"),
            CaptureVerdict::Ambiguous,
        ),
        (
            "a draft spelled with U+0020 is not recognized either and still does not pass",
            echoed.replace(input, "❯ half-typed text\n"),
            CaptureVerdict::Ambiguous,
        ),
        (
            "an echo below the input line does not hide the draft above it",
            echoed.replace(input, "❯\u{a0}half-typed text\n❯ later echo\n"),
            CaptureVerdict::DraftVisible,
        ),
        (
            "a bare pointer with no separator is not the input line",
            "transcript\n❯\n────────\n? for shortcuts\n".to_owned(),
            CaptureVerdict::Ambiguous,
        ),
        (
            "an indented pointer row is printed output, not the input line",
            echoed.replace(input, "  ❯\u{a0}\n"),
            CaptureVerdict::Ambiguous,
        ),
        (
            "an indented pointer row above the input line changes nothing",
            echoed.replace("❯ marker two", "  ❯\u{a0}"),
            CaptureVerdict::NoRejection,
        ),
        (
            "an indented pointer row does not stand in for a bash-mode input line that holds text",
            echoed.replace("❯ marker two", "  ❯\u{a0}").replace(input, "!\u{a0}ls -la\n"),
            CaptureVerdict::Ambiguous,
        ),
        (
            "two input lines cannot both be the input",
            echoed.replace("❯ marker two", "❯\u{a0}"),
            CaptureVerdict::Ambiguous,
        ),
        (
            "only non-whitespace after the separator is a draft",
            echoed.replace(input, "❯\u{a0} \u{a0}\n"),
            CaptureVerdict::NoRejection,
        ),
    ]
    .into_iter()
    .map(|(name, text, expected)| (name, (text, expected)))
    .collect();
    for (name, (text, expected)) in &cases {
        assert_eq!(classify(text, Keys::RemoteControl), *expected, "{name}");
    }

    // The panel replaces the input line; the echoed prompts above it stay on screen.
    let panel = fs::read_to_string(screens().join("c20-panel.txt")).unwrap();
    let transcript = echoed.split("❯\u{a0}").next().unwrap();
    let under_panel = format!("{transcript}{panel}");
    for keys in [Keys::RemoteControl, Keys::Disconnect] {
        assert_eq!(classify(&under_panel, keys), CaptureVerdict::NoRejection, "{keys:?}");
        // A draft that spells an option label is still a draft, with or without the panel's own row.
        for text in [
            format!("{under_panel}❯\u{a0}Continue\n"),
            under_panel.replace("❯ Continue", "❯\u{a0}Continue"),
        ] {
            assert_eq!(classify(&text, keys), CaptureVerdict::DraftVisible, "{keys:?}");
        }
    }
    assert_eq!(classify(&echoed, Keys::Disconnect), CaptureVerdict::PanelAbsent);
}

#[test]
fn capture_invalid_utf8_precedes_panel_rejection_for_both_key_groups() {
    let dir = tempfile::tempdir().unwrap();
    let bin = fake(
        dir.path(),
        &[("AGCTL_FAKE_TMUX_SCREEN", screens().join("capture_invalid.bin").display().to_string())],
    );
    let pane = Pane::parse("%7").unwrap();
    let ctx = context();
    for keys in [Keys::Disconnect, Keys::RemoteControl] {
        assert_eq!(capture(&bin, &pane, keys, &ctx, ctx.deadline()), CaptureVerdict::Invalid);
    }
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
fn send_nonzero_exit_is_reported_without_retry() {
    let dir = tempfile::tempdir().unwrap();
    let panes = dir.path().join("panes");
    let log = dir.path().join("log");
    fs::write(&panes, "%7 123 /dev/tty 0 0 0\n").unwrap();
    let bin = fake(
        dir.path(),
        &[
            ("AGCTL_FAKE_TMUX_PANES", panes.display().to_string()),
            ("AGCTL_FAKE_TMUX_LOG", log.display().to_string()),
            ("AGCTL_FAKE_TMUX_EXIT", "9".to_owned()),
        ],
    );
    let pane = Pane::parse("%7").unwrap();
    let ctx = context();
    for keys in [Keys::RemoteControl, Keys::Disconnect] {
        fs::write(&log, "").unwrap();
        assert_eq!(send(&bin, &pane, keys, &ctx, ctx.deadline()), Err(Failure::Nonzero));
        let logged = fs::read_to_string(&log).unwrap();
        assert_eq!(logged.matches("arg send-keys\n").count(), 1, "{keys:?}: no retry");
        assert!(logged.contains(&format!(
            "arg send-keys\narg -t\narg %7\narg {}\n",
            keys.argv().join("\narg ")
        )));
    }
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
