use std::fs::File;
use std::io::Read;
use std::time::Duration;

use super::*;
use crate::runtime::tty::tests::pty;

fn wait_question(master: &mut File) {
    let end = Instant::now() + Duration::from_secs(3);
    let mut text = Vec::new();
    loop {
        assert!(Instant::now() < end, "no question observed: {}", String::from_utf8_lossy(&text));
        let mut fds = [rustix::event::PollFd::new(&*master, rustix::event::PollFlags::IN)];
        let timeout = rustix::event::Timespec::try_from(Duration::from_millis(100)).unwrap();
        if rustix::event::poll(&mut fds, Some(&timeout)).unwrap() == 0 {
            continue;
        }
        let mut bytes = [0; 256];
        let n = master.read(&mut bytes).unwrap();
        text.extend_from_slice(&bytes[..n]);
        if text.windows(b"[y/N]".len()).any(|part| part == b"[y/N]") {
            return;
        }
    }
}

#[test]
fn remote_control_attestation_flushes_prequeued_and_late_answers() {
    let (mut master, slave) = pty();
    let mut output = slave.try_clone().unwrap();
    let cancel = Cancel::new();
    master.write_all(b"y\n").unwrap();
    let end = Instant::now() + Duration::from_millis(100);
    assert_eq!(
        attest_terminal(&slave, &mut output, "first [y/N]", end, &cancel),
        Attestation::NotObtained
    );
    // This is later than the first deadline and before the second flush.
    master.write_all(b"y\n").unwrap();
    let end = Instant::now() + Duration::from_millis(100);
    assert_eq!(
        attest_terminal(&slave, &mut output, "second [y/N]", end, &cancel),
        Attestation::NotObtained
    );
}

#[test]
fn remote_control_attestation_requires_an_exact_complete_line() {
    let cases: std::collections::BTreeMap<&str, (&[u8], Attestation)> = [
        ("yes", (&b"y\n"[..], Attestation::Yes)),
        ("no", (&b"n\n"[..], Attestation::Declined)),
        ("long yes", (&b"yes\n"[..], Attestation::Declined)),
        ("leading whitespace", (&b" y\n"[..], Attestation::Declined)),
        ("trailing whitespace", (&b"y \n"[..], Attestation::Declined)),
        ("uppercase", (&b"Y\n"[..], Attestation::Declined)),
        ("blank", (&b"\n"[..], Attestation::Declined)),
        ("partial", (&b"y"[..], Attestation::NotObtained)),
        ("eof", (&b"\x04"[..], Attestation::NotObtained)),
    ]
    .into();
    for (name, (answer, expected)) in cases {
        let (mut master, slave) = pty();
        let mut output = slave.try_clone().unwrap();
        let worker = std::thread::spawn(move || {
            attest_terminal(
                &slave,
                &mut output,
                "attest [y/N]",
                Instant::now() + Duration::from_millis(500),
                &Cancel::new(),
            )
        });
        wait_question(&mut master);
        master.write_all(answer).unwrap();
        assert_eq!(worker.join().unwrap(), expected, "{name}");
    }
}

#[test]
fn remote_control_attestation_observes_cancel_within_one_poll() {
    let (mut master, slave) = pty();
    let mut output = slave.try_clone().unwrap();
    let cancel = Cancel::new();
    let other = cancel.clone();
    let worker = std::thread::spawn(move || {
        let result = attest_terminal(
            &slave,
            &mut output,
            "restore [y/N]",
            Instant::now() + Duration::from_secs(3),
            &other,
        );
        // Measure the adapter, not the platform's last-PTY-close drain.
        (result, Instant::now())
    });
    wait_question(&mut master);
    let start = Instant::now();
    cancel.cancel();
    master.write_all(b"y\n").unwrap();
    let (result, returned) = worker.join().unwrap();
    assert_eq!(result, Attestation::NotObtained);
    assert!(
        returned.saturating_duration_since(start)
            <= crate::provider::claude::remote_control::RC_POLL + Duration::from_millis(100),
        "adapter latency: {:?}; including descriptor teardown: {:?}",
        returned.saturating_duration_since(start),
        start.elapsed()
    );
}

#[test]
fn remote_control_attestation_rejects_non_tty_and_expired_channels_without_printing() {
    let (master, slave) = pty();
    let mut output = slave.try_clone().unwrap();
    let input = tempfile::tempfile().unwrap();
    assert_eq!(
        attest_terminal(
            &input,
            &mut output,
            "must not print",
            Instant::now() + Duration::from_secs(1),
            &Cancel::new()
        ),
        Attestation::NotObtained
    );
    let mut file = tempfile::tempfile().unwrap();
    assert_eq!(
        attest_terminal(
            &slave,
            &mut file,
            "must not print",
            Instant::now() + Duration::from_secs(1),
            &Cancel::new()
        ),
        Attestation::NotObtained
    );
    assert_eq!(file.metadata().unwrap().len(), 0);
    assert_eq!(
        attest_terminal(&slave, &mut output, "must not print", Instant::now(), &Cancel::new()),
        Attestation::NotObtained
    );
    drop(master);
    assert_eq!(
        attest_terminal(
            &slave,
            &mut output,
            "lost TTY",
            Instant::now() + Duration::from_secs(1),
            &Cancel::new()
        ),
        Attestation::NotObtained
    );
}

#[test]
fn remote_control_tty_adapter_never_routes_prose_to_stdout() {
    let source = include_str!("mod.rs");
    let adapter = source
        .split("impl Prompt for AttestedTty {")
        .nth(1)
        .unwrap()
        .split("fn attest_terminal")
        .next()
        .unwrap();
    assert!(adapter.contains("writeln!(std::io::stderr()"));
    assert!(adapter.contains("write!(stderr"));
    assert!(!adapter.contains("stdout"));
    let _ = AttestedTty;
}
