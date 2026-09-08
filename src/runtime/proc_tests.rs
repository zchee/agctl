//! Tests for the process probes `doctor` and the lock body rely on.

use super::*;

/// A process id no running process can have.
///
/// `kill(0, 0)` addresses the caller's whole process group and `kill(-n, …)`
/// addresses another group, so zero and negatives are not usable as "surely
/// absent"; `u32::MAX` is above every `pid_max` any of these platforms
/// supports and does not even convert to the `i32` the syscall takes.
const IMPOSSIBLE_PID: u32 = u32::MAX;

#[test]
fn this_process_exists_and_is_alive() {
    let pid = std::process::id();
    assert!(exists(pid), "the running test process exists");
    assert_eq!(holder(pid), Holder::Alive);
}

#[test]
fn an_impossible_pid_is_dead() {
    assert!(!exists(IMPOSSIBLE_PID));
    assert_eq!(holder(IMPOSSIBLE_PID), Holder::Dead, "no subprocess is needed to say so");
}

#[test]
fn pid_one_exists_even_though_it_is_not_ours() {
    // `launchd` and `init` both run as root, so `kill(1, 0)` returns `EPERM`
    // rather than succeeding. That is the case this probe must not read as
    // "gone" (plan AC45: a lock held by another user's process is still held).
    assert!(exists(1), "pid 1 exists even when signalling it is refused");
}

#[test]
fn a_start_time_is_readable_and_stable() {
    // Plan AC48(c): the value the lock body records.
    let first = self_start_time().expect("`ps -o lstart=` answers for this process");
    assert!(!first.is_empty());
    assert_eq!(first, self_start_time().expect("memoized"), "memoized, so it cannot drift");
    assert_eq!(
        Some(first),
        start_time(std::process::id()),
        "the memo answers what a fresh read would"
    );
}

#[test]
fn a_start_time_for_an_impossible_pid_is_unavailable() {
    assert_eq!(start_time(IMPOSSIBLE_PID), None);
}

#[test]
fn holder_labels_are_the_words_doctor_prints() {
    assert_eq!(Holder::Alive.label(), "alive");
    assert_eq!(Holder::Stopped.label(), "stopped");
    assert_eq!(Holder::Dead.label(), "dead");
}

#[test]
fn a_stopped_child_is_reported_as_stopped() {
    // The whole reason `kill(pid, 0)` is not enough: a stopped process answers
    // the probe exactly as a running one does, and a lock it holds will never
    // be released by waiting.
    let mut child = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("kill -STOP $$; sleep 30")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("a shell should be spawnable");
    let pid = child.id();

    // The stop is the child's own first action, but "spawned" and "has run its
    // first line" are different moments, so the state is polled rather than
    // assumed.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut seen = Holder::Alive;
    while Instant::now() < deadline {
        seen = holder(pid);
        if seen == Holder::Stopped {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(seen, Holder::Stopped, "a SIGSTOPed process is not a live holder");
}
