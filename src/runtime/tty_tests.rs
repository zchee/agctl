use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::os::fd::AsFd;

use super::*;

pub(crate) fn pty() -> (File, File) {
    let master =
        rustix::pty::openpt(rustix::pty::OpenptFlags::RDWR | rustix::pty::OpenptFlags::NOCTTY)
            .unwrap();
    rustix::pty::grantpt(&master).unwrap();
    rustix::pty::unlockpt(&master).unwrap();
    let name = rustix::pty::ptsname(&master, Vec::new()).unwrap();
    let slave = rustix::fs::open(
        name.as_c_str(),
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOCTTY,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    (File::from(master), File::from(slave))
}

#[test]
fn tty_readiness_probes_poll_and_handles_the_real_device_result() {
    let (mut master, mut slave) = pty();
    master.write_all(b"y\n").unwrap();
    let mut probe = [PollFd::new(&slave, PollFlags::IN)];
    rustix::event::poll(&mut probe, Some(&Timespec::try_from(Duration::from_millis(100)).unwrap()))
        .unwrap();
    let needs_select = probe[0].revents().contains(PollFlags::NVAL);
    let mut waiter = Readiness::default();
    assert!(waiter.wait_readable(slave.as_fd(), Duration::from_millis(100)).unwrap());
    assert_eq!(waiter.use_select, needs_select, "the fallback remembers this device's poll result");
    let mut answer = [0; 2];
    slave.read_exact(&mut answer).unwrap();
    assert_eq!(&answer, b"y\n");
}

#[test]
fn tty_readiness_select_fallback_reads_a_real_pty_and_keeps_its_bound() {
    let (mut master, mut slave) = pty();
    // This is the state retained after POLLNVAL, exercised even on systems
    // whose PTYs support poll so the fallback cannot silently stop compiling.
    let mut waiter = Readiness { use_select: true };
    let started = Instant::now();
    assert!(!waiter.wait_readable(slave.as_fd(), Duration::from_millis(30)).unwrap());
    assert!(started.elapsed() < Duration::from_millis(250));
    master.write_all(b"y\n").unwrap();
    assert!(waiter.wait_readable(slave.as_fd(), Duration::from_millis(100)).unwrap());
    let mut answer = [0; 2];
    slave.read_exact(&mut answer).unwrap();
    assert_eq!(&answer, b"y\n");
    assert!(!waiter.wait_readable(slave.as_fd(), Duration::ZERO).unwrap());
}
