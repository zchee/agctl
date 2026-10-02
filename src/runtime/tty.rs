//! Bounded readiness waits for agctl's own terminal, never another process's input.

use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::time::Duration;
use std::time::Instant;

use rustix::event::PollFd;
use rustix::event::PollFlags;
use rustix::event::Timespec;
use rustix::io::Errno;

/// Remembers a device's unsupported poll result so subsequent waits use select.
#[derive(Debug, Default)]
pub struct Readiness {
    use_select: bool,
}

impl Readiness {
    /// Waits no longer than `timeout` for input or hangup on the borrowed live fd.
    /// An interrupted wait returns false, allowing the caller to observe cancellation.
    ///
    /// # Errors
    /// Returns the OS error for an invalid descriptor, unsupported wait, or invalid timeout.
    pub fn wait_readable(
        &mut self,
        fd: BorrowedFd<'_>,
        timeout: Duration,
    ) -> rustix::io::Result<bool> {
        let started = Instant::now();
        if !self.use_select {
            let timeout = Timespec::try_from(timeout).map_err(|_| Errno::INVAL)?;
            let mut fds = [PollFd::new(&fd, PollFlags::IN)];
            match rustix::event::poll(&mut fds, Some(&timeout)) {
                Ok(0) | Err(Errno::INTR) => return Ok(false),
                Ok(_) if fds[0].revents().contains(PollFlags::NVAL) => self.use_select = true,
                Ok(_) => return Ok(fds[0].revents().intersects(PollFlags::IN | PollFlags::HUP)),
                Err(error) => return Err(error),
            }
        }
        // A failing poll can itself consume time. Its fallback shares that
        // interval rather than postponing the caller's cancellation check.
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Ok(false);
        }
        let timeout = Timespec::try_from(remaining).map_err(|_| Errno::INVAL)?;
        let raw = fd.as_raw_fd();
        let nfds = raw.checked_add(1).ok_or(Errno::INVAL)?;
        let mut readfds = vec![
            rustix::event::FdSetElement::default();
            rustix::event::fd_set_num_elements(1, nfds)
        ];
        rustix::event::fd_set_insert(&mut readfds, raw);
        // SAFETY: fd borrows the sole inserted open descriptor for the whole
        // call, and rustix sizes the set for this exact highest descriptor.
        match unsafe { rustix::event::select(nfds, Some(&mut readfds), None, None, Some(&timeout)) }
        {
            Ok(count) => Ok(count > 0),
            Err(Errno::INTR) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
#[path = "tty_tests.rs"]
pub(crate) mod tests;
