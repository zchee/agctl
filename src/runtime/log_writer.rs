//! Where `tracing` output goes while the TUI owns the terminal.
//!
//! `agentctl claude watch` puts the terminal into raw mode on the alternate
//! screen and then draws a full frame several times a second. A log line
//! written to standard error in the middle of that lands *inside* the frame:
//! it is painted over by the next draw, so the user sees a flicker of text
//! they cannot read and the warning is lost. Worse, a multi-line line with the
//! line discipline off leaves the cursor somewhere the renderer does not
//! expect and corrupts the frame until the next full redraw.
//!
//! So while a [`Tui`](crate::tui::Tui) is entered, the writer this module
//! hands `tracing` does not touch the terminal at all. It appends to an
//! in-memory buffer, and the buffer is flushed to standard error by
//! [`release_terminal`] — which the terminal restore calls *after* the
//! terminal has been put back, so the lines land on the user's shell where
//! they can be read and scrolled.
//!
//! Everything else — every other command, and `watch` before it enters and
//! after it leaves — writes straight through to standard error, which is the
//! behaviour this replaced.
//!
//! # The buffer is capped
//!
//! A `watch` under `RUST_LOG=agentctl=trace` can run for hours, and a buffer
//! that grew for all of it would be a leak. Past [`BUFFER_LIMIT`] the *first*
//! bytes are kept and later ones counted but dropped: the beginning of a
//! failure is what explains it, and the flush ends with a single line saying
//! how much it left out.
//!
//! # Pass threads log through this too, and the flush never waits on one
//!
//! The writer is a unit struct over process-wide statics, so it is [`Send`] and
//! [`Sync`] and every thread writes through the same one — which matters
//! because most of `watch`'s `warn!` sites are on, or reached from, the worker
//! side. The buffer mutex is therefore held across a `memcpy` and nothing
//! else: never across a write to standard error, never across a syscall. That
//! is what lets [`release_terminal`] run on the way out without ever blocking
//! on a pass thread — which, since `q` does not join the worker, may still be
//! running and may still be logging. A line that thread writes after the
//! release goes straight to standard error, which by then is where it belongs.

use std::io;
use std::io::Write;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use tracing_subscriber::fmt::MakeWriter;

/// How much output is kept while the terminal is held.
const BUFFER_LIMIT: usize = 256 * 1024;

/// Whether the terminal currently belongs to something other than the log.
static HELD: AtomicBool = AtomicBool::new(false);

/// What was written while the terminal was held, and how much was dropped.
static BUFFER: LazyLock<Mutex<Buffered>> = LazyLock::new(|| Mutex::new(Buffered::new()));

/// The held output.
#[derive(Debug)]
struct Buffered {
    bytes: Vec<u8>,
    dropped: usize,
}

impl Buffered {
    const fn new() -> Self {
        Self { bytes: Vec::new(), dropped: 0 }
    }

    /// Appends what fits and counts what does not.
    fn append(&mut self, buf: &[u8]) {
        // Checked because this project compiles with `-C overflow-checks=off`
        // in every profile, so a wrapped remainder would turn a full buffer
        // into an enormous one.
        let room = BUFFER_LIMIT.saturating_sub(self.bytes.len());
        let taken = room.min(buf.len());
        self.bytes.extend_from_slice(&buf[..taken]);
        self.dropped = self.dropped.saturating_add(buf.len().saturating_sub(taken));
    }

    /// Empties the buffer, returning what to write and how much was lost.
    fn take(&mut self) -> (Vec<u8>, usize) {
        (std::mem::take(&mut self.bytes), std::mem::take(&mut self.dropped))
    }
}

/// Locks the buffer, recovering from poisoning.
///
/// A panic elsewhere must not silence the log: this runs on the way out of a
/// failing process, which is exactly when the buffered lines are wanted.
fn buffer() -> MutexGuard<'static, Buffered> {
    match BUFFER.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Whether log output is currently being held back from the terminal.
pub(crate) fn is_held() -> bool {
    HELD.load(Ordering::SeqCst)
}

/// Starts holding log output back, because the terminal is about to be taken
/// over by the TUI.
///
/// Idempotent, and safe to call from any thread.
pub fn hold_terminal() {
    HELD.store(true, Ordering::SeqCst);
}

/// Stops holding log output back and writes what was held to standard error.
///
/// Call this *after* the terminal has been restored: the whole point is that
/// these lines land on the shell rather than on the alternate screen.
///
/// Idempotent. A second call finds an empty buffer and writes nothing, which
/// is what makes it safe on the several restore routes — the destructor, the
/// panic hook and the signal registry can all reach it, in any order.
pub fn release_terminal() {
    release_terminal_to(&mut io::stderr());
}

/// [`release_terminal`], writing into `sink` instead of standard error.
///
/// The seam the tests use: standard error cannot be captured from inside the
/// process, so the sink is a parameter and the public entry point above is
/// the one-line specialization of it.
fn release_terminal_to<W: Write>(sink: &mut W) {
    HELD.store(false, Ordering::SeqCst);
    let (bytes, dropped) = buffer().take();

    if !bytes.is_empty() {
        let _ = sink.write_all(&bytes);
    }
    if dropped > 0 {
        let _ = writeln!(
            sink,
            "agentctl: {dropped} further bytes of log output were dropped while the \
             watch display held the terminal"
        );
    }
    let _ = sink.flush();
}

/// The writer `tracing` is given: standard error, unless the terminal is held.
///
/// A unit struct rather than a handle, because what it writes to is a process
/// -wide fact — which terminal is in use — and not something a caller chooses
/// per subscriber.
#[derive(Debug, Clone, Copy, Default)]
pub struct TerminalAwareWriter;

impl Write for TerminalAwareWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if is_held() {
            buffer().append(buf);
            // Buffering is not a short write: reporting fewer bytes would make
            // the formatting layer retry the tail and duplicate it.
            return Ok(buf.len());
        }
        io::stderr().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        if is_held() {
            return Ok(());
        }
        io::stderr().flush()
    }
}

impl MakeWriter<'_> for TerminalAwareWriter {
    type Writer = Self;

    fn make_writer(&self) -> Self::Writer {
        *self
    }
}

#[cfg(test)]
#[path = "log_writer_tests.rs"]
mod tests;
