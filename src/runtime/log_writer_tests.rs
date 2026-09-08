//! Proof that a warning raised while the TUI holds the terminal is kept back
//! and then delivered, rather than being painted into the alternate screen.
//!
//! # Why the sink is a parameter
//!
//! Standard error cannot be captured from inside the process, so asserting
//! "this did not reach the terminal" against the real stream is impossible.
//! [`release_terminal_to`] takes the sink instead, and [`release_terminal`] is
//! its one-line specialization — so what these tests drive is the same code
//! the binary runs, with the last byte of it pointed somewhere readable.
//!
//! # Why the global state is safe to touch
//!
//! [`HELD`] and [`BUFFER`] are process-wide, and `nextest` — the runner this
//! project's gate uses — runs each test in its own process. Each test below
//! also leaves the flag clear, so the order is irrelevant either way.

use tracing::warn;
use tracing_subscriber::fmt;

use super::*;

/// The bytes a writer produced while the terminal was held.
fn release_into_string() -> String {
    let mut sink: Vec<u8> = Vec::new();
    release_terminal_to(&mut sink);
    String::from_utf8_lossy(&sink).into_owned()
}

#[test]
fn output_written_while_the_terminal_is_held_is_buffered_and_then_flushed_once() {
    hold_terminal();
    assert!(is_held(), "the flag is what diverts the writer");

    let mut writer = TerminalAwareWriter;
    let written = writer.write(b"first line\n").expect("buffering never fails");
    assert_eq!(written, 11, "a buffered write is a whole write, not a short one");
    writer.write_all(b"second line\n").expect("buffering never fails");

    // Nothing has reached any stream yet: the bytes are still in the buffer,
    // which is the branch a terminal-bound write would not have taken.
    assert_eq!(buffer().bytes, b"first line\nsecond line\n");

    let flushed = release_into_string();
    assert_eq!(flushed, "first line\nsecond line\n");
    assert!(!is_held(), "the release clears the flag as well as the buffer");

    // Flushed once: a second restore route — the panic hook after the
    // destructor, say — must not print the same lines again.
    assert_eq!(release_into_string(), "", "the buffer is emptied by the flush that wrote it");
}

#[test]
fn a_warning_raised_while_the_terminal_is_held_lands_in_the_buffer() {
    let subscriber = fmt()
        .with_writer(TerminalAwareWriter)
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .finish();

    hold_terminal();
    tracing::subscriber::with_default(subscriber, || {
        warn!(target: "agentctl", "the account registry could not be read this pass");
    });

    let flushed = release_into_string();
    assert!(
        flushed.contains("the account registry could not be read this pass"),
        "the warning must survive the terminal being held: {flushed:?}"
    );
    assert!(flushed.ends_with('\n'), "and arrive as whole lines: {flushed:?}");
}

#[test]
fn the_writer_is_shareable_across_the_threads_that_log_through_it() {
    // Not decoration: `watch` does not join its worker, so a pass thread holds
    // this writer and logs through it concurrently with the UI thread.
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<TerminalAwareWriter>();
}

#[test]
fn a_line_written_from_another_thread_is_buffered_and_flushed_with_the_rest() {
    hold_terminal();

    let worker = std::thread::spawn(|| {
        let mut writer = TerminalAwareWriter;
        writer.write_all(b"from the pass thread\n").expect("buffering never fails");
    });
    worker.join().expect("the worker should not have panicked");

    let mut writer = TerminalAwareWriter;
    writer.write_all(b"from the loop\n").expect("buffering never fails");

    let flushed = release_into_string();
    assert!(flushed.contains("from the pass thread"), "{flushed:?}");
    assert!(flushed.contains("from the loop"), "{flushed:?}");
}

#[test]
fn nothing_is_buffered_while_the_terminal_is_free() {
    // The default state, and the one every command other than `watch` runs
    // in: the writer must be an ordinary standard-error writer.
    assert!(!is_held());

    let mut writer = TerminalAwareWriter;
    writer.write_all(b"").expect("an empty write to standard error succeeds");

    assert!(buffer().bytes.is_empty(), "a free terminal buffers nothing");
    assert_eq!(release_into_string(), "", "so a release has nothing to deliver");
}

#[test]
fn a_buffer_that_fills_keeps_the_beginning_and_says_what_it_dropped() {
    // A `watch` left running overnight under `RUST_LOG=agentctl=trace` is the
    // case this bounds. The first bytes are the ones that explain a failure,
    // so they are the ones kept.
    hold_terminal();
    let mut writer = TerminalAwareWriter;
    writer.write_all(&vec![b'a'; BUFFER_LIMIT]).expect("buffering never fails");
    writer.write_all(b"overflow").expect("buffering never fails");

    let flushed = release_into_string();

    assert!(flushed.starts_with("aaaa"), "the beginning is kept");
    assert!(!flushed.contains("overflow"), "and the tail past the cap is not");
    assert!(
        flushed.contains("8 further bytes of log output were dropped"),
        "the flush must say how much it left out: {}",
        &flushed[BUFFER_LIMIT.min(flushed.len())..]
    );
}
