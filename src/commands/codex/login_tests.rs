use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

use super::*;
use crate::provider::codex::login_child;
use crate::provider::codex::testkit;
use crate::runtime::fault::Fault;

/// A `Prompt` that answers the way a test chose, or fails to read an answer
/// at all — the two things a terminal can do to the one question `login` asks.
struct Scripted {
    answer: Result<bool, ()>,
    asked: Vec<String>,
}

impl Scripted {
    fn saying(answer: bool) -> Self {
        Self { answer: Ok(answer), asked: Vec::new() }
    }

    /// A terminal whose answer cannot be read: a closed stdin, or the EPIPE a
    /// `agctl codex login | head -1` produces.
    fn unreadable() -> Self {
        Self { answer: Err(()), asked: Vec::new() }
    }
}

impl Prompt for Scripted {
    fn tell(&mut self, _message: &str) {}

    fn confirm(&mut self, question: &str) -> Result<bool, AppError> {
        self.asked.push(question.to_owned());
        self.answer.map_err(|()| AppError::Io {
            context: "could not read the confirmation".to_owned(),
            source: std::io::Error::from(std::io::ErrorKind::BrokenPipe),
        })
    }
}

#[test]
fn an_install_and_an_overwrite_are_described_differently() {
    assert_eq!(describe(WriteKind::LoginInstall { overwrote: false }), "a new grant");
    assert_eq!(
        describe(WriteKind::LoginInstall { overwrote: true }),
        "replacing the grant that was there"
    );
}

#[test]
fn a_refusal_carries_the_underlying_sentence_unchanged() {
    // Every early exit in `run` is wrapped by `refused`, so the sentence the
    // user reads is the one the failing step wrote, not a generic one.
    let err = refused("the scratch root `/x` is a symbolic link");
    assert_eq!(err.to_string(), "refused: the scratch root `/x` is a symbolic link");
}

#[test]
fn ac107_without_a_terminal_the_overwrite_is_refused_and_names_the_way_out() {
    // There is no `--yes` on `login` (plan section 3.2), so the refusal must
    // not name one: what a non-interactive run does instead is remove the
    // account first. The shared `Prompt::confirm` names `--yes`, which is
    // exactly why this question is not put through it.
    let mut io = Scripted::saying(true);
    let err =
        confirm_overwrite("user-1/acct-1", false, &mut io).expect_err("a pipe is not a person");

    let reason = err.to_string();
    assert!(reason.contains("agctl codex accounts remove user-1/acct-1"), "{reason}");
    assert!(reason.contains("not a terminal"), "{reason}");
    assert!(!reason.contains("--yes"), "`login` has no `--yes` to point at: {reason}");
    assert!(io.asked.is_empty(), "no question is put where nobody can answer it");
}

#[test]
fn ac107_a_no_answer_leaves_the_stored_grant_alone() {
    let mut io = Scripted::saying(false);
    let err = confirm_overwrite("user-1/acct-1", true, &mut io).expect_err("`no` means no");
    assert!(err.to_string().contains("left as it was"), "{err}");
    assert_eq!(io.asked.len(), 1);
    assert!(io.asked[0].contains("replace the grant"), "{}", io.asked[0]);
}

#[test]
fn ac107_a_yes_lets_the_install_go_on() {
    let mut io = Scripted::saying(true);
    confirm_overwrite("user-1/acct-1", true, &mut io).expect("a person said so");
    assert_eq!(io.asked.len(), 1);
}

#[test]
fn ac107_an_answer_that_cannot_be_read_stops_the_install() {
    // The third exit the confirmation has. It matters as much as the other
    // two: `install_verified` returns, `Scratch` drops, and the credential
    // the child wrote is unlinked — an install that went ahead because the
    // question could not be delivered would overwrite a grant nobody agreed
    // to replace.
    let mut io = Scripted::unreadable();
    let err = confirm_overwrite("user-1/acct-1", true, &mut io)
        .expect_err("an unread answer is not a yes");
    assert!(matches!(err, AppError::Io { .. }), "{err}");
}

#[test]
fn ac107_only_a_row_agctl_owns_is_asked_about() {
    let (_dir, paths) = testkit::store();
    let record = testkit::owned_record(testkit::USER, testkit::ACCT);

    // A namespace with no record is AC105's crash window; the next login
    // adopts it rather than asking about a credential nothing claims.
    assert_eq!(already_owned(&paths, testkit::USER, testkit::ACCT).expect("loads"), None);

    AgctlConfig::update(&paths, |config| config.codex_accounts.push(record.clone()))
        .expect("the registry is writable");
    assert_eq!(
        already_owned(&paths, testkit::USER, testkit::ACCT).expect("loads").as_deref(),
        Some(format!("{}/{}", testkit::USER, testkit::ACCT).as_str())
    );
    // Another identity is a different account, not an overwrite.
    assert_eq!(already_owned(&paths, testkit::USER, "acct-other").expect("loads"), None);

    // A row agctl does not own has no grant of agctl's to replace.
    AgctlConfig::update(&paths, |config| {
        if let Some(row) = config.codex_accounts.first_mut() {
            row.kind = CodexKind::Live;
        }
    })
    .expect("the registry is writable");
    assert_eq!(already_owned(&paths, testkit::USER, testkit::ACCT).expect("loads"), None);
}

// ---------------------------------------------------------------------------
// The confirmation where it actually sits: inside `install_verified`
// (review C4-C-2)
// ---------------------------------------------------------------------------

/// What one `install_verified` run left behind.
struct Run {
    /// What the call returned.
    result: Result<(), AppError>,
    /// The credential the "child" wrote into its scratch home.
    scratch_credential: PathBuf,
}

/// Runs the half of `login` that follows the child: verify, notice, confirm,
/// lock, install, audit, record.
///
/// This is the wiring the four `confirm_overwrite` tests above cannot see. A
/// scratch home is created the way `run` creates it, a credential is written
/// into it the way the vendor's CLI would, and a clean `PostExitReport`
/// stands for a child that exited 0 and left nothing behind.
fn install_run(paths: &Paths, stdin_is_tty: bool, io: &mut dyn Prompt) -> Run {
    let root_path = paths.codex_scratch_root();
    let root = login_child::open_scratch_root(&root_path).expect("the scratch root opens");
    let scratch = login_child::Scratch::create(&root_path, root).expect("a scratch home");
    let scratch_credential = scratch.path().join("auth.json");
    let exp = jiff::Timestamp::now().as_second() + 3600;
    testkit::write_0600(
        &scratch_credential,
        &testkit::pretty(&testkit::chatgpt_doc(Some(exp), None)),
    );

    let args = CodexLoginArgs { label: None, no_refresh: false };
    let result = install_verified(
        paths,
        &scratch,
        &testkit::clean_report(0),
        &args,
        &Cancel::new(),
        &Fault::none(),
        stdin_is_tty,
        io,
    );
    // `scratch` drops here, exactly as it does in `run`: whatever the answer
    // was, the credential the child wrote is unlinked and the home removed.
    Run { result, scratch_credential }
}

/// The store, the installed credential and the registry as they are now.
fn state(paths: &Paths) -> (Vec<u8>, u64, Vec<u8>) {
    let installed = paths
        .codex_namespace_dir(testkit::USER, testkit::ACCT)
        .expect("valid ids")
        .join("auth.json");
    let bytes = std::fs::read(&installed).expect("an installed credential");
    let inode = std::fs::metadata(&installed).expect("metadata").ino();
    let registry = std::fs::read(paths.config_file()).expect("the registry");
    (bytes, inode, registry)
}

/// A store holding one account, installed through the same path.
fn already_logged_in() -> (tempfile::TempDir, Paths) {
    let (dir, paths) = testkit::store();
    let mut io = Scripted::saying(false);
    // No record yet, so nothing is asked and nothing can be overwritten.
    install_run(&paths, false, &mut io).result.expect("the first login installs");
    assert_eq!(io.asked.len(), 0, "a first login has no grant to replace");
    (dir, paths)
}

#[test]
fn ac107_a_no_answer_inside_the_install_leaves_the_grant_and_the_registry_alone() {
    let (_dir, paths) = already_logged_in();
    let before = state(&paths);

    let mut io = Scripted::saying(false);
    let run = install_run(&paths, true, &mut io);

    let err = run.result.expect_err("`no` means the grant stays");
    assert!(err.to_string().contains("left as it was"), "{err}");
    assert_eq!(io.asked.len(), 1, "the question was put");
    assert_eq!(state(&paths), before, "same bytes, same inode, same registry");
    assert!(!run.scratch_credential.exists(), "the grant the child wrote is gone");
}

#[test]
fn ac107_an_answer_that_cannot_be_read_inside_the_install_changes_nothing() {
    // The EPIPE exit: the question could not be answered, so the install must
    // not happen — and the credential the child wrote must still be unlinked.
    let (_dir, paths) = already_logged_in();
    let before = state(&paths);

    let mut io = Scripted::unreadable();
    let run = install_run(&paths, true, &mut io);

    assert!(matches!(run.result, Err(AppError::Io { .. })), "{:?}", run.result);
    assert_eq!(state(&paths), before, "same bytes, same inode, same registry");
    assert!(!run.scratch_credential.exists(), "the grant the child wrote is gone");
}

#[test]
fn ac107_a_yes_inside_the_install_replaces_the_grant() {
    // The control the two refusals need: the confirmation is a question, not
    // a wall. A `yes` installs, and the registry keeps exactly one row.
    let (_dir, paths) = already_logged_in();
    let (_before_bytes, before_inode, _) = state(&paths);

    let mut io = Scripted::saying(true);
    install_run(&paths, true, &mut io).result.expect("a person said so");

    assert_eq!(io.asked.len(), 1);
    let (_bytes, inode, registry) = state(&paths);
    assert_ne!(inode, before_inode, "the install is a rename over the old inode");
    let document: serde_json::Value = serde_json::from_slice(&registry).expect("JSON");
    assert_eq!(document["codex_accounts"].as_array().map(Vec::len), Some(1));
}

#[test]
fn ac107_the_refusal_reads_as_one_sentence() {
    // Review C4-C-1: the literal was hand-wrapped and its source indentation
    // ended up inside the message, twice. A refusal a person reads must not
    // carry a run of spaces from the way the code was formatted.
    let mut io = Scripted::saying(true);
    let err = confirm_overwrite("user-1/acct-1", false, &mut io).expect_err("no terminal");
    let printed = err.to_string();
    assert!(!printed.contains("  "), "the message carries a run of spaces:\n{printed}");
}
