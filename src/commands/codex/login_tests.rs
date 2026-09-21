use super::*;
use crate::provider::codex::testkit;

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
