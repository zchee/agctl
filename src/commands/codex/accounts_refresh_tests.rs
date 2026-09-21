//! Tests for `agctl codex accounts set` and `agctl codex accounts refresh`
//! (plan AC127).
//!
//! The gates themselves belong to `provider::codex::refresh` and are proved
//! there. What is proved here is the command layer: that a re-send is built
//! only from a consent a person could have given, that every refusal the
//! driver takes reaches the user as a sentence and a non-zero exit, and that
//! `set` changes a registry field without opening the namespace.
//!
//! The terminal is a value (`stdin_is_tty`), so "a `yes` on a TTY" and "`--yes`
//! with no terminal" are both testable without one; the POST is a
//! [`PostPermit`] built over an `httpmock` endpoint, so "exactly 1 POST" is
//! counted rather than assumed.

use std::fs;
use std::path::PathBuf;

use httpmock::Method::POST;
use httpmock::Mock;
use httpmock::MockServer;
use jiff::Timestamp;
use serde_json::Value;
use serde_json::json;

use super::*;
use crate::config::codex::CodexAccountRecord;
use crate::provider::codex::audit;
use crate::provider::codex::audit::CodexAuditEntry;
use crate::provider::codex::audit::CodexOutcome;
use crate::provider::codex::auth_store::Inflight;
use crate::provider::codex::auth_store::RefreshState;
use crate::provider::codex::credentials::Credentials;
use crate::provider::codex::oauth::RefreshClient;
use crate::provider::codex::testkit;

const TOKEN_PATH: &str = "/oauth/token";
const NEW_RT: &str = "agctl-test-codex-rt-0002";

/// A `Prompt` that answers every question the same way and keeps both sides
/// of the conversation, so a test can assert on the words a person read.
struct Scripted {
    answer: bool,
    asked: Vec<String>,
    told: Vec<String>,
}

impl Scripted {
    fn saying(answer: bool) -> Self {
        Self { answer, asked: Vec::new(), told: Vec::new() }
    }

    /// Everything printed, joined — for a `contains` assertion.
    fn output(&self) -> String {
        self.told.join("\n")
    }
}

impl Prompt for Scripted {
    fn tell(&mut self, message: &str) {
        self.told.push(message.to_owned());
    }

    fn confirm(&mut self, question: &str) -> Result<bool, AppError> {
        self.asked.push(question.to_owned());
        Ok(self.answer)
    }
}

/// A store holding one owned Codex account.
struct Fixture {
    _dir: tempfile::TempDir,
    paths: Paths,
    record: CodexAccountRecord,
}

impl Fixture {
    /// An owned account whose access token expires in `exp_days`.
    ///
    /// Nine days out for every re-send test: `Resend` compares the marker and
    /// never adopts a fresh row, which a fixture with an expired token could
    /// not tell apart from the proactive path (plan AC127, critic v5 M1).
    fn new(exp_days: i64) -> Self {
        let (dir, paths) = testkit::store();
        let record = testkit::owned_record(testkit::USER, testkit::ACCT);
        let fixture = Self { _dir: dir, paths, record };
        let exp = Timestamp::now().as_second() + exp_days * 86_400;
        fixture.write_auth(&testkit::chatgpt_doc(Some(exp), None));
        fixture.record();
        fixture
    }

    /// The same, with a row agctl does not own.
    fn live() -> Self {
        let (dir, paths) = testkit::store();
        let mut record = testkit::owned_record(testkit::USER, testkit::ACCT);
        record.kind = CodexKind::Live;
        let fixture = Self { _dir: dir, paths, record };
        fixture.record();
        fixture
    }

    fn ns_dir(&self) -> PathBuf {
        self.paths.codex_namespace_dir(testkit::USER, testkit::ACCT).expect("valid ids")
    }

    fn auth_path(&self) -> PathBuf {
        self.ns_dir().join("auth.json")
    }

    fn auth(&self) -> Vec<u8> {
        fs::read(self.auth_path()).expect("auth.json reads")
    }

    fn write_auth(&self, doc: &Value) {
        testkit::write_0600(&self.auth_path(), &testkit::pretty(doc));
    }

    /// Puts the record in the registry, which is what the command resolves.
    fn record(&self) {
        let record = self.record.clone();
        AgctlConfig::update(&self.paths, |config| config.codex_accounts.push(record.clone()))
            .expect("the registry is writable");
    }

    fn row(&self) -> CodexAccountRecord {
        AgctlConfig::load(&self.paths)
            .expect("the registry loads")
            .codex_accounts
            .first()
            .cloned()
            .expect("the row is there")
    }

    fn policy(&self) -> RefreshPolicy {
        match self.row().kind {
            CodexKind::Owned { refresh, .. } => refresh,
            other => panic!("not an owned row: {other:?}"),
        }
    }

    fn marker_path(&self) -> PathBuf {
        self.paths.codex_refresh_state_path(testkit::USER, testkit::ACCT).expect("valid ids")
    }

    fn marker(&self) -> Option<RefreshState> {
        match fs::read(self.marker_path()) {
            Ok(bytes) => Some(serde_json::from_slice(&bytes).expect("the marker parses")),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => panic!("marker: {err}"),
        }
    }

    fn write_marker(&self, state: &RefreshState) {
        testkit::write_0600(&self.marker_path(), &serde_json::to_vec(state).expect("serializes"));
    }

    /// A marker saying "this grant was sent `ago_secs` ago and nothing
    /// classified the answer" — the `interrupted` marker of AC128 (1)/(2),
    /// whose `since` is the send's own time.
    fn write_interrupted_marker(&self, ago_secs: i64) {
        let sent_at =
            Timestamp::from_second(Timestamp::now().as_second() - ago_secs).expect("a valid time");
        self.write_marker(&RefreshState {
            inflight: Some(Inflight { sent_digest8: self.refresh_digest8(), sent_at }),
            last_sent_at: Some(sent_at),
            ..RefreshState::default()
        });
    }

    fn refresh_digest8(&self) -> String {
        Credentials::parse(&self.auth())
            .expect("auth.json parses")
            .refresh_digest8()
            .expect("a refresh token")
    }

    fn request<'a>(&self, resend: bool, reset_floor: bool, yes: bool) -> Request<'a> {
        Request { id: testkit::USER, resend, reset_floor, yes }
    }

    fn audit(&self) -> Vec<CodexAuditEntry> {
        audit::read(&self.paths)
            .expect("the audit log reads")
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).expect("an entry"))
            .collect()
    }

    fn outcomes(&self) -> Vec<CodexOutcome> {
        self.audit().iter().map(|entry| entry.outcome).collect()
    }

    /// One `--resend`, with the endpoint the permit posts to chosen here.
    fn resend(
        &self,
        url: &str,
        stdin_is_tty: bool,
        yes: bool,
        io: &mut dyn Prompt,
    ) -> Result<(), AppError> {
        let permit = PostPermit::with_client(RefreshClient::new(url, "agctl/test"));
        let record = self.row();
        let owned = proof::owned(&record).expect("an owned record");
        let shown = accounts::key(&record);
        let request = self.request(true, false, yes);
        resend(&self.paths, &permit, owned, &shown, &request, stdin_is_tty, &Cancel::new(), io)
    }
}

fn mock<'a>(server: &'a MockServer, status: u16, body: &Value) -> Mock<'a> {
    server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(status).json_body(body.clone());
    })
}

/// A token response in fact F80's shape, carrying a rotated refresh token.
fn grant_body() -> Value {
    json!({
        "access_token": testkit::access_token(Some(Timestamp::now().as_second() + 10 * 86_400)),
        "token_type": "Bearer",
        "expires_in": 864_000,
        "refresh_token": NEW_RT,
        "id_token": testkit::id_token(&testkit::IdClaims::default()),
    })
}

fn refused_reason(err: &AppError) -> String {
    err.to_string()
}

// ---------------------------------------------------------------------------
// `set --refresh auto|never` (plan AC127, first clause)
// ---------------------------------------------------------------------------

#[test]
fn ac127_set_flips_the_policy_without_opening_the_namespace() {
    // The spy: `set` may write the registry and nothing else, so the
    // namespace directory must not exist afterwards — neither created by the
    // command nor by a lock it had no business taking.
    let fixture = Fixture::new(9);
    let ns = fixture.ns_dir();
    fs::remove_file(fixture.auth_path()).expect("the credential is removable");
    fs::remove_dir(&ns).expect("the namespace is removable");
    assert_eq!(fixture.policy(), RefreshPolicy::Auto);

    let mut io = Scripted::saying(false);
    set(&fixture.paths, testkit::USER, RefreshMode::Never, &mut io).expect("set never");
    assert_eq!(fixture.policy(), RefreshPolicy::Never);
    assert!(!ns.exists(), "`set` created a namespace: {}", ns.display());
    assert!(fixture.marker().is_none(), "`set` wrote a refresh marker");
    assert!(io.asked.is_empty(), "`set` asked a question: {:?}", io.asked);
    assert!(
        io.output().contains("expired (run agctl codex login)"),
        "the user is told what `never` does to the row:\n{}",
        io.output()
    );

    // And `auto` restores it.
    let mut io = Scripted::saying(false);
    set(&fixture.paths, testkit::USER, RefreshMode::Auto, &mut io).expect("set auto");
    assert_eq!(fixture.policy(), RefreshPolicy::Auto);
    assert!(!ns.exists(), "`set auto` created a namespace");
}

#[test]
fn set_says_so_rather_than_rewriting_when_the_policy_already_holds() {
    let fixture = Fixture::new(9);
    let mut io = Scripted::saying(false);
    set(&fixture.paths, testkit::USER, RefreshMode::Auto, &mut io).expect("set auto");
    assert!(io.output().contains("already `auto`"), "{}", io.output());
    assert_eq!(fixture.policy(), RefreshPolicy::Auto);
}

#[test]
fn set_refuses_a_row_agctl_stores_no_credential_for() {
    let fixture = Fixture::live();
    let mut io = Scripted::saying(true);
    let err = set(&fixture.paths, testkit::USER, RefreshMode::Never, &mut io)
        .expect_err("a live row has no agctl refresh policy");
    assert!(refused_reason(&err).contains("never refreshes"), "{err}");
    assert_eq!(err.exit_code(), crate::error::EXIT_PARTIAL);
}

#[test]
fn set_reports_an_id_that_matches_nothing_in_codex_accounts() {
    let fixture = Fixture::new(9);
    let mut io = Scripted::saying(true);
    let err = set(&fixture.paths, "nobody", RefreshMode::Never, &mut io).expect_err("no such row");
    assert!(err.to_string().contains("no account matches `nobody`"), "{err}");
}

// ---------------------------------------------------------------------------
// `refresh --resend` (plan AC127, second clause; decision D-035, risk R63)
// ---------------------------------------------------------------------------

#[test]
fn ac127_yes_without_a_terminal_is_refused_and_sends_nothing() {
    // `--yes` is not a way to schedule a re-send: `after_confirmation`
    // returns `Err` before a `SendMode::Resend` exists, so the POST count is
    // the proof that no send was even attempted.
    let server = MockServer::start();
    let post = mock(&server, 200, &grant_body());
    let fixture = Fixture::new(9);
    fixture.write_interrupted_marker(61 * 60);

    let mut io = Scripted::saying(true);
    let err = fixture
        .resend(&server.url(TOKEN_PATH), false, true, &mut io)
        .expect_err("no terminal, no re-send");

    post.assert_calls(0);
    assert!(refused_reason(&err).contains("interactive terminal"), "{err}");
    assert!(io.asked.is_empty(), "a question was put with no terminal to put it at");
    assert!(fixture.marker().expect("marker").inflight.is_some(), "the marker is untouched");
    assert!(!fixture.marker().expect("marker").resent, "nothing was spent");
    assert!(fixture.outcomes().is_empty(), "nothing was audited");
}

#[test]
fn ac127_a_no_answer_sends_nothing_and_is_not_a_failure() {
    let server = MockServer::start();
    let post = mock(&server, 200, &grant_body());
    let fixture = Fixture::new(9);
    fixture.write_interrupted_marker(61 * 60);

    let mut io = Scripted::saying(false);
    fixture.resend(&server.url(TOKEN_PATH), true, false, &mut io).expect("declining is an answer");

    post.assert_calls(0);
    assert_eq!(io.asked.len(), 1, "the question is put exactly once");
    assert!(
        io.asked[0].contains("R63"),
        "the question names the risk it carries:\n{}",
        io.asked[0]
    );
    assert!(io.output().contains("nothing was sent"), "{}", io.output());
    assert!(!fixture.marker().expect("marker").resent);
}

#[test]
fn ac127_an_interrupted_marker_is_re_sent_once_at_61_minutes_with_the_marker_digest() {
    let server = MockServer::start();
    let post = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(200).json_body(grant_body());
    });
    let fixture = Fixture::new(9);
    let sent_digest8 = fixture.refresh_digest8();
    fixture.write_interrupted_marker(61 * 60);
    let before = fixture.marker().expect("marker");

    let mut io = Scripted::saying(true);
    fixture.resend(&server.url(TOKEN_PATH), true, false, &mut io).expect("the re-send lands");

    // Exactly one POST, and it carried the grant the MARKER names — not a
    // fresher one the file might have held (the fixture's access token is
    // nine days from expiry, so nothing here is due).
    post.assert_calls(1);
    assert_eq!(before.inflight.as_ref().map(|i| i.sent_digest8.clone()), Some(sent_digest8));

    let doc: Value = serde_json::from_slice(&fixture.auth()).expect("json");
    assert_eq!(doc["tokens"]["refresh_token"], NEW_RT, "the rotated grant is stored");
    // `Ambiguous` first: this is the pass that finds an `inflight` nobody
    // classified and writes D-035's `ambiguous (interrupted)` line, which is
    // also what makes `since` the send's own time. Then the re-send, then the
    // grant it brought back.
    assert_eq!(
        fixture.outcomes(),
        [CodexOutcome::Ambiguous, CodexOutcome::Resend, CodexOutcome::Applied]
    );
    assert!(io.output().contains("new grant"), "{}", io.output());
}

#[test]
fn ac127_the_re_send_is_recorded_in_the_write_that_sends_it_and_never_happens_twice() {
    // A 5xx leaves the row unknown, which is what makes the second attempt
    // reach the `already resent` gate rather than the `not unknown` one.
    let server = MockServer::start();
    let post = mock(&server, 503, &json!({}));
    let fixture = Fixture::new(9);
    fixture.write_interrupted_marker(61 * 60);
    let before = fixture.marker().expect("marker");

    let mut io = Scripted::saying(true);
    let err = fixture
        .resend(&server.url(TOKEN_PATH), true, false, &mut io)
        .expect_err("the row is still not usable");
    post.assert_calls(1);
    assert_eq!(err.exit_code(), crate::error::EXIT_PARTIAL, "{err}");
    assert!(io.output().contains("still unknown"), "{}", io.output());

    let after = fixture.marker().expect("marker");
    assert!(after.resent, "`write_resend` records the spent re-send with the send itself");
    let (before_inflight, after_inflight) =
        (before.inflight.expect("inflight"), after.inflight.expect("inflight"));
    assert_eq!(
        after_inflight.sent_digest8, before_inflight.sent_digest8,
        "the same grant was re-sent"
    );
    assert!(after_inflight.sent_at > before_inflight.sent_at, "with a new send time");

    let mut io = Scripted::saying(true);
    let err = fixture
        .resend(&server.url(TOKEN_PATH), true, false, &mut io)
        .expect_err("a marker carries one re-send");
    post.assert_calls(1);
    assert!(refused_reason(&err).contains("already spent"), "{err}");
    assert!(refused_reason(&err).contains("agctl codex login"), "the way out is named: {err}");
}

#[test]
fn ac127_a_row_that_is_not_in_refresh_outcome_unknown_has_nothing_to_re_send() {
    let server = MockServer::start();
    let post = mock(&server, 200, &grant_body());
    let fixture = Fixture::new(9);

    let mut io = Scripted::saying(true);
    let err = fixture
        .resend(&server.url(TOKEN_PATH), true, false, &mut io)
        .expect_err("no marker, no re-send");

    post.assert_calls(0);
    assert!(refused_reason(&err).contains("not unknown"), "{err}");
}

#[test]
fn ac127_a_send_thirty_minutes_old_is_refused_and_names_the_hour() {
    let server = MockServer::start();
    let post = mock(&server, 200, &grant_body());
    let fixture = Fixture::new(9);
    fixture.write_interrupted_marker(30 * 60);

    let mut io = Scripted::saying(true);
    let err = fixture
        .resend(&server.url(TOKEN_PATH), true, false, &mut io)
        .expect_err("an answer may still be on its way");

    post.assert_calls(0);
    let reason = refused_reason(&err);
    assert!(reason.contains("an hour"), "the wait is named: {reason}");
    assert!(reason.contains("eligible at"), "and so is when it ends: {reason}");
}

#[test]
fn ac127_a_stray_staged_temporary_refuses_the_re_send_and_names_it() {
    let server = MockServer::start();
    let post = mock(&server, 200, &grant_body());
    let fixture = Fixture::new(9);
    fixture.write_interrupted_marker(61 * 60);
    testkit::write_0600(&fixture.ns_dir().join("auth.json.tmp.0123abcd"), b"{}");

    let mut io = Scripted::saying(true);
    let err = fixture
        .resend(&server.url(TOKEN_PATH), true, false, &mut io)
        .expect_err("a staged temporary may hold a rotated grant");

    post.assert_calls(0);
    let reason = refused_reason(&err);
    // The namespace and what the file is, not its name: spelling a store
    // file's name outside `auth_store.rs` is a `phase3-greps.sh` violation
    // (`auth_json`), so `doctor` is what names the path exactly.
    assert!(reason.contains("staged temporary"), "what is in the way is said: {reason}");
    assert!(reason.contains("rotated"), "and why it matters: {reason}");
    assert!(reason.contains("doctor"), "and what names it exactly: {reason}");
}

#[test]
fn ac127_a_parked_credential_is_resolved_first_and_the_stale_marker_refuses_the_re_send() {
    // The pending pair is what a crash between the POST and the rename leaves
    // behind. `resolve_pending` replays it before anything else, which
    // changes the file's refresh digest — so the marker that named the old
    // grant is stale, and there is nothing this command may re-send.
    let server = MockServer::start();
    let post = mock(&server, 200, &grant_body());
    let fixture = Fixture::new(9);
    fixture.write_interrupted_marker(61 * 60);

    let current = Credentials::parse(&fixture.auth()).expect("parses").digests().expect("digests");
    let mut parked = testkit::chatgpt_doc(Some(Timestamp::now().as_second() + 10 * 86_400), None);
    parked["tokens"]["refresh_token"] = json!(NEW_RT);
    testkit::write_0600(&fixture.ns_dir().join("auth.json.pending"), &testkit::pretty(&parked));
    testkit::write_0600(
        &fixture.ns_dir().join("auth.pending.meta"),
        json!({
            "derived_from_access_sha256": current.access_sha256,
            "derived_from_refresh_sha256": current.refresh_sha256,
            "created_at": Timestamp::now().to_string(),
            "new_expires_at": Timestamp::now().as_second() + 10 * 86_400,
        })
        .to_string()
        .as_bytes(),
    );

    let mut io = Scripted::saying(true);
    let err = fixture
        .resend(&server.url(TOKEN_PATH), true, false, &mut io)
        .expect_err("the parked grant is the newer one");

    post.assert_calls(0);
    assert!(refused_reason(&err).contains("not unknown"), "{err}");
    assert_eq!(
        serde_json::from_slice::<Value>(&fixture.auth()).expect("json")["tokens"]["refresh_token"],
        NEW_RT,
        "the parked grant was put in place"
    );
}

#[test]
fn a_row_agctl_stores_no_credential_for_has_no_refresh_state_to_act_on() {
    let fixture = Fixture::live();
    let mut io = Scripted::saying(true);
    let err = refresh_with(
        &fixture.paths,
        &fixture.request(true, false, false),
        true,
        &Cancel::new(),
        &mut io,
    )
    .expect_err("a live row is refreshed by its own client");
    assert!(refused_reason(&err).contains("stores no credential"), "{err}");
    assert!(io.asked.is_empty(), "the question is not even put");
}

#[test]
fn refresh_needs_one_of_the_two_actions() {
    let fixture = Fixture::new(9);
    let mut io = Scripted::saying(true);
    let err = refresh_with(
        &fixture.paths,
        &fixture.request(false, false, false),
        true,
        &Cancel::new(),
        &mut io,
    )
    .expect_err("a bare `refresh` does nothing");
    assert_eq!(err.exit_code(), crate::error::EXIT_FATAL, "a usage error is fatal: {err}");
    assert!(err.to_string().contains("--resend"), "{err}");
    assert!(err.to_string().contains("--reset-floor"), "{err}");
}

// ---------------------------------------------------------------------------
// `refresh --reset-floor` (plan AC127, last clause)
// ---------------------------------------------------------------------------

#[test]
fn ac127_reset_floor_lifts_the_terminal_state_with_an_audit_line_and_nothing_else() {
    let fixture = Fixture::new(9);
    fixture.write_marker(&RefreshState {
        did_not_help: 3,
        floor_min: 240,
        ..RefreshState::default()
    });
    let before = fixture.auth();

    let mut io = Scripted::saying(true);
    refresh_with(
        &fixture.paths,
        &fixture.request(false, true, false),
        true,
        &Cancel::new(),
        &mut io,
    )
    .expect("the floor is lifted");

    let marker = fixture.marker().expect("marker");
    assert_eq!((marker.did_not_help, marker.floor_min), (0, 60));
    assert_eq!(fixture.outcomes(), [CodexOutcome::FloorReset], "one audit line, no send");
    assert_eq!(fixture.auth(), before, "the credential is untouched");
    assert_eq!(io.asked.len(), 1, "a person said so");
}

#[test]
fn reset_floor_without_a_terminal_is_refused_and_changes_nothing() {
    let fixture = Fixture::new(9);
    fixture.write_marker(&RefreshState {
        did_not_help: 3,
        floor_min: 240,
        ..RefreshState::default()
    });

    let mut io = Scripted::saying(true);
    let err = refresh_with(
        &fixture.paths,
        &fixture.request(false, true, true),
        false,
        &Cancel::new(),
        &mut io,
    )
    .expect_err("`--yes` is refused without a terminal here too");

    assert!(refused_reason(&err).contains("interactive terminal"), "{err}");
    let marker = fixture.marker().expect("marker");
    assert_eq!((marker.did_not_help, marker.floor_min), (3, 240), "nothing was lifted");
    assert!(fixture.outcomes().is_empty(), "and nothing was audited");
}

#[test]
fn reset_floor_declined_changes_nothing_and_is_not_a_failure() {
    let fixture = Fixture::new(9);
    fixture.write_marker(&RefreshState { did_not_help: 3, ..RefreshState::default() });

    let mut io = Scripted::saying(false);
    refresh_with(
        &fixture.paths,
        &fixture.request(false, true, false),
        true,
        &Cancel::new(),
        &mut io,
    )
    .expect("declining is an answer");

    assert_eq!(fixture.marker().expect("marker").did_not_help, 3);
    assert!(io.output().contains("nothing was changed"), "{}", io.output());
}
