use std::fs;
use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::sync::Arc;
use std::thread::JoinHandle;

use httpmock::Method::POST;
use httpmock::Mock;
use httpmock::MockServer;
use serde_json::Value;
use serde_json::json;

use super::*;
use crate::config::codex::CodexAccountRecord;
use crate::provider::codex::audit::CodexAuditEntry;
use crate::provider::codex::audit::CodexOutcome;
use crate::provider::codex::auth_store::Inflight;
use crate::provider::codex::credentials::Credentials;
use crate::provider::codex::proof;
use crate::provider::codex::testkit;

const TOKEN_PATH: &str = "/oauth/token";

/// (name, answer, stdin is a terminal, `--yes`, expected).
type ConsentCase = (&'static str, &'static str, bool, bool, Result<(), ConsentRefusal>);
/// (name, status, body, headers, expected class).
type UnknownCase =
    (&'static str, u16, &'static str, &'static [(&'static str, &'static str)], UnknownClass);
const NEW_RT: &str = "agctl-test-codex-rt-0002";
const OTHER_RT: &str = "agctl-test-codex-rt-external";

/// The child-process switch: set only on a copy of this test binary that a
/// test re-executes to die at a fault point.
const CHILD_CONFIG_ENV: &str = "AGCTL_S32_CHILD_CONFIG";
const CHILD_URL_ENV: &str = "AGCTL_S32_CHILD_URL";
const CHILD_FAULT_ENV: &str = "AGCTL_S32_CHILD_FAULT";

fn now_s() -> i64 {
    Timestamp::now().as_second()
}

/// An `auth.json` whose access token expires at `exp` with refresh token `rt`.
fn doc(exp: i64, rt: &str) -> Value {
    let mut doc = testkit::chatgpt_doc(Some(exp), Some("2026-09-06T21:40:50.123456Z"));
    doc["tokens"]["refresh_token"] = json!(rt);
    doc
}

fn digest8(bytes: &[u8]) -> String {
    Credentials::parse(bytes).expect("parses").refresh_digest8().expect("a refresh token")
}

fn access_digest8(bytes: &[u8]) -> String {
    Credentials::parse(bytes).expect("parses").access_digest8().expect("an access token")
}

/// A token response in fact F80's shape.
fn grant_body(rt: Option<&str>) -> Value {
    let mut body = json!({
        "access_token": testkit::access_token(Some(now_s() + 10 * 86_400)),
        "token_type": "Bearer",
        "expires_in": 864_000,
        "id_token": testkit::id_token(&testkit::IdClaims::default()),
        "earliest_refresh_at": now_s() + 9 * 86_400,
        "oai_is": "agctl-test-codex-ak-opaque",
    });
    if let (Some(rt), Some(object)) = (rt, body.as_object_mut()) {
        object.insert("refresh_token".to_owned(), json!(rt));
    }
    body
}

struct Fixture {
    _dir: tempfile::TempDir,
    paths: Paths,
    record: CodexAccountRecord,
}

impl Fixture {
    fn new(doc: &Value) -> Self {
        let (dir, paths) = testkit::store();
        let fixture =
            Self { _dir: dir, paths, record: testkit::owned_record(testkit::USER, testkit::ACCT) };
        fixture.write_auth(doc);
        fixture
    }

    fn expired() -> Self {
        Self::new(&doc(1_000, testkit::RT_SENTINEL))
    }

    fn ns_dir(&self) -> PathBuf {
        self.paths.codex_namespace_dir(testkit::USER, testkit::ACCT).expect("valid ids")
    }

    fn auth_path(&self) -> PathBuf {
        self.ns_dir().join("auth.json")
    }

    fn write_auth(&self, doc: &Value) {
        testkit::write_0600(&self.auth_path(), &testkit::pretty(doc));
    }

    fn auth(&self) -> Vec<u8> {
        fs::read(self.auth_path()).expect("auth.json reads")
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

    fn owned(&self) -> OwnedRecord<'_> {
        proof::owned(&self.record).expect("an owned record")
    }

    fn run_with(&self, mode: SendMode, client: &RefreshClient, fault: &Fault) -> RefreshReport {
        let cancel = Cancel::new();
        let ctx = RefreshCtx {
            paths: &self.paths,
            client,
            deadline: Instant::now() + Duration::from_secs(60),
            lock_budget: LockBudget::Pass(PASS_LOCK_BUDGET),
            cancel: &cancel,
            fault,
        };
        run(self.owned(), mode, &ctx)
    }

    fn run(&self, mode: SendMode, client: &RefreshClient) -> RefreshReport {
        self.run_with(mode, client, &Fault::none())
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

    fn ns_entries(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(self.ns_dir())
            .expect("list")
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

fn client(url: &str) -> RefreshClient {
    RefreshClient::new(url, "agctl/test")
}

fn mock<'a>(server: &'a MockServer, status: u16, body: &Value) -> Mock<'a> {
    server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(status).json_body(body.clone());
    })
}

fn state_with_inflight(sent_digest8: &str, sent_at: Timestamp) -> RefreshState {
    RefreshState {
        inflight: Some(Inflight { sent_digest8: sent_digest8.to_owned(), sent_at }),
        last_sent_at: Some(sent_at),
        ..RefreshState::default()
    }
}

fn ago(seconds: i64) -> Timestamp {
    Timestamp::from_second(now_s() - seconds).expect("a valid time")
}

fn is_unknown(step: &RefreshStep, class: UnknownClass) -> bool {
    matches!(step, RefreshStep::OutcomeUnknown { class: found, .. } if *found == class)
}

/// Reads one HTTP request with a `content-length` body.
fn read_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let read = stream.read(&mut chunk).expect("read");
        assert!(read > 0, "the client closed early");
        buffer.extend_from_slice(&chunk[..read]);
        let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") else { continue };
        let head = String::from_utf8_lossy(&buffer[..end]).to_ascii_lowercase();
        let length: usize = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .and_then(|value| value.trim().parse().ok())
            .expect("content-length");
        while buffer.len() < end + 4 + length {
            let read = stream.read(&mut chunk).expect("read");
            assert!(read > 0, "the client closed mid-body");
            buffer.extend_from_slice(&chunk[..read]);
        }
        return buffer[end + 4..end + 4 + length].to_vec();
    }
}

/// A one-request token endpoint that runs `during` — an external writer, a
/// chmod — after the POST arrived and before it answers.
fn responder(
    during: impl FnOnce() -> (u16, String) + Send + 'static,
) -> (String, JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let url =
        format!("http://127.0.0.1:{}{TOKEN_PATH}", listener.local_addr().expect("addr").port());
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let body = read_request(&mut stream);
        let (status, reply) = during();
        let response = format!(
            "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
            reply.len()
        );
        stream.write_all(response.as_bytes()).expect("reply");
        body
    });
    (url, handle)
}

// ---------------------------------------------------------------------------
// Budget and consents
// ---------------------------------------------------------------------------

#[test]
fn the_post_budget_is_the_sum_of_the_six_phases_on_the_built_agent() {
    let agent = oauth::refresh_agent("agctl/test");
    let timeouts = agent.config().timeouts();
    let phases = [
        timeouts.resolve,
        timeouts.connect,
        timeouts.send_request,
        timeouts.send_body,
        timeouts.recv_response,
        timeouts.recv_body,
    ];
    let total = phases
        .iter()
        .try_fold(Duration::ZERO, |sum, phase| sum.checked_add(phase.expect("every phase is set")));
    assert_eq!(total, Some(REFRESH_POST_BUDGET));
    assert_eq!(REFRESH_POST_BUDGET, Duration::from_secs(19));
    assert_eq!(timeouts.await_100, ureq::config::Config::default().timeouts().await_100);
    assert_eq!(WRITE_ALLOWANCE, Duration::from_secs(1));
    assert_eq!(PASS_LOCK_BUDGET, Duration::from_secs(1));
    // Plan AC91 (b): the default Codex status deadline (lock + budget +
    // allowance + 2 × the default 10 s `--timeout`) leaves the check's 21 s.
    let needed = PASS_LOCK_BUDGET + REFRESH_POST_BUDGET + WRITE_ALLOWANCE;
    assert_eq!(needed, Duration::from_secs(21));
    assert!(needed + Duration::from_secs(20) >= needed);
}

#[test]
fn consents_need_a_terminal_and_a_yes() {
    let tests: [ConsentCase; 7] = [
        ("typed yes", "yes\n", true, false, Ok(())),
        ("typed YES", "  YES ", true, false, Ok(())),
        ("--yes on a terminal", "", true, true, Ok(())),
        ("typed y", "y", true, false, Err(ConsentRefusal::NotConfirmed)),
        ("typed no", "no", true, false, Err(ConsentRefusal::NotConfirmed)),
        ("--yes piped", "", false, true, Err(ConsentRefusal::NotATerminal)),
        ("yes piped", "yes", false, false, Err(ConsentRefusal::NotATerminal)),
    ];
    for (name, answer, tty, yes, expected) in tests {
        assert_eq!(
            ResendConsent::after_confirmation(answer, tty, yes).map(|_| ()),
            expected,
            "{name}"
        );
        assert_eq!(
            ResetConsent::after_confirmation(answer, tty, yes).map(|_| ()),
            expected,
            "{name}"
        );
    }
}

#[test]
fn clamps_and_waits() {
    let now = Timestamp::now();
    assert_eq!(clamp_earliest(None, now), None);
    assert_eq!(clamp_earliest(Some(ago(10)), now), None, "a past floor is no floor");
    let far = now.checked_add(SignedDuration::from_hours(24 * 365)).expect("time");
    assert_eq!(
        clamp_earliest(Some(far), now),
        now.checked_add(MAX_EARLIEST_REFRESH_AHEAD).ok(),
        "clamped to thirty days"
    );
    let since = ago(0);
    let hour = since.checked_add(SignedDuration::from_hours(1)).expect("time");
    assert_eq!(resend_eligible_at(since, UnknownClass::Ambiguous, None), hour);
    assert_eq!(
        resend_eligible_at(since, UnknownClass::Ambiguous, Some(Duration::from_secs(7200))),
        hour,
        "retry-after matters only for rate_limited"
    );
    assert_eq!(
        resend_eligible_at(since, UnknownClass::RateLimited, Some(Duration::from_secs(60))),
        hour,
        "at least an hour"
    );
    assert_eq!(
        resend_eligible_at(
            since,
            UnknownClass::RateLimited,
            Some(Duration::from_secs(10 * 86_400))
        ),
        since.checked_add(SignedDuration::from_hours(24)).expect("time"),
        "retry-after clamped to a day"
    );
}

// ---------------------------------------------------------------------------
// Applied (plan AC91 (a), AC93, AC117)
// ---------------------------------------------------------------------------

#[test]
fn an_expired_owned_grant_is_refreshed_with_one_post() {
    let fixture = Fixture::expired();
    let before = fixture.auth();
    let before_ino = fs::metadata(fixture.auth_path()).expect("stat").ino();
    let sent = digest8(&before);
    let server = MockServer::start();
    let post = mock(&server, 200, &grant_body(Some(NEW_RT)));

    let report = fixture.run(SendMode::Proactive, &client(&server.url(TOKEN_PATH)));

    assert_eq!(report.step, RefreshStep::Refreshed { parked: false }, "{report:?}");
    post.assert_calls(1);
    let after = fixture.auth();
    let meta = fs::metadata(fixture.auth_path()).expect("stat");
    assert_ne!(meta.ino(), before_ino, "replaced by rename, not in place");
    assert_eq!(meta.permissions().mode() & 0o7777, 0o600);
    assert!(meta.is_file());
    assert_ne!(digest8(&after), sent, "the rotated refresh token is on disk");

    // At most four leaves change: three tokens and last_refresh (plan AC87).
    let old: Value = serde_json::from_slice(&before).expect("json");
    let new: Value = serde_json::from_slice(&after).expect("json");
    let (old, new) = (testkit::leaves(&old), testkit::leaves(&new));
    let changed: Vec<&String> =
        old.keys().chain(new.keys()).filter(|key| old.get(*key) != new.get(*key)).collect();
    let mut changed: Vec<&str> = changed.iter().map(|key| key.as_str()).collect();
    changed.sort_unstable();
    changed.dedup();
    let allowed =
        ["/last_refresh", "/tokens/access_token", "/tokens/id_token", "/tokens/refresh_token"];
    assert!(
        changed.iter().all(|leaf| allowed.contains(leaf)),
        "only the four refresh leaves: {changed:?}"
    );
    for leaf in ["/last_refresh", "/tokens/access_token", "/tokens/refresh_token"] {
        assert!(changed.contains(&leaf), "{leaf} was written: {changed:?}");
    }
    assert!(
        !String::from_utf8_lossy(&after).contains("oai_is"),
        "an unknown member is not persisted"
    );

    assert_eq!(fixture.ns_entries(), ["auth.json"], "no tmp, no pending");
    let marker = fixture.marker().expect("a marker");
    assert_eq!(marker.inflight, None, "cleared on a definite outcome");
    let earliest = marker.earliest_refresh.expect("the server floor is recorded (282a)");
    assert_eq!(earliest.grant_digest8, digest8(&after));
    assert_eq!(fixture.outcomes(), [CodexOutcome::Applied]);
    let audit_text = fs::read_to_string(audit::log_path(&fixture.paths)).expect("log");
    testkit::assert_no_needles(&audit_text, "the audit log");
    testkit::assert_no_needles(&format!("{report:?}"), "the report");
}

#[test]
fn a_response_without_a_refresh_token_keeps_the_old_one() {
    let fixture = Fixture::expired();
    let sent = digest8(&fixture.auth());
    let server = MockServer::start();
    let post = mock(&server, 200, &grant_body(None));
    let report = fixture.run(SendMode::Proactive, &client(&server.url(TOKEN_PATH)));
    assert_eq!(report.step, RefreshStep::Refreshed { parked: false }, "{report:?}");
    post.assert_calls(1);
    assert_eq!(digest8(&fixture.auth()), sent, "no refresh_token means keep the old one (F92)");
}

#[test]
fn an_artefact_appearing_after_the_post_is_noted_and_the_grant_written() {
    let fixture = Fixture::expired();
    let daemon = fixture.ns_dir().join("app-server-daemon");
    let (url, server) = responder(move || {
        fs::create_dir(&daemon).expect("mkdir");
        fs::write(daemon.join("daemon.lock"), b"").expect("write");
        (200, grant_body(Some(NEW_RT)).to_string())
    });
    let report = fixture.run(SendMode::Proactive, &client(&url));
    server.join().expect("responder");
    assert_eq!(report.step, RefreshStep::Refreshed { parked: false }, "{report:?}");
    assert!(report.notes.contains(&RefreshNote::CodexSession(DaemonEvidence::ArtefactOnly)));
    assert_ne!(
        digest8(&fixture.auth()),
        digest8(&testkit::pretty(&doc(1_000, testkit::RT_SENTINEL)))
    );
}

#[test]
fn an_audit_log_that_refuses_after_a_landed_write_leaves_the_write() {
    let fixture = Fixture::expired();
    fs::create_dir_all(audit::log_path(&fixture.paths)).expect("a directory at the log's name");
    let server = MockServer::start();
    mock(&server, 200, &grant_body(Some(NEW_RT)));
    let report = fixture.run(SendMode::Proactive, &client(&server.url(TOKEN_PATH)));
    assert_eq!(report.step, RefreshStep::Refreshed { parked: false }, "{report:?}");
    assert!(report.notes.contains(&RefreshNote::AuditLogRefused), "{report:?}");
    assert_ne!(
        digest8(&fixture.auth()),
        digest8(&testkit::pretty(&doc(1_000, testkit::RT_SENTINEL)))
    );
}

// ---------------------------------------------------------------------------
// Gates before the send
// ---------------------------------------------------------------------------

#[test]
fn nothing_is_sent_without_the_time_the_send_needs() {
    // Plan AC124 (g): one second short of lock + budget + allowance.
    let fixture = Fixture::expired();
    let server = MockServer::start();
    let post = mock(&server, 200, &grant_body(Some(NEW_RT)));
    let cancel = Cancel::new();
    let client = client(&server.url(TOKEN_PATH));
    let ctx = RefreshCtx {
        paths: &fixture.paths,
        client: &client,
        deadline: Instant::now() + Duration::from_secs(20),
        lock_budget: LockBudget::Pass(PASS_LOCK_BUDGET),
        cancel: &cancel,
        fault: &Fault::none(),
    };
    let report = run(fixture.owned(), SendMode::Proactive, &ctx);
    assert_eq!(report.step, RefreshStep::Stale(StaleReason::NotEnoughTime));
    post.assert_calls(0);
    assert_eq!(fixture.marker(), None, "not even the marker");
}

#[test]
fn fresh_disabled_cancelled_and_busy_send_nothing() {
    let server = MockServer::start();
    let post = mock(&server, 200, &grant_body(Some(NEW_RT)));
    let client = client(&server.url(TOKEN_PATH));

    let fresh = Fixture::new(&doc(now_s() + 9 * 86_400, testkit::RT_SENTINEL));
    assert_eq!(
        fresh.run(SendMode::Proactive, &client).step,
        RefreshStep::Adopted(AdoptReason::Fresh)
    );

    let mut disabled = Fixture::expired();
    disabled.record.kind = crate::config::codex::CodexKind::Owned {
        export_spelling: "/x".to_owned(),
        refresh: RefreshPolicy::Never,
    };
    assert_eq!(disabled.run(SendMode::Proactive, &client).step, RefreshStep::Disabled);

    let cancelled = Fixture::expired();
    let cancel = Cancel::new();
    cancel.cancel();
    let ctx = RefreshCtx {
        paths: &cancelled.paths,
        client: &client,
        deadline: Instant::now() + Duration::from_secs(60),
        lock_budget: LockBudget::Pass(PASS_LOCK_BUDGET),
        cancel: &cancel,
        fault: &Fault::none(),
    };
    assert_eq!(
        run(cancelled.owned(), SendMode::Proactive, &ctx).step,
        RefreshStep::Stale(StaleReason::Cancelled)
    );

    let busy = Fixture::expired();
    let _held = testkit::lock_for(&busy.paths, &busy.record);
    assert_eq!(busy.run(SendMode::Proactive, &client).step, RefreshStep::Busy);

    post.assert_calls(0);
}

#[test]
fn daemon_evidence_under_the_lock() {
    let server = MockServer::start();
    let post = mock(&server, 200, &grant_body(Some(NEW_RT)));
    let client = client(&server.url(TOKEN_PATH));

    let live = Fixture::expired();
    let daemon = live.ns_dir().join("app-server-daemon");
    fs::create_dir(&daemon).expect("mkdir");
    let me = std::process::id();
    fs::write(
        daemon.join("app-server.pid"),
        json!({"pid": me, "processStartTime": "x", "executableIdentity": {"digest": "x"}})
            .to_string(),
    )
    .expect("write");
    assert_eq!(live.run(SendMode::Proactive, &client).step, RefreshStep::SessionDetected(me));

    let unreadable = Fixture::expired();
    let daemon = unreadable.ns_dir().join("app-server-daemon");
    fs::create_dir(&daemon).expect("mkdir");
    fs::write(daemon.join("app-server.pid"), b"{\"pid\":").expect("a torn record");
    assert_eq!(
        unreadable.run(SendMode::Proactive, &client).step,
        RefreshStep::Stale(StaleReason::DaemonRecordUnreadable),
        "review S30 F8"
    );
    post.assert_calls(0);
}

#[test]
fn a_torn_file_is_stale_or_unknown_never_needs_login() {
    let server = MockServer::start();
    let post = mock(&server, 200, &grant_body(Some(NEW_RT)));
    let client = client(&server.url(TOKEN_PATH));

    let fixture = Fixture::expired();
    let sent = digest8(&fixture.auth());
    testkit::write_0600(&fixture.auth_path(), b"{\"auth_mode\": \"chatgpt\", \"tok");
    assert_eq!(
        fixture.run(SendMode::Proactive, &client).step,
        RefreshStep::Stale(StaleReason::Torn)
    );

    fixture.write_marker(&state_with_inflight(&sent, ago(60)));
    let step = fixture.run(SendMode::Proactive, &client).step;
    assert!(is_unknown(&step, UnknownClass::Interrupted), "{step:?}");
    post.assert_calls(0);
}

#[test]
fn the_server_floor_blocks_an_automatic_refresh_of_its_grant() {
    let fixture = Fixture::expired();
    let grant = digest8(&fixture.auth());
    let at = Timestamp::from_second(now_s() + 3_600).expect("time");
    fixture.write_marker(&RefreshState {
        earliest_refresh: Some(EarliestRefresh { grant_digest8: grant, at }),
        ..RefreshState::default()
    });
    let server = MockServer::start();
    let post = mock(&server, 200, &grant_body(Some(NEW_RT)));
    let client = client(&server.url(TOKEN_PATH));
    assert_eq!(fixture.run(SendMode::Proactive, &client).step, RefreshStep::NotBefore(at));
    post.assert_calls(0);

    // A floor recorded for another grant does not apply.
    fixture.write_marker(&RefreshState {
        earliest_refresh: Some(EarliestRefresh { grant_digest8: "00000000".to_owned(), at }),
        ..RefreshState::default()
    });
    assert_eq!(
        fixture.run(SendMode::Proactive, &client).step,
        RefreshStep::Refreshed { parked: false }
    );
    post.assert_calls(1);
}

// ---------------------------------------------------------------------------
// The marker (plan AC128)
// ---------------------------------------------------------------------------

#[test]
fn a_marker_left_by_a_dead_process_is_interrupted_and_blocks_the_send() {
    let fixture = Fixture::expired();
    let sent = digest8(&fixture.auth());
    let sent_at = ago(120);
    fixture.write_marker(&state_with_inflight(&sent, sent_at));
    let server = MockServer::start();
    let post = mock(&server, 200, &grant_body(Some(NEW_RT)));
    let client = client(&server.url(TOKEN_PATH));

    for _ in 0..3 {
        let report = fixture.run(SendMode::Proactive, &client);
        let RefreshStep::OutcomeUnknown { since, class, resend_eligible_at } = report.step else {
            panic!("expected unknown, got {report:?}");
        };
        assert_eq!((since, class), (sent_at, UnknownClass::Interrupted));
        assert_eq!(resend_eligible_at, sent_at.checked_add(SignedDuration::from_hours(1)).ok());
    }
    post.assert_calls(0);
    assert_eq!(fixture.outcomes(), [CodexOutcome::Ambiguous], "one interrupted line, not three");
    assert_eq!(fixture.audit()[0].class.as_deref(), Some("interrupted"));
    // `rm -rf cache/codex` changes nothing: the marker is not in the cache.
    let _ = fs::remove_dir_all(fixture.paths.cache_dir_for(crate::provider::Provider::Codex));
    assert!(matches!(
        fixture.run(SendMode::Proactive, &client).step,
        RefreshStep::OutcomeUnknown { .. }
    ));
    post.assert_calls(0);
}

#[test]
fn a_marker_for_another_grant_is_cleared_and_the_pass_proceeds() {
    let fixture = Fixture::expired();
    fixture.write_marker(&state_with_inflight("0badc0de", ago(60)));
    let server = MockServer::start();
    let post = mock(&server, 200, &grant_body(Some(NEW_RT)));
    let report = fixture.run(SendMode::Proactive, &client(&server.url(TOKEN_PATH)));
    assert_eq!(report.step, RefreshStep::Refreshed { parked: false }, "{report:?}");
    assert!(report.notes.contains(&RefreshNote::StaleMarkerCleared));
    post.assert_calls(1);
}

#[test]
fn an_unreadable_or_unwritable_marker_sends_nothing() {
    let server = MockServer::start();
    let post = mock(&server, 200, &grant_body(Some(NEW_RT)));
    let client = client(&server.url(TOKEN_PATH));

    let unreadable = Fixture::expired();
    unreadable.write_marker(&RefreshState::default());
    fs::set_permissions(unreadable.marker_path(), fs::Permissions::from_mode(0o000))
        .expect("chmod");
    let step = unreadable.run(SendMode::Proactive, &client).step;
    fs::set_permissions(unreadable.marker_path(), fs::Permissions::from_mode(0o600))
        .expect("chmod");
    assert!(matches!(step, RefreshStep::StateUnavailable(_)), "{step:?}");

    let unwritable = Fixture::expired();
    let state_dir = unwritable.paths.codex_state_dir();
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o500)).expect("chmod");
    let step = unwritable.run(SendMode::Proactive, &client).step;
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).expect("chmod");
    assert!(matches!(step, RefreshStep::StateUnavailable(_)), "{step:?}");

    post.assert_calls(0);
    assert_eq!(unwritable.ns_entries(), ["auth.json"], "the marker never lives in the namespace");
}

#[test]
fn deleting_the_state_directory_re_arms_one_send() {
    // Plan AC128 (9), risk R68: asserted so the residue stays visible.
    let fixture = Fixture::expired();
    fixture.write_marker(&state_with_inflight(&digest8(&fixture.auth()), ago(60)));
    fs::remove_dir_all(fixture.paths.codex_state_dir()).expect("rm -rf .state");
    let server = MockServer::start();
    let post = mock(&server, 503, &json!({}));
    let step = fixture.run(SendMode::Proactive, &client(&server.url(TOKEN_PATH))).step;
    assert!(is_unknown(&step, UnknownClass::ServerError), "{step:?}");
    post.assert_calls(1);
}

#[test]
fn a_concurrent_pass_waits_then_sends_nothing() {
    // Plan AC128 (5): A holds the lock through a delayed ambiguous answer.
    let fixture = Arc::new(Fixture::expired());
    let server = MockServer::start();
    let post = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(503).delay(Duration::from_millis(1_500)).body("{}");
    });
    let url = server.url(TOKEN_PATH);
    let a = {
        let fixture = Arc::clone(&fixture);
        let url = url.clone();
        thread::spawn(move || fixture.run(SendMode::Proactive, &client(&url)).step)
    };
    thread::sleep(Duration::from_millis(300));
    let cancel = Cancel::new();
    let b_client = client(&url);
    let ctx = RefreshCtx {
        paths: &fixture.paths,
        client: &b_client,
        deadline: Instant::now() + Duration::from_secs(60),
        lock_budget: LockBudget::Pass(Duration::from_millis(100)),
        cancel: &cancel,
        fault: &Fault::none(),
    };
    assert_eq!(run(fixture.owned(), SendMode::Proactive, &ctx).step, RefreshStep::Busy);
    let a = a.join().expect("pass A");
    assert!(is_unknown(&a, UnknownClass::ServerError), "{a:?}");
    let b = run(fixture.owned(), SendMode::Proactive, &ctx).step;
    assert!(is_unknown(&b, UnknownClass::ServerError), "{b:?}");
    post.assert_calls(1);
}

// ---------------------------------------------------------------------------
// Outcomes (plan AC92, AC123)
// ---------------------------------------------------------------------------

#[test]
fn unknown_outcomes_keep_the_marker_and_never_resend() {
    let tests: [UnknownCase; 4] = [
        ("503", 503, "{}", &[], UnknownClass::ServerError),
        ("429", 429, "{}", &[("retry-after", "864000")], UnknownClass::RateLimited),
        ("200 not json", 200, "<html>", &[], UnknownClass::Ambiguous),
        (
            "200 no access token",
            200,
            r#"{"refresh_token":"agctl-test-codex-rt-0009"}"#,
            &[],
            UnknownClass::Ambiguous,
        ),
    ];
    for (name, status, body, headers, class) in tests {
        let fixture = Fixture::expired();
        let before = fixture.auth();
        let server = MockServer::start();
        let post = server.mock(|when, then| {
            when.method(POST).path(TOKEN_PATH);
            let mut then = then.status(status).body(body);
            for (header, value) in headers {
                then = then.header(*header, *value);
            }
        });
        let client = client(&server.url(TOKEN_PATH));
        let step = fixture.run(SendMode::Proactive, &client).step;
        assert!(is_unknown(&step, class), "{name}: {step:?}");
        assert_eq!(fixture.auth(), before, "{name}: file unchanged");
        let marker = fixture.marker().expect("marker");
        assert!(
            marker.inflight.is_some() && marker.ambiguous_since.is_some(),
            "{name}: {marker:?}"
        );
        if class == UnknownClass::RateLimited {
            assert_eq!(marker.retry_after, Some(MAX_RETRY_AFTER), "{name}: retry-after clamped");
        }
        for _ in 0..3 {
            let later = fixture.run(SendMode::Proactive, &client).step;
            assert!(is_unknown(&later, class), "{name}: {later:?}");
        }
        post.assert_calls(1);
        assert_eq!(fixture.outcomes(), [CodexOutcome::Ambiguous], "{name}");
    }
}

#[test]
fn a_proven_pre_send_failure_clears_the_marker_and_the_next_pass_sends_once() {
    let fixture = Fixture::expired();
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().expect("addr").port()
    };
    let closed = client(&format!("http://127.0.0.1:{port}{TOKEN_PATH}"));
    let step = fixture.run(SendMode::Proactive, &closed).step;
    assert!(matches!(step, RefreshStep::Stale(StaleReason::PreSend(_))), "{step:?}");
    assert_eq!(fixture.marker().and_then(|marker| marker.inflight), None);

    let server = MockServer::start();
    let post = mock(&server, 200, &grant_body(Some(NEW_RT)));
    let step = fixture.run(SendMode::Proactive, &client(&server.url(TOKEN_PATH))).step;
    assert_eq!(step, RefreshStep::Refreshed { parked: false });
    post.assert_calls(1);
}

#[test]
fn a_rejected_answer_clears_the_marker() {
    let fixture = Fixture::expired();
    let server = MockServer::start();
    let post = mock(&server, 403, &json!({"error": "forbidden"}));
    let step = fixture.run(SendMode::Proactive, &client(&server.url(TOKEN_PATH))).step;
    assert_eq!(step, RefreshStep::Stale(StaleReason::Rejected(403)));
    assert_eq!(fixture.marker().and_then(|marker| marker.inflight), None);
    post.assert_calls(1);
}

#[test]
fn a_dead_grant_needs_login_and_is_never_sent_again() {
    let fixture = Fixture::expired();
    let before = fixture.auth();
    let server = MockServer::start();
    let post = mock(&server, 400, &json!({"error": "invalid_grant"}));
    let client = client(&server.url(TOKEN_PATH));
    assert_eq!(
        fixture.run(SendMode::Proactive, &client).step,
        RefreshStep::NeedsLogin(NeedsLoginReason::Dead)
    );
    for _ in 0..2 {
        assert_eq!(
            fixture.run(SendMode::Proactive, &client).step,
            RefreshStep::NeedsLogin(NeedsLoginReason::Dead)
        );
    }
    post.assert_calls(1);
    assert_eq!(fixture.auth(), before);
    let marker = fixture.marker().expect("marker");
    assert_eq!(marker.inflight, None);
    assert_eq!(marker.dead_digest8, Some(digest8(&before)));
    assert_eq!(fixture.outcomes(), [CodexOutcome::NeedsLogin]);
    assert_eq!(fixture.audit()[0].class.as_deref(), Some("invalid_grant"));
}

// ---------------------------------------------------------------------------
// External writers (plan AC124)
// ---------------------------------------------------------------------------

#[test]
fn a_permanent_answer_while_another_writer_rotated_adopts_its_grant() {
    // AC124 (a): the writer rewrites in place inside the delayed responder.
    let fixture = Fixture::expired();
    let auth = fixture.auth_path();
    let external = testkit::pretty(&doc(now_s() + 10 * 86_400, OTHER_RT));
    let written = external.clone();
    let (url, server) = responder(move || {
        fs::write(&auth, &written).expect("in-place rewrite");
        (400, json!({"error": {"code": "refresh_token_reused"}}).to_string())
    });
    let step = fixture.run(SendMode::Proactive, &client(&url)).step;
    server.join().expect("responder");
    assert_eq!(step, RefreshStep::RacedExternal);
    assert_eq!(fixture.auth(), external, "the other writer's grant is kept");
    assert_eq!(fixture.marker().and_then(|marker| marker.inflight), None);
    assert_eq!(fixture.outcomes(), [CodexOutcome::AdoptedExternal]);
}

#[test]
fn an_applied_answer_after_another_writer_rotated_is_discarded() {
    // AC124 (d).
    let fixture = Fixture::expired();
    let auth = fixture.auth_path();
    let external = testkit::pretty(&doc(now_s() + 10 * 86_400, OTHER_RT));
    let written = external.clone();
    let (url, server) = responder(move || {
        fs::write(&auth, &written).expect("in-place rewrite");
        (200, grant_body(Some(NEW_RT)).to_string())
    });
    let step = fixture.run(SendMode::Proactive, &client(&url)).step;
    server.join().expect("responder");
    assert_eq!(step, RefreshStep::DiscardedExternal);
    assert_eq!(fixture.auth(), external);
    assert_eq!(fixture.outcomes(), [CodexOutcome::DiscardedExternal]);
    assert_eq!(fixture.marker().and_then(|marker| marker.inflight), None);
}

#[test]
fn an_applied_answer_merges_onto_a_file_whose_grant_is_unchanged() {
    // AC124 (c): the other writer touched the file but not the grant.
    let fixture = Fixture::expired();
    let auth = fixture.auth_path();
    let (url, server) = responder(move || {
        let mut doc = doc(1_000, testkit::RT_SENTINEL);
        doc["agctl_test_member"] = json!("kept");
        testkit::write_0600(&auth, &testkit::pretty(&doc));
        (200, grant_body(Some(NEW_RT)).to_string())
    });
    let step = fixture.run(SendMode::Proactive, &client(&url)).step;
    server.join().expect("responder");
    assert_eq!(step, RefreshStep::Refreshed { parked: false });
    let after: Value = serde_json::from_slice(&fixture.auth()).expect("json");
    assert_eq!(after["agctl_test_member"], "kept", "merged onto the current document");
    assert_eq!(after["tokens"]["refresh_token"], NEW_RT);
    assert_eq!(fixture.outcomes(), [CodexOutcome::Applied]);
}

#[test]
fn a_file_removed_during_the_post_gets_the_rotated_grant_back() {
    // Review S30 INFO-2 (fact F94): a vanished file is not a newer grant.
    let fixture = Fixture::expired();
    let auth = fixture.auth_path();
    let (url, server) = responder(move || {
        fs::remove_file(&auth).expect("rm");
        (200, grant_body(Some(NEW_RT)).to_string())
    });
    let step = fixture.run(SendMode::Proactive, &client(&url)).step;
    server.join().expect("responder");
    assert_eq!(step, RefreshStep::Refreshed { parked: false });
    let after: Value = serde_json::from_slice(&fixture.auth()).expect("json");
    assert_eq!(after["tokens"]["refresh_token"], NEW_RT);
}

#[test]
fn a_file_changed_before_the_post_is_adopted_when_fresh() {
    // AC124 (b): the rewrite lands during the `codex_before_post_snapshot`
    // pause. With no resume file the pause lasts its whole budget, so the
    // writer has ten seconds to land.
    let fixture = Fixture::expired();
    let auth = fixture.auth_path();
    let writer = thread::spawn(move || {
        thread::sleep(Duration::from_millis(500));
        testkit::write_0600(&auth, &testkit::pretty(&doc(now_s() + 10 * 86_400, OTHER_RT)));
    });
    let server = MockServer::start();
    let post = mock(&server, 200, &grant_body(Some(NEW_RT)));
    let fault = Fault::from_list("pause_codex_before_post_snapshot");
    let step = fixture.run_with(SendMode::Proactive, &client(&server.url(TOKEN_PATH)), &fault).step;
    writer.join().expect("writer");
    assert_eq!(step, RefreshStep::Adopted(AdoptReason::ChangedBeforePost));
    post.assert_calls(0);
    assert_eq!(fixture.marker(), None, "no marker was written");
}

// ---------------------------------------------------------------------------
// After Applied: every write failure (review S30 LOW-1)
// ---------------------------------------------------------------------------

#[test]
fn a_failed_rename_parks_the_grant_and_the_next_pass_replays_it() {
    let fixture = Fixture::expired();
    let server = MockServer::start();
    let post = mock(&server, 200, &grant_body(Some(NEW_RT)));
    let client = client(&server.url(TOKEN_PATH));
    let step =
        fixture.run_with(SendMode::Proactive, &client, &Fault::from_list("codex_rename_fail")).step;
    assert_eq!(step, RefreshStep::Refreshed { parked: true });
    assert_eq!(fixture.marker().and_then(|marker| marker.inflight), None);

    let report = fixture.run(SendMode::Proactive, &client);
    assert_eq!(report.step, RefreshStep::Adopted(AdoptReason::Fresh), "{report:?}");
    assert!(report.notes.contains(&RefreshNote::PendingReplayed));
    post.assert_calls(1);
    assert_eq!(
        serde_json::from_slice::<Value>(&fixture.auth()).expect("json")["tokens"]["refresh_token"],
        NEW_RT
    );
    assert_eq!(fixture.outcomes(), [CodexOutcome::SavedToPending, CodexOutcome::PendingReplayed]);
}

#[test]
fn a_write_that_lands_and_reports_an_error_is_not_written_twice() {
    // Review S30 INFO-4: a second write of the same merge would be read as
    // another writer's grant and reported as a discard.
    let fixture = Fixture::expired();
    let server = MockServer::start();
    let post = mock(&server, 200, &grant_body(Some(NEW_RT)));
    let fault = Fault::from_list("codex_error_after_rename");
    let report = fixture.run_with(SendMode::Proactive, &client(&server.url(TOKEN_PATH)), &fault);
    assert_eq!(report.step, RefreshStep::Refreshed { parked: false }, "{report:?}");
    post.assert_calls(1);
    assert_eq!(
        serde_json::from_slice::<Value>(&fixture.auth()).expect("json")["tokens"]["refresh_token"],
        NEW_RT
    );
    assert_eq!(fixture.ns_entries(), ["auth.json"]);
    assert_eq!(fixture.outcomes(), [CodexOutcome::Applied]);
    assert_eq!(fixture.marker().and_then(|marker| marker.inflight), None);
}

#[test]
fn an_unreadable_file_after_the_post_parks_the_grant_and_blocks_the_next_send() {
    let fixture = Fixture::expired();
    let auth = fixture.auth_path();
    let (url, server) = responder(move || {
        fs::set_permissions(&auth, fs::Permissions::from_mode(0o000)).expect("chmod");
        (200, grant_body(Some(NEW_RT)).to_string())
    });
    let step = fixture.run(SendMode::Proactive, &client(&url)).step;
    server.join().expect("responder");
    assert_eq!(step, RefreshStep::Refreshed { parked: true });
    assert!(
        fixture.ns_entries().contains(&"auth.json.pending".to_owned()),
        "{:?}",
        fixture.ns_entries()
    );

    // While the pending grant cannot be resolved nothing is sent (INFO-1).
    let server = MockServer::start();
    let post = mock(&server, 200, &grant_body(Some(NEW_RT)));
    let client = client(&server.url(TOKEN_PATH));
    let step = fixture.run(SendMode::Proactive, &client).step;
    assert!(matches!(step, RefreshStep::Failed(_)), "{step:?}");
    post.assert_calls(0);

    fs::set_permissions(fixture.auth_path(), fs::Permissions::from_mode(0o600)).expect("chmod");
    assert_eq!(
        fixture.run(SendMode::Proactive, &client).step,
        RefreshStep::Adopted(AdoptReason::Fresh)
    );
    post.assert_calls(0);
}

#[test]
fn a_file_that_stays_torn_after_the_post_parks_the_grant() {
    let fixture = Fixture::expired();
    let auth = fixture.auth_path();
    let (url, server) = responder(move || {
        testkit::write_0600(&auth, b"{\"auth_mode\": \"chat");
        (200, grant_body(Some(NEW_RT)).to_string())
    });
    let step = fixture.run(SendMode::Proactive, &client(&url)).step;
    server.join().expect("responder");
    assert_eq!(step, RefreshStep::Refreshed { parked: true });
    assert_eq!(fixture.outcomes(), [CodexOutcome::SavedToPending]);
}

#[test]
fn when_nothing_can_be_written_the_outcome_is_unknown_and_the_marker_stays() {
    let fixture = Fixture::expired();
    let dir = fixture.ns_dir();
    let (url, server) = responder(move || {
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).expect("chmod");
        (200, grant_body(Some(NEW_RT)).to_string())
    });
    let step = fixture.run(SendMode::Proactive, &client(&url)).step;
    server.join().expect("responder");
    fs::set_permissions(fixture.ns_dir(), fs::Permissions::from_mode(0o700)).expect("chmod");
    assert!(is_unknown(&step, UnknownClass::WriteFailed), "{step:?}");
    let marker = fixture.marker().expect("marker");
    assert!(marker.inflight.is_some(), "no definite outcome: the marker stays");

    let server = MockServer::start();
    let post = mock(&server, 200, &grant_body(Some(NEW_RT)));
    let later = fixture.run(SendMode::Proactive, &client(&server.url(TOKEN_PATH))).step;
    assert!(is_unknown(&later, UnknownClass::WriteFailed), "{later:?}");
    post.assert_calls(0);
    let audit = fixture.audit();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].class.as_deref(), Some("write_failed"));
}

// ---------------------------------------------------------------------------
// The 401 path (plan AC114)
// ---------------------------------------------------------------------------

fn valid_fixture() -> (Fixture, String) {
    let fixture = Fixture::new(&doc(now_s() + 9 * 86_400, testkit::RT_SENTINEL));
    let rejected = access_digest8(&fixture.auth());
    (fixture, rejected)
}

fn after_401(rejected: &str) -> SendMode {
    SendMode::AfterUnauthorized { rejected_access_digest8: rejected.to_owned() }
}

#[test]
fn the_401_floor_counts_sent_refreshes_that_did_not_help() {
    let server = MockServer::start();
    let post = mock(&server, 200, &grant_body(Some(NEW_RT)));
    let client = client(&server.url(TOKEN_PATH));
    let cancel = Cancel::new();

    // Another writer refreshed: adopt, 0 POSTs.
    let (fixture, _) = valid_fixture();
    assert_eq!(
        fixture.run(after_401("0badc0de"), &client).step,
        RefreshStep::Adopted(AdoptReason::ExternalAccess)
    );
    // A still-valid row is never refreshed proactively.
    assert_eq!(
        fixture.run(SendMode::Proactive, &client).step,
        RefreshStep::Adopted(AdoptReason::Fresh)
    );

    // A send five minutes ago: the floor.
    let (fixture, rejected) = valid_fixture();
    fixture.write_marker(&RefreshState { last_sent_at: Some(ago(300)), ..RefreshState::default() });
    let step = fixture.run(after_401(&rejected), &client).step;
    assert!(matches!(step, RefreshStep::UnauthorizedFloor { .. }), "{step:?}");
    assert_eq!(
        fixture.marker().expect("marker").did_not_help,
        0,
        "a floor-blocked 401 is not counted"
    );
    post.assert_calls(0);

    // Sixty-one minutes ago: one POST, and a 401 after it counts.
    fixture.write_marker(&RefreshState {
        last_sent_at: Some(ago(61 * 60)),
        ..RefreshState::default()
    });
    assert_eq!(
        fixture.run(after_401(&rejected), &client).step,
        RefreshStep::Refreshed { parked: false }
    );
    post.assert_calls(1);
    let ctx = RefreshCtx {
        paths: &fixture.paths,
        client: &client,
        deadline: Instant::now() + Duration::from_secs(60),
        lock_budget: LockBudget::Pass(PASS_LOCK_BUDGET),
        cancel: &cancel,
        fault: &Fault::none(),
    };
    record_retry_get(fixture.owned(), RetryGet::Unauthorized, &ctx).expect("recorded");
    let marker = fixture.marker().expect("marker");
    assert_eq!((marker.did_not_help, marker.floor_min), (1, 120));
    // The immediate second 401 of the same pass: the floor, not a POST.
    let rejected = access_digest8(&fixture.auth());
    assert!(matches!(
        fixture.run(after_401(&rejected), &client).step,
        RefreshStep::UnauthorizedFloor { .. }
    ));
    post.assert_calls(1);

    record_retry_get(fixture.owned(), RetryGet::Unauthorized, &ctx).expect("recorded");
    assert_eq!(fixture.marker().expect("marker").floor_min, 240);
    record_retry_get(fixture.owned(), RetryGet::Unauthorized, &ctx).expect("recorded");
    let mut marker = fixture.marker().expect("marker");
    assert_eq!(marker.did_not_help, 3);
    marker.last_sent_at = Some(ago(86_400));
    fixture.write_marker(&marker);
    assert_eq!(fixture.run(after_401(&rejected), &client).step, RefreshStep::UnauthorizedTerminal);
    post.assert_calls(1);

    // A 2xx after a sent refresh resets the count and the floor.
    record_retry_get(fixture.owned(), RetryGet::Succeeded, &ctx).expect("recorded");
    let marker = fixture.marker().expect("marker");
    assert_eq!((marker.did_not_help, marker.floor_min), (0, 60));
}

#[test]
fn reset_floor_lifts_the_terminal_state_and_is_audited() {
    let (fixture, _) = valid_fixture();
    fixture.write_marker(&RefreshState {
        did_not_help: 3,
        floor_min: 240,
        ..RefreshState::default()
    });
    let guard = testkit::lock_for(&fixture.paths, &fixture.record);
    let ns = OwnedNamespace::open(&fixture.paths, fixture.owned(), &guard).expect("opens");
    let consent = ResetConsent::after_confirmation("yes", true, false).expect("consent");
    reset_floor(&fixture.paths, &ns, consent).expect("reset");
    let marker = fixture.marker().expect("marker");
    assert_eq!((marker.did_not_help, marker.floor_min), (0, 60));
    assert_eq!(fixture.outcomes(), [CodexOutcome::FloorReset]);
}

// ---------------------------------------------------------------------------
// --resend (decision D-035)
// ---------------------------------------------------------------------------

fn unknown_marker(fixture: &Fixture, since_ago: i64, class: UnknownClass) -> RefreshState {
    let since = ago(since_ago);
    let mut state = state_with_inflight(&digest8(&fixture.auth()), since);
    state.ambiguous_since = Some(since);
    state.class = Some(class);
    state
}

fn consent() -> SendMode {
    SendMode::Resend(ResendConsent::after_confirmation("yes", true, false).expect("consent"))
}

#[test]
fn resend_sends_once_per_marker_and_only_when_eligible() {
    let server = MockServer::start();
    let post = mock(&server, 503, &json!({}));
    let client = client(&server.url(TOKEN_PATH));

    let none = Fixture::expired();
    assert_eq!(
        none.run(consent(), &client).step,
        RefreshStep::ResendRefused(ResendBlock::NotUnknown)
    );

    let early = Fixture::expired();
    early.write_marker(&unknown_marker(&early, 600, UnknownClass::Ambiguous));
    assert!(matches!(
        early.run(consent(), &client).step,
        RefreshStep::ResendRefused(ResendBlock::TooEarly(_))
    ));

    let limited = Fixture::expired();
    let mut state = unknown_marker(&limited, 90 * 60, UnknownClass::RateLimited);
    state.retry_after = Some(Duration::from_secs(2 * 3600));
    limited.write_marker(&state);
    assert!(
        matches!(
            limited.run(consent(), &client).step,
            RefreshStep::ResendRefused(ResendBlock::TooEarly(_))
        ),
        "max(retry-after, 1 h)"
    );

    let stray = Fixture::expired();
    stray.write_marker(&unknown_marker(&stray, 7200, UnknownClass::Ambiguous));
    testkit::write_0600(&stray.ns_dir().join("auth.json.tmp.0123abcd"), b"{}");
    assert_eq!(
        stray.run(consent(), &client).step,
        RefreshStep::ResendRefused(ResendBlock::StrayTmp)
    );
    post.assert_calls(0);

    let eligible = Fixture::expired();
    eligible.write_marker(&unknown_marker(&eligible, 7200, UnknownClass::Ambiguous));
    let step = eligible.run(consent(), &client).step;
    assert!(is_unknown(&step, UnknownClass::ServerError), "{step:?}");
    post.assert_calls(1);
    let marker = eligible.marker().expect("marker");
    assert!(marker.resent, "resent recorded in the same write as the send");
    assert!(matches!(step, RefreshStep::OutcomeUnknown { resend_eligible_at: None, .. }));
    assert_eq!(
        eligible.run(consent(), &client).step,
        RefreshStep::ResendRefused(ResendBlock::AlreadyResent)
    );
    // And no automatic send either.
    assert!(matches!(
        eligible.run(SendMode::Proactive, &client).step,
        RefreshStep::OutcomeUnknown { .. }
    ));
    post.assert_calls(1);
    assert_eq!(eligible.outcomes(), [CodexOutcome::Resend, CodexOutcome::Ambiguous]);
}

// ---------------------------------------------------------------------------
// A process that dies (plan AC128 (1), (2), (8)): a re-executed copy of this
// test binary runs one pass and dies at the named point.
// ---------------------------------------------------------------------------

/// The child's half. Inert unless the parent set its environment.
#[test]
#[ignore = "run only as a child process by the tests below"]
fn child_pass() {
    let (Some(config), Some(url)) =
        (std::env::var_os(CHILD_CONFIG_ENV), std::env::var(CHILD_URL_ENV).ok())
    else {
        return;
    };
    let paths = Paths::with_config_dir(PathBuf::from(config));
    let record = testkit::owned_record(testkit::USER, testkit::ACCT);
    let fault = Fault::from_list(&std::env::var(CHILD_FAULT_ENV).unwrap_or_default());
    let cancel = Cancel::new();
    let client = client(&url);
    let ctx = RefreshCtx {
        paths: &paths,
        client: &client,
        deadline: Instant::now() + Duration::from_secs(60),
        lock_budget: LockBudget::Pass(PASS_LOCK_BUDGET),
        cancel: &cancel,
        fault: &fault,
    };
    let owned = proof::owned(&record).expect("owned");
    let _ = run(owned, SendMode::Proactive, &ctx);
}

fn spawn_child(fixture: &Fixture, url: &str, fault: &str) -> std::process::Child {
    Command::new(std::env::current_exe().expect("the test binary"))
        .args([
            "--exact",
            "provider::codex::refresh::tests::child_pass",
            "--include-ignored",
            "--nocapture",
        ])
        .env(CHILD_CONFIG_ENV, fixture.paths.config_dir())
        .env(CHILD_URL_ENV, url)
        .env(CHILD_FAULT_ENV, fault)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the child pass")
}

#[test]
fn an_abort_after_the_marker_leaves_a_send_the_next_pass_will_not_repeat() {
    let fixture = Fixture::expired();
    let server = MockServer::start();
    let post = mock(&server, 200, &grant_body(Some(NEW_RT)));
    let url = server.url(TOKEN_PATH);
    let status = spawn_child(&fixture, &url, "codex_abort_after_marker").wait().expect("wait");
    assert_eq!(status.signal(), Some(libc::SIGABRT), "{status:?}");
    post.assert_calls(0);
    assert!(fixture.marker().and_then(|marker| marker.inflight).is_some(), "the marker is durable");

    let step = fixture.run(SendMode::Proactive, &client(&url)).step;
    assert!(is_unknown(&step, UnknownClass::Interrupted), "{step:?}");
    post.assert_calls(0);
}

#[test]
fn a_sigkill_during_the_post_leaves_a_send_the_next_pass_will_not_repeat() {
    let fixture = Fixture::expired();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let url =
        format!("http://127.0.0.1:{}{TOKEN_PATH}", listener.local_addr().expect("addr").port());
    let hold = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let _ = read_request(&mut stream);
        thread::sleep(Duration::from_secs(5));
    });
    let mut child = spawn_child(&fixture, &url, "");
    let started = Instant::now();
    while fixture.marker().and_then(|marker| marker.inflight).is_none() {
        assert!(started.elapsed() < Duration::from_secs(10), "the child never recorded its send");
        thread::sleep(Duration::from_millis(20));
    }
    thread::sleep(Duration::from_millis(200));
    child.kill().expect("SIGKILL");
    let status = child.wait().expect("wait");
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    hold.join().expect("listener");

    let server = MockServer::start();
    let post = mock(&server, 200, &grant_body(Some(NEW_RT)));
    let step = fixture.run(SendMode::Proactive, &client(&server.url(TOKEN_PATH))).step;
    assert!(is_unknown(&step, UnknownClass::Interrupted), "{step:?}");
    post.assert_calls(0);
}

#[test]
fn an_abort_between_the_parked_grant_and_the_marker_clear_is_recovered_pending_first() {
    let fixture = Fixture::expired();
    let server = MockServer::start();
    let post = mock(&server, 200, &grant_body(Some(NEW_RT)));
    let url = server.url(TOKEN_PATH);
    let status = spawn_child(&fixture, &url, "codex_rename_fail,codex_abort_after_pending")
        .wait()
        .expect("wait");
    assert_eq!(status.signal(), Some(libc::SIGABRT), "{status:?}");
    post.assert_calls(1);
    assert!(fixture.marker().and_then(|marker| marker.inflight).is_some());

    let report = fixture.run(SendMode::Proactive, &client(&url));
    assert_eq!(report.step, RefreshStep::Adopted(AdoptReason::Fresh), "{report:?}");
    assert!(report.notes.contains(&RefreshNote::PendingReplayed));
    assert!(report.notes.contains(&RefreshNote::StaleMarkerCleared));
    assert_eq!(fixture.marker().and_then(|marker| marker.inflight), None);
    post.assert_calls(1);
}

// ---------------------------------------------------------------------------
// A --resend that gets no answer about the grant (review S32-C2 F1, D26)
// ---------------------------------------------------------------------------

fn closed_port_client() -> RefreshClient {
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().expect("addr").port()
    };
    client(&format!("http://127.0.0.1:{port}{TOKEN_PATH}"))
}

#[test]
fn a_resend_that_never_left_restores_the_unknown_marker_and_arms_nothing() {
    let fixture = Fixture::expired();
    let before = unknown_marker(&fixture, 7200, UnknownClass::Ambiguous);
    fixture.write_marker(&before);

    let step = fixture.run(consent(), &closed_port_client()).step;
    assert!(is_unknown(&step, UnknownClass::Ambiguous), "{step:?}");
    assert!(
        matches!(step, RefreshStep::OutcomeUnknown { resend_eligible_at: Some(_), .. }),
        "the re-send was not spent: {step:?}"
    );
    let marker = fixture.marker().expect("marker");
    assert!(marker.inflight.is_some(), "the unknown marker stays");
    assert_eq!((marker.class, marker.resent), (Some(UnknownClass::Ambiguous), false));
    assert_eq!(marker.ambiguous_since, before.ambiguous_since);

    // The next automatic pass sends nothing.
    let server = MockServer::start();
    let post = mock(&server, 200, &grant_body(Some(NEW_RT)));
    let client = client(&server.url(TOKEN_PATH));
    for _ in 0..2 {
        let later = fixture.run(SendMode::Proactive, &client).step;
        assert!(is_unknown(&later, UnknownClass::Ambiguous), "{later:?}");
    }
    post.assert_calls(0);
}

#[test]
fn a_rejected_resend_spends_the_resend_and_arms_nothing() {
    let fixture = Fixture::expired();
    fixture.write_marker(&unknown_marker(&fixture, 7200, UnknownClass::ServerError));
    let server = MockServer::start();
    let post = mock(&server, 403, &json!({"error": "forbidden"}));
    let client = client(&server.url(TOKEN_PATH));

    let step = fixture.run(consent(), &client).step;
    assert_eq!(step, RefreshStep::NeedsLogin(NeedsLoginReason::ResendRejected(403)));
    post.assert_calls(1);
    let marker = fixture.marker().expect("marker");
    assert!(marker.inflight.is_some(), "the unknown marker stays");
    assert_eq!((marker.class, marker.resent), (Some(UnknownClass::ServerError), true));

    let later = fixture.run(SendMode::Proactive, &client).step;
    assert!(
        matches!(later, RefreshStep::OutcomeUnknown { resend_eligible_at: None, .. }),
        "{later:?}"
    );
    assert_eq!(
        fixture.run(consent(), &client).step,
        RefreshStep::ResendRefused(ResendBlock::AlreadyResent)
    );
    post.assert_calls(1);
}

#[test]
fn a_resend_is_stopped_by_daemon_evidence() {
    // Review S32-C2 F2: deviation D25 pinned.
    let server = MockServer::start();
    let post = mock(&server, 200, &grant_body(Some(NEW_RT)));
    let client = client(&server.url(TOKEN_PATH));

    let live = Fixture::expired();
    let marker = unknown_marker(&live, 7200, UnknownClass::Ambiguous);
    live.write_marker(&marker);
    let daemon = live.ns_dir().join("app-server-daemon");
    fs::create_dir(&daemon).expect("mkdir");
    let me = std::process::id();
    fs::write(
        daemon.join("app-server.pid"),
        json!({"pid": me, "processStartTime": "x", "executableIdentity": {"digest": "x"}})
            .to_string(),
    )
    .expect("write");
    assert_eq!(live.run(consent(), &client).step, RefreshStep::SessionDetected(me));
    assert_eq!(live.marker(), Some(marker.clone()), "nothing written");

    let torn = Fixture::expired();
    let marker = unknown_marker(&torn, 7200, UnknownClass::Ambiguous);
    torn.write_marker(&marker);
    let daemon = torn.ns_dir().join("app-server-daemon");
    fs::create_dir(&daemon).expect("mkdir");
    fs::write(daemon.join("app-server.pid"), b"{\"pid\":").expect("a torn record");
    assert_eq!(
        torn.run(consent(), &client).step,
        RefreshStep::Stale(StaleReason::DaemonRecordUnreadable)
    );
    assert_eq!(torn.marker(), Some(marker), "nothing written");

    post.assert_calls(0);
}
