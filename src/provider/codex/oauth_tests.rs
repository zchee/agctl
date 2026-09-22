use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use flate2::Compression;
use flate2::write::GzEncoder;
use httpmock::Method::POST;
use httpmock::MockServer;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::PrivatePkcs8KeyDer;
use serde_json::json;

use super::*;
use crate::config::paths::Paths;
use crate::provider::codex::auth_store::NamespaceRead;
use crate::provider::codex::auth_store::OwnedNamespace;
use crate::provider::codex::proof;
use crate::provider::codex::testkit;
use crate::provider::codex::testkit::record_header_names;

const TOKEN_PATH: &str = "/oauth/token";

/// A token response in the shape fact F80 observed, extra members included.
fn f80_body() -> serde_json::Value {
    json!({
        "access_token": testkit::access_token(Some(4_102_444_800)),
        "token_type": "Bearer",
        "expires_in": 864_000,
        "scope": "openid profile email offline_access",
        "id_token": testkit::id_token(&testkit::IdClaims::default()),
        "earliest_refresh_at": 1_790_417_597_i64,
        "refresh_token": "agctl-test-codex-rt-0002",
        "oai_is": "agctl-test-codex-ak-opaque-member",
    })
}

/// An owned namespace holding an expired credential, locked.
struct Namespace {
    _dir: tempfile::TempDir,
    paths: Paths,
    record: crate::config::codex::CodexAccountRecord,
}

impl Namespace {
    fn new() -> Self {
        let (dir, paths) = testkit::store();
        let record = testkit::owned_record(testkit::USER, testkit::ACCT);
        let auth = paths
            .codex_namespace_dir(testkit::USER, testkit::ACCT)
            .expect("valid ids")
            .join("auth.json");
        testkit::write_0600(
            &auth,
            &testkit::pretty(&testkit::chatgpt_doc(Some(1_000), Some("2026-09-06T21:40:50Z"))),
        );
        Self { _dir: dir, paths, record }
    }

    fn auth_path(&self) -> PathBuf {
        self.paths
            .codex_namespace_dir(testkit::USER, testkit::ACCT)
            .expect("valid ids")
            .join("auth.json")
    }

    /// Locks, reads, records the send, and sends once.
    fn send(&self, client: &RefreshClient, cancel: &Cancel) -> RefreshOutcome {
        let guard = testkit::lock_for(&self.paths, &self.record);
        let owned = proof::owned(&self.record).expect("an owned record");
        let ns = OwnedNamespace::open(&self.paths, owned, &guard).expect("opens");
        let credentials = match ns.read().expect("reads") {
            NamespaceRead::Credentials(credentials) => *credentials,
            other => panic!("expected credentials, got {other:?}"),
        };
        let token = ns.refresh_state().write_inflight(&credentials).expect("the marker is written");
        refresh(&credentials, token, client, cancel)
    }
}

fn client_for(url: &str) -> RefreshClient {
    RefreshClient::new(url, "agctl/test")
}

fn mock_client(server: &MockServer) -> RefreshClient {
    client_for(&server.url(TOKEN_PATH))
}

fn assert_ambiguous(outcome: &RefreshOutcome, class: AmbiguousClass) {
    assert!(
        matches!(outcome, RefreshOutcome::Ambiguous(found) if *found == class),
        "expected Ambiguous({class:?}), got {outcome:?}"
    );
}

fn assert_pre_send(outcome: &RefreshOutcome) {
    assert!(matches!(outcome, RefreshOutcome::PreSend(_)), "expected PreSend, got {outcome:?}");
}

// ---------------------------------------------------------------------------
// The agent (decision D-035's budget table, plan AC91 (b))
// ---------------------------------------------------------------------------

#[test]
fn the_agent_bounds_each_phase_and_nothing_else() {
    let agent = refresh_agent("agctl/test");
    let config = agent.config();
    let timeouts = config.timeouts();
    assert_eq!(
        [
            timeouts.resolve,
            timeouts.connect,
            timeouts.send_request,
            timeouts.send_body,
            timeouts.recv_response,
            timeouts.recv_body,
        ],
        PHASE_TIMEOUTS.map(Some),
        "the six phases are the budget table's"
    );
    assert_eq!(timeouts.global, None, "no whole-request budget");
    assert_eq!(timeouts.per_call, None, "no per-call budget");
    assert_eq!(
        timeouts.await_100,
        ureq::config::Config::default().timeouts().await_100,
        "await_100 stays at ureq's default"
    );
    assert!(!config.http_status_as_error(), "statuses are responses");
    assert_eq!(config.max_redirects(), 0, "redirects are not followed");
}

#[test]
fn the_six_phases_sum_to_nineteen_seconds() {
    let sum = PHASE_TIMEOUTS.iter().try_fold(Duration::ZERO, |sum, phase| sum.checked_add(*phase));
    assert_eq!(sum, Some(Duration::from_secs(19)));
}

// ---------------------------------------------------------------------------
// Applied (plan AC91 (a))
// ---------------------------------------------------------------------------

#[test]
fn one_post_carries_f65s_json_body_and_is_applied() {
    let server = MockServer::start();
    let names = Arc::new(Mutex::new(Vec::new()));
    let mock = server.mock(|when, then| {
        when.method(POST)
            .path(TOKEN_PATH)
            .header("content-type", "application/json")
            .header("user-agent", "agctl/test")
            .json_body(json!({
                "client_id": CLIENT_ID,
                "grant_type": "refresh_token",
                "refresh_token": testkit::RT_SENTINEL,
            }))
            .is_true(record_header_names(Arc::clone(&names)));
        then.status(200)
            .header("content-type", "application/json")
            .header("set-cookie", "__cf_bm=agctl-test-cookie; Path=/; HttpOnly")
            .json_body(f80_body());
    });
    let namespace = Namespace::new();
    let client = mock_client(&server);

    let outcome = namespace.send(&client, &Cancel::new());
    let RefreshOutcome::Applied(response) = outcome else {
        panic!("expected Applied, got {outcome:?}")
    };
    assert!(response.has_access_token());
    assert_eq!(response.earliest_refresh_at(), Timestamp::from_second(1_790_417_597).ok());
    mock.assert_calls(1);

    let rendered = format!("{response:?}");
    testkit::assert_no_needles(&rendered, "an applied response's Debug");
    assert!(!rendered.contains("oai_is") && !rendered.contains("opaque"), "{rendered}");

    let recorded = names.lock().expect("the header record is not poisoned");
    assert!(
        recorded.iter().all(|request| !request.iter().any(|name| name == "originator")),
        "no Codex identifying header (fact F93): {recorded:?}"
    );
}

#[test]
fn a_set_cookie_from_the_token_host_is_never_sent_back() {
    let server = MockServer::start();
    let names = Arc::new(Mutex::new(Vec::new()));
    let mock = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH).is_true(record_header_names(Arc::clone(&names)));
        then.status(200)
            .header("set-cookie", "__cf_bm=agctl-test-cookie; Path=/; HttpOnly")
            .json_body(f80_body());
    });
    let namespace = Namespace::new();
    let client = mock_client(&server);

    for _ in 0..2 {
        // A second namespace pass on the same client: the marker is cleared by
        // hand here, which only a test inside provider::codex can do.
        let outcome = namespace.send(&client, &Cancel::new());
        assert!(matches!(outcome, RefreshOutcome::Applied(_)), "{outcome:?}");
        let guard = testkit::lock_for(&namespace.paths, &namespace.record);
        let owned = proof::owned(&namespace.record).expect("owned");
        let ns = OwnedNamespace::open(&namespace.paths, owned, &guard).expect("opens");
        ns.refresh_state()
            .clear_inflight(crate::provider::codex::auth_store::DefiniteOutcome::Applied)
            .expect("clears");
    }

    mock.assert_calls(2);
    let recorded = names.lock().expect("the header record is not poisoned");
    assert!(
        recorded.iter().all(|request| !request.iter().any(|name| name == "cookie")),
        "a request carried a cookie: {recorded:?}"
    );
}

// ---------------------------------------------------------------------------
// Received responses (plan AC92, AC123)
// ---------------------------------------------------------------------------

/// One POST against a mock answering `status` with `body` and `headers`.
fn answered(status: u16, body: &str, headers: &[(&str, &str)]) -> RefreshOutcome {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        let mut then = then.status(status).body(body);
        for (name, value) in headers {
            then = then.header(*name, *value);
        }
    });
    let outcome = Namespace::new().send(&mock_client(&server), &Cancel::new());
    mock.assert_calls(1);
    outcome
}

#[test]
fn permanent_answers() {
    let tests: [(&str, u16, &str, PermanentClass); 7] = [
        ("401", 401, "{}", PermanentClass::Unauthorized),
        ("400 invalid_grant", 400, r#"{"error":"invalid_grant"}"#, PermanentClass::InvalidGrant),
        ("400 INVALID_GRANT", 400, r#"{"error":"INVALID_GRANT"}"#, PermanentClass::InvalidGrant),
        (
            "error.code reused",
            400,
            r#"{"error":{"code":"refresh_token_reused"}}"#,
            PermanentClass::Reused,
        ),
        (
            "error string expired",
            401,
            r#"{"error":"refresh_token_expired"}"#,
            PermanentClass::Expired,
        ),
        (
            "top-level code",
            403,
            r#"{"code":"refresh_token_invalidated"}"#,
            PermanentClass::Invalidated,
        ),
        (
            "a code on a 429 is still permanent",
            429,
            r#"{"error":{"code":"refresh_token_reused"}}"#,
            PermanentClass::Reused,
        ),
    ];
    for (name, status, body, class) in tests {
        let outcome = answered(status, body, &[]);
        assert!(
            matches!(outcome, RefreshOutcome::Permanent(found) if found == class),
            "{name}: expected Permanent({class:?}), got {outcome:?}"
        );
    }
}

#[test]
fn rejected_rate_limited_and_server_error() {
    let rejected = answered(400, r#"{"error":"invalid_request"}"#, &[]);
    assert!(matches!(rejected, RefreshOutcome::Rejected(400)), "{rejected:?}");
    let forbidden = answered(403, "forbidden", &[]);
    assert!(matches!(forbidden, RefreshOutcome::Rejected(403)), "{forbidden:?}");

    let limited = answered(429, "{}", &[("retry-after", "120")]);
    assert!(
        matches!(limited, RefreshOutcome::RateLimited { retry_after: Some(d) } if d == Duration::from_secs(120)),
        "{limited:?}"
    );
    let limited_bare = answered(429, "{}", &[]);
    assert!(
        matches!(limited_bare, RefreshOutcome::RateLimited { retry_after: None }),
        "{limited_bare:?}"
    );

    let unavailable = answered(503, "busy", &[]);
    assert!(matches!(unavailable, RefreshOutcome::ServerError(503)), "{unavailable:?}");
}

#[test]
fn a_2xx_that_is_not_a_grant_is_ambiguous_never_a_received_class() {
    assert_ambiguous(&answered(200, "<html>not json</html>", &[]), AmbiguousClass::ServerBody);
    assert_ambiguous(&answered(200, "", &[]), AmbiguousClass::ServerBody);
    assert_ambiguous(
        &answered(200, r#"{"refresh_token":"agctl-test-codex-rt-0003","id_token":null}"#, &[]),
        AmbiguousClass::ServerBody,
    );
    assert_ambiguous(&answered(200, r#"{"access_token":42}"#, &[]), AmbiguousClass::ServerBody);
    assert_ambiguous(&answered(201, r#"["access_token"]"#, &[]), AmbiguousClass::ServerBody);
}

#[test]
fn an_oversized_or_gzip_expanded_2xx_body_is_ambiguous() {
    let big = format!(r#"{{"access_token":"{}"}}"#, "a".repeat(512 * 1024));
    assert_ambiguous(&answered(200, &big, &[]), AmbiguousClass::ServerBody);

    let server = MockServer::start();
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    let document = format!(r#"{{"access_token":"x","pad":"{}"}}"#, " ".repeat(4 * 1024 * 1024));
    encoder.write_all(document.as_bytes()).expect("gzip into memory");
    let compressed = encoder.finish().expect("gzip finishes");
    assert!(compressed.len() < 64 * 1024, "the wire body is small: {}", compressed.len());
    let mock = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(200).header("content-encoding", "gzip").body(compressed.clone());
    });
    let outcome = Namespace::new().send(&mock_client(&server), &Cancel::new());
    mock.assert_calls(1);
    assert_ambiguous(&outcome, AmbiguousClass::ServerBody);
}

#[test]
fn a_redirect_is_not_followed_and_is_ambiguous() {
    let server = MockServer::start();
    let target = server.mock(|when, then| {
        when.method(POST).path("/elsewhere");
        then.status(200).json_body(f80_body());
    });
    let redirect = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(307).header("location", server.url("/elsewhere"));
    });
    let outcome = Namespace::new().send(&mock_client(&server), &Cancel::new());
    redirect.assert_calls(1);
    target.assert_calls(0);
    assert_ambiguous(&outcome, AmbiguousClass::ServerBody);
}

// ---------------------------------------------------------------------------
// Refused before the send
// ---------------------------------------------------------------------------

#[test]
fn a_cancel_seen_before_the_send_sends_nothing() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(200).json_body(f80_body());
    });
    let cancel = Cancel::new();
    cancel.cancel();
    let outcome = Namespace::new().send(&mock_client(&server), &cancel);
    assert_pre_send(&outcome);
    mock.assert_calls(0);
}

#[test]
fn a_token_for_another_grant_sends_nothing() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(200).json_body(f80_body());
    });
    let namespace = Namespace::new();
    let guard = testkit::lock_for(&namespace.paths, &namespace.record);
    let owned = proof::owned(&namespace.record).expect("owned");
    let ns = OwnedNamespace::open(&namespace.paths, owned, &guard).expect("opens");
    let NamespaceRead::Credentials(first) = ns.read().expect("reads") else {
        panic!("credentials")
    };
    let token = ns.refresh_state().write_inflight(&first).expect("marker");

    let mut doc = testkit::chatgpt_doc(Some(1_000), None);
    doc["tokens"]["refresh_token"] = json!("agctl-test-codex-rt-other");
    testkit::write_0600(&namespace.auth_path(), &testkit::pretty(&doc));
    let NamespaceRead::Credentials(second) = ns.read().expect("reads") else {
        panic!("credentials")
    };

    let outcome = refresh(&second, token, &mock_client(&server), &Cancel::new());
    assert_pre_send(&outcome);
    mock.assert_calls(0);
}

// ---------------------------------------------------------------------------
// Real transports (plan AC92's class-table test from real ureq calls)
// ---------------------------------------------------------------------------

/// A loopback port nothing listens on.
fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    port
}

#[test]
fn a_closed_loopback_port_is_proven_pre_send() {
    let url = format!("http://127.0.0.1:{}{TOKEN_PATH}", closed_port());
    let outcome = Namespace::new().send(&client_for(&url), &Cancel::new());
    assert_pre_send(&outcome);
}

/// Reads one HTTP request with a `content-length` body; returns the body.
fn read_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let read = stream.read(&mut chunk).expect("read the request");
        assert!(read > 0, "the client closed before sending a whole request");
        buffer.extend_from_slice(&chunk[..read]);
        let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") else { continue };
        let head = String::from_utf8_lossy(&buffer[..end]).to_ascii_lowercase();
        let length: usize = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .and_then(|value| value.trim().parse().ok())
            .expect("a content-length header");
        let body_start = end + 4;
        while buffer.len() < body_start + length {
            let read = stream.read(&mut chunk).expect("read the body");
            assert!(read > 0, "the client closed mid-body");
            buffer.extend_from_slice(&chunk[..read]);
        }
        return buffer[body_start..body_start + length].to_vec();
    }
}

/// Makes the next close send a TCP reset instead of a FIN.
fn reset_on_close(stream: &TcpStream) {
    let linger = libc::linger { l_onoff: 1, l_linger: 0 };
    let size = libc::socklen_t::try_from(std::mem::size_of::<libc::linger>()).expect("fits");
    // SAFETY: `stream`'s descriptor is open for the duration of the call, and
    // `linger` is a valid `struct linger` whose size is passed alongside it.
    let status = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            std::ptr::from_ref(&linger).cast(),
            size,
        )
    };
    assert_eq!(status, 0, "SO_LINGER");
}

#[test]
fn a_listener_that_resets_after_reading_the_body_is_ambiguous() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let body = read_request(&mut stream);
        reset_on_close(&stream);
        drop(stream);
        body
    });
    let url = format!("http://127.0.0.1:{port}{TOKEN_PATH}");
    let outcome = Namespace::new().send(&client_for(&url), &Cancel::new());
    let body = server.join().expect("the listener thread");
    let sent: serde_json::Value = serde_json::from_slice(&body).expect("the body was JSON");
    assert_eq!(sent["grant_type"], "refresh_token", "the whole body reached the listener");
    assert_ambiguous(&outcome, AmbiguousClass::Transport);
}

#[test]
fn a_response_that_never_comes_is_ambiguous() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let _ = read_request(&mut stream);
        thread::sleep(Duration::from_millis(1_500));
    });
    let short = Duration::from_millis(300);
    let client = RefreshClient {
        token_url: format!("http://127.0.0.1:{port}{TOKEN_PATH}"),
        agent: agent_with("agctl/test", [short, short, short, short, short, short]),
    };
    let outcome = Namespace::new().send(&client, &Cancel::new());
    server.join().expect("the listener thread");
    assert_ambiguous(&outcome, AmbiguousClass::Transport);
}

#[test]
fn a_tls_handshake_failure_is_ambiguous_tls_never_pre_send() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut hello = [0_u8; 1024];
        let read = stream.read(&mut hello).expect("the ClientHello");
        assert!(read > 5 && hello[0] == 0x16, "a TLS handshake record arrived");
        // A plaintext fatal `handshake_failure` alert: type 21, TLS 1.2
        // record version, length 2, level fatal (2), description 40.
        stream.write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]).expect("the alert");
    });
    let url = format!("https://127.0.0.1:{port}{TOKEN_PATH}");
    let outcome = Namespace::new().send(&client_for(&url), &Cancel::new());
    server.join().expect("the listener thread");
    assert_ambiguous(&outcome, AmbiguousClass::Tls);
}

#[test]
fn a_self_signed_tls_listener_is_ambiguous_tls() {
    // Generated per run: no key material lives in the repository (review
    // S32-C1 F1).
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).expect("a test cert");
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("protocol versions")
    .with_no_client_auth()
    .with_single_cert(vec![cert.der().clone()], key)
    .expect("a server config");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut connection =
            rustls::ServerConnection::new(Arc::new(config)).expect("a server connection");
        // The client refuses the certificate; the server's side of that is an
        // error here, and the test is about the client's.
        let _ = connection.complete_io(&mut stream);
    });
    let url = format!("https://127.0.0.1:{port}{TOKEN_PATH}");
    let outcome = Namespace::new().send(&client_for(&url), &Cancel::new());
    server.join().expect("the listener thread");
    assert_ambiguous(&outcome, AmbiguousClass::Tls);
}

// ---------------------------------------------------------------------------
// The table itself, one row per variant (built where a real call cannot be
// made without the network)
// ---------------------------------------------------------------------------

#[test]
fn the_transport_table() {
    use ureq::Error;
    use ureq::Timeout;

    let io = |kind| Error::Io(std::io::Error::from(kind));
    let tests: Vec<(&str, Error, Option<AmbiguousClass>)> = vec![
        ("host not found", Error::HostNotFound, None),
        ("refused", io(std::io::ErrorKind::ConnectionRefused), None),
        ("resolve timeout", Error::Timeout(Timeout::Resolve), None),
        ("connect timeout", Error::Timeout(Timeout::Connect), None),
        ("tls configuration", Error::Tls("Rustls invalid dns name error"), None),
        ("connection failed", Error::ConnectionFailed, None),
        ("reset", io(std::io::ErrorKind::ConnectionReset), Some(AmbiguousClass::Transport)),
        ("broken pipe", io(std::io::ErrorKind::BrokenPipe), Some(AmbiguousClass::Transport)),
        ("eof", io(std::io::ErrorKind::UnexpectedEof), Some(AmbiguousClass::Transport)),
        ("invalid data", io(std::io::ErrorKind::InvalidData), Some(AmbiguousClass::Transport)),
        ("unreachable", io(std::io::ErrorKind::HostUnreachable), Some(AmbiguousClass::Transport)),
        ("send request", Error::Timeout(Timeout::SendRequest), Some(AmbiguousClass::Transport)),
        ("send body", Error::Timeout(Timeout::SendBody), Some(AmbiguousClass::Transport)),
        ("await 100", Error::Timeout(Timeout::Await100), Some(AmbiguousClass::Transport)),
        ("recv response", Error::Timeout(Timeout::RecvResponse), Some(AmbiguousClass::Transport)),
        ("recv body", Error::Timeout(Timeout::RecvBody), Some(AmbiguousClass::Transport)),
        ("global", Error::Timeout(Timeout::Global), Some(AmbiguousClass::Transport)),
        ("per call", Error::Timeout(Timeout::PerCall), Some(AmbiguousClass::Transport)),
        ("body limit", Error::BodyExceedsLimit(1), Some(AmbiguousClass::Transport)),
        ("large header", Error::LargeResponseHeader(1, 1), Some(AmbiguousClass::Transport)),
        ("proxy", Error::ConnectProxyFailed("x".to_owned()), Some(AmbiguousClass::Transport)),
        ("status as error", Error::StatusCode(500), Some(AmbiguousClass::Transport)),
        ("too many redirects", Error::TooManyRedirects, Some(AmbiguousClass::Transport)),
        ("bad uri (wildcard)", Error::BadUri("x".to_owned()), Some(AmbiguousClass::Transport)),
        ("body stalled", Error::BodyStalled, Some(AmbiguousClass::Transport)),
        ("tls required", Error::TlsRequired, Some(AmbiguousClass::Transport)),
        ("redirect failed", Error::RedirectFailed, Some(AmbiguousClass::Transport)),
        ("other", Error::Other("x".into()), Some(AmbiguousClass::Transport)),
        (
            "rustls error",
            Error::Rustls(rustls::Error::General("x".to_owned())),
            Some(AmbiguousClass::Tls),
        ),
        (
            "rustls error inside io",
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                rustls::Error::InvalidMessage(rustls::InvalidMessage::InvalidContentType),
            )),
            Some(AmbiguousClass::Tls),
        ),
    ];
    for (name, err, expected) in tests {
        let outcome = classify_error(err);
        match expected {
            None => assert!(matches!(outcome, RefreshOutcome::PreSend(_)), "{name}: {outcome:?}"),
            Some(class) => assert!(
                matches!(outcome, RefreshOutcome::Ambiguous(found) if found == class),
                "{name}: expected Ambiguous({class:?}), got {outcome:?}"
            ),
        }
    }
}

#[test]
fn the_status_table() {
    let ok = serde_json::to_vec(&f80_body()).expect("serializes");
    assert!(matches!(classify_response(200, None, Some(&ok)), RefreshOutcome::Applied(_)));
    assert!(matches!(
        classify_response(200, None, None),
        RefreshOutcome::Ambiguous(AmbiguousClass::ServerBody)
    ));
    for status in [100, 204, 301, 302, 304, 307, 308] {
        let outcome = classify_response(status, None, Some(b"{}"));
        assert!(
            matches!(outcome, RefreshOutcome::Ambiguous(_) | RefreshOutcome::Applied(_))
                && !matches!(outcome, RefreshOutcome::Applied(_)),
            "{status}: {outcome:?}"
        );
    }
    assert!(matches!(
        classify_response(401, None, None),
        RefreshOutcome::Permanent(PermanentClass::Unauthorized)
    ));
    assert!(matches!(classify_response(400, None, None), RefreshOutcome::Rejected(400)));
    assert!(matches!(
        classify_response(418, None, Some(b"not json")),
        RefreshOutcome::Rejected(418)
    ));
    assert!(matches!(classify_response(500, None, None), RefreshOutcome::ServerError(500)));
    assert!(matches!(classify_response(599, None, None), RefreshOutcome::ServerError(599)));
}

#[test]
fn labels_are_the_fixed_words() {
    assert_eq!(AmbiguousClass::Transport.label(), "ambiguous");
    assert_eq!(AmbiguousClass::ServerBody.label(), "ambiguous");
    assert_eq!(AmbiguousClass::Tls.label(), "tls");
    assert_eq!(AmbiguousClass::WriteFailed.label(), "write_failed");
    assert_eq!(PermanentClass::Reused.label(), "refresh_token_reused");
    assert_eq!(TOKEN_URL, "https://auth.openai.com/oauth/token");
}

#[test]
fn from_env_never_falls_back_to_the_vendor_host_in_a_testing_build() {
    // The seam is read, never set, here: setting a process variable races the
    // other tests. Whatever it holds, a `testing` build's URL is it or the
    // loopback fallback — never `auth.openai.com` (review S32-C1 F2).
    let client = RefreshClient::from_env();
    #[cfg(feature = "testing")]
    {
        let expected = std::env::var(TOKEN_URL_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| TESTING_FALLBACK_TOKEN_URL.to_owned());
        assert_eq!(client.token_url(), expected);
        assert_ne!(client.token_url(), TOKEN_URL);
        assert!(TESTING_FALLBACK_TOKEN_URL.starts_with("http://127.0.0.1:"));
    }
    #[cfg(not(feature = "testing"))]
    assert_eq!(client.token_url(), TOKEN_URL);
}

#[cfg(feature = "testing")]
#[test]
fn the_testing_fallback_refuses_before_the_send() {
    let outcome = Namespace::new().send(&client_for(TESTING_FALLBACK_TOKEN_URL), &Cancel::new());
    assert_pre_send(&outcome);
}
