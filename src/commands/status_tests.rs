//! The `status` pass, driven end to end in this process.
//!
//! These are not unit tests of a function: each one stands up a temporary
//! store, a scripted keychain, and an `httpmock` server, runs
//! [`collect`] — the same code path `agentctl claude status` runs — and
//! asserts on the rows *and* on what reached the wire and the filesystem.
//! That is what makes them able to prove the negative claims the plan cares
//! about: zero requests for a row agentctl does not own, exactly one POST
//! when two passes race, no temporary file left behind.
//!
//! # Nothing here reads or writes the process environment
//!
//! `std::env::set_var` is `unsafe` in edition 2024 and would race every other
//! test in the binary. Every ambient input the pass has — the usage endpoint,
//! the keychain, the injected faults, the OAuth client — arrives inside
//! [`Shared`], which is why [`collect`] takes one instead of building it.
//!
//! # The refresh is a real POST
//!
//! [`HttpRefresher`] is a `TokenRefresher` that actually posts to the mock
//! server, rather than a counter that pretends to. "Exactly one POST" is then
//! an assertion about the wire, which is the claim plan AC6 and AC7 make.
//! When lane D's client lands it replaces this double in production and these
//! tests keep asserting the same thing.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use httpmock::Method::GET;
use httpmock::Method::POST;
use httpmock::Mock;
use httpmock::MockServer;
use secrecy::SecretString;
use serde_json::json;
use tempfile::TempDir;

use super::*;
use crate::config::AgentctlConfig;
use crate::config::new_record;
use crate::provider::claude::credentials::CLIENT_ID;
use crate::provider::claude::namespace::export_spelling;
use crate::provider::claude::namespace::sha8;
use crate::provider::claude::oauth::TokenResponse;
use crate::provider::claude::usage::USAGE_PATH;
use crate::secret::KeychainStatus;
use crate::secret::fake_reader::FakeReader;
use crate::secret::file_store::PENDING_META;
use crate::usage::model::Credits;
use crate::usage::model::CreditsState;
use crate::usage::model::Money;

const ACCT: &str = "11111111-2222-3333-4444-555555555555";
const ORG: &str = "66666666-7777-8888-9999-000000000000";
const TOKEN_PATH: &str = "/v1/oauth/token";
const LIVE_SERVICE: &str = "Claude Code-credentials";

/// The captured live body every successful fetch answers with.
const USAGE_BODY: &str = include_str!("../../fixtures/claude/usage-2026-09-08.json");

/// The captured live body from an account with extra-usage credits switched
/// on (plan section 3.8).
const CREDITS_BODY: &str = include_str!("../../fixtures/claude/usage-extra-usage-enabled.json");

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// A temporary store plus the paths that address it.
struct Store {
    _dir: TempDir,
    home: PathBuf,
    paths: Arc<Paths>,
}

fn store() -> Store {
    let dir = TempDir::new().expect("a temporary directory should be creatable");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("the fake home should be creatable");
    let paths = Arc::new(Paths::with_config_dir(dir.path().join("config")));
    paths.ensure_dirs().expect("the store directories should be creatable");
    Store { _dir: dir, home, paths }
}

fn now_millis() -> i64 {
    Timestamp::now().as_millisecond()
}

/// An expiry far enough in the past to be expired under any margin.
fn expired_at() -> i64 {
    now_millis() - 60_000
}

/// An expiry far enough ahead to be fresh under the 5-minute margin.
fn fresh_at() -> i64 {
    now_millis() + 3_600_000
}

/// A credential blob in Claude Code's shape (fact F40).
fn blob(access: &str, refresh: &str, expires_at_ms: i64) -> String {
    json!({
        "claudeAiOauth": {
            "accessToken": access,
            "refreshToken": refresh,
            "expiresAt": expires_at_ms,
            "scopes": ["user:inference", "user:profile"],
            "subscriptionType": "max",
            "tokenAccount": {
                "uuid": ACCT,
                "emailAddress": "owner@example.com",
                "organizationUuid": ORG,
                "organizationName": "Acme",
            },
        }
    })
    .to_string()
}

/// Writes `.credentials.json` into the namespace, creating the directory.
fn write_credential_file(store: &Store, blob: &str) -> PathBuf {
    let ns_dir = store.paths.namespace_dir(ACCT, ORG);
    fs::create_dir_all(&ns_dir).expect("the namespace directory should be creatable");
    let path = ns_dir.join(CREDENTIALS_FILE);
    fs::write(&path, blob).expect("the credential file should be writable");
    fs::set_permissions(&path, PermissionsExt::from_mode(0o600)).expect("mode 0600");
    path
}

/// A registry holding one account this store owns.
fn owned_config(store: &Store) -> AgentctlConfig {
    let ns_dir = store.paths.namespace_dir(ACCT, ORG);
    let spelling = export_spelling(&ns_dir);
    let mut config = AgentctlConfig::default();
    let mut record = new_record(
        ACCT.to_owned(),
        ORG.to_owned(),
        AccountKind::Owned { export_sha8: sha8(&spelling), export_spelling: spelling },
    )
    .expect("the fixture identifiers are valid path segments");
    record.email = Some("owner@example.com".to_owned());
    record.org_name = Some("Acme".to_owned());
    config.upsert(record);
    config
}

/// The keychain service a session would migrate this namespace to (fact F35).
fn migration_service(store: &Store) -> String {
    let spelling = export_spelling(&store.paths.namespace_dir(ACCT, ORG));
    format!("{LIVE_SERVICE}-{}", sha8(&spelling))
}

/// A scripted keychain holding the given `(service, blob)` items.
fn reader_with(items: &[(String, String)]) -> FakeReader {
    let mut reader = FakeReader::unlocked();
    for (service, blob) in items {
        reader = reader.with_entry(service).with_item(service, blob.as_bytes());
    }
    reader
}

/// A [`ReaderFactory`] that hands every worker its own scripted keychain.
fn readers(items: Vec<(String, String)>) -> ReaderFactory {
    let items = Arc::new(items);
    Arc::new(move |_ctx| Box::new(reader_with(&items)))
}

/// Discovery, run against a scripted keychain and a fake home.
fn discover_with(
    store: &Store,
    config: &AgentctlConfig,
    reader: &FakeReader,
) -> crate::provider::claude::discovery::Discovery {
    let env = EnvView::with_home(store.home.clone());
    let ctx = PassCtx::standalone(Cancel::new(), Instant::now() + Duration::from_secs(30));
    discovery::discover(config, &store.paths, reader, &env, &ctx)
}

/// How a pass should be configured.
struct Setup {
    refresher: Arc<dyn TokenRefresher>,
    readers: ReaderFactory,
    fault: Fault,
    options: Options,
    timeout: Duration,
}

impl Setup {
    fn new(server: &MockServer) -> Self {
        Self {
            refresher: Arc::new(HttpRefresher::new(server.url(TOKEN_PATH))),
            readers: readers(Vec::new()),
            fault: Fault::none(),
            options: Options { refresh: false, no_cache: false },
            timeout: Duration::from_secs(5),
        }
    }
}

/// Runs one whole pass and returns its rows.
fn pass(
    store: &Store,
    server: &MockServer,
    found: crate::provider::claude::discovery::Discovery,
    setup: Setup,
) -> Vec<RowOutcome> {
    let shared = Shared {
        paths: Arc::clone(&store.paths),
        client: UsageClient::new(&server.base_url(), "agentctl/test", setup.timeout),
        refresher: setup.refresher,
        reader_factory: setup.readers,
        listing: found.listing,
        fault: setup.fault,
        options: setup.options,
    };
    let deadline = Instant::now() + setup.timeout * PASS_TIMEOUT_MULTIPLIER;
    collect(found.rows, &[], shared, &Cancel::new(), deadline)
        .expect("no `--account` selector is in play")
}

/// The mock that answers a usage GET with the captured body.
fn usage_ok(server: &MockServer) -> Mock<'_> {
    server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(200).body(USAGE_BODY);
    })
}

/// The mock that answers a refresh POST with a rotated token pair.
fn token_ok(server: &MockServer) -> Mock<'_> {
    server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(200).json_body(json!({
            "access_token": "sk-ant-oat01-rotated",
            "refresh_token": "sk-ant-ort01-rotated",
            "token_type": "Bearer",
            "expires_in": 28_800,
            "refresh_token_expires_in": 2_377_445,
            "scope": "user:inference user:profile",
        }));
    })
}

/// The row for the account this store owns.
fn owned_row(rows: &[RowOutcome]) -> &RowOutcome {
    rows.iter()
        .find(|row| row.account == "owner@example.com")
        .expect("the owned account should have produced a row")
}

/// Everything in the namespace directory, by file name.
fn namespace_entries(store: &Store) -> Vec<String> {
    let ns_dir = store.paths.namespace_dir(ACCT, ORG);
    let Ok(dir) = fs::read_dir(&ns_dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = dir
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

// ---------------------------------------------------------------------------
// A `TokenRefresher` that really posts
// ---------------------------------------------------------------------------

/// Posts a refresh grant to a mock token endpoint.
///
/// This is the shape lane D's `OauthClient` will have, reduced to what the
/// pass tests need: it builds the body through
/// [`Credentials::refresh_body`] — so the refresh token is never exposed a
/// third time — and maps the answers onto [`RefreshError`] the same way the
/// documented adapter does.
struct HttpRefresher {
    url: String,
    agent: ureq::Agent,
    /// Lets a test see the call count without a mock, for the cases where the
    /// server is expected never to be reached at all.
    calls: AtomicUsize,
    /// Run inside `refresh`, after the body is built and before the request.
    /// Plan AC21's third clause needs an artefact to appear exactly here.
    during: Option<Box<dyn Fn() + Send + Sync>>,
}

impl HttpRefresher {
    fn new(url: String) -> Self {
        let config = ureq::config::Config::builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(5)))
            .build();
        Self {
            url,
            agent: ureq::Agent::new_with_config(config),
            calls: AtomicUsize::new(0),
            during: None,
        }
    }

    /// Runs `hook` inside every refresh, between the grant and the return.
    fn during(mut self, hook: impl Fn() + Send + Sync + 'static) -> Self {
        self.during = Some(Box::new(hook));
        self
    }
}

impl TokenRefresher for HttpRefresher {
    fn refresh(
        &self,
        credentials: &Credentials,
        _cancel: &Cancel,
    ) -> Result<TokenResponse, RefreshError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let body = credentials
            .refresh_body(CLIENT_ID)
            .map_err(|err| RefreshError::Transient(err.to_string()))?;

        let mut response = self
            .agent
            .post(&self.url)
            .header("content-type", "application/json")
            .send(body)
            .map_err(|err| RefreshError::Transient(err.to_string()))?;

        let status = response.status().as_u16();
        if status == 429 {
            return Err(RefreshError::RateLimited { retry_after_s: None });
        }
        let value: Value = response
            .body_mut()
            .read_json()
            .map_err(|err| RefreshError::Transient(err.to_string()))?;
        if status != 200 {
            if value.get("error").and_then(Value::as_str) == Some("invalid_grant") {
                return Err(RefreshError::InvalidGrant);
            }
            return Err(RefreshError::Transient(format!("HTTP {status}")));
        }

        if let Some(hook) = &self.during {
            hook();
        }
        Ok(token_response(&value))
    }
}

/// Builds a [`TokenResponse`] from a token-endpoint body.
fn token_response(value: &Value) -> TokenResponse {
    let secret = |key: &str| {
        value.get(key).and_then(Value::as_str).map(|text| SecretString::from(text.to_owned()))
    };
    TokenResponse {
        access_token: secret("access_token").unwrap_or_else(|| SecretString::from(String::new())),
        refresh_token: secret("refresh_token"),
        expires_in: value.get("expires_in").and_then(Value::as_i64).unwrap_or(28_800),
        refresh_token_expires_in: value.get("refresh_token_expires_in").and_then(Value::as_i64),
        scope: value.get("scope").and_then(Value::as_str).map(str::to_owned),
        token_type: value.get("token_type").and_then(Value::as_str).map(str::to_owned),
        account: None,
        organization: None,
        workspace: None,
    }
}

// ---------------------------------------------------------------------------
// AC5 — a row agentctl does not own is never refreshed and never fetched
// ---------------------------------------------------------------------------

#[test]
fn ac5_an_expired_live_row_makes_no_request_at_all() {
    let store = store();
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = token_ok(&server);

    // The live credential lives in the keychain and is expired. Its owner —
    // a running Claude Code session — is the only thing that may refresh it
    // (decision D-001).
    let reader = reader_with(&[(
        LIVE_SERVICE.to_owned(),
        blob("sk-ant-oat01-live", "sk-ant-ort01-live", expired_at()),
    )]);
    let found = discover_with(&store, &AgentctlConfig::default(), &reader);

    let rows = pass(&store, &server, found, Setup::new(&server));
    let live = &rows[0];

    assert_eq!(live.state, AccountState::Expired { read_only: true });
    assert!(live.state.is_failure(), "the row drives exit 2");
    assert!(live.usage.is_none());
    usage.assert_calls(0);
    token.assert_calls(0);
}

#[test]
fn ac5_a_fresh_live_row_is_fetched_but_still_never_refreshed() {
    let store = store();
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = token_ok(&server);

    let reader = reader_with(&[(
        LIVE_SERVICE.to_owned(),
        blob("sk-ant-oat01-live", "sk-ant-ort01-live", fresh_at()),
    )]);
    let found = discover_with(&store, &AgentctlConfig::default(), &reader);

    let rows = pass(&store, &server, found, Setup::new(&server));

    assert_eq!(rows[0].state, AccountState::Ok);
    assert_eq!(rows[0].usage.as_ref().map(|u| u.windows.len()), Some(3));
    usage.assert_calls(1);
    token.assert_calls(0);
}

// ---------------------------------------------------------------------------
// AC6 — an owned expired row refreshes exactly once and writes atomically
// ---------------------------------------------------------------------------

#[test]
fn ac6_an_owned_expired_row_makes_one_post_and_one_get() {
    let store = store();
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = token_ok(&server);

    let path = write_credential_file(
        &store,
        &blob("sk-ant-oat01-stale", "sk-ant-ort01-stale", expired_at()),
    );
    let before = fs::metadata(&path).expect("the credential file exists");

    let config = owned_config(&store);
    let reader = FakeReader::unlocked();
    let found = discover_with(&store, &config, &reader);

    let rows = pass(&store, &server, found, Setup::new(&server));
    let row = owned_row(&rows);

    token.assert_calls(1);
    usage.assert_calls(1);
    assert_eq!(row.state, AccountState::Ok);
    assert_eq!(row.usage.as_ref().map(|u| u.windows.len()), Some(3));

    let after = fs::metadata(&path).expect("the credential file is still there");
    assert!(after.is_file(), "a regular file, not a symlink or a directory");
    assert_ne!(before.ino(), after.ino(), "tmp-then-rename leaves a new inode");
    assert_eq!(after.permissions().mode() & 0o777, 0o600);

    let contents = fs::read(&path).expect("readable");
    let written = Credentials::parse_blob(&contents).expect("the written blob parses");
    assert!(!written.access_expired(now_millis(), REFRESH_MARGIN_MS), "the new token is fresh");

    assert_eq!(
        namespace_entries(&store),
        vec![CREDENTIALS_FILE.to_owned()],
        "no temporary file and no pending file survive a successful write"
    );
}

#[test]
fn ac6_the_keychain_is_only_ever_read() {
    // Invariant I1 is enforced at compile time — `KeychainReader` has no
    // write method — so what is left to check is that a refresh does not
    // even *read* an item it has no business reading.
    let store = store();
    let server = MockServer::start();
    usage_ok(&server);
    token_ok(&server);

    write_credential_file(&store, &blob("sk-ant-oat01-a", "sk-ant-ort01-a", expired_at()));
    let config = owned_config(&store);
    let reader = FakeReader::unlocked();
    let found = discover_with(&store, &config, &reader);

    pass(&store, &server, found, Setup::new(&server));

    assert_eq!(
        reader.reads(),
        vec![LIVE_SERVICE.to_owned()],
        "only the live service is read; a namespace with no listed migration \
         item issues no find-generic-password (plan AC20)"
    );
}

#[test]
fn ac30_the_five_minute_margin_decides_whether_to_refresh() {
    // Fact F27: four minutes to expiry is "expired", six minutes is not.
    for (remaining_ms, expected_posts) in [(240_000i64, 1usize), (360_000, 0)] {
        let store = store();
        let server = MockServer::start();
        let usage = usage_ok(&server);
        let token = token_ok(&server);

        write_credential_file(
            &store,
            &blob("sk-ant-oat01-a", "sk-ant-ort01-a", now_millis() + remaining_ms),
        );
        let config = owned_config(&store);
        let found = discover_with(&store, &config, &FakeReader::unlocked());

        let rows = pass(&store, &server, found, Setup::new(&server));

        token.assert_calls(expected_posts);
        usage.assert_calls(1);
        assert_eq!(owned_row(&rows).state, AccountState::Ok, "remaining {remaining_ms} ms");
    }
}

#[test]
fn a_dead_refresh_chain_is_needs_login_and_is_never_retried() {
    let store = store();
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(400).json_body(json!({"error": "invalid_grant"}));
    });

    write_credential_file(&store, &blob("sk-ant-oat01-a", "sk-ant-ort01-a", expired_at()));
    let config = owned_config(&store);
    let found = discover_with(&store, &config, &FakeReader::unlocked());

    let rows = pass(&store, &server, found, Setup::new(&server));

    assert_eq!(owned_row(&rows).state, AccountState::NeedsLogin);
    token.assert_calls(1);
    usage.assert_calls(0);
}

#[test]
fn a_rate_limited_token_endpoint_is_transient_and_never_needs_login() {
    // S3 probe: a 429 there does not consume the grant (fact R26).
    let store = store();
    let server = MockServer::start();
    let token = server.mock(|when, then| {
        when.method(POST).path(TOKEN_PATH);
        then.status(429).json_body(json!({"error": {"type": "rate_limit_error"}}));
    });

    write_credential_file(&store, &blob("sk-ant-oat01-a", "sk-ant-ort01-a", expired_at()));
    let config = owned_config(&store);
    let found = discover_with(&store, &config, &FakeReader::unlocked());

    let rows = pass(&store, &server, found, Setup::new(&server));
    let row = owned_row(&rows);

    token.assert_calls(1);
    assert_eq!(row.state, AccountState::RateLimited { retry_after_s: None });
    assert_ne!(row.state, AccountState::NeedsLogin);
}

// ---------------------------------------------------------------------------
// AC8 — a 429 shows the cached value and is not retried inside its window
// ---------------------------------------------------------------------------

#[test]
fn ac8_a_429_renders_the_cached_value_and_suppresses_the_next_call() {
    let store = store();
    let server = MockServer::start();

    write_credential_file(&store, &blob("sk-ant-oat01-a", "sk-ant-ort01-a", fresh_at()));
    let config = owned_config(&store);

    // Pass one populates the cache.
    let mut ok = usage_ok(&server);
    let found = discover_with(&store, &config, &FakeReader::unlocked());
    let rows = pass(&store, &server, found, Setup::new(&server));
    assert_eq!(owned_row(&rows).state, AccountState::Ok);
    ok.assert_calls(1);
    ok.delete();

    // Pass two bypasses the cache and meets a 429.
    let limited = server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(429).header("retry-after", "30").body("{}");
    });
    let found = discover_with(&store, &config, &FakeReader::unlocked());
    let mut setup = Setup::new(&server);
    setup.options.refresh = true;
    let rows = pass(&store, &server, found, setup);
    let row = owned_row(&rows);

    limited.assert_calls(1);
    assert_eq!(row.state, AccountState::RateLimited { retry_after_s: Some(30) });
    assert_eq!(row.state.label(), "rate-limited (retry in 30s)");
    assert!(row.state.is_failure(), "the row drives exit 2");
    assert_eq!(
        row.usage.as_ref().map(|usage| usage.windows.len()),
        Some(3),
        "the cached numbers are still rendered"
    );

    // Pass three, still inside the window, must not call at all — even with
    // `--refresh`, because the wait is the server's instruction, not a cache
    // policy the user can override.
    let found = discover_with(&store, &config, &FakeReader::unlocked());
    let mut setup = Setup::new(&server);
    setup.options.refresh = true;
    let rows = pass(&store, &server, found, setup);

    limited.assert_calls(1);
    let row = owned_row(&rows);
    assert!(matches!(row.state, AccountState::RateLimited { retry_after_s: Some(_) }));
    assert!(row.usage.is_some());
}

#[test]
fn a_fresh_cache_entry_is_served_without_a_request() {
    let store = store();
    let server = MockServer::start();
    let usage = usage_ok(&server);

    write_credential_file(&store, &blob("sk-ant-oat01-a", "sk-ant-ort01-a", fresh_at()));
    let config = owned_config(&store);

    let found = discover_with(&store, &config, &FakeReader::unlocked());
    pass(&store, &server, found, Setup::new(&server));
    usage.assert_calls(1);

    let found = discover_with(&store, &config, &FakeReader::unlocked());
    let rows = pass(&store, &server, found, Setup::new(&server));
    usage.assert_calls(1);
    assert_eq!(owned_row(&rows).usage.as_ref().map(|u| u.windows.len()), Some(3));

    // `--no-cache` goes back to the network.
    let found = discover_with(&store, &config, &FakeReader::unlocked());
    let mut setup = Setup::new(&server);
    setup.options.no_cache = true;
    pass(&store, &server, found, setup);
    usage.assert_calls(2);
}

#[test]
fn ac49_a_response_with_no_windows_says_so_and_drives_exit_two() {
    let store = store();
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(200).body(include_str!("../../fixtures/claude/usage-empty-limits.json"));
    });

    write_credential_file(&store, &blob("sk-ant-oat01-a", "sk-ant-ort01-a", fresh_at()));
    let config = owned_config(&store);
    let found = discover_with(&store, &config, &FakeReader::unlocked());

    let rows = pass(&store, &server, found, Setup::new(&server));
    let row = owned_row(&rows);

    assert_eq!(row.state, AccountState::NoSubscriptionLimits);
    assert!(row.state.is_failure());
    assert_eq!(row.usage.as_ref().map(|usage| usage.windows.len()), Some(0));
}

// ---------------------------------------------------------------------------
// AC21 — a namespace somebody else is using is never written
// ---------------------------------------------------------------------------

#[test]
fn ac21_a_foreign_refresh_lock_refuses_the_refresh_and_leaves_it_alone() {
    for artefact in [".oauth_refresh.lock", ".storage-write"] {
        let store = store();
        let server = MockServer::start();
        let usage = usage_ok(&server);
        let token = token_ok(&server);

        write_credential_file(&store, &blob("sk-ant-oat01-a", "sk-ant-ort01-a", expired_at()));
        let lock = store.paths.namespace_dir(ACCT, ORG).join(artefact);
        fs::write(&lock, b"claude code was here").expect("the artefact should be creatable");
        let before = fs::metadata(&lock).expect("present");

        let config = owned_config(&store);
        let found = discover_with(&store, &config, &FakeReader::unlocked());
        let rows = pass(&store, &server, found, Setup::new(&server));
        let row = owned_row(&rows);

        token.assert_calls(0);
        usage.assert_calls(0);
        assert!(
            matches!(row.state, AccountState::ClaudeSessionDetected { .. }),
            "{artefact}: got {:?}",
            row.state
        );
        assert!(row.state.is_failure(), "the row drives exit 2");

        let after = fs::metadata(&lock).expect("the artefact is still there");
        assert_eq!(before.ino(), after.ino(), "agentctl never removes a lock artefact");
        assert_eq!(
            fs::read(&lock).expect("readable"),
            b"claude code was here",
            "and never rewrites one"
        );
    }
}

#[test]
fn ac21_the_legacy_lock_beside_the_namespace_refuses_the_refresh_too() {
    let store = store();
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = token_ok(&server);

    write_credential_file(&store, &blob("sk-ant-oat01-a", "sk-ant-ort01-a", expired_at()));
    // Fact F17: the older lock sits *beside* the directory, named after its
    // resolved path with `.lock` appended.
    let ns_dir = store.paths.namespace_dir(ACCT, ORG);
    let canonical = crate::provider::claude::namespace::canonical(&ns_dir)
        .expect("the namespace directory resolves");
    let mut legacy = canonical.into_os_string();
    legacy.push(".lock");
    let legacy = PathBuf::from(legacy);
    fs::write(&legacy, b"{}").expect("the legacy lock should be creatable");

    let config = owned_config(&store);
    let found = discover_with(&store, &config, &FakeReader::unlocked());
    let rows = pass(&store, &server, found, Setup::new(&server));

    token.assert_calls(0);
    usage.assert_calls(0);
    assert!(matches!(owned_row(&rows).state, AccountState::ClaudeSessionDetected { .. }));
    assert!(legacy.exists(), "the legacy lock is left alone");
}

#[test]
fn ac21_an_artefact_appearing_mid_refresh_discards_the_new_credentials() {
    // The window plan AC21's third clause aims at: the POST has returned and
    // nothing has been written yet. The refresher creates the artefact from
    // inside that window, which makes the interleaving deterministic — no
    // sleeping, no second thread, no environment variable.
    let store = store();
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = token_ok(&server);

    let path =
        write_credential_file(&store, &blob("sk-ant-oat01-a", "sk-ant-ort01-a", expired_at()));
    let before = fs::read(&path).expect("readable");
    let before_meta = fs::metadata(&path).expect("present");

    let ns_dir = store.paths.namespace_dir(ACCT, ORG);
    let mut setup = Setup::new(&server);
    setup.refresher = Arc::new(HttpRefresher::new(server.url(TOKEN_PATH)).during(move || {
        fs::write(ns_dir.join(".oauth_refresh.lock"), b"a session started")
            .expect("the artefact should be creatable");
    }));

    let config = owned_config(&store);
    let found = discover_with(&store, &config, &FakeReader::unlocked());
    let rows = pass(&store, &server, found, setup);
    let row = owned_row(&rows);

    token.assert_calls(1);
    usage.assert_calls(0);
    assert_eq!(row.state, AccountState::RefreshDiscarded);
    assert_eq!(row.state.label(), "refresh discarded: namespace changed during refresh");

    assert_eq!(fs::read(&path).expect("readable"), before, "the credential file is untouched");
    assert_eq!(fs::metadata(&path).expect("present").ino(), before_meta.ino());
    let mut entries = namespace_entries(&store);
    entries.retain(|name| name != ".oauth_refresh.lock");
    assert_eq!(
        entries,
        vec![CREDENTIALS_FILE.to_owned()],
        "no temporary file and no pending file are left behind"
    );
}

#[test]
fn ac21_the_credential_file_changing_mid_refresh_discards_too() {
    // The other half of the pre-rename re-check: the artefact test covers
    // `detect`, this one covers the `(dev, ino, size, mtime)` comparison.
    let store = store();
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = token_ok(&server);

    let path =
        write_credential_file(&store, &blob("sk-ant-oat01-a", "sk-ant-ort01-a", expired_at()));

    let replacement = blob("sk-ant-oat01-someone-else", "sk-ant-ort01-someone-else", fresh_at());
    let store_path = path.clone();
    let mut setup = Setup::new(&server);
    setup.refresher = Arc::new(HttpRefresher::new(server.url(TOKEN_PATH)).during(move || {
        // A different writer replaced the file, exactly as `write_credentials`
        // would: a new inode under the same name.
        let tmp = store_path.with_extension("someone-else");
        fs::write(&tmp, replacement.as_bytes()).expect("writable");
        fs::rename(&tmp, &store_path).expect("renamable");
    }));

    let config = owned_config(&store);
    let found = discover_with(&store, &config, &FakeReader::unlocked());
    let rows = pass(&store, &server, found, setup);

    token.assert_calls(1);
    usage.assert_calls(0);
    assert_eq!(owned_row(&rows).state, AccountState::RefreshDiscarded);

    let kept = Credentials::parse_blob(&fs::read(&path).expect("readable")).expect("parses");
    assert_eq!(
        kept.digests().access_sha256,
        Credentials::parse_blob(
            blob("sk-ant-oat01-someone-else", "sk-ant-ort01-someone-else", fresh_at()).as_bytes()
        )
        .expect("parses")
        .digests()
        .access_sha256,
        "the other writer's file survives untouched"
    );
}

// ---------------------------------------------------------------------------
// AC7 — two passes racing for one namespace
// ---------------------------------------------------------------------------

#[test]
fn ac7_two_concurrent_passes_produce_exactly_one_post() {
    let store = store();
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = token_ok(&server);

    write_credential_file(&store, &blob("sk-ant-oat01-a", "sk-ant-ort01-a", expired_at()));
    let config = owned_config(&store);

    let states = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let store = &store;
                let server = &server;
                let config = &config;
                scope.spawn(move || {
                    let found = discover_with(store, config, &FakeReader::unlocked());
                    let rows = pass(store, server, found, Setup::new(server));
                    owned_row(&rows).state.clone()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("no worker panics"))
            .collect::<Vec<_>>()
    });

    token.assert_calls(1);
    assert_eq!(usage.calls(), 2, "both passes still fetch usage with the shared fresh token");
    for state in &states {
        assert_eq!(*state, AccountState::Ok, "the loser adopts the winner's file and exits 0");
        assert!(!state.is_failure());
    }
}

#[test]
fn ac7_a_lock_held_past_the_deadline_makes_the_second_pass_busy() {
    let store = store();
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = token_ok(&server);

    write_credential_file(&store, &blob("sk-ant-oat01-a", "sk-ant-ort01-a", expired_at()));
    let config = owned_config(&store);

    // Hold the namespace lock for longer than the second pass will wait.
    let holder_cancel = Cancel::new();
    let held = namespace_lock::acquire(
        &store.paths,
        ACCT,
        ORG,
        Instant::now() + Duration::from_secs(30),
        &holder_cancel,
        Fault::none(),
    )
    .expect("an uncontended lock should be acquirable");

    let found = discover_with(&store, &config, &FakeReader::unlocked());
    let mut setup = Setup::new(&server);
    setup.timeout = Duration::from_millis(200);
    let rows = pass(&store, &server, found, setup);
    let row = owned_row(&rows);

    drop(held);

    assert_eq!(row.state, AccountState::Busy);
    assert!(row.state.is_failure(), "a busy row drives exit 2");
    token.assert_calls(0);
    usage.assert_calls(0);
}

// ---------------------------------------------------------------------------
// AC33 — the pending decision table, driven through the real pass
// ---------------------------------------------------------------------------

/// Parks `pending_blob` as a pending write derived from `prior`.
///
/// Produced by the real writer under an injected rename failure, so the
/// metadata is exactly what a failed refresh would have left.
fn park_pending(store: &Store, pending_blob: &str, prior: Option<&Digests>) {
    let ns_dir = store.paths.namespace_dir(ACCT, ORG);
    fs::create_dir_all(&ns_dir).expect("the namespace directory should be creatable");
    let request = WriteRequest {
        paths: &store.paths,
        ns_dir: &ns_dir,
        blob_json: pending_blob,
        prior,
        new_expires_at_ms: now_millis(),
        fault: Fault::from_list("rename_fail"),
    };
    let ctx = PassCtx::standalone(Cancel::new(), Instant::now() + Duration::from_secs(30));
    let outcome = file_store::write_credentials(&request, &ctx)
        .expect("an injected rename failure parks rather than failing");
    assert!(
        matches!(outcome, WriteOutcome::SavedToPending { .. }),
        "the fixture depends on the write being parked"
    );
}

fn digests_of(blob: &str) -> Digests {
    Credentials::parse_blob(blob.as_bytes()).expect("the fixture blob parses").digests()
}

#[test]
fn ac33a_a_pending_matching_an_unchanged_file_is_replayed_without_a_post() {
    let store = store();
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = token_ok(&server);

    let original = blob("sk-ant-oat01-a", "sk-ant-ort01-a", fresh_at());
    write_credential_file(&store, &original);
    let replayed = blob("sk-ant-oat01-b", "sk-ant-ort01-b", fresh_at());
    park_pending(&store, &replayed, Some(&digests_of(&original)));

    let config = owned_config(&store);
    let found = discover_with(&store, &config, &FakeReader::unlocked());
    let rows = pass(&store, &server, found, Setup::new(&server));
    let row = owned_row(&rows);

    assert_eq!(row.state, AccountState::PendingReplayed);
    assert!(!row.state.is_failure(), "a replay is housekeeping, not a failure");
    token.assert_calls(0);
    usage.assert_calls(1);

    let path = store.paths.namespace_dir(ACCT, ORG).join(CREDENTIALS_FILE);
    let now = Credentials::parse_blob(&fs::read(&path).expect("readable")).expect("parses");
    assert_eq!(now.digests(), digests_of(&replayed), "the pending file is now the credential");
    assert_eq!(namespace_entries(&store), vec![CREDENTIALS_FILE.to_owned()]);
}

#[test]
fn ac33b_a_pending_whose_file_changed_is_discarded_and_the_refresh_proceeds() {
    let store = store();
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = token_ok(&server);

    let derived_from = blob("sk-ant-oat01-a", "sk-ant-ort01-a", fresh_at());
    park_pending(
        &store,
        &blob("sk-ant-oat01-b", "sk-ant-ort01-b", fresh_at()),
        Some(&digests_of(&derived_from)),
    );
    // Somebody replaced the file after the pending was parked.
    write_credential_file(&store, &blob("sk-ant-oat01-c", "sk-ant-ort01-c", expired_at()));

    let config = owned_config(&store);
    let found = discover_with(&store, &config, &FakeReader::unlocked());
    let rows = pass(&store, &server, found, Setup::new(&server));
    let row = owned_row(&rows);

    assert_eq!(row.state, AccountState::PendingDiscarded { reason: "file changed".to_owned() });
    token.assert_calls(1);
    usage.assert_calls(1);
    assert_eq!(namespace_entries(&store), vec![CREDENTIALS_FILE.to_owned()]);
}

#[test]
fn ac33c_a_pending_whose_token_has_since_expired_is_replayed_then_refreshed() {
    let store = store();
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = token_ok(&server);

    let original = blob("sk-ant-oat01-a", "sk-ant-ort01-a", expired_at());
    write_credential_file(&store, &original);
    park_pending(
        &store,
        &blob("sk-ant-oat01-b", "sk-ant-ort01-b", expired_at()),
        Some(&digests_of(&original)),
    );

    let config = owned_config(&store);
    let found = discover_with(&store, &config, &FakeReader::unlocked());
    let rows = pass(&store, &server, found, Setup::new(&server));

    // Replayed because the digests match, then refreshed because the
    // replayed token is itself expired.
    assert_eq!(owned_row(&rows).state, AccountState::PendingReplayed);
    token.assert_calls(1);
    usage.assert_calls(1);
}

#[test]
fn ac33d_a_pending_with_no_metadata_is_invalid() {
    let store = store();
    let server = MockServer::start();
    usage_ok(&server);
    let token = token_ok(&server);

    let original = blob("sk-ant-oat01-a", "sk-ant-ort01-a", fresh_at());
    write_credential_file(&store, &original);
    park_pending(
        &store,
        &blob("sk-ant-oat01-b", "sk-ant-ort01-b", fresh_at()),
        Some(&digests_of(&original)),
    );
    fs::remove_file(store.paths.namespace_dir(ACCT, ORG).join(PENDING_META))
        .expect("the metadata should be removable");

    let config = owned_config(&store);
    let found = discover_with(&store, &config, &FakeReader::unlocked());
    let rows = pass(&store, &server, found, Setup::new(&server));

    assert_eq!(
        owned_row(&rows).state,
        AccountState::PendingDiscarded { reason: "invalid".to_owned() }
    );
    token.assert_calls(0);
    assert_eq!(namespace_entries(&store), vec![CREDENTIALS_FILE.to_owned()]);
}

#[test]
fn ac33e_a_pending_that_is_a_symlink_is_invalid() {
    let store = store();
    let server = MockServer::start();
    usage_ok(&server);
    let token = token_ok(&server);

    let original = blob("sk-ant-oat01-a", "sk-ant-ort01-a", fresh_at());
    write_credential_file(&store, &original);
    park_pending(
        &store,
        &blob("sk-ant-oat01-b", "sk-ant-ort01-b", fresh_at()),
        Some(&digests_of(&original)),
    );

    // Replace the parked file with a link at somebody else's secret.
    let ns_dir = store.paths.namespace_dir(ACCT, ORG);
    let pending = ns_dir.join(PENDING_FILE);
    fs::remove_file(&pending).expect("removable");
    std::os::unix::fs::symlink(ns_dir.join(CREDENTIALS_FILE), &pending)
        .expect("the symlink should be creatable");

    let config = owned_config(&store);
    let found = discover_with(&store, &config, &FakeReader::unlocked());
    let rows = pass(&store, &server, found, Setup::new(&server));

    assert_eq!(
        owned_row(&rows).state,
        AccountState::PendingDiscarded { reason: "invalid".to_owned() }
    );
    token.assert_calls(0);
    assert!(!pending.exists(), "the link is destroyed, not followed");
    assert!(ns_dir.join(CREDENTIALS_FILE).exists(), "and its target survives");
}

#[test]
fn ac33f_a_first_write_pending_with_no_file_is_replayed() {
    let store = store();
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = token_ok(&server);

    // `prior: None` is what a first write records: there was no file to
    // derive from, so replaying cannot be undoing anything.
    park_pending(&store, &blob("sk-ant-oat01-b", "sk-ant-ort01-b", fresh_at()), None);

    let config = owned_config(&store);
    let found = discover_with(&store, &config, &FakeReader::unlocked());
    let rows = pass(&store, &server, found, Setup::new(&server));

    assert_eq!(owned_row(&rows).state, AccountState::PendingReplayed);
    token.assert_calls(0);
    usage.assert_calls(1);
    assert_eq!(namespace_entries(&store), vec![CREDENTIALS_FILE.to_owned()]);
}

#[test]
fn ac33g_a_pending_whose_file_was_removed_is_discarded_and_needs_login() {
    let store = store();
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = token_ok(&server);

    let original = blob("sk-ant-oat01-a", "sk-ant-ort01-a", fresh_at());
    write_credential_file(&store, &original);
    park_pending(
        &store,
        &blob("sk-ant-oat01-b", "sk-ant-ort01-b", fresh_at()),
        Some(&digests_of(&original)),
    );
    fs::remove_file(store.paths.namespace_dir(ACCT, ORG).join(CREDENTIALS_FILE))
        .expect("the credential should be removable");

    let config = owned_config(&store);
    let found = discover_with(&store, &config, &FakeReader::unlocked());
    let rows = pass(&store, &server, found, Setup::new(&server));

    // Replaying would resurrect a credential the user deleted.
    assert_eq!(owned_row(&rows).state, AccountState::NeedsLogin);
    token.assert_calls(0);
    usage.assert_calls(0);
    assert!(namespace_entries(&store).is_empty(), "both pending files are gone");
}

#[test]
fn a_pending_is_resolved_even_when_a_fresh_cache_entry_would_answer() {
    // A pending file holds a second copy of a refresh token (invariant I5,
    // risk R24). If the cache short-circuited ahead of the resolution, a user
    // who runs `status` inside the 300 s TTL would leave that copy on disk
    // for as long as they kept looking.
    let store = store();
    let server = MockServer::start();
    let usage = usage_ok(&server);

    let original = blob("sk-ant-oat01-a", "sk-ant-ort01-a", fresh_at());
    write_credential_file(&store, &original);
    let config = owned_config(&store);

    // Pass one fills the cache.
    let found = discover_with(&store, &config, &FakeReader::unlocked());
    pass(&store, &server, found, Setup::new(&server));
    usage.assert_calls(1);

    // A refresh from another process failed to rename and parked its result.
    let replayed = blob("sk-ant-oat01-b", "sk-ant-ort01-b", fresh_at());
    park_pending(&store, &replayed, Some(&digests_of(&original)));

    // Pass two answers from the cache — and still clears the pending pair.
    let found = discover_with(&store, &config, &FakeReader::unlocked());
    let rows = pass(&store, &server, found, Setup::new(&server));

    usage.assert_calls(1);
    assert_eq!(owned_row(&rows).state, AccountState::PendingReplayed);
    assert!(
        owned_row(&rows).usage.is_some(),
        "the cached numbers still answer the question that was asked"
    );
    assert_eq!(
        namespace_entries(&store),
        vec![CREDENTIALS_FILE.to_owned()],
        "the pending pair is gone"
    );

    let path = store.paths.namespace_dir(ACCT, ORG).join(CREDENTIALS_FILE);
    let now = Credentials::parse_blob(&fs::read(&path).expect("readable")).expect("parses");
    assert_eq!(now.digests(), digests_of(&replayed), "and the replay landed");
}

#[test]
fn ac33h_a_migrated_namespace_takes_the_pending_over() {
    let store = store();
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = token_ok(&server);

    let original = blob("sk-ant-oat01-a", "sk-ant-ort01-a", expired_at());
    write_credential_file(&store, &original);
    park_pending(
        &store,
        &blob("sk-ant-oat01-b", "sk-ant-ort01-b", fresh_at()),
        Some(&digests_of(&original)),
    );

    // A Claude Code session migrated this namespace into the keychain
    // (fact F35): agentctl must stop writing it, and the pending copy of a
    // refresh token must not survive.
    let service = migration_service(&store);
    let items =
        vec![(service.clone(), blob("sk-ant-oat01-migrated", "sk-ant-ort01-migrated", fresh_at()))];
    let reader = reader_with(&items);
    let config = owned_config(&store);
    let found = discover_with(&store, &config, &reader);

    let mut setup = Setup::new(&server);
    setup.readers = readers(items);
    let rows = pass(&store, &server, found, setup);

    assert_eq!(
        owned_row(&rows).state,
        AccountState::PendingDiscarded { reason: "namespace taken over".to_owned() }
    );
    token.assert_calls(0);
    usage.assert_calls(0);
    assert_eq!(
        namespace_entries(&store),
        vec![CREDENTIALS_FILE.to_owned()],
        "the pending pair is destroyed; the credential file is left alone"
    );
}

// ---------------------------------------------------------------------------
// Selection, rendering and the exit status
// ---------------------------------------------------------------------------

#[test]
fn an_account_selector_narrows_the_pass_and_an_unknown_one_is_fatal() {
    let store = store();
    let server = MockServer::start();
    usage_ok(&server);

    write_credential_file(&store, &blob("sk-ant-oat01-a", "sk-ant-ort01-a", fresh_at()));
    let config = owned_config(&store);
    let found = discover_with(&store, &config, &FakeReader::unlocked());
    let rows = found.rows;

    // Every spelling plan section 3.2 lists.
    for selector in [ACCT, "owner@example.com", &format!("{ACCT}/{ORG}")] {
        let kept = select(clone_rows(&rows), &[selector.to_owned()])
            .unwrap_or_else(|err| panic!("`{selector}` should match: {err}"));
        assert_eq!(kept.len(), 1, "selector `{selector}`");
        assert_eq!(kept[0].record.account_uuid, ACCT);
    }

    let err = select(clone_rows(&rows), &["nobody".to_owned()])
        .expect_err("an unknown selector is fatal, not an empty table");
    assert_eq!(err.exit_code(), crate::error::EXIT_FATAL);
    assert!(err.to_string().contains("nobody"), "the message names what was asked for");
}

/// Shallow-copies rows for a second selection pass.
///
/// `AccountRow` is deliberately not `Clone` — it holds a `Credentials`, and a
/// clone of one would need a third exposure site — so the copies here carry
/// no credentials, which is all `select` looks at.
fn clone_rows(rows: &[AccountRow]) -> Vec<AccountRow> {
    rows.iter()
        .map(|row| AccountRow {
            id: row.id.clone(),
            record: row.record.clone(),
            state: row.state.clone(),
            source: row.source,
            credentials: None,
            visible_by_default: row.visible_by_default,
            note: row.note.clone(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// `--json` — plan AC9, AC23, and AC7's JSON clause
// ---------------------------------------------------------------------------

/// The document a `--json` run would print, built from a finished pass.
fn document(outcomes: &[RowOutcome], show_all: bool, raw: bool) -> serde_json::Value {
    let report = Report {
        rows: outcomes.iter().map(RowOutcome::to_status_row).collect(),
        now: Timestamp::now(),
        show_all,
    };
    let document = json_report(outcomes, &report, raw);
    crate::render::json::assert_valid(&document);
    serde_json::to_value(&document).expect("a report serializes")
}

#[test]
fn ac9_the_json_report_validates_and_carries_no_token_material() {
    let store = store();
    let server = MockServer::start();
    usage_ok(&server);

    write_credential_file(&store, &blob("sk-ant-oat01-a", "sk-ant-ort01-a", fresh_at()));
    let config = owned_config(&store);
    let found = discover_with(&store, &config, &FakeReader::unlocked());
    let outcomes = pass(&store, &server, found, Setup::new(&server));

    // `assert_valid` inside `document` is half of AC9; this is the other half,
    // and it greps the *serialized* document rather than the typed one,
    // because a token could only ever escape as text.
    let value = document(&outcomes, false, true);
    let text = serde_json::to_string(&value).expect("the document serializes");
    assert!(!text.contains("sk-ant-"), "no token material reaches the document:\n{text}");
    assert!(!text.contains("oat01"), "not even a fragment of one:\n{text}");

    let row = value["rows"]
        .as_array()
        .expect("rows is an array")
        .iter()
        .find(|row| row["email"] == json!("owner@example.com"))
        .expect("the owned account is in the document");
    assert_eq!(row["kind"], json!("owned"));
    assert_eq!(row["source"], json!("file"));
    assert_eq!(row["state"], json!("ok"));
    assert_eq!(row["lock_state"], json!("none"), "a fresh token takes no lock");
    assert_eq!(row["account_uuid"], json!(ACCT));
    assert_eq!(row["organization_uuid"], json!(ORG));

    let kinds: Vec<&str> = row["windows"]
        .as_array()
        .expect("windows is an array")
        .iter()
        .filter_map(|window| window["kind"].as_str())
        .collect();
    assert_eq!(kinds, ["session", "weekly_all", "weekly_scoped"], "the captured body's windows");
    assert_eq!(row["windows"][0]["percent_floor"], json!(21));
    assert_eq!(row["windows"][2]["is_active"], json!(true));
}

#[test]
fn ac23_every_row_carries_credits_and_raw_carries_spend_untouched() {
    let store = store();
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(200).body(CREDITS_BODY);
    });

    write_credential_file(&store, &blob("sk-ant-oat01-a", "sk-ant-ort01-a", fresh_at()));
    let config = owned_config(&store);
    let found = discover_with(&store, &config, &FakeReader::unlocked());
    let outcomes = pass(&store, &server, found, Setup::new(&server));

    let value = document(&outcomes, true, true);
    let rows = value["rows"].as_array().expect("rows is an array");
    assert!(rows.len() > 1, "the live row is in the document too");
    for row in rows {
        assert!(row["credits"].is_object(), "every row carries a credits object: {row}");
        assert_eq!(row["credits"]["scope"], json!("organization"));
    }

    let fetched = rows
        .iter()
        .find(|row| row["email"] == json!("owner@example.com"))
        .expect("the owned account is in the document");
    assert_eq!(fetched["credits"]["state"], json!("on"));
    assert_eq!(fetched["credits"]["used_minor"], json!(21_956));
    assert_eq!(fetched["credits"]["limit_minor"], json!(500_000));
    assert_eq!(fetched["credits"]["currency"], json!("USD"));
    assert_eq!(fetched["credits"]["exponent"], json!(2));
    assert_eq!(fetched["credits"]["percent"], json!(4), "rounded, not floored");

    // The row that fetched nothing still answers the question.
    let live = rows
        .iter()
        .find(|row| row["kind"] == json!("live"))
        .expect("the live row is in the document");
    assert_eq!(live["credits"]["state"], json!("unavailable"));
    assert!(live["windows"].as_array().is_some_and(Vec::is_empty));

    // `spend` is never parsed into a typed value, so `--raw` is the only place
    // it survives — and it survives byte for byte (plan section 3.8).
    let id = fetched["id"].as_str().expect("the row has an id");
    let raw = &value["raw"][id];
    assert_eq!(raw["spend"]["used"]["amount_minor"], json!(21_956));
    assert_eq!(raw["spend"]["percent"], json!(4));
    assert_eq!(raw["extra_usage"]["utilization"], json!(4.3911999999999995));
}

#[test]
fn the_json_report_omits_raw_entirely_without_the_flag() {
    let store = store();
    let server = MockServer::start();
    usage_ok(&server);

    write_credential_file(&store, &blob("sk-ant-oat01-a", "sk-ant-ort01-a", fresh_at()));
    let config = owned_config(&store);
    let found = discover_with(&store, &config, &FakeReader::unlocked());
    let outcomes = pass(&store, &server, found, Setup::new(&server));

    let value = document(&outcomes, false, false);
    assert!(value.get("raw").is_none(), "absent, not null: {value}");
    assert_eq!(value["version"], json!(1));
    assert_eq!(value["hidden"], json!(0));
}

#[test]
fn ac7_the_json_report_reports_a_lock_held_past_the_deadline_as_busy() {
    // AC7's JSON clause. The table has no column for the lock, so `busy` in
    // the `State` column and `lock_state: "busy"` in the document are two
    // different assertions, and this is the second one.
    let store = store();
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = token_ok(&server);

    write_credential_file(&store, &blob("sk-ant-oat01-a", "sk-ant-ort01-a", expired_at()));
    let config = owned_config(&store);

    let holder_cancel = Cancel::new();
    let held = namespace_lock::acquire(
        &store.paths,
        ACCT,
        ORG,
        Instant::now() + Duration::from_secs(30),
        &holder_cancel,
        Fault::none(),
    )
    .expect("an uncontended lock should be acquirable");

    let found = discover_with(&store, &config, &FakeReader::unlocked());
    let mut setup = Setup::new(&server);
    setup.timeout = Duration::from_millis(200);
    let outcomes = pass(&store, &server, found, setup);
    drop(held);

    let value = document(&outcomes, false, false);
    let row = value["rows"]
        .as_array()
        .expect("rows is an array")
        .iter()
        .find(|row| row["email"] == json!("owner@example.com"))
        .expect("the owned account is in the document");

    assert_eq!(row["lock_state"], json!("busy"));
    assert_eq!(row["state"], json!("busy"));
    assert_eq!(row["state_label"], json!("busy"));
    token.assert_calls(0);
    usage.assert_calls(0);
}

#[test]
fn the_rendered_table_carries_the_row_the_pass_produced() {
    let store = store();
    let server = MockServer::start();
    usage_ok(&server);

    write_credential_file(&store, &blob("sk-ant-oat01-a", "sk-ant-ort01-a", fresh_at()));
    let config = owned_config(&store);
    let found = discover_with(&store, &config, &FakeReader::unlocked());
    let outcomes = pass(&store, &server, found, Setup::new(&server));

    let report = Report {
        rows: outcomes.iter().map(RowOutcome::to_status_row).collect(),
        now: Timestamp::now(),
        show_all: false,
    };
    let rendered = table::render(&report);

    assert!(rendered.contains("owner@example.com"), "got:\n{rendered}");
    assert!(rendered.contains("Acme"), "got:\n{rendered}");
    assert!(rendered.contains("21%"), "the session window: got:\n{rendered}");
    assert!(rendered.contains("35%"), "the weekly window: got:\n{rendered}");
    assert!(rendered.contains("56%"), "the Fable window: got:\n{rendered}");
    // The captured account has never enabled credits, so `extra_usage`
    // reports them switched off rather than saying nothing at all.
    assert!(rendered.contains("off"), "credits are off for this account: got:\n{rendered}");
    assert!(!rendered.contains("sk-ant"), "no token material reaches the table");
}

#[test]
fn credits_ride_on_the_same_response_the_windows_came_from() {
    // Plan section 3.8: the credits column costs no extra request. One GET
    // answers with the credits-enabled capture and the cell reads the
    // figures that body carries — 21956 of 500000 minor units at 4.3912 %.
    let store = store();
    let server = MockServer::start();
    let usage = server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(200).body(CREDITS_BODY);
    });

    write_credential_file(&store, &blob("sk-ant-oat01-a", "sk-ant-ort01-a", fresh_at()));
    let config = owned_config(&store);
    let found = discover_with(&store, &config, &FakeReader::unlocked());
    let outcomes = pass(&store, &server, found, Setup::new(&server));

    usage.assert_calls(1);

    let row = owned_row(&outcomes);
    let credits = &row.usage.as_ref().expect("the fetch succeeded").credits;
    assert_eq!(
        *credits,
        CreditsState::On(Credits {
            used: Some(Money { amount_minor: 21_956, currency: "USD".to_owned(), exponent: 2 }),
            limit: Some(Money { amount_minor: 500_000, currency: "USD".to_owned(), exponent: 2 }),
            percent: Some(4),
        })
    );

    let report = Report {
        rows: outcomes.iter().map(RowOutcome::to_status_row).collect(),
        now: Timestamp::now(),
        show_all: false,
    };
    let rendered = table::render(&report);
    assert!(rendered.contains("$219.56 / $5000.00 (4%)"), "got:\n{rendered}");
}

#[test]
fn a_keychain_that_cannot_be_read_never_falls_through_to_a_file() {
    // Invariant I10: a locked keychain is a transient answer, not a reason to
    // read some other store. The row says `keychain locked`, not `needs login`.
    let store = store();
    let server = MockServer::start();
    let usage = usage_ok(&server);

    let reader = FakeReader::unlocked().with_preflight(KeychainStatus::Locked);
    let found = discover_with(&store, &AgentctlConfig::default(), &reader);
    let rows = pass(&store, &server, found, Setup::new(&server));

    assert!(
        matches!(rows[0].state, AccountState::KeychainLocked { .. }),
        "got {:?}",
        rows[0].state
    );
    assert_ne!(rows[0].state, AccountState::NeedsLogin);
    usage.assert_calls(0);
}

#[test]
fn a_cancelled_pass_returns_without_fetching() {
    let store = store();
    let server = MockServer::start();
    let usage = usage_ok(&server);

    write_credential_file(&store, &blob("sk-ant-oat01-a", "sk-ant-ort01-a", fresh_at()));
    let config = owned_config(&store);
    let found = discover_with(&store, &config, &FakeReader::unlocked());

    let shared = Shared {
        paths: Arc::clone(&store.paths),
        client: UsageClient::new(&server.base_url(), "agentctl/test", Duration::from_secs(5)),
        refresher: Arc::new(HttpRefresher::new(server.url(TOKEN_PATH))),
        reader_factory: readers(Vec::new()),
        listing: found.listing,
        fault: Fault::none(),
        options: Options { refresh: false, no_cache: false },
    };

    let cancel = Cancel::new();
    cancel.cancel();
    let outcomes =
        collect(found.rows, &[], shared, &cancel, Instant::now() + Duration::from_secs(5))
            .expect("a cancelled pass is not an error");

    assert!(outcomes.is_empty(), "a cancelled pass starts no work");
    usage.assert_calls(0);
}

// ---------------------------------------------------------------------------
// AC8 on a row whose identifier is not a path segment
// ---------------------------------------------------------------------------

/// The row `import --from keychain` produces for an item that named nobody.
///
/// Its `account_uuid` is the keychain service name, because there was no
/// account UUID to key the record by and a `ConfigDirReadOnly` record never
/// gets a namespace directory for anything to derive a path from. The
/// credential handed in here does carry an identity — an item can gain a
/// `tokenAccount` after it was imported — so the row is readable and fetches
/// like any other.
fn service_keyed_row(service: &str, blob: &str) -> AccountRow {
    let credentials =
        Credentials::parse_blob(blob.as_bytes()).expect("the fixture blob should parse");
    let record = AccountRecord {
        account_uuid: service.to_owned(),
        organization_uuid: crate::config::paths::UNKNOWN_ORG.to_owned(),
        email: Some("other@example.com".to_owned()),
        org_name: None,
        label: None,
        kind: AccountKind::ConfigDirReadOnly {
            dir: PathBuf::from("/elsewhere/.claude"),
            service: service.to_owned(),
            shares_live_dir: false,
        },
        forgotten: false,
        created_at: String::new(),
    };
    AccountRow {
        id: service.to_owned(),
        record,
        state: AccountState::Ok,
        source: Source::Keychain,
        credentials: Some(credentials),
        visible_by_default: true,
        note: None,
    }
}

#[test]
fn ac8_a_row_keyed_by_a_service_name_caches_like_any_other() {
    // The cache file used to be named only for identifiers that were valid
    // path segments, and a keychain service name holds a space — so this row
    // missed the cache on every pass and spent a request against Anthropic
    // each time, for an account agentctl cannot even refresh. Worse, the
    // stale-while-error path AC8 rests on had nothing to fall back to: a 429
    // rendered an empty row rather than the last known numbers.
    let store = store();
    let server = MockServer::start();
    let service = format!("{LIVE_SERVICE}-6cdd6b98");
    let blob = blob("sk-ant-oat01-other", "sk-ant-ort01-other", fresh_at());

    let cache_path = cache::path(&store.paths, &service, crate::config::paths::UNKNOWN_ORG);
    assert_eq!(
        cache_path.parent(),
        Some(store.paths.cache_dir().as_path()),
        "a service name still names a file inside the cache directory"
    );

    // Pass one fetches and fills the cache.
    let mut ok = usage_ok(&server);
    let rows = pass(
        &store,
        &server,
        crate::provider::claude::discovery::Discovery {
            rows: vec![service_keyed_row(&service, &blob)],
            preflight: KeychainStatus::Unlocked,
            listing: Vec::new(),
        },
        Setup::new(&server),
    );
    assert_eq!(rows[0].state, AccountState::Ok);
    ok.assert_calls(1);
    ok.delete();
    assert!(cache_path.is_file(), "the entry was written: {}", cache_path.display());

    // Pass two meets a 429 and must render what pass one cached.
    let limited = server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(429).header("retry-after", "30").body("{}");
    });
    let mut setup = Setup::new(&server);
    setup.options.refresh = true;
    let rows = pass(
        &store,
        &server,
        crate::provider::claude::discovery::Discovery {
            rows: vec![service_keyed_row(&service, &blob)],
            preflight: KeychainStatus::Unlocked,
            listing: Vec::new(),
        },
        setup,
    );

    limited.assert_calls(1);
    assert_eq!(rows[0].state, AccountState::RateLimited { retry_after_s: Some(30) });
    assert_eq!(
        rows[0].usage.as_ref().map(|usage| usage.windows.len()),
        Some(3),
        "the cached numbers are rendered rather than an empty row"
    );
}
