//! Tests for `agctl claude login`.
//!
//! Each of these runs the whole command against a mock token endpoint and a
//! temporary configuration directory, and then asserts on the bytes and modes
//! that reached disk. Nothing here touches the keychain, `~/.claude`, or any
//! path outside its own `TempDir` (invariant I1).
//!
//! The fake terminal reads the `state` back out of the authorize URL it was
//! handed, which is what a real browser does. That is the only way the test
//! can produce a valid paste: the PKCE material is generated inside the
//! command, so a hard-coded `state` would be a mismatch — which is exactly
//! what the mismatch test asks for by overriding it.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use httpmock::Method;
use httpmock::MockServer;
use tempfile::TempDir;

use super::*;
use crate::provider::claude::credentials::CLIENT_ID;
use crate::provider::claude::credentials::DEFAULT_SCOPES;
use crate::secret::namespace_lock;

const ACCOUNT: &str = "11111111-1111-4111-8111-111111111111";
const ORGANIZATION: &str = "22222222-2222-4222-8222-222222222222";

/// A terminal that never blocks and never opens anything.
struct FakeIo {
    /// The authorization code the "browser" hands back.
    code: String,
    /// A `state` to paste instead of the one in the authorize URL.
    forged_state: Option<String>,
    /// The answer to any confirmation, or `None` to behave like a pipe.
    confirm: Option<bool>,
    /// The authorize URL the command offered.
    url: Option<String>,
    /// Everything the command said on standard output.
    said: Vec<String>,
    /// Everything the command said on standard error.
    warned: Vec<String>,
    /// How many confirmations were asked for.
    confirmations: usize,
}

impl FakeIo {
    fn new(code: &str) -> Self {
        Self {
            code: code.to_owned(),
            forged_state: None,
            confirm: Some(true),
            url: None,
            said: Vec::new(),
            warned: Vec::new(),
            confirmations: 0,
        }
    }

    /// The `state` the command put in the authorize URL.
    fn offered_state(&self) -> String {
        let url = self.url.as_deref().expect("the command should have offered a URL");
        let url = url::Url::parse(url).expect("the offered URL should parse");
        url.query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| value.into_owned())
            .expect("the authorize URL should carry a state")
    }
}

impl LoginIo for FakeIo {
    fn tell(&mut self, message: &str) {
        self.said.push(message.to_owned());
    }

    fn warn(&mut self, message: &str) {
        self.warned.push(message.to_owned());
    }

    fn open_browser(&mut self, url: &str) {
        self.url = Some(url.to_owned());
    }

    fn read_line(&mut self, _prompt: &str) -> Result<String, AppError> {
        let state = self.forged_state.clone().unwrap_or_else(|| self.offered_state());
        Ok(format!("{}#{state}\n", self.code))
    }

    fn confirm(&mut self, question: &str) -> Result<bool, AppError> {
        self.confirmations += 1;
        match self.confirm {
            Some(answer) => Ok(answer),
            None => Err(AppError::Config(format!("{question} — standard input is not a terminal"))),
        }
    }
}

/// The body a successful exchange returns, with the identity varied.
fn exchange_response(account: Option<&str>, organization: Option<&str>) -> serde_json::Value {
    let mut body = serde_json::json!({
        "token_type": "Bearer",
        "access_token": "sk-ant-oat01-fake-access",
        "expires_in": 28_800,
        "refresh_token": "sk-ant-ort01-fake-refresh",
        "scope": "user:file_upload user:inference user:mcp_servers user:profile user:sessions:claude_code",
        "token_uuid": "33333333-3333-4333-8333-333333333333",
        "refresh_token_expires_in": 2_377_445,
    });
    if let Some(uuid) = account {
        body["account"] = serde_json::json!({"uuid": uuid, "email_address": "user@example.com"});
    }
    if let Some(uuid) = organization {
        body["organization"] = serde_json::json!({"uuid": uuid, "name": "Example Org"});
    }
    body
}

/// A client pointed at a mock server.
fn client_for(server: &MockServer) -> OauthClient {
    OauthClient::with_endpoints(
        &server.url("/cai/oauth/authorize"),
        &server.url("/v1/oauth/token"),
        &server.url("/api/oauth/profile"),
        "agctl/test",
    )
    .expect("the mock endpoints should parse")
}

/// The mode bits of a path, or `None` when it does not exist.
fn mode_of(path: &std::path::Path) -> Option<u32> {
    std::fs::metadata(path).ok().map(|meta| meta.permissions().mode() & 0o777)
}

/// The stored blob at a namespace, parsed.
fn stored_blob(ns_dir: &std::path::Path) -> serde_json::Value {
    let path = ns_dir.join(file_store::CREDENTIALS_FILE);
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|err| panic!("`{}` should be readable: {err}", path.display()));
    serde_json::from_slice(&bytes).expect("the stored blob should be JSON")
}

#[test]
fn a_manual_login_writes_the_f40_blob_and_records_an_owned_account() {
    // AC12, in one pass: the directory and file modes, the blob shape, the
    // scopes, the derived expiry, the `Owned` record, and the fact that the
    // write happened while this process held the namespace lock.
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(Method::POST).path("/v1/oauth/token").json_body_includes(
            serde_json::json!({
                "grant_type": "authorization_code",
                "code": "CODE-A",
                "client_id": CLIENT_ID,
                "redirect_uri": crate::provider::claude::oauth::MANUAL_REDIRECT_URI,
            })
            .to_string(),
        );
        then.status(200).json_body(exchange_response(Some(ACCOUNT), Some(ORGANIZATION)));
    });

    let home = TempDir::new().expect("a temporary directory should be creatable");
    let paths = Paths::with_config_dir(home.path().to_path_buf());
    let cancel = Cancel::new();
    let login = Login {
        paths: &paths,
        manual: true,
        label: Some("work"),
        live_identity: None,
        live_identity_source: PathBuf::new(),
        no_duplicate: false,
        cancel: &cancel,
    };
    let mut io = FakeIo::new("CODE-A");

    let before_ms = jiff::Timestamp::now().as_millisecond();
    run_with(&login, &client_for(&server), &mut io).expect("the login should succeed");
    let after_ms = jiff::Timestamp::now().as_millisecond();

    mock.assert();

    let ns_dir = paths.namespace_dir(ACCOUNT, ORGANIZATION);
    assert_eq!(mode_of(&ns_dir), Some(0o700), "namespace directories are 0700");
    assert_eq!(
        mode_of(&ns_dir.join(file_store::CREDENTIALS_FILE)),
        Some(0o600),
        "credential files are 0600"
    );

    let blob = stored_blob(&ns_dir);
    let inner = &blob["claudeAiOauth"];
    assert_eq!(inner["accessToken"], serde_json::json!("sk-ant-oat01-fake-access"));
    assert_eq!(inner["refreshToken"], serde_json::json!("sk-ant-ort01-fake-refresh"));
    assert_eq!(
        inner["scopes"],
        serde_json::json!(DEFAULT_SCOPES.iter().collect::<Vec<_>>()),
        "the F4 five, as granted"
    );
    assert_eq!(inner["clientId"], serde_json::json!(CLIENT_ID));
    assert_eq!(inner["tokenAccount"]["uuid"], serde_json::json!(ACCOUNT));
    assert_eq!(inner["tokenAccount"]["organizationUuid"], serde_json::json!(ORGANIZATION));

    let expires_at = inner["expiresAt"].as_i64().expect("expiresAt should be a number");
    assert!(
        (before_ms + 28_800_000..=after_ms + 28_800_000).contains(&expires_at),
        "expiresAt should be now + expires_in*1000, got {expires_at}"
    );

    let config = AgctlConfig::load(&paths).expect("the config should load");
    let record = config.get(ACCOUNT, ORGANIZATION).expect("the account should be recorded");
    assert_eq!(record.label.as_deref(), Some("work"));
    assert_eq!(record.email.as_deref(), Some("user@example.com"));
    assert_eq!(record.org_name.as_deref(), Some("Example Org"));
    match &record.kind {
        AccountKind::Owned { export_spelling, export_sha8 } => {
            assert_eq!(PathBuf::from(export_spelling), ns_dir);
            assert_eq!(*export_sha8, namespace::sha8(export_spelling));
        }
        other => panic!("a login must record an owned account, got {other:?}"),
    }

    // The lock file is never unlinked, so its body is still the record of who
    // last held it — this process, during the write above.
    let body = namespace_lock::read_body(&paths.lock_path(ACCOUNT, ORGANIZATION))
        .expect("the lock body should be readable");
    assert_eq!(body.pid, std::process::id());

    // Nothing left behind.
    assert!(!ns_dir.join(file_store::PENDING_FILE).exists());
    assert!(!ns_dir.join(file_store::PENDING_META).exists());
    assert!(
        file_store::list_stray_tmp(&ns_dir).expect("the namespace should be listable").is_empty()
    );
}

#[test]
fn a_login_without_an_organization_lands_in_the_unknown_org_namespace() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(Method::POST).path("/v1/oauth/token");
        then.status(200).json_body(exchange_response(Some(ACCOUNT), None));
    });
    // The profile fallback is only consulted when the account itself is
    // unknown, so this must not reach it.
    let profile = server.mock(|when, then| {
        when.method(Method::GET).path("/api/oauth/profile");
        then.status(500);
    });

    let home = TempDir::new().expect("a temporary directory should be creatable");
    let paths = Paths::with_config_dir(home.path().to_path_buf());
    let cancel = Cancel::new();
    let login = Login {
        paths: &paths,
        manual: true,
        label: None,
        live_identity: None,
        live_identity_source: PathBuf::new(),
        no_duplicate: false,
        cancel: &cancel,
    };

    run_with(&login, &client_for(&server), &mut FakeIo::new("CODE-A"))
        .expect("the login should succeed");

    assert_eq!(profile.calls(), 0);
    let ns_dir = paths.namespace_dir(ACCOUNT, UNKNOWN_ORG);
    assert_eq!(mode_of(&ns_dir.join(file_store::CREDENTIALS_FILE)), Some(0o600));

    let config = AgctlConfig::load(&paths).expect("the config should load");
    assert!(config.get(ACCOUNT, UNKNOWN_ORG).is_some(), "the placeholder org is the record key");
}

#[test]
fn an_identity_the_exchange_omits_is_recovered_from_the_profile() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(Method::POST).path("/v1/oauth/token");
        then.status(200).json_body(exchange_response(None, None));
    });
    let profile = server.mock(|when, then| {
        when.method(Method::GET)
            .path("/api/oauth/profile")
            .header("authorization", "Bearer sk-ant-oat01-fake-access");
        then.status(200).json_body(serde_json::json!({
            "account": {"uuid": ACCOUNT, "email_address": "fallback@example.com"},
            "organization": {"uuid": ORGANIZATION, "name": "Fallback Org"},
        }));
    });

    let home = TempDir::new().expect("a temporary directory should be creatable");
    let paths = Paths::with_config_dir(home.path().to_path_buf());
    let cancel = Cancel::new();
    let login = Login {
        paths: &paths,
        manual: true,
        label: None,
        live_identity: None,
        live_identity_source: PathBuf::new(),
        no_duplicate: false,
        cancel: &cancel,
    };

    run_with(&login, &client_for(&server), &mut FakeIo::new("CODE-A"))
        .expect("the login should succeed");

    profile.assert();
    let config = AgctlConfig::load(&paths).expect("the config should load");
    let record = config.get(ACCOUNT, ORGANIZATION).expect("the profile should have named it");
    assert_eq!(record.email.as_deref(), Some("fallback@example.com"));
    assert_eq!(record.org_name.as_deref(), Some("Fallback Org"));
}

#[test]
fn a_login_whose_identity_stays_unknown_writes_nothing() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(Method::POST).path("/v1/oauth/token");
        then.status(200).json_body(exchange_response(None, None));
    });
    server.mock(|when, then| {
        when.method(Method::GET).path("/api/oauth/profile");
        then.status(401).body("no");
    });

    let home = TempDir::new().expect("a temporary directory should be creatable");
    let paths = Paths::with_config_dir(home.path().to_path_buf());
    let cancel = Cancel::new();
    let login = Login {
        paths: &paths,
        manual: true,
        label: None,
        live_identity: None,
        live_identity_source: PathBuf::new(),
        no_duplicate: false,
        cancel: &cancel,
    };

    let err = run_with(&login, &client_for(&server), &mut FakeIo::new("CODE-A"))
        .expect_err("an unidentifiable credential cannot be namespaced");

    assert_eq!(err.exit_code(), crate::error::EXIT_FATAL);
    assert!(!paths.namespace_root().exists(), "nothing should have been created");
    assert!(!paths.config_file().exists());
}

#[test]
fn a_forged_state_is_refused_before_the_exchange_and_writes_nothing() {
    // AC12's last clause. The mismatch is caught locally, so the mock never
    // sees a request and no directory is created.
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(Method::POST).path("/v1/oauth/token");
        then.status(200).json_body(exchange_response(Some(ACCOUNT), Some(ORGANIZATION)));
    });

    let home = TempDir::new().expect("a temporary directory should be creatable");
    let paths = Paths::with_config_dir(home.path().to_path_buf());
    let cancel = Cancel::new();
    let login = Login {
        paths: &paths,
        manual: true,
        label: None,
        live_identity: None,
        live_identity_source: PathBuf::new(),
        no_duplicate: false,
        cancel: &cancel,
    };
    let mut io = FakeIo::new("CODE-A");
    io.forged_state = Some("not-the-state-we-sent".to_owned());

    let err = run_with(&login, &client_for(&server), &mut io)
        .expect_err("a forged state should end the login");

    assert_eq!(mock.calls(), 0, "no code may be exchanged after a state mismatch");
    assert!(err.to_string().contains("state"), "{err}");
    assert!(!paths.namespace_root().exists(), "nothing should have been created");
    assert!(!paths.config_file().exists());
}

#[test]
fn logging_the_same_account_in_twice_asks_first_and_then_overwrites() {
    // AC41's second clause: the overwrite is allowed, but only after a person
    // says so, and it lands in the same namespace rather than a second one.
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(Method::POST).path("/v1/oauth/token");
        then.status(200).json_body(exchange_response(Some(ACCOUNT), Some(ORGANIZATION)));
    });

    let home = TempDir::new().expect("a temporary directory should be creatable");
    let paths = Paths::with_config_dir(home.path().to_path_buf());
    let cancel = Cancel::new();
    let client = client_for(&server);

    let first = Login {
        paths: &paths,
        manual: true,
        label: Some("first"),
        live_identity: None,
        live_identity_source: PathBuf::new(),
        no_duplicate: false,
        cancel: &cancel,
    };
    let mut io = FakeIo::new("CODE-A");
    run_with(&first, &client, &mut io).expect("the first login should succeed");
    assert_eq!(io.confirmations, 0, "a fresh account needs no confirmation");

    let second = Login {
        paths: &paths,
        manual: true,
        label: Some("second"),
        live_identity: None,
        live_identity_source: PathBuf::new(),
        no_duplicate: false,
        cancel: &cancel,
    };
    let mut io = FakeIo::new("CODE-A");
    run_with(&second, &client, &mut io).expect("the confirmed overwrite should succeed");
    assert_eq!(io.confirmations, 1, "an existing account must be confirmed over");

    let config = AgctlConfig::load(&paths).expect("the config should load");
    assert_eq!(config.accounts.len(), 1, "an overwrite replaces the record rather than adding one");
    assert_eq!(
        config.get(ACCOUNT, ORGANIZATION).and_then(|rec| rec.label.as_deref()),
        Some("second")
    );
}

#[test]
fn a_declined_confirmation_leaves_the_stored_credentials_alone() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(Method::POST).path("/v1/oauth/token");
        then.status(200).json_body(exchange_response(Some(ACCOUNT), Some(ORGANIZATION)));
    });

    let home = TempDir::new().expect("a temporary directory should be creatable");
    let paths = Paths::with_config_dir(home.path().to_path_buf());
    let cancel = Cancel::new();
    let client = client_for(&server);
    let login = Login {
        paths: &paths,
        manual: true,
        label: Some("first"),
        live_identity: None,
        live_identity_source: PathBuf::new(),
        no_duplicate: false,
        cancel: &cancel,
    };

    run_with(&login, &client, &mut FakeIo::new("CODE-A")).expect("the first login should succeed");
    let ns_dir = paths.namespace_dir(ACCOUNT, ORGANIZATION);
    let before = stored_blob(&ns_dir);

    let mut io = FakeIo::new("CODE-A");
    io.confirm = Some(false);
    let declined = Login {
        paths: &paths,
        manual: true,
        label: Some("second"),
        live_identity: None,
        live_identity_source: PathBuf::new(),
        no_duplicate: false,
        cancel: &cancel,
    };
    let err = run_with(&declined, &client, &mut io).expect_err("a declined login should not write");

    assert_eq!(err.exit_code(), crate::error::EXIT_FATAL);
    assert_eq!(stored_blob(&ns_dir), before, "the stored blob must be untouched");
    let config = AgctlConfig::load(&paths).expect("the config should load");
    assert_eq!(
        config.get(ACCOUNT, ORGANIZATION).and_then(|rec| rec.label.as_deref()),
        Some("first")
    );
}

#[test]
fn a_non_interactive_overwrite_is_refused_with_a_fatal_status() {
    // There is no `--yes` on `login` in phase 1, so a pipe cannot answer the
    // question and the command must refuse rather than assume.
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(Method::POST).path("/v1/oauth/token");
        then.status(200).json_body(exchange_response(Some(ACCOUNT), Some(ORGANIZATION)));
    });

    let home = TempDir::new().expect("a temporary directory should be creatable");
    let paths = Paths::with_config_dir(home.path().to_path_buf());
    let cancel = Cancel::new();
    let client = client_for(&server);
    let login = Login {
        paths: &paths,
        manual: true,
        label: None,
        live_identity: None,
        live_identity_source: PathBuf::new(),
        no_duplicate: false,
        cancel: &cancel,
    };

    run_with(&login, &client, &mut FakeIo::new("CODE-A")).expect("the first login should succeed");

    let mut io = FakeIo::new("CODE-A");
    io.confirm = None;
    let err = run_with(&login, &client, &mut io).expect_err("a pipe cannot confirm an overwrite");

    assert_eq!(err.exit_code(), crate::error::EXIT_FATAL);
    assert!(err.to_string().contains("terminal"), "{err}");
}

#[test]
fn the_same_account_in_two_organizations_gets_sibling_namespaces() {
    // AC41's first clause, and the reason the namespace key is the pair
    // rather than the account alone (decision D-008).
    const OTHER_ORG: &str = "44444444-4444-4444-8444-444444444444";

    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(Method::POST)
            .path("/v1/oauth/token")
            .json_body_includes(serde_json::json!({"code": "CODE-A"}).to_string());
        then.status(200).json_body(exchange_response(Some(ACCOUNT), Some(ORGANIZATION)));
    });
    server.mock(|when, then| {
        when.method(Method::POST)
            .path("/v1/oauth/token")
            .json_body_includes(serde_json::json!({"code": "CODE-B"}).to_string());
        then.status(200).json_body(exchange_response(Some(ACCOUNT), Some(OTHER_ORG)));
    });

    let home = TempDir::new().expect("a temporary directory should be creatable");
    let paths = Paths::with_config_dir(home.path().to_path_buf());
    let cancel = Cancel::new();
    let client = client_for(&server);
    let login = Login {
        paths: &paths,
        manual: true,
        label: None,
        live_identity: None,
        live_identity_source: PathBuf::new(),
        no_duplicate: false,
        cancel: &cancel,
    };

    let mut first = FakeIo::new("CODE-A");
    run_with(&login, &client, &mut first).expect("the first login should succeed");
    let mut second = FakeIo::new("CODE-B");
    run_with(&login, &client, &mut second).expect("the second login should succeed");

    assert_eq!(second.confirmations, 0, "a different organization is a different account");
    assert!(paths.namespace_dir(ACCOUNT, ORGANIZATION).join(file_store::CREDENTIALS_FILE).exists());
    assert!(paths.namespace_dir(ACCOUNT, OTHER_ORG).join(file_store::CREDENTIALS_FILE).exists());

    let config = AgctlConfig::load(&paths).expect("the config should load");
    assert_eq!(config.accounts.len(), 2);
}

#[test]
fn a_rejected_code_ends_the_login_without_creating_anything() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(Method::POST).path("/v1/oauth/token");
        then.status(400).json_body(serde_json::json!({"error": "invalid_grant"}));
    });

    let home = TempDir::new().expect("a temporary directory should be creatable");
    let paths = Paths::with_config_dir(home.path().to_path_buf());
    let cancel = Cancel::new();
    let login = Login {
        paths: &paths,
        manual: true,
        label: None,
        live_identity: None,
        live_identity_source: PathBuf::new(),
        no_duplicate: false,
        cancel: &cancel,
    };

    let err = run_with(&login, &client_for(&server), &mut FakeIo::new("CODE-A"))
        .expect_err("a rejected code should end the login");

    assert_eq!(err.exit_code(), crate::error::EXIT_FATAL);
    assert!(err.to_string().contains("invalid_grant"), "{err}");
    assert!(!paths.namespace_root().exists());
}

#[test]
fn a_superseded_pending_file_is_cleared_before_the_write() {
    // Invariant I9: the pending file describes credentials this login has just
    // replaced, and a stray temporary file is token material at rest (R24).
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(Method::POST).path("/v1/oauth/token");
        then.status(200).json_body(exchange_response(Some(ACCOUNT), Some(ORGANIZATION)));
    });

    let home = TempDir::new().expect("a temporary directory should be creatable");
    let paths = Paths::with_config_dir(home.path().to_path_buf());
    let ns_dir = paths.namespace_dir(ACCOUNT, ORGANIZATION);
    std::fs::create_dir_all(&ns_dir).expect("the namespace should be creatable");
    std::fs::write(ns_dir.join(file_store::PENDING_FILE), b"{}")
        .expect("pending should be writable");
    std::fs::write(ns_dir.join(file_store::PENDING_META), b"{}").expect("meta should be writable");
    let stray = ns_dir.join(format!("{}.tmp.deadbeef", file_store::CREDENTIALS_FILE));
    std::fs::write(&stray, b"leftover").expect("the stray file should be writable");

    let cancel = Cancel::new();
    let login = Login {
        paths: &paths,
        manual: true,
        label: None,
        live_identity: None,
        live_identity_source: PathBuf::new(),
        no_duplicate: false,
        cancel: &cancel,
    };
    run_with(&login, &client_for(&server), &mut FakeIo::new("CODE-A"))
        .expect("the login should succeed");

    assert!(!ns_dir.join(file_store::PENDING_FILE).exists());
    assert!(!ns_dir.join(file_store::PENDING_META).exists());
    assert!(!stray.exists());
    assert_eq!(mode_of(&ns_dir.join(file_store::CREDENTIALS_FILE)), Some(0o600));
}

#[test]
fn the_login_prints_the_authorize_url_it_wants_opened() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(Method::POST).path("/v1/oauth/token");
        then.status(200).json_body(exchange_response(Some(ACCOUNT), Some(ORGANIZATION)));
    });

    let home = TempDir::new().expect("a temporary directory should be creatable");
    let paths = Paths::with_config_dir(home.path().to_path_buf());
    let cancel = Cancel::new();
    let login = Login {
        paths: &paths,
        manual: true,
        label: None,
        live_identity: None,
        live_identity_source: PathBuf::new(),
        no_duplicate: false,
        cancel: &cancel,
    };
    let mut io = FakeIo::new("CODE-A");

    run_with(&login, &client_for(&server), &mut io).expect("the login should succeed");

    let offered = io.url.clone().expect("the URL should have been offered to a browser");
    assert!(io.said.iter().any(|line| line.contains(&offered)), "the URL must be printed too");
    assert!(offered.contains("code_challenge_method=S256"), "{offered}");
    assert!(io.said.iter().any(|line| line.contains("Logged in as user@example.com")));
}

#[test]
fn a_profile_document_without_an_identity_changes_nothing() {
    let mut credentials = crate::provider::claude::oauth::to_credentials(
        crate::provider::claude::oauth::TokenResponse {
            access_token: secrecy::SecretString::from("access"),
            refresh_token: None,
            expires_in: 60,
            refresh_token_expires_in: None,
            scope: None,
            token_type: None,
            account: None,
            organization: None,
            workspace: None,
        },
        0,
        &[],
    )
    .expect("the response should convert");

    apply_profile(&mut credentials, &serde_json::json!({"unrelated": true}));
    assert!(credentials.token_account.is_none(), "an empty profile must not invent an identity");

    apply_profile(&mut credentials, &serde_json::json!({"uuid": "flat-account"}));
    assert_eq!(
        credentials.token_account.and_then(|account| account.uuid).as_deref(),
        Some("flat-account"),
        "a flat document is accepted too, since the shape was never captured"
    );
}

// ---------------------------------------------------------------------------
// `same identity as live` (`agctl-p3-login-live-identity-warning-b90`)
// ---------------------------------------------------------------------------

/// The live identity a test declares, without touching the environment.
fn live(account_uuid: &str, organization_uuid: Option<&str>) -> Identity {
    Identity {
        account_uuid: account_uuid.to_owned(),
        organization_uuid: organization_uuid.map(str::to_owned),
        email: Some("user@example.com".to_owned()),
        org_name: None,
    }
}

/// Runs one manual login against a mock exchange and returns the terminal.
fn login_with_live(paths: &Paths, live_identity: Option<Identity>, server: &MockServer) -> FakeIo {
    let (io, outcome) = try_login_with_live(paths, live_identity, false, server);
    outcome.expect("the login should succeed");
    io
}

/// The same, with `--no-duplicate` selectable and the failure handed back
/// rather than unwrapped.
fn try_login_with_live(
    paths: &Paths,
    live_identity: Option<Identity>,
    no_duplicate: bool,
    server: &MockServer,
) -> (FakeIo, Result<(), AppError>) {
    let cancel = Cancel::new();
    let login = Login {
        paths,
        manual: true,
        label: None,
        live_identity,
        // A path that does not exist on this machine, on purpose: the refusal
        // must name where it looked, and it must name it without having
        // opened it (the reading happened in `run`, not here).
        live_identity_source: PathBuf::from("/fixture/home/.claude.json"),
        no_duplicate,
        cancel: &cancel,
    };
    let mut io = FakeIo::new("CODE-LIVE");
    let outcome = run_with(&login, &client_for(server), &mut io);
    (io, outcome)
}

#[test]
fn b90_a_login_into_the_live_account_says_so_and_completes_anyway() {
    // `agctl-p3-login-live-identity-warning-b90` (login notices when the
    // new identity is the live one's). Decision D-011: a second independent
    // token pair for one account is a supported `use --new-only` setup, so
    // the default is a sentence, not a refusal — the credential is written
    // and the record recorded exactly as they would have been.
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(Method::POST).path("/v1/oauth/token");
        then.status(200).json_body(exchange_response(Some(ACCOUNT), Some(ORGANIZATION)));
    });

    let home = TempDir::new().expect("a temporary directory should be creatable");
    let paths = Paths::with_config_dir(home.path().to_path_buf());
    let io = login_with_live(&paths, Some(live(ACCOUNT, Some(ORGANIZATION))), &server);

    mock.assert();
    let notice = io
        .warned
        .iter()
        .find(|line| line.contains("Claude Code is signed in as"))
        .unwrap_or_else(|| panic!("the notice should have been printed: {:?}", io.warned));
    assert!(notice.contains(ACCOUNT), "the notice names the account: {notice}");
    assert!(notice.contains("both stay valid"), "it says nothing broke: {notice}");
    assert!(notice.contains("use --live"), "it names the command for a swap: {notice}");
    assert!(!notice.contains("sk-ant-"), "no token material reaches the notice: {notice}");
    assert!(
        io.said.iter().all(|line| !line.contains("Claude Code is signed in as")),
        "the notice is not on standard output: {:?}",
        io.said
    );

    // And the login itself is untouched by it.
    let ns_dir = paths.namespace_dir(ACCOUNT, ORGANIZATION);
    assert!(ns_dir.join(file_store::CREDENTIALS_FILE).is_file(), "the credential was written");
    assert!(
        AgctlConfig::load(&paths)
            .expect("the registry should load")
            .get(ACCOUNT, ORGANIZATION)
            .is_some(),
        "the account was recorded"
    );
}

#[test]
fn b90_a_login_into_a_different_account_says_nothing() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(Method::POST).path("/v1/oauth/token");
        then.status(200).json_body(exchange_response(Some(ACCOUNT), Some(ORGANIZATION)));
    });

    let home = TempDir::new().expect("a temporary directory should be creatable");
    let paths = Paths::with_config_dir(home.path().to_path_buf());

    // Same organization, different account.
    let other = login_with_live(
        &paths,
        Some(live("99999999-9999-4999-8999-999999999999", Some(ORGANIZATION))),
        &server,
    );
    assert!(other.warned.is_empty(), "a different account is not a twin: {:?}", other.warned);

    // Nothing at all says who is live.
    let unknown = login_with_live(&paths, None, &server);
    assert!(
        unknown.warned.is_empty(),
        "an unknown live account is not a match: {:?}",
        unknown.warned
    );
}

#[test]
fn b90_an_organization_less_identity_matches_the_unknown_org_the_store_uses() {
    // A blob that named no organization is stored under `_unknown-org`, and
    // the comparison has to make the same substitution or the two halves of
    // one account would never line up. The reverse — a live account with an
    // organization against a login without one — must still not match.
    assert!(is_live_identity(Some(&live(ACCOUNT, None)), ACCOUNT, UNKNOWN_ORG));
    assert!(is_live_identity(Some(&live(ACCOUNT, Some(ORGANIZATION))), ACCOUNT, ORGANIZATION));
    assert!(!is_live_identity(Some(&live(ACCOUNT, Some(ORGANIZATION))), ACCOUNT, UNKNOWN_ORG));
    assert!(!is_live_identity(Some(&live(ACCOUNT, None)), ACCOUNT, ORGANIZATION));
    assert!(!is_live_identity(Some(&live(ACCOUNT, None)), ORGANIZATION, UNKNOWN_ORG));
    assert!(!is_live_identity(None, ACCOUNT, ORGANIZATION), "nothing known matches nothing");
}

// ---------------------------------------------------------------------------
// `--no-duplicate` (`agctl-3m0`)
// ---------------------------------------------------------------------------

/// Everything under a store's namespace root, recursively, by relative path.
///
/// "No store was written" is a claim about the whole tree, not about one file:
/// a directory created and left empty would satisfy a check for
/// `.credentials.json` alone and would still be a change to the machine.
fn namespace_tree(paths: &Paths) -> Vec<String> {
    fn walk(dir: &std::path::Path, root: &std::path::Path, found: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if let Ok(relative) = path.strip_prefix(root) {
                found.push(relative.to_string_lossy().into_owned());
            }
            if path.is_dir() {
                walk(&path, root, found);
            }
        }
    }
    let root = paths.namespace_dir(ACCOUNT, ORGANIZATION);
    let root = root.parent().and_then(std::path::Path::parent).map(std::path::Path::to_path_buf);
    let Some(root) = root else { return Vec::new() };
    let mut found = Vec::new();
    walk(&root, &root, &mut found);
    found.sort();
    found
}

#[test]
fn m3m0_no_duplicate_refuses_the_live_account_and_writes_nothing() {
    // `agctl-3m0`: the opt-in refusal. It happens before `ensure_dirs`,
    // before the namespace lock and before any store or registry write, so a
    // refused login leaves the machine exactly as it found it.
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(Method::POST).path("/v1/oauth/token");
        then.status(200).json_body(exchange_response(Some(ACCOUNT), Some(ORGANIZATION)));
    });

    let home = TempDir::new().expect("a temporary directory should be creatable");
    let paths = Paths::with_config_dir(home.path().to_path_buf());
    let before = namespace_tree(&paths);

    let (io, outcome) =
        try_login_with_live(&paths, Some(live(ACCOUNT, Some(ORGANIZATION))), true, &server);

    mock.assert();
    let err = outcome.expect_err("`--no-duplicate` should refuse");

    // The exit code is the one `accounts.rs` writes down for exactly this
    // shape: a command that refuses and renders nothing is `Config`, so it
    // exits 1. Exit 2 is reserved for a run that produced a table with a
    // degraded row in it, and a refused login produces no table.
    assert!(matches!(err, AppError::Config(_)), "unexpected variant: {err:?}");
    assert_eq!(err.exit_code(), crate::error::EXIT_FATAL);

    let message = err.to_string();
    assert!(message.contains(ACCOUNT), "it names the account: {message}");
    assert!(message.contains(".claude.json"), "it names where it looked: {message}");
    assert!(message.contains("/fixture/home/"), "by resolved path, not by guess: {message}");
    assert!(message.contains("use --live"), "it names the swap: {message}");
    assert!(message.contains("without `--no-duplicate`"), "and the escape: {message}");
    assert!(!message.contains("sk-ant-"), "no token material reaches it: {message}");

    // Nothing was written, and nothing was said either: a refusal is not also
    // a notice.
    assert_eq!(namespace_tree(&paths), before, "the store is untouched");
    assert!(!paths.config_file().exists(), "no registry was created");
    assert!(io.warned.is_empty(), "the refusal replaces the notice: {:?}", io.warned);
    assert_eq!(io.confirmations, 0, "and it refuses before asking anything");
}

#[test]
fn m3m0_no_duplicate_is_inert_for_any_other_account() {
    // The flag is a refusal of one specific coincidence, not a mode. A login
    // into a different account proceeds exactly as it would without it.
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(Method::POST).path("/v1/oauth/token");
        then.status(200).json_body(exchange_response(Some(ACCOUNT), Some(ORGANIZATION)));
    });

    let home = TempDir::new().expect("a temporary directory should be creatable");
    let paths = Paths::with_config_dir(home.path().to_path_buf());
    let live_elsewhere = live("99999999-9999-4999-8999-999999999999", Some(ORGANIZATION));

    let (io, outcome) = try_login_with_live(&paths, Some(live_elsewhere), true, &server);
    outcome.expect("a different account is not a duplicate");

    assert!(io.warned.is_empty(), "and there is nothing to notice either: {:?}", io.warned);
    assert!(
        paths.namespace_dir(ACCOUNT, ORGANIZATION).join(file_store::CREDENTIALS_FILE).is_file(),
        "the credential was written"
    );
    let config = AgctlConfig::load(&paths).expect("the registry should load");
    assert!(config.get(ACCOUNT, ORGANIZATION).is_some(), "and the account recorded");
}

#[test]
fn m3m0_without_the_flag_the_same_login_is_a_notice_and_not_a_refusal() {
    // The default is unchanged by `agctl-3m0`: decision D-011 says a second
    // independent session of one account is a supported setup, so the opt-in
    // is what says "not this time".
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(Method::POST).path("/v1/oauth/token");
        then.status(200).json_body(exchange_response(Some(ACCOUNT), Some(ORGANIZATION)));
    });

    let home = TempDir::new().expect("a temporary directory should be creatable");
    let paths = Paths::with_config_dir(home.path().to_path_buf());

    let (io, outcome) =
        try_login_with_live(&paths, Some(live(ACCOUNT, Some(ORGANIZATION))), false, &server);
    outcome.expect("the default path completes");

    assert_eq!(io.warned.len(), 1, "one notice: {:?}", io.warned);
    assert!(io.warned[0].contains("both stay valid"), "got: {}", io.warned[0]);
    assert!(
        !io.warned[0].contains("--no-duplicate"),
        "the notice does not advertise the flag as a fix: {}",
        io.warned[0]
    );
    assert!(
        paths.namespace_dir(ACCOUNT, ORGANIZATION).join(file_store::CREDENTIALS_FILE).is_file(),
        "and the credential was written"
    );
}
