#![cfg(feature = "testing")]

//! `agentctl claude login`, driven through the real binary.
//!
//! A login is the one command that mints a credential, so these tests are the
//! ones that watch bytes arrive on disk: the namespace directory's mode, the
//! file's mode, the blob's shape, and the registry record that points at it.
//!
//! # How a test can complete a real PKCE login
//!
//! The `state` is generated inside the process and checked against what comes
//! back, so nothing outside can guess it — but `login` prints it, in the URL it
//! asks the user to open. [`common::start_login`] reads that line back off
//! stdout and pastes a matching `code#state`, which is exactly the sequence a
//! person performs. The wrong-state test does the same thing with the wrong
//! half, and asserts that nothing at all was written.

mod common;

use std::fs;
use std::time::Duration;

use common::Fixture;
use httpmock::Method::POST;
use httpmock::Mock;
use httpmock::MockServer;
use serde_json::Value;
use serde_json::json;

/// The account the mock exchange names.
const EXCHANGE_ACCT: &str = "11111111-1111-4111-8111-111111111111";

/// The organization it names.
const EXCHANGE_ORG: &str = "22222222-2222-4222-8222-222222222222";

/// How long the access token the mock mints lasts (fact F25).
const EXPIRES_IN: i64 = 28_800;

/// The scope set agentctl asks for (fact F4, F28).
const SCOPES: &str =
    "user:file_upload user:inference user:mcp_servers user:profile user:sessions:claude_code";

/// The mock exchange, answering with the shape fact F25 records.
fn exchange<'a>(server: &'a MockServer, organization: Option<&str>) -> Mock<'a> {
    let mut body = json!({
        "token_type": "Bearer",
        "access_token": "sk-ant-oat01-minted",
        "refresh_token": "sk-ant-ort01-minted",
        "expires_in": EXPIRES_IN,
        "refresh_token_expires_in": 2_377_445,
        "scope": SCOPES,
        "account": { "uuid": EXCHANGE_ACCT, "email_address": "user@example.com" },
    });
    if let Some(uuid) = organization {
        body["organization"] = json!({ "uuid": uuid, "name": "Example Org" });
    }
    server.mock(|when, then| {
        when.method(POST).path(common::TOKEN_PATH);
        then.status(200).json_body(body);
    })
}

/// The registry, parsed.
fn registry(fixture: &Fixture) -> Value {
    let text = fs::read_to_string(fixture.config_file()).expect("the registry should exist");
    serde_json::from_str(&text).expect("the registry should be JSON")
}

#[test]
fn ac12_a_manual_login_writes_the_namespace_it_was_told_to() {
    // Plan AC12, decisions D-008 and D-009: the credential lands at
    // `<config>/claude/<acct>/<org>/.credentials.json`, 0600 inside 0700, in
    // Claude Code's own blob shape (fact F40) so phase 2 can point a session
    // at the directory without converting anything.
    let server = MockServer::start();
    let token = exchange(&server, Some(EXCHANGE_ORG));

    let mut fixture = Fixture::new();
    fixture.endpoints(&server.base_url());

    let mut session = common::start_login(&fixture, &[], &[]);
    assert!(session.url.contains("code_challenge="), "PKCE S256: {}", session.url);
    let state = session.state.clone();
    session.paste(&format!("minted-code#{state}"));
    let finished = session.finish();

    assert_eq!(finished.code(), 0, "stderr:\n{}", finished.stderr);
    assert!(finished.stdout.contains("Logged in as user@example.com"), "{}", finished.stdout);
    assert_eq!(token.calls(), 1, "one exchange, and no retry of it");

    let ns_dir = fixture.ns_dir(EXCHANGE_ACCT, EXCHANGE_ORG);
    let path = ns_dir.join(".credentials.json");
    assert_eq!(common::mode_of(&ns_dir), 0o700, "the namespace directory is private");
    assert_eq!(common::mode_of(&path), 0o600, "and so is the credential");

    let stored: Value = serde_json::from_str(
        &fs::read_to_string(&path).expect("the credential file should be readable"),
    )
    .expect("the credential file is JSON");
    let blob = &stored["claudeAiOauth"];
    assert_eq!(blob["accessToken"], json!("sk-ant-oat01-minted"));
    assert_eq!(blob["refreshToken"], json!("sk-ant-ort01-minted"));
    assert_eq!(
        blob["scopes"],
        json!(SCOPES.split(' ').collect::<Vec<_>>()),
        "the F4 scope set is stored as it was granted"
    );

    // `expiresAt = now + expires_in * 1000` (fact F8). The window is generous
    // on purpose: the clock the test reads is not the one the binary read.
    let expires_at = blob["expiresAt"].as_i64().expect("`expiresAt` is a number");
    let expected = common::now_ms() + EXPIRES_IN * 1000;
    assert!(
        (expires_at - expected).abs() < 60_000,
        "expiresAt {expires_at} should be about {expected}"
    );

    let config = registry(&fixture);
    let record = &config["accounts"][0];
    assert_eq!(record["account_uuid"], json!(EXCHANGE_ACCT));
    assert_eq!(record["organization_uuid"], json!(EXCHANGE_ORG));
    assert_eq!(record["kind"]["kind"], json!("owned"));
    let spelling = common::export_spelling(&ns_dir);
    assert_eq!(record["kind"]["export_spelling"], json!(spelling));
    assert_eq!(
        record["kind"]["export_sha8"],
        json!(common::sha8(&spelling)),
        "the recorded hash is the service name a session pointed here would migrate to (fact F35)"
    );

    // The lock file is created by `namespace_lock::acquire` and never
    // unlinked, so its existence is the observable trace — from outside the
    // process — that the write happened under the lock (invariant I3).
    assert!(
        fixture.lock_path(EXCHANGE_ACCT, EXCHANGE_ORG).exists(),
        "the namespace lock was taken for the write"
    );
}

#[test]
fn ac12_a_login_without_an_organization_uses_the_unknown_org_directory() {
    // Plan AC12 and decision D-008: an exchange that names no organization
    // still produces a usable account, in a directory `accounts relocate` can
    // move once the organization is known.
    let server = MockServer::start();
    let _token = exchange(&server, None);

    let mut fixture = Fixture::new();
    fixture.endpoints(&server.base_url());

    let mut session = common::start_login(&fixture, &[], &[]);
    let state = session.state.clone();
    session.paste(&format!("minted-code#{state}"));
    let finished = session.finish();

    assert_eq!(finished.code(), 0, "stderr:\n{}", finished.stderr);
    assert!(
        fixture.ns_dir(EXCHANGE_ACCT, common::UNKNOWN_ORG).join(".credentials.json").exists(),
        "the credential went to the `_unknown-org` namespace"
    );
    assert_eq!(registry(&fixture)["accounts"][0]["organization_uuid"], json!(common::UNKNOWN_ORG));
}

#[test]
fn ac12_a_mismatched_state_writes_nothing_at_all() {
    // Plan AC12: the state check is what stops a callback from another login —
    // or from somebody else's page — being exchanged. It runs before the
    // exchange, so a mismatch costs no request and leaves no directory.
    let server = MockServer::start();
    let token = exchange(&server, Some(EXCHANGE_ORG));

    let mut fixture = Fixture::new();
    fixture.endpoints(&server.base_url());

    let mut session = common::start_login(&fixture, &[], &[]);
    session.paste("minted-code#not-the-state-you-minted");
    let finished = session.finish();

    assert_eq!(finished.code(), 1, "a login that did not log in is fatal");
    assert_eq!(token.calls(), 0, "the code was never exchanged");
    assert!(!fixture.config_file().exists(), "no registry was written");
    assert!(
        !fixture.config_dir().join("claude").join(EXCHANGE_ACCT).exists(),
        "no namespace was created"
    );
}

#[test]
fn ac41_two_logins_for_different_organizations_make_sibling_namespaces() {
    // Plan AC41, decision D-008: the namespace key is the *pair*. One account
    // in two organizations is two namespaces, two records and two credentials,
    // not one row that overwrites itself.
    let server = MockServer::start();
    let mut first = exchange(&server, Some(EXCHANGE_ORG));

    let mut fixture = Fixture::new();
    fixture.endpoints(&server.base_url());

    let mut session = common::start_login(&fixture, &[], &[]);
    let state = session.state.clone();
    session.paste(&format!("minted-code#{state}"));
    assert_eq!(session.finish().code(), 0);
    first.delete();

    let other_org = "77777777-7777-4777-8777-777777777777";
    let _second = exchange(&server, Some(other_org));
    let mut session = common::start_login(&fixture, &[], &[]);
    let state = session.state.clone();
    session.paste(&format!("minted-code#{state}"));
    let finished = session.finish();
    assert_eq!(finished.code(), 0, "stderr:\n{}", finished.stderr);

    assert!(fixture.ns_dir(EXCHANGE_ACCT, EXCHANGE_ORG).join(".credentials.json").exists());
    assert!(fixture.ns_dir(EXCHANGE_ACCT, other_org).join(".credentials.json").exists());
    let accounts = registry(&fixture)["accounts"].as_array().expect("an array").len();
    assert_eq!(accounts, 2, "both organizations are recorded");
}

#[test]
fn ac41_a_second_login_for_the_same_pair_refuses_without_a_terminal() {
    // Plan AC41 and the module note on `login`: overwriting a stored
    // credential needs a person to say so, and there is no `--yes` on this
    // command in phase 1. A pipe is not a person, so the second login refuses
    // rather than replacing a credential another process may be refreshing.
    let server = MockServer::start();
    let token = exchange(&server, Some(EXCHANGE_ORG));

    let mut fixture = Fixture::new();
    fixture.endpoints(&server.base_url());

    let mut session = common::start_login(&fixture, &[], &[]);
    let state = session.state.clone();
    session.paste(&format!("minted-code#{state}"));
    assert_eq!(session.finish().code(), 0);
    let path = fixture.ns_dir(EXCHANGE_ACCT, EXCHANGE_ORG).join(".credentials.json");
    let before = common::inode_of(&path);

    let mut session = common::start_login(&fixture, &[], &[]);
    let state = session.state.clone();
    session.paste(&format!("minted-code#{state}"));
    let finished = session.finish();

    assert_eq!(finished.code(), 1);
    assert!(
        finished.stderr.contains("not a terminal"),
        "the refusal should say why:\n{}",
        finished.stderr
    );
    assert_eq!(token.calls(), 2, "the exchange happened; only the overwrite was refused");
    assert_eq!(common::inode_of(&path), before, "the stored credential was left alone");
}

#[test]
fn ac27_sigterm_with_a_staged_write_removes_the_temporary_file() {
    // Plan AC27's other clause. `pause_before_rename` holds the process in the
    // window where a temporary file holding a brand-new refresh token exists
    // and the rename has not happened. A signal there must leave neither the
    // temporary file (risk R24: token material at rest) nor a held lock.
    let server = MockServer::start();
    let _token = exchange(&server, Some(EXCHANGE_ORG));

    let mut fixture = Fixture::new();
    fixture.endpoints(&server.base_url());

    let mut session =
        common::start_login(&fixture, &[], &[("AGENTCTL_FAULT", "pause_before_rename")]);
    let state = session.state.clone();
    session.paste(&format!("minted-code#{state}"));

    let ns_dir = fixture.ns_dir(EXCHANGE_ACCT, EXCHANGE_ORG);
    let staged =
        || {
            fs::read_dir(&ns_dir).into_iter().flatten().flatten().any(|entry| {
                entry.file_name().to_string_lossy().starts_with(".credentials.json.tmp.")
            })
        };
    assert!(
        common::wait_until(Duration::from_secs(20), staged),
        "the writer should have staged a temporary file before the pause"
    );
    let lock = fixture.lock_path(EXCHANGE_ACCT, EXCHANGE_ORG);
    assert!(common::lock_is_held(&lock), "and it should be holding the namespace lock");

    common::send_sigterm(session.pid());
    let finished = session.finish();

    assert_eq!(finished.code(), 143, "128 + SIGTERM, from the handler thread");
    assert!(
        common::wait_until(Duration::from_secs(2), || !common::lock_is_held(&lock)),
        "the kernel released the lock when the holder died"
    );
    assert!(
        !ns_dir.join(".credentials.json").exists(),
        "the interrupted write left no credential behind"
    );
    assert_eq!(
        fixture.namespace_entries(EXCHANGE_ACCT, EXCHANGE_ORG),
        Vec::<String>::new(),
        "emergency cleanup removed the temporary file holding the new refresh token"
    );
}

// ---------------------------------------------------------------------------
// `same identity as live` (`agentctl-p3-login-live-identity-warning-b90`)
// ---------------------------------------------------------------------------

/// Writes a `.claude.json` naming `acct`/`org` as the signed-in account.
///
/// The file Claude Code keeps its `oauthAccount` in (fact F33), which is
/// where `login` learns who is live. Deliberately not the keychain: a notice
/// is not worth reading a token pair, and this way a `login` still touches no
/// credential but the one it is minting.
fn claude_json(fixture: &Fixture, acct: &str, org: &str) {
    fs::write(
        fixture.home().join(".claude.json"),
        json!({
            "oauthAccount": {
                "accountUuid": acct,
                "emailAddress": "user@example.com",
                "organizationUuid": org,
                "organizationName": "Example Org",
            }
        })
        .to_string(),
    )
    .expect("`.claude.json` should be writable");
}

#[test]
fn b90_a_login_into_the_live_account_notices_on_stderr_and_still_logs_in() {
    // `agentctl-p3-login-live-identity-warning-b90` (login notices when the
    // new identity is the live one's), through the binary. Standard error, so
    // that the "Logged in as …" line a script may be reading stays the only
    // new thing on standard output; exit 0 and a credential on disk, because
    // a second independent session of one account is a supported setup
    // (decision D-011) and the default must not refuse it.
    let server = MockServer::start();
    let token = exchange(&server, Some(EXCHANGE_ORG));

    let mut fixture = Fixture::new();
    fixture.endpoints(&server.base_url());
    claude_json(&fixture, EXCHANGE_ACCT, EXCHANGE_ORG);

    let mut session = common::start_login(&fixture, &[], &[]);
    let state = session.state.clone();
    session.paste(&format!("minted-code#{state}"));
    let finished = session.finish();

    assert_eq!(finished.code(), 0, "the login completes: stderr:\n{}", finished.stderr);
    assert_eq!(token.calls(), 1);
    assert!(
        finished.stderr.contains("Claude Code is signed in as"),
        "the notice is on standard error:\n{}",
        finished.stderr
    );
    assert!(finished.stderr.contains(EXCHANGE_ACCT), "it names the account:\n{}", finished.stderr);
    assert!(
        finished.stderr.contains("use --live"),
        "it names the command that swaps instead:\n{}",
        finished.stderr
    );
    assert!(
        !finished.stdout.contains("Claude Code is signed in as"),
        "and not on standard output:\n{}",
        finished.stdout
    );
    assert!(
        finished.stdout.contains("Logged in as user@example.com"),
        "the usual closing line is unchanged:\n{}",
        finished.stdout
    );
    assert!(
        fixture.ns_dir(EXCHANGE_ACCT, EXCHANGE_ORG).join(".credentials.json").is_file(),
        "the credential was written exactly as it would have been"
    );
}

#[test]
fn b90_a_login_into_another_account_says_nothing_about_the_live_one() {
    let server = MockServer::start();
    exchange(&server, Some(EXCHANGE_ORG));

    let mut fixture = Fixture::new();
    fixture.endpoints(&server.base_url());
    // Somebody else is live, so there is nothing to say.
    claude_json(&fixture, "99999999-9999-4999-8999-999999999999", EXCHANGE_ORG);

    let mut session = common::start_login(&fixture, &[], &[]);
    let state = session.state.clone();
    session.paste(&format!("minted-code#{state}"));
    let finished = session.finish();

    assert_eq!(finished.code(), 0, "stderr:\n{}", finished.stderr);
    assert!(
        !finished.stderr.contains("Claude Code is signed in as"),
        "no notice for a different account:\n{}",
        finished.stderr
    );
}

// ---------------------------------------------------------------------------
// `--no-duplicate` (`agentctl-3m0`)
// ---------------------------------------------------------------------------

/// Everything under the fixture's configuration directory, by relative path.
///
/// "Nothing was written" is a claim about the whole tree: a namespace
/// directory created and left empty would satisfy a check for
/// `.credentials.json` alone and would still be a change to the machine.
fn config_tree(fixture: &Fixture) -> Vec<String> {
    fn walk(dir: &std::path::Path, root: &std::path::Path, found: &mut Vec<String>) {
        let Ok(entries) = fs::read_dir(dir) else { return };
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
    let root = fixture.config_dir();
    let mut found = Vec::new();
    walk(&root, &root, &mut found);
    found.sort();
    found
}

#[test]
fn m3m0_no_duplicate_refuses_the_live_account_and_leaves_the_store_untouched() {
    // `agentctl-3m0`, through the binary: non-zero exit, a message that names
    // where the claim came from, and a store that is byte-for-byte what it was.
    let server = MockServer::start();
    let token = exchange(&server, Some(EXCHANGE_ORG));

    let mut fixture = Fixture::new();
    fixture.endpoints(&server.base_url());
    claude_json(&fixture, EXCHANGE_ACCT, EXCHANGE_ORG);
    let before = config_tree(&fixture);

    let mut session = common::start_login(&fixture, &["--no-duplicate"], &[]);
    let state = session.state.clone();
    session.paste(&format!("minted-code#{state}"));
    let finished = session.finish();

    assert_eq!(finished.code(), 1, "a refusal that renders nothing exits 1:\n{}", finished.stderr);
    assert_eq!(
        token.calls(),
        1,
        "the exchange still happened: the identity is not knowable before it"
    );

    let stderr = &finished.stderr;
    assert!(stderr.contains(EXCHANGE_ACCT), "the refusal names the account:\n{stderr}");
    assert!(stderr.contains(".claude.json"), "and where it looked:\n{stderr}");
    assert!(stderr.contains("use --live"), "and the swap:\n{stderr}");
    assert!(stderr.contains("without `--no-duplicate`"), "and the escape:\n{stderr}");
    assert!(!stderr.contains("sk-ant-"), "no token material reaches it:\n{stderr}");
    assert!(
        !stderr.contains("both stay valid"),
        "the refusal replaces the notice rather than joining it:\n{stderr}"
    );

    assert_eq!(config_tree(&fixture), before, "nothing was written");
    assert!(!fixture.config_file().exists(), "no registry record");
    assert!(
        !fixture.ns_dir(EXCHANGE_ACCT, EXCHANGE_ORG).exists(),
        "not even an empty namespace directory"
    );
}

#[test]
fn m3m0_no_duplicate_lets_a_login_into_any_other_account_through() {
    let server = MockServer::start();
    exchange(&server, Some(EXCHANGE_ORG));

    let mut fixture = Fixture::new();
    fixture.endpoints(&server.base_url());
    claude_json(&fixture, "99999999-9999-4999-8999-999999999999", EXCHANGE_ORG);

    let mut session = common::start_login(&fixture, &["--no-duplicate"], &[]);
    let state = session.state.clone();
    session.paste(&format!("minted-code#{state}"));
    let finished = session.finish();

    assert_eq!(finished.code(), 0, "stderr:\n{}", finished.stderr);
    assert!(
        fixture.ns_dir(EXCHANGE_ACCT, EXCHANGE_ORG).join(".credentials.json").is_file(),
        "the credential was written"
    );
    // Keyed on the account UUID, not the email: `Fixture::owned_record` gives
    // every owned account the same address (`agentctl-p95`).
    assert_eq!(registry(&fixture)["accounts"][0]["account_uuid"], json!(EXCHANGE_ACCT));
}
