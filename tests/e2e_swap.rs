#![cfg(feature = "testing")]

//! `claude use --live` through the real binary (plan section 3.4, W4a).
//!
//! Every test here drives the shipped `agctl` against the fake `security`
//! stand-in and, where a POST happens, an `httpmock` server. That is the only
//! way to answer the questions W4a is actually about: how many times the
//! keychain was touched, which item was named, what was left on disk when the
//! swap refused, and whether Claude Code's lock artefacts were released.
//!
//! # Two habits every test here keeps
//!
//! **The `security` call count is pinned, with the per-argv breakdown.** A
//! swap that silently grew a read would still pass an outcome assertion, and
//! reads of a credential store are exactly the thing that should not grow by
//! accident. So each test says how many calls it expects and what they were.
//!
//! **`.credentials.json` and `.credentials.adopted.json` are asserted before
//! *and* after.** A claim that the pass did not create a plaintext store is
//! only worth making against a namespace that did not have one to begin with
//! — the gap the W3 verifier found in the refresh tests, not repeated here.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use common::ACCT;
use common::EMAIL;
use common::Fixture;
use common::LIVE_SERVICE;
use common::ORG;
use httpmock::Method::POST;
use httpmock::Mock;
use httpmock::MockServer;
use serde_json::Value;
use serde_json::json;

/// A second account, for the incoming half of a swap.
const ACCT_T: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const ORG_T: &str = "ffffffff-0000-1111-2222-333333333333";
const EMAIL_T: &str = "incoming@example.com";

/// The adopted copy's name (decision D-024).
const ADOPTED: &str = ".credentials.adopted.json";

/// The refresh mock, when a test's incoming credential has expired.
fn token_ok(server: &MockServer) -> Mock<'_> {
    server.mock(|when, then| {
        when.method(POST).path(common::TOKEN_PATH);
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

/// A registry with the store account (**P**, migrated into the keychain) and
/// the incoming account (**T**, a plaintext store of its own).
///
/// Returns the fixture and the service name the store's item lives under.
fn two_accounts(server: &MockServer, t_expires_at: i64) -> (Fixture, String) {
    let mut fixture = Fixture::new();
    fixture.with_keychain().endpoints(&server.base_url());
    fixture.write_registry(vec![
        fixture.owned_record(ACCT, ORG),
        owned_record_for(&fixture, ACCT_T, ORG_T, EMAIL_T),
    ]);
    fs::create_dir_all(fixture.ns_dir(ACCT, ORG)).expect("the store namespace is creatable");

    // T's own credential, in its own namespace, as a plaintext store.
    fixture.write_credentials(
        ACCT_T,
        ORG_T,
        &common::identified_blob(
            "sk-ant-oat01-incoming",
            "sk-ant-ort01-incoming",
            t_expires_at,
            ACCT_T,
            Some(ORG_T),
        ),
    );

    // P: the store's own credential, already migrated into the item.
    let service = common::migration_service(&fixture.ns_dir(ACCT, ORG));
    fixture.dump(&[&service]);
    fixture.keychain_item(
        &service,
        &common::identified_blob(
            "sk-ant-oat01-outgoing",
            "sk-ant-ort01-outgoing",
            common::fresh_at(),
            ACCT,
            Some(ORG),
        ),
    );
    fixture.allow_write(&service);

    // The swap is driven from *inside* a session pointed at the store, which
    // is the only thing that names the target (ruling OQ1: no `--store` flag).
    let spelling = common::export_spelling(&fixture.ns_dir(ACCT, ORG));
    fixture.set("CLAUDE_SECURESTORAGE_CONFIG_DIR", &spelling);
    // The hold's own duration is only observable through the line the release
    // writes, and every test here that reaches Phase C asserts it: that is
    // what pins the **driver's** ordering rather than `swap.rs`'s annotation
    // of it (plan AC70).
    fixture.set("RUST_LOG", "agctl=debug");
    (fixture, service)
}

/// An `Owned` record for a second account, with its own namespace spelling.
fn owned_record_for(fixture: &Fixture, acct: &str, org: &str, email: &str) -> Value {
    let spelling = common::export_spelling(&fixture.ns_dir(acct, org));
    json!({
        "account_uuid": acct,
        "organization_uuid": org,
        "email": email,
        "org_name": "Acme",
        "label": null,
        "kind": {
            "kind": "owned",
            "export_spelling": spelling,
            "export_sha8": common::sha8(&spelling),
        },
        "forgotten": false,
        "created_at": "2026-09-08T00:00:00Z",
    })
}

/// Every `add-generic-password` the stand-in was asked to run.
fn writes(fixture: &Fixture) -> Vec<String> {
    fixture
        .security_log()
        .into_iter()
        .filter(|line| line.starts_with("add-generic-password"))
        .collect()
}

/// Every `find-generic-password` the stand-in was asked to run.
fn reads(fixture: &Fixture) -> Vec<String> {
    fixture
        .security_log()
        .into_iter()
        .filter(|line| line.starts_with("find-generic-password"))
        .collect()
}

/// How many times the stand-in was asked to read one service's password.
///
/// Keyed on the service rather than counted across all of them: the live
/// store's own read and the migration probe are both `find-generic-password`
/// lines, so a bare total says nothing about how far *this* item's pass has
/// got — and a test that waits on the wrong number writes its peer blob into
/// a window that has not opened yet.
fn finds_for(fixture: &Fixture, service: &str) -> usize {
    let suffix = format!("-s {service}");
    fixture
        .security_log()
        .iter()
        .filter(|line| line.starts_with("find-generic-password") && line.ends_with(&suffix))
        .count()
}

/// A credential blob naming an identity **and** an email address of its own.
///
/// `common::identified_blob` fixes the address at `owner@example.com`
/// whatever account it names, which would make "who holds this item" untestable:
/// every occupant would be reported under the same address as the record it is
/// occupying, and an assertion that could not tell them apart would pass on a
/// build that had confused them.
fn occupant_blob(access: &str, expires_at_ms: i64, acct: &str, org: &str, email: &str) -> String {
    json!({
        "claudeAiOauth": {
            "accessToken": access,
            "refreshToken": "sk-ant-ort01-occupant",
            "expiresAt": expires_at_ms,
            "scopes": ["user:inference", "user:profile"],
            "subscriptionType": "max",
            "tokenAccount": {
                "uuid": acct,
                "emailAddress": email,
                "organizationUuid": org,
                "organizationName": "Acme",
            },
        }
    })
    .to_string()
}

/// The audit log's lines, or none when it was never written.
fn audit_lines(fixture: &Fixture) -> Vec<String> {
    match fs::read_to_string(fixture.audit_log_path()) {
        Ok(text) => text.lines().map(str::to_owned).collect(),
        Err(_) => Vec::new(),
    }
}

/// Asserts the three Claude Code lock artefacts are gone.
fn artefacts_released(fixture: &Fixture) {
    for path in fixture.hold_artefacts(ACCT, ORG) {
        assert!(!path.exists(), "`{}` should have been released", path.display());
    }
}

/// Asserts nothing in the fixture ever named the live item as a write.
///
/// Plan AC81's sharpest clause, and the one worth checking by name rather
/// than by inspection: W4a's containment claim is that the live store is
/// untouched, and `WriteTarget::live` is never constructed on this path.
fn live_item_never_written(fixture: &Fixture) {
    for line in writes(fixture) {
        assert!(
            !line.contains(&format!("-s \"{LIVE_SERVICE}\"")),
            "the live item must never be written by a W4a swap: {line}"
        );
    }
}

/// The adopted copy's path for one namespace.
fn adopted_path(fixture: &Fixture, acct: &str, org: &str) -> std::path::PathBuf {
    fixture.ns_dir(acct, org).join(ADOPTED)
}

/// Pins the **whole** `security` conversation: every subcommand, by name,
/// with its count, and the total.
///
/// The contract's §E header asks this of every test in this file, and the
/// reason is that an outcome assertion cannot catch it: a swap that grew a
/// read of a credential store would still apply, still adopt, still release,
/// and still pass. `expected` is the complete set — a subcommand absent from
/// it must not appear at all, because the total is checked against the sum.
fn assert_security(fixture: &Fixture, expected: &[(&str, usize)]) {
    let log = fixture.security_log();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for line in &log {
        *counts.entry(line.split_whitespace().next().unwrap_or("")).or_default() += 1;
    }
    for (name, want) in expected {
        assert_eq!(
            counts.get(name).copied().unwrap_or(0),
            *want,
            "`security {name}` was called {} times, not {want}: {log:?}",
            counts.get(name).copied().unwrap_or(0)
        );
    }
    let total: usize = expected.iter().map(|(_, want)| want).sum();
    assert_eq!(total, log.len(), "the exact set of `security` invocations: {log:?}");
}

/// Asserts no audit line carries token material.
///
/// The audit log's vocabulary is digest prefixes, service names and outcome
/// words. A blob reaching it would put both tokens in a file that outlives
/// every pass and that `doctor` prints from.
fn audit_carries_no_token(fixture: &Fixture) {
    for line in audit_lines(fixture) {
        assert!(!line.contains("sk-ant-"), "an audit line carries token material: {line}");
    }
}

/// Asserts the store's plaintext file is absent, with a sentence saying why
/// it matters.
///
/// Called **before** as well as after every pass that reaches Phase B: a
/// claim that the swap did not create `.credentials.json` is only worth
/// making against a namespace that did not have one to begin with.
fn no_plaintext_store(fixture: &Fixture, when: &str) {
    let path = fixture.ns_dir(ACCT, ORG).join(".credentials.json");
    assert!(
        !path.exists(),
        "`.credentials.json` must not exist {when}: fact F35's composed read would shadow the \
         item with it on any keychain failure or throttle"
    );
}

/// The `hold_ms` the release line carries, under `RUST_LOG=agctl=debug`.
///
/// The hold's duration is only observable through this line, and invariant
/// I17's number is worth asserting rather than assuming — the position tests
/// in `swap_tests.rs` pin an annotation, not the driver.
fn hold_ms(stderr: &str) -> Option<u64> {
    let released =
        stderr.lines().find(|line| line.contains("released the credential-store hold"))?;
    assert!(released.contains("budget_ms=3000"), "the budget it is measured against: {released}");
    released
        .split_once("hold_ms=")
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .and_then(|field| field.parse().ok())
}

/// Asserts the pass took a hold and that it stayed inside the budget.
fn hold_within_budget(stderr: &str) {
    let held =
        hold_ms(stderr).unwrap_or_else(|| panic!("the release should have been logged:\n{stderr}"));
    assert!(held < 3000, "the hold was {held} ms, at or past its 3 000 ms budget");
}

/// Every JSON document on stdout, in order.
///
/// `--json` prints the **plan** before prompting and the **outcome**
/// afterwards, so a run that reaches the prompt emits two. Parsed as a stream
/// rather than split by hand, which is what a consumer would do.
fn json_docs(stdout: &str) -> Vec<Value> {
    serde_json::Deserializer::from_str(stdout)
        .into_iter::<Value>()
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|err| {
            panic!("stdout should be a stream of JSON documents: {err}\n{stdout}")
        })
}

/// The outcome document — the last one on stdout.
fn outcome_doc(stdout: &str) -> Value {
    json_docs(stdout).pop().unwrap_or_else(|| panic!("no JSON document on stdout: {stdout}"))
}

/// Watches the three hold artefacts from outside the process.
///
/// Contract §E: "every test that reaches Phase C proves the three artefacts
/// **created** … and **removed**". Removal is asserted at the end by
/// [`artefacts_released`]; creation can only be seen while the hold is open,
/// which is what this is for.
struct ArtefactWatch {
    stop: Arc<AtomicBool>,
    seen: Arc<AtomicUsize>,
    windows: Arc<AtomicUsize>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl ArtefactWatch {
    /// Starts polling `paths` until [`ArtefactWatch::finish`].
    fn start(paths: [std::path::PathBuf; 3]) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let seen = Arc::new(AtomicUsize::new(0));
        let windows = Arc::new(AtomicUsize::new(0));
        let handle = {
            let (stop, seen, windows) =
                (Arc::clone(&stop), Arc::clone(&seen), Arc::clone(&windows));
            std::thread::spawn(move || {
                let mut open = false;
                while !stop.load(Ordering::Relaxed) {
                    let present = paths.iter().filter(|path| path.exists()).count();
                    if present > seen.load(Ordering::Relaxed) {
                        seen.store(present, Ordering::Relaxed);
                    }
                    if present > 0 && !open {
                        open = true;
                        windows.fetch_add(1, Ordering::Relaxed);
                    } else if present == 0 {
                        open = false;
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
            })
        };
        Self { stop, seen, windows, handle: Some(handle) }
    }

    /// Stops polling and reports (most artefacts seen at once, hold windows).
    fn finish(mut self) -> (usize, usize) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        (self.seen.load(Ordering::Relaxed), self.windows.load(Ordering::Relaxed))
    }
}

/// Runs `claude use --live <id> --yes` and returns (code, stdout, stderr).
fn swap(fixture: &Fixture, extra: &[&str]) -> (i32, String, String) {
    let mut command = fixture.cmd();
    command.args(["claude", "use", "--live", EMAIL_T, "--yes"]);
    command.args(extra);
    let output = command.output().expect("the binary should run");
    (
        output.status.code().expect("the process exited normally"),
        String::from_utf8(output.stdout).expect("stdout is UTF-8"),
        common::strip_ansi(&String::from_utf8(output.stderr).expect("stderr is UTF-8")),
    )
}

/// Runs `claude use --live <id>` **without** `--yes`, so the confirmation is
/// reached and nobody answers it.
///
/// Standard input here is a pipe, so `Tty::confirm` fails closed — which is
/// the same consent outcome as an operator typing "n", and the shape every
/// scripted or CI run takes. (Answering "n" for real needs a pseudo-terminal
/// this suite has no dependency for; that arm is covered by `confirm`'s own
/// unit tests in `use_tests.rs`, which drive a scripted `Prompt`.)
fn swap_unconfirmed(fixture: &Fixture, extra: &[&str]) -> (i32, String, String) {
    let mut command = fixture.cmd();
    command.args(["claude", "use", "--live", EMAIL_T]);
    command.args(extra);
    let output = command.output().expect("the binary should run");
    (
        output.status.code().expect("the process exited normally"),
        String::from_utf8(output.stdout).expect("stdout is UTF-8"),
        common::strip_ansi(&String::from_utf8(output.stderr).expect("stderr is UTF-8")),
    )
}

/// Every path under both trees a pass may write into, with each regular
/// file's contents.
///
/// **Both** trees, and that is not incidental. `fixture.home()` is the fake
/// `$HOME`, which holds the live Claude Code store; `fixture.config_dir()` is
/// its **sibling**, passed as `--config-dir`, and it is where every namespace
/// lives — the adopted copy, a third account's `.credentials.json`, the locks
/// and the audit log. A walk of the home tree can never see a path under the
/// config tree, so seeding this from `home()` alone left the guard below
/// inert for exactly the files finding N-1 was about (verify round 3, V2).
///
/// The contents come along because the guard has to see an **overwrite**, not
/// only a creation: a path-set comparison is blind to a pre-existing file
/// rewritten with token material (finding N-13a). The trees are a few dozen
/// small files, so reading them is cheaper than the process launch each test
/// already pays for.
fn tree(fixture: &Fixture) -> BTreeMap<std::path::PathBuf, Option<Vec<u8>>> {
    let mut found = BTreeMap::new();
    for root in [fixture.config_dir(), fixture.home()] {
        for path in walk(&root) {
            let bytes = fs::read(&path).ok();
            found.insert(path, bytes);
        }
    }
    found
}

/// Asserts that nothing under the two trees holds token material it did not
/// already hold before the pass.
///
/// The whole-tree form of the claim, and the reason it is worth the walk: a
/// per-file assertion can only refuse the file names the test thought of.
/// Finding N-1 was invisible to `writes(..) == 0` (keychain writes only) and
/// to `no_plaintext_store(..)` (one file name in one namespace) precisely
/// because the credential landed under a **third** name in a **different**
/// namespace.
///
/// A file whose bytes are exactly what they were is skipped: the fixtures
/// deliberately start with credentials at rest (the incoming account's own
/// store is one), and the claim is about what *this pass* put there.
fn no_new_credential_at_rest(
    before: &BTreeMap<std::path::PathBuf, Option<Vec<u8>>>,
    after: &BTreeMap<std::path::PathBuf, Option<Vec<u8>>>,
    when: &str,
) {
    for (path, now) in after {
        let Some(bytes) = now else { continue };
        if before.get(path).is_some_and(|was| was.as_ref() == Some(bytes)) {
            continue;
        }
        let text = String::from_utf8_lossy(bytes);
        assert!(
            !text.contains("sk-ant-"),
            "`{}` was created or rewritten {when} and holds token material",
            path.display()
        );
    }
}

// ---------------------------------------------------------------------------
// AC67 — one test per refusal reachable in W4a
// ---------------------------------------------------------------------------

#[test]
fn the_scope_gate_sends_an_empty_securestorage_variable_to_the_live_store() {
    // The W4a form of this test asserted the **opposite**: an unset or empty
    // `CLAUDE_SECURESTORAGE_CONFIG_DIR` was refused as `not_implemented`,
    // exit 1. W4b removes that arm, so the claim inverts — and the half worth
    // keeping is *which* store the empty value selects.
    //
    // Empty, not unset, because that is fact F14's corner: `""` is falsy to
    // Claude Code, so it names the **unsuffixed live item** exactly as an unset
    // variable would, even with `CLAUDE_CONFIG_DIR` set. A gate that tested
    // presence rather than truthiness would route this run at a namespace and
    // pass every assertion about the refusal it then produced.
    //
    // This fixture's live store does not exist, so the pass refuses
    // `LiveUnreachable` in Phase A — which is exactly the evidence wanted: the
    // refusal is about the **live** store, and nothing was read to reach it.
    let server = MockServer::start();
    let (mut fixture, _service) = two_accounts(&server, common::fresh_at());
    fixture.set("CLAUDE_SECURESTORAGE_CONFIG_DIR", "");

    no_plaintext_store(&fixture, "before the pass");
    let (code, stdout, _stderr) = swap(&fixture, &["--json"]);
    assert_eq!(code, 23, "SWAP_EXIT_LIVE_UNREACHABLE: the live arm was taken");
    let doc = outcome_doc(&stdout);
    assert_eq!(doc["reason"], json!("live_unreachable"), "{doc}");
    assert_eq!(
        doc["service"],
        json!(LIVE_SERVICE),
        "and the item it was about is the unsuffixed one, not the namespace's: {doc}"
    );
    assert_ne!(doc["reason"], json!("not_owned"), "an empty value is not a namespace: {doc}");

    assert_eq!(reads(&fixture).len(), 0, "nothing was read: {:?}", reads(&fixture));
    assert_eq!(writes(&fixture).len(), 0, "and nothing was written");
    assert_security(&fixture, &[]);
    assert!(audit_lines(&fixture).is_empty(), "no audit entry for a Phase A refusal");
    artefacts_released(&fixture);
    no_plaintext_store(&fixture, "after a refusal that read nothing");
    audit_carries_no_token(&fixture);
}

#[test]
fn ac67_the_oq1_precondition_refuses_a_store_agctl_does_not_own() {
    // Ruling OQ1: the inherited spelling is matched byte for byte against an
    // owned record. A path no record names is refused *before* Phase A, with
    // its own exit code and no `refusal` letter.
    let server = MockServer::start();
    let (mut fixture, _service) = two_accounts(&server, common::fresh_at());
    fixture.set("CLAUDE_SECURESTORAGE_CONFIG_DIR", "/tmp/not-a-store-agctl-owns");

    no_plaintext_store(&fixture, "before the pass");
    let (code, stdout, _stderr) = swap(&fixture, &[]);
    assert_eq!(code, 15, "SWAP_EXIT_PRECONDITION");
    assert!(
        stdout.contains("not a store agctl owns"),
        "the message names the path and says why: {stdout}"
    );
    assert!(stdout.contains("/tmp/not-a-store-agctl-owns"), "{stdout}");

    assert_eq!(reads(&fixture).len(), 0, "decided before Phase A reads anything");
    assert_eq!(writes(&fixture).len(), 0);
    assert_security(&fixture, &[]);
    assert!(audit_lines(&fixture).is_empty());
    artefacts_released(&fixture);
    no_plaintext_store(&fixture, "after a precondition refusal");

    // The same refusal through `--json`. It used to go straight to the
    // terminal, so the one output shape a script reads got prose: the
    // precondition is the *only* refusal `--json` gives a `reason` rather
    // than a letter, and nothing proved it produced either.
    let (code, stdout, _stderr) = swap(&fixture, &["--json"]);
    assert_eq!(code, 15, "SWAP_EXIT_PRECONDITION under --json too");
    let doc = outcome_doc(&stdout);
    assert_eq!(doc["outcome"], json!("refused"), "{doc}");
    assert_eq!(doc["reason"], json!("not_owned"), "the unlettered precondition: {doc}");
    assert_eq!(doc["refusal"], Value::Null, "and no refusal letter: {doc}");
    audit_carries_no_token(&fixture);
}

#[test]
fn ac67_refusal_c_names_whose_environment_was_inspected() {
    // Decision D-020 narrowed refusal C to agctl's **own** environment,
    // and the message has to say so — otherwise a user reads it as a claim
    // about the session being swapped, which agctl cannot inspect.
    let server = MockServer::start();
    let (mut fixture, _service) = two_accounts(&server, common::fresh_at());
    fixture.set("CLAUDE_CODE_OAUTH_TOKEN", "sk-ant-oat01-from-the-environment");

    no_plaintext_store(&fixture, "before the pass");
    let (code, stdout, _stderr) = swap(&fixture, &[]);
    assert_eq!(code, 11, "SWAP_EXIT_REFUSED_C");
    assert!(stdout.contains("agctl's own environment"), "{stdout}");

    assert_eq!(writes(&fixture).len(), 0, "nothing written");
    // Decided from the environment alone, so the keychain is never opened.
    assert_security(&fixture, &[]);
    assert!(
        !audit_lines(&fixture).iter().any(|line| line.contains("\"event\":\"write\"")),
        "and no write entry: {:?}",
        audit_lines(&fixture)
    );
    artefacts_released(&fixture);
    no_plaintext_store(&fixture, "after refusal C");

    let (code, stdout, _stderr) = swap(&fixture, &["--json"]);
    assert_eq!(code, 11);
    let doc = outcome_doc(&stdout);
    assert_eq!(doc["outcome"], json!("refused"), "{doc}");
    assert_eq!(doc["refusal"], json!("C"), "the letter a script alerts on: {doc}");
    audit_carries_no_token(&fixture);
}

#[test]
fn ac67_refusal_b_is_a_warning_line_and_exit_zero() {
    // Decision D-020: no storage-V5 backend exists in this build, so refusing
    // on one would be refusing on a hypothesis. It degrades to a warning that
    // still says whose environment was inspected (M4).
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, service) = two_accounts(&server, common::fresh_at());
    no_plaintext_store(&fixture, "before the pass");

    let (code, stdout, stderr) = swap(&fixture, &[]);
    // On **stderr**, not stdout. A prose line in front of the `--json`
    // document made `use --live --json` unparseable, which is the one output
    // shape whose whole purpose is being parsed.
    assert!(
        stderr.contains("inspected its own environment for a secure-storage backend"),
        "the warning is present on stderr: {stderr}"
    );
    assert!(
        stderr.contains("cannot inspect the target session's"),
        "and it is honest about what it could not see: {stderr}"
    );
    assert!(
        !stdout.contains("secure-storage backend"),
        "and never on stdout, where a document goes: {stdout}"
    );
    assert_eq!(code, 0, "a warning is not a refusal");
    assert_eq!(writes(&fixture).len(), 1, "the swap still applied: {:?}", writes(&fixture));
    hold_within_budget(&stderr);
    no_plaintext_store(&fixture, "after the pass");
    audit_carries_no_token(&fixture);
    // Phase A's read, the re-read under the hold, and the verifying read
    // after the release; then the write, which the fake logs twice — the
    // `-i` argv it was invoked with, and the line it took off stdin.
    assert_security(
        &fixture,
        &[("find-generic-password", 3), ("-i", 1), ("add-generic-password", 1)],
    );
    let _ = service;
    let _ = token;
}

#[test]
fn ac67_refusal_f_when_the_outgoing_credential_cannot_be_read() {
    // What cannot be read cannot be put back, and a swap that cannot put the
    // outgoing credential back is a swap that loses it (decision D-017). The
    // item is present but unreadable: the fake reports a locked keychain.
    let server = MockServer::start();
    let (mut fixture, service) = two_accounts(&server, common::fresh_at());
    fixture.set("AGCTL_FAKE_SECURITY_FIND_EXIT", "36");
    fixture.set(
        "AGCTL_FAKE_SECURITY_STDERR",
        "The user name or passphrase you entered is not correct.",
    );

    no_plaintext_store(&fixture, "before the pass");
    let (code, stdout, _stderr) = swap(&fixture, &[]);
    assert_eq!(code, 14, "SWAP_EXIT_REFUSED_F");
    assert!(stdout.contains("cannot be adopted"), "{stdout}");

    assert_eq!(writes(&fixture).len(), 0, "nothing written");
    // One read, which came back unreadable, and nothing after it.
    assert_security(&fixture, &[("find-generic-password", 1)]);
    artefacts_released(&fixture);
    live_item_never_written(&fixture);
    no_plaintext_store(&fixture, "after refusal F");

    let (code, stdout, _stderr) = swap(&fixture, &["--json"]);
    assert_eq!(code, 14);
    let doc = outcome_doc(&stdout);
    assert_eq!(doc["outcome"], json!("refused"), "{doc}");
    assert_eq!(doc["refusal"], json!("F"), "{doc}");
    let _ = service;
    audit_carries_no_token(&fixture);
}

// ---------------------------------------------------------------------------
// AC72 — the incoming credential is already there
// ---------------------------------------------------------------------------

#[test]
fn ac72_a_swap_to_the_credential_already_in_the_item_writes_nothing() {
    // Plan AC72: adopt nothing, write nothing, and leave the registry byte
    // for byte as it was.
    let server = MockServer::start();
    let mut fixture = Fixture::new();
    fixture.with_keychain().endpoints(&server.base_url());
    fixture.write_registry(vec![
        fixture.owned_record(ACCT, ORG),
        owned_record_for(&fixture, ACCT_T, ORG_T, EMAIL_T),
    ]);
    fs::create_dir_all(fixture.ns_dir(ACCT, ORG)).expect("creatable");

    // One blob, in both places: T's store *and* the item.
    let blob = common::identified_blob(
        "sk-ant-oat01-same",
        "sk-ant-ort01-same",
        common::fresh_at(),
        ACCT_T,
        Some(ORG_T),
    );
    fixture.write_credentials(ACCT_T, ORG_T, &blob);
    let service = common::migration_service(&fixture.ns_dir(ACCT, ORG));
    fixture.dump(&[&service]);
    fixture.keychain_item(&service, &blob);
    fixture.allow_write(&service);
    let spelling = common::export_spelling(&fixture.ns_dir(ACCT, ORG));
    fixture.set("CLAUDE_SECURESTORAGE_CONFIG_DIR", &spelling);

    let registry_before = fs::read(fixture.config_file()).expect("the registry is readable");
    let adopted_before = adopted_path(&fixture, ACCT, ORG);
    assert!(!adopted_before.exists(), "no adopted copy before the pass");

    no_plaintext_store(&fixture, "before the pass");
    let (code, stdout, _stderr) = swap(&fixture, &[]);
    assert_eq!(code, 0, "already active is a success: {stdout}");
    assert!(stdout.contains("already"), "{stdout}");

    assert_eq!(writes(&fixture).len(), 0, "zero `-i` writes");
    assert!(
        !audit_lines(&fixture).iter().any(|line| line.contains("\"event\":\"write\"")),
        "zero audit write lines"
    );
    assert!(!adopted_before.exists(), "and nothing was adopted");
    assert_eq!(
        fs::read(fixture.config_file()).expect("still readable"),
        registry_before,
        "the registry is byte-identical"
    );
    // One read, and the pass stopped there: the incoming credential is the
    // one already in the item, so there is nothing to refresh, adopt or hold.
    assert_security(&fixture, &[("find-generic-password", 1)]);
    artefacts_released(&fixture);
    no_plaintext_store(&fixture, "after an already-active swap");
    audit_carries_no_token(&fixture);
}

// ---------------------------------------------------------------------------
// AC69 / D-024 — the displaced credential is adopted, and where
// ---------------------------------------------------------------------------

#[test]
fn a_swap_adopts_the_displaced_credential_into_the_adopted_copy_never_the_store() {
    // Decision D-024, and the reason this whole lane stopped for a ruling:
    // the displaced credential goes to `.credentials.adopted.json`, a name
    // Claude Code's composed read never visits (fact F35, F40). Putting it in
    // `.credentials.json` would have it served back to the session on any
    // keychain hiccup — undoing the swap the user just asked for.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, service) = two_accounts(&server, common::fresh_at());

    let store_credentials = fixture.ns_dir(ACCT, ORG).join(".credentials.json");
    let adopted = adopted_path(&fixture, ACCT, ORG);
    // Before: the store has migrated, so it has neither file. Asserted before
    // as well as after, because "the pass did not create it" is only a claim
    // worth making against a namespace that did not have it.
    assert!(!store_credentials.exists(), "the migrated store has no plaintext file to begin with");
    assert!(!adopted.exists(), "and no adopted copy");

    no_plaintext_store(&fixture, "before the pass");
    let (code, stdout, stderr) = swap(&fixture, &[]);
    assert_eq!(code, 0, "the swap applied: {stdout}");

    // After: the adopted copy holds the outgoing credential…
    assert!(adopted.exists(), "the displaced credential was adopted");
    let parked = fs::read_to_string(&adopted).expect("the adopted copy is readable");
    assert!(parked.contains("sk-ant-oat01-outgoing"), "and it is P's credential");
    // …and `.credentials.json` was NOT resurrected. This is the assertion the
    // OQ2(e) finding is about.
    assert!(
        !store_credentials.exists(),
        "`.credentials.json` must not be resurrected: fact F35's composed read would shadow the \
         item with it on any keychain failure or throttle"
    );

    // The item now holds T.
    let item = fixture.keychain_item_path_for(common::KEYCHAIN_ACCOUNT, &service);
    let after = fs::read_to_string(&item).expect("the item is readable");
    assert!(after.contains("sk-ant-oat01-incoming"), "the item holds the incoming credential");

    assert_eq!(writes(&fixture).len(), 1, "exactly one write: {:?}", writes(&fixture));
    assert!(writes(&fixture)[0].contains(&format!("-s \"{service}\"")), "naming the store's item");
    assert_security(
        &fixture,
        &[("find-generic-password", 3), ("-i", 1), ("add-generic-password", 1)],
    );
    hold_within_budget(&stderr);
    audit_carries_no_token(&fixture);
    artefacts_released(&fixture);
    live_item_never_written(&fixture);
    let _ = token;
    no_plaintext_store(&fixture, "after the pass");
}

#[test]
fn the_adopted_copy_is_removed_when_the_account_is_removed() {
    // The residual `write_adopted` would otherwise leave: a real token at
    // rest in a directory the user has just been told is gone. `accounts
    // remove` sweeps it because `remove_namespace` names it.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, _service) = two_accounts(&server, common::fresh_at());

    no_plaintext_store(&fixture, "before the swap");
    let (code, _stdout, stderr) = swap(&fixture, &[]);
    assert_eq!(code, 0);
    let adopted = adopted_path(&fixture, ACCT, ORG);
    assert!(adopted.exists(), "the swap adopted the displaced credential");
    assert_eq!(writes(&fixture).len(), 1, "one write reached the item");
    hold_within_budget(&stderr);
    no_plaintext_store(&fixture, "after the swap");
    let after_swap = fixture.security_log().len();
    assert_eq!(after_swap, 5, "the swap's own calls: {:?}", fixture.security_log());

    // `--delete-secret` is the flag that deletes what is stored — the adopted
    // copy is swept by the same `remove_namespace` that sweeps
    // `.credentials.json`, so the two cannot drift into a state where one
    // survives a removal the user was told deleted their credentials.
    fixture
        .cmd()
        .args(["claude", "accounts", "remove", EMAIL, "--yes", "--delete-secret"])
        .assert()
        .success();
    assert!(
        !adopted.exists(),
        "`accounts remove --delete-secret` must not leave a credential at rest: {}",
        adopted.display()
    );
    // The swap's three reads and one write, and nothing from the removal:
    // `accounts remove` deletes files, and the item is not one of them.
    assert_security(
        &fixture,
        &[("find-generic-password", 3), ("-i", 1), ("add-generic-password", 1)],
    );
    let _ = token;
    audit_carries_no_token(&fixture);
}

#[test]
fn doctor_reports_the_adopted_copy_without_printing_any_of_it() {
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, _service) = two_accounts(&server, common::fresh_at());
    no_plaintext_store(&fixture, "before the swap");
    let (code, _stdout, stderr) = swap(&fixture, &[]);
    assert_eq!(code, 0);
    assert_eq!(writes(&fixture).len(), 1, "one write reached the item");
    hold_within_budget(&stderr);
    no_plaintext_store(&fixture, "after the swap");
    assert_eq!(
        fixture.security_log().len(),
        5,
        "the swap's own calls: {:?}",
        fixture.security_log()
    );

    let output = fixture.cmd().args(["claude", "doctor"]).output().expect("doctor runs");
    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    assert!(stdout.contains("adopted copy"), "doctor names the file: {stdout}");
    assert!(!stdout.contains("sk-ant-"), "and never prints a byte of what is in it: {stdout}");
    // The swap's three reads and one write, then `doctor`'s preflight,
    // listing and three reads. `doctor` never reads the adopted copy — it
    // reports that the file is there and nothing about what is in it.
    assert_security(
        &fixture,
        &[
            ("show-keychain-info", 1),
            ("dump-keychain", 1),
            ("find-generic-password", 6),
            ("-i", 1),
            ("add-generic-password", 1),
        ],
    );
    let _ = token;
    audit_carries_no_token(&fixture);
}

// ---------------------------------------------------------------------------
// AC69 — `swap_write_fail`: the child ran and exited non-zero
// ---------------------------------------------------------------------------

#[test]
fn ac69_a_failed_write_audits_failed_issues_no_verify_read_and_leaves_p_adopted() {
    // Ruling OQ6's `failed` half. The item was demonstrably not touched, so
    // there is nothing to verify and **no verify read is issued** — asserted
    // by the read count not growing after the write attempt.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (mut fixture, _service) = two_accounts(&server, common::fresh_at());
    fixture.fault("swap_write_fail");

    no_plaintext_store(&fixture, "before the pass");
    let (code, stdout, stderr) = swap(&fixture, &[]);
    assert_eq!(code, 19, "SWAP_EXIT_WRITE_FAILED, its own code: {stdout}");
    // A failed write still took the hold and still released it: the child ran
    // inside it and exited non-zero.
    hold_within_budget(&stderr);

    // P is still recoverable, which is what AC69 asks.
    let adopted = adopted_path(&fixture, ACCT, ORG);
    assert!(adopted.exists(), "P was adopted before the write was attempted");
    assert!(
        fs::read_to_string(&adopted).expect("readable").contains("sk-ant-oat01-outgoing"),
        "and it is P"
    );

    let lines = audit_lines(&fixture);
    assert!(
        lines.iter().any(|line| line.contains("\"outcome\":\"failed\"")),
        "the audit line says `failed`: {lines:?}"
    );
    assert!(
        !lines.iter().any(|line| line.contains("\"outcome\":\"unknown\"")),
        "and never `unknown`, which would send the user to re-run `status` for nothing"
    );

    // The fault short-circuits before the child, so no write was even
    // attempted — and, crucially, no verifying read followed it.
    assert_eq!(writes(&fixture).len(), 0, "no child ran: {:?}", writes(&fixture));
    // Phase A's read and the re-read under the hold, and nothing else: a
    // `failed` write issues no verifying read (ruling OQ6).
    assert_security(&fixture, &[("find-generic-password", 2)]);
    audit_carries_no_token(&fixture);
    no_plaintext_store(&fixture, "after a failed write");
    artefacts_released(&fixture);
    let _ = token;
}

// ---------------------------------------------------------------------------
// AC71 — the pause outside the hold, and the discard it makes visible
// ---------------------------------------------------------------------------

#[test]
fn ac71_an_item_that_changes_before_the_hold_discards_the_swap() {
    // The pause point is **outside** the hold: a pause inside one would break
    // invariant I17 even under a fault. While paused, the test rewrites the
    // item; the swap then finds a digest it did not read and throws its work
    // away rather than writing over a newer credential (invariant I2′).
    let server = MockServer::start();
    let token = token_ok(&server);
    let (mut fixture, service) = two_accounts(&server, common::fresh_at());
    let resume = fixture.scratch("resume");
    fixture.fault("pause_before_swap_write");
    fixture.set("AGCTL_FAULT_RESUME", &resume.to_string_lossy());

    let item = fixture.keychain_item_path_for(common::KEYCHAIN_ACCOUNT, &service);
    let peer = common::identified_blob(
        "sk-ant-oat01-peer",
        "sk-ant-ort01-peer",
        common::fresh_at(),
        ACCT,
        Some(ORG),
    );

    no_plaintext_store(&fixture, "before the pass");
    let child = fixture
        .raw()
        .args(["claude", "use", "--live", EMAIL_T, "--yes", "--json"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the binary should start");

    // Wait until the swap has reached the pause, then move the item under it.
    common::wait_until(Duration::from_secs(20), || {
        fs::read_to_string(&item).is_ok_and(|text| text.contains("sk-ant-oat01-outgoing"))
    });
    std::thread::sleep(Duration::from_millis(200));
    fs::write(&item, &peer).expect("the peer writes the item");
    fs::write(&resume, b"go").expect("the resume file is writable");

    let output = child.wait_with_output().expect("the swap finishes");
    let code = output.status.code().expect("exited normally");
    assert_eq!(code, 17, "SWAP_EXIT_DISCARDED");
    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let doc = outcome_doc(&stdout);
    assert_eq!(doc["outcome"], json!("discarded"), "{doc}");
    assert_eq!(doc["refusal"], Value::Null, "a discard is not a lettered refusal: {doc}");
    assert!(!stdout.contains("sk-ant-"), "{stdout}");

    assert_eq!(writes(&fixture).len(), 0, "zero `-i` lines: {:?}", writes(&fixture));
    let after = fs::read_to_string(&item).expect("readable");
    assert!(after.contains("sk-ant-oat01-peer"), "the item still holds the peer's blob");
    // Phase A's read and the re-read under the hold that found the change.
    assert_security(&fixture, &[("find-generic-password", 2)]);
    artefacts_released(&fixture);
    no_plaintext_store(&fixture, "after a discarded swap");
    audit_carries_no_token(&fixture);
    let _ = token;
}

// ---------------------------------------------------------------------------
// AC81 — containment: every path created or removed is under the namespace root
// ---------------------------------------------------------------------------

#[test]
fn ac81_a_swap_touches_nothing_outside_the_namespace_root() {
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, _service) = two_accounts(&server, common::fresh_at());

    let live_store = fixture.live_store_dir();
    fs::create_dir_all(&live_store).expect("the live store dir is creatable");
    no_plaintext_store(&fixture, "before the pass");
    // Both trees: the namespaces the swap writes into are under the config
    // directory, which is the fake HOME's **sibling**, so a walk of HOME
    // alone made the containment loop below unreachable rather than true
    // (verify round 3, V2).
    let before: std::collections::BTreeSet<_> = tree(&fixture).into_keys().collect();

    let (code, _stdout, stderr) = swap(&fixture, &[]);
    assert_eq!(code, 0);
    hold_within_budget(&stderr);

    assert_eq!(writes(&fixture).len(), 1, "one write reached the item");
    let after: std::collections::BTreeSet<_> = tree(&fixture).into_keys().collect();
    let root = fixture.config_dir().join("claude");
    // `Paths::ensure_dirs` makes agctl's own cache directories on every
    // pass, and invariant I1 names `cache_dir()` alongside `config_dir()` as
    // the two places this binary may write at all. They are allowed **by
    // name** rather than by widening the bound, and each is asserted to be a
    // directory: anything else appearing under `cache/` — a file, a third
    // path — is not in this list and fails the containment check below.
    let allowed =
        [fixture.config_dir().join("cache"), fixture.config_dir().join("cache").join("claude")];
    for path in after.symmetric_difference(&before) {
        if allowed.contains(path) {
            assert!(path.is_dir(), "`{}` is agctl's own cache directory", path.display());
            continue;
        }
        assert!(
            path.starts_with(&root),
            "`{}` is outside the namespace root `{}`",
            path.display(),
            root.display()
        );
    }

    // The live store's own artefacts, by path rather than by inspection.
    for name in [".oauth_refresh.lock", ".storage-write", ".credentials.json"] {
        assert!(!live_store.join(name).exists(), "the live store must be untouched: {name}");
    }
    // Ruling OQ11's two namespace locks: both were taken, and both are under
    // the namespace root the walk above bounds everything by.
    for (acct, org) in [(ACCT, ORG), (ACCT_T, ORG_T)] {
        let lock = fixture.lock_path(acct, org);
        assert!(lock.exists(), "the namespace lock for {acct} was taken");
        assert!(lock.starts_with(&root), "and it is under the namespace root: {}", lock.display());
    }
    live_item_never_written(&fixture);
    no_plaintext_store(&fixture, "after a swap that touched nothing outside the root");
    assert_security(
        &fixture,
        &[("find-generic-password", 3), ("-i", 1), ("add-generic-password", 1)],
    );
    audit_carries_no_token(&fixture);
    let _ = token;
}

/// Every path under `root`, for the containment difference.
fn walk(root: &Path) -> std::collections::BTreeSet<std::path::PathBuf> {
    let mut found = std::collections::BTreeSet::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && !path.is_symlink() {
                stack.push(path.clone());
            }
            found.insert(path);
        }
    }
    found
}

// ---------------------------------------------------------------------------
// agctl-i9o — a broken stale lock followed by an acquire failure
// ---------------------------------------------------------------------------

#[test]
fn i9o_a_break_is_audited_even_when_the_acquire_then_fails() {
    // `agctl-i9o` (no caller-side e2e proves the break record is appended
    // on acquire's failing path). After `agctl-nq3` the draft rides an
    // `AcquireFailure` and the caller appends it once, unconditionally,
    // before every mapping arm — but until now that was proven by
    // construction and by unit tests, never by driving the real binary.
    //
    // The shape: a stale lock is planted so the break rule removes it, and a
    // symlink at the held-locks directory makes the acquire fail immediately
    // afterwards. Exactly one `broken` line must reach the audit log.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (mut fixture, _service) = two_accounts(&server, common::fresh_at());
    fixture.fault("lock_stale");

    // The peer's stale primary lock, which the break rule will remove.
    let [primary, _legacy, _storage] = fixture.hold_artefacts(ACCT, ORG);
    fs::create_dir_all(&primary).expect("the stale lock is plantable");
    // Genuinely old, not merely declared stale: the rule abandons a lock it
    // has not watched for long enough (`reason: too_young`) before the
    // staleness fault is ever consulted.
    age(&primary);

    // A symlink where the held-lock record must go, so the acquire refuses
    // *after* the break (`agctl-p2-held-locks-dir-through-symlink-1yj`).
    let held = fixture.held_locks_dir();
    let decoy = fixture.scratch("decoy");
    fs::create_dir_all(&decoy).expect("the decoy is creatable");
    if let Some(parent) = held.parent() {
        fs::create_dir_all(parent).expect("the namespace root is creatable");
    }
    let _ = fs::remove_dir_all(&held);
    std::os::unix::fs::symlink(&decoy, &held).expect("the symlink is plantable");

    no_plaintext_store(&fixture, "before the pass");
    let (code, _stdout, _stderr) = swap(&fixture, &[]);
    assert_ne!(code, 0, "the acquire failed, so the swap did not apply");

    let lines = audit_lines(&fixture);
    let broken: Vec<&String> =
        lines.iter().filter(|line| line.contains("\"outcome\":\"broken\"")).collect();
    assert_eq!(
        broken.len(),
        1,
        "exactly one break is recorded, on a path that then failed: {lines:?}"
    );
    assert!(
        broken[0].contains("\"tree\":\"agctl\""),
        "and it names the tree the lock was in: {}",
        broken[0]
    );
    assert!(!primary.exists(), "the peer's stale lock really was removed");
    assert_eq!(writes(&fixture).len(), 0, "and nothing was written");
    audit_carries_no_token(&fixture);
    no_plaintext_store(&fixture, "after an acquire that failed");
    // Phase A's read only: the acquire failed before the re-read.
    assert_security(&fixture, &[("find-generic-password", 1)]);
    let _ = token;
}

/// Backdates a path past the staleness threshold.
///
/// Through `touch(1)` rather than a crate, exactly as `e2e_doctor_stale.rs`
/// does it: setting an mtime is the whole of what is needed, and it sets a
/// directory's timestamp as readily as a file's.
fn age(path: &Path) {
    let status = std::process::Command::new("/usr/bin/touch")
        .args(["-t", "202601010000.00"])
        .arg(path)
        .status()
        .expect("`touch` should be runnable");
    assert!(status.success(), "`touch` failed: {status}");
}

// ---------------------------------------------------------------------------
// `use --undo` — plan section 3.4's rollback (W4a)
// ---------------------------------------------------------------------------

/// Runs `claude use --undo --yes` and returns (code, stdout, stderr).
fn undo(fixture: &Fixture) -> (i32, String, String) {
    let output = fixture
        .cmd()
        .args(["claude", "use", "--undo", "--yes"])
        .output()
        .expect("the binary should run");
    (
        output.status.code().expect("the process exited normally"),
        String::from_utf8(output.stdout).expect("stdout is UTF-8"),
        common::strip_ansi(&String::from_utf8(output.stderr).expect("stderr is UTF-8")),
    )
}

/// The `write` audit lines, oldest first.
fn write_lines(fixture: &Fixture) -> Vec<String> {
    audit_lines(fixture).into_iter().filter(|line| line.contains("\"event\":\"write\"")).collect()
}

/// One `"key":"value"` string field out of an audit line.
fn field(line: &str, key: &str) -> Option<String> {
    let value: Value = serde_json::from_str(line).ok()?;
    value.get(key)?.as_str().map(str::to_owned)
}

#[test]
fn undo_puts_the_displaced_credential_back_and_parks_the_incoming_one() {
    // The rollback, end to end: swap T in, then undo. Afterwards the item
    // holds P again, the adopted copy holds T, and `.credentials.json` is
    // still absent — the operation is its own inverse, and neither direction
    // resurrects a store fact F35's composed read would shadow.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, service) = two_accounts(&server, common::fresh_at());

    let item = fixture.keychain_item_path_for(common::KEYCHAIN_ACCOUNT, &service);
    let adopted = adopted_path(&fixture, ACCT, ORG);
    let store_credentials = fixture.ns_dir(ACCT, ORG).join(".credentials.json");
    assert!(!store_credentials.exists(), "no plaintext store before either pass");
    assert!(!adopted.exists(), "and no adopted copy");

    no_plaintext_store(&fixture, "before the pass");
    let (code, _stdout, stderr) = swap(&fixture, &[]);
    assert_eq!(code, 0, "the swap applied");
    hold_within_budget(&stderr);
    assert!(
        fs::read_to_string(&item).expect("readable").contains("sk-ant-oat01-incoming"),
        "the item holds T"
    );

    let (code, stdout, stderr) = undo(&fixture);
    assert_eq!(code, 0, "the undo applied: {stdout}");
    // The reversal's own hold, measured in the direction that had no
    // instance of this assertion at all.
    hold_within_budget(&stderr);

    // The item holds P again.
    let after = fs::read_to_string(&item).expect("the item is readable");
    assert!(after.contains("sk-ant-oat01-outgoing"), "the item holds P again: {after}");
    assert!(!after.contains("sk-ant-oat01-incoming"), "and no longer T");

    // T is now the displaced credential, parked in the same copy.
    let parked = fs::read_to_string(&adopted).expect("the adopted copy is readable");
    assert!(parked.contains("sk-ant-oat01-incoming"), "the copy now holds T: {parked}");

    // And `.credentials.json` was never resurrected in either direction.
    assert!(
        !store_credentials.exists(),
        "neither the swap nor its undo may resurrect `.credentials.json`"
    );

    // Exactly two writes, and the audit's digests cross: the undo's `from` is
    // the swap's `to`, and the undo's `to` is the swap's `from`.
    assert_eq!(writes(&fixture).len(), 2, "one write each way: {:?}", writes(&fixture));
    let lines = write_lines(&fixture);
    assert_eq!(lines.len(), 2, "one audit write line each way: {lines:?}");
    for line in &lines {
        assert_eq!(field(line, "outcome").as_deref(), Some("applied"), "{line}");
    }
    let (swap_from, swap_to) = (field(&lines[0], "from_digest8"), field(&lines[0], "to_digest8"));
    let (undo_from, undo_to) = (field(&lines[1], "from_digest8"), field(&lines[1], "to_digest8"));
    assert!(swap_from.is_some() && swap_to.is_some(), "the swap recorded both digests");
    assert_eq!(undo_from, swap_to, "the undo displaced what the swap wrote");
    assert_eq!(undo_to, swap_from, "and wrote back what the swap displaced");
    assert_ne!(swap_from, swap_to, "the two credentials really are different");

    artefacts_released(&fixture);
    live_item_never_written(&fixture);
    audit_carries_no_token(&fixture);
    // Three reads and one write each way.
    assert_security(
        &fixture,
        &[("find-generic-password", 6), ("-i", 2), ("add-generic-password", 2)],
    );
    let _ = token;
    no_plaintext_store(&fixture, "after the pass");
}

#[test]
fn undo_restores_p_after_a_write_that_failed_once_the_adoption_had_happened() {
    // Plan AC69's last clause: `swap_write_fail` leaves P recoverable by
    // `use --undo`. The failed swap wrote nothing to the item but *had*
    // already adopted P, so the copy is what the rollback reads.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (mut fixture, service) = two_accounts(&server, common::fresh_at());
    fixture.fault("swap_write_fail");

    let item = fixture.keychain_item_path_for(common::KEYCHAIN_ACCOUNT, &service);
    no_plaintext_store(&fixture, "before the pass");
    let (code, _stdout, stderr) = swap(&fixture, &[]);
    assert_ne!(code, 0, "the write failed");
    // A failed write still took the hold and still released it: the child ran
    // and exited non-zero inside it.
    hold_within_budget(&stderr);
    assert!(
        fs::read_to_string(&item).expect("readable").contains("sk-ant-oat01-outgoing"),
        "the item was never touched, so it still holds P"
    );
    assert!(adopted_path(&fixture, ACCT, ORG).exists(), "but P was already adopted");

    // The failed write is not reversible — it wrote nothing — so `--undo`
    // says so rather than inventing a rollback.
    let (code, stdout, stderr) = undo(&fixture);
    assert_eq!(code, 0, "nothing to undo is not an error: {stdout}{stderr}");
    assert!(stdout.contains("no swap to undo"), "{stdout}");
    assert_eq!(writes(&fixture).len(), 0, "and it wrote nothing");

    // P is still where AC69 says it is: readable, and still the item's.
    let parked = fs::read_to_string(adopted_path(&fixture, ACCT, ORG)).expect("readable");
    assert!(parked.contains("sk-ant-oat01-outgoing"), "P is recoverable from the copy");
    no_plaintext_store(&fixture, "after a failed write and an undo that found nothing");
    // The failed swap's two reads, and nothing from the undo, which refused
    // before reading anything.
    assert_security(&fixture, &[("find-generic-password", 2)]);
    let _ = token;
    audit_carries_no_token(&fixture);
}

#[test]
fn undo_with_no_reversible_entry_says_so_and_writes_nothing() {
    let server = MockServer::start();
    let (fixture, _service) = two_accounts(&server, common::fresh_at());

    no_plaintext_store(&fixture, "before the pass");
    let (code, stdout, _stderr) = undo(&fixture);
    assert_eq!(code, 0, "an empty log is not an error");
    assert!(stdout.contains("no swap to undo"), "{stdout}");
    assert_eq!(writes(&fixture).len(), 0);
    assert_security(&fixture, &[]);
    artefacts_released(&fixture);
    no_plaintext_store(&fixture, "after an undo with nothing to undo");
    audit_carries_no_token(&fixture);
}

#[test]
fn undo_of_a_live_target_entry_refuses_when_nothing_holds_the_credential_it_names() {
    // Constructed directly in the fixture, because W4a never writes a live
    // item — which is exactly why this case needs a hand-built entry to be
    // reachable at all.
    let server = MockServer::start();
    let (fixture, _service) = two_accounts(&server, common::fresh_at());

    let entry = json!({
        "ts": "2026-09-10T00:00:00Z",
        "monotonic_ms": 0,
        "agctl_pid": 1,
        "event": "write",
        "target": "live",
        "from_digest8": "deadbeef",
        "to_digest8": "cafebabe",
        "outcome": "applied",
    });
    let log = fixture.audit_log_path();
    fs::create_dir_all(log.parent().expect("the audit log has a parent"))
        .expect("the audit directory is creatable");
    fs::write(&log, format!("{entry}\n")).expect("the audit log is writable");

    no_plaintext_store(&fixture, "before the pass");
    let (code, _stdout, stderr) = undo(&fixture);
    // W4a refused this as `not_implemented`. W4b acts on a live entry — but a
    // hand-built one names a credential (`deadbeef`) that no namespace holds,
    // and a reversal that cannot find what the entry displaced will not guess.
    // The sentence names the digest so an operator can look for it.
    assert_eq!(code, 1, "an unresolvable entry is an `AppError::Config`, which exits EXIT_FATAL");
    assert!(stderr.contains("deadbeef"), "it names the credential it could not find: {stderr}");
    assert!(
        stderr.contains("nothing to put back") || stderr.contains("not in any namespace"),
        "and says why: {stderr}"
    );
    assert_eq!(writes(&fixture).len(), 0, "nothing was written");
    assert_security(&fixture, &[]);
    artefacts_released(&fixture);
    no_plaintext_store(&fixture, "after an undo of a live-target entry");
    audit_carries_no_token(&fixture);
}

#[test]
fn undo_refuses_when_the_adopted_copy_does_not_match_the_entry() {
    // The copy has to be the one that swap parked, matched by the digest the
    // entry recorded. Anything else and the rollback would restore a
    // credential the user never asked to come back.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, _service) = two_accounts(&server, common::fresh_at());

    no_plaintext_store(&fixture, "before the pass");
    let (code, _stdout, stderr) = swap(&fixture, &[]);
    assert_eq!(code, 0);
    hold_within_budget(&stderr);

    // Something else entirely, in place of the copy the swap wrote.
    let adopted = adopted_path(&fixture, ACCT, ORG);
    fs::write(
        &adopted,
        common::identified_blob(
            "sk-ant-oat01-stranger",
            "sk-ant-ort01-stranger",
            common::fresh_at(),
            ACCT,
            Some(ORG),
        ),
    )
    .expect("the copy is writable");

    let writes_before = writes(&fixture).len();
    let (code, _stdout, stderr) = undo(&fixture);
    assert_eq!(code, 1, "a mismatch is a refusal: {stderr}");
    assert!(stderr.contains("will not put back"), "{stderr}");
    assert_eq!(writes(&fixture).len(), writes_before, "and nothing further was written");
    // Only the swap's calls: the undo refused on the digest before it read
    // anything from the keychain.
    assert_security(
        &fixture,
        &[("find-generic-password", 3), ("-i", 1), ("add-generic-password", 1)],
    );
    no_plaintext_store(&fixture, "after a refused undo");
    let _ = token;
    audit_carries_no_token(&fixture);
}

// ---------------------------------------------------------------------------
// AC67 refusal D — the line does not fit, decided before any child exists
// ---------------------------------------------------------------------------

/// A blob whose fact-F42 line cannot fit, by padding the access token.
///
/// The line is the blob hex-encoded, so it is twice the blob's length: a
/// 3 000-byte token puts the line well past the 4 032-byte limit without
/// needing to know the rest of the shape.
fn oversized_blob(acct: &str, org: &str, expires_at_ms: i64) -> String {
    let padded = format!("sk-ant-oat01-{}", "x".repeat(3_000));
    common::identified_blob(&padded, "sk-ant-ort01-padded", expires_at_ms, acct, Some(org))
}

#[test]
fn ac67_refusal_d_on_the_stored_blob_is_decided_before_any_child_exists() {
    // Invariant I15, first check: the incoming credential as it sits in its
    // own store already exceeds the line, and that is settled in Phase A —
    // outside every lock, before the POST, and before a `security` child
    // could exist. Discovering it later would mean discovering it with the
    // peer's three locks held and a process already spawned.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, _service) = two_accounts(&server, common::fresh_at());
    fixture.write_credentials(ACCT_T, ORG_T, &oversized_blob(ACCT_T, ORG_T, common::fresh_at()));
    no_plaintext_store(&fixture, "before the pass");

    let (code, stdout, _stderr) = swap(&fixture, &[]);
    assert_eq!(code, 12, "SWAP_EXIT_REFUSED_D");
    assert!(stdout.contains("4032-byte keychain line"), "{stdout}");

    assert_eq!(token.calls(), 0, "refused before the POST");
    assert_eq!(writes(&fixture).len(), 0, "and before any child: {:?}", writes(&fixture));
    // One read of the item, and nothing after it: the refusal is decided from
    // the blob and the service name alone.
    assert_security(&fixture, &[("find-generic-password", 1)]);
    assert!(
        !audit_lines(&fixture).iter().any(|line| line.contains("\"event\":\"write\"")),
        "no write entry: {:?}",
        audit_lines(&fixture)
    );
    artefacts_released(&fixture);
    no_plaintext_store(&fixture, "after refusal D");
    live_item_never_written(&fixture);

    let (code, stdout, _stderr) = swap(&fixture, &["--json"]);
    assert_eq!(code, 12);
    let doc = outcome_doc(&stdout);
    assert_eq!(doc["outcome"], json!("refused"), "{doc}");
    assert_eq!(doc["refusal"], json!("D"), "{doc}");
    audit_carries_no_token(&fixture);
}

#[test]
fn ac67_refusal_d_on_the_refreshed_blob_is_decided_before_any_child_exists() {
    // The second check, and the one the first cannot stand in for: the stored
    // blob fits, the POST succeeds, and the credential that comes *back* is
    // the one that does not fit. Still Phase B, still outside Claude Code's
    // locks, still before any child.
    let server = MockServer::start();
    let token = server.mock(|when, then| {
        when.method(POST).path(common::TOKEN_PATH);
        then.status(200).json_body(json!({
            "access_token": format!("sk-ant-oat01-{}", "y".repeat(3_000)),
            "refresh_token": "sk-ant-ort01-rotated",
            "token_type": "Bearer",
            "expires_in": 28_800,
            "refresh_token_expires_in": 2_377_445,
            "scope": "user:inference user:profile",
        }));
    });
    // Expired, so step 13 refreshes it and the refreshed blob is what step 14
    // measures.
    let (fixture, _service) = two_accounts(&server, common::expired_at());
    no_plaintext_store(&fixture, "before the pass");

    let (code, stdout, _stderr) = swap(&fixture, &[]);
    assert_eq!(code, 12, "SWAP_EXIT_REFUSED_D on the refreshed blob");
    assert!(stdout.contains("4032-byte keychain line"), "{stdout}");

    assert_eq!(token.calls(), 1, "the POST happened; it is its answer that does not fit");
    assert_eq!(writes(&fixture).len(), 0, "and still no child: {:?}", writes(&fixture));
    // Phase A's read of the store's item; the probe that asks whether the
    // **incoming** store has migrated — which is only asked of a credential
    // that has expired, because that is the one case where refreshing it
    // would rotate a token this swap could not save (finding N-8); and the
    // write-back's own gate asking the same question again **under the lock,
    // after the POST**, once per name this namespace could have migrated
    // under (`agctl-r9w` review F1: the export spelling and, when it differs,
    // the canonical one — two here because a temporary directory's canonical
    // path is not the one the record was created with).
    assert_security(&fixture, &[("find-generic-password", 4)]);
    artefacts_released(&fixture);
    no_plaintext_store(&fixture, "after refusal D");
    assert!(
        !adopted_path(&fixture, ACCT, ORG).exists(),
        "and nothing was adopted: the refusal precedes step 15"
    );

    // The `--json` document for the same refusal, on a **fresh** fixture: the
    // run above saved its refreshed credential back into the incoming
    // account's own store (finding N-8), so a second pass over that fixture
    // would refuse at the *first* check on the now-oversized stored blob and
    // would prove the other test's point rather than this one's.
    let (fixture, _service) = two_accounts(&server, common::expired_at());
    let (code, stdout, _stderr) = swap(&fixture, &["--json"]);
    assert_eq!(code, 12);
    assert_eq!(token.calls(), 2, "the second pass made its own POST");
    let doc = outcome_doc(&stdout);
    assert_eq!(doc["outcome"], json!("refused"), "{doc}");
    assert_eq!(doc["refusal"], json!("D"), "{doc}");
    audit_carries_no_token(&fixture);
}

// ---------------------------------------------------------------------------
// AC67 refusal A — an artefact moved under a lock agctl was holding
// ---------------------------------------------------------------------------

#[test]
fn ac67_refusal_a_when_an_artefact_moves_under_the_hold() {
    // The one refusal that can only be decided *inside* the hold, and until
    // now the one with no test: `swap_pause_in_locks` is the seam the
    // contract designated for it, and it sits **above** the second drift
    // check precisely so a test can move an artefact's modification time
    // during the pause and have it looked at again.
    //
    // It doubles as the proof that the three artefacts are **created**: a
    // poller watches them from outside for the length of the pause, which is
    // the only window in which they exist.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (mut fixture, _service) = two_accounts(&server, common::fresh_at());
    let resume = fixture.scratch("resume");
    fixture.fault("swap_pause_in_locks");
    fixture.set("AGCTL_FAULT_RESUME", &resume.to_string_lossy());

    let artefacts = fixture.hold_artefacts(ACCT, ORG);
    let watch = ArtefactWatch::start(artefacts.clone());
    let [primary, _legacy, _storage] = artefacts.clone();

    no_plaintext_store(&fixture, "before the pass");
    let child = fixture
        .raw()
        .args(["claude", "use", "--live", EMAIL_T, "--yes", "--json"])
        .spawn()
        .expect("the binary should start");

    assert!(
        common::wait_until(Duration::from_secs(20), || primary.exists()),
        "the hold should have opened and then paused inside itself"
    );
    // The artefact appearing only says the hold opened; the pause is a few
    // microseconds later. Waiting past that is what makes this test *about*
    // the pause's position: with the pause below the second drift check, the
    // check has long since run by the time this fires, and the swap applies.
    std::thread::sleep(Duration::from_millis(300));
    // `utimes` on an artefact agctl is holding: the peer's protocol says
    // the holder owns that modification time, so a change to it is a
    // violation whoever made it.
    age(&primary);
    fs::write(&resume, b"go").expect("the resume file is writable");

    let output = child.wait_with_output().expect("the swap finishes");
    let (seen, windows) = watch.finish();
    let code = output.status.code().expect("exited normally");
    let stderr = common::strip_ansi(&String::from_utf8(output.stderr).expect("stderr is UTF-8"));
    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");

    assert_eq!(code, 10, "SWAP_EXIT_REFUSED_A: {stderr}");
    let doc = outcome_doc(&stdout);
    assert_eq!(doc["outcome"], json!("refused"), "{doc}");
    assert_eq!(
        doc["refusal"],
        json!("A"),
        "the one letter that means somebody moved a lock agctl was holding: {doc}"
    );
    assert!(doc["lock"]["hold_ms"].is_u64(), "the hold it was holding is reported: {doc}");
    assert!(!stdout.contains("sk-ant-"), "{stdout}");
    assert_eq!(seen, 3, "all three artefacts were created inside the hold");
    assert!(windows >= 1, "and the poller saw the hold open");
    assert_eq!(writes(&fixture).len(), 0, "nothing was written: {:?}", writes(&fixture));
    artefacts_released(&fixture);
    no_plaintext_store(&fixture, "after refusal A");
    audit_carries_no_token(&fixture);
    // Phase A's read and the re-read under the hold. The refusal lands before
    // the write, so there is no verifying read.
    assert_security(&fixture, &[("find-generic-password", 2)]);
    let _ = token;
}

// ---------------------------------------------------------------------------
// AC68 — a live refresh lock is waited out with nothing held
// ---------------------------------------------------------------------------

#[test]
fn ac68_a_fresh_refresh_lock_is_waited_out_with_nothing_held() {
    // Plan AC68. A Claude Code session is refreshing: its `.oauth_refresh.lock`
    // is present and **fresh**, so it is not stale and nothing may break it.
    // agctl waits on fact F36's own schedule — holding nothing — and when
    // the session releases, the swap completes. The evidence that the wait
    // happened outside the hold is the pair of numbers: seconds of wall clock
    // against a hold of milliseconds.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, _service) = two_accounts(&server, common::fresh_at());

    let [primary, _legacy, _storage] = fixture.hold_artefacts(ACCT, ORG);
    fs::create_dir_all(&primary).expect("the peer's lock is plantable");
    let releaser = {
        let primary = primary.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(2_000));
            let _ = fs::remove_dir_all(&primary);
        })
    };

    let started = Instant::now();
    no_plaintext_store(&fixture, "before the pass");
    let (code, stdout, stderr) = swap(&fixture, &[]);
    let waited = started.elapsed();
    let _ = releaser.join();

    assert_eq!(code, 0, "the swap completed once the session released: {stdout}{stderr}");
    hold_within_budget(&stderr);
    assert!(waited >= Duration::from_millis(1_000), "it really did wait: {waited:?}");
    assert_eq!(writes(&fixture).len(), 1, "exactly one write: {:?}", writes(&fixture));
    assert!(
        !audit_lines(&fixture).iter().any(|line| line.contains("\"event\":\"lock_break\"")),
        "a fresh lock is never broken: {:?}",
        audit_lines(&fixture)
    );
    let held =
        hold_ms(&stderr).unwrap_or_else(|| panic!("the release should be logged:\n{stderr}"));
    assert!(
        held < 1_000,
        "the hold was {held} ms; the wait was {waited:?} and happened outside it"
    );
    artefacts_released(&fixture);
    no_plaintext_store(&fixture, "after the swap");
    assert_security(
        &fixture,
        &[("find-generic-password", 3), ("-i", 1), ("add-generic-password", 1)],
    );
    let _ = token;
    audit_carries_no_token(&fixture);
}

// ---------------------------------------------------------------------------
// AC70 — an EEXIST restarts from the lock-free path, never waits while holding
// ---------------------------------------------------------------------------

#[test]
fn ac70_an_eexist_at_the_third_lock_restarts_without_waiting_inside_the_hold() {
    // Plan AC70, at the swap level rather than the lock module's. A fresh
    // `.storage-write` — position 3 of the peer's nesting — makes every
    // attempt fail *after* the first two locks are taken. The rule then
    // releases everything already held and returns to the lock-free path;
    // what it must never do is wait, sample or sleep while holding one.
    //
    // Two numbers say so. The whole pass finishes far inside
    // `STALE_SAMPLE_INTERVAL` (12 s), which is what a single sampling window
    // would cost; and the two locks that *were* taken are gone afterwards,
    // while the planted one — which agctl never owned — is untouched.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, _service) = two_accounts(&server, common::fresh_at());

    let [primary, legacy, storage] = fixture.hold_artefacts(ACCT, ORG);
    fs::create_dir_all(&storage).expect("the peer's storage-write lock is plantable");

    let started = Instant::now();
    no_plaintext_store(&fixture, "before the pass");
    let (code, stdout, stderr) = swap(&fixture, &[]);
    let elapsed = started.elapsed();

    assert_eq!(code, 16, "SWAP_EXIT_BUSY after the restarts ran out: {stdout}{stderr}");
    assert!(
        elapsed < Duration::from_secs(12),
        "a restart that waited would have cost a 12 s sampling window: {elapsed:?}"
    );
    assert!(!primary.exists(), "the primary agctl took was released on the EEXIST");
    assert!(!legacy.exists(), "and so was the legacy lock beneath it");
    assert!(storage.exists(), "while the lock agctl never owned is untouched");
    assert!(hold_ms(&stderr).is_none(), "no hold ever completed, so no release line: {stderr}");
    assert!(
        !audit_lines(&fixture).iter().any(|line| line.contains("\"event\":\"lock_break\"")),
        "nothing was stale, so nothing was broken: {:?}",
        audit_lines(&fixture)
    );
    assert_eq!(writes(&fixture).len(), 0, "and nothing was written: {:?}", writes(&fixture));
    no_plaintext_store(&fixture, "after a busy store");
    // Phase A's read only: the busy answer comes before the re-read.
    assert_security(&fixture, &[("find-generic-password", 1)]);

    let (code, stdout, _stderr) = swap(&fixture, &["--json"]);
    assert_eq!(code, 16);
    let doc = outcome_doc(&stdout);
    assert_eq!(doc["outcome"], json!("busy"), "{doc}");
    assert_eq!(doc["refusal"], Value::Null, "busy is not a lettered refusal: {doc}");
    let _ = fs::remove_dir_all(&storage);
    let _ = token;
    audit_carries_no_token(&fixture);
}

// ---------------------------------------------------------------------------
// AC72 — the first write, into an item that is not there yet
// ---------------------------------------------------------------------------

/// A registry whose store has **not** migrated: no item, and **P** in the
/// plaintext `.credentials.json`. The shape a first write starts from.
fn unmigrated_store(server: &MockServer) -> (Fixture, String) {
    let mut fixture = Fixture::new();
    fixture.with_keychain().endpoints(&server.base_url());
    fixture.write_registry(vec![
        fixture.owned_record(ACCT, ORG),
        owned_record_for(&fixture, ACCT_T, ORG_T, EMAIL_T),
    ]);
    fixture.write_credentials(
        ACCT_T,
        ORG_T,
        &common::identified_blob(
            "sk-ant-oat01-incoming",
            "sk-ant-ort01-incoming",
            common::fresh_at(),
            ACCT_T,
            Some(ORG_T),
        ),
    );
    fixture.write_credentials(
        ACCT,
        ORG,
        &common::identified_blob(
            "sk-ant-oat01-outgoing",
            "sk-ant-ort01-outgoing",
            common::fresh_at(),
            ACCT,
            Some(ORG),
        ),
    );
    let service = common::migration_service(&fixture.ns_dir(ACCT, ORG));
    fixture.dump(&[]);
    fixture.allow_write(&service);
    fixture.set(
        "CLAUDE_SECURESTORAGE_CONFIG_DIR",
        &common::export_spelling(&fixture.ns_dir(ACCT, ORG)),
    );
    fixture.set("RUST_LOG", "agctl=debug");
    (fixture, service)
}

#[test]
fn ac72_a_first_write_records_a_null_from_digest8_and_removes_the_shadowing_store() {
    // AC72's other half. The store has not migrated: there is no item, so the
    // credential displaced is the plaintext store's own and the audit line
    // records `from_digest8: null` — the shape `use --undo` reads as "this
    // swap displaced nothing an *item* held".
    //
    // And finding N-2, which reaching that path for the first time exposed.
    // This test used to assert `.credentials.json` was **byte-identical
    // afterwards**, encoding the leftover as intended. It is not: once the
    // write applies, the item holds T while that file still holds P, and fact
    // F35's composed read falls through to it on *no item, a read failure or
    // a throttle*. A keychain hiccup would hand the peer session the account
    // the user just swapped away from — the exposure decision D-024 exists to
    // prevent, two credentials at rest in one directory. P is in the adopted
    // copy by then, so the file is a duplicate and the swap removes it.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, service) = unmigrated_store(&server);

    let store_credentials = fixture.ns_dir(ACCT, ORG).join(".credentials.json");
    assert!(store_credentials.exists(), "the premise: P is in the plaintext store");
    assert!(
        !adopted_path(&fixture, ACCT, ORG).exists(),
        "and there is no adopted copy to begin with"
    );

    let (code, stdout, stderr) = swap(&fixture, &[]);
    assert_eq!(code, 0, "the first write applied: {stdout}{stderr}");

    no_plaintext_store(&fixture, "after a first write that applied");
    let item = fixture.keychain_item_path_for(common::KEYCHAIN_ACCOUNT, &service);
    assert!(
        fs::read_to_string(&item).expect("readable").contains("sk-ant-oat01-incoming"),
        "the item holds T"
    );
    let parked = fs::read_to_string(adopted_path(&fixture, ACCT, ORG))
        .expect("the adopted copy should hold the displaced credential");
    assert!(parked.contains("sk-ant-oat01-outgoing"), "and the copy holds P: {parked}");
    // A removal that succeeded says nothing; only a failure does. This was
    // written as `contains(..) || !contains(..)`, which is satisfied whenever
    // the stream says nothing at all — so it held even with the warning
    // deliberately forced on, and finding N-7 (an applied swap discarding its
    // own note) went straight past it. Stated as what it means instead, on
    // both streams, with the failing case covered by
    // `an_applied_swap_whose_cleanup_failed_warns_on_stderr_and_in_json`.
    assert!(stdout.contains("swapped:"), "the swap reported success: {stdout}");
    assert!(
        !stdout.contains("still holds") && !stderr.contains("still holds"),
        "a removal that succeeded raises no warning:\n{stdout}\n{stderr}"
    );

    assert_eq!(writes(&fixture).len(), 1, "exactly one `-i` line: {:?}", writes(&fixture));
    let lines = write_lines(&fixture);
    assert_eq!(lines.len(), 1, "one audit write line: {lines:?}");
    assert_eq!(
        field(&lines[0], "from_digest8"),
        None,
        "a first write displaced no item, so the entry records null: {}",
        lines[0]
    );
    assert!(field(&lines[0], "to_digest8").is_some(), "but it names what it wrote: {}", lines[0]);
    assert_eq!(field(&lines[0], "outcome").as_deref(), Some("applied"), "{}", lines[0]);
    hold_within_budget(&stderr);
    audit_carries_no_token(&fixture);
    artefacts_released(&fixture);
    live_item_never_written(&fixture);
    let _ = token;
    // Phase A's read (the item is absent), the re-read under the hold, the
    // write, and the verifying read that confirms it.
    assert_security(
        &fixture,
        &[("find-generic-password", 3), ("-i", 1), ("add-generic-password", 1)],
    );
}

/// The macOS user-immutable flag on one path, cleared when this is dropped.
///
/// `uchg` on the leaf is the smallest state that makes `unlinkat` fail with
/// `EPERM` while the directory stays writable, which is what a backup tool —
/// or an operator running `chflags uchg` — leaves behind. It is cleared on
/// **drop** rather than at the end of the test so a failing assertion still
/// leaves a removable temporary directory: the test binaries unwind, so this
/// runs on the panic path too.
struct ImmutableFile(std::path::PathBuf);

impl ImmutableFile {
    fn set(path: &Path) -> Self {
        let status = std::process::Command::new("/usr/bin/chflags")
            .arg("uchg")
            .arg(path)
            .status()
            .expect("`chflags` should be runnable");
        assert!(status.success(), "`chflags uchg {}` should succeed", path.display());
        Self(path.to_path_buf())
    }
}

impl Drop for ImmutableFile {
    fn drop(&mut self) {
        let _ = std::process::Command::new("/usr/bin/chflags").arg("nouchg").arg(&self.0).status();
    }
}

#[test]
fn an_applied_swap_whose_cleanup_failed_warns_on_stderr_and_in_json() {
    // Finding N-7. `emit` printed `Report::note` only on the **non**-applied
    // arm, so the one outcome on which the two notes exist — a swap that
    // applied and whose credential-at-rest cleanup then failed — was the one
    // outcome that discarded them. The operator saw `swapped: …`, exit 0, and
    // nothing else, while `.credentials.json` still held the credential the
    // swap had displaced under the one name fact F35's composed read falls
    // through to. `--json` kept the note; the terminal, which is the default,
    // did not.
    let server = MockServer::start();
    let token = token_ok(&server);

    // The terminal form: the warning has to reach stderr, not vanish behind
    // the success line and not land on stdout, which `--json` needs clean.
    {
        let (fixture, service) = unmigrated_store(&server);
        let store = fixture.credentials_path(ACCT, ORG);
        // Declared after the fixture, so it is dropped **before** the
        // temporary directory it lives in.
        let _immutable = ImmutableFile::set(&store);

        let (code, stdout, stderr) = swap(&fixture, &[]);
        assert_eq!(code, 0, "the swap applied; only its cleanup failed: {stdout}{stderr}");
        assert!(stdout.contains("swapped:"), "and it says so: {stdout}");
        assert!(
            stderr.contains("remove it by hand"),
            "but the operator is told what is left to do, on stderr: {stderr}"
        );
        assert!(stderr.contains(".credentials.json"), "and which file it is about: {stderr}");
        assert!(!stdout.contains("remove it by hand"), "never on stdout: {stdout}");

        assert!(store.exists(), "the file the unlink could not remove is still there");
        assert!(
            fs::read_to_string(&store).expect("readable").contains("sk-ant-oat01-outgoing"),
            "still holding the credential the swap displaced — which is the whole hazard"
        );
        let item = fixture.keychain_item_path_for(common::KEYCHAIN_ACCOUNT, &service);
        assert!(
            fs::read_to_string(&item).expect("readable").contains("sk-ant-oat01-incoming"),
            "while the item holds the incoming one"
        );
        assert_eq!(writes(&fixture).len(), 1, "one `-i` line: {:?}", writes(&fixture));
        assert_eq!(
            field(&write_lines(&fixture)[0], "outcome").as_deref(),
            Some("applied"),
            "the audit line still says the write applied"
        );
        hold_within_budget(&stderr);
        artefacts_released(&fixture);
        live_item_never_written(&fixture);
        assert_security(
            &fixture,
            &[("find-generic-password", 3), ("-i", 1), ("add-generic-password", 1)],
        );
        audit_carries_no_token(&fixture);
    }

    // The `--json` form, on its own fixture: the same failure, the same note,
    // reached through the document rather than the stream.
    {
        let (fixture, _service) = unmigrated_store(&server);
        let store = fixture.credentials_path(ACCT, ORG);
        let _immutable = ImmutableFile::set(&store);

        let (code, stdout, stderr) = swap(&fixture, &["--json"]);
        assert_eq!(code, 0, "{stdout}{stderr}");
        let doc = outcome_doc(&stdout);
        assert_eq!(doc["outcome"], json!("applied"), "{doc}");
        let note = doc["note"].as_str().unwrap_or_default();
        assert!(note.contains("remove it by hand"), "the same sentence: {note}");
        assert!(note.contains(".credentials.json"), "naming the same file: {note}");
        assert!(!stdout.contains("sk-ant-"), "never a token: {stdout}");
        assert!(store.exists(), "and the file is still there");
        audit_carries_no_token(&fixture);
    }
    let _ = token;
}

#[test]
fn a_first_write_whose_outcome_is_unknown_keeps_the_plaintext_store_and_says_so() {
    // The other half of the N-2 ruling. `unknown` means the write's outcome
    // is *undetermined*: the item may still be empty, in which case
    // `.credentials.json` is the credential's only readable home. Removing it
    // on a guess would cost a login, so the file stays and the note says so —
    // which is the difference between a removal decided by evidence and one
    // decided by optimism.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (mut fixture, _service) = unmigrated_store(&server);
    fixture.fault("keychain_write_hang");

    let store_credentials = fixture.ns_dir(ACCT, ORG).join(".credentials.json");
    let before = fs::read(&store_credentials).expect("the plaintext store is readable");

    let (code, stdout, stderr) = swap(&fixture, &["--json"]);
    assert_eq!(code, 18, "the hung write is `unknown`: {stdout}{stderr}");

    let doc = outcome_doc(&stdout);
    assert_eq!(doc["outcome"], json!("unknown"), "{doc}");
    assert_eq!(
        fs::read(&store_credentials).expect("still readable"),
        before,
        "the plaintext store is untouched while the item's contents are undetermined"
    );
    let note = doc["note"].as_str().unwrap_or_default();
    assert!(note.contains(".credentials.json"), "and the note names the file it left: {note}");
    assert!(note.contains("displaced"), "saying what is in it: {note}");
    // Finding N-9. The note used to end at "re-run `agctl claude status`",
    // which names a command that cannot remove the file — nothing in
    // `status`, `doctor` or `accounts` unlinks a `.credentials.json` — so the
    // advice read as "this will be cleaned up" when nothing ever cleans it
    // up. `status` answers the question the removal turns on: what the item
    // holds. The rest is the operator's, and the note says so.
    assert!(
        note.contains("agctl claude status"),
        "it still points at the command that can answer what the item holds: {note}"
    );
    assert!(
        note.contains("remove that file by hand"),
        "but says who has to remove it, because nothing else will: {note}"
    );
    assert!(note.contains("doctor"), "and names what reports it until then: {note}");
    assert!(!stdout.contains("sk-ant-"), "never a token: {stdout}");

    assert_eq!(field(&write_lines(&fixture)[0], "outcome").as_deref(), Some("unknown"));
    hold_within_budget(&stderr);
    audit_carries_no_token(&fixture);
    artefacts_released(&fixture);
    live_item_never_written(&fixture);
    let _ = token;
    // Phase A's read, the re-read under the hold, and the verifying read that
    // did not settle it. The write child never ran: the fault stands in for
    // one killed at `WRITE_TIMEOUT`.
    assert_security(&fixture, &[("find-generic-password", 3)]);
}

#[test]
fn an_undo_of_a_first_write_puts_p_back_without_recreating_the_plaintext_store() {
    // The consequence of N-2's ruling for `--undo`, and the reason a first
    // write must be reversible at all: after it, P lives **only** in the
    // adopted copy. `select_undo` used to skip a null `from_digest8` as
    // "displaced nothing", which was true of the item and false of the store
    // — and left the user's own credential parked with no supported way back.
    //
    // The reversal is the ordinary one: P into the item, T parked in the copy
    // in its place. What it must not do is resurrect `.credentials.json`,
    // which would put the whole exposure back.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, service) = unmigrated_store(&server);

    let store_credentials = fixture.ns_dir(ACCT, ORG).join(".credentials.json");
    assert!(store_credentials.exists(), "before the pass: P is in the plaintext store");

    let (code, stdout, stderr) = swap(&fixture, &[]);
    assert_eq!(code, 0, "the first write applied: {stdout}{stderr}");
    no_plaintext_store(&fixture, "after the first write");

    let (code, stdout, stderr) = undo(&fixture);
    assert_eq!(code, 0, "the reversal applied: {stdout}{stderr}");

    let item = fixture.keychain_item_path_for(common::KEYCHAIN_ACCOUNT, &service);
    let held = fs::read_to_string(&item).expect("the item is readable");
    assert!(held.contains("sk-ant-oat01-outgoing"), "the item holds P again: {held}");
    let parked = fs::read_to_string(adopted_path(&fixture, ACCT, ORG))
        .expect("the adopted copy is readable");
    assert!(parked.contains("sk-ant-oat01-incoming"), "and the copy now holds T: {parked}");
    no_plaintext_store(&fixture, "after undoing a first write");
    assert!(
        file_store_strays(&fixture).is_empty(),
        "and no staged temporary was left: {:?}",
        file_store_strays(&fixture)
    );

    let lines = write_lines(&fixture);
    assert_eq!(lines.len(), 2, "the first write and its reversal: {lines:?}");
    assert_eq!(field(&lines[1], "outcome").as_deref(), Some("applied"), "{}", lines[1]);
    hold_within_budget(&stderr);
    audit_carries_no_token(&fixture);
    artefacts_released(&fixture);
    live_item_never_written(&fixture);
    let _ = token;
    // The forward swap's three reads and one write, then the reversal's own
    // three reads and one write.
    assert_security(
        &fixture,
        &[("find-generic-password", 6), ("-i", 2), ("add-generic-password", 2)],
    );
}

#[test]
fn re_swapping_the_credential_an_unmigrated_store_already_holds_writes_nothing() {
    // Finding N-3. AC72's step 8 is "the incoming credential is already there
    // — adopt nothing, write nothing, touch nothing", and the fix that made
    // first writes work quietly took its baseline away: `before` is the
    // *item*, which on an unmigrated store is absent, so the comparison was
    // `None == Some(..)` and could never hold. Re-running the same swap then
    // performed a real keychain write, migrated a store nobody had asked to
    // migrate, left a duplicate credential at rest, and reported success for
    // a swap that changed nothing.
    let server = MockServer::start();
    let (fixture, _service) = unmigrated_store(&server);

    // The incoming account's credential *is* the one the store already holds,
    // so there is nothing to swap. Both namespaces get the same blob.
    let same = common::identified_blob(
        "sk-ant-oat01-shared",
        "sk-ant-ort01-shared",
        common::fresh_at(),
        ACCT_T,
        Some(ORG_T),
    );
    fixture.write_credentials(ACCT_T, ORG_T, &same);
    fixture.write_credentials(ACCT, ORG, &same);
    let store_credentials = fixture.ns_dir(ACCT, ORG).join(".credentials.json");
    let before = fs::read(&store_credentials).expect("the plaintext store is readable");

    let (code, stdout, stderr) = swap(&fixture, &["--json"]);
    assert_eq!(code, 0, "already active is a success: {stdout}{stderr}");

    let doc = outcome_doc(&stdout);
    assert_eq!(doc["outcome"], json!("already_active"), "{doc}");
    assert_eq!(doc["from"]["digest8"], Value::Null, "no item held anything: {doc}");
    assert!(doc["to"]["digest8"].is_string(), "but the active credential is named: {doc}");
    assert_eq!(doc["adopted_to"], Value::Null, "nothing was adopted: {doc}");

    assert_eq!(writes(&fixture).len(), 0, "no write: {:?}", writes(&fixture));
    assert_eq!(
        fs::read(&store_credentials).expect("still readable"),
        before,
        "and the store it was not asked to migrate is byte-identical"
    );
    assert!(
        !adopted_path(&fixture, ACCT, ORG).exists(),
        "no duplicate credential was left at rest"
    );
    assert!(audit_lines(&fixture).is_empty(), "and nothing was written to record");
    artefacts_released(&fixture);
    live_item_never_written(&fixture);
    // One read of the absent item, and the decision was taken there. No
    // refresh, because nothing is being written.
    assert_security(&fixture, &[("find-generic-password", 1)]);
    audit_carries_no_token(&fixture);
}

// ---------------------------------------------------------------------------
// AC74 — the write child is killed on a timeout, so the outcome is unknown
// ---------------------------------------------------------------------------

#[test]
fn ac74_a_write_that_hangs_is_unknown_with_its_audit_id_and_a_released_hold() {
    // Ruling OQ6's `unknown` half, and until now the word had no test and its
    // fault no implementation. `keychain_write_hang` is the transport's
    // `testing`-only injection at the spawn site: the caller sees exactly
    // what a child killed at `WRITE_TIMEOUT` produces, so the outcome of the
    // write is undetermined and the verifying read after the release is what
    // settles it. Here it disagrees, so the answer is `unknown` — which means
    // "re-run `status`", not "failed".
    let server = MockServer::start();
    let token = token_ok(&server);
    let (mut fixture, service) = two_accounts(&server, common::fresh_at());
    fixture.fault("keychain_write_hang");

    let item = fixture.keychain_item_path_for(common::KEYCHAIN_ACCOUNT, &service);
    no_plaintext_store(&fixture, "before the pass");
    let (code, stdout, stderr) = swap(&fixture, &["--json"]);
    assert_eq!(code, 18, "SWAP_EXIT_UNKNOWN: {stdout}{stderr}");
    hold_within_budget(&stderr);

    let lines = write_lines(&fixture);
    assert_eq!(lines.len(), 1, "one audit line: {lines:?}");
    assert_eq!(
        field(&lines[0], "outcome").as_deref(),
        Some("unknown"),
        "the write's outcome is undetermined, not failed: {}",
        lines[0]
    );

    let doc = outcome_doc(&stdout);
    assert_eq!(doc["outcome"], json!("unknown"), "{doc}");
    assert_eq!(doc["refusal"], Value::Null, "`unknown` is not a lettered refusal: {doc}");
    assert!(doc["audit"]["id"].is_string(), "the completion carries the audit id: {doc}");
    assert!(doc["target"].as_str().is_some_and(|t| t.starts_with("namespace:")), "{doc}");
    assert!(doc["from"]["digest8"].is_string(), "{doc}");
    assert!(doc["to"]["digest8"].is_string(), "{doc}");
    assert!(doc["lock"]["hold_ms"].is_u64(), "the lock timings the contract names: {doc}");
    assert_eq!(doc["lock"]["budget_ms"], json!(3000), "{doc}");
    assert_eq!(doc["lock"]["break"], Value::Null, "nothing was broken: {doc}");
    assert!(!stdout.contains("sk-ant-"), "no token material in the document: {stdout}");
    for (key, value) in doc.as_object().expect("the document is an object") {
        if let Some(text) = value.as_str() {
            assert!(
                text.len() <= 32 || !text.chars().all(|c| c.is_ascii_hexdigit()),
                "`{key}` looks like a raw hash rather than a digest prefix: {text}"
            );
        }
    }

    // The item was never touched: the child was killed before it could be.
    assert!(
        fs::read_to_string(&item).expect("readable").contains("sk-ant-oat01-outgoing"),
        "the item still holds P"
    );
    artefacts_released(&fixture);
    audit_carries_no_token(&fixture);
    no_plaintext_store(&fixture, "after an unknown write");
    // Phase A's read, the re-read under the hold, and the verifying read that
    // settles the question — the one thing `failed` never issues.
    assert_security(&fixture, &[("find-generic-password", 3)]);
    let _ = token;
}

// ---------------------------------------------------------------------------
// The store moved after its item was named (risk R25)
// ---------------------------------------------------------------------------

#[test]
fn the_swap_refuses_when_the_store_has_moved_since_its_item_was_named() {
    // The precondition's other half. The record still carries the spelling
    // the session inherited — so the byte-for-byte match succeeds — but the
    // namespace agctl derives *now* is somewhere else. The service names
    // the item the session reads; the directory names a store whose
    // `.oauth_refresh.lock` the peer never takes. Writing under those locks
    // would defeat invariant I3' for the one command that writes under the
    // peer's.
    let server = MockServer::start();
    let (mut fixture, _service) = two_accounts(&server, common::fresh_at());
    let moved = fixture.scratch("an-older-namespace");
    let spelling = common::export_spelling(&moved);
    fixture.write_registry(vec![
        json!({
            "account_uuid": ACCT,
            "organization_uuid": ORG,
            "email": EMAIL,
            "org_name": "Acme",
            "label": null,
            "kind": {
                "kind": "owned",
                "export_spelling": spelling,
                "export_sha8": common::sha8(&spelling),
            },
            "forgotten": false,
            "created_at": "2026-09-08T00:00:00Z",
        }),
        owned_record_for(&fixture, ACCT_T, ORG_T, EMAIL_T),
    ]);
    fixture.set("CLAUDE_SECURESTORAGE_CONFIG_DIR", &spelling);

    no_plaintext_store(&fixture, "before the pass");
    let (code, stdout, _stderr) = swap(&fixture, &[]);
    assert_eq!(code, 15, "SWAP_EXIT_PRECONDITION");
    assert!(stdout.contains("the store moved"), "the message says what happened: {stdout}");
    assert!(stdout.contains(&spelling), "and names the spelling the session carries: {stdout}");

    assert_eq!(reads(&fixture).len(), 0, "decided before anything is read");
    assert_eq!(writes(&fixture).len(), 0);
    assert_security(&fixture, &[]);
    assert!(audit_lines(&fixture).is_empty());
    artefacts_released(&fixture);
    no_plaintext_store(&fixture, "after a store-moved refusal");

    let (code, stdout, _stderr) = swap(&fixture, &["--json"]);
    assert_eq!(code, 15);
    let doc = outcome_doc(&stdout);
    assert_eq!(doc["outcome"], json!("refused"), "{doc}");
    assert_eq!(doc["reason"], json!("not_owned"), "{doc}");
    assert_eq!(doc["refusal"], Value::Null, "{doc}");
    audit_carries_no_token(&fixture);
}

#[test]
fn the_undo_refuses_when_the_store_has_moved_since_its_item_was_named() {
    // The same guard, the other direction — which until now was argued sound
    // by construction and had no test. A reversal has no session to inherit a
    // spelling from, so it takes the one the **record** carries; the guard
    // then asserts the same predicate the forward path does, that the
    // namespace agctl derives now is the namespace the item was made for.
    //
    // The shape: a real swap happens, and only then does the record's
    // recorded spelling stop describing where its namespace is. `export_sha8`
    // is left alone, so `--undo` still finds the record that derives the
    // audited item — which is exactly the state in which writing under the
    // Claude Code locks of the derived directory would defeat invariant I3'.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, service) = two_accounts(&server, common::fresh_at());
    no_plaintext_store(&fixture, "before the pass");
    swapped(&fixture, &service);

    let real = common::export_spelling(&fixture.ns_dir(ACCT, ORG));
    let moved = common::export_spelling(&fixture.scratch("an-older-namespace"));
    fixture.write_registry(vec![
        json!({
            "account_uuid": ACCT,
            "organization_uuid": ORG,
            "email": EMAIL,
            "org_name": "Acme",
            "label": null,
            "kind": {
                "kind": "owned",
                // The spelling has moved; the suffix has not, so the entry
                // still names an item this record derives.
                "export_spelling": moved,
                "export_sha8": common::sha8(&real),
            },
            "forgotten": false,
            "created_at": "2026-09-08T00:00:00Z",
        }),
        owned_record_for(&fixture, ACCT_T, ORG_T, EMAIL_T),
    ]);

    let before = writes(&fixture).len();
    let (code, stdout, _stderr) = undo(&fixture);
    assert_eq!(code, 15, "SWAP_EXIT_PRECONDITION, in the reverse direction: {stdout}");
    assert!(stdout.contains("the store moved"), "the message says what happened: {stdout}");
    assert!(stdout.contains(&moved), "and names the spelling the record carries: {stdout}");

    assert_eq!(writes(&fixture).len(), before, "the reversal wrote nothing");
    copy_still_holds_p(&fixture);
    artefacts_released(&fixture);
    no_plaintext_store(&fixture, "after a store-moved refusal in the undo direction");
    audit_carries_no_token(&fixture);
    live_item_never_written(&fixture);
    let _ = token;
    // The forward swap's three reads and one write; the reversal added one
    // read of the adopted copy — which is a file — and then refused before
    // touching the keychain at all.
    assert_security(
        &fixture,
        &[("find-generic-password", 3), ("-i", 1), ("add-generic-password", 1)],
    );
}

#[test]
fn the_namespace_locks_are_taken_in_ascending_key_order() {
    // Ruling OQ11's whole argument is the **order**: two swaps whose
    // namespace sets overlap and which take each other's locks in opposite
    // orders deadlock, and one global ascending sort is what makes that
    // impossible. The property had no test at any level — reversing the sort
    // in `lock_order` left the entire suite green — because the tests that
    // touch it assert the three locks *exist* afterwards, which is
    // order-agnostic.
    //
    // `hold_lock` stalls inside the **first** acquire, so from outside the
    // process the set of lock files that exists names the lock it took first.
    // Ascending over the three accounts here is ACCT ("1111…"), then ACCT_U
    // ("9999…"), then ACCT_T ("aaaa…") — so a reversed sort takes ACCT_T's
    // first and this fails.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (mut fixture, _service) = three_accounts(&server);
    fixture.fault("hold_lock");

    let locks = [
        (ACCT, ORG, "the store's own, and the smallest key"),
        (ACCT_U, ORG_U, "the third namespace's"),
        (ACCT_T, ORG_T, "the incoming account's, and the largest key"),
    ];
    for (acct, org, which) in locks {
        assert!(!fixture.lock_path(acct, org).exists(), "no lock exists before the pass ({which})");
    }

    no_plaintext_store(&fixture, "before the pass");
    let mut child = fixture
        .raw()
        .args(["claude", "use", "--live", EMAIL_T, "--yes"])
        .spawn()
        .expect("the binary should start");

    let first = fixture.lock_path(ACCT, ORG);
    let took_one = common::wait_until(Duration::from_secs(20), || {
        locks.iter().any(|(acct, org, _)| fixture.lock_path(acct, org).exists())
    });
    assert!(took_one, "the pass should have reached its first namespace acquire");

    // The pass is stalled inside that first acquire, so this is not a race:
    // nothing else can be taken until the fault lets go, which it does not.
    assert!(first.exists(), "the ascending-first lock is the one it took");
    for (acct, org, which) in [locks[1], locks[2]] {
        assert!(
            !fixture.lock_path(acct, org).exists(),
            "{which} lock must not be taken before the smaller key's"
        );
    }

    common::send_sigterm(child.id());
    let _ = child.wait();
    let _ = token;
    audit_carries_no_token(&fixture);
    no_plaintext_store(&fixture, "after the pass");
    // Finding N-11: this was the one test in the file with neither a total
    // `security` count nor a write assertion. The count is deterministic —
    // the pass stalls inside its **first** namespace acquire, which is after
    // Phase A's single read of the item and before anything else asks the
    // keychain — and pinning it proves the other half of what a `SIGTERM`'d
    // swap owes: that it wrote nothing on its way to being killed.
    assert_security(&fixture, &[("find-generic-password", 1)]);
    assert!(
        writes(&fixture).is_empty(),
        "a swap killed inside its first acquire writes nothing: {:?}",
        writes(&fixture)
    );
    live_item_never_written(&fixture);
}

// ---------------------------------------------------------------------------
// The third namespace: its lock is in the set, and its store is the target
// ---------------------------------------------------------------------------

/// A third account, whose credential is the one occupying the store's item.
const ACCT_U: &str = "99999999-8888-7777-6666-555555555555";
const ORG_U: &str = "44444444-3333-2222-1111-000000000000";
const EMAIL_U: &str = "third@example.com";

/// `two_accounts` plus a **third** registered account whose credential is the
/// one sitting in the store's item.
///
/// The ordinary state of the second and every later swap of one store: the
/// displaced credential is neither the store's nor the incoming account's, so
/// decision D-017's matrix files it in that third account's own namespace.
fn three_accounts(server: &MockServer) -> (Fixture, String) {
    let (fixture, service) = two_accounts(server, common::fresh_at());
    fixture.write_registry(vec![
        fixture.owned_record(ACCT, ORG),
        owned_record_for(&fixture, ACCT_T, ORG_T, EMAIL_T),
        owned_record_for(&fixture, ACCT_U, ORG_U, EMAIL_U),
    ]);
    fixture.keychain_item(
        &service,
        &common::identified_blob(
            "sk-ant-oat01-third",
            "sk-ant-ort01-third",
            common::fresh_at(),
            ACCT_U,
            Some(ORG_U),
        ),
    );
    (fixture, service)
}

#[test]
fn a_swap_whose_displaced_credential_belongs_to_a_third_account_locks_that_namespace() {
    // Ruling OQ11 ordered two locks; this write needs a third, or it is a
    // blind overwrite of a namespace a concurrent `status` may be refreshing.
    //
    // The lock file's existence afterwards is what proves the lock was taken:
    // it is created by the acquire and by nothing else on this path.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, _service) = three_accounts(&server);
    let third_store = fixture.ns_dir(ACCT_U, ORG_U).join(".credentials.json");
    let third_lock = fixture.lock_path(ACCT_U, ORG_U);
    assert!(!third_store.exists(), "the third namespace has no store before the pass");
    assert!(!third_lock.exists(), "and its namespace lock has never been taken");

    no_plaintext_store(&fixture, "before the pass");
    let (code, stdout, stderr) = swap(&fixture, &[]);
    assert_eq!(code, 0, "the swap applied: {stdout}{stderr}");

    assert!(third_lock.exists(), "the third namespace's lock was taken (ruling P2-4)");
    assert!(third_store.exists(), "and its store now holds the credential the swap displaced");
    assert!(
        fs::read_to_string(&third_store).expect("readable").contains("sk-ant-oat01-third"),
        "which is the third account's own credential"
    );
    assert!(
        !adopted_path(&fixture, ACCT, ORG).exists(),
        "the adopted copy is for the store's *own* credential, not a third party's"
    );
    // All three namespace locks, taken in ascending key order.
    for (acct, org) in [(ACCT, ORG), (ACCT_T, ORG_T), (ACCT_U, ORG_U)] {
        assert!(fixture.lock_path(acct, org).exists(), "the lock for {acct} was taken");
    }
    assert_eq!(writes(&fixture).len(), 1, "one write: {:?}", writes(&fixture));
    hold_within_budget(&stderr);
    artefacts_released(&fixture);
    no_plaintext_store(&fixture, "after the swap");
    // Phase A's read, the migration probe for the third namespace, the
    // re-read under the hold, and the verifying read.
    assert_security(
        &fixture,
        &[("find-generic-password", 4), ("-i", 1), ("add-generic-password", 1)],
    );
    let _ = token;
    audit_carries_no_token(&fixture);
}

// ---------------------------------------------------------------------------
// `--json`: the plan, the prompt it does not skip, and the fields it carries
// ---------------------------------------------------------------------------

#[test]
fn a_json_inspection_nobody_confirmed_writes_no_credential_anywhere() {
    // Finding N-1, in the shape that made it worth a HIGH: the adoption used
    // to be **committed at step 14**, before step 15 printed the plan and
    // asked. So the order was *write the credential, describe the write, ask
    // whether to do it, refuse* — and since `--json` stopped implying
    // `--yes`, `--json` without it became the documented "show me what this
    // would do" form, which `Tty::confirm` fails closed on a pipe. Every such
    // inspection run left a live access **and** refresh token in a 0600 file,
    // and in this three-account shape created a **different** account's
    // `.credentials.json` outright.
    //
    // The assertion is a whole-tree comparison rather than a file name,
    // because a file name is exactly what the old tests could see and this
    // could not: `writes(..) == 0` counts keychain writes, and
    // `no_plaintext_store(..)` looks at one name in one namespace.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, _service) = three_accounts(&server);
    let third_store = fixture.ns_dir(ACCT_U, ORG_U).join(".credentials.json");
    assert!(!third_store.exists(), "the third namespace has no store before the pass");
    no_plaintext_store(&fixture, "before an inspection nobody confirmed");
    let before = tree(&fixture);

    let (code, stdout, stderr) = swap_unconfirmed(&fixture, &["--json"]);
    assert_eq!(code, 20, "nobody agreed, so the swap is cancelled: {stdout}{stderr}");

    let docs = json_docs(&stdout);
    assert_eq!(docs.len(), 2, "the plan, then the outcome: {stdout}");
    assert_eq!(docs[0]["kind"], json!("plan"), "{}", docs[0]);
    let doc = &docs[1];
    assert_eq!(doc["outcome"], json!("cancelled"), "{doc}");
    assert_eq!(doc["refusal"], Value::Null, "a declined swap is not refusal F: {doc}");
    assert_eq!(doc["adopted_to"], Value::Null, "and nothing was adopted: {doc}");

    let after = tree(&fixture);
    no_new_credential_at_rest(&before, &after, "on a run nobody confirmed");
    assert!(
        !adopted_path(&fixture, ACCT, ORG).exists(),
        "no adopted copy on a run that exited refused"
    );
    assert!(!third_store.exists(), "and no third account's store was created");
    assert!(
        file_store_strays(&fixture).is_empty(),
        "not even a staged temporary: {:?}",
        file_store_strays(&fixture)
    );
    assert_eq!(writes(&fixture).len(), 0, "no keychain write: {:?}", writes(&fixture));
    assert!(audit_lines(&fixture).is_empty(), "and nothing was recorded");
    artefacts_released(&fixture);
    no_plaintext_store(&fixture, "after an inspection nobody confirmed");
    live_item_never_written(&fixture);
    let _ = token;
    // Phase A's one read of the item, and the migration probe the third
    // namespace's row of the matrix costs. Both are reads; the pass stopped
    // at the prompt.
    assert_security(&fixture, &[("find-generic-password", 2)]);
    audit_carries_no_token(&fixture);
}

#[test]
fn a_swap_nobody_confirmed_leaves_the_store_exactly_as_it_was() {
    // The same finding without `--json`, on the ordinary two-account shape
    // whose adoption target is the store's own `.credentials.adopted.json`.
    // Here the old order lost nothing — the item still held P — but it still
    // wrote a token to disk on a command the operator refused, which is a
    // consent failure whether or not it is also a loss.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, _service) = two_accounts(&server, common::fresh_at());
    no_plaintext_store(&fixture, "before a swap nobody confirmed");
    let before = tree(&fixture);

    let (code, stdout, stderr) = swap_unconfirmed(&fixture, &[]);
    assert_eq!(code, 20, "nobody agreed, so the swap is cancelled: {stdout}{stderr}");
    assert!(
        stderr.contains("not a terminal") || stdout.contains("not a terminal"),
        "and it says why nobody could be asked: {stdout}{stderr}"
    );

    let after = tree(&fixture);
    no_new_credential_at_rest(&before, &after, "on a swap nobody confirmed");
    assert!(!adopted_path(&fixture, ACCT, ORG).exists(), "no adopted copy");
    assert!(
        file_store_strays(&fixture).is_empty(),
        "and no staged temporary: {:?}",
        file_store_strays(&fixture)
    );
    assert_eq!(writes(&fixture).len(), 0, "no keychain write: {:?}", writes(&fixture));
    assert!(audit_lines(&fixture).is_empty(), "and nothing was recorded");
    artefacts_released(&fixture);
    no_plaintext_store(&fixture, "after a swap nobody confirmed");
    live_item_never_written(&fixture);
    let _ = token;
    assert_security(&fixture, &[("find-generic-password", 1)]);
    audit_carries_no_token(&fixture);
}

// ---------------------------------------------------------------------------
// N-8 — the refresh POST is behind the consent gate, and its result is saved
// ---------------------------------------------------------------------------

/// The incoming account's own store.
fn incoming_store(fixture: &Fixture) -> std::path::PathBuf {
    fixture.credentials_path(ACCT_T, ORG_T)
}

#[test]
fn a_swap_nobody_confirmed_makes_no_refresh_post_at_all() {
    // Finding N-8, in the shape that made it a HIGH. The refresh used to run
    // at step 11, **before** the plan and the prompt, and its result was a
    // local that every non-applying exit dropped. A refresh is not a read:
    // the server rotates the refresh token away from whatever held the old
    // one, so the run left the incoming account's own store holding a dead
    // grant and that account needing an interactive `login` — on a command
    // the operator had just declined. `--json` without `--yes` is the
    // documented "show me what this would do" form and `Tty::confirm` fails
    // closed on a pipe, so every scripted inspection of a dormant account
    // burned it.
    //
    // The credential here is expired, which for an account one is about to
    // swap **in** is the ordinary state — that is why this was the common
    // path rather than a corner.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, _service) = two_accounts(&server, common::expired_at());
    let store = incoming_store(&fixture);
    let held = fs::read(&store).expect("the incoming account's own store is readable");
    no_plaintext_store(&fixture, "before a swap nobody confirmed");
    let before = tree(&fixture);

    let (code, stdout, stderr) = swap_unconfirmed(&fixture, &["--json"]);
    assert_eq!(code, 20, "nobody agreed, so the swap is cancelled: {stdout}{stderr}");

    assert_eq!(token.calls(), 0, "and nobody's grant was spent to find that out");
    assert_eq!(
        fs::read(&store).expect("still readable"),
        held,
        "the incoming account's own store is byte-identical: a declined swap costs it nothing"
    );
    let after = tree(&fixture);
    no_new_credential_at_rest(&before, &after, "on a swap nobody confirmed");
    assert_eq!(writes(&fixture).len(), 0, "no keychain write: {:?}", writes(&fixture));
    assert!(audit_lines(&fixture).is_empty(), "and nothing was recorded");
    artefacts_released(&fixture);
    no_plaintext_store(&fixture, "after a swap nobody confirmed");
    live_item_never_written(&fixture);
    // Phase A's one read of the item. The migration probe that guards the
    // refresh sits *behind* the prompt with the POST, so a cancelled run does
    // not pay for it either.
    assert_security(&fixture, &[("find-generic-password", 1)]);
    audit_carries_no_token(&fixture);
}

#[test]
fn an_applied_swap_saves_the_refreshed_credential_back_to_the_incoming_store() {
    // The other half of N-8, and the half that was broken on the **success**
    // path too: the refreshed pair went into the item and the incoming
    // account's own store kept the rotated-away one, so swapping back out
    // again would have found a dead grant there. Every other refresh in this
    // crate persists its result immediately; this one now does too, under the
    // namespace lock step 10 already holds for that record.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, service) = two_accounts(&server, common::expired_at());
    let store = incoming_store(&fixture);
    assert!(
        fs::read_to_string(&store).expect("readable").contains("sk-ant-ort01-incoming"),
        "the premise: the incoming store holds the pre-refresh pair"
    );

    no_plaintext_store(&fixture, "before the pass");
    let (code, stdout, stderr) = swap(&fixture, &[]);
    assert_eq!(code, 0, "the swap applied: {stdout}{stderr}");
    assert_eq!(token.calls(), 1, "exactly one refresh POST");

    let saved = fs::read_to_string(&store).expect("the incoming store is still readable");
    assert!(saved.contains("sk-ant-oat01-rotated"), "it holds the refreshed access token: {saved}");
    assert!(
        saved.contains("sk-ant-ort01-rotated"),
        "and the refresh token the server rotated to, which is the one that matters: {saved}"
    );
    let item =
        fs::read_to_string(fixture.keychain_item_path_for(common::KEYCHAIN_ACCOUNT, &service))
            .expect("the item is readable");
    assert_eq!(
        item, saved,
        "the item and the incoming store hold the same credential, byte for byte: one refresh, \
         two homes, no dead grant"
    );

    assert_eq!(writes(&fixture).len(), 1, "one `-i` line: {:?}", writes(&fixture));
    hold_within_budget(&stderr);
    artefacts_released(&fixture);
    no_plaintext_store(&fixture, "after the swap");
    live_item_never_written(&fixture);
    // Phase A's read, the probe asking whether the incoming store has
    // migrated, the write-back gate's two (one per candidate service name,
    // asked again under the lock after the POST — `agctl-r9w` review F1), the
    // re-read under the hold, and the verifying read.
    assert_security(
        &fixture,
        &[("find-generic-password", 6), ("-i", 1), ("add-generic-password", 1)],
    );
    audit_carries_no_token(&fixture);
}

#[test]
fn a_swap_discarded_after_the_refresh_still_leaves_the_refreshed_pair_saved() {
    // The exit N-8 is really about: the POST has happened and the swap then
    // ends without writing. A discard throws the *item* write away, which is
    // right — the item moved under it — but the grant is already spent, so
    // the incoming account's own store must hold what the server rotated to
    // or that account is dead through no fault of its own.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (mut fixture, service) = two_accounts(&server, common::expired_at());
    let resume = fixture.scratch("resume");
    fixture.fault("pause_before_swap_write");
    fixture.set("AGCTL_FAULT_RESUME", &resume.to_string_lossy());

    let item = fixture.keychain_item_path_for(common::KEYCHAIN_ACCOUNT, &service);
    let peer = common::identified_blob(
        "sk-ant-oat01-peer",
        "sk-ant-ort01-peer",
        common::fresh_at(),
        ACCT,
        Some(ORG),
    );
    let store = incoming_store(&fixture);

    no_plaintext_store(&fixture, "before the pass");
    let child = fixture
        .raw()
        .args(["claude", "use", "--live", EMAIL_T, "--yes", "--json"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the binary should start");

    // The pause is after the refresh and after the adoption, so by the time
    // the store holds the rotated pair the swap is waiting to be let go.
    common::wait_until(Duration::from_secs(20), || {
        fs::read_to_string(&store).is_ok_and(|text| text.contains("sk-ant-ort01-rotated"))
    });
    std::thread::sleep(Duration::from_millis(200));
    fs::write(&item, &peer).expect("the peer writes the item");
    fs::write(&resume, b"go").expect("the resume file is writable");

    let output = child.wait_with_output().expect("the swap finishes");
    assert_eq!(output.status.code(), Some(17), "SWAP_EXIT_DISCARDED");
    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    assert_eq!(outcome_doc(&stdout)["outcome"], json!("discarded"), "{stdout}");

    assert_eq!(token.calls(), 1, "the POST happened before the discard");
    let saved = fs::read_to_string(&store).expect("the incoming store is readable");
    assert!(
        saved.contains("sk-ant-ort01-rotated"),
        "and its result is saved even though the swap wrote nothing: {saved}"
    );
    assert_eq!(writes(&fixture).len(), 0, "zero `-i` lines: {:?}", writes(&fixture));
    // Phase A's read, the migration probe, the write-back gate's two (one per
    // candidate service name, under the lock after the POST — `agctl-r9w`
    // review F1), and the re-read under the hold that found the change.
    assert_security(&fixture, &[("find-generic-password", 5)]);
    artefacts_released(&fixture);
    no_plaintext_store(&fixture, "after a discarded swap");
    live_item_never_written(&fixture);
    audit_carries_no_token(&fixture);
}

#[test]
fn an_expired_incoming_credential_in_a_migrated_store_is_refused_before_the_post() {
    // N-8's third clause. The write-back above can save a refreshed
    // credential into a plaintext `.credentials.json`; it cannot write a
    // second keychain item inside this pass, and no ruling authorises one. So
    // when the incoming store has migrated **and** its credential is stale,
    // the refresh would be spent and thrown away exactly as before — and the
    // answer is to refuse in front of the POST and name the command that does
    // refresh such an item in place and persist it.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, _service) = two_accounts(&server, common::expired_at());
    let incoming_service = common::migration_service(&fixture.ns_dir(ACCT_T, ORG_T));
    fixture.keychain_item(
        &incoming_service,
        &common::identified_blob(
            "sk-ant-oat01-incoming",
            "sk-ant-ort01-incoming",
            common::expired_at(),
            ACCT_T,
            Some(ORG_T),
        ),
    );
    let store = incoming_store(&fixture);
    let held = fs::read(&store).expect("readable");

    no_plaintext_store(&fixture, "before the pass");
    let (code, stdout, stderr) = swap(&fixture, &["--json"]);
    assert_eq!(code, 21, "SWAP_EXIT_NEEDS_REFRESH: {stdout}{stderr}");

    assert_eq!(token.calls(), 0, "refused in front of the POST, not after it");
    let doc = outcome_doc(&stdout);
    assert_eq!(doc["outcome"], json!("needs_refresh"), "{doc}");
    assert_eq!(doc["refusal"], Value::Null, "nothing about the store is wrong: {doc}");
    let note = doc["note"].as_str().unwrap_or_default();
    assert!(note.contains("agctl claude status"), "the note names the remedy: {note}");
    assert!(!stdout.contains("sk-ant-"), "never a token: {stdout}");

    assert_eq!(writes(&fixture).len(), 0, "and nothing was written: {:?}", writes(&fixture));
    assert_eq!(fs::read(&store).expect("readable"), held, "the incoming store is untouched");
    assert!(!adopted_path(&fixture, ACCT, ORG).exists(), "nothing was adopted");
    assert!(audit_lines(&fixture).is_empty(), "and nothing was recorded");
    artefacts_released(&fixture);
    no_plaintext_store(&fixture, "after the refusal");
    live_item_never_written(&fixture);
    // Phase A's read of the store's item, and the migration probe that
    // decided this.
    assert_security(&fixture, &[("find-generic-password", 2)]);
    audit_carries_no_token(&fixture);
}

#[test]
fn a_migrated_incoming_store_says_why_instead_of_sending_the_user_to_login() {
    // W4a reads the incoming credential from a plaintext store and only from
    // there, so an incoming namespace that has migrated into the keychain
    // cannot be swapped in yet. That refusal is right; its **sentence** was
    // not. It said "no readable credential to swap in; run `agctl claude
    // login` for it", which is false twice over: the credential is there, and
    // a fresh login would rotate a working refresh token away to fix nothing.
    //
    // Both halves are here because the correction has to discriminate. An
    // account that has genuinely never logged in still needs a `login`, and a
    // guard that could not tell the two apart would trade one wrong sentence
    // for another.
    let server = MockServer::start();
    let token = token_ok(&server);

    // Migrated: no plaintext store, a readable item under its own namespace's
    // migration service.
    {
        let (fixture, _service) = two_accounts(&server, common::fresh_at());
        let store = incoming_store(&fixture);
        fs::remove_file(&store).expect("the incoming plaintext store is removable");
        fixture.keychain_item(
            &common::migration_service(&fixture.ns_dir(ACCT_T, ORG_T)),
            &common::identified_blob(
                "sk-ant-oat01-incoming",
                "sk-ant-ort01-incoming",
                common::fresh_at(),
                ACCT_T,
                Some(ORG_T),
            ),
        );

        let (code, stdout, stderr) = swap(&fixture, &[]);
        assert_eq!(code, 14, "still refusal F, and still Phase A: {stdout}{stderr}");
        assert!(
            stdout.contains("lives in its keychain item"),
            "the refusal says where the credential actually is: {stdout}"
        );
        assert!(
            stdout.contains("not supported yet"),
            "and that this is a gap rather than a fault of the account's: {stdout}"
        );
        assert!(
            !stdout.contains("claude login"),
            "and it does not send the operator to rotate a working grant away: {stdout}"
        );
        assert_eq!(writes(&fixture).len(), 0, "nothing written: {:?}", writes(&fixture));
        assert!(audit_lines(&fixture).is_empty(), "and nothing recorded");
        artefacts_released(&fixture);
        no_plaintext_store(&fixture, "after the refusal");
        live_item_never_written(&fixture);
        // Phase A's read of the store's item, and the probe that separates a
        // migrated incoming namespace from one that never logged in.
        assert_security(&fixture, &[("find-generic-password", 2)]);
        audit_carries_no_token(&fixture);
    }

    // Never logged in: no plaintext store and no item either. The old
    // sentence is the right one here and must survive.
    {
        let (fixture, _service) = two_accounts(&server, common::fresh_at());
        fs::remove_file(incoming_store(&fixture)).expect("removable");

        let (code, stdout, stderr) = swap(&fixture, &[]);
        assert_eq!(code, 14, "{stdout}{stderr}");
        assert!(
            stdout.contains("no readable credential to swap in"),
            "an account with nothing anywhere: {stdout}"
        );
        assert!(stdout.contains("claude login"), "and that one is told to log in: {stdout}");
        assert!(
            !stdout.contains("keychain item"),
            "never the migrated sentence, which would be a lie here: {stdout}"
        );
        assert_eq!(writes(&fixture).len(), 0, "nothing written: {:?}", writes(&fixture));
        no_plaintext_store(&fixture, "after the refusal");
        live_item_never_written(&fixture);
        assert_security(&fixture, &[("find-generic-password", 2)]);
        audit_carries_no_token(&fixture);
    }
    let _ = token;
}

#[test]
fn a_fresh_credential_in_a_migrated_incoming_store_needs_no_refresh_and_proceeds() {
    // The guard above is on **expiry**, not on migration: a migrated incoming
    // store whose credential is still good needs no refresh, so there is
    // nothing to save and nothing to refuse. Dropping the expiry half of the
    // condition would turn a working swap into a refusal, which is what this
    // pins.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, service) = two_accounts(&server, common::fresh_at());
    fixture.keychain_item(
        &common::migration_service(&fixture.ns_dir(ACCT_T, ORG_T)),
        &common::identified_blob(
            "sk-ant-oat01-incoming",
            "sk-ant-ort01-incoming",
            common::fresh_at(),
            ACCT_T,
            Some(ORG_T),
        ),
    );

    no_plaintext_store(&fixture, "before the pass");
    let (code, stdout, stderr) = swap(&fixture, &[]);
    assert_eq!(code, 0, "the swap applied: {stdout}{stderr}");
    assert_eq!(token.calls(), 0, "a fresh credential is not refreshed at all");

    let item =
        fs::read_to_string(fixture.keychain_item_path_for(common::KEYCHAIN_ACCOUNT, &service))
            .expect("the item is readable");
    assert!(item.contains("sk-ant-oat01-incoming"), "and the item holds T: {item}");
    assert_eq!(writes(&fixture).len(), 1, "one `-i` line: {:?}", writes(&fixture));
    hold_within_budget(&stderr);
    artefacts_released(&fixture);
    no_plaintext_store(&fixture, "after the swap");
    live_item_never_written(&fixture);
    // Phase A's read, the re-read under the hold, and the verifying read: no
    // migration probe, because nothing expired to make one worth paying for.
    assert_security(
        &fixture,
        &[("find-generic-password", 3), ("-i", 1), ("add-generic-password", 1)],
    );
    audit_carries_no_token(&fixture);
}

#[test]
fn use_live_json_prints_the_plan_and_still_prompts() {
    // `--json` used to imply `--yes`, which inverted what the flag is for: the
    // machine-readable form is what an operator reaches for to see what a
    // swap *would* do, and it performed one instead. Now it prints the plan
    // and asks; with no terminal to ask at, `Tty::confirm` fails closed.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, _service) = two_accounts(&server, common::fresh_at());
    no_plaintext_store(&fixture, "before the pass");

    let output = fixture
        .cmd()
        .args(["claude", "use", "--live", EMAIL_T, "--json"])
        .output()
        .expect("the binary should run");
    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let docs = json_docs(&stdout);

    assert_eq!(docs.len(), 2, "the plan, then the outcome: {stdout}");
    let plan = &docs[0];
    assert_eq!(plan["kind"], json!("plan"), "the plan says it is one: {plan}");
    assert_eq!(plan["direction"], json!("forward"), "{plan}");
    assert!(plan["from"]["digest8"].is_string(), "digest prefixes only: {plan}");
    assert!(plan["to"]["digest8"].is_string(), "{plan}");
    assert!(!stdout.contains("sk-ant-"), "and never a token: {stdout}");

    let doc = &docs[1];
    // `cancelled`, not `refused`: nobody agreeing is not the same fact as a
    // store whose credential cannot be adopted, and while the two shared
    // refusal **F**'s letter and exit code a script could not tell them apart
    // (finding N-6). It is the shape `failed` already had — an outcome of its
    // own, with `refusal` null.
    assert_eq!(doc["outcome"], json!("cancelled"), "nothing was written: {doc}");
    assert_eq!(doc["refusal"], Value::Null, "and it carries no refusal letter: {doc}");
    assert_eq!(output.status.code(), Some(20), "with its own exit code: {stdout}");
    assert_eq!(writes(&fixture).len(), 0, "and no write happened: {:?}", writes(&fixture));
    artefacts_released(&fixture);
    no_plaintext_store(&fixture, "after a swap nobody confirmed");
    let _ = token;
    // One read, and then the prompt refused: `--json` printed the plan and
    // went no further.
    assert_security(&fixture, &[("find-generic-password", 1)]);
    audit_carries_no_token(&fixture);
}

#[test]
fn use_live_json_carries_the_lock_timings_and_never_a_token() {
    // The contract's `--json` clause: "target, both digest prefixes, outcome,
    // lock timings, any break, and no token material". `--yes` is what makes
    // the swap happen; `--json` only says what happened.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, _service) = two_accounts(&server, common::fresh_at());
    no_plaintext_store(&fixture, "before the pass");

    let (code, stdout, stderr) = swap(&fixture, &["--json"]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    no_plaintext_store(&fixture, "after the pass");
    let doc = outcome_doc(&stdout);

    assert_eq!(doc["outcome"], json!("applied"), "{doc}");
    assert!(doc["target"].as_str().is_some_and(|t| t.starts_with("namespace:")), "{doc}");
    assert!(doc["from"]["digest8"].is_string(), "{doc}");
    assert!(doc["to"]["digest8"].is_string(), "{doc}");
    assert!(doc["audit"]["id"].is_string(), "{doc}");
    assert_eq!(doc["adopted_to"], json!(ADOPTED), "{doc}");
    assert!(doc["lock"]["hold_ms"].is_u64(), "{doc}");
    assert_eq!(doc["lock"]["budget_ms"], json!(3000), "{doc}");
    assert_eq!(doc["lock"]["break"], Value::Null, "nothing was broken: {doc}");
    assert_eq!(doc["refusal"], Value::Null, "an applied swap refuses nothing: {doc}");
    // Refusal B's warning is a fact a person is told on stderr; `--json`
    // carries it too rather than losing it.
    let warnings = doc["warnings"].as_array().expect("the document carries a warnings array");
    assert!(
        warnings.iter().any(|w| w.as_str().is_some_and(|w| w.contains("secure-storage backend"))),
        "the degraded refusal B is in the document: {doc}"
    );
    assert!(!stdout.contains("sk-ant-"), "and no token material anywhere: {stdout}");
    hold_within_budget(&stderr);
    let _ = token;
    // The same three reads and one write any applied swap makes.
    assert_security(
        &fixture,
        &[("find-generic-password", 3), ("-i", 1), ("add-generic-password", 1)],
    );
    audit_carries_no_token(&fixture);
}

// ---------------------------------------------------------------------------
// A failed write is `failed`, with its own exit code, and the audit agrees
// ---------------------------------------------------------------------------

#[test]
fn a_failed_write_has_its_own_outcome_and_exit_code_and_the_audit_agrees() {
    // Refusal letters are security signals: **A** means somebody moved a lock
    // agctl was holding. A `security(1)` that exits non-zero is not that,
    // and reporting it as **A** made the exit code contradict the audit line
    // the same pass had just written.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (mut fixture, _service) = two_accounts(&server, common::fresh_at());
    fixture.fault("swap_write_fail");

    no_plaintext_store(&fixture, "before the pass");
    let (code, stdout, stderr) = swap(&fixture, &["--json"]);
    assert_eq!(code, 19, "SWAP_EXIT_WRITE_FAILED, not refusal A's 10: {stdout}{stderr}");
    hold_within_budget(&stderr);

    let doc = outcome_doc(&stdout);
    assert_eq!(doc["outcome"], json!("failed"), "{doc}");
    assert_eq!(doc["refusal"], Value::Null, "a write failure is not a lettered refusal: {doc}");
    let lines = write_lines(&fixture);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(
        field(&lines[0], "outcome").as_deref(),
        Some("failed"),
        "the audit line and the exit code say the same thing: {}",
        lines[0]
    );
    artefacts_released(&fixture);
    audit_carries_no_token(&fixture);
    // Phase A's read and the re-read under the hold. No verifying read: the
    // child ran and refused, so the item was demonstrably not touched.
    assert_security(&fixture, &[("find-generic-password", 2)]);
    let _ = token;
    no_plaintext_store(&fixture, "after the pass");
}

// ---------------------------------------------------------------------------
// `use --undo`: the copy is the restored credential's only home, so a
// reversal that does not reach the write must leave it alone
// ---------------------------------------------------------------------------

/// Runs a forward swap and returns the item's path, with the store in the
/// post-swap shape a reversal starts from: the item holds **T**, the adopted
/// copy holds **P**, and there is no plaintext store anywhere.
fn swapped(fixture: &Fixture, service: &str) -> std::path::PathBuf {
    no_plaintext_store(fixture, "before the forward swap");
    let (code, stdout, stderr) = swap(fixture, &[]);
    assert_eq!(code, 0, "the forward swap should apply: {stdout}{stderr}");
    // Every reversal test's forward half reaches Phase C, so the hold it took
    // is measured here rather than in each of them: invariant I17's number is
    // worth asserting wherever a hold happened, and the reverse-direction
    // tests are where the assertion had no instance at all.
    hold_within_budget(&stderr);
    audit_carries_no_token(fixture);
    let item = fixture.keychain_item_path_for(common::KEYCHAIN_ACCOUNT, service);
    assert!(
        fs::read_to_string(&item).expect("readable").contains("sk-ant-oat01-incoming"),
        "the item holds T"
    );
    let adopted = adopted_path(fixture, ACCT, ORG);
    assert!(
        fs::read_to_string(&adopted).expect("readable").contains("sk-ant-oat01-outgoing"),
        "and the copy holds P — which after a migration is P's only home"
    );
    no_plaintext_store(fixture, "after the forward swap");
    item
}

/// Asserts the adopted copy still holds **P**, the credential a reversal is
/// putting back.
fn copy_still_holds_p(fixture: &Fixture) {
    let adopted = adopted_path(fixture, ACCT, ORG);
    let parked = fs::read_to_string(&adopted).expect("the adopted copy should still be readable");
    assert!(
        parked.contains("sk-ant-oat01-outgoing"),
        "the copy is the only remaining home of the credential this rollback was restoring; a \
         reversal that did not reach the write must not have replaced it: {parked}"
    );
    assert!(!parked.contains("sk-ant-oat01-incoming"), "and it is not the occupant: {parked}");
    assert!(
        file_store_strays(fixture).is_empty(),
        "and the staged temporary was removed: {:?}",
        file_store_strays(fixture)
    );
}

/// Every leftover `.credentials.adopted.json.tmp.<hex>` in the store.
fn file_store_strays(fixture: &Fixture) -> Vec<String> {
    let prefix = format!("{ADOPTED}.tmp.");
    fs::read_dir(fixture.ns_dir(ACCT, ORG))
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(&prefix))
        .collect()
}

/// Runs `claude use --undo --yes` through `raw()` so a test can interleave.
fn undo_raw(fixture: &Fixture) -> std::process::Child {
    fixture
        .raw()
        .args(["claude", "use", "--undo", "--yes"])
        .spawn()
        .expect("the binary should start")
}

#[test]
fn an_undo_discarded_by_a_peer_write_leaves_the_restored_credential_in_the_copy() {
    // The sharpest case. A reversal reads P out of the adopted copy and puts
    // the occupant back into it — but the store has migrated, so that copy is
    // P's **only** remaining home. Committing the occupant before the item
    // write has landed destroys P on every exit that is not a write, and a
    // peer refresh during the prompt is enough to take one.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (mut fixture, service) = two_accounts(&server, common::fresh_at());
    no_plaintext_store(&fixture, "before the pass");
    let item = swapped(&fixture, &service);

    let resume = fixture.scratch("resume");
    fixture.fault("pause_before_swap_write");
    fixture.set("AGCTL_FAULT_RESUME", &resume.to_string_lossy());

    let peer = common::identified_blob(
        "sk-ant-oat01-peer",
        "sk-ant-ort01-peer",
        common::fresh_at(),
        ACCT_T,
        Some(ORG_T),
    );
    let child = undo_raw(&fixture);
    assert!(
        common::wait_until(Duration::from_secs(20), || {
            fs::read_to_string(&item).is_ok_and(|text| text.contains("sk-ant-oat01-incoming"))
        }),
        "the reversal should have reached its pause"
    );
    std::thread::sleep(Duration::from_millis(200));
    fs::write(&item, &peer).expect("the peer writes the item");
    fs::write(&resume, b"go").expect("the resume file is writable");

    let output = child.wait_with_output().expect("the undo finishes");
    assert_eq!(
        output.status.code(),
        Some(17),
        "SWAP_EXIT_DISCARDED: {}",
        common::strip_ansi(&String::from_utf8_lossy(&output.stderr))
    );
    copy_still_holds_p(&fixture);
    assert_eq!(writes(&fixture).len(), 1, "only the forward swap wrote: {:?}", writes(&fixture));
    no_plaintext_store(&fixture, "after a discarded reversal");
    artefacts_released(&fixture);
    let _ = token;
    // The forward swap's three reads and one write, then the reversal's
    // Phase A read and its re-read under the hold, which found the change.
    assert_security(
        &fixture,
        &[("find-generic-password", 5), ("-i", 1), ("add-generic-password", 1)],
    );
    audit_carries_no_token(&fixture);
}

#[test]
fn an_undo_refused_by_a_compromised_hold_leaves_the_restored_credential_in_the_copy() {
    // Refusal A during a reversal. The hold opened, an artefact moved under
    // it, and nothing was written — so the copy must still hold P.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (mut fixture, service) = two_accounts(&server, common::fresh_at());
    no_plaintext_store(&fixture, "before the pass");
    let _item = swapped(&fixture, &service);

    let resume = fixture.scratch("resume");
    fixture.fault("swap_pause_in_locks");
    fixture.set("AGCTL_FAULT_RESUME", &resume.to_string_lossy());
    let [primary, _legacy, _storage] = fixture.hold_artefacts(ACCT, ORG);

    let child = undo_raw(&fixture);
    assert!(
        common::wait_until(Duration::from_secs(20), || primary.exists()),
        "the reversal's hold should have opened and paused inside itself"
    );
    std::thread::sleep(Duration::from_millis(300));
    age(&primary);
    fs::write(&resume, b"go").expect("the resume file is writable");

    let output = child.wait_with_output().expect("the undo finishes");
    assert_eq!(output.status.code(), Some(10), "SWAP_EXIT_REFUSED_A");
    copy_still_holds_p(&fixture);
    assert_eq!(writes(&fixture).len(), 1, "only the forward swap wrote: {:?}", writes(&fixture));
    artefacts_released(&fixture);
    no_plaintext_store(&fixture, "after refusal A during a reversal");
    let _ = token;
    // The forward swap's three reads and one write, then the reversal's
    // Phase A read and its re-read; the refusal lands before the write.
    assert_security(
        &fixture,
        &[("find-generic-password", 5), ("-i", 1), ("add-generic-password", 1)],
    );
    audit_carries_no_token(&fixture);
}

#[test]
fn an_undo_that_finds_the_store_busy_leaves_the_restored_credential_in_the_copy() {
    // The `Busy` exit. A Claude Code session holds a fresh refresh lock and
    // never lets go, so agctl waits out fact F36's schedule and then
    // reports the store busy — having written nothing and, crucially, having
    // left the copy holding P.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, service) = two_accounts(&server, common::fresh_at());
    no_plaintext_store(&fixture, "before the pass");
    let _item = swapped(&fixture, &service);

    let [primary, _legacy, _storage] = fixture.hold_artefacts(ACCT, ORG);
    fs::create_dir_all(&primary).expect("the peer's lock is plantable");

    let (code, stdout, stderr) = undo(&fixture);
    assert_eq!(code, 16, "SWAP_EXIT_BUSY: {stdout}{stderr}");
    assert!(
        stdout.contains("refresh lock is held") || stdout.contains("another process"),
        "and says so in section 3.4's words: {stdout}"
    );
    let _ = fs::remove_dir_all(&primary);

    copy_still_holds_p(&fixture);
    assert_eq!(writes(&fixture).len(), 1, "only the forward swap wrote: {:?}", writes(&fixture));
    no_plaintext_store(&fixture, "after a busy reversal");
    let _ = token;
    // The forward swap's three reads and one write, then the reversal's
    // Phase A read; `busy` is answered before the re-read.
    assert_security(
        &fixture,
        &[("find-generic-password", 4), ("-i", 1), ("add-generic-password", 1)],
    );
    audit_carries_no_token(&fixture);
}

#[test]
fn an_undo_whose_write_fails_leaves_the_restored_credential_in_the_copy() {
    // The `failed` exit, and the sentence it prints. In the forward direction
    // "the outgoing credential is still recoverable with `use --undo`" is
    // true; in reverse it would be advising the user to re-run the command
    // that just failed, so the reversal says what is actually the case.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (mut fixture, service) = two_accounts(&server, common::fresh_at());
    no_plaintext_store(&fixture, "before the pass");
    let _item = swapped(&fixture, &service);
    fixture.fault("swap_write_fail");

    let (code, stdout, stderr) = undo(&fixture);
    assert_eq!(code, 19, "SWAP_EXIT_WRITE_FAILED: {stdout}{stderr}");
    // The reversal took a hold of its own and released it inside the budget —
    // the direction the assertion previously had no instance in at all.
    hold_within_budget(&stderr);
    assert!(
        stdout.contains("untouched in the adopted copy"),
        "the reverse direction's own wording: {stdout}"
    );
    assert!(
        !stdout.contains("recoverable with `agctl claude use --undo`"),
        "which is what `--undo` must not tell a user who is already running it: {stdout}"
    );
    copy_still_holds_p(&fixture);
    assert_eq!(writes(&fixture).len(), 1, "only the forward swap wrote: {:?}", writes(&fixture));
    artefacts_released(&fixture);
    no_plaintext_store(&fixture, "after a reversal whose write failed");
    let _ = token;
    // The forward swap's three reads and one write, then the reversal's
    // Phase A read and its re-read. A `failed` write issues no verifying
    // read (ruling OQ6), which is why this is five and not six.
    assert_security(
        &fixture,
        &[("find-generic-password", 5), ("-i", 1), ("add-generic-password", 1)],
    );
    audit_carries_no_token(&fixture);
}

// ---------------------------------------------------------------------------
// N1 / OQ2(d) — the identity guard, one test per site
// ---------------------------------------------------------------------------
//
// The guard exists because after a hot-swap the item a record's namespace
// names is **not that record's credential**. Treating it as one would show a
// stranger's usage under this account's name, refresh a token this row does
// not own, and file the answer under this row. The three sites are
// `refresh_in_place`'s target check and the two `adopted()` arms, and each
// one gets a test here: deleting any of them turns its row from `adopted`
// into something else.

/// The usage mock every `status` row needs to answer.
fn usage_ok(server: &MockServer) -> Mock<'_> {
    server.mock(|when, then| {
        when.method(httpmock::Method::GET).path(common::USAGE_PATH);
        then.status(200).body(common::USAGE_BODY);
    })
}

/// The owned row of a `status --json` document.
fn owned_row(stdout: &str) -> Value {
    let document: Value = serde_json::from_str(stdout)
        .unwrap_or_else(|err| panic!("stdout should be one JSON document: {err}\n{stdout}"));
    document["rows"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["kind"] == json!("owned")))
        .cloned()
        .unwrap_or_else(|| panic!("the document should carry an owned row:\n{stdout}"))
}

/// Asserts a row is the occupied one the guard produces.
fn assert_occupied_row(row: &Value, occupant: &str) {
    assert_eq!(
        row["state"],
        json!("adopted"),
        "the row names the state, not the credential: {row}"
    );
    assert_eq!(row["occupied_by"], json!(occupant), "and who holds the item: {row}");
    assert_eq!(
        row["note"],
        json!("its keychain item is held by another identity"),
        "in words rather than by omission: {row}"
    );
    assert_eq!(
        row["lock_state"],
        json!("none"),
        "nothing was locked to find this out — and this is not the pass action of the same \
         spelling: {row}"
    );
    assert!(!row.to_string().contains("sk-ant-"), "and never any token material: {row}");
}

#[test]
fn an_occupied_item_is_never_refreshed_for_the_record_that_names_it() {
    // Site 1: `refresh_in_place`'s target check, before the digest and before
    // the POST. The occupancy here is **real** — it was produced by an actual
    // `use --live` — and the row that results is a real `Adopted` row read
    // out of the adopted copy the same swap wrote.
    let server = MockServer::start();
    let token = token_ok(&server);
    let usage = usage_ok(&server);
    let (fixture, service) = two_accounts(&server, common::fresh_at());
    no_plaintext_store(&fixture, "before the pass");
    let item = swapped(&fixture, &service);
    let posts_after_swap = token.calls();

    // The occupant's credential ages. Without the guard this is exactly the
    // shape that makes `refresh_in_place` spend this row's grant on somebody
    // else's token and then store the answer under this row's name.
    fs::write(
        &item,
        occupant_blob("sk-ant-oat01-occupant", common::expired_at(), ACCT_T, ORG_T, EMAIL_T),
    )
    .expect("the item is writable");
    let writes_before = writes(&fixture).len();

    let output = fixture
        .cmd()
        .args(["claude", "status", "--json", "--refresh", "--account", EMAIL])
        .output()
        .expect("status runs");
    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let row = owned_row(&stdout);

    assert_occupied_row(&row, EMAIL_T);
    assert_eq!(token.calls(), posts_after_swap, "no grant was spent on an occupant's token");
    assert_eq!(writes(&fixture).len(), writes_before, "and nothing was written to the item");
    assert!(
        fs::read_to_string(&item).expect("readable").contains("sk-ant-oat01-occupant"),
        "the occupant's credential is exactly what is still there"
    );
    for artefact in fixture.hold_artefacts(ACCT, ORG) {
        assert!(!artefact.exists(), "nothing was held: {}", artefact.display());
    }
    no_plaintext_store(&fixture, "after a status pass over an occupied item");
    let _ = usage;
    // The swap's three reads and one write; then the status pass's
    // preflight, listing, the live row's read and discovery's two of this
    // item. No POST and no fourth read: the guard stopped the pass before
    // `refresh_in_place` could spend anything.
    assert_security(
        &fixture,
        &[
            ("show-keychain-info", 1),
            ("dump-keychain", 1),
            ("find-generic-password", 6),
            ("-i", 1),
            ("add-generic-password", 1),
        ],
    );
    audit_carries_no_token(&fixture);
}

#[test]
fn an_occupant_arriving_during_the_post_is_not_adopted_as_this_rows_credential() {
    // Site 2: the pre-POST re-read's `adopted()` arm. The item was this
    // record's when the pass started, so the target check passed; a
    // concurrent `use --live` changed it while the pass was between reads.
    // A changed item is normally a peer refresh worth adopting — but one that
    // has also stopped being this record's is an occupant, and adopting it
    // would file a stranger's token under this account.
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = token_ok(&server);
    let mut fixture = Fixture::new();
    fixture.with_keychain().endpoints(&server.base_url());
    fixture.write_registry(vec![fixture.owned_record(ACCT, ORG)]);
    fs::create_dir_all(fixture.ns_dir(ACCT, ORG)).expect("the namespace is creatable");
    let service = common::migration_service(&fixture.ns_dir(ACCT, ORG));
    fixture.dump(&[&service]);
    fixture.keychain_item(
        &service,
        &common::identified_blob(
            "sk-ant-oat01-mine",
            "sk-ant-ort01-mine",
            common::expired_at(),
            ACCT,
            Some(ORG),
        ),
    );
    fixture.allow_write(&service);
    // The record's own credential, parked where a swap would have put it.
    fs::write(
        adopted_path(&fixture, ACCT, ORG),
        common::identified_blob(
            "sk-ant-oat01-parked",
            "sk-ant-ort01-parked",
            common::fresh_at(),
            ACCT,
            Some(ORG),
        ),
    )
    .expect("the adopted copy is writable");

    let resume = fixture.scratch("resume");
    let item = fixture.keychain_item_path_for(common::KEYCHAIN_ACCOUNT, &service);
    no_plaintext_store(&fixture, "before the pass");
    let child = fixture
        .raw()
        .args(["claude", "status", "--json", "--refresh", "--timeout", "30s", "--account", EMAIL])
        .env("AGCTL_FAULT", "pause_before_migrated_reread")
        .env("AGCTL_FAULT_RESUME", &resume)
        .spawn()
        .expect("agctl should start");

    assert!(
        common::wait_until(Duration::from_secs(20), || finds_for(&fixture, &service) >= 3),
        "discovery should have read the item before the pause"
    );
    let occupant =
        occupant_blob("sk-ant-oat01-occupant", common::fresh_at(), ACCT_T, ORG_T, EMAIL_T);
    fs::write(&item, &occupant).expect("the item is writable");
    fs::write(&resume, "go").expect("the resume file is writable");

    let finished = common::finish(child);
    let row = owned_row(&finished.stdout);
    assert_occupied_row(&row, EMAIL_T);
    assert_ne!(row["lock_state"], json!("adopted"), "an occupant is not a peer refresh: {row}");
    assert_eq!(token.calls(), 0, "no grant was spent");
    assert!(writes(&fixture).is_empty(), "nothing was written: {:?}", fixture.security_log());
    assert_eq!(
        fs::read_to_string(&item).expect("readable"),
        occupant,
        "the occupant's credential is untouched"
    );
    let _ = usage;
    // Preflight, listing, the live row's read, discovery's three of this
    // item and the pre-POST re-read. No hold, so no re-read under one and
    // no verifying read; and no write at all.
    assert_security(
        &fixture,
        &[("show-keychain-info", 1), ("dump-keychain", 1), ("find-generic-password", 5)],
    );
    audit_carries_no_token(&fixture);
    no_plaintext_store(&fixture, "after the pass");
}

#[test]
fn an_occupant_arriving_after_an_invalid_grant_is_not_adopted_either() {
    // Site 3: `after_invalid_grant`'s `adopted()` arm. The grant is dead
    // either way — but whether that is a logout depends on *whose* refresh
    // consumed it, and an occupant's arrival answers a different question
    // from a peer refresh's. Taking the occupant here would be the same
    // confusion one recovery path later.
    let server = MockServer::start();
    let usage = usage_ok(&server);
    let token = server.mock(|when, then| {
        when.method(POST).path(common::TOKEN_PATH);
        then.status(400).json_body(json!({
            "error": "invalid_grant",
            "error_description": "refresh token is not valid",
        }));
    });
    let mut fixture = Fixture::new();
    fixture.with_keychain().endpoints(&server.base_url());
    fixture.write_registry(vec![fixture.owned_record(ACCT, ORG)]);
    fs::create_dir_all(fixture.ns_dir(ACCT, ORG)).expect("the namespace is creatable");
    let service = common::migration_service(&fixture.ns_dir(ACCT, ORG));
    fixture.dump(&[&service]);
    fixture.keychain_item(
        &service,
        &common::identified_blob(
            "sk-ant-oat01-mine",
            "sk-ant-ort01-mine",
            common::expired_at(),
            ACCT,
            Some(ORG),
        ),
    );
    fixture.allow_write(&service);
    fs::write(
        adopted_path(&fixture, ACCT, ORG),
        common::identified_blob(
            "sk-ant-oat01-parked",
            "sk-ant-ort01-parked",
            common::fresh_at(),
            ACCT,
            Some(ORG),
        ),
    )
    .expect("the adopted copy is writable");

    let resume = fixture.scratch("resume");
    let item = fixture.keychain_item_path_for(common::KEYCHAIN_ACCOUNT, &service);
    no_plaintext_store(&fixture, "before the pass");
    let child = fixture
        .raw()
        .args(["claude", "status", "--json", "--refresh", "--timeout", "30s", "--account", EMAIL])
        .env("AGCTL_FAULT", "pause_before_invalid_grant_reread")
        .env("AGCTL_FAULT_RESUME", &resume)
        .spawn()
        .expect("agctl should start");

    assert!(
        common::wait_until(Duration::from_secs(20), || token.calls() == 1),
        "the refresh POST should have been rejected before the pause"
    );
    let occupant =
        occupant_blob("sk-ant-oat01-occupant", common::fresh_at(), ACCT_T, ORG_T, EMAIL_T);
    fs::write(&item, &occupant).expect("the item is writable");
    fs::write(&resume, "go").expect("the resume file is writable");

    let finished = common::finish(child);
    let row = owned_row(&finished.stdout);
    assert_occupied_row(&row, EMAIL_T);
    assert_ne!(row["state"], json!("needs_login"), "a healthy occupied row is not a logout: {row}");
    assert_ne!(row["lock_state"], json!("adopted"), "{row}");
    assert!(writes(&fixture).is_empty(), "nothing was written: {:?}", fixture.security_log());
    assert_eq!(
        fs::read_to_string(&item).expect("readable"),
        occupant,
        "the occupant's credential is untouched"
    );
    let _ = usage;
    // The same set, plus the recovery's own read after the `invalid_grant`.
    assert_security(
        &fixture,
        &[("show-keychain-info", 1), ("dump-keychain", 1), ("find-generic-password", 6)],
    );
    audit_carries_no_token(&fixture);
    no_plaintext_store(&fixture, "after the pass");
}

#[test]
fn an_undo_whose_write_outcome_is_unknown_leaves_the_restored_credential_in_the_copy() {
    // The narrowest arm of finding P1-1, and the one the lead ruled on. The
    // write child was killed, so whether it landed is **undetermined**: the
    // item may hold the restored credential or may still hold the occupant.
    // Committing the staged occupant over the copy would, in the second case,
    // destroy the only remaining home of the credential this rollback exists
    // to put back. So `unknown` does not commit.
    //
    // Little is lost by that. The occupant that goes unparked came from its
    // own namespace store, where the forward swap read it and left it — and
    // that store *may* still hold a usable copy, which is all the note may
    // claim: a peer that refreshed that namespace's item since has rotated the
    // copy's refresh token away (`agctl-npu`). What *is* given up is undoing
    // this undo, and the note says so — and the
    // second `--undo` below proves it, refusing rather than restoring the
    // occupant on the strength of an entry whose copy does not match it.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (mut fixture, service) = two_accounts(&server, common::fresh_at());
    no_plaintext_store(&fixture, "before the pass");
    let item = swapped(&fixture, &service);
    fixture.fault("keychain_write_hang");

    let (code, stdout, stderr) = undo(&fixture);
    assert_eq!(code, 18, "SWAP_EXIT_UNKNOWN: {stdout}{stderr}");
    hold_within_budget(&stderr);
    assert!(
        stdout.contains("re-run `agctl claude status`"),
        "the user is told the write is unconfirmed: {stdout}"
    );
    assert!(
        stdout.contains("cannot itself be undone"),
        "and that this reversal is not reversible, because the occupant was not parked: {stdout}"
    );
    assert!(
        stdout.contains("was not parked; its own store may still hold a usable copy"),
        "with where a usable copy may be, and no more than that: {stdout}"
    );
    assert!(
        !stdout.contains("still in its own namespace store"),
        "never the old promise, which a peer refresh makes false (`agctl-npu`): {stdout}"
    );

    // The copy still holds the credential the rollback was restoring, and the
    // staged temporary is gone.
    copy_still_holds_p(&fixture);
    // The occupant is exactly where the note says.
    let occupant_store = fixture.ns_dir(ACCT_T, ORG_T).join(".credentials.json");
    assert!(
        fs::read_to_string(&occupant_store).expect("readable").contains("sk-ant-oat01-incoming"),
        "the occupant that was not parked is still in its own namespace store"
    );
    // The child was killed before it could touch the item.
    assert!(
        fs::read_to_string(&item).expect("readable").contains("sk-ant-oat01-incoming"),
        "the item still holds the occupant"
    );

    let lines = write_lines(&fixture);
    assert_eq!(lines.len(), 2, "one audit line each way: {lines:?}");
    let unknown: Vec<&String> =
        lines.iter().filter(|line| field(line, "outcome").as_deref() == Some("unknown")).collect();
    assert_eq!(unknown.len(), 1, "exactly one `unknown` line: {lines:?}");

    // A second `--undo` picks that entry — `unknown` is reversible in
    // principle — and then refuses, because the copy is not what the entry
    // says was displaced. The credential is put back by nobody rather than by
    // guesswork.
    let (code, stdout, stderr) = undo(&fixture);
    assert_eq!(code, 1, "the second undo refuses: {stdout}{stderr}");
    assert!(stderr.contains("will not put back"), "{stderr}");
    copy_still_holds_p(&fixture);

    assert_eq!(writes(&fixture).len(), 1, "only the forward swap wrote: {:?}", writes(&fixture));
    artefacts_released(&fixture);
    no_plaintext_store(&fixture, "after a reversal whose write outcome is unknown");
    audit_carries_no_token(&fixture);
    // The forward swap's three reads and one write; the reversal's Phase A
    // read, its re-read under the hold and the verifying read that left the
    // question open; then nothing from the second undo, which refused on the
    // digest before reading anything.
    assert_security(
        &fixture,
        &[("find-generic-password", 6), ("-i", 1), ("add-generic-password", 1)],
    );
    let _ = token;
}

// ---------------------------------------------------------------------------
// The write-back's guards (`agctl-r9w`, review4 N-15)
// ---------------------------------------------------------------------------

#[test]
fn a_write_back_racing_another_writer_keeps_the_other_writers_credential() {
    // N-15 (a), reproduced at the only moment it can happen: the incoming
    // credential is read in Phase A, *before* the locks, and the refresh POST
    // is the widest part of the window between that read and the write-back.
    // The mock holds the response open; a scoped thread waits for the request
    // to actually arrive — so the write below is provably after Phase A's
    // read — and writes a different credential into T's own store, which is
    // what a second agctl pass refreshing that account looks like from here.
    //
    // Pre-fix the write-back overwrote it: `WriteRequest::prior` is recorded
    // in the pending metadata and is not a compare-and-swap, so the other
    // writer's refresh token died and that account needed an interactive
    // `login`.
    let server = MockServer::start();
    let token = server.mock(|when, then| {
        when.method(POST).path(common::TOKEN_PATH);
        then.status(200).delay(Duration::from_millis(1_500)).json_body(json!({
            "access_token": "sk-ant-oat01-rotated",
            "refresh_token": "sk-ant-ort01-rotated",
            "token_type": "Bearer",
            "expires_in": 28_800,
            "refresh_token_expires_in": 2_377_445,
            "scope": "user:inference user:profile",
        }));
    });
    let (fixture, _service) = two_accounts(&server, common::expired_at());
    let store = incoming_store(&fixture);
    let raced = common::identified_blob(
        "sk-ant-oat01-raced",
        "sk-ant-ort01-raced",
        common::fresh_at(),
        ACCT_T,
        Some(ORG_T),
    );

    std::thread::scope(|scope| {
        scope.spawn(|| {
            assert!(
                common::wait_until(Duration::from_secs(20), || token.calls() > 0),
                "the refresh POST should reach the mock"
            );
            fs::write(&store, &raced).expect("the racing write lands");
        });

        let (code, stdout, stderr) = swap(&fixture, &[]);
        assert_eq!(code, 0, "the swap itself still applies: {stdout}{stderr}");
        assert_eq!(token.calls(), 1, "exactly one refresh POST");
        assert!(
            stderr.contains("was not saved back to its own store"),
            "the operator is told, rather than the write being reported as success:\n{stderr}"
        );
        assert!(
            stderr.contains("changed while this swap was preparing"),
            "and told which guard refused:\n{stderr}"
        );
    });

    assert_eq!(
        fs::read_to_string(&store).expect("T's store is readable"),
        raced,
        "the other writer's credential is still there, byte for byte: no lost update"
    );
    assert!(
        !store.with_extension("json.pending").exists(),
        "and nothing was parked beside it either"
    );
    assert_eq!(writes(&fixture).len(), 1, "the item write the operator asked for still happened");
    live_item_never_written(&fixture);
    audit_carries_no_token(&fixture);
    // The other shape of the count: no artefact, so the gate does reach the
    // keychain — Phase A's read, the migration probe, the gate's one read per
    // candidate service name under the lock, the re-read under the hold and
    // the verifying read (`agctl-r9w` review F1).
    assert_security(
        &fixture,
        &[("find-generic-password", 6), ("-i", 1), ("add-generic-password", 1)],
    );
}

#[test]
fn a_write_back_into_a_namespace_a_claude_session_holds_is_refused() {
    // N-15 (b): the namespace lock excludes another agctl pass and excludes
    // nothing else. A live Claude Code session in the **incoming** namespace
    // holds this same file under its own protocol, and its lock artefact is
    // the only sign of it. `status` refuses to write such a namespace; this
    // write site now refuses it too.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, _service) = two_accounts(&server, common::expired_at());
    let store = incoming_store(&fixture);
    let before = fs::read_to_string(&store).expect("T's store is readable");
    fs::create_dir(fixture.ns_dir(ACCT_T, ORG_T).join(".oauth_refresh.lock"))
        .expect("the artefact is plantable");

    let (code, stdout, stderr) = swap(&fixture, &[]);

    assert_eq!(code, 0, "the swap itself still applies: {stdout}{stderr}");
    assert_eq!(token.calls(), 1, "the refresh still happened — this is about where it is saved");
    assert!(
        stderr.contains("a Claude Code session holds `.oauth_refresh.lock` there"),
        "the refusal names the artefact it found:\n{stderr}"
    );
    assert_eq!(
        fs::read_to_string(&store).expect("T's store is readable"),
        before,
        "the session's file is untouched"
    );
    assert_eq!(writes(&fixture).len(), 1, "one write reached the item");
    live_item_never_written(&fixture);
    // The gate's artefact scan is pure filesystem and comes **first**, so a
    // namespace a session holds is refused without asking the keychain
    // anything: Phase A's read, the migration probe, the re-read under the
    // hold, and the verifying read — the count a swap had before `agctl-r9w`.
    assert_security(
        &fixture,
        &[("find-generic-password", 4), ("-i", 1), ("add-generic-password", 1)],
    );
}

#[test]
fn a_refused_write_back_is_carried_in_the_json_warnings() {
    // The `--json` half of the same refusal (review F5). The sentence goes to
    // stderr for a person and into `warnings` for a consumer, which is the
    // channel refusal B's degraded warning already uses — a machine reading
    // `--json` must not lose a fact the terminal shows.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, _service) = two_accounts(&server, common::expired_at());
    fs::create_dir(fixture.ns_dir(ACCT_T, ORG_T).join(".oauth_refresh.lock"))
        .expect("the artefact is plantable");

    let (code, stdout, stderr) = swap(&fixture, &["--json"]);

    assert_eq!(code, 0, "{stdout}{stderr}");
    assert_eq!(token.calls(), 1);
    let doc = outcome_doc(&stdout);
    let warnings = doc["warnings"].as_array().expect("the outcome carries `warnings`");
    assert!(
        warnings.iter().any(|warning| {
            let text = warning.as_str().unwrap_or_default();
            text.contains("was not saved back to its own store")
                && text.contains("a Claude Code session holds `.oauth_refresh.lock` there")
        }),
        "the refusal is in the document a consumer reads: {doc}"
    );
    assert!(!stdout.contains("sk-ant-"), "and the document carries no token material: {stdout}");
    // The same sentence on stderr, and nothing beyond it: `--json`'s contract
    // is that the document is the whole of stdout, and the note is a line for
    // a person rather than a second document.
    assert!(stderr.contains("was not saved back to its own store"), "{stderr}");
    assert!(!stderr.contains("sk-ant-"), "{stderr}");
}

#[test]
fn a_swap_that_writes_the_refresh_back_touches_nothing_outside_the_namespace_root() {
    // AC81's containment claim over the write-back's own output, which
    // `ac81_a_swap_touches_nothing_outside_the_namespace_root` cannot make:
    // that test's incoming credential is **fresh**, so no refresh and no
    // write-back happen inside it (review4 N-15's second sub-note). This one
    // is the same walk with an expired incoming credential, so the write-back
    // runs and every path it creates is inside the bound.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, _service) = two_accounts(&server, common::expired_at());
    let live_store = fixture.live_store_dir();
    fs::create_dir_all(&live_store).expect("the live store dir is creatable");
    let before: std::collections::BTreeSet<_> = tree(&fixture).into_keys().collect();

    let (code, stdout, stderr) = swap(&fixture, &[]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert_eq!(token.calls(), 1, "the refresh happened, so the write-back ran");
    assert!(
        fs::read_to_string(incoming_store(&fixture))
            .expect("readable")
            .contains("sk-ant-ort01-rotated"),
        "the premise: the write-back wrote"
    );

    let after: std::collections::BTreeSet<_> = tree(&fixture).into_keys().collect();
    let root = fixture.config_dir().join("claude");
    let allowed =
        [fixture.config_dir().join("cache"), fixture.config_dir().join("cache").join("claude")];
    for path in after.symmetric_difference(&before) {
        if allowed.contains(path) {
            assert!(path.is_dir(), "`{}` is agctl's own cache directory", path.display());
            continue;
        }
        assert!(
            path.starts_with(&root),
            "`{}` is outside the namespace root `{}`",
            path.display(),
            root.display()
        );
    }
    for name in [".oauth_refresh.lock", ".storage-write", ".credentials.json"] {
        assert!(!live_store.join(name).exists(), "the live store must be untouched: {name}");
    }
    live_item_never_written(&fixture);
}

// ---------------------------------------------------------------------------
// D-017's row for the incoming account's own displaced copy (`agctl-5gs`)
// ---------------------------------------------------------------------------

#[test]
fn an_item_holding_another_copy_of_the_incoming_account_applies_and_then_says_already_active() {
    // Review4 N-14's wedge, reproduced from its probe. The state is ordinary:
    // D's item holds a credential of **T** — which is what one earlier
    // `use --live T` leaves — and T's own store holds T's (expired) copy.
    //
    // Pre-fix, `third_namespace` resolved the displaced credential to T's own
    // record, so the adoption target was the very file step 13's write-back
    // writes: run 1 refused **F**/exit 14 with "the copy already stored
    // changed while this swap was preparing" — blaming a concurrent writer
    // that did not exist — and every later run refused `NewerCopy`, because
    // the write-back had made T's store newer than the copy being adopted.
    // The store was wedged: `use --live T` could not succeed again.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, service) = two_accounts(&server, common::expired_at());
    let earlier = common::identified_blob(
        "sk-ant-oat01-t-earlier",
        "sk-ant-ort01-t-earlier",
        common::fresh_at(),
        ACCT_T,
        Some(ORG_T),
    );
    fixture.keychain_item(&service, &earlier);
    let store = incoming_store(&fixture);

    // Run 1 applies.
    let (code, stdout, stderr) = swap(&fixture, &["--json"]);
    assert_eq!(code, 0, "run 1 applies rather than refusing F: {stdout}{stderr}");
    let doc = outcome_doc(&stdout);
    assert_eq!(doc["outcome"], json!("applied"), "{doc}");
    assert_eq!(doc["refusal"], Value::Null, "{doc}");
    assert_eq!(
        doc["adopted_to"],
        json!(".credentials.adopted.json"),
        "the displaced copy expires later than the one T's own store held, so it is kept in the \
         store's D-024 sibling rather than dropped (`agctl-r3h`): {doc}"
    );
    assert_eq!(token.calls(), 1, "one refresh POST");

    // The discarded copy went nowhere: not into T's store, not into an
    // adopted copy beside D, not into a plaintext store for D.
    let saved = fs::read_to_string(&store).expect("T's store is readable");
    assert!(saved.contains("sk-ant-ort01-rotated"), "T's store holds the refreshed pair: {saved}");
    assert!(
        !saved.contains("t-earlier"),
        "and not the older copy the item had been holding: {saved}"
    );
    let adopted =
        fs::read_to_string(adopted_path(&fixture, ACCT, ORG)).expect("the adopted copy is there");
    assert!(
        adopted.contains("sk-ant-ort01-t-earlier") && adopted.contains("sk-ant-oat01-t-earlier"),
        "and it holds the displaced pair, beside the **store** — never in T's own namespace, \
         which is the file the write-back writes: {adopted}"
    );
    no_plaintext_store(&fixture, "after a swap whose displaced copy was adopted beside the store");

    let item =
        fs::read_to_string(fixture.keychain_item_path_for(common::KEYCHAIN_ACCOUNT, &service))
            .expect("the item is readable");
    assert_eq!(item, saved, "the item and T's own store hold the same credential");
    assert_eq!(writes(&fixture).len(), 1, "one `-i` line: {:?}", writes(&fixture));

    // The audit line, named: one write, `applied`, for this store's item,
    // carrying the displaced copy's digest prefix as its `from`.
    let lines = audit_lines(&fixture);
    assert_eq!(lines.len(), 1, "one audit line: {lines:?}");
    assert!(lines[0].contains("\"event\":\"write\""), "{}", lines[0]);
    assert!(lines[0].contains("\"outcome\":\"applied\""), "{}", lines[0]);
    assert!(
        lines[0].contains(&format!(
            "\"target\":\"namespace:{}\"",
            common::sha8(&common::export_spelling(&fixture.ns_dir(ACCT, ORG)))
        )),
        "{}",
        lines[0]
    );
    assert!(
        !lines[0].contains("\"from_digest8\":null"),
        "the item held a credential, so the line names what it displaced: {}",
        lines[0]
    );
    audit_carries_no_token(&fixture);

    // Run 2 is `already_active`, not `NewerCopy` for ever.
    let (code, stdout, stderr) = swap(&fixture, &["--json"]);
    assert_eq!(code, 0, "run 2 is not a refusal: {stdout}{stderr}");
    let doc = outcome_doc(&stdout);
    assert_eq!(doc["outcome"], json!("already_active"), "{doc}");
    assert_eq!(doc["refusal"], Value::Null, "{doc}");
    assert_eq!(token.calls(), 1, "and it made no second refresh POST");
    assert_eq!(writes(&fixture).len(), 1, "no second keychain write: {:?}", writes(&fixture));
    assert_eq!(audit_lines(&fixture).len(), 1, "and no second audit line");
    live_item_never_written(&fixture);

    // Both runs' whole `security` conversation. Run 1: Phase A's read of the
    // item, the probe asking whether T's store has migrated, the write-back
    // gate's one read per candidate service name, the re-read under the hold
    // and the verifying read. The migrated probe the *adoption* used to make
    // is gone with the third-namespace row: this row reads no target at all.
    // Run 2: Phase A's read, and nothing else — `already_active` is decided
    // before any lock.
    assert_security(
        &fixture,
        &[("find-generic-password", 7), ("-i", 1), ("add-generic-password", 1)],
    );
}

#[test]
fn a_displaced_copy_newer_than_the_incoming_store_is_kept_and_an_undo_puts_it_back() {
    // `agctl-r3h`. The shape a working session leaves: D's item holds a
    // credential of **T** that a Claude Code session refreshed after an
    // earlier `use --live T`, so it expires *later* than the copy T's own
    // store holds — and T's store copy is still fresh, so this pass makes no
    // refresh POST at all. Discarding the displaced copy here would drop the
    // live half of T's refresh chain and cost that account a `login`; the row
    // keeps it in the **store's** D-024 sibling, which touches nothing the
    // write-back writes and is the file `use --undo` reads back.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, service) = two_accounts(&server, common::fresh_at());
    let newer = common::identified_blob(
        "sk-ant-oat01-t-session",
        "sk-ant-ort01-t-session",
        common::fresh_at() + 3_600_000,
        ACCT_T,
        Some(ORG_T),
    );
    fixture.keychain_item(&service, &newer);
    let store = incoming_store(&fixture);
    let before = fs::read_to_string(&store).expect("T's store is readable");

    let (code, stdout, stderr) = swap(&fixture, &["--json"]);

    assert_eq!(code, 0, "{stdout}{stderr}");
    let doc = outcome_doc(&stdout);
    assert_eq!(doc["outcome"], json!("applied"), "{doc}");
    assert_eq!(doc["adopted_to"], json!(".credentials.adopted.json"), "the copy was kept: {doc}");
    assert_eq!(token.calls(), 0, "T's own copy is fresh, so no refresh POST runs");

    let adopted =
        fs::read_to_string(adopted_path(&fixture, ACCT, ORG)).expect("the adopted copy is there");
    assert!(
        adopted.contains("sk-ant-ort01-t-session"),
        "the adopted copy holds the displaced pair: {adopted}"
    );
    assert_eq!(
        fs::read_to_string(&store).expect("T's store is readable"),
        before,
        "and T's own `.credentials.json` is untouched — the file the write-back writes and the \\
         one the wedge came from"
    );
    let item =
        fs::read_to_string(fixture.keychain_item_path_for(common::KEYCHAIN_ACCOUNT, &service))
            .expect("the item is readable");
    assert!(item.contains("sk-ant-oat01-incoming"), "the item now holds T's store copy: {item}");

    // And it is recoverable: the reversal reads the store's adopted copy,
    // which is why the copy is kept there rather than in T's namespace.
    let (code, stdout, stderr) = undo(&fixture);
    assert_eq!(code, 0, "{stdout}{stderr}");
    let item =
        fs::read_to_string(fixture.keychain_item_path_for(common::KEYCHAIN_ACCOUNT, &service))
            .expect("the item is readable");
    assert!(
        item.contains("sk-ant-ort01-t-session"),
        "the undo put the kept copy back into the item: {item}"
    );
    // The kept copy was consumed rather than left as a second home for it:
    // what is in the adopted copy now is what the *reversal* displaced, which
    // is the staging protocol's own shape ("undoing an undo is a swap").
    let adopted =
        fs::read_to_string(adopted_path(&fixture, ACCT, ORG)).expect("the adopted copy is there");
    assert!(
        !adopted.contains("t-session"),
        "the kept copy is out of the adopted file and back in the item: {adopted}"
    );
    assert!(
        adopted.contains("sk-ant-oat01-incoming"),
        "and what the reversal displaced took its place: {adopted}"
    );

    // Both passes' whole `security` conversation: the swap's Phase A read,
    // re-read under the hold and verifying read, then the undo's same three,
    // with one `-i` write each. No migration probe on either — the swap's
    // incoming copy is fresh, so nothing asks whether it has migrated, and
    // this row reads no target in the keychain at all.
    assert_security(
        &fixture,
        &[("find-generic-password", 6), ("-i", 2), ("add-generic-password", 2)],
    );
    live_item_never_written(&fixture);
    audit_carries_no_token(&fixture);
}

#[test]
fn a_kept_copy_refuses_rather_than_renaming_over_the_credential_beside_the_store() {
    // Review F1. The keep arm writes `<D>/.credentials.adopted.json`, and
    // `write_adopted` renames over that name blind — so without the matrix's
    // own guards the two-swap sequence the feature itself produces destroys
    // D's only credential: D's namespace has migrated, an earlier swap parked
    // D's credential in that sibling, the session refreshed the item, and this
    // run's displaced copy is newer than T's store copy. The row now takes
    // that file's conditions, so an occupied-and-newer sibling refuses **F**
    // and the file is left exactly as it was.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, service) = two_accounts(&server, common::fresh_at());
    fixture.keychain_item(
        &service,
        &common::identified_blob(
            "sk-ant-oat01-t-session",
            "sk-ant-ort01-t-session",
            common::fresh_at() + 3_600_000,
            ACCT_T,
            Some(ORG_T),
        ),
    );
    // What an earlier `use --live T` parked there: D's own credential, which
    // exists nowhere else because D's store has migrated into the item this
    // swap is about to overwrite. Newer than the displaced copy, which is the
    // state the matrix refuses on.
    let ds_own = common::identified_blob(
        "sk-ant-oat01-d-parked",
        "sk-ant-ort01-d-parked",
        common::fresh_at() + 7_200_000,
        ACCT,
        Some(ORG),
    );
    fs::write(adopted_path(&fixture, ACCT, ORG), &ds_own).expect("the sibling is plantable");

    let (code, stdout, stderr) = swap(&fixture, &["--json"]);

    assert_eq!(code, 14, "SWAP_EXIT_REFUSED_F: {stdout}{stderr}");
    let doc = outcome_doc(&stdout);
    assert_eq!(doc["outcome"], json!("refused"), "{doc}");
    assert_eq!(doc["refusal"], json!("F"), "{doc}");
    // Identity outranks the expiry comparison, so this is the sentence even
    // though the sibling is also newer (fix loop 3); the same-account/newer
    // arm — `Refused(NewerCopy)` — is the unit table's row.
    assert!(
        stdout.contains("the adopted copy beside the store belongs to another account"),
        "{stdout}"
    );
    assert_eq!(
        fs::read_to_string(adopted_path(&fixture, ACCT, ORG)).expect("the sibling is readable"),
        ds_own,
        "D's credential is byte-unchanged: it lives nowhere else, and a rename over it would \
         cost an interactive login"
    );
    assert_eq!(token.calls(), 0, "T's copy is fresh, so no refresh POST ran");
    assert_eq!(writes(&fixture).len(), 0, "nothing reached the item: {:?}", writes(&fixture));
    let item =
        fs::read_to_string(fixture.keychain_item_path_for(common::KEYCHAIN_ACCOUNT, &service))
            .expect("the item is readable");
    assert!(item.contains("sk-ant-oat01-t-session"), "and the item still holds it: {item}");
}

#[test]
fn a_kept_copy_refuses_an_older_sibling_of_another_account_rather_than_replacing_it() {
    // The same file, the same loss, one `expiresAt` away from the test above:
    // D's parked credential is **older** than the displaced T copy, so the
    // expiry comparison alone ("strictly older, so strictly worth replacing")
    // would rename over it. That comparison means nothing across two
    // accounts — an older credential of somebody else is not a worse copy of
    // this one, it is their only one — so condition (a) applies to this file
    // and refuses first (fix loop 3).
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, service) = two_accounts(&server, common::fresh_at());
    fixture.keychain_item(
        &service,
        &common::identified_blob(
            "sk-ant-oat01-t-session",
            "sk-ant-ort01-t-session",
            common::fresh_at() + 3_600_000,
            ACCT_T,
            Some(ORG_T),
        ),
    );
    let ds_own = common::identified_blob(
        "sk-ant-oat01-d-parked",
        "sk-ant-ort01-d-parked",
        common::fresh_at() - 1_800_000,
        ACCT,
        Some(ORG),
    );
    fs::write(adopted_path(&fixture, ACCT, ORG), &ds_own).expect("the sibling is plantable");

    let (code, stdout, stderr) = swap(&fixture, &["--json"]);

    assert_eq!(code, 14, "SWAP_EXIT_REFUSED_F: {stdout}{stderr}");
    let doc = outcome_doc(&stdout);
    assert_eq!(doc["outcome"], json!("refused"), "{doc}");
    assert_eq!(doc["refusal"], json!("F"), "{doc}");
    assert!(
        stdout.contains("the adopted copy beside the store belongs to another account"),
        "the refusal names what it found, rather than talking about expiries: {stdout}"
    );
    assert_eq!(
        fs::read_to_string(adopted_path(&fixture, ACCT, ORG)).expect("the sibling is readable"),
        ds_own,
        "D's credential is byte-unchanged even though it expires sooner than the copy this swap \
         was carrying"
    );
    assert_eq!(token.calls(), 0, "no refresh POST ran");
    assert_eq!(writes(&fixture).len(), 0, "nothing reached the item: {:?}", writes(&fixture));
}

// ---------------------------------------------------------------------------
// W4b — `use --live` against the LIVE store
// ---------------------------------------------------------------------------

/// A registry holding **P**'s owner and the incoming account **T**, and a live
/// store reached through a **symbolic link** whose item holds P.
///
/// Three things about the shape, each load-bearing:
///
/// - **No `CLAUDE_SECURESTORAGE_CONFIG_DIR`**, which is what selects the live
///   arm of the scope gate's partition.
/// - **The live store is a link** (ory ruling 9 item 6). On a real machine
///   `~/.claude` is one (fact F41), and `Tree::Live`'s anchor logic exists for
///   exactly that: the store is resolved once, the walk starts at the resolved
///   parent, and the legacy lock is named after the resolved last component. A
///   test against a real directory exercises none of it.
/// - **The live item is present**, so the store counts as migrated. An absent
///   one refuses (`LiveItemAbsent`, exit 24) and has its own test.
///
/// Returns the fixture and the **resolved** live store, which is where every
/// artefact assertion points.
fn live_accounts(server: &MockServer, t_expires_at: i64) -> (Fixture, std::path::PathBuf) {
    let mut fixture = Fixture::new();
    fixture.with_keychain().endpoints(&server.base_url());
    fixture.write_registry(vec![
        fixture.owned_record(ACCT, ORG),
        owned_record_for(&fixture, ACCT_T, ORG_T, EMAIL_T),
    ]);

    // T's own credential, plaintext, in its own namespace.
    fixture.write_credentials(
        ACCT_T,
        ORG_T,
        &common::identified_blob(
            "sk-ant-oat01-incoming",
            "sk-ant-ort01-incoming",
            t_expires_at,
            ACCT_T,
            Some(ORG_T),
        ),
    );

    let resolved = fixture.live_through_link();

    // P: the live item, identified as the account that owns namespace ACCT/ORG
    // — so the adoption has somewhere inside `namespace_root()` to file it.
    fixture.dump(&[LIVE_SERVICE]);
    fixture.keychain_item(
        LIVE_SERVICE,
        &common::identified_blob(
            "sk-ant-oat01-outgoing",
            "sk-ant-ort01-outgoing",
            common::fresh_at(),
            ACCT,
            Some(ORG),
        ),
    );
    fixture.allow_write(LIVE_SERVICE);
    fixture.set("RUST_LOG", "agctl=debug");
    (fixture, resolved)
}

/// Asserts the live store's three lock artefacts are gone, and that the naive
/// `$HOME/.claude.lock` was never the legacy lock's name.
fn live_artefacts_released(fixture: &Fixture, resolved: &Path) {
    for path in Fixture::live_hold_artefacts(resolved) {
        assert!(!path.exists(), "`{}` should have been released", path.display());
    }
    let naive = fixture.home().join(".claude.lock");
    assert!(
        !naive.exists(),
        "`{}` must never exist: the legacy lock is `realpath(D) + \".lock\"` (fact F17), and \
         putting it beside the *link* instead would restore the F54/F55 race that lock exists \
         to lose",
        naive.display()
    );
}

/// P's credential as `live_accounts` plants it in the live item.
fn p_blob() -> String {
    common::identified_blob(
        "sk-ant-oat01-outgoing",
        "sk-ant-ort01-outgoing",
        common::fresh_at(),
        ACCT,
        Some(ORG),
    )
}

/// The bytes the fake keychain holds for the live item, or `None`.
fn live_item(fixture: &Fixture) -> Option<String> {
    fs::read_to_string(fixture.keychain_item_path(LIVE_SERVICE)).ok()
}

#[test]
fn ac82_a_live_swap_writes_the_unsuffixed_item_and_locks_the_resolved_store() {
    // Plan AC82's e2e half: the item the write named and the directory the
    // locks were taken in have to be the pair one `EnvView` derived. The
    // unit rows in `use_tests.rs` prove the derivation; this proves the
    // *effect*, and it proves it through a **link**, where a build that kept
    // the caller's lexical parent would put the legacy lock in the wrong place
    // and still pass every outcome assertion.
    let server = MockServer::start();
    let (fixture, resolved) = live_accounts(&server, common::fresh_at());
    assert!(
        fs::symlink_metadata(fixture.live_store_dir()).expect("planted").file_type().is_symlink(),
        "the fixture really does reach the live store through a link"
    );
    assert_ne!(resolved, fixture.live_store_dir(), "and the two spellings differ");

    let watch = ArtefactWatch::start(Fixture::live_hold_artefacts(&resolved));
    let (code, stdout, stderr) = swap(&fixture, &["--json"]);
    let (seen, windows) = watch.finish();

    assert_eq!(code, 0, "a live swap applies: {stdout}{stderr}");
    let doc = outcome_doc(&stdout);
    assert_eq!(doc["kind"], json!("outcome"), "the outcome document says which it is: {doc}");
    assert_eq!(doc["outcome"], json!("applied"), "{doc}");
    assert_eq!(doc["target"], json!("live"), "and names the live item as the audit log does");
    assert_eq!(doc["service"], json!(LIVE_SERVICE), "unsuffixed: {doc}");

    // The item, at the account-and-service path a write with the right `-a`
    // creates (invariant I1′'s sibling).
    let item = fixture.keychain_item_path_for(common::KEYCHAIN_ACCOUNT, LIVE_SERVICE);
    let stored = fs::read_to_string(&item).expect("the live item should hold the incoming blob");
    assert!(stored.contains("sk-ant-oat01-incoming"), "the item now holds T: {stored}");

    // The three artefacts, created under the **resolved** store and released.
    assert_eq!(seen, 3, "all three lock artefacts were held at once");
    assert_eq!(windows, 1, "in exactly one hold window");
    live_artefacts_released(&fixture, &resolved);
    hold_within_budget(&stderr);

    assert_security(
        &fixture,
        &[("find-generic-password", 4), ("-i", 1), ("add-generic-password", 1)],
    );
    audit_carries_no_token(&fixture);
    let lines = audit_lines(&fixture);
    assert_eq!(lines.len(), 1, "one write entry: {lines:?}");
    assert!(lines[0].contains("\"target\":\"live\""), "and it names the live item: {}", lines[0]);
}

#[test]
fn ac81_a_live_swap_touches_nothing_outside_the_namespace_root_but_the_three_artefacts() {
    // Invariant I11′'s W4b relaxation, asserted **by path** rather than by
    // inspection. The relaxation is exactly *the three lock artefacts plus the
    // keychain item*, so a whole-tree walk before and after must differ, outside
    // `namespace_root()`, by nothing at all — the artefacts are created and
    // released inside the pass — and the transient creations must be only those
    // three, at the **resolved** store.
    //
    // A forced break is included because a break is the one thing W4b does
    // outside the namespace root that W4a never could: `lock_stale` makes the
    // rule remove a planted peer lock, so the break path runs for real.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
    fixture.fault("lock_stale");

    // The peer's stale primary lock, inside the **resolved** store, genuinely
    // old rather than merely declared stale.
    let [primary, legacy, storage] = Fixture::live_hold_artefacts(&resolved);
    fs::create_dir_all(&primary).expect("the stale lock is plantable");
    age(&primary);

    let before = tree(&fixture);
    let ns_root = fixture.config_dir().join("claude");
    let watch = ArtefactWatch::start([primary.clone(), legacy.clone(), storage.clone()]);
    let (code, stdout, stderr) = swap(&fixture, &[]);
    let (seen, _windows) = watch.finish();
    let after = tree(&fixture);

    assert_eq!(code, 0, "the swap applies over a broken stale lock: {stdout}{stderr}");
    assert_eq!(seen, 3, "all three artefacts were held at once, at the resolved store");

    // `Paths::ensure_dirs` makes agctl's own cache directories on every pass,
    // and invariant I1 names `cache_dir()` beside `config_dir()` as the two
    // places this binary may write at all. Allowed **by name** rather than by
    // widening the bound, exactly as W4a's own AC81 test does it: anything else
    // appearing under `cache/` is not in this list and fails below.
    let allowed =
        [fixture.config_dir().join("cache"), fixture.config_dir().join("cache").join("claude")];
    let exempt = |path: &Path| path.starts_with(&ns_root) || allowed.contains(&path.to_path_buf());

    // The three artefacts, in **both** spellings of the resolved store. The walk
    // reaches them through the fixture's own `$HOME` (`/var/folders/…` on
    // macOS) and `fs::canonicalize` names the same directory through
    // `/private/var/folders/…`: one file, two paths, and a comparison that
    // looked at only one of them would read a removal as unaccounted for.
    let walked = fixture.home().join(".claude-real");
    let artefacts: Vec<std::path::PathBuf> = Fixture::live_hold_artefacts(&resolved)
        .into_iter()
        .chain(Fixture::live_hold_artefacts(&walked))
        .collect();

    // The load-bearing assertion: outside the namespace root, the two walks are
    // the same set. The three artefacts are created *and released* inside the
    // pass, so they are in neither — and the `ArtefactWatch` above is what saw
    // them while they existed, which is the other half of the claim.
    for path in after.keys().filter(|path| !exempt(path)) {
        assert!(
            before.contains_key(path),
            "`{}` was created outside the namespace root, and the W4b relaxation is only the \
             three lock artefacts plus the item",
            path.display()
        );
    }
    for path in before.keys().filter(|path| !exempt(path)) {
        assert!(
            after.contains_key(path) || artefacts.contains(path),
            "`{}` was removed outside the namespace root; only the three lock artefacts may be \
             — which is the whole of invariant I11′'s W4b relaxation",
            path.display()
        );
    }
    // The contents half, scoped to outside the root. W4a's
    // `no_new_credential_at_rest` forbids a new credential at rest **anywhere**,
    // which is right for a namespace swap and wrong here: a live swap's
    // adoption writes P into `namespace(P)/.credentials.json`, and that write
    // is required by decision D-017 rather than a leak. What must not happen is
    // a credential landing outside the root — where `use --undo`, `doctor` and
    // `accounts remove` cannot see it, and where nothing would ever clean it
    // up. A path-set diff alone is blind to a pre-existing file *rewritten*
    // with token material (finding N-13a), so the bytes are compared too.
    for (path, now) in &after {
        if exempt(path) {
            continue;
        }
        let Some(bytes) = now else { continue };
        if before.get(path).is_some_and(|was| was.as_ref() == Some(bytes)) {
            continue;
        }
        assert!(
            !String::from_utf8_lossy(bytes).contains("sk-ant-"),
            "`{}` was created or rewritten outside the namespace root and holds token material",
            path.display()
        );
    }

    // And specifically: nothing of the credential-at-rest kind anywhere under
    // the live store, in either spelling.
    for dir in [resolved.clone(), fixture.live_store_dir()] {
        for name in [".credentials.json", ADOPTED, ".claude.json"] {
            let path = dir.join(name);
            assert!(
                !path.exists(),
                "`{}` must not exist: no file under the live store is ever written by S23, and \
                 `.claude.json` is S24's entirely (decision D-021)",
                path.display()
            );
        }
    }
    live_artefacts_released(&fixture, &resolved);
    hold_within_budget(&stderr);
    // The four reads and one write every applied live swap makes — Phase A's
    // read of the item, the adoption's probe asking whether P's namespace has
    // migrated, the re-read under the hold, the verifying read — and nothing
    // for the break, which is a filesystem rule and never asks `security`.
    assert_security(
        &fixture,
        &[("find-generic-password", 4), ("-i", 1), ("add-generic-password", 1)],
    );

    // Every break line names the live tree, the live item and a path under the
    // **resolved** store (ory ruling 9 item 4, contract §D3).
    let lines = audit_lines(&fixture);
    let broken: Vec<&String> =
        lines.iter().filter(|line| line.contains("\"event\":\"lock_break\"")).collect();
    assert!(!broken.is_empty(), "the forced break was recorded: {lines:?}");
    let under_resolved = resolved.display().to_string();
    for line in &broken {
        assert!(line.contains("\"tree\":\"live\""), "the break names the live tree: {line}");
        assert!(line.contains("\"target\":\"live\""), "and the live item: {line}");
        assert!(line.contains("\"service\":\"Claude Code-credentials\""), "by name: {line}");
        assert!(
            field(line, "path").is_some_and(|path| path.starts_with(&under_resolved)),
            "and a path under the resolved store, not the link's: {line}"
        );
    }
    audit_carries_no_token(&fixture);
    let _ = token;
}

#[test]
fn ac76_a_live_swap_is_reversed_by_undo_and_the_item_holds_p_again() {
    // AC76's half that can run under the fake `security`: the swap applies, the
    // reversal puts P back **byte-identically**, and both audit entries name
    // the live item. The other half — `cdat` unchanged, `mdat` moved, and the
    // item count steady on the **real** keychain — is a user-operated manual
    // check and is unrun here by construction.
    //
    // The reversal is where §D5's re-cut shows: the forward pass filed P in
    // `namespace(P)/.credentials.json`, inside `namespace_root()`, and the
    // reversal reads it back from there rather than from a
    // `.credentials.adopted.json` beside `~/.claude` that I11′ forbids.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, resolved) = live_accounts(&server, common::fresh_at());
    let planted = live_item(&fixture).expect("the live item is planted");
    assert!(
        planted.contains("sk-ant-oat01-outgoing") && planted.contains(ACCT),
        "the premise: the live item holds P: {planted}"
    );

    let watch = ArtefactWatch::start(Fixture::live_hold_artefacts(&resolved));
    let (code, stdout, stderr) = swap(&fixture, &[]);
    let (seen, _windows) = watch.finish();
    assert_eq!(code, 0, "the forward swap applies: {stdout}{stderr}");
    assert_eq!(seen, 3, "the forward hold took all three artefacts under the resolved store");
    hold_within_budget(&stderr);
    let held = live_item(&fixture).expect("the live item is readable");
    assert!(held.contains("sk-ant-oat01-incoming"), "the live item holds T's access token: {held}");
    assert!(held.contains("sk-ant-ort01-incoming"), "and T's refresh token: {held}");
    assert!(!held.contains("sk-ant-oat01-outgoing"), "and no longer P's: {held}");
    // P went to its own namespace's `.credentials.json`, inside the root.
    let ps_store = fixture.credentials_path(ACCT, ORG);
    let parked = fs::read_to_string(&ps_store).expect("P is in its own namespace");
    assert!(parked.contains("sk-ant-oat01-outgoing"), "and it is P: {parked}");
    assert!(
        !resolved.join(ADOPTED).exists() && !fixture.live_store_dir().join(ADOPTED).exists(),
        "and never in an adopted copy beside the live store"
    );

    let watch = ArtefactWatch::start(Fixture::live_hold_artefacts(&resolved));
    let (code, stdout, stderr) = undo(&fixture);
    let (seen, _windows) = watch.finish();
    assert_eq!(code, 0, "the reversal applies: {stdout}{stderr}");
    assert_eq!(seen, 3, "the reversal took its own hold of all three, under the resolved store");
    // **The same credential, byte for byte** — as agctl serialises it. The
    // planted fixture blob is not the comparison: the forward pass parsed it
    // and filed `to_blob_json` in P's namespace (the serializer's own shape,
    // with the `workspaceId`/`workspaceName` nulls it always emits), and the
    // reversal wrote exactly those bytes back into the item. So the item must
    // equal what was parked, byte for byte, and what was parked must be P.
    let back = live_item(&fixture).expect("the live item is readable");
    assert_eq!(back, parked, "the live item holds P again, byte-identical to the parked copy");
    for field in ["sk-ant-oat01-outgoing", "sk-ant-ort01-outgoing", ACCT, ORG] {
        assert!(back.contains(field), "and that copy is P (`{field}`): {back}");
    }
    assert!(!back.contains("sk-ant-oat01-incoming"), "and no longer T's: {back}");
    // T went home in turn, which is what makes the operation its own inverse.
    let ts_store = fs::read_to_string(fixture.credentials_path(ACCT_T, ORG_T))
        .expect("T's own namespace still has a store");
    assert!(ts_store.contains("sk-ant-oat01-incoming"), "T is back in its own store: {ts_store}");

    let writes_seen: Vec<String> = write_lines(&fixture);
    assert_eq!(writes_seen.len(), 2, "one write each way: {writes_seen:?}");
    for line in &writes_seen {
        assert!(line.contains("\"target\":\"live\""), "both entries name the live item: {line}");
        assert_eq!(field(line, "outcome").as_deref(), Some("applied"), "both applied: {line}");
    }
    // The two entries are each other's inverse, which is what `--undo` means.
    let forward_from = field(&writes_seen[0], "from_digest8");
    assert!(forward_from.is_some(), "a live write always displaced something: {writes_seen:?}");
    assert_eq!(
        field(&writes_seen[1], "from_digest8"),
        field(&writes_seen[0], "to_digest8"),
        "the reversal displaced what the swap wrote"
    );
    assert_eq!(
        field(&writes_seen[1], "to_digest8"),
        forward_from,
        "and wrote back what the swap displaced"
    );
    live_artefacts_released(&fixture, &resolved);
    hold_within_budget(&stderr);
    // Four reads and one write each way: Phase A's read of the item, the probe
    // asking whether the third party's namespace has migrated (P's forward, T's
    // in reverse), the re-read under the hold and the verifying read.
    assert_security(
        &fixture,
        &[("find-generic-password", 8), ("-i", 2), ("add-generic-password", 2)],
    );
    audit_carries_no_token(&fixture);
    let _ = token;
}

#[test]
fn ac67_e_an_undo_of_a_live_entry_from_a_namespaced_shell_refuses_e() {
    // **The one reachable site of refusal E** (ruling G1). The forward scope
    // gate partitions on `CLAUDE_SECURESTORAGE_CONFIG_DIR`, so a forward
    // `use --live` can never reach the live subject build with it set. A
    // reversal takes its target from the **audit log**, so the two can and do
    // disagree — and that disagreement is the bug: locks in the namespace, a
    // write to the live item.
    //
    // The variable is set to a namespace agctl **owns**, so `NotOwned` cannot
    // fire and E is what is being tested.
    let server = MockServer::start();
    let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
    let spelling = common::export_spelling(&fixture.ns_dir(ACCT, ORG));
    fs::create_dir_all(fixture.ns_dir(ACCT, ORG)).expect("the namespace is creatable");

    // A live swap to reverse, then a shell pointed at a namespace.
    let (code, _stdout, _stderr) = swap(&fixture, &[]);
    assert_eq!(code, 0, "the forward swap applies from a shell with no namespace set");
    let writes_before = writes(&fixture).len();
    let audit_before = audit_lines(&fixture).len();
    assert_eq!(writes_before, 1, "the premise: the forward swap wrote the live item once");
    assert_eq!(audit_before, 1, "and left one entry, the live write `--undo` selects");
    fixture.set("CLAUDE_SECURESTORAGE_CONFIG_DIR", &spelling);

    let watch = ArtefactWatch::start(Fixture::live_hold_artefacts(&resolved));
    let (code, stdout, stderr) = undo(&fixture);
    let (seen, _windows) = watch.finish();
    assert_eq!(
        code, 13,
        "SWAP_EXIT_REFUSED_E — not refusal A's 10, not `live_unreachable`'s 23: {stdout}{stderr}"
    );
    assert_eq!(seen, 0, "no Claude Code lock artefact existed at any moment of the refused run");
    assert!(stdout.contains("CLAUDE_SECURESTORAGE_CONFIG_DIR"), "names the variable: {stdout}");
    assert!(stdout.contains(&spelling), "and its value: {stdout}");
    assert!(
        stdout.contains("run without it") && stdout.contains("target that namespace"),
        "and offers both ways out: {stdout}"
    );

    // The negatives r4v ruling 7 item 3 asks for: E must not arrive dressed as
    // refusal A, which means *somebody moved a lock agctl was holding*.
    let said = format!("{stdout}{stderr}");
    assert!(!said.contains("compromised"), "never the compromised-hold sentence: {said}");

    let (code, stdout, _stderr) = undo_json(&fixture);
    assert_eq!(code, 13, "SWAP_EXIT_REFUSED_E under --json too");
    let doc = outcome_doc(&stdout);
    assert_eq!(doc["outcome"], json!("refused"), "{doc}");
    assert_eq!(doc["refusal"], json!("E"), "the lettered refusal: {doc}");
    assert_eq!(doc["reason"], Value::Null, "and no `reason`, because it has a letter: {doc}");

    // Nothing locked, nothing written, nothing adopted, by either run.
    assert_eq!(writes(&fixture).len(), writes_before, "zero further `add-generic-password` lines");
    let lines = audit_lines(&fixture);
    assert_eq!(lines.len(), audit_before, "and no further audit entry: {lines:?}");
    assert_eq!(
        lines.iter().filter(|line| line.contains("\"event\":\"write\"")).count(),
        1,
        "the forward swap's write entry is the only one: {lines:?}"
    );
    assert!(
        !lines.iter().any(|line| line.contains("\"event\":\"lock_break\"")),
        "and no lock was broken by anybody: {lines:?}"
    );
    live_artefacts_released(&fixture, &resolved);
    for path in fixture.hold_artefacts(ACCT, ORG) {
        assert!(!path.exists(), "`{}` was never created either", path.display());
    }
    // The whole conversation is the forward swap's — Phase A's read, the
    // adoption's migration probe, the re-read under the hold, the verifying
    // read and the one write — and **nothing** from either refused undo: E is
    // decided where the live subject is built, before the item is read, so it
    // spawns no child at all (§D1).
    assert_security(
        &fixture,
        &[("find-generic-password", 4), ("-i", 1), ("add-generic-password", 1)],
    );
    audit_carries_no_token(&fixture);
}

/// `claude use --undo --yes --json`.
fn undo_json(fixture: &Fixture) -> (i32, String, String) {
    let output = fixture
        .cmd()
        .args(["claude", "use", "--undo", "--yes", "--json"])
        .output()
        .expect("the binary should run");
    (
        output.status.code().expect("the process exited normally"),
        String::from_utf8(output.stdout).expect("stdout is UTF-8"),
        common::strip_ansi(&String::from_utf8(output.stderr).expect("stderr is UTF-8")),
    )
}

// ---------------------------------------------------------------------------
// The audit-log gate (ruling G2) — a refused log refuses the LIVE swap
// ---------------------------------------------------------------------------

/// Plants a log agctl refuses, and returns the sentence `doctor` prints for it.
///
/// Two shapes, because they are refused by two different mechanisms and a test
/// that used only one would leave the other untested: a **wrong mode** is caught
/// on the opened descriptor, and a **symbolic link** is caught by `O_NOFOLLOW`
/// on the open itself.
fn plant_refused_log(fixture: &Fixture, shape: &str) {
    let log = fixture.audit_log_path();
    fs::create_dir_all(log.parent().expect("the log has a parent"))
        .expect("the namespace root is creatable");
    let _ = fs::remove_file(&log);
    match shape {
        "mode" => {
            fs::write(&log, b"").expect("the log is writable");
            fs::set_permissions(&log, std::os::unix::fs::PermissionsExt::from_mode(0o644))
                .expect("the mode is settable");
        }
        "symlink" => {
            let decoy = fixture.scratch("audit-decoy.jsonl");
            fs::write(&decoy, b"").expect("the decoy is writable");
            std::os::unix::fs::symlink(&decoy, &log).expect("the symlink is plantable");
        }
        other => panic!("unknown shape `{other}`"),
    }
}

#[test]
fn a_refused_audit_log_refuses_the_live_swap_and_writes_nothing() {
    // Ruling G2. Invariant I16 makes the audit line the only durable evidence
    // that agctl removed a lock in the user's own `~/.claude`, and the failure
    // is attacker-selectable: one `chmod 0644`, or one `ln -s`. A control whose
    // only failure mode is *the adversary switches it off and the privileged
    // action proceeds* is not a control, so the swap stops.
    //
    // Both shapes, and the assertion that matters for each is the same: **zero**
    // `add-generic-password` lines and no artefact created, so the refusal
    // really is in front of the mutation rather than after it.
    for shape in ["mode", "symlink"] {
        let server = MockServer::start();
        // An **expired** incoming credential and a live token endpoint: were the
        // gate after step 13's refresh POST, this run would spend the incoming
        // account's refresh token before refusing.
        let token = token_ok(&server);
        let (fixture, resolved) = live_accounts(&server, common::expired_at());
        plant_refused_log(&fixture, shape);

        let (code, stdout, stderr) = swap(&fixture, &["--json"]);
        assert_eq!(code, 22, "SWAP_EXIT_AUDIT_REFUSED for the `{shape}` shape: {stdout}{stderr}");
        let doc = outcome_doc(&stdout);
        assert_eq!(doc["outcome"], json!("refused"), "{doc}");
        assert_eq!(doc["reason"], json!("audit_refused"), "unlettered, with its own reason: {doc}");
        assert_eq!(doc["refusal"], Value::Null, "and no letter, because A–F is canonical: {doc}");

        // The sentence is `LogState::note()`'s, which is the one `doctor`'s
        // `audit log` row prints — so the CLI refusal and the diagnosis cannot
        // drift into two descriptions of one state.
        let note = doc["note"].as_str().unwrap_or_default();
        let sentence = match shape {
            "mode" => {
                "present, but its mode is 0644 and not 0600: agctl refuses the log and will not \
                 change it"
            }
            _ => "a symbolic link, which agctl will not append through",
        };
        assert!(
            note.contains(sentence),
            "`LogState::note()`'s sentence for the `{shape}` shape, verbatim: {note}"
        );
        assert!(
            note.contains(&fixture.audit_log_path().display().to_string()),
            "and it names the log: {note}"
        );
        // Refused, never repaired: what agctl will not append to, it also leaves
        // exactly as it found it.
        match shape {
            "mode" => {
                assert_eq!(common::mode_of(&fixture.audit_log_path()) & 0o7777, 0o644);
                assert_eq!(fs::read_to_string(fixture.audit_log_path()).expect("readable"), "");
            }
            _ => {
                let meta = fs::symlink_metadata(fixture.audit_log_path()).expect("stat-able");
                assert!(meta.file_type().is_symlink(), "the planted link is left where it was");
                let decoy = fs::read_to_string(fixture.scratch("audit-decoy.jsonl"));
                assert_eq!(decoy.expect("readable"), "", "and nothing reached its target");
            }
        }

        assert_eq!(writes(&fixture).len(), 0, "zero writes for the `{shape}` shape");
        // **One** read: Phase A's of the live item, and nothing else. That count
        // is itself an ordering assertion — the gate sits after the namespace
        // locks and *before* `decide_adoption`, so the adoption's own migration
        // probe (a second `find-generic-password` on every swap that gets that
        // far) has not happened. A gate that had drifted below the adoption
        // would show up here as two.
        assert_security(&fixture, &[("find-generic-password", 1)]);
        assert_eq!(token.calls(), 0, "no refresh POST for the `{shape}` shape: the gate is first");
        live_artefacts_released(&fixture, &resolved);
        for path in Fixture::live_hold_artefacts(&resolved) {
            assert!(!path.exists(), "`{}` was never created", path.display());
        }
        assert!(
            !fixture.credentials_path(ACCT, ORG).exists(),
            "and the adoption — itself a mutation — never ran either"
        );
    }
}

#[test]
fn a_refused_audit_log_does_not_refuse_a_namespaced_swap() {
    // The other half of ruling G2's scope: W4a's behaviour is **unchanged**. A
    // namespace swap logs the failed append and carries on, so the `broken`
    // line is ABSENT rather than redirected — fail-closed in the sense that
    // matters, and not a denial of service on a store whose blast radius is one
    // namespace agctl owns rather than the user's live session.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, service) = two_accounts(&server, common::fresh_at());
    plant_refused_log(&fixture, "mode");

    let (code, stdout, stderr) = swap(&fixture, &["--json"]);
    assert_eq!(code, 0, "a namespaced swap still applies over a refused log: {stdout}{stderr}");
    let doc = outcome_doc(&stdout);
    assert_eq!(doc["outcome"], json!("applied"), "{doc}");
    assert_eq!(doc["audit"]["id"], Value::Null, "and records no audit id, because it could not");
    assert_eq!(writes(&fixture).len(), 1, "the item was written");
    let stored = fs::read_to_string(fixture.keychain_item_path(&service)).expect("readable");
    assert!(stored.contains("sk-ant-oat01-incoming"), "with the incoming credential: {stored}");
    // The log itself is untouched: refused, never repaired.
    assert_eq!(
        common::mode_of(&fixture.audit_log_path()) & 0o7777,
        0o644,
        "agctl does not chmod the log back, because that would erase the evidence that \
         somebody else can read this machine's swap history"
    );
    assert_eq!(fs::read_to_string(fixture.audit_log_path()).expect("readable"), "");
    // A namespace swap's ordinary conversation, unchanged by the refused log:
    // Phase A's read, the re-read under the hold, the verifying read, one write.
    assert_security(
        &fixture,
        &[("find-generic-password", 3), ("-i", 1), ("add-generic-password", 1)],
    );
    let _ = token;
}

// ---------------------------------------------------------------------------
// The live store's own three refusals
// ---------------------------------------------------------------------------

#[test]
fn a_dangling_live_store_is_unreachable_rather_than_a_compromised_hold() {
    // Ruling G3. Every `LockError` used to collapse into refusal **A**, which
    // means *somebody moved a lock agctl was holding* — a security signal. A
    // `~/.claude` whose target has been removed is a configuration fact, and
    // spending **A** on it sends the user looking for an attacker.
    let server = MockServer::start();
    let (fixture, _resolved) = live_accounts(&server, common::fresh_at());
    // Replace the planted link's target with nothing, so the link dangles.
    fs::remove_dir_all(fixture.home().join(".claude-real")).expect("the target is removable");

    let (code, stdout, stderr) = swap(&fixture, &["--json"]);
    assert_eq!(code, 23, "SWAP_EXIT_LIVE_UNREACHABLE: {stdout}{stderr}");
    let doc = outcome_doc(&stdout);
    assert_eq!(doc["outcome"], json!("refused"), "{doc}");
    assert_eq!(doc["reason"], json!("live_unreachable"), "{doc}");
    assert_eq!(doc["refusal"], Value::Null, "never a letter: {doc}");
    let note = doc["note"].as_str().unwrap_or_default();
    assert!(
        note.contains(&fixture.live_store_dir().display().to_string()),
        "it names the spelling the environment gave: {note}"
    );
    assert!(note.contains("could not be resolved"), "and the failure: {note}");
    assert!(!note.contains("compromised"), "and never the compromised-hold sentence: {note}");

    // Decided in Phase A: nothing read, nothing locked, nothing written.
    assert_security(&fixture, &[]);
    assert!(audit_lines(&fixture).is_empty(), "and nothing audited");
    assert!(!fixture.home().join(".claude.lock").exists(), "no artefact anywhere");
}

#[test]
fn an_unmigrated_live_store_is_refused_and_its_plaintext_file_is_untouched() {
    // Ruling G4, and the reason the whole containment claim is exactly "three
    // artefacts plus the item". W4a's first-write path **removes**
    // `<D>/.credentials.json` once the write applies (finding N-2); for a live
    // target that is a deletion inside the user's own `~/.claude`, which
    // invariant I11′ does not price. So an absent live item refuses.
    let server = MockServer::start();
    let (fixture, resolved) = live_accounts(&server, common::fresh_at());
    // Un-migrate: remove the item and put P in the plaintext store instead,
    // which is what a live store that has never been opened by a recent
    // `claude` looks like.
    fs::remove_file(fixture.keychain_item_path(LIVE_SERVICE)).expect("the item is removable");
    let plaintext = resolved.join(".credentials.json");
    fs::write(&plaintext, p_blob()).expect("the live plaintext store is writable");
    let before = fs::read(&plaintext).expect("readable");

    let (code, stdout, stderr) = swap(&fixture, &["--json"]);
    assert_eq!(code, 24, "SWAP_EXIT_LIVE_ITEM_ABSENT: {stdout}{stderr}");
    let doc = outcome_doc(&stdout);
    assert_eq!(doc["reason"], json!("live_item_absent"), "{doc}");
    assert_eq!(doc["refusal"], Value::Null, "unlettered: {doc}");
    let note = doc["note"].as_str().unwrap_or_default();
    assert!(note.contains(&resolved.display().to_string()) || note.contains(".claude"), "{note}");
    assert!(
        note.contains("run `claude` once"),
        "the condition is transient and self-healing, so the message says so: {note}"
    );

    // The load-bearing assertion: the file is **byte-identical**, present
    // before and after. A claim that the pass did not remove it is only worth
    // making against a file that was there to remove.
    assert_eq!(
        fs::read(&plaintext).expect("readable"),
        before,
        "the live store's plaintext credential is untouched, which is the whole of ruling G4"
    );
    assert_eq!(writes(&fixture).len(), 0, "zero writes");
    // One read: Phase A's, which is what found the item absent.
    assert_security(&fixture, &[("find-generic-password", 1)]);
    live_artefacts_released(&fixture, &resolved);
    assert!(audit_lines(&fixture).is_empty(), "nothing was audited");
}

// ---------------------------------------------------------------------------
// D-017 against a live target (§D5) — where the displaced credential goes
// ---------------------------------------------------------------------------

#[test]
fn the_live_r3h_row_parks_the_displaced_copy_in_the_incoming_namespace() {
    // `agctl-r3h`'s **live re-cut**, and the one row whose destination the
    // contract had to move rather than inherit. Task 4's keep arm writes
    // `<D>/.credentials.adopted.json` — correct for a namespace target, where
    // `D` is itself under `namespace_root()` and where `use --undo` reads it
    // back. For a live target `D` is `~/.claude`, so the same decision would
    // write a live access **and** refresh token into the user's own store,
    // outside `namespace_root()`, where nothing agctl has would ever clean it
    // up. §D5 substitutes `<namespace(T)>/.credentials.adopted.json`: inside the
    // root, and still not a `.credentials.json`, so neither the write-back's
    // compare-and-swap nor T's own store is touched.
    //
    // The shape: the live item holds a credential of **T** (what one earlier
    // `use --live T` leaves) that is *strictly newer* than what T's own store
    // holds — the state a Claude Code session produces by refreshing after that
    // swap.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, resolved) = live_accounts(&server, common::fresh_at());
    let newer = common::identified_blob(
        "sk-ant-oat01-t-newer",
        "sk-ant-ort01-t-newer",
        common::fresh_at() + 3_600_000,
        ACCT_T,
        Some(ORG_T),
    );
    fixture.keychain_item(LIVE_SERVICE, &newer);

    let watch = ArtefactWatch::start(Fixture::live_hold_artefacts(&resolved));
    let (code, stdout, stderr) = swap(&fixture, &[]);
    let (seen, _windows) = watch.finish();
    assert_eq!(code, 0, "the swap applies: {stdout}{stderr}");
    assert_eq!(seen, 3, "the hold took all three artefacts under the resolved store");
    hold_within_budget(&stderr);

    // The load-bearing pair of assertions.
    let kept = fixture.ns_dir(ACCT_T, ORG_T).join(ADOPTED);
    let parked = fs::read_to_string(&kept).expect("the displaced copy is in T's own namespace");
    assert!(parked.contains("sk-ant-oat01-t-newer"), "and it is the newer copy: {parked}");
    for dir in [resolved.clone(), fixture.live_store_dir()] {
        assert!(
            !dir.join(ADOPTED).exists(),
            "`{}` must not exist: `ToAdoptedCopy` against a live target would write inside the \\
             user's own store, which invariant I11′ forbids",
            dir.join(ADOPTED).display()
        );
    }
    // And the property the row exists to preserve: T's own `.credentials.json`
    // is what the write-back writes, so the adoption must not have touched it.
    let ts_store =
        fs::read_to_string(fixture.credentials_path(ACCT_T, ORG_T)).expect("T's store is readable");
    assert!(
        ts_store.contains("sk-ant-oat01-incoming") && !ts_store.contains("sk-ant-oat01-t-newer"),
        "T's own store still holds what it held: {ts_store}"
    );

    // And `use --undo` reads it back **from there** — through the `PathBuf`
    // `Source::AdoptedCopy` already carries, so no type had to widen.
    let (code, stdout, stderr) = undo(&fixture);
    assert_eq!(code, 0, "the reversal applies: {stdout}{stderr}");
    let back = live_item(&fixture).expect("the live item is readable");
    assert!(back.contains("sk-ant-oat01-t-newer"), "the newer copy is back in the item: {back}");
    hold_within_budget(&stderr);
    live_artefacts_released(&fixture, &resolved);
    // Two passes of three reads and one write — Phase A's read, the re-read
    // under the hold, the verifying read — and **no** migration probe in
    // either: this row names no third namespace, forward or back.
    assert_security(
        &fixture,
        &[("find-generic-password", 6), ("-i", 2), ("add-generic-password", 2)],
    );
    audit_carries_no_token(&fixture);
    let _ = token;
}

#[test]
fn a_live_credential_no_record_claims_is_refused_rather_than_adopted_anywhere() {
    // Decision D-017 is categorical: adopt the displaced credential or refuse
    // the swap. There is no third answer in which the swap proceeds and the
    // credential is dropped — and for a live target there is no store record to
    // fall back on, so a credential agctl cannot attribute to an account it
    // **owns** has nowhere to go. Refusal **F**, before the prompt and before
    // any mutation, in three shapes, each with the sentence that is true of it
    // (§D5): an account agctl has never heard of, an account agctl knows only as
    // a read-only row (whose credentials live outside agctl's store, so a
    // namespace for it would be manufactured), and no account at all.
    const STRANGER_ACCT: &str = "cccccccc-dddd-eeee-ffff-000000000000";
    const STRANGER_ORG: &str = "11112222-3333-4444-5555-666677778888";
    let stranger = occupant_blob(
        "sk-ant-oat01-stranger",
        common::fresh_at(),
        STRANGER_ACCT,
        STRANGER_ORG,
        "stranger@example.com",
    );
    let anonymous = json!({
        "claudeAiOauth": {
            "accessToken": "sk-ant-oat01-anonymous",
            "refreshToken": "sk-ant-ort01-anonymous",
            "expiresAt": common::fresh_at(),
            "scopes": ["user:inference"],
            "subscriptionType": "max",
        }
    })
    .to_string();
    let no_record = "no account agctl owns is that one";
    let shapes = [
        ("an account agctl has never heard of", stranger.clone(), false, no_record),
        ("an account agctl knows only as a read-only row", stranger, true, no_record),
        ("no account at all", anonymous, false, "does not say which account it belongs to"),
    ];

    for (shape, item, read_only_row, sentence) in shapes {
        let server = MockServer::start();
        let (fixture, resolved) = live_accounts(&server, common::fresh_at());
        if read_only_row {
            fixture.write_registry(vec![
                fixture.owned_record(ACCT, ORG),
                owned_record_for(&fixture, ACCT_T, ORG_T, EMAIL_T),
                fixture.config_dir_record(
                    STRANGER_ACCT,
                    STRANGER_ORG,
                    "Claude Code-credentials-0badc0de",
                ),
            ]);
        }
        fixture.keychain_item(LIVE_SERVICE, &item);

        let (code, stdout, stderr) = swap(&fixture, &["--json"]);
        assert_eq!(code, 14, "SWAP_EXIT_REFUSED_F for {shape}: {stdout}{stderr}");
        let doc = outcome_doc(&stdout);
        assert_eq!(doc["refusal"], json!("F"), "{shape}: {doc}");
        let note = doc["note"].as_str().unwrap_or_default();
        assert!(note.contains(sentence), "{shape}: the sentence true of it: {note}");
        assert!(
            !note.contains("the account that owns this store"),
            "{shape}: never the namespace target's sentence, whose owner the live store lacks"
        );

        // Phase A's read of the item and nothing else: refused before the
        // adoption's migration probe, before the prompt and before the hold.
        assert_security(&fixture, &[("find-generic-password", 1)]);
        live_artefacts_released(&fixture, &resolved);
        assert!(audit_lines(&fixture).is_empty(), "{shape}: nothing audited");
        // Nothing was filed anywhere, in either tree — including a namespace
        // for the stranger, which is what a manufactured filing would create.
        for (acct, org) in [(ACCT, ORG), (ACCT_T, ORG_T)] {
            assert!(!adopted_path(&fixture, acct, org).exists(), "{shape}: no copy for {acct}");
        }
        assert!(!fixture.credentials_path(ACCT, ORG).exists(), "{shape}: no store for P's owner");
        assert!(
            !fixture.ns_dir(STRANGER_ACCT, STRANGER_ORG).exists(),
            "{shape}: and no namespace manufactured for the stranger"
        );
        audit_carries_no_token(&fixture);
    }
}

#[test]
fn a_live_swap_between_two_orgs_of_one_account_files_the_displaced_credential_in_its_own_org() {
    // Review F1. The registry is keyed by (account, organisation), and one
    // account in two organisations is a supported shape. Here the live item
    // holds account A's **org2** credential and the swap brings in A's
    // **org1**. Choosing the third party by account alone found org1's record
    // — the incoming one, listed first — and filed org2's credential over
    // org1's own `.credentials.json` whenever it was the newer of the two: the
    // undo could not find it afterwards, and org1's store was gone. §D5 names
    // the destination `namespace(P.identity)`: account **and** organisation.
    const ORG_1: &str = "12121212-1111-4111-8111-121212121212";
    const ORG_2: &str = "23232323-2222-4222-8222-232323232323";
    let server = MockServer::start();
    let token = token_ok(&server);
    let mut fixture = Fixture::new();
    fixture.with_keychain().endpoints(&server.base_url());
    // org1 first, so an account-only search meets the incoming record before
    // the credential's own.
    fixture.write_registry(vec![
        owned_record_for(&fixture, ACCT_T, ORG_1, "a-org1@example.com"),
        owned_record_for(&fixture, ACCT_T, ORG_2, "a-org2@example.com"),
    ]);
    let org1_store = fixture.write_credentials(
        ACCT_T,
        ORG_1,
        &common::identified_blob(
            "sk-ant-oat01-org1",
            "sk-ant-ort01-org1",
            common::fresh_at(),
            ACCT_T,
            Some(ORG_1),
        ),
    );
    let org1_before = fs::read(&org1_store).expect("org1's store is readable");
    let resolved = fixture.live_through_link();
    fixture.dump(&[LIVE_SERVICE]);
    // A's org2 credential, an hour **newer** than org1's store copy: the shape
    // in which the account-only selection overwrote org1's store rather than
    // refusing `NewerCopy`.
    fixture.keychain_item(
        LIVE_SERVICE,
        &common::identified_blob(
            "sk-ant-oat01-org2",
            "sk-ant-ort01-org2",
            common::fresh_at() + 3_600_000,
            ACCT_T,
            Some(ORG_2),
        ),
    );
    fixture.allow_write(LIVE_SERVICE);
    fixture.set("RUST_LOG", "agctl=debug");

    let id = format!("{ACCT_T}/{ORG_1}");
    let watch = ArtefactWatch::start(Fixture::live_hold_artefacts(&resolved));
    let output = fixture
        .cmd()
        .args(["claude", "use", "--live", id.as_str(), "--yes"])
        .output()
        .expect("the binary should run");
    let (seen, _windows) = watch.finish();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = common::strip_ansi(&String::from_utf8_lossy(&output.stderr));
    assert_eq!(output.status.code(), Some(0), "the org switch applies: {stdout}{stderr}");
    assert_eq!(seen, 3, "under a real hold of all three artefacts at the resolved store");
    hold_within_budget(&stderr);

    // The load-bearing pair, by path.
    let org2_store = fixture.credentials_path(ACCT_T, ORG_2);
    let parked =
        fs::read_to_string(&org2_store).expect("org2's credential is in org2's own namespace");
    assert!(parked.contains("sk-ant-oat01-org2"), "and it is org2's: {parked}");
    assert_eq!(
        fs::read(&org1_store).expect("readable"),
        org1_before,
        "org1's own store is byte-identical: the displaced org2 credential was not filed over it"
    );
    let item = live_item(&fixture).expect("the live item is readable");
    assert!(item.contains("sk-ant-oat01-org1"), "the item holds org1's credential: {item}");

    // And `--undo` finds org2's credential where it was filed.
    let (code, stdout, stderr) = undo(&fixture);
    assert_eq!(code, 0, "the reversal finds the org2 credential and applies: {stdout}{stderr}");
    let back = live_item(&fixture).expect("the live item is readable");
    assert_eq!(back, parked, "the live item holds org2's credential again, byte for byte");
    assert_eq!(
        fs::read(&org1_store).expect("readable"),
        org1_before,
        "org1's store still untouched"
    );
    hold_within_budget(&stderr);
    live_artefacts_released(&fixture, &resolved);
    // Each way: Phase A's read, the probe of the third party's namespace (org2
    // forward, org1 in reverse), the re-read under the hold, the verifying read
    // and the write.
    assert_security(
        &fixture,
        &[("find-generic-password", 8), ("-i", 2), ("add-generic-password", 2)],
    );
    audit_carries_no_token(&fixture);
    let _ = token;
}

#[test]
fn a_live_swap_creates_ps_namespace_only_under_the_namespace_root() {
    // The ordinary live row, in the state that exercises the creation: P's
    // namespace does not exist yet, because P has only ever lived in the live
    // item. It is created through `file_store`'s `O_NOFOLLOW` walk under
    // `namespace_root()` and nowhere else — no new artefact class (invariant
    // I5′), and never a path derived from anything but `Paths::namespace_dir`.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, resolved) = live_accounts(&server, common::fresh_at());
    let ns = fixture.ns_dir(ACCT, ORG);
    assert!(!ns.exists(), "P's namespace does not exist before the pass");

    let watch = ArtefactWatch::start(Fixture::live_hold_artefacts(&resolved));
    let (code, stdout, stderr) = swap(&fixture, &[]);
    let (seen, _windows) = watch.finish();
    assert_eq!(code, 0, "the swap applies: {stdout}{stderr}");
    assert_eq!(seen, 3, "all three artefacts were held, under the resolved store");
    hold_within_budget(&stderr);
    assert!(ns.is_dir(), "P's namespace was created");
    assert!(
        ns.starts_with(fixture.config_dir().join("claude")),
        "under the namespace root and nowhere else: {}",
        ns.display()
    );
    assert_eq!(
        common::mode_of(&ns) & 0o777,
        0o700,
        "and at 0700, like every other directory this binary creates"
    );
    let entries = fixture.namespace_entries(ACCT, ORG);
    assert_eq!(
        entries,
        vec![".credentials.json".to_owned()],
        "exactly the adoption's own file, and no new artefact class: {entries:?}"
    );
    let parked = fs::read_to_string(fixture.credentials_path(ACCT, ORG)).expect("readable");
    assert!(parked.contains("sk-ant-oat01-outgoing"), "and that file is P: {parked}");
    assert_eq!(common::mode_of(&fixture.credentials_path(ACCT, ORG)) & 0o777, 0o600, "at 0600");
    live_artefacts_released(&fixture, &resolved);
    assert_security(
        &fixture,
        &[("find-generic-password", 4), ("-i", 1), ("add-generic-password", 1)],
    );
    let _ = token;
}

#[test]
fn a_live_undo_refreshes_an_expired_credential_and_persists_it() {
    // `agctl-bk5` (a reversal discarded a refreshed credential) under §D5's
    // reversal rule. For a live target both directions reduce to `ToStore`
    // against the credential's own namespace, so the credential being put back
    // is read from `namespace(P)/.credentials.json` — which makes the reverse
    // write-back a **change of target** rather than a new path: it goes through
    // `guarded_write_back`, with task 3's five guards including
    // `detect_unlisted`.
    //
    // Without it the POST would rotate the server's refresh token away from the
    // copy in P's own store and throw the result away, costing P an interactive
    // `login` — which is finding N-8, in the one direction W4a could not reach.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, resolved) = live_accounts(&server, common::fresh_at());

    let (code, stdout, stderr) = swap(&fixture, &[]);
    assert_eq!(code, 0, "the forward swap applies: {stdout}{stderr}");

    // Age P where the forward pass parked it, so the reversal has to refresh it.
    let ps_store = fixture.credentials_path(ACCT, ORG);
    fs::write(
        &ps_store,
        common::identified_blob(
            "sk-ant-oat01-outgoing",
            "sk-ant-ort01-outgoing",
            common::expired_at(),
            ACCT,
            Some(ORG),
        ),
    )
    .expect("P's store is writable");

    let watch = ArtefactWatch::start(Fixture::live_hold_artefacts(&resolved));
    let (code, stdout, stderr) = undo(&fixture);
    let (seen, _windows) = watch.finish();
    assert_eq!(code, 0, "the reversal applies over a refreshed credential: {stdout}{stderr}");
    assert_eq!(seen, 3, "the reversal's hold took all three artefacts under the resolved store");

    // The item holds the **rotation**, not the expired pair.
    let back = live_item(&fixture).expect("the live item is readable");
    assert!(back.contains("sk-ant-oat01-rotated"), "the item holds the refreshed access: {back}");
    // And the refreshed pair was saved back where it was read from, which is
    // the whole of `bk5`: the refresh token the server has just rotated to is
    // in P's own store rather than lost.
    let saved = fs::read_to_string(&ps_store).expect("P's store is readable");
    assert!(
        saved.contains("sk-ant-ort01-rotated"),
        "the refreshed refresh token was persisted through `guarded_write_back`: {saved}"
    );
    assert!(!saved.contains("sk-ant-ort01-outgoing"), "and the spent one is gone: {saved}");
    assert_eq!(token.calls(), 1, "exactly one refresh POST");
    assert_eq!(
        back, saved,
        "one refresh, two homes: the item and P's own store hold the same credential, byte for byte"
    );
    hold_within_budget(&stderr);
    live_artefacts_released(&fixture, &resolved);
    // The forward swap's four reads and one write, then the reversal's: Phase
    // A's read, the probe asking whether T's namespace has migrated (T is the
    // third party now), the pre-POST probe asking the same of P's, the
    // write-back gate's two — `detect_unlisted`, one per candidate service name
    // (`agctl-r9w` review F1) — the re-read under the hold, the verifying read.
    assert_security(
        &fixture,
        &[("find-generic-password", 11), ("-i", 2), ("add-generic-password", 2)],
    );
    audit_carries_no_token(&fixture);
}

#[test]
fn a_live_undo_whose_refreshed_credential_cannot_be_saved_warns_on_stderr_and_in_json() {
    // `agctl-bk5`'s refusal half, through `guarded_write_back`'s own guard
    // rather than a stand-in for it. P's namespace is planted as **migrated**
    // under its *canonical* spelling's service — a name `detect_unlisted` asks
    // about and the pre-POST probe (which reads only the recorded spelling's)
    // does not — so the refresh runs and its write-back is refused: a
    // plaintext write there would land where nobody reads it (invariant I5′).
    // The empty-listing `detect` would see no item under either name and write
    // the file anyway, which is the substitution this test exists to catch.
    //
    // A refused write-back does not fail the reversal — the item write is what
    // was asked for — but it is not silent either: a `note:` on stderr for a
    // person, and the same sentence in `--json`'s `warnings` for a machine.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (fixture, resolved) = live_accounts(&server, common::fresh_at());
    let (code, stdout, stderr) = swap(&fixture, &[]);
    assert_eq!(code, 0, "the forward swap applies: {stdout}{stderr}");

    let ps_store = fixture.credentials_path(ACCT, ORG);
    let expired = common::identified_blob(
        "sk-ant-oat01-outgoing",
        "sk-ant-ort01-outgoing",
        common::expired_at(),
        ACCT,
        Some(ORG),
    );
    fs::write(&ps_store, &expired).expect("P's store is writable");
    let migrated = common::canonical_migration_service(&fixture.ns_dir(ACCT, ORG));
    assert_ne!(
        migrated,
        common::migration_service(&fixture.ns_dir(ACCT, ORG)),
        "the premise: two spellings, two services, so only the write-back gate asks about this one"
    );
    fixture.keychain_item(
        &migrated,
        &common::identified_blob(
            "sk-ant-oat01-migrated",
            "sk-ant-ort01-migrated",
            common::fresh_at(),
            ACCT,
            Some(ORG),
        ),
    );

    let (code, stdout, stderr) = undo_json(&fixture);
    assert_eq!(code, 0, "the reversal still applies: {stdout}{stderr}");
    let doc = outcome_doc(&stdout);
    assert_eq!(doc["outcome"], json!("applied"), "{doc}");
    let warnings = doc["warnings"].as_array().expect("the document carries a warnings array");
    let refused: Vec<&str> = warnings
        .iter()
        .filter_map(Value::as_str)
        .filter(|warning| warning.contains("was not saved back to its own store"))
        .collect();
    assert_eq!(refused.len(), 1, "exactly one write-back warning in `--json`: {doc}");
    assert!(refused[0].contains("migrated into the keychain item"), "why: {}", refused[0]);
    assert!(refused[0].contains(&migrated), "and which item: {}", refused[0]);
    assert!(
        stderr.contains(&format!("note: {}", refused[0])),
        "the same sentence reaches stderr as a note: {stderr}"
    );
    assert!(!stdout.contains("sk-ant-"), "{stdout}");

    // The refusal is real: the refreshed pair reached the item and nothing else.
    assert_eq!(token.calls(), 1, "the refresh POST ran");
    let back = live_item(&fixture).expect("the live item is readable");
    assert!(back.contains("sk-ant-oat01-rotated"), "the item holds the rotation: {back}");
    assert_eq!(
        fs::read_to_string(&ps_store).expect("readable"),
        expired,
        "and P's plaintext store was not written: the write-back refused"
    );
    hold_within_budget(&stderr);
    live_artefacts_released(&fixture, &resolved);
    // Forward: four reads and one write. Reversal: Phase A's read, T's
    // migration probe, P's pre-POST probe, the write-back gate's two (the
    // recorded spelling's item absent, the canonical spelling's present), the
    // re-read under the hold, the verifying read, and the write.
    assert_security(
        &fixture,
        &[("find-generic-password", 11), ("-i", 2), ("add-generic-password", 2)],
    );
    audit_carries_no_token(&fixture);
}

// ---------------------------------------------------------------------------
// AC71 / AC72 / AC74 against the live store
// ---------------------------------------------------------------------------

#[test]
fn ac72_a_live_swap_to_the_credential_already_in_the_item_is_already_active() {
    // Plan AC72 against the live item: nothing adopted, nothing written, and —
    // the assertion that makes it load-bearing — **zero** `-i` lines and zero
    // audit lines, because `already_active` is decided in Phase A before any
    // lock exists.
    let server = MockServer::start();
    let (fixture, resolved) = live_accounts(&server, common::fresh_at());
    let t = common::identified_blob(
        "sk-ant-oat01-incoming",
        "sk-ant-ort01-incoming",
        common::fresh_at(),
        ACCT_T,
        Some(ORG_T),
    );
    fixture.write_credentials(ACCT_T, ORG_T, &t);
    fixture.keychain_item(LIVE_SERVICE, &t);

    let (code, stdout, stderr) = swap(&fixture, &["--json"]);
    assert_eq!(code, 0, "already active is exit 0: {stdout}{stderr}");
    let doc = outcome_doc(&stdout);
    assert_eq!(doc["outcome"], json!("already_active"), "{doc}");
    assert_eq!(doc["adopted_to"], Value::Null, "nothing was adopted: {doc}");
    assert_eq!(doc["lock"]["hold_ms"], Value::Null, "and no hold was taken: {doc}");
    assert_eq!(writes(&fixture).len(), 0, "zero `-i` lines");
    assert!(audit_lines(&fixture).is_empty(), "and zero audit lines");
    assert_security(&fixture, &[("find-generic-password", 1)]);
    live_artefacts_released(&fixture, &resolved);
}

#[test]
fn ac74_a_live_write_that_hangs_is_unknown_with_its_audit_id_and_a_released_hold() {
    // Plan AC74 against the live item. A child killed at the hold timeout
    // leaves the write's outcome **undetermined**, which is what `unknown`
    // means — "re-run `status`", not "failed" — and the verifying read after the
    // release is what would have settled it.
    //
    // Three things are asserted beyond the outcome, each because a weaker test
    // passed on a build that got one wrong: the hold is **released** (all three
    // artefacts gone), the audit id is in the completion line so an operator can
    // find the entry, and `--json` carries no token material and no long hex.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
    fixture.fault("keychain_write_hang");
    let before = live_item(&fixture).expect("the live item is readable");

    let watch = ArtefactWatch::start(Fixture::live_hold_artefacts(&resolved));
    let (code, stdout, stderr) = swap(&fixture, &["--json"]);
    let (seen, _windows) = watch.finish();
    assert_eq!(code, 18, "SWAP_EXIT_UNKNOWN: {stdout}{stderr}");
    assert_eq!(seen, 3, "the write was attempted inside a real hold of all three artefacts");
    hold_within_budget(&stderr);

    let doc = outcome_doc(&stdout);
    // The exact key set, so nothing can be added to the outcome document —
    // a digest, a path, a sample — without this test saying so.
    let keys: std::collections::BTreeSet<&str> =
        doc.as_object().expect("the document is an object").keys().map(String::as_str).collect();
    let expected: std::collections::BTreeSet<&str> = [
        "adopted_to",
        "audit",
        "from",
        "kind",
        "lock",
        "note",
        "outcome",
        "refusal",
        "service",
        "target",
        "to",
        "warnings",
    ]
    .into_iter()
    .collect();
    assert_eq!(keys, expected, "the outcome document's key set: {doc}");
    assert_eq!(doc["kind"], json!("outcome"), "{doc}");
    assert_eq!(doc["outcome"], json!("unknown"), "{doc}");
    assert_eq!(doc["refusal"], Value::Null, "`unknown` is not a lettered refusal: {doc}");
    assert_eq!(doc["target"], json!("live"), "{doc}");
    assert_eq!(doc["service"], json!(LIVE_SERVICE), "{doc}");
    assert!(doc["from"]["digest8"].is_string() && doc["to"]["digest8"].is_string(), "{doc}");
    assert!(doc["lock"]["hold_ms"].is_u64(), "the lock timings the contract names: {doc}");
    assert_eq!(doc["lock"]["budget_ms"], json!(3000), "{doc}");
    let id = doc["audit"]["id"].as_str().expect("the audit id is in the document");
    assert!(!id.is_empty(), "and it is not empty");
    let note = doc["note"].as_str().unwrap_or_default();
    assert!(note.contains("re-run"), "the note says what to do: {note}");

    // No token material, and no hex string long enough to be a whole digest,
    // anywhere in the document — nested members included.
    assert!(!stdout.contains("sk-ant-"), "{stdout}");
    let mut stack = vec![&doc];
    while let Some(value) = stack.pop() {
        match value {
            Value::String(text) => assert!(
                text.len() <= 32 || !text.chars().all(|c| c.is_ascii_hexdigit()),
                "a raw hash rather than a digest prefix: {text}"
            ),
            Value::Array(items) => stack.extend(items),
            Value::Object(members) => stack.extend(members.values()),
            _ => {}
        }
    }

    let lines = write_lines(&fixture);
    assert_eq!(lines.len(), 1, "one entry: {lines:?}");
    assert_eq!(field(&lines[0], "outcome").as_deref(), Some("unknown"), "{}", lines[0]);
    assert_eq!(field(&lines[0], "target").as_deref(), Some("live"), "{}", lines[0]);
    // The child was killed before it could touch the item.
    assert_eq!(live_item(&fixture).expect("readable"), before, "the live item still holds P");
    live_artefacts_released(&fixture, &resolved);
    audit_carries_no_token(&fixture);
    // Phase A's read, the adoption's migration probe, the re-read under the
    // hold and the verifying read that settles the question — and no `-i`,
    // because the hang is injected where the child would have been spawned.
    assert_security(&fixture, &[("find-generic-password", 4)]);
    let _ = token;
}

#[test]
fn ac71_a_live_item_that_changes_before_the_hold_discards_the_swap() {
    // Plan AC71 against the live item, invariant I2′'s window. The pause point
    // is **outside** the hold — a pause inside one would violate invariant I17
    // even under a fault — so the peer's write lands where a real session's
    // would, and the re-read under the hold finds a digest Phase A never saw.
    //
    // Thrown away rather than written over: the credential now in the item may
    // hold a refresh token the server has already rotated away from the one
    // this pass was going to install.
    let server = MockServer::start();
    let token = token_ok(&server);
    let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
    let resume = fixture.scratch("resume");
    fixture.fault("pause_before_swap_write");
    fixture.set("AGCTL_FAULT_RESUME", &resume.to_string_lossy());

    let item = fixture.keychain_item_path_for(common::KEYCHAIN_ACCOUNT, LIVE_SERVICE);
    let peer = common::identified_blob(
        "sk-ant-oat01-peer",
        "sk-ant-ort01-peer",
        common::fresh_at(),
        ACCT,
        Some(ORG),
    );

    let watch = ArtefactWatch::start(Fixture::live_hold_artefacts(&resolved));
    let child = fixture
        .raw()
        .args(["claude", "use", "--live", EMAIL_T, "--yes", "--json"])
        .spawn()
        .expect("the binary should start");
    common::wait_until(Duration::from_secs(20), || {
        fs::read_to_string(&item).is_ok_and(|text| text.contains("sk-ant-oat01-outgoing"))
    });
    std::thread::sleep(Duration::from_millis(200));
    fs::write(&item, &peer).expect("the peer writes the live item");
    fs::write(&resume, b"go").expect("the resume file is writable");

    let output = child.wait_with_output().expect("the swap finishes");
    let (seen, _windows) = watch.finish();
    assert_eq!(output.status.code(), Some(17), "SWAP_EXIT_DISCARDED");
    assert_eq!(seen, 3, "the change was found under a real hold of all three artefacts");
    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let doc = outcome_doc(&stdout);
    assert_eq!(doc["outcome"], json!("discarded"), "{doc}");
    assert_eq!(doc["refusal"], Value::Null, "a discard is not a lettered refusal: {doc}");
    assert!(!stdout.contains("sk-ant-"), "{stdout}");

    assert_eq!(writes(&fixture).len(), 0, "zero `-i` lines: {:?}", writes(&fixture));
    let after = fs::read_to_string(&item).expect("readable");
    assert!(after.contains("sk-ant-oat01-peer"), "the live item still holds the peer's blob");
    live_artefacts_released(&fixture, &resolved);
    // Phase A's read, the adoption's migration probe, and the re-read under
    // the hold that found the change — no write and no verifying read.
    assert_security(&fixture, &[("find-generic-password", 3)]);
    audit_carries_no_token(&fixture);
    let _ = token;
}
