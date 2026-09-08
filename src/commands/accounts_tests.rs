//! `accounts`, driven end to end in this process (plan AC26, AC40, AC42,
//! AC47).
//!
//! Every test stands up a temporary store and a scripted keychain, runs the
//! same functions `agentctl claude accounts` runs, and then asserts on the
//! filesystem and the registry rather than only on the words printed. That is
//! what lets them prove the negative claims: the lock file survives the
//! command that deletes the namespace it protects, `forget` never issues a
//! keychain read, `remove` refuses a row it does not own.
//!
//! Nothing here reads or writes the process environment. `EnvView::with_home`
//! points discovery at a temporary home, and the keychain arrives as a
//! [`FakeReader`]: `std::env::set_var` is `unsafe` in edition 2024 and would
//! race every other test in the binary.

use std::fs;
use std::sync::Mutex;
use std::time::Duration;

use httpmock::Method::GET;
use httpmock::MockServer;
use serde_json::json;
use tempfile::TempDir;

use super::*;
use crate::config::new_record;
use crate::provider::claude::namespace::export_spelling;
use crate::provider::claude::namespace::sha8;
use crate::secret::fake_reader::FakeReader;

const ACCT: &str = "11111111-2222-3333-4444-555555555555";
const ORG: &str = "66666666-7777-8888-9999-000000000000";
const LIVE_SERVICE: &str = "Claude Code-credentials";
const PROFILE_PATH: &str = "/api/oauth/profile";

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// A temporary store, plus the fake home discovery reads.
struct Store {
    _dir: TempDir,
    home: PathBuf,
    paths: Paths,
    env: EnvView,
    cancel: Cancel,
}

fn store() -> Store {
    let dir = TempDir::new().expect("a temporary directory should be creatable");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("the fake home should be creatable");
    let paths = Paths::with_config_dir(dir.path().join("config"));
    paths.ensure_dirs().expect("the store directories should be creatable");
    let env = EnvView::with_home(home.clone());
    Store { _dir: dir, home, paths, env, cancel: Cancel::new() }
}

impl Store {
    fn accounts(&self) -> Accounts<'_> {
        Accounts { paths: &self.paths, env: &self.env, cancel: &self.cancel }
    }

    fn ctx(&self) -> PassCtx {
        PassCtx::standalone(self.cancel.clone(), Instant::now() + Duration::from_secs(30))
    }

    fn config(&self) -> AgentctlConfig {
        AgentctlConfig::load(&self.paths).expect("the registry should be readable")
    }

    fn ns_dir(&self, org: &str) -> PathBuf {
        self.paths.namespace_dir(ACCT, org)
    }
}

/// What a command printed, so a test can assert on it without capturing stdout.
#[derive(Default)]
struct Recorder {
    lines: Mutex<Vec<String>>,
    /// The answer every [`Prompt::confirm`] gets, or `None` to fail the test
    /// if one is asked at all.
    answer: Option<bool>,
}

impl Recorder {
    fn answering(answer: bool) -> Self {
        Self { lines: Mutex::new(Vec::new()), answer: Some(answer) }
    }

    fn text(&self) -> String {
        self.lines.lock().map(|lines| lines.join("\n")).unwrap_or_default()
    }
}

impl Prompt for Recorder {
    fn tell(&mut self, message: &str) {
        if let Ok(mut lines) = self.lines.lock() {
            lines.push(message.to_owned());
        }
    }

    fn confirm(&mut self, question: &str) -> Result<bool, AppError> {
        self.tell(question);
        match self.answer {
            Some(answer) => Ok(answer),
            None => panic!("this command was not supposed to ask for a confirmation"),
        }
    }
}

/// A prompt that changes the store while its question is on screen.
///
/// The window this exists to reproduce is the one between `relocate`'s
/// pre-lock read and its locks: an HTTP request and then an unbounded wait for
/// a human, during which any other process may do anything at all to the
/// namespace. `confirm` is the honest place to stand in that window, because
/// it *is* that window.
struct RacingPrompt<F: FnMut()> {
    lines: Mutex<Vec<String>>,
    act: F,
    answer: bool,
}

impl<F: FnMut()> RacingPrompt<F> {
    fn answering(answer: bool, act: F) -> Self {
        Self { lines: Mutex::new(Vec::new()), act, answer }
    }

    fn text(&self) -> String {
        self.lines.lock().map(|lines| lines.join("\n")).unwrap_or_default()
    }
}

impl<F: FnMut()> Prompt for RacingPrompt<F> {
    fn tell(&mut self, message: &str) {
        if let Ok(mut lines) = self.lines.lock() {
            lines.push(message.to_owned());
        }
    }

    fn confirm(&mut self, question: &str) -> Result<bool, AppError> {
        self.tell(question);
        (self.act)();
        Ok(self.answer)
    }
}

fn now_millis() -> i64 {
    jiff::Timestamp::now().as_millisecond()
}

/// A credential blob in Claude Code's shape (fact F40).
fn blob(access: &str, org: Option<&str>) -> String {
    let mut account = json!({
        "uuid": ACCT,
        "emailAddress": "owner@example.com",
    });
    if let Some(org) = org {
        account["organizationUuid"] = json!(org);
        account["organizationName"] = json!("Acme");
    }
    json!({
        "claudeAiOauth": {
            "accessToken": access,
            "refreshToken": "sk-ant-ort01-secret",
            "expiresAt": now_millis() + 3_600_000,
            "scopes": ["user:inference", "user:profile"],
            "subscriptionType": "max",
            "tokenAccount": account,
        }
    })
    .to_string()
}

/// Writes a namespace's credential file, creating the directory.
fn write_credential_file(store: &Store, org: &str, blob: &str) -> PathBuf {
    let ns_dir = store.ns_dir(org);
    fs::create_dir_all(&ns_dir).expect("the namespace directory should be creatable");
    let path = ns_dir.join(file_store::CREDENTIALS_FILE);
    fs::write(&path, blob).expect("the credential file should be writable");
    path
}

/// Records one owned account, with the spelling a real login would record.
fn record_owned(store: &Store, org: &str) {
    let spelling = export_spelling(&store.ns_dir(org));
    let mut record = new_record(
        ACCT.to_owned(),
        org.to_owned(),
        AccountKind::Owned { export_sha8: sha8(&spelling), export_spelling: spelling },
    )
    .expect("the fixture identifiers are valid path segments");
    record.email = Some("owner@example.com".to_owned());
    record.org_name = Some("Acme".to_owned());
    AgentctlConfig::update(&store.paths, |config| config.upsert(record))
        .expect("the registry should be writable");
}

/// Records one read-only keychain row, as `import --from keychain` would.
fn record_config_dir(store: &Store, service: &str, shares_live_dir: bool) {
    let mut record = new_record(
        "99999999-8888-7777-6666-555555555555".to_owned(),
        "cccccccc-dddd-eeee-ffff-000000000000".to_owned(),
        AccountKind::ConfigDirReadOnly {
            dir: PathBuf::from("/somewhere/else"),
            service: service.to_owned(),
            shares_live_dir,
        },
    )
    .expect("the fixture identifiers are valid path segments");
    record.email = Some("other@example.com".to_owned());
    AgentctlConfig::update(&store.paths, |config| config.upsert(record))
        .expect("the registry should be writable");
}

/// Records one read-only keychain row that names nobody, exactly as
/// `import --from keychain` writes it.
///
/// The key is the *service name*: the item's blob carried no `tokenAccount`,
/// so there was no account UUID to key it by, and a `ConfigDirReadOnly` record
/// never gets a namespace directory for anything to derive a path from. Built
/// by hand rather than through `new_record` because a service name holds a
/// space and `validate_segment` — rightly — rejects it.
fn record_service_keyed(store: &Store, service: &str) {
    let record = AccountRecord {
        account_uuid: service.to_owned(),
        organization_uuid: UNKNOWN_ORG.to_owned(),
        email: None,
        org_name: None,
        label: None,
        kind: AccountKind::ConfigDirReadOnly {
            dir: PathBuf::from("/elsewhere/.claude"),
            service: service.to_owned(),
            shares_live_dir: false,
        },
        forgotten: false,
        created_at: jiff::Timestamp::now().to_string(),
    };
    AgentctlConfig::update(&store.paths, |config| config.upsert(record))
        .expect("the registry should be writable");
}

/// Every path under the namespace root, sorted.
///
/// The evidence a refused command created nothing and removed nothing: a
/// comparison of the registry bytes alone would miss a namespace directory
/// deleted on the way to the refusal.
fn namespace_root_listing(store: &Store) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![store.paths.namespace_root()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path.clone());
            }
            found.push(path);
        }
    }
    found.sort();
    found
}

/// The keychain service naming the same physical directory as the live store.
fn sibling_service(store: &Store) -> String {
    format!("{LIVE_SERVICE}-{}", sha8(&export_spelling(&store.home.join(".claude"))))
}

/// A keychain no agentctl record claims.
fn unclaimed_service() -> String {
    format!("{LIVE_SERVICE}-6cdd6b98")
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

#[test]
fn list_shows_the_kind_the_source_and_the_export_spelling() {
    let store = store();
    write_credential_file(&store, ORG, &blob("sk-ant-oat01-owned", Some(ORG)));
    record_owned(&store, ORG);

    let mut io = Recorder::default();
    list(&store.accounts(), &FakeReader::unlocked(), &store.ctx(), false, &mut io)
        .expect("listing a healthy store should succeed");
    let text = io.text();

    assert!(text.contains("owner@example.com"), "{text}");
    assert!(text.contains("owned"), "the Kind column names the record kind:\n{text}");
    assert!(text.contains("file"), "the Source column says where it was read:\n{text}");
    assert!(
        text.contains(&export_spelling(&store.ns_dir(ORG))),
        "the Location column carries the export spelling:\n{text}"
    );
    assert!(!text.contains("sk-ant-"), "no token material reaches the listing:\n{text}");
}

#[test]
fn list_hides_siblings_and_forgotten_rows_until_all() {
    // Plan AC42's second half: `accounts list --all` is where a stale sibling
    // and a forgotten service become visible.
    let store = store();
    let sibling = sibling_service(&store);
    let forgotten = unclaimed_service();
    let reader = FakeReader::unlocked()
        .with_item(&sibling, blob("sk-ant-oat01-sibling", Some(ORG)).as_bytes())
        .with_item(&forgotten, blob("sk-ant-oat01-other", Some(ORG)).as_bytes());

    let mut io = Recorder::default();
    forget(&store.accounts(), &forgotten, true, &mut io).expect("forgetting a service works");

    let mut io = Recorder::default();
    list(&store.accounts(), &reader, &store.ctx(), false, &mut io).expect("listing works");
    let default_view = io.text();
    assert!(!default_view.contains(&sibling), "the sibling is hidden:\n{default_view}");
    assert!(!default_view.contains(&forgotten), "the forgotten row is hidden:\n{default_view}");
    assert!(default_view.contains("2 entries hidden (--all)"), "{default_view}");

    let mut io = Recorder::default();
    list(&store.accounts(), &reader, &store.ctx(), true, &mut io).expect("listing works");
    let all = io.text();
    assert!(all.contains(&sibling), "--all shows the sibling:\n{all}");
    assert!(all.contains("stale sibling of live"), "{all}");
    assert!(all.contains(&forgotten), "--all shows the forgotten row:\n{all}");
    assert!(all.contains("forgotten"), "{all}");
    assert!(!all.contains("hidden (--all)"), "--all hides nothing, so no footer:\n{all}");
}

// ---------------------------------------------------------------------------
// show
// ---------------------------------------------------------------------------

#[test]
fn show_reports_the_namespace_without_reporting_a_token() {
    let store = store();
    let blob = blob("sk-ant-oat01-owned", Some(ORG));
    write_credential_file(&store, ORG, &blob);
    record_owned(&store, ORG);
    fs::write(store.ns_dir(ORG).join(file_store::PENDING_FILE), &blob)
        .expect("a pending file should be writable");
    fs::write(
        store.ns_dir(ORG).join(format!("{}.tmp.0123abcd", file_store::CREDENTIALS_FILE)),
        &blob,
    )
    .expect("a stray temporary should be writable");

    // Held so the body names a live process, which is what `doctor` and this
    // command both report.
    let guard = namespace_lock::acquire(
        &store.paths,
        ACCT,
        ORG,
        Instant::now() + Duration::from_secs(5),
        &store.cancel,
        Fault::none(),
    )
    .expect("an uncontended lock should be acquirable");

    let mut io = Recorder::default();
    show(&store.accounts(), &FakeReader::unlocked(), &store.ctx(), ACCT, &mut io)
        .expect("showing a recorded account should succeed");
    drop(guard);
    let text = io.text();

    assert!(text.contains("owner@example.com"), "{text}");
    assert!(text.contains(&store.ns_dir(ORG).display().to_string()), "{text}");
    assert!(text.contains(&store.paths.lock_path(ACCT, ORG).display().to_string()), "{text}");
    assert!(
        text.contains(&format!("pid {} (alive)", std::process::id())),
        "the lock body names its holder:\n{text}"
    );
    assert!(text.contains("access expires"), "{text}");
    assert!(text.contains(".tmp.0123abcd"), "the stray temporary is named:\n{text}");
    assert!(text.contains("pending write"), "{text}");
    assert!(!text.contains("sk-ant-"), "no token material is printed:\n{text}");
}

#[test]
fn show_names_the_unambiguous_spellings_when_an_id_is_ambiguous() {
    let store = store();
    record_owned(&store, ORG);
    record_owned(&store, UNKNOWN_ORG);

    let mut io = Recorder::default();
    let err = show(&store.accounts(), &FakeReader::unlocked(), &store.ctx(), ACCT, &mut io)
        .expect_err("one uuid now names two records");
    let message = err.to_string();
    assert!(message.contains(&format!("{ACCT}/{ORG}")), "{message}");
    assert!(message.contains(&format!("{ACCT}/{UNKNOWN_ORG}")), "{message}");

    // And the spelling the message recommends resolves to exactly one row.
    let mut io = Recorder::default();
    show(
        &store.accounts(),
        &FakeReader::unlocked(),
        &store.ctx(),
        &format!("{ACCT}/{UNKNOWN_ORG}"),
        &mut io,
    )
    .expect("the `<account>/<organization>` spelling is never ambiguous");
    assert!(io.text().contains(UNKNOWN_ORG), "{}", io.text());
}

// ---------------------------------------------------------------------------
// remove — plan AC26, invariant I9
// ---------------------------------------------------------------------------

#[test]
fn remove_without_delete_secret_leaves_the_files() {
    let store = store();
    let path = write_credential_file(&store, ORG, &blob("sk-ant-oat01-owned", Some(ORG)));
    record_owned(&store, ORG);

    let mut io = Recorder::default();
    let removal = Removal { id: ACCT, delete_secret: false, yes: false };
    remove(&store.accounts(), &removal, &mut io).expect("removing a record should succeed");

    assert!(path.exists(), "the credential file survives a record-only removal");
    assert!(store.config().accounts.is_empty(), "the record is gone");
    assert!(io.text().contains("--delete-secret"), "the message says how to finish the job");
}

#[test]
fn remove_with_delete_secret_clears_the_namespace_and_keeps_the_lock() {
    // Plan AC26: the namespace goes, including the pending write and the stray
    // temporary; the lock file stays.
    let store = store();
    let blob = blob("sk-ant-oat01-owned", Some(ORG));
    write_credential_file(&store, ORG, &blob);
    record_owned(&store, ORG);
    let ns_dir = store.ns_dir(ORG);
    fs::write(ns_dir.join(file_store::PENDING_FILE), &blob).expect("writable");
    fs::write(ns_dir.join(file_store::PENDING_META), "{}").expect("writable");
    fs::write(ns_dir.join(format!("{}.tmp.0123abcd", file_store::CREDENTIALS_FILE)), &blob)
        .expect("writable");

    // Taken and released, so the lock file exists before the removal and its
    // survival afterwards is a real assertion.
    let lock_path = {
        let guard = namespace_lock::acquire(
            &store.paths,
            ACCT,
            ORG,
            Instant::now() + Duration::from_secs(5),
            &store.cancel,
            Fault::none(),
        )
        .expect("an uncontended lock should be acquirable");
        guard.path().to_path_buf()
    };

    let mut io = Recorder::answering(true);
    let removal = Removal { id: ACCT, delete_secret: true, yes: false };
    remove(&store.accounts(), &removal, &mut io).expect("the removal should succeed");

    assert!(!ns_dir.exists(), "the namespace directory is gone: {}", ns_dir.display());
    assert!(
        lock_path.exists(),
        "the lock file outlives the namespace it protects (plan section 3.5)"
    );
    assert!(store.config().accounts.is_empty(), "the record is gone");
    assert!(io.text().contains("only copy"), "the risk was stated before the question");
}

#[test]
fn remove_declined_changes_nothing() {
    let store = store();
    let path = write_credential_file(&store, ORG, &blob("sk-ant-oat01-owned", Some(ORG)));
    record_owned(&store, ORG);

    let mut io = Recorder::answering(false);
    let removal = Removal { id: ACCT, delete_secret: true, yes: false };
    let err = remove(&store.accounts(), &removal, &mut io).expect_err("a declined removal fails");

    assert!(err.to_string().contains("cancelled"), "{err}");
    assert!(path.exists(), "the credential file is untouched");
    assert_eq!(store.config().accounts.len(), 1, "the record is untouched");
}

#[test]
fn remove_refuses_a_read_only_row() {
    // Invariant I9. Deleting the record would leave the credential exactly
    // where it is, because agentctl cannot delete a keychain item at all.
    let store = store();
    let service = unclaimed_service();
    record_config_dir(&store, &service, false);

    let mut io = Recorder::default();
    let removal = Removal { id: "other@example.com", delete_secret: false, yes: true };
    let err = remove(&store.accounts(), &removal, &mut io).expect_err("a read-only row is refused");

    let message = err.to_string();
    assert!(message.contains("login keychain"), "{message}");
    assert!(message.contains("accounts forget"), "the refusal names what to do instead");
    assert_eq!(store.config().accounts.len(), 1, "nothing was removed");
}

#[test]
fn remove_refuses_a_stale_sibling() {
    let store = store();
    let service = sibling_service(&store);
    record_config_dir(&store, &service, true);

    let mut io = Recorder::default();
    let removal = Removal { id: "other@example.com", delete_secret: true, yes: true };
    let err = remove(&store.accounts(), &removal, &mut io).expect_err("a sibling row is refused");
    assert!(err.to_string().contains("read-only row"), "{err}");
    assert_eq!(store.config().accounts.len(), 1, "nothing was removed");
}

#[test]
fn remove_waits_for_a_held_lock_and_then_proceeds() {
    // Plan AC26's last clause. A `status` mid-refresh holds this lock, and a
    // removal that ignored it would delete the namespace under a rename.
    let store = store();
    write_credential_file(&store, ORG, &blob("sk-ant-oat01-owned", Some(ORG)));
    record_owned(&store, ORG);
    let ns_dir = store.ns_dir(ORG);

    let held = Duration::from_millis(400);
    let started = Instant::now();
    std::thread::scope(|scope| {
        let paths = &store.paths;
        let holder = scope.spawn(move || {
            let cancel = Cancel::new();
            let guard = namespace_lock::acquire(
                paths,
                ACCT,
                ORG,
                Instant::now() + Duration::from_secs(5),
                &cancel,
                Fault::none(),
            )
            .expect("the holder takes the lock first");
            std::thread::sleep(held);
            drop(guard);
        });

        // Long enough that the holder is certainly in, short enough that the
        // removal still has most of the hold to wait through.
        std::thread::sleep(Duration::from_millis(50));
        let mut io = Recorder::default();
        let removal = Removal { id: ACCT, delete_secret: true, yes: true };
        remove(&store.accounts(), &removal, &mut io).expect("the removal waits, then proceeds");
        holder.join().expect("the holder thread finishes");
    });

    assert!(
        started.elapsed() >= held,
        "the removal waited for the lock rather than proceeding without it"
    );
    assert!(!ns_dir.exists(), "and then did the work");
}

// ---------------------------------------------------------------------------
// relocate — plan AC40
// ---------------------------------------------------------------------------

#[test]
fn relocate_moves_an_unknown_org_namespace_named_by_the_credential() {
    let store = store();
    let blob = blob("sk-ant-oat01-owned", Some(ORG));
    write_credential_file(&store, UNKNOWN_ORG, &blob);
    record_owned(&store, UNKNOWN_ORG);
    let source = store.ns_dir(UNKNOWN_ORG);
    // Invariant I9: a pending write from the old namespace must not survive.
    fs::write(source.join(file_store::PENDING_FILE), &blob).expect("writable");
    fs::write(source.join(file_store::PENDING_META), "{}").expect("writable");

    let mut io = Recorder::answering(true);
    relocate(&store.accounts(), None, ACCT, false, &mut io).expect("the relocation should succeed");

    let target = store.ns_dir(ORG);
    assert!(!source.exists(), "the old namespace is gone");
    assert!(target.join(file_store::CREDENTIALS_FILE).is_file(), "the credential moved");
    assert!(!target.join(file_store::PENDING_FILE).exists(), "the pending write did not travel");

    let config = store.config();
    let record = config.get(ACCT, ORG).expect("the record now names the organization");
    let AccountKind::Owned { export_spelling: spelling, export_sha8 } = &record.kind else {
        panic!("the relocated record is still owned");
    };
    assert_eq!(spelling, &export_spelling(&target), "the spelling follows the namespace");
    assert_eq!(export_sha8, &sha8(spelling));
    assert!(config.get(ACCT, UNKNOWN_ORG).is_none(), "the old record is gone");
}

#[test]
fn relocate_refuses_when_the_target_namespace_exists() {
    // Plan AC40's last clause: the target is never merged into or overwritten.
    let store = store();
    write_credential_file(&store, UNKNOWN_ORG, &blob("sk-ant-oat01-owned", Some(ORG)));
    record_owned(&store, UNKNOWN_ORG);
    let target = store.ns_dir(ORG);
    fs::create_dir_all(&target).expect("the target directory should be creatable");

    let mut io = Recorder::default();
    let err = relocate(&store.accounts(), None, ACCT, true, &mut io)
        .expect_err("an existing target is refused");

    assert!(err.to_string().contains("already exists"), "{err}");
    assert!(
        store.ns_dir(UNKNOWN_ORG).join(file_store::CREDENTIALS_FILE).is_file(),
        "the source is untouched"
    );
    assert!(store.config().get(ACCT, UNKNOWN_ORG).is_some(), "the record is untouched");
}

#[test]
fn relocate_refuses_a_namespace_that_already_names_an_organization() {
    let store = store();
    write_credential_file(&store, ORG, &blob("sk-ant-oat01-owned", Some(ORG)));
    record_owned(&store, ORG);

    let mut io = Recorder::default();
    let err = relocate(&store.accounts(), None, ACCT, true, &mut io)
        .expect_err("only `_unknown-org` namespaces are relocated");
    assert!(err.to_string().contains(UNKNOWN_ORG), "{err}");
}

#[test]
fn relocate_falls_back_to_the_profile_endpoint() {
    // The realistic case: the namespace is `_unknown-org` precisely because
    // nothing named an organization at login, so the blob cannot answer and
    // the profile has to (fact F26).
    let store = store();
    write_credential_file(&store, UNKNOWN_ORG, &blob("sk-ant-oat01-owned", None));
    record_owned(&store, UNKNOWN_ORG);

    let server = MockServer::start();
    let profile = server.mock(|when, then| {
        when.method(GET).path(PROFILE_PATH);
        then.status(200).json_body(json!({
            "account": { "uuid": ACCT, "email_address": "owner@example.com" },
            "organization": { "uuid": ORG, "name": "Acme from the profile" },
        }));
    });
    let client = OauthClient::with_endpoints(
        &server.url("/authorize"),
        &server.url("/token"),
        &server.url(PROFILE_PATH),
        "agentctl/test",
    )
    .expect("the mock endpoints are usable URLs");

    let mut io = Recorder::default();
    relocate(&store.accounts(), Some(&client), ACCT, true, &mut io)
        .expect("the relocation should succeed");

    profile.assert_calls(1);
    let config = store.config();
    let record = config.get(ACCT, ORG).expect("the profile named the organization");
    assert_eq!(record.org_name.as_deref(), Some("Acme from the profile"));
    assert!(store.ns_dir(ORG).join(file_store::CREDENTIALS_FILE).is_file());
}

// ---------------------------------------------------------------------------
// forget / unforget — plan AC47
// ---------------------------------------------------------------------------

#[test]
fn forget_hides_a_service_without_touching_the_keychain() {
    let store = store();
    let service = unclaimed_service();
    let reader = FakeReader::unlocked()
        .with_item(&service, blob("sk-ant-oat01-other", Some(ORG)).as_bytes());

    let mut io = Recorder::default();
    forget(&store.accounts(), &service, true, &mut io).expect("forgetting works");
    assert!(io.text().contains("keychain was not touched"), "{}", io.text());
    assert_eq!(store.config().forgotten_services, vec![service.clone()]);

    let mut io = Recorder::default();
    list(&store.accounts(), &reader, &store.ctx(), false, &mut io).expect("listing works");
    assert!(!io.text().contains(&service), "the row is hidden:\n{}", io.text());

    assert!(
        !reader.reads().contains(&service),
        "a forgotten service is never read from the keychain: {:?}",
        reader.reads()
    );
}

#[test]
fn unforget_reverses_it() {
    let store = store();
    let service = unclaimed_service();
    let reader = FakeReader::unlocked()
        .with_item(&service, blob("sk-ant-oat01-other", Some(ORG)).as_bytes());

    let mut io = Recorder::default();
    forget(&store.accounts(), &service, true, &mut io).expect("forgetting works");
    forget(&store.accounts(), &service, false, &mut io).expect("unforgetting works");
    assert!(store.config().forgotten_services.is_empty());

    let mut io = Recorder::default();
    list(&store.accounts(), &reader, &store.ctx(), false, &mut io).expect("listing works");
    assert!(io.text().contains(&service), "the row is reported again:\n{}", io.text());
}

#[test]
fn forget_flips_the_flag_on_a_recorded_service() {
    // The other shape: a service that already has a registry record carries
    // the flag on the record rather than in the service list.
    let store = store();
    let service = unclaimed_service();
    record_config_dir(&store, &service, false);

    let mut io = Recorder::default();
    forget(&store.accounts(), &service, true, &mut io).expect("forgetting works");
    let config = store.config();
    assert!(config.forgotten_services.is_empty(), "no duplicate bookkeeping");
    assert!(config.accounts[0].forgotten, "the record carries the flag");

    forget(&store.accounts(), &service, false, &mut io).expect("unforgetting works");
    assert!(!store.config().accounts[0].forgotten);
}

#[test]
fn forget_refuses_the_live_service() {
    let store = store();
    let mut io = Recorder::default();
    let err = forget(&store.accounts(), LIVE_SERVICE, true, &mut io)
        .expect_err("hiding the live row is refused");
    assert!(err.to_string().contains("right now"), "{err}");
    assert!(store.config().forgotten_services.is_empty());
}

#[test]
fn forgetting_twice_says_so_rather_than_recording_it_twice() {
    let store = store();
    let service = unclaimed_service();
    let mut io = Recorder::default();
    forget(&store.accounts(), &service, true, &mut io).expect("forgetting works");
    forget(&store.accounts(), &service, true, &mut io).expect("forgetting again is harmless");

    assert_eq!(store.config().forgotten_services.len(), 1, "recorded once");
    assert!(io.text().contains("already hidden"), "{}", io.text());
}

#[test]
fn remove_delete_secret_refuses_a_service_keyed_read_only_record() {
    // The shape `import --from keychain` writes for an item whose blob names
    // nobody: `account_uuid` is the keychain service name and the
    // organization is `_unknown-org`. `--delete-secret` on it must refuse
    // before it goes looking for `claude/<service name>/_unknown-org/`, and
    // must not drop the record either — the credential is in the login
    // keychain, which agentctl never writes (invariant I9, decision D-001).
    let store = store();
    let service = unclaimed_service();
    record_service_keyed(&store, &service);

    let registry = store.paths.config_file();
    let before = fs::read(&registry).expect("the registry should be readable");
    let root_before = namespace_root_listing(&store);

    let mut io = Recorder::default();
    let removal = Removal { id: &service, delete_secret: true, yes: true };
    let err = remove(&store.accounts(), &removal, &mut io)
        .expect_err("a read-only row is refused whatever the flags say");

    let message = err.to_string();
    assert!(
        message.contains("read-only row (kind `config_dir`)"),
        "the refusal names the kind:\n{message}"
    );
    assert!(
        message.contains(&format!("keychain service `{service}`")),
        "and names the item by its service, not as an `<account>/<organization>` pair:\n{message}"
    );
    assert!(message.contains("login keychain"), "and where the credential actually is:\n{message}");
    assert!(message.contains("accounts forget"), "and what to do instead:\n{message}");
    assert_eq!(
        err.exit_code(),
        crate::error::EXIT_FATAL,
        "a command that refused and rendered nothing exits 1"
    );
    assert_eq!(
        fs::read(&registry).expect("the registry should still be readable"),
        before,
        "the registry is byte for byte what it was"
    );
    assert_eq!(
        namespace_root_listing(&store),
        root_before,
        "nothing was created or removed under the namespace root"
    );
    assert!(io.text().is_empty(), "nothing was said before the refusal:\n{}", io.text());
}

#[test]
fn show_names_the_service_and_never_passes_it_off_as_an_account() {
    // The same record, read rather than removed. Its key is a keychain
    // service name, and printing that under a bare `account` label would
    // present it as an Anthropic account UUID — a user would copy it into
    // `--account` believing it identified an account.
    let store = store();
    let service = unclaimed_service();
    record_service_keyed(&store, &service);

    let mut io = Recorder::default();
    show(&store.accounts(), &FakeReader::unlocked(), &store.ctx(), &service, &mut io)
        .expect("a recorded read-only row can be shown");
    let text = io.text();

    assert!(
        text.contains(&format!("service            {service}")),
        "the keychain service has a line of its own:\n{text}"
    );
    assert!(
        !text.contains(&format!("account            {service}")),
        "and is never printed as an account uuid:\n{text}"
    );
    assert!(
        text.contains("keyed by its service name"),
        "the account line says why it is empty:\n{text}"
    );
    assert!(text.contains("kind               config_dir"), "{text}");
}

#[test]
fn show_still_prints_the_account_uuid_of_an_identified_read_only_row() {
    // The counterpart: an item whose blob *did* name an account is keyed by
    // that account, and the `account` line must go on saying so.
    let store = store();
    let service = unclaimed_service();
    record_config_dir(&store, &service, false);

    let mut io = Recorder::default();
    show(&store.accounts(), &FakeReader::unlocked(), &store.ctx(), "other@example.com", &mut io)
        .expect("a recorded read-only row can be shown");
    let text = io.text();

    assert!(
        text.contains("account            99999999-8888-7777-6666-555555555555"),
        "the account uuid is printed as an account uuid:\n{text}"
    );
    assert!(text.contains(&format!("service            {service}")), "{text}");
    assert!(!text.contains("keyed by its service name"), "{text}");
}

#[test]
fn forget_refuses_a_service_that_is_not_agentctls_to_hide() {
    // Plan AC47 hides agentctl's own rows. A `claude-switcher:*` item is not
    // one: it is hidden already, never read (fact F10), and `forgotten_services`
    // is consulted only where an unclaimed `Claude Code-credentials-<sha8>`
    // item is being decided about — so recording one would change nothing
    // while telling the user agentctl had touched another tool's credential.
    let store = store();
    let switcher = format!("{SWITCHER_SERVICE_PREFIX}someone@example.com");

    let mut io = Recorder::default();
    let err = forget(&store.accounts(), &switcher, true, &mut io)
        .expect_err("a foreign service is refused");
    let message = err.to_string();
    assert!(message.contains("belongs to claude-switcher"), "{message}");
    assert!(message.contains("never reads or writes it"), "{message}");
    assert_eq!(
        err.exit_code(),
        crate::error::EXIT_FATAL,
        "a command that refused and rendered nothing exits 1"
    );
    assert!(store.config().forgotten_services.is_empty(), "nothing was recorded");

    // `unforget` is refused for the same reason: there is nothing it could
    // have hidden in the first place.
    let err = forget(&store.accounts(), &switcher, false, &mut io)
        .expect_err("unforgetting a foreign service is refused too");
    assert!(err.to_string().contains("belongs to claude-switcher"), "{err}");

    // And so is a legacy `Claude Code-<sha8>` API-key item, which is not a
    // credentials item either (fact F5).
    let err = forget(&store.accounts(), "Claude Code-6cdd6b98", true, &mut io)
        .expect_err("a legacy API-key item is refused");
    let message = err.to_string();
    assert!(message.contains("is not an item agentctl reports"), "{message}");
    assert_eq!(err.exit_code(), crate::error::EXIT_FATAL);
    assert!(store.config().forgotten_services.is_empty(), "still nothing was recorded");
}

#[test]
fn relocate_aborts_when_the_source_changed_while_the_question_was_on_screen() {
    // The move used to write whatever the pre-lock read saw. A `status
    // --refresh` landing in the window between that read and the locks
    // rotates the refresh token (fact F8) — so the blob the probe holds is
    // superseded, and writing it into the new namespace and then deleting the
    // old one would leave the account with a dead refresh chain and no copy
    // of the live one. Only a fresh login would recover it.
    let store = store();
    let source = store.ns_dir(UNKNOWN_ORG);
    write_credential_file(&store, UNKNOWN_ORG, &blob("sk-ant-oat01-first", Some(ORG)));
    record_owned(&store, UNKNOWN_ORG);

    let rotated = blob("sk-ant-oat01-rotated", Some(ORG));
    let credential = source.join(file_store::CREDENTIALS_FILE);
    let (rotated_for_prompt, path_for_prompt) = (rotated.clone(), credential.clone());
    let mut io = RacingPrompt::answering(true, move || {
        fs::write(&path_for_prompt, &rotated_for_prompt).expect("the refresh should be writable");
    });

    let err = relocate(&store.accounts(), None, ACCT, false, &mut io)
        .expect_err("a namespace that moved under the command is not written over");

    let message = err.to_string();
    assert!(message.contains("changed during relocate"), "{message}");
    assert!(message.contains("re-run"), "the message says what to do next:\n{message}");
    assert_eq!(err.exit_code(), crate::error::EXIT_FATAL, "nothing was rendered, so exit 1");

    assert_eq!(
        fs::read(&credential).expect("the source is still readable"),
        rotated.as_bytes(),
        "the source holds the rotated credential, untouched by the abort"
    );
    assert!(!store.ns_dir(ORG).exists(), "and nothing was written to the target");
    assert!(store.config().get(ACCT, UNKNOWN_ORG).is_some(), "and the record is untouched");
    assert!(io.text().contains("Relocate"), "the question was asked before any of that");
}

#[test]
fn relocate_refuses_a_target_that_appeared_while_the_question_was_on_screen() {
    // Plan AC40, from the other side. The target check moved under the target
    // lock precisely for this: a `login` into the same organization takes only
    // that lock, so a check made before taking it runs against a namespace
    // that does not exist yet — and the move would then overwrite a
    // credential that was minutes old.
    let store = store();
    write_credential_file(&store, UNKNOWN_ORG, &blob("sk-ant-oat01-owned", Some(ORG)));
    record_owned(&store, UNKNOWN_ORG);

    let target = store.ns_dir(ORG);
    let fresh = blob("sk-ant-oat01-just-logged-in", Some(ORG));
    let (target_for_prompt, fresh_for_prompt) = (target.clone(), fresh.clone());
    let mut io = RacingPrompt::answering(true, move || {
        fs::create_dir_all(&target_for_prompt).expect("the login creates its namespace");
        fs::write(target_for_prompt.join(file_store::CREDENTIALS_FILE), &fresh_for_prompt)
            .expect("and writes its credential");
    });

    let err = relocate(&store.accounts(), None, ACCT, false, &mut io)
        .expect_err("an occupied target is refused");

    assert!(err.to_string().contains("already exists"), "{err}");
    assert_eq!(
        fs::read(target.join(file_store::CREDENTIALS_FILE)).expect("readable"),
        fresh.as_bytes(),
        "the credential that landed in the window is untouched"
    );
    assert!(
        store.ns_dir(UNKNOWN_ORG).join(file_store::CREDENTIALS_FILE).is_file(),
        "and so is the source"
    );
    assert!(store.config().get(ACCT, UNKNOWN_ORG).is_some(), "and the record");
}

#[test]
fn relocate_finishes_a_move_that_crashed_after_the_write() {
    // The first crash window. The order under the locks is write the target,
    // update the registry, remove the source; a crash after the write leaves
    // the credential in both places with the registry still naming the old
    // one. Re-running must recognise its own earlier attempt — same digests —
    // and finish, rather than refuse the namespace it created itself.
    let store = store();
    let blob = blob("sk-ant-oat01-owned", Some(ORG));
    write_credential_file(&store, UNKNOWN_ORG, &blob);
    write_credential_file(&store, ORG, &blob);
    record_owned(&store, UNKNOWN_ORG);

    let mut io = Recorder::default();
    relocate(&store.accounts(), None, ACCT, true, &mut io)
        .expect("re-running finishes the interrupted move");

    assert!(!store.ns_dir(UNKNOWN_ORG).exists(), "the source is gone");
    assert!(store.ns_dir(ORG).join(file_store::CREDENTIALS_FILE).is_file(), "the target remains");
    let config = store.config();
    assert!(config.get(ACCT, ORG).is_some(), "and the registry now names the organization");
    assert!(config.get(ACCT, UNKNOWN_ORG).is_none(), "and no longer names the old one");
    assert!(io.text().contains("already in place"), "the message says so:\n{}", io.text());
}

#[test]
fn relocate_waits_for_a_held_lock_and_then_proceeds() {
    // Plan AC26's rule, applied to the other command that mutates a
    // namespace: a `status` mid-refresh holds the source lock, and a
    // relocation that ignored it would copy a credential out from under a
    // rename and then delete the directory being renamed into.
    let store = store();
    write_credential_file(&store, UNKNOWN_ORG, &blob("sk-ant-oat01-owned", Some(ORG)));
    record_owned(&store, UNKNOWN_ORG);

    let held = Duration::from_millis(400);
    let started = Instant::now();
    std::thread::scope(|scope| {
        let paths = &store.paths;
        let holder = scope.spawn(move || {
            let cancel = Cancel::new();
            let guard = namespace_lock::acquire(
                paths,
                ACCT,
                UNKNOWN_ORG,
                Instant::now() + Duration::from_secs(5),
                &cancel,
                Fault::none(),
            )
            .expect("the holder takes the source lock first");
            std::thread::sleep(held);
            drop(guard);
        });

        std::thread::sleep(Duration::from_millis(50));
        let mut io = Recorder::default();
        relocate(&store.accounts(), None, ACCT, true, &mut io)
            .expect("the relocation waits, then proceeds");
        holder.join().expect("the holder thread finishes");
    });

    assert!(started.elapsed() >= held, "the relocation waited for the lock");
    assert!(
        store.ns_dir(ORG).join(file_store::CREDENTIALS_FILE).is_file(),
        "and then did the work"
    );
    assert!(!store.ns_dir(UNKNOWN_ORG).exists());
}
