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
