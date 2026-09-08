//! `doctor`, and the one path in agentctl that deletes a lock (plan AC45,
//! invariant I11).
//!
//! # Why these tests do not take twelve seconds
//!
//! The staleness rule is "two samples at least twelve seconds apart show the
//! same modification time". A test that honoured that literally would add
//! twelve seconds per case and would be skipped or deleted within the month,
//! which is why [`Doctor::sample_interval`] is a field: production passes
//! [`STALE_SAMPLE_INTERVAL`], and these pass milliseconds. What is being
//! tested is the *decision* — same mtime, different mtime, too young, wrong
//! place, wrong name, no `--yes` — and none of that depends on how long the
//! wait was.
//!
//! The age threshold is not faked in the same way: [`STALE_MIN_AGE`] is
//! compared against a real modification time, so the fixtures set that time
//! with `utimensat` rather than waiting a minute for one to arrive.

use std::fs;
use std::sync::Mutex;
use std::time::Duration;

use rustix::fs::AtFlags;
use rustix::fs::Timestamps;
use rustix::fs::utimensat;
use serde_json::json;
use tempfile::TempDir;

use super::*;
use crate::config::new_record;
use crate::provider::claude::namespace::export_spelling;
use crate::provider::claude::namespace::sha8;
use crate::runtime::fault::Fault;
use crate::secret::fake_reader::FakeReader;
use crate::secret::namespace_lock;

const ACCT: &str = "11111111-2222-3333-4444-555555555555";
const ORG: &str = "66666666-7777-8888-9999-000000000000";
const LIVE_SERVICE: &str = "Claude Code-credentials";

/// Short enough that the tests are instant, long enough that a rewrite between
/// the samples has time to land.
const TEST_INTERVAL: Duration = Duration::from_millis(120);

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

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
    fn doctor(&self) -> Doctor<'_> {
        Doctor {
            paths: &self.paths,
            env: &self.env,
            cancel: &self.cancel,
            sample_interval: TEST_INTERVAL,
        }
    }

    fn ctx(&self) -> PassCtx {
        PassCtx::standalone(self.cancel.clone(), Instant::now() + Duration::from_secs(30))
    }

    fn ns_dir(&self, org: &str) -> PathBuf {
        self.paths.namespace_dir(ACCT, org)
    }
}

/// What `doctor` printed.
#[derive(Default)]
struct Recorder {
    lines: Mutex<Vec<String>>,
}

impl Recorder {
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

    fn confirm(&mut self, _question: &str) -> Result<bool, AppError> {
        panic!("`doctor` gates on `--yes`, never on a prompt");
    }
}

fn blob(access: &str, expires_at_ms: i64) -> String {
    json!({
        "claudeAiOauth": {
            "accessToken": access,
            "refreshToken": "sk-ant-ort01-secret",
            "expiresAt": expires_at_ms,
            "refreshTokenExpiresAt": expires_at_ms + 86_400_000,
            "scopes": ["user:inference"],
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

fn write_credential_file(store: &Store, org: &str, blob: &str) -> PathBuf {
    let ns_dir = store.ns_dir(org);
    fs::create_dir_all(&ns_dir).expect("the namespace directory should be creatable");
    let path = ns_dir.join(file_store::CREDENTIALS_FILE);
    fs::write(&path, blob).expect("the credential file should be writable");
    path
}

/// Records one owned account, optionally under a spelling from another store.
fn record_owned(store: &Store, org: &str, spelling: Option<&str>) {
    let spelling = spelling.map_or_else(|| export_spelling(&store.ns_dir(org)), str::to_owned);
    let mut record = new_record(
        ACCT.to_owned(),
        org.to_owned(),
        AccountKind::Owned { export_sha8: sha8(&spelling), export_spelling: spelling },
    )
    .expect("the fixture identifiers are valid path segments");
    record.email = Some("owner@example.com".to_owned());
    AgentctlConfig::update(&store.paths, |config| config.upsert(record))
        .expect("the registry should be writable");
}

/// Backdates a file's modification time by `age`.
///
/// `utimensat` rather than a `sleep`: the rule under test is a sixty-second
/// threshold, and the only alternative to setting the timestamp is waiting a
/// minute for one.
fn backdate(path: &Path, age: Duration) {
    let now = SystemTime::now();
    let target = now.checked_sub(age).expect("the fixture age is within the epoch");
    let since_epoch =
        target.duration_since(SystemTime::UNIX_EPOCH).expect("the fixture time is after 1970");
    let spec = rustix::fs::Timespec {
        tv_sec: i64::try_from(since_epoch.as_secs()).expect("seconds fit in an i64"),
        tv_nsec: i64::from(since_epoch.subsec_nanos()),
    };
    utimensat(
        rustix::fs::CWD,
        path,
        &Timestamps { last_access: spec, last_modification: spec },
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .expect("the fixture's timestamp should be settable");
}

/// Plants a Claude Code refresh lock in a namespace, aged `age`.
fn plant_artefact(store: &Store, org: &str, name: &str, age: Duration) -> PathBuf {
    let ns_dir = store.ns_dir(org);
    fs::create_dir_all(&ns_dir).expect("the namespace directory should be creatable");
    let path = ns_dir.join(name);
    fs::write(&path, "{\"pid\":424242}").expect("the artefact should be writable");
    backdate(&path, age);
    path
}

// ---------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------

#[test]
fn the_report_covers_the_store_the_keychain_and_the_accounts() {
    let store = store();
    write_credential_file(&store, ORG, &blob("sk-ant-oat01-owned", now_ms() + 3_600_000));
    record_owned(&store, ORG, None);

    let mut io = Recorder::default();
    report(&store.doctor(), &FakeReader::unlocked(), &store.ctx(), &mut io)
        .expect("a healthy store reports cleanly");
    let text = io.text();

    assert!(text.contains(&store.paths.config_dir().display().to_string()), "{text}");
    assert!(text.contains("preflight        unlocked"), "{text}");
    assert!(text.contains("live service     Claude Code-credentials"), "{text}");
    assert!(text.contains("owner@example.com"), "{text}");
    assert!(text.contains("access in "), "the expiries are reported:\n{text}");
    assert!(text.contains("refresh in "), "both of them:\n{text}");
    assert!(text.contains("no Claude Code lock artefacts"), "{text}");
    assert!(!text.contains("sk-ant-"), "no token material is printed:\n{text}");
}

#[test]
fn the_report_names_the_lock_holder_and_whether_it_is_alive() {
    // Plan AC45's lock-body clause, and AC48(c)'s payoff: the body carries a
    // pid and a start time, and this is what reads them.
    let store = store();
    record_owned(&store, ORG, None);
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
    report(&store.doctor(), &FakeReader::unlocked(), &store.ctx(), &mut io)
        .expect("the report should succeed");
    drop(guard);
    let text = io.text();

    assert!(text.contains("namespace locks"), "{text}");
    assert!(
        text.contains(&format!("pid {} (alive)", std::process::id())),
        "the holder is this very process:\n{text}"
    );
}

#[test]
fn the_report_names_a_recycled_pid_rather_than_the_process_now_using_it() {
    // The reason the body carries a start time at all: pid 1 exists on every
    // machine, and reporting it as the holder of a namespace lock would send
    // the user after `launchd`.
    let store = store();
    record_owned(&store, ORG, None);
    let lock_path = store.paths.lock_path(ACCT, ORG);
    fs::write(
        &lock_path,
        json!({ "pid": 1, "pid_start_time": "a time pid 1 certainly did not start at",
                "acquired_at": "2026-09-09T12:00:00Z" })
        .to_string(),
    )
    .expect("the lock body should be writable");

    let mut io = Recorder::default();
    report(&store.doctor(), &FakeReader::unlocked(), &store.ctx(), &mut io)
        .expect("the report should succeed");
    assert!(io.text().contains("pid 1 (dead (pid recycled))"), "{}", io.text());
}

#[test]
fn the_report_lists_pending_writes_and_stray_temporaries() {
    let store = store();
    let blob = blob("sk-ant-oat01-owned", now_ms() + 3_600_000);
    write_credential_file(&store, ORG, &blob);
    record_owned(&store, ORG, None);
    let ns_dir = store.ns_dir(ORG);
    fs::write(ns_dir.join(file_store::PENDING_FILE), &blob).expect("writable");
    fs::write(ns_dir.join(file_store::PENDING_META), "{}").expect("writable");
    fs::write(ns_dir.join(format!("{}.tmp.0123abcd", file_store::CREDENTIALS_FILE)), &blob)
        .expect("writable");

    let mut io = Recorder::default();
    report(&store.doctor(), &FakeReader::unlocked(), &store.ctx(), &mut io)
        .expect("the report should succeed");
    let text = io.text();

    assert!(text.contains("pending write"), "{text}");
    assert!(text.contains("pending meta"), "{text}");
    assert!(text.contains(".tmp.0123abcd"), "{text}");
    assert!(text.contains("token material at rest"), "the stray file's risk is stated:\n{text}");
}

#[test]
fn the_report_samples_an_artefact_twice_and_offers_the_removal() {
    let store = store();
    record_owned(&store, ORG, None);
    let artefact = plant_artefact(&store, ORG, REFRESH_LOCK, Duration::from_secs(120));

    let mut io = Recorder::default();
    report(&store.doctor(), &FakeReader::unlocked(), &store.ctx(), &mut io)
        .expect("the report should succeed");
    let text = io.text();

    assert!(text.contains("sampling again in 0s"), "the wait is announced:\n{text}");
    assert!(text.contains("holder not beating"), "{text}");
    assert!(
        text.contains(&format!("--remove-stale {} --yes", artefact.display())),
        "the report names the exact command:\n{text}"
    );
}

#[test]
fn the_report_flags_siblings_forgotten_rows_duplicates_and_unknown_orgs() {
    let store = store();
    // Two keychain items holding one credential, plus a sibling of the live
    // directory: the duplicate check folds by digest, never by path.
    let shared = blob("sk-ant-oat01-shared", now_ms() + 3_600_000);
    let sibling = format!("{LIVE_SERVICE}-{}", sha8(&export_spelling(&store.home.join(".claude"))));
    let first = format!("{LIVE_SERVICE}-6cdd6b98");
    let second = format!("{LIVE_SERVICE}-7dee7ca9");
    let forgotten = format!("{LIVE_SERVICE}-8eff8dba");
    let reader = FakeReader::unlocked()
        .with_item(&sibling, blob("sk-ant-oat01-sibling", now_ms() + 3_600_000).as_bytes())
        .with_item(&first, shared.as_bytes())
        .with_item(&second, shared.as_bytes());

    AgentctlConfig::update(&store.paths, |config| {
        config.forgotten_services.push(forgotten.clone());
    })
    .expect("the registry should be writable");
    write_credential_file(&store, UNKNOWN_ORG, &blob("sk-ant-oat01-owned", now_ms() + 3_600_000));
    record_owned(&store, UNKNOWN_ORG, None);

    let mut io = Recorder::default();
    report(&store.doctor(), &reader, &store.ctx(), &mut io).expect("the report should succeed");
    let text = io.text();

    assert!(text.contains("names the same directory as the live credential"), "{text}");
    assert!(text.contains("hold the same access token"), "the duplicate is named:\n{text}");
    assert!(
        text.contains(&format!("accounts relocate {ACCT}")),
        "the `_unknown-org` namespace is named:\n{text}"
    );
    assert!(
        text.contains(&format!("{forgotten}  is on the forgotten list")),
        "a forgotten service that has left the keychain is reported:\n{text}"
    );
}

#[test]
fn the_report_flags_a_record_written_by_another_store() {
    // Risk R25: two stores holding one refresh chain. The evidence available
    // locally is the recorded spelling, which is not the one this store uses.
    let store = store();
    write_credential_file(&store, ORG, &blob("sk-ant-oat01-owned", now_ms() + 3_600_000));
    record_owned(&store, ORG, Some("/somewhere/else/claude/acct/org"));

    let mut io = Recorder::default();
    report(&store.doctor(), &FakeReader::unlocked(), &store.ctx(), &mut io)
        .expect("the report should succeed");
    assert!(io.text().contains("risk R25"), "{}", io.text());
}

#[test]
fn the_report_flags_a_namespace_a_session_has_migrated() {
    let store = store();
    record_owned(&store, ORG, None);
    let migrated = format!("{LIVE_SERVICE}-{}", sha8(&export_spelling(&store.ns_dir(ORG))));
    let reader = FakeReader::unlocked()
        .with_item(&migrated, blob("sk-ant-oat01-migrated", now_ms() + 3_600_000).as_bytes());

    let mut io = Recorder::default();
    report(&store.doctor(), &reader, &store.ctx(), &mut io).expect("the report should succeed");
    assert!(io.text().contains("has migrated it"), "{}", io.text());
}

// ---------------------------------------------------------------------------
// --remove-stale — the accept case
// ---------------------------------------------------------------------------

#[test]
fn remove_stale_removes_a_lapsed_artefact_after_stating_the_risk() {
    let store = store();
    record_owned(&store, ORG, None);
    let artefact = plant_artefact(&store, ORG, REFRESH_LOCK, Duration::from_secs(120));

    let mut io = Recorder::default();
    remove_stale(&store.doctor(), &artefact, true, &mut io).expect("a lapsed artefact is removed");

    assert!(!artefact.exists(), "the artefact is gone");
    let text = io.text();
    assert!(text.contains("This is Claude Code's lock, not agentctl's"), "{text}");
    assert!(text.contains("a login lost"), "the risk is stated in full:\n{text}");
    assert!(
        text.find("About to remove").unwrap_or(usize::MAX) < text.find("Removed `").unwrap_or(0),
        "the risk is stated before the removal, not after:\n{text}"
    );
}

#[test]
fn remove_stale_accepts_the_storage_write_guard_and_the_legacy_lock() {
    let store = store();
    record_owned(&store, ORG, None);

    let storage = plant_artefact(&store, ORG, STORAGE_WRITE_LOCK, Duration::from_secs(120));
    let mut io = Recorder::default();
    remove_stale(&store.doctor(), &storage, true, &mut io)
        .expect("`.storage-write` is an artefact");
    assert!(!storage.exists());

    // The legacy lock sits beside the namespace, named after it (fact F17).
    let legacy = store.paths.namespace_dir(ACCT, "").parent().map(|dir| dir.join("org.lock"));
    let legacy = legacy.expect("the namespace has a parent inside the store");
    fs::write(&legacy, "{}").expect("the legacy lock should be writable");
    backdate(&legacy, Duration::from_secs(120));
    let mut io = Recorder::default();
    remove_stale(&store.doctor(), &legacy, true, &mut io).expect("a legacy `.lock` is an artefact");
    assert!(!legacy.exists());
}

// ---------------------------------------------------------------------------
// --remove-stale — the refusal matrix (invariant I11)
// ---------------------------------------------------------------------------

#[test]
fn remove_stale_refuses_an_artefact_younger_than_the_threshold() {
    let store = store();
    record_owned(&store, ORG, None);
    let artefact = plant_artefact(&store, ORG, REFRESH_LOCK, Duration::from_secs(5));

    let mut io = Recorder::default();
    let err = remove_stale(&store.doctor(), &artefact, true, &mut io)
        .expect_err("a fresh artefact is refused");

    assert!(err.to_string().contains("staleness threshold"), "{err}");
    assert!(artefact.exists(), "and is still there");
}

#[test]
fn remove_stale_refuses_an_artefact_whose_holder_is_still_beating() {
    // The two-sample rule (fact F36): a modification time that moves between
    // the samples is a heartbeat, whatever the age said.
    let store = store();
    record_owned(&store, ORG, None);
    let artefact = plant_artefact(&store, ORG, REFRESH_LOCK, Duration::from_secs(120));

    let beating = artefact.clone();
    std::thread::scope(|scope| {
        scope.spawn(move || {
            std::thread::sleep(TEST_INTERVAL / 3);
            fs::write(&beating, "{\"pid\":424242,\"beat\":2}")
                .expect("the heartbeat should be writable");
        });
        let mut io = Recorder::default();
        let err = remove_stale(&store.doctor(), &artefact, true, &mut io)
            .expect_err("a beating holder is refused");
        assert!(err.to_string().contains("rewritten between the two samples"), "{err}");
    });

    assert!(artefact.exists(), "the artefact survives");
}

#[test]
fn remove_stale_refuses_without_yes() {
    let store = store();
    record_owned(&store, ORG, None);
    let artefact = plant_artefact(&store, ORG, REFRESH_LOCK, Duration::from_secs(120));

    let mut io = Recorder::default();
    let err =
        remove_stale(&store.doctor(), &artefact, false, &mut io).expect_err("`--yes` is required");

    assert!(err.to_string().contains("`--yes` is required"), "{err}");
    assert!(artefact.exists());
    assert!(
        io.text().contains("About to remove"),
        "the risk is still stated, so the user knows what `--yes` would agree to"
    );
}

#[test]
fn remove_stale_refuses_a_path_outside_the_namespace_root() {
    let store = store();
    let outside = store.home.join(".claude").join(REFRESH_LOCK);
    fs::create_dir_all(store.home.join(".claude")).expect("creatable");
    fs::write(&outside, "{}").expect("writable");
    backdate(&outside, Duration::from_secs(120));

    let mut io = Recorder::default();
    let err = remove_stale(&store.doctor(), &outside, true, &mut io)
        .expect_err("the live store is not agentctl's to tidy");

    assert!(err.to_string().contains("not inside"), "{err}");
    assert!(outside.exists(), "the live store's lock is untouched");
}

#[test]
fn remove_stale_refuses_a_name_that_is_not_an_artefact() {
    let store = store();
    record_owned(&store, ORG, None);
    let credentials =
        write_credential_file(&store, ORG, &blob("sk-ant-oat01-owned", now_ms() + 3_600_000));
    backdate(&credentials, Duration::from_secs(120));

    let mut io = Recorder::default();
    let err = remove_stale(&store.doctor(), &credentials, true, &mut io)
        .expect_err("only the three artefact names are removable");

    assert!(err.to_string().contains("not a Claude Code lock artefact"), "{err}");
    assert!(credentials.exists(), "the credential file is untouched");
}

#[test]
fn remove_stale_refuses_agentctls_own_namespace_lock() {
    // The lock file is never unlinked by anything, including this: `flock`
    // locks an inode, and a recreated lock file is a second inode.
    let store = store();
    record_owned(&store, ORG, None);
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
    backdate(&lock_path, Duration::from_secs(120));

    let mut io = Recorder::default();
    let err = remove_stale(&store.doctor(), &lock_path, true, &mut io)
        .expect_err("agentctl's own locks are not removable");

    assert!(err.to_string().contains("never unlinked"), "{err}");
    assert!(lock_path.exists());
}

#[test]
fn remove_stale_refuses_a_symbolic_link() {
    let store = store();
    record_owned(&store, ORG, None);
    let target = plant_artefact(&store, ORG, "target.lock", Duration::from_secs(120));
    let link = store.ns_dir(ORG).join(REFRESH_LOCK);
    std::os::unix::fs::symlink(&target, &link).expect("a symbolic link should be creatable");

    let mut io = Recorder::default();
    let err = remove_stale(&store.doctor(), &link, true, &mut io)
        .expect_err("agentctl never deletes through a link");

    assert!(err.to_string().contains("symbolic link"), "{err}");
    assert!(fs::symlink_metadata(&link).is_ok(), "the link is still there");
    assert!(target.exists(), "and so is what it pointed at");
}

#[test]
fn remove_stale_refuses_a_directory() {
    let store = store();
    record_owned(&store, ORG, None);
    let dir = store.ns_dir(ORG).join(REFRESH_LOCK);
    fs::create_dir_all(&dir).expect("a directory should be creatable");

    let mut io = Recorder::default();
    let err =
        remove_stale(&store.doctor(), &dir, true, &mut io).expect_err("a directory is refused");
    assert!(err.to_string().contains("not a regular file"), "{err}");
    assert!(dir.exists());
}

#[test]
fn remove_stale_refuses_something_that_is_not_there() {
    let store = store();
    let absent = store.ns_dir(ORG).join(REFRESH_LOCK);

    let mut io = Recorder::default();
    let err = remove_stale(&store.doctor(), &absent, true, &mut io)
        .expect_err("nothing to remove is still a refusal, not a success");
    assert!(err.to_string().contains("cannot be examined"), "{err}");
}

#[test]
fn a_bare_dot_lock_is_not_a_legacy_lock_name() {
    // `<namespace>.lock` has a namespace in front of it; a file called exactly
    // `.lock` is something else, and something else is not removable.
    assert!(is_artefact_name(Path::new("/store/claude/acct/org.lock")));
    assert!(is_artefact_name(Path::new("/store/claude/acct/org/.oauth_refresh.lock")));
    assert!(is_artefact_name(Path::new("/store/claude/acct/org/.storage-write")));
    assert!(!is_artefact_name(Path::new("/store/claude/acct/org/.lock")));
    assert!(!is_artefact_name(Path::new("/store/claude/acct/org/.credentials.json")));
    assert!(!is_artefact_name(Path::new("/store/claude")));
}

/// Now, in milliseconds since the epoch.
fn now_ms() -> i64 {
    jiff::Timestamp::now().as_millisecond()
}
