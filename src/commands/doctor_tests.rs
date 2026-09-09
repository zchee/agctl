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

    fn session_dir(&self, org: &str) -> PathBuf {
        self.paths.session_dir(ACCT, org)
    }

    fn live_dir(&self) -> PathBuf {
        self.home.join(".claude")
    }
}

/// Places a symlink, panicking with a message that names both paths on
/// failure.
fn symlink(target: &Path, link: &Path) {
    std::os::unix::fs::symlink(target, link).unwrap_or_else(|err| {
        panic!("`{}` -> `{}` should be creatable: {err}", link.display(), target.display())
    });
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

#[test]
fn the_report_lists_foreign_items_and_says_they_are_never_read() {
    // A `claude-switcher:*` item (fact F10) and `CLAUDE_CODE_OAUTH_TOKEN`
    // (fact F19). Both exist on real machines, neither is agentctl's, and a
    // user comparing `security dump-keychain` against this report should not
    // have to guess whether agentctl is quietly using them.
    let store = store();
    let switcher = format!("{}someone@example.com", crate::secret::SWITCHER_SERVICE_PREFIX);
    let reader = FakeReader::unlocked().with_entry(&switcher);
    let env = EnvView { oauth_token_set: true, ..store.env.clone() };
    let doctor = Doctor {
        paths: &store.paths,
        env: &env,
        cancel: &store.cancel,
        sample_interval: TEST_INTERVAL,
    };

    let mut io = Recorder::default();
    report(&doctor, &reader, &store.ctx(), &mut io).expect("the report should succeed");
    let text = io.text();

    assert!(text.contains("foreign items (never read)"), "{text}");
    assert!(text.contains(&switcher), "the switcher item is named:\n{text}");
    assert!(text.contains("belongs to claude-switcher"), "{text}");
    assert!(text.contains("CLAUDE_CODE_OAUTH_TOKEN"), "the environment token is named:\n{text}");
    assert!(text.contains("short-circuits every credential store"), "{text}");
    assert!(
        !reader.reads().contains(&switcher),
        "a foreign item is listed, never read: {:?}",
        reader.reads()
    );
}

#[test]
fn the_foreign_section_says_none_when_there_is_nothing_foreign() {
    // The section is always present, so its absence is never mistaken for
    // "agentctl did not look".
    let store = store();
    let mut io = Recorder::default();
    report(&store.doctor(), &FakeReader::unlocked(), &store.ctx(), &mut io)
        .expect("the report should succeed");
    let text = io.text();

    assert!(text.contains("foreign items (never read)"), "{text}");
    assert!(text.contains("foreign items (never read)\n  none"), "{text}");
}

// ---------------------------------------------------------------------------
// --remove-stale and symbolic links on the way to the artefact
// ---------------------------------------------------------------------------

/// Plants a real refresh lock outside the store, aged past the threshold.
///
/// This stands in for `~/.claude/.oauth_refresh.lock` — the file a live Claude
/// Code session is holding, and the one invariant I11 exists to protect.
fn plant_outside(at: &Path) -> PathBuf {
    fs::create_dir_all(at).expect("the outside directory should be creatable");
    let path = at.join(REFRESH_LOCK);
    fs::write(&path, "{\"pid\":424242}").expect("the artefact should be writable");
    backdate(&path, Duration::from_secs(120));
    path
}

#[test]
fn remove_stale_refuses_a_symlinked_organization_component() {
    // `<root>/<acct>/<org>/.oauth_refresh.lock` spells a location under the
    // namespace root and passes every lexical check, while `<org>` is a link
    // to somebody else's directory. The final component is a real file, so the
    // `lstat` sees nothing wrong either — only walking the chain with
    // `O_NOFOLLOW` catches it.
    let store = store();
    let victim = plant_outside(&store.home.join(".claude"));

    let acct_dir = store.paths.namespace_root().join(ACCT);
    fs::create_dir_all(&acct_dir).expect("the account directory should be creatable");
    std::os::unix::fs::symlink(store.home.join(".claude"), acct_dir.join(ORG))
        .expect("the link should be creatable");

    let path = store.ns_dir(ORG).join(REFRESH_LOCK);
    let mut io = Recorder::default();
    let err = remove_stale(&store.doctor(), &path, true, &mut io)
        .expect_err("a symlinked namespace component is refused");

    assert!(err.to_string().contains("symbolic link"), "{err}");
    assert_eq!(err.exit_code(), crate::error::EXIT_FATAL, "nothing was removed, so exit 1");
    assert!(victim.exists(), "the live session's lock is untouched: {}", victim.display());
}

#[test]
fn remove_stale_refuses_a_symlinked_account_component() {
    // The same attack one level up: `<acct>` is the link, so the artefact's
    // whole parent chain is somebody else's.
    let store = store();
    let elsewhere = store.home.join("elsewhere");
    let victim = plant_outside(&elsewhere.join(ORG));

    fs::create_dir_all(store.paths.namespace_root()).expect("the root should be creatable");
    std::os::unix::fs::symlink(&elsewhere, store.paths.namespace_root().join(ACCT))
        .expect("the link should be creatable");

    let path = store.ns_dir(ORG).join(REFRESH_LOCK);
    let mut io = Recorder::default();
    let err = remove_stale(&store.doctor(), &path, true, &mut io)
        .expect_err("a symlinked account component is refused");

    assert!(err.to_string().contains("symbolic link"), "{err}");
    assert!(victim.exists(), "the file the link pointed at is untouched");
}

#[test]
fn the_report_prints_a_legacy_lock_command_that_remove_stale_accepts() {
    // The legacy lock is named after the *resolved* namespace (fact F17), and
    // on macOS a temporary directory resolves through `/private` — so the
    // canonical spelling does not begin with the namespace root as `Paths`
    // spells it, and printing it produced a `--remove-stale` command this very
    // build refused. The store here is deliberately reached through a symbolic
    // link so the two spellings differ.
    let dir = TempDir::new().expect("a temporary directory should be creatable");
    let real = dir.path().join("real-config");
    fs::create_dir_all(&real).expect("creatable");
    let linked = dir.path().join("config-link");
    std::os::unix::fs::symlink(&real, &linked).expect("the link should be creatable");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("creatable");

    let paths = Paths::with_config_dir(linked);
    paths.ensure_dirs().expect("the store directories should be creatable");
    let store = Store {
        _dir: dir,
        home: home.clone(),
        paths,
        env: EnvView::with_home(home),
        cancel: Cancel::new(),
    };
    record_owned(&store, ORG, None);
    let ns_dir = store.ns_dir(ORG);
    fs::create_dir_all(&ns_dir).expect("the namespace should be creatable");

    // Written where Claude Code would write it: beside the *resolved*
    // directory.
    let canonical = namespace::canonical(&ns_dir).expect("the namespace resolves");
    let mut legacy = canonical.clone().into_os_string();
    legacy.push(LEGACY_LOCK_SUFFIX);
    let legacy = PathBuf::from(legacy);
    fs::write(&legacy, "{\"pid\":424242}").expect("writable");
    backdate(&legacy, Duration::from_secs(120));
    assert_ne!(canonical, ns_dir, "the fixture is only meaningful if the spellings differ");

    let mut io = Recorder::default();
    report(&store.doctor(), &FakeReader::unlocked(), &store.ctx(), &mut io)
        .expect("the report should succeed");
    let text = io.text();

    let printed = text
        .split_once("--remove-stale ")
        .and_then(|(_, rest)| rest.split_once(" --yes"))
        .map(|(path, _)| PathBuf::from(path))
        .unwrap_or_else(|| panic!("the report offers a removal:\n{text}"));
    assert!(
        printed.starts_with(store.paths.namespace_root()),
        "the printed path is the one the store spells, not the resolved one: {}",
        printed.display()
    );

    // Taken verbatim, as a user would paste it.
    let mut io = Recorder::default();
    remove_stale(&store.doctor(), &printed, true, &mut io)
        .expect("the command the report printed is the command the build accepts");
    assert!(!legacy.exists(), "and it removed the artefact: {}", legacy.display());
}

#[test]
fn the_report_hides_forgotten_services_behind_one_line() {
    // Plan AC47: `accounts forget` means `doctor` stops reporting the service.
    // A count stands in for it, so a user who forgot something and then went
    // looking for it is told it is hidden rather than left to conclude the
    // item is gone.
    let store = store();
    let forgotten = format!("{LIVE_SERVICE}-6cdd6b98");
    let reader = FakeReader::unlocked()
        .with_item(&forgotten, blob("sk-ant-oat01-other", now_ms() + 3_600_000).as_bytes());
    AgentctlConfig::update(&store.paths, |config| {
        config.forgotten_services.push(forgotten.clone());
    })
    .expect("the registry should be writable");

    let mut io = Recorder::default();
    report(&store.doctor(), &reader, &store.ctx(), &mut io).expect("the report should succeed");
    let text = io.text();

    assert!(!text.contains(&forgotten), "the hidden service is named nowhere:\n{text}");
    assert!(text.contains("1 forgotten service(s) hidden"), "{text}");
    assert!(text.contains("accounts list --all"), "and says where to see it:\n{text}");
    assert!(
        !reader.reads().contains(&forgotten),
        "and it was never read from the keychain: {:?}",
        reader.reads()
    );
}

#[test]
fn the_report_does_not_offer_relocate_for_a_row_that_cannot_be_relocated() {
    // A record `import --from keychain` wrote for an item that named nobody is
    // keyed by its service name and its organization is `_unknown-org` — so it
    // matched the `_unknown-org` rule and drew a suggestion `relocate` refuses
    // outright, spelled `accounts relocate Claude Code-credentials-…`.
    let store = store();
    let service = format!("{LIVE_SERVICE}-6cdd6b98");
    let record = AccountRecord {
        account_uuid: service.clone(),
        organization_uuid: UNKNOWN_ORG.to_owned(),
        email: None,
        org_name: None,
        label: None,
        kind: AccountKind::ConfigDirReadOnly {
            dir: PathBuf::from("/elsewhere/.claude"),
            service: service.clone(),
            shares_live_dir: false,
        },
        forgotten: false,
        created_at: jiff::Timestamp::now().to_string(),
    };
    AgentctlConfig::update(&store.paths, |config| config.upsert(record))
        .expect("the registry should be writable");

    let mut io = Recorder::default();
    report(&store.doctor(), &FakeReader::unlocked(), &store.ctx(), &mut io)
        .expect("the report should succeed");
    let text = io.text();

    assert!(!text.contains("accounts relocate"), "advice that cannot be taken:\n{text}");

    // And the owned case still gets it.
    record_owned(&store, UNKNOWN_ORG, None);
    let mut io = Recorder::default();
    report(&store.doctor(), &FakeReader::unlocked(), &store.ctx(), &mut io)
        .expect("the report should succeed");
    assert!(io.text().contains(&format!("accounts relocate {ACCT}")), "{}", io.text());
}

// ---------------------------------------------------------------------------
// Isolation (plan AC58)
// ---------------------------------------------------------------------------

#[test]
fn link_entry_reports_every_state() {
    let store = store();
    let live = store.live_dir();
    fs::create_dir_all(&live).expect("the live config dir should be creatable");
    let session_dir = store.session_dir(ORG);
    fs::create_dir_all(&session_dir).expect("the session directory should be creatable");

    // linked: a symlink whose fully resolved target is the expected live path.
    let live_settings = live.join("settings.json");
    fs::write(&live_settings, "{}").expect("the live settings file should be writable");
    symlink(&live_settings, &session_dir.join("settings.json"));

    // occupied (not a symlink at all): something else was written there.
    fs::write(session_dir.join("CLAUDE.md"), "not agentctl's")
        .expect("the file should be writable");

    // absent: nothing there — `skills` is never created.

    // missing-target: a symlink whose target does not exist.
    symlink(&live.join("projects"), &session_dir.join("projects"));

    // occupied (a symlink, but to the wrong place): points at something real,
    // just not what agentctl would have placed.
    let elsewhere = store.home.join("elsewhere");
    fs::create_dir_all(&elsewhere).expect("the decoy directory should be creatable");
    symlink(&elsewhere, &session_dir.join("shell-snapshots"));

    let settings = link_entry(&session_dir, "settings.json", "tier1", &live_settings);
    assert_eq!(settings.state, "linked");
    assert_eq!(settings.target.as_deref(), Some(live_settings.to_string_lossy().as_ref()));

    let claude_md = link_entry(&session_dir, "CLAUDE.md", "tier1", &live.join("CLAUDE.md"));
    assert_eq!(claude_md.state, "occupied");
    assert!(claude_md.target.is_none(), "a plain file carries no symlink target");

    let skills = link_entry(&session_dir, "skills", "tier1", &live.join("skills"));
    assert_eq!(skills.state, "absent");

    let projects = link_entry(&session_dir, "projects", "tier2", &live.join("projects"));
    assert_eq!(projects.state, "missing-target");
    assert!(projects.target.is_some(), "a dangling symlink still reports its raw target");

    let snapshots =
        link_entry(&session_dir, "shell-snapshots", "tier2", &live.join("shell-snapshots"));
    assert_eq!(snapshots.state, "occupied");
    assert!(snapshots.target.is_some(), "a symlink to the wrong place still reports its target");

    // The seed row (`.claude.json`) carries its own, disjoint vocabulary:
    // `seeded` | `occupied` | `absent` — never the symlink states above.
    let seed_absent = seed_link_entry(&session_dir);
    assert_eq!(seed_absent.state, "absent");
    assert_eq!(seed_absent.tier, "seed");
    assert!(seed_absent.target.is_none());

    fs::write(session_dir.join(".claude.json"), "{}").expect("the seed file should be writable");
    let seed_seeded = seed_link_entry(&session_dir);
    assert_eq!(seed_seeded.state, "seeded");

    fs::remove_file(session_dir.join(".claude.json")).expect("the seed file should be removable");
    symlink(&live_settings, &session_dir.join(".claude.json"));
    let seed_occupied = seed_link_entry(&session_dir);
    assert_eq!(seed_occupied.state, "occupied", "a symlink at the seed path is never `seeded`");
}

#[test]
fn seed_keys_reports_the_seeded_set_and_flags_a_leaked_key() {
    let store = store();
    let session_dir = store.session_dir(ORG);
    fs::create_dir_all(&session_dir).expect("the session directory should be creatable");
    fs::write(
        session_dir.join(".claude.json"),
        json!({
            "hasCompletedOnboarding": true,
            "theme": "dark",
            "oauthAccount": {"uuid": "leaked"},
        })
        .to_string(),
    )
    .expect("the seed fixture should be writable");

    let (seeded, leaked) = seed_keys(&session_dir);
    assert_eq!(
        seeded,
        vec!["hasCompletedOnboarding".to_owned(), "oauthAccount".to_owned(), "theme".to_owned()]
    );
    assert_eq!(leaked, vec!["oauthAccount".to_owned()], "oauthAccount is on the never-seed list");
}

#[test]
fn seed_keys_is_empty_when_the_session_was_never_seeded() {
    let store = store();
    let session_dir = store.session_dir(ORG);
    fs::create_dir_all(&session_dir).expect("the session directory should be creatable");

    let (seeded, leaked) = seed_keys(&session_dir);
    assert!(seeded.is_empty());
    assert!(leaked.is_empty());
}

#[test]
fn unexposed_entries_lists_whatever_is_on_neither_allowlist() {
    let store = store();
    let live = store.live_dir();
    fs::create_dir_all(live.join("skills")).expect("a tier1 dir should be creatable");
    fs::create_dir_all(live.join("projects")).expect("a tier2 dir should be creatable");
    fs::create_dir_all(live.join("backups")).expect("an unlisted dir should be creatable");
    fs::create_dir_all(live.join("cache")).expect("an unlisted dir should be creatable");
    fs::write(live.join("settings.json"), "{}").expect("a tier1 file should be writable");
    fs::write(live.join("history.jsonl"), "{}").expect("the never-linked file should be writable");

    let unexposed = unexposed_entries(&live);
    assert_eq!(unexposed, vec!["backups".to_owned(), "cache".to_owned()]);
}

#[test]
fn unexposed_entries_is_empty_when_the_live_dir_does_not_exist() {
    let store = store();
    assert!(unexposed_entries(&store.live_dir()).is_empty());
}

#[test]
fn mcp_credential_entries_counts_only_servers_carrying_env_or_headers() {
    let store = store();
    let session_dir = store.session_dir(ORG);
    fs::create_dir_all(&session_dir).expect("the session directory should be creatable");

    let mut servers = serde_json::Map::new();
    for i in 1..=9 {
        servers.insert(format!("plain{i}"), json!({"command": "true"}));
    }
    servers.insert(
        "creds1".to_owned(),
        json!({"command": "true", "env": {"API_KEY": "leaked-secret-1"}}),
    );
    servers.insert(
        "creds2".to_owned(),
        json!({"command": "true", "headers": {"Authorization": "Bearer leaked-secret-2"}}),
    );
    servers.insert(
        "creds3".to_owned(),
        json!({"command": "true", "env": {"TOKEN": "leaked-secret-3"}}),
    );
    assert_eq!(servers.len(), 12, "the fixture is twelve servers, three of them credential-shaped");

    let live_claude_json = store.home.join(".claude.json");
    fs::write(&live_claude_json, json!({"mcpServers": servers}).to_string())
        .expect("the live `.claude.json` fixture should be writable");
    symlink(&live_claude_json, &session_dir.join("mcp.json"));

    let row = isolation_row(
        &store.paths,
        &AgentctlConfig::default(),
        &store.env,
        ACCT,
        ORG,
        &session_dir,
        &IsolationContext { unexposed: &[], listing: &[] },
    );
    assert!(row.mcp.linked);
    assert_eq!(row.mcp.credential_entries, Some(3));

    // The count is the only thing that may appear: no fixture value leaks
    // into either representation `doctor` produces.
    let data = IsolationData { rows: vec![row.clone()], policy: isolation_policy(&store.env) };
    let text = isolation_section(&data, &store.paths.session_root()).join("\n");
    let document = json::DoctorReport::new(vec![row], data.policy);
    json::assert_valid_doctor(&document);
    let rendered = serde_json::to_string_pretty(&document).expect("a doctor report serializes");

    for leaked in ["leaked-secret-1", "leaked-secret-2", "leaked-secret-3"] {
        assert!(!text.contains(leaked), "the table must not leak a credential value:\n{text}");
        assert!(
            !rendered.contains(leaked),
            "the JSON document must not leak a credential value:\n{rendered}"
        );
    }
}

#[test]
fn mcp_credential_entries_is_unreadable_on_a_parse_failure() {
    let store = store();
    let session_dir = store.session_dir(ORG);
    fs::create_dir_all(&session_dir).expect("the session directory should be creatable");
    let bogus = store.home.join("bogus.json");
    fs::write(&bogus, "{ not valid json").expect("the bogus target should be writable");
    symlink(&bogus, &session_dir.join("mcp.json"));

    let row = isolation_row(
        &store.paths,
        &AgentctlConfig::default(),
        &store.env,
        ACCT,
        ORG,
        &session_dir,
        &IsolationContext { unexposed: &[], listing: &[] },
    );
    assert!(row.mcp.linked, "it is still a symlink, just not a readable one");
    assert_eq!(row.mcp.credential_entries, None);

    let data = IsolationData { rows: vec![row], policy: isolation_policy(&store.env) };
    let text = isolation_section(&data, &store.paths.session_root()).join("\n");
    assert!(text.contains("credential_entries=unreadable"), "{text}");
}

#[test]
fn isolation_row_reports_migrated_when_a_keychain_item_exists_for_the_namespace() {
    // Plan AC58's "migration state" clause: the same probe
    // `the_report_flags_a_namespace_a_session_has_migrated` exercises for
    // `attention_section`, reused here for the isolation row.
    let store = store();
    record_owned(&store, ORG, None);
    let session_dir = store.session_dir(ORG);
    fs::create_dir_all(&session_dir).expect("the session directory should be creatable");

    let config = AgentctlConfig::load(&store.paths).expect("the registry should load");
    let record = config.get(ACCT, ORG).expect("record_owned just recorded this account");
    let AccountKind::Owned { export_sha8, .. } = &record.kind else {
        panic!("record_owned always creates an Owned account");
    };
    let listing = vec![ServiceEntry {
        service: format!("{LIVE_SERVICE}-{export_sha8}"),
        account: None,
        cdat: None,
        mdat: None,
    }];

    let migrated_row = isolation_row(
        &store.paths,
        &config,
        &store.env,
        ACCT,
        ORG,
        &session_dir,
        &IsolationContext { unexposed: &[], listing: &listing },
    );
    assert!(migrated_row.migrated, "a keychain item for this namespace means it has migrated");

    let absent_row = isolation_row(
        &store.paths,
        &config,
        &store.env,
        ACCT,
        ORG,
        &session_dir,
        &IsolationContext { unexposed: &[], listing: &[] },
    );
    assert!(!absent_row.migrated, "no matching keychain item means it has not migrated");

    let text = isolation_section(
        &IsolationData { rows: vec![migrated_row], policy: isolation_policy(&store.env) },
        &store.paths.session_root(),
    )
    .join("\n");
    assert!(text.contains("migrated=true"), "{text}");
}

#[test]
fn disable_sideload_flags_reports_true_false_or_not_set() {
    let dir = TempDir::new().expect("a temporary directory should be creatable");
    let live = dir.path().join("live-settings.json");
    let managed = dir.path().join("managed-settings.json");

    assert_eq!(disable_sideload_flags(&live, &managed), None, "neither file exists");

    fs::write(&live, json!({"policySettings": {"disableSideloadFlags": false}}).to_string())
        .expect("the live settings fixture should be writable");
    assert_eq!(disable_sideload_flags(&live, &managed), Some(false));

    fs::write(&managed, json!({"policySettings": {"disableSideloadFlags": true}}).to_string())
        .expect("the managed settings fixture should be writable");
    assert_eq!(
        disable_sideload_flags(&live, &managed),
        Some(true),
        "true from either file wins over false from the other"
    );
}

#[test]
fn the_isolation_section_says_the_root_is_empty_when_there_are_no_sessions() {
    let store = store();
    let data = collect_isolation(&store.doctor(), &AgentctlConfig::default(), &[]);
    assert!(data.rows.is_empty());

    let text = isolation_section(&data, &store.paths.session_root()).join("\n");
    assert!(text.contains("has no isolated sessions"), "{text}");
    assert!(
        text.contains(&store.paths.session_root().display().to_string()),
        "the root's own path is named:\n{text}"
    );
}

#[test]
fn the_report_includes_the_isolation_section_for_a_registered_session() {
    let store = store();
    record_owned(&store, ORG, None);

    let session_dir = store.session_dir(ORG);
    fs::create_dir_all(&session_dir).expect("the session directory should be creatable");
    let live = store.live_dir();
    fs::create_dir_all(&live).expect("the live config dir should be creatable");
    fs::write(live.join("settings.json"), "{}").expect("the live settings file should be writable");
    symlink(&live.join("settings.json"), &session_dir.join("settings.json"));

    let live_claude_json = store.home.join(".claude.json");
    fs::write(&live_claude_json, json!({"mcpServers": {}}).to_string())
        .expect("the live `.claude.json` fixture should be writable");
    symlink(&live_claude_json, &session_dir.join("mcp.json"));

    fs::write(session_dir.join(".claude.json"), json!({"theme": "dark"}).to_string())
        .expect("the seed fixture should be writable");

    let mut io = Recorder::default();
    report(&store.doctor(), &FakeReader::unlocked(), &store.ctx(), &mut io)
        .expect("the report should succeed");
    let text = io.text();

    assert!(text.contains("isolation"), "{text}");
    assert!(text.contains(&format!("id={ACCT}")), "{text}");
    assert!(text.contains("sha8_match=true"), "{text}");
    assert!(text.contains("settings.json"), "{text}");
    assert!(text.contains("linked"), "{text}");
    assert!(text.contains("agentctl claude use --forget"), "{text}");
    assert!(text.contains("policySettings.disableSideloadFlags"), "{text}");
    assert!(text.contains("secure-storage backend"), "{text}");
}

#[test]
fn the_report_reports_unregistered_for_a_session_with_no_matching_record() {
    let store = store();
    let session_dir = store.session_dir(ORG);
    fs::create_dir_all(&session_dir).expect("the session directory should be creatable");

    let mut io = Recorder::default();
    report(&store.doctor(), &FakeReader::unlocked(), &store.ctx(), &mut io)
        .expect("the report should succeed");
    let text = io.text();

    assert!(text.contains("id=unregistered"), "{text}");
    assert!(
        text.contains(&format!("agentctl claude use --forget {}", session_dir.display())),
        "an unregistered session is forgotten by path:\n{text}"
    );
}
