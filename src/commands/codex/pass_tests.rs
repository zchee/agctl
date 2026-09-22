//! The read-only pass, in-process, against `httpmock` endpoints and a
//! temporary store. Nothing here reads a real Codex home: every home is a
//! directory under the test's own temporary tree (invariant I25).
//!
//! These are the facts that hold for `watch` as much as for `status`, so they
//! are tested through the pass alone — with no permit anywhere in scope, which
//! is the point of the module they exercise. The pre-pass, the 401 post-pass
//! and the deadline are `status`'s, and are tested in `status_tests.rs`.

use std::fs;
use std::path::Path;

use httpmock::Method::GET;
use httpmock::Method::POST;
use httpmock::Mock;
use httpmock::MockServer;

use super::*;
use crate::provider::codex::refresh::MAX_RETRY_AFTER;
use crate::provider::codex::testkit;
use crate::provider::codex::testkit::ago;
use crate::provider::codex::testkit::doc;
use crate::provider::codex::testkit::grant;
use crate::provider::codex::testkit::now_s;
use crate::provider::codex::testkit::only;
use crate::provider::codex::testkit::usage_body;

const USAGE_PATH: &str = "/backend-api/wham/usage";
const TOKEN_PATH: &str = "/oauth/token";
const NEW_RT: &str = "agctl-test-codex-rt-0002";

struct Store {
    _dir: tempfile::TempDir,
    paths: Arc<Paths>,
    server: MockServer,
}

impl Store {
    fn new() -> Self {
        let (dir, paths) = testkit::store();
        paths.ensure_dirs().expect("the Claude store too");
        Self { _dir: dir, paths: Arc::new(paths), server: MockServer::start() }
    }

    fn root(&self) -> &Path {
        self._dir.path()
    }

    /// A Codex home under the test's tree, with `doc` as its `auth.json` when
    /// given.
    fn home(&self, name: &str, doc: Option<&Value>) -> PathBuf {
        let home = self.root().join("homes").join(name);
        fs::create_dir_all(&home).expect("a home");
        if let Some(doc) = doc {
            testkit::write_0600(&home.join("auth.json"), &testkit::pretty(doc));
        }
        home
    }

    fn owned(&self, doc: &Value) -> CodexAccountRecord {
        let record = testkit::owned_record(testkit::USER, testkit::ACCT);
        let dir = self.paths.codex_namespace_dir(testkit::USER, testkit::ACCT).expect("valid ids");
        testkit::write_0600(&dir.join("auth.json"), &testkit::pretty(doc));
        record
    }

    fn usage_ok(&self) -> Mock<'_> {
        self.server.mock(|when, then| {
            when.method(GET).path(USAGE_PATH);
            then.status(200).json_body(usage_body());
        })
    }

    fn token(&self, status: u16, body: Value) -> Mock<'_> {
        self.server.mock(|when, then| {
            when.method(POST).path(TOKEN_PATH);
            then.status(status).json_body(body);
        })
    }

    /// What `watch` does, and what `status` does around its refreshes: the
    /// pass alone. No permit exists in this file, so none can be passed.
    fn watch(&self, plans: Vec<RowPlan>) -> Vec<CodexRowOutcome> {
        let cancel = Cancel::new();
        let deadline = Instant::now() + Duration::from_secs(30);
        let shared = Arc::new(Shared {
            paths: Arc::clone(&self.paths),
            client: UsageClient::new(&self.server.base_url(), "agctl/test", Duration::from_secs(5)),
            keyring: KeyringListing::NotNeeded,
            fault: Fault::none(),
            options: Options::default(),
            allow_post: false,
        });
        finish(collect(plans, &shared, &cancel, deadline))
    }
}

fn plan(index: usize, source: PlanSource) -> RowPlan {
    RowPlan { index, source, pre_pass: None, retry: None }
}

fn owned_plan(record: CodexAccountRecord) -> RowPlan {
    plan(0, PlanSource::Owned { record, evidence: DaemonEvidence::None })
}

// --- `watch` never sends (U44 = 5, AC104) ---------------------------------

#[test]
fn u44_an_expired_owned_row_in_watch_sends_nothing_and_names_status() {
    let store = Store::new();
    let usage = store.usage_ok();
    let token = store.token(200, grant(NEW_RT));
    let record = store.owned(&doc(1_000, testkit::RT_SENTINEL));

    let row = only(store.watch(vec![owned_plan(record)]));

    assert_eq!(row.state, CodexState::Expired { reason: EXPIRED_IN_WATCH.to_owned() });
    assert_eq!(token.calls(), 0, "watch reached the token endpoint");
    assert_eq!(usage.calls(), 0);
}

#[test]
fn u44_a_401_in_watch_sends_nothing() {
    let store = Store::new();
    let rejected = store.server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(401);
    });
    let token = store.token(200, grant(NEW_RT));
    let record = store.owned(&doc(now_s() + 9 * 86_400, testkit::RT_SENTINEL));

    let row = only(store.watch(vec![owned_plan(record)]));

    assert_eq!(row.state, CodexState::Unauthorized { refreshed_recently: false });
    assert!(row.note.as_deref().is_some_and(|note| note.contains(EXPIRED_IN_WATCH)), "{row:?}");
    assert_eq!(rejected.calls(), 1);
    assert_eq!(token.calls(), 0, "watch reached the token endpoint");
}

// --- reading a home (deviation D18, review S33-C2 B2) ---------------------

#[test]
fn d18_a_codex_home_with_no_credential_says_so_and_needs_login() {
    let store = Store::new();
    let usage = store.usage_ok();
    let home = store.home("empty", None);

    let row = only(store.watch(vec![plan(0, PlanSource::Live { home })]));

    assert_eq!(row.state, CodexState::NeedsLogin);
    assert_eq!(
        row.note.as_deref(),
        Some("no credential in this Codex home"),
        "the wording D18 records is what the row shows: {row:?}"
    );
    assert!(!row.state.is_exit_neutral(), "an explicit Codex command exits non-zero: {row:?}");
    assert_eq!(usage.calls(), 0, "a home with no credential was fetched");
}

#[test]
fn b3_a_machine_that_has_never_run_codex_has_no_live_row() {
    let store = Store::new();
    let home = store.root().join("no-such-user");
    fs::create_dir_all(&home).expect("a home directory");
    let env = CodexEnv::new(None, Some(home.clone()));

    let plans = plan_rows(&store.paths, &[], &env, &Cancel::new());

    assert!(plans.is_empty(), "a home with no `.codex` still planned a row: {plans:?}");
    assert!(!home.join(".codex").exists(), "the test created the directory it is asserting about");
}

#[test]
fn b3_an_existing_codex_home_without_a_credential_keeps_its_row() {
    let store = Store::new();
    let home = store.root().join("has-codex");
    fs::create_dir_all(home.join(".codex")).expect("a Codex home");
    let env = CodexEnv::new(None, Some(home));

    let plans = plan_rows(&store.paths, &[], &env, &Cancel::new());

    assert_eq!(plans.len(), 1, "{plans:?}");
    assert!(matches!(plans[0].source, PlanSource::Live { .. }), "{plans:?}");
    // D18 still holds for a home that exists: the row says so and exits 2.
    let row = only(store.watch(plans));
    assert_eq!(row.state, CodexState::NeedsLogin);
    assert_eq!(row.note.as_deref(), Some("no credential in this Codex home"));
}

#[test]
fn b3_a_home_that_cannot_be_stated_keeps_its_row() {
    let store = Store::new();
    // A regular file where a directory belongs: `symlink_metadata` on
    // `<file>/.codex` fails with ENOTDIR, not NotFound. Only NotFound means
    // "this machine has never run Codex"; everything else is a home that is
    // there and unreadable, and its row says so (review S33-C3a F2).
    let home = store.root().join("a-file-not-a-directory");
    fs::write(&home, b"not a directory").expect("a regular file");
    let err = fs::symlink_metadata(home.join(".codex")).expect_err("a path under a file");
    assert_ne!(err.kind(), std::io::ErrorKind::NotFound, "{err}");
    let env = CodexEnv::new(None, Some(home));

    let plans = plan_rows(&store.paths, &[], &env, &Cancel::new());

    assert_eq!(plans.len(), 1, "a home that cannot be stat'ed vanished instead of reporting");
    assert!(matches!(plans[0].source, PlanSource::Live { .. }), "{plans:?}");
}

#[test]
fn b3_a_dangling_codex_symlink_is_not_a_missing_home() {
    let store = Store::new();
    let home = store.root().join("dangling");
    fs::create_dir_all(&home).expect("a home directory");
    std::os::unix::fs::symlink(home.join("nowhere"), home.join(".codex")).expect("a symlink");
    let env = CodexEnv::new(None, Some(home));

    let plans = plan_rows(&store.paths, &[], &env, &Cancel::new());

    assert_eq!(plans.len(), 1, "a broken Codex home vanished instead of reporting: {plans:?}");
}

// --- selection and the display id ------------------------------------------

#[test]
fn d039_a_shared_user_id_is_qualified_by_its_account() {
    let row = |user: &str, acct: &str| CodexRowOutcome {
        index: 0,
        id: String::new(),
        user_id: user.to_owned(),
        account_id: acct.to_owned(),
        email: None,
        plan: None,
        kind: CodexRowKind::Owned,
        state: CodexState::Ok,
        lock_state: "none",
        note: None,
        usage: None,
        visible_by_default: true,
    };
    let users = vec!["user-a".to_owned(), "user-a".to_owned(), "user-b".to_owned()];
    assert_eq!(display_id(&row("user-a", "acct-1"), &users), "user-a/acct-1");
    assert_eq!(display_id(&row("user-b", "acct-2"), &users), "user-b");
    assert_eq!(display_id(&row("", ""), &users), "live");
}

#[test]
fn account_selectors_name_a_user_a_pair_an_email_or_live() {
    let mut record = testkit::owned_record("user-0009", "acct-0009");
    record.email = Some("nine@example.invalid".to_owned());
    let plans = || {
        vec![
            plan(0, PlanSource::Live { home: PathBuf::from("/nonexistent") }),
            plan(1, PlanSource::Owned { record: record.clone(), evidence: DaemonEvidence::None }),
        ]
    };
    for (selector, expected) in
        [("user-0009", 1), ("user-0009/acct-0009", 1), ("nine@example.invalid", 1), ("live", 0)]
    {
        let selected = select(plans(), &[selector.to_owned()]).expect("matches");
        assert_eq!(selected.len(), 1, "{selector}");
        assert_eq!(selected[0].index, expected, "{selector}");
    }
    let err = select(plans(), &["nobody".to_owned()]).expect_err("no match");
    assert!(err.to_string().contains("no Codex account matches `nobody`"), "{err}");
}

// --- one wording for a spent `--resend` (review S32-C2 R2-I2) --------------

struct SignedDurationExt;

impl SignedDurationExt {
    fn from(duration: Duration) -> jiff::SignedDuration {
        jiff::SignedDuration::try_from(duration).expect("in range")
    }
}

#[test]
fn r2_i2_a_spent_resend_reads_the_same_whichever_way_it_was_spent() {
    let (state, note) = unknown_state(ago(7_200), UnknownClass::Ambiguous, None);
    assert!(matches!(state, CodexState::RefreshOutcomeUnknown { resend_eligible: false, .. }));
    assert_eq!(note.as_deref(), Some(RESEND_SPENT));
    assert_eq!(
        needs_login_note(NeedsLoginReason::ResendRejected(400)),
        format!("refresh outcome unknown; {RESEND_SPENT}")
    );
    let (_, eligible) = unknown_state(ago(7_200), UnknownClass::Ambiguous, Some(ago(10)));
    assert!(eligible.is_some_and(|note| note.contains("--resend is available")));
    // The eligibility rule rendered here is the driver's own.
    let since = ago(0);
    assert_eq!(
        refresh::resend_eligible_at(since, UnknownClass::RateLimited, Some(MAX_RETRY_AFTER * 2)),
        since.checked_add(SignedDurationExt::from(MAX_RETRY_AFTER)).expect("in range")
    );
}
