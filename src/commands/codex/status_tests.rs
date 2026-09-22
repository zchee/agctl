//! The Codex pass, in-process, against `httpmock` endpoints and a temporary
//! store. Nothing here reads a real Codex home: every home is a directory
//! under the test's own temporary tree (invariant I25).

use std::fs;
use std::path::Path;
use std::path::PathBuf;

use httpmock::Method::GET;
use httpmock::Method::POST;
use httpmock::Mock;
use httpmock::MockServer;
use serde_json::json;

use super::*;
use crate::commands::codex::pass::EXPIRED_NEVER;
use crate::commands::codex::pass::EXPIRED_READ_ONLY;
use crate::commands::codex::pass::KeyringListing;
use crate::config::codex::CodexAccountRecord;
use crate::config::codex::CodexKind;
use crate::config::codex::RefreshPolicy;
use crate::provider::Provider;
use crate::provider::codex::account::CodexRowKind;
use crate::provider::codex::auth_store;
use crate::provider::codex::auth_store::Inflight;
use crate::provider::codex::auth_store::RefreshState;
use crate::provider::codex::auth_store::UnknownClass;
use crate::provider::codex::credentials::Credentials;
use crate::provider::codex::home;
use crate::provider::codex::home::DaemonEvidence;
use crate::provider::codex::home::StoreMode;
use crate::provider::codex::oauth::RefreshClient;
use crate::provider::codex::testkit;
use crate::provider::codex::testkit::ago;
use crate::provider::codex::testkit::doc;
use crate::provider::codex::testkit::grant;
use crate::provider::codex::testkit::now_s;
use crate::provider::codex::testkit::only;
use crate::provider::codex::testkit::usage_body;
use crate::render::json_v2::assert_valid_v2;
use crate::secret::ServiceEntry;
use crate::usage::cache;

const USAGE_PATH: &str = "/backend-api/wham/usage";
const TOKEN_PATH: &str = "/oauth/token";
const NEW_RT: &str = "agctl-test-codex-rt-0002";

fn bearer_of(doc: &Value) -> String {
    format!("Bearer {}", doc["tokens"]["access_token"].as_str().expect("an access token"))
}

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
    /// given and `config` as its `config.toml` when given.
    fn home(&self, name: &str, doc: Option<&Value>, config: Option<&str>) -> PathBuf {
        let home = self.root().join("homes").join(name);
        fs::create_dir_all(&home).expect("a home");
        if let Some(doc) = doc {
            testkit::write_0600(&home.join("auth.json"), &testkit::pretty(doc));
        }
        if let Some(config) = config {
            fs::write(home.join("config.toml"), config).expect("a config");
        }
        home
    }

    fn owned(&self, doc: &Value) -> CodexAccountRecord {
        let record = testkit::owned_record(testkit::USER, testkit::ACCT);
        let dir = self.paths.codex_namespace_dir(testkit::USER, testkit::ACCT).expect("valid ids");
        testkit::write_0600(&dir.join("auth.json"), &testkit::pretty(doc));
        record
    }

    fn marker_path(&self) -> PathBuf {
        self.paths.codex_refresh_state_path(testkit::USER, testkit::ACCT).expect("valid ids")
    }

    fn write_marker(&self, state: &RefreshState) {
        testkit::write_0600(&self.marker_path(), &serde_json::to_vec(state).expect("serializes"));
    }

    fn marker(&self) -> Option<RefreshState> {
        fs::read(self.marker_path())
            .ok()
            .map(|bytes| serde_json::from_slice(&bytes).expect("the marker parses"))
    }

    fn shared(&self, allow_post: bool) -> Arc<Shared> {
        Arc::new(Shared {
            paths: Arc::clone(&self.paths),
            client: UsageClient::new(&self.server.base_url(), "agctl/test", Duration::from_secs(5)),
            keyring: KeyringListing::NotNeeded,
            fault: Fault::none(),
            options: Options::default(),
            allow_post,
        })
    }

    fn permit(&self) -> PostPermit {
        PostPermit::with_client(RefreshClient::new(&self.server.url(TOKEN_PATH), "agctl/test"))
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

    /// What `status` does: pre-pass, pass, post-pass, finish.
    fn status(&self, plans: Vec<RowPlan>) -> Vec<CodexRowOutcome> {
        let cancel = Cancel::new();
        let deadline = pass_deadline(Duration::from_secs(10), true);
        let permit = self.permit();
        let shared = self.shared(true);
        let plans =
            refresh_pre_pass(&permit, plans, &self.paths, &Fault::none(), &cancel, deadline);
        let passes = collect(plans, &shared, &cancel, deadline);
        finish(after_unauthorized(&permit, passes, &shared, &cancel, deadline))
    }

    /// What `watch` does: the pass alone.
    fn watch(&self, plans: Vec<RowPlan>) -> Vec<CodexRowOutcome> {
        let cancel = Cancel::new();
        let deadline = Instant::now() + Duration::from_secs(30);
        finish(collect(plans, &self.shared(false), &cancel, deadline))
    }
}

fn plan(index: usize, source: PlanSource) -> RowPlan {
    RowPlan { index, source, pre_pass: None, retry: None }
}

fn owned_plan(record: CodexAccountRecord) -> RowPlan {
    plan(0, PlanSource::Owned { record, evidence: DaemonEvidence::None })
}

// --- the deadline (D-035, review S31 F9) ----------------------------------

#[test]
fn f9_one_request_can_spend_four_short_and_two_long_phases() {
    let cases: [(u64, u64); 4] =
        [(10, 4 * 5 + 2 * 10), (2, 4 * 2 + 2 * 2), (5, 4 * 5 + 2 * 5), (300, 4 * 5 + 600)];
    for (timeout, expected) in cases {
        assert_eq!(
            usage_request_budget(Duration::from_secs(timeout)),
            Duration::from_secs(expected),
            "--timeout {timeout}s"
        );
    }
    assert_eq!(usage_request_budget(Duration::MAX), Duration::MAX, "saturates, never wraps");
}

#[test]
fn ac91b_the_default_deadline_leaves_a_refresh_its_whole_budget_after_a_first_get() {
    let timeout = Duration::from_secs(10);
    let with_refresh = pass_budget(timeout, true);
    assert_eq!(with_refresh, Duration::from_secs(1 + 19 + 1 + 2 * 40));
    let needed = PASS_LOCK_BUDGET + REFRESH_POST_BUDGET + WRITE_ALLOWANCE;
    assert!(
        with_refresh >= needed + usage_request_budget(timeout) * 2,
        "a refresh after a slow first GET must still pass refresh::run's time check"
    );
    assert_eq!(pass_budget(timeout, false), Duration::from_secs(40));
    assert_eq!(pass_budget(Duration::MAX, true), Duration::MAX);
}

// --- reading homes (AC94, AC95) --------------------------------------------

#[test]
fn a_live_home_is_read_and_fetched_with_its_identity() {
    let store = Store::new();
    let usage = store.usage_ok();
    let home = store.home("live", Some(&doc(now_s() + 86_400, testkit::RT_SENTINEL)), None);

    let row = only(store.watch(vec![plan(0, PlanSource::Live { home })]));

    assert_eq!(row.state, CodexState::Ok, "{row:?}");
    assert_eq!(row.kind, CodexRowKind::Live);
    assert_eq!(row.user_id, testkit::USER);
    assert_eq!(row.account_id, testkit::ACCT);
    assert_eq!(row.id, testkit::USER, "a unique user id is the display id (D-039)");
    assert_eq!(row.plan.as_deref(), Some("plus"), "the response's plan wins over the claim");
    assert_eq!(usage.calls(), 1);
    let raw = row.usage.as_ref().and_then(|usage| usage.raw.as_ref()).expect("raw kept");
    assert!(raw.get("email").is_none(), "the response's email is never kept");
}

#[test]
fn ac95_keyring_and_ephemeral_homes_are_not_read_and_not_fetched() {
    for mode in ["keyring", "ephemeral"] {
        let store = Store::new();
        let usage = store.usage_ok();
        let home = store.home(
            mode,
            Some(&doc(now_s() + 86_400, testkit::RT_SENTINEL)),
            Some(&format!("cli_auth_credentials_store = \"{mode}\"\n")),
        );

        let row = only(store.watch(vec![plan(0, PlanSource::Live { home })]));

        assert!(matches!(row.state, CodexState::StoreModeUnsupported { .. }), "{mode}: {row:?}");
        assert_eq!(usage.calls(), 0, "{mode}: nothing is fetched for a store agctl does not read");
        assert!(row.user_id.is_empty(), "{mode}: the file was not read");
    }
}

#[test]
fn ac95_auto_reads_the_file_only_when_no_item_is_listed_for_this_home() {
    let store = Store::new();
    let _usage = store.usage_ok();
    let home = store.home(
        "auto",
        Some(&doc(now_s() + 86_400, testkit::RT_SENTINEL)),
        Some("cli_auth_credentials_store = \"auto\"\n"),
    );
    let entry = |account: Option<String>| ServiceEntry {
        service: home::KEYRING_SERVICE.to_owned(),
        account,
        cdat: None,
        mdat: None,
    };
    let cases = [
        ("no item", KeyringListing::Entries(Vec::new()), true),
        (
            "another home's item",
            KeyringListing::Entries(vec![entry(Some("cli|0000000000000000".to_owned()))]),
            true,
        ),
        (
            "this home's item",
            KeyringListing::Entries(vec![entry(Some(home::keyring_account(&home)))]),
            false,
        ),
        ("coarse: no account column", KeyringListing::Entries(vec![entry(None)]), false),
        ("listing unavailable", KeyringListing::Unavailable, true),
    ];

    for (name, keyring, read) in cases {
        let shared =
            Arc::new(Shared { keyring, ..Arc::into_inner(store.shared(false)).expect("unshared") });
        let rows = finish(collect(
            vec![plan(0, PlanSource::Live { home: home.clone() })],
            &shared,
            &Cancel::new(),
            Instant::now() + Duration::from_secs(30),
        ));
        let row = only(rows);
        if read {
            assert_eq!(row.state, CodexState::Ok, "{name}: {row:?}");
            assert!(
                row.note.as_deref().is_some_and(|note| note.contains("auto (file in effect)")),
                "{name}"
            );
        } else {
            assert!(
                matches!(row.state, CodexState::StoreModeUnsupported { mode: StoreMode::Auto }),
                "{name}: {row:?}"
            );
        }
    }
}

#[test]
fn ac94_a_torn_file_is_retried_once_and_never_needs_login() {
    let store = Store::new();
    let usage = store.usage_ok();
    let home = store.home("torn", None, None);
    fs::write(home.join("auth.json"), b"{\"auth_mode\": \"chatg").expect("a torn file");

    let row = only(store.watch(vec![plan(0, PlanSource::Live { home })]));

    assert_eq!(row.state, CodexState::TornRead, "{row:?}");
    assert_eq!(usage.calls(), 0);
    assert!(row.state.label().contains("was being rewritten"));
}

#[test]
fn an_apikey_home_has_no_usage_source_and_is_exit_neutral() {
    let store = Store::new();
    let usage = store.usage_ok();
    let home = store.home("apikey", None, None);
    fs::write(home.join("auth.json"), testkit::fixture("auth-apikey.json")).expect("apikey");

    let row = only(store.watch(vec![plan(0, PlanSource::Live { home })]));

    assert!(matches!(row.state, CodexState::NoUsageSource { .. }), "{row:?}");
    assert!(row.state.is_exit_neutral());
    assert_eq!(usage.calls(), 0);
}

#[test]
fn an_expired_read_only_row_is_never_fetched() {
    let store = Store::new();
    let usage = store.usage_ok();
    let home = store.home("expired", Some(&doc(1_000, testkit::RT_SENTINEL)), None);

    let row = only(store.status(vec![plan(0, PlanSource::Live { home })]));

    assert_eq!(row.state, CodexState::Expired { reason: EXPIRED_READ_ONLY.to_owned() });
    assert_eq!(usage.calls(), 0);
}

// --- U44 = (5): watch never POSTs ----------------------------------------

#[test]
fn a_never_policy_row_expires_with_a_login_hint_and_sends_nothing() {
    let store = Store::new();
    let token = store.token(200, grant(NEW_RT));
    let mut record = store.owned(&doc(1_000, testkit::RT_SENTINEL));
    record.kind =
        CodexKind::Owned { export_spelling: "/x".to_owned(), refresh: RefreshPolicy::Never };

    let row = only(store.status(vec![owned_plan(record)]));

    assert_eq!(row.state, CodexState::Expired { reason: EXPIRED_NEVER.to_owned() });
    assert_eq!(token.calls(), 0);
}

// --- the pre-pass and the 401 post-pass (status) -------------------------

#[test]
fn ac91_an_expired_owned_row_is_refreshed_once_then_fetched_with_the_new_token() {
    let store = Store::new();
    let token = store.token(200, grant(NEW_RT));
    let usage = store.usage_ok();
    let record = store.owned(&doc(1_000, testkit::RT_SENTINEL));

    let row = only(store.status(vec![owned_plan(record)]));

    assert_eq!(row.state, CodexState::Ok, "{row:?}");
    assert_eq!(token.calls(), 1, "exactly one POST");
    assert_eq!(usage.calls(), 1, "then one GET");
    assert!(row.note.as_deref().is_some_and(|note| note.contains("refreshed")), "{row:?}");
    assert!(store.marker().is_some_and(|marker| marker.inflight.is_none()), "marker cleared");
}

#[test]
fn ac114_a_401_on_a_valid_token_sends_one_refresh_and_retries_the_get() {
    let store = Store::new();
    let old = doc(now_s() + 9 * 86_400, testkit::RT_SENTINEL);
    let rejected = store.server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH).header("authorization", bearer_of(&old));
        then.status(401);
    });
    let accepted = store.server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(200).json_body(usage_body());
    });
    let token = store.token(200, grant(NEW_RT));
    let record = store.owned(&old);
    // A raised floor from an older failure, which the 2xx resets.
    store.write_marker(&RefreshState {
        did_not_help: 1,
        floor_min: 120,
        last_sent_at: Some(ago(3 * 3600)),
        ..RefreshState::default()
    });

    let row = only(store.status(vec![owned_plan(record)]));

    assert_eq!(row.state, CodexState::Ok, "{row:?}");
    assert_eq!(rejected.calls(), 1);
    assert_eq!(token.calls(), 1, "the 401 path sent exactly one refresh");
    assert_eq!(accepted.calls(), 1, "and retried the GET once");
    let marker = store.marker().expect("a marker");
    assert_eq!((marker.did_not_help, marker.floor_min), (0, auth_store::DEFAULT_FLOOR_MIN));
}

#[test]
fn ac114_a_retry_that_401s_again_counts_once_and_raises_the_floor() {
    let store = Store::new();
    let rejected = store.server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(401);
    });
    let token = store.token(200, grant(NEW_RT));
    let record = store.owned(&doc(now_s() + 9 * 86_400, testkit::RT_SENTINEL));

    let row = only(store.status(vec![owned_plan(record.clone())]));

    assert_eq!(row.state, CodexState::Unauthorized { refreshed_recently: true }, "{row:?}");
    assert_eq!((token.calls(), rejected.calls()), (1, 2));
    let marker = store.marker().expect("a marker");
    assert_eq!(marker.did_not_help, 1);

    // The next pass: inside the floor, nothing is sent.
    let row = only(store.status(vec![owned_plan(record)]));
    assert_eq!(row.state, CodexState::UnauthorizedFloor, "{row:?}");
    assert_eq!(token.calls(), 1, "two passes, at most one POST");
}

#[test]
fn ac114_a_401_whose_bearer_is_no_longer_in_the_file_adopts_and_sends_nothing() {
    let store = Store::new();
    let old = doc(now_s() + 9 * 86_400, testkit::RT_SENTINEL);
    let newer = doc(now_s() + 10 * 86_400, NEW_RT);
    let token = store.token(200, grant("agctl-test-codex-rt-0003"));
    let record = store.owned(&old);
    let shared = store.shared(true);
    let cancel = Cancel::new();
    let deadline = pass_deadline(Duration::from_secs(10), true);
    let rejected = store.server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH).header("authorization", bearer_of(&old));
        then.status(401);
    });
    let passes = collect(vec![owned_plan(record.clone())], &shared, &cancel, deadline);
    assert!(passes[0].rejected.is_some(), "the pass recorded the rejected bearer");
    // Another writer refreshes between the GET and the post-pass.
    store.owned(&newer);
    let accepted = store.server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH).header("authorization", bearer_of(&newer));
        then.status(200).json_body(usage_body());
    });

    let row = only(finish(after_unauthorized(&store.permit(), passes, &shared, &cancel, deadline)));

    assert_eq!(row.state, CodexState::Ok, "{row:?}");
    assert_eq!(token.calls(), 0, "adopted, never sent");
    assert_eq!((rejected.calls(), accepted.calls()), (1, 1));
}

#[test]
fn ac114_the_terminal_state_is_not_lifted_by_refresh_or_no_cache() {
    let store = Store::new();
    let _rejected = store.server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(401);
    });
    let token = store.token(200, grant(NEW_RT));
    let record = store.owned(&doc(now_s() + 9 * 86_400, testkit::RT_SENTINEL));
    store.write_marker(&RefreshState {
        did_not_help: 3,
        floor_min: 240,
        last_sent_at: Some(ago(30 * 86_400)),
        ..RefreshState::default()
    });

    let row = only(store.status(vec![owned_plan(record)]));

    assert_eq!(row.state, CodexState::UnauthorizedTerminal, "{row:?}");
    assert!(row.note.as_deref().is_some_and(|note| note.contains("--reset-floor")), "{row:?}");
    assert_eq!(token.calls(), 0);
}

#[test]
fn ac123_an_unknown_outcome_probes_the_old_token_while_it_lives_and_sends_nothing() {
    let store = Store::new();
    let usage = store.usage_ok();
    let token = store.token(200, grant(NEW_RT));
    let live = doc(now_s() + 3_600, testkit::RT_SENTINEL);
    let record = store.owned(&live);
    let grant8 =
        Credentials::parse(&testkit::pretty(&live)).expect("parses").refresh_digest8().expect("rt");
    let sent_at = ago(600);
    store.write_marker(&RefreshState {
        inflight: Some(Inflight { sent_digest8: grant8, sent_at }),
        ambiguous_since: Some(sent_at),
        class: Some(UnknownClass::ServerError),
        last_sent_at: Some(sent_at),
        ..RefreshState::default()
    });

    for pass in 0..3 {
        let row = only(store.status(vec![owned_plan(record.clone())]));
        assert!(
            matches!(
                row.state,
                CodexState::RefreshOutcomeUnknown { class: UnknownClass::ServerError, .. }
            ),
            "pass {pass}: {row:?}"
        );
        assert!(row.usage.is_some(), "pass {pass}: the old token's numbers are shown");
    }
    assert_eq!(token.calls(), 0, "no automatic re-send");
    assert!(usage.calls() >= 1);
}

#[test]
fn ac123_an_unknown_outcome_past_exp_needs_login_without_a_request() {
    let store = Store::new();
    let usage = store.usage_ok();
    let token = store.token(200, grant(NEW_RT));
    let dead = doc(1_000, testkit::RT_SENTINEL);
    let record = store.owned(&dead);
    let grant8 =
        Credentials::parse(&testkit::pretty(&dead)).expect("parses").refresh_digest8().expect("rt");
    store.write_marker(&RefreshState {
        inflight: Some(Inflight { sent_digest8: grant8, sent_at: ago(600) }),
        class: Some(UnknownClass::Ambiguous),
        ambiguous_since: Some(ago(600)),
        ..RefreshState::default()
    });

    let row = only(store.status(vec![owned_plan(record)]));

    assert_eq!(row.state, CodexState::NeedsLogin, "{row:?}");
    assert!(
        row.note.as_deref().is_some_and(|note| note.contains("refresh outcome unknown")),
        "{row:?}"
    );
    assert_eq!((usage.calls(), token.calls()), (0, 0));
}

#[test]
fn i2_the_server_floor_is_rendered_with_a_login_hint() {
    let at: Timestamp = "2026-10-01T00:00:00Z".parse().expect("valid");
    let note = step_note(&RefreshStep::NotBefore(at)).expect("a note");
    assert!(note.contains("run agctl codex login") && note.contains("2026-10-01"), "{note}");
}

// --- the fold, ids and selection -------------------------------------------

#[test]
fn d23_an_import_of_the_live_grant_is_folded_and_one_that_moved_on_is_a_stale_sibling() {
    let store = Store::new();
    let _usage = store.usage_ok();
    let live_doc = doc(now_s() + 86_400, testkit::RT_SENTINEL);
    let live = store.home("live", Some(&live_doc), None);
    let copy = store.home("copy", Some(&live_doc), None);
    let recorded = |user: &str, acct: &str, dir: &Path| {
        let mut record = testkit::owned_record(user, acct);
        record.kind = CodexKind::HomeReadOnly { dir: dir.to_path_buf() };
        record
    };

    // Another directory holding the very grant the live home holds.
    let rows = store.watch(vec![
        plan(0, PlanSource::Live { home: live.clone() }),
        plan(
            1,
            PlanSource::HomeReadOnly {
                record: recorded(testkit::USER, testkit::ACCT, &copy),
                dir: copy,
            },
        ),
    ]);
    assert!(rows[0].visible_by_default);
    assert!(!rows[1].visible_by_default, "the same grant twice is one account: {rows:?}");
    assert_eq!(rows[1].state, CodexState::Ok);

    // The live directory itself, recorded for an account it no longer holds.
    let rows = store.watch(vec![
        plan(0, PlanSource::Live { home: live.clone() }),
        plan(
            1,
            PlanSource::HomeReadOnly {
                record: recorded("user-0002", "acct-0002", &live),
                dir: live.clone(),
            },
        ),
    ]);
    assert_eq!(rows[1].state, CodexState::StaleSiblingOfLive, "{rows:?}");
    assert!(!rows[1].visible_by_default);
    assert!(rows[1].usage.is_none(), "a stale sibling does not show the live account's numbers");

    // An import of another home with its own grant stays its own row.
    let other = store.home("other", Some(&doc(now_s() + 2 * 86_400, NEW_RT)), None);
    let mut other_doc = doc(now_s() + 2 * 86_400, NEW_RT);
    other_doc["tokens"]["access_token"] = json!(testkit::access_token(Some(now_s() + 3 * 86_400)));
    testkit::write_0600(&other.join("auth.json"), &testkit::pretty(&other_doc));
    let rows = store.watch(vec![
        plan(0, PlanSource::Live { home: live }),
        plan(
            1,
            PlanSource::HomeReadOnly {
                record: recorded(testkit::USER, testkit::ACCT, &other),
                dir: other,
            },
        ),
    ]);
    assert!(rows[1].visible_by_default, "{rows:?}");
}

// --- the cache and rate limits (AC101) --------------------------------------

#[test]
fn ac101_a_429_is_honoured_across_passes_without_a_request() {
    let store = Store::new();
    let limited = store.server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(429).header("retry-after", "30");
    });
    let home = store.home("live", Some(&doc(now_s() + 86_400, testkit::RT_SENTINEL)), None);

    let first = only(store.watch(vec![plan(0, PlanSource::Live { home: home.clone() })]));
    let second = only(store.watch(vec![plan(0, PlanSource::Live { home })]));

    assert!(matches!(first.state, CodexState::RateLimited { retry_after: Some(30) }), "{first:?}");
    assert!(matches!(second.state, CodexState::RateLimited { .. }), "{second:?}");
    assert_eq!(limited.calls(), 1, "no retry within the window");
}

#[test]
fn a_fresh_cache_entry_is_served_and_no_cache_bypasses_it() {
    let store = Store::new();
    let usage = store.usage_ok();
    let home = store.home("live", Some(&doc(now_s() + 86_400, testkit::RT_SENTINEL)), None);

    only(store.watch(vec![plan(0, PlanSource::Live { home: home.clone() })]));
    let cached = only(store.watch(vec![plan(0, PlanSource::Live { home: home.clone() })]));
    assert_eq!(usage.calls(), 1, "the second pass was served from the cache");
    assert_eq!(cached.state, CodexState::Ok);
    let cache_file = cache::path_for(&store.paths, Provider::Codex, testkit::USER, testkit::ACCT);
    let text = fs::read_to_string(&cache_file).expect("a Codex cache entry");
    assert!(!text.contains("agctl-test-codex-email-0001"), "the cache keeps no email");
    assert!(cache_file.starts_with(store.paths.cache_dir_for(Provider::Codex)));

    let shared = Arc::new(Shared {
        options: Options { refresh: false, no_cache: true },
        ..Arc::into_inner(store.shared(false)).expect("unshared")
    });
    finish(collect(
        vec![plan(0, PlanSource::Live { home })],
        &shared,
        &Cancel::new(),
        Instant::now() + Duration::from_secs(30),
    ));
    assert_eq!(usage.calls(), 2, "--no-cache went to the wire");
}

// --- the document (AC102) ----------------------------------------------------

#[test]
fn ac102_a_pass_serializes_into_a_valid_v2_document_without_a_needle() {
    let store = Store::new();
    let _usage = store.usage_ok();
    let _token = store.token(200, grant(NEW_RT));
    let home = store.home("live", Some(&doc(now_s() + 86_400, testkit::RT_SENTINEL)), None);
    let record = store.owned(&doc(1_000, testkit::RT_SENTINEL));

    let rows = store.status(vec![
        plan(0, PlanSource::Live { home }),
        plan(1, PlanSource::Owned { record, evidence: DaemonEvidence::None }),
    ]);
    let report = StatusReportV2::from_rows(&rows, Timestamp::now(), 0);

    assert_valid_v2(&report);
    let text = serde_json::to_string(&report).expect("serializes");
    testkit::assert_no_needles(&text, "the v2 document");
    assert!(!text.contains("agctl-test-codex-email-0001"), "the response's email leaked");
    for row in &report.rows {
        assert_eq!(row.provider, "codex");
    }
    let debug = format!("{rows:?}");
    testkit::assert_no_needles(&debug, "a row's Debug");
}

#[test]
fn ac123_a_401_on_the_old_token_of_an_unknown_grant_needs_login_and_sends_nothing() {
    let store = Store::new();
    let rejected = store.server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(401);
    });
    let token = store.token(200, grant(NEW_RT));
    let live = doc(now_s() + 3_600, testkit::RT_SENTINEL);
    let record = store.owned(&live);
    let grant8 =
        Credentials::parse(&testkit::pretty(&live)).expect("parses").refresh_digest8().expect("rt");
    store.write_marker(&RefreshState {
        inflight: Some(Inflight { sent_digest8: grant8, sent_at: ago(600) }),
        class: Some(UnknownClass::Ambiguous),
        ambiguous_since: Some(ago(600)),
        ..RefreshState::default()
    });

    let row = only(store.status(vec![owned_plan(record)]));

    assert_eq!(row.state, CodexState::NeedsLogin, "{row:?}");
    assert!(row.note.as_deref().is_some_and(|note| note.contains("refresh outcome unknown")));
    assert_eq!((rejected.calls(), token.calls()), (1, 0));
}

#[test]
fn an_unknown_grant_keeps_its_state_when_the_probe_fails_in_transit() {
    let store = Store::new();
    let _failing = store.server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(503);
    });
    let live = doc(now_s() + 3_600, testkit::RT_SENTINEL);
    let record = store.owned(&live);
    let grant8 =
        Credentials::parse(&testkit::pretty(&live)).expect("parses").refresh_digest8().expect("rt");
    store.write_marker(&RefreshState {
        inflight: Some(Inflight { sent_digest8: grant8, sent_at: ago(600) }),
        class: Some(UnknownClass::ServerError),
        ambiguous_since: Some(ago(600)),
        ..RefreshState::default()
    });

    let row = only(store.status(vec![owned_plan(record)]));

    assert!(matches!(row.state, CodexState::RefreshOutcomeUnknown { .. }), "{row:?}");
    assert!(row.note.as_deref().is_some_and(|note| note.contains("HTTP 503")), "{row:?}");
}

#[test]
fn the_timeout_help_states_the_deadline_rule_this_module_computes() {
    use clap::CommandFactory;

    let mut command = crate::cli::Cli::command();
    let codex = command.find_subcommand_mut("codex").expect("codex");
    let status = codex.find_subcommand_mut("status").expect("status");
    let mut help = Vec::new();
    status.write_long_help(&mut help).expect("help renders");
    let help = String::from_utf8(help).expect("UTF-8");

    let default = Duration::from_secs(10);
    let request = usage_request_budget(default).as_secs();
    let pass = pass_budget(default, true).as_secs();
    assert!(help.contains(&format!("({request}s by default)")), "{help}");
    assert!(help.contains(&format!("({pass}s by default)")), "{help}");
    assert!(help.contains("4 × min(--timeout, 5s) + 2 × --timeout"), "{help}");
}
