#![cfg(feature = "testing")]

//! `agctl codex import --from codex-home`, driven through the real binary
//! (plan AC106, and AC95's set cases through `--codex-home`).
//!
//! Every Codex home here is inside the fixture's temporary tree: `HOME` points
//! into it, the Codex home variable is removed from every spawn, and
//! `CodexFixture::set` refuses to put it back, so no run can reach the
//! developer's own `~/.codex` (invariant I25). A home this file names is
//! passed with `--codex-home`, which is the flag that exists for exactly that
//! reason.
//!
//! # Zero writes under the source home
//!
//! The central claim of this command is a negative, so it is measured rather
//! than asserted: [`manifest`] records every entry under a home — relative
//! name, whether it is a directory, its mode, size, nanosecond mtime and the
//! SHA-256 of its bytes — and the two AC106 cases compare that manifest across
//! a run. One of them also makes the home unwritable first (0500 directories,
//! 0400 files) and requires the import to succeed anyway, so a write that the
//! manifest could somehow miss would still have to fail loudly.
//!
//! # Every launch goes through `checked`
//!
//! Which asserts neither stream carries a needle, refuses a run whose binary
//! dropped a Codex write receipt before the audit log (S34 C2-a), and writes
//! both streams to `AGCTL_E2E_TRACE_DIR` when one is named, so
//! `scripts/phase3-greps.sh --log` scans them.

mod common;

#[path = "common/codex.rs"]
mod codex;

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Output;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use codex::CodexFixture;
use codex::Needle;
use codex::Stream;
use httpmock::Method::GET;
use httpmock::MockServer;
use serde_json::Value;
use serde_json::json;

const USAGE_PATH: &str = "/backend-api/wham/usage";

const USER: &str = "user-import-0001";
const ACCT: &str = "11111111-2222-4333-8444-555555555555";
/// A second identity, for the home that no longer holds what was imported.
const OTHER_USER: &str = "user-import-0002";
const OTHER_ACCT: &str = "66666666-7777-4888-8999-aaaaaaaaaaaa";
const EMAIL: &str = "codex-import@example.invalid";

/// The needles no stream of an import may carry, by name.
const NEEDLES: [Needle; 8] = [
    ("an access token", "agctl-test-codex-at-"),
    ("a refresh token", "agctl-test-codex-rt-"),
    ("an API key", "agctl-test-codex-ak-"),
    ("a JWT", "agctl-test-codex-jwt-"),
    ("an email sentinel", "agctl-test-codex-email-"),
    ("a JWT header", "eyJ"),
    ("a Bearer header", "Bearer "),
    ("a bearer header", "bearer "),
];

fn now_s() -> i64 {
    jiff::Timestamp::now().as_second()
}

fn jwt(payload: &Value, signature: &str) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).expect("serializes"));
    format!("{header}.{body}.{signature}")
}

/// A ChatGPT `auth.json` for `user`/`acct`, with `rt` as its refresh token.
fn auth_doc(user: &str, acct: &str, rt: &str) -> Value {
    let exp = now_s() + 86_400;
    let id_token = jwt(
        &json!({
            "email": EMAIL,
            "https://api.openai.com/auth": {
                "chatgpt_user_id": user,
                "chatgpt_account_id": acct,
                "chatgpt_plan_type": "pro",
            },
            "exp": exp,
        }),
        "agctl-test-codex-jwt-sig",
    );
    json!({
        "auth_mode": "chatgpt",
        "OPENAI_API_KEY": null,
        "tokens": {
            "id_token": id_token,
            "access_token": jwt(&json!({ "exp": exp, "jti": "j" }), "agctl-test-codex-at-sig"),
            "refresh_token": rt,
            "account_id": acct,
        },
        "last_refresh": "2026-09-16T00:00:00Z",
    })
}

fn write_0600(path: &Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
    fs::write(path, bytes).expect("write");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("chmod");
}

fn write_doc(path: &Path, doc: &Value) {
    write_0600(path, &serde_json::to_vec_pretty(doc).expect("serializes"));
}

/// A fixture with tracing on and no route to the vendor.
///
/// The usage seam is pointed at a closed loopback port by default: `import`
/// makes no request at all, and a test that proves that is better served by a
/// port nothing answers than by a mock nobody asserts on.
fn new_fixture() -> CodexFixture {
    let mut fixture = CodexFixture::new();
    fixture.set("AGCTL_CODEX_USAGE_URL", "http://127.0.0.1:1");
    fixture.set("AGCTL_CODEX_TOKEN_URL", "http://127.0.0.1:1");
    fixture.set("RUST_LOG", "agctl=trace");
    fixture
}

/// A Codex home inside the fixture, holding `doc`.
fn home_with(fixture: &CodexFixture, name: &str, doc: &Value) -> PathBuf {
    let home = fixture.codex_home(name);
    write_doc(&home.join("auth.json"), doc);
    home
}

/// The live home's `auth.json`: `$HOME/.codex`, inside the fixture.
fn live_home(fixture: &CodexFixture) -> PathBuf {
    fixture.inner().home().join(".codex")
}

fn checked(fixture: &CodexFixture, name: &str, output: Output) -> Output {
    codex::checked(
        "e2e_codex_import",
        name,
        output,
        &NEEDLES,
        &[Stream::Stdout, Stream::Stderr],
        Some(&fixture.security_log_path()),
    )
}

/// Runs `agctl <args>` through [`checked`]. Every launch in this file is one
/// of these.
fn run(fixture: &CodexFixture, name: &str, args: &[&str]) -> Output {
    checked(fixture, name, fixture.cmd().args(args).output().expect("the binary runs"))
}

/// `agctl codex import --from codex-home --codex-home <home>`, plus `extra`.
fn import(fixture: &CodexFixture, name: &str, home: &Path, extra: &[&str]) -> Output {
    let home = home.to_string_lossy().into_owned();
    let mut args = vec!["codex", "import", "--from", "codex-home", "--codex-home", &home];
    args.extend_from_slice(extra);
    run(fixture, name, &args)
}

/// The registry document, or `None` when the file does not exist.
fn registry(fixture: &CodexFixture) -> Option<Value> {
    let path = fixture.inner().config_dir().join("config.json");
    fs::read(&path).ok().map(|bytes| serde_json::from_slice(&bytes).expect("the registry is JSON"))
}

fn codex_rows(fixture: &CodexFixture) -> Vec<Value> {
    registry(fixture)
        .and_then(|document| document["codex_accounts"].as_array().cloned())
        .unwrap_or_default()
}

/// `(name, is_dir, mode, size, mtime_ns, sha256)` for every entry under `dir`,
/// sorted — the whole observable state of a home, short of its inode numbers.
fn manifest(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        for entry in fs::read_dir(&next).expect("the home is listable").flatten() {
            let path = entry.path();
            let meta = fs::symlink_metadata(&path).expect("stat");
            let digest = if meta.is_file() {
                let bytes = fs::read(&path).expect("readable");
                hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&bytes))
            } else {
                String::new()
            };
            out.push(format!(
                "{} dir={} mode={:o} size={} mtime_ns={} sha256={digest}",
                path.strip_prefix(dir).expect("under dir").display(),
                meta.is_dir(),
                meta.permissions().mode() & 0o777,
                meta.len(),
                meta.mtime() * 1_000_000_000 + meta.mtime_nsec(),
            ));
            if meta.is_dir() {
                stack.push(path);
            }
        }
    }
    out.sort();
    out
}

fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod");
}

#[test]
fn ac106_records_the_home_read_only_with_the_identity_from_its_claims() {
    let fixture = new_fixture();
    let home = home_with(&fixture, "other", &auth_doc(USER, ACCT, "agctl-test-codex-rt-0001"));

    let output = import(&fixture, "records", &home, &[]);
    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));

    let rows = codex_rows(&fixture);
    assert_eq!(rows.len(), 1, "one row: {rows:#?}");
    assert_eq!(rows[0]["chatgpt_user_id"], USER);
    assert_eq!(rows[0]["chatgpt_account_id"], ACCT);
    assert_eq!(rows[0]["email"], EMAIL);
    assert_eq!(rows[0]["plan_type"], "pro");
    assert_eq!(rows[0]["forgotten"], false);
    assert_eq!(rows[0]["kind"]["kind"], "home_read_only");
    assert_eq!(
        Path::new(rows[0]["kind"]["dir"].as_str().expect("a dir")),
        home.canonicalize().expect("canonical"),
        "the recorded dir is the canonical home"
    );

    // Metadata only (decision D-007): the registry file holds no token, and
    // `checked` has already refused either stream carrying one.
    let document = fs::read_to_string(fixture.inner().config_dir().join("config.json"))
        .expect("the registry file");
    for (name, needle) in NEEDLES {
        assert!(!document.contains(needle), "the registry carries {name}");
    }
}

#[test]
fn ac106_writes_nothing_under_the_home_it_reads() {
    // The AC's "0 writes under <dir>", measured twice: once against a normal
    // home, and once against one that is not writable at all.
    let fixture = new_fixture();
    let home = home_with(&fixture, "read-only", &auth_doc(USER, ACCT, "agctl-test-codex-rt-0001"));
    fs::write(home.join("config.toml"), "# nothing agctl sets\n").expect("a config");

    let before = manifest(&home);
    let output = import(&fixture, "no-writes", &home, &[]);
    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(manifest(&home), before, "the import wrote under the home it read");

    // Now with every write refused by the filesystem. The modes are set before
    // the first manifest, so the only difference this can report is one the
    // import made.
    let fixture = new_fixture();
    let home = home_with(&fixture, "sealed", &auth_doc(USER, ACCT, "agctl-test-codex-rt-0001"));
    fs::write(home.join("config.toml"), "# nothing agctl sets\n").expect("a config");
    chmod(&home.join("auth.json"), 0o400);
    chmod(&home.join("config.toml"), 0o400);
    chmod(&home, 0o500);
    let before = manifest(&home);

    let output = import(&fixture, "sealed", &home, &[]);
    let after = manifest(&home);

    chmod(&home, 0o700);
    chmod(&home.join("auth.json"), 0o600);
    chmod(&home.join("config.toml"), 0o600);

    assert_eq!(
        output.status.code(),
        Some(0),
        "an unwritable home is still importable: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(after, before, "the import wrote under a home it could not write");
    assert_eq!(codex_rows(&fixture).len(), 1, "and the account was recorded");
}

#[test]
fn ac106_is_idempotent() {
    let fixture = new_fixture();
    let home = home_with(&fixture, "other", &auth_doc(USER, ACCT, "agctl-test-codex-rt-0001"));

    let first = import(&fixture, "idempotent-1", &home, &[]);
    assert_eq!(first.status.code(), Some(0), "{}", String::from_utf8_lossy(&first.stderr));
    let path = fixture.inner().config_dir().join("config.json");
    let bytes = fs::read(&path).expect("the registry file");
    let meta = fs::metadata(&path).expect("stat");
    let (mtime, mtime_ns) = (meta.mtime(), meta.mtime_nsec());

    let second = import(&fixture, "idempotent-2", &home, &[]);
    assert_eq!(second.status.code(), Some(0), "{}", String::from_utf8_lossy(&second.stderr));
    assert!(
        String::from_utf8_lossy(&second.stdout).contains("already recorded"),
        "{}",
        String::from_utf8_lossy(&second.stdout)
    );
    assert_eq!(codex_rows(&fixture).len(), 1, "no second row");
    assert_eq!(fs::read(&path).expect("the registry file"), bytes, "the registry changed");
    let meta = fs::metadata(&path).expect("stat");
    // C2b-3: both halves of the mtime, not `mtime_nsec()` alone — a rewrite
    // that happened to land in the same nanosecond of a different second would
    // otherwise pass unnoticed. The byte comparison above carries the real
    // weight; this is belt and braces.
    assert_eq!(
        (meta.mtime(), meta.mtime_nsec()),
        (mtime, mtime_ns),
        "the registry was rewritten with the same bytes"
    );
}

#[test]
fn ac106_dry_run_writes_nothing() {
    let fixture = new_fixture();
    let home = home_with(&fixture, "other", &auth_doc(USER, ACCT, "agctl-test-codex-rt-0001"));
    let store = fixture.inner().config_dir();
    let registry_path = store.join("config.json");
    assert!(!registry_path.exists(), "the fixture starts with no registry file");
    let home_before = manifest(&home);
    let store_before = manifest(&store);

    let output = import(&fixture, "dry-run", &home, &["--dry-run"]);

    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--dry-run: nothing was written"), "{stdout}");
    assert!(
        stdout.contains(&home.canonicalize().expect("canonical").display().to_string()),
        "it still says what it would record: {stdout}"
    );
    assert!(!registry_path.exists(), "a store that did not exist still does not");
    assert_eq!(manifest(&home), home_before, "the source home changed");
    assert_eq!(manifest(&store), store_before, "the agctl store changed");
}

#[test]
fn ac106_a_dir_that_is_the_live_home_folds_into_it_when_the_grant_is_the_same() {
    // The AC's "equal → folded": `status` reads one credential twice — once as
    // the live row, once as the imported record — and says so rather than
    // reporting two accounts. The verdict is `pass::finish`'s; `import` does
    // not compute it, which is why this is proved through `status`.
    let server = MockServer::start();
    let usage = server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(200).json_body(usage_body(ACCT));
    });
    let mut fixture = new_fixture();
    fixture.set("AGCTL_CODEX_USAGE_URL", &server.base_url());
    let live = live_home(&fixture);
    write_doc(&live.join("auth.json"), &auth_doc(USER, ACCT, "agctl-test-codex-rt-0001"));

    let output = import(&fixture, "folded-import", &live, &[]);
    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));

    let status = run(&fixture, "folded-status", &["codex", "status", "--json", "--all"]);
    let document: Value = serde_json::from_slice(&status.stdout).expect("stdout is JSON");
    let rows = document["rows"].as_array().expect("rows");

    let imported = row_of_kind(rows, "home_read_only");
    assert_ne!(imported["state"], "stale_sibling_of_live", "{document:#}");
    assert!(
        imported["note"].as_str().unwrap_or_default().contains("same credential as live"),
        "the imported row is folded into the live one: {document:#}"
    );
    assert!(usage.calls() >= 1, "the live row was still read");
}

#[test]
fn ac106_a_dir_that_is_the_live_home_is_a_stale_sibling_once_the_grant_differs() {
    // The AC's "different digests → stale sibling of live": the home was
    // imported while it held one account and now holds another, so the record
    // names something the home no longer has.
    let server = MockServer::start();
    let _usage = server.mock(|when, then| {
        when.method(GET).path(USAGE_PATH);
        then.status(200).json_body(usage_body(OTHER_ACCT));
    });
    let mut fixture = new_fixture();
    fixture.set("AGCTL_CODEX_USAGE_URL", &server.base_url());
    let live = live_home(&fixture);
    write_doc(&live.join("auth.json"), &auth_doc(USER, ACCT, "agctl-test-codex-rt-0001"));

    let output = import(&fixture, "stale-import", &live, &[]);
    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));

    // Someone logs in as a different account in that home.
    write_doc(
        &live.join("auth.json"),
        &auth_doc(OTHER_USER, OTHER_ACCT, "agctl-test-codex-rt-0002"),
    );

    let status = run(&fixture, "stale-status", &["codex", "status", "--json", "--all"]);
    let document: Value = serde_json::from_slice(&status.stdout).expect("stdout is JSON");
    let rows = document["rows"].as_array().expect("rows");
    let imported = row_of_kind(rows, "home_read_only");
    assert_eq!(imported["state"], "stale_sibling_of_live", "{document:#}");
    assert!(imported["usage"].is_null(), "a stale sibling reports no usage: {document:#}");

    // …and it is hidden without `--all`, which is what `--all` is for.
    let plain = run(&fixture, "stale-status-plain", &["codex", "status", "--json"]);
    let plain: Value = serde_json::from_slice(&plain.stdout).expect("stdout is JSON");
    let shown = plain["rows"].as_array().expect("rows");
    assert!(
        shown.iter().all(|row| row["kind"] != "home_read_only"),
        "the stale sibling is shown by default: {plain:#}"
    );
}

/// The one row of `kind` in `rows`.
fn row_of_kind<'a>(rows: &'a [Value], kind: &str) -> &'a Value {
    let mut found = rows.iter().filter(|row| row["kind"] == kind);
    let row = found.next().unwrap_or_else(|| panic!("no `{kind}` row in {rows:#?}"));
    assert!(found.next().is_none(), "more than one `{kind}` row in {rows:#?}");
    row
}

fn usage_body(account: &str) -> Value {
    json!({
        "plan_type": "pro",
        "email": "agctl-test-codex-email-0001",
        "user_id": USER,
        "account_id": account,
        "rate_limit": {
            "allowed": true,
            "limit_reached": false,
            "primary_window": { "used_percent": 42.0, "limit_window_seconds": 18_000, "reset_after_seconds": 3_600 },
            "secondary_window": { "used_percent": 7.0, "limit_window_seconds": 604_800, "reset_after_seconds": 86_400 },
        },
        "credits": { "has_credits": true, "unlimited": false, "balance": "0" },
    })
}

#[test]
fn ac95_the_codex_home_flag_obeys_the_same_rules_as_the_variable() {
    // AC95's set cases, through the binary. The variable itself cannot be
    // tested here — `CodexFixture::set` refuses to put it into a spawned
    // environment (invariant I25) — which is exactly why the flag exists and
    // why its rules must be the same ones.
    let fixture = new_fixture();

    // Set + a directory → canonical, through a symbolic link.
    let real = home_with(&fixture, "real", &auth_doc(USER, ACCT, "agctl-test-codex-rt-0001"));
    let linked = fixture.root().join("linked-home");
    std::os::unix::fs::symlink(&real, &linked).expect("symlink");
    let output = import(&fixture, "ac95-canonical", &linked, &[]);
    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(
        Path::new(codex_rows(&fixture)[0]["kind"]["dir"].as_str().expect("a dir")),
        real.canonicalize().expect("canonical"),
        "the link was recorded instead of its target"
    );

    // Set + missing.
    let fixture = new_fixture();
    let missing = fixture.root().join("not-here");
    let output = import(&fixture, "ac95-missing", &missing, &[]);
    assert_ne!(output.status.code(), Some(0), "a missing home is refused");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--codex-home"), "the refusal names the flag: {stderr}");
    assert!(stderr.contains("does not exist"), "{stderr}");
    assert!(!stderr.contains("CODEX_HOME"), "it blames a variable nobody set: {stderr}");

    // Set + not a directory.
    let file = fixture.root().join("a-file");
    fs::write(&file, b"x").expect("writable");
    let output = import(&fixture, "ac95-not-a-dir", &file, &[]);
    assert_ne!(output.status.code(), Some(0), "a file is refused");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--codex-home") && stderr.contains("not a directory"), "{stderr}");
    assert!(registry(&fixture).is_none(), "a refusal recorded something");
}

#[test]
fn ac95_a_keyring_home_is_refused_without_reading_its_credential() {
    // AC95's "`keyring` → not read, 0 `auth.json` reads", through the binary.
    // The credential is unparseable, so a read would have to be reported as
    // one; the refusal this asserts is the store-mode one.
    let fixture = new_fixture();
    let home = fixture.codex_home("keyring");
    fs::write(home.join("config.toml"), "cli_auth_credentials_store = \"keyring\"\n")
        .expect("a config");
    write_0600(&home.join("auth.json"), b"{ not a credential, and never parsed");

    let output = import(&fixture, "ac95-keyring", &home, &[]);

    assert_ne!(output.status.code(), Some(0), "a keyring home is refused");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("keyring"), "the refusal names the mode: {stderr}");
    assert!(stderr.contains("nothing to import"), "{stderr}");
    assert!(
        !stderr.contains("does not parse") && !stderr.contains("not a credential"),
        "the credential was read after all: {stderr}"
    );
    assert!(registry(&fixture).is_none(), "nothing was recorded");
}

/// The keychain account Codex uses for a home (fact F94):
/// `cli|<first 16 hex digits of sha256(canonical home)>`.
///
/// Spelled here rather than taken from the crate: a test that computed it the
/// way the code does would agree with a wrong implementation. `Fixture::dump`
/// cannot be used for this — it writes `acct="example"`, which matches no
/// home — so the listing is written by hand, in the same format.
fn keyring_account(home: &Path) -> String {
    let canonical = home.canonicalize().unwrap_or_else(|_| home.to_path_buf());
    let digest =
        hex::encode(<sha2::Sha256 as sha2::Digest>::digest(canonical.to_string_lossy().as_bytes()));
    format!("cli|{}", &digest[..16])
}

/// Writes a `security dump-keychain` listing naming one `Codex Auth` item for
/// `account`, in the format the fake `security` prints.
fn write_listing(fixture: &CodexFixture, account: &str) {
    let mut text = String::from(
        "keychain: \"/Users/example/Library/Keychains/login.keychain-db\"\nversion: 512\n",
    );
    text.push_str("class: \"genp\"\nattributes:\n");
    text.push_str("    0x00000007 <blob>=\"Codex Auth\"\n");
    text.push_str(&format!("    \"acct\"<blob>=\"{account}\"\n"));
    text.push_str(
        "    \"cdat\"<timedate>=0x32303236303930383031323030355A00  \"20260908012005Z\\000\"\n",
    );
    text.push_str(
        "    \"mdat\"<timedate>=0x32303236303930383031323030355A00  \"20260908012005Z\\000\"\n",
    );
    text.push_str("    \"svce\"<blob>=\"Codex Auth\"\n");
    text.push_str("    \"type\"<uint32>=<NULL>\n");
    fs::write(fixture.keychain_dump_path(), text).expect("the listing is writable");
}

#[test]
fn ac95_an_auto_home_whose_item_is_listed_is_not_read() {
    // AC95's fourth rule through the binary (fact F94): under `auto` the
    // credential is in the keychain when an item for THIS home is listed, so
    // `auth.json` is not what Codex uses and the import must not record an
    // identity out of it. `status` answers the same question from the same
    // listing, so one home gets one answer from both commands.
    //
    // The credential is poisoned: a read would have to be reported as a parse
    // failure, and the refusal asserted below is the store-mode one. That is
    // how "0 `auth.json` reads" is shown through a binary whose reads a test
    // cannot count.
    let mut fixture = new_fixture();
    fixture.with_keychain();
    let home = fixture.codex_home("auto-listed");
    fs::write(home.join("config.toml"), "cli_auth_credentials_store = \"auto\"\n")
        .expect("a config");
    write_0600(&home.join("auth.json"), b"{ not a credential, and never parsed");
    write_listing(&fixture, &keyring_account(&home));

    let output = import(&fixture, "ac95-auto-listed", &home, &[]);

    assert_ne!(output.status.code(), Some(0), "an `auto` home with a listed item was read");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("auto"), "the refusal names the mode: {stderr}");
    assert!(stderr.contains("nothing to import"), "{stderr}");
    assert!(
        !stderr.contains("does not parse") && !stderr.contains("not a credential"),
        "the credential was read after all: {stderr}"
    );
    assert!(registry(&fixture).is_none(), "nothing was recorded");
}

#[test]
fn ac95_an_auto_home_whose_item_is_not_listed_is_read() {
    // The twin, and the reason the test above proves anything: the same
    // fixture with the listing naming a DIFFERENT home records normally and
    // says which branch ran.
    let mut fixture = new_fixture();
    fixture.with_keychain();
    let home =
        home_with(&fixture, "auto-unlisted", &auth_doc(USER, ACCT, "agctl-test-codex-rt-0001"));
    fs::write(home.join("config.toml"), "cli_auth_credentials_store = \"auto\"\n")
        .expect("a config");
    let elsewhere = fixture.codex_home("someone-else");
    write_listing(&fixture, &keyring_account(&elsewhere));

    let output = import(&fixture, "ac95-auto-unlisted", &home, &[]);

    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("auto (file in effect)"),
        "the note says which branch ran: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(codex_rows(&fixture).len(), 1, "the account was recorded");
}

#[test]
fn an_import_creates_no_codex_tree_in_the_agctl_store() {
    // Plan AC97's posture for this command: `import` takes no namespace lock
    // and writes no credential, so it has no business calling
    // `ensure_codex_dirs`. The registry is the only thing it writes.
    let fixture = new_fixture();
    let home = home_with(&fixture, "other", &auth_doc(USER, ACCT, "agctl-test-codex-rt-0001"));

    let output = import(&fixture, "no-codex-tree", &home, &[]);
    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));

    let store = fixture.inner().config_dir();
    for absent in ["codex/.locks", "codex/.scratch", "codex/.state"] {
        assert!(
            !store.join(absent).exists(),
            "`import` created `{absent}`: {:?}",
            manifest(&store)
        );
    }
    assert!(store.join("config.json").is_file(), "but the registry was written");
}
