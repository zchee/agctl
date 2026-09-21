#![cfg(feature = "testing")]

//! `agctl codex doctor`, driven through the real binary (plan AC108, and the
//! `doctor` halves of AC116, AC117 and AC125).
//!
//! # The home is the fallback, because a test may not name one
//!
//! `doctor` takes no `--codex-home`: it reports the home this machine would
//! resolve. `CodexFixture::set` refuses to put the Codex home variable into a
//! spawned environment (invariant I25), so every home here is
//! `<fixture>/home/.codex` — the fallback path, inside the fixture's own
//! temporary tree, which `CodexFixture::new` asserts is empty before the test
//! starts.
//!
//! # What this file measures rather than asserts
//!
//! Two negatives. [`manifest`] records every entry under the store — relative
//! name, directory flag, mode, size, nanosecond mtime and the SHA-256 of the
//! bytes — and the read-only case compares it across a run, so a write
//! `doctor` might make anywhere under the store fails the test rather than
//! passing unnoticed. And the needles: three of these tests plant a sentinel
//! where a naive report would echo it — in a malformed `config.toml` line, as
//! a **member name** in `auth.json`, and as a `codex-switcher:` keychain
//! service — and every launch goes through [`checked`], which refuses a run
//! whose stdout or stderr carries one.

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
use serde_json::Value;
use serde_json::json;

const USER: &str = "user-doctor-0001";
const ACCT: &str = "11111111-2222-4333-8444-555555555555";

/// The sentinel a malformed `config.toml` line carries (plan AC116).
const CONFIG_NEEDLE: &str = "agctl-test-codex-ak-0002";

/// The sentinel planted as an `auth.json` **member name**, which the field-set
/// comparison must count and never print (premortem PM22).
const MEMBER_NEEDLE: &str = "agctl-test-codex-ak-0004";

/// The sentinel planted as a `codex-switcher:` keychain service, which the
/// report counts and never names (plan AC108).
const SWITCHER_NEEDLE: &str = "agctl-test-codex-email-0009";

/// The needles no stream and no document of a `doctor` run may carry.
const NEEDLES: [Needle; 9] = [
    ("an access token", "agctl-test-codex-at-"),
    ("a refresh token", "agctl-test-codex-rt-"),
    ("an API key", "agctl-test-codex-ak-"),
    ("a JWT", "agctl-test-codex-jwt-"),
    ("an email sentinel", "agctl-test-codex-email-"),
    ("a JWT header", "eyJ"),
    ("a Bearer header", "Bearer "),
    ("a bearer header", "bearer "),
    ("a multi-auth credential", "agctl-test-codex-multiauth-"),
];

/// Asserts neither stream carries a needle, then keeps both for the log sweep.
fn checked(fixture: &CodexFixture, name: &str, output: Output) -> Output {
    codex::checked(
        "e2e_codex_doctor",
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

/// `agctl codex doctor`, as a table.
fn doctor(fixture: &CodexFixture, name: &str) -> String {
    let output = run(fixture, name, &["codex", "doctor"]);
    assert!(output.status.success(), "`codex doctor` failed: {output:?}");
    String::from_utf8(output.stdout).expect("the table is UTF-8")
}

/// `agctl codex doctor --json`, parsed and validated against the schema.
fn doctor_json(fixture: &CodexFixture, name: &str) -> Value {
    let output = run(fixture, name, &["codex", "doctor", "--json"]);
    assert!(output.status.success(), "`codex doctor --json` failed: {output:?}");
    let document: Value = serde_json::from_slice(&output.stdout).expect("the report is JSON");
    validate(&document);
    document
}

/// The published schema, compiled in so a rename fails here rather than
/// silently validating against nothing.
const SCHEMA: &str = include_str!("../schemas/codex-doctor.v1.json");

fn validate(document: &Value) {
    let schema: Value = serde_json::from_str(SCHEMA).expect("the schema is JSON");
    let validator = jsonschema::validator_for(&schema).expect("the schema compiles");
    let errors: Vec<String> = validator
        .iter_errors(document)
        .map(|err| format!("{}: {err}", err.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "the report does not match schemas/codex-doctor.v1.json:\n{}",
        errors.join("\n")
    );
}

/// The Codex home this machine resolves to, inside the fixture.
fn live_home(fixture: &CodexFixture) -> PathBuf {
    let home = fixture.inner().home().join(".codex");
    fs::create_dir_all(&home).expect("the fallback home");
    home
}

/// The namespace directory `<store>/codex/<user>/<acct>`.
fn namespace(fixture: &CodexFixture) -> PathBuf {
    fixture.inner().config_dir().join("codex").join(USER).join(ACCT)
}

/// The Codex write log, `<store>/codex/writes.jsonl`.
fn audit_log(fixture: &CodexFixture) -> PathBuf {
    fixture.inner().config_dir().join("codex").join("writes.jsonl")
}

fn write_0600(path: &Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
    fs::write(path, bytes).expect("write");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("chmod");
}

/// Writes a registry holding `codex_rows`.
fn registry(fixture: &CodexFixture, codex_rows: Vec<Value>) {
    fixture.inner().write_registry_document(&json!({
        "version": 2,
        "accounts": [],
        "forgotten_services": [],
        "codex_accounts": codex_rows,
    }));
}

/// An owned record for `(USER, ACCT)`.
fn owned_row() -> Value {
    json!({
        "chatgpt_user_id": USER,
        "chatgpt_account_id": ACCT,
        "email": null,
        "plan_type": null,
        "label": null,
        "kind": { "kind": "owned", "export_spelling": "/x", "refresh": "auto" },
        "forgotten": false,
        "created_at": "2026-09-22T00:00:00Z",
    })
}

/// A JWT in the shape the claims parser reads, with `signature` as its third
/// segment.
fn jwt(payload: &Value, signature: &str) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).expect("serializes"));
    format!("{header}.{body}.{signature}")
}

/// A ChatGPT `auth.json` whose every token is a sentinel.
///
/// The two JWTs are real enough to decode — the claims parser refuses a
/// document whose id token does not — and each carries a needle in its
/// signature, so a report that echoed one would be caught by [`checked`].
fn auth_document() -> Value {
    let exp = jiff::Timestamp::now().as_second() + 86_400;
    json!({
        "auth_mode": "chatgpt",
        "OPENAI_API_KEY": null,
        "tokens": {
            "id_token": jwt(
                &json!({
                    "email": "agctl-test-codex-email-0001",
                    "https://api.openai.com/auth": {
                        "chatgpt_user_id": USER,
                        "chatgpt_account_id": ACCT,
                        "chatgpt_plan_type": "pro",
                    },
                    "exp": exp,
                }),
                "agctl-test-codex-jwt-doctor",
            ),
            "access_token": jwt(&json!({ "exp": exp }), "agctl-test-codex-at-doctor"),
            "refresh_token": "agctl-test-codex-rt-doctor",
            "account_id": ACCT,
        },
        "last_refresh": "2026-09-20T00:00:00Z",
    })
}

/// `cli|<first 16 hex of sha256(canonical home)>`, the account Codex gives a
/// home's keychain item (fact F94). Computed here rather than imported: an
/// integration test sees only the binary.
fn keyring_account(home: &Path) -> String {
    let canonical = home.canonicalize().unwrap_or_else(|_| home.to_path_buf());
    let digest =
        hex::encode(<sha2::Sha256 as sha2::Digest>::digest(canonical.to_string_lossy().as_bytes()));
    format!("cli|{}", &digest[..16])
}

/// Writes a `dump-keychain` listing in `security(1)`'s own format.
///
/// `Fixture::dump` writes `acct="example"` for every item; a `Codex Auth`
/// item's account is the home hash, and matching it is the whole of plan
/// AC95's `auto` case, so the listing is written here instead.
fn keychain_listing(fixture: &CodexFixture, items: &[(&str, &str)]) {
    let mut text = String::from(
        "keychain: \"/Users/example/Library/Keychains/login.keychain-db\"\nversion: 512\n",
    );
    for (service, account) in items {
        text.push_str("class: \"genp\"\nattributes:\n");
        text.push_str(&format!("    0x00000007 <blob>=\"{service}\"\n"));
        text.push_str(&format!("    \"acct\"<blob>=\"{account}\"\n"));
        text.push_str(&format!("    \"svce\"<blob>=\"{service}\"\n"));
        text.push_str("    \"type\"<uint32>=<NULL>\n");
    }
    fs::write(fixture.keychain_dump_path(), text).expect("the listing is writable");
}

/// Moves `path`'s modification time `seconds` into the past.
///
/// Through `rustix`, which this crate already depends on, rather than a new
/// development dependency for one call.
fn age_by(path: &Path, seconds: i64) {
    let then = jiff::Timestamp::now().as_second() - seconds;
    let when = rustix::fs::Timespec { tv_sec: then, tv_nsec: 0 };
    rustix::fs::utimensat(
        rustix::fs::CWD,
        path,
        &rustix::fs::Timestamps { last_access: when, last_modification: when },
        rustix::fs::AtFlags::empty(),
    )
    .expect("the modification time is settable");
}

/// `(name, dir, mode, size, mtime_ns, sha256)` for every entry under `dir`,
/// sorted; empty when the directory does not exist.
fn manifest(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        let Ok(entries) = fs::read_dir(&next) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            let meta = fs::symlink_metadata(&path).expect("stat");
            let digest = if meta.is_file() {
                hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
                    fs::read(&path).unwrap_or_default(),
                ))
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

// ---------------------------------------------------------------------------

#[test]
fn the_report_names_every_item_and_validates_against_the_schema() {
    // Plan AC108, in one run: a planted `multi-auth/` and a `codex-switcher:`
    // item are both counted and neither is named; `config-keyring.toml` gives
    // `keyring (not read)`; a non-`auth.json` entry in an owned namespace is
    // `codex session artefacts present`; a credential that is not 0600 warns;
    // `CODEX_API_KEY` is `present` and never its value; and the write log's
    // last lines are rendered.
    let mut fixture = CodexFixture::new();
    fixture.with_keychain();
    fixture.set("CODEX_API_KEY", "agctl-test-codex-ak-0005");
    let home = live_home(&fixture);

    fs::write(home.join("config.toml"), "cli_auth_credentials_store = \"keyring\"\n")
        .expect("a config");
    write_0600(&home.join("auth.json"), &serde_json::to_vec(&auth_document()).expect("bytes"));
    fs::set_permissions(home.join("auth.json"), fs::Permissions::from_mode(0o644)).expect("chmod");
    fs::create_dir_all(home.join("multi-auth")).expect("a multi-auth dir");
    fs::write(home.join("multi-auth").join("auth.json"), "agctl-test-codex-multiauth-0001")
        .expect("a foreign credential");
    keychain_listing(
        &fixture,
        &[
            ("Codex Auth", &keyring_account(&home)),
            (&format!("codex-switcher:{SWITCHER_NEEDLE}"), "example"),
        ],
    );

    registry(&fixture, vec![owned_row()]);
    let dir = namespace(&fixture);
    write_0600(&dir.join("auth.json"), br#"{"auth_mode":"chatgpt"}"#);
    fs::create_dir_all(dir.join("sessions")).expect("a Codex session artefact");
    write_0600(
        &audit_log(&fixture),
        format!(
            "{}\n{}\n",
            json!({"ts":"2026-09-22T00:00:00Z","agctl_pid":1,"provider":"codex","user_id":USER,"account_id":ACCT,"outcome":"applied"}),
            json!({"ts":"2026-09-22T00:01:00Z","agctl_pid":1,"provider":"codex","user_id":USER,"account_id":ACCT,"outcome":"login_overwrite"}),
        )
        .as_bytes(),
    );

    let table = doctor(&fixture, "every-item");
    let document = doctor_json(&fixture, "every-item-json");

    assert_eq!(document["store"]["mode"], json!("keyring"), "{table}");
    assert_eq!(document["store"]["read"], json!("not read"), "{table}");
    assert_eq!(document["live"]["state"], json!("not read"), "{table}");
    assert_eq!(document["foreign"]["multi_auth_present"], json!(true), "{table}");
    assert_eq!(document["foreign"]["switcher_items"], json!(1), "{table}");
    assert_eq!(document["foreign"]["codex_auth_items"], json!(1), "{table}");
    let artefacts = document["namespaces"][0]["artefacts"].to_string();
    assert!(artefacts.contains("codex session artefacts present"), "{artefacts}");
    assert_eq!(document["audit"].as_array().expect("an array").len(), 2, "{table}");
    let api_key = document["environment"]
        .as_array()
        .expect("an array")
        .iter()
        .find(|var| var["name"] == json!("CODEX_API_KEY"))
        .expect("the variable is listed");
    assert_eq!(api_key["present"], json!(true));
    assert!(table.contains("profiles not consulted"), "{table}");

    // The names the report must never carry, on top of the needle sweep every
    // launch already ran.
    let rendered = format!("{table}\n{document}");
    assert!(!rendered.contains("multi-auth/auth.json"), "the directory was listed");
    assert!(!rendered.contains(SWITCHER_NEEDLE), "a switcher item was named");

    // The only `security` subcommand a Codex report issues is the read-only
    // listing (plan AC109, ledger #121), and it reads neither the planted
    // item nor the `multi-auth/` file.
    let calls = fixture.inner().security_log();
    assert!(!calls.is_empty(), "the listing was never taken");
    for line in &calls {
        assert!(
            line.contains("dump-keychain"),
            "a Codex doctor run issued something other than a listing: {line}"
        );
    }
}

#[test]
fn a_credential_that_is_read_is_reported_by_its_shape_only() {
    // The `file` half of the run above: the document is read, and what comes
    // out of it is a mode, a size, an expiry, an auth mode and two counts.
    let mut fixture = CodexFixture::new();
    fixture.with_keychain();
    let home = live_home(&fixture);
    let mut document = auth_document();
    document.as_object_mut().expect("an object").insert(MEMBER_NEEDLE.to_owned(), json!("value"));
    write_0600(&home.join("auth.json"), &serde_json::to_vec(&document).expect("bytes"));

    let table = doctor(&fixture, "shape-only");
    let report = doctor_json(&fixture, "shape-only-json");

    assert_eq!(report["live"]["state"], json!("credentials"), "{table}");
    assert_eq!(report["live"]["auth_mode"], json!("chatgpt"), "{table}");
    assert_eq!(report["live"]["mode_bits"], json!("0600"), "{table}");
    // Premortem PM22 under the S35 ruling: the member the file added is a
    // count, and the missing ones are names from the binary's own list.
    assert_eq!(report["live"]["unknown_member_count"], json!(1), "{table}");
    let missing = report["live"]["missing_known_members"].to_string();
    assert!(missing.contains("bedrock_api_key"), "{missing}");
    assert!(!table.contains(MEMBER_NEEDLE), "a member name was printed");
    assert!(!report.to_string().contains(MEMBER_NEEDLE), "a member name reached --json");
}

#[test]
fn a_malformed_config_is_reported_by_line_number_and_never_quoted() {
    // Plan AC116's e2e half. The bad line carries a key, and `toml`'s own
    // message quotes the line it stopped on.
    let mut fixture = CodexFixture::new();
    fixture.with_keychain();
    let home = live_home(&fixture);
    fs::write(
        home.join("config.toml"),
        format!("model = 'gpt-test'\n\n[mcp_servers.x.env]\nKEY = \"{CONFIG_NEEDLE}\n"),
    )
    .expect("a config");

    let table = doctor(&fixture, "malformed-config");
    let report = doctor_json(&fixture, "malformed-config-json");

    let note = report["store"]["config_note"].as_str().expect("a note");
    assert!(note.starts_with("unparseable config.toml (line "), "{note}");
    assert!(table.contains("unparseable config.toml (line "), "{table}");
    assert!(!table.contains(CONFIG_NEEDLE), "the line was echoed to the table");
    assert!(!report.to_string().contains(CONFIG_NEEDLE), "the line reached --json");
}

#[test]
fn a_well_formed_config_holding_a_key_is_never_echoed_either() {
    // AC116's second half: the file parses, and the value sits in a member
    // agctl does not read.
    let mut fixture = CodexFixture::new();
    fixture.with_keychain();
    let home = live_home(&fixture);
    fs::write(
        home.join("config.toml"),
        format!(
            "cli_auth_credentials_store = 'file'\n\n[mcp_servers.x.env]\nKEY = \"{CONFIG_NEEDLE}\"\n"
        ),
    )
    .expect("a config");

    let table = doctor(&fixture, "mcp-key-config");
    let report = doctor_json(&fixture, "mcp-key-config-json");

    assert_eq!(report["store"]["mode"], json!("file"), "{table}");
    assert!(report["store"]["config_note"].is_null(), "a parsing file has no note");
    assert!(!table.contains(CONFIG_NEEDLE));
    assert!(!report.to_string().contains(CONFIG_NEEDLE));
}

#[test]
fn the_three_login_orphans_are_reported() {
    // Plan AC125's `doctor` half: a namespace with no record, a record whose
    // namespace holds no credential, and a scratch directory older than the
    // login deadline plus five minutes, with `scratch.lock` free.
    let mut fixture = CodexFixture::new();
    fixture.with_keychain();
    live_home(&fixture);
    registry(&fixture, vec![owned_row()]);

    let codex_root = fixture.inner().config_dir().join("codex");
    // A namespace no record explains.
    fs::create_dir_all(codex_root.join("user-orphan-0002").join(ACCT)).expect("a namespace");
    // The recorded namespace exists and holds nothing.
    fs::create_dir_all(namespace(&fixture)).expect("the recorded namespace");
    // A scratch directory left by a login that died, aged past the sweep.
    let scratch = codex_root.join(".scratch").join("agctl-codex-login-deadbeef");
    fs::create_dir_all(&scratch).expect("a scratch dir");
    age_by(&scratch, 30 * 60);
    assert!(
        !codex_root.join(".locks").join("scratch.lock").exists(),
        "no login is running, so the scratch lock is free"
    );

    let table = doctor(&fixture, "orphans");
    let report = doctor_json(&fixture, "orphans-json");

    let kinds: Vec<&str> = report["orphans"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|orphan| orphan["kind"].as_str().expect("a kind"))
        .collect();
    assert!(kinds.contains(&"namespace without record"), "{kinds:?}\n{table}");
    assert!(kinds.contains(&"record without auth.json"), "{kinds:?}\n{table}");
    assert!(kinds.contains(&"stale scratch"), "{kinds:?}\n{table}");
    assert!(table.contains("agctl-codex-login-deadbeef"), "{table}");
}

#[test]
fn every_write_path_the_log_records_is_rendered() {
    // Plan AC117's `doctor` half (invariant I30): each outcome the Codex
    // writers append is shown, through the same reader `agctl claude doctor`
    // uses for its own log.
    let mut fixture = CodexFixture::new();
    fixture.with_keychain();
    live_home(&fixture);
    registry(&fixture, vec![owned_row()]);

    let outcomes = [
        "applied",
        "saved_to_pending",
        "discarded_external",
        "pending_replayed",
        "pending_discarded",
        "login_install",
        "login_overwrite",
        "delete",
        "adopted_external",
        "ambiguous",
    ];
    let lines: Vec<String> = outcomes
        .iter()
        .map(|outcome| {
            json!({
                "ts": "2026-09-22T00:00:00Z",
                "agctl_pid": 1,
                "provider": "codex",
                "user_id": USER,
                "account_id": ACCT,
                "outcome": outcome,
            })
            .to_string()
        })
        .collect();
    write_0600(&audit_log(&fixture), format!("{}\n", lines.join("\n")).as_bytes());

    let table = doctor(&fixture, "write-log");
    let report = doctor_json(&fixture, "write-log-json");

    let rendered = report["audit"].to_string();
    for outcome in outcomes {
        assert!(rendered.contains(outcome), "the log line for `{outcome}` is not rendered");
    }
    assert!(table.contains("login_overwrite"), "{table}");
    assert!(!rendered.contains('@'), "an audit line carries an address");
}

#[test]
fn a_run_changes_nothing_and_creates_nothing() {
    // The C3 carry (ledger #469), measured: a report over a seeded store
    // leaves every byte and every modification time where it was, and a
    // report over a store with no Codex tree at all does not make one.
    let mut fixture = CodexFixture::new();
    fixture.with_keychain();
    let home = live_home(&fixture);
    write_0600(&home.join("auth.json"), &serde_json::to_vec(&auth_document()).expect("bytes"));
    registry(&fixture, vec![owned_row()]);
    let dir = namespace(&fixture);
    write_0600(&dir.join("auth.json"), br#"{"auth_mode":"chatgpt"}"#);
    write_0600(&dir.join("auth.json.pending"), br#"{"auth_mode":"chatgpt"}"#);
    write_0600(&dir.join("auth.json.tmp.0badc0de"), b"{}");
    let state = fixture.inner().config_dir().join("codex").join(".state");
    write_0600(
        &state.join(format!("{USER}+{ACCT}.refresh")),
        json!({
            "schema": 1,
            "inflight": { "sent_digest8": "0123abcd", "sent_at": "2026-09-21T00:00:00Z" },
            "floor_min": 60,
            "did_not_help": 1,
            "ambiguous_since": "2026-09-21T00:00:00Z",
            "class": "tls",
            "resent": false,
        })
        .to_string()
        .as_bytes(),
    );

    let store = fixture.inner().config_dir();
    let before = manifest(&store);
    let home_before = manifest(&home);
    let table = doctor(&fixture, "read-only");
    let report = doctor_json(&fixture, "read-only-json");
    let after = manifest(&store);
    let home_after = manifest(&home);

    assert_eq!(before, after, "a `doctor` run changed the store");
    assert_eq!(home_before, home_after, "a `doctor` run changed the Codex home");
    assert_eq!(report["namespaces"][0]["marker"]["state"], json!("present"), "{table}");
    assert_eq!(report["namespaces"][0]["marker"]["class"], json!("tls"), "{table}");
    assert_eq!(report["namespaces"][0]["marker"]["inflight_digest8"], json!("0123abcd"));
    let artefacts = report["namespaces"][0]["artefacts"].to_string();
    assert!(artefacts.contains("stray tmp (rotated grant?)"), "{artefacts}");
    assert!(artefacts.contains("a parked pending write"), "{artefacts}");
    assert!(table.contains("re-arms one refresh send per namespace"), "{table}");

    // The second half: a store that has never held a Codex tree.
    let mut clean = CodexFixture::new();
    clean.with_keychain();
    live_home(&clean);
    let table = doctor(&clean, "no-tree");
    assert!(
        !clean.inner().config_dir().join("codex").exists(),
        "a `doctor` run created a `codex/` tree:\n{table}"
    );
    assert!(table.contains("owned namespaces\n  none"), "{table}");
}

#[test]
fn a_keychain_account_agctl_did_not_write_never_reaches_a_command() {
    // Review S35 C1, end to end. The `acct` attribute of a keychain item is
    // set by whoever created the item, and `doctor` offers a removal command
    // for an item it cannot explain — something a reader pastes into a shell.
    // Four hostile spellings are planted: a needle, a command substitution, a
    // backtick and an ANSI escape. None may appear in the table, in `--json`
    // or in a command, and `checked` fails the run on the needle by itself.
    let mut fixture = CodexFixture::new();
    fixture.with_keychain();
    // The home must resolve, so that the well-formed account below is foreign
    // to it rather than foreign for want of a home to compare against.
    live_home(&fixture);
    // S35 C6: the command-substitution payload targets a path INSIDE the
    // fixture, never a shared `/tmp` path another concurrent run could also
    // write.
    let ran = fixture.root().join("command-substitution-ran");
    let hostile = [
        "agctl-test-codex-ak-0006".to_owned(),
        format!("cli|$(id > {})", ran.display()),
        "cli|`id`".to_owned(),
        "cli|\u{1b}]0;pwned\u{7}".to_owned(),
    ];
    let mut items: Vec<(&str, &str)> = vec![("Codex Auth", "cli|00112233abcdefff")];
    items.extend(hostile.iter().map(|account| ("Codex Auth", account.as_str())));
    keychain_listing(&fixture, &items);

    let table = doctor(&fixture, "hostile-account");
    let report = doctor_json(&fixture, "hostile-account-json");

    // The one well-formed foreign account still gets its command...
    let removals = report["foreign"]["unexplained_removals"].as_array().expect("an array");
    assert_eq!(removals.len(), 1, "{removals:?}");
    assert_eq!(
        removals[0],
        json!("security delete-generic-password -s \"Codex Auth\" -a \"cli|00112233abcdefff\"")
    );
    // ...and every other one is a count and a sentence.
    assert_eq!(report["foreign"]["unnameable_items"], json!(hostile.len()), "{table}");
    assert!(table.contains("agctl will not print an account string it did not make"), "{table}");

    let rendered = format!("{table}\n{report}");
    for account in &hostile {
        assert!(
            !rendered.contains(account.as_str()),
            "an account agctl did not write reached a stream"
        );
    }
    for fragment in ["$(id", "`id`", "\u{1b}]0;"] {
        assert!(!rendered.contains(fragment), "`{fragment}` reached a stream");
    }
    assert!(!ran.exists(), "a planted account ran");
}

#[test]
fn a_home_that_cannot_be_resolved_still_produces_a_report() {
    // The command reports what is wrong rather than refusing to report: the
    // fallback home does not exist at all here.
    let mut fixture = CodexFixture::new();
    fixture.with_keychain();

    let table = doctor(&fixture, "no-home");
    let report = doctor_json(&fixture, "no-home-json");

    assert_eq!(report["live"]["state"], json!("absent"), "{table}");
    assert!(table.contains("codex home"), "{table}");
}
