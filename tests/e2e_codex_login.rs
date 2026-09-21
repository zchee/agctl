#![cfg(feature = "testing")]

//! `agctl codex login` through the real binary (plan AC105, AC126).
//!
//! The vendor's CLI is `fixtures/fake-codex.sh`, wired through
//! `AGCTL_CODEX_BIN` and asserted to live inside the fixture. **With no knobs
//! set the fake reproduces what fact F81 measured a normal, successful
//! `codex login` to leave behind** — an unheld `tmp/arg0/codex-arg0<rand>/.lock`,
//! three symlinks and a login log, in the modes F81 measured — and it records a
//! `residue` line, so the happy path here proves that a login leaving a real
//! login's mess still installs, rather than assuming the fixture did its part.
//!
//! **Keychain.** `Fixture::new` disables the keychain for every test, so a test
//! here that does not call `with_keychain()` runs keychain-less: both listings
//! are empty. The tests named `ac105_keychain_*` wire the fake `security` and
//! exercise the two real listings — the F95 backstop.
//!
//! # The trace capture
//!
//! Every run goes through [`checked`], which asserts neither stream carries a
//! needle and, when `AGCTL_E2E_TRACE_DIR` names a directory, writes both
//! streams there as `e2e_codex_login-<name>.{stdout,stderr}` so
//! `scripts/phase3-greps.sh --log` scans them. The child's stdio is inherited
//! by design (the vendor prints its URL there), so the captured streams hold
//! the fake's output too.

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

const USER: &str = "user-login-0001";
const ACCT: &str = "acct-login-0001";
const EMAIL: &str = "codex-login@example.invalid";

/// The refresh token and the JWT signature the fixture's documents carry.
const REFRESH_TOKEN: &str = "agctl-test-codex-login-rt-0001";
const JWT_SIGNATURE: &str = "agctl-test-codex-login-sig";

/// Strings that must never appear on either stream of a login run, by name.
const NEEDLES: [Needle; 5] = [
    ("the refresh token", REFRESH_TOKEN),
    ("the JWT signature", JWT_SIGNATURE),
    ("a JWT header", "eyJ"),
    ("a Bearer header", "Bearer "),
    ("a bearer header", "bearer "),
];

fn jwt(payload: &Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).expect("serializes"));
    format!("{header}.{body}.{JWT_SIGNATURE}")
}

/// A ChatGPT-mode `auth.json` the fake writes into its scratch home.
fn auth_doc(user: &str, acct: &str, mode: &str) -> Value {
    let exp = jiff::Timestamp::now().as_second() + 3600;
    json!({
        "auth_mode": mode,
        "OPENAI_API_KEY": null,
        "tokens": {
            "id_token": jwt(&json!({
                "email": EMAIL,
                "https://api.openai.com/auth": {
                    "chatgpt_user_id": user,
                    "chatgpt_account_id": acct,
                    "chatgpt_plan_type": "pro",
                },
                "exp": exp,
            })),
            "access_token": jwt(&json!({ "exp": exp, "jti": "j" })),
            "refresh_token": REFRESH_TOKEN,
            "account_id": acct,
        },
        "last_refresh": "2026-09-16T00:00:00Z",
    })
}

/// Writes `doc` where the fake will read it, and points the fake at it.
fn arm(fixture: &mut CodexFixture, name: &str, doc: &Value) -> PathBuf {
    let path = fixture.root().join(name);
    fs::write(&path, serde_json::to_vec_pretty(doc).expect("serializes")).expect("writable");
    fixture.set("AGCTL_FAKE_CODEX_AUTH", &path.to_string_lossy());
    path
}

/// A fixture with the fake's log wired and a valid ChatGPT document armed.
fn armed() -> (CodexFixture, PathBuf) {
    let mut fixture = CodexFixture::new();
    let log = fixture.codex_log_path();
    fixture.set("AGCTL_FAKE_CODEX_LOG", &log.to_string_lossy());
    let doc = arm(&mut fixture, "login-doc.json", &auth_doc(USER, ACCT, "chatgpt"));
    (fixture, doc)
}

/// Asserts neither stream carries a needle and captures both streams.
fn checked(fixture: &CodexFixture, name: &str, output: Output) -> Output {
    codex::checked(
        "e2e_codex_login",
        name,
        output,
        &NEEDLES,
        &[Stream::Stdout, Stream::Stderr],
        Some(&fixture.security_log_path()),
    )
}

/// The shared `checked` reports a leaked needle by NAME and byte offset, and
/// never prints the value or the stream around it (the positive control that
/// its report is safe to put in a failure log).
#[test]
fn checked_reports_a_needle_by_name_and_offset_never_by_value() {
    use std::os::unix::process::ExitStatusExt;

    let refused = |test: &str, stdout: String, stderr: String| {
        let leaky = Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: stdout.into_bytes(),
            stderr: stderr.into_bytes(),
        };
        // The `;` makes the closure return `()`: when `checked` does NOT
        // refuse, `expect_err` prints that `()`, never the `Output` (both
        // streams, the needle included).
        let report = std::panic::catch_unwind(|| {
            codex::checked("e2e_codex_login", test, leaky, &NEEDLES, &[], None);
        })
        .expect_err("a stream carrying a needle is refused");
        report
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| report.downcast_ref::<&str>().map(|text| (*text).to_owned()))
            .unwrap_or_default()
    };
    // The whole report is pinned: it names the test, the stream, the
    // needle's NAME and its offset, and nothing else — not the value, not
    // the text around it. Each value guard runs BEFORE its `assert_eq!`,
    // whose failure would print the report.
    let first = refused("positive-control", format!("before {REFRESH_TOKEN} after"), String::new());
    assert!(!first.contains(REFRESH_TOKEN), "the report printed the needle's value");
    assert_eq!(first, "positive-control: stdout carries the needle `the refresh token` at byte 7");
    // stderr is scanned too, not only stdout.
    let on_stderr =
        refused("positive-control-stderr", "clean".to_owned(), format!("x {JWT_SIGNATURE} y"));
    assert!(!on_stderr.contains(JWT_SIGNATURE), "the report printed the needle's value");
    assert_eq!(
        on_stderr,
        "positive-control-stderr: stderr carries the needle `the JWT signature` at byte 2"
    );
    // Every needle is scanned, not only the first: the LAST one alone.
    let last = refused("positive-control-last", "abc bearer xyz".to_owned(), String::new());
    assert_eq!(
        last,
        "positive-control-last: stdout carries the needle `a bearer header` at byte 4"
    );

    // The twin: clean streams pass and come back unchanged.
    let clean = Output {
        status: std::process::ExitStatus::from_raw(0),
        stdout: b"nothing to see".to_vec(),
        stderr: b"nor here".to_vec(),
    };
    let back =
        codex::checked("e2e_codex_login", "positive-control-clean", clean, &NEEDLES, &[], None);
    assert_eq!(back.stdout, b"nothing to see");
    assert_eq!(back.stderr, b"nor here");
}

/// The shared `checked` also refuses a run whose binary dropped a Codex write
/// receipt before the audit log, by name rather than as a wrong exit code.
///
/// C2-a's e2e twin. The check itself lives in the binary and is proven to fire
/// by `auth_store_tests::a_receipt_dropped_before_the_audit_log_fails_the_test_
/// that_drops_it`; what is proven here is the other half — that its line on
/// stderr fails the e2e test that saw it, including one that expected the run
/// to refuse. The real binary is not driven into the state on purpose: no
/// production path reaches it, and a fault seam that created one would be a
/// seam whose only user is its own test.
#[test]
fn checked_refuses_a_run_that_dropped_a_write_receipt() {
    use std::os::unix::process::ExitStatusExt;

    // Exit 2 — a refusal — so the case is the one a status assertion misses.
    let aborted = Output {
        status: std::process::ExitStatus::from_raw(2 << 8),
        stdout: Vec::new(),
        stderr: b"agctl unaudited write receipt: Delete was dropped before codex::audit::append\n"
            .to_vec(),
    };
    let report = std::panic::catch_unwind(|| {
        codex::checked("e2e_codex_login", "positive-control-receipt", aborted, &NEEDLES, &[], None);
    })
    .expect_err("a run that dropped a receipt is refused");
    let report = report
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| report.downcast_ref::<&str>().map(|text| (*text).to_owned()))
        .unwrap_or_default();
    assert_eq!(
        report,
        "positive-control-receipt: the binary dropped a Codex write receipt before the audit log: \
         agctl unaudited write receipt: Delete was dropped before codex::audit::append"
    );

    // The other door: two Codex e2e launches read an exit status rather than
    // an `Output` and call the rejection directly (`e2e_codex::run`, and the
    // signalled pass in `e2e_codex_status`). Same helper, so prove the same
    // message arrives through it.
    let direct = std::panic::catch_unwind(|| {
        codex::assert_receipts_were_audited(
            "positive-control-receipt",
            b"agctl unaudited write receipt: Delete was dropped before codex::audit::append\n",
        );
    })
    .expect_err("the exported rejection refuses it too");
    assert_eq!(
        direct
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| direct.downcast_ref::<&str>().map(|text| (*text).to_owned()))
            .unwrap_or_default(),
        report,
        "both doors report the same thing"
    );

    // The twin: a clean stderr passes through both.
    codex::assert_receipts_were_audited("positive-control-clean-receipt", b"nothing to see here");
}

/// Runs `agctl codex login` through [`checked`].
fn login(fixture: &CodexFixture, name: &str) -> Output {
    checked(
        fixture,
        name,
        fixture.cmd().args(["codex", "login"]).output().expect("the binary runs"),
    )
}

/// Drops the registry row for `(USER, ACCT)` — the credential and its
/// namespace stay where they are.
///
/// S34 C4 gave `login` AC107's confirmation, so a second login over an
/// account agctl **owns** now refuses without a terminal. A test that needs
/// the install to happen a second time therefore removes the record first,
/// which is the same state AC105's crash window leaves: a namespace with
/// nothing claiming it, which `login` adopts.
fn drop_the_record(fixture: &CodexFixture, name: &str) {
    let output = checked(
        fixture,
        name,
        fixture
            .cmd()
            .args(["codex", "accounts", "remove", &format!("{USER}/{ACCT}")])
            .output()
            .expect("the binary runs"),
    );
    assert!(output.status.success(), "{}", stderr(&output));
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The namespace `login` installs into.
fn namespace(fixture: &CodexFixture, user: &str, acct: &str) -> PathBuf {
    fixture.inner().config_dir().join("codex").join(user).join(acct)
}

/// The scratch root, which must be empty after every run.
fn scratch_root(fixture: &CodexFixture) -> PathBuf {
    fixture.inner().config_dir().join("codex").join(".scratch")
}

/// Every scratch home left behind.
fn scratch_leaves(fixture: &CodexFixture) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(scratch_root(fixture)) else { return Vec::new() };
    entries.flatten().map(|entry| entry.path()).collect()
}

/// The fake `codex`'s log.
fn codex_log(fixture: &CodexFixture) -> String {
    fs::read_to_string(fixture.codex_log_path()).expect("the fake logged its run")
}

/// A directory OUTSIDE the scratch that the fake links to from inside its
/// residue (order C3). A cleanup that followed a link inside the scratch home
/// would reach it; the file inside must survive every login byte-identical.
fn sentinel(fixture: &mut CodexFixture) -> PathBuf {
    let dir = fixture.root().join("sentinel");
    fs::create_dir_all(&dir).expect("mkdir");
    fs::write(dir.join("keep.txt"), b"a live home agctl must never empty").expect("write");
    fixture.set("AGCTL_FAKE_CODEX_SENTINEL", &dir.to_string_lossy());
    dir
}

fn assert_sentinel_untouched(dir: &Path, name: &str) {
    assert_eq!(
        fs::read(dir.join("keep.txt"))
            .unwrap_or_else(|err| panic!("{name}: the sentinel was emptied: {err}")),
        b"a live home agctl must never empty",
        "{name}: nothing behind a link inside the scratch home was touched"
    );
}

/// Asserts a refusal installed nothing and left no scratch home.
fn assert_nothing_installed(fixture: &CodexFixture, name: &str) {
    assert!(
        !namespace(fixture, USER, ACCT).join("auth.json").exists(),
        "{name}: nothing is installed"
    );
    assert!(scratch_leaves(fixture).is_empty(), "{name}: the scratch home is removed");
}

#[test]
fn ac105_a_login_that_leaves_a_normal_logins_residue_installs() {
    // Fact F81 / ledger #310. The fake's default run leaves the measured
    // residue, including an UNHELD `.lock`. A survivor check keyed on a lock
    // file's existence would refuse this, and every real login with it.
    let (mut fixture, doc) = armed();
    let sentinel = sentinel(&mut fixture);

    let output = login(&fixture, "residue-installs");
    assert!(output.status.success(), "{}", stderr(&output));
    assert_sentinel_untouched(&sentinel, "residue-installs");

    // The positive control: this test ran against the residue, not against an
    // empty home. Mutant: the fake leaves no default residue — red here.
    let log = codex_log(&fixture);
    assert!(
        log.lines().any(|line| line.starts_with("residue tmp/arg0/codex-arg0")
            && line.ends_with("/.lock")),
        "the fake left F81's residue:\n{log}"
    );

    let installed = namespace(&fixture, USER, ACCT).join("auth.json");
    let want = fs::read(&doc).expect("the fake's document is readable");
    let got = fs::read(&installed).expect("the credential was installed");
    assert_eq!(got, want, "the installed bytes are the ones `verify_login` parsed");

    let mode = fs::metadata(&installed).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "a credential is 0600 before it is visible");

    assert!(scratch_leaves(&fixture).is_empty(), "the scratch home is removed on success");
}

#[test]
fn ac105_the_install_is_a_copy_not_a_rename() {
    // Architect M5: the namespace receives the verified bytes written through
    // writer 1's primitive, so it is a different inode from the source.
    let (fixture, doc) = armed();
    let before = fs::metadata(&doc).expect("metadata").ino();

    let output = login(&fixture, "copy-not-rename");
    assert!(output.status.success(), "{}", stderr(&output));

    let installed = namespace(&fixture, USER, ACCT).join("auth.json");
    let after = fs::metadata(&installed).expect("metadata").ino();
    assert_ne!(after, before, "the install copies; it does not move the fake's document");
}

#[test]
fn ac105_the_child_sees_exactly_the_allowlist_and_no_decoy() {
    // Decision D-037. The fake records its environment by NAME, and values for
    // only the three the assertions need. The decoy is a name the allowlist
    // must drop that does NOT start with `KACHE_`: an `assert_cmd` failure
    // prints every variable a test set, and a `KACHE_` name there would trip
    // the leak gate on a failure log (ledger #339).
    let (mut fixture, _doc) = armed();
    fixture.set("AWS_SECRET_ACCESS_KEY", "decoy-value-must-not-appear");
    fixture.set("CODEX_API_KEY", "decoy-value-must-not-appear");
    // A value that spans lines, in a variable the `testing` pass-through lets
    // reach the child: its second line must never be recorded as a name.
    fixture.set("AGCTL_FAKE_CODEX_MULTILINE", "first\nenv DECOY_FROM_A_VALUE");

    let output = login(&fixture, "allowlist");
    assert!(output.status.success(), "{}", stderr(&output));

    let log = codex_log(&fixture);
    let names: Vec<&str> = log.lines().filter_map(|line| line.strip_prefix("env ")).collect();

    assert!(!names.contains(&"AWS_SECRET_ACCESS_KEY"), "a cloud credential name reached the child");
    assert!(!names.contains(&"CODEX_API_KEY"), "an API key name reached the child");
    assert!(names.contains(&"CODEX_HOME"), "the child is told which home to use");
    assert!(names.contains(&"PATH"), "the child keeps PATH");

    assert!(
        names.contains(&"AGCTL_FAKE_CODEX_MULTILINE"),
        "the multi-line decoy reached the child (the positive control for the next line)"
    );
    assert!(
        !log.contains("DECOY_FROM_A_VALUE"),
        "a line of a multi-line VALUE was recorded as a name"
    );

    // Values for exactly the named three, and never a decoy's.
    assert!(!log.contains("decoy-value-must-not-appear"), "a decoy VALUE reached the log");
    let mut valued: Vec<&str> = log
        .lines()
        .filter_map(|line| line.strip_prefix("value "))
        .map(|rest| rest.split('=').next().unwrap_or_default())
        .collect();
    valued.sort_unstable();
    assert_eq!(
        valued,
        ["CODEX_HOME", "HOME", "TMPDIR"],
        "the values recorded are exactly the three"
    );
    // Under direnv this also proves any real, inherited `KACHE_*` name was
    // dropped: agctl inherits the test runner's environment.
    assert_eq!(log.matches("KACHE_").count(), 0, "no KACHE_ name appears anywhere in the record");
}

#[test]
fn ac105_the_lowercase_proxy_names_reach_the_child_and_nothing_else_new() {
    // D-037's list names the uppercase proxy variables only, and a machine
    // that exports only the lowercase spellings — the ones Rust's HTTP stacks
    // read — could not log in at all. The four are on the list now. What this
    // proves through the real binary is both halves at once: the child sees
    // them, and it sees nothing else that it did not see before, which is the
    // half a unit test over `allowed_env` cannot state about the shipped
    // environment-building path.
    let names_recorded = |log: &str| -> Vec<String> {
        let mut names: Vec<String> =
            log.lines().filter_map(|line| line.strip_prefix("env ")).map(str::to_owned).collect();
        names.sort();
        names
    };

    let (baseline_fixture, _baseline_doc) = armed();
    let baseline = login(&baseline_fixture, "proxy-lowercase-baseline");
    assert!(baseline.status.success(), "{}", stderr(&baseline));
    let before = names_recorded(&codex_log(&baseline_fixture));

    let (mut fixture, _doc) = armed();
    fixture.set("http_proxy", "http://proxy.invalid:3128");
    fixture.set("https_proxy", "http://proxy.invalid:3128");
    fixture.set("no_proxy", "localhost");
    fixture.set("all_proxy", "socks5://proxy.invalid:1080");
    // A spelling on neither list, set alongside them: the allowlist compares
    // exact names, so this one must not ride in with its neighbours.
    fixture.set("Https_Proxy", "http://proxy.invalid:3128");

    let output = login(&fixture, "proxy-lowercase");
    assert!(output.status.success(), "{}", stderr(&output));
    let after = names_recorded(&codex_log(&fixture));

    for name in ["http_proxy", "https_proxy", "no_proxy", "all_proxy"] {
        assert!(after.iter().any(|seen| seen == name), "the child never saw `{name}`: {after:?}");
    }

    let added: Vec<&str> = after
        .iter()
        .filter(|name| !before.iter().any(|seen| seen == *name))
        .map(String::as_str)
        .collect();
    assert_eq!(
        added,
        ["all_proxy", "http_proxy", "https_proxy", "no_proxy"],
        "the child sees exactly the four new names and nothing else new"
    );
    let dropped: Vec<&str> = before
        .iter()
        .filter(|name| !after.iter().any(|seen| seen == *name))
        .map(String::as_str)
        .collect();
    assert!(dropped.is_empty(), "the four cost the child a name it had before: {dropped:?}");
}

#[test]
fn ac105_the_child_runs_in_its_scratch_home_and_is_given_it() {
    // Order A4: the child's working directory is its scratch home, so no
    // `.codex/` Project config layer (fact F95) from wherever agctl was started
    // reaches it. And `CODEX_HOME` names that same directory.
    let (fixture, _doc) = armed();

    let output = login(&fixture, "cwd");
    assert!(output.status.success(), "{}", stderr(&output));

    let log = codex_log(&fixture);
    let cwd = log.lines().find_map(|line| line.strip_prefix("cwd ")).expect("cwd recorded");
    let home = log
        .lines()
        .find_map(|line| line.strip_prefix("value CODEX_HOME="))
        .expect("the fake records which home it was given");
    let root = fs::canonicalize(scratch_root(&fixture)).expect("the scratch root exists");
    let cwd = PathBuf::from(cwd);
    let parent = cwd.parent().map(|p| fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf()));
    assert_eq!(
        parent.as_deref(),
        Some(root.as_path()),
        "the child runs in a scratch leaf: {cwd:?}"
    );
    assert_eq!(cwd.file_name(), Path::new(home).file_name(), "the same leaf `CODEX_HOME` names");
}

#[test]
fn ac105_the_child_gets_the_measured_argv() {
    // S28 / fact F95 measured `codex -c '<override>' login`. The override is a
    // request, not a guarantee, which is why the second keychain listing is
    // mandatory; it must still be sent, in the order that was measured.
    let (fixture, _doc) = armed();

    let output = login(&fixture, "argv");
    assert!(output.status.success(), "{}", stderr(&output));

    let log = codex_log(&fixture);
    // One `arg` line per argument: the override and its `-c` are two words,
    // never the one word `-c cli_auth…` that a `$*` record could not tell apart.
    let argv: Vec<&str> = log.lines().filter_map(|line| line.strip_prefix("arg ")).collect();
    assert_eq!(argv, ["-c", "cli_auth_credentials_store=\"file\"", "login"]);
}

#[test]
fn ac105_a_child_that_fails_installs_nothing_and_leaves_no_scratch() {
    let (mut fixture, _doc) = armed();
    fixture.set("AGCTL_FAKE_CODEX_EXIT", "3");

    let output = login(&fixture, "child-fails");
    assert!(!output.status.success(), "a failed child is refused");
    assert_nothing_installed(&fixture, "child-fails");
}

#[test]
fn ac105_an_apikey_login_is_refused_because_it_has_no_usage_source() {
    let mut fixture = CodexFixture::new();
    let log = fixture.codex_log_path();
    fixture.set("AGCTL_FAKE_CODEX_LOG", &log.to_string_lossy());
    arm(&mut fixture, "apikey.json", &auth_doc(USER, ACCT, "apikey"));

    let output = login(&fixture, "apikey");
    assert!(!output.status.success(), "an apikey login is refused");
    assert_nothing_installed(&fixture, "apikey");
}

#[test]
fn ac105_a_child_that_starts_a_daemon_is_refused() {
    let (mut fixture, _doc) = armed();
    fixture.set("AGCTL_FAKE_CODEX_DAEMON_DIR", "1");
    let sentinel = sentinel(&mut fixture);

    let output = login(&fixture, "daemon");
    assert!(!output.status.success(), "a child that started a daemon is refused");
    assert_nothing_installed(&fixture, "daemon");
    // `Drop` runs on a refusal too, over the same child-written tree.
    assert_sentinel_untouched(&sentinel, "daemon");
}

#[test]
fn ac105_a_child_that_leaves_a_held_lock_is_refused() {
    // The other half of the residue test: an unheld lock installs, a HELD one
    // refuses. The fake holds it with a real `flock` from a live process.
    let (mut fixture, _doc) = armed();
    fixture.set("AGCTL_FAKE_CODEX_HELD_LOCK", "1");

    let output = login(&fixture, "held-lock");

    // The child SUCCEEDED — it is the lock it left that is refused. This test
    // once passed while running a child that had failed (its holder never
    // reported in), which is exactly what this line now rules out.
    assert!(codex_log(&fixture).lines().any(|line| line == "exit 0"), "the child exited 0");
    let text = stderr(&output);
    assert!(!output.status.success(), "a held lock is refused");
    assert!(text.contains("held"), "and the refusal names the held lock: {text}");
    assert_nothing_installed(&fixture, "held-lock");
}

#[test]
fn ac105_keychain_a_normal_login_takes_exactly_two_listings_and_installs() {
    // AC105: "the fake `security` log shows two `dump-keychain` invocations
    // per login". The twin of the two refusals below.
    let (mut fixture, _doc) = armed();
    fixture.with_keychain();

    let output = login(&fixture, "keychain-two-listings");
    assert!(output.status.success(), "{}", stderr(&output));

    let log = fs::read_to_string(fixture.security_log_path()).expect("the fake security logged");
    let dumps = log.lines().filter(|line| line.starts_with("dump-keychain")).count();
    assert_eq!(dumps, 2, "one listing before the child and one after:\n{log}");
    assert!(namespace(&fixture, USER, ACCT).join("auth.json").exists(), "and it installed");
}

#[test]
fn ac105_keychain_a_child_that_creates_a_codex_auth_item_is_refused() {
    // Fact F95: the `-c` override is outranked by legacy-managed layers, so the
    // second listing is the only thing that catches a child which stored its
    // credential in the keychain anyway. The fake appends one `Codex Auth`
    // record to the dump between the two listings. Mutant: serve listing #2
    // from listing #1's memo — the gain is invisible and this goes red.
    let (mut fixture, _doc) = armed();
    fixture.with_keychain();
    let dump = fixture.keychain_dump_path();
    fixture.set("AGCTL_FAKE_CODEX_KEYCHAIN_GAIN", &dump.to_string_lossy());

    let output = login(&fixture, "keychain-gain");

    let text = stderr(&output);
    assert!(!output.status.success(), "a child that created a keychain item is refused");
    assert!(text.contains("Codex Auth"), "the refusal names the kind of item: {text}");
    assert!(text.contains("cli|0123456789abcdef"), "and the item itself: {text}");
    assert!(
        !text.contains("agctl would not have written"),
        "a well-spelled item is named, not counted: {text}"
    );
    assert_nothing_installed(&fixture, "keychain-gain");

    // agctl deletes no keychain item, so the only way this one can ever be
    // cleaned up is by hand — and `doctor` offers that command for an item
    // agctl's own log says agctl caused. The refusal is where that is known,
    // so the refusal writes it down. Mutant: delete the
    // `record_gained_keychain_items` call in `login.rs` — red here.
    assert_eq!(audit_outcomes(&fixture), ["login_keychain_gained"], "the gain is recorded");
    assert_eq!(
        audit_keychain_accounts(&fixture),
        ["cli|0123456789abcdef"],
        "the line names the item, and nothing else"
    );
}

#[test]
fn ac105_keychain_an_item_a_child_gained_is_named_only_in_agctls_spelling() {
    // The write-side guard on a credential path: what the second listing
    // gained is a string from outside agctl, and `doctor` will put it inside
    // a command a person pastes into a shell. A spelling agctl would not have
    // written reaches no log line at all — so `doctor` can never name it.
    let (mut fixture, _doc) = armed();
    fixture.with_keychain();
    let dump = fixture.keychain_dump_path();
    fixture.set("AGCTL_FAKE_CODEX_KEYCHAIN_GAIN", &dump.to_string_lossy());
    fixture.set("AGCTL_FAKE_CODEX_KEYCHAIN_GAIN_ACCOUNT", "cli|0123456789abcdef\"; id; \"");

    let output = login(&fixture, "keychain-gain-hostile");

    assert!(!output.status.success(), "a child that created a keychain item is refused");
    assert!(audit_keychain_accounts(&fixture).is_empty(), "a hostile spelling reached the log");
    let text = stderr(&output);
    assert!(text.contains("Codex Auth"), "the refusal still names the kind of item: {text}");
    // Review S37-b1, carry 3: the refusal SENTENCE carried the raw account
    // too, and that sentence goes to the user's terminal. The value guard
    // runs before the message-shape assertion, so a regression cannot leak
    // through this test's own failure output.
    assert!(!text.contains("; id; "), "a hostile account reached standard error");
    assert!(
        text.contains("agctl would not have written"),
        "the refusal counts what it will not name: {text}"
    );
    assert_nothing_installed(&fixture, "keychain-gain-hostile");
}

#[test]
fn ac105_keychain_a_second_listing_that_fails_is_a_refusal() {
    // Order A3: an unreadable second listing refuses — it never reads as
    // "nothing gained". The fake `codex` creates a marker, and the fake
    // `security` fails every dump once that marker exists, so the first
    // listing succeeds and the second exits 36 (a locked keychain).
    let (mut fixture, _doc) = armed();
    fixture.with_keychain();
    let marker = fixture.root().join("second-dump-fails");
    fixture.set("AGCTL_FAKE_CODEX_TOUCH", &marker.to_string_lossy());
    fixture.set("AGCTL_FAKE_SECURITY_DUMP_EXIT_IF", &marker.to_string_lossy());

    let output = login(&fixture, "keychain-second-fails");

    let text = stderr(&output);
    assert!(!output.status.success(), "a keychain that cannot be read afterwards refuses");
    assert!(text.contains("after the login"), "and says when: {text}");
    assert_nothing_installed(&fixture, "keychain-second-fails");
}

/// Runs a login that stops at the pause point before `install`, lets `during`
/// act on the scratch home, then releases it.
///
/// No sleep decides anything, and nothing is inferred. `Fault::pause_point`
/// creates `<resume>.reached` before it waits, so the swapper acts only once it
/// has PROOF that agctl is held at `pause_codex_login_before_install` — between
/// `verify_login` and `install`. Delete the pause, or rename it, and the marker
/// never appears: the swapper fails loudly instead of racing the install.
fn run_paused_before_install(
    fixture: &CodexFixture,
    name: &str,
    during: impl FnOnce(&Path) + Send,
) -> Output {
    let resume = fixture.root().join("resume");
    let reached = fixture.root().join("resume.reached");
    let installed = namespace(fixture, USER, ACCT).join("auth.json");
    let root = scratch_root(fixture);
    let output = std::thread::scope(|scope| {
        scope.spawn(|| {
            let start = std::time::Instant::now();
            while !reached.exists() && start.elapsed() < std::time::Duration::from_secs(10) {
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            assert!(reached.exists(), "{name}: agctl never reported reaching the pause");
            assert!(!installed.exists(), "{name}: agctl is held BEFORE the install, not after it");
            let leaf = fs::read_dir(&root)
                .expect("the scratch root exists")
                .flatten()
                .map(|entry| entry.path())
                .next()
                .expect("the scratch home is still there while agctl waits");
            during(&leaf);
            fs::write(&resume, b"go").expect("the resume file is writable");
        });
        fixture
            .cmd()
            .env("AGCTL_FAULT", "pause_codex_login_before_install")
            .env("AGCTL_FAULT_RESUME", &resume)
            .args(["codex", "login"])
            .output()
            .expect("the binary runs")
    });
    checked(fixture, name, output)
}

/// Architect M5: a scratch document swapped while agctl is paused between
/// `verify_login` and `install` never reaches the namespace, because the
/// install copies the bytes that were verified. Mutant: install re-reads
/// `<scratch>/auth.json` — each mode below goes red on its own (the symlink one
/// because the no-follow read refuses it outright).
fn assert_swap_after_verification_is_ignored(mode: &str) {
    let (fixture, doc) = armed();
    let other = fixture.root().join("other.json");
    let other_bytes =
        serde_json::to_vec_pretty(&auth_doc("user-swapped", "acct-swapped", "chatgpt"))
            .expect("serializes");
    fs::write(&other, &other_bytes).expect("writable");
    let record = fixture.root().join("swapped");

    let output = run_paused_before_install(&fixture, &format!("swap-{mode}"), |leaf| {
        let auth = leaf.join("auth.json");
        let inode = fs::metadata(&auth).expect("the verified file is there").ino();
        match mode {
            "symlink" => {
                fs::remove_file(&auth).expect("unlink");
                std::os::unix::fs::symlink(&other, &auth).expect("symlink");
                assert!(fs::symlink_metadata(&auth).expect("lstat").file_type().is_symlink());
            }
            "replace" => {
                fs::remove_file(&auth).expect("unlink");
                fs::write(&auth, &other_bytes).expect("write");
                assert_ne!(fs::metadata(&auth).expect("stat").ino(), inode, "a new inode");
            }
            _ => {
                fs::write(&auth, &other_bytes).expect("rewrite in place");
                assert_eq!(fs::metadata(&auth).expect("stat").ino(), inode, "the same inode");
            }
        }
        assert_eq!(fs::read(&auth).expect("readable"), other_bytes, "the swap landed");
        // The positive control: the swap really happened inside the
        // window, while agctl waited, not after the scratch was gone.
        fs::write(&record, format!("swapped {mode}\n")).expect("record");
    });

    assert_eq!(
        fs::read_to_string(&record).expect("the swapper ran"),
        format!("swapped {mode}\n"),
        "{mode}: the swap happened while agctl was paused"
    );
    assert!(output.status.success(), "{mode}: {}", stderr(&output));
    let installed = namespace(&fixture, USER, ACCT).join("auth.json");
    let got = fs::read(&installed).unwrap_or_else(|err| panic!("{mode}: {err}"));
    assert_eq!(got, fs::read(&doc).expect("readable"), "{mode}: the verified bytes landed");
    assert!(
        !namespace(&fixture, "user-swapped", "acct-swapped").exists(),
        "{mode}: the swapped identity never became a namespace"
    );
}

#[test]
fn ac126_a_scratch_document_swapped_for_a_symlink_never_lands() {
    assert_swap_after_verification_is_ignored("symlink");
}

#[test]
fn ac126_a_scratch_document_replaced_by_another_file_never_lands() {
    assert_swap_after_verification_is_ignored("replace");
}

#[test]
fn ac126_a_scratch_document_rewritten_in_place_never_lands() {
    assert_swap_after_verification_is_ignored("inplace");
}

#[test]
fn ac126_a_failed_install_rename_leaves_the_previous_grant_byte_identical() {
    // `codex_install_rename_fail` is the install's own fault name. Install
    // passes `pending: None`, so there is no pending fallback: the previous
    // credential simply survives.
    let (mut fixture, doc) = armed();
    let first_run = login(&fixture, "rename-fail-first");
    assert!(first_run.status.success(), "{}", stderr(&first_run));
    let installed = namespace(&fixture, USER, ACCT).join("auth.json");
    let first = fs::read(&installed).expect("installed");
    assert_eq!(first, fs::read(&doc).expect("readable"));

    drop_the_record(&fixture, "rename-fail-drop-record");
    fixture.set("AGCTL_FAULT", "codex_install_rename_fail");
    let second = login(&fixture, "rename-fail-second");
    fixture.set("AGCTL_FAULT", "");

    assert!(!second.status.success(), "a failed rename is reported");
    assert_eq!(fs::read(&installed).expect("still there"), first, "the previous grant survives");
    assert!(scratch_leaves(&fixture).is_empty(), "and the scratch home is removed");
}

#[test]
fn ac105_a_login_audits_an_install_and_then_an_overwrite() {
    // The source-reading rule that pins "every receipt reaches
    // `codex::audit::append`" cannot see `install(` receipts today (bead
    // `agctl-meqv`, S34 C1b), so the behaviour is pinned here. Mutant: drop
    // the receipt in `login.rs` instead of calling `audit::append` — red here.
    let (fixture, _doc) = armed();

    let first_run = login(&fixture, "audit-install");
    assert!(first_run.status.success(), "{}", stderr(&first_run));
    assert_eq!(audit_outcomes(&fixture), ["login_install"], "a first login is an install");

    drop_the_record(&fixture, "audit-drop-record");
    let second_run = login(&fixture, "audit-overwrite");
    assert!(second_run.status.success(), "{}", stderr(&second_run));
    assert_eq!(
        audit_outcomes(&fixture),
        ["login_install", "login_overwrite"],
        "a second login over the same namespace is an overwrite"
    );
}

#[test]
fn a1_a_symlinked_scratch_root_is_refused_and_nothing_behind_it_is_swept() {
    // Reviewer C1a F1, end to end. `ensure_codex_dirs` trusts an existing
    // `.scratch` — a symlink included — so the root must be judged before the
    // sweep, the one destructive operation on it, ever runs. Here it is a link
    // to a directory holding an aged, scratch-shaped subdirectory: the login is
    // refused, and that subdirectory survives.
    let (fixture, _doc) = armed();
    let target = fixture.root().join("somewhere-else");
    let aged = target.join("agctl-codex-login-0000d00d");
    fs::create_dir_all(&aged).expect("mkdir");
    // 0700, like an honest scratch root: the LINK must be the only reason left
    // to refuse. Against a 0755 target, a verifier that followed the link would
    // still refuse — on the mode — and this test could not tell the difference.
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).expect("chmod 0700");
    let when = std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(60 * 60))
        .expect("representable");
    fs::File::open(&aged)
        .expect("opens")
        .set_times(fs::FileTimes::new().set_modified(when))
        .expect("aged");
    let codex_root = fixture.inner().config_dir().join("codex");
    fs::create_dir_all(&codex_root).expect("mkdir");
    fs::set_permissions(&codex_root, fs::Permissions::from_mode(0o700)).expect("chmod");
    std::os::unix::fs::symlink(&target, codex_root.join(".scratch")).expect("symlink");

    let output = login(&fixture, "symlinked-root");

    let text = stderr(&output);
    assert!(!output.status.success(), "a symlinked scratch root is refused");
    assert!(text.contains("symbolic link"), "and the refusal says why: {text}");
    assert!(aged.exists(), "nothing behind the link was swept");
    assert!(!fixture.codex_log_path().exists(), "and no child was ever started");
}

/// The `outcome` of every line in the Codex audit log, oldest first.
fn audit_outcomes(fixture: &CodexFixture) -> Vec<String> {
    let log = fixture.inner().config_dir().join("codex").join("writes.jsonl");
    let Ok(text) = fs::read_to_string(&log) else { return Vec::new() };
    text.lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter_map(|value| value.get("outcome")?.as_str().map(str::to_owned))
        .collect()
}

/// The `keychain_account` of every line the Codex write log holds.
fn audit_keychain_accounts(fixture: &CodexFixture) -> Vec<String> {
    let log = fixture.inner().config_dir().join("codex").join("writes.jsonl");
    let Ok(text) = fs::read_to_string(&log) else { return Vec::new() };
    text.lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter_map(|value| value.get("keychain_account")?.as_str().map(str::to_owned))
        .collect()
}

/// Writes a same-identity `auth.json` into the live home, so the F82 notice
/// ("this home already holds that account") prints — the re-login case.
fn live_home_holds_the_same_account(fixture: &CodexFixture) {
    let live = fixture.inner().home().join(".codex");
    fs::create_dir_all(&live).expect("mkdir");
    let path = live.join("auth.json");
    fs::write(&path, serde_json::to_vec_pretty(&auth_doc(USER, ACCT, "chatgpt")).expect("json"))
        .expect("write");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
}

#[test]
fn c1_a_closed_stdout_never_decides_whether_the_credential_is_removed() {
    // Order C1 / reviewer probe P-ABORT. `println!` panics when stdout is a
    // pipe whose reader has gone, and under `panic = "abort"` that panic skips
    // the `Scratch` drop, leaving a verified credential in the scratch home.
    // Mutant: put `println!` back for the notice — this run aborts (SIGABRT)
    // and the scratch keeps `auth.json`.
    //
    // The positive control first: with a normal stdout, this fixture's state
    // really does make agctl print the notice, so the closed-stdout run below
    // exercises the write that used to panic.
    let (control, _doc) = armed();
    live_home_holds_the_same_account(&control);
    let shown = login(&control, "closed-stdout-control");
    assert!(shown.status.success(), "{}", stderr(&shown));
    assert!(
        String::from_utf8_lossy(&shown.stdout).contains("already holds this same account"),
        "the same-identity notice prints in this state"
    );

    let (fixture, _doc) = armed();
    live_home_holds_the_same_account(&fixture);
    let mut command = fixture.raw();
    command.args(["codex", "login"]);
    let mut child = command.spawn().expect("the binary starts");
    // The closed reader: agctl's first write to stdout meets EPIPE. The fake
    // `codex` inherits this stdout too; it writes nothing there.
    drop(child.stdout.take());
    drop(child.stdin.take());
    let output =
        checked(&fixture, "closed-stdout", child.wait_with_output().expect("the binary ends"));

    use std::os::unix::process::ExitStatusExt;
    assert_ne!(
        output.status.signal(),
        Some(libc::SIGABRT),
        "a closed stdout must not abort: {}",
        stderr(&output)
    );
    assert!(scratch_leaves(&fixture).is_empty(), "and the scratch home is removed");
    assert!(
        namespace(&fixture, USER, ACCT).join("auth.json").exists(),
        "the login still installed"
    );
}

/// Blocks the namespace's refresh marker with a non-empty directory, so the
/// install's refresh-state reset fails and agctl logs its `warn!` — the
/// tracing event that sits inside the window between the child's write and the
/// post-install unlink.
fn block_the_refresh_marker(fixture: &CodexFixture) {
    let marker = fixture
        .inner()
        .config_dir()
        .join("codex")
        .join(".state")
        .join(format!("{USER}+{ACCT}.refresh"));
    fs::create_dir_all(&marker).expect("a directory where the marker file goes");
    fs::write(marker.join("occupied"), b"x").expect("make it non-empty");
}

#[test]
fn e1_a_closed_stderr_never_decides_whether_the_credential_is_removed() {
    // Order E1 / reviewer probe P-STDERR-real. The tracing subscriber reports a
    // write it could not deliver with `eprintln!` on the same broken stderr,
    // which panics — and under `panic = "abort"` that skips the `Scratch` drop.
    // `main.rs` builds it with `log_internal_errors(false)`, so an
    // undeliverable log line is dropped instead. Mutant: remove that line —
    // this run aborts (SIGABRT) and the scratch keeps a verified `auth.json`.
    //
    // The positive control first: with a normal stderr, this fixture's state
    // really does make agctl log inside the window.
    let (control, _doc) = armed();
    block_the_refresh_marker(&control);
    let shown = login(&control, "closed-stderr-control");
    assert!(shown.status.success(), "{}", stderr(&shown));
    assert!(
        stderr(&shown).contains("the refresh marker could not be reset after a login install"),
        "the in-window warning is logged in this state: {}",
        stderr(&shown)
    );
    assert!(scratch_leaves(&control).is_empty(), "and the scratch home is removed");

    let (fixture, _doc) = armed();
    block_the_refresh_marker(&fixture);
    let mut command = fixture.raw();
    command.args(["codex", "login"]);
    let mut child = command.spawn().expect("the binary starts");
    // The closed reader: agctl's first write to stderr meets EPIPE. The fake
    // `codex` inherits this stderr too; on the happy path it writes nothing.
    drop(child.stderr.take());
    drop(child.stdin.take());
    let output =
        checked(&fixture, "closed-stderr", child.wait_with_output().expect("the binary ends"));

    use std::os::unix::process::ExitStatusExt;
    assert_ne!(output.status.signal(), Some(libc::SIGABRT), "a closed stderr must not abort");
    assert!(scratch_leaves(&fixture).is_empty(), "and the scratch home is removed");
}

/// S36's owed e2e half of AC105 (`p3-s34-review-request.md` §8): `Scratch::create`
/// registers `<scratch>/auth.json` with `runtime::cleanup` **before** the child
/// spawns. Holding the login at [`run_paused_before_install`]'s pause proves the
/// registration already covers the file the fake wrote — a document that exists
/// only because the child ran — and a SIGTERM there proves the registration is
/// live, not merely present: the signal handler (`signals.rs`) runs the
/// emergency cleanup and removes it, with nothing installed.
#[test]
fn ac105_a_sigterm_while_paused_before_install_removes_the_registered_scratch_document() {
    let (mut fixture, _doc) = armed();
    let resume = fixture.root().join("resume");
    let reached = fixture.root().join("resume.reached");
    fixture.set("AGCTL_FAULT", "pause_codex_login_before_install");
    fixture.set("AGCTL_FAULT_RESUME", &resume.to_string_lossy());

    let mut command = fixture.raw();
    command
        .args(["codex", "login"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command.spawn().expect("the binary starts");

    let start = std::time::Instant::now();
    while !reached.exists() && start.elapsed() < std::time::Duration::from_secs(10) {
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    assert!(reached.exists(), "agctl never reported reaching the pause before install");

    let root = scratch_root(&fixture);
    let leaf = fs::read_dir(&root)
        .expect("the scratch root exists")
        .flatten()
        .map(|entry| entry.path())
        .next()
        .expect("the scratch home the fake wrote into still exists while agctl waits");
    let scratch_auth = leaf.join("auth.json");
    assert!(
        scratch_auth.is_file(),
        "the scratch document must exist before a signal here proves anything"
    );

    let pid = rustix::process::Pid::from_raw(i32::try_from(child.id()).expect("a pid fits an i32"))
        .expect("a live pid");
    rustix::process::kill_process(pid, rustix::process::Signal::TERM)
        .expect("the signal is delivered");
    let status = child.wait().expect("the child is waitable");

    use std::os::unix::process::ExitStatusExt;
    assert!(!status.success(), "a SIGTERM exit is not success");
    assert_ne!(status.signal(), Some(libc::SIGABRT), "a SIGTERM must not abort");
    assert!(
        !scratch_auth.exists(),
        "the registered scratch document survived a SIGTERM taken before the spawn"
    );
    // Only the registered document is the emergency cleanup's job (invariant
    // AC105's "the file is gone", not "the scratch tree is gone"): the rest of
    // the scratch home's residue — `Scratch::drop`'s ordinary job — is not
    // reached by a signal handler that never unwinds through it.
    assert!(leaf.is_dir(), "the scratch home itself is a `Scratch::drop` matter, not this one");
    assert!(!namespace(&fixture, USER, ACCT).join("auth.json").exists(), "nothing was installed");
}

/// AC126 (d'): a re-login over a namespace already in the terminal 401 state
/// resets its refresh marker — `install` calls `reset_for_login` under the
/// guard (S30), which S36 proves end to end with a real 401 fixture rather than
/// by reading the unit test alone.
#[test]
fn ac126_a_relogin_over_a_terminal_namespace_resets_its_refresh_state() {
    let (fixture, _doc) = armed();
    let first = login(&fixture, "relogin-terminal-first");
    assert!(first.status.success(), "{}", stderr(&first));

    let marker_path = fixture
        .inner()
        .config_dir()
        .join("codex")
        .join(".state")
        .join(format!("{USER}+{ACCT}.refresh"));
    fs::create_dir_all(marker_path.parent().expect("a parent")).expect("mkdir");
    // A terminal 401 state (plan AC114): three counted failures, a raised
    // floor, and an already-spent re-send — everything `install`'s reset must
    // clear.
    fs::write(
        &marker_path,
        json!({ "schema": 1, "floor_min": 240, "did_not_help": 3, "resent": true }).to_string(),
    )
    .expect("the marker is writable");
    fs::set_permissions(&marker_path, fs::Permissions::from_mode(0o600)).expect("chmod");

    drop_the_record(&fixture, "relogin-terminal-drop-record");
    let second = login(&fixture, "relogin-terminal-second");
    assert!(second.status.success(), "{}", stderr(&second));

    let marker: Value =
        serde_json::from_slice(&fs::read(&marker_path).expect("the marker still exists"))
            .expect("the marker parses");
    assert_eq!(marker["did_not_help"], json!(0), "the terminal count is reset: {marker}");
    assert_eq!(marker["floor_min"], json!(60), "the floor is reset: {marker}");
    assert_eq!(marker["resent"], json!(false), "the spent re-send is reset: {marker}");
    assert!(
        marker.get("inflight").is_none_or(Value::is_null),
        "no send is left in flight: {marker}"
    );
}

#[test]
fn an_odd_lock_the_child_named_is_reported_without_its_name_reaching_stderr() {
    // Review S37-b1b F2, from the reviewer's own probe. `is_lock_name` is
    // only `ends_with(".lock")`, so the login child chooses these bytes, and
    // `anomalies()` joined the full paths into the sentence agctl prints.
    let (mut fixture, _doc) = armed();
    fixture.set("AGCTL_FAKE_CODEX_ODD_LOCK", "PROBEODD\u{1b}]0;pwned\u{7}$(id).lock");

    let text = stderr(&login(&fixture, "odd-lock-hostile"));

    for shape in ["PROBEODD", "\u{1b}]0;", "$(id)"] {
        assert!(!text.contains(shape), "an odd-lock path reached stderr: shape {shape:?}");
    }
    // The anomaly is still REPORTED: the guard hides the name, not the fact.
    assert!(text.contains("not regular files"), "the anomaly is still reported: {text}");
    assert!(text.contains("unnameable lock file"), "and it is counted: {text}");
}

#[test]
fn an_odd_lock_named_the_way_agctl_writes_one_is_still_named() {
    // The positive control the reviewer asked for: the GREEN direction must
    // not be "the arm was switched off". A name agctl would accept is still
    // shown, so the guard above is a filter and not a switch.
    let (mut fixture, _doc) = armed();
    fixture.set("AGCTL_FAKE_CODEX_ODD_LOCK", "codex.lock");

    let text = stderr(&login(&fixture, "odd-lock-plain"));

    assert!(text.contains("not regular files"), "a well-spelled odd lock is an anomaly: {text}");
    assert!(text.contains("codex.lock"), "and it is named: {text}");
    assert!(!text.contains("unnameable lock file"), "nothing was withheld: {text}");
}
