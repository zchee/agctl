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
use serde_json::Value;
use serde_json::json;

const USER: &str = "user-login-0001";
const ACCT: &str = "acct-login-0001";
const EMAIL: &str = "codex-login@example.invalid";

/// The refresh token and the JWT signature the fixture's documents carry.
const REFRESH_TOKEN: &str = "agctl-test-codex-login-rt-0001";
const JWT_SIGNATURE: &str = "agctl-test-codex-login-sig";

/// Strings that must never appear on either stream of a login run.
const NEEDLES: [&str; 5] = [REFRESH_TOKEN, JWT_SIGNATURE, "eyJ", "Bearer ", "bearer "];

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
fn checked(name: &str, output: Output) -> Output {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    for needle in NEEDLES {
        assert!(!stdout.contains(needle), "{name}: stdout carries `{needle}`:\n{stdout}");
        assert!(!stderr.contains(needle), "{name}: stderr carries `{needle}`:\n{stderr}");
    }
    if let Some(dir) = std::env::var_os("AGCTL_E2E_TRACE_DIR") {
        let dir = PathBuf::from(dir);
        fs::write(dir.join(format!("e2e_codex_login-{name}.stdout")), &output.stdout)
            .expect("the trace directory is writable");
        fs::write(dir.join(format!("e2e_codex_login-{name}.stderr")), &output.stderr)
            .expect("the trace directory is writable");
    }
    output
}

/// Runs `agctl codex login` through [`checked`].
fn login(fixture: &CodexFixture, name: &str) -> Output {
    checked(name, fixture.cmd().args(["codex", "login"]).output().expect("the binary runs"))
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

    let output = login(&fixture, "allowlist");
    assert!(output.status.success(), "{}", stderr(&output));

    let log = codex_log(&fixture);
    let names: Vec<&str> = log.lines().filter_map(|line| line.strip_prefix("env ")).collect();

    assert!(!names.contains(&"AWS_SECRET_ACCESS_KEY"), "a cloud credential name reached the child");
    assert!(!names.contains(&"CODEX_API_KEY"), "an API key name reached the child");
    assert!(names.contains(&"CODEX_HOME"), "the child is told which home to use");
    assert!(names.contains(&"PATH"), "the child keeps PATH");

    // No value but the named three, and never a decoy's.
    assert!(!log.contains("decoy-value-must-not-appear"), "a decoy VALUE reached the log");
    for line in log.lines() {
        if let Some(rest) = line.strip_prefix("value ") {
            let name = rest.split('=').next().unwrap_or_default();
            assert!(
                ["CODEX_HOME", "HOME", "TMPDIR"].contains(&name),
                "a value was logged for {name}"
            );
        }
    }
    // Under direnv this also proves any real, inherited `KACHE_*` name was
    // dropped: agctl inherits the test runner's environment.
    assert_eq!(log.matches("KACHE_").count(), 0, "no KACHE_ name appears anywhere in the record");
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
    let argv = log.lines().find_map(|line| line.strip_prefix("argv ")).expect("argv recorded");
    assert_eq!(argv, "-c cli_auth_credentials_store=\"file\" login");
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
    assert_nothing_installed(&fixture, "keychain-gain");
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
    checked(name, output)
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
    let output = checked("closed-stdout", child.wait_with_output().expect("the binary ends"));

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
    let output = checked("closed-stderr", child.wait_with_output().expect("the binary ends"));

    use std::os::unix::process::ExitStatusExt;
    assert_ne!(output.status.signal(), Some(libc::SIGABRT), "a closed stderr must not abort");
    assert!(scratch_leaves(&fixture).is_empty(), "and the scratch home is removed");
}
