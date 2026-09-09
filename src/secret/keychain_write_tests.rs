//! Tests for the keychain write transport.
//!
//! Four groups, in the order the plan's acceptance criteria name them:
//!
//! - **The target** (plan AC59, AC82): the two constructors, the derivation
//!   from one [`EnvView`], and the two mechanical checks that stand in for the
//!   compile-fail tests. `trybuild` is not a dependency and a `compile_fail`
//!   doc-test cannot help either: `agentctl` is a **binary** crate, so cargo
//!   never compiles its doc-tests and a `compile_fail` block in this crate
//!   would pass by never running. What is asserted instead is the property the
//!   doc-test was there to protect — that the fields are private and that no
//!   other module contains a struct literal for either type — read off the
//!   sources themselves, which is a check a future edit cannot silently lose.
//! - **The line** (plan AC59): the shape on stdin, byte for byte.
//! - **The outcomes** (plan AC60): every `security` exit status and every one
//!   of fact F34's ten stderr classes, plus the timeout and the spawn failure.
//! - **The fake** (plan AC59, AC61): the argv log, the redaction, the
//!   allowlist, and the write-then-read round trip.

use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

use tempfile::TempDir;

use super::*;
use crate::config::AccountRecord;
use crate::provider::claude::credentials::Credentials;
use crate::provider::claude::namespace::sha8;
use crate::runtime::coordinator::Cancel;

/// A blob small enough that the line is nowhere near fact F42's limit.
const BLOB: &[u8] =
    br#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-test","expiresAt":0,"scopes":[]}}"#;

/// The `acct` attribute the tests write under.
const ACCOUNT: &str = "example";

fn ctx() -> PassCtx {
    PassCtx::standalone(Cancel::new(), Instant::now() + Duration::from_secs(60))
}

fn credentials() -> Credentials {
    Credentials::parse_blob(BLOB).expect("the fixture blob parses")
}

fn line_for(account: &str, service: &str) -> KeychainStdinLine {
    credentials()
        .to_keychain_stdin_line(account, service)
        .expect("a short line is within the limit")
}

/// Writes an executable `/bin/sh` stand-in and returns its path.
fn stub(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("the stub should be writable");
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o755))
        .expect("the stub should be made executable");
    path
}

/// A stand-in that prints `stderr` and exits `code`, reading stdin first.
fn exiting(dir: &Path, name: &str, code: i32, stderr: &str) -> PathBuf {
    let body = if stderr.is_empty() {
        format!("cat > /dev/null\nexit {code}")
    } else {
        format!("cat > /dev/null\nprintf '%s\\n' '{stderr}' >&2\nexit {code}")
    };
    stub(dir, name, &body)
}

/// An `Owned` record for one namespace, with `sha8` as its stored suffix.
fn owned_record(acct: &str, org: &str, export_sha8: &str) -> AccountRecord {
    AccountRecord {
        account_uuid: acct.to_owned(),
        organization_uuid: org.to_owned(),
        email: None,
        org_name: None,
        label: None,
        kind: AccountKind::Owned {
            export_spelling: format!("/nowhere/{acct}/{org}"),
            export_sha8: export_sha8.to_owned(),
        },
        forgotten: false,
        created_at: "2026-09-09T00:00:00Z".to_owned(),
    }
}

/// A record of some other kind, keyed the same way.
fn record_of(kind: AccountKind) -> AccountRecord {
    AccountRecord { kind, ..owned_record("acct", "org", "deadbeef") }
}

// ---------------------------------------------------------------------------
// The target
// ---------------------------------------------------------------------------

#[test]
fn live_derives_the_store_directory_and_the_service_from_one_env_view() {
    // The finding-3 case (plan AC82, risk R42): with `CLAUDE_CONFIG_DIR` set,
    // the live item is the *suffixed* one and the store is that directory. A
    // service name derived from any other view of the environment — the home
    // directory's, say — would be the unsuffixed name, so the two halves
    // disagreeing is observable rather than theoretical.
    let mut env = EnvView::with_home(PathBuf::from("/home/example"));
    env.config_dir = Some("/elsewhere/claude".to_owned());

    let target = WriteTarget::live(&env).expect("no securestorage dir is set");
    assert_eq!(target.store_dir(), Path::new("/elsewhere/claude"));
    assert_eq!(target.service(), format!("{LIVE_SERVICE}-{}", sha8("/elsewhere/claude")));

    let home_only = EnvView::with_home(PathBuf::from("/home/example"));
    let from_the_other_view = WriteTarget::live(&home_only).expect("nothing is set");
    assert_eq!(
        from_the_other_view.service(),
        LIVE_SERVICE,
        "the two views must disagree, or this test proves nothing"
    );
    assert_ne!(from_the_other_view.service(), target.service());
    assert_ne!(from_the_other_view.store_dir(), target.store_dir());
}

#[test]
fn live_refuses_an_inherited_securestorage_dir() {
    // Refusal E, checked at the derivation so no wave can reach the case by
    // accident: this shell has been pointed at a namespace, so "the live item"
    // is not what the caller means.
    let mut env = EnvView::with_home(PathBuf::from("/home/example"));
    env.securestorage_dir = Some("/store/claude/acct/org".to_owned());

    let refusal = WriteTarget::live(&env).expect_err("a namespaced shell is refused");
    let message = refusal.to_string();
    assert!(message.contains(SECURESTORAGE_ENV), "{message}");
    assert!(message.contains("/store/claude/acct/org"), "{message}");
}

#[test]
fn live_accepts_an_empty_securestorage_dir_because_it_is_falsy() {
    // Fact F14's truthiness rule: an empty value names the live item exactly
    // as an unset variable does, so refusing it would refuse the live case.
    let mut env = EnvView::with_home(PathBuf::from("/home/example"));
    env.securestorage_dir = Some(String::new());

    let target = WriteTarget::live(&env).expect("an empty value is falsy");
    assert_eq!(target.service(), LIVE_SERVICE);
    assert_eq!(target.store_dir(), Path::new("/home/example/.claude"));
}

#[test]
fn migrated_names_the_records_own_item_and_its_own_namespace() {
    let dir = TempDir::new().expect("a temporary directory");
    let paths = Paths::with_config_dir(dir.path().to_path_buf());
    let record = owned_record("acct", "org", "0123abcd");

    let sha8 = OwnedSha8::from_record(&paths, &record).expect("an owned record has a sha8");
    assert_eq!(sha8.sha8(), "0123abcd");

    let target = WriteTarget::migrated(sha8);
    assert_eq!(target.service(), "Claude Code-credentials-0123abcd");
    assert_eq!(target.store_dir(), paths.namespace_dir("acct", "org"));
}

#[test]
fn owned_sha8_refuses_every_kind_agentctl_does_not_own() {
    let dir = TempDir::new().expect("a temporary directory");
    let paths = Paths::with_config_dir(dir.path().to_path_buf());

    for kind in [
        AccountKind::Live,
        AccountKind::ConfigDirReadOnly {
            dir: PathBuf::from("/somewhere"),
            service: "Claude Code-credentials-deadbeef".to_owned(),
            shares_live_dir: false,
        },
        AccountKind::Foreign { source: "claude-switcher".to_owned() },
    ] {
        let record = record_of(kind.clone());
        assert!(
            OwnedSha8::from_record(&paths, &record).is_none(),
            "a `{}` row must not be nameable as a write target (risk R40)",
            kind.name()
        );
    }
}

#[test]
fn owned_sha8_refuses_a_suffix_that_is_not_eight_lowercase_hex_digits() {
    let dir = TempDir::new().expect("a temporary directory");
    let paths = Paths::with_config_dir(dir.path().to_path_buf());

    for suffix in ["", "abc", "0123abcde", "0123ABCD", "0123abcg", " 123abcd"] {
        let record = owned_record("acct", "org", suffix);
        assert!(
            OwnedSha8::from_record(&paths, &record).is_none(),
            "`{suffix}` is not a service suffix and must not become one"
        );
    }
}

#[test]
fn owned_sha8_refuses_a_record_whose_namespace_escapes_the_store() {
    let dir = TempDir::new().expect("a temporary directory");
    let paths = Paths::with_config_dir(dir.path().to_path_buf());
    // `new_record` validates both segments, so this shape only arrives from a
    // hand-edited or corrupted registry — which is a reason to stop, not a
    // reason to go on and lock some other directory.
    let record = owned_record("..", "..", "0123abcd");
    assert!(OwnedSha8::from_record(&paths, &record).is_none());
}

#[test]
fn i1_prime_no_other_module_contains_a_literal_for_either_type() {
    // The mechanical half of I1′: private fields make a struct literal
    // impossible outside this module, and this asserts that nobody has moved
    // one *into* the module's neighbourhood or made the fields public.
    for (path, text) in source_files() {
        let name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
        if name == "keychain_write.rs" || name == "keychain_write_tests.rs" {
            continue;
        }
        for literal in ["WriteTarget {", "WriteTarget{", "OwnedSha8 {", "OwnedSha8{", "OwnedSha8("]
        {
            assert!(
                !text.contains(literal),
                "`{}` contains `{literal}`; a write target may only come from one of the two \
                 constructors (invariant I1′)",
                path.display()
            );
        }
    }
}

#[test]
fn i1_prime_both_types_keep_every_field_private() {
    let text = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/secret/keychain_write.rs"),
    )
    .expect("this module should be readable");

    for declaration in ["pub struct WriteTarget {", "pub struct OwnedSha8 {"] {
        let body = struct_body(&text, declaration);
        assert!(!body.is_empty(), "`{declaration}` should still be a braced struct");
        assert!(
            !body.contains("pub "),
            "`{declaration}` has a public field, which would make invariant I1′ a convention \
             rather than a compile-time property: {body}"
        );
    }
}

/// The text between the braces of the declaration starting at `declaration`.
fn struct_body(text: &str, declaration: &str) -> String {
    let Some(start) = text.find(declaration) else {
        return String::new();
    };
    let after = &text[start + declaration.len()..];
    match after.find('}') {
        Some(end) => after[..end].to_owned(),
        None => String::new(),
    }
}

/// Every `.rs` file under `src/`, with its text.
fn source_files() -> Vec<(PathBuf, String)> {
    let mut found = Vec::new();
    collect_rs(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src"), &mut found);
    assert!(found.len() > 20, "the walk should have found the crate's sources, not {found:?}");
    found
}

/// Appends every `.rs` file under `dir`, recursively.
fn collect_rs(dir: &Path, found: &mut Vec<(PathBuf, String)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            collect_rs(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "rs")
            && let Ok(text) = std::fs::read_to_string(&path)
        {
            found.push((path, text));
        }
    }
}

// ---------------------------------------------------------------------------
// The line
// ---------------------------------------------------------------------------

#[test]
fn the_budget_terms_fit_inside_the_hold() {
    // Plan section 3.4's table: 500 ms spawn allowance + 800 ms re-read +
    // 1 200 ms write + 500 ms lock syscalls = 3 000 ms, itself derived from
    // fact F53's 4 000 ms floor. The two terms this module owns are asserted
    // here; the hold budget itself belongs to the lock module.
    assert_eq!(READ_TIMEOUT + WRITE_TIMEOUT, Duration::from_millis(2000));
    assert!(WRITE_TIMEOUT < Duration::from_millis(3000));
}

#[test]
fn line_text_refuses_a_name_that_would_break_out_of_its_quotes() {
    for (field, account, service) in [
        ("account", "ex\"ample", LIVE_SERVICE),
        ("account", "ex\\ample", LIVE_SERVICE),
        ("account", "ex\nample", LIVE_SERVICE),
        ("service", ACCOUNT, "Claude Code-credentials\" -s \"other"),
        ("service", ACCOUNT, "Claude Code-credentials\nadd-generic-password"),
    ] {
        let refused = line_text(account, service, "00").expect_err("the name is unquotable");
        assert_eq!(refused, KeychainWriteError::Unquotable { field });
        assert!(!refused.is_transient());
    }
}

// ---------------------------------------------------------------------------
// The outcomes
// ---------------------------------------------------------------------------

#[test]
fn a_write_puts_the_line_on_stdin_and_nothing_in_argv() {
    // Plan AC59's core assertion, made against a stand-in that records both
    // halves: argv is exactly `-i`, and the bytes it received are fact F42's
    // line, byte for byte, trailing newline included.
    let dir = TempDir::new().expect("a temporary directory");
    let argv = dir.path().join("argv");
    let stdin = dir.path().join("stdin");
    let bin = stub(
        dir.path(),
        "security",
        &format!(
            "printf '%s\\n' \"$*\" >> '{}'\ncat >> '{}'\nexit 0",
            argv.display(),
            stdin.display()
        ),
    );

    let target = WriteTarget::live(&EnvView::with_home(dir.path().to_path_buf()))
        .expect("nothing is set in this view");
    write_item_through(&bin, &target, ACCOUNT, line_for(ACCOUNT, target.service()), &ctx())
        .expect("the stand-in exits 0");

    assert_eq!(std::fs::read_to_string(&argv).expect("argv recorded"), "-i\n");
    let expected = format!(
        "add-generic-password -U -a \"{ACCOUNT}\" -s \"{}\" -X \"{}\"\n",
        target.service(),
        hex::encode(credentials().to_blob_json())
    );
    assert_eq!(std::fs::read_to_string(&stdin).expect("stdin recorded"), expected);
}

#[test]
fn an_over_long_line_is_refused_before_any_child_exists() {
    // Plan AC59's second half. The line has to be built by hand: the builder
    // refuses an over-long one first, which is the point — the transport's own
    // check is the guarantee a caller with a hand-rolled line still gets.
    let dir = TempDir::new().expect("a temporary directory");
    let marker = dir.path().join("ran");
    let spy =
        stub(dir.path(), "security", &format!("printf 'ran\\n' >> '{}'\nexit 0", marker.display()));

    let target = WriteTarget::live(&EnvView::with_home(dir.path().to_path_buf()))
        .expect("nothing is set in this view");
    let over = KeychainStdinLine::from_raw_for_test(
        "x".repeat(SECURITY_STDIN_LIMIT + 1),
        ACCOUNT,
        target.service(),
    );

    let refused = write_item_through(&spy, &target, ACCOUNT, over, &ctx())
        .expect_err("one byte over the limit is refused");
    assert_eq!(
        refused,
        KeychainWriteError::LineTooLong {
            len: SECURITY_STDIN_LIMIT + 1,
            limit: SECURITY_STDIN_LIMIT
        }
    );
    assert!(!refused.is_transient());
    assert!(!marker.exists(), "no child may be spawned for a line that cannot be sent");
}

#[test]
fn a_line_built_for_another_item_is_refused_before_any_child_exists() {
    let dir = TempDir::new().expect("a temporary directory");
    let marker = dir.path().join("ran");
    let spy =
        stub(dir.path(), "security", &format!("printf 'ran\\n' >> '{}'\nexit 0", marker.display()));
    let target = WriteTarget::live(&EnvView::with_home(dir.path().to_path_buf()))
        .expect("nothing is set in this view");

    let wrong_service = line_for(ACCOUNT, "Claude Code-credentials-deadbeef");
    let refused = write_item_through(&spy, &target, ACCOUNT, wrong_service, &ctx())
        .expect_err("the line names another item");
    assert_eq!(
        refused,
        KeychainWriteError::TargetMismatch {
            expected: LIVE_SERVICE.to_owned(),
            found: "Claude Code-credentials-deadbeef".to_owned(),
        }
    );

    let wrong_account = line_for("somebody-else", target.service());
    let refused = write_item_through(&spy, &target, ACCOUNT, wrong_account, &ctx())
        .expect_err("the line names another account");
    assert_eq!(
        refused,
        KeychainWriteError::TargetMismatch {
            expected: ACCOUNT.to_owned(),
            found: "somebody-else".to_owned(),
        }
    );
    assert!(!marker.exists(), "no child may be spawned for a mismatched line");
}

#[test]
fn every_security_outcome_maps_to_the_documented_error() {
    // Plan AC60. Exit 0 is the success above; the rest is this table, and it
    // covers all ten of fact F34's classes so a change to the classifier
    // cannot quietly re-route a write failure.
    let dir = TempDir::new().expect("a temporary directory");
    let target = WriteTarget::live(&EnvView::with_home(dir.path().to_path_buf()))
        .expect("nothing is set in this view");

    let cases: [(&str, i32, &str, KeychainWriteError); 12] = [
        ("locked", EXIT_LOCKED, "security: the keychain is locked", KeychainWriteError::Locked),
        (
            "not-found",
            EXIT_NOT_FOUND,
            "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.",
            KeychainWriteError::Failed {
                class: StderrClass::ItemNotFound,
                stderr: "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.".to_owned(),
            },
        ),
        (
            "empty",
            1,
            "",
            KeychainWriteError::Failed { class: StderrClass::Empty, stderr: String::new() },
        ),
        (
            "duplicate",
            1,
            "security: SecKeychainItemCreateFromContent: The specified item already exists in the keychain.",
            KeychainWriteError::Failed {
                class: StderrClass::DuplicateItem,
                stderr: "security: SecKeychainItemCreateFromContent: The specified item already exists in the keychain.".to_owned(),
            },
        ),
        (
            "unavailable",
            1,
            "security: unable to open the login keychain",
            KeychainWriteError::Failed {
                class: StderrClass::KeychainUnavailable,
                stderr: "security: unable to open the login keychain".to_owned(),
            },
        ),
        (
            "no-keychain",
            1,
            "security: SecKeychainCopyDefault: A default keychain is not set",
            KeychainWriteError::Failed {
                class: StderrClass::NoKeychain,
                stderr: "security: SecKeychainCopyDefault: A default keychain is not set".to_owned(),
            },
        ),
        (
            "item-not-found",
            1,
            "security: SecKeychainItemModifyContent: The specified item could not be found in the keychain.",
            KeychainWriteError::Failed {
                class: StderrClass::ItemNotFound,
                stderr: "security: SecKeychainItemModifyContent: The specified item could not be found in the keychain.".to_owned(),
            },
        ),
        (
            "no-interaction",
            1,
            "security: SecKeychainItemModifyContent: User interaction is not allowed.",
            KeychainWriteError::Failed {
                class: StderrClass::InteractionNotAllowed,
                stderr: "security: SecKeychainItemModifyContent: User interaction is not allowed.".to_owned(),
            },
        ),
        (
            "canceled",
            1,
            "security: SecKeychainItemModifyContent: User canceled the operation.",
            KeychainWriteError::Failed {
                class: StderrClass::UserCanceled,
                stderr: "security: SecKeychainItemModifyContent: User canceled the operation.".to_owned(),
            },
        ),
        (
            "auth-failed",
            1,
            "security: SecKeychainItemModifyContent: The user name or passphrase you entered is not correct.",
            KeychainWriteError::Failed {
                class: StderrClass::AuthFailed,
                stderr: "security: SecKeychainItemModifyContent: The user name or passphrase you entered is not correct.".to_owned(),
            },
        ),
        (
            "keychain-locked",
            1,
            "security: SecKeychainItemModifyContent: the keychain is locked and cannot be modified",
            KeychainWriteError::Failed {
                class: StderrClass::KeychainLocked,
                stderr: "security: SecKeychainItemModifyContent: the keychain is locked and cannot be modified".to_owned(),
            },
        ),
        (
            "other",
            1,
            "security: SecKeychainItemModifyContent: something new in a later release",
            KeychainWriteError::Failed {
                class: StderrClass::Other,
                stderr: "security: SecKeychainItemModifyContent: something new in a later release".to_owned(),
            },
        ),
    ];

    for (name, code, stderr, expected) in cases {
        let bin = exiting(dir.path(), &format!("security-{name}"), code, stderr);
        let got =
            write_item_through(&bin, &target, ACCOUNT, line_for(ACCOUNT, target.service()), &ctx())
                .expect_err("a non-zero exit is a failed write");
        assert_eq!(got, expected, "case `{name}`");
        assert!(got.is_transient(), "case `{name}`: a keychain failure is worth retrying");
    }
}

#[test]
fn a_child_that_never_answers_is_a_transient_timeout() {
    let dir = TempDir::new().expect("a temporary directory");
    let bin = stub(dir.path(), "security", "cat > /dev/null\nsleep 5\nexit 0");
    let target = WriteTarget::live(&EnvView::with_home(dir.path().to_path_buf()))
        .expect("nothing is set in this view");

    let started = Instant::now();
    let got =
        write_item_through(&bin, &target, ACCOUNT, line_for(ACCOUNT, target.service()), &ctx())
            .expect_err("the child outlives its budget");
    assert_eq!(got, KeychainWriteError::Timeout(1200));
    assert!(got.is_transient(), "a busy machine is worth retrying");
    assert!(started.elapsed() < Duration::from_secs(5), "the child must be killed, not waited on");
}

#[test]
fn a_missing_binary_is_a_permanent_spawn_failure() {
    let dir = TempDir::new().expect("a temporary directory");
    let missing = dir.path().join("no-such-security");
    let target = WriteTarget::live(&EnvView::with_home(dir.path().to_path_buf()))
        .expect("nothing is set in this view");

    let got =
        write_item_through(&missing, &target, ACCOUNT, line_for(ACCOUNT, target.service()), &ctx())
            .expect_err("a binary that is not there cannot write");
    assert!(matches!(got, KeychainWriteError::Spawn(_)), "{got:?}");
    assert!(!got.is_transient(), "a missing binary does not appear on a retry");
}

#[test]
fn the_transport_binary_is_resolved_without_being_told() {
    // Referenced rather than called: calling it would resolve
    // `/usr/bin/security` and no test goes near the real keychain.
    let entry: fn(
        &WriteTarget,
        &str,
        KeychainStdinLine,
        &PassCtx,
    ) -> Result<(), KeychainWriteError> = write_item;
    let _ = entry;

    // A release build resolves one absolute path and nothing else.
    #[cfg(not(feature = "testing"))]
    assert!(security_bin().expect("a release build always has one").is_absolute());

    // A `testing` build fails closed instead. `AGENTCTL_SECURITY_BIN` is unset
    // in this process — a unit test cannot set one safely — and the answer is
    // a refusal rather than `/usr/bin/security`, so no test can reach the
    // developer's own keychain by forgetting to wire a stand-in. This is the
    // assertion that would have stopped a real write, and it is worth more
    // than the absoluteness of a path nobody here is allowed to use.
    #[cfg(feature = "testing")]
    {
        let refused = security_bin().expect_err("a `testing` build has no default transport");
        assert!(
            matches!(refused, KeychainWriteError::Spawn(ref why) if why.contains("no write transport")),
            "the refusal says why, and names the seam: {refused:?}"
        );
        assert!(!refused.is_transient(), "a missing transport is not worth retrying");
    }
}

// ---------------------------------------------------------------------------
// The fake
// ---------------------------------------------------------------------------

#[cfg(feature = "testing")]
mod against_the_fake_script {
    use super::*;
    use crate::secret::KeychainReader;
    use crate::secret::fake_security;
    use crate::secret::security_cli::SecurityCli;

    /// The fake, wrapped in a script that exports its environment.
    ///
    /// The same shape `security_cli_tests` uses, and for the same reason: this
    /// process cannot set an environment variable safely — `std::env::set_var`
    /// is `unsafe` in edition 2024 and would race every other test in this
    /// binary.
    fn wired(dir: &Path, vars: &[(&str, String)]) -> PathBuf {
        let inner = fake_security::write_fake_security(dir).expect("the fake should be writable");
        let mut script = String::from("#!/bin/sh\n");
        for (name, value) in vars {
            script.push_str(&format!("{name}='{value}'\nexport {name}\n"));
        }
        script.push_str(&format!("exec '{}' \"$@\"\n", inner.display()));
        stub(dir, "security-wrapper", &script)
    }

    #[test]
    fn the_only_argv_this_module_builds_is_dash_i() {
        assert_eq!(argv_shapes(), vec![vec!["-i"]]);
    }

    #[test]
    fn a_write_lands_where_a_read_finds_it_and_the_log_redacts_the_hex() {
        let dir = TempDir::new().expect("a temporary directory");
        let items = dir.path().join("items");
        let log = dir.path().join("argv.log");
        let target = WriteTarget::live(&EnvView::with_home(dir.path().to_path_buf()))
            .expect("nothing is set in this view");
        fake_security::allow_service(&items, target.service()).expect("registrable");

        let bin = wired(
            dir.path(),
            &[
                ("AGENTCTL_FAKE_SECURITY_ITEMS", items.to_string_lossy().into_owned()),
                ("AGENTCTL_FAKE_SECURITY_LOG", log.to_string_lossy().into_owned()),
            ],
        );
        write_item_through(&bin, &target, ACCOUNT, line_for(ACCOUNT, target.service()), &ctx())
            .expect("a registered service is written");

        // Read back through the read transport: the bytes on the pipe and the
        // bytes an item holds are the same bytes.
        let reader = SecurityCli::new(bin, ACCOUNT.to_owned(), ctx());
        let read =
            reader.read(target.service()).expect("the read works").expect("the item is there");
        assert_eq!(read, credentials().to_blob_json().into_bytes());

        let logged = std::fs::read_to_string(&log).expect("the log should exist");
        let write_lines: Vec<&str> =
            logged.lines().filter(|line| line.starts_with("add-generic-password")).collect();
        assert_eq!(write_lines.len(), 1, "one write, one line: {logged}");
        assert!(logged.lines().any(|line| line == "-i"), "argv is exactly `-i`: {logged}");
        let hex = hex::encode(credentials().to_blob_json());
        assert!(!logged.contains(&hex), "the log must not carry the payload: {logged}");
        assert_eq!(
            write_lines[0],
            format!(
                "add-generic-password -U -a \"{ACCOUNT}\" -s \"{}\" -X <REDACTED:{}>",
                target.service(),
                hex.len()
            )
        );
    }

    #[test]
    fn the_fake_refuses_a_service_no_test_registered() {
        let dir = TempDir::new().expect("a temporary directory");
        let items = dir.path().join("items");
        std::fs::create_dir_all(&items).expect("creatable");
        let target = WriteTarget::live(&EnvView::with_home(dir.path().to_path_buf()))
            .expect("nothing is set in this view");

        let bin = wired(
            dir.path(),
            &[("AGENTCTL_FAKE_SECURITY_ITEMS", items.to_string_lossy().into_owned())],
        );
        let refused =
            write_item_through(&bin, &target, ACCOUNT, line_for(ACCOUNT, target.service()), &ctx())
                .expect_err("an unregistered service is refused");
        let KeychainWriteError::Failed { class, stderr } = refused else {
            panic!("expected a classified failure, got {refused:?}");
        };
        assert_eq!(class, StderrClass::Other);
        assert!(stderr.contains("not registered with this stand-in"), "{stderr}");
        assert!(
            !fake_security::item_path(&items, ACCOUNT, target.service()).exists(),
            "a refused write stores nothing"
        );
    }

    #[test]
    fn the_fake_honours_the_write_exit_knob_so_every_class_is_reachable() {
        let dir = TempDir::new().expect("a temporary directory");
        let items = dir.path().join("items");
        let target = WriteTarget::live(&EnvView::with_home(dir.path().to_path_buf()))
            .expect("nothing is set in this view");
        fake_security::allow_service(&items, target.service()).expect("registrable");

        let bin = wired(
            dir.path(),
            &[
                ("AGENTCTL_FAKE_SECURITY_ITEMS", items.to_string_lossy().into_owned()),
                ("AGENTCTL_FAKE_SECURITY_WRITE_EXIT", "36".to_owned()),
            ],
        );
        let refused =
            write_item_through(&bin, &target, ACCOUNT, line_for(ACCOUNT, target.service()), &ctx())
                .expect_err("exit 36 is a locked keychain");
        assert_eq!(refused, KeychainWriteError::Locked);
        assert!(
            !fake_security::item_path(&items, ACCOUNT, target.service()).exists(),
            "a forced failure stores nothing"
        );
    }
}
