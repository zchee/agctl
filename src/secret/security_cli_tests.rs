//! Tests for the `security(1)` transport.
//!
//! The dump parser is exercised against the fixture; the transport itself is
//! exercised against the fake script from [`crate::secret::fake_security`],
//! which is where the timeout, the exit-status mapping and the argv log get
//! their coverage. Nothing here goes near the real keychain.

use std::path::PathBuf;

use super::*;

fn fixture(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/claude").join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("fixture `{}`: {err}", path.display()))
}

#[test]
fn the_dump_parser_finds_every_service_in_the_fixture() {
    let entries = parse_dump(&fixture("security-dump.txt"));
    let services: Vec<&str> = entries.iter().map(|e| e.service.as_str()).collect();
    assert_eq!(
        services,
        [
            "Claude Code-credentials",
            "Claude Code-credentials-5cdc535f",
            "Claude Code-credentials-6cdd6b98",
            "claude-switcher:alice@example.com",
            "claude-switcher:bob@example.com",
            "Claude Code-86c75be7",
            "Chrome Safe Storage",
        ]
    );
}

#[test]
fn the_dump_parser_reads_the_account_and_timestamps() {
    let entries = parse_dump(&fixture("security-dump.txt"));
    let live = entries.first().expect("the fixture has entries");
    assert_eq!(live.account.as_deref(), Some("example"));
    // The hex form is followed by the printable rendering, and the trailing
    // NUL that `security` prints inside it is dropped.
    assert_eq!(live.cdat.as_deref(), Some("20260908012005Z"));
    assert_eq!(live.mdat.as_deref(), Some("20260908012005Z"));
}

#[test]
fn the_dump_parser_drops_records_with_no_service_name() {
    let dump = "\
class: \"genp\"
attributes:
    \"acct\"<blob>=\"example\"
    \"svce\"<blob>=<NULL>
class: \"genp\"
attributes:
    \"svce\"<blob>=\"kept\"
";
    let entries = parse_dump(dump);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].service, "kept");
    assert_eq!(entries[0].account, None);
}

#[test]
fn the_dump_parser_returns_nothing_for_empty_or_unrelated_output() {
    assert!(parse_dump("").is_empty());
    assert!(parse_dump("security: SecKeychainCopyDefault failed\n").is_empty());
}

#[cfg(feature = "testing")]
mod against_the_fake_script {
    use std::time::Duration;
    use std::time::Instant;

    use tempfile::TempDir;

    use super::*;
    use crate::runtime::coordinator::Cancel;
    use crate::secret::fake_security;

    /// A reader wired to the fake script, plus the directory holding it.
    struct Harness {
        dir: TempDir,
        reader: SecurityCli,
    }

    fn harness() -> Harness {
        let dir = TempDir::new().expect("a temporary directory should be available");
        let bin = fake_security::write_fake_security(dir.path())
            .expect("the fake script should be writable");
        let ctx = crate::runtime::coordinator::PassCtx::standalone(
            Cancel::new(),
            Instant::now() + Duration::from_secs(60),
        );
        Harness { dir, reader: SecurityCli::new(bin, "example".to_owned(), ctx) }
    }

    /// Runs `f` with the fake script's environment variables set.
    ///
    /// The script reads its script from the environment, and this process
    /// cannot set environment variables safely — `std::env::set_var` is
    /// `unsafe` in edition 2024 and would race every other test in the
    /// binary. So the values are baked into a wrapper script instead, which
    /// is what `AGENTCTL_SECURITY_BIN` would point at in the end-to-end
    /// suite.
    fn with_env(dir: &TempDir, vars: &[(&str, String)], inner: &std::path::Path) -> PathBuf {
        let mut script = String::from("#!/bin/sh\n");
        for (name, value) in vars {
            script.push_str(&format!("{name}='{value}'\nexport {name}\n"));
        }
        script.push_str(&format!("exec '{}' \"$@\"\n", inner.display()));

        let path = dir.path().join("security-wrapper");
        std::fs::write(&path, script).expect("the wrapper should be writable");
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .expect("the wrapper should be executable");
        path
    }

    fn wired(vars: &[(&str, String)]) -> Harness {
        let plain = harness();
        let inner = plain.dir.path().join("security");
        let wrapper = with_env(&plain.dir, vars, &inner);
        let ctx = crate::runtime::coordinator::PassCtx::standalone(
            Cancel::new(),
            Instant::now() + Duration::from_secs(60),
        );
        Harness { dir: plain.dir, reader: SecurityCli::new(wrapper, "example".to_owned(), ctx) }
    }

    #[test]
    fn a_default_preflight_is_unlocked() {
        let harness = harness();
        assert_eq!(harness.reader.preflight(), KeychainStatus::Unlocked);
    }

    #[test]
    fn exit_36_is_locked() {
        let harness = wired(&[("AGENTCTL_FAKE_SECURITY_PREFLIGHT_EXIT", "36".to_owned())]);
        assert_eq!(harness.reader.preflight(), KeychainStatus::Locked);
    }

    #[test]
    fn a_preflight_failure_is_unavailable_with_the_class_named() {
        let harness = wired(&[
            ("AGENTCTL_FAKE_SECURITY_PREFLIGHT_EXIT", "1".to_owned()),
            (
                "AGENTCTL_FAKE_SECURITY_PREFLIGHT_STDERR",
                "security: unable to open the keychain".to_owned(),
            ),
        ]);
        let status = harness.reader.preflight();
        let KeychainStatus::Unavailable(detail) = status else {
            panic!("expected unavailable, got {status:?}")
        };
        assert!(detail.contains("KeychainUnavailable"), "{detail}");
    }

    #[test]
    fn a_missing_item_reads_as_none_not_as_an_error() {
        let harness = harness();
        assert_eq!(harness.reader.read("Claude Code-credentials").expect("no error"), None);
    }

    #[test]
    fn an_item_reads_back_without_its_trailing_newline() {
        let dir = TempDir::new().expect("a temporary directory");
        let items = dir.path().join("items");
        fake_security::write_item(&items, "Claude Code-credentials", b"{\"a\":1}\n")
            .expect("the item should be writable");

        let harness =
            wired(&[("AGENTCTL_FAKE_SECURITY_ITEMS", items.to_string_lossy().into_owned())]);
        let blob = harness
            .reader
            .read("Claude Code-credentials")
            .expect("no error")
            .expect("the item is there");
        assert_eq!(blob, b"{\"a\":1}");
    }

    #[test]
    fn listing_parses_the_fixture_dump_and_filters_by_prefix() {
        let path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/claude/security-dump.txt");
        let harness =
            wired(&[("AGENTCTL_FAKE_SECURITY_DUMP", path.to_string_lossy().into_owned())]);

        let claude = harness.reader.list_services("Claude Code").expect("the dump should parse");
        assert_eq!(claude.len(), 4, "three credential items plus the legacy key");

        let switcher =
            harness.reader.list_services("claude-switcher:").expect("the dump should parse");
        assert_eq!(switcher.len(), 2);
    }

    #[test]
    fn the_dump_is_read_once_per_reader() {
        let dump =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/claude/security-dump.txt");
        let dir = TempDir::new().expect("a temporary directory");
        let log = dir.path().join("argv.log");
        let harness = wired(&[
            ("AGENTCTL_FAKE_SECURITY_DUMP", dump.to_string_lossy().into_owned()),
            ("AGENTCTL_FAKE_SECURITY_LOG", log.to_string_lossy().into_owned()),
        ]);

        harness.reader.list_services("Claude Code").expect("the dump should parse");
        harness.reader.list_services("claude-switcher:").expect("the dump should parse");

        let logged = std::fs::read_to_string(&log).expect("the log should exist");
        assert_eq!(
            logged.lines().filter(|line| line.starts_with("dump-keychain")).count(),
            1,
            "two prefixes, one ten-second dump: {logged}"
        );
    }

    #[test]
    fn only_read_subcommands_are_ever_issued() {
        // The unit half of plan AC25.
        let dump =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/claude/security-dump.txt");
        let dir = TempDir::new().expect("a temporary directory");
        let log = dir.path().join("argv.log");
        let harness = wired(&[
            ("AGENTCTL_FAKE_SECURITY_DUMP", dump.to_string_lossy().into_owned()),
            ("AGENTCTL_FAKE_SECURITY_LOG", log.to_string_lossy().into_owned()),
        ]);

        harness.reader.preflight();
        harness.reader.list_services("Claude Code").expect("the dump should parse");
        harness.reader.read("Claude Code-credentials").expect("no error");

        let logged = std::fs::read_to_string(&log).expect("the log should exist");
        for line in logged.lines() {
            let subcommand = line.split_whitespace().next().unwrap_or_default();
            assert!(
                matches!(
                    subcommand,
                    "show-keychain-info" | "find-generic-password" | "dump-keychain"
                ),
                "unexpected subcommand `{subcommand}` in: {logged}"
            );
        }
        assert_eq!(logged.lines().count(), 3);
    }

    #[test]
    fn a_secret_never_appears_in_argv() {
        // Invariant I8: the service name is an argument, the password is not.
        let dir = TempDir::new().expect("a temporary directory");
        let items = dir.path().join("items");
        fake_security::write_item(&items, "Claude Code-credentials", b"sk-ant-oat01-FAKE")
            .expect("the item should be writable");
        let log = dir.path().join("argv.log");
        let harness = wired(&[
            ("AGENTCTL_FAKE_SECURITY_ITEMS", items.to_string_lossy().into_owned()),
            ("AGENTCTL_FAKE_SECURITY_LOG", log.to_string_lossy().into_owned()),
        ]);

        harness.reader.read("Claude Code-credentials").expect("no error");
        let logged = std::fs::read_to_string(&log).expect("the log should exist");
        assert!(!logged.contains("sk-ant-"), "argv carried a secret: {logged}");
        assert!(logged.contains("-a example -w -s Claude Code-credentials"), "{logged}");
    }

    #[test]
    fn a_hanging_child_is_killed_at_its_budget() {
        // Fact F34's 2 000 ms read budget, and invariant I12: a keychain
        // prompt nobody answers must not hold the pass open.
        let harness = wired(&[("AGENTCTL_FAKE_SECURITY_SLEEP", "30".to_owned())]);
        let start = Instant::now();
        let status = harness.reader.preflight();
        let elapsed = start.elapsed();

        assert_eq!(status, KeychainStatus::Timeout);
        assert!(elapsed >= READ_TIMEOUT, "returned before its budget: {elapsed:?}");
        assert!(elapsed < READ_TIMEOUT + Duration::from_secs(5), "overran its budget: {elapsed:?}");
    }

    #[test]
    fn a_hanging_read_is_a_timeout_not_a_fallback() {
        let harness = wired(&[("AGENTCTL_FAKE_SECURITY_SLEEP", "30".to_owned())]);
        let err = harness
            .reader
            .read("Claude Code-credentials")
            .expect_err("a hanging read must not report an absent item");
        assert!(matches!(err, KeychainError::Timeout(2000)), "got {err:?}");
        assert!(err.is_transient());
    }

    #[test]
    fn a_missing_binary_is_a_spawn_failure() {
        let ctx = crate::runtime::coordinator::PassCtx::standalone(
            Cancel::new(),
            Instant::now() + Duration::from_secs(5),
        );
        let reader =
            SecurityCli::new(PathBuf::from("/nonexistent/security"), "example".to_owned(), ctx);
        let err = reader.read("anything").expect_err("a missing binary should fail");
        assert!(matches!(err, KeychainError::Spawn(_)), "got {err:?}");
        assert!(!err.is_transient(), "a missing binary will not fix itself");
    }

    #[test]
    fn a_classified_read_failure_carries_its_class() {
        let harness = wired(&[
            ("AGENTCTL_FAKE_SECURITY_FIND_EXIT", "1".to_owned()),
            ("AGENTCTL_FAKE_SECURITY_STDERR", "errSecInteractionNotAllowed".to_owned()),
        ]);
        let err = harness.reader.read("Claude Code-credentials").expect_err("exit 1 is a failure");
        assert!(
            matches!(
                err,
                KeychainError::Failed {
                    class: crate::secret::StderrClass::InteractionNotAllowed,
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn exit_36_on_a_read_is_locked() {
        let harness = wired(&[("AGENTCTL_FAKE_SECURITY_FIND_EXIT", "36".to_owned())]);
        let err = harness.reader.read("Claude Code-credentials").expect_err("36 is a failure");
        assert_eq!(err, KeychainError::Locked);
    }
}
