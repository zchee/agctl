//! Tests for the keychain vocabulary: the ten-class stderr classifier
//! (fact F34), the error mapping, and the compile-time absence of a write
//! method (plan AC15, AC25).

use super::*;

#[test]
fn the_classifier_matches_every_class_in_order() {
    // Fact F34, verbatim and in order. The order is load-bearing: several of
    // these messages contain more than one of the substrings below, and the
    // first match is what Claude Code reports — so agreeing about the order
    // is agreeing about whether a failure is transient.
    let tests = [
        ("empty", "", StderrClass::Empty),
        ("whitespace only", "   \n", StderrClass::Empty),
        ("duplicate by code", "errSecDuplicateItem", StderrClass::DuplicateItem),
        ("duplicate by text", "The item already exists.", StderrClass::DuplicateItem),
        ("unavailable", "security: unable to open /x", StderrClass::KeychainUnavailable),
        (
            "unavailable, other wording",
            "could not open the keychain",
            StderrClass::KeychainUnavailable,
        ),
        ("no keychain by code", "errSecNoDefaultKeychain", StderrClass::NoKeychain),
        ("no keychain by text", "A default keychain could not be found", StderrClass::NoKeychain),
        ("not found by code", "errSecItemNotFound", StderrClass::ItemNotFound),
        (
            "not found by text",
            "The specified item could not be found in the keychain.",
            StderrClass::ItemNotFound,
        ),
        ("interaction by code", "errSecInteractionNotAllowed", StderrClass::InteractionNotAllowed),
        (
            "interaction by text",
            "User interaction is not allowed.",
            StderrClass::InteractionNotAllowed,
        ),
        ("cancelled by code", "errSecUserCanceled", StderrClass::UserCanceled),
        ("cancelled by text", "the user pressed Cancel", StderrClass::UserCanceled),
        ("auth by code", "errSecAuthFailed", StderrClass::AuthFailed),
        (
            "auth by text",
            "The user name or passphrase you entered is not correct.",
            StderrClass::AuthFailed,
        ),
        ("locked", "The user interaction... keychain is locked", StderrClass::KeychainLocked),
        ("unlock", "please unlock the keychain first", StderrClass::KeychainLocked),
        ("anything else", "something entirely new", StderrClass::Other),
    ];
    for (name, stderr, expected) in tests {
        assert_eq!(classify_stderr(stderr), expected, "{name}: `{stderr}`");
    }
}

#[test]
fn the_classifier_is_case_insensitive() {
    assert_eq!(classify_stderr("ERRSECITEMNOTFOUND"), StderrClass::ItemNotFound);
    assert_eq!(classify_stderr("The Keychain Is LOCKED"), StderrClass::KeychainLocked);
}

#[test]
fn a_message_matching_two_classes_takes_the_earlier_one() {
    // "could not open" (keychain_unavailable) precedes "no keychain", and
    // both appear here.
    assert_eq!(
        classify_stderr("could not open: no keychain available"),
        StderrClass::KeychainUnavailable
    );
    // "cancel" (user_canceled) precedes "authorization".
    assert_eq!(classify_stderr("authorization cancelled by the user"), StderrClass::UserCanceled);
}

#[test]
fn every_failure_but_a_missing_binary_is_transient() {
    let transient = [
        KeychainError::Locked,
        KeychainError::Timeout(2000),
        KeychainError::Failed { class: StderrClass::Other, stderr: "x".to_owned() },
    ];
    for err in transient {
        assert!(err.is_transient(), "{err:?} should be transient");
    }
    assert!(
        !KeychainError::Spawn("no such file".to_owned()).is_transient(),
        "a missing `security` will not fix itself"
    );
}

#[test]
fn errors_map_onto_the_user_facing_classes() {
    let tests = [
        (KeychainError::Locked, KeychainClass::Locked),
        (KeychainError::Timeout(2000), KeychainClass::Timeout),
        (
            KeychainError::Failed { class: StderrClass::ItemNotFound, stderr: String::new() },
            KeychainClass::NotFound,
        ),
        (
            KeychainError::Failed { class: StderrClass::KeychainLocked, stderr: String::new() },
            KeychainClass::Locked,
        ),
        (
            KeychainError::Failed { class: StderrClass::NoKeychain, stderr: String::new() },
            KeychainClass::Unavailable,
        ),
        (
            KeychainError::Failed {
                class: StderrClass::KeychainUnavailable,
                stderr: String::new(),
            },
            KeychainClass::Unavailable,
        ),
        (
            KeychainError::Failed { class: StderrClass::UserCanceled, stderr: String::new() },
            KeychainClass::Other("UserCanceled".to_owned()),
        ),
    ];
    for (err, expected) in tests {
        assert_eq!(err.class(), expected, "{err:?}");
    }
}

#[test]
fn a_keychain_error_becomes_a_partial_exit_not_a_fatal_one() {
    let app: AppError = KeychainError::Locked.into();
    assert_eq!(app.exit_code(), crate::error::EXIT_PARTIAL);
    assert!(app.to_string().contains("locked"), "{app}");
}

#[test]
fn the_disabled_backend_answers_nothing_to_everything() {
    let reader = DisabledReader;
    assert_eq!(reader.preflight(), KeychainStatus::Unavailable("disabled".to_owned()));
    assert_eq!(reader.list_services("").expect("the disabled reader never fails"), Vec::new());
    assert_eq!(reader.read("anything").expect("the disabled reader never fails"), None);
}

#[test]
fn the_reader_trait_is_read_only() {
    // Plan AC15 and AC25 ask for a compile-time guarantee that no code path
    // can write a keychain item. The guarantee is the trait's surface, not
    // this call: `KeychainReader` declares three methods, all reads, so a
    // `dyn KeychainReader` has no vocabulary for a write and no caller can
    // reach one through it. What this test adds is a place where that surface
    // is written down and exercised — adding a `write` method would leave it
    // passing, so the check a reviewer must make is against the list below.
    fn only_reads<R: KeychainReader>(reader: &R) -> (KeychainStatus, usize, bool) {
        let status = reader.preflight();
        let listed = reader.list_services("").map(|entries| entries.len()).unwrap_or_default();
        let read = reader.read("service").map(|item| item.is_some()).unwrap_or_default();
        (status, listed, read)
    }
    let (status, listed, read) = only_reads(&DisabledReader);
    assert_eq!(status, KeychainStatus::Unavailable("disabled".to_owned()));
    assert_eq!(listed, 0);
    assert!(!read);
}

#[test]
fn the_service_prefixes_are_the_ones_seen_on_a_real_machine() {
    assert_eq!(CLAUDE_SERVICE_PREFIX, "Claude Code-credentials");
    assert_eq!(SWITCHER_SERVICE_PREFIX, "claude-switcher:");
    assert_eq!(SECURITY_BIN, "/usr/bin/security", "never resolved through PATH");
}

#[test]
fn current_account_is_a_string_even_with_nothing_set() {
    // Not asserting the value: the test runner's environment owns it. What
    // matters is that a missing `$USER` yields a well-formed argument rather
    // than a panic.
    let account = current_account();
    assert!(!account.contains('\0'));
}

#[cfg(feature = "testing")]
#[test]
fn the_test_only_environment_variable_names_are_the_documented_ones() {
    assert_eq!(KEYCHAIN_BACKEND_ENV, "AGENTCTL_KEYCHAIN_BACKEND");
    assert_eq!(SECURITY_BIN_ENV, "AGENTCTL_SECURITY_BIN");
}

#[test]
fn default_reader_builds_without_touching_the_keychain() {
    // Constructing a reader must not run `security(1)`: discovery decides
    // whether to, and a test run that reached the real keychain would be a
    // test run that could prompt the user.
    let ctx = PassCtx::standalone(
        crate::runtime::coordinator::Cancel::new(),
        std::time::Instant::now() + std::time::Duration::from_secs(5),
    );
    let reader = default_reader(&ctx);
    // And, under the `testing` feature with no stand-in wired, it is not even
    // a reader that *could* spawn one: an unset `AGENTCTL_SECURITY_BIN` fails
    // closed to `DisabledReader` rather than defaulting to the real
    // `security(1)`. Calling `preflight` is therefore safe here, and is the
    // assertion — a test that only dropped the reader would still pass if the
    // fallback came back.
    assert_eq!(
        reader.preflight(),
        KeychainStatus::Unavailable("disabled".to_owned()),
        "a `testing` build with no stand-in wired has no keychain at all"
    );
    assert_eq!(reader.list_services("Claude Code").expect("no error"), Vec::new());
    assert_eq!(reader.read("Claude Code-credentials").expect("no error"), None);
}
