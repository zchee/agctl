//! Tests for the exit-code contract and error rendering.

use std::time::Duration;

use super::*;

/// Every `AppError` variant, so the exit-code table below is exhaustive by
/// construction: adding a variant without extending this list leaves the new
/// one untested, and the match in `exit_code` will not compile until it is
/// handled.
fn every_variant() -> Vec<(&'static str, AppError, i32)> {
    vec![
        ("Config is fatal", AppError::Config("bad config".to_owned()), EXIT_FATAL),
        (
            "Io is fatal",
            AppError::Io {
                context: "reading the store".to_owned(),
                source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
            },
            EXIT_FATAL,
        ),
        ("Keychain is partial", AppError::Keychain { class: KeychainClass::Locked }, EXIT_PARTIAL),
        (
            "Http is partial",
            AppError::Http { status: 429, retry_after: Some(Duration::from_secs(30)) },
            EXIT_PARTIAL,
        ),
        ("Auth is partial", AppError::Auth { invalid_grant: true }, EXIT_PARTIAL),
        (
            "Refused is partial",
            AppError::Refused { reason: "claude session detected".to_owned() },
            EXIT_PARTIAL,
        ),
        ("Partial is partial", AppError::Partial { failed: 2 }, EXIT_PARTIAL),
    ]
}

#[test]
fn exit_code_matches_the_contract_for_every_variant() {
    for (name, err, expected) in every_variant() {
        assert_eq!(err.exit_code(), expected, "{name}: {err}");
    }
}

#[test]
fn exit_code_is_never_zero() {
    // An `AppError` value always means the run was at least degraded; success
    // is the `Ok` arm at the call site, never an error that maps to 0.
    for (name, err, _) in every_variant() {
        assert_ne!(err.exit_code(), EXIT_OK, "{name}: an error must not map to the success status");
    }
}

#[test]
fn exit_codes_are_the_documented_numbers() {
    assert_eq!(EXIT_OK, 0);
    assert_eq!(EXIT_FATAL, 1);
    assert_eq!(EXIT_PARTIAL, 2);
}

#[test]
fn keychain_classes_render_their_own_label() {
    let tests = [
        ("locked", KeychainClass::Locked, "locked"),
        ("unavailable", KeychainClass::Unavailable, "unavailable"),
        ("timeout", KeychainClass::Timeout, "timeout"),
        ("not found", KeychainClass::NotFound, "not found"),
        (
            "other carries the class verbatim",
            KeychainClass::Other("errSec-25300".to_owned()),
            "errSec-25300",
        ),
    ];

    for (name, class, expected) in tests {
        assert_eq!(class.to_string(), expected, "{name}");
        let rendered = AppError::Keychain { class: class.clone() }.to_string();
        assert!(rendered.contains(expected), "{name}: `{rendered}` should mention `{expected}`");
    }
}

#[test]
fn http_errors_mention_retry_after_only_when_the_server_sent_one() {
    let with_hint =
        AppError::Http { status: 429, retry_after: Some(Duration::from_secs(30)) }.to_string();
    assert!(with_hint.contains("429"), "status should appear: {with_hint}");
    assert!(with_hint.contains("30"), "retry window should appear: {with_hint}");

    let without_hint = AppError::Http { status: 503, retry_after: None }.to_string();
    assert!(without_hint.contains("503"), "status should appear: {without_hint}");
    assert!(
        !without_hint.contains("retry"),
        "no retry window should be claimed when none was sent: {without_hint}"
    );
}

#[test]
fn invalid_grant_tells_the_user_how_to_recover() {
    let dead_chain = AppError::Auth { invalid_grant: true }.to_string();
    assert!(dead_chain.contains("invalid_grant"), "name the upstream code: {dead_chain}");
    assert!(dead_chain.contains("login"), "point at the recovery: {dead_chain}");

    let generic = AppError::Auth { invalid_grant: false }.to_string();
    assert!(
        !generic.contains("invalid_grant"),
        "do not claim invalid_grant when the server did not say so: {generic}"
    );
}

#[test]
fn not_implemented_names_the_command_and_is_fatal() {
    let err = AppError::not_implemented("agentctl claude status");
    assert_eq!(err.exit_code(), EXIT_FATAL, "an unbuilt command must not exit 0 or 2");
    let rendered = err.to_string();
    assert!(rendered.contains("agentctl claude status"), "name the command: {rendered}");
    assert!(rendered.contains("not implemented"), "say why: {rendered}");
}

#[test]
fn io_errors_keep_their_source() {
    use std::error::Error;

    let err = AppError::Io {
        context: "writing the credential file".to_owned(),
        source: std::io::Error::new(std::io::ErrorKind::StorageFull, "no space"),
    };
    assert_eq!(err.to_string(), "writing the credential file");
    let source = err.source().expect("an Io error must expose its underlying cause");
    assert!(source.to_string().contains("no space"), "source should survive: {source}");
}

#[test]
fn partial_reports_how_many_rows_are_degraded() {
    let rendered = AppError::Partial { failed: 3 }.to_string();
    assert!(rendered.contains('3'), "the count should be visible: {rendered}");
}

#[test]
fn refused_reports_the_reason() {
    let rendered = AppError::Refused {
        reason: "claude session detected (lock .oauth_refresh.lock)".to_owned(),
    }
    .to_string();
    assert!(rendered.contains("claude session detected"), "the reason should survive: {rendered}");
}
