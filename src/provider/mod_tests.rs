use std::time::Duration;

use super::*;

#[test]
fn transience_decides_whether_another_pass_is_worth_it() {
    let transient = [
        FetchError::RateLimited { retry_after: Some(Duration::from_secs(30)) },
        FetchError::RateLimited { retry_after: None },
        FetchError::Transport("connection reset".to_owned()),
        FetchError::Http { status: 500 },
        FetchError::Http { status: 503 },
    ];
    for error in transient {
        assert!(error.is_transient(), "{error} should be transient");
    }

    let permanent = [
        FetchError::Unauthorized,
        FetchError::Http { status: 400 },
        FetchError::Http { status: 404 },
        FetchError::Parse("no `limits` array".to_owned()),
        FetchError::Cancelled,
    ];
    for error in permanent {
        assert!(!error.is_transient(), "{error} should not be transient");
    }
}

#[test]
fn rate_limited_renders_its_hint_only_when_the_server_sent_one() {
    // The message must not claim a retry window the server never named:
    // a user who reads "retry in 0s" and retries immediately gets another
    // 429 and no explanation.
    let with_hint = FetchError::RateLimited { retry_after: Some(Duration::from_secs(30)) };
    assert_eq!(with_hint.to_string(), "rate limited, retry in 30s");

    let without = FetchError::RateLimited { retry_after: None };
    assert_eq!(without.to_string(), "rate limited");
}

#[test]
fn error_messages_name_the_status_without_a_body() {
    // Bodies are never interpolated into an error: a token can appear in an
    // echoed request and this string reaches stderr and the JSON report.
    assert_eq!(FetchError::Http { status: 502 }.to_string(), "HTTP 502");
    assert_eq!(FetchError::Unauthorized.to_string(), "the access token was rejected");
}
