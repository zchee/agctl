//! Tests for the row-state vocabulary.
//!
//! The two behavioural methods are what matter: [`AccountState::is_failure`]
//! decides the process exit status, and [`AccountState::allows_network`]
//! decides whether a row is allowed to spend an HTTP request.

use super::*;

fn every_state() -> Vec<AccountState> {
    vec![
        AccountState::Ok,
        AccountState::Expired { read_only: true },
        AccountState::Expired { read_only: false },
        AccountState::NeedsLogin,
        AccountState::IdentityUnknown,
        AccountState::StaleSiblingOfLive,
        AccountState::Unclaimed,
        AccountState::Forgotten,
        AccountState::MigratedToKeychain { service: "Claude Code-credentials-5cdc535f".to_owned() },
        AccountState::Adopted { occupant: "someone@example.com".to_owned() },
        AccountState::ClaudeSessionDetected {
            lock: ".oauth_refresh.lock".to_owned(),
            age_ms: 12_000,
        },
        AccountState::KeychainLocked { detail: String::new() },
        AccountState::KeychainLocked { detail: "user cancelled".to_owned() },
        AccountState::KeychainTimeout,
        AccountState::Busy,
        AccountState::LockUnavailable,
        AccountState::Stale,
        AccountState::NoSubscriptionLimits,
        AccountState::PendingReplayed,
        AccountState::PendingDiscarded { reason: "file changed".to_owned() },
        AccountState::RateLimited { retry_after_s: Some(30) },
        AccountState::RateLimited { retry_after_s: None },
        AccountState::RefreshDiscarded,
        AccountState::EnvToken,
        AccountState::Error("something went wrong".to_owned()),
    ]
}

#[test]
fn every_state_has_a_non_empty_label() {
    for state in every_state() {
        let label = state.label();
        assert!(!label.is_empty(), "{state:?} has an empty label");
        assert_eq!(label.trim(), label, "{state:?} has a padded label");
    }
}

#[test]
fn labels_match_the_plan_wording() {
    let tests = [
        (AccountState::Ok, "ok"),
        (AccountState::NeedsLogin, "needs login"),
        (AccountState::IdentityUnknown, "identity unknown"),
        (AccountState::StaleSiblingOfLive, "stale sibling of live"),
        (AccountState::Unclaimed, "unclaimed"),
        (AccountState::KeychainTimeout, "keychain timeout (transient)"),
        (AccountState::Busy, "busy"),
        (AccountState::NoSubscriptionLimits, "no subscription limits (API/console account?)"),
        (AccountState::PendingReplayed, "pending replayed"),
        (
            AccountState::PendingDiscarded { reason: "file changed".to_owned() },
            "pending discarded: file changed",
        ),
        (AccountState::RateLimited { retry_after_s: Some(30) }, "rate-limited (retry in 30s)"),
        (AccountState::RefreshDiscarded, "refresh discarded: namespace changed during refresh"),
    ];
    for (state, expected) in tests {
        assert_eq!(state.label(), expected);
    }
}

#[test]
fn a_detected_session_names_the_lock_and_its_age_in_seconds() {
    let state = AccountState::ClaudeSessionDetected {
        lock: ".oauth_refresh.lock".to_owned(),
        age_ms: 12_400,
    };
    assert_eq!(
        state.label(),
        "claude session detected — refresh refused (lock .oauth_refresh.lock, age 12s)"
    );
}

#[test]
fn informational_states_are_not_failures() {
    // A row that is a true statement about the machine, or that produced
    // numbers, must not make the process exit 2.
    for state in [
        AccountState::Ok,
        AccountState::Unclaimed,
        AccountState::StaleSiblingOfLive,
        AccountState::Forgotten,
        AccountState::PendingReplayed,
        AccountState::EnvToken,
        AccountState::MigratedToKeychain { service: "svc".to_owned() },
    ] {
        assert!(!state.is_failure(), "{state:?} should not be a failure");
    }
}

#[test]
fn degraded_states_are_failures() {
    for state in [
        AccountState::Expired { read_only: true },
        AccountState::Expired { read_only: false },
        AccountState::NeedsLogin,
        AccountState::IdentityUnknown,
        AccountState::ClaudeSessionDetected { lock: "l".to_owned(), age_ms: 0 },
        AccountState::KeychainLocked { detail: String::new() },
        AccountState::KeychainTimeout,
        AccountState::Busy,
        AccountState::LockUnavailable,
        AccountState::Stale,
        AccountState::NoSubscriptionLimits,
        AccountState::PendingDiscarded { reason: "invalid".to_owned() },
        AccountState::RateLimited { retry_after_s: None },
        AccountState::RefreshDiscarded,
        AccountState::Error("boom".to_owned()),
    ] {
        assert!(state.is_failure(), "{state:?} should be a failure");
    }
}

#[test]
fn a_rate_limited_row_never_makes_another_request() {
    // Plan AC8: the point of honouring `retry-after` is not making the call.
    assert!(!AccountState::RateLimited { retry_after_s: Some(30) }.allows_network());
    assert!(!AccountState::RateLimited { retry_after_s: None }.allows_network());
}

#[test]
fn a_read_only_expired_row_does_no_network_but_a_refreshable_one_does() {
    // Decision D-001: the live row is never refreshed, so an expired one has
    // nothing to spend a request on.
    assert!(!AccountState::Expired { read_only: true }.allows_network());
    assert!(AccountState::Expired { read_only: false }.allows_network());
}

#[test]
fn a_detected_session_still_allows_a_usage_fetch() {
    // The refusal is about *refreshing*, which would rotate a token out from
    // under the session. Reading usage with the token already on disk does
    // not disturb anything.
    let state = AccountState::ClaudeSessionDetected { lock: "l".to_owned(), age_ms: 0 };
    assert!(state.allows_network());
    assert!(state.is_failure(), "but the row is still degraded, so exit 2");
}

#[test]
fn states_with_no_credential_do_no_network() {
    for state in [
        AccountState::NeedsLogin,
        AccountState::IdentityUnknown,
        AccountState::Unclaimed,
        AccountState::Forgotten,
        AccountState::StaleSiblingOfLive,
        AccountState::KeychainLocked { detail: String::new() },
        AccountState::KeychainTimeout,
        AccountState::Busy,
        AccountState::LockUnavailable,
    ] {
        assert!(!state.allows_network(), "{state:?} should not reach the network");
    }
}
