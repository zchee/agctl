use std::collections::BTreeSet;

use jiff::Timestamp;

use super::*;

fn every_state() -> Vec<CodexState> {
    vec![
        CodexState::Ok,
        CodexState::Expired { reason: "run agctl codex login".to_owned() },
        CodexState::NeedsLogin,
        CodexState::NoUsageSource { mode: "apikey".to_owned() },
        CodexState::NoUsageWindows,
        CodexState::StoreModeUnsupported { mode: StoreMode::Keyring },
        CodexState::HomeUnreadable { reason: "x".to_owned() },
        CodexState::TornRead,
        CodexState::Unauthorized { refreshed_recently: false },
        CodexState::StaleSiblingOfLive,
        CodexState::Forgotten,
        CodexState::CodexSessionDetected { evidence: "pid alive".to_owned() },
        CodexState::Busy,
        CodexState::LockUnavailable,
        CodexState::Stale,
        CodexState::RateLimited { retry_after: Some(30) },
        CodexState::PendingReplayed,
        CodexState::PendingDiscarded { reason: "invalid".to_owned() },
        CodexState::RefreshDiscarded,
        CodexState::IdentityDrift,
        CodexState::RefreshOutcomeUnknown {
            since: Timestamp::UNIX_EPOCH,
            class: UnknownClass::Interrupted,
            resend_eligible: false,
        },
        CodexState::RefreshStateUnavailable { reason: "x".to_owned() },
        CodexState::RefreshRacedExternal,
        CodexState::RefreshDisabled,
        CodexState::UnauthorizedFloor,
        CodexState::UnauthorizedTerminal,
        CodexState::AdoptedGrantDead,
        CodexState::DiscardedExternal,
        CodexState::Error("x".to_owned()),
    ]
}

#[test]
fn every_state_has_a_distinct_snake_case_name() {
    let states = every_state();
    let names: BTreeSet<&str> = states.iter().map(CodexState::name).collect();
    assert_eq!(names.len(), states.len(), "names are unique: {names:?}");
    for name in names {
        assert!(name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'), "{name}");
    }
}

#[test]
fn only_ok_no_usage_source_and_forgotten_are_exit_neutral() {
    let neutral: Vec<&str> =
        every_state().iter().filter(|s| s.is_exit_neutral()).map(CodexState::name).collect();
    assert_eq!(neutral, ["ok", "no_usage_source", "forgotten"]);
}

#[test]
fn credits_keep_the_wire_string() {
    let credits = CodexCredits::Balance { balance: Some("12.34".to_owned()), unlimited: false };
    assert_ne!(credits, CodexCredits::Unavailable);
    assert!(matches!(credits, CodexCredits::Balance { balance: Some(ref b), .. } if b == "12.34"));
    assert_eq!(StoreMode::Keyring.label(), "keyring");
    assert_eq!(StoreMode::Unknown("x".to_owned()).label(), "x");
}
