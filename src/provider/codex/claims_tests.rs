use serde_json::json;

use super::*;
use crate::provider::codex::testkit;
use crate::provider::codex::testkit::IdClaims;

#[test]
fn the_allowlist_is_read_from_a_synthetic_id_token() {
    // Plan AC89: every allowlisted claim, including the FedRAMP flag.
    let claims = IdClaims { fedramp: Some(true), ..IdClaims::default() };
    let parsed = parse(&testkit::id_token(&claims)).expect("a well-formed token parses");
    assert_eq!(
        parsed,
        Claims {
            email: Some("codex-user@example.invalid".to_owned()),
            chatgpt_user_id: Some(testkit::USER.to_owned()),
            chatgpt_account_id: Some(testkit::ACCT.to_owned()),
            plan_type: Some("pro".to_owned()),
            is_fedramp: true,
            exp: Some(1_788_734_450),
        }
    );
}

#[test]
fn missing_claims_are_none_and_fedramp_defaults_to_false() {
    let claims = IdClaims { user: None, acct: None, email: None, plan: None, fedramp: None };
    let parsed =
        parse(&testkit::id_token(&claims)).expect("a token without identity claims still parses");
    assert_eq!(parsed.email, None);
    assert_eq!(parsed.chatgpt_user_id, None);
    assert_eq!(parsed.chatgpt_account_id, None);
    assert_eq!(parsed.plan_type, None);
    assert!(!parsed.is_fedramp);
}

#[test]
fn fallbacks_follow_codex_email_from_profile_and_user_from_user_id() {
    // Fact F85: `email` falls back to the profile claim, `chatgpt_user_id` to
    // `user_id`.
    let payload = json!({
        "https://api.openai.com/profile": { "email": "profile@example.invalid" },
        "https://api.openai.com/auth": { "user_id": "user-fallback", "chatgpt_account_is_fedramp": "yes" },
    });
    let parsed = parse(&testkit::jwt(&payload, testkit::JWT_SENTINEL)).expect("parses");
    assert_eq!(parsed.email.as_deref(), Some("profile@example.invalid"));
    assert_eq!(parsed.chatgpt_user_id.as_deref(), Some("user-fallback"));
    assert!(!parsed.is_fedramp, "a non-boolean flag is not `true`");
}

#[test]
fn malformed_tokens_are_errors_that_name_no_token_byte() {
    // Plan AC89: malformed → an error, no panic, and nothing of the input in
    // the message.
    let good = testkit::id_token(&IdClaims::default());
    let mut parts = good.split('.');
    let header = parts.next().unwrap_or_default();
    let tests: [(&str, String, ClaimsError); 7] = [
        ("empty", String::new(), ClaimsError::Shape),
        ("two segments", format!("{header}.{}", testkit::JWT_SENTINEL), ClaimsError::Shape),
        ("four segments", format!("{good}.extra"), ClaimsError::Shape),
        ("empty payload", format!("{header}..{}", testkit::JWT_SENTINEL), ClaimsError::Shape),
        (
            "not base64url",
            format!("{header}.agctl-test-codex-jwt-!!.{}", testkit::JWT_SENTINEL),
            ClaimsError::Encoding,
        ),
        (
            "not an object",
            testkit::jwt(&json!(["agctl-test-codex-jwt-array"]), testkit::JWT_SENTINEL),
            ClaimsError::Json,
        ),
        ("too large", format!("{header}.{}.x", "A".repeat(300 * 1024)), ClaimsError::TooLarge),
    ];
    for (name, token, expected) in tests {
        let err = parse(&token).expect_err(name);
        assert_eq!(err, expected, "{name}");
        let rendered = format!("{err} {err:?}");
        testkit::assert_no_needles(&rendered, name);
        assert!(!rendered.contains(header), "{name}: the error quoted the token");
    }
}

#[test]
fn padding_is_tolerated() {
    let token = testkit::id_token(&IdClaims::default());
    let mut parts: Vec<&str> = token.split('.').collect();
    let padded = format!("{}==", parts[1]);
    parts[1] = &padded;
    assert!(parse(&parts.join(".")).is_ok());
}

#[test]
fn the_debug_render_carries_no_token_byte_and_no_claim_outside_the_allowlist() {
    // Plan AC89: `Claims` is allowlist-only, so its derived `Debug` cannot
    // carry the organization title or session id the token also holds.
    let token = testkit::id_token(&IdClaims::default());
    let parsed = parse(&token).expect("parses");
    for rendered in [format!("{parsed:?}"), format!("{parsed:#?}")] {
        testkit::assert_no_needles(&rendered, "Claims Debug");
        assert!(!rendered.contains(&token[..20]), "a token prefix leaked");
    }
}

#[test]
fn expiry_reads_exp_alone_and_none_without_it() {
    assert_eq!(expiry(&testkit::access_token(Some(42))), Ok(Some(42)));
    assert_eq!(expiry(&testkit::access_token(None)), Ok(None));
    assert_eq!(
        expiry(testkit::RT_SENTINEL),
        Err(ClaimsError::Shape),
        "an opaque refresh token is not a JWT"
    );
}
