//! Tests for the OAuth response types.
//!
//! Thin on purpose: lane D owns this module, and everything worth asserting
//! about a refresh — that `scope` is sent, that an absent `refresh_token`
//! keeps the old one, that seconds become milliseconds — is asserted in
//! `credentials_tests.rs`, where the merging lives.
//!
//! What this file does do is read every field, including the ones lane A does
//! not use, so the module's `dead_code` expectation stays honest in both the
//! test and non-test configurations.

use super::*;

#[test]
fn a_response_carries_every_field_the_exchange_returns() {
    let response = TokenResponse {
        access_token: SecretString::from("access"),
        refresh_token: Some(SecretString::from("refresh")),
        expires_in: 28_800,
        refresh_token_expires_in: Some(2_377_445),
        scope: Some("user:inference".to_owned()),
        token_type: Some("Bearer".to_owned()),
        account: Some(ExchangeAccount {
            uuid: "11111111-1111-4111-8111-111111111111".to_owned(),
            email_address: Some("user@example.com".to_owned()),
        }),
        organization: Some(ExchangeOrganization {
            uuid: "22222222-2222-4222-8222-222222222222".to_owned(),
            name: Some("Example Org".to_owned()),
        }),
        workspace: Some(serde_json::json!({"id": "w", "name": "Workspace"})),
    };

    assert_eq!(response.expires_in, 28_800);
    assert_eq!(response.refresh_token_expires_in, Some(2_377_445));
    assert_eq!(response.scope.as_deref(), Some("user:inference"));
    assert_eq!(response.token_type.as_deref(), Some("Bearer"));
    assert!(response.refresh_token.is_some());
    assert_eq!(
        response.account.as_ref().map(|a| a.uuid.as_str()),
        Some("11111111-1111-4111-8111-111111111111")
    );
    assert_eq!(response.organization.as_ref().and_then(|o| o.name.as_deref()), Some("Example Org"));
    assert_eq!(
        response.workspace.as_ref().and_then(|w| w.get("id")),
        Some(&serde_json::json!("w"))
    );
}

#[test]
fn the_exchange_fixture_deserializes_into_the_account_and_organization_blocks() {
    // The captured response (redacted) from plan step S3. It grew a
    // `token_uuid` field after capture, which must not break parsing.
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/claude/exchange-response.json");
    let bytes =
        std::fs::read(&path).unwrap_or_else(|err| panic!("fixture `{}`: {err}", path.display()));
    let document: serde_json::Value =
        serde_json::from_slice(&bytes).expect("the fixture should be JSON");

    let account: ExchangeAccount =
        serde_json::from_value(document["account"].clone()).expect("account should deserialize");
    let organization: ExchangeOrganization =
        serde_json::from_value(document["organization"].clone())
            .expect("organization should deserialize");

    assert_eq!(account.uuid, "11111111-1111-4111-8111-111111111111");
    assert_eq!(account.email_address.as_deref(), Some("user@example.com"));
    assert_eq!(organization.uuid, "22222222-2222-4222-8222-222222222222");
    assert_eq!(organization.name.as_deref(), Some("Example Org"));
    assert!(document.get("token_uuid").is_some(), "the fixture still carries the new field");
}
