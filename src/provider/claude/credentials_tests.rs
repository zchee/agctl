//! Tests for the credential blob (plan AC29, AC30, facts F4, F8, F18, F27).

use std::path::PathBuf;

use super::*;

/// A fixture blob, read from `fixtures/claude/`.
fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/claude").join(name);
    std::fs::read(&path).unwrap_or_else(|err| panic!("fixture `{}`: {err}", path.display()))
}

fn parse(name: &str) -> Credentials {
    Credentials::parse_blob(&fixture(name))
        .unwrap_or_else(|err| panic!("fixture `{name}` should parse: {err}"))
}

fn token_response(expires_in: i64, refresh: Option<&str>) -> TokenResponse {
    TokenResponse {
        access_token: SecretString::from("new-access"),
        refresh_token: refresh.map(SecretString::from),
        expires_in,
        refresh_token_expires_in: None,
        scope: None,
        token_type: Some("Bearer".to_owned()),
        account: None,
        organization: None,
        workspace: None,
    }
}

#[test]
fn parses_an_old_blob_without_the_newer_fields() {
    let credentials = parse("credentials-old-blob.json");
    assert_eq!(credentials.expires_at_ms, 1_756_000_000_000);
    assert_eq!(credentials.refresh_token_expires_at_ms, None);
    assert_eq!(credentials.client_id, None);
    assert_eq!(credentials.token_account, None);
    assert_eq!(credentials.scopes, ["user:inference", "user:profile"]);
    assert_eq!(credentials.subscription_type.as_deref(), Some("max"));
    assert!(credentials.refresh_token.is_some());
    // An old blob carries no identity, which is what makes `identity unknown`
    // a state a real account can be in (plan AC39).
    assert_eq!(credentials.identity(), None);
}

#[test]
fn parses_a_new_blob_including_the_identity_block() {
    let credentials = parse("credentials-new-blob.json");
    assert_eq!(credentials.client_id.as_deref(), Some(CLIENT_ID));
    assert_eq!(credentials.scopes, DEFAULT_SCOPES);
    assert_eq!(credentials.refresh_token_expires_at_ms, Some(1_759_900_000_000));

    let identity = credentials.identity().expect("a new blob names its account");
    assert_eq!(identity.account_uuid, "11111111-1111-4111-8111-111111111111");
    assert_eq!(identity.organization_uuid.as_deref(), Some("22222222-2222-4222-8222-222222222222"));
    assert_eq!(identity.email.as_deref(), Some("user@example.com"));
    assert_eq!(identity.org_name.as_deref(), Some("Example Org"));
}

#[test]
fn rejects_a_blob_missing_a_required_field() {
    let tests = [
        ("not json at all", &b"{"[..], "Json"),
        ("no root object", &br#"{"other": {}}"#[..], "MissingRoot"),
        ("no access token", &br#"{"claudeAiOauth": {"expiresAt": 1}}"#[..], "MissingField"),
        ("no expiry", &br#"{"claudeAiOauth": {"accessToken": "a"}}"#[..], "MissingField"),
    ];
    for (name, bytes, expected) in tests {
        let err = Credentials::parse_blob(bytes)
            .err()
            .unwrap_or_else(|| panic!("{name}: should not parse"));
        let actual = format!("{err:?}");
        assert!(actual.starts_with(expected), "{name}: got {actual}");
    }
}

#[test]
fn round_trips_unknown_keys() {
    // `profile` is a real field this build does not model, and the exchange
    // response recently grew `token_uuid`. Losing either on a refresh would
    // silently degrade the Claude Code session that reads the file next.
    let blob = br#"{"claudeAiOauth":{"accessToken":"a","expiresAt":5,"scopes":[],"profile":{"x":1},"tokenUuid":"u"}}"#;
    let credentials = Credentials::parse_blob(blob).expect("the blob should parse");
    assert_eq!(credentials.extra.len(), 2, "unknown keys are kept: {:?}", credentials.extra);

    let written = credentials.to_blob_json();
    let reparsed: serde_json::Value =
        serde_json::from_str(&written).expect("the output should be JSON");
    let inner = reparsed.get(BLOB_ROOT).and_then(serde_json::Value::as_object).expect("root");
    assert_eq!(inner.get("profile"), Some(&serde_json::json!({"x": 1})));
    assert_eq!(inner.get("tokenUuid"), Some(&serde_json::json!("u")));
    assert_eq!(inner.get("accessToken"), Some(&serde_json::json!("a")));
    assert!(!inner.contains_key("refreshToken"), "an absent optional is omitted, not null");
}

#[test]
fn to_blob_json_round_trips_a_fixture_field_for_field() {
    let credentials = parse("credentials-new-blob.json");
    let written = credentials.to_blob_json();
    let reparsed = Credentials::parse_blob(written.as_bytes()).expect("the output should reparse");

    assert_eq!(reparsed.digests(), credentials.digests());
    assert_eq!(reparsed.expires_at_ms, credentials.expires_at_ms);
    assert_eq!(reparsed.refresh_token_expires_at_ms, credentials.refresh_token_expires_at_ms);
    assert_eq!(reparsed.scopes, credentials.scopes);
    assert_eq!(reparsed.token_account, credentials.token_account);
    assert_eq!(reparsed.client_id, credentials.client_id);
    assert_eq!(reparsed.extra, credentials.extra);
}

#[test]
fn access_expired_uses_the_five_minute_margin() {
    // Plan AC30: 4 minutes to expiry refreshes, 6 minutes does not.
    let mut credentials = parse("credentials-new-blob.json");
    let now = 1_000_000_000_000;
    credentials.expires_at_ms = now + 4 * 60 * 1000;
    assert!(credentials.access_expired(now, REFRESH_MARGIN_MS), "4 minutes should refresh");

    credentials.expires_at_ms = now + 6 * 60 * 1000;
    assert!(!credentials.access_expired(now, REFRESH_MARGIN_MS), "6 minutes should not refresh");
}

#[test]
fn access_expired_treats_overflow_as_expired() {
    let mut credentials = parse("credentials-new-blob.json");
    credentials.expires_at_ms = i64::MAX;
    assert!(
        credentials.access_expired(i64::MAX, REFRESH_MARGIN_MS),
        "an overflowing sum must not wrap into a distant future"
    );
}

#[test]
fn merge_refresh_keeps_the_old_refresh_token_when_the_server_sends_none() {
    let mut credentials = parse("credentials-new-blob.json");
    let before = credentials.digests();

    credentials.merge_refresh(token_response(3600, None), 1_000_000_000_000).expect("merge");

    let after = credentials.digests();
    assert_ne!(after.access_sha256, before.access_sha256, "the access token was replaced");
    assert_eq!(after.refresh_sha256, before.refresh_sha256, "the refresh chain was kept (fact F8)");
    assert_eq!(credentials.expires_at_ms, 1_000_000_000_000 + 3_600_000, "seconds became millis");
}

#[test]
fn merge_refresh_takes_a_rotated_refresh_token() {
    let mut credentials = parse("credentials-new-blob.json");
    let before = credentials.digests();
    credentials
        .merge_refresh(token_response(60, Some("rotated-refresh")), 0)
        .expect("merge should succeed");
    assert_ne!(credentials.digests().refresh_sha256, before.refresh_sha256);
}

#[test]
fn merge_refresh_replaces_scopes_only_when_the_server_names_them() {
    let mut credentials = parse("credentials-old-blob.json");
    let mut response = token_response(60, None);
    response.scope = Some("user:inference user:profile user:sessions:claude_code".to_owned());
    credentials.merge_refresh(response, 0).expect("merge should succeed");
    assert_eq!(credentials.scopes, ["user:inference", "user:profile", "user:sessions:claude_code"]);

    credentials.merge_refresh(token_response(60, None), 0).expect("merge should succeed");
    assert_eq!(credentials.scopes.len(), 3, "an absent `scope` leaves the stored set alone");
}

#[test]
fn merge_refresh_reports_an_overflowing_expiry() {
    let mut credentials = parse("credentials-new-blob.json");
    let err = credentials
        .merge_refresh(token_response(i64::MAX, None), 0)
        .expect_err("an absurd lifetime should not wrap");
    assert!(matches!(err, CredentialsError::ExpiryOverflow("expires_in")), "got {err:?}");
}

#[test]
fn merge_refresh_carries_a_new_refresh_expiry_and_keeps_an_absent_one() {
    let mut credentials = parse("credentials-new-blob.json");
    let mut response = token_response(60, None);
    response.refresh_token_expires_in = Some(120);
    credentials.merge_refresh(response, 1000).expect("merge should succeed");
    assert_eq!(credentials.refresh_token_expires_at_ms, Some(121_000));

    credentials.merge_refresh(token_response(60, None), 1000).expect("merge should succeed");
    assert_eq!(
        credentials.refresh_token_expires_at_ms,
        Some(121_000),
        "absent keeps the old value"
    );
}

#[test]
fn refresh_body_carries_the_scopes_and_client_id() {
    // Plan AC29: the body must include `scope`, or the server narrows the
    // grant to its default single scope (fact F28).
    let credentials = parse("credentials-new-blob.json");
    let body = credentials.refresh_body(CLIENT_ID).expect("there is a refresh token");
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("the body should be JSON");

    assert_eq!(parsed["grant_type"], "refresh_token");
    assert_eq!(parsed["client_id"], CLIENT_ID);
    assert_eq!(parsed["scope"], DEFAULT_SCOPES.join(" "));
    assert_eq!(
        parsed["refresh_token"],
        "sk-ant-ort01-FAKE-NEW-REFRESH-TOKEN-NOT-A-REAL-CREDENTIAL"
    );
}

#[test]
fn refresh_body_refuses_an_account_with_no_refresh_token() {
    let blob = br#"{"claudeAiOauth":{"accessToken":"a","expiresAt":1,"scopes":[]}}"#;
    let credentials = Credentials::parse_blob(blob).expect("the blob should parse");
    assert!(matches!(credentials.refresh_body(CLIENT_ID), Err(CredentialsError::NoRefreshToken)));
}

#[test]
fn digests_are_the_sha256_of_the_token_text() {
    let blob = br#"{"claudeAiOauth":{"accessToken":"abc","refreshToken":"def","expiresAt":1}}"#;
    let credentials = Credentials::parse_blob(blob).expect("the blob should parse");
    let digests = credentials.digests();
    // sha256("abc") and sha256("def"), so the digest scheme is pinned rather
    // than merely self-consistent.
    assert_eq!(
        digests.access_sha256,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        digests.refresh_sha256.as_deref(),
        Some("cb8379ac2098aa165029e3938a51da0bcecfc008fd6795f401178647f96c5b34")
    );
}

#[test]
fn debug_never_prints_a_token() {
    let credentials = parse("credentials-new-blob.json");
    let rendered = format!("{credentials:?}");
    assert!(!rendered.contains("sk-ant-"), "Debug leaked a token: {rendered}");
    assert!(rendered.contains("<redacted>"));
    assert!(rendered.contains(&credentials.digests().access_sha256));
}

#[test]
fn a_wrong_typed_known_key_keeps_its_place_among_the_unknown_ones() {
    // A blob whose `subscriptionType` is a number rather than a string is not
    // something to lose, and not something to reorder either: `extra` is an
    // index-backed map, so a remove-then-reinsert would move the key to the
    // end and change the bytes agentctl writes back for a file it did not
    // author.
    let blob = br#"{"claudeAiOauth":{"accessToken":"a","expiresAt":5,"alpha":1,"subscriptionType":7,"omega":2}}"#;
    let credentials = Credentials::parse_blob(blob).expect("the blob should parse");
    assert_eq!(credentials.subscription_type, None, "a number is not a subscription type");

    let keys: Vec<&str> = credentials.extra.keys().map(String::as_str).collect();
    assert_eq!(keys, ["alpha", "subscriptionType", "omega"], "the key moved");
    assert_eq!(credentials.extra.get("subscriptionType"), Some(&serde_json::json!(7)));
}

#[test]
fn a_wrong_typed_expiry_keeps_its_place_too() {
    let blob = br#"{"claudeAiOauth":{"accessToken":"a","expiresAt":5,"alpha":1,"refreshTokenExpiresAt":"soon","omega":2}}"#;
    let credentials = Credentials::parse_blob(blob).expect("the blob should parse");
    assert_eq!(credentials.refresh_token_expires_at_ms, None);

    let keys: Vec<&str> = credentials.extra.keys().map(String::as_str).collect();
    assert_eq!(keys, ["alpha", "refreshTokenExpiresAt", "omega"], "the key moved");
}
