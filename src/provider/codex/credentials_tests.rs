use std::time::Duration;

use jiff::Timestamp;
use serde_json::Value;
use serde_json::json;

use super::*;
use crate::provider::AccountRef;
use crate::provider::codex::testkit;
use crate::provider::codex::testkit::IdClaims;

fn parse_value(value: &Value) -> Credentials {
    Credentials::parse(&testkit::pretty(value)).expect("a synthetic document parses")
}

fn written(credentials: &Credentials) -> Vec<u8> {
    let mut out = Vec::new();
    credentials.write_json_to(&mut out).expect("writing to a Vec cannot fail");
    out
}

#[test]
fn a_codex_format_file_round_trips_byte_for_byte() {
    // Plan AC87, fact F90: pretty, two-space indent, no trailing newline.
    let original = testkit::fixture("auth-codex-format.json");
    assert_ne!(original.last(), Some(&b'\n'), "the fixture itself has no trailing newline");
    let credentials = Credentials::parse(&original).expect("the fixture parses");
    assert_eq!(String::from_utf8_lossy(&written(&credentials)), String::from_utf8_lossy(&original));
}

#[test]
fn unknown_members_keep_their_positions_everywhere() {
    // Plan AC87: unknown members at the top level, inside `tokens`, and
    // between known keys all come back where they were.
    let original = testkit::fixture("auth-unknown-members.json");
    let credentials = Credentials::parse(&original).expect("the fixture parses");
    let out = written(&credentials);
    assert_eq!(String::from_utf8_lossy(&out), String::from_utf8_lossy(&original));
    let value: Value = serde_json::from_slice(&out).expect("valid JSON");
    let top: Vec<&str> =
        value.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
    assert_eq!(
        top,
        [
            "x_agctl_first",
            "auth_mode",
            "x_agctl_between",
            "OPENAI_API_KEY",
            "tokens",
            "last_refresh",
            "x_agctl_last"
        ]
    );
}

#[test]
fn other_modes_round_trip_with_their_secrets() {
    // The API-key member is a secret too: taken out at parse, put back on write.
    let original = testkit::fixture("auth-apikey.json");
    let credentials = Credentials::parse(&original).expect("parses");
    assert_eq!(written(&credentials), original);
    let object_secret = json!({ "bedrock_access_keys": { "id": "agctl-test-codex-ak-id", "secret": "agctl-test-codex-ak-secret", "n": 1.5 } });
    let credentials = parse_value(&object_secret);
    assert_eq!(written(&credentials), testkit::pretty(&object_secret));
}

#[test]
fn auth_mode_inference_table() {
    // Plan AC88 / fact F61: explicit wins; else PAT → Bedrock → API key → ChatGPT.
    let tests: [(&str, Value, AuthMode, bool); 10] = [
        (
            "explicit chatgpt",
            testkit::chatgpt_doc(Some(4_102_444_800), None),
            AuthMode::ChatGpt,
            true,
        ),
        (
            "explicit wins over a key",
            json!({ "auth_mode": "chatgptauthtokens", "OPENAI_API_KEY": testkit::AK_SENTINEL, "tokens": { "access_token": testkit::access_token(None) } }),
            AuthMode::ChatGptAuthTokens,
            true,
        ),
        (
            "explicit apikey",
            json!({ "auth_mode": "apikey", "OPENAI_API_KEY": testkit::AK_SENTINEL }),
            AuthMode::ApiKey,
            false,
        ),
        (
            "inferred apikey",
            json!({ "OPENAI_API_KEY": testkit::AK_SENTINEL }),
            AuthMode::ApiKey,
            false,
        ),
        (
            "inferred pat beats key",
            json!({ "OPENAI_API_KEY": testkit::AK_SENTINEL, "personal_access_token": "agctl-test-codex-ak-pat" }),
            AuthMode::PersonalAccessToken,
            false,
        ),
        (
            "inferred bedrock key",
            json!({ "bedrock_api_key": "agctl-test-codex-ak-bedrock" }),
            AuthMode::BedrockApiKey,
            false,
        ),
        (
            "inferred bedrock access keys",
            json!({ "bedrock_access_keys": { "id": "x" } }),
            AuthMode::BedrockAccessKeys,
            false,
        ),
        (
            "null key is not a key",
            json!({ "OPENAI_API_KEY": null, "tokens": { "access_token": testkit::access_token(None) } }),
            AuthMode::ChatGpt,
            true,
        ),
        (
            "unknown explicit",
            json!({ "auth_mode": "workload" }),
            AuthMode::Unknown("workload".to_owned()),
            false,
        ),
        (
            "chatgpt without an access token",
            json!({ "auth_mode": "chatgpt" }),
            AuthMode::ChatGpt,
            false,
        ),
    ];
    for (name, doc, mode, usage) in tests {
        let credentials = parse_value(&doc);
        assert_eq!(*credentials.auth_mode(), mode, "{name}");
        assert_eq!(credentials.has_usage_source(), usage, "{name}");
    }
    let hostile =
        parse_value(&json!({ "auth_mode": "agctl-test-codex-ak-looks-like-a-key-0123456789" }));
    assert_eq!(hostile.auth_mode().label(), "<unrecognised>", "an odd mode is not echoed");
}

#[test]
fn wrong_types_and_torn_documents_are_named_errors() {
    let tests: [(&str, &[u8], CredentialsError); 7] = [
        ("empty", b"", CredentialsError::Truncated),
        (
            "cut off",
            br#"{"auth_mode": "chatgpt", "tokens": {"access_"#,
            CredentialsError::Truncated,
        ),
        ("not json", b"}{", CredentialsError::Json { line: 1, column: 1 }),
        ("array", b"[]", CredentialsError::NotAnObject),
        (
            "tokens not object",
            br#"{"tokens": "agctl-test-codex-at-x"}"#,
            CredentialsError::WrongType("tokens"),
        ),
        (
            "token not string",
            br#"{"tokens": {"access_token": 7}}"#,
            CredentialsError::WrongType("access_token"),
        ),
        ("mode not string", br#"{"auth_mode": 7}"#, CredentialsError::WrongType("auth_mode")),
    ];
    for (name, bytes, expected) in tests {
        let err = Credentials::parse(bytes).expect_err(name);
        assert_eq!(err, expected, "{name}");
        testkit::assert_no_needles(&format!("{err} {err:?}"), name);
    }
    let bad_id = json!({ "tokens": { "id_token": "agctl-test-codex-jwt-not.a.jwt!", "access_token": testkit::access_token(None) } });
    let err = Credentials::parse(&testkit::pretty(&bad_id)).expect_err("a bad id token");
    assert!(matches!(err, CredentialsError::Claims(_)), "{err:?}");
    testkit::assert_no_needles(&format!("{err} {err:?}"), "claims error");
}

#[test]
fn access_expired_boundaries() {
    // Plan AC90: `exp = now + 5 min ± 1 s`; the `last_refresh + 8 d ± 1 s`
    // fallback; neither → expired.
    let now = Timestamp::from_second(1_800_000_000).expect("a valid instant");
    let margin = ACCESS_REFRESH_MARGIN;
    let at = |exp: i64| parse_value(&testkit::chatgpt_doc(Some(exp), None));
    assert!(at(1_800_000_300 - 1).access_expired(now, margin), "exp one second inside the margin");
    assert!(at(1_800_000_300).access_expired(now, margin), "exp exactly at the margin (<=)");
    assert!(!at(1_800_000_300 + 1).access_expired(now, margin), "exp one second outside");

    let eight_days = 8 * 86_400;
    let refreshed = |secs: i64| {
        let stamp = Timestamp::from_second(secs).expect("valid").to_string();
        parse_value(&testkit::chatgpt_doc(None, Some(&stamp)))
    };
    assert!(
        refreshed(1_800_000_000 - eight_days - 1).access_expired(now, margin),
        "older than 8 days"
    );
    assert!(
        !refreshed(1_800_000_000 - eight_days).access_expired(now, margin),
        "exactly 8 days is not older"
    );
    assert!(
        !refreshed(1_800_000_000 - eight_days + 1).access_expired(now, margin),
        "younger than 8 days"
    );

    assert!(
        parse_value(&testkit::chatgpt_doc(None, None)).access_expired(now, margin),
        "neither known"
    );
    assert!(
        parse_value(&testkit::chatgpt_doc(None, Some("not a time"))).access_expired(now, margin),
        "an unreadable last_refresh is unknown"
    );
    // Checked arithmetic: a margin that overflows is "expired", not a wrap.
    assert!(at(i64::MAX).access_expired(now, Duration::from_secs(u64::MAX)));
    assert!(
        at(i64::MAX).access_expired(Timestamp::MAX, Duration::from_secs(i64::MAX.unsigned_abs()))
    );
}

#[test]
fn identity_prefers_tokens_account_id_and_flags_drift() {
    let credentials = parse_value(&testkit::chatgpt_doc(Some(4_102_444_800), None));
    assert_eq!(
        credentials.identity(),
        Some(CodexIdentity {
            user_id: testkit::USER.to_owned(),
            account_id: testkit::ACCT.to_owned(),
            email: Some("codex-user@example.invalid".to_owned()),
            plan: Some("pro".to_owned()),
        })
    );
    assert!(!credentials.identity_drift());

    let mut drifted = testkit::chatgpt_doc(Some(4_102_444_800), None);
    drifted["tokens"]["account_id"] = json!("22222222-2222-4333-8444-555555555555");
    let drifted = parse_value(&drifted);
    assert_eq!(
        drifted.identity().map(|i| i.account_id).as_deref(),
        Some("22222222-2222-4333-8444-555555555555")
    );
    assert!(drifted.identity_drift(), "F92: kept account id vs new claim");

    let mut odd_plan = testkit::chatgpt_doc(Some(4_102_444_800), None);
    odd_plan["tokens"]["id_token"] = json!(testkit::id_token(&IdClaims {
        plan: Some("mystery_tier".to_owned()),
        ..IdClaims::default()
    }));
    assert_eq!(parse_value(&odd_plan).identity().and_then(|i| i.plan).as_deref(), Some("unknown"));

    let mut no_user = testkit::chatgpt_doc(Some(4_102_444_800), None);
    no_user["tokens"]["id_token"] =
        json!(testkit::id_token(&IdClaims { user: None, ..IdClaims::default() }));
    assert_eq!(parse_value(&no_user).identity(), None);
}

#[test]
fn debug_of_the_credential_formatted_alone_carries_no_secret() {
    // S29b seam review: `AccountRef`'s own `Debug` does not cover a
    // `Credentials` formatted directly, so this type redacts for itself.
    let mut doc = testkit::chatgpt_doc(Some(4_102_444_800), Some("2026-09-06T21:40:50Z"));
    doc["x_agctl_unknown_secret"] = json!("agctl-test-codex-ak-unknown-member");
    doc["OPENAI_API_KEY"] = json!(testkit::AK_SENTINEL);
    let credentials = parse_value(&doc);
    for rendered in [format!("{credentials:?}"), format!("{credentials:#?}")] {
        testkit::assert_no_needles(&rendered, "Credentials Debug");
        assert!(rendered.contains(testkit::ACCT), "the ids are shown: {rendered}");
        assert!(!rendered.to_ascii_lowercase().contains("bearer"), "{rendered}");
    }
}

#[test]
fn an_account_ref_over_codex_credentials_renders_no_token_and_no_bearer() {
    // Plan AC96 for the Codex half.
    let credentials = parse_value(&testkit::chatgpt_doc(Some(4_102_444_800), None));
    let account = AccountRef { id: "codex-row", auth: &credentials };
    for rendered in [format!("{account:?}"), format!("{account:#?}")] {
        testkit::assert_no_needles(&rendered, "AccountRef Debug");
        assert!(!rendered.to_ascii_lowercase().contains("bearer"), "{rendered}");
    }
}

#[test]
fn the_usage_headers_are_built_from_the_file() {
    let credentials = parse_value(&testkit::chatgpt_doc(Some(4_102_444_800), None));
    let header = credentials.authorization_header();
    assert_eq!(header, format!("Bearer {}", testkit::access_token(Some(4_102_444_800))));
    assert_eq!(credentials.extra_headers(), vec![("ChatGPT-Account-Id", testkit::ACCT.to_owned())]);

    let mut fedramp = testkit::chatgpt_doc(Some(4_102_444_800), None);
    fedramp["tokens"]["id_token"] =
        json!(testkit::id_token(&IdClaims { fedramp: Some(true), ..IdClaims::default() }));
    assert_eq!(
        parse_value(&fedramp).extra_headers(),
        vec![
            ("ChatGPT-Account-Id", testkit::ACCT.to_owned()),
            ("X-OpenAI-Fedramp", "true".to_owned())
        ]
    );

    let mut hostile = testkit::chatgpt_doc(Some(4_102_444_800), None);
    hostile["tokens"]["account_id"] = json!("acct\r\nX-Injected: 1");
    assert!(parse_value(&hostile).extra_headers().is_empty(), "a header-splitting id is not sent");

    let apikey = Credentials::parse(&testkit::fixture("auth-apikey.json")).expect("parses");
    assert_eq!(apikey.authorization_header(), "", "no access token, no bearer");
}

#[test]
fn digests_are_sha256_of_the_tokens() {
    let credentials = parse_value(&testkit::chatgpt_doc(Some(4_102_444_800), None));
    let digests = credentials.digests().expect("an access token");
    assert_eq!(digests.access_sha256, sha256_hex(&testkit::access_token(Some(4_102_444_800))));
    assert_eq!(digests.refresh_sha256.as_deref(), Some(sha256_hex(testkit::RT_SENTINEL).as_str()));
    assert_eq!(
        credentials.refresh_digest8().as_deref(),
        Some(&sha256_hex(testkit::RT_SENTINEL)[..8])
    );
    assert_eq!(
        Credentials::parse(&testkit::fixture("auth-apikey.json")).ok().and_then(|c| c.digests()),
        None
    );
}

#[test]
fn pending_credential_rules() {
    let bytes = testkit::fresh_auth_bytes();
    assert!(<Credentials as PendingCredential>::validate(&bytes));
    assert!(!<Credentials as PendingCredential>::validate(b"{\"auth_mode\":"));
    assert!(
        !<Credentials as PendingCredential>::validate(&testkit::fixture("auth-apikey.json")),
        "no tokens to replay"
    );
    assert_eq!(
        <Credentials as PendingCredential>::digests(&bytes),
        Credentials::parse(&bytes).ok().and_then(|c| c.digests())
    );
    const { assert!(!<Credentials as PendingCredential>::UNUSABLE_IS_ABSENT) };
    const { assert!(!<Credentials as PendingCredential>::META_REQUIRES_EXPIRY) };
}

fn locked<'g>(credentials: Credentials, guard: &'g CodexNamespaceGuard) -> LockedCredentials<'g> {
    LockedCredentials::from_locked_read(credentials, (testkit::USER, testkit::ACCT), guard)
}

#[test]
fn merge_refresh_changes_at_most_four_leaves() {
    // Plan AC87's second half: a serde_json leaf diff lists exactly the
    // returned tokens and `last_refresh`, and `account_id` is kept.
    let (_dir, paths) = testkit::store();
    let guard = testkit::lock_for(&paths, &testkit::owned_record(testkit::USER, testkit::ACCT));
    let original = testkit::fixture("auth-unknown-members.json");
    let before: Value = serde_json::from_slice(&original).expect("json");
    let credentials = locked(Credentials::parse(&original).expect("parses"), &guard);

    let new_access = testkit::access_token(Some(4_102_444_900));
    let new_id = testkit::id_token(&IdClaims::default());
    let body = json!({ "access_token": new_access, "id_token": new_id, "refresh_token": "agctl-test-codex-rt-0002" });
    let response =
        RefreshResponse::parse(&serde_json::to_vec(&body).expect("json")).expect("parses");
    let now = Timestamp::from_second(1_800_000_000).expect("valid");
    let (merged, outcome) = credentials.merge_refresh(response, now).expect("merges");
    assert_eq!(
        outcome,
        MergeOutcome { identity_drift: false, refresh_rotated: true, id_token_unreadable: false }
    );

    let after: Value = serde_json::from_slice(&written(merged.credentials())).expect("json");
    let (old, new) = (testkit::leaves(&before), testkit::leaves(&after));
    let changed: Vec<&String> =
        new.iter().filter(|(k, v)| old.get(*k) != Some(*v)).map(|(k, _)| k).collect();
    assert_eq!(
        changed,
        ["/last_refresh", "/tokens/access_token", "/tokens/id_token", "/tokens/refresh_token"],
        "exactly the three returned tokens and the stamp"
    );
    assert_eq!(old.len(), new.len(), "no leaf added or removed");
    assert_eq!(after["last_refresh"], json!("2027-01-15T08:00:00Z"));
    assert_eq!(after["tokens"]["account_id"], json!(testkit::ACCT));
}

#[test]
fn merge_refresh_keeps_absent_tokens_and_stamps_last_refresh() {
    // Fact F92: every response member is optional; absent means "keep".
    let (_dir, paths) = testkit::store();
    let guard = testkit::lock_for(&paths, &testkit::owned_record(testkit::USER, testkit::ACCT));
    let original = testkit::fixture("auth-codex-format.json");
    let credentials = locked(Credentials::parse(&original).expect("parses"), &guard);
    let response = RefreshResponse::parse(b"{}").expect("an empty object parses");
    let now = Timestamp::from_second(1_800_000_000).expect("valid")
        + jiff::SignedDuration::from_micros(123_456);
    let (merged, outcome) = credentials.merge_refresh(response, now).expect("merges");
    assert_eq!(
        outcome,
        MergeOutcome { identity_drift: false, refresh_rotated: false, id_token_unreadable: false }
    );
    let after: Value = serde_json::from_slice(&written(merged.credentials())).expect("json");
    let before: Value = serde_json::from_slice(&original).expect("json");
    let (old, new) = (testkit::leaves(&before), testkit::leaves(&after));
    let changed: Vec<&String> =
        new.iter().filter(|(k, v)| old.get(*k) != Some(*v)).map(|(k, _)| k).collect();
    assert_eq!(changed, ["/last_refresh"]);
    assert_eq!(
        after["last_refresh"],
        json!("2027-01-15T08:00:00.123456Z"),
        "chrono AutoSi spelling"
    );
}

#[test]
fn merge_refresh_flags_identity_drift_and_keeps_the_grant_over_a_bad_id_token() {
    let (_dir, paths) = testkit::store();
    let guard = testkit::lock_for(&paths, &testkit::owned_record(testkit::USER, testkit::ACCT));
    let bytes = testkit::fresh_auth_bytes();
    let other = testkit::id_token(&IdClaims {
        acct: Some("99999999-2222-4333-8444-555555555555".to_owned()),
        ..IdClaims::default()
    });
    let response =
        RefreshResponse::parse(&serde_json::to_vec(&json!({ "id_token": other })).expect("json"))
            .expect("parses");
    let (merged, outcome) = locked(Credentials::parse(&bytes).expect("parses"), &guard)
        .merge_refresh(response, Timestamp::now())
        .expect("merges");
    assert!(outcome.identity_drift);
    assert_eq!(
        merged.credentials().identity().map(|i| i.account_id).as_deref(),
        Some(testkit::ACCT),
        "kept"
    );

    // Review S30 F3: an id token the allowlist decoder refuses must not cost
    // the rotated grant. The file's id token is kept, the new access and
    // refresh tokens land, and the outcome says so.
    let original = Credentials::parse(&bytes).expect("parses");
    let id_before = {
        let mut out = Vec::new();
        original.write_json_to(&mut out).expect("serializes");
        serde_json::from_slice::<Value>(&out).expect("json")["tokens"]["id_token"].clone()
    };
    let bad = RefreshResponse::parse(
        br#"{"id_token":"agctl-test-codex-jwt-garbage","access_token":"agctl-test-codex-at-new","refresh_token":"agctl-test-codex-rt-rotated"}"#,
    )
    .expect("parses");
    let (merged, outcome) = locked(original, &guard)
        .merge_refresh(bad, Timestamp::now())
        .expect("an unreadable id token does not fail the merge");
    assert_eq!(
        outcome,
        MergeOutcome { identity_drift: false, refresh_rotated: true, id_token_unreadable: true }
    );
    let after: Value = serde_json::from_slice(&written(merged.credentials())).expect("json");
    assert_eq!(after["tokens"]["id_token"], id_before, "the file's id token is kept");
    assert_eq!(after["tokens"]["access_token"], json!("agctl-test-codex-at-new"));
    assert_eq!(after["tokens"]["refresh_token"], json!("agctl-test-codex-rt-rotated"));
    assert_eq!(merged.ids(), (testkit::USER, testkit::ACCT), "the namespace survives a merge");
    assert!(
        Credentials::parse(&written(merged.credentials())).is_ok(),
        "the written document parses"
    );

    let no_tokens = RefreshResponse::parse(b"{}").expect("parses");
    let apikey = Credentials::parse(&testkit::fixture("auth-apikey.json")).expect("parses");
    assert_eq!(
        locked(apikey, &guard).merge_refresh(no_tokens, Timestamp::now()).err(),
        Some(CredentialsError::MissingField("tokens"))
    );
}

#[test]
fn a_refresh_response_is_parsed_without_echoing_it() {
    for (name, body, expected) in [
        ("not an object", &b"[]"[..], CredentialsError::NotAnObject),
        ("number token", br#"{"refresh_token": 5}"#, CredentialsError::WrongType("refresh_token")),
        ("cut off", br#"{"access_token": "agctl-test-codex-at-"#, CredentialsError::Truncated),
    ] {
        assert_eq!(RefreshResponse::parse(body).err(), Some(expected), "{name}");
    }
    let response =
        RefreshResponse::parse(br#"{"access_token":"agctl-test-codex-at-x","refresh_token":null}"#)
            .expect("parses");
    let rendered = format!("{response:?}");
    testkit::assert_no_needles(&rendered, "RefreshResponse Debug");
    assert!(
        rendered.contains("access_token: true") && rendered.contains("refresh_token: false"),
        "{rendered}"
    );
}

#[test]
fn the_refresh_body_is_f65s_json() {
    let (_dir, paths) = testkit::store();
    let guard = testkit::lock_for(&paths, &testkit::owned_record(testkit::USER, testkit::ACCT));
    let credentials =
        locked(Credentials::parse(&testkit::fresh_auth_bytes()).expect("parses"), &guard);
    let mut body = Vec::new();
    credentials.write_refresh_body_to(&mut body, "app_agctl_test").expect("writes");
    assert_eq!(
        String::from_utf8_lossy(&body),
        format!(
            r#"{{"client_id":"app_agctl_test","grant_type":"refresh_token","refresh_token":"{}"}}"#,
            testkit::RT_SENTINEL
        )
    );
    let rendered = format!("{credentials:?}");
    testkit::assert_no_needles(&rendered, "LockedCredentials Debug");

    let apikey =
        locked(Credentials::parse(&testkit::fixture("auth-apikey.json")).expect("parses"), &guard);
    let err = apikey.write_refresh_body_to(&mut Vec::new(), "x").expect_err("no refresh token");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn codex_timestamps_use_the_fewest_exact_fraction_digits() {
    let base = Timestamp::from_second(1_800_000_000).expect("valid");
    let tests = [
        (0, "2027-01-15T08:00:00Z"),
        (5_000_000, "2027-01-15T08:00:00.005Z"),
        (123_456_000, "2027-01-15T08:00:00.123456Z"),
        (123_456_789, "2027-01-15T08:00:00.123456789Z"),
    ];
    for (nanos, expected) in tests {
        let at = base + jiff::SignedDuration::from_nanos(nanos);
        assert_eq!(codex_timestamp(at), expected);
        assert_eq!(expected.parse::<Timestamp>().ok(), Some(at), "and it reads back");
    }
}
