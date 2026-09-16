//! Tests for the Codex half of the registry (plan section 3.6, AC99).

use super::*;

/// A record of each kind, for the round-trip.
fn record(kind: CodexKind) -> CodexAccountRecord {
    CodexAccountRecord {
        chatgpt_user_id: "user-01".to_owned(),
        chatgpt_account_id: "acct-01".to_owned(),
        email: Some("someone@example.com".to_owned()),
        plan_type: Some("plus".to_owned()),
        label: Some("work".to_owned()),
        kind,
        forgotten: false,
        created_at: "2026-09-17T00:00:00Z".to_owned(),
    }
}

#[test]
fn every_kind_round_trips_through_the_registry_document() {
    let kinds = [
        CodexKind::Owned {
            export_spelling: "/store/codex/user-01/acct-01".to_owned(),
            refresh: RefreshPolicy::Auto,
        },
        CodexKind::Live,
        CodexKind::HomeReadOnly { dir: PathBuf::from("/elsewhere/.codex") },
    ];

    for kind in kinds {
        let original = record(kind);
        let text = serde_json::to_string(&original).expect("a record serializes");
        let back: CodexAccountRecord = serde_json::from_str(&text).expect("and parses back");
        assert_eq!(back, original, "{text}");
    }
}

#[test]
fn the_kind_is_an_internally_tagged_snake_case_token() {
    // The same shape `AccountKind` publishes, because `accounts list` and the
    // v2 JSON report show both providers' rows and a reader should not have
    // to learn two spellings.
    let value = serde_json::to_value(record(CodexKind::Live)).expect("a record serializes");
    assert_eq!(value["kind"]["kind"], serde_json::json!("live"));

    let owned = record(CodexKind::Owned {
        export_spelling: "/store/codex/user-01/acct-01".to_owned(),
        refresh: RefreshPolicy::Never,
    });
    let value = serde_json::to_value(owned).expect("a record serializes");
    assert_eq!(value["kind"]["kind"], serde_json::json!("owned"));
    assert_eq!(value["kind"]["refresh"], serde_json::json!("never"));

    let read_only = record(CodexKind::HomeReadOnly { dir: PathBuf::from("/elsewhere/.codex") });
    let value = serde_json::to_value(read_only).expect("a record serializes");
    assert_eq!(value["kind"]["kind"], serde_json::json!("home_read_only"));
    assert_eq!(value["kind"]["dir"], serde_json::json!("/elsewhere/.codex"));
}

#[test]
fn the_refresh_policy_is_written_even_when_it_is_the_default() {
    // A policy the file does not state is a policy that changes when the
    // build's default changes. `accounts set --refresh never` is a promise
    // about this machine, so it is written down.
    let owned = record(CodexKind::Owned {
        export_spelling: "/store/codex/user-01/acct-01".to_owned(),
        refresh: RefreshPolicy::default(),
    });
    let text = serde_json::to_string(&owned).expect("a record serializes");
    assert!(text.contains(r#""refresh":"auto""#), "{text}");
    assert_eq!(RefreshPolicy::default(), RefreshPolicy::Auto);
}

#[test]
fn a_record_written_before_the_refresh_policy_existed_reads_as_auto() {
    // `#[serde(default)]` on the read half: a document that predates the
    // member is not a parse failure, and the mode it lands in is the one the
    // user would have got anyway.
    let text = r#"{
        "chatgpt_user_id": "user-01",
        "chatgpt_account_id": "acct-01",
        "email": null,
        "plan_type": null,
        "label": null,
        "kind": { "kind": "owned", "export_spelling": "/store/codex/user-01/acct-01" },
        "created_at": "2026-09-17T00:00:00Z"
    }"#;

    let parsed: CodexAccountRecord = serde_json::from_str(text).expect("the record parses");
    assert_eq!(
        parsed.kind,
        CodexKind::Owned {
            export_spelling: "/store/codex/user-01/acct-01".to_owned(),
            refresh: RefreshPolicy::Auto,
        }
    );
    assert!(!parsed.forgotten, "an absent `forgotten` is not a hidden row");
}
