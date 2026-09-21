//! The Codex doctor report's two renderings.
//!
//! The report is built in `commands::codex::doctor`, whose own tests drive it
//! over real directories. What is proved here is the part that has no store
//! behind it: that a report with **every** optional field filled validates
//! against the published schema, that a report with none of them filled does
//! too, and that the table says the things plan section 3.3 requires it to
//! say.

use super::*;

/// A report with every optional field present, so the schema sees each one.
fn full() -> CodexDoctorReport {
    CodexDoctorReport {
        version: VERSION,
        home: HomeSection {
            path: Some("/tmp/codex-home".to_owned()),
            symlink_chain: vec!["/tmp/codex-home -> /elsewhere".to_owned()],
            error: None,
        },
        store: StoreSection {
            mode: "auto".to_owned(),
            read: "auto (file in effect)".to_owned(),
            coarse_match: true,
            profiles_consulted: false,
            base_url: Some("https://example.invalid".to_owned()),
            config_note: Some("unparseable config.toml (line 3)".to_owned()),
        },
        environment: vec![EnvVar { name: "CODEX_API_KEY", present: true }],
        live: LiveSection {
            state: "credentials",
            auth_mode: Some("chatgpt"),
            mode_bits: Some("0600".to_owned()),
            mode_warning: Some("warning: mode".to_owned()),
            size: Some(1_024),
            access_expiry: Some("in 9m".to_owned()),
            last_refresh: Some("expired 2h ago".to_owned()),
            matches_namespace: Some("user-0001+acct-0001".to_owned()),
            daemon: "a daemon is running",
            missing_known_members: vec!["bedrock_api_key"],
            unknown_member_count: 2,
        },
        foreign: ForeignSection {
            multi_auth_present: true,
            switcher_items: 3,
            codex_auth_items: 1,
            unexplained_removals: vec![
                "security delete-generic-password -s \"Codex Auth\" -a \"cli|00112233abcdefff\""
                    .to_owned(),
            ],
            unexplained_items: 4,
            unnameable_items: 2,
        },
        namespaces: vec![NamespaceSection {
            user: "user-0001".to_owned(),
            acct: "acct-0001".to_owned(),
            path: "/tmp/store/codex/user-0001/acct-0001".to_owned(),
            credentials_present: true,
            refresh_policy: "auto",
            lock: Some(LockSection {
                pid: 4_242,
                acquired_at: "2026-09-22T00:00:00Z".to_owned(),
                holder: "held",
            }),
            artefacts: vec!["stray tmp (rotated grant?): 1 file(s)".to_owned()],
            marker: MarkerSection {
                state: "present",
                unavailable: None,
                inflight_digest8: Some("0123abcd".to_owned()),
                inflight_age: Some("2h".to_owned()),
                class: Some("tls"),
                floor_min: Some(60),
                did_not_help: Some(1),
                resent: Some(false),
                ambiguous_since: Some("2h".to_owned()),
                resend_eligible: Some(true),
            },
            notes: vec!["a note".to_owned()],
        }],
        orphans: vec![OrphanEntry {
            kind: "stale scratch".to_owned(),
            subject: "agctl-codex-login-abcd".to_owned(),
            age: Some("22m".to_owned()),
        }],
        audit: vec!["{\"provider\":\"codex\"}".to_owned()],
        notes: vec!["a report-wide note".to_owned()],
    }
}

/// A report with nothing found, which is what a clean machine produces.
fn empty() -> CodexDoctorReport {
    CodexDoctorReport {
        version: VERSION,
        home: HomeSection {
            path: None,
            symlink_chain: Vec::new(),
            error: Some("no home".to_owned()),
        },
        store: StoreSection {
            mode: "file".to_owned(),
            read: "not read".to_owned(),
            coarse_match: false,
            profiles_consulted: false,
            base_url: None,
            config_note: None,
        },
        environment: Vec::new(),
        live: LiveSection {
            state: "absent",
            auth_mode: None,
            mode_bits: None,
            mode_warning: None,
            size: None,
            access_expiry: None,
            last_refresh: None,
            matches_namespace: None,
            daemon: "none",
            missing_known_members: Vec::new(),
            unknown_member_count: 0,
        },
        foreign: ForeignSection {
            multi_auth_present: false,
            switcher_items: 0,
            codex_auth_items: 0,
            unexplained_removals: Vec::new(),
            unexplained_items: 0,
            unnameable_items: 0,
        },
        namespaces: Vec::new(),
        orphans: Vec::new(),
        audit: Vec::new(),
        notes: Vec::new(),
    }
}

#[test]
fn a_report_with_every_field_filled_validates() {
    assert_valid(&full());
}

#[test]
fn a_report_with_nothing_found_validates() {
    assert_valid(&empty());
}

#[test]
fn the_version_is_the_one_the_schema_pins() {
    let document = serde_json::to_value(empty()).expect("a report serializes");
    assert_eq!(document["version"], serde_json::json!(1));
}

#[test]
fn the_table_says_what_section_three_three_requires() {
    let rendered = render(&full());

    for expected in [
        "codex home",
        "/tmp/codex-home -> /elsewhere",
        "mode auto (auto (file in effect))",
        "coarse match",
        "profiles not consulted",
        "chatgpt_base_url https://example.invalid",
        "unparseable config.toml (line 3)",
        "CODEX_API_KEY present",
        "auth_mode chatgpt",
        "mode 0600, 1024 bytes",
        "daemon evidence: a daemon is running",
        "fields absent: bedrock_api_key",
        "2 field(s) this build does not know",
        "`multi-auth/` present",
        "codex-switcher keychain items: 3",
        "`Codex Auth` keychain items: 1",
        "2 further `Codex Auth` item(s) are listed under an account agctl would not have written",
        "stray tmp (rotated grant?): 1 file(s)",
        "send outstanding for 0123abcd, 2h ago",
        "class tls",
        "ambiguous refresh outstanding since 2h",
        "--resend eligible",
        "stale scratch (agctl-codex-login-abcd, 22m)",
        STATE_WARNING,
    ] {
        assert!(rendered.contains(expected), "the table does not carry `{expected}`:\n{rendered}");
    }
}

#[test]
fn a_clean_machine_reads_as_a_clean_machine() {
    let rendered = render(&empty());

    assert!(rendered.contains("owned namespaces\n  none"), "{rendered}");
    assert!(rendered.contains("left behind\n  nothing"), "{rendered}");
    assert!(rendered.contains("no Codex write has been recorded"), "{rendered}");
    assert!(
        !rendered.contains(STATE_WARNING),
        "the marker warning belongs to a machine that has markers"
    );
}

#[test]
fn a_marker_that_could_not_be_read_names_the_path_and_the_reason() {
    let mut report = full();
    report.namespaces[0].marker = MarkerSection {
        state: "unavailable",
        unavailable: Some("`/tmp/store/codex/.state/x.refresh` (permission denied)".to_owned()),
        inflight_digest8: None,
        inflight_age: None,
        class: None,
        floor_min: None,
        did_not_help: None,
        resent: None,
        ambiguous_since: None,
        resend_eligible: None,
    };

    let rendered = render(&report);

    assert!(
        rendered.contains("refresh state unavailable: `/tmp/store/codex/.state/x.refresh`"),
        "{rendered}"
    );
    assert_valid(&report);
}
