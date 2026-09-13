//! Tests for the live `.claude.json` rewrite (decision D-021, plan AC75).
//!
//! Every test runs against a temporary `$HOME` in the reference machine's
//! shape: `$HOME/.claude` → `$HOME/.claude-real` and `$HOME/.claude.json` →
//! `$HOME/.claude-real/.claude.json`, both **symbolic links**, so the
//! literal-lock and follow-the-link rules are exercised rather than assumed.
//! The environment is always `EnvView::with_home(<tempdir>)`; nothing here
//! reads the process environment or the developer's own files.
//!
//! The byte-identity test builds its expected output from **text**, never from
//! `serde_json`: a test whose expected side went through the same serializer
//! as the code under test could not see the serializer disagree with
//! `JSON.stringify`.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Instant;
use std::time::SystemTime;

use tempfile::TempDir;

use super::*;
use crate::provider::claude::oauth::parse_profile;
use crate::runtime::coordinator::Cancel;
use crate::secret::claude_lock::FsError;
use crate::secret::claude_lock::LockSlot;
use crate::secret::claude_lock::TimeSource;

/// The instant every rewrite here stamps `profileFetchedAt` with.
const NOW: i64 = 1_789_000_000_000;

// ---------------------------------------------------------------------------
// The fixture home
// ---------------------------------------------------------------------------

/// A temporary `$HOME` with the live layout's two links.
struct LiveHome {
    dir: TempDir,
}

impl LiveHome {
    fn new() -> Self {
        let dir = TempDir::new().expect("a temporary home");
        let real = dir.path().join(".claude-real");
        fs::create_dir_all(&real).expect("the link target is creatable");
        std::os::unix::fs::symlink(&real, dir.path().join(".claude")).expect("the store link");
        std::os::unix::fs::symlink(real.join(".claude.json"), dir.path().join(".claude.json"))
            .expect("the config link");
        Self { dir }
    }

    fn home(&self) -> PathBuf {
        self.dir.path().to_path_buf()
    }

    fn env(&self) -> EnvView {
        EnvView::with_home(self.home())
    }

    fn link(&self) -> PathBuf {
        self.home().join(".claude.json")
    }

    fn real(&self) -> PathBuf {
        self.home().join(".claude-real")
    }

    fn target(&self) -> PathBuf {
        self.real().join(".claude.json")
    }

    fn lock_dir(&self) -> PathBuf {
        self.home().join(".claude.json.lock")
    }

    fn backups(&self) -> PathBuf {
        self.real().join("backups")
    }

    /// Writes the target's bytes, through its own path (the link is left as is).
    fn plant(&self, text: &str) {
        fs::write(self.target(), text).expect("the target is writable");
    }

    fn contents(&self) -> Vec<u8> {
        fs::read(self.target()).expect("the target is readable")
    }

    /// Every file in the target's directory whose name holds `.tmp.`.
    fn temps(&self) -> Vec<String> {
        names(&self.real()).into_iter().filter(|name| name.contains(".tmp.")).collect()
    }

    /// The backups' names, sorted.
    fn backup_names(&self) -> Vec<String> {
        if self.backups().exists() { names(&self.backups()) } else { Vec::new() }
    }
}

fn names(dir: &Path) -> Vec<String> {
    let mut found: Vec<String> = fs::read_dir(dir)
        .expect("the directory is listable")
        .map(|entry| entry.expect("an entry").file_name().to_string_lossy().into_owned())
        .collect();
    found.sort();
    found
}

fn ctx() -> PassCtx {
    PassCtx::standalone(Cancel::new(), Instant::now() + Duration::from_secs(60))
}

/// T's profile, shaped like `tests/common::mock_profile`'s document: the
/// members `Btt` copies plus three it does not.
fn t_profile() -> Profile {
    parse_profile(serde_json::json!({
        "account": {
            "uuid": "acct-t",
            "email": "t@example.com",
            "display_name": "Tee",
            "created_at": "2026-01-01T00:00:00Z",
        },
        "organization": {
            "uuid": "org-t",
            "name": "Acme",
            "organization_type": "claude_max",
            "billing_type": "stripe_subscription",
            "rate_limit_tier": "default_claude_max_20x",
        },
    }))
    .expect("a V14 document")
}

/// `t_profile`'s `oauthAccount` member at `NOW`, as `JSON.stringify(_, null, 2)`
/// writes it at the top level — spelled by hand.
fn t_chunk() -> String {
    [
        "  \"oauthAccount\": {",
        "    \"accountUuid\": \"acct-t\",",
        "    \"emailAddress\": \"t@example.com\",",
        "    \"organizationUuid\": \"org-t\",",
        "    \"hasExtraUsageEnabled\": false,",
        "    \"billingType\": \"stripe_subscription\",",
        "    \"accountCreatedAt\": \"2026-01-01T00:00:00Z\",",
        "    \"ccOnboardingFlags\": {},",
        "    \"claudeCodeTrialEndsAt\": null,",
        "    \"claudeCodeTrialDurationDays\": null,",
        "    \"seatTier\": null,",
        "    \"displayName\": \"Tee\",",
        "    \"profileFetchedAt\": 1789000000000",
        "  }",
    ]
    .join("\n")
}

/// P's `oauthAccount` value as a login leaves it: twenty keys, six of which
/// the start-up refresh never writes.
fn p_value() -> String {
    [
        "{",
        "    \"accountUuid\": \"acct-p\",",
        "    \"emailAddress\": \"p@example.com\",",
        "    \"organizationUuid\": \"org-p\",",
        "    \"hasExtraUsageEnabled\": true,",
        "    \"billingType\": \"stripe_subscription\",",
        "    \"accountCreatedAt\": \"2025-01-01T00:00:00Z\",",
        "    \"subscriptionCreatedAt\": \"2025-02-01T00:00:00Z\",",
        "    \"ccOnboardingFlags\": {",
        "      \"seen\": true",
        "    },",
        "    \"claudeCodeTrialEndsAt\": null,",
        "    \"claudeCodeTrialDurationDays\": null,",
        "    \"seatTier\": \"premium\",",
        "    \"displayName\": \"Pee\",",
        "    \"fullName\": \"P Person\",",
        "    \"profileFetchedAt\": 1780000000000,",
        "    \"organizationRole\": \"admin\",",
        "    \"workspaceRole\": \"developer\",",
        "    \"organizationName\": \"P Org\",",
        "    \"organizationType\": \"claude_max\",",
        "    \"organizationRateLimitTier\": \"default_claude_max_20x\",",
        "    \"userRateLimitTier\": \"default\"",
        "  }",
    ]
    .join("\n")
}

/// One top-level member as JS writes it.
fn chunk(key: &str, value: &str) -> String {
    format!("  \"{key}\": {value}")
}

/// A top-level object from its members.
fn document(chunks: &[String]) -> String {
    format!("{{\n{}\n}}", chunks.join(",\n"))
}

fn rewrite(home: &LiveHome, profile: &Profile) -> ConfigReport {
    rewrite_with(home, profile, &Clock::system(), Arc::new(RealFs), &HoldHooks::default())
}

fn rewrite_with(
    home: &LiveHome,
    profile: &Profile,
    clock: &Clock,
    fs: Arc<dyn LockFs>,
    hooks: &HoldHooks,
) -> ConfigReport {
    match prepare(&home.env(), profile, NOW) {
        Ok(prepared) => write_with(prepared, &ctx(), clock, fs, hooks),
        Err(stopped) => *stopped,
    }
}

fn assert_link_intact(home: &LiveHome) {
    let meta = fs::symlink_metadata(home.link()).expect("the link is there");
    assert!(meta.file_type().is_symlink(), "`.claude.json` is still a symlink");
    assert_eq!(fs::read_link(home.link()).expect("readable link"), home.target());
}

/// A small JS-shaped document and what the rewrite must turn it into.
fn small_pair() -> (String, String) {
    let before = document(&[
        chunk("numStartups", "12"),
        chunk("oauthAccount", &p_value()),
        chunk("modelAccessCache", "{\n    \"a\": true\n  }"),
        chunk("userID", "\"u-1\""),
    ]);
    let after = document(&[chunk("numStartups", "12"), t_chunk(), chunk("userID", "\"u-1\"")]);
    (before, after)
}

// ---------------------------------------------------------------------------
// AC75: byte identity outside the allowlist
// ---------------------------------------------------------------------------

/// A filler member's value, as JS writes it at indent 2: nested objects,
/// arrays, empty containers, literal Japanese and emoji, escapes, 13-digit
/// timestamps, floats, negatives, `null` and booleans.
fn filler_value(i: usize) -> String {
    let stamp = 1_789_000_000_000_u64.saturating_add(u64::try_from(i).expect("small"));
    match i % 12 {
        0 => [
            "{",
            "    \"enabled\": true,",
            "    \"count\": 3,",
            "    \"nested\": {",
            "      \"list\": [",
            "        1,",
            "        \"two\",",
            "        null",
            "      ],",
            "      \"empty\": {}",
            "    }",
            "  }",
        ]
        .join("\n"),
        1 => [
            "[",
            "    \"alpha\",",
            "    -7,",
            "    {",
            "      \"k\": \"v\"",
            "    },",
            "    []",
            "  ]",
        ]
        .join("\n"),
        2 => "{}".to_owned(),
        3 => "[]".to_owned(),
        4 => format!("\"日本語のテキスト {i} 🦀✨\""),
        5 => "\"line\\nbreak\\ttab \\\"quoted\\\" back\\\\slash\"".to_owned(),
        6 => stamp.to_string(),
        7 => "0.5601675".to_owned(),
        8 => format!("-{}", i.saturating_add(1)),
        9 => "null".to_owned(),
        10 => "true".to_owned(),
        _ => "false".to_owned(),
    }
}

#[test]
fn the_rmw_replaces_oauth_account_deletes_five_caches_and_keeps_every_other_byte() {
    // 166 top-level members: 159 fillers, `userID`, `oauthAccount` mid-document,
    // and the five caches at the first, middle and last positions.
    let mut before = Vec::new();
    let mut expected = Vec::new();
    let mut filler = 0_usize;
    for index in 0..166_usize {
        let (key, value, kind) = match index {
            0 => {
                ("modelAccessCache".to_owned(), "{\n    \"claude-opus\": true\n  }".to_owned(), 'c')
            }
            40 => ("orgModelDefaultCache".to_owned(), "\"claude-opus-5\"".to_owned(), 'c'),
            83 => ("oauthAccount".to_owned(), p_value(), 'o'),
            84 => ("userID".to_owned(), "\"0123456789abcdef\"".to_owned(), 'k'),
            100 => ("cachedExtraUsageDisabledReason".to_owned(), "null".to_owned(), 'c'),
            120 => (
                "cachedUsageUtilization".to_owned(),
                "{\n    \"five_hour\": 0.25,\n    \"seven_day\": -0.5\n  }".to_owned(),
                'c',
            ),
            165 => (
                "passesEligibilityCache".to_owned(),
                "{\n    \"eligible\": false\n  }".to_owned(),
                'c',
            ),
            _ => {
                filler = filler.saturating_add(1);
                (format!("setting{filler:03}"), filler_value(filler), 'k')
            }
        };
        let text = chunk(&key, &value);
        before.push(text.clone());
        match kind {
            'k' => expected.push(text),
            'o' => expected.push(t_chunk()),
            _ => {}
        }
    }
    assert_eq!(before.len(), 166, "the synthetic N-key fixture");
    let before = document(&before);
    let expected = document(&expected);

    let home = LiveHome::new();
    home.plant(&before);
    let report = rewrite(&home, &t_profile());

    assert_eq!((report.outcome, report.reason), (ConfigOutcome::Applied, None), "{report:?}");
    let after = String::from_utf8(home.contents()).expect("UTF-8");
    if after != expected {
        let at = after.bytes().zip(expected.bytes()).take_while(|(a, b)| a == b).count();
        let window = |text: &str| {
            text.get(at.saturating_sub(80)..).unwrap_or("").chars().take(160).collect::<String>()
        };
        panic!(
            "every byte outside the allowlist is unchanged — first difference at byte {at} \
             (lengths {} vs {}):\n--- written ---\n{}\n--- expected ---\n{}",
            after.len(),
            expected.len(),
            window(&after),
            window(&expected)
        );
    }
    assert!(!after.ends_with('\n'), "no trailing newline");
    assert_link_intact(&home);
    assert_eq!(report.from_sha8, sha8(before.as_bytes()), "the digest of what was read");
    assert_eq!(report.to_sha8, sha8(expected.as_bytes()), "the digest of what was written");
    assert_eq!(report.account.as_ref().map(|ids| ids.account_uuid.as_str()), Some("acct-t"));
    assert!(!home.lock_dir().exists(), "the lock was released");
    assert!(home.temps().is_empty(), "no temporary file left: {:?}", home.temps());
}

// ---------------------------------------------------------------------------
// The guard
// ---------------------------------------------------------------------------

#[test]
fn the_guard_refuses_every_document_it_cannot_reproduce() {
    let base = "{\n  \"a\": 1,\n  \"b\": \"x\"\n}";
    let rows: [(&str, Vec<u8>, ConfigReason); 12] = [
        ("trailing newline", format!("{base}\n").into_bytes(), ConfigReason::NotReproducible),
        ("CRLF", base.replace('\n', "\r\n").into_bytes(), ConfigReason::NotReproducible),
        (
            "4-space indent",
            b"{\n    \"a\": 1,\n    \"b\": \"x\"\n}".to_vec(),
            ConfigReason::NotReproducible,
        ),
        (
            "é escaped as \\u00e9",
            b"{\n  \"a\": \"caf\\u00e9\"\n}".to_vec(),
            ConfigReason::NotReproducible,
        ),
        ("\\/", b"{\n  \"a\": \"a\\/b\"\n}".to_vec(), ConfigReason::NotReproducible),
        (
            "1e21 (serde writes 1e+21)",
            b"{\n  \"a\": 1e21\n}".to_vec(),
            ConfigReason::NotReproducible,
        ),
        (
            "0.000001 (serde writes 1e-6)",
            b"{\n  \"a\": 0.000001\n}".to_vec(),
            ConfigReason::NotReproducible,
        ),
        ("duplicate key", b"{\n  \"a\": 1,\n  \"a\": 2\n}".to_vec(), ConfigReason::NotReproducible),
        ("a lone surrogate", b"{\n  \"a\": \"\\ud800\"\n}".to_vec(), ConfigReason::Unparseable),
        ("compact", b"{\"a\":1,\"b\":\"x\"}".to_vec(), ConfigReason::NotReproducible),
        ("BOM", [&[0xEF, 0xBB, 0xBF][..], base.as_bytes()].concat(), ConfigReason::Unparseable),
        ("top-level array", b"[\n  1\n]".to_vec(), ConfigReason::NotAnObject),
    ];
    for (row, bytes, reason) in rows {
        assert_eq!(reproduce(&bytes).map(|_| ()), Err(reason), "{row}");

        let home = LiveHome::new();
        fs::write(home.target(), &bytes).expect("plantable");
        assert!(prepare(&home.env(), &t_profile(), NOW).is_err(), "{row}: step P refuses");
        let report = rmw(&home.env(), &t_profile(), &ctx());
        assert_eq!(
            (report.outcome, report.reason),
            (ConfigOutcome::Refused, Some(reason)),
            "row \"{row}\" expected Refused({reason:?})"
        );
        assert_eq!(home.contents(), bytes, "{row}: the file is byte-identical");
        assert!(!home.backups().exists(), "{row}: refused before step P5, so before any lock");
        assert!(!home.lock_dir().exists(), "{row}: no lock directory");
        assert!(home.temps().is_empty(), "{row}: no temporary file");
        assert_eq!(report.hold_ms, None, "{row}: no hold was taken");
    }

    // Not every number spelling is a disagreement: `serde_json` 1.0.151 writes
    // `1e+21` exactly as `JSON.stringify` does, and `1.0` back as `1.0`, so the
    // guard reproduces both and every byte of them survives a rewrite.
    for number in ["1e+21", "1.0", "1e-7", "0.5601675", "-17", "1789000000000"] {
        let text = format!("{{\n  \"a\": {number}\n}}");
        assert!(reproduce(text.as_bytes()).is_ok(), "{number} is reproduced and carried over");
    }
    // And the fixture shape Claude Code writes passes.
    assert!(reproduce(base.as_bytes()).is_ok());
    assert_eq!(reproduce(b"").map(|_| ()), Err(ConfigReason::Unparseable), "an empty file");
}

#[test]
fn the_shipped_build_parses_floats_exactly() {
    // Review round 1 F1. Without `serde_json/float_roundtrip` a float is parsed
    // best-effort and lands one ULP off for roughly one 17-digit value in ten
    // (`0.18813200000000002`, `90.28571428571429`, …), so the guard would refuse
    // the real `.claude.json` — its `projects.*.lastCost` are such values — as
    // `not_reproducible`. `jsonschema`, a dev-dependency, turns the feature on in
    // every test build, so a number row alone would pass even if the shipped
    // build lost it: the manifest is the pin.
    let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("the manifest is readable");
    let line = manifest
        .lines()
        .find(|line| line.trim_start().starts_with("serde_json "))
        .expect("serde_json is a dependency");
    assert!(
        line.contains("\"float_roundtrip\""),
        "the shipped build needs exact float parsing for the guard: {line}"
    );
    assert!(line.contains("\"preserve_order\""), "and key order: {line}");

    // JS's shortest forms of doubles, as `JSON.stringify` writes them: the
    // `0.1 + 0.2` class, a `Math.random()` class, accumulated costs of 16 and 17
    // digits. The four marked * do not reproduce under best-effort parsing
    // (probed on serde_json 1.0.151 without the feature).
    let doubles = [
        "0.30000000000000004",
        "0.18813200000000002",  // *
        "90.28571428571429",    // *
        "0.45202095760750516",  // *
        "0.013142054551181559", // *
        "7.744551763382691",
        "2.3333333333333335",
        "8.024999999999999",
    ];
    for number in doubles {
        let text = format!("{{\n  \"a\": {number}\n}}");
        assert!(reproduce(text.as_bytes()).is_ok(), "{number}: JS's shortest form reproduces");
    }

    // And end to end: a document whose projects carry such costs is rewritten,
    // every one of those numbers carried over as the bytes it was.
    let costs: Vec<String> = doubles
        .iter()
        .enumerate()
        .map(|(index, number)| chunk(&format!("lastCost{index}"), number))
        .collect();
    let projects = format!(
        "{{\n{}\n  }}",
        costs.iter().map(|c| format!("  {c}")).collect::<Vec<_>>().join(",\n")
    );
    let home = LiveHome::new();
    home.plant(&document(&[chunk("oauthAccount", &p_value()), chunk("projects", &projects)]));
    let report = rewrite(&home, &t_profile());
    assert_eq!(report.outcome, ConfigOutcome::Applied, "{report:?}");
    assert_eq!(
        String::from_utf8(home.contents()).expect("UTF-8"),
        document(&[t_chunk(), chunk("projects", &projects)]),
        "the costs survive byte for byte"
    );
}

// ---------------------------------------------------------------------------
// The object
// ---------------------------------------------------------------------------

fn built(account: Value, organization: Value) -> Map<String, Value> {
    let mut account = account;
    account["uuid"] = Value::from("acct-t");
    account["email"] = Value::from("t@example.com");
    let mut organization = organization;
    organization["uuid"] = Value::from("org-t");
    let profile =
        parse_profile(serde_json::json!({ "account": account, "organization": organization }))
            .expect("a V14 document");
    match build_oauth_account(&profile, NOW) {
        Value::Object(object) => object,
        other => panic!("an object, not {other}"),
    }
}

#[test]
fn the_oauth_account_object_is_the_v14_field_set_in_btts_order() {
    use serde_json::json;

    // Every row present: all fourteen keys, in `Btt`'s order.
    let full = built(
        json!({ "created_at": "c", "display_name": "D", "full_name": "F" }),
        json!({
            "has_extra_usage_enabled": true,
            "billing_type": "b",
            "subscription_created_at": "s",
            "cc_onboarding_flags": { "x": 1 },
            "claude_code_trial_ends_at": "e",
            "claude_code_trial_duration_days": 30,
            "seat_tier": "t",
            "name": "Acme",
            "organization_type": "claude_max",
            "rate_limit_tier": "default_claude_max_20x",
        }),
    );
    let order: Vec<&str> = full.keys().map(String::as_str).collect();
    assert_eq!(
        order,
        [
            "accountUuid",
            "emailAddress",
            "organizationUuid",
            "hasExtraUsageEnabled",
            "billingType",
            "accountCreatedAt",
            "subscriptionCreatedAt",
            "ccOnboardingFlags",
            "claudeCodeTrialEndsAt",
            "claudeCodeTrialDurationDays",
            "seatTier",
            "displayName",
            "fullName",
            "profileFetchedAt",
        ],
        "V14's field set in Btt's order"
    );
    assert_eq!(full["claudeCodeTrialDurationDays"], json!(30), "an integer stays an integer");
    assert_eq!(full["ccOnboardingFlags"], json!({ "x": 1 }));
    for extra in ["organizationName", "organizationType", "organizationRateLimitTier", "name"] {
        assert!(!full.contains_key(extra), "the profile's `{extra}`-like members are not copied");
    }

    // (row, account members, organization members, key, expected: None = omitted)
    let rows: Vec<(&str, Value, Value, &str, Option<Value>)> = vec![
        (
            "has_extra_usage_enabled absent",
            json!({}),
            json!({}),
            "hasExtraUsageEnabled",
            Some(json!(false)),
        ),
        (
            "has_extra_usage_enabled null",
            json!({}),
            json!({ "has_extra_usage_enabled": null }),
            "hasExtraUsageEnabled",
            Some(json!(false)),
        ),
        (
            "has_extra_usage_enabled true",
            json!({}),
            json!({ "has_extra_usage_enabled": true }),
            "hasExtraUsageEnabled",
            Some(json!(true)),
        ),
        ("billing_type absent", json!({}), json!({}), "billingType", None),
        ("billing_type null", json!({}), json!({ "billing_type": null }), "billingType", None),
        (
            "billing_type present",
            json!({}),
            json!({ "billing_type": "b" }),
            "billingType",
            Some(json!("b")),
        ),
        ("created_at absent", json!({}), json!({}), "accountCreatedAt", None),
        (
            "created_at null is written",
            json!({ "created_at": null }),
            json!({}),
            "accountCreatedAt",
            Some(Value::Null),
        ),
        (
            "created_at present",
            json!({ "created_at": "c" }),
            json!({}),
            "accountCreatedAt",
            Some(json!("c")),
        ),
        ("subscription_created_at absent", json!({}), json!({}), "subscriptionCreatedAt", None),
        (
            "subscription_created_at null",
            json!({}),
            json!({ "subscription_created_at": null }),
            "subscriptionCreatedAt",
            None,
        ),
        ("cc_onboarding_flags absent", json!({}), json!({}), "ccOnboardingFlags", Some(json!({}))),
        (
            "cc_onboarding_flags null",
            json!({}),
            json!({ "cc_onboarding_flags": null }),
            "ccOnboardingFlags",
            Some(json!({})),
        ),
        ("trial_ends_at absent", json!({}), json!({}), "claudeCodeTrialEndsAt", Some(Value::Null)),
        (
            "trial_ends_at present",
            json!({}),
            json!({ "claude_code_trial_ends_at": "e" }),
            "claudeCodeTrialEndsAt",
            Some(json!("e")),
        ),
        (
            "trial_duration_days null",
            json!({}),
            json!({ "claude_code_trial_duration_days": null }),
            "claudeCodeTrialDurationDays",
            Some(Value::Null),
        ),
        ("seat_tier absent", json!({}), json!({}), "seatTier", Some(Value::Null)),
        ("seat_tier present", json!({}), json!({ "seat_tier": "t" }), "seatTier", Some(json!("t"))),
        ("display_name absent", json!({}), json!({}), "displayName", None),
        ("display_name null", json!({ "display_name": null }), json!({}), "displayName", None),
        ("display_name empty", json!({ "display_name": "" }), json!({}), "displayName", None),
        ("display_name false", json!({ "display_name": false }), json!({}), "displayName", None),
        ("display_name 0", json!({ "display_name": 0 }), json!({}), "displayName", None),
        (
            "display_name a string",
            json!({ "display_name": "D" }),
            json!({}),
            "displayName",
            Some(json!("D")),
        ),
        (
            "display_name true is copied as is",
            json!({ "display_name": true }),
            json!({}),
            "displayName",
            Some(json!(true)),
        ),
        (
            "display_name 5 is copied as is",
            json!({ "display_name": 5 }),
            json!({}),
            "displayName",
            Some(json!(5)),
        ),
        (
            "display_name [] is truthy",
            json!({ "display_name": [] }),
            json!({}),
            "displayName",
            Some(json!([])),
        ),
        ("full_name empty", json!({ "full_name": "" }), json!({}), "fullName", None),
        (
            "full_name a string",
            json!({ "full_name": "F" }),
            json!({}),
            "fullName",
            Some(json!("F")),
        ),
    ];
    for (row, account, organization, key, expected) in rows {
        let object = built(account, organization);
        assert_eq!(object.get(key).cloned(), expected, "row \"{row}\"");
    }

    // Nothing optional present: the keys that are always written, in order.
    let bare = built(json!({}), json!({}));
    assert_eq!(
        bare.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "accountUuid",
            "emailAddress",
            "organizationUuid",
            "hasExtraUsageEnabled",
            "ccOnboardingFlags",
            "claudeCodeTrialEndsAt",
            "claudeCodeTrialDurationDays",
            "seatTier",
            "profileFetchedAt",
        ]
    );
    assert_eq!(bare["profileFetchedAt"], json!(NOW), "profileFetchedAt == now_ms");
    assert_eq!(
        (
            bare["accountUuid"].clone(),
            bare["emailAddress"].clone(),
            bare["organizationUuid"].clone()
        ),
        (json!("acct-t"), json!("t@example.com"), json!("org-t"))
    );
}

#[test]
fn p_s_six_extra_keys_do_not_survive_the_replacement() {
    // S13-2: REPLACE, never merge. A shallow merge — `Btt`'s own behaviour —
    // would leave six of P's keys behind, three of them behavioural.
    let home = LiveHome::new();
    let (before, expected) = small_pair();
    home.plant(&before);

    let report = rewrite(&home, &t_profile());
    assert_eq!(report.outcome, ConfigOutcome::Applied, "{report:?}");

    let written: Value = serde_json::from_slice(&home.contents()).expect("JSON");
    let object = written["oauthAccount"].as_object().expect("an object");
    for extra in [
        "organizationRole",
        "workspaceRole",
        "organizationName",
        "organizationType",
        "organizationRateLimitTier",
        "userRateLimitTier",
    ] {
        assert!(!object.contains_key(extra), "`{extra}` absent");
    }
    assert!(object.len() <= 14, "at most V14's fourteen keys: {}", object.len());
    for from_p in ["subscriptionCreatedAt", "fullName"] {
        assert!(!object.contains_key(from_p), "P's `{from_p}` does not survive either");
    }
    assert_eq!(String::from_utf8(home.contents()).expect("UTF-8"), expected);
    assert_eq!(
        written["oauthAccount"],
        build_oauth_account(&t_profile(), NOW),
        "exactly T's object"
    );
}

#[test]
fn oauth_account_keeps_its_index_and_is_appended_when_absent() {
    let keys = |bytes: &[u8]| -> Vec<String> {
        match serde_json::from_slice::<Value>(bytes).expect("JSON") {
            Value::Object(object) => object.keys().cloned().collect(),
            other => panic!("an object, not {other}"),
        }
    };

    // Present: the index is unchanged, around a deleted cache before it.
    let home = LiveHome::new();
    home.plant(&document(&[
        chunk("cachedUsageUtilization", "{}"),
        chunk("a", "1"),
        chunk("oauthAccount", &p_value()),
        chunk("b", "2"),
        chunk("c", "3"),
    ]));
    assert_eq!(rewrite(&home, &t_profile()).outcome, ConfigOutcome::Applied);
    assert_eq!(
        keys(&home.contents()),
        ["a", "oauthAccount", "b", "c"],
        "the index in the key sequence"
    );

    // Absent: appended last, which is `{...F, oauthAccount}`'s order.
    let home = LiveHome::new();
    home.plant(&document(&[chunk("a", "1"), chunk("b", "2")]));
    assert_eq!(rewrite(&home, &t_profile()).outcome, ConfigOutcome::Applied);
    assert_eq!(keys(&home.contents()), ["a", "b", "oauthAccount"], "an absent key lands last");
    assert_eq!(
        String::from_utf8(home.contents()).expect("UTF-8"),
        document(&[chunk("a", "1"), chunk("b", "2"), t_chunk()])
    );
}

// ---------------------------------------------------------------------------
// Under the lock
// ---------------------------------------------------------------------------

#[test]
fn a_change_under_the_lock_aborts_before_the_rename() {
    // AC75: a digest change under the lock writes nothing. Only a lock-free
    // writer can cause it — an exiting session, a contending session's fallback
    // — and the hook stands in for one, between H5 and H6.
    let home = LiveHome::new();
    let (before, _) = small_pair();
    home.plant(&before);
    let target = home.target();
    let changed = document(&[chunk("numStartups", "13")]);
    let hook_bytes = changed.clone();
    let hooks = HoldHooks {
        after_temp: Some(Box::new(move || {
            fs::write(&target, &hook_bytes).expect("a peer's write")
        })),
        ..HoldHooks::default()
    };

    let report = rewrite_with(&home, &t_profile(), &Clock::system(), Arc::new(RealFs), &hooks);

    assert_eq!(
        (report.outcome, report.reason),
        (ConfigOutcome::Aborted, Some(ConfigReason::ChangedUnderLock)),
        "{report:?}"
    );
    assert_eq!(home.contents(), changed.as_bytes(), "the target holds the hook's bytes");
    assert!(home.temps().is_empty(), "no `.tmp.` left in read_dir: {:?}", home.temps());
    assert!(!home.lock_dir().exists(), "the lock directory is released");
    let backups = home.backup_names();
    assert_eq!(backups.len(), 1, "the backup present: {backups:?}");
    assert_eq!(fs::read(home.backups().join(&backups[0])).expect("readable"), before.as_bytes());
    assert_eq!(report.to_sha8, None, "nothing was written");
    assert_link_intact(&home);
}

#[test]
fn a_config_lock_whose_mtime_moved_aborts_as_compromised() {
    let home = LiveHome::new();
    let (before, _) = small_pair();
    home.plant(&before);
    let lock_dir = home.lock_dir();
    let hooks = HoldHooks {
        after_temp: Some(Box::new(move || {
            let moved = SystemTime::now().checked_sub(Duration::from_secs(3)).expect("an instant");
            set_mtime(&lock_dir, moved);
        })),
        ..HoldHooks::default()
    };

    let report = rewrite_with(&home, &t_profile(), &Clock::system(), Arc::new(RealFs), &hooks);

    assert_eq!(
        (report.outcome, report.reason),
        (ConfigOutcome::Aborted, Some(ConfigReason::Compromised)),
        "{report:?}"
    );
    assert_eq!(home.contents(), before.as_bytes(), "target unchanged");
    assert!(home.temps().is_empty(), "no temp: {:?}", home.temps());
    assert!(!home.lock_dir().exists(), "released");
}

fn set_mtime(path: &Path, at: SystemTime) {
    let since = at.duration_since(SystemTime::UNIX_EPOCH).expect("after the epoch");
    let stamp = rustix::fs::Timespec {
        tv_sec: i64::try_from(since.as_secs()).expect("a plausible second"),
        tv_nsec: i64::from(since.subsec_nanos()),
    };
    rustix::fs::utimensat(
        rustix::fs::CWD,
        path,
        &rustix::fs::Timestamps { last_access: stamp, last_modification: stamp },
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .expect("the modification time should be settable");
}

/// Real wall time, a monotonic clock a test can move forward, and free sleeps.
struct SteppedClock {
    base: Instant,
    offset_ms: Arc<AtomicU64>,
}

impl TimeSource for SteppedClock {
    fn wall(&self) -> SystemTime {
        SystemTime::now()
    }

    fn monotonic(&self) -> Instant {
        self.base + Duration::from_millis(self.offset_ms.load(Ordering::SeqCst))
    }

    fn sleep(&self, _how_long: Duration, _cancel: &Cancel) -> bool {
        false
    }
}

#[test]
fn an_overrun_term_is_not_started_and_the_lock_is_released() {
    // §D5: each row moves the hold's clock just past the point where its term
    // would end after its cumulative deadline, immediately before that term's
    // gate. The term does not start, its effect and every later one's is
    // absent, and the lock is released.
    // (term, elapsed at its gate in ms, backup expected, the outcome)
    let rows = [
        (Term::Lock, 51, false, ConfigOutcome::Aborted),
        (Term::Read, 51, false, ConfigOutcome::Aborted),
        (Term::Transform, 201, false, ConfigOutcome::Aborted),
        (Term::Backup, 401, false, ConfigOutcome::Aborted),
        (Term::Temp, 651, true, ConfigOutcome::Aborted),
        (Term::Recheck, 951, true, ConfigOutcome::Aborted),
        (Term::Rename, 1101, true, ConfigOutcome::Aborted),
        // Exactly on the line still starts: the budget is inclusive.
        (Term::Rename, 1100, true, ConfigOutcome::Applied),
    ];
    assert_eq!(Term::Rename.deadline(), CONFIG_HOLD_BUDGET, "the last deadline is the budget");
    for (term, at_ms, backup, outcome) in rows {
        let home = LiveHome::new();
        let (before, after) = small_pair();
        home.plant(&before);
        let offset_ms = Arc::new(AtomicU64::new(0));
        let clock = Clock::from_source(Arc::new(SteppedClock {
            base: Instant::now(),
            offset_ms: Arc::clone(&offset_ms),
        }));
        let hooks = HoldHooks {
            before_term: Some(Box::new(move |at| {
                if at == term {
                    offset_ms.store(at_ms, Ordering::SeqCst);
                }
            })),
            ..HoldHooks::default()
        };

        let report = rewrite_with(&home, &t_profile(), &clock, Arc::new(RealFs), &hooks);

        let row = format!("{term:?} at {at_ms} ms");
        assert_eq!(report.outcome, outcome, "row {row}: {report:?}");
        if outcome == ConfigOutcome::Aborted {
            assert_eq!(report.reason, Some(ConfigReason::Budget), "row {row}");
            assert_eq!(home.contents(), before.as_bytes(), "row {row}: no rename");
        } else {
            assert_eq!(home.contents(), after.as_bytes(), "row {row}: renamed");
        }
        assert_eq!(home.backup_names().len(), usize::from(backup), "row {row}: backup {backup}");
        assert!(home.temps().is_empty(), "row {row}: no temp left: {:?}", home.temps());
        assert!(!home.lock_dir().exists(), "row {row}: lock released");
        assert_eq!(report.hold_ms, Some(at_ms), "row {row}: the hold measured on the same clock");
    }
}

/// What the seams saw, in one timeline.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    Mkdir(bool),
    Rmdir,
    Sleep,
}

type Timeline = Arc<Mutex<Vec<Seen>>>;

fn push(timeline: &Timeline, seen: Seen) {
    timeline.lock().unwrap_or_else(PoisonError::into_inner).push(seen);
}

struct SpyFs(Timeline);

impl LockFs for SpyFs {
    fn mkdir(&self, at: LockSlot<'_>) -> Result<(), FsError> {
        let result = RealFs.mkdir(at);
        push(&self.0, Seen::Mkdir(result.is_ok()));
        result
    }

    fn rmdir(&self, at: LockSlot<'_>) -> Result<(), FsError> {
        push(&self.0, Seen::Rmdir);
        RealFs.rmdir(at)
    }

    fn mtime(&self, at: LockSlot<'_>) -> Option<SystemTime> {
        RealFs.mtime(at)
    }
}

/// Real clocks whose sleeps are recorded, and whose first sleep sees a peer
/// release the lock it was waiting on.
struct SpyClock {
    timeline: Timeline,
    released_by_peer: PathBuf,
    released: AtomicBool,
}

impl TimeSource for SpyClock {
    fn wall(&self) -> SystemTime {
        SystemTime::now()
    }

    fn monotonic(&self) -> Instant {
        Instant::now()
    }

    fn sleep(&self, _how_long: Duration, _cancel: &Cancel) -> bool {
        push(&self.timeline, Seen::Sleep);
        // Only the first sleep is the peer's release: a later one would be
        // agctl sleeping inside its own hold, and removing agctl's lock then
        // would hide that behind a compromised-lock abort.
        if !self.released.swap(true, Ordering::SeqCst) {
            let _ = fs::remove_dir(&self.released_by_peer);
        }
        false
    }
}

#[test]
fn the_hold_never_sleeps_and_asks_nothing_of_the_network() {
    // Ruling R-D. The behavioural half: one timeline shared by a recording
    // `LockFs` and a recording `TimeSource`, over a pass that did have to wait
    // — so the spy demonstrably records sleeps — shows none between the
    // successful `mkdir` and the `rmdir`.
    let home = LiveHome::new();
    let (before, after) = small_pair();
    home.plant(&before);
    fs::create_dir(home.lock_dir()).expect("a peer holds the lock at first");
    let timeline: Timeline = Arc::new(Mutex::new(Vec::new()));
    let clock = Clock::from_source(Arc::new(SpyClock {
        timeline: Arc::clone(&timeline),
        released_by_peer: home.lock_dir(),
        released: AtomicBool::new(false),
    }));

    let report = rewrite_with(
        &home,
        &t_profile(),
        &clock,
        Arc::new(SpyFs(Arc::clone(&timeline))),
        &HoldHooks::default(),
    );
    assert_eq!(report.outcome, ConfigOutcome::Applied, "{report:?}");
    assert_eq!(home.contents(), after.as_bytes());

    let seen = timeline.lock().unwrap_or_else(PoisonError::into_inner).clone();
    let held_from = seen.iter().position(|op| *op == Seen::Mkdir(true)).expect("a mkdir Ok");
    let held_to = seen.iter().position(|op| *op == Seen::Rmdir).expect("an rmdir");
    assert!(
        !seen[held_from..held_to].contains(&Seen::Sleep),
        "no sleep between `mkdir Ok` and `rmdir`: {seen:?}"
    );
    assert_eq!(seen, [Seen::Mkdir(false), Seen::Sleep, Seen::Mkdir(true), Seen::Rmdir], "{seen:?}");

    // The structural half: the hold is called with exactly its parameters — the
    // prepared write, the lock and the hooks. There is no profile source, no
    // cancellation and no prompt it could reach.
    let home = LiveHome::new();
    home.plant(&before);
    let prepared = prepare(&home.env(), &t_profile(), NOW).expect("step P passes");
    let lock =
        config_lock::acquire(&prepared.config_path, &Clock::system(), Arc::new(RealFs), &ctx())
            .expect("a free lock");
    let report = hold(prepared, lock, &HoldHooks::default());
    assert_eq!(report.outcome, ConfigOutcome::Applied, "{report:?}");
    assert_eq!(home.contents(), after.as_bytes());
}

// ---------------------------------------------------------------------------
// Backups
// ---------------------------------------------------------------------------

#[test]
fn the_backup_is_the_pre_write_bytes_under_the_peers_name() {
    let home = LiveHome::new();
    let (before, _) = small_pair();
    home.plant(&before);

    let report = rewrite(&home, &t_profile());
    assert_eq!(report.outcome, ConfigOutcome::Applied, "{report:?}");

    let backups = home.backup_names();
    assert_eq!(backups.len(), 1, "one backup exists: {backups:?}");
    let name = &backups[0];
    let stamp = name.strip_prefix(".claude.json.backup.").expect("the peer's name shape");
    assert!(stamp.len() == 13 && stamp.bytes().all(|b| b.is_ascii_digit()), "{name}");
    let path = home.backups().join(name);
    assert_eq!(
        fs::metadata(&path).expect("stat").permissions().mode() & 0o7777,
        0o600,
        "mode 0600"
    );
    assert_eq!(
        fs::read(&path).expect("readable"),
        before.as_bytes(),
        "backup == the pre-write file"
    );
    assert_eq!(report.backup.as_deref(), Some(name.as_str()), "the report names it");
}

#[test]
fn backups_is_created_when_absent_and_an_unwritable_one_refuses() {
    // Absent: created at 0700 through the `~/.claude` link, and the backup
    // written into it.
    let home = LiveHome::new();
    let (before, after) = small_pair();
    home.plant(&before);
    assert!(!home.backups().exists());
    assert_eq!(rewrite(&home, &t_profile()).outcome, ConfigOutcome::Applied);
    let mode = fs::metadata(home.backups()).expect("created").permissions().mode() & 0o7777;
    assert_eq!(mode, 0o700, "created 0700");
    assert_eq!(home.backup_names().len(), 1);
    assert_eq!(home.contents(), after.as_bytes());

    // Unwritable (ruling G8): refused, and nothing is written without a backup.
    let home = LiveHome::new();
    home.plant(&before);
    fs::create_dir(home.backups()).expect("creatable");
    fs::set_permissions(home.backups(), fs::Permissions::from_mode(0o500)).expect("chmod");
    let report = rewrite(&home, &t_profile());
    fs::set_permissions(home.backups(), fs::Permissions::from_mode(0o700)).expect("restore");

    assert_eq!(
        (report.outcome, report.reason),
        (ConfigOutcome::Refused, Some(ConfigReason::BackupUnwritable)),
        "{report:?}"
    );
    assert_eq!(home.contents(), before.as_bytes(), "target byte-identical");
    assert!(home.temps().is_empty(), "no temp");
    assert!(home.backup_names().is_empty(), "no backup");
    assert!(!home.lock_dir().exists(), "lock released");
}

#[test]
fn agctl_never_prunes_backups() {
    // Ruling G7: the peer prunes to five on its next locked save; agctl never
    // removes one.
    let home = LiveHome::new();
    let (before, _) = small_pair();
    home.plant(&before);
    fs::create_dir(home.backups()).expect("creatable");
    let planted: Vec<(String, String)> = (1..=5)
        .map(|n| (format!(".claude.json.backup.178000000000{n}"), format!("old backup {n}")))
        .collect();
    for (name, text) in &planted {
        fs::write(home.backups().join(name), text).expect("plantable");
    }

    assert_eq!(rewrite(&home, &t_profile()).outcome, ConfigOutcome::Applied);

    assert_eq!(home.backup_names().len(), 6, "5 planted → 6 after");
    for (name, text) in &planted {
        assert_eq!(
            fs::read_to_string(home.backups().join(name)).expect("still there"),
            *text,
            "{name}"
        );
    }
}

// ---------------------------------------------------------------------------
// The link, the mode, and an absent file
// ---------------------------------------------------------------------------

#[test]
fn the_link_is_followed_and_left_intact_and_the_target_mode_is_kept() {
    for mode in [0o600, 0o640] {
        let home = LiveHome::new();
        let (before, after) = small_pair();
        home.plant(&before);
        fs::set_permissions(home.target(), fs::Permissions::from_mode(mode)).expect("chmod");
        let link_inode = fs::symlink_metadata(home.link()).expect("the link").ino();

        let report = rewrite(&home, &t_profile());
        assert_eq!(report.outcome, ConfigOutcome::Applied, "{mode:o}: {report:?}");

        assert_link_intact(&home);
        assert_eq!(
            fs::symlink_metadata(home.link()).expect("the link").ino(),
            link_inode,
            "{mode:o}: the link's own inode"
        );
        let kept = fs::metadata(home.target()).expect("stat").permissions().mode() & 0o7777;
        assert_eq!(kept, mode, "row {mode:04o}: the target's mode is kept");
        assert_eq!(home.contents(), after.as_bytes(), "{mode:o}: content = expected");
        assert!(home.temps().is_empty());
    }
}

#[test]
fn an_absent_config_file_is_skipped_without_a_lock() {
    // No document: Claude Code's next start-up refresh writes `oauthAccount`
    // from the current token. The link here dangles, which reads as absent.
    let home = LiveHome::new();
    let report = rmw(&home.env(), &t_profile(), &ctx());
    assert_eq!(
        (report.outcome, report.reason),
        (ConfigOutcome::Skipped, Some(ConfigReason::Absent))
    );
    assert!(!home.lock_dir().exists(), "no lock directory");
    assert!(!home.backups().exists(), "no backups/ created");
    assert!(!home.target().exists(), "nothing was created");
    assert_eq!(report.hold_ms, None);
    assert!(fs::symlink_metadata(home.link()).expect("the link").file_type().is_symlink());

    // No link at all either.
    let bare = TempDir::new().expect("a home");
    fs::create_dir(bare.path().join(".claude")).expect("a config home");
    let report = rmw(&EnvView::with_home(bare.path().to_path_buf()), &t_profile(), &ctx());
    assert_eq!(
        (report.outcome, report.reason),
        (ConfigOutcome::Skipped, Some(ConfigReason::Absent))
    );
    assert_eq!(names(bare.path()), [".claude"], "nothing created beside it");
}
