//! Synthetic Codex credentials for the unit tests of `provider::codex`.
//!
//! Every token here is built from the four test sentinels
//! (`agctl-test-codex-{at,rt,ak,jwt}-…`), so a leak of any byte of one is a
//! substring search away, and nothing here resembles a real grant: the JWT
//! signatures are the sentinels themselves.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::ExitStatus;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Map;
use serde_json::Value;
use serde_json::json;

use crate::config::codex::CodexAccountRecord;
use crate::config::codex::CodexKind;
use crate::config::codex::RefreshPolicy;
use crate::config::paths::Paths;

/// The user id every default document names.
pub(crate) const USER: &str = "user-0001";
/// The account id every default document names.
pub(crate) const ACCT: &str = "11111111-2222-4333-8444-555555555555";
/// The access token's signature segment.
pub(crate) const AT_SENTINEL: &str = "agctl-test-codex-at-signature0001";
/// The refresh token.
pub(crate) const RT_SENTINEL: &str = "agctl-test-codex-rt-0001";
/// The id token's signature segment.
pub(crate) const JWT_SENTINEL: &str = "agctl-test-codex-jwt-signature0001";
/// An API key.
pub(crate) const AK_SENTINEL: &str = "agctl-test-codex-ak-0001";
/// A claim outside the allowlist.
pub(crate) const EXTRA_CLAIM_SENTINEL: &str = "agctl-test-codex-jwt-extra-claim";

/// Every needle a leak check looks for.
pub(crate) const NEEDLES: [&str; 5] = [
    "agctl-test-codex-at-",
    "agctl-test-codex-rt-",
    "agctl-test-codex-ak-",
    "agctl-test-codex-jwt-",
    "eyJ",
];

/// A JWT with `payload` and a sentinel signature.
pub(crate) fn jwt(payload: &Value, signature: &str) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT","kid":"agctl-test"}"#);
    let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).unwrap_or_default());
    format!("{header}.{body}.{signature}")
}

/// Parameters of a synthetic id token.
#[derive(Debug, Clone)]
pub(crate) struct IdClaims {
    pub user: Option<String>,
    pub acct: Option<String>,
    pub email: Option<String>,
    pub plan: Option<String>,
    pub fedramp: Option<bool>,
}

impl Default for IdClaims {
    fn default() -> Self {
        Self {
            user: Some(USER.to_owned()),
            acct: Some(ACCT.to_owned()),
            email: Some("codex-user@example.invalid".to_owned()),
            plan: Some("pro".to_owned()),
            fedramp: None,
        }
    }
}

/// An id token carrying `claims` plus claims outside the allowlist.
pub(crate) fn id_token(claims: &IdClaims) -> String {
    let mut auth = Map::new();
    if let Some(user) = &claims.user {
        auth.insert("chatgpt_user_id".to_owned(), json!(user));
    }
    if let Some(acct) = &claims.acct {
        auth.insert("chatgpt_account_id".to_owned(), json!(acct));
    }
    if let Some(plan) = &claims.plan {
        auth.insert("chatgpt_plan_type".to_owned(), json!(plan));
    }
    if let Some(fedramp) = claims.fedramp {
        auth.insert("chatgpt_account_is_fedramp".to_owned(), json!(fedramp));
    }
    auth.insert(
        "organizations".to_owned(),
        json!([{ "id": "org-x", "title": EXTRA_CLAIM_SENTINEL, "role": "owner" }]),
    );
    let mut payload = Map::new();
    if let Some(email) = &claims.email {
        payload.insert("email".to_owned(), json!(email));
    }
    payload.insert("https://api.openai.com/auth".to_owned(), Value::Object(auth));
    payload.insert("sid".to_owned(), json!(EXTRA_CLAIM_SENTINEL));
    payload.insert("exp".to_owned(), json!(1_788_734_450_i64));
    jwt(&Value::Object(payload), JWT_SENTINEL)
}

/// An access token expiring at `exp` (seconds since the epoch), or without an
/// `exp` claim.
pub(crate) fn access_token(exp: Option<i64>) -> String {
    let mut payload = json!({ "client_id": "app_agctl_test", "jti": "agctl-test-codex-at-jti" });
    if let (Some(exp), Some(object)) = (exp, payload.as_object_mut()) {
        object.insert("exp".to_owned(), json!(exp));
    }
    jwt(&payload, AT_SENTINEL)
}

/// A ChatGPT `auth.json` in Codex's key order (fact F90).
pub(crate) fn chatgpt_doc(exp: Option<i64>, last_refresh: Option<&str>) -> Value {
    let mut doc = Map::new();
    doc.insert("auth_mode".to_owned(), json!("chatgpt"));
    doc.insert("OPENAI_API_KEY".to_owned(), Value::Null);
    doc.insert(
        "tokens".to_owned(),
        json!({
            "id_token": id_token(&IdClaims::default()),
            "access_token": access_token(exp),
            "refresh_token": RT_SENTINEL,
            "account_id": ACCT,
        }),
    );
    if let Some(at) = last_refresh {
        doc.insert("last_refresh".to_owned(), json!(at));
    }
    Value::Object(doc)
}

/// `doc` serialized the way Codex writes it.
pub(crate) fn pretty(doc: &Value) -> Vec<u8> {
    serde_json::to_vec_pretty(doc).unwrap_or_default()
}

/// A ChatGPT `auth.json` whose access token expires in ten days.
pub(crate) fn fresh_auth_bytes() -> Vec<u8> {
    let exp = jiff::Timestamp::now().as_second() + 10 * 86_400;
    pretty(&chatgpt_doc(Some(exp), Some("2026-09-06T21:40:50.123456Z")))
}

/// Asserts `haystack` carries none of [`NEEDLES`].
pub(crate) fn assert_no_needles(haystack: &str, what: &str) {
    for needle in NEEDLES {
        assert!(!haystack.contains(needle), "{what} leaked `{needle}`:\n{haystack}");
    }
    assert!(
        !haystack.contains(EXTRA_CLAIM_SENTINEL),
        "{what} leaked a claim outside the allowlist:\n{haystack}"
    );
}

/// An exit status with `code`.
pub(crate) fn exit_status(code: i32) -> ExitStatus {
    ExitStatus::from_raw(code << 8)
}

/// A temporary agctl store with the Codex tree created.
pub(crate) fn store() -> (tempfile::TempDir, Paths) {
    let dir = tempfile::tempdir().unwrap_or_else(|err| panic!("tempdir: {err}"));
    let paths = Paths::with_config_dir(dir.path().join("agctl"));
    paths.ensure_codex_dirs().unwrap_or_else(|err| panic!("ensure_codex_dirs: {err}"));
    (dir, paths)
}

/// An owned registry record for `(user, acct)`.
pub(crate) fn owned_record(user: &str, acct: &str) -> CodexAccountRecord {
    CodexAccountRecord {
        chatgpt_user_id: user.to_owned(),
        chatgpt_account_id: acct.to_owned(),
        email: None,
        plan_type: None,
        label: None,
        kind: CodexKind::Owned {
            export_spelling: "/somewhere/else".to_owned(),
            refresh: RefreshPolicy::Auto,
        },
        forgotten: false,
        created_at: "2026-09-17T00:00:00Z".to_owned(),
    }
}

/// Writes `bytes` to `path` at 0600.
pub(crate) fn write_0600(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .unwrap_or_else(|err| panic!("mkdir {}: {err}", parent.display()));
    }
    fs::write(path, bytes).unwrap_or_else(|err| panic!("write {}: {err}", path.display()));
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|err| panic!("chmod: {err}"));
}

/// The repository's `fixtures/codex/<name>`.
pub(crate) fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/codex").join(name);
    fs::read(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

/// The namespace lock for an owned record, taken with a command budget.
pub(crate) fn lock_for(
    paths: &Paths,
    record: &CodexAccountRecord,
) -> crate::provider::codex::proof::CodexNamespaceGuard {
    let owned =
        crate::provider::codex::proof::owned(record).unwrap_or_else(|| panic!("an owned record"));
    crate::provider::codex::lock::acquire_codex(
        paths,
        owned,
        crate::provider::codex::lock::LockBudget::Command(std::time::Duration::from_secs(2)),
        &crate::runtime::coordinator::Cancel::new(),
        &crate::runtime::fault::Fault::none(),
    )
    .unwrap_or_else(|err| panic!("lock: {err}"))
}

/// Every leaf of `value` keyed by its JSON pointer.
pub(crate) fn leaves(value: &Value) -> std::collections::BTreeMap<String, Value> {
    fn walk(prefix: &str, value: &Value, out: &mut std::collections::BTreeMap<String, Value>) {
        match value {
            Value::Object(map) if !map.is_empty() => {
                for (key, child) in map {
                    walk(&format!("{prefix}/{key}"), child, out);
                }
            }
            Value::Array(items) if !items.is_empty() => {
                for (index, child) in items.iter().enumerate() {
                    walk(&format!("{prefix}/{index}"), child, out);
                }
            }
            leaf => {
                out.insert(prefix.to_owned(), leaf.clone());
            }
        }
    }
    let mut out = std::collections::BTreeMap::new();
    walk("", value, &mut out);
    out
}
