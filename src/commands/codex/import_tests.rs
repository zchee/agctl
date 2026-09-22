use std::fs;
use std::path::Path;
use std::path::PathBuf;

use super::*;
use crate::config::codex::RefreshPolicy;
use crate::provider::codex::home::StoreMode;
use crate::provider::codex::testkit;
use crate::provider::codex::testkit::rows;
use crate::secret::ServiceEntry;

/// A Codex home holding a fresh ChatGPT credential.
fn home_with_credential(root: &Path, name: &str) -> PathBuf {
    let home = root.join(name);
    fs::create_dir_all(&home).expect("a home directory");
    testkit::write_0600(&home.join("auth.json"), &testkit::fresh_auth_bytes());
    home
}

/// `--from codex-home`, with the flags a case needs.
fn args(codex_home: Option<&Path>, dry_run: bool) -> CodexImportArgs {
    CodexImportArgs {
        from: CodexImportSource::CodexHome,
        codex_home: codex_home.map(Path::to_path_buf),
        dry_run,
    }
}

/// Runs one import against `home` with the listing a case chose.
fn import(
    paths: &Paths,
    home: &Path,
    args: &CodexImportArgs,
    keyring: &KeyringListing,
) -> Result<Vec<String>, AppError> {
    run_with(&Import { paths, args, home, keyring })
}

/// A `Codex Auth` listing naming `home`'s item (fact F94).
fn listing_for(home: &Path) -> KeyringListing {
    KeyringListing::Entries(vec![ServiceEntry {
        service: home::KEYRING_SERVICE.to_owned(),
        account: Some(home::keyring_account(home)),
        cdat: None,
        mdat: None,
    }])
}

/// A spy that fails the test if `auth.json` is opened at all.
///
/// The store-mode rules say `keyring` and `ephemeral` homes are **not read**
/// with zero `auth.json` reads (plan AC95), and "zero" is not something an
/// assertion on the output can show. So the file is made unopenable: any read
/// would be an error the import would have to report, and the refusal the test
/// asserts is the store-mode one, by text.
fn poison_the_credential(home: &Path) {
    let path = home.join("auth.json");
    testkit::write_0600(&path, b"{ this is not a credential and must never be parsed");
}

#[test]
fn record_once_does_not_add_a_second_row_for_ids_the_registry_already_names() {
    // The race re-check, driven directly. It only matters in the window
    // between `run_with`'s load and `AgctlConfig::update`'s re-read under
    // `.config.lock` — a window no ordinary run enters, which is exactly why
    // it was unfalsifiable while it lived inside the closure: `if true` there
    // passed the whole suite (review C2-b, Q6). Deterministic: no seam, no
    // thread, no sleep, just the function and a registry that already names
    // the ids.
    let identity = CodexIdentity {
        user_id: testkit::USER.to_owned(),
        account_id: testkit::ACCT.to_owned(),
        email: Some("someone@example.invalid".to_owned()),
        plan: Some("pro".to_owned()),
    };

    // Already recorded, and under a DIFFERENT kind, so a push would be both a
    // duplicate and a downgrade of a row the user logged in to create.
    let mut config = AgctlConfig::default();
    config.codex_accounts.push(testkit::owned_record(testkit::USER, testkit::ACCT));
    let before = serde_json::to_string(&config).expect("serializes");

    record_once(&mut config, &identity, PathBuf::from("/somewhere"));

    assert_eq!(config.codex_accounts.len(), 1, "a second row was pushed for ids already named");
    assert_eq!(
        serde_json::to_string(&config).expect("serializes"),
        before,
        "the registry was changed for ids it already named"
    );

    // …and the twin: with the ids absent it does push, so the guard above is
    // a guard and not a function that never records anything.
    let mut empty = AgctlConfig::default();
    record_once(&mut empty, &identity, PathBuf::from("/somewhere"));
    assert_eq!(empty.codex_accounts.len(), 1);
    assert_eq!(
        empty.codex_accounts[0].kind,
        CodexKind::HomeReadOnly { dir: PathBuf::from("/somewhere") }
    );
}

#[test]
fn a_home_with_a_credential_is_recorded_read_only_with_the_identity_from_its_claims() {
    // Plan AC106: `HomeReadOnly{dir}` + identity from the claims, metadata
    // only (decision D-007's posture).
    let (dir, paths) = testkit::store();
    let home = home_with_credential(dir.path(), "other-home");

    let lines = import(&paths, &home, &args(Some(&home), false), &KeyringListing::NotNeeded)
        .expect("records");

    let recorded = rows(&paths);
    assert_eq!(recorded.len(), 1, "exactly one row: {recorded:?}");
    let record = &recorded[0];
    assert_eq!(record.chatgpt_user_id, testkit::USER);
    assert_eq!(record.chatgpt_account_id, testkit::ACCT);
    assert_eq!(record.kind, CodexKind::HomeReadOnly { dir: home.clone() });
    assert!(!record.forgotten);
    assert!(record.label.is_none(), "import never invents a label");
    assert!(!record.created_at.is_empty());

    // Metadata only: no token, no digest, nothing a needle would match.
    testkit::assert_no_needles(&format!("{record:?}"), "the recorded row");
    testkit::assert_no_needles(&lines.join("\n"), "the import's output");
    let document = fs::read_to_string(paths.config_file()).expect("the registry file");
    testkit::assert_no_needles(&document, "the registry file");
}

#[test]
fn a_second_import_of_the_same_home_changes_nothing() {
    // Plan AC106 "idempotent": the same run twice leaves the registry file
    // byte-identical, and says so rather than adding a row.
    let (dir, paths) = testkit::store();
    let home = home_with_credential(dir.path(), "other-home");
    let args = args(Some(&home), false);

    import(&paths, &home, &args, &KeyringListing::NotNeeded).expect("records");
    let after_first = fs::read(paths.config_file()).expect("the registry file");

    let lines = import(&paths, &home, &args, &KeyringListing::NotNeeded).expect("reports");
    assert!(
        lines.iter().any(|line| line.contains("already recorded")),
        "the second run says so: {lines:?}"
    );
    assert_eq!(rows(&paths).len(), 1, "no second row");
    assert_eq!(
        fs::read(paths.config_file()).expect("the registry file"),
        after_first,
        "the registry file is byte-identical"
    );
}

#[test]
fn an_account_already_recorded_under_another_kind_is_reported_and_left_alone() {
    // Decision D-007: an import never overwrites what you have, whatever kind
    // it is — which is what stops it turning a logged-in account back into a
    // read-only row. The `forgotten` case is included: a hidden row is still
    // a row the user decided about.
    for forgotten in [false, true] {
        let (dir, paths) = testkit::store();
        let home = home_with_credential(dir.path(), "other-home");
        let mut owned = testkit::owned_record(testkit::USER, testkit::ACCT);
        owned.forgotten = forgotten;
        owned.label = Some("the one I logged in with".to_owned());
        let before = owned.clone();
        AgctlConfig::update(&paths, |config| config.codex_accounts.push(owned))
            .expect("seeds the registry");

        let lines = import(&paths, &home, &args(Some(&home), false), &KeyringListing::NotNeeded)
            .expect("reports");

        assert!(
            lines.iter().any(|line| line.contains("already recorded")),
            "forgotten={forgotten}: {lines:?}"
        );
        assert_eq!(
            rows(&paths),
            vec![before],
            "the owned row is untouched (forgotten={forgotten})"
        );
    }
}

#[test]
fn dry_run_writes_nothing_and_leaves_a_store_that_did_not_exist_still_absent() {
    // Plan AC106: `--dry-run` writes nothing. The registry file is the thing
    // this command writes, so the proof is that it never comes into existence.
    let (dir, paths) = testkit::store();
    let home = home_with_credential(dir.path(), "other-home");
    let registry = paths.config_file();
    let existed = registry.exists();

    let lines =
        import(&paths, &home, &args(Some(&home), true), &KeyringListing::NotNeeded).expect("plans");

    assert!(
        lines.iter().any(|line| line.contains("--dry-run: nothing was written")),
        "the run says it wrote nothing: {lines:?}"
    );
    assert!(
        lines.iter().any(|line| line.contains(&home.display().to_string())),
        "and still says what it would have recorded: {lines:?}"
    );
    assert_eq!(registry.exists(), existed, "a store that did not exist still does not");
    if existed {
        assert!(rows(&paths).is_empty(), "no row was added");
    }
}

#[test]
fn a_keyring_or_ephemeral_home_is_refused_without_reading_its_credential() {
    // Plan AC95: `keyring` and `ephemeral` → not read, 0 `auth.json` reads.
    // The credential is poisoned, so a read would report a parse failure
    // instead of the store-mode refusal this asserts.
    for (store, label) in [("keyring", "keyring"), ("ephemeral", "ephemeral")] {
        let (dir, paths) = testkit::store();
        let home = dir.path().join(format!("{store}-home"));
        fs::create_dir_all(&home).expect("a home directory");
        fs::write(home.join("config.toml"), format!("cli_auth_credentials_store = \"{store}\"\n"))
            .expect("a config");
        poison_the_credential(&home);

        let err = import(&paths, &home, &args(Some(&home), false), &KeyringListing::NotNeeded)
            .expect_err("refused");
        let reason = err.to_string();

        assert!(reason.contains(label), "the refusal names the mode: {reason}");
        assert!(reason.contains("nothing to import"), "{reason}");
        assert!(
            !reason.contains("does not parse") && !reason.contains("not a credential"),
            "the credential was read after all: {reason}"
        );
        assert!(rows(&paths).is_empty(), "nothing was recorded");
    }
}

#[test]
fn an_auto_home_reads_the_file_only_when_the_listing_names_no_item() {
    // Plan AC95's fourth rule (fact F94), through the SAME listing `status`
    // takes: `auto` + an item listed → not read; `auto` + no item → read, with
    // the note. The lead's ruling of 01:53: a unit test with an injected
    // reader, here rather than deferred.
    let (dir, paths) = testkit::store();
    let home = home_with_credential(dir.path(), "auto-home");
    fs::write(home.join("config.toml"), "cli_auth_credentials_store = \"auto\"\n")
        .expect("a config");
    assert_eq!(home::store_mode(&home).0, StoreMode::Auto, "the fixture is in auto mode");

    // An item IS listed for this home: the file is not what Codex uses.
    let err =
        import(&paths, &home, &args(Some(&home), false), &listing_for(&home)).expect_err("refused");
    assert!(err.to_string().contains("auto"), "the refusal names the mode: {err}");
    assert!(rows(&paths).is_empty(), "nothing was recorded");

    // An item listed for a DIFFERENT home does not count.
    let elsewhere = dir.path().join("somewhere-else");
    fs::create_dir_all(&elsewhere).expect("a directory");
    let lines = import(&paths, &home, &args(Some(&home), false), &listing_for(&elsewhere))
        .expect("records");
    assert!(
        lines.iter().any(|line| line.contains("auto (file in effect)")),
        "the note says which branch ran: {lines:?}"
    );
    assert_eq!(rows(&paths).len(), 1);

    // A listing that could not be taken falls back to reading the file, the
    // way `file_in_effect` decides it for `status`.
    let (dir, paths) = testkit::store();
    let home = home_with_credential(dir.path(), "auto-home");
    fs::write(home.join("config.toml"), "cli_auth_credentials_store = \"auto\"\n")
        .expect("a config");
    import(&paths, &home, &args(Some(&home), false), &KeyringListing::Unavailable)
        .expect("records");
    assert_eq!(rows(&paths).len(), 1);
}

#[test]
fn a_home_with_no_usable_credential_is_refused_by_name() {
    let (dir, paths) = testkit::store();

    // Absent.
    let empty = dir.path().join("empty-home");
    fs::create_dir_all(&empty).expect("a home directory");
    let err = import(&paths, &empty, &args(Some(&empty), false), &KeyringListing::NotNeeded)
        .expect_err("refused");
    assert!(err.to_string().contains("holds no"), "{err}");

    // Torn (fact F66): a retry, never "there is nothing here".
    let torn = dir.path().join("torn-home");
    fs::create_dir_all(&torn).expect("a home directory");
    testkit::write_0600(&torn.join("auth.json"), &testkit::fresh_auth_bytes()[..40]);
    let err = import(&paths, &torn, &args(Some(&torn), false), &KeyringListing::NotNeeded)
        .expect_err("refused");
    let reason = err.to_string();
    assert!(reason.contains("being rewritten") && reason.contains("run this again"), "{reason}");

    // A ChatGPT document whose claims name no account.
    let anonymous = dir.path().join("anonymous-home");
    fs::create_dir_all(&anonymous).expect("a home directory");
    let mut doc = testkit::chatgpt_doc(Some(4_102_444_800), None);
    doc["tokens"]["id_token"] = serde_json::json!(testkit::id_token(&testkit::IdClaims {
        user: None,
        ..testkit::IdClaims::default()
    }));
    testkit::write_0600(&anonymous.join("auth.json"), &testkit::pretty(&doc));
    let err =
        import(&paths, &anonymous, &args(Some(&anonymous), false), &KeyringListing::NotNeeded)
            .expect_err("refused");
    assert!(err.to_string().contains("names no ChatGPT user or account"), "{err}");

    assert!(rows(&paths).is_empty(), "no refusal recorded anything");
}

#[test]
fn the_codex_home_flag_obeys_codex_homes_own_rules_and_names_itself_in_a_refusal() {
    // Plan AC95's set cases, through the flag rather than the variable: one
    // implementation (`home::codex_home`), two entry points. The refusal names
    // what the user typed.
    let dir = tempfile::tempdir().expect("tempdir");
    let env = CodexEnv::new(None, Some(dir.path().to_path_buf()));

    // Set + a directory → canonical.
    let real = dir.path().join("real-home");
    fs::create_dir_all(&real).expect("a home directory");
    let linked = dir.path().join("linked-home");
    std::os::unix::fs::symlink(&real, &linked).expect("symlink");
    let resolved = resolve_home(&args(Some(&linked), false), &env).expect("resolves");
    assert_eq!(resolved, real.canonicalize().expect("canonical"), "the flag's path is canonical");

    // Set + missing.
    let missing = dir.path().join("not-here");
    let err = resolve_home(&args(Some(&missing), false), &env).expect_err("refused");
    let reason = err.to_string();
    assert!(reason.contains("--codex-home"), "the refusal names the flag: {reason}");
    assert!(reason.contains("does not exist"), "{reason}");
    assert!(!reason.contains("CODEX_HOME"), "it does not blame a variable nobody set: {reason}");

    // Set + not a directory.
    let file = dir.path().join("a-file");
    fs::write(&file, b"x").expect("writable");
    let err = resolve_home(&args(Some(&file), false), &env).expect_err("refused");
    let reason = err.to_string();
    assert!(reason.contains("--codex-home") && reason.contains("not a directory"), "{reason}");

    // No flag → the environment's own answer, unchanged.
    let fallback = resolve_home(&args(None, false), &env).expect("resolves");
    assert_eq!(fallback, dir.path().join(".codex"), "the unset rule is `$HOME/.codex`");
}

#[test]
fn an_import_writes_nothing_under_the_home_it_reads() {
    // Plan AC106, invariant I21's file half: the import succeeds against a
    // home whose directories are 0500 and whose credential is 0400, and the
    // home's manifest is identical afterwards. The e2e half runs the same
    // check through the binary.
    let (dir, paths) = testkit::store();
    let home = home_with_credential(dir.path(), "read-only-home");
    fs::write(home.join("config.toml"), "\n").expect("a config");

    // The modes are set BEFORE the first manifest, so the only difference the
    // comparison can report is one the import made. 0500 on the directory
    // still allows the read and the listing; it refuses creation and removal.
    chmod(&home.join("auth.json"), 0o400);
    chmod(&home.join("config.toml"), 0o400);
    chmod(&home, 0o500);
    let before = manifest(&home);

    let result = import(&paths, &home, &args(Some(&home), false), &KeyringListing::NotNeeded);

    let after = manifest(&home);
    chmod(&home, 0o700);
    chmod(&home.join("auth.json"), 0o600);
    chmod(&home.join("config.toml"), 0o600);

    result.expect("a read-only home is still importable");
    assert_eq!(after, before, "the home changed");
    assert_eq!(rows(&paths).len(), 1, "and the account was recorded");
}

/// `(name, is_dir, mode, size, mtime_ns, sha256)` for every entry under `dir`.
fn manifest(dir: &Path) -> Vec<String> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;

    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        for entry in fs::read_dir(&next).expect("readable").flatten() {
            let path = entry.path();
            let meta = fs::symlink_metadata(&path).expect("stat");
            let digest = if meta.is_file() {
                let bytes = fs::read(&path).expect("readable");
                hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&bytes))
            } else {
                String::new()
            };
            out.push(format!(
                "{} dir={} mode={:o} size={} mtime_ns={} sha256={digest}",
                path.strip_prefix(dir).expect("under dir").display(),
                meta.is_dir(),
                meta.permissions().mode() & 0o777,
                meta.len(),
                meta.mtime_nsec() + meta.mtime() * 1_000_000_000,
            ));
            if meta.is_dir() {
                stack.push(path);
            }
        }
    }
    out.sort();
    out
}

fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod");
}

#[test]
fn the_recorded_row_keeps_its_refresh_policy_out_of_the_kind() {
    // A read-only home has no policy to have: only `Owned` carries one, so a
    // row this command writes cannot be told to refresh (invariant I21).
    let (dir, paths) = testkit::store();
    let home = home_with_credential(dir.path(), "other-home");
    import(&paths, &home, &args(Some(&home), false), &KeyringListing::NotNeeded).expect("records");

    match &rows(&paths)[0].kind {
        CodexKind::HomeReadOnly { dir } => assert_eq!(dir, &home),
        other => panic!("import recorded a writable kind: {other:?}"),
    }
    // The type makes it so; this is the compile-time twin of the assertion.
    let _: fn(RefreshPolicy) -> CodexKind =
        |refresh| CodexKind::Owned { export_spelling: String::new(), refresh };
}
