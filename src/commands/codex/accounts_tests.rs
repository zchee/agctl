use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;

use super::*;
use crate::config::codex::RefreshPolicy;
use crate::provider::codex::testkit;

/// A `Prompt` that answers every question the same way and keeps what it was
/// told, so a test can assert on the words a person would have read.
struct Scripted {
    answer: bool,
    asked: Vec<String>,
    told: Vec<String>,
}

impl Scripted {
    fn saying(answer: bool) -> Self {
        Self { answer, asked: Vec::new(), told: Vec::new() }
    }

    /// Everything printed, joined — for a `contains` assertion.
    fn output(&self) -> String {
        self.told.join("\n")
    }
}

impl Prompt for Scripted {
    fn tell(&mut self, message: &str) {
        self.told.push(message.to_owned());
    }

    fn confirm(&mut self, question: &str) -> Result<bool, AppError> {
        self.asked.push(question.to_owned());
        Ok(self.answer)
    }
}

/// An owned row for the testkit's ids.
fn owned_row() -> CodexAccountRecord {
    testkit::owned_record(testkit::USER, testkit::ACCT)
}

/// A read-only row for another home.
fn home_row(dir: &Path) -> CodexAccountRecord {
    CodexAccountRecord {
        chatgpt_user_id: "user-imported".to_owned(),
        chatgpt_account_id: "acct-imported".to_owned(),
        email: Some("imported@example.invalid".to_owned()),
        plan_type: Some("plus".to_owned()),
        label: None,
        kind: CodexKind::HomeReadOnly { dir: dir.to_path_buf() },
        forgotten: false,
        created_at: "2026-09-17T00:00:00Z".to_owned(),
    }
}

/// The live row.
fn live_row() -> CodexAccountRecord {
    CodexAccountRecord {
        chatgpt_user_id: "user-live".to_owned(),
        chatgpt_account_id: "acct-live".to_owned(),
        email: Some("live@example.invalid".to_owned()),
        plan_type: Some("pro".to_owned()),
        label: None,
        kind: CodexKind::Live,
        forgotten: false,
        created_at: "2026-09-17T00:00:00Z".to_owned(),
    }
}

fn seed(paths: &Paths, rows: Vec<CodexAccountRecord>) {
    AgctlConfig::update(paths, |config| config.codex_accounts = rows).expect("seeds the registry");
}

fn rows(paths: &Paths) -> Vec<CodexAccountRecord> {
    AgctlConfig::load(paths).expect("loads").codex_accounts
}

fn ns_dir(paths: &Paths) -> PathBuf {
    paths.codex_namespace_dir(testkit::USER, testkit::ACCT).expect("valid ids")
}

/// A namespace holding a credential, the way a login leaves it.
fn namespace_with_a_credential(paths: &Paths) -> PathBuf {
    let dir = ns_dir(paths);
    testkit::write_0600(&dir.join("auth.json"), &testkit::fresh_auth_bytes());
    dir
}

#[test]
fn show_resolves_within_codex_accounts_only_and_by_every_spelling() {
    // Plan AC107 and invariant I28: one email, two registries, and this
    // command can only see one of them.
    let (_dir, paths) = testkit::store();
    let mut row = owned_row();
    row.email = Some("shared@example.invalid".to_owned());
    row.label = Some("work".to_owned());
    seed(&paths, vec![row]);
    let key = format!("{}/{}", testkit::USER, testkit::ACCT);

    for spelling in [key.as_str(), testkit::USER, testkit::ACCT, "shared@example.invalid", "work"] {
        let mut io = Scripted::saying(false);
        show(&paths, spelling, &mut io).unwrap_or_else(|err| panic!("`{spelling}`: {err}"));
        assert!(io.output().contains(&key), "`{spelling}` showed the wrong row: {}", io.output());
    }

    let mut io = Scripted::saying(false);
    let err = show(&paths, "nobody@example.invalid", &mut io).expect_err("refused");
    assert!(err.to_string().contains("no account matches"), "{err}");
}

#[test]
fn an_ambiguous_id_names_the_unambiguous_spellings() {
    let (_dir, paths) = testkit::store();
    let mut first = owned_row();
    first.email = Some("both@example.invalid".to_owned());
    let mut second = testkit::owned_record(testkit::USER, "99999999-2222-4333-8444-555555555555");
    second.email = Some("both@example.invalid".to_owned());
    seed(&paths, vec![first, second]);

    let mut io = Scripted::saying(false);
    let err = show(&paths, "both@example.invalid", &mut io).expect_err("refused");
    let reason = err.to_string();
    assert!(reason.contains("matches 2 rows"), "{reason}");
    assert!(reason.contains(testkit::ACCT), "it names the spellings: {reason}");
}

#[test]
fn list_hides_forgotten_rows_until_all_is_given() {
    let (_dir, paths) = testkit::store();
    let mut hidden = owned_row();
    hidden.forgotten = true;
    seed(&paths, vec![hidden]);

    let mut io = Scripted::saying(false);
    list(&paths, false, &mut io).expect("lists");
    assert!(io.output().contains("1 forgotten"), "{}", io.output());
    assert!(!io.output().contains(testkit::ACCT), "a forgotten row was shown: {}", io.output());

    let mut io = Scripted::saying(false);
    list(&paths, true, &mut io).expect("lists");
    assert!(io.output().contains(testkit::ACCT), "{}", io.output());
    assert!(io.output().contains("(forgotten)"), "{}", io.output());
}

#[test]
fn forget_and_unforget_touch_the_registry_and_nothing_else() {
    let (_dir, paths) = testkit::store();
    seed(&paths, vec![owned_row()]);
    let dir = namespace_with_a_credential(&paths);
    let before = fs::read(dir.join("auth.json")).expect("the credential");

    let mut io = Scripted::saying(false);
    forget(&paths, testkit::USER, true, &mut io).expect("forgets");
    assert!(rows(&paths)[0].forgotten, "the row was not hidden");
    assert!(io.output().contains("hidden from reports"), "{}", io.output());

    // Saying it twice is not an error, and does not rewrite anything.
    let mut io = Scripted::saying(false);
    forget(&paths, testkit::USER, true, &mut io).expect("idempotent");
    assert!(io.output().contains("already forgotten"), "{}", io.output());

    let mut io = Scripted::saying(false);
    forget(&paths, testkit::USER, false, &mut io).expect("unforgets");
    assert!(!rows(&paths)[0].forgotten, "the row was not shown again");

    assert_eq!(fs::read(dir.join("auth.json")).expect("the credential"), before, "forget deleted");
}

#[test]
fn remove_without_delete_secret_leaves_the_credential_alone() {
    // Decision D-007's other half: forgetting the record is not deleting the
    // secret, and the flag is the whole difference.
    let (_dir, paths) = testkit::store();
    seed(&paths, vec![owned_row()]);
    let dir = namespace_with_a_credential(&paths);

    let mut io = Scripted::saying(false);
    let removal = Removal { id: testkit::USER, delete_secret: false, yes: false };
    remove(&paths, &removal, &Cancel::new(), &mut io).expect("removes the row");

    assert!(rows(&paths).is_empty(), "the row is gone");
    assert!(dir.join("auth.json").is_file(), "the credential must still be there");
    assert!(io.asked.is_empty(), "nothing to confirm when no secret is deleted");
}

#[test]
fn delete_secret_is_refused_on_a_row_whose_home_agctl_did_not_create() {
    // Invariant I21, said by name rather than silently doing less.
    let (dir, paths) = testkit::store();
    let elsewhere = dir.path().join("their-home");
    fs::create_dir_all(&elsewhere).expect("a home");
    testkit::write_0600(&elsewhere.join("auth.json"), &testkit::fresh_auth_bytes());
    seed(&paths, vec![live_row(), home_row(&elsewhere)]);

    for id in ["user-live", "user-imported"] {
        let mut io = Scripted::saying(true);
        let removal = Removal { id, delete_secret: true, yes: true };
        let err = remove(&paths, &removal, &Cancel::new(), &mut io).expect_err("refused");
        let reason = err.to_string();
        assert!(reason.contains("did not create"), "`{id}`: {reason}");
        assert!(reason.contains("accounts forget"), "it says what to do instead: {reason}");
    }

    assert_eq!(rows(&paths).len(), 2, "a refusal removed a row");
    assert!(elsewhere.join("auth.json").is_file(), "a refusal deleted a foreign credential");
}

#[test]
fn a_declined_confirmation_removes_nothing_at_all() {
    let (_dir, paths) = testkit::store();
    seed(&paths, vec![owned_row()]);
    let dir = namespace_with_a_credential(&paths);

    let mut io = Scripted::saying(false);
    let removal = Removal { id: testkit::USER, delete_secret: true, yes: false };
    remove(&paths, &removal, &Cancel::new(), &mut io).expect("a declined removal is not an error");

    assert_eq!(io.asked.len(), 1, "the question was asked once");
    assert!(io.output().contains("nothing was removed"), "{}", io.output());
    assert_eq!(rows(&paths).len(), 1, "the row is still recorded");
    assert!(dir.join("auth.json").is_file(), "the credential is still there");
}

#[test]
fn remove_of_a_record_without_a_credential_file_creates_no_namespace() {
    // Plan AC125, and the "remove that writes" twin of the lead's ruling:
    // `OwnedNamespace::open` CREATES the directory it opens, so a remove that
    // opened one here would leave a namespace behind for a record that had
    // none. The check is an lstat under the guard; when it says NotFound the
    // namespace work is skipped, so nothing is written and — there being no
    // receipt — nothing is audited either.
    let (_dir, paths) = testkit::store();
    seed(&paths, vec![owned_row()]);
    let dir = ns_dir(&paths);
    assert!(!dir.exists(), "the fixture starts with no namespace");

    let mut io = Scripted::saying(true);
    let removal = Removal { id: testkit::USER, delete_secret: true, yes: true };
    remove(&paths, &removal, &Cancel::new(), &mut io).expect("succeeds");

    assert!(io.output().contains("no stored credential"), "it says so: {}", io.output());
    assert!(rows(&paths).is_empty(), "the row is gone");
    assert!(!dir.exists(), "the removal CREATED a namespace it then had to delete");
    assert!(
        !paths.codex_root().join(testkit::USER).exists(),
        "and it created the user directory above it"
    );
    assert!(
        !audit_log_mentions_delete(&paths),
        "a `delete` was audited for a write that never was"
    );
}

#[test]
fn a_symlink_at_the_namespace_path_is_refused_and_its_target_is_untouched() {
    // Condition (iii) of the ruling: only `NotFound` skips. A link is NOT a
    // skip — it goes on to `OwnedNamespace::open`, whose no-follow walk owns
    // that refusal. What must never happen is the link's target being emptied.
    let (dir, paths) = testkit::store();
    seed(&paths, vec![owned_row()]);
    let target = dir.path().join("somewhere-else");
    fs::create_dir_all(&target).expect("a directory");
    testkit::write_0600(&target.join("auth.json"), &testkit::fresh_auth_bytes());
    let ns = ns_dir(&paths);
    fs::create_dir_all(ns.parent().expect("a parent")).expect("the user directory");
    std::os::unix::fs::symlink(&target, &ns).expect("symlink");

    let mut io = Scripted::saying(true);
    let removal = Removal { id: testkit::USER, delete_secret: true, yes: true };
    let err = remove(&paths, &removal, &Cancel::new(), &mut io).expect_err("refused");

    assert!(!io.output().contains("no stored credential"), "a link was treated as absent: {err}");
    assert!(target.join("auth.json").is_file(), "the link's target was emptied");
    assert!(ns.symlink_metadata().is_ok_and(|m| m.is_symlink()), "the link itself is gone");
    assert_eq!(rows(&paths).len(), 1, "the row was dropped despite the refusal");
}

#[test]
fn remove_deletes_exactly_its_own_files_and_audits_one_delete() {
    // Plan AC115's positive half at the command level; `remove_named_files`
    // owns the file rules and has its own tests in `auth_store_tests.rs`.
    let (_dir, paths) = testkit::store();
    seed(&paths, vec![owned_row()]);
    let dir = namespace_with_a_credential(&paths);
    for name in ["auth.json.pending", "auth.pending.meta", "auth.json.tmp.0badc0de"] {
        testkit::write_0600(&dir.join(name), b"x");
    }
    let lock_dir = paths.codex_locks_dir();

    let mut io = Scripted::saying(true);
    let removal = Removal { id: testkit::USER, delete_secret: true, yes: false };
    remove(&paths, &removal, &Cancel::new(), &mut io).expect("removes");

    assert_eq!(io.asked.len(), 1, "it asked before deleting a secret");
    assert!(!dir.exists(), "the namespace directory is still there");
    assert!(rows(&paths).is_empty(), "the row is still recorded");
    assert!(lock_dir.is_dir(), "the lock directory was removed with the namespace");
    assert!(audit_log_mentions_delete(&paths), "the removal was not audited");
}

#[test]
fn a_namespace_holding_something_agctl_did_not_create_is_refused_with_nothing_removed() {
    // Plan AC115's refusal half, at the command level: the whole namespace is
    // still there afterwards, the refresh marker included, and the row is
    // still recorded because the registry update never runs.
    let (_dir, paths) = testkit::store();
    seed(&paths, vec![owned_row()]);
    let dir = namespace_with_a_credential(&paths);
    fs::create_dir(dir.join("sessions")).expect("a Codex session directory");
    fs::write(dir.join("config.toml"), b"# theirs\n").expect("a config");
    let before = manifest(&dir);

    let mut io = Scripted::saying(true);
    let removal = Removal { id: testkit::USER, delete_secret: true, yes: true };
    let err = remove(&paths, &removal, &Cancel::new(), &mut io).expect_err("refused");
    let reason = err.to_string();

    assert!(reason.contains("sessions"), "the refusal names what it found: {reason}");
    assert!(reason.contains("config.toml"), "{reason}");
    assert!(reason.contains("nothing was removed"), "{reason}");
    assert_eq!(manifest(&dir), before, "the namespace changed");
    assert_eq!(rows(&paths).len(), 1, "the row was dropped despite the refusal");
    assert!(!audit_log_mentions_delete(&paths), "a refusal was audited as a delete");
}

#[test]
fn a_leftover_refresh_marker_is_removed_when_the_namespace_is_already_gone() {
    // Bead `agctl-r1gu` (2). The marker does not live in the namespace — it is
    // `codex/.state/<user>+<acct>.refresh` — so the skip that protects an
    // absent namespace from being CREATED in order to be deleted used to walk
    // past it, and dropping the row left the marker with nothing referencing
    // it. A successful remove may not leave that behind.
    let (_dir, paths) = testkit::store();
    seed(&paths, vec![owned_row()]);
    let marker = marker_path(&paths);
    plant_a_marker(&marker);
    assert!(!ns_dir(&paths).exists(), "the fixture starts with no namespace");

    let mut io = Scripted::saying(true);
    let removal = Removal { id: testkit::USER, delete_secret: true, yes: true };
    remove(&paths, &removal, &Cancel::new(), &mut io).expect("succeeds");

    assert!(!marker.exists(), "the refresh marker outlived the account it belonged to");
    assert!(rows(&paths).is_empty(), "the row is gone");
    assert!(!ns_dir(&paths).exists(), "the cleanup CREATED the namespace it was avoiding");
    assert!(
        !paths.codex_root().join(testkit::USER).exists(),
        "and it created the user directory above it"
    );
    assert!(
        io.output().contains("refresh marker"),
        "a person is told what was removed: {}",
        io.output()
    );
    assert!(audit_log_mentions_delete(&paths), "a removal that happened was not audited");
}

#[test]
fn a_successful_remove_leaves_neither_a_credential_nor_a_marker_nor_a_row() {
    // The pin for bead `agctl-r1gu` as a whole: after a remove that reports
    // success there is no state left for `doctor` to report — no `auth.json`,
    // no namespace, no marker, no registry row. The two halves of the bead are
    // the two ways that was false.
    let (_dir, paths) = testkit::store();
    seed(&paths, vec![owned_row()]);
    let dir = namespace_with_a_credential(&paths);
    let marker = marker_path(&paths);
    plant_a_marker(&marker);

    let mut io = Scripted::saying(true);
    let removal = Removal { id: testkit::USER, delete_secret: true, yes: true };
    remove(&paths, &removal, &Cancel::new(), &mut io).expect("succeeds");

    assert!(!dir.join("auth.json").exists(), "the credential is still there");
    assert!(!dir.exists(), "the namespace is still there");
    assert!(!marker.exists(), "the refresh marker is still there");
    assert!(rows(&paths).is_empty(), "the row is still recorded");
}

#[test]
fn a_registry_update_that_fails_after_the_delete_leaves_the_state_ac125_describes() {
    // Bead `agctl-r1gu` (5), ruled: the ordering stays as it is — delete under
    // the namespace guard, drop the guard, then update the registry — and this
    // test pins what that ordering costs when the last step fails. The
    // credential is gone and the row remains: a record without an `auth.json`,
    // which is exactly the state plan AC125 defines and `doctor` reports. The
    // alternative ordering would drop the row first and lose the only pointer
    // to a credential still on disk, which is worse and is why it was not
    // chosen.
    //
    // The registry is written temp-then-rename into the config directory, so a
    // directory the process may search and read but not write fails that step
    // and only that step: the lock file already exists, and the namespace, its
    // marker and the audit log live one level down in `codex/`.
    let (_dir, paths) = testkit::store();
    seed(&paths, vec![owned_row()]);
    let dir = namespace_with_a_credential(&paths);
    let marker = marker_path(&paths);
    plant_a_marker(&marker);
    let config_dir = paths.config_dir().to_path_buf();
    let restore = fs::metadata(&config_dir).expect("metadata").permissions();
    fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o500)).expect("read-only");

    let mut io = Scripted::saying(true);
    let removal = Removal { id: testkit::USER, delete_secret: true, yes: true };
    let result = remove(&paths, &removal, &Cancel::new(), &mut io);

    fs::set_permissions(&config_dir, restore).expect("restores the mode");
    let err = result.expect_err("the registry update failed, so the remove did");

    assert!(!dir.exists(), "the delete did not run before the registry update: {err}");
    assert!(!marker.exists(), "the marker survived a delete that did run");
    assert_eq!(rows(&paths).len(), 1, "the row was dropped although its update failed");
    assert!(audit_log_mentions_delete(&paths), "the delete that happened was not audited");
}

/// The refresh marker's path for the testkit's ids.
fn marker_path(paths: &Paths) -> PathBuf {
    paths.codex_refresh_state_path(testkit::USER, testkit::ACCT).expect("valid ids")
}

/// Writes a marker the way a refresh leaves one.
fn plant_a_marker(marker: &Path) {
    fs::create_dir_all(marker.parent().expect("a parent")).expect("the state directory");
    let state = serde_json::json!({
        "schema": 1,
        "floor_min": 60,
        "did_not_help": 1,
        "resent": false,
    });
    testkit::write_0600(marker, serde_json::to_string(&state).expect("serializes").as_bytes());
}

/// Whether the Codex audit log holds a `delete` outcome.
fn audit_log_mentions_delete(paths: &Paths) -> bool {
    let path = audit::log_path(paths);
    fs::read_to_string(path).is_ok_and(|text| text.contains("\"delete\""))
}

/// `(name, is_dir, mode, size, sha256)` for every entry under `dir`, sorted.
fn manifest(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        for entry in fs::read_dir(&next).expect("listable").flatten() {
            let path = entry.path();
            let meta = fs::symlink_metadata(&path).expect("stat");
            let digest = if meta.is_file() {
                hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
                    fs::read(&path).expect("readable"),
                ))
            } else {
                String::new()
            };
            out.push(format!(
                "{} dir={} mode={:o} size={} sha256={digest}",
                path.strip_prefix(dir).expect("under dir").display(),
                meta.is_dir(),
                meta.permissions().mode() & 0o777,
                meta.len(),
            ));
            if meta.is_dir() {
                stack.push(path);
            }
        }
    }
    out.sort();
    out
}

#[test]
fn show_names_the_refresh_policy_of_an_owned_row() {
    let (_dir, paths) = testkit::store();
    let mut row = owned_row();
    row.kind = CodexKind::Owned {
        export_spelling: "/somewhere".to_owned(),
        refresh: RefreshPolicy::Never,
    };
    seed(&paths, vec![row]);

    let mut io = Scripted::saying(false);
    show(&paths, testkit::USER, &mut io).expect("shows");
    assert!(io.output().contains("never"), "{}", io.output());
    assert!(io.output().contains("/somewhere"), "{}", io.output());
}
