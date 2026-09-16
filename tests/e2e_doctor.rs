#![cfg(feature = "testing")]

//! `doctor`'s isolation section, driven through the real binary (plan AC58),
//! and the store block's own audit-log row (`agctl-9je`).
//!
//! Like `tests/e2e_isolate.rs`, these only exercise the session-directory
//! half of the store: no test here installs the fake `security(1)`, and every
//! session directory a test needs beyond what S15's `env` already creates is
//! built by hand with plain filesystem calls, so these run regardless of
//! whether S16's seeding has landed.

mod common;

use std::fs;
use std::os::unix::fs::symlink;

use common::ACCT;
use common::Fixture;
use common::ORG;
use serde_json::json;

/// An isolated store with one owned account, a live `.claude.json`, and the
/// session directory `env` creates: the directory, the D-019 `mcp.json`
/// symlink, and a seed carrying only the floor key, because the live file
/// here has no tier-1 entries and none of the seed keys.
fn store_with_session() -> Fixture {
    let fixture = Fixture::new();
    fixture.write_registry(vec![fixture.owned_record(ACCT, ORG)]);
    fs::write(fixture.home().join(".claude.json"), json!({"mcpServers": {}}).to_string())
        .expect("the live `.claude.json` fixture should be writable");
    fixture.cmd().args(["claude", "env", ACCT]).assert().success();
    fixture
}

#[test]
fn ac58_the_isolation_section_reports_a_minimal_session() {
    let fixture = store_with_session();

    let output =
        fixture.cmd().args(["claude", "doctor"]).output().expect("`claude doctor` should run");
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("isolation"), "{stdout}");
    assert!(stdout.contains(&format!("id={ACCT}")), "{stdout}");
    assert!(stdout.contains("sha8_match=true"), "{stdout}");
    assert!(stdout.contains("mcp.json"), "{stdout}");
    assert!(stdout.contains("linked"), "the D-019 symlink S15 placed is reported:\n{stdout}");
    assert!(
        stdout.contains("hasCompletedOnboarding"),
        "the seed carries only the floor key when the live file has none:\n{stdout}"
    );
    assert!(stdout.contains("leaked keys      none"), "{stdout}");
    assert!(stdout.contains("agctl claude use --forget"), "{stdout}");
    assert!(stdout.contains("policySettings.disableSideloadFlags"), "{stdout}");
    assert!(stdout.contains("secure-storage backend"), "{stdout}");
}

#[test]
fn ac58_the_isolation_section_flags_a_hand_seeded_leak_and_an_occupied_path() {
    let fixture = store_with_session();
    let session_dir = fixture.session_dir(ACCT, ORG);

    // Hand-build a partially seeded state: one tier1 symlink placed
    // correctly, one occupied by something agctl did not put there, and a
    // seed file carrying a key that must never be seeded (plan AC54's leak
    // vocabulary, also `doctor`'s).
    let live_settings = fixture.home().join(".claude").join("settings.json");
    fs::create_dir_all(live_settings.parent().expect("the live settings path has a parent"))
        .expect("the live config dir should be creatable");
    fs::write(&live_settings, "{}").expect("the live settings file should be writable");
    symlink(&live_settings, session_dir.join("settings.json"))
        .expect("the tier1 symlink should be creatable");
    fs::write(session_dir.join("CLAUDE.md"), "not agctl's")
        .expect("the occupying file should be writable");

    fs::write(
        session_dir.join(".claude.json"),
        json!({"theme": "dark", "oauthAccount": {"uuid": "leaked"}}).to_string(),
    )
    .expect("the seed fixture should be writable");

    let output =
        fixture.cmd().args(["claude", "doctor"]).output().expect("`claude doctor` should run");
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("settings.json"), "{stdout}");
    assert!(stdout.contains("occupied"), "CLAUDE.md is not agctl's symlink:\n{stdout}");
    assert!(stdout.contains("oauthAccount"), "the leaked key is named:\n{stdout}");
    assert!(stdout.contains("leaked keys"), "{stdout}");
    assert!(
        !stdout.contains("\"leaked\""),
        "no leaked value is printed, only the key name:\n{stdout}"
    );
}

#[test]
fn ac58_the_isolation_section_reports_both_exports_the_unexposed_entries_the_mcp_count_and_the_drift()
 {
    // The five fields of AC58's row that `ac58_the_isolation_section_reports_a_minimal_session`
    // leaves alone: both exports by value, every live-config entry on neither
    // allowlist, the MCP credential count, the live-file drift, and the
    // migration state. They are the fields a reader acts on — "which
    // directories is this session actually pointed at", "what is *not*
    // exposed to it", "how many of my MCP servers carry a secret the linked
    // file hands over" — and until now `doctor` could have rendered any of
    // them wrong, or stopped rendering them at all, with the suite green.
    //
    // The live store is furnished so each field has a non-trivial answer: a
    // tier-1 file and a tier-2 directory that must NOT be called unexposed, a
    // `history.jsonl` that must not either (it is never linked by design),
    // and two genuine tier-3 entries that must be.
    let fixture = Fixture::new();
    fixture.write_registry(vec![fixture.owned_record(ACCT, ORG)]);

    let live_dir = fixture.home().join(".claude");
    fs::create_dir_all(live_dir.join("projects")).expect("the tier-2 directory is creatable");
    fs::write(live_dir.join("settings.json"), "{}").expect("the tier-1 file is writable");
    fs::write(live_dir.join("history.jsonl"), "").expect("the never-linked file is writable");
    fs::create_dir_all(live_dir.join("statsig")).expect("a tier-3 directory is creatable");
    fs::write(live_dir.join("todos.json"), "[]").expect("a tier-3 file is writable");

    // Three MCP servers, two of which carry credential material: one through
    // `env`, one through `headers`. The third has an empty `env`, which is
    // what makes the count a count rather than a server tally.
    fs::write(
        fixture.home().join(".claude.json"),
        json!({
            "hasCompletedOnboarding": true,
            "mcpServers": {
                "with-env": { "command": "a", "env": { "TOKEN": "secret-one" } },
                "with-headers": { "type": "http", "headers": { "Authorization": "secret-two" } },
                "plain": { "command": "b", "env": {} },
            },
        })
        .to_string(),
    )
    .expect("the live `.claude.json` fixture should be writable");

    fixture.cmd().args(["claude", "env", ACCT]).assert().success();

    // The live file moves after the seed was taken, which is the whole point
    // of the drift row: the session is running against a snapshot that no
    // longer matches what a new session would get.
    std::thread::sleep(std::time::Duration::from_millis(50));
    let live_json = fixture.home().join(".claude.json");
    let text = fs::read_to_string(&live_json).expect("readable");
    fs::write(&live_json, text).expect("the live file is rewritable");

    let output =
        fixture.cmd().args(["claude", "doctor"]).output().expect("`claude doctor` should run");
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Both exports, by value: these are the two variables a user would paste
    // into a shell, and a report naming the wrong directory for either is
    // worse than one naming neither.
    assert!(
        stdout.contains(&format!(
            "CLAUDE_SECURESTORAGE_CONFIG_DIR={} CLAUDE_CONFIG_DIR={}",
            common::export_spelling(&fixture.ns_dir(ACCT, ORG)),
            fixture.session_dir(ACCT, ORG).display()
        )),
        "both exports, in one row, by value:\n{stdout}"
    );
    assert!(stdout.contains("migrated=false"), "no keychain item exists for it:\n{stdout}");

    // Tier 3, and only tier 3.
    let unexposed = stdout
        .lines()
        .find_map(|line| line.trim_start().strip_prefix("unexposed"))
        .map(|rest| rest.trim().to_owned())
        .unwrap_or_else(|| panic!("the report has an `unexposed` row:\n{stdout}"));
    assert_eq!(
        unexposed, "statsig, todos.json",
        "exactly the entries on neither allowlist, sorted; `settings.json` and `projects` are \
         exposed and `history.jsonl` is never linked by design, so none of the three belongs \
         here:\n{stdout}"
    );

    assert!(
        stdout.contains("credential_entries=2"),
        "two of the three servers carry an `env` or `headers` the linked file hands over; the \
         empty one does not:\n{stdout}"
    );
    assert!(
        !stdout.contains("secret-one") && !stdout.contains("secret-two"),
        "and the count is all that is printed — never a key name or a value:\n{stdout}"
    );
    assert!(
        stdout.contains("changed_since_seed=true"),
        "the live file was rewritten after the seed was taken:\n{stdout}"
    );
}

#[test]
fn ac58_the_isolation_section_says_the_root_is_empty_with_no_sessions() {
    let fixture = Fixture::new();

    let output =
        fixture.cmd().args(["claude", "doctor"]).output().expect("`claude doctor` should run");
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("has no isolated sessions"), "{stdout}");
}

/// The audit log's own row in the store block: `doctor` names a mode `append`
/// refuses, and repairs nothing (`agctl-9je`).
///
/// The log lives in the same directory as the held-lock records, so the
/// attacker who could plant one name could plant the other — and this file is
/// the only durable evidence a broken lock leaves. A wrong mode is therefore a
/// state to report, not one to quietly fix: a `chmod` here would erase the
/// evidence that somebody else can read this machine's swap history.
#[test]
fn the_store_block_names_an_audit_log_agctl_refuses_and_leaves_its_mode_alone() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new();
    fixture.write_registry(vec![fixture.owned_record(ACCT, ORG)]);
    let log = fixture.audit_log_path();
    fs::create_dir_all(log.parent().expect("the log path has a parent"))
        .expect("the namespace root should be creatable");
    fs::write(&log, "").expect("the log fixture should be writable");
    fs::set_permissions(&log, fs::Permissions::from_mode(0o644))
        .expect("the mode should be settable");

    let output =
        fixture.cmd().args(["claude", "doctor"]).output().expect("`claude doctor` should run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("audit log"), "{stdout}");
    assert!(stdout.contains(&log.display().to_string()), "the row names the file:\n{stdout}");
    assert!(
        stdout.contains("its mode is 0644 and not 0600"),
        "the row names the mode it found:\n{stdout}"
    );
    assert!(stdout.contains("will not change it"), "and says it will not repair it:\n{stdout}");

    let mode = fs::symlink_metadata(&log).expect("stat-able").permissions().mode() & 0o7777;
    assert_eq!(mode, 0o644, "reported, never repaired");

    // The same row tracks the fix: nothing else about the store changed.
    fs::set_permissions(&log, fs::Permissions::from_mode(0o600)).expect("the mode is settable");
    let second =
        fixture.cmd().args(["claude", "doctor"]).output().expect("`claude doctor` should run");
    let stdout = String::from_utf8_lossy(&second.stdout);
    assert!(stdout.contains("audit log"), "{stdout}");
    assert!(!stdout.contains("its mode is"), "a 0600 log is reported as present:\n{stdout}");
}

/// The `store` block of a `doctor` report: its header to the blank line after.
fn store_block(stdout: &str) -> String {
    stdout
        .lines()
        .skip_while(|line| *line != "store")
        .take_while(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Whether `text` holds anything shaped like a UUID (8-4-4-4-12 hex digits).
fn has_uuid_shape(text: &str) -> bool {
    let groups = [8_usize, 4, 4, 4, 12];
    let span = groups.iter().sum::<usize>() + groups.len() - 1;
    text.as_bytes().windows(span).any(|window| {
        let mut at = 0;
        groups.iter().enumerate().all(|(index, len)| {
            let hex = window[at..at + len].iter().all(u8::is_ascii_hexdigit);
            at += len;
            let dash = index + 1 == groups.len() || window.get(at) == Some(&b'-');
            at += 1;
            hex && dash
        })
    })
}

#[test]
fn the_store_block_names_the_config_path_its_lock_and_whether_the_file_agrees() {
    // Rulings G14, Q6 and R-G: one row after `audit log` naming the live
    // configuration file and its lock by their literal paths, and what the newest
    // config step did — against today's file, in words only.
    const OTHER_ACCT: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    const OTHER_ORG: &str = "ffffffff-0000-1111-2222-333333333333";
    let write = json!({
        "ts": "2026-09-11T00:00:01Z",
        "monotonic_ms": 1,
        "agctl_pid": 1,
        "event": "write",
        "target": "live",
        "from_digest8": "0a0b0c0d",
        "to_digest8": "1a1b1c1d",
        "outcome": "applied",
        "direction": "forward",
        "incoming_identity": { "account_uuid": ACCT, "organization_uuid": ORG },
    });
    let config_write = json!({
        "ts": "2026-09-11T00:00:02Z",
        "monotonic_ms": 2,
        "agctl_pid": 1,
        "event": "config_write",
        "after": "2026-09-11T00:00:01Z#1",
        "outcome": "applied",
        "reason": null,
        "account": { "account_uuid": ACCT, "organization_uuid": ORG },
        "from_sha8": "0123abcd",
        "to_sha8": "89abcdef",
        "backup": ".claude.json.backup.1789000000000",
        "hold_ms": 4,
    });
    // (arm, the log, whom the file names, the verdict)
    type Arm<'a> = (&'a str, bool, Option<(&'a str, &'a str)>, &'a str);
    let arms: [Arm<'_>; 3] = [
        ("no log", false, None, "no config write recorded"),
        (
            "the file names the recorded account",
            true,
            Some((ACCT, ORG)),
            "last config write applied at 2026-09-11T00:00:02Z#1 after 2026-09-11T00:00:01Z#1; \
             its account agrees with the file",
        ),
        (
            "the file names another account",
            true,
            Some((OTHER_ACCT, OTHER_ORG)),
            "last config write applied at 2026-09-11T00:00:02Z#1 after 2026-09-11T00:00:01Z#1; \
             its account differs from the file",
        ),
    ];
    for (arm, logged, names, verdict) in arms {
        let fixture = Fixture::new();
        fixture.write_registry(vec![fixture.owned_record(ACCT, ORG)]);
        if logged {
            fixture.plant_audit_lines(&[write.clone(), config_write.clone()]);
        }
        if let Some((acct, org)) = names {
            fixture.live_through_link();
            fixture.live_claude_json_js(&common::live_config_document_naming(acct, org));
        }

        let output =
            fixture.cmd().args(["claude", "doctor"]).output().expect("`claude doctor` should run");
        assert!(output.status.success(), "{arm}: {}", String::from_utf8_lossy(&output.stderr));
        let stdout = String::from_utf8_lossy(&output.stdout);
        let block = store_block(&stdout);
        let home = fixture.home();
        let row = format!(
            "  claude config    {} (lock {}); {verdict}",
            home.join(".claude.json").display(),
            home.join(".claude.json.lock").display()
        );
        assert!(block.lines().any(|line| line == row), "{arm}: the row `{row}` in:\n{block}");
        let lines: Vec<&str> = block.lines().collect();
        let audit_at = lines.iter().position(|l| l.starts_with("  audit log")).expect("audit log");
        assert_eq!(
            lines.get(audit_at + 1),
            Some(&row.as_str()),
            "{arm}: directly after `audit log`"
        );
        assert_eq!(block.matches('@').count(), 0, "{arm}: no email in the store block:\n{block}");
        assert!(
            !has_uuid_shape(&block),
            "{arm}: no uuid-shaped string in the store block:\n{block}"
        );
    }
}
