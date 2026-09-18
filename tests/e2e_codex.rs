#![cfg(feature = "testing")]

//! The Codex surface, driven through the real binary.
//!
//! Two claims live here, and the first is the one phase 3 is judged on.
//!
//! **Claude commands are blind to Codex rows** (plan AC112, invariant I28).
//! Every `agctl claude …` output is compared byte for byte between a registry
//! that holds two Codex accounts and one that holds none — including the case
//! where a Codex account carries the *same email address* as the Claude one,
//! which is where a resolver that looked in both lists would turn an
//! unambiguous selector into an ambiguous one.
//!
//! **The `agctl codex` skeleton refuses without doing anything** (plan §3.2).
//! Every subcommand parses, exits non-zero, names itself, and leaves the
//! store exactly as it found it — no `codex/` tree, no network.

mod common;

#[path = "common/codex.rs"]
mod codex;

use std::fs;
use std::path::Path;

use codex::CODEX_HOME_ENV;
use codex::CodexFixture;
use common::ACCT;
use common::EMAIL;
use common::Fixture;
use common::OLD_BLOB;
use common::ORG;
use predicates::str::contains;
use serde_json::Value;
use serde_json::json;

// ---------------------------------------------------------------------------
// AC112: a Claude command cannot see a Codex row
// ---------------------------------------------------------------------------

/// The `agctl claude …` lines AC112 compares.
///
/// `accounts show <shared-email>` is the important one: the Codex row added
/// below carries the same address, so a resolver that searched both lists
/// would answer "matches 2 accounts" and change this output.
const CLAUDE_LINES: [&[&str]; 6] = [
    &["claude", "status", "--json"],
    &["claude", "status"],
    &["claude", "accounts", "list", "--all"],
    &["claude", "accounts", "show", EMAIL],
    &["claude", "doctor"],
    &["claude", "use", "--undo", "--json"],
];

/// A Codex record, in the shape `config::codex` deserializes.
fn codex_record(user: &str, acct: &str, email: &str, kind: Value) -> Value {
    json!({
        "chatgpt_user_id": user,
        "chatgpt_account_id": acct,
        "email": email,
        "plan_type": "plus",
        "label": null,
        "kind": kind,
        "forgotten": false,
        "created_at": "2026-09-17T00:00:00Z",
    })
}

/// What one `agctl` run produced: status, stdout and stderr, normalised.
fn run(fixture: &Fixture, args: &[&str]) -> String {
    let output = fixture.cmd().args(args).output().expect("the binary should run");
    format!(
        "exit: {:?}\n--- stdout\n{}\n--- stderr\n{}",
        output.status.code(),
        normalise(&String::from_utf8_lossy(&output.stdout)),
        normalise(&String::from_utf8_lossy(&output.stderr))
    )
}

/// Replaces the two things that differ between any two runs of the same
/// command, whatever the registry holds, and leaves every other byte.
///
/// Both are facts about *this run* rather than about the accounts: when the
/// report was built, and which process last took the namespace lock and when.
/// They are matched narrowly — a `"generated_at":` line, and the tail of a
/// line from `pid <digits>` on — rather than by a pattern over timestamps in
/// general, because a normaliser that erased every timestamp could erase a
/// Codex row's `created_at` leaking into a Claude document, which is one of
/// the things this test is looking for.
fn normalise(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        if line.trim_start().starts_with("\"generated_at\":") {
            out.push_str("  \"generated_at\": <per-run>");
        } else if let Some(at) = pid_at(line) {
            out.push_str(&line[..at]);
            out.push_str("<per-run>");
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

/// Where `pid <digits>` starts in a line, when it does.
fn pid_at(line: &str) -> Option<usize> {
    line.match_indices("pid ").find_map(|(at, _)| {
        let rest = line.get(at + "pid ".len()..)?;
        rest.starts_with(|c: char| c.is_ascii_digit()).then_some(at)
    })
}

/// A store with one owned Claude account and its credential.
fn claude_store() -> Fixture {
    let fixture = Fixture::new();
    fixture.write_registry(vec![fixture.owned_record(ACCT, ORG)]);
    fixture.write_credentials(ACCT, ORG, OLD_BLOB);
    fixture
}

#[test]
fn ac112_claude_output_is_byte_identical_with_codex_rows_present() {
    // One store, three passes: without the Codex rows, with them, and without
    // them again. Two stores would have differed in their temporary paths and
    // forced a normaliser broad enough to hide the difference this is looking
    // for; the third pass is what says the store itself did not drift under
    // the first two.
    let fixture = claude_store();
    let claude_only = json!({
        "version": 1,
        "accounts": [fixture.owned_record(ACCT, ORG)],
        "forgotten_services": [],
    });
    // Version 2, two Codex rows, one of them carrying the Claude account's
    // own email address — where a resolver that searched both lists would
    // turn an unambiguous selector into an ambiguous one.
    let with_codex = json!({
        "version": 2,
        "accounts": [fixture.owned_record(ACCT, ORG)],
        "forgotten_services": [],
        "codex_accounts": [
            codex_record("user-01", "acct-01", EMAIL, json!({ "kind": "live" })),
            codex_record(
                "user-02",
                "acct-02",
                "second@example.com",
                json!({
                    "kind": "owned",
                    "export_spelling": "/store/codex/user-02/acct-02",
                    "refresh": "auto",
                }),
            ),
        ],
    });

    fixture.write_registry_document(&claude_only);
    let before: Vec<String> = CLAUDE_LINES.iter().map(|args| run(&fixture, args)).collect();

    fixture.write_registry_document(&with_codex);
    let during: Vec<String> = CLAUDE_LINES.iter().map(|args| run(&fixture, args)).collect();

    fixture.write_registry_document(&claude_only);
    let after: Vec<String> = CLAUDE_LINES.iter().map(|args| run(&fixture, args)).collect();

    for (index, args) in CLAUDE_LINES.iter().enumerate() {
        assert_eq!(
            before[index],
            after[index],
            "`agctl {}` is not stable across runs, so this test cannot say anything about the \
             Codex rows",
            args.join(" ")
        );
        assert_eq!(
            during[index],
            before[index],
            "`agctl {}` changed when Codex rows were added to the registry",
            args.join(" ")
        );
    }

    // And the rows really were there for the middle pass: no Claude command
    // rewrote them away.
    fixture.write_registry_document(&with_codex);
    run(&fixture, &["claude", "status", "--json"]);
    let document: Value = serde_json::from_slice(
        &fs::read(fixture.config_file()).expect("the registry should be readable"),
    )
    .expect("the registry is JSON");
    assert_eq!(document["version"], json!(2));
    assert_eq!(document["codex_accounts"].as_array().map(Vec::len), Some(2));
}

#[test]
fn ac112_a_claude_command_does_not_resolve_a_codex_account() {
    // The other direction of the same claim: the shared email resolves to the
    // Claude row, and an id only the Codex list holds resolves to nothing.
    let fixture = claude_store();
    fixture.write_registry_document(&json!({
        "version": 2,
        "accounts": [fixture.owned_record(ACCT, ORG)],
        "forgotten_services": [],
        "codex_accounts": [codex_record("user-01", "acct-01", EMAIL, json!({ "kind": "live" }))],
    }));

    fixture
        .cmd()
        .args(["claude", "accounts", "show", EMAIL])
        .assert()
        .success()
        .stdout(contains(ACCT));

    fixture
        .cmd()
        .args(["claude", "accounts", "show", "user-01"])
        .assert()
        .failure()
        .stderr(contains("no account matches `user-01`"));
}

// ---------------------------------------------------------------------------
// The skeleton
// ---------------------------------------------------------------------------

/// Whether a `codex/` tree exists under a store.
fn codex_tree(config_dir: &Path) -> bool {
    config_dir.join("codex").exists()
}

#[test]
fn every_codex_subcommand_refuses_without_touching_the_store() {
    let fixture = CodexFixture::new();
    // `status` and `watch` landed at S33 (`tests/e2e_codex_status.rs`); the
    // rest are still stubs.
    let lines: [(&[&str], &str); 5] = [
        (&["codex", "login"], "agctl codex login"),
        (&["codex", "import", "--from", "codex-home"], "agctl codex import"),
        (&["codex", "doctor"], "agctl codex doctor"),
        (&["codex", "accounts", "list"], "agctl codex accounts list"),
        (&["codex", "accounts", "refresh", "x", "--reset-floor"], "agctl codex accounts refresh"),
    ];

    for (args, named) in lines {
        fixture
            .cmd()
            .args(args)
            .assert()
            .failure()
            .stderr(contains("not implemented"))
            .stderr(contains(named));
    }

    assert!(
        !codex_tree(&fixture.inner().config_dir()),
        "a stub created a `codex/` tree; no stub may touch a file"
    );
    assert!(
        !fixture.codex_log_path().exists(),
        "a stub spawned the fake `codex`; no stub may spawn a child"
    );
}

#[test]
fn the_codex_flags_parse_before_the_commands_exist() {
    // A refusal from the command, not from the parser: every flag plan §3.2
    // names is accepted today, so completions and `--help` describe the real
    // surface rather than half of it. (`status`'s flags are exercised by the
    // command itself in `tests/e2e_codex_status.rs`.)
    let fixture = CodexFixture::new();

    fixture
        .cmd()
        .args(["codex", "accounts", "set", "x", "--refresh", "never"])
        .assert()
        .failure()
        .stderr(contains("not implemented"));

    // And a flag it does not name is still a usage error.
    fixture.cmd().args(["codex", "status", "--by-identity"]).assert().code(2);
}

// ---------------------------------------------------------------------------
// I25: the harness itself (plan AC109)
// ---------------------------------------------------------------------------

#[test]
fn ac109_the_fixture_closes_every_route_to_a_real_codex_home() {
    let fixture = CodexFixture::new();

    // `cmd()` asserts both halves on every call; this states them as the
    // test's own claim so a change to the harness fails here rather than
    // silently stopping to check.
    let command = fixture.cmd();
    let mut removed = false;
    let mut home = None;
    for (key, value) in command.get_envs() {
        if key == CODEX_HOME_ENV {
            assert!(value.is_none(), "the Codex home variable is set for a spawned command");
            removed = true;
        }
        if key == "HOME" {
            home = value.map(std::path::PathBuf::from);
        }
    }
    assert!(removed, "the Codex home variable must be removed, not merely unset in this shell");
    assert_eq!(home.as_deref(), Some(fixture.inner().home().as_path()));

    // The fake `codex` is the copy the fixture wrote, inside the fixture.
    assert!(fixture.codex_bin().starts_with(fixture.root()));
    fixture.assert_no_real_codex_home();
}

#[test]
#[should_panic(expected = "must not set")]
fn ac109_a_test_that_sets_the_codex_home_variable_panics_in_the_harness() {
    let mut fixture = CodexFixture::new();
    fixture.set(CODEX_HOME_ENV, "/somewhere/real");
}
