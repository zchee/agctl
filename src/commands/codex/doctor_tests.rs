//! `agctl codex doctor`, in process, over temporary stores.
//!
//! Every Codex home here is a directory the test made under its own temporary
//! tree, and every keychain answer comes from [`FakeReader`]: nothing reads a
//! real home, a real keychain or a real process (invariant I25).
//!
//! The claims these tests carry that the e2e cannot: that a report built over
//! a store leaves no directory behind, and that a document, a configuration
//! file or a listing carrying a needle produces a report that does not.

use std::fs;
use std::os::unix::fs::PermissionsExt;

use serde_json::Value;
use serde_json::json;

use super::*;
use crate::provider::codex::testkit;
use crate::secret::fake_reader::FakeReader;

/// A store whose Codex tree has **not** been created, so a test can prove that
/// running `doctor` does not create one.
fn bare_store() -> (tempfile::TempDir, Paths) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let paths = Paths::with_config_dir(dir.path().join("agctl"));
    (dir, paths)
}

/// A Codex home under `root`, with `config.toml` and `auth.json` when given.
fn home_with(root: &Path, config: Option<&str>, doc: Option<&Value>) -> PathBuf {
    let home = root.join("codex-home");
    fs::create_dir_all(&home).expect("a home");
    if let Some(config) = config {
        fs::write(home.join("config.toml"), config).expect("a config");
    }
    if let Some(doc) = doc {
        testkit::write_0600(&home.join("auth.json"), &testkit::pretty(doc));
    }
    home
}

/// An environment view naming `home` and no Codex variables.
fn env_for(home: &Path) -> EnvView {
    EnvView { codex: home::CodexEnv::new(Some(home.as_os_str().to_owned()), None), set: Vec::new() }
}

/// The report as a document, for the needle sweeps.
fn document(report: &CodexDoctorReport) -> String {
    serde_json::to_string(report).expect("a report serializes")
}

#[test]
fn a_report_creates_nothing_under_the_store() {
    // The C3 carry (ledger #469): `doctor` inspects namespaces without going
    // through `OwnedNamespace::open`, which creates the directory it opens. A
    // store that has never seen `agctl codex login` must look the same after a
    // diagnosis as before it.
    let (dir, paths) = bare_store();
    let home = home_with(dir.path(), None, Some(&testkit::chatgpt_doc(None, None)));
    let record = testkit::owned_record(testkit::USER, testkit::ACCT);

    let report = build(
        &paths,
        std::slice::from_ref(&record),
        &env_for(&home),
        &Listings::default(),
        &Cancel::new(),
    )
    .expect("a report over a store that does not exist yet");

    assert!(!paths.codex_root().exists(), "doctor created {}", paths.codex_root().display());
    let namespace = paths.codex_namespace_dir(testkit::USER, testkit::ACCT).expect("valid ids");
    assert!(!namespace.exists(), "doctor created {}", namespace.display());
    assert_eq!(report.namespaces.len(), 1, "the record is still reported");
    assert!(!report.namespaces[0].credentials_present);
    assert_eq!(report.namespaces[0].marker.state, "absent");
}

#[test]
fn an_unparseable_config_is_reported_by_its_line_number_only() {
    // Plan AC116 at the report boundary: the offending line carries a key, and
    // the parser's own message quotes it, so only the number may be rendered
    // (invariant I31).
    let (dir, paths) = bare_store();
    let config = format!("store = \"file\"\nthis is not toml = {}\n", testkit::AK_SENTINEL);
    let home = home_with(dir.path(), Some(&config), None);

    let report = build(&paths, &[], &env_for(&home), &Listings::default(), &Cancel::new())
        .expect("a report");

    let note = report.store.config_note.as_deref().expect("a note");
    assert!(note.starts_with("unparseable config.toml (line "), "{note}");
    testkit::assert_no_needles(&document(&report), "the report");
    testkit::assert_no_needles(&crate::render::codex_doctor::render(&report), "the table");
}

#[test]
fn a_store_mode_this_build_does_not_know_is_reported_as_unknown() {
    // The spelling came out of `config.toml`; rendering it back would echo
    // whatever was written there.
    let (dir, paths) = bare_store();
    let config = format!("cli_auth_credentials_store = \"{}\"\n", testkit::AK_SENTINEL);
    let home = home_with(dir.path(), Some(&config), None);

    let report = build(&paths, &[], &env_for(&home), &Listings::default(), &Cancel::new())
        .expect("a report");

    assert_eq!(report.store.mode, "unknown", "the mode word never comes from the file");
    testkit::assert_no_needles(&document(&report), "the report");
}

#[test]
fn auto_reads_the_file_only_when_no_item_is_listed() {
    // Plan AC95's `auto` rows, through a listing rather than a stub answer.
    let (dir, paths) = bare_store();
    let home = home_with(
        dir.path(),
        Some("cli_auth_credentials_store = \"auto\"\n"),
        Some(&testkit::chatgpt_doc(None, None)),
    );
    let account = home::keyring_account(&home);

    let listed = Listings::from_reader(
        &FakeReader::unlocked().with_entry_for(home::KEYRING_SERVICE, Some(&account)),
    );
    let report = build(&paths, &[], &env_for(&home), &listed, &Cancel::new()).expect("a report");
    assert_eq!(report.store.read, "not read");
    assert_eq!(report.live.state, "not read");
    assert!(!report.store.coarse_match);

    let empty = Listings::from_reader(&FakeReader::unlocked());
    let report = build(&paths, &[], &env_for(&home), &empty, &Cancel::new()).expect("a report");
    assert_eq!(report.store.read, "auto (file in effect)");
    assert_eq!(report.live.state, "credentials");
}

#[test]
fn a_listing_without_an_account_column_is_a_coarse_match() {
    let (dir, paths) = bare_store();
    let home = home_with(dir.path(), Some("cli_auth_credentials_store = \"auto\"\n"), None);
    let listings =
        Listings::from_reader(&FakeReader::unlocked().with_entry_for(home::KEYRING_SERVICE, None));

    let report = build(&paths, &[], &env_for(&home), &listings, &Cancel::new()).expect("a report");

    assert!(report.store.coarse_match, "a listing with no account column matches by service");
    assert_eq!(report.store.read, "not read");
}

#[test]
fn the_field_set_comparison_names_what_is_missing_and_counts_the_rest() {
    // Premortem PM22, under the lead's ruling of 2026-09-22: the names come
    // from this crate's own list, and a member the file added is a count —
    // here the key itself is a needle.
    let (dir, paths) = bare_store();
    let mut doc = testkit::chatgpt_doc(None, None);
    doc.as_object_mut().expect("an object").insert(testkit::AK_SENTINEL.to_owned(), json!("value"));
    let home = home_with(dir.path(), None, Some(&doc));

    let report = build(&paths, &[], &env_for(&home), &Listings::default(), &Cancel::new())
        .expect("a report");

    assert_eq!(report.live.unknown_member_count, 1);
    assert!(
        report.live.missing_known_members.contains(&"bedrock_api_key"),
        "{:?}",
        report.live.missing_known_members
    );
    testkit::assert_no_needles(&document(&report), "the report");
    testkit::assert_no_needles(&crate::render::codex_doctor::render(&report), "the table");
}

#[test]
fn a_credential_file_that_is_not_0600_warns_and_carries_its_size() {
    let (dir, paths) = bare_store();
    let home = home_with(dir.path(), None, Some(&testkit::chatgpt_doc(None, None)));
    fs::set_permissions(home.join("auth.json"), fs::Permissions::from_mode(0o644)).expect("chmod");

    let report = build(&paths, &[], &env_for(&home), &Listings::default(), &Cancel::new())
        .expect("a report");

    assert_eq!(report.live.mode_bits.as_deref(), Some("0644"));
    assert!(report.live.mode_warning.is_some(), "mode 0644 must warn");
    assert!(report.live.size.is_some_and(|size| size > 0));
}

#[test]
fn a_namespace_entry_is_classified_and_never_named() {
    // Plan AC108's `codex session artefacts present`, and the stray temporary
    // file `--resend` is refused over. The entry names are file system content
    // and are counted, not printed.
    let (_dir, paths) = bare_store();
    let namespace = paths.codex_namespace_dir(testkit::USER, testkit::ACCT).expect("valid ids");
    fs::create_dir_all(&namespace).expect("a namespace");
    testkit::write_0600(
        &namespace.join("auth.json"),
        &testkit::pretty(&testkit::chatgpt_doc(None, None)),
    );
    fs::write(namespace.join(format!("sessions-{}", testkit::AK_SENTINEL)), "x").expect("an entry");
    fs::write(namespace.join("auth.json.tmp.0123abcd"), "x").expect("a stray tmp");

    let (artefacts, present) = artefacts(&namespace);

    assert!(present, "auth.json is there");
    assert!(
        artefacts.iter().any(|line| line.starts_with("codex session artefacts present")),
        "{artefacts:?}"
    );
    assert!(artefacts.iter().any(|line| line.starts_with("stray tmp")), "{artefacts:?}");
    testkit::assert_no_needles(&artefacts.join("\n"), "the artefact lines");
}

#[test]
fn a_marker_is_read_without_opening_the_namespace() {
    // The marker's reader is the one thing S35 widened (deviation D1). It must
    // read a marker whose namespace directory does not exist at all, and leave
    // it not existing.
    let (dir, paths) = bare_store();
    let marker = paths.codex_refresh_state_path(testkit::USER, testkit::ACCT).expect("valid ids");
    fs::create_dir_all(marker.parent().expect("a parent")).expect("the state dir");
    let since = jiff::Timestamp::now().as_second() - 7_200;
    let state = json!({
        "schema": 1,
        "inflight": { "sent_digest8": "0123abcd", "sent_at": ts(since) },
        "floor_min": 60,
        "did_not_help": 2,
        "ambiguous_since": ts(since),
        "class": "tls",
        "resent": false,
    });
    testkit::write_0600(&marker, &testkit::pretty(&state));

    let section = marker_section(&paths, testkit::USER, testkit::ACCT);

    assert_eq!(section.state, "present");
    assert_eq!(section.inflight_digest8.as_deref(), Some("0123abcd"));
    assert_eq!(section.class, Some("tls"));
    assert_eq!(section.floor_min, Some(60));
    assert_eq!(section.did_not_help, Some(2));
    assert_eq!(section.resent, Some(false));
    assert_eq!(section.resend_eligible, Some(true), "an hour has passed");
    let namespace = paths.codex_namespace_dir(testkit::USER, testkit::ACCT).expect("valid ids");
    assert!(!namespace.exists(), "reading a marker created {}", namespace.display());
    drop(dir);
}

/// An epoch second as the marker spells a time.
fn ts(seconds: i64) -> String {
    jiff::Timestamp::from_second(seconds).expect("a valid time").to_string()
}

#[test]
fn a_marker_that_cannot_be_read_is_reported_rather_than_returned() {
    let (dir, paths) = bare_store();
    let marker = paths.codex_refresh_state_path(testkit::USER, testkit::ACCT).expect("valid ids");
    fs::create_dir_all(marker.parent().expect("a parent")).expect("the state dir");
    fs::write(&marker, b"{not json").expect("a marker");

    let section = marker_section(&paths, testkit::USER, testkit::ACCT);

    assert_eq!(section.state, "unavailable");
    assert!(section.unavailable.is_some());
    drop(dir);
}

#[test]
fn the_environment_is_reported_by_presence_and_never_by_value() {
    let (dir, paths) = bare_store();
    let home = home_with(dir.path(), None, None);
    let env = EnvView { codex: env_for(&home).codex, set: vec!["CODEX_API_KEY"] };

    let report = build(&paths, &[], &env, &Listings::default(), &Cancel::new()).expect("a report");

    let api_key = report
        .environment
        .iter()
        .find(|var| var.name == "CODEX_API_KEY")
        .expect("the variable is listed");
    assert!(api_key.present);
    assert_eq!(report.environment.len(), REPORTED_ENV.len(), "all four are listed");
    let rendered = crate::render::codex_doctor::render(&report);
    assert!(rendered.contains("CODEX_API_KEY present"), "{rendered}");
}

#[test]
fn foreign_credentials_are_counted_and_never_named() {
    // Plan AC108: `multi-auth/` and a `codex-switcher:` item are both counted,
    // and neither is read or named.
    let (dir, paths) = bare_store();
    let home = home_with(dir.path(), None, None);
    fs::create_dir_all(home.join(MULTI_AUTH_DIR)).expect("a multi-auth dir");
    fs::write(home.join(MULTI_AUTH_DIR).join("auth.json"), testkit::RT_SENTINEL)
        .expect("a foreign credential");
    let listings = Listings::from_reader(
        &FakeReader::unlocked()
            .with_entry_for(SWITCHER_PREFIX, Some(testkit::AK_SENTINEL))
            .with_entry_for(home::KEYRING_SERVICE, Some(&home::keyring_account(&home))),
    );

    let report = build(&paths, &[], &env_for(&home), &listings, &Cancel::new()).expect("a report");

    assert!(report.foreign.multi_auth_present);
    assert_eq!(report.foreign.switcher_items, 1);
    assert_eq!(report.foreign.codex_auth_items, 1);
    assert!(report.foreign.unexplained_removals.is_empty(), "the item is this home's");
    testkit::assert_no_needles(&document(&report), "the report");
}

#[test]
fn an_account_agctl_did_not_write_is_counted_and_never_printed() {
    // Review S35 C1. An account is a keychain attribute, and any application
    // on this machine can set it to anything; `doctor` offers a removal
    // COMMAND, which a reader pastes into a shell. So a command is built only
    // from `cli|` + sixteen lowercase hex digits, and everything else is a
    // count — including a string that is a needle, one carrying shell
    // metacharacters, and one carrying an escape byte.
    let (dir, paths) = bare_store();
    let home = home_with(dir.path(), None, None);
    let hostile = [
        testkit::AK_SENTINEL,
        "cli|$(id > /tmp/agctl-owned)",
        "cli|`id`",
        "cli|\u{1b}]0;pwned\u{7}",
        "cli|\"; id; \"",
        "cli|00112233ABCDEFFF",
        "cli|00112233abcdef",
    ];
    let mut reader = FakeReader::unlocked();
    for account in hostile {
        reader = reader.with_entry_for(home::KEYRING_SERVICE, Some(account));
    }

    let report =
        build(&paths, &[], &env_for(&home), &Listings::from_reader(&reader), &Cancel::new())
            .expect("a report");

    assert!(
        report.foreign.unexplained_removals.is_empty(),
        "{:?}",
        report.foreign.unexplained_removals
    );
    assert_eq!(report.foreign.unnameable_items, hostile.len());
    assert_eq!(report.foreign.codex_auth_items, hostile.len());
    let rendered =
        format!("{}\n{}", document(&report), crate::render::codex_doctor::render(&report));
    for account in hostile {
        assert!(!rendered.contains(account), "the report carries an account agctl did not write");
    }
    testkit::assert_no_needles(&rendered, "the report");
}

#[test]
fn the_account_format_check_is_exact() {
    // The predicate the command is gated on, at its boundaries. An uppercase
    // digit, a short digest, a long one and an empty one are all refused: the
    // spelling agctl writes is lowercase and exactly sixteen (fact F94).
    assert!(is_home_account("cli|00112233abcdefff"));
    assert!(is_home_account("cli|0123456789abcdef"));
    assert!(!is_home_account("cli|00112233ABCDEFFF"));
    assert!(!is_home_account("cli|00112233abcdeff"));
    assert!(!is_home_account("cli|00112233abcdefff0"));
    assert!(!is_home_account("cli|"));
    assert!(!is_home_account("cli|00112233abcdefg0"));
    assert!(!is_home_account("00112233abcdefff"));
    assert!(!is_home_account(""));
}

#[test]
fn a_codex_auth_item_that_is_not_this_homes_gets_a_removal_command() {
    let (dir, paths) = bare_store();
    let home = home_with(dir.path(), None, None);
    let listings = Listings::from_reader(
        &FakeReader::unlocked().with_entry_for(home::KEYRING_SERVICE, Some("cli|00112233abcdefff")),
    );

    let report = build(&paths, &[], &env_for(&home), &listings, &Cancel::new()).expect("a report");

    assert_eq!(report.foreign.unexplained_removals.len(), 1);
    assert!(
        report.foreign.unexplained_removals[0].contains("delete-generic-password"),
        "{:?}",
        report.foreign.unexplained_removals
    );
    drop(dir);
}

#[test]
fn a_home_that_cannot_be_resolved_is_reported_rather_than_returned() {
    let (dir, paths) = bare_store();
    let missing = dir.path().join("there-is-no-home-here");
    let env = EnvView {
        codex: home::CodexEnv::new(Some(missing.as_os_str().to_owned()), None),
        set: Vec::new(),
    };

    let report = build(&paths, &[], &env, &Listings::default(), &Cancel::new()).expect("a report");

    assert!(report.home.path.is_none());
    assert!(report.home.error.is_some_and(|err| err.contains("codex home unreadable")));
    assert_eq!(report.live.state, "no home");
}

#[test]
fn a_symlinked_home_names_every_hop() {
    let (dir, paths) = bare_store();
    let real = home_with(dir.path(), None, None);
    let link = dir.path().join("linked-home");
    std::os::unix::fs::symlink(&real, &link).expect("a symlink");
    let env = EnvView {
        codex: home::CodexEnv::new(None, Some(dir.path().to_path_buf())),
        set: Vec::new(),
    };
    std::os::unix::fs::symlink(&real, dir.path().join(".codex")).expect("the fallback link");

    let report = build(&paths, &[], &env, &Listings::default(), &Cancel::new()).expect("a report");

    assert!(
        report.home.symlink_chain.iter().any(|hop| hop.contains(".codex -> ")),
        "{:?}",
        report.home.symlink_chain
    );
    drop(link);
}

#[test]
fn the_live_grant_is_folded_onto_the_owned_namespace_holding_it() {
    let (dir, paths) = bare_store();
    let doc = testkit::chatgpt_doc(None, None);
    let home = home_with(dir.path(), None, Some(&doc));
    let namespace = paths.codex_namespace_dir(testkit::USER, testkit::ACCT).expect("valid ids");
    testkit::write_0600(&namespace.join("auth.json"), &testkit::pretty(&doc));
    let record = testkit::owned_record(testkit::USER, testkit::ACCT);

    let report = build(
        &paths,
        std::slice::from_ref(&record),
        &env_for(&home),
        &Listings::default(),
        &Cancel::new(),
    )
    .expect("a report");

    assert_eq!(
        report.live.matches_namespace.as_deref(),
        Some(format!("{}+{}", testkit::USER, testkit::ACCT).as_str())
    );
}

#[test]
fn the_write_log_is_rendered_and_its_last_lines_kept() {
    let (dir, paths) = bare_store();
    let home = home_with(dir.path(), None, None);
    let log = paths.codex_root().join("writes.jsonl");
    fs::create_dir_all(paths.codex_root()).expect("the codex root");
    let lines: Vec<String> = (0..AUDIT_LINES + 3)
        .map(|index| format!("{{\"provider\":\"codex\",\"n\":{index}}}"))
        .collect();
    testkit::write_0600(&log, lines.join("\n").as_bytes());

    let report = build(&paths, &[], &env_for(&home), &Listings::default(), &Cancel::new())
        .expect("a report");

    assert_eq!(report.audit.len(), AUDIT_LINES, "only the last lines are kept");
    assert!(report.audit[AUDIT_LINES - 1].contains(&format!("\"n\":{}", AUDIT_LINES + 2)));
}

#[test]
fn the_report_validates_against_the_published_schema() {
    let (dir, paths) = bare_store();
    let home = home_with(
        dir.path(),
        Some(
            "cli_auth_credentials_store = \"auto\"\nchatgpt_base_url = \"https://example.invalid\"\n",
        ),
        Some(&testkit::chatgpt_doc(
            Some(jiff::Timestamp::now().as_second() + 600),
            Some("2026-09-20T00:00:00Z"),
        )),
    );
    let namespace = paths.codex_namespace_dir(testkit::USER, testkit::ACCT).expect("valid ids");
    fs::create_dir_all(&namespace).expect("a namespace");
    let record = testkit::owned_record(testkit::USER, testkit::ACCT);

    let report = build(
        &paths,
        std::slice::from_ref(&record),
        &env_for(&home),
        &Listings::from_reader(&FakeReader::unlocked()),
        &Cancel::new(),
    )
    .expect("a report");

    crate::render::codex_doctor::assert_valid(&report);
}
