//! Tests for the audit log.
//!
//! Three properties carry the weight: an entry survives the round trip
//! (otherwise `doctor` and `use --undo` have nothing to read), the file is
//! 0600 with one line per entry (otherwise two processes interleave), and
//! **no line can carry token material** — asserted on the raw bytes, not on
//! the typed value, because that is the form the risk (R34) is about.

use std::path::PathBuf;

use tempfile::TempDir;

use super::*;

/// A store in a temporary directory.
fn store() -> (TempDir, Paths) {
    let dir = TempDir::new().expect("a temporary directory");
    let paths = Paths::with_config_dir(dir.path().to_path_buf());
    (dir, paths)
}

fn write_event(to: &str, from: Option<&str>) -> AuditEvent {
    AuditEvent::Write {
        target: Target::Namespace("0123abcd".to_owned()),
        from_digest8: from.map(str::to_owned),
        to_digest8: to.to_owned(),
        outcome: WriteOutcome::Applied,
    }
}

fn sample(mtime_ns: i64, age_ms: u64) -> LockSample {
    LockSample { at: Timestamp::now(), mtime_ns, age_ms }
}

/// A break record with every member populated, so a shape assertion can see
/// the whole key set at once.
///
/// `outcome: broken` with `reason: retaken` is the one combination that
/// populates both: a lock that *was* removed and that a peer took back before
/// agctl could re-create it. Every other reason implies `abandoned`, and a
/// clean break carries no reason at all — which is what
/// [`a_clean_break_records_no_reason`] pins.
fn break_record() -> LockBreakRecord {
    LockBreakRecord {
        path: PathBuf::from("/home/example/.claude/.oauth_refresh.lock"),
        store_dir: PathBuf::from("/home/example/.claude"),
        tree: Tree::Live,
        service: "Claude Code-credentials".to_owned(),
        target: Target::Live,
        sample_a: sample(1_700_000_000_000_000_000, 61_000),
        sample_b: Some(sample(1_700_000_000_000_000_000, 73_000)),
        sample_c: Some(sample(1_700_000_000_000_000_000, 73_010)),
        interval_wall_ms: 12_000,
        interval_monotonic_ms: 12_004,
        holder_evidence: HolderEvidence::NoStoppedClaude,
        outcome: BreakOutcome::Broken,
        reason: Some(BreakReason::Retaken),
    }
}

#[test]
fn an_entry_round_trips_through_the_log() {
    let (_dir, paths) = store();
    let entry = AuditEntry::new(write_event("aabbccdd", Some("11223344")));

    let id = append(&paths, &entry).expect("the log should be appendable");
    assert_eq!(id, entry.id());
    assert_eq!(id.ts, entry.ts);
    assert_eq!(id.agctl_pid, std::process::id());

    let read = tail(&paths, 10).expect("the log should be readable");
    assert_eq!(read.entries, vec![entry]);
    assert!(read.unreadable.is_empty(), "nothing was damaged");
}

#[test]
fn a_break_record_round_trips_through_the_log() {
    let (_dir, paths) = store();
    let entry = AuditEntry::new(AuditEvent::LockBreak(break_record()));
    append(&paths, &entry).expect("the log should be appendable");
    assert_eq!(tail(&paths, 1).expect("readable").entries, vec![entry]);
}

#[test]
fn a_clean_break_records_no_reason() {
    // The other half of the `reason` cardinality, and the half the vocabulary
    // is built around: every word in `BreakReason` is a reason *not* to have
    // broken a lock, so a break with nothing to explain writes no `reason` key
    // rather than inventing a seventh word for success.
    let mut record = break_record();
    record.reason = None;
    let entry = AuditEntry::new(AuditEvent::LockBreak(record));
    let value: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&entry).expect("serializable"))
            .expect("valid JSON");
    let object = value.as_object().expect("an object");
    assert!(!object.contains_key("reason"), "{object:?}");
    assert_eq!(object["outcome"], "broken");
    assert_eq!(object.len(), 16, "one key fewer than the fully populated shape");

    let (_dir, paths) = store();
    append(&paths, &entry).expect("appendable");
    assert_eq!(tail(&paths, 1).expect("readable").entries, vec![entry], "and it round-trips");
}

#[test]
fn the_log_is_0600_with_one_line_per_entry() {
    use std::os::unix::fs::PermissionsExt;

    let (_dir, paths) = store();
    for digest in ["aaaaaaaa", "bbbbbbbb", "cccccccc"] {
        append(&paths, &AuditEntry::new(write_event(digest, None))).expect("appendable");
    }

    let path = log_path(&paths);
    let mode = std::fs::metadata(&path).expect("stat-able").permissions().mode() & 0o7777;
    assert_eq!(mode, 0o600, "the log holds a machine's swap history");

    let text = std::fs::read_to_string(&path).expect("readable");
    assert_eq!(text.lines().count(), 3);
    assert!(text.ends_with('\n'), "every entry is a whole line: {text:?}");
}

#[test]
fn tail_returns_the_last_entries_oldest_first() {
    let (_dir, paths) = store();
    for digest in ["aaaaaaaa", "bbbbbbbb", "cccccccc"] {
        append(&paths, &AuditEntry::new(write_event(digest, None))).expect("appendable");
    }

    let last_two = tail(&paths, 2).expect("readable");
    let digests: Vec<String> = last_two
        .entries
        .iter()
        .map(|entry| match &entry.event {
            AuditEvent::Write { to_digest8, .. } => to_digest8.clone(),
            AuditEvent::LockBreak(_) => panic!("these are writes"),
        })
        .collect();
    assert_eq!(digests, ["bbbbbbbb", "cccccccc"]);
    assert_eq!(
        tail(&paths, 99).expect("readable").entries.len(),
        3,
        "asking for more is not an error"
    );
}

#[test]
fn tail_of_an_absent_log_is_no_entries() {
    let (_dir, paths) = store();
    let read = tail(&paths, 5).expect("an absent log is not a failure");
    assert!(read.entries.is_empty());
    assert!(read.unreadable.is_empty());
}

#[test]
fn tail_names_the_line_it_cannot_read_and_returns_the_rest() {
    // Inverted from "a corrupt line is reported, not skipped", which enshrined
    // the opposite of the contract: one damaged line must not take `doctor`
    // down. The line number is still reported — the caller names it — but the
    // entries that *did* parse come back, because `doctor` explaining nothing
    // and `use --undo` refusing to run is the failure mode this log exists to
    // survive.
    let (_dir, paths) = store();
    append(&paths, &AuditEntry::new(write_event("aaaaaaaa", None))).expect("appendable");
    let path = log_path(&paths);
    let mut text = std::fs::read_to_string(&path).expect("readable");
    text.push_str("{\"ts\":\"not a timestamp\"}\n");
    rewrite_log(&path, &text);

    let read = tail(&paths, 5).expect("a corrupt line is skipped, not fatal");

    assert_eq!(read.entries.len(), 1, "the good entry is still returned");
    let AuditEvent::Write { to_digest8, .. } = &read.entries[0].event else { panic!("a write") };
    assert_eq!(to_digest8, "aaaaaaaa");
    assert_eq!(read.unreadable.len(), 1, "and the bad one is named: {:?}", read.unreadable);
    assert_eq!(read.unreadable[0].0, 2, "by line number");
    assert!(!read.unreadable[0].1.is_empty(), "with a reason");
}

#[test]
fn a_truncated_last_line_does_not_hide_the_entries_before_it() {
    // The crash this is really about, and the reason the fix is not cosmetic:
    // `append` is one `write` plus an `fsync`, so a process killed between them
    // — or a short write at `ENOSPC` — leaves the final line half-written. That
    // line is by construction inside the last `n`, so a `tail` that failed on it
    // would fail on **every** read after such a crash, which is exactly when
    // `doctor` and `use --undo` are needed.
    let (_dir, paths) = store();
    for digest in ["aaaaaaaa", "bbbbbbbb"] {
        append(&paths, &AuditEntry::new(write_event(digest, None))).expect("appendable");
    }
    let path = log_path(&paths);
    let whole = std::fs::read_to_string(&path).expect("readable");
    // Truncate mid-line: the last entry keeps its first ten bytes and nothing
    // else, which is what a killed `write` leaves behind.
    let mut lines: Vec<&str> = whole.lines().collect();
    let last = lines.pop().expect("two lines");
    let cut = last.get(..10).expect("a line longer than ten bytes");
    rewrite_log(&path, &format!("{}\n{cut}", lines.join("\n")));

    let read = tail(&paths, 5).expect("a truncated tail is not fatal");

    assert_eq!(read.entries.len(), 1, "the earlier entry survives");
    assert_eq!(read.unreadable.len(), 1, "and the truncated one is named");
    assert_eq!(read.unreadable[0].0, 2);
}

/// Replaces the log's contents, for the tests that damage it deliberately.
fn rewrite_log(path: &std::path::Path, text: &str) {
    std::fs::write(path, text).expect("the log should be writable");
}

#[test]
fn an_entry_with_members_this_build_does_not_know_still_reads() {
    // Principle P3: a log written by a later agctl must remain readable, so
    // an unknown member is ignored rather than fatal.
    let (_dir, paths) = store();
    append(&paths, &AuditEntry::new(write_event("aaaaaaaa", None))).expect("appendable");
    let path = log_path(&paths);
    let line = std::fs::read_to_string(&path).expect("readable");
    let widened = line.trim_end().replace('}', ",\"something_new\":true}");
    std::fs::write(&path, format!("{widened}\n")).expect("writable");

    let read = tail(&paths, 1).expect("an unknown member is not a failure");
    assert_eq!(read.entries.len(), 1);
    assert!(read.unreadable.is_empty(), "an unknown member is not damage either");
}

#[test]
fn no_line_carries_token_material() {
    // Asserted on the raw bytes rather than on the typed value, because the
    // file is the artefact risk R34 is about. The long-hex check is the
    // mechanical half: a digest is 64 hex digits and a hex-encoded blob is
    // thousands, so nothing that big may appear — while a nanosecond mtime,
    // the longest legitimate run at 19 digits, must still pass.
    let (_dir, paths) = store();
    append(&paths, &AuditEntry::new(write_event("aabbccdd", Some("11223344"))))
        .expect("appendable");
    append(&paths, &AuditEntry::new(AuditEvent::LockBreak(break_record()))).expect("appendable");

    let bytes = std::fs::read(log_path(&paths)).expect("readable");
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains("sk-ant-"), "{text}");
    assert!(!text.contains("claudeAiOauth"), "{text}");
    assert!(!text.contains("accessToken"), "{text}");
    let longest =
        text.split(|c: char| !c.is_ascii_hexdigit()).map(str::len).max().unwrap_or_default();
    assert!(longest <= 24, "a {longest}-digit hex run is too long to be a prefix: {text}");
}

#[test]
fn append_refuses_a_digest_that_is_not_a_prefix() {
    let (_dir, paths) = store();
    let whole = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";

    for event in [write_event(whole, None), write_event("aabbccdd", Some(whole))] {
        let refused = append(&paths, &AuditEntry::new(event))
            .expect_err("a whole digest is not a digest prefix");
        assert!(refused.to_string().contains("digest prefixes only"), "{refused}");
    }
    for event in [write_event("AABBCCDD", None), write_event("aabbccd", None)] {
        assert!(append(&paths, &AuditEntry::new(event)).is_err());
    }

    assert!(!log_path(&paths).exists(), "a refused entry creates no log");
}

#[test]
fn a_break_record_serialises_with_the_plans_field_names() {
    let entry = AuditEntry::new(AuditEvent::LockBreak(break_record()));
    let text = serde_json::to_string(&entry).expect("serializable");
    let value: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
    let object = value.as_object().expect("an object");

    let keys: Vec<&str> = object.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        [
            "ts",
            "monotonic_ms",
            "agctl_pid",
            "event",
            "path",
            "store_dir",
            "tree",
            "service",
            "target",
            "sample_a",
            "sample_b",
            "sample_c",
            "interval_wall_ms",
            "interval_monotonic_ms",
            "holder_evidence",
            "outcome",
            "reason",
        ],
        "plan section 3.8 fixes this shape, and `use --undo` and `doctor` read it"
    );
    assert_eq!(object["event"], "lock_break");
    assert_eq!(object["tree"], "live");
    assert_eq!(object["target"], "live");
    assert_eq!(object["holder_evidence"], "no_stopped_claude");
    assert_eq!(object["outcome"], "broken");
    assert_eq!(object["reason"], "retaken");
    let sample_a = object["sample_a"].as_object().expect("an object");
    let sample_keys: Vec<&str> = sample_a.keys().map(String::as_str).collect();
    assert_eq!(sample_keys, ["at", "mtime_ns", "age_ms"]);
}

#[test]
fn a_write_serialises_with_the_documented_field_names() {
    let entry = AuditEntry::new(write_event("aabbccdd", Some("11223344")));
    let value: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&entry).expect("serializable"))
            .expect("valid JSON");
    let keys: Vec<&str> =
        value.as_object().expect("an object").keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        [
            "ts",
            "monotonic_ms",
            "agctl_pid",
            "event",
            "target",
            "from_digest8",
            "to_digest8",
            "outcome"
        ]
    );
    assert_eq!(value["event"], "write");
    assert_eq!(value["target"], "namespace:0123abcd");
    assert_eq!(value["outcome"], "applied");
    assert_eq!(value["from_digest8"], "11223344");
}

#[test]
fn a_first_write_records_itself_as_one() {
    let (_dir, paths) = store();
    append(&paths, &AuditEntry::new(write_event("aabbccdd", None))).expect("appendable");
    let read = tail(&paths, 1).expect("readable");
    let AuditEvent::Write { from_digest8, .. } = &read.entries[0].event else {
        panic!("a write");
    };
    assert_eq!(*from_digest8, None, "no outgoing credential means the item was absent");
}

#[test]
fn the_vocabulary_serialises_to_the_documented_tokens() {
    // Plan AC80's clause about the log: the three holder-evidence values are
    // the whole vocabulary, and **no value names a pid or claims a store was
    // identified**. Asserted on the vocabulary itself so a later edit cannot
    // reintroduce attribution through the field.
    let evidence = [
        (HolderEvidence::StoppedClaudePresent, "\"stopped_claude_present\""),
        (HolderEvidence::NoStoppedClaude, "\"no_stopped_claude\""),
        (HolderEvidence::None, "\"none\""),
    ];
    for (value, token) in evidence {
        let text = serde_json::to_string(&value).expect("serializable");
        assert_eq!(text, token);
        assert!(
            !text.chars().any(char::is_numeric),
            "no holder-evidence value may carry a number: {text}"
        );
        assert!(!text.contains("pid"), "{text}");
    }

    for (value, token) in [(Tree::Agctl, "\"agctl\""), (Tree::Live, "\"live\"")] {
        assert_eq!(serde_json::to_string(&value).expect("serializable"), token);
    }
    for (value, token) in
        [(BreakOutcome::Broken, "\"broken\""), (BreakOutcome::Abandoned, "\"abandoned\"")]
    {
        assert_eq!(serde_json::to_string(&value).expect("serializable"), token);
    }
    for (value, token) in [
        (BreakReason::HeartbeatObserved, "\"heartbeat_observed\""),
        (BreakReason::TooYoung, "\"too_young\""),
        (BreakReason::Vanished, "\"vanished\""),
        (BreakReason::ClockJump, "\"clock_jump\""),
        (BreakReason::Retaken, "\"retaken\""),
        (BreakReason::HolderStopped, "\"holder_stopped\""),
    ] {
        assert_eq!(serde_json::to_string(&value).expect("serializable"), token);
    }
    // Six words, and no seventh. `stale` was a member of this enum and appears
    // nowhere in plan section 3.8: staleness is the *precondition* of the break
    // rule, so a reason saying so would be the only member that is not a reason
    // to have left a lock alone.
    assert!(
        serde_json::from_str::<BreakReason>("\"stale\"").is_err(),
        "the vocabulary is exactly section 3.8's six words"
    );
    for (value, token) in [
        (WriteOutcome::Applied, "\"applied\""),
        (WriteOutcome::Unknown, "\"unknown\""),
        (WriteOutcome::Failed, "\"failed\""),
    ] {
        assert_eq!(serde_json::to_string(&value).expect("serializable"), token);
    }
    assert_eq!(Target::Live.to_string(), "live");
    assert_eq!(Target::Namespace("0123abcd".to_owned()).to_string(), "namespace:0123abcd");
    assert!(
        serde_json::from_str::<Target>("\"something-else\"").is_err(),
        "an unknown target is not silently accepted"
    );
}

#[test]
fn digest8_takes_a_prefix_and_refuses_anything_else() {
    assert_eq!(
        digest8("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899").as_deref(),
        Some("aabbccdd")
    );
    assert_eq!(digest8("aabbccdd").as_deref(), Some("aabbccdd"));
    assert_eq!(digest8("aabbccd"), None, "too short to be a prefix");
    assert_eq!(digest8("AABBCCDDEE"), None, "hex is lowercase here");
    assert_eq!(digest8("sk-ant-oat01-whatever"), None, "not a digest at all");
}

#[test]
fn an_audit_id_names_the_entry_and_this_process() {
    let entry = AuditEntry::new(write_event("aabbccdd", None));
    let id = entry.id();
    let rendered = id.to_string();
    assert!(rendered.contains(&entry.ts.to_string()), "{rendered}");
    assert!(rendered.ends_with(&format!("#{}", std::process::id())), "{rendered}");
}

#[test]
fn the_log_lives_beside_the_namespaces() {
    let (_dir, paths) = store();
    assert_eq!(log_path(&paths), paths.namespace_root().join("keychain-writes.jsonl"));
}
