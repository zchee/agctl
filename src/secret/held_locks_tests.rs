//! Tests for the held-lock record reader (plan section 3.9, AC73).
//!
//! The JSON shape asserted here is a contract between two modules written in
//! parallel: `claude_lock` writes it before its first `mkdir`, and `doctor`
//! reads it to decide whether `--remove-stale` may leave the namespace root.
//! So the keys and the `tree` spelling are asserted against literal JSON
//! rather than a round trip through this module's own `Serialize`, which would
//! agree with itself whatever it spelled.

use std::fs;

use tempfile::TempDir;

use super::*;

/// A store whose held-locks directory exists.
struct Store {
    _dir: TempDir,
    paths: Paths,
}

fn store() -> Store {
    let dir = TempDir::new().expect("a temporary directory should be available");
    let paths = Paths::with_config_dir(dir.path().join("agentctl"));
    fs::create_dir_all(dir_of(&paths)).expect("the held-locks directory should be creatable");
    Store { _dir: dir, paths }
}

/// [`dir`] under a name that does not collide with the local bindings.
fn dir_of(paths: &Paths) -> PathBuf {
    dir(paths)
}

/// Writes one record file verbatim.
fn write_record(store: &Store, name: &str, body: &str) -> PathBuf {
    let path = dir_of(&store.paths).join(name);
    fs::write(&path, body).expect("the record should be writable");
    path
}

/// The shape `claude_lock` writes (contract section 2).
fn record_json(pid: u32, tree: &str, store_dir: &str, paths: &[&str]) -> String {
    let paths: Vec<String> = paths.iter().map(|path| format!("\"{path}\"")).collect();
    format!(
        r#"{{"agentctl_pid":{pid},"tree":"{tree}","store_dir":"{store_dir}",
           "paths":[{}],"taken_at":"2026-09-09T12:00:00Z"}}"#,
        paths.join(",")
    )
}

#[test]
fn read_all_parses_the_shape_claude_lock_writes() {
    let store = store();
    let file = write_record(
        &store,
        "4242.json",
        &record_json(
            4242,
            "live",
            "/Users/someone/.claude",
            &["/Users/someone/.claude/.oauth_refresh.lock", "/Users/someone/.claude.lock"],
        ),
    );

    let found = read_all(&store.paths);

    assert_eq!(found.len(), 1, "one record, one entry: {found:?}");
    assert_eq!(found[0].file, file, "the entry names the file it came from");
    assert_eq!(found[0].record.agentctl_pid, 4242);
    assert_eq!(found[0].record.tree, Tree::Live);
    assert_eq!(found[0].record.store_dir, Path::new("/Users/someone/.claude"));
    assert_eq!(found[0].record.paths.len(), 2);
    assert_eq!(found[0].record.taken_at, "2026-09-09T12:00:00Z");
}

#[test]
fn the_tree_field_is_spelled_agentctl_or_live() {
    // Both spellings, in both directions: this is the one field whose value a
    // reader and a writer in different lanes have to agree on.
    let store = store();
    write_record(&store, "a.json", &record_json(1, "agentctl", "/store/acct/org", &[]));
    write_record(&store, "b.json", &record_json(2, "live", "/store/live", &[]));

    let found = read_all(&store.paths);
    assert_eq!(found.len(), 2, "{found:?}");
    assert_eq!(found[0].record.tree, Tree::Agentctl);
    assert_eq!(found[1].record.tree, Tree::Live);

    let rendered = serde_json::to_string(&Tree::Agentctl).expect("serializable");
    assert_eq!(rendered, "\"agentctl\"", "the writer's spelling is the reader's");
    assert_eq!(serde_json::to_string(&Tree::Live).expect("serializable"), "\"live\"");
}

#[test]
fn read_all_is_empty_when_there_is_no_directory_at_all() {
    // The common case on every machine that has never held a Claude Code
    // lock, and it must not be an error: `doctor` reports it as "none".
    let dir = TempDir::new().expect("a temporary directory should be available");
    let paths = Paths::with_config_dir(dir.path().join("agentctl"));
    assert!(read_all(&paths).is_empty());
}

#[test]
fn read_all_skips_what_is_not_a_readable_record() {
    // A `doctor` that refuses to report because one file here is malformed is
    // a `doctor` that cannot diagnose the machine it was run on.
    let store = store();
    write_record(&store, "good.json", &record_json(7, "agentctl", "/store/acct/org", &[]));
    write_record(&store, "truncated.json", "{\"agentctl_pid\":");
    write_record(&store, "wrong-tree.json", &record_json(8, "somewhere-else", "/store", &[]));
    write_record(&store, "notes.txt", &record_json(9, "live", "/store", &[]));
    fs::create_dir(dir_of(&store.paths).join("a-directory.json"))
        .expect("the directory should be creatable");

    let found = read_all(&store.paths);

    assert_eq!(found.len(), 1, "only the parseable record survives: {found:?}");
    assert_eq!(found[0].record.agentctl_pid, 7);
}

#[test]
fn read_all_refuses_a_record_reached_through_a_symbolic_link() {
    // The record decides whether a removal may leave the namespace root, so
    // it is read with the same `O_NOFOLLOW` care as a credential file.
    let store = store();
    let elsewhere = store._dir.path().join("planted.json");
    fs::write(&elsewhere, record_json(11, "live", "/Users/someone/.claude", &[]))
        .expect("writable");
    std::os::unix::fs::symlink(&elsewhere, dir_of(&store.paths).join("linked.json"))
        .expect("the symlink should be creatable");

    assert!(read_all(&store.paths).is_empty(), "a linked record is not read");
}

#[test]
fn read_all_refuses_a_record_larger_than_the_limit() {
    let store = store();
    let padding = "x".repeat(usize::try_from(MAX_RECORD_BYTES).expect("the limit fits in a usize"));
    write_record(
        &store,
        "huge.json",
        &format!(
            r#"{{"agentctl_pid":1,"tree":"live","store_dir":"/store","paths":[],
               "taken_at":"{padding}"}}"#
        ),
    );

    assert!(read_all(&store.paths).is_empty(), "an oversized record is not parsed");
}

#[test]
fn attests_compares_whole_paths_and_never_a_parent() {
    let store = store();
    write_record(
        &store,
        "one.json",
        &record_json(
            5,
            "live",
            "/Users/someone/.claude",
            &["/Users/someone/.claude/.oauth_refresh.lock"],
        ),
    );
    let found = read_all(&store.paths);
    let record = &found.first().expect("one record").record;

    assert!(record.attests(Path::new("/Users/someone/.claude/.oauth_refresh.lock")));
    assert!(
        !record.attests(Path::new("/Users/someone/.claude")),
        "the store directory is not one of the locks"
    );
    assert!(
        !record.attests(Path::new("/Users/someone/.claude/.storage-write")),
        "a sibling artefact the record does not name is not attested"
    );
    assert!(
        !record.attests(Path::new("/Users/someone/.claude/.oauth_refresh.lock/inner")),
        "and neither is anything below one"
    );
}

#[test]
fn the_anchor_is_the_store_directorys_parent() {
    // The legacy lock is `<store_dir>.lock`, beside the store rather than
    // inside it (fact F17), so an anchor at the store could not reach it.
    let store = store();
    write_record(&store, "one.json", &record_json(5, "live", "/Users/someone/.claude", &[]));
    let found = read_all(&store.paths);
    let record = &found.first().expect("one record").record;

    assert_eq!(record.anchor(), Some(Path::new("/Users/someone")));
}
