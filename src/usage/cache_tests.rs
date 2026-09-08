use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;

use serde_json::json;
use tempfile::TempDir;

use super::*;

const ACCT: &str = "11111111-2222-3333-4444-555555555555";
const ORG: &str = "66666666-7777-8888-9999-000000000000";

fn store_dir() -> (TempDir, Paths) {
    let dir = TempDir::new().expect("a temporary directory should be creatable");
    let paths = Paths::with_config_dir(dir.path().to_path_buf());
    paths.ensure_dirs().expect("the store directories should be creatable");
    (dir, paths)
}

fn body() -> Value {
    json!({"limits": [{"kind": "session", "percent": 21, "is_active": false}]})
}

#[test]
fn path_is_the_account_and_organization_under_the_cache_dir() {
    let (_dir, paths) = store_dir();
    let path = path(&paths, ACCT, ORG);
    assert_eq!(path.parent(), Some(paths.cache_dir().as_path()));
    let name = path.file_name().and_then(|n| n.to_str()).expect("the name is UTF-8");
    assert!(name.starts_with(&format!("{ACCT}.{ORG}.")), "the readable half is intact: {name}");
    assert!(name.ends_with(".json"), "{name}");
}

#[test]
fn path_names_a_file_inside_the_cache_dir_for_any_identifier_at_all() {
    // The identifiers that used to be refused outright, which meant a row
    // keyed by a keychain service name had no cache and re-fetched on every
    // pass. Every one of them must now name a file, and that file must be
    // directly inside the cache directory — a `..` or a `/` that survived
    // into the name would be an escape.
    let (_dir, paths) = store_dir();
    let awkward = ["..", ".", "", "a/b", "../../etc/passwd", "Claude Code-credentials-6cdd6b98"];
    for value in awkward {
        for (acct, org) in [(value, ORG), (ACCT, value)] {
            let path = path(&paths, acct, org);
            assert_eq!(
                path.parent(),
                Some(paths.cache_dir().as_path()),
                "`{value}` escaped the cache directory: {}",
                path.display()
            );
            let name = path.file_name().and_then(|n| n.to_str()).expect("the name is UTF-8");
            assert!(!name.contains('/'), "{name}");
            assert!(name.ends_with(".json"), "{name}");
            // And it is writable, which is the point of naming it at all.
            std::fs::write(&path, "{}")
                .unwrap_or_else(|err| panic!("`{}` should be writable: {err}", path.display()));
        }
    }
}

#[test]
fn two_identifiers_that_sanitize_alike_still_get_their_own_entry() {
    // The readable half is lossy on purpose, so the digest is what keeps two
    // rows from reading each other's usage figures.
    let (_dir, paths) = store_dir();
    let first = path(&paths, "a b", ORG);
    let second = path(&paths, "a/b", ORG);
    assert_ne!(first, second, "the digest separates them: {}", first.display());
}

#[test]
fn a_stored_entry_round_trips() {
    let (_dir, paths) = store_dir();
    let path = path(&paths, ACCT, ORG);
    let entry = CacheEntry::new(1_757_000_000_000, body());

    store(&path, &entry).expect("the cache entry should be writable");
    let loaded = load(&path).expect("the entry just written should load");
    assert_eq!(loaded, entry);
    assert_eq!(loaded.body, body());
}

#[test]
fn a_stored_entry_is_a_regular_file_at_0600_with_no_temporary_left_behind() {
    let (_dir, paths) = store_dir();
    let path = path(&paths, ACCT, ORG);
    store(&path, &CacheEntry::new(0, body())).expect("writable");

    let meta = std::fs::metadata(&path).expect("the entry should exist");
    assert!(meta.is_file());
    assert_eq!(meta.permissions().mode() & 0o777, FILE_MODE);

    let strays: Vec<_> = std::fs::read_dir(paths.cache_dir())
        .expect("the cache directory should be readable")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains(".tmp."))
        .collect();
    assert!(strays.is_empty(), "temporary files left behind: {strays:?}");
}

#[test]
fn a_rewrite_replaces_the_file_atomically() {
    let (_dir, paths) = store_dir();
    let path = path(&paths, ACCT, ORG);

    store(&path, &CacheEntry::new(1, body())).expect("writable");
    let first = std::fs::metadata(&path).expect("present").ino();

    store(&path, &CacheEntry::new(2, body())).expect("writable");
    let second = std::fs::metadata(&path).expect("present");

    // A new inode is the observable signature of tmp-then-rename; a truncate
    // in place would keep the old one and expose a half-written window.
    assert_ne!(first, second.ino());
    assert_eq!(second.permissions().mode() & 0o777, FILE_MODE);
    assert_eq!(load(&path).expect("loads").fetched_at_ms, 2);
}

#[test]
fn freshness_ends_exactly_at_the_ttl() {
    let entry = CacheEntry::new(1_000_000, body());
    let ttl_ms = i64::try_from(TTL.as_millis()).expect("300s fits in an i64 of milliseconds");

    assert!(entry.is_fresh(1_000_000, TTL), "an entry fetched now is fresh");
    assert!(entry.is_fresh(1_000_000 + ttl_ms - 1, TTL), "one millisecond short of the TTL");
    assert!(!entry.is_fresh(1_000_000 + ttl_ms, TTL), "exactly at the TTL is stale");
    assert!(!entry.is_fresh(1_000_000 + ttl_ms * 10, TTL), "long past the TTL is stale");
}

#[test]
fn an_entry_from_the_future_is_not_fresh() {
    // A clock that jumped backwards would otherwise pin an entry as fresh
    // forever, and the account would stop refetching until someone noticed.
    let entry = CacheEntry::new(2_000_000, body());
    assert!(!entry.is_fresh(1_000_000, TTL));
}

#[test]
fn rate_limit_remaining_counts_down_and_then_clears() {
    let mut entry = CacheEntry::new(0, body());
    entry.rate_limited_until_ms = Some(30_000);

    assert_eq!(entry.rate_limited_for(0), Some(30));
    assert_eq!(entry.rate_limited_for(29_500), Some(1), "a part second still counts as waiting");
    assert_eq!(entry.rate_limited_for(30_000), None);
    assert_eq!(entry.rate_limited_for(60_000), None);

    entry.rate_limited_until_ms = None;
    assert_eq!(entry.rate_limited_for(0), None);
}

#[test]
fn an_unreadable_entry_loads_as_none_rather_than_failing() {
    let (_dir, paths) = store_dir();
    let path = path(&paths, ACCT, ORG);

    assert_eq!(load(&path), None, "an absent file");

    std::fs::write(&path, b"{ not json").expect("writable");
    assert_eq!(load(&path), None, "a corrupt file");

    std::fs::write(&path, br#"{"version":99,"fetched_at_ms":0,"body":{}}"#).expect("writable");
    assert_eq!(load(&path), None, "an entry from a future build");

    std::fs::write(&path, vec![b'x'; usize::try_from(MAX_ENTRY_BYTES).unwrap_or(usize::MAX) + 1])
        .expect("writable");
    assert_eq!(load(&path), None, "an oversized file");

    std::fs::remove_file(&path).expect("removable");
    std::fs::create_dir(&path).expect("a directory can take the entry's place");
    assert_eq!(load(&path), None, "a directory where the entry should be");
}

#[test]
fn a_stale_entry_still_loads_so_it_can_be_rendered_stale() {
    // The whole point of stale-while-error: `load` must not apply the TTL,
    // only `is_fresh` does, so a failed fetch can still show yesterday's
    // numbers next to a `stale` badge.
    let (_dir, paths) = store_dir();
    let path = path(&paths, ACCT, ORG);
    store(&path, &CacheEntry::new(0, body())).expect("writable");

    let loaded = load(&path).expect("a stale entry still loads");
    assert!(!loaded.is_fresh(i64::from(u32::MAX), TTL));
    assert_eq!(loaded.body, body());
}
