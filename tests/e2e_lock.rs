//! The gates that keep decision D-022 and ruling 4 true (plan AC80).
//!
//! # Why these live here and the rest of the lock suite does not
//!
//! `agentctl` is a **binary-only crate**: there is no `[lib]` target, so an
//! integration test cannot reach `secret::claude_lock` or `runtime::proc` at
//! all. The acquire truth table (AC62), the break rule (AC63) and the drift
//! check (AC64) therefore live in the sibling unit-test files, where they can
//! call the functions they are about; the two child-process tests AC64 asks
//! for are there too, re-executing the unit-test binary.
//!
//! What is left for this file is the half that needs no crate API and could
//! not be asserted from inside one module anyway: **greps over the whole
//! tree, and over the built artifact.** They are the mechanical form of a
//! rule the reviews reached twice — that agentctl reads process *state* and
//! never process arguments or environment — and they are here so that a later
//! edit to any module has to trip them.

use std::path::Path;
use std::path::PathBuf;

/// Every non-test source file in the crate.
///
/// `*_tests.rs` is excluded exactly as plan section 9.3's globs exclude it: a
/// test may name a retired mechanism in order to assert it is gone.
fn production_sources() -> Vec<PathBuf> {
    let mut found = Vec::new();
    collect(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src"), &mut found);
    found.retain(|path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".rs") && !name.ends_with("_tests.rs"))
    });
    found.sort();
    assert!(found.len() > 20, "the walk found the tree: {} files", found.len());
    found
}

fn collect(dir: &Path, into: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, into);
        } else {
            into.push(path);
        }
    }
}

/// Whether `needle` appears in `haystack` as a whole word.
///
/// Needed for one of the banned names: `environ` is a prefix of
/// `environment`, and the crate says "environment" in a great deal of honest
/// prose. The C symbol is what is banned, not the English word.
fn contains_token(haystack: &str, needle: &str) -> bool {
    let boundary =
        |byte: Option<u8>| byte.is_none_or(|byte| !byte.is_ascii_alphanumeric() && byte != b'_');
    haystack.match_indices(needle).any(|(at, _)| {
        let before = at.checked_sub(1).map(|index| haystack.as_bytes()[index]);
        let after = haystack.as_bytes().get(at + needle.len()).copied();
        boundary(before) && boundary(after)
    })
}

// ---------------------------------------------------------------------------
// AC80 — no child process, and no process-argument or environment API
// ---------------------------------------------------------------------------

#[test]
fn no_production_source_spawns_a_process_lister() {
    // Decision D-022 retired `/bin/ps` because it is setuid root and cannot
    // be exec'd inside the phase-2 manual-check sandbox at all, which would
    // have produced process ids with no states — a shape the audit vocabulary
    // cannot express, and whose tempting reading is the one false negative
    // that licenses a lock break (spike V12).
    let banned = [
        "Command::new(\"ps\")",
        "Command::new(\"/bin/ps\")",
        "Command::new(PS_BIN)",
        "Command::new(\"pgrep\")",
        "Command::new(\"/usr/bin/pgrep\")",
        "pgrep",
        "/bin/ps",
        "PS_BIN",
        "PS_TIMEOUT",
    ];
    for path in production_sources() {
        let source = std::fs::read_to_string(&path).expect("a readable source file");
        for needle in banned {
            assert!(
                !source.contains(needle),
                "`{needle}` appears in {}; decision D-022 retired it",
                path.display()
            );
        }
    }
}

#[test]
fn no_production_source_names_a_process_argument_or_environment_api() {
    // Ruling 4, and the reason it is a rule rather than a bound: the review
    // ran the retired command and found unrelated plaintext secrets in its
    // output — a password-manager master password, two third-party API
    // secrets, a messaging token. No parser discipline makes that worth a
    // diagnostic field, and the bound the earlier draft offered did not cover
    // a panic payload, a `Debug` render or an error carrying a child's stdout.
    // So the mechanism is gone as a class, and this is the grep that keeps it
    // gone.
    let literals = ["KERN_PROCARGS", "KERN_PROCARGS2", "proc_pidpath", " -E", "\"-E\"", "\"-f\""];
    let tokens = ["environ", "environb"];
    for path in production_sources() {
        let source = std::fs::read_to_string(&path).expect("a readable source file");
        for needle in literals {
            assert!(
                !source.contains(needle),
                "`{needle}` appears in {}; phase 2 reads no process arguments",
                path.display()
            );
        }
        for needle in tokens {
            assert!(
                !contains_token(&source, needle),
                "`{needle}` appears in {}; phase 2 reads no process environment",
                path.display()
            );
        }
    }
}

#[test]
fn the_grep_can_fail() {
    // Plan AC83's lesson, applied here: a gate that cannot fail is not a
    // gate. Three of the plan's own greps were inert because `\|` is an
    // escaped literal pipe in ripgrep's regex, and they passed
    // unconditionally on the rules they were written to enforce. So this
    // suite proves its own matcher against planted text before trusting it
    // against the tree.
    assert!(contains_token("let e = environ;", "environ"));
    assert!(contains_token("environ", "environ"));
    assert!(contains_token("(environ)", "environ"));
    assert!(!contains_token("agentctl reads no environment", "environ"));
    assert!(!contains_token("environments", "environ"));
    assert!(!contains_token("my_environ_var", "environ"));
    assert!("Command::new(\"ps\")".contains("Command::new(\"ps\")"));
}

#[test]
fn the_only_unsafe_in_the_crate_is_the_libproc_wrapper() {
    // Decision D-022 brought the crate its first `unsafe`. It is confined to
    // one private module inside `runtime/proc.rs`, every call carries a
    // `// SAFETY:` comment, and no other module gains any.
    let mut unsafe_files: Vec<(PathBuf, usize)> = Vec::new();
    for path in production_sources() {
        let source = std::fs::read_to_string(&path).expect("a readable source file");
        let count = source.matches("unsafe ").count();
        if count > 0 {
            unsafe_files.push((path, count));
        }
    }
    let names: Vec<String> =
        unsafe_files.iter().map(|(path, count)| format!("{}:{count}", path.display())).collect();
    assert_eq!(unsafe_files.len(), 1, "exactly one file has any `unsafe`: {names:?}");
    let (path, count) = &unsafe_files[0];
    assert!(
        path.ends_with("runtime/proc.rs"),
        "and it is the libproc wrapper, not {}",
        path.display()
    );

    let source = std::fs::read_to_string(path).expect("readable");
    let safety = source.matches("// SAFETY:").count();
    assert!(
        safety >= *count,
        "every `unsafe` carries a `// SAFETY:` comment: {count} blocks, {safety} comments"
    );
}

#[test]
fn the_lock_fault_names_are_declared_where_the_fault_switch_documents_them() {
    // The seven names plan section 3.8 and W4a need. Declared in one place so
    // that W4a does not have to edit `runtime/fault.rs` again — and asserted
    // here so a rename cannot quietly orphan an injection.
    let fault = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/runtime/fault.rs");
    let source = std::fs::read_to_string(&fault).expect("a readable source file");
    for name in [
        "swap_pause_in_locks",
        "swap_write_fail",
        "swap_lock_leak",
        "keychain_write_hang",
        "lock_contended",
        "lock_stale",
        "lock_resume_after_sample_b",
    ] {
        assert!(source.contains(name), "`{name}` is documented in runtime/fault.rs");
    }
}

#[test]
fn no_production_source_reads_the_lock_suites_own_test_variables() {
    // The two variables the child-process half of AC64 uses are read in one
    // `#[cfg(test)]` file and nowhere else, so they are not crate seams: they
    // cannot reach a release artifact and the release gate has nothing to
    // register.
    for name in ["AGENTCTL_LOCK_CHILD_ROLE", "AGENTCTL_LOCK_CHILD_DIR"] {
        for path in production_sources() {
            let source = std::fs::read_to_string(&path).expect("a readable source file");
            assert!(!source.contains(name), "`{name}` appears in {}", path.display());
        }
    }
}

// ---------------------------------------------------------------------------
// AC80 — and none of it in the artifact either
// ---------------------------------------------------------------------------

#[test]
fn the_built_binary_carries_no_process_lister_and_no_argument_api() {
    // The same claim as the source greps, one level down: a string that is
    // not in the source cannot be in the binary, but a dependency could
    // reintroduce one, and this is the artifact a user runs.
    let binary = std::fs::read(env!("CARGO_BIN_EXE_agentctl")).expect("the test binary exists");
    for needle in ["/bin/ps", "pgrep", "KERN_PROCARGS"] {
        assert!(!contains_bytes(&binary, needle.as_bytes()), "`{needle}` is in the built artifact");
    }
    // And the call that replaced them is: an undefined symbol the dynamic
    // linker has to resolve. Only `proc_pidinfo` is asserted, because it is
    // the only one `doctor` reaches today — `proc_listpids` and `proc_name`
    // are reached solely from `claude_processes`, whose caller is the break
    // rule, whose caller arrives in W4a. When it does, this list grows.
    assert!(
        contains_bytes(&binary, b"proc_pidinfo"),
        "the process state comes from libproc, in-process"
    );
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

// ---------------------------------------------------------------------------
// AC64's `doctor` half, and why it is not asserted here
// ---------------------------------------------------------------------------

#[test]
fn the_stale_remover_refuses_a_path_outside_the_namespace_root_without_a_record() {
    // Plan AC64's last clause is "`swap_lock_leak` leaves them and `doctor`
    // names them", and section 3.9 row 2 is what makes the leaked directories
    // recoverable: `--remove-stale` accepts a path outside `namespace_root()`
    // **only** when a held-lock record names that exact path and the process
    // that wrote it is gone.
    //
    // This is the "only" half. The store below has no held-lock record at all,
    // so the refusal is unconditional — and it stays unconditional now that
    // the attested branch exists, which is why the name says *without a
    // record* rather than reading as a blanket refusal. The positive half, and
    // every other negative, live in `commands/doctor_tests.rs` and
    // `tests/e2e_accounts.rs`.
    let store = tempfile::tempdir().expect("a temporary directory");
    let config = tempfile::tempdir().expect("a temporary directory");
    let outside = store.path().join(".oauth_refresh.lock");
    std::fs::create_dir(&outside).expect("a lock directory, as Claude Code makes it");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_agentctl"))
        .arg("--config-dir")
        .arg(config.path())
        .arg("claude")
        .arg("doctor")
        .arg("--remove-stale")
        .arg(&outside)
        .arg("--yes")
        .output()
        .expect("the binary should run");

    assert!(!output.status.success(), "a path outside the store, with no record, is refused");
    assert!(outside.is_dir(), "and nothing is removed");
}
