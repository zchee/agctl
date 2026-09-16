//! Plan AC119: the invariants visibility cannot hold on its own, checked by
//! reading the source (the `keychain_write_tests.rs` precedent).
//!
//! Outside `provider::codex` the proof types are unforgeable by privacy, and
//! `scripts/phase3-structural.sh` proves that by compiling planted violations
//! (AC122). *Inside* it, every `pub(super)` constructor is visible to every
//! sibling, so which sibling may call each one is pinned here. Each rule is
//! also run against a planted copy of the tree and must report the plant — a
//! rule that has never been seen to fail proves nothing.

use std::fs;
use std::path::Path;

use super::*;

/// One source file: repo-relative path and contents.
type Source = (String, String);

/// Every `.rs` file under `src/`.
fn tree() -> Vec<Source> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<Source>) {
        let mut entries: Vec<_> = fs::read_dir(dir)
            .unwrap_or_else(|err| panic!("read_dir {}: {err}", dir.display()))
            .flatten()
            .collect();
        entries.sort_by_key(|entry| entry.path());
        for entry in entries {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, root, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().into_owned();
                let text =
                    fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {rel}: {err}"));
                out.push((rel, text));
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    walk(&root.join("src"), root, &mut out);
    assert!(
        out.iter().any(|(path, _)| path == "src/provider/codex/auth_store.rs"),
        "the scan found the tree"
    );
    out
}

fn is_test_file(path: &str) -> bool {
    path.ends_with("_tests.rs")
}

/// Non-comment lines of non-test files, with their file and 1-based number.
fn code_lines(sources: &[Source]) -> impl Iterator<Item = (&str, usize, &str)> {
    sources.iter().filter(|(path, _)| !is_test_file(path)).flat_map(|(path, text)| {
        text.lines()
            .enumerate()
            .filter(|(_, line)| !line.trim_start().starts_with("//"))
            .map(move |(index, line)| (path.as_str(), index + 1, line))
    })
}

/// Whether `word` occurs in `line` as a whole identifier at `at`.
fn is_word_at(line: &str, at: usize, word: &str) -> bool {
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let before = line[..at].chars().next_back().is_none_or(|c| !ident(c));
    let after = line[at + word.len()..].chars().next().is_none_or(|c| !ident(c));
    before && after
}

/// The struct-literal (or tuple-constructor) uses of `name` in `line`: the
/// name, an optional generic list, then `{` (or `(` when `tuple`), not in a
/// type position (`struct`, `impl`, `for`, `->`, `enum`).
fn literal_uses(line: &str, name: &str, tuple: bool) -> bool {
    line.match_indices(name).any(|(at, _)| {
        if !is_word_at(line, at, name) {
            return false;
        }
        let prefix = line[..at].trim_end();
        let type_position = prefix.trim_start().starts_with("impl")
            || ["struct", "enum", "for", "->", "dyn"].iter().any(|kw| prefix.ends_with(kw));
        if type_position {
            return false;
        }
        let mut rest = line[at + name.len()..].trim_start();
        // A turbofish (`Name::<'g> { .. }`) is a literal as much as `Name { .. }`.
        if rest.starts_with("::<") {
            rest = &rest[2..];
        }
        if let Some(generics) = rest.strip_prefix('<') {
            let Some(close) = generics.find('>') else { return false };
            rest = generics[close + 1..].trim_start();
        }
        rest.starts_with('{') || (tuple && rest.starts_with('('))
    })
}

/// Whether `line` binds to `_` or an `_`-prefixed name: `let _ =`, `let _x =`,
/// `let _x: T =`.
fn is_underscore_binding(line: &str) -> bool {
    let Some(rest) = line.trim_start().strip_prefix("let ") else { return false };
    let rest = rest.trim_start().strip_prefix("mut ").unwrap_or(rest.trim_start());
    let Some(rest) = rest.strip_prefix('_') else { return false };
    let name_end =
        rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(rest.len());
    let tail = rest[name_end..].trim_start();
    tail.starts_with('=') || tail.starts_with(':')
}

/// Every AC119 violation in `sources`, one sentence each.
fn violations(sources: &[Source]) -> Vec<String> {
    let mut found = Vec::new();

    // (1) No struct literal of a proof, guard or handle type outside its module.
    let literals: [(&str, &str, bool); 8] = [
        ("OwnedNamespace", "src/provider/codex/auth_store.rs", false),
        ("InstallNamespace", "src/provider/codex/auth_store.rs", false),
        ("InflightToken", "src/provider/codex/auth_store.rs", false),
        ("WriteReceipt", "src/provider/codex/auth_store.rs", false),
        ("LockedCredentials", "src/provider/codex/credentials.rs", false),
        ("VerifiedLogin", "src/provider/codex/proof.rs", false),
        ("OwnedRecord", "src/provider/codex/proof.rs", false),
        ("PostExitReport", "src/provider/codex/proof.rs", false),
    ];
    for (file, number, line) in code_lines(sources) {
        for (name, home, tuple) in
            literals.iter().chain([&("CodexNamespaceGuard", "src/provider/codex/proof.rs", true)])
        {
            if file != *home && literal_uses(line, name, *tuple) {
                found.push(format!("{file}:{number}: a `{name}` literal outside {home}"));
            }
        }
    }

    // (2) Pinned call sites. A definition line (`fn name`) is not a call.
    let pins: [(&str, &[&str]); 21] = [
        ("from_locked_read(", &["src/provider/codex/auth_store.rs"]),
        ("LockedCredentials::new(", &["src/provider/codex/credentials.rs"]),
        ("write_refresh_body_to(", &["src/provider/codex/oauth.rs"]),
        ("resolve_pending_with", &["src/secret/file_store.rs", "src/provider/codex/auth_store.rs"]),
        ("from_verified(", &["src/provider/codex/auth_store.rs"]),
        ("CodexNamespaceGuard::wrap(", &["src/provider/codex/lock.rs"]),
        ("PostExitReport::from_child(", &["src/provider/codex/login_child.rs"]),
        ("ResendConsent::after_confirmation(", &["src/commands/codex/accounts.rs"]),
        ("ResetConsent::after_confirmation(", &["src/commands/codex/accounts.rs"]),
        (".write_inflight(", &["src/provider/codex/refresh.rs"]),
        (".write_resend(", &["src/provider/codex/refresh.rs"]),
        (".clear_inflight(", &["src/provider/codex/refresh.rs"]),
        (".mark_interrupted(", &["src/provider/codex/refresh.rs"]),
        (".mark_unknown(", &["src/provider/codex/refresh.rs"]),
        (".reset_floor(", &["src/provider/codex/refresh.rs"]),
        // The same mutators spelled as associated functions (review S30 F5).
        ("RefreshStateFile::write_inflight(", &["src/provider/codex/refresh.rs"]),
        ("RefreshStateFile::write_resend(", &["src/provider/codex/refresh.rs"]),
        ("RefreshStateFile::clear_inflight(", &["src/provider/codex/refresh.rs"]),
        ("RefreshStateFile::mark_interrupted(", &["src/provider/codex/refresh.rs"]),
        ("RefreshStateFile::mark_unknown(", &["src/provider/codex/refresh.rs"]),
        ("RefreshStateFile::reset_floor(", &["src/provider/codex/refresh.rs"]),
    ];
    for (file, number, line) in code_lines(sources) {
        for (pattern, allowed) in pins {
            let bare = pattern
                .rsplit("::")
                .next()
                .unwrap_or(pattern)
                .trim_start_matches('.')
                .trim_end_matches('(');
            let definition = line.contains(&format!("fn {bare}"));
            let in_home = pattern == "resolve_pending_with" && file == "src/secret/pending.rs";
            if line.contains(pattern) && !definition && !in_home && !allowed.contains(&file) {
                found.push(format!("{file}:{number}: `{pattern}` called outside {allowed:?}"));
            }
        }
    }

    // (3) `SecretFile::open` only in file_store.rs and auth_store.rs, and
    // once in auth_store.rs, where one function binds the descriptor and the
    // displayed path together (review F7).
    let opens: Vec<(&str, usize)> = code_lines(sources)
        .filter(|(_, _, line)| line.contains("SecretFile::open("))
        .map(|(file, number, _)| (file, number))
        .collect();
    for (file, number) in &opens {
        if !["src/secret/file_store.rs", "src/provider/codex/auth_store.rs"].contains(file) {
            found.push(format!(
                "{file}:{number}: `SecretFile::open` outside file_store.rs and auth_store.rs"
            ));
        }
    }
    let in_auth_store =
        opens.iter().filter(|(file, _)| *file == "src/provider/codex/auth_store.rs").count();
    if in_auth_store > 1 {
        found.push(format!(
            "src/provider/codex/auth_store.rs: `SecretFile::open` at {in_auth_store} sites, not one"
        ));
    }

    // (4) `AUTH_FILE` is private.
    for (file, number, line) in code_lines(sources) {
        let spelled = line.contains("const AUTH_FILE");
        if spelled && line.trim_start().starts_with("pub") {
            found.push(format!("{file}:{number}: `AUTH_FILE` is not private"));
        }
    }

    // (5) A recorded spelling never reaches a writer or a namespace path.
    let writer_calls =
        ["SecretFile::open(", "OwnedNamespace::open(", "open_for_install(", "codex_namespace_dir("];
    for (file, number, line) in code_lines(sources) {
        if writer_calls.iter().any(|call| line.contains(call))
            && (line.contains("export_spelling") || line.contains("HomeReadOnly"))
        {
            found.push(format!("{file}:{number}: a recorded path reaches a namespace writer"));
        }
    }

    // (6) A receipt is never discarded with `let _ =` or `let _name =`
    // (invariant I30; review S30 F5): both silence `#[must_use]`.
    let receipt_calls = [".install(", ".remove_named_files(", ".resolve_pending(", "ns.write("];
    for (file, number, line) in code_lines(sources) {
        if is_underscore_binding(line) && receipt_calls.iter().any(|call| line.contains(call)) {
            found.push(format!("{file}:{number}: a write receipt discarded with `let _… =`"));
        }
    }

    // (7) No test builds a `CodexEnv` from the process (invariant I25).
    for (file, text) in sources.iter().filter(|(path, _)| is_test_file(path)) {
        let needle = format!("CodexEnv::{}", "from_process");
        if let Some(index) = text.lines().position(|line| line.contains(&needle)) {
            found.push(format!(
                "{file}:{}: a test reads the process environment for a Codex home",
                index + 1
            ));
        }
    }

    found
}

#[test]
fn the_tree_satisfies_every_ac119_rule() {
    let found = violations(&tree());
    assert!(found.is_empty(), "AC119 violations:\n{}", found.join("\n"));
}

/// Adds `line` to `file` in a copy of the tree (creating the file if needed).
fn planted(base: &[Source], file: &str, line: &str) -> Vec<Source> {
    let mut sources = base.to_vec();
    match sources.iter_mut().find(|(path, _)| path == file) {
        Some((_, text)) => {
            text.push('\n');
            text.push_str(line);
        }
        None => sources.push((file.to_owned(), line.to_owned())),
    }
    sources
}

#[test]
fn every_rule_reports_its_plant() {
    // Includes the plan's named plant: a `from_locked_read` call in
    // `provider/codex/discovery.rs`, which compiles and must fail this test.
    let base = tree();
    let plants: [(&str, &str, &str); 20] = [
        (
            "discovery from_locked_read",
            "src/provider/codex/discovery.rs",
            "fn p(c: Credentials, g: &CodexNamespaceGuard) -> LockedCredentials<'_> { LockedCredentials::from_locked_read(c, g) }",
        ),
        (
            "rustfmt-shaped call",
            "src/provider/codex/discovery.rs",
            "        from_locked_read(c, g)",
        ),
        (
            "OwnedRecord literal",
            "src/provider/codex/discovery.rs",
            "    let r = OwnedRecord { user, acct, export_spelling: None, refresh };",
        ),
        ("guard tuple", "src/provider/codex/usage.rs", "    let g = CodexNamespaceGuard(inner);"),
        (
            "inflight literal",
            "src/provider/codex/refresh.rs",
            "    let t = InflightToken { digest8, _guard: PhantomData };",
        ),
        (
            "generic literal",
            "src/provider/codex/refresh.rs",
            "    LockedCredentials::<'g> { inner, _guard: PhantomData }",
        ),
        (
            "receipt literal",
            "src/provider/codex/audit.rs",
            "    let WriteReceipt { kind, .. } = receipt;",
        ),
        (
            "private new",
            "src/provider/codex/refresh.rs",
            "    let c = LockedCredentials::new(inner);",
        ),
        (
            "marker from commands",
            "src/commands/codex/status.rs",
            "    ns.refresh_state().clear_inflight(DefiniteOutcome::Applied)?;",
        ),
        (
            "marker from discovery",
            "src/provider/codex/discovery.rs",
            "    state.write_inflight(&c)?;",
        ),
        (
            "wrap outside lock.rs",
            "src/provider/codex/auth_store.rs",
            "    let g = CodexNamespaceGuard::wrap(inner);",
        ),
        (
            "consent outside accounts",
            "src/commands/codex/status.rs",
            "    let c = ResendConsent::after_confirmation(\"yes\", true, false)?;",
        ),
        (
            "second SecretFile::open",
            "src/provider/codex/auth_store.rs",
            "    let f = SecretFile::open(&root, fd, name, &shown);",
        ),
        (
            "public AUTH_FILE",
            "src/provider/codex/auth_store.rs",
            "pub(crate) const AUTH_FILE: &str = \"auth.json\";",
        ),
        (
            "export spelling to a writer",
            "src/commands/codex/login.rs",
            "    let d = paths.codex_namespace_dir(export_spelling, acct)?;",
        ),
        ("discarded receipt", "src/commands/codex/login.rs", "    let _ = ns.install(&fault);"),
        (
            "named discard",
            "src/commands/codex/login.rs",
            "    let _receipt = install.install(&fault)?;",
        ),
        (
            "UFCS marker clear",
            "src/provider/codex/discovery.rs",
            "    RefreshStateFile::clear_inflight(&state, DefiniteOutcome::Applied)?;",
        ),
        (
            "UFCS marker arm",
            "src/provider/codex/usage.rs",
            "    let t = RefreshStateFile::write_inflight(state, &c)?;",
        ),
        (
            "from_process in a test",
            "src/commands/codex/status_tests.rs",
            "    let env = CodexEnv::from_\u{70}rocess();",
        ),
    ];
    for (name, file, line) in plants {
        let found = violations(&planted(&base, file, line));
        assert!(!found.is_empty(), "the plant `{name}` in {file} was not reported");
    }
}

#[test]
fn literal_detection_ignores_type_positions() {
    for line in [
        "pub struct OwnedRecord<'a> {",
        "impl<'g> OwnedNamespace<'g> {",
        "    pub fn open(paths: &Paths) -> Result<OwnedNamespace<'g>, E> {",
        "    fn owned_record(&self) -> OwnedRecord<'_> {",
        "impl fmt::Debug for VerifiedLogin {",
        "pub struct CodexNamespaceGuard(NamespaceLockGuard);",
        "    let x = proof::OwnedRecord::user(&r);",
    ] {
        let hit = ["OwnedRecord", "OwnedNamespace", "VerifiedLogin"]
            .iter()
            .any(|n| literal_uses(line, n, false))
            || literal_uses(line, "CodexNamespaceGuard", true);
        assert!(!hit, "a type position was read as a literal: {line}");
    }
}

#[test]
fn the_plan_type_vocabulary_is_fact_f63s() {
    assert_eq!(PLAN_TYPES.len(), 22);
    assert!(is_known_plan("pro") && is_known_plan("free_workspace") && is_known_plan("unknown"));
    assert!(!is_known_plan("Pro") && !is_known_plan(""));
    assert_eq!(USER_AGENT_ENV, "AGCTL_CODEX_USER_AGENT");
}
