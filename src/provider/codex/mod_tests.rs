//! Plan AC119: the invariants visibility cannot hold on its own, checked by
//! reading the source (the `keychain_write_tests.rs` precedent).
//!
//! Outside `provider::codex` the proof types are unforgeable by privacy, and
//! `scripts/phase3-structural.sh` proves that by compiling planted violations
//! (AC122). *Inside* it, every `pub(super)` constructor is visible to every
//! sibling, so which sibling may call each one is pinned here. Each rule is
//! also run against a planted copy of the tree and must report the plant — a
//! rule that has never been seen to fail proves nothing.
//!
//! Every finding starts with its rule's tag (`R1:` … `R8b:`), and every plant
//! names the tag it must raise, so a plant caught by the wrong rule does not
//! count. The rules that follow a value rather than a spelling (R2s, R6c–R6f,
//! R8, R8b) read the tree through `syn`: `ac119_syntax_tests.rs` parses it and
//! derives the receipt vocabulary, `ac119_receipts_tests.rs` checks every
//! receipt binding.

use std::fs;
use std::path::Path;

use super::*;

#[path = "ac119_receipts_tests.rs"]
mod receipts;
#[path = "ac119_syntax_tests.rs"]
mod syntax;

use syntax::Parsed;

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
            // A symlink could point the scan outside `src/`, or at the same
            // file twice: refused, not followed (round 2, A9). None today.
            let kind = fs::symlink_metadata(&path)
                .unwrap_or_else(|err| panic!("lstat {}: {err}", path.display()))
                .file_type();
            assert!(
                !kind.is_symlink(),
                "{} is a symlink inside src/; the scan refuses it",
                path.display()
            );
            if kind.is_dir() {
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

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Whether `word` occurs in `line` as a whole identifier at `at`.
fn is_word_at(line: &str, at: usize, word: &str) -> bool {
    let before = line[..at].chars().next_back().is_none_or(|c| !is_ident_char(c));
    let after = line[at + word.len()..].chars().next().is_none_or(|c| !is_ident_char(c));
    before && after
}

/// Whether `line` names the path `path` — a call, a `.map(path)`, a
/// function pointer, anything — rather than a longer identifier that starts
/// with it. A path that begins with an identifier must also not continue
/// one (`MyLockedCredentials::new` is not `LockedCredentials::new`).
fn names_path(line: &str, path: &str) -> bool {
    line.match_indices(path).any(|(at, _)| {
        let after = line[at + path.len()..].chars().next().is_none_or(|c| !is_ident_char(c));
        let before = !path.starts_with(is_ident_char)
            || line[..at].chars().next_back().is_none_or(|c| !is_ident_char(c));
        after && before
    })
}

/// The struct-literal (or tuple-constructor) uses of `name` in `line`: the
/// name, an optional generic list, then `{` (or `(` when `tuple`), not in a
/// type position (`struct`, `impl`, `for`, `->`, `enum`).
fn literal_uses(line: &str, name: &str, tuple: bool) -> bool {
    line.match_indices(name).any(|(at, _)| {
        if !is_word_at(line, at, name) {
            return false;
        }
        // A reference type (`-> &'a mut T {`) is a type position too: look
        // through `&`, `mut` and a lifetime before the keyword test.
        let mut prefix = line[..at].trim_end();
        loop {
            let stripped = prefix
                .strip_suffix('&')
                .or_else(|| prefix.strip_suffix("mut").filter(|p| p.ends_with([' ', '&'])))
                .or_else(|| {
                    let tick = prefix.rfind('\'')?;
                    let lifetime = &prefix[tick + 1..];
                    (!lifetime.is_empty() && lifetime.chars().all(is_ident_char))
                        .then(|| &prefix[..tick])
                });
            match stripped {
                Some(rest) => prefix = rest.trim_end(),
                None => break,
            }
        }
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
    let name_end = rest.find(|c: char| !is_ident_char(c)).unwrap_or(rest.len());
    let tail = rest[name_end..].trim_start();
    tail.starts_with('=') || tail.starts_with(':')
}

/// Every AC119 violation in `sources`, one tagged sentence each. `parsed`
/// holds the same files, parsed (the harness re-parses only a planted one).
fn violations(sources: &[Source], parsed: &[&Parsed]) -> Vec<String> {
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
                found.push(format!("R1: {file}:{number}: a `{name}` literal outside {home}"));
            }
        }
    }

    // (2) Pinned PATHS (bead agctl-meqv item 2). A pin spelled as a call —
    // `CodexNamespaceGuard::wrap(` — is blind to the same function passed by
    // name (`.map(CodexNamespaceGuard::wrap)`), so each pin is the path alone,
    // not followed by an identifier character. A definition line (`fn name`)
    // is not a use. R2s (`r2_spelling_violations`) adds the type-qualified
    // pins' three other spellings: through a `use … as` / `type` alias,
    // `<T>::m`, and `Self::m` inside an `impl T`.
    //
    // Residuals, written: a bare-name pin (`from_locked_read`,
    // `write_refresh_body_to`, `resolve_pending_with`, `from_verified`)
    // imported under another name (`use …::write_refresh_body_to as w`); a
    // method pin (`.write_inflight`) called through a trait or a function
    // pointer bound elsewhere; a type-qualified pin spelled through an alias,
    // `<T>::` or `Self::` INSIDE a macro invocation (`vec![G::wrap(g)]`: token
    // streams are opaque to R2s; R2's text still sees the plain spelling
    // there); a glob import is no hole (`use …::T::*` does not compile for a
    // struct).
    let pins: [(&str, &[&str]); 27] = [
        ("from_locked_read", &["src/provider/codex/auth_store.rs"]),
        ("LockedCredentials::new", &["src/provider/codex/credentials.rs"]),
        ("write_refresh_body_to", &["src/provider/codex/oauth.rs"]),
        ("resolve_pending_with", &["src/secret/file_store.rs", "src/provider/codex/auth_store.rs"]),
        ("from_verified", &["src/provider/codex/auth_store.rs"]),
        ("CodexNamespaceGuard::wrap", &["src/provider/codex/lock.rs"]),
        ("PostExitReport::from_child", &["src/provider/codex/login_child.rs"]),
        ("ResendConsent::after_confirmation", &["src/commands/codex/accounts.rs"]),
        ("ResetConsent::after_confirmation", &["src/commands/codex/accounts.rs"]),
        (".write_inflight", &["src/provider/codex/refresh.rs"]),
        (".write_resend", &["src/provider/codex/refresh.rs"]),
        (".clear_inflight", &["src/provider/codex/refresh.rs"]),
        (".mark_interrupted", &["src/provider/codex/refresh.rs"]),
        (".mark_unknown", &["src/provider/codex/refresh.rs"]),
        (".reset_floor", &["src/provider/codex/refresh.rs"]),
        (".settle_inflight", &["src/provider/codex/refresh.rs"]),
        (".record_did_not_help", &["src/provider/codex/refresh.rs"]),
        (".restore_unknown", &["src/provider/codex/refresh.rs"]),
        // The same mutators spelled as associated functions (review S30 F5).
        ("RefreshStateFile::write_inflight", &["src/provider/codex/refresh.rs"]),
        ("RefreshStateFile::write_resend", &["src/provider/codex/refresh.rs"]),
        ("RefreshStateFile::clear_inflight", &["src/provider/codex/refresh.rs"]),
        ("RefreshStateFile::mark_interrupted", &["src/provider/codex/refresh.rs"]),
        ("RefreshStateFile::mark_unknown", &["src/provider/codex/refresh.rs"]),
        ("RefreshStateFile::reset_floor", &["src/provider/codex/refresh.rs"]),
        ("RefreshStateFile::settle_inflight", &["src/provider/codex/refresh.rs"]),
        ("RefreshStateFile::record_did_not_help", &["src/provider/codex/refresh.rs"]),
        ("RefreshStateFile::restore_unknown", &["src/provider/codex/refresh.rs"]),
    ];
    for (file, number, line) in code_lines(sources) {
        for (pattern, allowed) in pins {
            let bare = pattern.rsplit("::").next().unwrap_or(pattern).trim_start_matches('.');
            let definition = line.contains(&format!("fn {bare}"));
            let in_home = pattern == "resolve_pending_with" && file == "src/secret/pending.rs";
            if names_path(line, pattern) && !definition && !in_home && !allowed.contains(&file) {
                found.push(format!("R2: {file}:{number}: `{pattern}` used outside {allowed:?}"));
            }
        }
    }

    found.extend(r2_spelling_violations(parsed, &pins));

    // (2b) The refresh POST's one caller (invariant I26). Claude's client has a
    // function of the same name, so the pin reads Codex trees and any file
    // that names `codex::oauth`. Path-based, like (2).
    let codex_scope = |path: &str| {
        path.starts_with("src/provider/codex/") || path.starts_with("src/commands/codex/")
    };
    for (file, text) in sources.iter().filter(|(path, _)| !is_test_file(path)) {
        if !(codex_scope(file) || text.contains("codex::oauth")) {
            continue;
        }
        for (index, line) in text.lines().enumerate() {
            let code = !line.trim_start().starts_with("//");
            if code && names_path(line, "oauth::refresh") && file != "src/provider/codex/refresh.rs"
            {
                found.push(format!(
                    "R2b: {file}:{}: `oauth::refresh` used outside refresh.rs",
                    index + 1
                ));
            }
        }
    }

    // (3) `SecretFile::open` only in file_store.rs and auth_store.rs, and
    // once in auth_store.rs, where one function binds the descriptor and the
    // displayed path together (review F7).
    let opens: Vec<(&str, usize)> = code_lines(sources)
        .filter(|(_, _, line)| names_path(line, "SecretFile::open"))
        .map(|(file, number, _)| (file, number))
        .collect();
    for (file, number) in &opens {
        if !["src/secret/file_store.rs", "src/provider/codex/auth_store.rs"].contains(file) {
            found.push(format!(
                "R3: {file}:{number}: `SecretFile::open` outside file_store.rs and auth_store.rs"
            ));
        }
    }
    let in_auth_store =
        opens.iter().filter(|(file, _)| *file == "src/provider/codex/auth_store.rs").count();
    if in_auth_store > 1 {
        found.push(format!(
            "R3: src/provider/codex/auth_store.rs: `SecretFile::open` at {in_auth_store} sites, not one"
        ));
    }

    // (4) `AUTH_FILE` is private.
    for (file, number, line) in code_lines(sources) {
        let spelled = line.contains("const AUTH_FILE");
        if spelled && line.trim_start().starts_with("pub") {
            found.push(format!("R4: {file}:{number}: `AUTH_FILE` is not private"));
        }
    }

    // (5) A recorded spelling never reaches a writer or a namespace path.
    // Residual (bead agctl-meqv item D): a same-LINE co-occurrence — a
    // spelling bound on one line and handed to a writer on the next passes.
    let writer_calls =
        ["SecretFile::open", "OwnedNamespace::open", "open_for_install", "codex_namespace_dir"];
    for (file, number, line) in code_lines(sources) {
        if writer_calls.iter().any(|call| names_path(line, call))
            && (line.contains("export_spelling") || line.contains("HomeReadOnly"))
        {
            found.push(format!("R5: {file}:{number}: a recorded path reaches a namespace writer"));
        }
    }

    // (6) A receipt is never discarded with `let _ =` or `let _name =`
    // (invariant I30; review S30 F5): both silence `#[must_use]`. A textual
    // twin of R6c, kept because it does not depend on the parser.
    let receipt_calls =
        [".install(", ".remove_named_files(", ".resolve_pending(", ".write(", ".park("];
    for (file, number, line) in code_lines(sources) {
        let in_codex =
            file.starts_with("src/provider/codex/") || file.starts_with("src/commands/codex/");
        if in_codex
            && is_underscore_binding(line)
            && receipt_calls.iter().any(|call| line.contains(call))
        {
            found.push(format!("R6: {file}:{number}: a write receipt discarded with `let _… =`"));
        }
    }

    // (6b) A receipt is never dropped by a pattern (review S30 LOW-2): a
    // `Landed { .. }`/`ChangedSinceRead { .. }` that does not bind `receipt`,
    // or binds it to `_`, and a `resolve_pending` tuple whose middle element is
    // `_`-prefixed — across lines, for any receiver. A textual twin of R6c's
    // pattern clause.
    //
    // Its former last clause — "a file that takes receipts calls
    // `codex::audit::append` somewhere" — is retired (bead agctl-meqv item A):
    // a second, unaudited receipt in a file that audits a first one passed it.
    // R6c checks every binding instead.
    for (file, text) in sources.iter().filter(|(path, _)| !is_test_file(path)) {
        if file == "src/provider/codex/auth_store.rs" {
            continue;
        }
        // Comment lines are blanked, not dropped, so an offset still maps to
        // its real line (round 2, A9).
        let code: String = text
            .lines()
            .map(|line| if line.trim_start().starts_with("//") { "" } else { line })
            .collect::<Vec<_>>()
            .join("\n");
        let line_at = |offset: usize| code[..offset].matches('\n').count() + 1;
        for variant in ["Landed", "ChangedSinceRead"] {
            let mut rest = code.as_str();
            while let Some(at) = rest.find(variant) {
                let offset = code.len() - rest.len() + at;
                let after = rest[at + variant.len()..].trim_start();
                if let Some(body) = after.strip_prefix('{')
                    && let Some(close) = body.find('}')
                {
                    let fields = &body[..close];
                    let binds = fields.split(',').any(|field| field.trim() == "receipt");
                    if !binds {
                        found.push(format!(
                            "R6b: {file}:{}: a `{variant} {{ .. }}` pattern drops its receipt",
                            line_at(offset)
                        ));
                    }
                }
                rest = &rest[at + variant.len()..];
            }
        }
        let mut rest = code.as_str();
        while let Some(at) = rest.find(".resolve_pending(") {
            let offset = code.len() - rest.len() + at;
            let head = &rest[..at];
            if let Some(open) = head.rfind("let (") {
                let pattern = &head[open + 5..];
                let elements: Vec<&str> =
                    pattern.split(')').next().unwrap_or("").split(',').map(str::trim).collect();
                if elements.get(1).is_some_and(|middle| middle.starts_with('_')) {
                    found.push(format!(
                        "R6b: {file}:{}: a `resolve_pending` receipt bound to `_`",
                        line_at(offset)
                    ));
                }
            }
            rest = &rest[at + 1..];
        }
    }

    // (6c)–(6f) Every receipt BINDING reaches `codex::audit::append`
    // (`ac119_receipts_tests.rs`), with the vocabulary derived from the tree.
    let vocab = syntax::Vocabulary::derive(parsed);
    found.extend(receipts::violations(&vocab, receipts::ALLOW));

    // (7) No test builds a `CodexEnv` from the process (invariant I25).
    for (file, text) in sources.iter().filter(|(path, _)| is_test_file(path)) {
        let needle = format!("CodexEnv::{}", "from_process");
        if let Some(index) = text.lines().position(|line| line.contains(&needle)) {
            found.push(format!(
                "R7: {file}:{}: a test reads the process environment for a Codex home",
                index + 1
            ));
        }
    }

    // (8) A `ScratchSurvey` is built by name in two places only: the survey
    // itself and the testkit (bead agctl-meqv item 3). Test files are read
    // too — a test that builds a spotless survey by hand is the forgery the
    // type exists to prevent. (8b) It has no `Default`, derived or written.
    found.extend(survey_violations(parsed));

    found
}

/// The names a type is spelled by across the tree: itself, every
/// `type X = …T` and every `use …::T as X`, to a fixed point. Keyed by name,
/// like the vocabulary (the safe direction: a same-named type elsewhere is
/// read as this one).
fn spellings(parsed: &[&Parsed], ty: &str) -> std::collections::BTreeSet<String> {
    struct Aliases<'n> {
        names: &'n mut std::collections::BTreeSet<String>,
    }
    impl<'ast> syn::visit::Visit<'ast> for Aliases<'_> {
        fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
            if syntax::type_name(&item.ty).is_some_and(|name| self.names.contains(&name)) {
                self.names.insert(item.ident.to_string());
            }
            syn::visit::visit_item_type(self, item);
        }

        fn visit_use_rename(&mut self, rename: &'ast syn::UseRename) {
            if self.names.contains(&rename.ident.to_string()) {
                self.names.insert(rename.rename.to_string());
            }
            syn::visit::visit_use_rename(self, rename);
        }
    }
    let mut names = std::collections::BTreeSet::from([ty.to_owned()]);
    loop {
        let before = names.len();
        for file in parsed {
            syn::visit::Visit::visit_file(&mut Aliases { names: &mut names }, &file.file);
        }
        if names.len() == before {
            return names;
        }
    }
}

/// The `impl` self types enclosing a visitor's position, innermost last, so
/// `Self` resolves to the INNER one inside a nested `impl`.
#[derive(Default)]
struct SelfTypes(Vec<Option<String>>);

impl SelfTypes {
    /// `name`, with `Self` read as the innermost `impl`'s type.
    fn resolve(&self, name: &str) -> Option<String> {
        if name == "Self" { self.0.last().cloned().flatten() } else { Some(name.to_owned()) }
    }
}

/// Whether a `derive` or a `cfg_attr` (nested to any depth) derives
/// `Default` — `#[cfg_attr(test, derive(Default))]` forges a default as
/// surely as `#[derive(Default)]` (round 2, B1). `defaults` holds every
/// spelling of `Default`, renames included (round 3, B3).
fn derives_default(meta: &syn::Meta, defaults: &std::collections::BTreeSet<String>) -> bool {
    use syn::punctuated::Punctuated;
    let syn::Meta::List(list) = meta else { return false };
    if list.path.is_ident("derive") {
        let paths = list.parse_args_with(Punctuated::<syn::Path, syn::Token![,]>::parse_terminated);
        return paths.is_ok_and(|paths| {
            paths.iter().any(|path| {
                path.segments.last().is_some_and(|seg| defaults.contains(&seg.ident.to_string()))
            })
        });
    }
    if list.path.is_ident("cfg_attr") {
        let metas = list.parse_args_with(Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated);
        // The first element is the predicate; the rest are the attributes.
        return metas
            .is_ok_and(|metas| metas.iter().skip(1).any(|meta| derives_default(meta, defaults)));
    }
    false
}

/// Rules R8 and R8b over every parsed file, test files included.
///
/// A literal is the type's name, any alias of it (round 2, B3), or `Self`
/// inside an `impl` of it (B2). Residual: a macro that expands to a literal
/// is not seen (token streams are opaque).
fn survey_violations(parsed: &[&Parsed]) -> Vec<String> {
    const SURVEY: &str = "ScratchSurvey";
    const HOMES: [&str; 2] =
        ["src/provider/codex/login_child.rs", "src/provider/codex/testkit_tests.rs"];
    struct Survey<'f> {
        file: &'f str,
        names: &'f std::collections::BTreeSet<String>,
        defaults: &'f std::collections::BTreeSet<String>,
        self_types: SelfTypes,
        found: Vec<String>,
    }
    impl Survey<'_> {
        fn names_survey(&self, name: &str) -> bool {
            self.self_types.resolve(name).is_some_and(|name| self.names.contains(&name))
        }
    }
    impl<'ast> syn::visit::Visit<'ast> for Survey<'_> {
        fn visit_expr_struct(&mut self, literal: &'ast syn::ExprStruct) {
            if let Some(last) = literal.path.segments.last()
                && self.names_survey(&last.ident.to_string())
                && !HOMES.contains(&self.file)
            {
                self.found.push(format!(
                    "R8: {}:{}: a `{SURVEY}` literal (spelled `{}`) outside {HOMES:?}",
                    self.file,
                    syntax::line(last.ident.span()),
                    last.ident
                ));
            }
            syn::visit::visit_expr_struct(self, literal);
        }

        fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
            if self.names.contains(&item.ident.to_string())
                && item.attrs.iter().any(|attr| derives_default(&attr.meta, self.defaults))
            {
                self.found.push(format!(
                    "R8b: {}:{}: `{SURVEY}` derives `Default`",
                    self.file,
                    syntax::line(item.ident.span())
                ));
            }
            syn::visit::visit_item_struct(self, item);
        }

        fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
            let self_type = syntax::type_name(&item.self_ty);
            let for_survey = self_type.as_deref().is_some_and(|name| self.names.contains(name));
            let is_default = item
                .trait_
                .as_ref()
                .and_then(|(path, _)| path.segments.last())
                .is_some_and(|seg| self.defaults.contains(&seg.ident.to_string()));
            if for_survey && is_default {
                self.found.push(format!(
                    "R8b: {}:{}: `{SURVEY}` implements `Default`",
                    self.file,
                    syntax::line(item.impl_token.span)
                ));
            }
            self.self_types.0.push(self_type);
            syn::visit::visit_item_impl(self, item);
            self.self_types.0.pop();
        }
    }
    let names = spellings(parsed, SURVEY);
    let defaults = spellings(parsed, "Default");
    let mut found = Vec::new();
    for file in parsed {
        let mut survey = Survey {
            file: &file.path,
            names: &names,
            defaults: &defaults,
            self_types: SelfTypes::default(),
            found: Vec::new(),
        };
        syn::visit::Visit::visit_file(&mut survey, &file.file);
        found.extend(survey.found);
    }
    found
}

/// R2s: the type-qualified pins of R2, in the three spellings a text rule
/// cannot see (round 2, B4): through an alias (`use …::T as G; G::m`),
/// through a qualified self (`<T>::m`), and as `Self::m` inside an `impl T`.
/// The plain `T::m` spelling is R2's. Non-test files only, like R2.
fn r2_spelling_violations(parsed: &[&Parsed], pins: &[(&str, &[&str])]) -> Vec<String> {
    struct Spelled<'f> {
        file: &'f str,
        pins: &'f [(String, String, Vec<String>, std::collections::BTreeSet<String>)],
        self_types: SelfTypes,
        found: Vec<String>,
    }
    impl<'ast> syn::visit::Visit<'ast> for Spelled<'_> {
        fn visit_expr_path(&mut self, expr: &'ast syn::ExprPath) {
            let segments: Vec<String> =
                expr.path.segments.iter().map(|seg| seg.ident.to_string()).collect();
            let (owner, method, how) = match (&expr.qself, segments.as_slice()) {
                (Some(qself), [.., method]) if qself.position == 0 => {
                    (syntax::type_name(&qself.ty), method.clone(), "`<T>::`")
                }
                (None, [.., owner, method]) => {
                    let resolved = self.self_types.resolve(owner);
                    let how = if owner == "Self" { "`Self::`" } else { "an alias" };
                    (resolved, method.clone(), how)
                }
                _ => (None, String::new(), ""),
            };
            if let Some(owner) = owner {
                for (ty, pinned, allowed, spellings) in self.pins {
                    let literal = segments.len() >= 2 && segments[segments.len() - 2] == *ty;
                    if *pinned == method
                        && spellings.contains(&owner)
                        && !(literal && expr.qself.is_none())
                        && !allowed.iter().any(|home| home == self.file)
                    {
                        self.found.push(format!(
                            "R2s: {}:{}: `{ty}::{pinned}` spelled through {how} outside {allowed:?}",
                            self.file,
                            expr.path.segments.last().map_or(0, |seg| syntax::line(seg.ident.span()))
                        ));
                    }
                }
            }
            syn::visit::visit_expr_path(self, expr);
        }

        fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
            self.self_types.0.push(syntax::type_name(&item.self_ty));
            syn::visit::visit_item_impl(self, item);
            self.self_types.0.pop();
        }
    }
    let typed: Vec<(String, String, Vec<String>, std::collections::BTreeSet<String>)> = pins
        .iter()
        .filter_map(|(pin, allowed)| {
            let (ty, method) = pin.split_once("::")?;
            ty.starts_with(|c: char| c.is_ascii_uppercase()).then(|| {
                let allowed = allowed.iter().map(|home| (*home).to_owned()).collect();
                (ty.to_owned(), method.to_owned(), allowed, spellings(parsed, ty))
            })
        })
        .collect();
    let mut found = Vec::new();
    for file in parsed.iter().filter(|file| !is_test_file(&file.path)) {
        let mut spelled = Spelled {
            file: &file.path,
            pins: &typed,
            self_types: SelfTypes::default(),
            found: Vec::new(),
        };
        syn::visit::Visit::visit_file(&mut spelled, &file.file);
        found.extend(spelled.found);
    }
    found
}

/// The tree, and the tree parsed.
fn parsed_tree() -> (Vec<Source>, Vec<Parsed>) {
    let sources = tree();
    let parsed = syntax::parse(&sources);
    (sources, parsed)
}

#[test]
fn the_tree_satisfies_every_ac119_rule() {
    let (tree, parsed) = parsed_tree();
    let refs: Vec<&Parsed> = parsed.iter().collect();
    let found = violations(&tree, &refs);
    assert!(found.is_empty(), "AC119 violations:\n{}", found.join("\n"));
    // The consumer rule is not vacuous: the refresh driver takes receipts.
    let refresh = tree
        .iter()
        .find(|(path, _)| path == "src/provider/codex/refresh.rs")
        .map(|(_, text)| text.as_str())
        .unwrap_or_default();
    assert!(
        refresh.contains("audit::append(") && refresh.contains("Landed {"),
        "refresh.rs audits its receipts"
    );
}

/// The vocabulary R6c derives must CONTAIN every producer and carrier known
/// today. This list is a floor, not the vocabulary: the rule reads the
/// derived set, so a producer added tomorrow is checked with no edit here.
#[test]
fn the_derived_vocabulary_contains_every_known_producer() {
    let (_, parsed) = parsed_tree();
    let refs: Vec<&Parsed> = parsed.iter().collect();
    let vocab = syntax::Vocabulary::derive(&refs);
    for carrier in ["WriteReceipt", "CodexWrite"] {
        assert!(vocab.carriers.contains(carrier), "`{carrier}` is not a derived carrier");
    }
    let producers: std::collections::BTreeSet<(String, String)> = vocab
        .fns
        .iter()
        .filter(|def| vocab.is_producer(def))
        .map(|def| (def.owner.clone(), def.name()))
        .collect();
    let floor = [
        ("OwnedNamespace", "write"),
        ("OwnedNamespace", "park"),
        ("OwnedNamespace", "resolve_pending"),
        ("OwnedNamespace", "remove_named_files"),
        ("InstallNamespace", "install"),
    ];
    for (owner, name) in floor {
        assert!(
            producers.contains(&(owner.to_owned(), name.to_owned())),
            "`{owner}::{name}` is not a derived producer; derived: {producers:?}"
        );
    }
    // The name-alike functions that must NOT resolve as producers at their
    // real call sites (arity and qualifier decide, never a list).
    let calls = [
        ("SecretFile::write, 4 arguments", vocab.method_producers("write", 4).len()),
        ("OpenOptions::write, 1 argument", vocab.method_producers("write", 1).len()),
        ("SecretFile::park, 3 arguments", vocab.method_producers("park", 3).len()),
        ("signals::install(cancel)", vocab.path_producers(&path("signals::install"), 1).len()),
        (
            "file_store::resolve_pending(dir, activity)",
            vocab.path_producers(&path("file_store::resolve_pending"), 2).len(),
        ),
        ("std::fs::write(path, blob)", vocab.path_producers(&path("std::fs::write"), 2).len()),
    ];
    for (call, resolved) in calls {
        assert_eq!(resolved, 0, "{call} resolved to a receipt producer");
    }
    // And the real ones do.
    assert_eq!(vocab.method_producers("install", 1).len(), 1, "`.install(fault)`");
    assert_eq!(vocab.method_producers("write", 2).len(), 1, "`.write(&merged, fault)`");
}

/// A path parsed from its spelling.
fn path(spelled: &str) -> syn::Path {
    syn::parse_str(spelled).unwrap_or_else(|err| panic!("{spelled}: {err}"))
}

/// R6c is not vacuous: on the real tree it follows every receipt binding
/// known today, and nothing it follows is reported.
#[test]
fn the_receipt_rule_follows_every_real_receipt_binding() {
    let (_, parsed) = parsed_tree();
    let refs: Vec<&Parsed> = parsed.iter().collect();
    let vocab = syntax::Vocabulary::derive(&refs);
    let receipts::Census { followed, exit_checked } = receipts::census(&vocab);
    // Site → how many bindings of that name it holds: `drive` binds the
    // tuple's `receipt` and then the `Some(receipt)` inside it; `applied`
    // has four arms (write and park, each `Landed` and `ChangedSinceRead`).
    // Site → (bindings visited, statement scans run). `drive:resolved` is a
    // single-expression arm (`Ok(resolved) => resolved`): nothing stands
    // before its use, so no statement scan runs there.
    let known = [
        ("src/commands/codex/login.rs:install_verified:receipt", 1, 1),
        ("src/provider/codex/auth_store.rs:install:receipt", 1, 1),
        ("src/provider/codex/refresh.rs:drive:resolved", 1, 0),
        ("src/provider/codex/refresh.rs:drive:receipt", 2, 2),
        ("src/provider/codex/refresh.rs:applied:receipt", 4, 4),
    ];
    // A floor, not an exact count (round-2 ruling A7). Visiting a site is
    // not checking it: the second list is pushed ONLY where the statement
    // scan (R6e) runs — round 1 visited four `match` arms and checked none.
    for (site, visits, scans) in known {
        let visited = followed.iter().filter(|f| *f == site).count();
        let checked = exit_checked.iter().filter(|f| *f == site).count();
        assert!(
            visited >= visits && checked >= scans,
            "`{site}`: visited {visited}×, R6e ran {checked}×, expected {visits}/{scans}; \
             followed: {followed:#?}; checked: {exit_checked:#?}"
        );
    }
}

/// R6f's own positive control: a row that matches nothing is reported.
#[test]
fn a_stale_allow_row_is_reported() {
    let (_, parsed) = parsed_tree();
    let refs: Vec<&Parsed> = parsed.iter().collect();
    let vocab = syntax::Vocabulary::derive(&refs);
    assert!(receipts::violations(&vocab, receipts::ALLOW).is_empty(), "the tree is clean");
    let stale = [("src/commands/codex/login.rs", "install_verified", "gone", "a test row")];
    let found = receipts::violations(&vocab, &stale);
    assert!(
        found.iter().any(|line| line.starts_with("R6f: ") && line.contains("`gone`")),
        "a stale row was not reported: {found:?}"
    );
    // A row with no reason is refused even when it matches (round 2, A6).
    let tree = tree();
    let dropped = planted(
        &tree,
        "src/commands/codex/login.rs",
        &Edit::Replace("        audit::append(paths, receipt)?;\n", ""),
    );
    let replanted: Vec<Parsed> = syntax::parse(&dropped);
    let refs: Vec<&Parsed> = replanted.iter().collect();
    let vocab = syntax::Vocabulary::derive(&refs);
    let blank = [("src/commands/codex/login.rs", "install_verified", "receipt", "  ")];
    let found = receipts::violations(&vocab, &blank);
    assert!(
        found.iter().any(|line| line.starts_with("R6f: ") && line.contains("has no reason")),
        "a row with a blank reason was accepted: {found:?}"
    );
}

/// A `ref` binding of a receipt is reported as a DROP, not merely as a
/// receipt that never reaches the audit: the borrow ends with the scope and
/// the owned receipt with it (round 3, A1 / K-a). The plant table's tag alone
/// cannot tell the two apart, so the message is asserted here.
#[test]
fn a_ref_binding_of_a_receipt_is_a_drop() {
    let (base, base_parsed) = parsed_tree();
    let file = "src/commands/codex/login.rs";
    let sources = planted(
        &base,
        file,
        &Edit::Append(
            "fn p(i: InstallNamespace<'_>, f: &Fault) -> Result<WriteKind, FileStoreError> {\n    let ref got = i.install(f)?;\n    Ok(got.0.kind())\n}",
        ),
    );
    let replanted =
        sources.iter().find(|(path, _)| path == file).map(syntax::parse_one).expect("planted");
    let parsed: Vec<&Parsed> = base_parsed
        .iter()
        .map(|parsed| if parsed.path == file { &replanted } else { parsed })
        .collect();
    let found = violations(&sources, &parsed);
    assert!(
        found.iter().any(
            |line| line.starts_with("R6c: ") && line.contains("binds it by reference as `got`")
        ),
        "a `ref` binding was not reported as a drop: {found:?}"
    );
}

/// How a plant changes a real file.
enum Edit {
    /// Appends one item (or several) at the end of the file.
    Append(&'static str),
    /// Replaces exactly one occurrence of the first text with the second.
    Replace(&'static str, &'static str),
}

/// A copy of `base` with `edit` applied to `file`, which must exist: a plant
/// proves a rule only against a file that already has legitimate content.
fn planted(base: &[Source], file: &str, edit: &Edit) -> Vec<Source> {
    let mut sources = base.to_vec();
    let Some((_, text)) = sources.iter_mut().find(|(path, _)| path == file) else {
        panic!("the plant target {file} does not exist: a plant must go INTO a real file");
    };
    match edit {
        Edit::Append(item) => {
            text.push('\n');
            text.push_str(item);
            text.push('\n');
        }
        Edit::Replace(old, new) => {
            let count = text.matches(old).count();
            assert_eq!(
                count, 1,
                "the plant's anchor in {file} matched {count} times, expected exactly once"
            );
            *text = text.replacen(old, new, 1);
        }
    }
    sources
}

#[test]
fn the_plant_harness_refuses_a_missing_target() {
    let result = std::panic::catch_unwind(|| {
        planted(&tree(), "src/provider/codex/no_such_file.rs", &Edit::Append("fn p() {}"))
    });
    assert!(result.is_err(), "a plant into a file that does not exist was accepted");
}

#[test]
fn every_rule_reports_its_plant() {
    // Includes the plan's named plant: a `from_locked_read` call in
    // `provider/codex/discovery.rs`, which compiles and must fail this test.
    let (base, base_parsed) = parsed_tree();
    let plants: [(&str, &str, &str, Edit); 69] = [
        (
            "discovery from_locked_read",
            "R2",
            "src/provider/codex/discovery.rs",
            Edit::Append(
                "fn p(c: Credentials, g: &CodexNamespaceGuard) -> LockedCredentials<'_> { LockedCredentials::from_locked_read(c, g) }",
            ),
        ),
        (
            "rustfmt-shaped call",
            "R2",
            "src/provider/codex/discovery.rs",
            Edit::Append("fn p(c: C, g: G) -> L {\n    from_locked_read(\n        c, g,\n    )\n}"),
        ),
        (
            "OwnedRecord literal",
            "R1",
            "src/provider/codex/discovery.rs",
            Edit::Append(
                "fn p() {\n    let r = OwnedRecord { user, acct, export_spelling: None, refresh };\n}",
            ),
        ),
        (
            "guard tuple",
            "R1",
            "src/provider/codex/usage.rs",
            Edit::Append("fn p() {\n    let g = CodexNamespaceGuard(inner);\n}"),
        ),
        (
            "inflight literal",
            "R1",
            "src/provider/codex/refresh.rs",
            Edit::Append(
                "fn p() {\n    let t = InflightToken { digest8, _guard: PhantomData };\n}",
            ),
        ),
        (
            "generic literal",
            "R1",
            "src/provider/codex/refresh.rs",
            Edit::Append(
                "fn p() -> L {\n    LockedCredentials::<'g> { inner, _guard: PhantomData }\n}",
            ),
        ),
        (
            "receipt literal",
            "R1",
            "src/provider/codex/audit.rs",
            Edit::Append("fn p(receipt: R) {\n    let WriteReceipt { kind, .. } = receipt;\n}"),
        ),
        (
            "private new",
            "R2",
            "src/provider/codex/refresh.rs",
            Edit::Append("fn p() {\n    let c = LockedCredentials::new(inner);\n}"),
        ),
        (
            "marker from commands",
            "R2",
            "src/commands/codex/status.rs",
            Edit::Append(
                "fn p() -> R {\n    ns.refresh_state().clear_inflight(DefiniteOutcome::Applied)?;\n}",
            ),
        ),
        (
            "marker from discovery",
            "R2",
            "src/provider/codex/discovery.rs",
            Edit::Append("fn p() -> R {\n    state.write_inflight(&c)?;\n}"),
        ),
        (
            "wrap outside lock.rs",
            "R2",
            "src/provider/codex/auth_store.rs",
            Edit::Append("fn p() {\n    let g = CodexNamespaceGuard::wrap(inner);\n}"),
        ),
        (
            // Bead agctl-meqv item 2: the pin is the PATH, so passing the
            // function by name is caught like calling it.
            "wrap passed by name",
            "R2",
            "src/provider/codex/auth_store.rs",
            Edit::Append(
                "fn p(g: Option<NamespaceLockGuard>) -> Option<CodexNamespaceGuard> {\n    g.map(CodexNamespaceGuard::wrap)\n}",
            ),
        ),
        (
            "marker mutator passed by name",
            "R2",
            "src/provider/codex/discovery.rs",
            Edit::Append("fn p() {\n    let f = RefreshStateFile::clear_inflight;\n}"),
        ),
        (
            "consent outside accounts",
            "R2",
            "src/commands/codex/status.rs",
            Edit::Append(
                "fn p() -> R {\n    let c = ResendConsent::after_confirmation(\"yes\", true, false)?;\n}",
            ),
        ),
        (
            "second SecretFile::open",
            "R3",
            "src/provider/codex/auth_store.rs",
            Edit::Append("fn p() {\n    let f = SecretFile::open(&root, fd, name, &shown);\n}"),
        ),
        (
            "public AUTH_FILE",
            "R4",
            "src/provider/codex/auth_store.rs",
            Edit::Append("pub(crate) const AUTH_FILE: &str = \"auth.json\";"),
        ),
        (
            "export spelling to a writer",
            "R5",
            "src/commands/codex/login.rs",
            Edit::Append(
                "fn p() -> R {\n    let d = paths.codex_namespace_dir(export_spelling, acct)?;\n}",
            ),
        ),
        (
            "discarded receipt",
            "R6",
            "src/commands/codex/login.rs",
            Edit::Append("fn p() {\n    let _ = ns.install(&fault);\n}"),
        ),
        (
            "named discard",
            "R6",
            "src/commands/codex/login.rs",
            Edit::Append("fn p() -> R {\n    let _receipt = install.install(&fault)?;\n}"),
        ),
        (
            "UFCS marker clear",
            "R2",
            "src/provider/codex/discovery.rs",
            Edit::Append(
                "fn p() -> R {\n    RefreshStateFile::clear_inflight(&state, DefiniteOutcome::Applied)?;\n}",
            ),
        ),
        (
            "UFCS marker arm",
            "R2",
            "src/provider/codex/usage.rs",
            Edit::Append(
                "fn p() -> R {\n    let t = RefreshStateFile::write_inflight(state, &c)?;\n}",
            ),
        ),
        (
            "settle from discovery",
            "R2",
            "src/provider/codex/discovery.rs",
            Edit::Append(
                "fn p() -> R {\n    state.settle_inflight(DefiniteOutcome::Applied, Settled::default())?;\n}",
            ),
        ),
        (
            "oauth::refresh from discovery",
            "R2b",
            "src/provider/codex/discovery.rs",
            Edit::Append("fn p() {\n    let o = oauth::refresh(&c, token, &client, &cancel);\n}"),
        ),
        (
            "oauth::refresh via an import outside codex",
            "R2b",
            "src/commands/status.rs",
            Edit::Append(
                "use crate::provider::codex::oauth;\nfn p() { let _ = oauth::refresh(c, t, r, x); }",
            ),
        ),
        (
            "Landed with ..",
            "R6b",
            "src/provider/codex/refresh.rs",
            Edit::Append(
                "fn p(w: CodexWrite) { if let CodexWrite::Landed {\n    outcome, ..\n} = w {} }",
            ),
        ),
        (
            "ChangedSinceRead receipt: _",
            "R6b",
            "src/provider/codex/refresh.rs",
            Edit::Append(
                "fn p(w: CodexWrite) { if let CodexWrite::ChangedSinceRead { receipt: _ } = w {} }",
            ),
        ),
        (
            "resolve_pending tuple",
            "R6b",
            "src/provider/codex/refresh.rs",
            Edit::Append(
                "fn p() -> R {\n    let (decision,\n        _receipt, evidence) = owned.resolve_pending(&cancel)?;\n}",
            ),
        ),
        (
            // Kept from before: the simple shape, a receipt dropped in a file
            // that never writes (`watch.rs`, U44 = 5).
            "receipts taken, never audited",
            "R6c",
            "src/commands/codex/watch.rs",
            Edit::Append(
                "fn p(w: CodexWrite) { if let CodexWrite::Landed { outcome, receipt } = w { drop(receipt) } }",
            ),
        ),
        (
            // Bead agctl-meqv item C: a SECOND receipt, dropped, in the real
            // `login.rs`, whose own receipt is audited. The retired
            // file-level clause passed exactly this.
            "second receipt dropped beside an audited one",
            "R6c",
            "src/commands/codex/login.rs",
            Edit::Append(
                "fn p(install: InstallNamespace<'_>, fault: &Fault) -> Result<(), AppError> {\n    let (receipt, _) = install.install(fault).map_err(refused)?;\n    drop(receipt);\n    Ok(())\n}",
            ),
        ),
        (
            // The same file with its own audit removed: the receipt reaches
            // nothing (round-1 mutant M1 of C1, now caught by a source rule).
            "login.rs with its audit removed",
            "R6c",
            "src/commands/codex/login.rs",
            Edit::Replace("        audit::append(paths, receipt)?;\n", ""),
        ),
        (
            "let _ = <producer> (derived)",
            "R6c",
            "src/commands/codex/login.rs",
            Edit::Append(
                "fn p(i: InstallNamespace<'_>, f: &Fault) {\n    let _ = i.install(f);\n}",
            ),
        ),
        (
            "a producer passed to drop",
            "R6d",
            "src/commands/codex/login.rs",
            Edit::Append(
                "fn p(i: InstallNamespace<'_>, f: &Fault) -> R {\n    drop(i.install(f)?);\n}",
            ),
        ),
        (
            "a producer's result tested and dropped",
            "R6d",
            "src/provider/codex/refresh.rs",
            Edit::Append(
                "fn p(ns: &OwnedNamespace<'_>, m: &M, f: &Fault) -> bool {\n    ns.write(m, f).is_ok()\n}",
            ),
        ),
        (
            "a NEW producer whose caller drops the receipt",
            "R6c",
            "src/commands/codex/login.rs",
            Edit::Append(
                "fn plant_new_producer() -> Result<WriteReceipt, AppError> {\n    todo!()\n}\nfn p() {\n    let fresh = plant_new_producer();\n    let _unrelated = 1;\n}",
            ),
        ),
        (
            "a helper returns a receipt; its caller drops it",
            "R6c",
            "src/commands/codex/login.rs",
            Edit::Append(
                "fn plant_helper(i: InstallNamespace<'_>, f: &Fault) -> Result<WriteReceipt, FileStoreError> {\n    let (r, _) = i.install(f)?;\n    Ok(r)\n}\nfn p(i: InstallNamespace<'_>, f: &Fault) -> Result<(), FileStoreError> {\n    let got = plant_helper(i, f)?;\n    drop(got);\n    Ok(())\n}",
            ),
        ),
        (
            // A carrier two levels deep, named to sort BEFORE `CodexWrite`:
            // the vocabulary's fixed point needs a second pass to see it, so
            // a single-pass derivation misses the producer and its caller.
            "a two-level carrier's producer, dropped",
            "R6c",
            "src/commands/codex/login.rs",
            Edit::Append(
                "struct AaHolder {\n    write: Option<CodexWrite>,\n}\nfn plant_holder() -> AaHolder {\n    todo!()\n}\nfn p() {\n    let held = plant_holder();\n    drop(held);\n}",
            ),
        ),
        (
            "a consumer that drops what it takes",
            "R6c",
            "src/commands/codex/login.rs",
            Edit::Append("fn plant_consumer(r: WriteReceipt) {\n    let _kind = r.kind();\n}"),
        ),
        (
            "an early exit between the receipt and its audit",
            "R6e",
            "src/commands/codex/login.rs",
            Edit::Append(
                "fn p(i: InstallNamespace<'_>, f: &Fault, paths: &Paths) -> Result<(), AppError> {\n    let (r, _) = i.install(f).map_err(refused)?;\n    step()?;\n    audit::append(paths, r)?;\n    Ok(())\n}",
            ),
        ),
        (
            // Round 2, A1: R6e INSIDE a real `match` arm of `applied`.
            "an early exit inside a real CodexWrite arm",
            "R6e",
            "src/provider/codex/refresh.rs",
            Edit::Replace(
                "            Ok(CodexWrite::Landed { receipt, .. }) => {\n                self.audited(",
                "            Ok(CodexWrite::Landed { receipt, .. }) => {\n                if notes.is_empty() {\n                    return self.unknown(grant, UnknownClass::WriteFailed, None, notes);\n                }\n                self.audited(",
            ),
        ),
        (
            // Round 2, A5: `?` in another argument of the auditing call.
            "an early exit inside the auditing call's arguments",
            "R6e",
            "src/commands/codex/login.rs",
            Edit::Replace(
                "        audit::append(paths, receipt)?;\n",
                "        audit::append(plant_paths(paths)?, receipt)?;\n",
            ),
        ),
        (
            // Round 2, A2: a receipt moved into a tuple binding.
            "a receipt moved into a tuple, then dropped",
            "R6c",
            "src/commands/codex/login.rs",
            Edit::Replace(
                "        audit::append(paths, receipt)?;\n",
                "        let pair = (receipt, kind);\n        let _ = pair.1;\n",
            ),
        ),
        (
            "a receipt moved into an array, then dropped",
            "R6c",
            "src/commands/codex/login.rs",
            Edit::Replace(
                "        audit::append(paths, receipt)?;\n",
                "        let held = [receipt];\n",
            ),
        ),
        (
            // Round 2, A4 (a) twin: the field that holds the receipt is never audited.
            "a carrier whose receipt field is never audited",
            "R6c",
            "src/commands/codex/login.rs",
            Edit::Append(
                "struct PlantGot {\n    receipt: WriteReceipt,\n    n: u8,\n}\nfn plant_make() -> PlantGot {\n    todo!()\n}\nfn p() -> u8 {\n    let got = plant_make();\n    got.n\n}",
            ),
        ),
        (
            // Round 3, A1: a collection of receipts is unsupported. Bound
            // and iterated, the binding is reported (R6c) ...
            "a Vec of receipts bound and iterated",
            "R6c",
            "src/commands/codex/login.rs",
            Edit::Append(
                "fn plant_all() -> Vec<WriteReceipt> {\n    Vec::new()\n}\nfn p(paths: &Paths) -> Result<(), AppError> {\n    let all = plant_all();\n    for receipt in all {\n        audit::append(paths, receipt)?;\n        break;\n    }\n    Ok(())\n}",
            ),
        ),
        (
            // ... and iterated straight from the producer, it is lost (R6d).
            "a producer's Vec iterated directly",
            "R6d",
            "src/commands/codex/login.rs",
            Edit::Append(
                "fn plant_all() -> Vec<WriteReceipt> {\n    Vec::new()\n}\nfn p(paths: &Paths) -> Result<(), AppError> {\n    for receipt in plant_all() {\n        audit::append(paths, receipt)?;\n    }\n    Ok(())\n}",
            ),
        ),
        (
            "a Vec of receipts iterated by reference",
            "R6c",
            "src/commands/codex/login.rs",
            Edit::Append(
                "fn plant_all() -> Vec<WriteReceipt> {\n    Vec::new()\n}\nfn p() {\n    let all = plant_all();\n    for ref r in all {\n        let _k = r.kind();\n    }\n}",
            ),
        ),
        (
            // Round 3, A1 (K-a): a `ref` binding keeps a borrow and drops the receipt.
            "a receipt bound by reference",
            "R6c",
            "src/commands/codex/login.rs",
            Edit::Append(
                "fn p(i: InstallNamespace<'_>, f: &Fault) -> Result<WriteKind, FileStoreError> {\n    let ref got = i.install(f)?;\n    Ok(got.0.kind())\n}",
            ),
        ),
        (
            // Round 3, A2: an exit in a real arm's GUARD.
            "an early exit in a real CodexWrite arm's guard",
            "R6e",
            "src/provider/codex/refresh.rs",
            Edit::Replace(
                "            Ok(CodexWrite::Landed { receipt, .. }) => {\n",
                "            Ok(CodexWrite::Landed { receipt, .. }) if plant_guard()? => {\n",
            ),
        ),
        (
            // Round 3, A3: a `&mut` getter to a carrier stays a producer.
            "a receipt taken out through a &mut getter",
            "R6d",
            "src/commands/codex/login.rs",
            Edit::Append(
                "struct PlantSlot {\n    s: Option<WriteReceipt>,\n}\nimpl PlantSlot {\n    fn slot(&mut self) -> &mut Option<WriteReceipt> {\n        &mut self.s\n    }\n}\nfn p(h: &mut PlantSlot) {\n    let r = h.slot().take();\n    drop(r);\n}",
            ),
        ),
        (
            // Round 3, B2: an alias of an alias, the first link declared
            // BEFORE the name it points at — `spellings()` needs two passes.
            "a ScratchSurvey literal through a two-link alias chain",
            "R8",
            "src/provider/codex/refresh.rs",
            Edit::Append(
                "type PlantSb = PlantSa;\ntype PlantSa = proof::ScratchSurvey;\nfn p() -> PlantSb {\n    PlantSb { daemon_dir: false, held_locks: Vec::new(), odd_locks: Vec::new(), truncated: false }\n}",
            ),
        ),
        (
            "wrap through a two-link alias chain",
            "R2s",
            "src/provider/codex/auth_store.rs",
            Edit::Append(
                "type PlantH = PlantG;\nuse crate::provider::codex::proof::CodexNamespaceGuard as PlantG;\nfn p(g: NamespaceLockGuard) -> PlantH {\n    PlantH::wrap(g)\n}",
            ),
        ),
        (
            // Round 3, B3: a renamed `Default`, derived and implemented.
            "ScratchSurvey derives a renamed Default",
            "R8b",
            "src/provider/codex/proof.rs",
            Edit::Replace(
                "#[derive(Debug)]\npub struct ScratchSurvey {",
                "use core::default::Default as PlantD;\n#[derive(Debug, PlantD)]\npub struct ScratchSurvey {",
            ),
        ),
        (
            "ScratchSurvey implements a renamed Default",
            "R8b",
            "src/provider/codex/refresh.rs",
            Edit::Append(
                "use core::default::Default as PlantD2;\nimpl PlantD2 for proof::ScratchSurvey {\n    fn default() -> Self {\n        todo!()\n    }\n}",
            ),
        ),
        (
            // Round 2, A8: a receipt through a `use … as` rename.
            "a renamed receipt type, dropped",
            "R6c",
            "src/commands/codex/login.rs",
            Edit::Append(
                "use crate::provider::codex::auth_store::WriteReceipt as PlantWr;\nfn plant_mk() -> PlantWr {\n    todo!()\n}\nfn p() {\n    let fresh = plant_mk();\n    drop(fresh);\n}",
            ),
        ),
        (
            // Round 2, B1: `Default` derived behind `cfg_attr`.
            "ScratchSurvey derives Default behind cfg_attr",
            "R8b",
            "src/provider/codex/proof.rs",
            Edit::Replace(
                "#[derive(Debug)]\npub struct ScratchSurvey {",
                "#[derive(Debug)]\n#[cfg_attr(feature = \"testing\", derive(Default))]\npub struct ScratchSurvey {",
            ),
        ),
        (
            "ScratchSurvey derives Default behind a nested cfg_attr",
            "R8b",
            "src/provider/codex/proof.rs",
            Edit::Replace(
                "#[derive(Debug)]\npub struct ScratchSurvey {",
                "#[derive(Debug)]\n#[cfg_attr(test, cfg_attr(unix, derive(core::default::Default)))]\npub struct ScratchSurvey {",
            ),
        ),
        (
            // Round 2, B2: a second constructor through `Self { … }`.
            "a Self literal inside impl ScratchSurvey",
            "R8",
            "src/provider/codex/proof.rs",
            Edit::Append(
                "impl ScratchSurvey {\n    pub(super) fn spotless() -> Self {\n        Self { daemon_dir: false, held_locks: Vec::new(), odd_locks: Vec::new(), truncated: false }\n    }\n}",
            ),
        ),
        (
            "a Self literal inside impl proof::ScratchSurvey elsewhere",
            "R8",
            "src/provider/codex/refresh.rs",
            Edit::Append(
                "impl proof::ScratchSurvey {\n    fn spotless() -> Self {\n        Self { daemon_dir: false, held_locks: Vec::new(), odd_locks: Vec::new(), truncated: false }\n    }\n}",
            ),
        ),
        (
            "a nested impl ScratchSurvey inside another impl",
            "R8",
            "src/provider/codex/refresh.rs",
            Edit::Append(
                "struct PlantOuter;\nimpl PlantOuter {\n    fn p() {\n        impl proof::ScratchSurvey {\n            fn spotless() -> Self {\n                Self { daemon_dir: false, held_locks: Vec::new(), odd_locks: Vec::new(), truncated: false }\n            }\n        }\n    }\n}",
            ),
        ),
        (
            // Round 2, B3: aliases of the type.
            "a ScratchSurvey literal through a type alias",
            "R8",
            "src/provider/codex/refresh.rs",
            Edit::Append(
                "type PlantSv = proof::ScratchSurvey;\nfn p() -> PlantSv {\n    PlantSv { daemon_dir: false, held_locks: Vec::new(), odd_locks: Vec::new(), truncated: false }\n}",
            ),
        ),
        (
            "a ScratchSurvey literal through a use rename",
            "R8",
            "src/provider/codex/refresh.rs",
            Edit::Append(
                "use crate::provider::codex::proof::ScratchSurvey as PlantSv2;\nfn p() -> PlantSv2 {\n    PlantSv2 { daemon_dir: false, held_locks: Vec::new(), odd_locks: Vec::new(), truncated: false }\n}",
            ),
        ),
        (
            // Round 2, B4: three spellings of a pinned path R2's text misses.
            "wrap through a use rename",
            "R2s",
            "src/provider/codex/auth_store.rs",
            Edit::Append(
                "use crate::provider::codex::proof::CodexNamespaceGuard as PlantG;\nfn p(g: NamespaceLockGuard) -> PlantG {\n    PlantG::wrap(g)\n}",
            ),
        ),
        (
            "wrap through a qualified self",
            "R2s",
            "src/provider/codex/auth_store.rs",
            Edit::Append(
                "fn p(g: NamespaceLockGuard) -> CodexNamespaceGuard {\n    <CodexNamespaceGuard>::wrap(g)\n}",
            ),
        ),
        (
            "wrap through Self inside impl CodexNamespaceGuard",
            "R2s",
            "src/provider/codex/proof.rs",
            Edit::Append(
                "impl CodexNamespaceGuard {\n    fn plant(g: NamespaceLockGuard) -> Self {\n        Self::wrap(g)\n    }\n}",
            ),
        ),
        (
            "park receipt discarded",
            "R6",
            "src/provider/codex/refresh.rs",
            Edit::Append("fn p() {\n    let _ = self.ns.park(&merged, fault);\n}"),
        ),
        (
            "from_process in a test",
            "R7",
            "src/commands/codex/status_tests.rs",
            Edit::Append("fn p() {\n    let env = CodexEnv::from_\u{70}rocess();\n}"),
        ),
        (
            "ScratchSurvey literal in a command",
            "R8",
            "src/commands/codex/login.rs",
            Edit::Append(
                "fn p() -> ScratchSurvey {\n    ScratchSurvey { daemon_dir: false, held_locks: Vec::new(), odd_locks: Vec::new(), truncated: false }\n}",
            ),
        ),
        (
            "ScratchSurvey literal in another test file",
            "R8",
            "src/provider/codex/login_child_tests.rs",
            Edit::Append(
                "fn p() -> proof::ScratchSurvey {\n    proof::ScratchSurvey { daemon_dir: false, held_locks: Vec::new(), odd_locks: Vec::new(), truncated: false }\n}",
            ),
        ),
        (
            "ScratchSurvey derives Default",
            "R8b",
            "src/provider/codex/proof.rs",
            Edit::Replace(
                "#[derive(Debug)]\npub struct ScratchSurvey {",
                "#[derive(Debug, Default)]\npub struct ScratchSurvey {",
            ),
        ),
    ];
    let mut missed = Vec::new();
    for (name, rule, file, edit) in &plants {
        let sources = planted(&base, file, edit);
        let replanted = sources
            .iter()
            .find(|(path, _)| path == file)
            .map(syntax::parse_one)
            .unwrap_or_else(|| panic!("the planted {file} vanished"));
        let parsed: Vec<&Parsed> = base_parsed
            .iter()
            .map(|parsed| if parsed.path == *file { &replanted } else { parsed })
            .collect();
        let found = violations(&sources, &parsed);
        let tag = format!("{rule}: ");
        // R6c/R6d/R6e findings must say how to comply (round 3, A5).
        let complies =
            |line: &str| !matches!(*rule, "R6c" | "R6d" | "R6e") || line.contains(" — to comply,");
        let caught = found
            .iter()
            .any(|line| line.starts_with(&tag) && line.contains(file) && complies(line));
        if !caught {
            missed.push(format!("`{name}` in {file} (expected {rule}); found: {found:?}"));
        }
    }
    assert!(missed.is_empty(), "plants not reported by their rule:\n{}", missed.join("\n"));
}

/// A plant of the retired `impl Default` shape, kept apart from the table
/// because it adds an item rather than editing one.
#[test]
fn a_written_default_for_the_survey_is_reported() {
    let (base, base_parsed) = parsed_tree();
    let file = "src/provider/codex/proof.rs";
    let sources = planted(
        &base,
        file,
        &Edit::Append(
            "impl Default for ScratchSurvey {\n    fn default() -> Self {\n        todo!()\n    }\n}",
        ),
    );
    let replanted =
        sources.iter().find(|(path, _)| path == file).map(syntax::parse_one).expect("planted");
    let parsed: Vec<&Parsed> = base_parsed
        .iter()
        .map(|parsed| if parsed.path == file { &replanted } else { parsed })
        .collect();
    let found = violations(&sources, &parsed);
    assert!(found.iter().any(|line| line.starts_with("R8b: ")), "not reported: {found:?}");
}

/// The legitimate shapes the rules must NOT report (round 2, A4 and B2):
/// each is inserted into a real file, and the planted tree must be exactly
/// as clean as the real one. A rule that is RED on code a later change will
/// plausibly write gets allow-listed and then ignored.
#[test]
fn every_legitimate_shape_stays_clean() {
    let (base, base_parsed) = parsed_tree();
    let shapes = [
        (
            "a carrier's receipt field handed to audit::append",
            "src/commands/codex/login.rs",
            Edit::Append(
                "struct PlantGot {\n    receipt: WriteReceipt,\n    n: u8,\n}\nfn plant_make() -> PlantGot {\n    todo!()\n}\nfn p(paths: &Paths) -> Result<(), AppError> {\n    let got = plant_make();\n    audit::append(paths, got.receipt)?;\n    Ok(())\n}",
            ),
        ),
        (
            "a &WriteReceipt getter",
            "src/commands/codex/login.rs",
            Edit::Append(
                "struct PlantHolder {\n    n: u8,\n}\nimpl PlantHolder {\n    fn peek(&self) -> &WriteReceipt {\n        todo!()\n    }\n}\nfn p(h: &PlantHolder) -> WriteKind {\n    let r = h.peek();\n    r.kind()\n}",
            ),
        ),
        (
            // Round 3, B2: `peel` unwraps `Result`/`Option`/`Box` in a
            // bounded loop; a tuple two wrappers deep needs two steps, or the
            // `_` beside the receipt reads as a dropped receipt.
            "a receipt two wrappers deep, destructured and audited",
            "src/commands/codex/login.rs",
            Edit::Append(
                "fn plant_nested() -> Result<Option<(WriteReceipt, u8)>, AppError> {\n    todo!()\n}\nfn p(paths: &Paths) -> Result<(), AppError> {\n    let (receipt, _) = plant_nested()?.expect(\"plant\");\n    audit::append(paths, receipt)?;\n    Ok(())\n}",
            ),
        ),
        (
            // Round 3, B4: R2s false-positive shapes (reviewer FP-1…5, P-32c/e).
            "Self::wrap in another type's impl with its own wrap",
            "src/provider/codex/auth_store.rs",
            Edit::Append(
                "struct PlantO;\nimpl PlantO {\n    fn wrap(n: u8) -> u8 {\n        n\n    }\n    fn p() -> u8 {\n        Self::wrap(1)\n    }\n}",
            ),
        ),
        (
            "<Other>::wrap",
            "src/provider/codex/auth_store.rs",
            Edit::Append(
                "struct PlantO;\nimpl PlantO {\n    fn wrap(n: u8) -> u8 {\n        n\n    }\n}\nfn p() -> u8 {\n    <PlantO>::wrap(1)\n}",
            ),
        ),
        (
            "use Other as G; G::wrap",
            "src/provider/codex/auth_store.rs",
            Edit::Append(
                "use crate::provider::codex::plant_m::Other as PlantOg;\nfn p() -> u8 {\n    PlantOg::wrap(1)\n}",
            ),
        ),
        (
            "Self::new in another type's impl",
            "src/provider/codex/refresh.rs",
            Edit::Append(
                "struct PlantO;\nimpl PlantO {\n    fn new() -> Self {\n        PlantO\n    }\n    fn p() -> Self {\n        Self::new()\n    }\n}",
            ),
        ),
        (
            "<Other as Trait>::wrap",
            "src/provider/codex/auth_store.rs",
            Edit::Append("fn p() -> u8 {\n    <PlantO as PlantT>::wrap(1)\n}"),
        ),
        (
            "Self::wrap inside the home lock.rs",
            "src/provider/codex/lock.rs",
            Edit::Append(
                "impl CodexNamespaceGuard {\n    fn p(g: NamespaceLockGuard) -> Self {\n        Self::wrap(g)\n    }\n}",
            ),
        ),
        (
            "a nested other-type impl inside impl CodexNamespaceGuard",
            "src/provider/codex/auth_store.rs",
            Edit::Append(
                "impl CodexNamespaceGuard {\n    fn p() {\n        struct PlantO;\n        impl PlantO {\n            fn wrap(n: u8) -> u8 {\n                n\n            }\n            fn q() -> u8 {\n                Self::wrap(1)\n            }\n        }\n    }\n}",
            ),
        ),
        (
            // B1/B3 false-positive shapes (reviewer S-19, S-20).
            "a cfg_attr derive of something else on ScratchSurvey",
            "src/provider/codex/proof.rs",
            Edit::Replace(
                "#[derive(Debug)]\npub struct ScratchSurvey {",
                "#[derive(Debug)]\n#[cfg_attr(test, derive(Clone))]\npub struct ScratchSurvey {",
            ),
        ),
        (
            "a cfg_attr Default on another struct",
            "src/provider/codex/proof.rs",
            Edit::Append("#[cfg_attr(test, derive(Default))]\nstruct PlantOther {\n    n: u8,\n}"),
        ),
        (
            "a receipt moved into a tuple, audited through the tuple",
            "src/commands/codex/login.rs",
            Edit::Replace(
                "        audit::append(paths, receipt)?;\n",
                "        let pair = (receipt, kind);\n        audit::append(paths, pair.0)?;\n",
            ),
        ),
        (
            "a consumer that audits what it takes",
            "src/commands/codex/login.rs",
            Edit::Append(
                "fn plant_consumer(paths: &Paths, receipt: WriteReceipt) -> Result<(), AppError> {\n    audit::append(paths, receipt)\n}",
            ),
        ),
        (
            "a Self literal inside an impl of another type",
            "src/provider/codex/refresh.rs",
            Edit::Append(
                "struct PlantOther {\n    n: u8,\n}\nimpl PlantOther {\n    fn new() -> Self {\n        Self { n: 0 }\n    }\n}",
            ),
        ),
        (
            "a nested impl of another type inside impl ScratchSurvey's home file",
            "src/provider/codex/refresh.rs",
            Edit::Append(
                "struct PlantInner {\n    n: u8,\n}\nimpl proof::ScratchSurvey {\n    fn p() {\n        impl PlantInner {\n            fn new() -> Self {\n                Self { n: 0 }\n            }\n        }\n    }\n}",
            ),
        ),
    ];
    let mut reported = Vec::new();
    for (name, file, edit) in &shapes {
        let sources = planted(&base, file, edit);
        let replanted = sources
            .iter()
            .find(|(path, _)| path == file)
            .map(syntax::parse_one)
            .unwrap_or_else(|| panic!("the planted {file} vanished"));
        let parsed: Vec<&Parsed> = base_parsed
            .iter()
            .map(|parsed| if parsed.path == *file { &replanted } else { parsed })
            .collect();
        let found = violations(&sources, &parsed);
        if !found.is_empty() {
            reported.push(format!("`{name}` in {file}: {found:?}"));
        }
    }
    assert!(reported.is_empty(), "legitimate shapes reported:\n{}", reported.join("\n"));
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
        "    fn peek(&self) -> &WriteReceipt {",
        "    fn get<'a>(&'a mut self) -> &'a mut OwnedRecord<'a> {",
    ] {
        let hit = ["OwnedRecord", "OwnedNamespace", "VerifiedLogin", "WriteReceipt"]
            .iter()
            .any(|n| literal_uses(line, n, false))
            || literal_uses(line, "CodexNamespaceGuard", true);
        assert!(!hit, "a type position was read as a literal: {line}");
    }
}

#[test]
fn a_path_pin_matches_every_spelling_but_a_longer_name() {
    let tests: [(&str, &str, bool); 7] = [
        ("    Ok(CodexNamespaceGuard::wrap(guard))", "CodexNamespaceGuard::wrap", true),
        ("    g.map(CodexNamespaceGuard::wrap)", "CodexNamespaceGuard::wrap", true),
        ("    let f = CodexNamespaceGuard::wrap;", "CodexNamespaceGuard::wrap", true),
        ("    CodexNamespaceGuard::wrapped(g)", "CodexNamespaceGuard::wrap", false),
        ("    MyLockedCredentials::new(x)", "LockedCredentials::new", false),
        ("    state.write_inflight\n", ".write_inflight", true),
        ("    state.write_inflight_all(x)", ".write_inflight", false),
    ];
    for (line, path, expected) in tests {
        assert_eq!(names_path(line, path), expected, "names_path({line:?}, {path:?})");
    }
}

#[test]
fn the_plan_type_vocabulary_is_fact_f63s() {
    assert_eq!(PLAN_TYPES.len(), 22);
    assert!(is_known_plan("pro") && is_known_plan("free_workspace") && is_known_plan("unknown"));
    assert!(!is_known_plan("Pro") && !is_known_plan(""));
    assert_eq!(USER_AGENT_ENV, "AGCTL_CODEX_USER_AGENT");
}
