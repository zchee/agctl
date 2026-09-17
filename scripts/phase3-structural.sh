#!/usr/bin/env bash
# AC122 — phase 3's structural gate.
#
# Some phase-3 invariants are enforced by the compiler rather than by a test:
# a private field, a `pub(super)` constructor, a private tuple-struct field.
# A test cannot prove "this does not compile", so this script does it the only
# honest way: it plants the violating code in a copy of the tree, runs
# `cargo check --all-features --message-format=json`, and requires a diagnostic
# whose `code` matches AND whose primary span is the planted file and line. An
# unrelated failure elsewhere (an unresolved import, a typo in the plant) does
# not count, because it would pass a gate that proved nothing.
#
# The copy is a snapshot of the WORKING TREE, not of HEAD, because the gate
# runs before the step's commit (plan §4). It is built through a temporary
# index — `git read-tree HEAD`, `git add -A`, `git write-tree`,
# `git commit-tree` — and checked out as a detached worktree. `git stash
# create` is not used: it omits untracked files, and returns nothing at all
# when the only changes are untracked (critic v5 m4). The snapshot's file list
# is asserted equal to `git ls-files -co --exclude-standard` minus deleted
# files before anything is planted.
#
# A clean `cargo check` of the unplanted snapshot must pass first. Every clause
# then runs against that same snapshot, restored between clauses, with one
# shared CARGO_TARGET_DIR so dependencies build once.
#
# A clause runs only when its plant file exists in the snapshot: each clause
# belongs to the step that creates its file (plan §4), so an earlier step skips
# it and says so. S29a lands the harness and clause 6; S30 clauses 1-5, 7, 9,
# 11 and the re-run of 6 in auth_store.rs.
#
# Usage: scripts/phase3-structural.sh
#
# Environment:
#   CARGO_TARGET_DIR  shared across clauses and runs; defaults to a directory
#                     under $TMPDIR so the snapshot never builds into ./target.
#
# This file is also sourced by scripts/phase3-greps.sh for phase3_snapshot and
# phase3_restore; sourcing runs nothing.

set -euo pipefail

# Prints a message to stderr and exits non-zero.
phase3_die() {
    printf 'phase3: %s\n' "$*" >&2
    exit 1
}

# phase3_snapshot <dest>
#
# Creates a detached worktree at <dest> (which must not exist) holding the
# working tree of the repository containing the current directory: tracked
# files as they are on disk, untracked files that are not ignored, deletions
# applied. Fails closed on an empty commit or a file-list mismatch.
phase3_snapshot() {
    local dest=$1 root index_dir tree sha
    root=$(git rev-parse --show-toplevel)
    index_dir=$(mktemp -d "${TMPDIR:-/tmp}/agctl-phase3-index.XXXXXX")

    # Review F9: `git add -A` copies every untracked or modified file into
    # .git/objects, where it stays until `git gc`. A developer's scratch copy of
    # a real credential must not get another copy at rest that way, so a file
    # named like one, outside fixtures/, stops the gate before anything is
    # stored.
    local suspect
    suspect=$(cd "$root" && git ls-files -mo --exclude-standard | while IFS= read -r path; do
        case $path in fixtures/*) continue ;; esac
        case ${path##*/} in
            auth.json | .credentials.json | *.pending | *.pending.meta | *.tmp.* | *.pem | *.key)
                printf '%s\n' "$path"
                ;;
        esac
    done)
    if [[ -n $suspect ]]; then
        rm -rf "$index_dir"
        printf '%s\n' "$suspect" >&2
        phase3_die "snapshot: refusing to copy credential-shaped files (above) into .git/objects; move them out of the tree or under fixtures/"
    fi

    GIT_INDEX_FILE="$index_dir/index" git -C "$root" read-tree HEAD
    GIT_INDEX_FILE="$index_dir/index" git -C "$root" add -A
    tree=$(GIT_INDEX_FILE="$index_dir/index" git -C "$root" write-tree)
    rm -rf "$index_dir"
    [[ -n $tree ]] || phase3_die "snapshot: git write-tree returned nothing"

    sha=$(git -C "$root" commit-tree "$tree" -p HEAD -m 'phase3 gate snapshot (never pushed)')
    [[ -n $sha ]] || phase3_die "snapshot: git commit-tree returned nothing"

    git -C "$root" worktree add --quiet --detach "$dest" "$sha"

    local expected actual
    expected=$(cd "$root" && comm -23 \
        <(git ls-files -co --exclude-standard | LC_ALL=C sort -u) \
        <(git ls-files -d | LC_ALL=C sort -u))
    actual=$(git -C "$dest" ls-files | LC_ALL=C sort -u)
    if [[ $expected != "$actual" ]]; then
        diff <(printf '%s\n' "$expected") <(printf '%s\n' "$actual") >&2 || true
        phase3_die "snapshot: the snapshot's files differ from the working tree's (above: < tree, > snapshot)"
    fi
}

# phase3_restore <worktree>
#
# Puts a snapshot worktree back to its snapshot commit: planted edits reverted,
# planted files removed.
phase3_restore() {
    git -C "$1" checkout --quiet -- .
    git -C "$1" clean -fdq
}

# phase3_drop <worktree>
phase3_drop() {
    local root
    root=$(git rev-parse --show-toplevel)
    git -C "$root" worktree remove --force "$1" 2>/dev/null || rm -rf "$1"
    git -C "$root" worktree prune
}

# cargo_check <worktree> <json-out>: returns cargo's exit status. cargo's
# stderr is kept beside the JSON as <json-out>.stderr: a failure that happens
# before any compiler message (an ambient RUSTFLAGS the toolchain rejects, a
# registry that cannot be reached) has no diagnostic to print otherwise.
cargo_check() {
    local status=0
    cargo check --all-features --message-format=json --manifest-path "$1/Cargo.toml" \
        >"$2" 2>"$2.stderr" || status=$?
    return "$status"
}

# cargo_stderr_tail <json-out>: the last lines cargo wrote to stderr.
cargo_stderr_tail() {
    printf '  cargo stderr (last 20 lines):\n' >&2
    tail -n 20 "$1.stderr" | sed 's/^/    /' >&2
}

# clause <number> <plant-file> <error-code> <plant-line> <description>
#
# Appends <plant-line> as one line to <plant-file> in the snapshot, requires
# the check to fail with <error-code> whose primary span is that file:line, and
# restores the snapshot.
clause() {
    local number=$1 file=$2 code=$3 plant=$4 what=$5
    local target="$SNAPSHOT/$file"

    if [[ ! -f $target ]]; then
        printf 'clause %-2s skipped: %s does not exist yet (%s)\n' "$number" "$file" "$what"
        SKIPPED=$((SKIPPED + 1))
        return 0
    fi

    printf '%s\n' "$plant" >>"$target"
    local line
    line=$(wc -l <"$target" | tr -d ' ')

    local out="$WORK/clause-$number.json" status=0
    cargo_check "$SNAPSHOT" "$out" || status=$?
    phase3_restore "$SNAPSHOT"

    if [[ $status -eq 0 ]]; then
        printf 'clause %-2s FAILED: the planted violation compiled (%s at %s:%s)\n' \
            "$number" "$code" "$file" "$line" >&2
        FAILED=$((FAILED + 1))
        return 0
    fi

    local hits
    hits=$(jq -r --arg code "$code" --arg file "$file" --argjson line "$line" '
        select(.reason == "compiler-message")
        | .message
        | select(.code != null and .code.code == $code)
        | .spans[]
        | select(.is_primary and .file_name == $file and .line_start == $line)
        | "\(.file_name):\(.line_start)"' "$out" | wc -l | tr -d ' ')

    if [[ $hits -gt 0 ]]; then
        printf 'clause %-2s ok: %s at %s:%s (%s)\n' "$number" "$code" "$file" "$line" "$what"
    else
        printf 'clause %-2s FAILED: no %s with its primary span at %s:%s; the check failed with:\n' \
            "$number" "$code" "$file" "$line" >&2
        jq -r 'select(.reason == "compiler-message") | .message
            | select(.level == "error")
            | "  \(.code.code // "-") \(.spans[0].file_name // "?"):\(.spans[0].line_start // "?") \(.message)"' \
            "$out" >&2
        cargo_stderr_tail "$out"
        FAILED=$((FAILED + 1))
    fi
}

main() {
    command -v jq >/dev/null || phase3_die "jq is required"
    cd "$(git rev-parse --show-toplevel)"

    WORK=$(mktemp -d "${TMPDIR:-/tmp}/agctl-phase3-structural.XXXXXX")
    SNAPSHOT="$WORK/snapshot"
    trap 'phase3_drop "$SNAPSHOT"; rm -rf "$WORK"' EXIT
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/agctl-phase3-target}"
    FAILED=0
    SKIPPED=0

    phase3_snapshot "$SNAPSHOT"
    printf 'snapshot: %s (%s files), target dir %s\n' \
        "$(git -C "$SNAPSHOT" rev-parse --short HEAD)" \
        "$(git -C "$SNAPSHOT" ls-files | wc -l | tr -d ' ')" "$CARGO_TARGET_DIR"

    local baseline="$WORK/baseline.json"
    if ! cargo_check "$SNAPSHOT" "$baseline"; then
        jq -r 'select(.reason == "compiler-message") | .message | select(.level == "error")
            | "  \(.code.code // "-") \(.message)"' "$baseline" >&2
        cargo_stderr_tail "$baseline"
        phase3_die "baseline: the unplanted snapshot does not compile, so no clause can prove anything"
    fi
    printf 'baseline ok: the unplanted snapshot compiles\n'

    # Clause 6 (S29a; re-run in provider/codex/auth_store.rs from S30): a
    # `SecretFile` cannot be built outside `secret_file.rs` without naming its
    # root through `SecretFile::open`, because every field is private.
    clause 6 src/secret/pending.rs E0451 \
        "fn _phase3_plant(root: &'static std::path::Path, dir: std::os::fd::BorrowedFd<'static>, name: &'static str, shown: &'static std::path::Path) -> crate::secret::secret_file::SecretFile<'static> { crate::secret::secret_file::SecretFile { root, dir, name, shown } }" \
        "SecretFile literal outside secret_file.rs"

    # S30's clauses. The plan places clauses 1, 3, 4, 5, 7 and 11 in
    # commands/codex/{login,status}.rs and clause 9 in provider/codex/refresh.rs;
    # none of those files exists at S30 (S33/S34 and S32 create them), so each
    # plant goes into an existing file on the same side of the same boundary —
    # commands/codex/mod.rs is outside `provider::codex` exactly as login.rs and
    # status.rs will be, and lock.rs is a sibling of refresh.rs inside it — and
    # the owning step moves it to the plan's file. Every plant is path-qualified,
    # so the only error it can raise is the privacy one it is there to prove.
    local cmd=src/commands/codex/mod.rs codex=src/provider/codex

    # Clause 1: a `VerifiedLogin` cannot be built outside `proof.rs`.
    clause 1 "$cmd" E0451 \
        "fn _phase3_plant(doc: crate::provider::codex::credentials::Credentials, user: String, acct: String) -> crate::provider::codex::proof::VerifiedLogin { crate::provider::codex::proof::VerifiedLogin { doc, user, acct } }" \
        "VerifiedLogin literal outside provider::codex"

    # Clause 2 (moved into refresh.rs at S32): `LockedCredentials::new` is
    # private to credentials.rs, even from the refresh driver.
    clause 2 "$codex/refresh.rs" E0624 \
        "fn _phase3_plant(inner: super::credentials::Credentials) -> super::credentials::LockedCredentials<'static> { super::credentials::LockedCredentials::new(inner, (String::new(), String::new()), None) }" \
        "LockedCredentials::new from the refresh driver"

    # Clause 3: the credential file's name is private to auth_store.rs.
    clause 3 "$cmd" E0603 \
        "const _PHASE3_PLANT: &str = crate::provider::codex::auth_store::AUTH_FILE;" \
        "AUTH_FILE outside auth_store.rs"

    # Clause 4: a registry record is not an owned-record proof.
    clause 4 "$cmd" E0308 \
        "fn _phase3_plant(paths: &crate::config::paths::Paths, record: &crate::config::codex::CodexAccountRecord, guard: &crate::provider::codex::proof::CodexNamespaceGuard) { let _ = crate::provider::codex::auth_store::OwnedNamespace::open(paths, record, guard); }" \
        "OwnedNamespace::open with a CodexAccountRecord"

    # Clause 5: a namespace lock proof cannot be wrapped outside provider::codex.
    clause 5 "$cmd" E0603 \
        "fn _phase3_plant(g: crate::secret::namespace_lock::NamespaceLockGuard) -> crate::provider::codex::proof::CodexNamespaceGuard { crate::provider::codex::proof::CodexNamespaceGuard(g) }" \
        "CodexNamespaceGuard tuple constructor outside provider::codex"

    # Clause 6 (re-run from S30): a `SecretFile` literal in auth_store.rs.
    clause 6r "$codex/auth_store.rs" E0451 \
        "fn _phase3_plant(root: &'static std::path::Path, dir: std::os::fd::BorrowedFd<'static>, name: &'static str, shown: &'static std::path::Path) -> crate::secret::secret_file::SecretFile<'static> { crate::secret::secret_file::SecretFile { root, dir, name, shown } }" \
        "SecretFile literal in provider/codex/auth_store.rs"

    # Clause 7: a login child's report cannot be forged outside proof.rs.
    clause 7 "$cmd" E0451 \
        "fn _phase3_plant(gained_codex_auth: Vec<String>, survivors: Vec<std::path::PathBuf>, daemon_dir: bool, lock_files: Vec<std::path::PathBuf>, exit: std::process::ExitStatus) -> crate::provider::codex::proof::PostExitReport { crate::provider::codex::proof::PostExitReport { gained_codex_auth, survivors, daemon_dir, lock_files, exit } }" \
        "PostExitReport literal outside provider::codex"

    # Clause 8 (S32): the refresh POST is `pub(super)`, so a command cannot send
    # one. Planted in commands/codex/mod.rs until S33 creates status.rs.
    clause 8 "$cmd" E0603 \
        "fn _phase3_plant(c: &crate::provider::codex::credentials::LockedCredentials<'static>, t: crate::provider::codex::auth_store::InflightToken<'static>, r: &crate::provider::codex::oauth::RefreshClient, x: &crate::runtime::coordinator::Cancel) { let _ = crate::provider::codex::oauth::refresh(c, t, r, x); }" \
        "oauth::refresh from commands/"

    # Clause 9 (moved into refresh.rs at S32): the token a POST consumes
    # cannot be built by the driver that sends the POST.
    clause 9 "$codex/refresh.rs" E0451 \
        "fn _phase3_plant(digest8: String) -> super::auth_store::InflightToken<'static> { super::auth_store::InflightToken { digest8, _guard: std::marker::PhantomData } }" \
        "InflightToken literal in provider/codex/refresh.rs"

    # Clause 10 (S32, ledger #272 ruling 1): a re-send consent cannot be built
    # outside refresh.rs except through its confirming constructor. Planted in
    # commands/codex/mod.rs until S34 creates accounts.rs.
    clause 10 "$cmd" E0603 \
        "fn _phase3_plant() -> crate::provider::codex::refresh::ResendConsent { crate::provider::codex::refresh::ResendConsent(()) }" \
        "ResendConsent tuple literal from commands/"

    # Clause 11: a command cannot clear a refresh marker.
    clause 11 "$cmd" E0624 \
        "fn _phase3_plant(ns: &crate::provider::codex::auth_store::OwnedNamespace<'_>) { let _ = ns.refresh_state().clear_inflight(crate::provider::codex::auth_store::DefiniteOutcome::Applied); }" \
        "RefreshStateFile::clear_inflight from commands/"

    if [[ $FAILED -gt 0 ]]; then
        phase3_die "$FAILED clause(s) failed"
    fi
    printf 'phase3-structural: all runnable clauses passed (%s skipped)\n' "$SKIPPED"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
