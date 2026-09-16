#!/usr/bin/env bash
# AC120 — phase 3's source greps (plan §9.3), fail-closed.
#
# A grep that has never been seen to fail proves nothing: a typo in its
# pattern, a path that moved, a scope that excludes the file it was written
# for, and it passes forever. So every check here runs twice. First against a
# snapshot of the working tree with one violating line planted — the same
# temporary-index snapshot scripts/phase3-structural.sh builds — where it MUST
# fail; then against the working tree itself, where it must pass. The script
# exits non-zero if either half is wrong.
#
# Scope, for every literal grep (plan ledger #142): code lines only — the
# match may start the line's text (a rustfmt continuation such as
# `        .unwrap();`) or follow code on it, but a line whose first non-blank
# character is `/` never matches, so doc comments and `//` comments do not
# count — and `src` without the `*_tests.rs` siblings. Every check whose
# pattern can begin a line is also proven against a plant in that shape.
#
# The base baselines, landed by S29a; later steps append their own checks:
#
#   unwrap        `.unwrap()` on a code line                          → none
#   remove_set    files spelling `remove_dir`/`rmdir`/`unlinkat`      → within the
#                 eight base files plus secret_file.rs, and codex's
#                 auth_store.rs and login_child.rs
#   codex_home    the `"CODEX_HOME"` literal                          → at most one,
#                 in src/provider/codex/home.rs (`home::CODEX_HOME_ENV`)
#   sentinels     `agctl-test-codex-{at,rt,ak,jwt}-`                  → none
#   jwt           `eyJ` (a base64url JSON object: a JWT)              → none
#   bearer        `bearer` + space or `%20`, any case                 → one line at most
#                 per file, only in the two providers' credentials.rs
#   removal_helpers  users of the descriptor-relative removal helpers (whole word) →
#                 `unlink_at` only in file_store.rs, secret_file.rs, pending.rs;
#                 `remove_dir_under` and `remove_dir_under_root` only in file_store.rs
#                 and commands/doctor.rs (their base-tree caller)
#
# S29b appends two more:
#
#   codex_bin     the `AGCTL_CODEX_BIN` name (the test-only `codex` override) →
#                 only in provider/codex/login_child.rs, the one module that
#                 spawns the vendor's binary
#   codex_env     `std::env` inside provider/codex/home.rs                 → none.
#                 The Codex home is resolved from an injected `CodexEnv`, never
#                 from the process, which is what lets every home-resolution test
#                 run in-process without touching the developer's own (I25).
#                 Vacuous until S30 creates that file; the planted violation
#                 creates it, so the check itself is proven now.
#
# With `--log <file>...` the leak needles (the four sentinels, `eyJ`, `Bearer `
# and `sk-ant-`) are also counted in each named file — a nextest trace log, a
# `--json` document (plan §9.4) — and every count must be zero. The needles
# are proven on every run, `--log` or not: one planted file per needle, each of
# which must be reported for that needle. An unreadable log is a failure.
#
# Usage: scripts/phase3-greps.sh [--log <file>...]

set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=scripts/phase3-structural.sh
source "$here/phase3-structural.sh"

# The files allowed to spell a removal (plan §9.3). The first eight are the
# base tree's, verified at 317722b.
REMOVE_ALLOWED=(
    src/commands/doctor.rs
    src/commands/isolate.rs
    src/commands/status.rs
    src/provider/claude/claude_json.rs
    src/secret/audit.rs
    src/secret/claude_lock.rs
    src/secret/config_lock.rs
    src/secret/file_store.rs
    src/secret/secret_file.rs
    src/provider/codex/auth_store.rs
    src/provider/codex/login_child.rs
)

BEARER_ALLOWED=(
    src/provider/claude/credentials.rs
    src/provider/codex/credentials.rs
)

# Users of file_store's removal helpers (review F3, re-review N2): widening
# `unlink_at` to pub(crate) would otherwise let any module delete credential
# material without spelling `unlinkat`, and the removal-set check above would
# never see it. Matched on the whole word, not `name(`, so an import alias or a
# function passed by name is caught too.
UNLINK_HELPER_ALLOWED=(
    src/secret/file_store.rs
    src/secret/secret_file.rs
    src/secret/pending.rs
)

REMOVE_DIR_UNDER_ALLOWED=(
    src/secret/file_store.rs
    src/commands/doctor.rs
)

REMOVE_DIR_UNDER_ROOT_ALLOWED=(
    src/secret/file_store.rs
    src/commands/doctor.rs
)

# The test-only `codex` binary override (plan §3.2, ledger #145). Production
# resolves `codex` on PATH and refuses with `codex not on PATH`; the override is
# compiled only under the `testing` feature and is on the release gate's seam
# list, so a second reader of it would be a second way into a release artifact.
CODEX_BIN_ALLOWED=(
    src/provider/codex/login_child.rs
)

# The file that must not read the process environment (invariant I25).
CODEX_HOME_MODULE=src/provider/codex/home.rs

LEAK_NEEDLES=(
    agctl-test-codex-at-
    agctl-test-codex-rt-
    agctl-test-codex-ak-
    agctl-test-codex-jwt-
    eyJ
    'Bearer '
    sk-ant-
)

# code_hits <root> <regex>: `path:line:text` for every non-test code line under
# <root>/src matching <regex>. rg's "no match" is not an error; anything else
# (an unreadable file, say) returns 2. Every caller runs this inside `$(…)`,
# where a `phase3_die` would only leave the subshell, so each one propagates
# the status itself with `|| scan_failed` — a scan that could not read `src`
# proves nothing and must not report ok (re-review N1).
code_hits() {
    local root=$1 pattern=$2 status=0 out
    out=$(cd "$root" && rg --line-number --no-heading --color never \
        --glob '!*_tests.rs' -e "^\\s*(?:[^/\\s].*)?(?:${pattern})" src) || status=$?
    printf '%s' "$out"
    if [[ $status -gt 1 ]]; then
        printf 'phase3: rg failed (%s) for pattern %s\n' "$status" "$pattern" >&2
        return 2
    fi
    return 0
}

# scan_failed <check>: dies in the calling shell after code_hits failed.
scan_failed() {
    phase3_die "$1: rg could not scan src; a scan that could not read the tree proves nothing"
}

# contains <needle> <list...>
contains() {
    local needle=$1 item
    shift
    for item in "$@"; do
        [[ $item == "$needle" ]] && return 0
    done
    return 1
}

# Each check_<name> <root> prints what is wrong and returns 1, or returns 0.

check_unwrap() {
    local hits
    hits=$(code_hits "$1" '\.unwrap\(\)') || scan_failed check_unwrap
    [[ -z $hits ]] && return 0
    printf '  `.unwrap()` on a code line:\n%s\n' "$hits"
    return 1
}

check_remove_set() {
    local hits file bad=0
    hits=$(code_hits "$1" 'remove_dir|rmdir|unlinkat') || scan_failed check_remove_set
    while IFS= read -r file; do
        [[ -z $file ]] && continue
        if ! contains "$file" "${REMOVE_ALLOWED[@]}"; then
            printf '  %s spells a removal and is not in the allow-list\n' "$file"
            bad=1
        fi
    done < <(printf '%s\n' "$hits" | cut -d: -f1 | LC_ALL=C sort -u)
    return "$bad"
}

check_codex_home() {
    local hits count
    hits=$(code_hits "$1" '"CODEX_HOME"') || scan_failed check_codex_home
    [[ -z $hits ]] && return 0
    count=$(printf '%s\n' "$hits" | wc -l | tr -d ' ')
    if [[ $count -le 1 && $hits == src/provider/codex/home.rs:* ]]; then
        return 0
    fi
    printf '  the "CODEX_HOME" literal belongs only in src/provider/codex/home.rs, once:\n%s\n' "$hits"
    return 1
}

check_sentinels() {
    local hits
    hits=$(code_hits "$1" 'agctl-test-codex-(?:at|rt|ak|jwt)-') || scan_failed check_sentinels
    [[ -z $hits ]] && return 0
    printf '  a fixture sentinel in non-test code:\n%s\n' "$hits"
    return 1
}

check_jwt() {
    local hits
    hits=$(code_hits "$1" 'eyJ') || scan_failed check_jwt
    [[ -z $hits ]] && return 0
    printf '  a JWT-shaped literal in non-test code:\n%s\n' "$hits"
    return 1
}

check_bearer() {
    local hits file count bad=0
    hits=$(code_hits "$1" '(?i:bearer(?:\s|%20))') || scan_failed check_bearer
    while IFS= read -r file; do
        [[ -z $file ]] && continue
        count=$(printf '%s\n' "$hits" | cut -d: -f1 | grep -cxF "$file")
        if ! contains "$file" "${BEARER_ALLOWED[@]}" || [[ $count -gt 1 ]]; then
            printf '  %s builds a bearer string (%s line(s)); only the two credentials.rs may, once each\n' \
                "$file" "$count"
            bad=1
        fi
    done < <(printf '%s\n' "$hits" | cut -d: -f1 | LC_ALL=C sort -u)
    [[ $bad -eq 1 ]] && printf '%s\n' "$hits"
    return "$bad"
}

# check_logs <file...>: every leak needle absent from every file.
check_logs() {
    local file needle count status bad=0
    for file in "$@"; do
        [[ -f $file && -r $file ]] || { printf '  %s is not a readable file\n' "$file"; bad=1; continue; }
        for needle in "${LEAK_NEEDLES[@]}"; do
            status=0
            count=$(rg --count-matches --fixed-strings --no-filename -e "$needle" "$file") || status=$?
            if [[ $status -gt 1 ]]; then
                phase3_die "rg could not read ${file} (exit ${status}); an unread log proves nothing"
            fi
            if [[ -n $count && $count != 0 ]]; then
                printf '  %s: %s occurrence(s) of `%s`\n' "$file" "$count" "$needle"
                bad=1
            fi
        done
    done
    return "$bad"
}

# check_helper_callers <root> <pattern> <what> <allowed...>
check_helper_callers() {
    local root=$1 pattern=$2 what=$3 hits file bad=0
    shift 3
    hits=$(code_hits "$root" "$pattern") || scan_failed "check_helper_callers ($what)"
    while IFS= read -r file; do
        [[ -z $file ]] && continue
        if ! contains "$file" "$@"; then
            printf '  %s calls %s and is not in its allow-list\n' "$file" "$what"
            bad=1
        fi
    done < <(printf '%s\n' "$hits" | cut -d: -f1 | LC_ALL=C sort -u)
    return "$bad"
}

check_codex_bin() {
    check_helper_callers "$1" '\bAGCTL_CODEX_BIN\b' 'AGCTL_CODEX_BIN' "${CODEX_BIN_ALLOWED[@]}"
}

check_codex_env() {
    local file="$1/$CODEX_HOME_MODULE" hits status=0
    # Vacuous until S30 writes it. Stated rather than silent: the plant below
    # creates the file, so the check is proven on every run regardless.
    [[ -f $file ]] || return 0
    hits=$(rg --line-number --no-heading --color never \
        -e '^\s*(?:[^/\s].*)?std::env' "$file") || status=$?
    if [[ $status -gt 1 ]]; then
        phase3_die "check_codex_env: rg could not read $CODEX_HOME_MODULE"
    fi
    [[ -z $hits ]] && return 0
    printf '  %s reads the process environment; the Codex home comes from an injected CodexEnv:\n%s\n' \
        "$CODEX_HOME_MODULE" "$hits"
    return 1
}

check_removal_helpers() {
    local bad=0
    check_helper_callers "$1" '\bunlink_at\b' 'unlink_at' "${UNLINK_HELPER_ALLOWED[@]}" || bad=1
    check_helper_callers "$1" '\bremove_dir_under\b' 'remove_dir_under' \
        "${REMOVE_DIR_UNDER_ALLOWED[@]}" || bad=1
    check_helper_callers "$1" '\bremove_dir_under_root\b' 'remove_dir_under_root' \
        "${REMOVE_DIR_UNDER_ROOT_ALLOWED[@]}" || bad=1
    return "$bad"
}

# Each plant_<name> <root> adds exactly one violation of its check.
PLANT_FILE=src/main.rs
plant_line() { printf '\n%s\n' "$2" >>"$1/$PLANT_FILE"; }

# Inline plants: the match follows code on the same line.
plant_unwrap() { plant_line "$1" 'fn _phase3_plant() { let _ = Some(1).unwrap(); }'; }
plant_remove_set() { plant_line "$1" 'fn _phase3_plant() { let _ = std::fs::remove_dir("x"); }'; }
plant_codex_home() { plant_line "$1" 'const _PHASE3_PLANT: &str = "CODEX_HOME";'; }
plant_sentinels() { plant_line "$1" 'const _PHASE3_PLANT: &str = "agctl-test-codex-rt-0001";'; }
plant_jwt() { plant_line "$1" 'const _PHASE3_PLANT: &str = "eyJhbGciOiJub25lIn0";'; }
plant_bearer() { plant_line "$1" 'fn _phase3_plant(t: &str) -> String { format!("bearer {t}") }'; }
plant_unlink_helper() { plant_line "$1" 'fn _phase3_plant(d: BorrowedFd<'"'"'_>) { let _ = file_store::unlink_at(d, "x"); }'; }
plant_unlink_alias() { plant_line "$1" 'use crate::secret::file_store::unlink_at as _phase3_plant;'; }
plant_remove_dir_under_root() { plant_line "$1" 'fn _phase3_plant(p: &Paths, d: &Path) { let _ = file_store::remove_dir_under_root(p, d); }'; }
plant_remove_dir_under() { plant_line "$1" 'fn _phase3_plant(a: &Path, p: &Path) { let _ = file_store::remove_dir_under(a, p); }'; }
plant_codex_bin() { plant_line "$1" 'const _PHASE3_PLANT: &str = "AGCTL_CODEX_BIN";'; }
# Creates the module as well as the violation: until S30 writes it, this is
# also what proves the check can fail at all.
plant_codex_env() {
    mkdir -p "$1/$(dirname "$CODEX_HOME_MODULE")"
    printf 'fn _phase3_plant() -> Option<std::ffi::OsString> { std::env::var_os("X") }\n' \
        >>"$1/$CODEX_HOME_MODULE"
}

# rustfmt-shaped plants: the match begins the line's code text (review F1).
plant_unwrap_fmt() { plant_line "$1" $'fn _phase3_plant() {\n    let _ = Some(1)\n        .unwrap();\n}'; }
plant_remove_set_fmt() { plant_line "$1" $'fn _phase3_plant(d: &str) {\n    unlinkat(d);\n}'; }
plant_codex_home_fmt() { plant_line "$1" $'const _PHASE3_PLANT: [&str; 1] = [\n    "CODEX_HOME",\n];'; }
plant_unlink_helper_fmt() { plant_line "$1" $'fn _phase3_plant(d: BorrowedFd<\'_>) {\n    unlink_at(d, "x");\n}'; }
plant_remove_dir_under_fmt() { plant_line "$1" $'fn _phase3_plant(a: &Path, p: &Path) {\n    remove_dir_under(\n        a, p,\n    );\n}'; }

CHECKS=(unwrap remove_set codex_home sentinels jwt bearer removal_helpers codex_bin codex_env)

# "<check> <plant>" pairs: every plant must make its check fail.
PLANTS=(
    "unwrap plant_unwrap"
    "unwrap plant_unwrap_fmt"
    "remove_set plant_remove_set"
    "remove_set plant_remove_set_fmt"
    "codex_home plant_codex_home"
    "codex_home plant_codex_home_fmt"
    "sentinels plant_sentinels"
    "jwt plant_jwt"
    "bearer plant_bearer"
    "removal_helpers plant_unlink_helper"
    "removal_helpers plant_unlink_helper_fmt"
    "removal_helpers plant_remove_dir_under"
    "removal_helpers plant_remove_dir_under_fmt"
    "removal_helpers plant_unlink_alias"
    "removal_helpers plant_remove_dir_under_root"
    "codex_bin plant_codex_bin"
    "codex_env plant_codex_env"
)

main() {
    local logs=()
    while [[ $# -gt 0 ]]; do
        case $1 in
            --log)
                [[ $# -ge 2 ]] || phase3_die "--log needs a file"
                logs+=("$2")
                shift 2
                ;;
            *) phase3_die "unknown argument: $1 (usage: scripts/phase3-greps.sh [--log <file>...])" ;;
        esac
    done

    command -v rg >/dev/null || phase3_die "rg is required"
    local root
    root=$(git rev-parse --show-toplevel)
    cd "$root"

    WORK=$(mktemp -d "${TMPDIR:-/tmp}/agctl-phase3-greps.XXXXXX")
    SNAPSHOT="$WORK/snapshot"
    trap 'phase3_drop "$SNAPSHOT"; rm -rf "$WORK"' EXIT
    phase3_snapshot "$SNAPSHOT"

    local failed=0 name pair check plant
    printf '== planted violations (each check must fail)\n'
    for pair in "${PLANTS[@]}"; do
        read -r check plant <<<"$pair"
        "$plant" "$SNAPSHOT"
        if "check_$check" "$SNAPSHOT" >"$WORK/$plant.txt"; then
            printf 'planted %-26s NOT CAUGHT by %s: the check passed over its own violation\n' "$plant" "$check" >&2
            failed=1
        else
            printf 'planted %-26s caught: %s\n' "$plant" "$(grep -m1 . "$WORK/$plant.txt" | sed 's/^ *//')"
        fi
        phase3_restore "$SNAPSHOT"
    done
    # N1: an unreadable file under src/ must stop the gate, not pass the scan.
    # Run in a subshell so its `phase3_die` is observable here.
    local unreadable="$SNAPSHOT/src/phase3_unreadable_plant.rs" status=0
    printf 'fn _p() { let _ = Some(1).unwrap(); }\n' >"$unreadable"
    chmod 000 "$unreadable"
    (check_unwrap "$SNAPSHOT") >"$WORK/plant_unreadable.txt" 2>&1 || status=$?
    chmod 600 "$unreadable"
    phase3_restore "$SNAPSHOT"
    if [[ $status -ne 0 ]] && grep -q 'could not scan src' "$WORK/plant_unreadable.txt"; then
        printf 'planted %-26s caught: %s\n' plant_unreadable_src "$(grep -m1 'could not scan' "$WORK/plant_unreadable.txt")"
    else
        printf 'planted %-26s NOT CAUGHT: an unreadable file under src/ let the scan pass (exit %s)\n' \
            plant_unreadable_src "$status" >&2
        failed=1
    fi

    local index=0 needle planted_log
    for needle in "${LEAK_NEEDLES[@]}"; do
        planted_log="$WORK/planted-needle-$index.log"
        printf 'a trace line carrying %s<-here\n' "$needle" >"$planted_log"
        check_logs "$planted_log" >"$WORK/planted-needle-$index.txt" || true
        if grep -qF "of \`$needle\`" "$WORK/planted-needle-$index.txt"; then
            printf 'planted %-26s caught: `%s`\n' "needle-$index" "$needle"
        else
            printf 'planted %-26s NOT CAUGHT: the needle `%s` was not counted in its own planted log\n' \
                "needle-$index" "$needle" >&2
            failed=1
        fi
        index=$((index + 1))
    done

    printf '== the working tree (each check must pass)\n'
    for name in "${CHECKS[@]}"; do
        if "check_$name" "$root"; then
            printf 'tree    %-26s ok\n' "$name"
        else
            printf 'tree    %-26s FAILED\n' "$name" >&2
            failed=1
        fi
    done
    if [[ ${#logs[@]} -gt 0 ]]; then
        if check_logs "${logs[@]}"; then
            printf 'tree    %-26s ok (%s file(s))\n' logs "${#logs[@]}"
        else
            printf 'tree    %-26s FAILED\n' logs >&2
            failed=1
        fi
    fi

    [[ $failed -eq 0 ]] || phase3_die "phase3-greps failed"
    printf 'phase3-greps: ok\n'
}

main "$@"
