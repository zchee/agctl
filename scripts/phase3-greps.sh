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
# S29b appends three more:
#
#   exposed       `expose_secret` on a code line                           → at most one
#                 line per file, only in the two providers' credentials.rs, and
#                 no `pub`/`pub(crate)`/`pub(super)` `fn exposed` anywhere. The
#                 whole crate reaches a token's plaintext through those two
#                 one-line functions; a third site, or a public one, is how a
#                 token reaches a log (AC96, invariant I20).
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
# S30 appends nine more:
#
#   exposed (tightened)  once both credentials.rs exist, exactly two
#                 `expose_secret` lines in the crate (AC96: "exactly 2")
#   auth_json     `auth.json` on a code line                               → only
#                 provider/codex/auth_store.rs, the one opener (I23)
#   account_header  `ChatGPT-Account-Id`                                   → only
#                 provider/codex/credentials.rs
#   toml          `toml::`                                                 → only
#                 provider/codex/home.rs (I31)
#   locked_read   callers of `from_locked_read(` (not its `fn`)            → only
#                 provider/codex/auth_store.rs (I26)
#   marker_mutators  `.write_inflight(` `.write_resend(` `.clear_inflight(`
#                 `.mark_interrupted(` `.mark_unknown(` `.reset_floor(`    → only
#                 provider/codex/refresh.rs (seeded at S30, re-run at S32)
#   stop_policy   `StopPolicy::Complete` only in secret_file.rs and
#                 provider/codex/auth_store.rs, and in auth_store.rs exactly one
#                 `None, StopPolicy::Complete` write (the install) and one
#                 `Some(spec), StopPolicy::Complete` write (writer 1) — review
#                 ruling 3: no pending fallback is reachable only from install
#   codex_debug_assert  `debug_assert` in src/provider/codex             → none
#   state_path    `codex_refresh_state_path` / `.state/`                   → only
#                 config/paths.rs and provider/codex/auth_store.rs
#   codex_flock   `flock` on a code line in src/provider/codex, src/commands/codex → none
#                 (plan §9.3; review S30 F12). The marker mutators are also pinned
#                 in their `RefreshStateFile::name(` spelling (review S30 F5), and
#                 the `Bearer ` log needle is `(?i)bearer(?:\s|%20)`.
#
# S31 appends six more:
#
#   wham_usage    `wham/usage` on a code line                              → only
#                 provider/codex/usage.rs, the one client of the endpoint
#   codex_usage_url  the `AGCTL_CODEX_USAGE_URL` name (the test-only endpoint
#                 override)                                                → only
#                 provider/codex/usage.rs; it is also on the release gate's seam list
#   codex_timeouts  `timeout_global`, `timeout_per_call`, `http_status_as_error(true)`
#                 on a code line in src/provider/codex                     → none
#                 (plan §9.3: a whole-request budget hides which phase timed out,
#                 and a status-as-error agent cannot read a 401/403/429)
#   codex_redirects  exactly one `.max_redirects(0)` code line in
#                 provider/codex/usage.rs, and no other `max_redirects(` in
#                 src/provider/codex (review S31 F1: a followed redirect sends the
#                 account id to the Location host and turns its 401 into the
#                 refresh trigger)
#   codex_decoded_cap  a `.take(MAX_BODY_BYTES` code line in
#                 provider/codex/usage.rs (review S31 F2/N1: the wire limit sits
#                 under the gzip decoder, so the decoded bytes need their own cap)
#   credits_state `CreditsState` on a code line in src/provider/codex,
#                 src/commands/codex and src/render/json_v2.rs             → none
#                 (plan §9.3 m2; ledger #274 (a): Codex credits are `CodexCredits`)
#   account_header  unchanged (ledger #277): usage.rs requires the header through
#                 `credentials::ACCOUNT_ID_HEADER`, so the literal keeps one site
#
# With `--log`, the `LOG_ONLY_NEEDLES` are counted too: the sentinel email a
# usage fixture carries (ledger #274). They are deliberately not code needles
# — the fixture that carries the sentinel is how a leak test proves anything —
# so they apply to log, trace and `--json` output only.
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

# The only files that may reach a `SecretString`'s plaintext, one line each
# (AC96). The Codex half arrives at S30; until then this is a one-file rule and
# the plants below prove it can fail.
EXPOSE_ALLOWED=(
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

AUTH_JSON_ALLOWED=(
    src/provider/codex/auth_store.rs
)

ACCOUNT_HEADER_ALLOWED=(
    src/provider/codex/credentials.rs
)

TOML_ALLOWED=(
    src/provider/codex/home.rs
)

LOCKED_READ_ALLOWED=(
    src/provider/codex/auth_store.rs
)

MARKER_MUTATOR_ALLOWED=(
    src/provider/codex/refresh.rs
)

STOP_COMPLETE_ALLOWED=(
    src/secret/secret_file.rs
    src/provider/codex/auth_store.rs
)

STATE_PATH_ALLOWED=(
    src/config/paths.rs
    src/provider/codex/auth_store.rs
)

# S31: the one client of the usage endpoint, and of its test-only override.
WHAM_USAGE_ALLOWED=(
    src/provider/codex/usage.rs
)

CODEX_USAGE_URL_ALLOWED=(
    src/provider/codex/usage.rs
)

# Where `CreditsState` (Claude's credits) must not appear (plan §9.3 m2).
CREDITS_STATE_FORBIDDEN=(
    src/provider/codex
    src/commands/codex
    src/render/json_v2.rs
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

# Counted in `--log` files only (ledger #274): the usage fixtures' sentinel
# email, which lives in fixtures/codex/usage-sentinel-email.json and its test.
LOG_ONLY_NEEDLES=(
    agctl-test-codex-email-
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
        for needle in "${LEAK_NEEDLES[@]}" "${LOG_ONLY_NEEDLES[@]}"; do
            status=0
            # Review N4 / S30 F12: `Bearer ` is counted as the code check counts
            # it — any case, followed by whitespace or `%20` — so a trace line
            # spelling `authorization: bearer …` or `bearer%20…` is caught too.
            if [[ $needle == 'Bearer ' ]]; then
                count=$(rg --count-matches --no-filename -e '(?i)bearer(?:\s|%20)' "$file") || status=$?
            else
                count=$(rg --count-matches --fixed-strings --no-filename -e "$needle" "$file") || status=$?
            fi
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

check_exposed() {
    local hits file count bad=0 public
    hits=$(code_hits "$1" '\bexpose_secret\b') || scan_failed check_exposed
    while IFS= read -r file; do
        [[ -z $file ]] && continue
        count=$(printf '%s\n' "$hits" | cut -d: -f1 | grep -cxF "$file")
        if ! contains "$file" "${EXPOSE_ALLOWED[@]}" || [[ $count -gt 1 ]]; then
            printf '  %s reaches a secret'"'"'s plaintext (%s line(s)); only the two credentials.rs may, once each\n' \
                "$file" "$count"
            bad=1
        fi
    done < <(printf '%s\n' "$hits" | cut -d: -f1 | LC_ALL=C sort -u)
    [[ $bad -eq 1 ]] && printf '%s\n' "$hits"

    # `fn exposed` is the exposure site itself: public, it would be callable
    # from anywhere in the crate and the count above would stop meaning
    # anything.
    public=$(code_hits "$1" 'pub(?:\([^)]*\))?\s+fn\s+exposed\b') || scan_failed check_exposed
    if [[ -n $public ]]; then
        printf '  the exposure site is public:\n%s\n' "$public"
        bad=1
    fi
    return "$bad"
}

# check_exposure_count: once both exposure sites exist, exactly two lines.
check_exposure_count() {
    local root=$1 hits count
    [[ -f $root/src/provider/codex/credentials.rs && -f $root/src/provider/claude/credentials.rs ]] || return 0
    hits=$(code_hits "$root" '\bexpose_secret\b') || scan_failed check_exposure_count
    count=$(printf '%s' "$hits" | grep -c . || true)
    [[ $count -eq 2 ]] && return 0
    printf '  %s `expose_secret` line(s); the crate has exactly two exposure sites:\n%s\n' "$count" "$hits"
    return 1
}

check_auth_json() {
    check_helper_callers "$1" 'auth\.json' '`auth.json`' "${AUTH_JSON_ALLOWED[@]}"
}

check_account_header() {
    check_helper_callers "$1" 'ChatGPT-Account-Id' 'ChatGPT-Account-Id' "${ACCOUNT_HEADER_ALLOWED[@]}"
}

check_toml() {
    check_helper_callers "$1" '\btoml::' 'toml::' "${TOML_ALLOWED[@]}"
}

# check_callers_not_fn <root> <prefix> <names> <what> <allowed...>: callers of
# the `|`-separated <names> — <prefix> (`\b` for any call, `\.` for a method
# call), a name, then `(` — where a line that defines one of them (`fn <name>`)
# is not a call. Only a definition of a pinned name is excluded: a call inside
# some other `fn` still counts. The marker mutators are pinned as method calls,
# so S34's `refresh::reset_floor(ns, consent)` (a different function) is not
# mistaken for one.
check_callers_not_fn() {
    local root=$1 prefix=$2 names=$3 what=$4 hits file bad=0 status=0
    shift 4
    hits=$(code_hits "$root" "${prefix}(?:${names})\\(") || scan_failed "check_callers_not_fn ($what)"
    hits=$(printf '%s\n' "$hits" | rg -v -e "\\bfn\\s+(?:${names})\\b") || status=$?
    [[ $status -gt 1 ]] && phase3_die "check_callers_not_fn ($what): rg failed filtering definitions"
    while IFS= read -r file; do
        [[ -z $file ]] && continue
        if ! contains "$file" "$@"; then
            printf '  %s calls %s and is not in its allow-list\n' "$file" "$what"
            bad=1
        fi
    done < <(printf '%s\n' "$hits" | cut -d: -f1 | LC_ALL=C sort -u)
    return "$bad"
}

check_locked_read() {
    check_callers_not_fn "$1" '\b' 'from_locked_read' 'from_locked_read' "${LOCKED_READ_ALLOWED[@]}"
}

MARKER_MUTATORS='write_inflight|write_resend|clear_inflight|mark_interrupted|mark_unknown|reset_floor'

check_marker_mutators() {
    local bad=0
    check_callers_not_fn "$1" '\.' "$MARKER_MUTATORS" \
        'a refresh-marker mutator' "${MARKER_MUTATOR_ALLOWED[@]}" || bad=1
    # Review S30 F5: the associated-function spelling reaches the same method.
    check_callers_not_fn "$1" 'RefreshStateFile::' "$MARKER_MUTATORS" \
        'a refresh-marker mutator (associated-function call)' "${MARKER_MUTATOR_ALLOWED[@]}" || bad=1
    return "$bad"
}

# check_codex_flock: plan §9.3 — no `flock` on a code line in the Codex trees.
# agctl takes its Codex locks through `namespace_lock::acquire_at`, and never
# contends for a lock inside a Codex home (invariant I21).
check_codex_flock() {
    local root=$1 dir hits status=0 found=""
    for dir in src/provider/codex src/commands/codex; do
        [[ -d $root/$dir ]] || continue
        status=0
        hits=$(cd "$root" && rg --line-number --no-heading --color never --glob '!*_tests.rs' \
            -e '^\s*(?:[^/\s].*)?\bflock\b' "$dir") || status=$?
        [[ $status -gt 1 ]] && phase3_die "check_codex_flock: rg could not read $dir"
        [[ -n $hits ]] && found+="$hits"$'\n'
    done
    [[ -z $found ]] && return 0
    printf '  `flock` in Codex code; take locks through namespace_lock only:\n%s' "$found"
    return 1
}

check_stop_policy() {
    local root=$1 bad=0 store=$1/src/provider/codex/auth_store.rs none some
    check_helper_callers "$root" 'StopPolicy::Complete' 'StopPolicy::Complete' "${STOP_COMPLETE_ALLOWED[@]}" || bad=1
    if [[ -f $store ]]; then
        none=$(rg -c -e '^\s*(?:[^/\s].*)?\bNone,\s*StopPolicy::Complete' "$store" || true)
        some=$(rg -c -e '^\s*(?:[^/\s].*)?\bSome\(spec\),\s*StopPolicy::Complete' "$store" || true)
        if [[ ${none:-0} -ne 1 || ${some:-0} -ne 1 ]]; then
            printf '  auth_store.rs: %s write(s) with no pending fallback and %s with one; expected exactly 1 and 1 (ruling 3)\n' \
                "${none:-0}" "${some:-0}"
            bad=1
        fi
    fi
    return "$bad"
}

check_codex_debug_assert() {
    local dir=$1/src/provider/codex hits status=0
    [[ -d $dir ]] || return 0
    hits=$(rg --line-number --no-heading --color never --glob '!*_tests.rs' \
        -e '^\s*(?:[^/\s].*)?debug_assert' "$dir") || status=$?
    [[ $status -gt 1 ]] && phase3_die "check_codex_debug_assert: rg could not read src/provider/codex"
    [[ -z $hits ]] && return 0
    printf '  debug assertions are off in every build (AGENTS.md); use a real check:\n%s\n' "$hits"
    return 1
}

check_state_path() {
    check_helper_callers "$1" '\bcodex_refresh_state_path\b|\.state/' 'the refresh-marker path' "${STATE_PATH_ALLOWED[@]}"
}

check_wham_usage() {
    check_helper_callers "$1" 'wham/usage' '`wham/usage`' "${WHAM_USAGE_ALLOWED[@]}"
}

check_codex_usage_url() {
    check_helper_callers "$1" '\bAGCTL_CODEX_USAGE_URL\b' 'AGCTL_CODEX_USAGE_URL' "${CODEX_USAGE_URL_ALLOWED[@]}"
}

# scoped_code_hits <root> <regex> <path...>: code_hits limited to the named
# directories or files (each skipped when absent). Like code_hits it runs
# inside `$(…)`, so an unreadable path returns 2 for the caller's
# `|| scan_failed` rather than dying in the subshell (re-review N1).
scoped_code_hits() {
    local root=$1 pattern=$2 path hits status found=""
    shift 2
    for path in "$@"; do
        [[ -e $root/$path ]] || continue
        status=0
        hits=$(cd "$root" && rg --line-number --no-heading --color never --glob '!*_tests.rs' \
            -e "^\\s*(?:[^/\\s].*)?(?:${pattern})" "$path") || status=$?
        if [[ $status -gt 1 ]]; then
            printf 'phase3: rg failed (%s) reading %s\n' "$status" "$path" >&2
            return 2
        fi
        [[ -n $hits ]] && found+="$hits"$'\n'
    done
    printf '%s' "$found"
    return 0
}

check_codex_timeouts() {
    local hits
    hits=$(scoped_code_hits "$1" '\btimeout_global\b|\btimeout_per_call\b|http_status_as_error\(\s*true\s*\)' \
        src/provider/codex) || scan_failed check_codex_timeouts
    [[ -z $hits ]] && return 0
    printf '  a whole-request timeout or status-as-error agent in Codex code (plan §9.3):\n%s' "$hits"
    return 1
}

CODEX_USAGE_MODULE=src/provider/codex/usage.rs

check_codex_redirects() {
    local root=$1 hits zero others count
    # Vacuous before S31 writes the client; the plant below needs it to exist.
    [[ -f $root/$CODEX_USAGE_MODULE ]] || return 0
    hits=$(scoped_code_hits "$root" '\bmax_redirects\(' src/provider/codex) || scan_failed check_codex_redirects
    zero=$(printf '%s' "$hits" | rg -e "^${CODEX_USAGE_MODULE}:[0-9]+:.*\.max_redirects\(0\)" || true)
    others=$(printf '%s' "$hits" | rg -v -e "^${CODEX_USAGE_MODULE}:[0-9]+:.*\.max_redirects\(0\)" || true)
    count=$(printf '%s' "$zero" | grep -c . || true)
    [[ $count -eq 1 && -z $others ]] && return 0
    printf '  the Codex usage client must follow no redirect: %s `.max_redirects(0)` line(s) in %s (expected 1)%s\n' \
        "$count" "$CODEX_USAGE_MODULE" "${others:+, and other max_redirects settings:}"
    [[ -n $others ]] && printf '%s\n' "$others"
    return 1
}

check_codex_decoded_cap() {
    local root=$1 hits
    [[ -f $root/$CODEX_USAGE_MODULE ]] || return 0
    hits=$(scoped_code_hits "$root" '\.take\(MAX_BODY_BYTES' "$CODEX_USAGE_MODULE") || scan_failed check_codex_decoded_cap
    [[ -n $hits ]] && return 0
    printf '  %s reads the body with no decoded-byte cap (`.take(MAX_BODY_BYTES…)`); gzip can expand past the wire limit\n' \
        "$CODEX_USAGE_MODULE"
    return 1
}

check_credits_state() {
    local hits
    hits=$(scoped_code_hits "$1" '\bCreditsState\b' "${CREDITS_STATE_FORBIDDEN[@]}") || scan_failed check_credits_state
    [[ -z $hits ]] && return 0
    printf '  Claude'"'"'s CreditsState in Codex code; Codex credits are CodexCredits (plan §9.3 m2):\n%s' "$hits"
    return 1
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
# plant_line <root> <line> [file]: appends one line to <file> (default the
# plant file) under <root>.
plant_line() { printf '\n%s\n' "$2" >>"$1/${3:-$PLANT_FILE}"; }

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
plant_expose_elsewhere() { plant_line "$1" 'fn _phase3_plant(s: &SecretString) -> String { s.expose_secret().to_owned() }'; }
plant_expose_public() { plant_line "$1" 'pub(crate) fn exposed<R>(s: &SecretString, f: impl FnOnce(&str) -> R) -> R { f("") }'; }
# A second exposure line inside an allowed file: the allow-list alone would
# pass it, the per-file count is what does not.
plant_expose_twice() { plant_line "$1/src/provider/claude" 'fn _phase3_plant(s: &SecretString) -> String { s.expose_secret().to_owned() }' credentials.rs; }
# Creates the module as well as the violation: until S30 writes it, this is
# also what proves the check can fail at all.
plant_codex_env() {
    mkdir -p "$1/$(dirname "$CODEX_HOME_MODULE")"
    printf 'fn _phase3_plant() -> Option<std::ffi::OsString> { std::env::var_os("X") }\n' \
        >>"$1/$CODEX_HOME_MODULE"
}

plant_expose_third() {
    mkdir -p "$1/src/provider/codex"
    [[ -f $1/src/provider/codex/credentials.rs ]] || printf 'fn exposed() { s.expose_secret() }\n' >"$1/src/provider/codex/credentials.rs"
    plant_line "$1" 'fn _phase3_plant(s: &SecretString) -> String { s.expose_secret().to_owned() }' src/provider/claude/usage.rs
}
plant_auth_json() { plant_line "$1" 'const _PHASE3_PLANT: &str = "auth.json";'; }
plant_account_header() { plant_line "$1" 'const _PHASE3_PLANT: &str = "ChatGPT-Account-Id";'; }
plant_toml() { plant_line "$1" 'fn _phase3_plant(t: &str) { let _ = toml::de::DeTable::parse(t); }'; }
plant_locked_read() { plant_line "$1" 'fn _phase3_plant(c: Credentials, g: &Guard) { let _ = LockedCredentials::from_locked_read(c, g); }'; }
plant_locked_read_fmt() { plant_line "$1" $'fn _phase3_plant(c: Credentials, g: &Guard) {\n    from_locked_read(\n        c, g,\n    );\n}'; }
plant_marker_mutator() { plant_line "$1" 'fn _phase3_plant(ns: &OwnedNamespace<'"'"'_>) { let _ = ns.refresh_state().clear_inflight(DefiniteOutcome::Applied); }'; }
plant_marker_mutator_fmt() { plant_line "$1" $'fn _phase3_plant(s: &RefreshStateFile) {\n    s\n        .reset_floor();\n}'; }
plant_stop_complete_elsewhere() { plant_line "$1" 'fn _phase3_plant() -> StopPolicy<'"'"'static> { StopPolicy::Complete }'; }
plant_stop_second_none() {
    mkdir -p "$1/src/provider/codex"
    plant_line "$1" '    let _ = self.ns.auth_file().write(&bytes, None, StopPolicy::Complete, &faults);' src/provider/codex/auth_store.rs
}
plant_codex_debug_assert() {
    mkdir -p "$1/src/provider/codex"
    plant_line "$1" 'fn _phase3_plant(a: &Path, b: &Path) { debug_assert_eq!(a, b); }' src/provider/codex/lock.rs
}
plant_marker_mutator_ufcs() { plant_line "$1" 'fn _phase3_plant(s: &RefreshStateFile) { let _ = RefreshStateFile::clear_inflight(s, DefiniteOutcome::Applied); }'; }
plant_codex_flock() {
    mkdir -p "$1/src/provider/codex"
    plant_line "$1" 'fn _phase3_plant(f: &std::fs::File) { let _ = rustix::fs::flock(f, rustix::fs::FlockOperation::LockExclusive); }' src/provider/codex/home.rs
}
plant_wham_usage() { plant_line "$1" 'const _PHASE3_PLANT: &str = "https://chatgpt.com/backend-api/wham/usage";'; }
plant_codex_usage_url() { plant_line "$1" 'const _PHASE3_PLANT: &str = "AGCTL_CODEX_USAGE_URL";'; }
plant_codex_timeouts() {
    mkdir -p "$1/src/provider/codex"
    plant_line "$1" 'fn _phase3_plant(b: ConfigBuilder) -> ConfigBuilder { b.timeout_global(None) }' src/provider/codex/usage.rs
}
plant_codex_status_as_error() {
    mkdir -p "$1/src/provider/codex"
    plant_line "$1" $'fn _phase3_plant(b: ConfigBuilder) -> ConfigBuilder {\n    b\n        .http_status_as_error(true)\n}' src/provider/codex/usage.rs
}
plant_codex_redirects_removed() {
    [[ -f $1/$CODEX_USAGE_MODULE ]] || phase3_die "plant_codex_redirects_removed: $CODEX_USAGE_MODULE is missing from the snapshot"
    perl -ni -e 'print unless /\.max_redirects\(0\)/' "$1/$CODEX_USAGE_MODULE"
}
plant_codex_redirects_followed() {
    plant_line "$1" $'fn _phase3_plant(b: ConfigBuilder) -> ConfigBuilder {\n    b\n        .max_redirects(10)\n}' src/provider/codex/usage.rs
}
plant_codex_decoded_cap_removed() {
    [[ -f $1/$CODEX_USAGE_MODULE ]] || phase3_die "plant_codex_decoded_cap_removed: $CODEX_USAGE_MODULE is missing from the snapshot"
    perl -ni -e 'print unless /\.take\(MAX_BODY_BYTES/' "$1/$CODEX_USAGE_MODULE"
}
plant_credits_state() {
    mkdir -p "$1/src/provider/codex"
    plant_line "$1" 'fn _phase3_plant(c: &crate::usage::model::CreditsState) {}' src/provider/codex/account.rs
}
plant_credits_state_json_v2() { plant_line "$1" $'fn _phase3_plant(\n    c: CreditsState,\n) {}' src/render/json_v2.rs; }
plant_state_path() { plant_line "$1" 'fn _phase3_plant(p: &Paths) { let _ = p.codex_state_dir().join(".state/x"); }'; }

# rustfmt-shaped plants: the match begins the line's code text (review F1).
plant_unwrap_fmt() { plant_line "$1" $'fn _phase3_plant() {\n    let _ = Some(1)\n        .unwrap();\n}'; }
plant_remove_set_fmt() { plant_line "$1" $'fn _phase3_plant(d: &str) {\n    unlinkat(d);\n}'; }
plant_codex_home_fmt() { plant_line "$1" $'const _PHASE3_PLANT: [&str; 1] = [\n    "CODEX_HOME",\n];'; }
plant_unlink_helper_fmt() { plant_line "$1" $'fn _phase3_plant(d: BorrowedFd<\'_>) {\n    unlink_at(d, "x");\n}'; }
plant_remove_dir_under_fmt() { plant_line "$1" $'fn _phase3_plant(a: &Path, p: &Path) {\n    remove_dir_under(\n        a, p,\n    );\n}'; }

CHECKS=(unwrap remove_set codex_home sentinels jwt bearer removal_helpers exposed codex_bin codex_env
    exposure_count auth_json account_header toml locked_read marker_mutators stop_policy
    codex_debug_assert state_path codex_flock wham_usage codex_usage_url codex_timeouts codex_redirects codex_decoded_cap credits_state)

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
    "exposed plant_expose_elsewhere"
    "exposed plant_expose_public"
    "exposed plant_expose_twice"
    "codex_bin plant_codex_bin"
    "codex_env plant_codex_env"
    "exposure_count plant_expose_third"
    "auth_json plant_auth_json"
    "account_header plant_account_header"
    "toml plant_toml"
    "locked_read plant_locked_read"
    "locked_read plant_locked_read_fmt"
    "marker_mutators plant_marker_mutator"
    "marker_mutators plant_marker_mutator_fmt"
    "stop_policy plant_stop_complete_elsewhere"
    "stop_policy plant_stop_second_none"
    "codex_debug_assert plant_codex_debug_assert"
    "state_path plant_state_path"
    "marker_mutators plant_marker_mutator_ufcs"
    "codex_flock plant_codex_flock"
    "wham_usage plant_wham_usage"
    "codex_usage_url plant_codex_usage_url"
    "codex_timeouts plant_codex_timeouts"
    "codex_timeouts plant_codex_status_as_error"
    "codex_redirects plant_codex_redirects_removed"
    "codex_redirects plant_codex_redirects_followed"
    "codex_decoded_cap plant_codex_decoded_cap_removed"
    "credits_state plant_credits_state"
    "credits_state plant_credits_state_json_v2"
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

    # Review N4 / S30 F12: each spelling of a bearer line must be counted.
    local bearer_index=0 bearer_line bearer_log
    for bearer_line in 'authorization: bearer <-here' 'authorization: bearer%20<-here' $'authorization: BEARER\t<-here'; do
        bearer_log="$WORK/planted-needle-bearer-$bearer_index.log"
        printf '%s\n' "$bearer_line" >"$bearer_log"
        if check_logs "$bearer_log" >"$bearer_log.txt"; then
            printf 'planted %-26s NOT CAUGHT: %q was not counted\n' "needle-bearer-$bearer_index" "$bearer_line" >&2
            failed=1
        else
            printf 'planted %-26s caught: %q\n' "needle-bearer-$bearer_index" "$bearer_line"
        fi
        bearer_index=$((bearer_index + 1))
    done

    local index=0 needle planted_log
    for needle in "${LEAK_NEEDLES[@]}" "${LOG_ONLY_NEEDLES[@]}"; do
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
