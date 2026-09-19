#!/usr/bin/env bash
# AC37 and AC78 — the release-artifact gate.
#
# Builds agctl the way a release is built (default features, release profile)
# into a scratch target directory, then proves two things about the artifact:
#
#   1. none of the thirteen test-seam environment-variable names appear in it, and
#   2. the three production-visible names do.
#
# It also runs scripts/docs-gate.sh first (AC77 and AC83), so that one command
# covers everything a release must satisfy that the three check-skill commands
# do not. That gate is cheap and needs no build; it is run before the build so
# a prose failure is reported in seconds rather than after a release compile.
#
# It also checks, from cargo's normal-edge feature resolution, that the shipped
# and the `testing` builds get `serde_json/float_roundtrip` (the live
# `.claude.json` guard's exact float parsing).
#
# The thirteen are one representative name per seam-owning module, not the whole
# test-only surface — fixtures/fake-security.sh alone defines ten
# AGCTL_FAKE_SECURITY_* names on its own. The fake's write knob is the one
# exception to "one per owner": the keychain *write* path is the only seam that
# can change a keychain, so it is gated by name rather than by family. A new
# seam-owning module adds its representative to the `seams` array below and to
# the table in .claude/skills/check/SKILL.md, in the same change that
# introduces it.
#
# Three AGCTL_* names in the tree are deliberately NOT in the array below,
# because none of them is a crate seam and adding them would blur what the
# array means:
#
#   AGCTL_LOCK_CHILD_ROLE, AGCTL_LOCK_CHILD_DIR
#     Declared and read only inside src/secret/claude_lock_tests.rs, a
#     `#[cfg(test)]` sibling, to tell a re-executed copy of the *test* binary
#     to act as the lock child. They are not compiled into the crate at all,
#     and tests/e2e_lock.rs already asserts that no non-test source mentions
#     them — a stronger check than this artifact grep, since it fires the
#     moment one moves into production code rather than only at release.
#
#   AGCTL_E2E_MARKER
#     Set by tests/e2e_isolate.rs on a child it spawns, to prove the child's
#     environment is passed through. The crate never reads it.
#
# Phase 3 adds AGCTL_CODEX_BIN (S29b): the `codex` binary `agctl codex login`
# spawns. Listed from the step that introduces the name rather than from the
# step that first reads it, so no intermediate commit ships a seam nobody has
# gated. Production resolves `codex` on PATH and refuses with `codex not on
# PATH`; a release binary that honoured the override would run whatever an
# environment variable pointed at, with the user's browser session behind it.
#
# S31 adds AGCTL_CODEX_USAGE_URL: the Codex usage endpoint's base URL, read
# only by src/provider/codex/usage.rs under `testing`. A release binary that
# honoured it would send a ChatGPT bearer token and the account id header
# wherever an environment variable pointed them. AGCTL_CODEX_USER_AGENT is not
# yet on the production list: at S31 nothing outside tests constructs the
# Codex client, so the name is folded out of a release artifact (ledger #268);
# the step whose command first reads it adds the presence check.
#
# S32 adds AGCTL_CODEX_TOKEN_URL: the Codex token endpoint, read only by
# src/provider/codex/oauth.rs under `testing`. A release binary that honoured
# it would POST a Codex refresh token wherever an environment variable pointed
# it — the same exfiltration AGCTL_CLAUDE_TOKEN_URL is gated against.
#
# S33 adds AGCTL_CODEX_USER_AGENT to the production list (plan AC110): from
# S33 `agctl codex status` builds the Codex usage client, so the name is no
# longer folded out of a release artifact — verified with `strings` on a
# default-feature release build before this line was added (ledger #268).
#
# Phase 2 added no other seam: AGCTL_SECURITY_BIN (the write transport) and
# AGCTL_CLAUDE_PROFILE_URL (the live swap's profile GET) are both listed, and
# `rg -o 'AGCTL_[A-Z0-9_]+' src --glob '!*_tests.rs'` enumerates nothing else
# outside this array and the production list below.
#
# The first is the one that matters. The `testing` feature compiles overrides for
# the OAuth token endpoint, the authorize endpoint, the profile endpoint and the
# usage endpoint; a release binary that honoured AGCTL_CLAUDE_TOKEN_URL would send
# a refresh token wherever an environment variable pointed it, and one that
# honoured AGCTL_CLAUDE_PROFILE_URL would send the live item's bearer token. The
# second half is there so that a build which somehow contains no strings at all
# cannot pass by accident.
#
# The build goes to a scratch directory, never ./target and never the shared
# dev target dir (~/.cache/rust/target, formerly /Volumes/tmpfs/target), so
# running this cannot disturb a working tree's artifacts or another lane's
# build. Override with AGCTL_RELEASE_GATE_TARGET.
#
# No dev-profile cargo config is passed: this is a release build with its own
# --target-dir.
#
# The build is a plain `cargo build --release`, exactly the command README
# documents, run in whatever environment the caller has (a developer shell
# that loads a project .envrc includes its RUSTFLAGS; a fresh clone has none).
# The seam detection below does not depend on RUSTFLAGS either way: the seam
# constants either do not exist at all (feature off) or are live and
# referenced (feature on), so a dead-strip flag cannot remove them in either
# case.
#
# Usage: scripts/release-gate.sh
# Exit:  0 every check passed; 1 a check failed or the build did not produce a
#        binary.

set -euo pipefail

unset CDPATH
repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$repo_root"

# Resolves $1 to an absolute, symlink-free path, without requiring that it
# exist yet. Relative spellings, `.` and `..` components, and a target that
# does not exist must all still land on the physical path the shared-dir
# refusal below compares against — otherwise "target", "./target" or
# ".../target/../target" walk past a check written against the canonical
# spelling. The nearest existing ancestor is resolved with `cd` + `pwd -P`;
# any path segments below that ancestor are appended back on literally.
canonicalize() {
	local target=$1
	local remainder=
	local parent
	local resolved
	while [ ! -d "$target" ]; do
		remainder=$(basename -- "$target")${remainder:+/}$remainder
		parent=$(dirname -- "$target")
		if [ "$parent" = "$target" ]; then
			break
		fi
		target=$parent
	done
	resolved=$(cd -- "$target" && pwd -P)
	if [ -n "$remainder" ]; then
		printf '%s/%s\n' "$resolved" "$remainder"
	else
		printf '%s\n' "$resolved"
	fi
}

# The test-only seams. Every one of these must be ABSENT from the artifact.
seams=(
	AGCTL_FAULT
	AGCTL_FAULT_RESUME
	AGCTL_KEYCHAIN_BACKEND
	AGCTL_SECURITY_BIN
	AGCTL_CLAUDE_USAGE_URL
	AGCTL_CLAUDE_TOKEN_URL
	AGCTL_CLAUDE_AUTHORIZE_URL
	AGCTL_CLAUDE_PROFILE_URL
	AGCTL_FAKE_SECURITY_LOG
	AGCTL_FAKE_SECURITY_WRITE_EXIT
	AGCTL_NO_BROWSER
	AGCTL_CODEX_BIN
	AGCTL_CODEX_USAGE_URL
	AGCTL_CODEX_TOKEN_URL
	# S34: the login child's `testing`-only allowlist prefix and the pause
	# point between `verify_login` and `install`.
	#
	# What the PREFIX entry proves, and what it does not: it proves no copy of
	# the literal survives as data in the artifact. It does NOT prove a
	# default-feature build cannot honour the prefix — a `starts_with` against
	# a short constant compiles to immediate compares and leaves no string
	# behind. That half is `scripts/phase3-greps.sh`'s `fake_prefix` rule (the
	# literal spelled once, under `#[cfg(feature = "testing")]`) plus the
	# default-feature clippy gate. The fake's individual knob names are read by
	# the fixture script only — agctl's code names none of them — so they are
	# not listed here.
	AGCTL_FAKE_CODEX_
	codex_login_before_install
)

# The production surface. Every one of these must be PRESENT.
production=(
	AGCTL_CONFIG_DIR
	AGCTL_CLAUDE_USER_AGENT
	AGCTL_CLAUDE_OAUTH_SCOPES
	AGCTL_CODEX_USER_AGENT
)

if [ -n "${AGCTL_RELEASE_GATE_TARGET:-}" ]; then
	target_dir=$AGCTL_RELEASE_GATE_TARGET
elif [ -d "${XDG_CACHE_HOME:-$HOME/.cache}/rust" ]; then
	target_dir=${XDG_CACHE_HOME:-$HOME/.cache}/rust/agctl-release-gate
else
	target_dir=${TMPDIR:-/tmp}/agctl-release-gate
fi

target_dir=$(canonicalize "$target_dir")

case "$target_dir" in
"$repo_root"/target | "$repo_root"/target/* | "${XDG_CACHE_HOME:-$HOME/.cache}"/rust/target | "${XDG_CACHE_HOME:-$HOME/.cache}"/rust/target/* | /Volumes/tmpfs/target | /Volumes/tmpfs/target/*)
	echo "release-gate: refusing to build into the shared target dir $target_dir" >&2
	exit 1
	;;
esac

for tool in rg cargo; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		echo "release-gate: $tool is required but not on PATH" >&2
		exit 1
	fi
done

failures=0

# AC77 and AC83 first: no build needed, so a prose failure is reported in
# seconds. Its failures join this script's count rather than exiting here, so
# one run reports everything that is wrong rather than the first thing.
echo "release-gate: running scripts/docs-gate.sh (AC77, AC83)"
if "$repo_root/scripts/docs-gate.sh"; then
	echo "release-gate: docs-gate PASS"
else
	echo "release-gate: docs-gate FAIL" >&2
	failures=$((failures + 1))
fi
echo

echo "release-gate: target-dir $target_dir"
echo "release-gate: building default-feature release"
cargo build --release --target-dir "$target_dir"

binary=$target_dir/release/agctl
if [ ! -f "$binary" ]; then
	echo "release-gate: FAIL — no binary at $binary" >&2
	exit 1
fi

echo "release-gate: artifact $binary ($(wc -c <"$binary" | tr -d ' ') bytes)"
echo

echo "test seams (must be absent):"
for name in "${seams[@]}"; do
	count=$(rg -a -c -F -- "$name" "$binary" || true)
	count=${count:-0}
	if [ "$count" -eq 0 ]; then
		printf '  ok      %-32s 0\n' "$name"
	else
		printf '  FAIL    %-32s %s\n' "$name" "$count"
		failures=$((failures + 1))
	fi
done

echo
echo "production names (must be present):"
for name in "${production[@]}"; do
	count=$(rg -a -c -F -- "$name" "$binary" || true)
	count=${count:-0}
	if [ "$count" -gt 0 ]; then
		printf '  ok      %-32s %s\n' "$name" "$count"
	else
		printf '  FAIL    %-32s 0\n' "$name"
		failures=$((failures + 1))
	fi
done

echo
echo "resolved dependency features (must be present):"
# The live `.claude.json` rewrite's guard needs exact float parsing. Every test
# build gets `serde_json/float_roundtrip` from a dev-dependency, so only the
# normal-edge feature resolution — the shipped build's, and the `testing` build
# AC75 runs — can show whether the artifact has it. `-e features` alone would
# include the dev-dependency edge and pass without the feature.
for features in "" "testing"; do
	label=${features:-default}
	# Captured first rather than piped: under `pipefail` an early `rg -q` exit
	# could fail the pipeline through `cargo tree`'s SIGPIPE.
	tree=$(cargo tree --offline -e features,normal ${features:+--features "$features"} -i serde_json 2>/dev/null || true)
	if rg -q -F 'serde_json feature "float_roundtrip"' <<<"$tree"; then
		printf '  ok      %-32s %s\n' "serde_json/float_roundtrip" "$label"
	else
		printf '  FAIL    %-32s %s\n' "serde_json/float_roundtrip" "$label"
		failures=$((failures + 1))
	fi
done

echo
if [ "$failures" -eq 0 ]; then
	echo "release-gate: PASS — docs-gate clean, ${#seams[@]} seams absent, ${#production[@]} production names present"
	exit 0
fi

echo "release-gate: FAIL — $failures check(s) failed" >&2
echo "release-gate: a seam in a release artifact means the build enabled the \`testing\`" >&2
echo "release-gate: feature. Never build or install agctl with --all-features." >&2
exit 1
