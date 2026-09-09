#!/usr/bin/env bash
# AC37 — the release-artifact gate.
#
# Builds agentctl the way a release is built (default features, release profile)
# into a scratch target directory, then proves two things about the artifact:
#
#   1. none of the ten test-seam environment-variable names appear in it, and
#   2. the three production-visible names do.
#
# The ten are one representative name per seam-owning module, not the whole
# test-only surface — fixtures/fake-security.sh alone defines ten
# AGENTCTL_FAKE_SECURITY_* names on its own. The fake's write knob is the one
# exception to "one per owner": the keychain *write* path is the only seam that
# can change a keychain, so it is gated by name rather than by family. A new
# seam-owning module adds its representative to the `seams` array below and to
# the table in .claude/skills/check/SKILL.md, in the same change that
# introduces it.
#
# The first is the one that matters. The `testing` feature compiles overrides for
# the OAuth token endpoint, the authorize endpoint and the usage endpoint; a
# release binary that honoured AGENTCTL_CLAUDE_TOKEN_URL would send a refresh
# token wherever an environment variable pointed it. The second half is there so
# that a build which somehow contains no strings at all cannot pass by accident.
#
# The build goes to a scratch directory, never ./target and never the shared
# dev target dir (~/.cache/rust/target, formerly /Volumes/tmpfs/target), so
# running this cannot disturb a working tree's artifacts or another lane's
# build. Override with AGENTCTL_RELEASE_GATE_TARGET.
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
	AGENTCTL_FAULT
	AGENTCTL_FAULT_RESUME
	AGENTCTL_KEYCHAIN_BACKEND
	AGENTCTL_SECURITY_BIN
	AGENTCTL_CLAUDE_USAGE_URL
	AGENTCTL_CLAUDE_TOKEN_URL
	AGENTCTL_CLAUDE_AUTHORIZE_URL
	AGENTCTL_FAKE_SECURITY_LOG
	AGENTCTL_FAKE_SECURITY_WRITE_EXIT
	AGENTCTL_NO_BROWSER
)

# The production surface. Every one of these must be PRESENT.
production=(
	AGENTCTL_CONFIG_DIR
	AGENTCTL_CLAUDE_USER_AGENT
	AGENTCTL_CLAUDE_OAUTH_SCOPES
)

if [ -n "${AGENTCTL_RELEASE_GATE_TARGET:-}" ]; then
	target_dir=$AGENTCTL_RELEASE_GATE_TARGET
elif [ -d "${XDG_CACHE_HOME:-$HOME/.cache}/rust" ]; then
	target_dir=${XDG_CACHE_HOME:-$HOME/.cache}/rust/agentctl-release-gate
else
	target_dir=${TMPDIR:-/tmp}/agentctl-release-gate
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

echo "release-gate: target-dir $target_dir"
echo "release-gate: building default-feature release"
cargo build --release --target-dir "$target_dir"

binary=$target_dir/release/agentctl
if [ ! -f "$binary" ]; then
	echo "release-gate: FAIL — no binary at $binary" >&2
	exit 1
fi

echo "release-gate: artifact $binary ($(wc -c <"$binary" | tr -d ' ') bytes)"
echo

failures=0

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
if [ "$failures" -eq 0 ]; then
	echo "release-gate: PASS — ${#seams[@]} seams absent, ${#production[@]} production names present"
	exit 0
fi

echo "release-gate: FAIL — $failures check(s) failed" >&2
echo "release-gate: a seam in a release artifact means the build enabled the \`testing\`" >&2
echo "release-gate: feature. Never build or install agentctl with --all-features." >&2
exit 1
