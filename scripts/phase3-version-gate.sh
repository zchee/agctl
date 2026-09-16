#!/usr/bin/env bash
# AC99 — a phase-2 build refuses a version-2 registry, and writes nothing.
#
# The registry gained `codex_accounts` and a version that is derived from the
# content: 1 while there are no Codex rows, 2 once there are (decision D-038).
# A build that predates the member cannot keep it across a write, so it must
# refuse the file rather than read it and silently drop the rows on its next
# save. That claim is about a *binary that no longer exists in this tree*, so
# no test in this repository can make it: the gate builds the old binary from
# the base commit and runs it.
#
# What it proves, in order:
#
#   1. the phase-2 binary, given a version-2 registry, exits non-zero;
#   2. its message names the version, so a user can tell this from a corrupt
#      file;
#   3. the registry is byte-identical afterwards (`AgctlConfig::update` never
#      ran);
#   4. the same binary reads a version-1 registry as it always did, so the
#      refusal is about the version and not about the file.
#
# Usage: scripts/phase3-version-gate.sh
#
# Environment:
#   PHASE3_BASE        the commit to build the old binary from (default: the
#                      W1 base pinned below).
#   PHASE3_GATE_TARGET cargo target directory for that build. Defaults to a
#                      directory under $TMPDIR, never ./target: this binary is
#                      a comparison artefact, not something to ship.

set -euo pipefail

# `<W1 base>` (plan ledger #257): the last commit before phase 3 touched the
# registry. Overridable so the gate can be pointed at a release tag later.
BASE=${PHASE3_BASE:-317722b}

die() {
	printf 'phase3-version-gate: %s\n' "$*" >&2
	exit 1
}

main() {
	command -v shasum >/dev/null || die "shasum is required"
	cd "$(git rev-parse --show-toplevel)"

	git rev-parse --verify --quiet "$BASE^{commit}" >/dev/null ||
		die "the base commit $BASE is not in this repository"

	WORK=$(mktemp -d "${TMPDIR:-/tmp}/agctl-phase3-version.XXXXXX")
	OLD="$WORK/base"
	trap 'git worktree remove --force "$OLD" 2>/dev/null || rm -rf "$OLD"; git worktree prune; rm -rf "$WORK"' EXIT

	git worktree add --quiet --detach "$OLD" "$BASE"
	printf 'base %s (%s)\n' "$BASE" "$(git -C "$OLD" log -1 --format=%s)"

	local target=${PHASE3_GATE_TARGET:-${TMPDIR:-/tmp}/agctl-phase3-version-target}
	# `testing` so the keychain can be switched off: this gate is about one
	# refusal from one file, and a build that could reach the real `security(1)`
	# would be reading the developer's keychain to prove a point about JSON.
	#
	# RUSTFLAGS is cleared deliberately. The worktree has no environment of its
	# own, so it would inherit whatever the invoking shell exports — and a flag
	# set for another toolchain fails this build for a reason that has nothing
	# to do with what is being proved. Nothing here depends on optimisation.
	printf 'building the phase-2 binary (this takes a few minutes the first time)\n'
	(
		cd "$OLD"
		env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS \
			cargo build --quiet --features testing --target-dir "$target"
	) || die "the phase-2 binary would not build"

	local binary="$target/debug/agctl"
	[[ -x $binary ]] || die "no binary at $binary"

	local store="$WORK/store"
	mkdir -p "$store"

	# A version-2 registry: one Codex row, and no Claude account at all, so
	# nothing but the version can decide the outcome.
	cat >"$store/config.json" <<'JSON'
{
  "version": 2,
  "accounts": [],
  "forgotten_services": [],
  "codex_accounts": [
    {
      "chatgpt_user_id": "user-01",
      "chatgpt_account_id": "acct-01",
      "email": null,
      "plan_type": null,
      "label": null,
      "kind": { "kind": "live" },
      "forgotten": false,
      "created_at": "2026-09-17T00:00:00Z"
    }
  ]
}
JSON

	local before after status=0 output
	before=$(shasum -a 256 <"$store/config.json")

	output=$(HOME="$WORK/home" AGCTL_KEYCHAIN_BACKEND=none \
		"$binary" --config-dir "$store" claude accounts list 2>&1) || status=$?

	after=$(shasum -a 256 <"$store/config.json")

	if [[ $status -eq 0 ]]; then
		printf '%s\n' "$output" >&2
		die "the phase-2 binary accepted a version-2 registry"
	fi
	printf 'refused: exit %s\n' "$status"

	if ! printf '%s' "$output" | grep -q 'version 2'; then
		printf '%s\n' "$output" >&2
		die "the refusal does not name the version, so a user cannot tell it from a corrupt file"
	fi
	printf 'message:  %s\n' "$(printf '%s' "$output" | head -n 1)"

	[[ $before == "$after" ]] ||
		die "the phase-2 binary rewrote the registry it refused"
	printf 'unchanged: %s\n' "${before%% *}"

	# The control: the same binary, the same command, a version-1 file.
	cat >"$store/config.json" <<'JSON'
{
  "version": 1,
  "accounts": [],
  "forgotten_services": []
}
JSON
	status=0
	output=$(HOME="$WORK/home" AGCTL_KEYCHAIN_BACKEND=none \
		"$binary" --config-dir "$store" claude accounts list 2>&1) || status=$?
	if [[ $status -ne 0 ]]; then
		printf '%s\n' "$output" >&2
		die "the phase-2 binary refused a version-1 registry too, so the gate proves nothing"
	fi
	printf 'control:  version 1 still reads\n'

	printf 'phase3-version-gate: ok\n'
}

main "$@"
