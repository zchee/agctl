#!/usr/bin/env bash
# AC77 and AC83 — the documentation gates.
#
# Two rules about prose, both cheap enough to run on every change, and both
# expressed as greps rather than as judgement (AC77's wording: "a grep, not a
# judgement").
#
#   AC77  README.md no longer carries the retired absolute claim that agctl
#         never writes the keychain, and does carry the enumerated replacement
#         that names both `WriteTarget` constructors. The retired sentence was
#         true in phase 1 and false from the moment `use --live` landed; a
#         README that still made it would be worse than one that said nothing,
#         because a reader would rely on it.
#
#   AC83  The two development wrappers this machine uses -- the direnv layout
#         invocation, and the dev-profile cargo config that redirects the
#         target directory -- appear nowhere in README.md, docs/, scripts/ or
#         src/. They are this machine's wrappers, not project build
#         instructions: `.envrc` is untracked, so a fresh clone has no layout
#         and no RUSTFLAGS at all, and a reader who copies a wrapped command
#         gets an error rather than a build. Both stay in AGENTS.md (which
#         CLAUDE.md symlinks to) and in .claude/skills/check/SKILL.md, which
#         are lane-facing; neither path is scanned here.
#
# Why this is a script rather than one more line in the check skill: the v2
# spelling of AC83 joined its two patterns with a backslash-pipe, and in
# ripgrep's regex that is an ESCAPED LITERAL PIPE, not alternation. The gate
# looked for one eighteen-character string containing a pipe character, found
# it nowhere, and passed unconditionally -- on the one rule the user had just
# ruled on. So: every alternation below is `-e A -e B`, which cannot be
# mis-escaped by a later edit, and the AC83 check runs FIRST against a planted
# file that contains both strings and is REQUIRED to fail. A gate that has
# never been seen to fail is not a gate.
#
# A note on how the two patterns are spelled, because it is deliberate and
# looks like a typo otherwise. This file lives under scripts/, which AC83
# scans, so a pattern written as the plain literal would match itself and the
# gate could never pass. A bracketed space matches a space and is not matched
# by one, and a backslash-escaped dot in the file is not matched by a pattern
# wanting a literal dot there. Both spellings below are chosen so that AC83's
# own hand-run command -- the one written out in the plan, with both literals
# quoted -- still returns empty against this tree, this file included. Read
# them as the literals; do not "fix" them into literals.
#
# Usage: scripts/docs-gate.sh
# Exit:  0 both gates passed; 1 a gate failed, including the self-test.

set -euo pipefail

unset CDPATH
repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$repo_root"

if ! command -v rg >/dev/null 2>&1; then
	echo "docs-gate: rg is required but not on PATH" >&2
	exit 1
fi

# AC83's two patterns. See the note above on why they are spelled this way.
wrapper_pattern='direnv[ ]exec'
devconfig_pattern='config\.dev\.toml'

# The reader-facing surfaces. AGENTS.md and .claude/skills/ are absent on
# purpose: they are lane-facing and the wrappers belong there.
scanned=(README.md docs scripts src)

# Runs AC83's grep over the paths given. Returns 0 when something matched
# (i.e. the rule is VIOLATED) and 1 when nothing did, which is rg's own
# convention and is why both call sites read the exit status, not the output.
wrappers_found() {
	rg -n -e "$wrapper_pattern" -e "$devconfig_pattern" "$@"
}

failures=0

echo "AC83 self-test (a planted file must fail the gate):"
planted_dir=$(mktemp -d "${TMPDIR:-/tmp}/agctl-docs-gate.XXXXXX")
trap 'rm -rf "$planted_dir"' EXIT
planted=$planted_dir/planted.md

# Assembled from pieces rather than written out, for the same reason the
# patterns are: the planted file must hold the real literals, and this file
# must not.
wrapper_word=direnv
wrapper_verb=exec
devconfig_stem=config
devconfig_ext=toml
printf 'run %s %s cargo build\n' "$wrapper_word" "$wrapper_verb" >"$planted"
printf 'cargo --config ~/.config/rust/%s.dev.%s nextest run\n' "$devconfig_stem" "$devconfig_ext" >>"$planted"

if wrappers_found "$planted" >/dev/null 2>&1; then
	echo "  ok      the gate detects a planted violation"
else
	echo "  FAIL    a file containing both strings did NOT fail the gate" >&2
	echo "  FAIL    the patterns are inert; suspect a mis-escaped alternation" >&2
	echo "  FAIL    planted file was:" >&2
	sed 's/^/          /' "$planted" >&2
	exit 1
fi

echo
echo "AC83 (development wrappers absent from reader-facing surfaces):"
if hits=$(wrappers_found "${scanned[@]}" 2>/dev/null); then
	echo "  FAIL    a development wrapper appears in a reader-facing surface:" >&2
	printf '%s\n' "$hits" | sed 's/^/          /' >&2
	failures=$((failures + 1))
else
	printf '  ok      %s\n' "no match in ${scanned[*]}"
fi

echo
echo "AC77 (README's keychain-write claim):"

# The retired sentence, as a fixed string: it is prose, not a pattern.
retired='never writes the keychain'
if rg -q -F -- "$retired" README.md; then
	echo "  FAIL    README still carries the retired claim:" >&2
	rg -n -F -- "$retired" README.md | sed 's/^/          /' >&2
	failures=$((failures + 1))
else
	printf '  ok      %s\n' "retired claim absent"
fi

# The enumerated replacement. Naming both constructors is what makes the claim
# checkable rather than reassuring: the set of keychain items agctl can write
# is exactly the set these two can name, so a README that enumerates them can
# be diffed against src/secret/keychain_write.rs by anyone who doubts it.
for ctor in 'WriteTarget::live' 'WriteTarget::migrated'; do
	if rg -q -F -- "$ctor" README.md; then
		printf '  ok      %-24s named in README\n' "$ctor"
	else
		printf '  FAIL    %-24s not named in README\n' "$ctor" >&2
		failures=$((failures + 1))
	fi
done

echo
if [ "$failures" -eq 0 ]; then
	echo "docs-gate: PASS"
	exit 0
fi

echo "docs-gate: FAIL — $failures check(s) failed" >&2
exit 1
