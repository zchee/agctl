#!/bin/sh
# A stand-in for the `codex` binary, wired through AGCTL_CODEX_BIN under the
# `testing` feature. The twin of fixtures/fake-security.sh, and it exists for
# the same reason: `agctl codex login` spawns the vendor's own CLI, and a test
# that spawned the real one would open a browser and mint a real grant against
# the developer's own ChatGPT account.
#
# It records what it was asked to do and then does exactly what the control
# variables say. Every path it writes is inside the scratch home agctl handed
# it through CODEX_HOME; it never looks at, let alone touches, a home it was
# not given.
#
# WITH NO KNOBS SET it reproduces what fact F81 measured a NORMAL, successful
# `codex login` to leave behind at alpha.12 — see "the residue" below. That is
# deliberate: the residue includes an unheld `tmp/arg0/codex-arg0<rand>/.lock`,
# and a survivor check that treated a lock file's existence as evidence would
# refuse every real login (ledger #310). The happy-path test only proves what
# it claims if the happy path leaves a real login's mess behind.
#
#   AGCTL_FAKE_CODEX_LOG        append `argv`, `cwd`, `env`, `residue` and `exit`
#                               records here
#   AGCTL_FAKE_CODEX_SLEEP      seconds to sleep before doing anything
#   AGCTL_FAKE_CODEX_EXIT       exit status (default 0)
#   AGCTL_FAKE_CODEX_AUTH       a file whose contents become <CODEX_HOME>/auth.json
#   AGCTL_FAKE_CODEX_DAEMON_DIR create <CODEX_HOME>/app-server-daemon/ as well
#   AGCTL_FAKE_CODEX_NO_RESIDUE leave no `tmp/arg0` residue at all
#   AGCTL_FAKE_CODEX_HELD_LOCK  leave the residue's `.lock` HELD by a live
#                               process, so the refusal path meets a real held
#                               lock and not a simulated one
#   AGCTL_FAKE_CODEX_KEYCHAIN_GAIN
#                               a fake `security` dump file: append one
#                               `Codex Auth` record to it, as a child that put
#                               its credential in the keychain would
#   AGCTL_FAKE_CODEX_TOUCH      create this file (a marker another fake reads)
#   AGCTL_FAKE_CODEX_SENTINEL   a directory OUTSIDE the scratch: link it from
#                               inside the residue, so a cleanup that followed
#                               a link would reach it. A knob, not default
#                               residue: F81 measured links to FILES
#

# There is deliberately no knob that swaps `auth.json` after this process
# exits. That used to exist and never fired inside its window (a 0.2 s timer
# against an agctl that had already removed the scratch). The AC126 test now
# does the swap itself, while agctl waits at a `testing` pause point.
#
# THE ENVIRONMENT RECORD IS NAMES ONLY, except for the three variables whose
# values the assertions need (CODEX_HOME, HOME, TMPDIR). A fixture that dumped
# every value would be a fixture that writes secrets to a file the moment
# somebody runs it with a real environment.

# The modes fact F81 measured a real login to leave: `drwx------` and
# `-rw-------`. Set before anything is created.
umask 077

if [ -n "${AGCTL_FAKE_CODEX_LOG:-}" ]; then
	{
		printf 'argv %s\n' "$*"
		printf 'cwd %s\n' "$(pwd)"
		# One `env <NAME>` line per variable, sorted, so a test can assert on
		# the whole environment rather than on the names it happened to think
		# of — without the values ever reaching disk.
		env | sed 's/=.*//' | LC_ALL=C sort | sed 's/^/env /'
		# The three the assertions actually compare. None of them is a secret,
		# and each is named here rather than swept up by a pattern.
		for named in CODEX_HOME HOME TMPDIR; do
			eval "value=\${$named:-}"
			[ -n "$value" ] && printf 'value %s=%s\n' "$named" "$value"
		done
	} >>"$AGCTL_FAKE_CODEX_LOG"
fi

if [ -n "${AGCTL_FAKE_CODEX_SLEEP:-}" ]; then
	sleep "$AGCTL_FAKE_CODEX_SLEEP"
fi

if [ -n "${AGCTL_FAKE_CODEX_AUTH:-}" ] && [ -n "${CODEX_HOME:-}" ]; then
	mkdir -p "$CODEX_HOME"
	cat "$AGCTL_FAKE_CODEX_AUTH" >"$CODEX_HOME/auth.json"
	chmod 600 "$CODEX_HOME/auth.json"
fi

if [ -n "${AGCTL_FAKE_CODEX_DAEMON_DIR:-}" ] && [ -n "${CODEX_HOME:-}" ]; then
	mkdir -p "$CODEX_HOME/app-server-daemon"
fi

# The residue, exactly as fact F81 measured it: a `tmp/arg0/codex-arg0<rand>/`
# directory holding a 0-byte `.lock` and three symlinks, plus a login log. The
# `residue` record is what lets the happy-path test prove it ran against this
# mess rather than against an empty home.
if [ -z "${AGCTL_FAKE_CODEX_NO_RESIDUE:-}" ] && [ -n "${CODEX_HOME:-}" ]; then
	arg0="$CODEX_HOME/tmp/arg0/codex-arg0$$"
	mkdir -p "$arg0"
	: >"$arg0/.lock"
	for helper in apply_patch applypatch codex-execve-wrapper; do
		ln -sf /usr/bin/true "$arg0/$helper"
	done
	mkdir -p "$CODEX_HOME/log"
	printf 'fake codex login\n' >>"$CODEX_HOME/log/codex-login.log"
	if [ -n "${AGCTL_FAKE_CODEX_LOG:-}" ]; then
		printf 'residue tmp/arg0/codex-arg0%s/.lock\n' "$$" >>"$AGCTL_FAKE_CODEX_LOG"
	fi
	if [ -n "${AGCTL_FAKE_CODEX_SENTINEL:-}" ]; then
		ln -s "$AGCTL_FAKE_CODEX_SENTINEL" "$arg0/sentinel"
	fi

	if [ -n "${AGCTL_FAKE_CODEX_HELD_LOCK:-}" ]; then
		# A real holder, not a simulated one: a background process that takes
		# an exclusive lock and sits on it. It outlives this process on
		# purpose — that is the condition under test.
		#
		# `flock(1)` is a util-linux program and does NOT exist on macOS, so
		# the holder is `perl`, which ships with the system and whose `flock`
		# is the same syscall. `$| = 1` unbuffers its output: without it the
		# `held` line sat in perl's buffer until perl exited, the wait below
		# always timed out, and the test ran a child that had failed. The
		# holder exits as soon as the scratch home is gone, so it never
		# outlives the login that cleaned it up.
		if ! command -v perl >/dev/null 2>&1; then
			echo "fake-codex: HELD_LOCK needs perl" >&2
			exit 97
		fi
		perl -e '$| = 1; open(my $f, ">>", $ARGV[0]) or die; flock($f, 2) or die; print "held\n"; while (-d $ARGV[1]) { sleep 1 }' \
			"$arg0/.lock" "$CODEX_HOME" >"$arg0/.held" 2>/dev/null &
		# Wait until the holder says it has the lock, so the survey cannot run
		# before the condition it is meant to see exists.
		waited=0
		while [ ! -s "$arg0/.held" ] && [ "$waited" -lt 50 ]; do
			sleep 0.1
			waited=$((waited + 1))
		done
		if [ ! -s "$arg0/.held" ]; then
			echo "fake-codex: the lock holder never took the lock" >&2
			exit 96
		fi
	fi
fi

# A child that stored its credential in the keychain despite being asked not
# to (fact F95): one `Codex Auth` record appended to the fake `security` dump,
# in `security(1)`'s own format, between agctl's two listings.
if [ -n "${AGCTL_FAKE_CODEX_KEYCHAIN_GAIN:-}" ]; then
	cat >>"$AGCTL_FAKE_CODEX_KEYCHAIN_GAIN" <<'RECORD'
class: "genp"
attributes:
    0x00000007 <blob>="Codex Auth"
    "acct"<blob>="cli|0123456789abcdef"
    "svce"<blob>="Codex Auth"
    "type"<uint32>=<NULL>
RECORD
fi

if [ -n "${AGCTL_FAKE_CODEX_TOUCH:-}" ]; then
	: >"$AGCTL_FAKE_CODEX_TOUCH"
fi

status="${AGCTL_FAKE_CODEX_EXIT:-0}"
if [ -n "${AGCTL_FAKE_CODEX_LOG:-}" ]; then
	printf 'exit %s\n' "$status" >>"$AGCTL_FAKE_CODEX_LOG"
fi
exit "$status"
