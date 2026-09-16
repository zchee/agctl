#!/bin/sh
# A stand-in for the `codex` binary, wired through AGCTL_CODEX_BIN under the
# `testing` feature. The twin of fixtures/fake-security.sh, and it exists for
# the same reason: `agctl codex login` spawns the vendor's own CLI, and a test
# that spawned the real one would open a browser and mint a real grant against
# the developer's own ChatGPT account.
#
# It records what it was asked to do and then does exactly what the control
# variables say — nothing else. Every path it writes is inside the scratch
# home agctl handed it through CODEX_HOME; it never looks at, let alone
# touches, a home it was not given.
#
#   AGCTL_FAKE_CODEX_LOG        append `argv`, `cwd` and `env` records here
#   AGCTL_FAKE_CODEX_SLEEP      seconds to sleep before doing anything
#   AGCTL_FAKE_CODEX_EXIT       exit status (default 0)
#   AGCTL_FAKE_CODEX_AUTH       a file whose contents become <CODEX_HOME>/auth.json
#   AGCTL_FAKE_CODEX_DAEMON_DIR create <CODEX_HOME>/app-server-daemon/ as well
#
# With none of them set it logs nothing, writes nothing and exits 0.

if [ -n "${AGCTL_FAKE_CODEX_LOG:-}" ]; then
	{
		printf 'argv %s\n' "$*"
		printf 'cwd %s\n' "$(pwd)"
		# One `env <NAME>=<value>` line per variable, sorted, so a test can
		# assert on the whole environment rather than on the presence of the
		# names it happened to think of.
		env | LC_ALL=C sort | sed 's/^/env /'
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

exit "${AGCTL_FAKE_CODEX_EXIT:-0}"
