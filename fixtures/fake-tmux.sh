#!/bin/sh
# Synthetic tmux transport; never contacts a server or starts Claude Code.
# AGCTL_FAKE_TMUX_LOG: argv (including arg0), environment names, and observations.
# AGCTL_FAKE_TMUX_WATCH: colon-separated files to hash, or report absent.
# AGCTL_FAKE_TMUX_LOCKS: colon-separated paths to report present/absent.
# AGCTL_FAKE_TMUX_FLOCKS: colon-separated files to probe with nonblocking flock.
# AGCTL_FAKE_TMUX_PANES: file of %N pid tty in_mode dead synchronized rows.
# AGCTL_FAKE_TMUX_STATES: directory of pid.panel/disconnected/reconnected.json copies.
# AGCTL_FAKE_TMUX_REGISTRY: temporary registry directory receiving atomic copies.
# AGCTL_FAKE_TMUX_NULL_AFTER_MS: disconnect delay, or never.
# AGCTL_FAKE_TMUX_SET_AFTER_MS: reconnect delay, or never.
# AGCTL_FAKE_TMUX_DROP_AFTER_MS: optional delay before dropping a reconnected bridge.
# AGCTL_FAKE_TMUX_REBRIDGE_AFTER_MS: optional external reconnect after disconnect, before agctl reconnects.
# Only NULL_AFTER_MS and SET_AFTER_MS also accept a file of pid/value rows.
# REBRIDGE_AFTER_MS and DROP_AFTER_MS accept only a plain delay value.
# AGCTL_FAKE_TMUX_SCREEN: file of synthetic screen bytes (absent means zero bytes).
# AGCTL_FAKE_TMUX_CAPTURE_EXIT: capture-only exit status.
# AGCTL_FAKE_TMUX_CAPTURE_BYTES: fixed ASCII fixture byte count, including a screen sentinel.
# fixture-state pid state: synchronous test-owned invalidation, using the same logged atomic move.
# AGCTL_FAKE_TMUX_EXIT: send-only exit status.
# AGCTL_FAKE_TMUX_SLEEP: seconds to pause before answering.
umask 077

move_state() {
    copy="$AGCTL_FAKE_TMUX_REGISTRY/.$1.$$.json"
    cp "$AGCTL_FAKE_TMUX_STATES/$1.$2.json" "$copy" && mv "$copy" "$AGCTL_FAKE_TMUX_REGISTRY/$1.json" || return 5
    [ -z "${AGCTL_FAKE_TMUX_LOG:-}" ] || printf 'move %s %s\n' "$1" "$2" >> "$AGCTL_FAKE_TMUX_LOG"
}

if [ "${1:-}" = fixture-state ]; then
    move_state "$2" "$3"
    exit $?
fi

if [ -n "${AGCTL_FAKE_TMUX_LOG:-}" ]; then
    {
        printf 'call\narg0 %s\n' "$0"
        for word in "$@"; do printf 'arg %s\n' "$word"; done
        perl -e 'print "env $_\n" for sort keys %ENV'
        old_ifs=$IFS
        IFS=:
        for file in ${AGCTL_FAKE_TMUX_WATCH:-}; do
            if [ -f "$file" ]; then
                hash=$(shasum -a 256 "$file" | cut -d ' ' -f 1)
                printf 'watch %s %s\n' "$file" "$hash"
            else
                printf 'watch %s absent\n' "$file"
            fi
        done
        for file in ${AGCTL_FAKE_TMUX_LOCKS:-}; do
            if [ -e "$file" ]; then state=present; else state=absent; fi
            printf 'lock %s %s\n' "$file" "$state"
        done
        for file in ${AGCTL_FAKE_TMUX_FLOCKS:-}; do
            state=$(perl -e 'open(my $f, "+<", $ARGV[0]) or die; print flock($f, 6) ? "free" : "held"' "$file") || exit 97
            printf 'flock %s %s\n' "$file" "$state"
        done
        IFS=$old_ifs
    } >> "$AGCTL_FAKE_TMUX_LOG"
fi

if [ -n "${AGCTL_FAKE_TMUX_SLEEP:-}" ]; then
    # exec ensures the timeout test checks the registered child itself.
    exec sleep "$AGCTL_FAKE_TMUX_SLEEP"
fi

command=$1
shift
pane=
while [ "$#" -gt 0 ]; do
    if [ "$1" = -t ]; then shift; pane=$1; shift; break; fi
    shift
done
row=$(awk -v pane="$pane" '$1 == pane { print; exit }' "${AGCTL_FAKE_TMUX_PANES:-/dev/null}")

if [ "$command" = capture-pane ]; then
    [ "${AGCTL_FAKE_TMUX_CAPTURE_EXIT:-0}" = 0 ] || exit "$AGCTL_FAKE_TMUX_CAPTURE_EXIT"
    if [ -n "${AGCTL_FAKE_TMUX_CAPTURE_BYTES:-}" ]; then
        perl -e 'my $s = "RC_SCREEN_SENTINEL "; print substr($s x (1 + $ARGV[0] / length($s)), 0, $ARGV[0])' "$AGCTL_FAKE_TMUX_CAPTURE_BYTES"
    elif [ -n "${AGCTL_FAKE_TMUX_SCREEN:-}" ]; then
        cat "$AGCTL_FAKE_TMUX_SCREEN"
    fi
    exit 0
fi

[ -n "$row" ] || { printf "can't find pane\n" >&2; exit 1; }
if [ "$command" = display-message ]; then
    printf '%s\n' "$row" | cut -d ' ' -f 2-
    exit 0
fi
[ "$command" = send-keys ] || exit 2
[ "${AGCTL_FAKE_TMUX_EXIT:-0}" = 0 ] || exit "$AGCTL_FAKE_TMUX_EXIT"
pid=$(printf '%s\n' "$row" | cut -d ' ' -f 2)
registry=${AGCTL_FAKE_TMUX_REGISTRY:-}
states=${AGCTL_FAKE_TMUX_STATES:-}
[ -n "$registry" ] && [ -n "$states" ] || exit 0

bridge=$(perl -MJSON::PP -e 'local $/; open my $f, "<", $ARGV[0] or die; my $v=decode_json(<$f>); print defined($v->{bridgeSessionId}) && length($v->{bridgeSessionId}) ? "on" : "off"' "$registry/$pid.json") || exit 3
case "$*" in
    '/remote-control Enter')
        if [ "$bridge" = on ]; then state=panel; delay=0
        else state=reconnected; delay=${AGCTL_FAKE_TMUX_SET_AFTER_MS:-0}; fi ;;
    'Up Up Enter') state=disconnected; delay=${AGCTL_FAKE_TMUX_NULL_AFTER_MS:-0} ;;
    *) exit 4 ;;
esac
if [ -f "$delay" ]; then delay=$(awk -v pid="$pid" '$1 == pid {print $2; exit}' "$delay"); fi
[ "$delay" != never ] || exit 0

# The detached fixture writer owns no transport pipe, so completion stays bounded.
(
    perl -e 'select undef, undef, undef, $ARGV[0] / 1000' "${delay:-0}"
    move_state "$pid" "$state" || exit 5
    if [ "$state" = disconnected ] && [ -n "${AGCTL_FAKE_TMUX_REBRIDGE_AFTER_MS:-}" ]; then
        perl -e 'select undef, undef, undef, $ARGV[0] / 1000' "$AGCTL_FAKE_TMUX_REBRIDGE_AFTER_MS"
        move_state "$pid" reconnected || exit 5
    fi
    if [ "$state" = reconnected ] && [ -n "${AGCTL_FAKE_TMUX_DROP_AFTER_MS:-}" ]; then
        perl -e 'select undef, undef, undef, $ARGV[0] / 1000' "$AGCTL_FAKE_TMUX_DROP_AFTER_MS"
        move_state "$pid" disconnected || exit 5
    fi
) </dev/null >/dev/null 2>&1 &
exit 0
