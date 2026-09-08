#!/bin/sh
# A read-only stand-in for security(1). See src/secret/fake_security.rs.
if [ -n "${AGENTCTL_FAKE_SECURITY_LOG:-}" ]; then
    printf '%s\n' "$*" >> "$AGENTCTL_FAKE_SECURITY_LOG"
fi
if [ -n "${AGENTCTL_FAKE_SECURITY_SLEEP:-}" ]; then
    sleep "$AGENTCTL_FAKE_SECURITY_SLEEP"
fi

subcommand="$1"
[ $# -gt 0 ] && shift

case "$subcommand" in
show-keychain-info)
    if [ -n "${AGENTCTL_FAKE_SECURITY_PREFLIGHT_STDERR:-}" ]; then
        printf '%s\n' "$AGENTCTL_FAKE_SECURITY_PREFLIGHT_STDERR" >&2
    fi
    exit "${AGENTCTL_FAKE_SECURITY_PREFLIGHT_EXIT:-0}"
    ;;
dump-keychain)
    if [ -n "${AGENTCTL_FAKE_SECURITY_DUMP:-}" ] && [ -f "$AGENTCTL_FAKE_SECURITY_DUMP" ]; then
        cat "$AGENTCTL_FAKE_SECURITY_DUMP"
    fi
    exit "${AGENTCTL_FAKE_SECURITY_DUMP_EXIT:-0}"
    ;;
find-generic-password)
    service=''
    while [ $# -gt 0 ]; do
        case "$1" in
        -s)
            service="$2"
            shift 2
            ;;
        *)
            shift
            ;;
        esac
    done
    if [ -n "${AGENTCTL_FAKE_SECURITY_FIND_EXIT:-}" ]; then
        if [ -n "${AGENTCTL_FAKE_SECURITY_STDERR:-}" ]; then
            printf '%s\n' "$AGENTCTL_FAKE_SECURITY_STDERR" >&2
        fi
        exit "$AGENTCTL_FAKE_SECURITY_FIND_EXIT"
    fi
    key=$(printf '%s' "$service" | tr -c 'A-Za-z0-9._-' '_')
    file="${AGENTCTL_FAKE_SECURITY_ITEMS:-/nonexistent}/$key"
    if [ -f "$file" ]; then
        cat "$file"
        exit 0
    fi
    printf 'security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\n' >&2
    exit 44
    ;;
*)
    printf 'security: this stand-in implements read subcommands only, not %s\n' "$subcommand" >&2
    exit 1
    ;;
esac
