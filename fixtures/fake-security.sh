#!/bin/sh
# A stand-in for security(1): the read subcommands, plus `-i`. See
# src/secret/fake_security.rs.
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
    account=''
    while [ $# -gt 0 ]; do
        case "$1" in
        -s)
            service="$2"
            shift 2
            ;;
        -a)
            account="$2"
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
    # A generic password is identified by its account **and** its service, the
    # way the shipped `security(1)` documents `-a` ("Match \"account\" string").
    # So the item lives under a per-account directory and an `-a` naming a
    # different account finds nothing, however familiar the service.
    key=$(printf '%s' "$service" | tr -c 'A-Za-z0-9._-' '_')
    who=$(printf '%s' "$account" | tr -c 'A-Za-z0-9._-' '_')
    file="${AGENTCTL_FAKE_SECURITY_ITEMS:-/nonexistent}/$who/$key"
    if [ -f "$file" ]; then
        cat "$file"
        exit 0
    fi
    printf 'security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\n' >&2
    exit 44
    ;;
-i)
    # The write transport (fact F42): one command line on stdin, nothing
    # secret in argv. This is the stand-in's only mutating path, and it is
    # deliberately strict — a line it does not recognise runs nothing.
    input=$(cat)
    if [ -z "$input" ]; then
        printf 'security: -i expects one command line on standard input, and got none\n' >&2
        exit 1
    fi
    lines=$(printf '%s\n' "$input" | wc -l | tr -d ' ')
    if [ "$lines" != 1 ]; then
        printf 'security: -i expects exactly one command line, and got %s\n' "$lines" >&2
        exit 1
    fi
    case "$input" in
    'add-generic-password -U -a "'*'" -s "'*'" -X "'*'"') ;;
    *)
        printf 'security: -i does not recognise that command line\n' >&2
        exit 1
        ;;
    esac
    rest=${input#'add-generic-password -U -a "'}
    account=${rest%%'" -s "'*}
    rest=${rest#*'" -s "'}
    service=${rest%%'" -X "'*}
    hex=${rest#*'" -X "'}
    hex=${hex%'"'}
    hexlen=$(printf '%s' "$hex" | wc -c | tr -d ' ')

    # Logged redacted at the source, before anything else can go wrong with
    # the line: the log is what plan AC59 and AC61 read, and a stand-in that
    # wrote the hex would put a credential in the test output.
    if [ -n "${AGENTCTL_FAKE_SECURITY_LOG:-}" ]; then
        printf 'add-generic-password -U -a "%s" -s "%s" -X <REDACTED:%s>\n' \
            "$account" "$service" "$hexlen" >> "$AGENTCTL_FAKE_SECURITY_LOG"
    fi

    if [ -n "${AGENTCTL_FAKE_SECURITY_WRITE_EXIT:-}" ]; then
        if [ -n "${AGENTCTL_FAKE_SECURITY_STDERR:-}" ]; then
            printf '%s\n' "$AGENTCTL_FAKE_SECURITY_STDERR" >&2
        fi
        exit "$AGENTCTL_FAKE_SECURITY_WRITE_EXIT"
    fi

    items=${AGENTCTL_FAKE_SECURITY_ITEMS:-/nonexistent}
    if ! grep -q -F -x -- "$service" "$items/.allowed-services" 2>/dev/null; then
        printf 'security: SecKeychainItemModifyAttributesAndData: %s\n' \
            'that service is not registered with this stand-in as a write target' >&2
        exit 1
    fi

    case "$hex" in
    '' | *[!0-9a-f]*)
        printf 'security: the -X value is not lowercase hexadecimal\n' >&2
        exit 1
        ;;
    esac
    if [ $((hexlen % 2)) -ne 0 ]; then
        printf 'security: the -X value has an odd number of hexadecimal digits\n' >&2
        exit 1
    fi

    # `-U` updates the item matching **both** names and creates one when there
    # is none, so a line whose `-a` is not the account the reader matches on
    # lands in a sibling item that no read will ever serve. Keying the file on
    # the account as well as the service is what lets a test see that.
    key=$(printf '%s' "$service" | tr -c 'A-Za-z0-9._-' '_')
    who=$(printf '%s' "$account" | tr -c 'A-Za-z0-9._-' '_')
    mkdir -p "$items/$who"
    if command -v xxd >/dev/null 2>&1; then
        printf '%s' "$hex" | xxd -r -p > "$items/$who/$key"
    elif command -v perl >/dev/null 2>&1; then
        printf '%s' "$hex" |
            perl -e 'my $h = do { local $/; <STDIN> }; print pack("H*", $h);' > "$items/$who/$key"
    else
        printf 'security: this stand-in needs xxd or perl to decode the -X value\n' >&2
        exit 1
    fi
    exit 0
    ;;
delete-generic-password)
    # Refused rather than unimplemented, and refused loudly: agentctl issues
    # no delete anywhere (fact F43), so this arriving means a code path exists
    # that should not. The invocation is already in the log by the time this
    # runs, which is what plan AC61 counts.
    printf 'security: this stand-in refuses to delete an item; agentctl has no delete path\n' >&2
    exit 1
    ;;
*)
    printf 'security: this stand-in implements the read subcommands and -i only, not %s\n' \
        "$subcommand" >&2
    exit 1
    ;;
esac
