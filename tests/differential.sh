#!/usr/bin/env bash
#
# Runs the Go module and this one against the same stub server, through the
# same PAM stack, on the same scenarios, and compares the answers.
#
# Two implementations of one protocol diverge in the cases nobody tests.
# This is the countermeasure: any difference is a bug in the C module until
# proven otherwise, with the three exceptions recorded below.
#
# What is compared is the PAM return code, exactly. The syslog lines are
# printed side by side but not compared, because the two modules word their
# messages differently on purpose -- the C one names the algorithm in a
# signature refusal, for instance -- and a diff of prose would be noise
# hiding the signal.
#
# Each module is loaded alone, under `required`, so pam_authenticate returns
# the module's own code rather than a stack's verdict. That is the point of
# the comparison, and it is not the stanza anyone deploys.
#
#   SSOOSSH_GO_MODULE=/path/to/pam_ssoossh.so sudo tests/differential.sh
#
# Build the Go one with, from the monorepo:
#
#   CGO_ENABLED=1 go build -tags=pam -buildmode=c-shared \
#       -o pam_ssoossh_go.so ./pam_ssoossh/
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"

# GNU make, which is not the base `make` everywhere: FreeBSD's is bmake, and
# it rejects --no-print-directory outright rather than ignoring it. A run
# started through the Makefile inherits MAKE from it and so uses the same one
# it was invoked with; run by hand, gmake is the name to look for first.
make="${MAKE:-$(command -v gmake || echo make)}"
port="${SSOOSSH_DIFF_PORT:-18447}"
service="ssoossh-diff"
go_module="${SSOOSSH_GO_MODULE:-}"
workdir=""
stub_pid=""
sink_pid=""

log() { printf '%s\n' "$*" >&2; }

cleanup() {
    if [ -n "$stub_pid" ]; then kill "$stub_pid" 2>/dev/null || true; fi
    if [ -n "$sink_pid" ]; then kill "$sink_pid" 2>/dev/null || true; fi
    if [ -n "$workdir" ]; then rm -rf "$workdir"; fi
    rm -f "/etc/pam.d/$service"
    if [ -n "${securitydir:-}" ]; then
        rm -f "$securitydir/pam_ssoossh_go.so"
    fi
}
trap cleanup EXIT

if [ "$(id -u)" -ne 0 ]; then
    log "differential: needs root"
    exit 2
fi
if [ -z "$go_module" ] || [ ! -f "$go_module" ]; then
    log "differential: set SSOOSSH_GO_MODULE to the built Go module"
    exit 2
fi

securitydir="$("$make" -C "$repo" --no-print-directory print-SECURITYDIR)"
if [ -z "$securitydir" ] || [ ! -d "$securitydir" ]; then
    log "differential: no PAM module directory on this platform"
    log "differential: Linux only anyway -- the Go module hardcodes"
    log "              Linux-PAM's numeric return codes, so it is not a"
    log "              correct reference to compare against elsewhere"
    exit 2
fi

workdir="$(mktemp -d)"
chmod 755 "$workdir"
ssh-keygen -q -N '' -t ecdsa -b 384 -f "$workdir/ca_ecdsa384" -C diff-ca
ssh-keygen -q -N '' -t ecdsa -b 384 -f "$workdir/ca_untrusted" -C diff-untrusted
chmod 644 "$workdir"/*.pub

logfile=/var/log/auth.log
if [ ! -S /dev/log ]; then
    logfile="$workdir/syslog.log"
    : > "$logfile"
    python3 "$here/logsink.py" --out "$logfile" >/dev/null 2>&1 &
    sink_pid=$!
    for _ in $(seq 1 50); do [ -S /dev/log ] && break; sleep 0.1; done
fi

# Unique ports per comparison, for the same reason e2e.sh uses them: reusing
# one means depending on the previous stub's listener being gone, and under
# load it is not.
next_port() { port=$((port + 1)); }

"$make" -C "$repo" --no-print-directory install >/dev/null
install -m 0644 "$go_module" "$securitydir/pam_ssoossh_go.so"

# wc -c rather than stat: BSD stat spells the same question -f%z, and this
# script is read on machines that have one or the other.
log "differential: C module $(wc -c < "$securitydir/pam_ssoossh.so") bytes," \
    "Go module $(wc -c < "$securitydir/pam_ssoossh_go.so") bytes"

start_stub() {
    python3 "$here/stubd.py" --port "$port" --workdir "$workdir" "$@" \
        >"$workdir/stubd.log" 2>&1 &
    stub_pid=$!
    for _ in $(seq 1 50); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
            exec 3>&-
            return 0
        fi
        sleep 0.1
    done
    return 1
}

stop_stub() {
    if [ -n "$stub_pid" ]; then
        kill "$stub_pid" 2>/dev/null || true
        wait "$stub_pid" 2>/dev/null || true
        stub_pid=""
    fi
}

# Runs one module against one scenario and echoes the PAM code pamtest saw.
# `required` with nothing else in the stack, so what comes back is the
# module's own answer.
one() {
    local module="$1" timeout="$2"
    shift 2
    local out

    cat > "/etc/pam.d/$service" <<EOF
auth    required  $module server=http://127.0.0.1:$port \\
                  trusted-ca-file=$workdir/ca_ecdsa384.pub \\
                  timeout=$timeout skew-tolerance=2s debug
EOF
    : > "$logfile" 2>/dev/null || true
    start_stub "$@" || { echo "STUB-FAILED"; return; }
    out="$("$repo/tests/pamtest" "$service" 2>&1 || true)"
    stop_stub
    printf '%s' "$out" | sed -n 's/^auth=//p' | head -1
}

failures=0
divergences=0

# compare <label> <timeout> <expected divergence: ""|reason> [stubd args...]
compare() {
    local label="$1" timeout="$2" expected="$3"
    shift 3
    local c_code go_code

    printf '  %-18s ' "$label"
    next_port
    c_code="$(one pam_ssoossh.so "$timeout" "$@")"
    local c_log
    c_log="$(grep -a pam_ssoossh "$logfile" 2>/dev/null | tail -3 || true)"
    next_port
    go_code="$(one pam_ssoossh_go.so "$timeout" "$@")"
    local go_log
    go_log="$(grep -a pam_ssoossh "$logfile" 2>/dev/null | tail -3 || true)"

    if [ "$c_code" = "$go_code" ]; then
        if [ -n "$expected" ]; then
            printf 'FAILED (expected a divergence: %s)\n' "$expected"
            failures=$((failures + 1))
        else
            printf 'same: %s\n' "$c_code"
        fi
        return
    fi

    if [ -n "$expected" ]; then
        printf 'diverges as intended: C=%s Go=%s (%s)\n' "$c_code" "$go_code" \
            "$expected"
        divergences=$((divergences + 1))
        return
    fi

    printf 'DIVERGED: C=%s Go=%s\n' "$c_code" "$go_code"
    log "    C  says: $(printf '%s' "$c_log" | tail -1)"
    log "    Go says: $(printf '%s' "$go_log" | tail -1)"
    failures=$((failures + 1))
}

log "differential: comparing return codes; syslog wording differs by design"

compare approved        15s '' --scenario approved
compare denied          15s '' --scenario denied
compare expired         15s '' --scenario expired
compare failed          15s '' --scenario failed
compare enrolled        15s '' --scenario enrolled
compare no-cert         15s '' --scenario no-cert
compare envelope-error  15s '' --scenario envelope-error
compare drop            15s '' --scenario drop
compare error-500       15s '' --scenario error-500
compare error-404       15s '' --scenario error-404
compare bad-json        15s '' --scenario bad-json
compare create-500      15s '' --scenario create-500
compare wrong-key       15s '' --scenario wrong-key
compare untrusted       15s '' --scenario untrusted
compare wrong-principal 15s '' --scenario approved --principals nobody
compare expired-cert    15s '' --scenario approved --validity=-20m:-10m
compare timeout          3s '' --scenario slow --hold 60

# The one this harness exists to keep honest. An ssh-rsa CA signature is
# RSA with SHA-1: x/crypto/ssh still verifies it, so the Go module accepts
# such a certificate and this one refuses it by name. Not reachable through
# the stub, which signs with ECDSA, so it is asserted by the unit suite
# instead -- named here so the list of known divergences is in one place.

log ""
if [ "$failures" -ne 0 ]; then
    log "differential: $failures unexplained divergence(s)"
    exit 1
fi
log "differential: no unexplained divergence ($divergences expected)"
