#!/usr/bin/env bash
#
# Drives the built module through a real PAM stack against tests/stubd.py,
# once per scenario, and checks both halves of the answer: the PAM return
# code the stack saw, and the decision line the module wrote to syslog.
#
# This is the test that exercises the code nothing else reaches -- the HTTP
# client, the events stream, the reconnect, the deadline, and the four
# checks against a certificate that was really signed a moment ago. Every
# certificate here is minted by ssh-keygen at request time against a CA
# generated for the run; nothing is canned.
#
# Needs root, because installing a module into the security directory and
# writing /etc/pam.d does. See tests/README.md.
#
#   sudo tests/e2e.sh                   every scenario
#   sudo tests/e2e.sh approved denied   one or two
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"

# GNU make, which is not the base `make` everywhere: FreeBSD's is bmake, and
# it rejects --no-print-directory outright rather than ignoring it. A run
# started through the Makefile inherits MAKE from it and so uses the same one
# it was invoked with; run by hand, gmake is the name to look for first.
make="${MAKE:-$(command -v gmake || echo make)}"
# A base, not a port. Each scenario takes the next one, because reusing a
# port means depending on the previous stub's listener being gone -- and
# under load it is not, so the new scenario's requests reach a server that
# knows nothing about them and answers 404. Unique ports remove the race
# rather than waiting on it.
port_base="${SSOOSSH_E2E_PORT:-18443}"
port="$port_base"
service="ssoossh-e2e"
workdir=""
stub_pid=""
syslog_conf_saved=""

log() { printf '%s\n' "$*" >&2; }

# A scenario this platform cannot run, said out loud rather than failed or
# silently dropped: a suite that quietly skips is a suite nobody notices
# has stopped measuring.
skip() { printf '  %-18s SKIP (%s)\n' "$1" "$2"; }

# Whether an sshd is anywhere above this process -- the same question
# ssoossh_ssh_session_ancestry() asks of the process table, matched on the
# same "sshd" prefix, so that a scenario needing a session that did not
# arrive over SSH can say so rather than fail.
#
# The SSH_* variables do not settle it on their own: sudo scrubs them, so
# `sudo make e2e` on a machine driven over ssh -- a FreeBSD CI VM, say --
# looks local to the environment and has an sshd ancestor regardless.
# comm is basenamed because macOS ps prints the full path where Linux and
# FreeBSD print the name.
#
# One -o per column, not "-o ppid=,comm=". POSIX lets an empty header run to
# the end of the argument, so BSD ps reads that second spelling as ppid alone
# under the header ",comm=" -- one column, and a header line where a pid was
# expected. GNU ps splits it on the comma and both look alike on Linux.
under_sshd() {
    local pid=$$ ppid comm

    for _ in $(seq 1 64); do
        [ "$pid" -gt 1 ] || return 1
        read -r ppid comm < <(ps -o ppid= -o comm= -p "$pid" 2>/dev/null) ||
            return 1
        # Anything but a pid means the walk has lost the thread -- ps said
        # something unexpected, or the process went away mid-walk.
        case "$ppid" in '' | *[!0-9]*) return 1 ;; esac
        case "${comm##*/}" in sshd*) return 0 ;; esac
        [ "$ppid" != "$pid" ] || return 1
        pid="$ppid"
    done
    return 1
}

# SIGHUP is what syslogd re-reads its configuration on; service(8) is the
# spelling that knows where the pid file is.
reload_syslogd() {
    service syslogd reload >/dev/null 2>&1 ||
        pkill -HUP syslogd >/dev/null 2>&1 || true
    # The reload is asynchronous and the next scenario writes immediately.
    sleep 1
}

cleanup() {
    if [ -n "$stub_pid" ]; then kill "$stub_pid" 2>/dev/null || true; fi
    if [ -n "$sink_pid" ]; then kill "$sink_pid" 2>/dev/null || true; fi
    if [ -n "$syslog_conf_saved" ]; then
        cat "$syslog_conf_saved" > /etc/syslog.conf
        reload_syslogd
    fi
    if [ -n "$workdir" ]; then rm -rf "$workdir"; fi
    rm -f "/etc/pam.d/$service"
}
trap cleanup EXIT

if [ "$(id -u)" -ne 0 ]; then
    log "e2e: needs root -- it installs a PAM module and writes /etc/pam.d"
    exit 2
fi
for tool in ssh-keygen python3; do
    command -v "$tool" >/dev/null || { log "e2e: $tool is required"; exit 2; }
done

workdir="$(mktemp -d)"
chmod 755 "$workdir"

# Where the module's syslog output can be read back, which is a different
# question on each platform.
#
#   Linux    libc writes to /dev/log. In the devcontainer rsyslog owns it and
#            files LOG_AUTHPRIV into /var/log/auth.log; a bare CI job
#            container has no daemon at all, so tests/logsink.py binds the
#            socket instead.
#   FreeBSD  the socket is /var/run/log, and syslogd runs by default, filing
#            LOG_AUTHPRIV into /var/log/auth.log per the stock syslog.conf --
#            but only at info and above, so the run adds authpriv.debug for
#            its own duration. If syslogd is not running, the sink binds
#            /var/run/log the same way.
#   macOS    there is no socket to bind: syslog(3) feeds the unified logging
#            system. `log stream` is the way back out, and it plays the same
#            role the sink does elsewhere. --info and --debug are not
#            optional: syslog's LOG_INFO and LOG_DEBUG land at those os_log
#            levels, and `log stream` hides both by default -- which is
#            every "successful authentication" line and every debug line
#            this suite matches on.
os="$(uname -s)"
logfile=""
sink_pid=""

case "$os" in
Darwin)
    logfile="$workdir/syslog.log"
    : > "$logfile"
    # By path, not by name: this script's log() function above shadows
    # log(1), and a bare `log stream` here ran that function, wrote its
    # arguments to stderr, and returned -- leaving no sink at all and every
    # scenario failing its syslog match.
    /usr/bin/log stream --style compact --info --debug \
        --predicate 'process == "pamtest"' > "$logfile" 2>/dev/null &
    sink_pid=$!
    # log stream takes a moment to attach; nothing before that is captured.
    sleep 2
    log "e2e: reading the unified log through 'log stream'"
    ;;
*)
    case "$os" in
    FreeBSD) syslog_socket=/var/run/log ;;
    *)       syslog_socket=/dev/log ;;
    esac

    if [ -S "$syslog_socket" ]; then
        logfile=/var/log/auth.log
        # FreeBSD's stock syslog.conf files authpriv at info and above, so
        # every LOG_DEBUG line is dropped before it reaches auth.log -- and
        # the lines that prove a decision was reached the intended way,
        # rather than merely reached, are debug ones: "authorized via
        # principals-map" is the scenario that caught this. Add the level
        # for the length of the run and put the file back in cleanup.
        #
        # Appended rather than dropped into /etc/syslog.d because that
        # directory is only read if the stock conf still includes it, and a
        # rule that silently does not apply is worse here than an edit that
        # is undone. Linux's rsyslog files authpriv.* already, so this is
        # FreeBSD's alone.
        if [ "$os" = FreeBSD ]; then
            syslog_conf_saved="$workdir/syslog.conf.orig"
            cp /etc/syslog.conf "$syslog_conf_saved"
            printf 'authpriv.debug\t/var/log/auth.log\n' >> /etc/syslog.conf
            reload_syslogd
        fi
    else
        logfile="$workdir/syslog.log"
        : > "$logfile"
        python3 "$here/logsink.py" --socket "$syslog_socket" --out "$logfile" \
            >"$workdir/logsink.log" 2>&1 &
        sink_pid=$!
        for _ in $(seq 1 50); do
            [ -S "$syslog_socket" ] && break
            sleep 0.1
        done
        if [ ! -S "$syslog_socket" ]; then
            log "e2e: could not start a syslog sink on $syslog_socket"
            cat "$workdir/logsink.log" >&2
            exit 2
        fi
        log "e2e: no syslog daemon; reading from $logfile"
    fi
    ;;
esac

# The CA private halves are generated per run and thrown away. Committing
# them would mean committing a signing key, even a worthless one.
ssh-keygen -q -N '' -t ecdsa -b 384 -f "$workdir/ca_ecdsa384" -C e2e-ca
ssh-keygen -q -N '' -t ecdsa -b 384 -f "$workdir/ca_untrusted" -C e2e-untrusted
chmod 644 "$workdir"/*.pub

# How the pam.d line names the module.
#
# Normally it is installed into the platform's module directory and named
# bare. macOS has no such directory this may write to -- /usr/lib/pam is
# protected by System Integrity Protection -- so the Makefile reports none,
# and a pam.d entry takes an absolute path to the build directory instead.
# That form is supported by every PAM implementation here and is the
# documented way to test on macOS.
module_file="$("$make" -C "$repo" --no-print-directory print-MODULE)"
securitydir="$("$make" -C "$repo" --no-print-directory print-SECURITYDIR)"

if [ -n "$securitydir" ]; then
    "$make" -C "$repo" --no-print-directory install >/dev/null
    module_ref="pam_ssoossh.so"
else
    module_ref="$repo/$module_file"
    log "e2e: no module directory on this platform; loading $module_ref by path"
fi

# Invoked directly rather than through `make e2e`, which builds these. A
# missing binary otherwise surfaces as exit 127 inside a scenario, which
# reads like a module failure.
for f in "$repo/$module_file" "$repo/tests/pamtest"; do
    [ -e "$f" ] || {
        log "e2e: $f is missing -- run 'make && make tests/pamtest' first"
        exit 2
    }
done

# Alpine's linux-pam package ships no /etc/pam.d at all, so the directory
# has to exist before anything can be written into it.
mkdir -p /etc/pam.d

# A dedicated service, so iterating never touches the real sudo stack.
# pam_permit follows under `sufficient`, which is the documented stanza: an
# approval ends the stack and anything else falls through.
write_pamd() {
    local timeout="$1" extra="$2"

    cat > "/etc/pam.d/$service" <<EOF
auth    sufficient  $module_ref server=http://127.0.0.1:$port \\
                    trusted-ca-file=$workdir/ca_ecdsa384.pub \\
                    timeout=$timeout skew-tolerance=2s debug $extra
auth    required    pam_permit.so
account required    pam_permit.so
EOF
}

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
    log "e2e: the stub never came up"
    cat "$workdir/stubd.log" >&2
    return 1
}

stop_stub() {
    if [ -n "$stub_pid" ]; then
        kill "$stub_pid" 2>/dev/null || true
        wait "$stub_pid" 2>/dev/null || true
        stub_pid=""
    fi
}

# The next scenario's port. Called before the pam.d file is written, since
# that file names it.
next_port() {
    port=$((port + 1))
}

failures=0
LAST_OUT=""
pamtest_env=""

# Reads back the module's syslog output, waiting up to two seconds for the
# line a caller is looking for to land.
#
# Not paranoia. Where there is no syslog daemon the sink is a Python loop
# reading datagrams, and pamtest can exit before it has written them out --
# a gap that is invisible on an idle machine and reliably wide enough to
# fail on a CI runner with three job containers competing for it. Grepping
# once is how this test suite spent an afternoon looking like a module bug.
await_log() {
    local want="$1" logged=""

    for _ in $(seq 1 20); do
        logged="$(grep -a pam_ssoossh "$logfile" 2>/dev/null | tail -60 || true)"
        if grep -qE "$want" <<< "$logged"; then
            break
        fi
        sleep 0.1
    done
    printf '%s' "$logged"
}

# run <label> <stub scenario> <want pamtest exit> <want syslog pattern>
#     <timeout> <pam.d extras> [extra stubd args...]
#
# pamtest exits 0 when the stack said Success. Under `sufficient` with
# pam_permit behind it, that is the answer for both an approval and a
# refusal -- which is the documented posture, not an oversight. So the
# syslog pattern is what distinguishes them, and it is the same line the
# differential harness compares.
run() {
    local label="$1" scenario="$2" want_exit="$3" want_log="$4"
    local timeout="$5" extra="$6"
    shift 6
    local out rc logged ok=1

    printf '  %-18s ' "$label"
    # Truncated per run, so a pattern can only match this scenario's own
    # output -- an earlier scenario's line matching would make a failing
    # case look like a passing one.
    : > "$logfile" 2>/dev/null || true
    next_port
    write_pamd "$timeout" "$extra"
    if ! start_stub --scenario "$scenario" "$@"; then
        printf 'FAILED (stub)\n'
        failures=$((failures + 1))
        return
    fi

    # pamtest_env: extra words for env(1) in front of pamtest -- a variable
    # to set, or -u NAME to clear one -- for a scenario that depends on the
    # environment the module sees. Unquoted on purpose: it is a word list.
    # shellcheck disable=SC2086
    out="$(env $pamtest_env "$repo/tests/pamtest" "$service" 2>&1)" && rc=0 || rc=$?
    stop_stub
    # Kept for a caller that wants to assert on what reached the terminal
    # rather than on what reached syslog.
    LAST_OUT="$out"

    logged="$(await_log "$want_log")"

    if [ "$rc" != "$want_exit" ]; then
        ok=0
        log ""
        log "    pamtest exited $rc, want $want_exit"
        log "    output: $out"
    fi
    # A here-string rather than a pipe into grep -q. Under `set -o
    # pipefail`, grep -q exits as soon as it matches, printf takes SIGPIPE,
    # and the pipeline reports failure -- so a *matching* pattern fails the
    # check, and only once the log is long enough for the race to happen.
    if ! grep -qE "$want_log" <<< "$logged"; then
        ok=0
        log ""
        log "    syslog did not match: $want_log"
        printf '%s\n' "$logged" | tail -12 >&2
    fi

    if [ "$ok" = 1 ]; then
        printf 'ok\n'
    else
        printf 'FAILED\n'
        failures=$((failures + 1))
    fi
}

# Ctrl-C at the approval prompt. The module returns PAM_IGNORE -- "this
# module contributes nothing" -- so libpam moves on to whatever the stack
# lists next. The Go module returns PAM_AUTH_ERR there, which tears the
# whole attempt down, and this is the one sanctioned divergence between
# them.
#
# Proving it needs a control flag that tells the two codes apart. Under
# `sufficient` both continue, so that stanza cannot distinguish them; under
# `requisite` and under the bracketed form, PAM_AUTH_ERR is immediately
# final and PAM_IGNORE is not. Both are run, because the documentation
# offers them and a dispatcher that treats PAM_IGNORE as a failure under one
# of them is a documentation bug worth finding before it is published.
run_cancel() {
    local flag="$1" label="$2"
    local pid rc logged ok=1

    printf '  %-18s ' "$label"
    : > "$logfile" 2>/dev/null || true
    next_port
    cat > "/etc/pam.d/$service" <<EOF
auth    $flag  $module_ref server=http://127.0.0.1:$port \\
                    trusted-ca-file=$workdir/ca_ecdsa384.pub \\
                    timeout=60s debug
auth    required    pam_permit.so
account required    pam_permit.so
EOF

    if ! start_stub --scenario slow --hold 120; then
        printf 'FAILED (stub)\n'
        failures=$((failures + 1))
        return
    fi

    "$repo/tests/pamtest" "$service" >"$workdir/cancel.out" 2>&1 &
    pid=$!
    # Long enough for the module to have reached the wait.
    sleep 2
    kill -INT "$pid" 2>/dev/null || true
    wait "$pid" && rc=0 || rc=$?
    stop_stub

    logged="$(await_log 'interrupted by the user')"

    # pam_permit followed, so the stack says Success -- which it can only do
    # if PAM_IGNORE let it continue.
    if [ "$rc" != 0 ]; then
        ok=0
        log ""
        log "    pamtest exited $rc, want 0 (the stack should have continued)"
        cat "$workdir/cancel.out" >&2
    fi
    if ! grep -q 'interrupted by the user' <<< "$logged"; then
        ok=0
        log ""
        log "    the module did not report an interruption"
        printf '%s\n' "$logged" | tail -8 >&2
    fi

    if [ "$ok" = 1 ]; then
        printf 'ok\n'
    else
        printf 'FAILED\n'
        failures=$((failures + 1))
    fi
}

scenarios=("$@")
if [ ${#scenarios[@]} -eq 0 ]; then
    scenarios=(approved denied expired failed unknown envelope-error no-cert
               enrolled drop error-500 error-404 bad-json create-500 escape
               wrong-key untrusted expired-cert wrong-principal
               principals-map slow console cancel-requisite
               cancel-bracketed ssh-only-local ssh-only-remote)
fi

for s in "${scenarios[@]}"; do
    case "$s" in
    approved)
        # The happy path, and then what went out on it: the stub records
        # the create body, and context_check.py asserts the context fields
        # are there, well-formed, and agree with what this harness knows
        # about the host -- the service name it wrote, the CA it generated.
        run approved approved 0 'successful authentication' 15s '' \
            --record "$workdir/create.json"
        printf '  %-18s ' "context-fields"
        if out="$(python3 "$here/context_check.py" "$workdir/create.json" \
                    "$service" "$workdir/ca_ecdsa384.pub" 2>&1)"; then
            printf 'ok\n'
        else
            printf 'FAILED\n'
            printf '%s\n' "$out" | sed 's/^/    /' >&2
            failures=$((failures + 1))
        fi ;;
    denied)
        run denied denied 0 'the request was denied' 15s '' ;;
    expired)
        run expired expired 0 'expired before anyone approved it' 15s '' ;;
    failed)
        run failed failed 0 'could not issue the certificate' 15s '' ;;
    unknown)
        # An event name nobody listed is informational, not an outcome --
        # the same choice the Go client makes, and for the same reason:
        # inventing a result from an unrecognized name would be worse than
        # waiting. So this ends at the timeout.
        run unknown unknown 0 'timed out waiting for approval' 3s '' ;;
    enrolled)
        # A terminal status that resolves a service enrollment and carries
        # no certificate a PAM login could use.
        run enrolled enrolled 0 'resolved as an enrollment' 15s '' ;;
    envelope-error)
        run envelope-error envelope-error 0 'the signer refused' 15s '' ;;
    no-cert)
        run no-cert no-cert 0 'approved but no certificate' 15s '' ;;
    drop)
        # Establishes, drops, and the module reconnects and gets the answer.
        run drop drop 0 'successful authentication' 15s '' ;;
    error-500)
        # Retryable: refused once, then served.
        run error-500 error-500 0 'successful authentication' 15s '' ;;
    error-404)
        # Definitive, and not retried.
        run error-404 error-404 0 'returned status 404' 15s '' ;;
    bad-json)
        run bad-json bad-json 0 'carried no events URL' 15s '' ;;
    create-500)
        run create-500 create-500 0 'returned status 500' 15s '' ;;
    escape)
        # A hostile approval URL carrying terminal control. Two assertions,
        # because the interesting one is not the log line: the module must
        # report dropping the bytes, *and* what actually reached the
        # terminal must not contain them. The second is the whole point --
        # this is a root process's tty.
        run escape escape 0 'not valid in a URL' 15s ''
        printf '  %-18s ' "escape-tty"
        # A POSIX character class, not grep -P: BSD grep has no PCRE, and
        # this suite has to run on FreeBSD and macOS. grep works a line at a
        # time, so the newlines between them are never candidates.
        if printf '%s' "$LAST_OUT" | LC_ALL=C grep -q '[[:cntrl:]]'; then
            printf 'FAILED\n'
            log "    a control byte reached the terminal:"
            printf '%s' "$LAST_OUT" | cat -v | tail -5 >&2
            failures=$((failures + 1))
        elif ! printf '%s' "$LAST_OUT" | grep -q 'Approve this request'; then
            printf 'FAILED\n'
            log "    the approval prompt did not reach the terminal at all"
            failures=$((failures + 1))
        else
            printf 'ok\n'
        fi ;;
    wrong-key)
        # Check 2: correctly signed, right principals, inside its window,
        # and issued to a keypair this attempt never generated.
        run wrong-key wrong-key 0 'does not match the key generated' 15s '' ;;
    untrusted)
        run untrusted untrusted 0 'not signed by a trusted CA' 15s '' ;;
    expired-cert)
        # --validity= rather than a separate argument: argparse reads a
        # value beginning with '-' as another option otherwise.
        run expired-cert approved 0 'certificate expired' 15s '' \
            --validity=-20m:-10m ;;
    wrong-principal)
        run wrong-principal approved 0 'do not include' 15s '' \
            --principals nobody ;;
    principals-map)
        # The map authorizes the account through a principal that is not
        # its name, which is the whole point of having one.
        # The certificate carries only "ops", so nothing but the map can
        # authorize the account -- which is the whole point of having one.
        printf 'games:\n  - ops\n' > "$workdir/principals.yaml"
        chmod 644 "$workdir/principals.yaml"
        run principals-map approved 0 'authorized via principals-map' 15s \
            "principals-map=$workdir/principals.yaml" --principals ops ;;
    slow)
        # The module's own timeout ends this, not the server.
        run slow slow 0 'timed out waiting for approval' 3s '' --hold 60 ;;
    console)
        # Console mode is compiled in on Linux and FreeBSD only; on macOS
        # mode=console is refused at argument-parse time, by design.
        if [ "$os" = Darwin ]; then
            skip console 'console mode is not compiled in on macOS'
        else
            run console console 0 'console flow' 15s 'mode=console'
        fi ;;
    ssh-only-local)
        # A login that did not arrive over SSH: the module stands aside
        # with PAM_IGNORE before any network, pam_permit follows, and the
        # stack says Success without a request ever being created. The
        # SSH variables are cleared so the harness's own session does not
        # leak in -- but a harness itself run over SSH has an sshd
        # ancestor the module will find regardless, so the case is
        # skipped there rather than reported as a module bug.
        if [ -n "${SSH_CONNECTION:-}${SSH_CLIENT:-}${SSH_TTY:-}" ] ||
           under_sshd; then
            skip ssh-only-local 'this harness is itself running over SSH'
        else
            pamtest_env="-u SSH_CONNECTION -u SSH_CLIENT -u SSH_TTY"
            run ssh-only-local slow 0 'standing aside' 15s 'ssh-only' --hold 60
            pamtest_env=""
        fi ;;
    ssh-only-remote)
        # The same line, in a session that did arrive over SSH: the flow
        # runs as if ssh-only were not there. SSH_TTY rather than
        # SSH_CONNECTION only because pamtest_env is a word list and
        # SSH_CONNECTION's value has spaces in it.
        pamtest_env="SSH_TTY=/dev/pts/9"
        run ssh-only-remote approved 0 'successful authentication' 15s 'ssh-only'
        pamtest_env="" ;;
    cancel-requisite)
        run_cancel requisite cancel-requisite ;;
    cancel-bracketed)
        # The [success=... default=...] control syntax is Linux-PAM's own.
        # OpenPAM (FreeBSD, macOS) has only the four keywords, and refuses
        # the stack at pam_start.
        if [ "$os" != Linux ]; then
            skip cancel-bracketed 'bracketed controls are Linux-PAM only'
        else
            run_cancel '[success=done ignore=ignore default=die]' \
                cancel-bracketed
        fi ;;
    *)
        log "e2e: unknown scenario $s"
        failures=$((failures + 1)) ;;
    esac
done

if [ "$failures" -ne 0 ]; then
    log "e2e: $failures scenario(s) failed"
    exit 1
fi
log "e2e: all scenarios passed"
