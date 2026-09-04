# Testing

Two harnesses, split by what they need.

## `loadtest` — runs anywhere, no privileges

```console
$ make test
check-symbols: ok
loadtest: ok (./pam_ssoossh.so)
```

`make check-symbols` reads the symbol table statically and asserts that
exactly `pam_sm_authenticate` and `pam_sm_setcred` are exported.
`tests/loadtest.c` asserts the same thing through the dynamic loader, which
additionally catches a missing `DT_NEEDED`, a failed constructor, and a symbol
that is in the table but unresolvable in practice. It also names internals
that must *not* resolve, so a regression in `-fvisibility=hidden` or the
version script fails the build rather than quietly widening what `sudo` can
see.

Both run in CI on every platform. Neither needs root, and neither calls
`pam_sm_authenticate` — that needs a live `pam_handle_t`, which needs a real
PAM stack.

## `pamtest` — needs root

`tests/pamtest.c` drives `pam_start` / `pam_authenticate` / `pam_acct_mgmt`
against a named service, using the platform's tty conversation function so
`PAM_TEXT_INFO` messages (the approval URL, and later the console code and QR)
print to the terminal.

```console
$ make tests/pamtest
```

On Linux that links `-lpam_misc` for `misc_conv`; on FreeBSD and macOS it uses
`openpam_ttyconv`, which is in libpam itself. The Makefile picks per platform.

### Install the module

```console
# Debian, Ubuntu
$ sudo install -m 0644 pam_ssoossh.so /lib/x86_64-linux-gnu/security/

# RHEL family
$ sudo install -m 0644 pam_ssoossh.so /lib64/security/

# Alpine
$ sudo install -m 0644 pam_ssoossh.so /lib/security/

# FreeBSD
$ sudo install -m 0644 pam_ssoossh.so /usr/local/lib/security/
```

On macOS, do not install into `/usr/lib/pam/` — it is protected by System
Integrity Protection. A `pam.d` entry accepts an absolute path, so point it
straight at the build directory instead:

```
auth  sufficient  /Users/you/ssoossh-pam-c/pam_ssoossh.bundle  server=...
```

### A dedicated test service

A separate service name, so iterating never touches the real `sudo` or `login`
stack:

```
# /etc/pam.d/ssoossh-test
auth    sufficient  pam_ssoossh.so server=https://ssoossh.example.com \
                    trusted-ca-file=/etc/ssoossh/ca.pub \
                    principals-map=/etc/ssoossh/principals.yaml \
                    skew-tolerance=2s timeout=60s debug
auth    required    pam_unix.so
account required    pam_unix.so
```

`sufficient` is the documented control flag: an approval ends the auth stack,
and anything else — a cancellation, a denial, a timeout, an unreachable server
— hands over to `pam_unix`. That means a denied approval reaches the password
prompt, which is the intended posture rather than an oversight.

### Run it

```console
$ ./tests/pamtest ssoossh-test
$ journalctl -t sudo -f          # or: tail -f /var/log/auth.log
```

At P0 the module logs its version and denies, so the expected output is
`auth=Authentication failure` with a version line in syslog.

### Before touching a real service

Only once this is solid against `ssoossh-test` should the same stanza go near
`/etc/pam.d/sudo` or `/etc/pam.d/login`. **Keep a second root shell open while
editing either.** A `login` stack that refuses everyone is not recoverable
over SSH if SSH is also using it.

## Cross-platform matrix

The Linux jobs can be reproduced locally with the same images CI uses:

```console
$ docker run --rm -v "$PWD:/src:ro" -w /w almalinux:8 bash -c \
    'dnf install -y -q gcc make pkgconf-pkg-config openssl-devel pam-devel &&
     cp -r /src/. /w/ && make && make test'
```

`almalinux:8` is the version floor — gcc 8.5, OpenSSL 1.1.1k, curl 7.61.1. It
is the only image that will compile the OpenSSL 1.1.1 and `curl_multi_wait`
paths once those exist, so it is the one worth running before claiming a
change is portable.

Red Hat's own `ubi8` cannot be used: `pam-devel` is not in the unentitled UBI
repositories, so the module cannot be built there at all.

## Validating the workflows

`make cross` proves the module builds; it says nothing about whether
`.github/workflows/ci.yml` is correct. [nektos/act](https://github.com/nektos/act)
runs the workflow itself against the host's Docker daemon:

```console
$ make ci-list                  # what act sees
$ make ci-local                 # the whole push event
$ make ci-local JOB=linux       # one job
$ act push -j linux --matrix name:el8   # one matrix entry
```

Because every job in `ci.yml` runs inside its own `container:`, what act
executes is close to what GitHub will — the runner image is only a host for
the job container. That makes a local run worth trusting for everything except
runner-specific behaviour (secrets, OIDC, the hosted tool cache).

FreeBSD and macOS are in `.github/workflows/cross-platform.yml` behind
`workflow_dispatch`, and act cannot run either: there is no macOS runner to
emulate, and the FreeBSD VM action needs nested virtualisation. They are
deliberately not on the push path until the port is finished on Linux.
