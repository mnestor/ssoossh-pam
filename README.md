# pam_ssoossh

A PAM module that authenticates a local account by asking
[ssoosshd](https://github.com/mnestor/ssoossh) for a short-lived SSH
certificate, showing the person at the terminal how to approve it, waiting
for a human to approve it, and validating the certificate that comes back.

This is a pure C reimplementation of the Go module in the ssoossh monorepo.
The Go build is a `-buildmode=c-shared` object of 12.9 MB that carries the Go
runtime into `sudo` and `sshd`; this one is **82 KB stripped** and links only
libraries the operating system already ships.

**Status: complete and under test.** The module authenticates end to end
against a stub `ssoosshd` on Linux: it creates a certificate request, waits
on the events stream, and runs all four checks against a certificate that was
really signed. What has *not* happened yet is a run against a production
`ssoosshd`, or on FreeBSD or macOS — see [Verified, and not](#verified-and-not).

## What it does

```
$ sudo -i
Approve this request in your browser:
https://ssoossh.example.com/approve/6f1c0a5e-1f2b-4c3d-8e9f-0a1b2c3d4e5f
```

On a machine with no browser in front of it — a virtual console, a serial
line, a BMC viewer — it prints a code and a QR code instead, and the approver
carries them to a device that does have one:

```
Approve this login from a device with a browser.

  Go to:  https://ssoossh.example.com/console
  Code:   K7M4-QP2X

  █████████████████████████████████
  ██ ▄▄▄▄▄ █▄ ▀ ▀▄▄ █▀ █▄█ ▄▄▄▄▄ ██
  ██ █   █ █▄▀ ▀▄▄█▀▀ ▀▄▀█ █   █ ██
  ...
```

Which one you get is decided per login, not per host: `mode=auto` is the
default and picks the console flow when `PAM_RHOST` is empty and `PAM_TTY`
names a physical terminal. A pseudo-terminal is a terminal emulator or an SSH
session, where a browser is a keystroke away, so it is not a console.

## Configuration

The documented stanza, and the only one:

```
# /etc/pam.d/sudo
auth    sufficient  pam_ssoossh.so server=https://ssoossh.example.com \
                    trusted-ca-file=/etc/ssoossh/ca.pub \
                    principals-map=/etc/ssoossh/principals.yaml \
                    skew-tolerance=2s timeout=60s
auth    required    pam_unix.so
```

`sufficient` means an approval ends the auth stack, and anything else — a
cancellation, a denial, a timeout, an unreachable server — hands over to
`pam_unix`. **A denied approval therefore reaches the password prompt.** That
is the intended posture rather than an oversight: ssoossh is an additional way
to authenticate, not a gate that can lock an operator out of a host when the
browser flow is unavailable.

Every argument, every return code and the principals-map grammar are in
[`docs/pam_ssoossh.8`](docs/pam_ssoossh.8) — `man -l docs/pam_ssoossh.8`.

| Argument | Default | |
| --- | --- | --- |
| `server` | — | required; a missing scheme becomes `https://` |
| `trusted-ca-file` | — | required; `authorized_keys` format, one CA per line |
| `principals-map` | unset | which principals may assume which account |
| `mode` | `auto` | `auto`, `sudo`, or `console` |
| `skew-tolerance` | `2s` | applied to both ends of the validity window |
| `timeout` | `60s` | bounds the whole attempt |
| `insecure-skip-verify` | off | skips TLS verification; logs a warning when used |
| `debug` | off | logs each check's decision |

Durations use Go's `time.ParseDuration` grammar — `2s`, `500ms`, `1h30m` —
because that is what existing `pam.d` lines already contain.

## The four checks

Every one of them has to pass, they run in order, and every failure produces
`PAM_AUTH_ERR` with its reason in syslog.

1. **CA signature** — signed by a key in `trusted-ca-file`. A signature
   verification, not a string comparison against that file's contents.
2. **Key binding** — the certificate's public key is the one generated for
   this attempt. Without it, checks 1, 3 and 4 passing together would accept
   any CA-signed certificate carrying the right principal, including one
   issued to somebody else's keypair.
3. **Principal** — the certificate's principals authorize this local account.
4. **Validity window** — now is inside `[valid_after, valid_before]` ±
   `skew-tolerance`.

## Development container

`.devcontainer/` carries everything this repo needs: the C toolchain, libpam
and its test headers, OpenSSL, libcurl, clang with libFuzzer, valgrind,
`ssh-keygen`, a running syslog to read the module's own output from, and Node
and Go for the plan bridge and the P6 differential harness.

Two things about it are deliberate and worth knowing before changing them:

- **The host's Docker socket is mounted**, so `make cross` builds the module
  inside the real CI images. Those are sibling containers run by the host
  daemon, not nested ones.
- **The host's checkout root is mounted at `/workspace`**, with this repo
  opened at `/workspace/ssoossh-pam-c`, and where that came from exported as
  `HOST_WORKSPACE_ROOT`. A sibling container's `-v "$PWD:/src"` is resolved
  by the host daemon against the *host* filesystem, so a container path would
  mount the wrong thing or nothing at all. Because the whole tree hangs off
  one mount, translating it is a prefix swap, and `tests/cross-build.sh` is
  the only thing that has to do it.

## Building

```console
$ make            # builds pam_ssoossh.so (pam_ssoossh.bundle on macOS)
$ make test       # symbol gate, load gate, and the unit suite
$ make san        # the same, rebuilt with AddressSanitizer and UBSan
$ sudo make e2e   # the whole flow against a stub ssoosshd, through real PAM
$ make fuzz-run   # libFuzzer over every parser that reads network bytes
$ sudo make differential  # the same scenarios, against the Go module too
$ make cross      # build and gate on every Linux image CI uses
$ make lint       # actionlint, shellcheck, clang-format, cppcheck
$ make ci-local   # run the CI workflow locally with nektos/act
$ make help
```

`make cross` is the one to run before claiming a change is portable — the
`el8` image is the only place the OpenSSL 1.1.1 and `curl_multi_wait` paths
get compiled:

```console
$ make cross
=== debian12 (debian:12) ===   cc 12.2.0, libcrypto 3.0.20   PASS
=== alpine (alpine:3) ===      cc 15.2.0, libcrypto 3.5.8    PASS
=== el8 (almalinux:8) ===      cc  8.5.0, libcrypto 1.1.1k   PASS
```

Build dependencies are libpam, libcrypto and libcurl:

| Platform | Packages |
| --- | --- |
| Debian, Ubuntu | `build-essential pkg-config libssl-dev libcurl4-openssl-dev libpam0g-dev` |
| RHEL 8+, AlmaLinux, Rocky | `gcc make pkgconf-pkg-config openssl-devel libcurl-devel pam-devel` |
| Alpine | `build-base pkgconf openssl-dev curl-dev linux-pam-dev` |
| FreeBSD | `gmake pkgconf curl` (libpam and OpenSSL are in base; libcurl is not — base has `fetch`) |
| macOS 15+ | Xcode command line tools only — no OpenSSL, no Homebrew |

## Supported platforms

| | Crypto | Console mode | Ships an artifact |
| --- | --- | --- | --- |
| Linux glibc (x86-64, arm64) | OpenSSL ≥ 1.1.1 | yes | yes |
| Linux musl / Alpine | OpenSSL ≥ 1.1.1 | yes | yes |
| FreeBSD | OpenSSL in base | yes | yes |
| macOS 15 Sequoia (arm64) | Security.framework | no | no — developer and CI only |

**OpenSSL 1.1.1 is a hard floor**, set by RHEL 8. A build against anything
older fails at compile time. OpenSSL 1.0.2 and the releases carrying it
(RHEL 7, CentOS 7) are out of scope permanently.

### CA key types

The crypto backend decides what can be verified, so this differs by platform.
Anything unsupported fails with an error naming the algorithm, never with a
vague signature failure.

| CA key type in `trusted-ca-file` | Linux, FreeBSD | macOS |
| --- | --- | --- |
| `ecdsa-sha2-nistp256` / `384` / `521` | supported | supported |
| `rsa-sha2-256` / `rsa-sha2-512` | supported | supported |
| `ssh-ed25519` | supported | **not supported** |
| `ssh-rsa` (SHA-1) | rejected by policy | rejected by policy |

`ssh-rsa` names RSA with SHA-1, which OpenSSH has disabled by default since
8.8. `x/crypto/ssh` still verifies it, so the Go module accepts such a
certificate today and this one refuses it by name — the one place the C
module is deliberately stricter.

macOS has no C-callable Ed25519: Apple's implementation is in CryptoKit,
which is Swift-only. Since macOS ships no artifact, the gap is documented
rather than worked around.

## Crypto is linked, not shipped

The default build bundles no crypto. Which OpenSSL is resident in `sudo` is a
property of the host, and patching it is the distribution's job — so the
module reports the versions it actually linked, at `LOG_INFO`, on every
authentication:

```
pam_ssoossh: 1.0.0 | crypto: OpenSSL 1.1.1k | http: libcurl/7.61.1 OpenSSL/1.1.1k
```

That line is what makes "which crypto is running in sudo across the fleet" a
syslog grep rather than guesswork, including for a host whose distribution
has stopped issuing updates. Two OpenSSLs appear because there are two: the
one this module calls directly, and the one libcurl drives for TLS. The
second is historically the larger attack surface — X.509 chain parsing of
whatever certificate `ssoosshd` presents — and it is worth naming on its own.

The line is built from `curl_version_info`, not `curl_version`. Building the
full feature string asks every backend for its version, which on a libcurl
compiled with LDAP support initialises an LDAP client and a SASL library
inside `sudo` — on every authentication, to write a log line. Valgrind is
how that was found.

For a host in exactly that position, build against a self-maintained OpenSSL
without changing any source:

```console
$ make OPENSSL_PREFIX=/opt/openssl-3.5
```

## Logging

Everything goes to `syslog(3)` under `LOG_AUTHPRIV`. Nothing writes to stdout
or stderr — the module is loaded into `sudo` and `sshd`, where both streams
belong to the host process. `make check-stdio` is the gate that keeps it that
way.

`openlog(3)` and `closelog(3)` are deliberately never called: `openlog`
mutates process-global state and `closelog` closes a descriptor the host may
be holding. Messages carry their own `pam_ssoossh:` prefix instead, so syslog
attributing the line to `sudo` costs nothing.

## Third-party code

Two libraries are vendored, pinned by hash, and compiled in — neither adds
anything to `ldd` output or to the exported symbol table:

- [`third_party/jsmn`](third_party/jsmn/) — a non-allocating JSON tokenizer.
- [`third_party/qrcodegen`](third_party/qrcodegen/) — the QR encoder console
  mode draws with.

Vendoring is not linking, and the distinction is the rule this project holds
to: every *link-time* dependency is a library the operating system already
ships.

## Verified, and not

What has been run, and what has not, stated plainly.

**Verified on Linux (glibc and musl, and the RHEL 8 floor):** the build, the
symbol and load gates, 15 unit suites, the same suites under ASan and UBSan,
five libFuzzer targets over every parser that reads network bytes, and 23
end-to-end scenarios through a real PAM stack against a stub `ssoosshd` —
including the approval, a denial, an expiry, a mid-stream drop and reconnect,
a retryable refusal, a timeout, a certificate for the wrong key, a
certificate from an untrusted CA, an approval URL carrying terminal escape
sequences, and Ctrl-C falling through to the next module under two control
flags.

It also agrees with the Go module. `make differential` loads both against
the same stub, on the same scenarios, and compares the PAM return code —
and it earned its keep on the first run, finding four cases where this
module returned `PAM_AUTH_ERR` for an HTTP failure that should have been
`PAM_AUTHINFO_UNAVAIL`. Those are fixed and the harness is clean. Two
divergences remain and both are intended: Ctrl-C returns `PAM_IGNORE` here
and `PAM_AUTH_ERR` there, and an `ssh-rsa` (SHA-1) certificate is refused
here and accepted there.

**Not verified:** a run against a production `ssoosshd`; FreeBSD and macOS,
whose Makefile branches and crypto backend exist but have never been
compiled, let alone executed; and console mode against the real server
endpoints, which exist in the monorepo but have only been driven from a
stub written against them.

[`docs/porting.md`](docs/porting.md) is the sequence for building and
testing on those two by hand — what to install, what to run, what is most
likely to break first, and why an Objective-C backend would not close the
Ed25519 gap on macOS.

## Testing

`make test` runs everywhere and needs no privileges. `make e2e` needs root —
see [tests/README.md](tests/README.md).

## Licence

MIT. See [LICENSE](LICENSE).
