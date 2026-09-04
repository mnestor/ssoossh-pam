# pam_ssoossh

A PAM module that authenticates a local account by asking
[ssoosshd](https://github.com/mnestor/ssoossh) for a short-lived SSH
certificate, showing the approver a URL, waiting for a human to approve it in
a browser, and validating the certificate that comes back.

This is a pure C reimplementation of the Go module in the ssoossh monorepo.
The Go build is a `-buildmode=c-shared` object of 12.9 MB that carries the Go
runtime into `sudo` and `sshd`; this one links only libraries the operating
system already ships.

**Status: in progress.** P0 of
[the plan](plans/pam-ssoossh-c/plan.mdx) is complete — the module builds on all
four target platforms, loads, reports its version, and denies. It does not
authenticate anyone yet.

## Building

```console
$ make          # builds pam_ssoossh.so (pam_ssoossh.bundle on macOS)
$ make test     # symbol and load gates
$ make san      # rebuild with AddressSanitizer and UndefinedBehaviorSanitizer
$ make help
```

Build dependencies are libpam and libcrypto (libcurl joins them at P4):

| Platform | Packages |
| --- | --- |
| Debian, Ubuntu | `build-essential pkg-config libssl-dev libpam0g-dev` |
| RHEL 8+, AlmaLinux, Rocky | `gcc make pkgconf-pkg-config openssl-devel pam-devel` |
| Alpine | `build-base pkgconf openssl-dev linux-pam-dev` |
| FreeBSD | `gmake pkgconf` (libpam and OpenSSL are in base) |
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

macOS has no C-callable Ed25519: Apple's implementation is in CryptoKit,
which is Swift-only. Since macOS ships no artifact, the gap is documented
rather than worked around.

## Crypto is linked, not shipped

The default build bundles no crypto. Which OpenSSL is resident in `sudo` is a
property of the host, and patching it is the distribution's job — so the
module reports the version it actually linked, at `LOG_INFO`, on every
authentication:

```
pam_ssoossh: 1.0.0 | crypto: OpenSSL 1.1.1k  FIPS 25 Mar 2021
```

That line is what makes "which crypto is running in sudo across the fleet" a
syslog grep rather than guesswork, including for a host whose distribution has
stopped issuing updates.

For a host in exactly that position, build against a self-maintained OpenSSL
without changing any source:

```console
$ make OPENSSL_PREFIX=/opt/openssl-3.5
```

## Logging

Everything goes to `syslog(3)` under `LOG_AUTHPRIV`. Nothing writes to stdout
or stderr — the module is loaded into `sudo` and `sshd`, where both streams
belong to the host process.

`openlog(3)` and `closelog(3)` are deliberately never called: `openlog`
mutates process-global state and `closelog` closes a descriptor the host may
be holding. Messages carry their own `pam_ssoossh:` prefix instead, so syslog
attributing the line to `sudo` costs nothing.

## Testing

`make test` runs everywhere, including CI, and needs no privileges. Exercising
the module against a real PAM stack needs root — see
[tests/README.md](tests/README.md).

## Licence

MIT. See [LICENSE](LICENSE).
