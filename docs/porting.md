# Building and testing on FreeBSD and macOS

**Neither platform has ever been compiled.** The Makefile branches, the
`ld64` symbol list, and `src/crypto_darwin.c` are all written, and none of it
has been near a machine that could run it. This document is the sequence to
follow the first time, what is likely to break, and how to tell a real
problem from an assumption that was simply wrong.

Everything on Linux — glibc, musl, and the RHEL 8 floor — is verified. These
two are not.

The same sequence runs unattended in
[`.github/workflows/cross-platform.yml`](../.github/workflows/cross-platform.yml),
behind `workflow_dispatch`:

```console
$ gh workflow run cross-platform.yml                # both
$ gh workflow run cross-platform.yml -f job=macos   # one
$ gh run watch
```

Do that first if you have no machine to hand — it costs nothing and the
first step on each platform reports what the SDK and package set actually
contain, which is where most of the answers are.

## Why the two platforms differ in importance

**FreeBSD ships an artifact. macOS does not.** FreeBSD is the OpenPAM target
that reaches real hosts, so a bug there matters in production. macOS exists
to keep the OpenPAM paths, the `ld64` symbol list, and the
Security.framework backend under test on every commit — it ships nothing,
console mode is not compiled into it, and nothing installs under System
Integrity Protection.

If you only have time for one, do FreeBSD.

---

## FreeBSD

### A machine

Any FreeBSD 13 or 14 will do. A VM is fine; this needs no hardware.

- `pkg install` needs network.
- The e2e harness needs root, which in a VM you have.
- FreeBSD's `cc` is clang, so the sanitiser build works the same way it does
  with clang on Linux.

### Packages

```console
# pkg install gmake pkgconf curl bash python3
```

Every one of those is load-bearing:

| | why |
| --- | --- |
| `gmake` | the Makefile uses GNU make features; `make` here is BSD make |
| `pkgconf` | how the build finds libcrypto and libcurl |
| `curl` | **libcurl is not in FreeBSD base.** Base has `fetch(1)`. This is the package most likely to be missing when the build fails at the link |
| `bash` | `tests/e2e.sh` is bash, and base has no bash |
| `python3` | `tests/stubd.py` and `tests/logsink.py` |

libpam and OpenSSL *are* in base, and so is `ssh-keygen`.

### Build and gate

```console
$ gmake print-SECURITYDIR        # should say /usr/local/lib
$ gmake
$ gmake check-symbols            # exactly two exported names
$ gmake test                     # load gate and 16 unit suites
$ gmake check-stdio              # nothing writes to stdout or stderr
$ gmake check-size               # under 512 KB stripped
$ gmake san                      # the whole suite under ASan and UBSan
```

Then the flow, end to end, through a real PAM stack:

```console
$ gmake && gmake tests/pamtest   # build as yourself
$ sudo gmake e2e                 # 24 scenarios against a stub ssoosshd
```

`syslogd` runs by default on FreeBSD and the stock `syslog.conf` files
`LOG_AUTHPRIV` into `/var/log/auth.log`, which is where the harness reads the
module's decisions from. If it is not running, `tests/logsink.py` binds
`/var/run/log` itself — that is the FreeBSD spelling of the socket, and
`tests/e2e.sh` already knows it.

The differential harness is Linux-only and will refuse to run here, on
purpose: the Go module hardcodes Linux-PAM's numeric return codes, so it is
not a correct reference to compare against on OpenPAM. It would report
`PAM_PERM_DENIED` where it means `PAM_AUTH_ERR`.

### What is most likely to break, and why

1. **The link fails on `-lcurl`.** The `curl` package is missing. This is the
   single most likely first failure.

2. **`gmake install` says there is no module directory.** FreeBSD has no
   `security/` subdirectory at all: base modules sit directly in `/usr/lib`
   and ports install to `/usr/local/lib`. The Makefile assumes the latter.
   Confirm with `ls /usr/lib/pam_unix.so`, and override if it is wrong:

   ```console
   $ sudo gmake install SECURITYDIR=/usr/local/lib
   ```

3. **`pkg-config` cannot find libcrypto.** FreeBSD's base OpenSSL does not
   always install a `libcrypto.pc`. The Makefile already falls back to a
   plain `-lcrypto` when pkg-config does not know the package, so this
   should be handled — but if the build fails looking for a header rather
   than a library, that is the fallback not being enough.

4. **A return code differs from Linux.** That is the whole reason this
   platform is a target. Linux-PAM and OpenPAM number their constants
   differently — `7` is `PAM_AUTH_ERR` on one and `PAM_PERM_DENIED` on the
   other — and this module takes every constant from
   `<security/pam_modules.h>` precisely so the numbers follow the platform.
   If a scenario's *decision* is wrong rather than its numbering, that is a
   real bug.

5. **`PAM_IGNORE` behaves differently under a control flag.** The two
   `cancel-*` scenarios exist for this. OpenPAM's dispatcher is an
   independent implementation of Linux-PAM's, and OpenPAM has `binding`
   where Linux-PAM has bracketed actions. If `PAM_IGNORE` is treated as a
   failure under one of them, that is a documentation bug — the stanza in
   the README would need to say so — not a module bug.

---

## macOS

### A machine

macOS 15 Sequoia on arm64 is the baseline (`-mmacosx-version-min=15.0`).
Xcode command line tools only:

```console
$ xcode-select --install
```

**No Homebrew, and nothing to install.** That is the point of the
Security.framework backend: everything this needs — libpam, libcurl,
Security, CoreFoundation — ships with the OS. If a build here starts needing
Homebrew, something has gone wrong with the platform decision rather than
with the build.

### What the SDK should contain

Check before building, because half of porting is finding out an assumption
was wrong:

```console
$ sdk=$(xcrun --show-sdk-path)
$ ls "$sdk/usr/include/curl/curl.h"          # present: libcurl is a system library
$ ls -d "$sdk/usr/include/openssl"           # absent: hence the Apple backend
$ ls "$sdk/usr/include/security/openpam.h"   # present: OpenPAM, not Linux-PAM
$ ls /usr/lib/pam/                           # the SIP-protected module directory
```

### Build and gate

```console
$ make                     # produces pam_ssoossh.bundle, not .so
$ make check-symbols       # nm -gU here, not nm -D
$ make test
$ make check-apple-spi     # the Ed25519 SPI, in the SDK and at runtime
$ make check-stdio
$ make check-size
$ make san
```

Then the flow:

```console
$ make && make tests/pamtest
$ sudo make e2e
```

Two things about e2e on macOS work differently, and both are handled:

**The module is loaded by absolute path.** `/usr/lib/pam` is protected by
System Integrity Protection, so nothing installs there. `make
print-SECURITYDIR` reports nothing on this platform, and `tests/e2e.sh`
writes a `pam.d` entry naming the bundle where it was built:

```
auth  sufficient  /Users/you/ssoossh-pam-c/pam_ssoossh.bundle  server=...
```

That form is supported by every PAM implementation here. One OpenPAM
detail worth knowing if it fails: `openpam_dynamic` tries `<path>.<version>`
before `<path>`, so it will look for `pam_ssoossh.bundle.2` first and fall
back. That fallback is expected to work; if it does not, symlink the
versioned name.

**The log is read through `log stream`.** `syslog(3)` on macOS feeds the
unified logging system — there is no socket to bind, so the sink used on
Linux and FreeBSD does not apply. `tests/e2e.sh` runs

```console
$ log stream --style compact --predicate 'process == "pamtest"'
```

in the background instead. To watch a run by hand:

```console
$ log stream --predicate 'eventMessage CONTAINS "pam_ssoossh"' --style compact
```

### What is most likely to break, and why

1. **`src/crypto_darwin.c` does not compile.** This is the file the macOS job
   exists for and the one most likely to fail first. It is written against
   the documented Security.framework API and has never been through a
   compiler. Expect argument-type mismatches, a `CFNumberRef` where a
   `CFTypeRef` was wanted, and `-Wconversion` complaints on `CFIndex`.
   Everything above `src/crypto.h` is platform-neutral and already verified,
   so a failure here is contained to one file.

2. **`SecKeyCreateRandomKey` refuses to generate.** The key is deliberately
   not persisted — `kSecAttrIsPermanent: false` inside `kSecPrivateKeyAttrs`
   — because it is per-attempt and must not outlive the transaction. If
   generation fails, that dictionary is the first place to look. A key that
   lands in the keychain instead would be a security bug, not a
   convenience.

3. **`make check-symbols` reports more than two names.** `ld64` has no
   version script; the equivalent is `pam_ssoossh.syms`, which lists
   `_pam_sm_authenticate` and `_pam_sm_setcred` with the leading underscore
   Mach-O adds. If a vendored symbol leaks, that file and
   `-fvisibility=hidden` are what should have stopped it.

4. **Ed25519 works, through an SPI, and says so.** `make check-apple-spi`
   must print `exported:` for both symbols and pass the `crypto` and
   `ed25519` suites, and the version line in the log must read
   `Security.framework (Ed25519 SPI ok)`. If instead the suites report
   `no ssh-ed25519 support`, the version line says which of two things
   happened: `(no Ed25519 SPI)` means `dlsym` found nothing, which on a
   macOS 14 or later SDK would be news; `(Ed25519 SPI FAILED self-test)`
   means the symbols resolved and the RFC 8032 known-answer test did not
   pass, which is either a bug in `key_from_ssh_blob`'s Ed25519 branch or
   Apple changing what the constants mean. Either way an `ssh-ed25519` CA
   is skipped with a warning naming the type, never a bare signature
   failure. See "Ed25519 on macOS" below.

5. **Console mode is absent, correctly.** `mode=console` is refused at
   argument-parse time, `mode=auto` uses the browser flow, and neither
   `src/qr.c` nor the vendored encoder is compiled in. The `console` and
   `qr` test suites are `#ifdef`'d out.

---

## Ed25519 on macOS

An earlier version of this section concluded that macOS had no C-callable
Ed25519, because the public SecKey headers name no Ed25519 key type, and
went on to weigh a Swift shim against a vendored verifier. The conclusion
was wrong in a way the public headers could not show, and the reasoning is
kept below because it still decides what to do if the SPI ever goes away.

### What Apple actually exports

Since macOS 14, Security.framework has exported an Ed25519 key type and an
EdDSA signature algorithm for SecKey. They are SPI — declared in Apple's
private headers, absent from the SDK's public ones, and promised nothing —
but they are exported unconditionally on macOS and implemented over the
same corecrypto call CryptoKit makes. The evidence, all checkable:

- **The declarations**, in Apple's open-source Security project at tag
  `Security-61901.120.67` (macOS 26.5):
  [`keychain/headers/SecItemPriv.h`](https://github.com/apple-oss-distributions/Security/blob/Security-61901.120.67/keychain/headers/SecItemPriv.h)
  has `kSecAttrKeyTypeEd25519` and
  [`keychain/headers/SecKeyPriv.h`](https://github.com/apple-oss-distributions/Security/blob/Security-61901.120.67/keychain/headers/SecKeyPriv.h)
  has `kSecKeyAlgorithmEdDSASignatureMessageCurve25519SHA512`, both
  annotated `SPI_AVAILABLE(macos(14.0), ios(17.0), ...)`.
- **The export list**,
  [`OSX/sec/Security/SecExports.exp-in`](https://github.com/apple-oss-distributions/Security/blob/Security-61901.120.67/OSX/sec/Security/SecExports.exp-in),
  lists both symbols for `TARGET_OS_OSX`.
- **The shipping SDK stubs.** `Security.tbd` in the 14.5, 15.5 and 26.5
  SDKs all carry `_kSecAttrKeyTypeEd25519` and
  `_kSecKeyAlgorithmEdDSASignatureMessageCurve25519SHA512` in their
  macOS export lists. `tests/apple-spi-check.sh --sdk` reads the one on
  whatever machine it runs on.
- **The implementation**,
  [`OSX/sec/Security/SecKeyCurve25519.m`](https://github.com/apple-oss-distributions/Security/blob/Security-61901.120.67/OSX/sec/Security/SecKeyCurve25519.m):
  `SecKeyCreateWithData` with that key type takes the raw 32 bytes and
  refuses any other length; verification requires a 64-byte signature and
  calls `cced25519_verify(ccsha512_di(), ...)`, which is what CryptoKit's
  `Curve25519.Signing` calls too.
- **Prior art in C.** GNOME's glib-networking declares the key-type
  constant itself and calls `SecKeyCreateWithData` with it, exactly as
  this backend does.

Semantics match the other platforms. Third-party edge-case testing of
CryptoKit (the ed25519-speccheck suite, which sits on the same corecrypto
call) gives the same accept/reject row as OpenSSL 3, BoringSSL and Go, so
a certificate cannot verify on Linux and fail on a Mac or the reverse.
`tests/unit/ed25519_test.c` pins that row on every platform.

### What the backend does with it

`src/crypto_darwin.c` treats the SPI as something to check on every host
rather than something to assume:

1. **`dlsym`, not a link.** The bundle is linked with `-bind_at_load`, so
   a hard reference to a symbol a future macOS drops would stop the module
   loading at all, inside `sudo`. Both constants are resolved at first use
   instead; a lookup that fails degrades to "`ssh-ed25519` unsupported",
   which is exactly what the backend did before, with a warning naming the
   missing symbol.
2. **A known-answer self-test before trust.** RFC 8032 §7.1 test 3 must
   verify, the same signature with one byte flipped must not, and a
   signature whose S is not below the group order (ed25519-speccheck case
   6) must be refused. An SPI that resolves but has changed meaning under
   the same name fails this and is treated as absent — with an error in
   the log saying which check failed.
3. **The outcome in the version line.** Every authentication logs
   `crypto: Security.framework (Ed25519 SPI ok)`, `(no Ed25519 SPI)` or
   `(Ed25519 SPI FAILED self-test)`, so "which Macs lost Ed25519 after the
   update" is a grep of syslog.

Nothing is added to `otool -L`, no runtime is loaded, and the build still
needs only the command line tools.

### Watching Apple

The SPI can change in three ways, and each has a check that runs before a
host sees it:

| what changes | where it shows first | the check |
| --- | --- | --- |
| the symbols leave the export list | the next SDK, in a beta Xcode | `tests/apple-spi-check.sh --sdk` over every Xcode on a runner |
| the symbols stay but behave differently | the next macOS, in a beta OS | the backend's self-test and the `ed25519` suite, on that OS |
| the SPI becomes public API | the next SDK's headers | the same script, which exits 2 with a note to switch to the header |

**On every macOS CI run**, `cross-platform.yml` checks the SDK before
building and runs `make check-apple-spi` after the unit suite.

**Weekly**, [`apple-drift.yml`](../.github/workflows/apple-drift.yml)
runs three jobs on a schedule and on demand:

- `sdk` — on the two newest hosted macOS images and GitHub's preview
  image, every `/Applications/Xcode*.app` is checked, which is where the
  beta SDKs are. GitHub installs Xcode betas on its images before the
  matching macOS ships, so this is usually the first view of a change.
- `runtime` — the module built and its Ed25519 suite run through the
  framework of the macOS each image runs.
- `source` — the newest tag of Apple's open-source Security project,
  checked for the declarations, the availability annotations and the
  export list. This lags releases but is the one view with a diff to
  read when something has moved.

Failure notifications for scheduled workflows go to the author of the last
commit that touched the workflow file; keep that someone who reads them.
The runner labels in the matrix move with each Xcode cycle — when a row
fails with "no runner matched", update it from
[GitHub's image list](https://github.com/actions/runner-images#available-images)
and `.github/actionlint.yaml`.

**With an Apple developer account: a Mac on the developer beta.** No
hosted image runs a beta *OS* before GitHub publishes it, and the runtime
check is the one that catches a change in behaviour rather than in
exports. A Mac of your own closes that gap:

1. Sign in to the Mac with an Apple ID enrolled in the Apple Developer
   Program, then enable the developer beta under System Settings →
   General → Software Update → Beta Updates. Install the beta and each
   Xcode beta as they appear (Xcode betas are on
   [developer.apple.com/download](https://developer.apple.com/download/)
   and install beside the release one as `Xcode-beta.app`, which the
   workflow's glob picks up).
2. Install a GitHub Actions self-hosted runner on it (repository
   Settings → Actions → Runners → New self-hosted runner) and give it the
   extra label `apple-beta`. The job's `runs-on` is
   `[self-hosted, macOS, apple-beta]`.
3. Set the repository variable `SSOOSSH_APPLE_BETA_RUNNER` to `true`
   (Settings → Secrets and variables → Actions → Variables). The
   `beta-runtime` job is skipped until then, so a repo without such a Mac
   never queues on a label nobody serves.

That Mac then runs the SDK check over every installed Xcode and the
runtime check through the beta framework, weekly, and the developer beta
is typically months ahead of the release the hosted images get. Betas
occasionally break unrelated things; a failure on that job alone, with
the hosted rows green, is a reason to read the log, not to change the
backend.

### If the SPI ever goes

Nothing breaks: every affected host logs `(no Ed25519 SPI)` and skips
`ssh-ed25519` CAs with a warning, and every other CA type keeps working.
The question is only whether to restore Ed25519, and the two candidates
from the original analysis still stand in the same order:

**Vendor a verify-only implementation.** libsodium's ref10 verifier
(`open.c` with `fe`, `ge` and `sc` and their tables; ISC) is the candidate:
about a hundred lines of verify logic over well-known arithmetic, with
checks that are a strict superset of OpenSSL's, so nothing Linux would
reject passes on a Mac. SHA-512 comes from CommonCrypto rather than being
vendored. It would sit in `third_party/ed25519/` beside `jsmn` and
`qrcodegen`, pinned by hash, adding nothing to `otool -L` or the exported
symbol table, and `tests/unit/ed25519_test.c` already pins the profile it
would have to match. Verification-only also removes most of what makes
vendoring crypto risky: no key generation, no signing, no secret, nothing
for a timing side channel to leak.

**Not a Swift shim.** It would work — CryptoKit's `Curve25519.Signing` is
reachable from a Swift object with a C-callable entry point, and Swift 6.3
formalised that attribute as `@c` — but Apple's own engineers state that
neither the Swift nor the Objective-C runtime supports unloading, and
OpenPAM `dlclose`s modules, so behaviour after `pam_end` is undefined. It
also makes the build need `swiftc`, and puts a language runtime back into
`sudo`, which is the trade this port exists to remove. Objective-C cannot
reach CryptoKit at all, and there is no Swift-to-C path.

---

## Turning these on in CI

Once both pass, move the jobs into
[`ci.yml`](../.github/workflows/ci.yml) so a failure interrupts, and delete
`cross-platform.yml`. Until then they stay behind `workflow_dispatch`:
running them on every commit would produce failures nobody is ready to act
on, on platforms nobody is working on yet.

Update the "Verified, and not" section of the [README](../README.md) at the
same time. It currently says these platforms have never been compiled, and
that should stop being true in the same commit that makes it untrue.
