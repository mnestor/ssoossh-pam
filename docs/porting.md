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
$ gmake test                     # load gate and 15 unit suites
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

4. **Ed25519 is refused, correctly.** An `ssh-ed25519` CA in
   `trusted-ca-file` is skipped with a warning naming the algorithm, and a
   certificate signed by one is refused with an error naming it too — never
   with a bare signature failure. That is the documented capability gap, not
   a bug. See below.

5. **Console mode is absent, correctly.** `mode=console` is refused at
   argument-parse time, `mode=auto` uses the browser flow, and neither
   `src/qr.c` nor the vendored encoder is compiled in. The `console` and
   `qr` test suites are `#ifdef`'d out.

---

## Ed25519 on macOS

The question is whether writing part of the backend in Objective-C would
close the one capability gap. It would not, and it is worth setting out why,
because the reasoning also says what *would*.

### Objective-C does not help

Apple's Ed25519 is in **CryptoKit** (`Curve25519.Signing`), which is a pure
Swift framework. It is built out of generics, protocols with associated
types, and value types that have no Objective-C representation, and Apple
publishes no `@objc` bridging for it. **Objective-C cannot call CryptoKit.**
Rewriting `crypto_darwin.c` as `crypto_darwin.m` buys nothing — it would
reach exactly the same C-level APIs the file already uses.

Those C-level APIs have no Ed25519:

- **SecKey** — `kSecAttrKeyTypeRSA` and `kSecAttrKeyTypeECSECPrimeRandom`
  (plus deprecated EC aliases). No Ed25519 as of this writing.
- **CommonCrypto** — digests, HMAC, symmetric ciphers, key derivation. No
  public-key signature verification at all.
- **corecrypto** — Apple's actual implementation, and not a public API:
  no shipped headers, and linking against it is unsupported.

The macOS CI job prints the SDK's key-type constants on every run precisely
so this can be *checked* rather than believed:

```console
$ grep -rho 'kSecAttrKeyType[A-Za-z0-9]*' \
    "$(xcrun --show-sdk-path)/System/Library/Frameworks/Security.framework/Headers/" |
  sort -u
```

If `kSecAttrKeyTypeEd25519` ever appears there, the gap closes with about
twenty lines in `key_from_ssh_blob` and `sig_algo_info`, and nothing else
in this section applies.

### A Swift shim would work, and costs the thing this port removed

Swift can export a C-callable symbol:

```swift
import CryptoKit

@_cdecl("ssoossh_ed25519_verify")
public func ssoossh_ed25519_verify(/* key, msg, sig pointers and lengths */) -> Int32 {
    // Curve25519.Signing.PublicKey(rawRepresentation:).isValidSignature(_:for:)
}
```

Compiled with `swiftc` and linked into the bundle, this genuinely works. It
is also the wrong trade here, for the reason the whole project exists:

**It loads the Swift runtime into `sudo`.** The Go module's 12.9 MB and its
runtime threads and signal handlers are what this port removed; putting a
different language runtime back into the same root process to gain one
signature algorithm on a platform that ships no artifact inverts the trade
deliberately. The Swift runtime lives in `/usr/lib/swift/` on macOS 10.14.4
and later so it is a dynamic dependency rather than a static one — but it is
still a runtime being initialised inside `sudo`.

Two smaller objections. `@_cdecl` is an underscored attribute: officially
unstable and not covered by source compatibility. And it makes the build
need Swift, which means the "Xcode command line tools only, nothing to
install" property of this platform stops being true.

### Vendoring a C verifier is the right answer, if the gap ever matters

Ed25519 **verification** is self-contained and small: TweetNaCl's
`crypto_sign_open` is about 800 lines of public-domain, fully portable C,
and ref10 and donna are comparable. It would sit beside `jsmn` and
`qrcodegen` in `third_party/`, pinned by hash, adding nothing to `otool -L`
output and nothing to the exported symbol table — exactly the rule this
project holds everywhere: every *link-time* dependency is a library the
operating system already ships, and anything else is vendored and auditable.

Verification-only also removes most of what makes vendoring crypto risky.
There is no key generation, no signing, and no secret: the CA public key,
the signature and the signed bytes are all public. There is nothing for a
timing side channel to leak, which is the usual reason to insist on a
reviewed implementation.

The plan anticipated this and deferred it, and that judgement still holds:

> A vendored Ed25519 verifier would close it without adding a linked
> dependency, and remains available if the limit ever becomes real for a
> deployment; it is not worth carrying extra crypto code in a root process
> on the chance.

### So: should you?

**Not yet.** The gap only exists on a platform that ships no artifact. The
only person who can hit it is a developer with an `ssh-ed25519` CA testing
on a Mac, and for them the module already does the right thing: it names the
algorithm rather than failing mysteriously.

The condition that would change the answer is macOS becoming a shipping
target, or an Ed25519 CA appearing in a deployment that has Macs in it. At
that point vendor the C verifier — not Objective-C, which cannot reach
CryptoKit, and not a Swift shim, which puts a runtime back into `sudo`.

If it is ever done, the work is contained:

- `third_party/ed25519/` with the pinned source and a `README.md` naming the
  version and hash, like the other two.
- `ssoossh_crypto_supports_key` gains `ssh-ed25519` on Darwin.
- `sig_algo_info` gains the algorithm, dispatching to the vendored verifier
  rather than to `SecKeyVerifySignature`.
- `tests/unit/key_test.c` and `cert_test.c` already assert the capability
  matrix per platform; the `#ifdef __APPLE__` branches there come out, and
  the existing Ed25519 fixture certificate starts being verified rather than
  refused.

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
