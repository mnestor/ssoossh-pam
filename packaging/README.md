# Packaging

deb, rpm and apk are produced from the release tarballs by
[nfpm](https://nfpm.goreleaser.com) — a standalone packager that wraps files
it is given, which is the right shape for a C module: nothing here builds
anything. The module in a package is byte-for-byte the one in the tarball
for the same target.

The macOS package is the same idea with Apple's tools: `macos.sh` lays the
tarball out as it will land on the host, signs the module, wraps it with
`pkgbuild` and `productbuild`, signs the package, and has Apple notarize
it.

| file | does |
| --- | --- |
| `nfpm.yaml` | what goes where, and what each format calls the libraries the module needs |
| `package.sh` | one tarball in, its packages out: picks formats, module directory and soname by target; hands a macOS tarball to `macos.sh` |
| `macos.sh` | one macOS tarball in, a signed and notarized `.pkg` out |
| `macos/` | the installer's `Distribution.xml` (title, arm64 only, OS floor) and its welcome and readme panes |
| `version.sh` | `git describe` into a package version, shared by both |

```console
$ make packages                       # from `make dist`; nfpm on Linux, pkgbuild on a Mac
$ packaging/package.sh dist/pam_ssoossh-v1.2.0-linux-x86_64-glibc-openssl3.tar.gz
$ packaging/package.sh dist/pam_ssoossh-v1.2.0-macos15-aarch64.tar.gz     # on a Mac
```

## Which target becomes which package

| target | formats | module directory |
| --- | --- | --- |
| `linux-*-glibc-openssl3` | deb, rpm | `/usr/lib/<triplet>/security`, `/usr/lib64/security` |
| `linux-*-glibc-openssl1.1` | rpm | `/usr/lib64/security` |
| `linux-*-musl` | apk | `/lib/security` |
| `freebsd*` | none | — |
| `macos*-aarch64` | pkg | `/usr/local/lib/pam` |

The macOS module goes under `/usr/local` because `/usr/lib/pam`, the one
directory OpenPAM looks a bare name up in, is protected by System Integrity
Protection. A `pam.d` line names it by absolute path;
`docs/examples/pam.d/sudo_local` is the stanza. The package is arm64 only
and refuses, in the installer, an Intel Mac or a macOS older than the
deployment target the module was built with (`MINVER` in the Makefile, in
the target name). Man pages go to `/usr/local/share/man`, the examples and
`BUILDINFO` to `/usr/local/share/doc/pam_ssoossh`. Removing it is deleting
those files and `pkgutil --forget org.mikenestor.pam_ssoossh`.

No deb for the OpenSSL 1.1 build: the Debian and Ubuntu releases that had
`libssl1.1` are past their support dates. Add one in `package.sh` if that
ever matters.

Dependencies are sonames wherever the format allows — `libcrypto.so.3()(64bit)`
for rpm, `so:libcrypto.so.3` for apk — which is what `rpmbuild` and `abuild`
derive on their own and never gets renamed. Debian has no such provides, so
the deb names packages, with both spellings of the ones the 64-bit `time_t`
transition renamed (`libssl3t64 | libssl3`).

Nothing is written to `/etc/pam.d`. Wiring the module into a service is the
operator's decision, and `pam_ssoossh(8)` is the place it is described.

## Versions

`git describe` becomes the package version:

| tag or describe | deb, rpm | apk |
| --- | --- | --- |
| `v1.2.0` | `1.2.0` | `1.2.0` |
| `v1.2.0-rc1` | `1.2.0~rc1` | `1.2.0_rc1` |
| `v1.2.0-3-gabc1234` | `1.2.0~3.gabc1234` | `1.2.0_3.gabc1234` |
| no tag at all | `0.0.0~dev.abc1234` | `0.0.0_dev.abc1234` |

A pre-release sorts *before* the release it precedes in every format, and
an untagged build can never outrank a real one on a host.

## Signing

Three sets of material, because the formats disagree. Two keys for the
Linux packages:

- **An OpenPGP key** signs the deb (`_gpgorigin`, dpkg-sig style), the rpm
  (RPM v4 header signature) and the release's `SHA256SUMS`, which is what
  covers the tarballs. Generate a signing-only key without an expiry you
  will forget, and keep the private half only in the repository secrets:

  ```console
  $ gpg --quick-generate-key 'pam_ssoossh release <release@example.org>' rsa4096 sign never
  $ gpg --armor --export-secret-keys release@example.org   # -> private.pgp
  $ gpg --fingerprint release@example.org                  # -> README
  ```

  The apk needs a second key, and cannot share that one. nfpm signs an apk
  with RSA, and Alpine's `apk` verifies it against an RSA public key
  installed under `/etc/apk/keys/<name>` rather than against an OpenPGP
  keyring — so an OpenPGP key is not merely inconvenient here, it is the
  wrong kind of key, and nfpm rejects it with "Signing error: no PEM block
  found". Generate an unencrypted RSA key for it:

  ```console
  $ openssl genrsa -out apk.pem 4096                       # -> apk.pem
  $ openssl rsa -in apk.pem -pubout -out pam-ssoossh.rsa.pub
  ```

  The workflow derives the public half itself and attaches it to the
  release; the command above is for checking it by hand.

  The public key's filename is what `apk` matches the signature against.
  `nfpm.yaml` fixes it as `pam-ssoossh`, so a host installs the public half
  as `/etc/apk/keys/pam-ssoossh.rsa.pub`, exactly that name.

Repository secrets the release workflow reads:

| secret | holds |
| --- | --- |
| `OP_SERVICE_ACCOUNT_TOKEN` | a 1Password service account token |

That is the only repository secret. The keys themselves live in 1Password,
in the item the release job names, and the service account must be able to
read the vault holding it:

| field | holds |
| --- | --- |
| `private.pgp` | the **armored** OpenPGP private key; deb, rpm, SHA256SUMS |
| `password` | its passphrase |
| `apk.pem` | an unencrypted RSA private key in PEM; the apk |

`private.pgp` has to be armored: a binary `gpg --export-secret-keys` does
not survive the trip through a step output.

All optional, and each is checked before it is used: a missing token, or a
key of the wrong kind, leaves that one format unsigned rather than failing
a release that has everything else built.
Both public keys are attached to every release, as
`pam-ssoossh-release-key.asc` and `pam-ssoossh.rsa.pub`; publish the
OpenPGP fingerprint somewhere that is not the release page as well.

Locally, the same through the environment:

```console
$ PKG_GPG_KEY_FILE=~/release.asc NFPM_PASSPHRASE=... PKG_APK_KEY_FILE=~/apk.pem make packages
```

### macOS

Gatekeeper refuses a downloaded `.pkg` unless it is signed with a
**Developer ID Installer** certificate and notarized, so the macOS package
needs an Apple Developer Program membership and three things from it:

- a **Developer ID Application** identity, which signs the module inside
  the package;
- a **Developer ID Installer** identity, which signs the package itself —
  a different certificate, issued from the same developer account;
- an **App Store Connect API key** with the Developer role, for
  `notarytool`.

`macos.sh` reads them from the environment under the names the ssoossh
server's [quill](https://github.com/anchore/quill) setup uses, so one
1Password item and one `.env.local` serve both projects:

| variable | holds |
| --- | --- |
| `QUILL_SIGN_P12` | the identities and their private keys, PKCS#12, base64 |
| `QUILL_INSTALLER_P12` | optional: the Installer identity on its own, if it is not in the P12 above |
| `QUILL_SIGN_PASSWORD` | the password of both |
| `QUILL_NOTARY_ISSUER`, `QUILL_NOTARY_KEY_ID` | the API key's issuer and key ids |
| `QUILL_NOTARY_KEY` | the API key, PEM or its base64 |

quill only ever needed the Application identity, so a P12 exported for it
may not hold the Installer one. Keychain Access exports both at once when
both are selected; or export the Installer identity alone into
`QUILL_INSTALLER_P12`. With signing on and no Installer identity anywhere,
`macos.sh` stops rather than build a package every Mac would refuse.

All optional together: with none of them set the package is built
unsigned, and the log says so. With the P12 and no notary key it is signed
but not notarized.

In the release workflow the values come from 1Password through
`1password/load-secrets-action`, and the only repository secret is the
service account token, `OP_SERVICE_ACCOUNT_TOKEN`. Without it the
1Password step is skipped and the package is unsigned. The `op://`
references in `release.yml` name the item; the optional
`QUILL_INSTALLER_P12` line there is commented out, because a reference to a
field that does not exist fails the step.

Locally, from the same `.env.local` the server project uses:

```console
$ set -a; . ./.env.local; set +a
$ make dist && make packages
```

The script imports the identities into a keychain of its own and deletes it
on exit; nothing lands in the login keychain.

## Verifying a download

```console
$ gpg --import pam-ssoossh-release-key.asc
$ gpg --verify SHA256SUMS.asc SHA256SUMS
$ sha256sum -c SHA256SUMS --ignore-missing

$ rpm --import pam-ssoossh-release-key.asc && rpm -K pam-ssoossh-*.rpm
$ sudo cp pam-ssoossh.rsa.pub /etc/apk/keys/ && sudo apk add ./pam-ssoossh-*.apk
```

For the deb, `apt` verifies repositories rather than files, so the
`SHA256SUMS` signature is the check that matters; the embedded `_gpgorigin`
can be checked with `dpkg-sig --verify` where that tool exists.

On a Mac, what Gatekeeper will decide, and the signature and the stapled
notarization ticket behind it:

```console
$ spctl --assess --type install -vv pam_ssoossh-*.pkg
$ pkgutil --check-signature pam_ssoossh-*.pkg
$ xcrun stapler validate pam_ssoossh-*.pkg
```

And when the repository is public, GitHub's own provenance:

```console
$ gh attestation verify pam-ssoossh_1.2.0_amd64.deb -R <owner>/<repo>
```
