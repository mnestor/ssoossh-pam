# Packaging

deb, rpm and apk are produced from the release tarballs by
[nfpm](https://nfpm.goreleaser.com) — a standalone packager that wraps files
it is given, which is the right shape for a C module: nothing here builds
anything. The module in a package is byte-for-byte the one in the tarball
for the same target.

| file | does |
| --- | --- |
| `nfpm.yaml` | what goes where, and what each format calls the libraries the module needs |
| `package.sh` | one tarball in, its packages out: picks formats, module directory and soname by target |

```console
$ make packages                       # from `make dist`, needs nfpm on PATH
$ packaging/package.sh dist/pam_ssoossh-v1.2.0-linux-x86_64-glibc-openssl3.tar.gz
```

## Which target becomes which package

| target | formats | module directory |
| --- | --- | --- |
| `linux-*-glibc-openssl3` | deb, rpm | `/usr/lib/<triplet>/security`, `/usr/lib64/security` |
| `linux-*-glibc-openssl1.1` | rpm | `/usr/lib64/security` |
| `linux-*-musl` | apk | `/lib/security` |
| `freebsd*` | none | — |

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

Two keys, because the formats disagree:

- **An OpenPGP key** signs the deb (`_gpgorigin`, dpkg-sig style), the rpm
  (RPM v4 header signature) and the release's `SHA256SUMS`, which is what
  covers the tarballs. Generate a signing-only key without an expiry you
  will forget, and keep the private half only in the repository secrets:

  ```console
  $ gpg --quick-generate-key 'pam_ssoossh release <release@example.org>' rsa4096 sign never
  $ gpg --armor --export-secret-keys release@example.org   # -> RELEASE_GPG_PRIVATE_KEY
  $ gpg --fingerprint release@example.org                  # -> README
  ```

- **A bare RSA key** signs the apk: Alpine's `apk` verifies with an RSA
  public key installed under `/etc/apk/keys/<name>`, not with OpenPGP.

  ```console
  $ openssl genrsa -out apk-private.pem 4096                # -> RELEASE_APK_PRIVATE_KEY
  $ openssl rsa -in apk-private.pem -pubout -out pam-ssoossh.rsa.pub
  ```

  The public key's filename is what `apk` matches the signature against.
  `nfpm.yaml` fixes it as `pam-ssoossh`, so a host installs the public half
  as `/etc/apk/keys/pam-ssoossh.rsa.pub`, exactly that name.

Repository secrets the release workflow reads:

| secret | holds |
| --- | --- |
| `RELEASE_GPG_PRIVATE_KEY` | the armored OpenPGP private key |
| `RELEASE_GPG_PASSPHRASE` | its passphrase, if it has one |
| `RELEASE_APK_PRIVATE_KEY` | the RSA private key, PEM |

All optional. A release without them is unsigned and the job log says so.
Both public keys are attached to every release, as
`pam-ssoossh-release-key.asc` and `pam-ssoossh.rsa.pub`; publish the
OpenPGP fingerprint somewhere that is not the release page as well.

Locally, the same through the environment:

```console
$ PKG_GPG_KEY_FILE=~/release.asc NFPM_PASSPHRASE=... PKG_APK_KEY_FILE=~/apk.pem make packages
```

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

And when the repository is public, GitHub's own provenance:

```console
$ gh attestation verify pam-ssoossh_1.2.0_amd64.deb -R <owner>/<repo>
```
