#!/bin/sh
# Packages one release tarball from `make dist` as deb, rpm and/or apk with
# nfpm, choosing the formats, the module directory and the dependencies
# from the target the tarball was built for:
#
#   linux-glibc-openssl3_*     deb (Debian 12+, Ubuntu 22.04+) and rpm (EL 9+)
#   linux-glibc-openssl1.1_*   rpm (EL 8)
#   linux-musl_*               apk (Alpine)
#   freebsd*                   pkg, through freebsd.sh -- on FreeBSD only,
#                              and only on the major release the tarball
#                              was built for, since pkg takes a package's
#                              ABI from the host
#   darwin_*                   pkg, through macos.sh -- on a Mac only, since
#                              the tools that build and sign one exist
#                              nowhere else
#   anything else              nothing, and says so
#
#   packaging/package.sh dist/pam-ssoossh_1.2.0_linux-glibc-openssl3_x86_64.tar.gz [outdir]
#
# The version and target are read from the tarball's own BUILDINFO rather
# than parsed out of its name, so a version with hyphens in it (v1.2.0-rc1,
# or `git describe` between tags) cannot be split in the wrong place.
#
# Every package is named <package>_<version>_<os>_<arch> like the tarball
# it came from, rather than left to whatever the format's own convention
# is. nfpm's rpm convention has no room for the os field, so the EL 8 and
# EL 9 rpms for one architecture are the same filename under it, and the
# second silently overwrote the first on the way into a release.
#
# Needs nfpm on PATH, or NFPM pointing at one:
# https://github.com/goreleaser/nfpm/releases -- the release workflow pins
# a version and checks its hash.
#
# Signing is by environment, and off when the variables are empty:
#
#   PKG_GPG_KEY_FILE   armored OpenPGP private key; signs deb and rpm
#   NFPM_PASSPHRASE    its passphrase, if it has one
#   PKG_APK_KEY_FILE   RSA private key in PEM; signs apk. The public half
#                      must be installed on hosts as
#                      /etc/apk/keys/pam-ssoossh.rsa.pub, the name nfpm.yaml
#                      fixes.
set -eu

tarball=${1:?usage: $0 <dist tarball> [outdir]}
outdir=${2:-$(dirname "$tarball")}
NFPM=${NFPM:-nfpm}
PKG_MAINTAINER=${PKG_MAINTAINER:-"Mike Nestor <me@mikenestor.org>"}
PKG_HOMEPAGE=${PKG_HOMEPAGE:-https://github.com/mnestor/ssoossh}
PKG_GPG_KEY_FILE=${PKG_GPG_KEY_FILE:-}
PKG_APK_KEY_FILE=${PKG_APK_KEY_FILE:-}
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source-path=SCRIPTDIR
. "$here/version.sh"

stage=$(mktemp -d "${TMPDIR:-/tmp}/pam_ssoossh-pkg.XXXXXX")
trap 'rm -rf "$stage"' EXIT
tar -C "$stage" --strip-components=1 -xzf "$tarball"

field() {
    sed -n "s/^$1:[[:space:]]*//p" "$stage/BUILDINFO" | head -1
}
describe=$(field version)
target=$(field target)
compat=$(field ssoosshd)
if [ -z "$describe" ] || [ -z "$target" ]; then
    echo "package: $tarball has no usable BUILDINFO" >&2
    exit 1
fi

# <os>_<arch>: the os field decides the formats and the dependencies, the
# arch field is the tarball's spelling of the machine. Split on the first
# underscore, not the last: no os field holds one, and x86_64 does.
target_os=${target%%_*}
target_arch=${target#*_}
# The version as the tarball spells it, which is `git describe` without its
# leading v. PKG_VERSION below is the same thing in what each format will
# accept; this is only ever a filename.
filever=${describe#v}

case $target_os in
linux-*)
    case $target_arch in
    x86_64)
        PKG_ARCH=amd64
        multiarch=x86_64-linux-gnu
        ;;
    aarch64)
        PKG_ARCH=arm64
        multiarch=aarch64-linux-gnu
        ;;
    *)
        echo "package: no packages are defined for $target_arch" >&2
        exit 1
        ;;
    esac
    ;;
freebsd*)
    # pkg create exists only on FreeBSD, and the package it writes is
    # stamped with the ABI of the host it ran on, so this is built in the
    # release workflow's FreeBSD VM. On the Linux runner that merges the
    # release, as with the macOS package below, it is a no-op.
    if [ "$(uname -s)" = FreeBSD ]; then
        # Not exec: the trap above still has this script's staging to
        # remove. freebsd.sh unpacks the tarball again for itself.
        "$here/freebsd.sh" "$tarball" "$outdir"
        exit 0
    fi
    echo "package: $target is packaged on FreeBSD (packaging/freebsd.sh); nothing to do here"
    exit 0
    ;;
darwin)
    # The installer package needs pkgbuild, productbuild and codesign,
    # which only a Mac has. The release workflow builds it in its macOS
    # job; on the Linux runner that merges the release, this is a no-op.
    if [ "$(uname -s)" = Darwin ]; then
        # Not exec: the trap above still has this script's staging to
        # remove. macos.sh unpacks the tarball again for itself.
        "$here/macos.sh" "$tarball" "$outdir"
        exit 0
    fi
    echo "package: $target is packaged on macOS (packaging/macos.sh); nothing to do here"
    exit 0
    ;;
*)
    echo "package: $target is not a Linux target; no packages to build"
    exit 0
    ;;
esac

command -v "$NFPM" >/dev/null || {
    echo "package: nfpm not found; install it or set NFPM=/path/to/nfpm" >&2
    exit 1
}

gzip -9n "$stage"/man/*.[58]
pkg_version "$describe"

case $target_os in
linux-glibc-openssl3)
    formats="deb rpm"
    PKG_CRYPTO_SO=libcrypto.so.3
    PKG_DEB_CRYPTO="libssl3t64 | libssl3"
    ;;
linux-glibc-openssl1.1)
    # No deb: the distributions with libcrypto.so.1.1 and this glibc are
    # past their support dates.
    formats="rpm"
    PKG_CRYPTO_SO=libcrypto.so.1.1
    PKG_DEB_CRYPTO=
    ;;
linux-musl)
    formats="apk"
    PKG_CRYPTO_SO=libcrypto.so.3
    PKG_DEB_CRYPTO=
    ;;
*)
    echo "package: no package format is defined for $target"
    exit 0
    ;;
esac

mkdir -p "$outdir"
outdir=$(cd "$outdir" && pwd)
for fmt in $formats; do
    # Where this distribution's libpam looks. Discovered at install time
    # by the Makefile; fixed per format here, since a package cannot look.
    # The arch in the file name is the one that format's own tooling
    # expects to read there, and the one inside the package: deb says
    # amd64 where the tarball says x86_64.
    case $fmt in
    deb)
        PKG_SECURITYDIR=/usr/lib/$multiarch/security
        fmt_arch=$PKG_ARCH
        ;;
    rpm)
        PKG_SECURITYDIR=/usr/lib64/security
        fmt_arch=$target_arch
        ;;
    apk)
        PKG_SECURITYDIR=/lib/security
        fmt_arch=$target_arch
        ;;
    esac
    # The one substitution nfpm cannot do itself: the destination of the
    # module. Everything else in the config is expanded by nfpm from the
    # environment exported below.
    sed "s|@SECURITYDIR@|$PKG_SECURITYDIR|g" "$here/nfpm.yaml" > "$stage/nfpm.yaml"
    export PKG_ARCH PKG_VERSION PKG_PRERELEASE PKG_MAINTAINER PKG_HOMEPAGE \
        PKG_TARGET="$target" PKG_COMPAT="${compat:-unknown}" \
        PKG_CRYPTO_SO PKG_DEB_CRYPTO \
        PKG_GPG_KEY_FILE PKG_APK_KEY_FILE
    # From inside the staging directory: nfpm resolves content sources
    # relative to the working directory.
    # --target as a file, not a directory: nfpm would otherwise name the
    # package its format's own way, which for rpm collides across targets.
    (cd "$stage" && "$NFPM" package --config nfpm.yaml --packager "$fmt" \
        --target "$outdir/pam-ssoossh_${filever}_${target_os}_${fmt_arch}.$fmt")
done
