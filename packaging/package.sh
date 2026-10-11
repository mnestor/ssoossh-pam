#!/bin/sh
# Packages one release tarball from `make dist` as deb, rpm and/or apk with
# nfpm, choosing the formats, the module directory and the dependencies
# from the target the tarball was built for:
#
#   linux-glibc-openssl3_*     deb (Debian 12+, Ubuntu 22.04+) and two rpms,
#                              tagged .el9 and .el10 -- one build serves
#                              both majors, see the dist tag notes below
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

# The dist tag the rpm's Release carries, and what keeps the glibc variants
# apart.
#
# Without it both builds are pam-ssoossh-<version>-1.<arch>: the same NEVRA
# with different libcrypto dependencies, which no repository can hold --
# two packages with one NEVRA are one package as far as any repository is
# concerned, and the one that lands last silently wins. The variants are
# already aligned to EL major (release.yml builds openssl1.1 in almalinux:8
# and openssl3 in almalinux:9), so the build's own EL major is the exact
# discriminator, and a per-releasever repository files each where it
# belongs.
#
# Two variables, because one build can serve more than one EL major:
#
#   rpm_dist   the major this tarball was built on. The SELinux policy
#              package uses this one, since its .pp and its recorded policy
#              floor come from that host and are true of nowhere else.
#   rpm_dists  every major the module is published for. The module rpm is
#              built once per entry, identical but for the Release.
#
# EL 10 is served by the EL 9 build rather than by one of its own. Its
# libcrypto soname is libcrypto.so.3, the same as EL 9, so dist-target.sh
# names both linux-glibc-openssl3 and a separate row would collide on the
# artifact name. More to the point it would be worse: EL 10 has glibc 2.39
# against EL 9's 2.34, and glibc is forward compatible, so the EL 9 build
# runs on EL 10 while an EL 10 build would not run on EL 9. Building
# against the floor is what this repository already does everywhere else.
# Verified rather than assumed: the EL 9 rpm installs on almalinux:10 and
# every soname it links resolves there.
#
# Only rpm gets a dist tag. In a Debian version 1.el9 would be a revision
# string that sorts and reads wrong, and apk has no equivalent.
case $target_os in
linux-glibc-openssl3)
    formats="deb rpm"
    PKG_CRYPTO_SO=libcrypto.so.3
    PKG_DEB_CRYPTO="libssl3t64 | libssl3"
    rpm_dist=.el9
    rpm_dists=".el9 .el10"
    ;;
linux-glibc-openssl1.1)
    # No deb: the distributions with libcrypto.so.1.1 and this glibc are
    # past their support dates.
    formats="rpm"
    PKG_CRYPTO_SO=libcrypto.so.1.1
    PKG_DEB_CRYPTO=
    rpm_dist=.el8
    rpm_dists=.el8
    ;;
linux-musl)
    formats="apk"
    PKG_CRYPTO_SO=libcrypto.so.3
    PKG_DEB_CRYPTO=
    rpm_dist=
    rpm_dists=
    ;;
*)
    echo "package: no package format is defined for $target"
    exit 0
    ;;
esac

mkdir -p "$outdir"
outdir=$(cd "$outdir" && pwd)
for fmt in $formats; do
    # Where this distribution's libpam looks, and the mode its own PAM
    # modules carry there. Discovered at install time by the Makefile;
    # fixed per format here, since a package cannot look.
    # The arch in the file name is the one that format's own tooling
    # expects to read there, and the one inside the package: deb says
    # amd64 where the tarball says x86_64.
    #
    # dists is what the format is built once per. Only rpm has more than
    # one: "none" is the single unadorned build the other formats get, and
    # is spelled rather than left empty because an empty list would run the
    # inner loop zero times and silently produce no package.
    case $fmt in
    deb)
        PKG_SECURITYDIR=/usr/lib/$multiarch/security
        PKG_MODULE_MODE=0644
        fmt_arch=$PKG_ARCH
        dists=none
        ;;
    rpm)
        PKG_SECURITYDIR=/usr/lib64/security
        PKG_MODULE_MODE=0755
        fmt_arch=$target_arch
        dists=$rpm_dists
        ;;
    apk)
        PKG_SECURITYDIR=/lib/security
        PKG_MODULE_MODE=0755
        fmt_arch=$target_arch
        dists=none
        ;;
    esac
    for d in $dists; do
        # The dist tag is in the file name as well as in the Release,
        # because two majors served by one build differ in nothing else:
        # without it the EL 10 rpm would overwrite the EL 9 one on the way
        # into the release, which is the same collision the tag exists to
        # prevent, one level up.
        case $d in
        none) PKG_RELEASE=1; suffix= ;;
        *) PKG_RELEASE=1$d; suffix=$d ;;
        esac
        # The one substitution nfpm cannot do itself: the destination of
        # the module. Everything else in the config is expanded by nfpm
        # from the environment exported below.
        sed -e "s|@SECURITYDIR@|$PKG_SECURITYDIR|g" \
            -e "s|@MODULE_MODE@|$PKG_MODULE_MODE|g" \
            "$here/nfpm.yaml" > "$stage/nfpm.yaml"
        export PKG_ARCH PKG_VERSION PKG_PRERELEASE PKG_MAINTAINER PKG_HOMEPAGE \
            PKG_TARGET="$target" PKG_COMPAT="${compat:-unknown}" \
            PKG_CRYPTO_SO PKG_DEB_CRYPTO PKG_RELEASE \
            PKG_GPG_KEY_FILE PKG_APK_KEY_FILE
        # From inside the staging directory: nfpm resolves content sources
        # relative to the working directory.
        # --target as a file, not a directory: nfpm would otherwise name
        # the package its format's own way, which for rpm collides across
        # targets.
        (cd "$stage" && "$NFPM" package --config nfpm.yaml --packager "$fmt" \
            --target "$outdir/pam-ssoossh_${filever}_${target_os}_${fmt_arch}${suffix}.$fmt")
    done
done

# The SELinux policy package. rpm only -- the policy is for the targeted
# policy that EL and Fedora ship, and see packaging/nfpm-selinux.yaml for
# why this is a separate package rather than a subpackage.
#
# Built only when `make selinux` put a .pp in the tarball. A tarball
# without one is not an error: the policy needs checkpolicy and
# policycoreutils at build time, which a cross-build host or a developer's
# laptop need not have, and the module package is complete without it.
#
# EL 9 only, for the openssl3 build, even though the module rpm from the
# same tarball is also published for EL 10. The policy is the one part that
# does not travel: the .pp and the version floor beside it come from the
# host that compiled them, and EL 10's base policy is a different
# generation entirely -- selinux-policy 42.1.18 against EL 9's 38.1.75.
# More importantly the rule itself was confirmed on Oracle Linux 9.8 and
# nowhere else, and selinux/pam_ssoossh.te allows only domains with a
# denial reproduced on a real host. Publishing it for EL 10 would assert
# something nobody has observed there. See pam_ssoossh(8), SELINUX.
#
# noarch, and therefore built from one architecture's tarball only.
#
# The payload is a compiled policy module and two text files, none of which
# is machine code, so the package is genuinely noarch and saying x86_64
# would be a lie that makes a repository carry it twice. But noarch means
# the EL 9 x86_64 build and the EL 9 aarch64 build would produce one NEVRA
# from two jobs, and their output is not byte-identical: nfpm stamps the
# rpm's BUILDTIME from the clock, so two runs of this script three seconds
# apart already differ. Two files with one NEVRA is the collision the dist
# tag exists to prevent, arriving by another route -- and it would be
# resolved by whichever job's artifact was unpacked last.
#
# So it is built from the canonical architecture and skipped on the other.
# The other job's tarball still carries its own .pp, which is what makes
# this safe to decide here rather than in the workflow: if the two majors
# ever needed different policy the .pp would differ per major, which this
# preserves, and only the per-architecture duplicate is dropped.
SELINUX_PKG_ARCH=x86_64
case " $formats " in
*" rpm "*)
    if [ -f "$stage/selinux/pam_ssoossh.pp" ] &&
       [ "$target_arch" != "$SELINUX_PKG_ARCH" ]; then
        echo "package: pam-ssoossh-selinux is noarch and is built from the" \
             "$SELINUX_PKG_ARCH tarball; skipping it for $target_arch"
    elif [ -f "$stage/selinux/pam_ssoossh.pp" ]; then
        # A binary policy module will not load on a host whose policy is
        # older than the one it was compiled against, so the package says
        # so rather than letting semodule fail in postinstall. The version
        # is whatever `make selinux` recorded on the host that built the
        # .pp; without it the dependency is unversioned, which is honest
        # about knowing nothing rather than guessing a floor.
        vf=$stage/selinux/pam_ssoossh.policyver
        if [ -s "$vf" ]; then
            PKG_SELINUX_POLICY="selinux-policy-base >= $(cat "$vf")"
        else
            PKG_SELINUX_POLICY="selinux-policy-base"
            echo "package: no recorded policy version; pam-ssoossh-selinux" \
                 "will require selinux-policy-base with no floor" >&2
        fi
        export PKG_SELINUX_POLICY
        cp "$here/nfpm-selinux.yaml" "$stage/nfpm-selinux.yaml"
        cp "$here/selinux-postinstall.sh" "$here/selinux-postremove.sh" "$stage/"
        PKG_RELEASE=1$rpm_dist
        # nfpm spells noarch "all". Set here rather than in the config so
        # the module package above keeps the real architecture it needs.
        PKG_ARCH=all
        export PKG_ARCH PKG_VERSION PKG_PRERELEASE PKG_MAINTAINER \
            PKG_HOMEPAGE PKG_GPG_KEY_FILE PKG_RELEASE
        (cd "$stage" && "$NFPM" package --config nfpm-selinux.yaml \
            --packager rpm \
            --target "$outdir/pam-ssoossh-selinux_${filever}_${target_os}_noarch.rpm")
    elif [ -n "${PKG_REQUIRE_SELINUX:-}" ]; then
        # For a release. Shipping without the policy package is a silent
        # regression for every EL site: console login keeps failing and
        # nothing in the release says why, so the release build asks to be
        # stopped rather than to continue quietly.
        echo "package: no selinux/pam_ssoossh.pp in $tarball" >&2
        echo "  PKG_REQUIRE_SELINUX is set, so this is fatal." >&2
        echo "  Build it with 'make selinux' before 'make dist'; that needs" >&2
        echo "  checkpolicy and policycoreutils on the build host." >&2
        exit 1
    else
        echo "package: WARNING: no selinux/pam_ssoossh.pp in $tarball" >&2
        echo "  skipping pam-ssoossh-selinux. Console login stays broken on" >&2
        echo "  EL hosts without it -- see pam_ssoossh(8), SELINUX." >&2
        echo "  Build it with 'make selinux' before 'make dist', or set" >&2
        echo "  PKG_REQUIRE_SELINUX=1 to make this an error." >&2
    fi
    ;;
esac
