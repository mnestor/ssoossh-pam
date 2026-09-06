#!/bin/sh
# One FreeBSD release tarball in, one pkg(8) package out.
#
#   packaging/freebsd.sh dist/pam-ssoossh_1.2.0_freebsd15_x86_64.tar.gz [outdir]
#
# Reached through packaging/package.sh, which routes a freebsd* target
# here the way it routes a darwin one to macos.sh. Like both of those,
# nothing is built: the module in the package is the one from the tarball
# for the same target.
#
# Why a package at all, when the tarball already carries the module: pkg
# stamps every package with the ABI of the release it was built on --
# FreeBSD:14:amd64, FreeBSD:15:amd64 -- and refuses to install one whose
# ABI does not match the host. That refusal is the whole point here. Base
# OpenSSL changes with the major release (14 has libcrypto.so.30, 15 has
# libcrypto.so.35, and no port supplies the other's), so a module built on
# 14 cannot load on 15; with a tarball that surfaces as a module that fails
# to load at authentication time, which is the worst possible place for it.
# With a package it surfaces as `pkg install` saying no.
#
# nfpm, which wraps the Linux tarballs, has no FreeBSD packager, and
# `pkg create` exists only on FreeBSD -- so this runs in the release
# workflow's FreeBSD VM, beside the build, rather than in the job that
# merges the release.
#
# The package's own name is pam_ssoossh, with an underscore, because that
# is what FreeBSD calls a PAM module (pam_ssh_agent_auth, pam_mysql) and
# because it is the name an eventual security/pam_ssoossh port would carry.
# The file keeps the project's <package>_<version>_<os>_<arch> spelling,
# like every other artifact in a release.
set -eu

tarball=${1:?usage: $0 <dist tarball> [outdir]}
outdir=${2:-$(dirname "$tarball")}
PKG_MAINTAINER=${PKG_MAINTAINER:-"Mike Nestor <me@mikenestor.org>"}
PKG_HOMEPAGE=${PKG_HOMEPAGE:-https://github.com/mnestor/ssoossh}
PKG=${PKG:-pkg}
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source-path=SCRIPTDIR
. "$here/version.sh"

if [ "$(uname -s)" != FreeBSD ]; then
    echo "freebsd: pkg(8) builds packages only on FreeBSD; nothing to do here"
    exit 0
fi
command -v "$PKG" >/dev/null || {
    echo "freebsd: pkg not found on PATH" >&2
    exit 1
}

stage=$(mktemp -d "${TMPDIR:-/tmp}/pam_ssoossh-pkg.XXXXXX")
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/src"
tar -C "$stage/src" --strip-components=1 -xzf "$tarball"

field() {
    sed -n "s/^$1:[[:space:]]*//p" "$stage/src/BUILDINFO" | head -1
}
describe=$(field version)
target=$(field target)
compat=$(field ssoosshd)
if [ -z "$describe" ] || [ -z "$target" ]; then
    echo "freebsd: $tarball has no usable BUILDINFO" >&2
    exit 1
fi

# Split on the first underscore, not the last: no os field holds one, and
# x86_64 does.
target_os=${target%%_*}
target_arch=${target#*_}
case $target_os in
freebsd[0-9]*) ;;
*)
    echo "freebsd: $target is not a FreeBSD target" >&2
    exit 1
    ;;
esac
target_major=${target_os#freebsd}
filever=${describe#v}

# The host decides the ABI stamped into the package, and pkg gives no way
# to say otherwise, so building a freebsd14 tarball's package on a 15 host
# would produce a package labelled FreeBSD:15 holding a module that needs
# libcrypto.so.30 -- precisely the failure this package exists to prevent,
# now carrying a label that says it cannot happen. Refuse instead.
abi=$($PKG config abi)
abi_major=$(printf '%s' "$abi" | cut -d: -f2)
if [ "$abi_major" != "$target_major" ]; then
    echo "freebsd: this is FreeBSD $abi_major ($abi) and the tarball is for" \
        "FreeBSD $target_major ($target). A package must be built on the" \
        "release it is for, since pkg takes the ABI from the host." >&2
    exit 1
fi

# libcurl is the one library the module needs that FreeBSD base does not
# have -- base ships fetch(1). libpam and libcrypto are in base and belong
# to no package, so they are named by soname in BUILDINFO and nowhere here.
# The version recorded is the one this was packaged against; pkg resolves
# the dependency by name and origin.
curl_origin=$($PKG query %o curl 2>/dev/null || true)
curl_version=$($PKG query %v curl 2>/dev/null || true)
if [ -z "$curl_origin" ]; then
    echo "freebsd: curl is not installed here; recording the dependency at its floor"
    curl_origin=ftp/curl
    curl_version=8.0.0
fi

pkg_version "$describe"

# The layout as it lands on the host, under /usr/local. The module goes to
# ${LOCALBASE}/lib because that is the second entry in OpenPAM's own module
# path (/usr/lib, then ${LOCALBASE}/lib, then ${LOCALBASE}/lib/security),
# and the first belongs to base -- so a pam.d line naming pam_ssoossh.so
# finds it there without an absolute path, and nothing of ours is written
# into a base directory. Man pages are left uncompressed: FreeBSD stopped
# compressing them in ports, and man(1) reads either.
root=$stage/root
prefix=/usr/local
install -d "$root$prefix/lib" \
    "$root$prefix/share/man/man5" "$root$prefix/share/man/man8" \
    "$root$prefix/share/doc/pam_ssoossh/examples/pam.d"
install -m 0444 "$stage/src/pam_ssoossh.so" "$root$prefix/lib/pam_ssoossh.so"
install -m 0444 "$stage/src"/man/*.5 "$root$prefix/share/man/man5/"
install -m 0444 "$stage/src"/man/*.8 "$root$prefix/share/man/man8/"
install -m 0444 "$stage/src/BUILDINFO" "$stage/src/LICENSE" \
    "$root$prefix/share/doc/pam_ssoossh/"
install -m 0444 "$stage/src"/examples/pam.d/* \
    "$root$prefix/share/doc/pam_ssoossh/examples/pam.d/"
install -m 0444 "$stage/src"/examples/README "$stage/src"/examples/*.yaml \
    "$root$prefix/share/doc/pam_ssoossh/examples/"

# The plist is every file, relative to the prefix. Generated rather than
# written out, so a man page or an example added to `make dist` reaches the
# package without a second list to remember.
(cd "$root$prefix" && find . -type f | sed 's|^\./||' | sort) > "$stage/plist"

cat > "$stage/+MANIFEST" <<MANIFEST
name: pam_ssoossh
version: "$PKG_FREEBSD_VERSION"
origin: security/pam_ssoossh
comment: "PAM module authenticating against ssoosshd"
maintainer: "$PKG_MAINTAINER"
www: "$PKG_HOMEPAGE"
prefix: "$prefix"
categories [ "security" ]
licenselogic: "single"
licenses [ "MIT" ]
deps {
  curl { origin: "$curl_origin", version: "$curl_version" }
}
desc <<EOD
PAM module authenticating against ssoosshd.

Loads into sudo, sshd and login; links the operating system's own
libcrypto, libcurl and libpam and ships no crypto of its own. Built for
$target and qualified against ssoosshd ${compat:-unknown}: see
$prefix/share/doc/pam_ssoossh/BUILDINFO.

Nothing is written to /etc/pam.d -- wiring the module into a service is
an operator's decision. See pam_ssoossh(8) and the stanzas under
$prefix/share/doc/pam_ssoossh/examples/pam.d.
EOD
MANIFEST

mkdir -p "$stage/out" "$outdir"
outdir=$(cd "$outdir" && pwd)
"$PKG" create -M "$stage/+MANIFEST" -p "$stage/plist" -r "$root" -o "$stage/out"

# pkg names what it wrote <name>-<version> plus the extension of whatever
# format this pkg defaults to, so the file is found rather than assumed,
# and renamed to the project's own spelling on the way out.
produced=$(find "$stage/out" -type f | head -1)
if [ -z "$produced" ]; then
    echo "freebsd: pkg create wrote no package" >&2
    exit 1
fi
out="$outdir/pam-ssoossh_${filever}_${target_os}_${target_arch}.${produced##*.}"
mv "$produced" "$out"
echo "freebsd: $out"
"$PKG" info -F "$out" | sed 's/^/  /'
