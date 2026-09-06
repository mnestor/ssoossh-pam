#!/bin/sh
# Will this module load on this host?
#
#   ./preflight.sh                          in an unpacked release tarball
#   packaging/preflight.sh pam_ssoossh.so   from a source tree
#
# The module links the host's libraries rather than shipping them, so
# whether it loads is a property of the pair, not of the download. Both
# halves of the answer are already written down and nothing was comparing
# them:
#
#   1. What the module was built for. BUILDINFO says `target:`, and
#      dist-target.sh prints what this host wants. They must agree --
#      freebsd14 and freebsd15 are different packages because base OpenSSL
#      changes with the major release, as are the two glibc/OpenSSL rows
#      and musl.
#   2. Whether every soname it links resolves here. That is the failure
#      itself rather than a proxy for it, and it catches a host that is the
#      right target but is missing a package -- libcurl, on a FreeBSD that
#      has only base.
#
# A module that fails either of these does not fail at install time. It
# fails inside sudo, at authentication, which is why this exists.
#
# `make install` runs it on the module it is about to install;
# PREFLIGHT=0 skips it, for a deliberate cross-install into a DESTDIR that
# is not this host.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
module=${1:-$here/pam_ssoossh.so}
info=${2:-$here/BUILDINFO}

# FreeBSD's ldd takes a bare name as a soname to look up on the library
# path rather than as a file in the current directory, and answers with its
# own "not found" -- so `make install` in a source tree, which passes
# pam_ssoossh.so, asked it the wrong question and got an alarming answer to
# it. Give it a path.
case $module in
*/*) ;;
*) module=./$module ;;
esac

# In a release tarball both of these sit beside this script; in a source
# tree only dist-target.sh exists, one directory over, and there is no
# BUILDINFO until `make dist` writes one.
if [ -x "$here/dist-target.sh" ]; then
    dist_target=$here/dist-target.sh
elif [ -x "$here/../tests/dist-target.sh" ]; then
    dist_target=$here/../tests/dist-target.sh
else
    dist_target=
fi

status=0

if [ ! -f "$module" ]; then
    echo "preflight: no module at $module" >&2
    exit 1
fi

if [ -n "$dist_target" ] && [ -f "$info" ]; then
    built=$(sed -n 's/^target:[[:space:]]*//p' "$info" | head -1)
    host=$("$dist_target")
    if [ -z "$built" ]; then
        echo "preflight: $info names no target; cannot check this host against it" >&2
        status=1
    elif [ "$built" != "$host" ]; then
        echo "preflight: this module was built for $built and this host wants $host." >&2
        echo "           Install the $host artifact instead, or build from source here." >&2
        status=1
    else
        echo "preflight: built for $built, which is what this host wants"
    fi
fi

# ldd on the module itself, which is the question asked in the form the
# loader will ask it. Every platform spells an unresolved dependency its
# own way -- "=> not found" on glibc and FreeBSD, "Error loading shared
# library" on musl -- and none of them reliably exit non-zero over one, so
# the output is what is read; the exit status only tells us whether ldd
# managed to look at all, which is a different report to make. macOS has no
# ldd, and the bundle links only frameworks that ship with the OS, so there
# is nothing to ask there.
case $(uname -s) in
Darwin)
    echo "preflight: macOS links only system frameworks; no sonames to resolve"
    ;;
*)
    if out=$(ldd "$module" 2>&1); then rc=0; else rc=$?; fi
    unresolved=$(printf '%s\n' "$out" |
        grep -E '=>[[:space:]]*not found|Error loading shared library' || true)
    if [ -n "$unresolved" ]; then
        echo "preflight: this host is missing libraries the module links:" >&2
        printf '%s\n' "$unresolved" | sed 's/^/  /' >&2
        echo "           A soname in that list that no package on this host provides" >&2
        echo "           means the wrong artifact -- see the \`needs:\` list in BUILDINFO." >&2
        status=1
    elif [ "$rc" != 0 ]; then
        echo "preflight: ldd could not read $module, so nothing here was checked:" >&2
        printf '%s\n' "$out" | sed 's/^/  /' >&2
        status=1
    else
        echo "preflight: every soname the module links resolves on this host"
    fi
    ;;
esac

# One more thing that is not this module's fault and will still break a
# login: /usr/lib comes before ${LOCALBASE}/lib in OpenPAM's module path,
# so a copy left in /usr/lib shadows the one a package puts under
# /usr/local/lib, and a pam.d line naming the bare module keeps loading the
# old one. Said rather than refused -- it says nothing about whether *this*
# module loads, which is what the exit status means.
if [ "$(uname -s)" = FreeBSD ] && [ -e /usr/lib/pam_ssoossh.so ]; then
    echo "preflight: warning: /usr/lib/pam_ssoossh.so exists. /usr/lib comes before"
    echo "           /usr/local/lib in OpenPAM's module path, so a pam.d line naming"
    echo "           pam_ssoossh.so loads that copy and not the one installed under"
    echo "           /usr/local/lib. Remove it unless it is deliberate."
fi

exit $status
