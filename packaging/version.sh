# shellcheck shell=sh
# PKG_VERSION, PKG_PRERELEASE and PKG_FREEBSD_VERSION are what this file is
# for: the caller that sources it reads them, so from inside they look
# written and never read.
# shellcheck disable=SC2034
# Sourced by package.sh, macos.sh and freebsd.sh: `git describe` into what
# package formats accept. A tag is the version; what follows it becomes the
# pre-release, which each packager spells its own way (1.2.0~rc1 for deb
# and rpm, 1.2.0_rc1 for apk, 1.2.0-rc1 in a macOS pkg receipt) and which
# sorts before the release proper. A build with no tag at all is 0.0.0 plus
# the commit, so it can never outrank a real release on a host.
#
#   pkg_version v1.2.0-3-gabc1234     -> PKG_VERSION=1.2.0 PKG_PRERELEASE=3.gabc1234
#                                        PKG_FREEBSD_VERSION=1.2.0.pre.3.gabc1234
pkg_version() {
    case $1 in
    v[0-9]*.[0-9]*.[0-9]*-*)
        PKG_VERSION=${1#v}
        PKG_VERSION=${PKG_VERSION%%-*}
        PKG_PRERELEASE=$(printf '%s' "${1#v*-}" | tr -- '-' '.')
        ;;
    v[0-9]*.[0-9]*.[0-9]*)
        PKG_VERSION=${1#v}
        PKG_PRERELEASE=
        ;;
    *)
        PKG_VERSION=0.0.0
        PKG_PRERELEASE=$(printf 'dev.%s' "$1" | tr -- '-' '.')
        ;;
    esac

    # FreeBSD pkg has no separate pre-release field: it compares one version
    # string against another by pkg-version(8)'s rules, and the only way to
    # sort *before* a release there is a component with no version number of
    # its own. A component beginning with "pl", "alpha", "beta", "pre", "rc"
    # or "snap" is exactly that -- its number is taken as -1, so it loses to
    # the implicit 0 of a version that simply ends. Hence 1.2.0.pre.rc1 <
    # 1.2.0 < 1.2.0.1, which is the same promise the ~ makes in a deb
    # version. Spelling it "pre" rather than letting the pre-release lead
    # keeps that true for `3.gabc1234` too, which begins with a digit and
    # would otherwise sort above the tag it follows.
    if [ -n "$PKG_PRERELEASE" ]; then
        PKG_FREEBSD_VERSION="$PKG_VERSION.pre.$PKG_PRERELEASE"
    else
        PKG_FREEBSD_VERSION=$PKG_VERSION
    fi
}
