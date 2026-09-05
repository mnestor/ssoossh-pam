# shellcheck shell=sh
# Sourced by package.sh and macos.sh: `git describe` into what package
# formats accept. A tag is the version; what follows it becomes the
# pre-release, which each packager spells its own way (1.2.0~rc1 for deb
# and rpm, 1.2.0_rc1 for apk, 1.2.0-rc1 in a pkg receipt) and which sorts
# before the release proper. A build with no tag at all is 0.0.0 plus the
# commit, so it can never outrank a real release on a host.
#
#   pkg_version v1.2.0-3-gabc1234     -> PKG_VERSION=1.2.0 PKG_PRERELEASE=3.gabc1234
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
}
