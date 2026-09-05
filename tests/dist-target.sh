#!/bin/sh
# Names the platform a release artifact was built for, from the machine
# building it, as the <os>_<arch> half of the artifact name:
#
#   linux-glibc-openssl3_x86_64     linux-musl_aarch64
#   linux-glibc-openssl1.1_x86_64   freebsd14_x86_64
#   darwin_aarch64
#
# The os field carries what decides whether the module will *load* on a
# host, because it links the host's libraries rather than shipping them:
# the C library ABI, and on glibc which libcrypto soname it was linked
# against (musl distributions all carry OpenSSL 3 by now, so the name stays
# short). FreeBSD carries its major release, since base OpenSSL changes
# with it. macOS carries neither: the bundle links only what ships with the
# OS, and the deployment floor it was built with is recorded in BUILDINFO
# rather than in the name, so the name does not move when the floor does.
#
# Two artifacts that differ only in this field are different packages --
# the EL 8 and EL 9 rpms are the case that matters -- so it is what keeps
# them from overwriting each other on the way into a release.
#
# The release workflow compares this against the matrix entry it expected,
# so a container image that quietly changes what it ships fails the build
# rather than mislabelling an artifact.
set -eu

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case $(uname -m) in
x86_64 | amd64) arch=x86_64 ;;
aarch64 | arm64) arch=aarch64 ;;
*) arch=$(uname -m) ;;
esac

case $os in
linux)
    if [ -n "$(ls /lib/ld-musl-* 2>/dev/null)" ] ||
        ldd --version 2>&1 | grep -qi musl; then
        echo "linux-musl_$arch"
        exit 0
    fi
    version=$(pkg-config --modversion libcrypto 2>/dev/null || true)
    major=${version%%.*}
    if [ -z "$major" ]; then
        crypto="openssl-unknown"
    elif [ "$major" = 1 ]; then
        # 1.1.1 is the floor and its soname is libcrypto.so.1.1, so the
        # minor matters here and nowhere else.
        minor=${version#*.}
        crypto="openssl$major.${minor%%.*}"
    else
        crypto="openssl$major"
    fi
    echo "linux-glibc-${crypto}_$arch"
    ;;
freebsd)
    echo "freebsd$(uname -r | cut -d. -f1)_$arch"
    ;;
darwin)
    echo "darwin_$arch"
    ;;
*)
    echo "${os}_$arch"
    ;;
esac
