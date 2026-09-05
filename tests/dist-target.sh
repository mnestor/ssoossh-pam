#!/bin/sh
# Names the platform a release artifact was built for, from the machine
# building it:
#
#   linux-x86_64-glibc-openssl3     linux-aarch64-musl
#   linux-x86_64-glibc-openssl1.1   freebsd14-x86_64
#
# The name carries what decides whether the module will *load* on a host,
# because it links the host's libraries rather than shipping them: the C
# library ABI, and on glibc which libcrypto soname it was linked against
# (musl distributions all carry OpenSSL 3 by now, so the name stays short).
# FreeBSD carries its major release, since base OpenSSL changes with it.
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
        echo "linux-$arch-musl"
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
    echo "linux-$arch-glibc-$crypto"
    ;;
freebsd)
    echo "freebsd$(uname -r | cut -d. -f1)-$arch"
    ;;
darwin)
    # Never shipped; named so `make dist` still works for a local look.
    echo "macos$(sw_vers -productVersion 2>/dev/null | cut -d. -f1)-$arch"
    ;;
*)
    echo "$os-$arch"
    ;;
esac
