#!/bin/sh
# Names the platform a release artifact was built for, from the machine
# building it:
#
#   linux-x86_64-glibc-openssl3     linux-aarch64-musl
#   linux-x86_64-glibc-openssl1.1   freebsd14-x86_64
#   macos15-aarch64
#
# The name carries what decides whether the module will *load* on a host,
# because it links the host's libraries rather than shipping them: the C
# library ABI, and on glibc which libcrypto soname it was linked against
# (musl distributions all carry OpenSSL 3 by now, so the name stays short).
# FreeBSD carries its major release, since base OpenSSL changes with it.
# macOS carries the deployment target rather than the building Mac's
# release: the bundle links only what ships with the OS and is built with
# -mmacosx-version-min, so it loads on that release and every later one.
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
    # The floor is the Makefile's MINVER, read from the file rather than
    # asked of make: the Makefile runs this script to name `make dist`, so
    # running make from here would recurse without end. The running
    # release only if the Makefile is somehow not beside this script.
    floor=$(sed -n 's/^ *MINVER *?= *//p' "$(dirname "$0")/../Makefile" 2>/dev/null | head -1)
    [ -n "$floor" ] || floor=$(sw_vers -productVersion 2>/dev/null)
    echo "macos${floor%%.*}-$arch"
    ;;
*)
    echo "$os-$arch"
    ;;
esac
