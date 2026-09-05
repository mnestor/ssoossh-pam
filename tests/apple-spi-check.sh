#!/bin/sh
# Watches the Ed25519 SPI this module's macOS backend depends on.
#
# Security.framework exports kSecAttrKeyTypeEd25519 and the EdDSA
# SecKeyAlgorithm without declaring them in any public header. The backend
# resolves them with dlsym and self-tests them before use, so a host where
# they vanish degrades to "ssh-ed25519 unsupported" rather than breaking --
# but degrading silently across a fleet is still the thing to find out
# first. This script is the finding-out, in two views that drift
# separately:
#
#   the SDK      what the *next* macOS will export, readable from any
#                Xcode's Security.tbd, betas included, on any Mac
#   the runtime  what *this* macOS does, by running the module's own
#                Ed25519 suite through the real framework
#
#   tests/apple-spi-check.sh              the default SDK, then the runtime
#   tests/apple-spi-check.sh --sdk PATH   one SDK only (no build needed)
#   tests/apple-spi-check.sh --runtime    the runtime only
#
# Exit status: 0 when everything is as the backend expects; 1 when a symbol
# is missing from the SDK or the runtime suite fails; 2 when the SPI has
# turned up in a *public* header, which is good news that still needs a
# human -- the dlsym should become a plain reference and this check should
# change shape.
set -eu

SYMS='_kSecAttrKeyTypeEd25519 _kSecKeyAlgorithmEdDSASignatureMessageCurve25519SHA512'

mode=both
sdk=

while [ $# -gt 0 ]; do
    case $1 in
    --sdk)
        mode=sdk
        sdk=$2
        shift 2
        ;;
    --runtime)
        mode=runtime
        shift
        ;;
    *)
        echo "usage: $0 [--sdk PATH | --runtime]" >&2
        exit 64
        ;;
    esac
done

if [ "$(uname -s)" != Darwin ]; then
    echo "apple-spi-check: not macOS; nothing to check here"
    exit 0
fi

rc=0

check_sdk() {
    fw="$1/System/Library/Frameworks/Security.framework"
    tbd="$fw/Versions/A/Security.tbd"
    [ -f "$tbd" ] || tbd="$fw/Security.tbd"
    version=$(sed -n 's/.*"Version":"\([^"]*\)".*/\1/p' "$1/SDKSettings.json" 2>/dev/null | head -1)
    echo "apple-spi-check: SDK ${version:-?} at $1"

    if [ ! -f "$tbd" ]; then
        echo "  Security.tbd not found under $fw -- the layout changed"
        rc=1
        return
    fi
    for sym in $SYMS; do
        if grep -qw -- "$sym" "$tbd"; then
            echo "  exported: $sym"
        else
            echo "  MISSING:  $sym"
            rc=1
        fi
    done

    # The other direction: Apple making it public. Every kSecAttrKeyType*
    # the public headers know is listed so a rename shows up too.
    echo "  public SecKey key types:" \
        "$(grep -rho 'kSecAttrKeyType[A-Za-z0-9]*' "$fw/Headers/" 2>/dev/null | sort -u | tr '\n' ' ')"
    if grep -rq 'kSecAttrKeyTypeEd25519\|kSecKeyAlgorithmEdDSA' "$fw/Headers/" 2>/dev/null; then
        echo "  PUBLIC: the Ed25519 SPI is now declared in a public header." \
            "Replace the dlsym in src/crypto_darwin.c with the declaration and" \
            "update this check."
        [ $rc -eq 0 ] && rc=2
    fi
}

check_runtime() {
    echo "apple-spi-check: runtime macOS $(sw_vers -productVersion) ($(uname -m))"
    if [ ! -x tests/unit_tests ]; then
        echo "  tests/unit_tests is not built; run make tests/unit_tests first"
        rc=1
        return
    fi
    # The crypto suite asserts the capability matrix, which now includes
    # ssh-ed25519 on this platform; the ed25519 suite is the pinned
    # acceptance profile through the real framework.
    for suite in crypto ed25519; do
        if ./tests/unit_tests "$suite"; then
            :
        else
            echo "  FAILED: unit suite $suite"
            rc=1
        fi
    done
}

case $mode in
sdk)
    check_sdk "$sdk"
    ;;
runtime)
    check_runtime
    ;;
both)
    check_sdk "$(xcrun --show-sdk-path)"
    check_runtime
    ;;
esac

case $rc in
0) echo "apple-spi-check: ok" ;;
2) echo "apple-spi-check: SPI became public API -- act on it" ;;
*) echo "apple-spi-check: FAILED" ;;
esac
exit $rc
