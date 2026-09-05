#!/bin/sh
# Wraps one macOS release tarball from `make dist` as an installer package,
# signed and notarized when the material is in the environment:
#
#   packaging/macos.sh dist/pam_ssoossh-v1.2.0-macos15-aarch64.tar.gz [outdir]
#
# The package installs what `make install` would, in the same places, all
# of them outside System Integrity Protection:
#
#   /usr/local/lib/pam/pam_ssoossh.so
#   /usr/local/share/man/man8/pam_ssoossh.8, man5/pam_ssoossh-*.5
#   /usr/local/share/doc/pam_ssoossh/BUILDINFO, LICENSE, examples/
#
# Nothing under /etc/pam.d, as with every other package: the operator adds
# the line, by absolute path, and docs/examples/pam.d/sudo_local shows it.
# macos/Distribution.xml and the two html files beside it are the installer's
# panes and its refusals (Intel, or a macOS older than the deployment
# target). The module inside the package is the one from the tarball,
# re-signed; nothing is built here.
#
# Signing and notarization are by environment, and off when the variables
# are empty -- a local `make packages` gets an unsigned package and the log
# says so. The names are the ones the ssoossh server's quill setup uses, so
# the same 1Password item and the same .env.local serve both projects:
#
#   QUILL_SIGN_P12          PKCS#12 with the Developer ID identities and
#                           their private keys, base64. Needs a "Developer
#                           ID Application" identity for the module and a
#                           "Developer ID Installer" one for the package;
#                           the second may instead come from
#   QUILL_INSTALLER_P12     a PKCS#12 holding the Installer identity, base64.
#                           The identity, not the certificate on its own:
#                           an export without the private key imports
#                           cleanly and then signs nothing
#   QUILL_SIGN_PASSWORD     the password of both files
#   QUILL_NOTARY_ISSUER     App Store Connect API issuer id
#   QUILL_NOTARY_KEY_ID     App Store Connect API key id
#   QUILL_NOTARY_KEY        that key, PEM or the PEM's base64
#
# Gatekeeper refuses a downloaded package whose signature is not a Developer
# ID Installer one, so the Installer identity is not optional once signing
# is on: a P12 without it fails here, loudly, rather than producing a
# package every Mac would reject.
set -eu

tarball=${1:?usage: $0 <dist tarball> [outdir]}
outdir=${2:-$(dirname "$tarball")}
PKG_IDENTIFIER=${PKG_IDENTIFIER:-org.mikenestor.pam_ssoossh}
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source-path=SCRIPTDIR
. "$here/version.sh"

[ "$(uname -s)" = Darwin ] || {
    echo "macos: pkgbuild, productbuild and codesign exist only on macOS" >&2
    exit 1
}

work=$(mktemp -d "${TMPDIR:-/tmp}/pam_ssoossh-macos.XXXXXX")
keychain=
cleanup() {
    [ -z "$keychain" ] || security delete-keychain "$keychain" 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT

stage=$work/stage
mkdir -p "$stage"
tar -C "$stage" --strip-components=1 -xzf "$tarball"

field() {
    sed -n "s/^$1:[[:space:]]*//p" "$stage/BUILDINFO" | head -1
}
describe=$(field version)
target=$(field target)
# Optional, like it is in package.sh: a tarball built before the field
# existed still packages, it just cannot name a server release.
compat=$(field ssoosshd)
if [ -z "$describe" ] || [ -z "$target" ]; then
    echo "macos: $tarball has no usable BUILDINFO" >&2
    exit 1
fi
case $target in
macos[0-9]*-aarch64) ;;
*)
    echo "macos: $target is not an arm64 macOS target" >&2
    exit 1
    ;;
esac

# The receipt's version: 1.2.0, 1.2.0-rc1, 0.0.0-dev.abc1234. The file
# name carries `git describe` as it is, like every other artifact.
pkg_version "$describe"
pkgver=$PKG_VERSION${PKG_PRERELEASE:+-$PKG_PRERELEASE}
# The OS floor is in the target name, and is the -mmacosx-version-min the
# module was built with.
minver=${target#macos}
minver=${minver%%-*}.0
name=$(basename "$tarball" .tar.gz)
mkdir -p "$outdir"
outdir=$(cd "$outdir" && pwd)
out=$outdir/$name.pkg

# The payload, laid out as it will land on the host.
root=$work/root
doc=$root/usr/local/share/doc/pam_ssoossh
install -d "$root/usr/local/lib/pam" \
    "$root/usr/local/share/man/man8" "$root/usr/local/share/man/man5" \
    "$doc/examples/pam.d"
install -m 0644 "$stage/pam_ssoossh.so" "$root/usr/local/lib/pam/"
install -m 0644 "$stage"/man/*.8 "$root/usr/local/share/man/man8/"
install -m 0644 "$stage"/man/*.5 "$root/usr/local/share/man/man5/"
install -m 0644 "$stage"/examples/pam.d/* "$doc/examples/pam.d/"
install -m 0644 "$stage"/examples/*.yaml "$stage/examples/README" "$doc/examples/"
install -m 0644 "$stage/BUILDINFO" "$stage/LICENSE" "$doc/"
# Extended attributes would otherwise ride along as AppleDouble entries in
# the payload. Quarantine goes; com.apple.provenance, which a tagged
# process's files get at creation, cannot be removed by anyone and shows
# up as `._` entries in the listing below. Harmless, and absent on a
# runner, which tags nothing.
xattr -rc "$root"
module=$root/usr/local/lib/pam/pam_ssoossh.so

# A secret arrives as the file's base64, which is the one form an
# environment variable and a secrets store can both hold; a PEM key may
# also arrive as itself. Written to a file either way, mode 0600.
materialise() {
    umask 077
    case $1 in
    *-----BEGIN*) printf '%s\n' "$1" > "$2" ;;
    *) printf '%s' "$1" | tr -d '[:space:]' | base64 -d > "$2" ;;
    esac
}

# The identities, into a keychain of their own that the trap removes. The
# partition list is what lets codesign and productsign use the keys
# without a dialog nobody is there to click.
sign_app=
sign_inst=
if [ -n "${QUILL_SIGN_P12:-}" ]; then
    keychain=$work/sign.keychain-db
    kcpass=$(head -c 24 /dev/urandom | base64)
    security create-keychain -p "$kcpass" "$keychain"
    security set-keychain-settings "$keychain"
    security unlock-keychain -p "$kcpass" "$keychain"
    # `security import` says "1 identity imported." for a certificate with
    # its private key and "1 certificate imported." for one without, and a
    # certificate on its own is no use here: it imports without complaint
    # and then signs nothing. That line is the whole diagnosis when the
    # check below fails, so it is not thrown away.
    materialise "$QUILL_SIGN_P12" "$work/sign.p12"
    echo "macos: QUILL_SIGN_P12:"
    security import "$work/sign.p12" -k "$keychain" -f pkcs12 \
        -P "${QUILL_SIGN_PASSWORD:-}" \
        -T /usr/bin/codesign -T /usr/bin/productsign -T /usr/bin/security
    if [ -n "${QUILL_INSTALLER_P12:-}" ]; then
        materialise "$QUILL_INSTALLER_P12" "$work/installer.p12"
        echo "macos: QUILL_INSTALLER_P12:"
        security import "$work/installer.p12" -k "$keychain" -f pkcs12 \
            -P "${QUILL_SIGN_PASSWORD:-}" \
            -T /usr/bin/codesign -T /usr/bin/productsign -T /usr/bin/security
    fi
    security set-key-partition-list -S apple-tool:,apple: -s \
        -k "$kcpass" "$keychain" >/dev/null
    sign_app=$(security find-identity -v -p codesigning "$keychain" |
        sed -n 's/.*"\(Developer ID Application: [^"]*\)".*/\1/p' | head -1)
    sign_inst=$(security find-identity -v "$keychain" |
        sed -n 's/.*"\(Developer ID Installer: [^"]*\)".*/\1/p' | head -1)
    if [ -z "$sign_app" ]; then
        echo "macos: QUILL_SIGN_P12 holds no valid Developer ID Application identity" >&2
        security find-identity "$keychain" >&2
        exit 1
    fi
    if [ -z "$sign_inst" ]; then
        echo "macos: no valid Developer ID Installer identity in QUILL_SIGN_P12 or QUILL_INSTALLER_P12;" \
            "Gatekeeper would refuse the package, so it is not built" >&2
        security find-identity "$keychain" >&2
        # An identity is a certificate *and* its private key. The
        # certificates are listed as well because the Installer one
        # appearing here and not above says which half is missing: the
        # export left the key behind.
        echo "  certificates in the keychain:" >&2
        security find-certificate -a "$keychain" |
            sed -n 's/^ *"labl"<blob>=/    /p' >&2
        exit 1
    fi
fi

# The module. `make dist` left it ad-hoc signed, which is what lets an arm64
# Mac load it at all; this replaces that with the Developer ID signature
# and a timestamp, which is what notarization wants to see inside.
if [ -n "$sign_app" ]; then
    codesign --force --timestamp --options runtime \
        --identifier "$PKG_IDENTIFIER" --keychain "$keychain" \
        --sign "$sign_app" "$module"
    codesign --verify --strict --verbose=2 "$module"
    echo "macos: module signed by $sign_app"
else
    echo "macos: QUILL_SIGN_P12 is not set; the module keeps its ad-hoc signature and the package will be unsigned"
fi

# The component package, then the product around it with the panes and
# the refusals from Distribution.xml.
pkgbuild --quiet --root "$root" --identifier "$PKG_IDENTIFIER" \
    --version "$pkgver" --install-location / --ownership recommended \
    "$work/component.pkg"

res=$work/resources
mkdir -p "$res"
cp "$stage/LICENSE" "$res/LICENSE.txt"
fill() {
    sed -e "s|@VERSION@|$describe|g" -e "s|@PKGVER@|$pkgver|g" \
        -e "s|@TARGET@|$target|g" -e "s|@MINVER@|$minver|g" \
        -e "s|@COMPAT@|${compat:-unknown}|g" \
        -e "s|@IDENTIFIER@|$PKG_IDENTIFIER|g" "$1" > "$2"
}
fill "$here/macos/welcome.html" "$res/welcome.html"
fill "$here/macos/readme.html" "$res/readme.html"
fill "$here/macos/Distribution.xml" "$work/Distribution.xml"
productbuild --quiet --distribution "$work/Distribution.xml" \
    --resources "$res" --package-path "$work" "$work/unsigned.pkg"

if [ -n "$sign_inst" ]; then
    productsign --timestamp --keychain "$keychain" --sign "$sign_inst" \
        "$work/unsigned.pkg" "$out" >/dev/null
    pkgutil --check-signature "$out"
    echo "macos: package signed by $sign_inst"
else
    mv "$work/unsigned.pkg" "$out"
fi

# Notarization, then the ticket stapled on so a Mac with no network can
# still check it. Only for a signed package: the service rejects anything
# else, so with no signature there is nothing to submit.
if [ -n "$sign_inst" ] && [ -n "${QUILL_NOTARY_KEY:-}" ]; then
    materialise "$QUILL_NOTARY_KEY" "$work/notary.p8"
    xcrun notarytool submit "$out" \
        --key "$work/notary.p8" \
        --key-id "${QUILL_NOTARY_KEY_ID:?QUILL_NOTARY_KEY_ID is not set}" \
        --issuer "${QUILL_NOTARY_ISSUER:?QUILL_NOTARY_ISSUER is not set}" \
        --wait --timeout 30m | tee "$work/notary.log"
    if ! grep -q '^ *status: Accepted' "$work/notary.log"; then
        id=$(sed -n 's/^ *id: //p' "$work/notary.log" | head -1)
        echo "macos: notarization did not end in Accepted; the service's log:" >&2
        [ -z "$id" ] || xcrun notarytool log "$id" \
            --key "$work/notary.p8" --key-id "$QUILL_NOTARY_KEY_ID" \
            --issuer "$QUILL_NOTARY_ISSUER" >&2 || true
        exit 1
    fi
    xcrun stapler staple "$out"
    # What Gatekeeper will say when someone double-clicks it.
    spctl --assess --type install --verbose=2 "$out"
    echo "macos: notarized and stapled"
elif [ -n "$sign_inst" ]; then
    echo "macos: QUILL_NOTARY_KEY is not set; the package is signed but not notarized"
fi

echo "macos: $out"
pkgutil --payload-files "$out" | sed 's/^/  /'
