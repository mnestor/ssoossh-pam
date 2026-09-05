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
#
# Both must be legacy-shape PKCS#12, which is what `openssl pkcs12 -export
# -legacy` writes. `security import` cannot read the shape a newer macOS
# produces (PBES2, AES-256-CBC, SHA-256 MAC): it fails the MAC check and
# reports it as a wrong password, whatever the password is. Keychain Access
# on macOS 26 exports that newer shape, so a P12 exported there does not
# import on the macOS 15 runner this job uses, and has to be converted once
# on the way into the secret store.
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
searchlist=
defaultkc=
cleanup() {
    # The runner's own keychain configuration goes back before the keychain
    # that displaced it is deleted, in the order it was changed.
    # shellcheck disable=SC2086 # one keychain path per line, none with spaces
    [ -z "$defaultkc" ] || security default-keychain -d user -s "$defaultkc" 2>/dev/null || true
    # shellcheck disable=SC2086 # as above
    [ -z "$searchlist" ] || security list-keychains -d user -s $searchlist >/dev/null 2>&1 || true
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
# The package this script writes, read again by every signing, notarization
# and listing step at the end. A shell has no scoping to protect it, so
# nothing below may reuse the name -- the functions above capture what a
# command said in `said` for that reason.
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

# The identities, into a keychain of their own that the trap removes.
sign_app=
sign_inst=

# What the keychain ended up holding, for a failure that has to be read out
# of a log afterwards. An identity is a certificate *and* its private key,
# so a certificate in the second listing that is not in the first says which
# half is missing: the export left the key behind.
dump_keychain() {
    echo "  identities:" >&2
    security find-identity "$keychain" >&2 || true
    echo "  certificates:" >&2
    security find-certificate -a "$keychain" 2>/dev/null |
        sed -n 's/^ *"labl"<blob>=/    /p' >&2
}

# `security import` says "1 identity imported." for a certificate with its
# private key and "1 certificate imported." for one without, and a
# certificate on its own is no use here: it imports without complaint and
# then signs nothing. That line is the whole diagnosis when the checks below
# fail, so it is kept, labelled with the variable it came from and with the
# size of what that variable decoded to -- an empty, truncated or
# wrong-field secret shows itself there first.
#
# No -f pkcs12, deliberately. The flag suppresses that line -- and worse, it
# swallowed the failure underneath it: the import that fails below with "MAC
# verification failed" exited 0 with the flag on, printing nothing, so an
# empty keychain looked like a successful import and the run died three
# commands later on a message about an item that could not be found. Without
# the flag the format is read from the file, which is where it was written
# anyway, and both the summary and the failure come back.
import_p12() {
    # What the variable decoded to, named before the keychain is involved
    # at all. A PKCS#12 is DER, so it opens with a SEQUENCE -- 0x30 0x82 --
    # and a field holding a PEM, a .cer, an already-decoded blob or nothing
    # much fails that here, where the message can say so, rather than three
    # lines down as a MAC failure that reads like a wrong password. The
    # digest is the file's, not a secret: it is the one way to tell from a
    # log whether the field holds the P12 you think it does, since the same
    # command over the same file on your Mac prints the same 16 characters.
    size=$(wc -c < "$2" | tr -d ' ')
    digest=$(shasum -a 256 "$2" | cut -c1-16)
    if [ "$(head -c 2 "$2" | od -An -tx1 | tr -d ' \n')" != 3082 ]; then
        echo "macos: $1: $size bytes, sha256 $digest, first bytes" \
            "$(head -c 8 "$2" | od -An -tx1)" >&2
        echo "macos: $1 did not decode to a PKCS#12, which is DER and opens 30 82;" \
            "the field holds something that is not the base64 of a .p12" >&2
        exit 1
    fi
    if said=$(security import "$2" -k "$keychain" \
        -P "${QUILL_SIGN_PASSWORD:-}" \
        -T /usr/bin/codesign -T /usr/bin/productsign \
        -T /usr/bin/security 2>&1); then
        echo "macos: $1: $size bytes, sha256 $digest;" \
            "${said:-security import printed nothing}"
    else
        echo "macos: $1: $size bytes, sha256 $digest;" \
            "security import failed: ${said:-no output}" >&2
        case ${said:-} in
        *"MAC verification failed"*)
            # Two very different faults share this one message, and the
            # second is the one nobody guesses: this importer reads only the
            # legacy PKCS#12 shape, and a P12 written with PBES2,
            # AES-256-CBC and a SHA-256 MAC fails the MAC check here
            # whatever the password is. That shape is not exotic -- it is
            # what Keychain Access on macOS 26 writes, and what OpenSSL 3
            # writes by default -- so a P12 exported on a Mac newer than the
            # one this runs on lands here with a correct password and a
            # message that blames it. `openssl pkcs12 -info -noout` over the
            # same file names the algorithms and, by not complaining, clears
            # the password.
            echo "macos: either QUILL_SIGN_PASSWORD is not the password $1 was" \
                "exported with -- one password opens both P12s -- or $1 is in the" \
                "PKCS#12 shape a newer macOS writes and this one cannot read," \
                "whatever the password. Check with:" >&2
            echo "    openssl pkcs12 -info -noout -in <the p12> -passin pass:<password>" >&2
            echo "  \"MAC: sha256\" or \"AES-256-CBC\" there is the second fault. Convert it:" >&2
            echo "    openssl pkcs12 -in <the p12> -nodes -passin env:PW |" >&2
            echo "        openssl pkcs12 -export -legacy -passout env:PW -out <new p12>" >&2
            ;;
        esac
        exit 1
    fi
}

if [ -n "${QUILL_SIGN_P12:-}" ]; then
    keychain=$work/sign.keychain-db
    kcpass=$(head -c 24 /dev/urandom | base64)
    security create-keychain -p "$kcpass" "$keychain"
    security set-keychain-settings "$keychain"
    security unlock-keychain -p "$kcpass" "$keychain"
    # codesign resolves an identity by name through the search list and the
    # default keychain, not through the --keychain it is handed, so a
    # keychain that exists only as a path signs nothing: it fails with "The
    # specified item could not be found in the keychain" over an identity
    # that find-identity, pointed straight at that keychain, has just
    # listed. Put it in front of both. The trap puts them back.
    searchlist=$(security list-keychains -d user | sed 's/^[[:space:]]*"//;s/"$//')
    defaultkc=$(security default-keychain -d user 2>/dev/null |
        sed 's/^[[:space:]]*"//;s/"$//') || defaultkc=
    # shellcheck disable=SC2086 # one keychain path per line, none with spaces
    security list-keychains -d user -s "$keychain" $searchlist >/dev/null
    security default-keychain -d user -s "$keychain" >/dev/null

    materialise "$QUILL_SIGN_P12" "$work/sign.p12"
    import_p12 QUILL_SIGN_P12 "$work/sign.p12"
    if [ -n "${QUILL_INSTALLER_P12:-}" ]; then
        materialise "$QUILL_INSTALLER_P12" "$work/installer.p12"
        import_p12 QUILL_INSTALLER_P12 "$work/installer.p12"
    fi

    # What lets codesign and productsign use the keys without a dialog
    # nobody is there to click. Not fatal on its own, because the way it
    # fails is a symptom and not the disease: a keychain with no private key
    # in it -- every P12 here holding a bare certificate -- fails this with
    # "The specified item could not be found in the keychain", which says
    # far less than the identity checks just below it do. Let those speak.
    # If the keys are there and this still failed, codesign says so itself a
    # few lines further on, and just as loudly.
    if ! said=$(security set-key-partition-list -S apple-tool:,apple: -s \
        -k "$kcpass" "$keychain" 2>&1); then
        echo "macos: set-key-partition-list: ${said:-no output}" >&2
    fi

    sign_app=$(security find-identity -v -p codesigning "$keychain" |
        sed -n 's/.*"\(Developer ID Application: [^"]*\)".*/\1/p' | head -1)
    sign_inst=$(security find-identity -v "$keychain" |
        sed -n 's/.*"\(Developer ID Installer: [^"]*\)".*/\1/p' | head -1)
    if [ -z "$sign_app" ]; then
        echo "macos: QUILL_SIGN_P12 holds no valid Developer ID Application identity" >&2
        dump_keychain
        exit 1
    fi
    if [ -z "$sign_inst" ]; then
        echo "macos: no valid Developer ID Installer identity in QUILL_SIGN_P12 or QUILL_INSTALLER_P12;" \
            "Gatekeeper would refuse the package, so it is not built" >&2
        dump_keychain
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
