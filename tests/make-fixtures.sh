#!/usr/bin/env bash
#
# Regenerates tests/fixtures/ with ssh-keygen.
#
# The fixtures are checked in rather than generated at test time: the CI
# images are minimal and a test that quietly skips because openssh-client is
# absent is worse than no test. Run this when a new key type or certificate
# shape needs covering, and commit what it writes.
#
# Everything here is a throwaway key generated on the spot. None of it is
# secret, and none of it is valid for anything: the CAs exist only to sign
# the fixtures beside them.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$here/fixtures"

rm -rf "$out"
mkdir -p "$out"
cd "$out"

keygen() {
    ssh-keygen -q -N '' -C "$1" -f "$1" "${@:2}"
}

# One CA per key type the capability matrix names, so the matrix can be a
# test rather than a table in a document.
keygen ca_ecdsa256 -t ecdsa -b 256
keygen ca_ecdsa384 -t ecdsa -b 384
keygen ca_ecdsa521 -t ecdsa -b 521
keygen ca_ed25519  -t ed25519
keygen ca_rsa      -t rsa -b 3072

# The subject key is P-384 because that is what the module generates.
keygen user -t ecdsa -b 384

# An untrusted CA: same shape as ca_ecdsa384, never listed in a CA file.
keygen ca_untrusted -t ecdsa -b 384

# A certificate per CA. -V bounds the validity window; the far-future one
# is so the fixtures do not expire and start failing check 4 in a year.
#
# rsa CAs sign with rsa-sha2-512 unless told otherwise; the SHA-1 variant is
# minted deliberately below because refusing it is a policy this module has
# to prove it holds.
for ca in ca_ecdsa256 ca_ecdsa384 ca_ecdsa521 ca_ed25519 ca_rsa; do
    cp user.pub "cert_$ca.pub"
    ssh-keygen -q -s "$ca" -I "test-key-id" -n "alice,ops" \
        -V "19700101:20991231" -z 12345 "cert_$ca.pub"
    mv "cert_$ca-cert.pub" "cert_$ca.cert"
    rm -f "cert_$ca.pub"
done

# rsa-sha2-256, so both RSA signature algorithms are covered.
cp user.pub cert_ca_rsa_sha256.pub
ssh-keygen -q -s ca_rsa -t rsa-sha2-256 -I "test-key-id" -n "alice,ops" \
    -V "19700101:20991231" -z 12345 cert_ca_rsa_sha256.pub
mv cert_ca_rsa_sha256-cert.pub cert_ca_rsa_sha256.cert
rm -f cert_ca_rsa_sha256.pub

# ssh-rsa: RSA with SHA-1, which this module refuses by policy. OpenSSH
# still mints one when asked, which is the only reason this fixture can
# exist at all.
cp user.pub cert_ca_rsa_sha1.pub
ssh-keygen -q -s ca_rsa -t ssh-rsa -I "test-key-id" -n "alice,ops" \
    -V "19700101:20991231" -z 12345 cert_ca_rsa_sha1.pub
mv cert_ca_rsa_sha1-cert.pub cert_ca_rsa_sha1.cert
rm -f cert_ca_rsa_sha1.pub

# Signed by a CA no test file lists.
cp user.pub cert_untrusted.pub
ssh-keygen -q -s ca_untrusted -I "test-key-id" -n "alice,ops" \
    -V "19700101:20991231" -z 12345 cert_untrusted.pub
mv cert_untrusted-cert.pub cert_untrusted.cert
rm -f cert_untrusted.pub

# An expired one and a not-yet-valid one, for check 4.
cp user.pub cert_expired.pub
ssh-keygen -q -s ca_ecdsa384 -I "test-key-id" -n "alice,ops" \
    -V "19700101:19700102" -z 12346 cert_expired.pub
mv cert_expired-cert.pub cert_expired.cert
rm -f cert_expired.pub

cp user.pub cert_future.pub
ssh-keygen -q -s ca_ecdsa384 -I "test-key-id" -n "alice,ops" \
    -V "20900101:20991231" -z 12347 cert_future.pub
mv cert_future-cert.pub cert_future.cert
rm -f cert_future.pub

# Certificates whose principals differ, for check 3.
cp user.pub cert_bob.pub
ssh-keygen -q -s ca_ecdsa384 -I "test-key-id" -n "bob" \
    -V "19700101:20991231" -z 12348 cert_bob.pub
mv cert_bob-cert.pub cert_bob.cert
rm -f cert_bob.pub

# A certificate over a *different* subject key, which is what check 2
# exists to catch: correctly signed by a trusted CA, right principals,
# inside its validity window, and issued to somebody else's keypair.
keygen other -t ecdsa -b 384
cp other.pub cert_other_key.pub
ssh-keygen -q -s ca_ecdsa384 -I "test-key-id" -n "alice,ops" \
    -V "19700101:20991231" -z 12349 cert_other_key.pub
mv cert_other_key-cert.pub cert_other_key.cert
rm -f cert_other_key.pub

# CA files: one usable key, several, and the mixed case the skip-unsupported
# path exists for.
cat ca_ecdsa384.pub                      > cas_one.pub
cat ca_ecdsa256.pub ca_ecdsa384.pub      > cas_two.pub
cat ca_ed25519.pub ca_ecdsa384.pub       > cas_mixed.pub
# A CA type no backend supports, beside one every backend does, for the
# skip-with-a-warning path. Hand-built: the blob is only the type string,
# which is all the loader reads before asking the backend, and ssh-keygen
# on a current OpenSSH will not mint a DSA key at all.
{
    printf 'ssh-dss %s ca_dss_unusable_everywhere\n' \
        "$(printf '\000\000\000\007ssh-dss' | base64)"
    cat ca_ecdsa384.pub
} > cas_unusable.pub
{
    echo "# a comment line"
    echo
    cat ca_ecdsa384.pub
} > cas_comments.pub
echo "ecdsa-sha2-nistp384 not-base64!!" > cas_malformed.pub
: > cas_empty.pub

# Private keys are not needed by any test and are not committed.
rm -f ca_ecdsa256 ca_ecdsa384 ca_ecdsa521 ca_ed25519 ca_rsa ca_untrusted \
      user other

echo "wrote $(find "$out" -type f | wc -l) fixtures to $out"
