/* Certificate parsing and CA signature verification, against certificates
 * ssh-keygen actually minted and CAs it actually generated.
 *
 * Everything here is a real signature over real bytes. A parser that gets
 * the signed extent wrong by one byte passes any test written against its
 * own output and fails every one of these.
 */
#include <string.h>

#include "crypto.h"
#include "fixture.h"
#include "sshcert.h"
#include "sshkey.h"
#include "suites.h"
#include "test.h"

/* Loads a fixture certificate, leaving the decoded blob in scratch, which
 * the returned cert borrows from. */
static bool load_cert(const char *name, uint8_t *scratch, size_t scratch_cap,
                      ssoossh_cert *cert)
{
    char line[SSOOSSH_MAX_CERT_LINE];
    size_t n = fixture_read_line(name, line, sizeof(line));

    if (n == 0) {
        return false;
    }
    if (ssoossh_cert_parse_line(line, n, scratch, scratch_cap, cert) !=
        SSOOSSH_CERT_OK) {
        t_failf(__FILE__, __LINE__, "%s did not parse", name);
        return false;
    }
    return true;
}

static bool load_ca(const char *name, uint8_t *blob, size_t blob_cap,
                    size_t *blob_len)
{
    char line[SSOOSSH_MAX_KEY_LINE];
    char algo[64];
    bool blank = false;
    size_t n = fixture_read_line(name, line, sizeof(line));

    if (n == 0) {
        return false;
    }
    return ssoossh_sshkey_parse_line(line, n, blob, blob_cap, blob_len, algo,
                                     sizeof(algo), &blank);
}

int suite_sshcert(void)
{
    uint8_t scratch[SSOOSSH_MAX_CERT];
    uint8_t ca[SSOOSSH_MAX_KEY_BLOB];
    size_t ca_len = 0;
    ssoossh_cert cert;

    /* The fields, from a certificate whose contents make-fixtures.sh
     * chose: key id "test-key-id", principals alice and ops, serial
     * 12345, a user certificate. */
    if (load_cert("cert_ca_ecdsa384.cert", scratch, sizeof(scratch), &cert)) {
        T_EQ_STR(cert.algo, "ecdsa-sha2-nistp384-cert-v01@openssh.com");
        T_EQ_INT(cert.serial, 12345);
        T_EQ_INT(cert.type, 1); /* SSH2_CERT_TYPE_USER */
        T_EQ_MEM(cert.key_id.p, cert.key_id.len, "test-key-id", 11);
        T_EQ_INT(cert.principal_count, 2);
        T_CHECK(ssoossh_cert_has_principal(&cert, "alice"));
        T_CHECK(ssoossh_cert_has_principal(&cert, "ops"));
        T_CHECK(!ssoossh_cert_has_principal(&cert, "bob"));
        /* A prefix must not match: "ali" is not "alice". */
        T_CHECK(!ssoossh_cert_has_principal(&cert, "ali"));
        T_CHECK(!ssoossh_cert_has_principal(&cert, ""));
        T_EQ_STR(cert.signature_algo, "ecdsa-sha2-nistp384");
        T_CHECK(cert.signed_len > 0 && cert.signed_len < SSOOSSH_MAX_CERT);

        /* The subject key rebuilt out of the certificate equals the key
         * file it was issued for, byte for byte. This is check 2's
         * comparison, done here against a file rather than against a
         * generated key. */
        {
            uint8_t user_blob[SSOOSSH_MAX_KEY_BLOB];
            size_t user_len = 0;
            if (load_ca("user.pub", user_blob, sizeof(user_blob), &user_len)) {
                T_EQ_MEM(cert.key_blob, cert.key_blob_len, user_blob, user_len);
            }
        }
    }

    /* Every CA key type the capability matrix calls supported verifies its
     * own certificate, and none of them verifies anyone else's. */
    {
        static const struct {
            const char *cert;
            const char *ca;
            const char *sig_algo;
        } pairs[] = {
            {"cert_ca_ecdsa256.cert", "ca_ecdsa256.pub", "ecdsa-sha2-nistp256"},
            {"cert_ca_ecdsa384.cert", "ca_ecdsa384.pub", "ecdsa-sha2-nistp384"},
            {"cert_ca_ecdsa521.cert", "ca_ecdsa521.pub", "ecdsa-sha2-nistp521"},
            {"cert_ca_ed25519.cert", "ca_ed25519.pub", "ssh-ed25519"},
            {"cert_ca_rsa.cert", "ca_rsa.pub", "rsa-sha2-512"},
            {"cert_ca_rsa_sha256.cert", "ca_rsa.pub", "rsa-sha2-256"},
        };

        for (size_t i = 0; i < sizeof(pairs) / sizeof(pairs[0]); i++) {
            ssoossh_verify_result want = SSOOSSH_VERIFY_OK;

            if (!load_cert(pairs[i].cert, scratch, sizeof(scratch), &cert) ||
                !load_ca(pairs[i].ca, ca, sizeof(ca), &ca_len)) {
                continue;
            }
            T_EQ_STR(cert.signature_algo, pairs[i].sig_algo);

#ifdef __APPLE__
            /* No C-callable Ed25519 on this platform: the answer is
             * "cannot", reported by name, and never a bare failure. */
            if (strcmp(pairs[i].sig_algo, "ssh-ed25519") == 0) {
                want = SSOOSSH_VERIFY_UNSUPPORTED;
            }
#endif
            T_CHECKF(ssoossh_cert_verify(&cert, ca, ca_len) == want,
                     "%s against %s did not give the expected result",
                     pairs[i].cert, pairs[i].ca);
        }
    }

    /* Signed by a CA the file does not list. This is the ordinary "not
     * signed by a trusted CA" case and must be BAD, not an error. */
    if (load_cert("cert_untrusted.cert", scratch, sizeof(scratch), &cert) &&
        load_ca("ca_ecdsa384.pub", ca, sizeof(ca), &ca_len)) {
        T_EQ_INT(ssoossh_cert_verify(&cert, ca, ca_len), SSOOSSH_VERIFY_BAD);
    }

    /* ssh-rsa is RSA with SHA-1. OpenSSH has refused it by default since
     * 8.8 and x/crypto/ssh still verifies it, so this is a place the C
     * module is deliberately stricter than the Go one. */
    if (load_cert("cert_ca_rsa_sha1.cert", scratch, sizeof(scratch), &cert) &&
        load_ca("ca_rsa.pub", ca, sizeof(ca), &ca_len)) {
        T_EQ_STR(cert.signature_algo, "ssh-rsa");
        T_EQ_INT(ssoossh_cert_verify(&cert, ca, ca_len),
                 SSOOSSH_VERIFY_UNSUPPORTED);
    }

    /* A CA key whose type disagrees with the signature algorithm is a
     * malformed certificate, not a failed check -- the distinction the
     * operator needs, because one is a broken server and the other is an
     * attack. */
    if (load_cert("cert_ca_ecdsa384.cert", scratch, sizeof(scratch), &cert) &&
        load_ca("ca_rsa.pub", ca, sizeof(ca), &ca_len)) {
        T_EQ_INT(ssoossh_cert_verify(&cert, ca, ca_len), SSOOSSH_VERIFY_ERROR);
    }

    /* Tampering. Every byte of the signed extent is covered by the
     * signature, so flipping any of them must fail -- and the parser must
     * still not walk off the end while doing it. */
    if (load_cert("cert_ca_ecdsa384.cert", scratch, sizeof(scratch), &cert) &&
        load_ca("ca_ecdsa384.pub", ca, sizeof(ca), &ca_len)) {
        /* The signature is the last field, so its end is the blob's end. */
        size_t full =
            (size_t)(cert.signature.p + cert.signature.len - cert.blob);
        size_t signed_len = cert.signed_len;
        size_t offsets[] = {signed_len / 4, signed_len / 2, signed_len * 3 / 4,
                            signed_len - 1};

        for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
            uint8_t copy[SSOOSSH_MAX_CERT];
            ssoossh_cert tampered;

            memcpy(copy, scratch, full);
            copy[offsets[i]] ^= 0x01;

            /* Some flips break the encoding rather than the signature, and
             * a refusal to parse is just as good an answer. What must
             * never happen is a parse that then verifies. */
            if (ssoossh_cert_parse(copy, full, &tampered) == SSOOSSH_CERT_OK) {
                T_CHECKF(ssoossh_cert_verify(&tampered, ca, ca_len) !=
                             SSOOSSH_VERIFY_OK,
                         "a certificate tampered at offset %zu still verified",
                         offsets[i]);
            }
        }

        /* And a flip inside the signature itself, which must parse and
         * then fail the check rather than fail to parse. */
        {
            uint8_t copy[SSOOSSH_MAX_CERT];
            ssoossh_cert tampered;
            size_t sig_at = (size_t)(cert.signature.p - cert.blob);

            memcpy(copy, scratch, full);
            copy[sig_at + cert.signature.len / 2] ^= 0x01;
            if (ssoossh_cert_parse(copy, full, &tampered) == SSOOSSH_CERT_OK) {
                T_CHECK(ssoossh_cert_verify(&tampered, ca, ca_len) !=
                        SSOOSSH_VERIFY_OK);
            }
        }
    }

    /* Malformed inputs. None of these may parse, and under ASan none of
     * them may read past the end of the buffer they were given. */
    {
        static const uint8_t empty[] = {0};
        static const uint8_t not_a_cert[] = {
            /* A plain ecdsa public key, which has no -cert- suffix. */
            0x00, 0x00, 0x00, 0x13, 'e', 'c', 'd', 's', 'a', '-', 's', 'h',
            'a',  '2',  '-',  'n',  'i', 's', 't', 'p', '3', '8', '4'};
        static const uint8_t truncated_name[] = {0x00, 0x00, 0x00, 0x40, 'x'};

        T_EQ_INT(ssoossh_cert_parse(empty, 0, &cert), SSOOSSH_CERT_MALFORMED);
        T_EQ_INT(ssoossh_cert_parse(not_a_cert, sizeof(not_a_cert), &cert),
                 SSOOSSH_CERT_MALFORMED);
        T_EQ_INT(
            ssoossh_cert_parse(truncated_name, sizeof(truncated_name), &cert),
            SSOOSSH_CERT_MALFORMED);
    }

    /* Every prefix of a real certificate. A parser that reads one field
     * past what it checked fails here, at whichever length exposes it. */
    {
        char line[SSOOSSH_MAX_CERT_LINE];
        size_t n =
            fixture_read_line("cert_ca_ecdsa384.cert", line, sizeof(line));
        uint8_t blob[SSOOSSH_MAX_CERT];

        if (n > 0 && ssoossh_cert_parse_line(line, n, blob, sizeof(blob),
                                             &cert) == SSOOSSH_CERT_OK) {
            size_t full = 0;

            /* Recover the decoded length: the signature is the last field,
             * so its end is the blob's end. */
            full = (size_t)(cert.signature.p + cert.signature.len - blob);
            for (size_t cut = 0; cut < full; cut++) {
                ssoossh_cert partial;
                T_CHECKF(ssoossh_cert_parse(blob, cut, &partial) !=
                             SSOOSSH_CERT_OK,
                         "a certificate truncated to %zu bytes parsed", cut);
            }
            /* And one byte too many. */
            {
                ssoossh_cert extra;
                uint8_t longer[SSOOSSH_MAX_CERT];
                memcpy(longer, blob, full);
                longer[full] = 0x00;
                T_CHECK(ssoossh_cert_parse(longer, full + 1, &extra) !=
                        SSOOSSH_CERT_OK);
            }
        }
    }

    return t_failures;
}
