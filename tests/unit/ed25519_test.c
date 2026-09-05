/* Ed25519 verification, pinned to a known acceptance profile.
 *
 * Two things are asserted here and both matter more on macOS than
 * anywhere else. First, that the backend verifies Ed25519 at all: on macOS
 * that goes through a Security.framework SPI Apple does not document, so a
 * host where the symbols vanished, or resolved but failed the backend's
 * self-test, fails this suite by name rather than skipping it. Second,
 * that it accepts and rejects exactly what the other platforms do. The
 * twelve edge cases from ed25519-speccheck (Chalkias, Garillot and
 * Nikolaenko, "Taming the many EdDSAs") are where verifiers disagree --
 * small-order points, S outside the group order, non-canonical encodings
 * -- and OpenSSL, BoringSSL, Go and Apple's CryptoKit all give the same
 * row. That row is pinned below. A backend that drifts from it, in either
 * direction, is a certificate that verifies on one platform and not on
 * another, and that is the failure this suite exists to catch before a
 * host does.
 */
#include <stdio.h>
#include <string.h>

#include "crypto.h"
#include "sshwire.h"
#include "suites.h"
#include "test.h"

static size_t unhex(const char *hex, uint8_t *out, size_t cap)
{
    size_t n = strlen(hex) / 2;

    if (strlen(hex) % 2 != 0 || n > cap) {
        return (size_t)-1;
    }
    for (size_t i = 0; i < n; i++) {
        unsigned v;

        if (sscanf(hex + 2 * i, "%2x", &v) != 1) {
            return (size_t)-1;
        }
        out[i] = (uint8_t)v;
    }
    return n;
}

/* An ssh-ed25519 public key blob around 32 raw bytes, which is what
 * ssoossh_crypto_verify takes as the CA key. */
static size_t ed25519_blob(const uint8_t *pk, uint8_t *out, size_t cap)
{
    ssh_wr w;

    ssh_wr_init(&w, out, cap);
    ssh_wr_cstr(&w, "ssh-ed25519");
    ssh_wr_str(&w, pk, 32);
    return ssh_wr_ok(&w) ? ssh_wr_len(&w) : 0;
}

typedef struct {
    const char *name;
    const char *pk;
    const char *msg;
    const char *sig;
    ssoossh_verify_result want;
} vector;

static void run(const vector *v)
{
    uint8_t pk[32], msg[64], sig[64], blob[64];
    size_t pk_len = unhex(v->pk, pk, sizeof(pk));
    size_t msg_len = unhex(v->msg, msg, sizeof(msg));
    size_t sig_len = unhex(v->sig, sig, sizeof(sig));
    size_t blob_len;
    ssoossh_verify_result got;

    if (pk_len != 32 || msg_len == (size_t)-1 || sig_len != 64) {
        t_failf(__FILE__, __LINE__, "%s: vector is malformed", v->name);
        return;
    }
    blob_len = ed25519_blob(pk, blob, sizeof(blob));
    if (blob_len == 0) {
        t_failf(__FILE__, __LINE__, "%s: could not build key blob", v->name);
        return;
    }
    got = ssoossh_crypto_verify("ssh-ed25519", blob, blob_len, msg, msg_len,
                                sig, sig_len);
    T_CHECKF(got == v->want, "%s: got %d, want %d", v->name, (int)got,
             (int)v->want);
}

int suite_ed25519(void)
{
    /* RFC 8032 §7.1. */
    static const vector rfc[] = {
        {"rfc8032 test 1",
         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
         "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
         SSOOSSH_VERIFY_OK},
        {"rfc8032 test 2",
         "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
         "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
         "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
         SSOOSSH_VERIFY_OK},
        {"rfc8032 test 3",
         "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
         "af82",
         "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
         "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
         SSOOSSH_VERIFY_OK},
        /* Test 3 again, with one byte of the signature, then of the
         * message, then of the key, changed. */
        {"rfc8032 test 3, signature corrupted",
         "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
         "af82",
         "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
         "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40b",
         SSOOSSH_VERIFY_BAD},
        {"rfc8032 test 3, message corrupted",
         "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
         "af83",
         "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
         "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
         SSOOSSH_VERIFY_BAD},
        {"rfc8032 test 3, wrong key",
         "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
         "af82",
         "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
         "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
         SSOOSSH_VERIFY_BAD},
    };

    /* ed25519-speccheck cases 0..11, from
     * https://github.com/novifinancial/ed25519-speccheck/blob/main/cases.json
     * with the expected results the OpenSSL 3, BoringSSL, Go and CryptoKit
     * row of its README gives: V V V V X X X X X X X V.
     *
     *   0-2  small-order A or R, or both        accepted
     *   3    mixed A and R, both equations hold accepted
     *   4    mixed, cofactored only             rejected (cofactorless)
     *   5    pre-reduced scalar                 rejected
     *   6-7  S >= L                             rejected
     *   8-9  non-canonical R                    rejected
     *   10   non-canonical A                    rejected
     *   11   non-canonical A, other form        accepted */
    static const vector speccheck[] = {
        {"speccheck 0",
         "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
         "8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6",
         "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"
         "0000000000000000000000000000000000000000000000000000000000000000",
         SSOOSSH_VERIFY_OK},
        {"speccheck 1",
         "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
         "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
         "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43"
         "a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
         SSOOSSH_VERIFY_OK},
        {"speccheck 2",
         "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
         "aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab",
         "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"
         "8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e",
         SSOOSSH_VERIFY_OK},
        {"speccheck 3",
         "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
         "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
         "9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f"
         "87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009",
         SSOOSSH_VERIFY_OK},
        {"speccheck 4",
         "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
         "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
         "160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed512"
         "5ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09",
         SSOOSSH_VERIFY_BAD},
        {"speccheck 5",
         "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
         "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
         "21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7"
         "e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405",
         SSOOSSH_VERIFY_BAD},
        {"speccheck 6",
         "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
         "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
         "e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e"
         "547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514",
         SSOOSSH_VERIFY_BAD},
        {"speccheck 7",
         "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
         "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
         "8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa1942"
         "7e71f98a473474f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22",
         SSOOSSH_VERIFY_BAD},
        {"speccheck 8",
         "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
         "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
         "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
         "03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f",
         SSOOSSH_VERIFY_BAD},
        {"speccheck 9",
         "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
         "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
         "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
         "ca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908",
         SSOOSSH_VERIFY_BAD},
        {"speccheck 10",
         "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
         "e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b",
         "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dc"
         "a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
         SSOOSSH_VERIFY_BAD},
        {"speccheck 11",
         "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
         "39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f",
         "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dc"
         "a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
         SSOOSSH_VERIFY_OK},
    };

    /* The one acceptable reason to have no Ed25519 is a FIPS
     * configuration without EdDSA, which key_test.c already checks is the
     * case whenever support is missing; this suite then has nothing to
     * measure and says so. Anywhere else -- on macOS, the
     * Security.framework SPI being absent or failing the backend's
     * self-test -- it is a failure, with the version line saying which. */
    if (!ssoossh_crypto_supports_key("ssh-ed25519")) {
        if (ssoossh_crypto_fips_state() == SSOOSSH_FIPS_ON) {
            printf("  note: ssh-ed25519 unavailable under FIPS mode; "
                   "profile not measured\n");
            return t_failures;
        }
        t_failf(__FILE__, __LINE__,
                "backend reports no ssh-ed25519 support (crypto: %s)",
                ssoossh_crypto_version());
        return t_failures;
    }
#ifdef __APPLE__
    T_CHECKF(strstr(ssoossh_crypto_version(), "Ed25519 SPI ok") != NULL,
             "version line does not report the SPI as usable: %s",
             ssoossh_crypto_version());
#endif

    for (size_t i = 0; i < sizeof(rfc) / sizeof(rfc[0]); i++) {
        run(&rfc[i]);
    }
    for (size_t i = 0; i < sizeof(speccheck) / sizeof(speccheck[0]); i++) {
        run(&speccheck[i]);
    }

    /* Shape errors are ERROR, not BAD: a 63-byte signature or a 31-byte
     * key is malformed input, and the operator should hear that rather
     * than "not signed by a trusted CA". */
    {
        uint8_t pk[32], msg[2], sig[64], blob[64];
        size_t blob_len;
        ssh_wr w;

        (void)unhex(rfc[2].pk, pk, sizeof(pk));
        (void)unhex(rfc[2].msg, msg, sizeof(msg));
        (void)unhex(rfc[2].sig, sig, sizeof(sig));
        blob_len = ed25519_blob(pk, blob, sizeof(blob));

        T_EQ_INT(ssoossh_crypto_verify("ssh-ed25519", blob, blob_len, msg,
                                       sizeof(msg), sig, 63),
                 SSOOSSH_VERIFY_ERROR);
        T_EQ_INT(ssoossh_crypto_verify("ssh-ed25519", blob, blob_len, msg,
                                       sizeof(msg), sig, 65),
                 SSOOSSH_VERIFY_ERROR);

        ssh_wr_init(&w, blob, sizeof(blob));
        ssh_wr_cstr(&w, "ssh-ed25519");
        ssh_wr_str(&w, pk, 31);
        T_EQ_INT(ssoossh_crypto_verify("ssh-ed25519", blob, ssh_wr_len(&w), msg,
                                       sizeof(msg), sig, 64),
                 SSOOSSH_VERIFY_ERROR);

        /* An Ed25519 signature over an ECDSA key blob is a malformed
         * certificate, not a failed check. */
        ssh_wr_init(&w, blob, sizeof(blob));
        ssh_wr_cstr(&w, "ecdsa-sha2-nistp256");
        ssh_wr_cstr(&w, "nistp256");
        ssh_wr_str(&w, pk, 32);
        T_EQ_INT(ssoossh_crypto_verify("ssh-ed25519", blob, ssh_wr_len(&w), msg,
                                       sizeof(msg), sig, 64),
                 SSOOSSH_VERIFY_ERROR);
    }

    return t_failures;
}
