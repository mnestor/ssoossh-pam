/* The OpenSSL backend: Linux and FreeBSD.
 *
 * The version floor is a project boundary, not an observation. OpenSSL
 * 1.0.2 and the releases carrying it are out of scope permanently -- that
 * is where EVP_MD_CTX and the ECDSA_SIG accessors become structurally
 * different rather than renamed, which would mean a third API path through
 * the file that verifies certificates as root, to serve a library upstream
 * stopped patching in 2019.
 */
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x10101000L
#    error "pam_ssoossh requires OpenSSL 1.1.1 or newer (RHEL 8 baseline)"
#endif

#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include "crypto.h"
#include "der.h"
#include "ed25519_kat.h"
#include "log.h"
#include "sshwire.h"

/* ------------------------------------------------------------------------
 * FIPS, and what the host's OpenSSL will actually verify.
 *
 * A host in FIPS mode -- RHEL with fips=1, or an OpenSSL configured to use
 * only its FIPS provider -- decides for itself which algorithms exist.
 * Which ones is a property of that host's OpenSSL, not of this module:
 * RHEL 8's 1.1.1 refuses Ed25519 in FIPS mode, RHEL 9's 3.5 allows it,
 * and both are right. So the module hardcodes nothing. The per-attempt key
 * is P-384, approved everywhere; RSA and ECDSA CAs are verified through
 * the same EVP calls whether FIPS is on or not, and a refusal is reported
 * with OpenSSL's own reason; and Ed25519, the one algorithm a FIPS
 * configuration commonly lacks, is probed once with a known answer before
 * the module claims to support it, exactly as the macOS backend probes its
 * SPI. What FIPS mode changes is therefore visible in two places: the
 * version line every authentication logs, and a warning naming FIPS when
 * an ssh-ed25519 CA has to be skipped because of it.
 * ------------------------------------------------------------------------ */

/* The kernel's switch, where there is one. Linux only; FreeBSD has no such
 * flag and its OpenSSL is asked directly below. */
static bool kernel_fips(void)
{
    FILE *f = fopen("/proc/sys/crypto/fips_enabled", "r");
    int c;

    if (f == NULL) {
        return false;
    }
    c = fgetc(f);
    (void)fclose(f);
    return c == '1';
}

/* The library's own view: the default property query selecting only FIPS
 * implementations on 3.x, or the global mode flag on 1.1.1, which the
 * distributions that build 1.1.1 with a FIPS module still honour. */
static bool library_fips(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    return EVP_default_properties_is_fips_enabled(NULL) == 1;
#else
    return FIPS_mode() != 0;
#endif
}

/* Read once per process: neither the kernel flag nor the library's mode
 * changes while sudo is running, and the version line asks on every
 * authentication. */
static pthread_once_t fips_once = PTHREAD_ONCE_INIT;
static ssoossh_fips_state fips_state;

static void fips_init(void)
{
    fips_state =
        (kernel_fips() || library_fips()) ? SSOOSSH_FIPS_ON : SSOOSSH_FIPS_OFF;
}

ssoossh_fips_state ssoossh_crypto_fips_state(void)
{
    (void)pthread_once(&fips_once, fips_init);
    return fips_state;
}

/* OpenSSL's reason for the last failure, for a log line, and the queue
 * cleared: it is thread-local state in a process -- sudo, sshd -- that
 * this module does not own. */
static const char *openssl_reason(void)
{
    unsigned long e = ERR_peek_last_error();
    const char *reason = e != 0 ? ERR_reason_error_string(e) : NULL;

    ERR_clear_error();
    return reason != NULL ? reason : "no OpenSSL error recorded";
}

/* Public keys reach OpenSSL as a DER SubjectPublicKeyInfo through
 * d2i_PUBKEY, rather than being assembled from raw components. See der.h
 * for why: one call covers EC, RSA and Ed25519, and it is undeprecated on
 * both 1.1.1 and 3.x, so the file that runs as root over network bytes has
 * no version-conditional code in it at all. */

struct ssoossh_keypair {
    EVP_PKEY *pkey;
};

bool ssoossh_crypto_keygen(ssoossh_keypair **out)
{
    EVP_PKEY_CTX *ctx = NULL;
    ssoossh_keypair *kp = NULL;
    bool ok = false;

    *out = NULL;

    /* This path needs no version guard: EVP_PKEY_CTX_new_id with
     * set_ec_paramgen_curve_nid is current API on 1.1.1 and on 3.x alike.
     * EVP_EC_gen would be shorter and is 3.0-only. */
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (ctx == NULL || EVP_PKEY_keygen_init(ctx) <= 0) {
        goto done;
    }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp384r1) <= 0) {
        goto done;
    }

    kp = OPENSSL_zalloc(sizeof(*kp));
    if (kp == NULL) {
        goto done;
    }
    if (EVP_PKEY_keygen(ctx, &kp->pkey) <= 0) {
        goto done;
    }
    *out = kp;
    kp = NULL;
    ok = true;

done:
    EVP_PKEY_CTX_free(ctx);
    if (kp != NULL) {
        EVP_PKEY_free(kp->pkey);
        OPENSSL_free(kp);
    }
    return ok;
}

void ssoossh_crypto_keypair_free(ssoossh_keypair *kp)
{
    if (kp == NULL) {
        return;
    }
    /* EVP_PKEY_free clears the private scalar itself -- EC_KEY_free ends in
     * BN_clear_free -- so the wipe here is about the handle, not the key
     * material. Both are done because the cost is nothing and the failure
     * is silent. */
    EVP_PKEY_free(kp->pkey);
    OPENSSL_cleanse(kp, sizeof(*kp));
    OPENSSL_free(kp);
}

bool ssoossh_crypto_public_point(const ssoossh_keypair *kp, uint8_t *out,
                                 size_t out_cap, size_t *out_len)
{
    /* i2d_PUBKEY gives an SPKI; the point is the BIT STRING at its end.
     * Rather than unwrap that by hand, the point is taken through the
     * generic parameter accessor on 3.x and the EC accessor on 1.1.1 --
     * the one place in this file where the two differ, and it touches a
     * key this process generated rather than one a peer sent. */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    size_t n = 0;

    if (EVP_PKEY_get_octet_string_param(kp->pkey, "encoded-pub-key", out,
                                        out_cap, &n) != 1) {
        return false;
    }
    *out_len = n;
    return true;
#else
    const EC_KEY *ec = EVP_PKEY_get0_EC_KEY(kp->pkey);
    const EC_POINT *point;
    const EC_GROUP *group;
    size_t n;

    if (ec == NULL) {
        return false;
    }
    point = EC_KEY_get0_public_key(ec);
    group = EC_KEY_get0_group(ec);
    if (point == NULL || group == NULL) {
        return false;
    }
    n = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, out,
                           out_cap, NULL);
    if (n == 0) {
        return false;
    }
    *out_len = n;
    return true;
#endif
}

/* Maps an SSH key blob onto a SubjectPublicKeyInfo. The blob's own type
 * string decides the shape, and everything is read through the bounds
 * checked reader. */
static bool spki_from_ssh_key(const uint8_t *blob, size_t blob_len,
                              uint8_t *out, size_t out_cap, size_t *out_len,
                              char *type_out, size_t type_cap)
{
    ssh_rd r;
    const uint8_t *type = NULL, *a = NULL, *b = NULL;
    size_t type_len = 0, a_len = 0, b_len = 0;

    ssh_rd_init(&r, blob, blob_len);
    if (!ssh_rd_str(&r, &type, &type_len) || type_len == 0 ||
        type_len >= type_cap) {
        return false;
    }
    memcpy(type_out, type, type_len);
    type_out[type_len] = '\0';

    if (strcmp(type_out, "ssh-ed25519") == 0) {
        if (!ssh_rd_str(&r, &a, &a_len) || !ssh_rd_done(&r)) {
            return false;
        }
        return ssoossh_der_spki_ed25519(a, a_len, out, out_cap, out_len);
    }

    if (strcmp(type_out, "ssh-rsa") == 0) {
        /* e then n, which is the reverse of the DER RSAPublicKey order.
         * Getting this backwards produces a key that parses and verifies
         * nothing, so it is worth naming. */
        if (!ssh_rd_str(&r, &a, &a_len) || !ssh_rd_str(&r, &b, &b_len) ||
            !ssh_rd_done(&r)) {
            return false;
        }
        return ssoossh_der_spki_rsa(a, a_len, b, b_len, out, out_cap, out_len);
    }

    if (strncmp(type_out, "ecdsa-sha2-nistp", 16) == 0) {
        ssoossh_curve curve;
        const char *want_curve;

        if (strcmp(type_out + 16, "256") == 0) {
            curve = SSOOSSH_CURVE_P256;
            want_curve = "nistp256";
        } else if (strcmp(type_out + 16, "384") == 0) {
            curve = SSOOSSH_CURVE_P384;
            want_curve = "nistp384";
        } else if (strcmp(type_out + 16, "521") == 0) {
            curve = SSOOSSH_CURVE_P521;
            want_curve = "nistp521";
        } else {
            return false;
        }

        if (!ssh_rd_str(&r, &a, &a_len) || !ssh_rd_str(&r, &b, &b_len) ||
            !ssh_rd_done(&r)) {
            return false;
        }
        /* The blob names its curve twice: in the key type and in a field of
         * its own. A key where the two disagree is malformed, and taking
         * the type string alone would let the mismatch through. */
        if (a_len != strlen(want_curve) || memcmp(a, want_curve, a_len) != 0) {
            return false;
        }
        return ssoossh_der_spki_ec(curve, b, b_len, out, out_cap, out_len);
    }

    return false;
}

static ssoossh_verify_result verify_spki(const uint8_t *spki, size_t spki_len,
                                         const EVP_MD *md, const uint8_t *msg,
                                         size_t msg_len, const uint8_t *sig,
                                         size_t sig_len, const char **why);

/* Ed25519, probed. The known answers in ed25519_kat.h must come out as
 * they say -- the RFC 8032 vector verifies, a corrupted copy and an
 * out-of-range S do not -- or this host cannot verify ssh-ed25519 and says
 * so once. "Cannot" includes the "unsupported" or "disallowed" OpenSSL
 * raises when its FIPS provider has no EdDSA. */
static pthread_once_t ed25519_once = PTHREAD_ONCE_INIT;
static bool ed25519_ok;

static ssoossh_verify_result probe(const ssoossh_ed25519_vector *v,
                                   const uint8_t *sig, const char **why)
{
    uint8_t spki[64];
    size_t spki_len = 0;

    if (!ssoossh_der_spki_ed25519(v->pk, sizeof(v->pk), spki, sizeof(spki),
                                  &spki_len)) {
        *why = "could not encode the probe key";
        return SSOOSSH_VERIFY_ERROR;
    }
    return verify_spki(spki, spki_len, NULL, v->msg, v->msg_len, sig, 64, why);
}

static void ed25519_init(void)
{
    const ssoossh_ed25519_vector *kat = &SSOOSSH_ED25519_KAT;
    const char *why = "unknown";
    const char *fips =
        ssoossh_crypto_fips_state() == SSOOSSH_FIPS_ON ? "on" : "off";
    uint8_t flipped[64];

    memcpy(flipped, kat->sig, sizeof(flipped));
    flipped[SSOOSSH_ED25519_KAT_FLIP_BYTE] ^= 0x01;

    if (probe(kat, kat->sig, &why) != SSOOSSH_VERIFY_OK) {
        /* why is set. */
    } else if (probe(kat, flipped, &why) != SSOOSSH_VERIFY_BAD) {
        why = "a corrupted signature was not refused";
    } else if (probe(&SSOOSSH_ED25519_BIG_S, SSOOSSH_ED25519_BIG_S.sig, &why) !=
               SSOOSSH_VERIFY_BAD) {
        why = "a signature with S >= L was not refused";
    } else {
        ed25519_ok = true;
        ssoossh_debugf("Ed25519: %s verified the known answers (fips: %s)",
                       OpenSSL_version(OPENSSL_VERSION), fips);
        return;
    }
    ssoossh_warnf("Ed25519: %s cannot verify it here (%s; fips: %s); "
                  "ssh-ed25519 CAs cannot be used on this host",
                  OpenSSL_version(OPENSSL_VERSION), why, fips);
}

static bool ed25519_usable(void)
{
    (void)pthread_once(&ed25519_once, ed25519_init);
    return ed25519_ok;
}

bool ssoossh_crypto_supports_key(const char *key_algo)
{
    if (strcmp(key_algo, "ssh-ed25519") == 0) {
        return ed25519_usable();
    }
    return strcmp(key_algo, "ssh-rsa") == 0 ||
           strcmp(key_algo, "ecdsa-sha2-nistp256") == 0 ||
           strcmp(key_algo, "ecdsa-sha2-nistp384") == 0 ||
           strcmp(key_algo, "ecdsa-sha2-nistp521") == 0;
}

/* Which key type a signature algorithm must have been produced by, and
 * which digest goes with it. NULL md means Ed25519, whose one-shot verify
 * takes no separate digest.
 *
 * ssh-rsa is absent on purpose. That algorithm name means RSA with SHA-1,
 * which OpenSSH has refused by default since 8.8; x/crypto/ssh still
 * verifies it, so the Go module accepts such a CA today and this one does
 * not. The caller turns the resulting UNSUPPORTED into an error naming the
 * algorithm, so an operator learns the key type is the problem rather than
 * reading "not signed by a trusted CA". */
static bool sig_algo_info(const char *sig_algo, const char **key_type,
                          const EVP_MD **md)
{
    if (strcmp(sig_algo, "ssh-ed25519") == 0) {
        if (!ed25519_usable()) {
            return false;
        }
        *key_type = "ssh-ed25519";
        *md = NULL;
        return true;
    }
    if (strcmp(sig_algo, "rsa-sha2-256") == 0) {
        *key_type = "ssh-rsa";
        *md = EVP_sha256();
        return true;
    }
    if (strcmp(sig_algo, "rsa-sha2-512") == 0) {
        *key_type = "ssh-rsa";
        *md = EVP_sha512();
        return true;
    }
    if (strcmp(sig_algo, "ecdsa-sha2-nistp256") == 0) {
        *key_type = "ecdsa-sha2-nistp256";
        *md = EVP_sha256();
        return true;
    }
    if (strcmp(sig_algo, "ecdsa-sha2-nistp384") == 0) {
        *key_type = "ecdsa-sha2-nistp384";
        *md = EVP_sha384();
        return true;
    }
    if (strcmp(sig_algo, "ecdsa-sha2-nistp521") == 0) {
        *key_type = "ecdsa-sha2-nistp521";
        *md = EVP_sha512();
        return true;
    }
    return false;
}

/* ECDSA signatures arrive as two mpints and OpenSSL wants an
 * ECDSA-Sig-Value, so they are re-encoded rather than passed through. */
static bool ecdsa_sig_to_der(const uint8_t *sig, size_t sig_len, uint8_t *out,
                             size_t out_cap, size_t *out_len)
{
    ssh_rd r;
    const uint8_t *rr = NULL, *ss = NULL;
    size_t r_len = 0, s_len = 0;

    ssh_rd_init(&r, sig, sig_len);
    if (!ssh_rd_str(&r, &rr, &r_len) || !ssh_rd_str(&r, &ss, &s_len) ||
        !ssh_rd_done(&r)) {
        return false;
    }
    return ssoossh_der_ecdsa_sig(rr, r_len, ss, s_len, out, out_cap, out_len);
}

/* The EVP half: a SubjectPublicKeyInfo, a digest (NULL for Ed25519), the
 * bytes and the signature. why receives OpenSSL's reason when the result is
 * ERROR, which is how a FIPS refusal -- "unsupported", "disallowed", a key
 * below the approved size -- reaches a log line instead of reading as a
 * malformed certificate. */
static ssoossh_verify_result verify_spki(const uint8_t *spki, size_t spki_len,
                                         const EVP_MD *md, const uint8_t *msg,
                                         size_t msg_len, const uint8_t *sig,
                                         size_t sig_len, const char **why)
{
    const uint8_t *spki_p = spki;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *ctx = NULL;
    ssoossh_verify_result result = SSOOSSH_VERIFY_ERROR;
    int rc;

    *why = NULL;
    ERR_clear_error();

    pkey = d2i_PUBKEY(NULL, &spki_p, (long)spki_len);
    if (pkey == NULL) {
        *why = openssl_reason();
        return SSOOSSH_VERIFY_ERROR;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        *why = "out of memory";
        goto done;
    }
    if (EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey) != 1) {
        *why = openssl_reason();
        goto done;
    }

    /* One-shot EVP_DigestVerify for every algorithm, not only Ed25519,
     * which requires it. The whole signed extent is already in memory --
     * sshcert.c captured it as an offset into the certificate blob -- so
     * there is nothing to stream. */
    rc = EVP_DigestVerify(ctx, sig, sig_len, msg, msg_len);
    if (rc == 1) {
        result = SSOOSSH_VERIFY_OK;
    } else if (rc == 0) {
        result = SSOOSSH_VERIFY_BAD;
        ERR_clear_error();
    } else {
        *why = openssl_reason();
    }

done:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return result;
}

ssoossh_verify_result ssoossh_crypto_verify(const char *sig_algo,
                                            const uint8_t *ca_key,
                                            size_t ca_key_len,
                                            const uint8_t *msg, size_t msg_len,
                                            const uint8_t *sig, size_t sig_len)
{
    uint8_t spki_buf[2048];
    uint8_t der_sig[256];
    char key_type[64];
    const char *want_key_type = NULL;
    const char *why = NULL;
    const EVP_MD *md = NULL;
    size_t spki_len = 0;
    ssoossh_verify_result result;

    if (!sig_algo_info(sig_algo, &want_key_type, &md)) {
        return SSOOSSH_VERIFY_UNSUPPORTED;
    }
    if (!spki_from_ssh_key(ca_key, ca_key_len, spki_buf, sizeof(spki_buf),
                           &spki_len, key_type, sizeof(key_type))) {
        return SSOOSSH_VERIFY_ERROR;
    }
    if (strcmp(key_type, want_key_type) != 0) {
        /* A certificate claiming an ECDSA P-384 signature over an RSA CA
         * key, say. Malformed rather than merely wrong. */
        return SSOOSSH_VERIFY_ERROR;
    }

    if (strncmp(sig_algo, "ecdsa-", 6) == 0) {
        size_t n = 0;
        if (!ecdsa_sig_to_der(sig, sig_len, der_sig, sizeof(der_sig), &n)) {
            return SSOOSSH_VERIFY_ERROR;
        }
        sig = der_sig;
        sig_len = n;
    } else if (strcmp(sig_algo, "ssh-ed25519") == 0 && sig_len != 64) {
        return SSOOSSH_VERIFY_ERROR;
    }

    result =
        verify_spki(spki_buf, spki_len, md, msg, msg_len, sig, sig_len, &why);
    if (result == SSOOSSH_VERIFY_ERROR && why != NULL) {
        /* The one place a FIPS refusal of an RSA or ECDSA CA surfaces: the
         * caller reports "could not be verified", and this line says why
         * in OpenSSL's words. */
        ssoossh_errf("%s verification with a %s key failed in %s: %s", sig_algo,
                     key_type, OpenSSL_version(OPENSSL_VERSION), why);
    }
    return result;
}

bool ssoossh_crypto_sha256(const uint8_t *in, size_t in_len, uint8_t out[32])
{
    unsigned int n = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    bool ok = false;

    if (ctx == NULL) {
        return false;
    }
    ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
         EVP_DigestUpdate(ctx, in, in_len) == 1 &&
         EVP_DigestFinal_ex(ctx, out, &n) == 1 && n == 32;
    EVP_MD_CTX_free(ctx);
    return ok;
}

void ssoossh_crypto_wipe(void *p, size_t n)
{
    OPENSSL_cleanse(p, n);
}

const char *ssoossh_crypto_version(void)
{
    return OpenSSL_version(OPENSSL_VERSION);
}
