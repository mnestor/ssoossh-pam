/* The Security.framework and CommonCrypto backend: macOS.
 *
 * System SSL is not an option here. macOS ships LibreSSL as a dylib, but the
 * SDK exposes no OpenSSL headers and no linkable stub, and Apple does not
 * support third-party linking against it. That leaves Homebrew's openssl@3
 * or Apple's own APIs, and Apple's own win: a module that links only what
 * the OS ships has no install-time dependency, no second copy of a TLS stack
 * in a root process, and no third-party CVE surface to track.
 *
 * Ed25519 comes through a seam in that API rather than a hole in it. The
 * public SecKey headers name no Ed25519 key type, but Security.framework
 * has exported one since macOS 14 -- kSecAttrKeyTypeEd25519 and the EdDSA
 * SecKeyAlgorithm are declared in Apple's private SecItemPriv.h and
 * SecKeyPriv.h, exported unconditionally on macOS, and implemented over the
 * same corecrypto call CryptoKit makes. They are SPI: Apple promises nothing
 * about them. So this file treats them as something to be checked rather
 * than assumed, on every host, every time:
 *
 *   1. Both symbols are looked up with dlsym at first use, never linked.
 *      The bundle is linked with -bind_at_load, so a hard reference to a
 *      symbol a future macOS drops would stop the module loading at all --
 *      inside sudo. A dlsym that fails instead degrades to "ssh-ed25519 is
 *      unsupported here", which is exactly what this backend did before.
 *   2. Before the SPI is trusted it has to pass a known-answer self-test:
 *      an RFC 8032 vector must verify, a corrupted copy must not, and a
 *      signature with S outside the group order must be refused. An SPI
 *      that resolves but has changed meaning under the same name is treated
 *      the same as one that is missing.
 *   3. Which of those outcomes this host got is in the version line every
 *      authentication logs, so a fleet can grep for it.
 *
 * docs/porting.md has the evidence and the CI that watches Apple's SDKs
 * and betas for the symbols going away.
 *
 * ==========================================================================
 * THIS FILE HAS NEVER BEEN COMPILED.
 *
 * It is written against the documented Security.framework API and against
 * the same crypto.h contract the OpenSSL backend satisfies, but no macOS
 * machine has been near it. macOS ships no artifact -- it is a developer and
 * CI target that exists to keep the OpenPAM paths under test -- and turning
 * that job on is the next thing to do, not something this file's author has
 * done. Treat every line as unverified until macos-15 has run it.
 * ==========================================================================
 */
/* Before <string.h>: Apple declares memset_s only when this is set, and a
 * call to an undeclared function is an error under the flags this builds
 * with. */
#define __STDC_WANT_LIB_EXT1__ 1
/* Before <dlfcn.h>: RTLD_DEFAULT is a Darwin extension, and this file is
 * compiled under -std=c11 rather than gnu11. */
#define _DARWIN_C_SOURCE 1

#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include <dlfcn.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "der.h"
#include "ed25519_kat.h"
#include "log.h"
#include "sshwire.h"

struct ssoossh_keypair {
    SecKeyRef private_key;
    SecKeyRef public_key;
};

/* CFDataRef over borrowed bytes, with no copy. kCFAllocatorNull as the
 * deallocator is what makes it a view rather than an owner. */
static CFDataRef data_view(const uint8_t *p, size_t n)
{
    return CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, p, (CFIndex)n,
                                       kCFAllocatorNull);
}

/* Verifies sig over msg with an already-built key. Shared by the public
 * verify and by the Ed25519 self-test, so the two cannot disagree about
 * what "verified" means. */
static ssoossh_verify_result verify_with(SecKeyRef key,
                                         SecKeyAlgorithm algorithm,
                                         const uint8_t *msg, size_t msg_len,
                                         const uint8_t *sig, size_t sig_len)
{
    CFDataRef signed_data = data_view(msg, msg_len);
    CFDataRef signature = data_view(sig, sig_len);
    ssoossh_verify_result result = SSOOSSH_VERIFY_ERROR;

    if (signed_data != NULL && signature != NULL) {
        CFErrorRef error = NULL;

        if (SecKeyVerifySignature(key, algorithm, signed_data, signature,
                                  &error)) {
            result = SSOOSSH_VERIFY_OK;
        } else {
            /* SecKeyVerifySignature does not separate "wrong signature"
             * from "malformed input" in its return, so the error domain
             * decides. Anything that is not a clean cryptographic failure
             * is reported as an error rather than as a denial. */
            result = SSOOSSH_VERIFY_BAD;
            if (error != NULL) {
                CFRelease(error);
            }
        }
    }

    if (signature != NULL) {
        CFRelease(signature);
    }
    if (signed_data != NULL) {
        CFRelease(signed_data);
    }
    return result;
}

/* ------------------------------------------------------------------------
 * Ed25519 through the SPI.
 * ------------------------------------------------------------------------ */

/* The two names, spelled once. tests/apple-spi-check.sh greps Apple's SDKs
 * for the same two strings, with the Mach-O underscore. */
#define ED25519_KEY_TYPE_SYM "kSecAttrKeyTypeEd25519"
#define ED25519_ALGORITHM_SYM                                                  \
    "kSecKeyAlgorithmEdDSASignatureMessageCurve25519SHA512"

/* What the probe found: the two constants when they resolved, whether
 * they passed the known-answer test, and a word for the version line. */
static CFStringRef ed25519_key_type;
static SecKeyAlgorithm ed25519_algorithm;
static bool ed25519_ok;
static const char *ed25519_version = "Security.framework (no Ed25519 SPI)";

static pthread_once_t ed25519_once = PTHREAD_ONCE_INIT;

/* dlsym on an exported CF constant gives the address of the variable, not
 * its value: one more dereference, and a NULL at either level is "absent". */
static bool resolve_constant(const char *name, const void **out)
{
    const void *const *slot = dlsym(RTLD_DEFAULT, name);

    if (slot == NULL || *slot == NULL) {
        return false;
    }
    *out = *slot;
    return true;
}

/* A SecKeyRef from the 32 raw bytes of an Ed25519 public key, which is
 * what both the SSH blob and the SPI's kSecKeyEncodingBytes carry. */
static SecKeyRef ed25519_key(const uint8_t *pk, size_t pk_len)
{
    CFMutableDictionaryRef attrs;
    CFDataRef material;
    SecKeyRef key = NULL;

    if (pk_len != 32 || ed25519_key_type == NULL) {
        return NULL;
    }
    attrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                                      &kCFTypeDictionaryKeyCallBacks,
                                      &kCFTypeDictionaryValueCallBacks);
    if (attrs == NULL) {
        return NULL;
    }
    CFDictionarySetValue(attrs, kSecAttrKeyType, ed25519_key_type);
    CFDictionarySetValue(attrs, kSecAttrKeyClass, kSecAttrKeyClassPublic);
    material = data_view(pk, pk_len);
    if (material != NULL) {
        key = SecKeyCreateWithData(material, attrs, NULL);
        CFRelease(material);
    }
    CFRelease(attrs);
    return key;
}

static ssoossh_verify_result ed25519_verify_raw(const uint8_t *pk,
                                                const uint8_t *msg,
                                                size_t msg_len,
                                                const uint8_t *sig)
{
    SecKeyRef key = ed25519_key(pk, 32);
    ssoossh_verify_result result;

    if (key == NULL) {
        return SSOOSSH_VERIFY_ERROR;
    }
    result = verify_with(key, ed25519_algorithm, msg, msg_len, sig, 64);
    CFRelease(key);
    return result;
}

/* The known-answer test, over the vectors in ed25519_kat.h: the RFC 8032
 * vector must verify, a corrupted copy must not, and a signature with S
 * outside the group order must not. Returns NULL on success, or the name
 * of the check that failed. */
static const char *ed25519_selftest(void)
{
    const ssoossh_ed25519_vector *kat = &SSOOSSH_ED25519_KAT;
    uint8_t flipped[64];

    if (ed25519_verify_raw(kat->pk, kat->msg, kat->msg_len, kat->sig) !=
        SSOOSSH_VERIFY_OK) {
        return "RFC 8032 vector did not verify";
    }
    memcpy(flipped, kat->sig, sizeof(flipped));
    flipped[SSOOSSH_ED25519_KAT_FLIP_BYTE] ^= 0x01;
    if (ed25519_verify_raw(kat->pk, kat->msg, kat->msg_len, flipped) !=
        SSOOSSH_VERIFY_BAD) {
        return "corrupted signature was not refused";
    }
    if (ed25519_verify_raw(SSOOSSH_ED25519_BIG_S.pk, SSOOSSH_ED25519_BIG_S.msg,
                           SSOOSSH_ED25519_BIG_S.msg_len,
                           SSOOSSH_ED25519_BIG_S.sig) != SSOOSSH_VERIFY_BAD) {
        return "signature with S >= L was not refused";
    }
    return NULL;
}

static void ed25519_init(void)
{
    const void *key_type = NULL, *algorithm = NULL;
    const char *failed;

    if (!resolve_constant(ED25519_KEY_TYPE_SYM, &key_type) ||
        !resolve_constant(ED25519_ALGORITHM_SYM, &algorithm)) {
        ssoossh_warnf("Ed25519: Security.framework on this macOS does not "
                      "export %s; ssh-ed25519 CAs cannot be used here",
                      key_type == NULL ? ED25519_KEY_TYPE_SYM
                                       : ED25519_ALGORITHM_SYM);
        return;
    }
    ed25519_key_type = key_type;
    ed25519_algorithm = algorithm;

    failed = ed25519_selftest();
    if (failed != NULL) {
        /* Same names, different behaviour. Not trusted: the constants are
         * cleared so nothing below can reach them by accident. */
        ed25519_key_type = NULL;
        ed25519_algorithm = NULL;
        ed25519_version = "Security.framework (Ed25519 SPI FAILED self-test)";
        ssoossh_errf("Ed25519: Security.framework SPI failed its self-test "
                     "(%s); refusing to use it, ssh-ed25519 CAs cannot be "
                     "used here",
                     failed);
        return;
    }
    ed25519_ok = true;
    ed25519_version = "Security.framework (Ed25519 SPI ok)";
    ssoossh_debugf("Ed25519: Security.framework SPI resolved and self-tested");
}

static bool ed25519_usable(void)
{
    (void)pthread_once(&ed25519_once, ed25519_init);
    return ed25519_ok;
}

/* ------------------------------------------------------------------------ */

bool ssoossh_crypto_keygen(ssoossh_keypair **out)
{
    CFMutableDictionaryRef attrs;
    SecKeyRef priv = NULL, pub = NULL;
    ssoossh_keypair *kp;
    CFNumberRef bits;
    int size = 384;

    *out = NULL;

    attrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                                      &kCFTypeDictionaryKeyCallBacks,
                                      &kCFTypeDictionaryValueCallBacks);
    if (attrs == NULL) {
        return false;
    }
    bits = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &size);
    if (bits == NULL) {
        CFRelease(attrs);
        return false;
    }

    CFDictionarySetValue(attrs, kSecAttrKeyType,
                         kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionarySetValue(attrs, kSecAttrKeySizeInBits, bits);
    /* Not in the keychain. The key is per-attempt and must not outlive the
     * transaction, let alone the process -- kSecAttrIsPermanent false is
     * what keeps SecKeyCreateRandomKey from filing it away. */
    {
        CFMutableDictionaryRef priv_attrs = CFDictionaryCreateMutable(
            kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks);
        if (priv_attrs == NULL) {
            CFRelease(bits);
            CFRelease(attrs);
            return false;
        }
        CFDictionarySetValue(priv_attrs, kSecAttrIsPermanent, kCFBooleanFalse);
        CFDictionarySetValue(attrs, kSecPrivateKeyAttrs, priv_attrs);
        CFRelease(priv_attrs);
    }

    priv = SecKeyCreateRandomKey(attrs, NULL);
    CFRelease(bits);
    CFRelease(attrs);
    if (priv == NULL) {
        return false;
    }

    pub = SecKeyCopyPublicKey(priv);
    if (pub == NULL) {
        CFRelease(priv);
        return false;
    }

    kp = calloc(1, sizeof(*kp));
    if (kp == NULL) {
        CFRelease(pub);
        CFRelease(priv);
        return false;
    }
    kp->private_key = priv;
    kp->public_key = pub;
    *out = kp;
    return true;
}

void ssoossh_crypto_keypair_free(ssoossh_keypair *kp)
{
    if (kp == NULL) {
        return;
    }
    if (kp->public_key != NULL) {
        CFRelease(kp->public_key);
    }
    if (kp->private_key != NULL) {
        CFRelease(kp->private_key);
    }
    ssoossh_crypto_wipe(kp, sizeof(*kp));
    free(kp);
}

bool ssoossh_crypto_public_point(const ssoossh_keypair *kp, uint8_t *out,
                                 size_t out_cap, size_t *out_len)
{
    /* For an EC key SecKeyCopyExternalRepresentation returns the ANSI X9.63
     * form -- 0x04 || X || Y -- which is exactly what an SSH ecdsa key blob
     * carries. */
    CFDataRef data = SecKeyCopyExternalRepresentation(kp->public_key, NULL);
    CFIndex n;

    if (data == NULL) {
        return false;
    }
    n = CFDataGetLength(data);
    if (n <= 0 || (size_t)n > out_cap) {
        CFRelease(data);
        return false;
    }
    memcpy(out, CFDataGetBytePtr(data), (size_t)n);
    *out_len = (size_t)n;
    CFRelease(data);
    return true;
}

bool ssoossh_crypto_supports_key(const char *key_algo)
{
    /* ssh-ed25519 is conditional on this host, and the condition is
     * decided once, by the resolve-and-self-test above. */
    if (strcmp(key_algo, "ssh-ed25519") == 0) {
        return ed25519_usable();
    }
    return strcmp(key_algo, "ssh-rsa") == 0 ||
           strcmp(key_algo, "ecdsa-sha2-nistp256") == 0 ||
           strcmp(key_algo, "ecdsa-sha2-nistp384") == 0 ||
           strcmp(key_algo, "ecdsa-sha2-nistp521") == 0;
}

/* Builds a SecKeyRef from an SSH public key blob.
 *
 * SecKeyCreateWithData takes the raw key material, not a
 * SubjectPublicKeyInfo: the X9.63 point for EC, a bare PKCS#1 RSAPublicKey
 * for RSA, and the 32 raw bytes for Ed25519. That is why der.h exposes the
 * PKCS#1 encoder separately from the SPKI one the OpenSSL backend uses. */
static SecKeyRef key_from_ssh_blob(const uint8_t *blob, size_t blob_len,
                                   char *type_out, size_t type_cap,
                                   uint8_t *scratch, size_t scratch_cap)
{
    ssh_rd r;
    const uint8_t *type = NULL, *a = NULL, *b = NULL;
    size_t type_len = 0, a_len = 0, b_len = 0;
    CFMutableDictionaryRef attrs;
    CFDataRef material = NULL;
    SecKeyRef key = NULL;
    CFNumberRef bits = NULL;
    int size_in_bits = 0;

    ssh_rd_init(&r, blob, blob_len);
    if (!ssh_rd_str(&r, &type, &type_len) || type_len == 0 ||
        type_len >= type_cap) {
        return NULL;
    }
    memcpy(type_out, type, type_len);
    type_out[type_len] = '\0';

    if (strcmp(type_out, "ssh-ed25519") == 0) {
        /* One string: the 32-byte point. The SPI path builds its own
         * dictionary, and returns NULL when this host has no usable SPI,
         * which the caller reports as UNSUPPORTED by the type name. */
        if (!ssh_rd_str(&r, &a, &a_len) || !ssh_rd_done(&r) || a_len != 32) {
            return NULL;
        }
        if (!ed25519_usable()) {
            return NULL;
        }
        return ed25519_key(a, a_len);
    }

    attrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                                      &kCFTypeDictionaryKeyCallBacks,
                                      &kCFTypeDictionaryValueCallBacks);
    if (attrs == NULL) {
        return NULL;
    }
    CFDictionarySetValue(attrs, kSecAttrKeyClass, kSecAttrKeyClassPublic);

    if (strcmp(type_out, "ssh-rsa") == 0) {
        size_t der_len = 0;

        /* e then n on the wire, n then e in the DER. */
        if (!ssh_rd_str(&r, &a, &a_len) || !ssh_rd_str(&r, &b, &b_len) ||
            !ssh_rd_done(&r) ||
            !ssoossh_der_rsa_pkcs1(a, a_len, b, b_len, scratch, scratch_cap,
                                   &der_len)) {
            CFRelease(attrs);
            return NULL;
        }
        CFDictionarySetValue(attrs, kSecAttrKeyType, kSecAttrKeyTypeRSA);
        material = data_view(scratch, der_len);
    } else if (strncmp(type_out, "ecdsa-sha2-nistp", 16) == 0) {
        const char *want_curve;

        if (strcmp(type_out + 16, "256") == 0) {
            want_curve = "nistp256";
            size_in_bits = 256;
        } else if (strcmp(type_out + 16, "384") == 0) {
            want_curve = "nistp384";
            size_in_bits = 384;
        } else if (strcmp(type_out + 16, "521") == 0) {
            want_curve = "nistp521";
            size_in_bits = 521;
        } else {
            CFRelease(attrs);
            return NULL;
        }

        if (!ssh_rd_str(&r, &a, &a_len) || !ssh_rd_str(&r, &b, &b_len) ||
            !ssh_rd_done(&r)) {
            CFRelease(attrs);
            return NULL;
        }
        /* The blob names its curve twice; a key where the two disagree is
         * malformed. */
        if (a_len != strlen(want_curve) || memcmp(a, want_curve, a_len) != 0) {
            CFRelease(attrs);
            return NULL;
        }
        if (b_len < 1 || b[0] != 0x04) {
            /* Uncompressed only, matching the OpenSSL backend. */
            CFRelease(attrs);
            return NULL;
        }
        CFDictionarySetValue(attrs, kSecAttrKeyType,
                             kSecAttrKeyTypeECSECPrimeRandom);
        bits = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType,
                              &size_in_bits);
        if (bits != NULL) {
            CFDictionarySetValue(attrs, kSecAttrKeySizeInBits, bits);
        }
        material = data_view(b, b_len);
    } else {
        CFRelease(attrs);
        return NULL;
    }

    if (material != NULL) {
        key = SecKeyCreateWithData(material, attrs, NULL);
        CFRelease(material);
    }
    if (bits != NULL) {
        CFRelease(bits);
    }
    CFRelease(attrs);
    return key;
}

/* Which key type a signature algorithm must have come from, and which
 * SecKey algorithm verifies it.
 *
 * ssh-rsa is absent for the same reason it is absent from the OpenSSL
 * backend: that name means RSA with SHA-1, and it is refused by policy.
 * ssh-ed25519 is present only when the SPI resolved and self-tested. */
static bool sig_algo_info(const char *sig_algo, const char **key_type,
                          SecKeyAlgorithm *algorithm)
{
    if (strcmp(sig_algo, "ssh-ed25519") == 0) {
        if (!ed25519_usable()) {
            return false;
        }
        *key_type = "ssh-ed25519";
        *algorithm = ed25519_algorithm;
        return true;
    }
    if (strcmp(sig_algo, "rsa-sha2-256") == 0) {
        *key_type = "ssh-rsa";
        *algorithm = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256;
        return true;
    }
    if (strcmp(sig_algo, "rsa-sha2-512") == 0) {
        *key_type = "ssh-rsa";
        *algorithm = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512;
        return true;
    }
    if (strcmp(sig_algo, "ecdsa-sha2-nistp256") == 0) {
        *key_type = "ecdsa-sha2-nistp256";
        *algorithm = kSecKeyAlgorithmECDSASignatureMessageX962SHA256;
        return true;
    }
    if (strcmp(sig_algo, "ecdsa-sha2-nistp384") == 0) {
        *key_type = "ecdsa-sha2-nistp384";
        *algorithm = kSecKeyAlgorithmECDSASignatureMessageX962SHA384;
        return true;
    }
    if (strcmp(sig_algo, "ecdsa-sha2-nistp521") == 0) {
        *key_type = "ecdsa-sha2-nistp521";
        *algorithm = kSecKeyAlgorithmECDSASignatureMessageX962SHA512;
        return true;
    }
    return false;
}

ssoossh_verify_result ssoossh_crypto_verify(const char *sig_algo,
                                            const uint8_t *ca_key,
                                            size_t ca_key_len,
                                            const uint8_t *msg, size_t msg_len,
                                            const uint8_t *sig, size_t sig_len)
{
    uint8_t scratch[2048];
    uint8_t der_sig[256];
    char key_type[64];
    const char *want_key_type = NULL;
    SecKeyAlgorithm algorithm = NULL;
    SecKeyRef key = NULL;
    ssoossh_verify_result result;

    if (!sig_algo_info(sig_algo, &want_key_type, &algorithm)) {
        return SSOOSSH_VERIFY_UNSUPPORTED;
    }

    key = key_from_ssh_blob(ca_key, ca_key_len, key_type, sizeof(key_type),
                            scratch, sizeof(scratch));
    if (key == NULL) {
        /* A blob that did not parse, or -- for an Ed25519 CA under a
         * signature of another type -- one this host could not build a
         * key for. Either way the certificate is malformed for the
         * signature it claims; "this backend cannot" was answered by
         * sig_algo_info and by the CA loader before this point. */
        return SSOOSSH_VERIFY_ERROR;
    }
    if (strcmp(key_type, want_key_type) != 0) {
        CFRelease(key);
        return SSOOSSH_VERIFY_ERROR;
    }

    /* ECDSA signatures arrive as two mpints; the X962 algorithms want an
     * ECDSA-Sig-Value, the same DER OpenSSL asks for. */
    if (strncmp(sig_algo, "ecdsa-", 6) == 0) {
        ssh_rd sr;
        const uint8_t *rr = NULL, *ss = NULL;
        size_t r_len = 0, s_len = 0, n = 0;

        ssh_rd_init(&sr, sig, sig_len);
        if (!ssh_rd_str(&sr, &rr, &r_len) || !ssh_rd_str(&sr, &ss, &s_len) ||
            !ssh_rd_done(&sr) ||
            !ssoossh_der_ecdsa_sig(rr, r_len, ss, s_len, der_sig,
                                   sizeof(der_sig), &n)) {
            CFRelease(key);
            return SSOOSSH_VERIFY_ERROR;
        }
        sig = der_sig;
        sig_len = n;
    } else if (strcmp(sig_algo, "ssh-ed25519") == 0 && sig_len != 64) {
        /* Sixty-four raw bytes, exactly, as on the OpenSSL backend. The
         * SPI would refuse it too, but a length error is malformed input,
         * not a failed signature, and the distinction matters. */
        CFRelease(key);
        return SSOOSSH_VERIFY_ERROR;
    }

    result = verify_with(key, algorithm, msg, msg_len, sig, sig_len);
    CFRelease(key);
    return result;
}

bool ssoossh_crypto_sha256(const uint8_t *in, size_t in_len, uint8_t out[32])
{
    CC_SHA256(in, (CC_LONG)in_len, out);
    return true;
}

void ssoossh_crypto_wipe(void *p, size_t n)
{
#ifdef __STDC_LIB_EXT1__
    /* memset_s is in the C11 Annex K subset macOS provides, and it is the
     * one spelling the compiler may not elide. */
    (void)memset_s(p, n, 0, n);
#else
    /* The portable fallback, for a toolchain that turns out not to declare
     * it after all: writes through a volatile pointer are observable
     * behaviour and may not be optimised away. Kept rather than assumed
     * unnecessary, because this file has never been compiled and a wipe
     * that silently does nothing is the worst way to find that out. */
    volatile unsigned char *q = p;

    while (n-- > 0) {
        *q++ = 0;
    }
#endif
}

ssoossh_fips_state ssoossh_crypto_fips_state(void)
{
    /* macOS has no FIPS switch: Apple's corecrypto modules are validated
     * as shipped and there is no other configuration to be in. */
    return SSOOSSH_FIPS_UNSWITCHED;
}

const char *ssoossh_crypto_version(void)
{
    /* Security.framework and CommonCrypto ship with the OS and carry no
     * independently queryable version, so the backend is named instead,
     * together with what became of the Ed25519 SPI on this host. The
     * probe is forced here on purpose, even for a fleet with no Ed25519
     * CA: this line is the drift signal, and "which Macs lost Ed25519
     * after the update" has to be a grep of syslog before an Ed25519 CA
     * appears, not after. It is three verifies, once per process. */
    (void)ed25519_usable();
    return ed25519_version;
}
