/* The Security.framework and CommonCrypto backend: macOS.
 *
 * System SSL is not an option here. macOS ships LibreSSL as a dylib, but the
 * SDK exposes no openssl/*.h and no linkable stub, and Apple does not
 * support third-party linking against it. That leaves Homebrew's openssl@3
 * or Apple's own APIs, and Apple's own win: a module that links only what
 * the OS ships has no install-time dependency, no second copy of a TLS stack
 * in a root process, and no third-party CVE surface to track.
 *
 * One capability gap comes with that, and it is documented rather than
 * worked around: SecKey has no Ed25519. Apple's implementation is in
 * CryptoKit, which is Swift-only with no C API. So an ssh-ed25519 CA cannot
 * be used on macOS, ssoossh_crypto_supports_key says so, and a certificate
 * signed by one is refused with an error naming the algorithm rather than a
 * bare signature failure.
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

#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "der.h"
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
    /* ssh-ed25519 is absent, and that absence is the capability matrix. */
    return strcmp(key_algo, "ssh-rsa") == 0 ||
           strcmp(key_algo, "ecdsa-sha2-nistp256") == 0 ||
           strcmp(key_algo, "ecdsa-sha2-nistp384") == 0 ||
           strcmp(key_algo, "ecdsa-sha2-nistp521") == 0;
}

/* Builds a SecKeyRef from an SSH public key blob.
 *
 * SecKeyCreateWithData takes the raw key material, not a
 * SubjectPublicKeyInfo: the X9.63 point for EC, and a bare PKCS#1
 * RSAPublicKey for RSA. That is why der.h exposes the PKCS#1 encoder
 * separately from the SPKI one the OpenSSL backend uses. */
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
        /* ssh-ed25519 lands here, which is the documented gap. */
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
 * backend: that name means RSA with SHA-1, and it is refused by policy. */
static bool sig_algo_info(const char *sig_algo, const char **key_type,
                          SecKeyAlgorithm *algorithm)
{
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
    CFDataRef signed_data = NULL, signature = NULL;
    ssoossh_verify_result result = SSOOSSH_VERIFY_ERROR;

    if (!sig_algo_info(sig_algo, &want_key_type, &algorithm)) {
        return SSOOSSH_VERIFY_UNSUPPORTED;
    }

    key = key_from_ssh_blob(ca_key, ca_key_len, key_type, sizeof(key_type),
                            scratch, sizeof(scratch));
    if (key == NULL) {
        /* Distinguish "this backend cannot" from "that is not a key", so
         * the operator is told which. */
        if (strcmp(key_type, "ssh-ed25519") == 0) {
            return SSOOSSH_VERIFY_UNSUPPORTED;
        }
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
    }

    signed_data = data_view(msg, msg_len);
    signature = data_view(sig, sig_len);
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

const char *ssoossh_crypto_version(void)
{
    /* Security.framework and CommonCrypto ship with the OS and carry no
     * independently queryable version, so the backend is named instead. An
     * operator grepping syslog for "which crypto is in sudo here" gets an
     * answer either way; on this platform the answer is "whatever this
     * macOS is". */
    return "Security.framework";
}
