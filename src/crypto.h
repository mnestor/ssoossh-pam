/* The crypto seam.
 *
 * Everything above this line -- the wire reader, the certificate parser,
 * the four checks -- is identical on every platform. Everything below it is
 * whatever the operating system already ships: OpenSSL on Linux and
 * FreeBSD, Security.framework and CommonCrypto on macOS. There is no
 * third-party crypto library to install, vendor, or track advisories for on
 * any target.
 *
 * The seam is deliberately small. Five operations is what a module that
 * generates one ephemeral key and verifies one signature actually needs,
 * and every operation one backend has to implement is one more place the
 * two can disagree about a certificate.
 */
#ifndef PAM_SSOOSSH_CRYPTO_H
#define PAM_SSOOSSH_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The per-attempt keypair. Opaque: the private half never leaves the
 * backend, and nothing above this header can accidentally copy it
 * somewhere it would not be wiped. */
typedef struct ssoossh_keypair ssoossh_keypair;

/* Generates the per-attempt keypair: always ECDSA P-384, which every
 * backend supports and which is the shared FIPS-approved default the Go
 * module used. PAM has no configuration surface for key type, so there is
 * no operator setting to honour here. */
bool ssoossh_crypto_keygen(ssoossh_keypair **out);

/* Frees the keypair, wiping the private half first. Safe on NULL. */
void ssoossh_crypto_keypair_free(ssoossh_keypair *kp);

/* Writes the public key as an uncompressed X9.62 point (0x04 || X || Y),
 * which is what an SSH ecdsa key blob carries. */
bool ssoossh_crypto_public_point(const ssoossh_keypair *kp, uint8_t *out,
                                 size_t out_cap, size_t *out_len);

typedef enum {
    /* The signature is by this key over these bytes. */
    SSOOSSH_VERIFY_OK,
    /* Cryptographically checked and wrong. */
    SSOOSSH_VERIFY_BAD,
    /* This backend cannot verify this algorithm at all -- Ed25519 on
     * macOS -- or will not, as with SHA-1 RSA. Distinct from BAD because
     * the operator needs to be told the algorithm is the problem, not the
     * key. */
    SSOOSSH_VERIFY_UNSUPPORTED,
    /* The key or signature blob is malformed. */
    SSOOSSH_VERIFY_ERROR,
} ssoossh_verify_result;

/* Verifies sig over msg using the SSH-format public key in ca_key.
 *
 * sig_algo is the algorithm named by the signature blob, not by the key:
 * an RSA key signs as rsa-sha2-256 or rsa-sha2-512, and which one it was is
 * only knowable from the signature. sig is the signature blob's body, in
 * whatever shape that algorithm packs -- two mpints for ECDSA, 64 raw bytes
 * for Ed25519, a PKCS#1 v1.5 block for RSA.
 *
 * A key whose own type disagrees with sig_algo is SSOOSSH_VERIFY_ERROR
 * rather than BAD: it is a malformed certificate, not a failed check. */
ssoossh_verify_result ssoossh_crypto_verify(const char *sig_algo,
                                            const uint8_t *ca_key,
                                            size_t ca_key_len,
                                            const uint8_t *msg, size_t msg_len,
                                            const uint8_t *sig, size_t sig_len);

/* Whether a CA key of this blob type can be used on this backend at all.
 * Called when loading trusted-ca-file, so an unusable key is skipped with a
 * warning naming its algorithm instead of failing later as a mysterious
 * signature mismatch. */
bool ssoossh_crypto_supports_key(const char *key_algo);

/* SHA-256, for the SHA256: fingerprints in log lines. */
bool ssoossh_crypto_sha256(const uint8_t *in, size_t in_len, uint8_t out[32]);

/* Overwrites memory in a way the compiler may not elide. */
void ssoossh_crypto_wipe(void *p, size_t n);

/* Names the crypto actually linked into this process, for the version line
 * every authentication logs. This is the fleet's only answer to "which
 * OpenSSL is really resident in sudo on that host". */
const char *ssoossh_crypto_version(void);

#endif /* PAM_SSOOSSH_CRYPTO_H */
