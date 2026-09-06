/* The parts of a crypto backend that are not about crypto.
 *
 * crypto.h is the seam between the module and whichever library verifies a
 * signature. This is the seam's other side: the facts about SSH's wire
 * encoding that both backends need and neither should own -- which key type
 * a signature algorithm implies, and how an SSH signature becomes the DER
 * an X.509 library wants. Written twice, they were already drifting; a
 * certificate must mean the same thing on both platforms, and one copy is
 * how it does.
 *
 * Everything genuinely platform-specific -- building a key object, choosing
 * a digest constant, deciding whether Ed25519 is available here -- stays in
 * the backend.
 */
#ifndef PAM_SSOOSSH_CRYPTO_COMMON_H
#define PAM_SSOOSSH_CRYPTO_COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Whether this host can verify with Ed25519. Implemented by each backend:
 * on OpenSSL it is a version-and-FIPS question, on macOS it is whether an
 * SPI resolved and passed its self-test. Both answer it once and cache it.
 */
bool ssoossh_crypto_ed25519_usable(void);

/* The key type a signature algorithm must have been produced by, or NULL
 * for one no backend accepts.
 *
 * ssh-rsa is absent on purpose. That algorithm name means RSA with SHA-1,
 * which OpenSSH has refused by default since 8.8; x/crypto/ssh still
 * verifies it, so the Go module accepts such a CA today and this one does
 * not. ssh-ed25519 is present only where the backend says it is usable.
 * The caller turns a NULL into an error naming the algorithm, so an
 * operator learns the key type is the problem rather than reading "not
 * signed by a trusted CA". */
const char *ssoossh_sig_algo_key_type(const char *sig_algo);

/* Re-encodes an SSH ECDSA signature -- two mpints -- as the
 * ECDSA-Sig-Value both OpenSSL and Security.framework ask for. */
bool ssoossh_ecdsa_sig_to_der(const uint8_t *sig, size_t sig_len, uint8_t *out,
                              size_t out_cap, size_t *out_len);

#endif /* PAM_SSOOSSH_CRYPTO_COMMON_H */
