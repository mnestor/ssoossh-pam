/* The minimum DER this module needs, which is four shapes.
 *
 * Two of them are what the plan anticipated: an ECDSA-Sig-Value built from
 * the r and s an SSH signature packs separately, and an RSA public key from
 * the e and n an SSH key blob packs separately.
 *
 * The other two are a deviation from the plan worth stating plainly. The
 * plan expected each crypto backend to build an EVP_PKEY from raw
 * components, guarded per OpenSSL version -- EC_KEY_oct2point and
 * RSA_set0_key on 1.1.1, EVP_PKEY_fromdata on 3.0. Encoding a
 * SubjectPublicKeyInfo here instead and handing it to d2i_PUBKEY replaces
 * both with one path: d2i_PUBKEY is present and undeprecated on 1.1.1 and
 * on 3.x alike, and it is the same call for EC, RSA and Ed25519. That
 * removes the version guard from the file that verifies certificates as
 * root, which is the file where a second, rarely-compiled code path was
 * least welcome. The 1.1.1 floor itself is unchanged and still enforced at
 * compile time.
 *
 * Everything here writes; nothing here parses. DER parsing of
 * attacker-controlled bytes stays inside OpenSSL, which has had rather more
 * review than this file will get.
 */
#ifndef PAM_SSOOSSH_DER_H
#define PAM_SSOOSSH_DER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* SEQUENCE { INTEGER r, INTEGER s } -- what OpenSSL's ECDSA verifier
 * expects, from what an SSH signature blob actually carries. */
bool ssoossh_der_ecdsa_sig(const uint8_t *r, size_t r_len, const uint8_t *s,
                           size_t s_len, uint8_t *out, size_t out_cap,
                           size_t *out_len);

/* Named curves, by the OID a SubjectPublicKeyInfo carries. */
typedef enum {
    SSOOSSH_CURVE_P256,
    SSOOSSH_CURVE_P384,
    SSOOSSH_CURVE_P521,
} ssoossh_curve;

/* SPKI for an EC public key, from the uncompressed point an SSH key blob
 * carries. */
bool ssoossh_der_spki_ec(ssoossh_curve curve, const uint8_t *point,
                         size_t point_len, uint8_t *out, size_t out_cap,
                         size_t *out_len);

/* SPKI for an RSA public key, from the SSH blob's e and n. */
bool ssoossh_der_spki_rsa(const uint8_t *e, size_t e_len, const uint8_t *n,
                          size_t n_len, uint8_t *out, size_t out_cap,
                          size_t *out_len);

/* SPKI for an Ed25519 public key, from the 32 raw bytes. */
bool ssoossh_der_spki_ed25519(const uint8_t *key, size_t key_len, uint8_t *out,
                              size_t out_cap, size_t *out_len);

#endif /* PAM_SSOOSSH_DER_H */
