#include "der.h"

#include <string.h>

/* A write cursor with the same latched-failure discipline as ssh_wr: an
 * overflow poisons the rest and the caller checks once. */
typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t len;
    bool bad;
} der_wr;

static void der_init(der_wr *w, uint8_t *buf, size_t cap)
{
    w->buf = buf;
    w->cap = cap;
    w->len = 0;
    w->bad = false;
}

static void der_raw(der_wr *w, const uint8_t *p, size_t n)
{
    if (w->bad || n > w->cap - w->len) {
        w->bad = true;
        return;
    }
    memcpy(w->buf + w->len, p, n);
    w->len += n;
}

static void der_byte(der_wr *w, uint8_t b)
{
    der_raw(w, &b, 1);
}

/* DER length: short form below 128, long form above, with no leading zero
 * in the length bytes. The definite-length long form beyond three bytes is
 * not written because nothing here is that big -- an 8192-bit RSA modulus
 * is 1024 bytes. */
static void der_len(der_wr *w, size_t n)
{
    if (n < 0x80) {
        der_byte(w, (uint8_t)n);
    } else if (n <= 0xff) {
        der_byte(w, 0x81);
        der_byte(w, (uint8_t)n);
    } else if (n <= 0xffff) {
        der_byte(w, 0x82);
        der_byte(w, (uint8_t)(n >> 8));
        der_byte(w, (uint8_t)n);
    } else {
        w->bad = true;
    }
}

static void der_tlv(der_wr *w, uint8_t tag, const uint8_t *content, size_t n)
{
    der_byte(w, tag);
    der_len(w, n);
    der_raw(w, content, n);
}

/* INTEGER from a big-endian magnitude: leading zero bytes dropped, and a
 * zero byte prepended when the top bit is set so the value does not read as
 * negative. The same normalization an SSH mpint has, in a different
 * encoding -- which is exactly why a signature has to be re-encoded rather
 * than passed through. */
static void der_integer(der_wr *w, const uint8_t *p, size_t n)
{
    size_t i = 0;

    while (i < n && p[i] == 0) {
        i++;
    }
    if (i == n) {
        static const uint8_t zero = 0;
        der_tlv(w, 0x02, &zero, 1);
        return;
    }
    if (p[i] & 0x80) {
        der_byte(w, 0x02);
        der_len(w, n - i + 1);
        der_byte(w, 0x00);
        der_raw(w, p + i, n - i);
        return;
    }
    der_tlv(w, 0x02, p + i, n - i);
}

/* BIT STRING with no unused bits, which is the only kind a key encoding
 * uses. */
static void der_bitstring(der_wr *w, const uint8_t *p, size_t n)
{
    der_byte(w, 0x03);
    der_len(w, n + 1);
    der_byte(w, 0x00);
    der_raw(w, p, n);
}

static bool der_finish(const der_wr *w, size_t *out_len)
{
    if (w->bad) {
        return false;
    }
    *out_len = w->len;
    return true;
}

bool ssoossh_der_ecdsa_sig(const uint8_t *r, size_t r_len, const uint8_t *s,
                           size_t s_len, uint8_t *out, size_t out_cap,
                           size_t *out_len)
{
    /* Two P-521 integers with sign padding and headers: 2 * (2 + 1 + 66)
     * plus the outer header. 256 is comfortable and fixed. */
    uint8_t body[256];
    der_wr in, w;
    size_t body_len;

    der_init(&in, body, sizeof(body));
    der_integer(&in, r, r_len);
    der_integer(&in, s, s_len);
    if (!der_finish(&in, &body_len)) {
        return false;
    }

    der_init(&w, out, out_cap);
    der_tlv(&w, 0x30, body, body_len);
    return der_finish(&w, out_len);
}

/* OIDs, as complete TLVs so the assembly below is a memcpy rather than a
 * length calculation. */
static const uint8_t oid_ec_public_key[] = {0x06, 0x07, 0x2a, 0x86, 0x48,
                                            0xce, 0x3d, 0x02, 0x01};
static const uint8_t oid_p256[] = {0x06, 0x08, 0x2a, 0x86, 0x48,
                                   0xce, 0x3d, 0x03, 0x01, 0x07};
static const uint8_t oid_p384[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22};
static const uint8_t oid_p521[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23};
static const uint8_t oid_rsa[] = {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                                  0xf7, 0x0d, 0x01, 0x01, 0x01};
static const uint8_t oid_ed25519[] = {0x06, 0x03, 0x2b, 0x65, 0x70};
static const uint8_t asn1_null[] = {0x05, 0x00};

/* SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier,
 *                                     subjectPublicKey BIT STRING } */
static bool spki(const uint8_t *alg, size_t alg_len, const uint8_t *params,
                 size_t params_len, const uint8_t *key, size_t key_len,
                 uint8_t *out, size_t out_cap, size_t *out_len)
{
    uint8_t alg_id[64];
    uint8_t body[2048];
    der_wr a, b, w;
    size_t alg_id_len, body_len;

    der_init(&a, alg_id, sizeof(alg_id));
    der_raw(&a, alg, alg_len);
    if (params != NULL) {
        der_raw(&a, params, params_len);
    }
    if (!der_finish(&a, &alg_id_len)) {
        return false;
    }

    der_init(&b, body, sizeof(body));
    der_tlv(&b, 0x30, alg_id, alg_id_len);
    der_bitstring(&b, key, key_len);
    if (!der_finish(&b, &body_len)) {
        return false;
    }

    der_init(&w, out, out_cap);
    der_tlv(&w, 0x30, body, body_len);
    return der_finish(&w, out_len);
}

bool ssoossh_der_spki_ec(ssoossh_curve curve, const uint8_t *point,
                         size_t point_len, uint8_t *out, size_t out_cap,
                         size_t *out_len)
{
    const uint8_t *oid;
    size_t oid_len;

    switch (curve) {
    case SSOOSSH_CURVE_P256:
        oid = oid_p256;
        oid_len = sizeof(oid_p256);
        break;
    case SSOOSSH_CURVE_P384:
        oid = oid_p384;
        oid_len = sizeof(oid_p384);
        break;
    case SSOOSSH_CURVE_P521:
        oid = oid_p521;
        oid_len = sizeof(oid_p521);
        break;
    default:
        return false;
    }

    /* Only the uncompressed form. OpenSSH does not emit compressed points
     * and accepting them here would mean two encodings of one key, which a
     * fingerprint comparison cannot survive. */
    if (point_len < 1 || point[0] != 0x04) {
        return false;
    }

    return spki(oid_ec_public_key, sizeof(oid_ec_public_key), oid, oid_len,
                point, point_len, out, out_cap, out_len);
}

bool ssoossh_der_spki_rsa(const uint8_t *e, size_t e_len, const uint8_t *n,
                          size_t n_len, uint8_t *out, size_t out_cap,
                          size_t *out_len)
{
    /* RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
     * -- note the order is n then e, the reverse of the SSH blob's. */
    uint8_t inner[1200];
    uint8_t key[1216];
    der_wr i, k;
    size_t inner_len, key_len;

    der_init(&i, inner, sizeof(inner));
    der_integer(&i, n, n_len);
    der_integer(&i, e, e_len);
    if (!der_finish(&i, &inner_len)) {
        return false;
    }

    der_init(&k, key, sizeof(key));
    der_tlv(&k, 0x30, inner, inner_len);
    if (!der_finish(&k, &key_len)) {
        return false;
    }

    /* RSA's AlgorithmIdentifier carries an explicit NULL parameter; the EC
     * one carries the curve OID and Ed25519's carries nothing at all. */
    return spki(oid_rsa, sizeof(oid_rsa), asn1_null, sizeof(asn1_null), key,
                key_len, out, out_cap, out_len);
}

bool ssoossh_der_spki_ed25519(const uint8_t *key, size_t key_len, uint8_t *out,
                              size_t out_cap, size_t *out_len)
{
    if (key_len != 32) {
        return false;
    }
    return spki(oid_ed25519, sizeof(oid_ed25519), NULL, 0, key, key_len, out,
                out_cap, out_len);
}
