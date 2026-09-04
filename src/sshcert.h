/* OpenSSH certificate parsing and signature verification.
 *
 * This is the code that runs as root on bytes a network peer chose, so it
 * is written to a narrower standard than the rest of the module: every
 * field is read through sshwire.c, nothing here does pointer arithmetic,
 * nothing here allocates, and every field that a caller reads back is a
 * borrowed slice of the caller's own buffer.
 *
 * That last point is the ownership rule and it is load-bearing: an
 * ssoossh_cert is only valid while the blob it was parsed from is. The
 * struct is a set of offsets into somebody else's memory, which is exactly
 * why it cannot leak.
 */
#ifndef PAM_SSOOSSH_SSHCERT_H
#define PAM_SSOOSSH_SSHCERT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "crypto.h"
#include "sshkey.h"

/* A certificate larger than this is not a certificate. Real ones are two
 * or three kilobytes; the cap is here because this runs inside sudo. */
#define SSOOSSH_MAX_CERT (32 * 1024)

/* Base64 of the above, plus the type prefix and a newline. */
#define SSOOSSH_MAX_CERT_LINE (SSOOSSH_MAX_CERT * 4 / 3 + 128)

/* More principals than any certificate this server issues, and few enough
 * that the array is cheap to carry. A certificate with more is refused
 * rather than truncated -- silently ignoring principals would be silently
 * changing the answer to check 3. */
#define SSOOSSH_MAX_PRINCIPALS 64

/* A length-delimited slice borrowed from the certificate blob. */
typedef struct {
    const uint8_t *p;
    size_t len;
} ssoossh_slice;

typedef struct {
    /* The certificate's own algorithm name, e.g.
     * "ecdsa-sha2-nistp384-cert-v01@openssh.com". */
    char algo[64];

    /* The subject key, rebuilt as an ordinary SSH public key blob so it can
     * be compared byte for byte against the key this attempt generated.
     * Rebuilt by prepending the base algorithm name to the certificate's
     * own key fields rather than by re-encoding them, so the result is
     * necessarily what OpenSSH would have written. */
    uint8_t key_blob[SSOOSSH_MAX_KEY_BLOB];
    size_t key_blob_len;

    uint64_t serial;
    uint32_t type; /* 1 user, 2 host */

    ssoossh_slice key_id;
    ssoossh_slice principals[SSOOSSH_MAX_PRINCIPALS];
    size_t principal_count;

    uint64_t valid_after;
    uint64_t valid_before;

    /* The CA key that signed it, as an SSH public key blob. */
    ssoossh_slice signature_key;

    /* The algorithm the signature names, which is not always the CA key's
     * own type: an RSA key signs as rsa-sha2-256 or rsa-sha2-512, and only
     * the signature says which. */
    char signature_algo[64];
    ssoossh_slice signature;

    /* Exactly the bytes the CA signed: blob[0 .. signed_len). Captured as
     * an offset during the single parse pass, which is what replaces the
     * Go implementation's copy-clear-marshal-trim reconstruction. */
    size_t signed_len;
    const uint8_t *blob;
} ssoossh_cert;

typedef enum {
    SSOOSSH_CERT_OK = 0,
    /* Truncated, over-long, self-inconsistent, or carrying trailing bytes.
     * One code, because none of them is a certificate. */
    SSOOSSH_CERT_MALFORMED,
    /* A well-formed certificate of a key type this module does not handle. */
    SSOOSSH_CERT_UNSUPPORTED,
} ssoossh_cert_status;

/* Parses a decoded certificate blob. out borrows from blob, which must
 * outlive it. */
ssoossh_cert_status ssoossh_cert_parse(const uint8_t *blob, size_t blob_len,
                                       ssoossh_cert *out);

/* Parses one authorized_keys-format certificate line -- which is what
 * ssoosshd returns in its JSON -- decoding the base64 into scratch. out
 * borrows from scratch. */
ssoossh_cert_status ssoossh_cert_parse_line(const char *line, size_t line_len,
                                            uint8_t *scratch,
                                            size_t scratch_cap,
                                            ssoossh_cert *out);

/* Verifies the certificate's signature against one candidate CA key.
 *
 * SSOOSSH_VERIFY_UNSUPPORTED covers both "this backend cannot do that
 * algorithm" and "this module refuses that algorithm", the second being
 * ssh-rsa: that name means RSA with SHA-1, which OpenSSH has disabled by
 * default since 8.8. x/crypto/ssh still verifies it, so the Go module
 * accepts such a certificate today and this one does not. Callers report
 * the algorithm by name rather than as a generic signature failure. */
ssoossh_verify_result ssoossh_cert_verify(const ssoossh_cert *cert,
                                          const uint8_t *ca_blob,
                                          size_t ca_blob_len);

/* Whether the certificate's principals include name. */
bool ssoossh_cert_has_principal(const ssoossh_cert *cert, const char *name);

#endif /* PAM_SSOOSSH_SSHCERT_H */
