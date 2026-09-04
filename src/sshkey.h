/* SSH public keys: the per-attempt key this module generates, and the CA
 * keys it loads out of trusted-ca-file.
 *
 * Everything here works in the authorized_keys encoding, because that is
 * what both ends of the wire speak: the module sends its public key as an
 * authorized_keys line and ssoosshd returns a certificate as one.
 */
#ifndef PAM_SSOOSSH_SSHKEY_H
#define PAM_SSOOSSH_SSHKEY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "crypto.h"

/* An RSA-8192 CA key blob is about 1 KiB. 2 KiB leaves room without
 * inviting a file to hold something that is not a key. */
#define SSOOSSH_MAX_KEY_BLOB 2048

/* An authorized_keys line for the biggest blob above, base64 and all. */
#define SSOOSSH_MAX_KEY_LINE 3072

/* Enough CA keys for any rotation an operator is actually performing.
 * Loading stops here rather than growing, and says so. */
#define SSOOSSH_MAX_CAS 32

/* "SHA256:" plus 43 base64 characters plus a NUL. */
#define SSOOSSH_FINGERPRINT_LEN 52

/* Builds the SSH public key blob for a P-384 point:
 *   string "ecdsa-sha2-nistp384", string "nistp384", string point */
bool ssoossh_sshkey_blob_p384(const uint8_t *point, size_t point_len,
                              uint8_t *out, size_t out_cap, size_t *out_len);

/* Renders a key blob as an authorized_keys line: "<type> <base64>\n".
 *
 * The trailing newline is not decoration -- Go's ssh.MarshalAuthorizedKey
 * emits one, and the Go module sends its result as the public_key field
 * verbatim. Byte-for-byte wire parity means sending it too. */
bool ssoossh_sshkey_authorized_line(const uint8_t *blob, size_t blob_len,
                                    char *out, size_t out_cap);

/* SHA256:... as ssh-keygen -l prints it, for log lines. Never fails: a key
 * that cannot be hashed renders as "<none>" rather than costing a caller an
 * error path in the middle of a message. */
void ssoossh_sshkey_fingerprint(const uint8_t *blob, size_t blob_len,
                                char out[SSOOSSH_FINGERPRINT_LEN]);

typedef struct {
    uint8_t blob[SSOOSSH_MAX_KEY_BLOB];
    size_t len;
    char algo[64];
} ssoossh_ca_key;

typedef struct {
    ssoossh_ca_key keys[SSOOSSH_MAX_CAS];
    size_t count;
    /* Keys this platform's backend cannot verify with, skipped during the
     * load. Non-zero with count > 0 is the mid-rotation case the skip
     * behaviour exists for. */
    size_t skipped;
} ssoossh_ca_list;

typedef enum {
    SSOOSSH_CA_OK = 0,
    SSOOSSH_CA_UNREADABLE,
    SSOOSSH_CA_MALFORMED,
    /* Parsed fine and left nothing usable: an empty file, or one whose
     * every key is an algorithm this backend cannot verify. */
    SSOOSSH_CA_NONE_USABLE,
} ssoossh_ca_status;

/* Reads trusted-ca-file: one key per line, authorized_keys format, so a
 * deployment can rotate CAs without a coordinated restart.
 *
 * A key whose algorithm this backend cannot verify is skipped with a
 * warning naming the algorithm and the line, and loading continues -- a
 * file mid-rotation may legitimately list a key this platform cannot use,
 * and taking the host offline over it is the failure this avoids. If
 * nothing usable remains, that is SSOOSSH_CA_NONE_USABLE, which the caller
 * reports the same way as an unreadable file.
 *
 * Anything actually malformed still fails the whole file. A CA file is
 * operator-controlled, and a line nobody can parse is a mistake worth
 * refusing rather than reading past. */
ssoossh_ca_status ssoossh_ca_load(const char *path, ssoossh_ca_list *out);

/* Parses one authorized_keys line into a blob. Exposed for the CA loader
 * and for the certificate parser, which reads the same encoding out of a
 * JSON string. Returns false for a blank line, a comment, or anything
 * malformed; *is_blank distinguishes the first two, which a file may
 * contain and a certificate may not. */
bool ssoossh_sshkey_parse_line(const char *line, size_t line_len, uint8_t *blob,
                               size_t blob_cap, size_t *blob_len, char *algo,
                               size_t algo_cap, bool *is_blank);

#endif /* PAM_SSOOSSH_SSHKEY_H */
