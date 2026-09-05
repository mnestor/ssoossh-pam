/* The authorized_keys line parser and the base64 under it, which read the
 * trusted-ca-file and the certificate string alike.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "base64.h"
#include "sshkey.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t blob[SSOOSSH_MAX_KEY_BLOB];
    size_t blob_len = 0;
    char algo[64];
    bool blank = false;

    if (size > SSOOSSH_MAX_KEY_LINE) {
        return 0;
    }

    if (ssoossh_sshkey_parse_line((const char *)data, size, blob, sizeof(blob),
                                  &blob_len, algo, sizeof(algo), &blank)) {
        char fp[SSOOSSH_FINGERPRINT_LEN];

        if (blob_len > sizeof(blob)) {
            __builtin_trap();
        }
        ssoossh_sshkey_fingerprint(blob, blob_len, fp);
    }

    /* The decoder on its own, so a corpus of pure base64 is useful. */
    (void)ssoossh_b64_decode((const char *)data, size, blob, sizeof(blob),
                             &blob_len);
    return 0;
}
