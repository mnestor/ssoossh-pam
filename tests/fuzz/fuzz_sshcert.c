/* The certificate parser, over bytes a network peer chose.
 *
 * This is the whole security weight of the project in one function: it runs
 * as root, on a blob a server handed over, before anything has authenticated
 * that server beyond TLS. Both entry points are fuzzed -- the decoded blob
 * and the authorized_keys line the JSON actually carries -- because the
 * line form goes through base64 first and a decoder bug would never reach
 * the blob form.
 *
 * Seed the corpus from tests/fixtures: those are real certificates, so the
 * fuzzer starts from something structurally valid and mutates outward,
 * which is where the interesting inputs are.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "sshcert.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ssoossh_cert cert;
    uint8_t scratch[SSOOSSH_MAX_CERT];

    if (size > SSOOSSH_MAX_CERT) {
        return 0;
    }

    if (ssoossh_cert_parse(data, size, &cert) == SSOOSSH_CERT_OK) {
        /* A parse that succeeded has to leave a self-consistent view: the
         * signed extent inside the blob, every borrowed slice inside it,
         * and the rebuilt key blob within its buffer. A parser that
         * returned OK with an offset past the end would hand
         * ssoossh_crypto_verify a length it would then read. */
        if (cert.signed_len > size) {
            __builtin_trap();
        }
        if (cert.signature.p < data || cert.signature.p > data + size ||
            cert.signature.p + cert.signature.len > data + size) {
            __builtin_trap();
        }
        if (cert.signature_key.p < data ||
            cert.signature_key.p + cert.signature_key.len > data + size) {
            __builtin_trap();
        }
        if (cert.key_blob_len > sizeof(cert.key_blob)) {
            __builtin_trap();
        }
        for (size_t i = 0; i < cert.principal_count; i++) {
            if (cert.principals[i].p < data ||
                cert.principals[i].p + cert.principals[i].len > data + size) {
                __builtin_trap();
            }
        }
        /* Reading the principals must not walk off anything. */
        (void)ssoossh_cert_has_principal(&cert, "alice");
    }

    /* The line form, which is what a JSON response actually carries. */
    (void)ssoossh_cert_parse_line((const char *)data, size, scratch,
                                  sizeof(scratch), &cert);
    return 0;
}
