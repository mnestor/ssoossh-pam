/* Base64, as authorized_keys uses it.
 *
 * Written here rather than taken from OpenSSL, for two reasons. The decoder
 * runs on the trusted-ca-file and on certificate text from the server, so
 * it is parser surface that belongs under this project's own fuzzing rather
 * than behind an API (EVP_DecodeBlock) whose padding handling is famously
 * easy to hold wrong. And crypto.h exists so that nothing above it is
 * platform-specific -- a base64 that came from OpenSSL would have to be
 * written a second time for the Darwin backend.
 */
#ifndef PAM_SSOOSSH_BASE64_H
#define PAM_SSOOSSH_BASE64_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Decodes standard base64 with the usual alphabet and '=' padding.
 *
 * Strict: no whitespace, no line breaks, no alternate alphabet, and
 * padding must be correct and terminal. An authorized_keys field is one
 * unbroken token, so anything else is a malformed file rather than a
 * variant to be lenient about.
 *
 * Returns false if the input is malformed or the output does not fit,
 * without writing a partial result the caller might use. */
bool ssoossh_b64_decode(const char *in, size_t in_len, uint8_t *out,
                        size_t out_cap, size_t *out_len);

/* Encodes with padding. out_cap must hold 4*ceil(n/3) bytes plus a NUL. */
bool ssoossh_b64_encode(const uint8_t *in, size_t in_len, char *out,
                        size_t out_cap);

#endif /* PAM_SSOOSSH_BASE64_H */
