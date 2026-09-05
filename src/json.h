/* Reading the three JSON shapes ssoosshd sends.
 *
 * Every response the module reads is an envelope -- {"data": ..., "error":
 * ..., "error_code": ...} -- so two accessors cover all of them: one for a
 * field of the data object and one for a field of the envelope itself. The
 * create response, the terminal event payload and the error body are all
 * read through those.
 *
 * Deliberately not a decoder. There is no object graph built here and
 * nothing allocated: jsmn tokenizes into a fixed array of offsets, and the
 * value the caller asked for is unescaped into the caller's own buffer.
 * That leaves a malformed response nothing to corrupt.
 */
#ifndef PAM_SSOOSSH_JSON_H
#define PAM_SSOOSSH_JSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Responses are capped before parsing, matching the Go client's own
 * error-body cap. Anything larger is something other than ssoosshd
 * answering, and none of it belongs in sudo's memory. */
#define SSOOSSH_MAX_RESPONSE (64 * 1024)

/* Reads data.<field> as a string, unescaping it into out.
 *
 * Returns false when the body is not a JSON object, when the field is
 * absent or null, when it is not a string, or when it does not fit. A
 * caller distinguishes "absent" from "malformed" by checking the body
 * parsed at all -- which every caller here does by reading a field it knows
 * must be present first. */
bool ssoossh_json_data_string(const char *body, size_t body_len,
                              const char *field, char *out, size_t out_cap);

/* The same, for a field of the envelope rather than of its data: "error"
 * and "error_code". */
bool ssoossh_json_top_string(const char *body, size_t body_len,
                             const char *field, char *out, size_t out_cap);

/* Appends a JSON string literal, quotes and escaping included, to a buffer
 * that *len bytes of are already used. Returns false when it does not fit,
 * leaving the buffer in whatever state it reached -- callers build a body
 * and check once at the end, never partially.
 *
 * Escapes what JSON requires and nothing else: a control byte becomes
 * \uXXXX, a quote and a backslash get a backslash. A forward slash is left
 * alone, because escaping it is optional and the Go encoder does not. */
bool ssoossh_json_append_string(char *buf, size_t cap, size_t *len,
                                const char *s);

/* Appends raw text -- punctuation, field names already quoted, a literal
 * true or null. */
bool ssoossh_json_append(char *buf, size_t cap, size_t *len, const char *raw);

/* Parses the RFC 3339 timestamps ssoosshd sends, as Unix seconds UTC.
 *
 * Only the shape Go's time.Time marshals to: a date, a T, a time, an
 * optional fractional part, and either Z or a numeric offset. A fractional
 * second is parsed and discarded -- the values this reads are deadlines
 * measured in tens of seconds, and rounding one down by under a second
 * cannot change a decision. */
bool ssoossh_parse_rfc3339(const char *s, int64_t *out_unix);

#endif /* PAM_SSOOSSH_JSON_H */
