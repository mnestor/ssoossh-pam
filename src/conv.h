/* The PAM conversation: the only channel a module has to put text in front
 * of whoever is running the transaction, and the only place this module is
 * allowed to produce output that a human sees.
 *
 * Two things here are deliberate.
 *
 * The message style is a parameter rather than baked in. PAM_TEXT_INFO is
 * what the sudo flow needs; PAM_PROMPT_ECHO_ON, which console mode needs to
 * collect a typed answer, differs from it by an enum value and a response
 * that has to be freed. Building this Info-only would mean reopening the
 * file that talks to the tty in order to add the second one.
 *
 * And everything written through here is whitelisted first. The approval
 * URL is a field of a JSON response from a server the module has not
 * authenticated beyond TLS -- and with insecure-skip-verify, not even that.
 * Passing it straight to a conversation function puts server-chosen bytes,
 * including terminal escape sequences, on the tty of a process running as
 * root. The Go module does exactly that today; this is where that stops.
 */
#ifndef PAM_SSOOSSH_CONV_H
#define PAM_SSOOSSH_CONV_H

#include <stddef.h>

#include <security/pam_appl.h>

/* Which characters are allowed through for a given kind of value. Each
 * class is the smallest set that still renders the thing it names.
 *
 * A class is chosen by what the value *is*, never by where it came from:
 * the point is that a server cannot widen the set by sending something
 * unexpected. */
typedef enum {
    /* The RFC 3986 URI repertoire: unreserved, reserved, and '%'. Wide
     * enough for any URL ssoosshd can legitimately produce, and narrow
     * enough that no control byte, no ESC, and nothing non-ASCII survives. */
    SSOOSSH_TEXT_URL,

    /* Crockford Base32 plus the '-' that groups it for reading. The
     * console user code, which is the only value of this shape. */
    SSOOSSH_TEXT_CODE,

    /* Exactly the three half-block characters a QR code is drawn from --
     * U+2580, U+2584, U+2588 -- plus space and newline. Multi-byte
     * sequences are matched whole, so a truncated or spoofed prefix is
     * dropped rather than passed through a byte at a time. */
    SSOOSSH_TEXT_QR,
} ssoossh_text_class;

/* Copies in to out keeping only the bytes cls allows, NUL-terminating the
 * result. Returns the number of *input* bytes dropped, which the caller
 * logs: a URL that lost characters is worth knowing about, whether it was a
 * hostile server or an ssoosshd that changed shape.
 *
 * Truncation to out_size is counted as dropped too, so a caller checking
 * for a non-zero return catches both. */
size_t ssoossh_sanitize(ssoossh_text_class cls, const char *in, char *out,
                        size_t out_size);

/* Sends one message through the conversation function pamh carries.
 *
 * style is a PAM message style: PAM_TEXT_INFO to display, PAM_PROMPT_ECHO_ON
 * or PAM_PROMPT_ECHO_OFF to ask. For the prompt styles, *response receives
 * the answer, which the caller must free; it is set to NULL for the display
 * styles and whenever the conversation returned none.
 *
 * text must already be sanitized -- this function does not know what class
 * a caller's string belongs to, and guessing would be the whole hole
 * reopened.
 *
 * Returns PAM_SUCCESS, or the PAM error the conversation reported. */
int ssoossh_conv(pam_handle_t *pamh, int style, const char *text,
                 char **response);

#endif /* PAM_SSOOSSH_CONV_H */
