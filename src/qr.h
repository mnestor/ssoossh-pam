/* Drawing the console verification URL as a QR code on a terminal.
 *
 * Rendered here, from the URL, rather than fetched as ANSI art from the
 * server. The proposal weighed shipping pre-rendered terminal bytes in the
 * create response and rejected it, and that reasoning is the same one
 * src/conv.c exists for: writing server-chosen bytes to a terminal owned by
 * a root process is the thing this module does not do.
 *
 * Not compiled on macOS. Console mode is Linux and FreeBSD only -- macOS
 * ships no artifact, so a console login there is scope with no user.
 */
#ifndef PAM_SSOOSSH_QR_H
#define PAM_SSOOSSH_QR_H

#include <stddef.h>

/* Enough for the largest code this renders (version 4, 33 modules, plus a
 * two-module quiet zone each side): 37 columns of up to three bytes, 19
 * rows, and a newline each. */
#define SSOOSSH_QR_MAX_OUT 2560

/* Renders text as a QR code drawn with half-block characters, two module
 * rows per terminal row, and returns the number of bytes written.
 *
 * Returns 0 when the text will not fit in a code this narrow, which is not
 * an error: the caller prints the code and the URL either way, and the QR
 * is the convenience on top. Version 4 at error-correction level L holds 78
 * bytes, and the URL it is given is the deliberately terse /c/<code> form.
 *
 * Polarity is chosen for a light-on-dark console, which is what a VT, a
 * serial line and a BMC viewer all are: light modules are drawn as bright
 * blocks and dark modules are left as the terminal's background. On a
 * light-background terminal the image inverts and a scanner will refuse it
 * -- the same limitation qrencode's UTF-8 output has -- which is one more
 * reason the typed code is always printed alongside.
 *
 * The output uses only space, newline, U+2580, U+2584 and U+2588. It still
 * goes through the conversation whitelist before it reaches a tty; that is
 * belt and braces, not redundancy, because the whitelist is what holds if
 * this function is ever changed. */
size_t ssoossh_qr_render(const char *text, char *out, size_t out_cap);

#endif /* PAM_SSOOSSH_QR_H */
