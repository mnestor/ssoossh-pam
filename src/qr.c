#include "qr.h"

#include <stdbool.h>
#include <string.h>

#include "../third_party/qrcodegen/qrcodegen.h"

/* Version 4 is 33 modules. With a two-module quiet zone that is 37 columns
 * and 19 terminal rows, which fits an 80x24 console with the code, the URL
 * and a blank line around them. Version 4 at level L holds 78 bytes, and
 * the URL rendered here is the terse /c/<code> form the server returns for
 * exactly this purpose. */
#define QR_MAX_VERSION 4
#define QUIET 2

/* The three block characters, as their UTF-8 bytes. */
static const char *const upper_only = "\xe2\x96\x80"; /* U+2580 */
static const char *const lower_only = "\xe2\x96\x84"; /* U+2584 */
static const char *const both = "\xe2\x96\x88";       /* U+2588 */

static bool put(char *out, size_t out_cap, size_t *w, const char *s, size_t n)
{
    if (*w + n + 1 > out_cap) {
        return false;
    }
    memcpy(out + *w, s, n);
    *w += n;
    return true;
}

/* True when the module at (x, y) is light. Outside the code is the quiet
 * zone, which is light too -- and load-bearing: a scanner needs it to find
 * the code's edges at all. */
static bool light(const uint8_t *qr, int size, int x, int y)
{
    if (x < 0 || y < 0 || x >= size || y >= size) {
        return true;
    }
    return !qrcodegen_getModule(qr, x, y);
}

size_t ssoossh_qr_render(const char *text, char *out, size_t out_cap)
{
    uint8_t qr[qrcodegen_BUFFER_LEN_FOR_VERSION(QR_MAX_VERSION)];
    uint8_t tmp[qrcodegen_BUFFER_LEN_FOR_VERSION(QR_MAX_VERSION)];
    int size, width;
    size_t w = 0;

    if (out_cap == 0) {
        return 0;
    }
    out[0] = '\0';

    if (!qrcodegen_encodeText(text, tmp, qr, qrcodegen_Ecc_LOW, 1,
                              QR_MAX_VERSION, qrcodegen_Mask_AUTO, true)) {
        /* Too long for a code this narrow. Not an error: the caller prints
         * the code and the URL regardless. */
        return 0;
    }

    size = qrcodegen_getSize(qr);
    width = size + 2 * QUIET;

    /* Two module rows per terminal row. y steps by two and each column
     * picks the character that lights the right halves. */
    for (int y = -QUIET; y < size + QUIET; y += 2) {
        for (int x = -QUIET; x < size + QUIET; x++) {
            bool top = light(qr, size, x, y);
            bool bottom = light(qr, size, x, y + 1);
            bool ok;

            /* The last row of an odd-height image has no lower half; the
             * quiet zone below it is light, which light() already returns
             * for an out-of-range y. */
            if (top && bottom) {
                ok = put(out, out_cap, &w, both, 3);
            } else if (top) {
                ok = put(out, out_cap, &w, upper_only, 3);
            } else if (bottom) {
                ok = put(out, out_cap, &w, lower_only, 3);
            } else {
                ok = put(out, out_cap, &w, " ", 1);
            }
            if (!ok) {
                out[0] = '\0';
                return 0;
            }
        }
        if (!put(out, out_cap, &w, "\n", 1)) {
            out[0] = '\0';
            return 0;
        }
    }

    (void)width;
    out[w] = '\0';
    return w;
}
