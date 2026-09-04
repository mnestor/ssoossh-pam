#include "base64.h"

static const char alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* 0..63 for an alphabet character, 64 for '=', 255 for anything else. A
 * table rather than a search so the decode is constant-shaped -- there is
 * nothing secret in a certificate, but a branchy inner loop over
 * attacker-controlled bytes is worth not writing anyway. */
static uint8_t decode_value(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') {
        return (uint8_t)(c - 'A');
    }
    if (c >= 'a' && c <= 'z') {
        return (uint8_t)(c - 'a' + 26);
    }
    if (c >= '0' && c <= '9') {
        return (uint8_t)(c - '0' + 52);
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    if (c == '=') {
        return 64;
    }
    return 255;
}

bool ssoossh_b64_decode(const char *in, size_t in_len, uint8_t *out,
                        size_t out_cap, size_t *out_len)
{
    uint32_t acc = 0;
    unsigned nbits = 0;
    size_t w = 0, i;
    size_t pad = 0;

    /* Length is checked before anything is decoded: base64 comes in groups
     * of four, and a length that is not a multiple of four cannot be one no
     * matter what the bytes are. */
    if (in_len % 4 != 0) {
        return false;
    }

    for (i = 0; i < in_len; i++) {
        uint8_t v = decode_value((unsigned char)in[i]);

        if (v == 255) {
            return false;
        }
        if (v == 64) {
            /* Padding is terminal: at most two '=', and only in the last
             * group. Anything else is a re-encoding trick rather than a
             * key. */
            pad++;
            if (pad > 2 || i < in_len - 2) {
                return false;
            }
            continue;
        }
        if (pad > 0) {
            return false; /* data after padding */
        }

        acc = acc << 6 | v;
        nbits += 6;
        if (nbits >= 8) {
            nbits -= 8;
            if (w >= out_cap) {
                return false;
            }
            out[w++] = (uint8_t)(acc >> nbits);
        }
    }

    /* Whatever bits are left over must be zero. A group whose padding bits
     * carry data decodes to the same bytes as one that does not, which is
     * two spellings of one key -- and two spellings is one more than a
     * fingerprint comparison can survive. */
    if (nbits > 0 && (acc & ((1u << nbits) - 1)) != 0) {
        return false;
    }

    *out_len = w;
    return true;
}

bool ssoossh_b64_encode(const uint8_t *in, size_t in_len, char *out,
                        size_t out_cap)
{
    size_t need = (in_len + 2) / 3 * 4;
    size_t w = 0, i = 0;

    if (need + 1 > out_cap) {
        return false;
    }

    while (i + 3 <= in_len) {
        uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i + 1] << 8 |
                     (uint32_t)in[i + 2];
        out[w++] = alphabet[v >> 18 & 0x3f];
        out[w++] = alphabet[v >> 12 & 0x3f];
        out[w++] = alphabet[v >> 6 & 0x3f];
        out[w++] = alphabet[v & 0x3f];
        i += 3;
    }

    if (i < in_len) {
        uint32_t v = (uint32_t)in[i] << 16;
        bool two = (in_len - i) == 2;

        if (two) {
            v |= (uint32_t)in[i + 1] << 8;
        }
        out[w++] = alphabet[v >> 18 & 0x3f];
        out[w++] = alphabet[v >> 12 & 0x3f];
        out[w++] = two ? alphabet[v >> 6 & 0x3f] : '=';
        out[w++] = '=';
    }

    out[w] = '\0';
    return true;
}
