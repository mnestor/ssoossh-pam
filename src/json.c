#include "json.h"

#include <stdint.h>
#include <string.h>

/* Static, so jsmn's own symbols cannot reach the host process even before
 * the version script gets a chance to hide them.
 *
 * The warning suppression is scoped to this include and nothing else.
 * jsmn is vendored unmodified and pinned by hash (see third_party/jsmn),
 * and it does not compile clean under -Wconversion -- it moves freely
 * between int and unsigned for its buffer offsets. Patching a vendored
 * dependency to satisfy our warning flags would mean carrying a fork and
 * re-applying it at every update; silencing it here costs nothing, because
 * every byte it touches has already been bounded by the caller and the code
 * below stays under the full flag set. */
#define JSMN_STATIC
#define JSMN_PARENT_LINKS
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include "../third_party/jsmn/jsmn.h"
#pragma GCC diagnostic pop

/* A response from ssoosshd has a couple of dozen tokens. 512 is room for a
 * shape that changed without warning, and a hard stop for one that is
 * trying to make the module walk a deep structure. */
#define MAX_TOKENS 512

/* Writes one UTF-8 encoding of a code point. Only used for \uXXXX, so the
 * range is bounded and there is no four-byte case beyond the surrogate
 * pair handling in unescape. */
static bool put_utf8(uint32_t cp, char *out, size_t out_cap, size_t *w)
{
    size_t n = cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;

    if (*w + n >= out_cap) {
        return false;
    }
    switch (n) {
    case 1:
        out[(*w)++] = (char)cp;
        break;
    case 2:
        out[(*w)++] = (char)(0xc0 | (cp >> 6));
        out[(*w)++] = (char)(0x80 | (cp & 0x3f));
        break;
    case 3:
        out[(*w)++] = (char)(0xe0 | (cp >> 12));
        out[(*w)++] = (char)(0x80 | ((cp >> 6) & 0x3f));
        out[(*w)++] = (char)(0x80 | (cp & 0x3f));
        break;
    default:
        out[(*w)++] = (char)(0xf0 | (cp >> 18));
        out[(*w)++] = (char)(0x80 | ((cp >> 12) & 0x3f));
        out[(*w)++] = (char)(0x80 | ((cp >> 6) & 0x3f));
        out[(*w)++] = (char)(0x80 | (cp & 0x3f));
        break;
    }
    return true;
}

static bool hex4(const char *p, uint32_t *out)
{
    uint32_t v = 0;

    for (int i = 0; i < 4; i++) {
        char c = p[i];
        uint32_t d;

        if (c >= '0' && c <= '9') {
            d = (uint32_t)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            d = (uint32_t)(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            d = (uint32_t)(c - 'A' + 10);
        } else {
            return false;
        }
        v = v << 4 | d;
    }
    *out = v;
    return true;
}

/* JSON string unescaping. jsmn hands back the raw bytes between the quotes,
 * escapes and all, so this is where they become the value.
 *
 * An unknown escape is rejected rather than passed through: a server that
 * sent one is not speaking JSON, and guessing at it would mean two
 * spellings of a URL that gets shown to a human. */
static bool unescape(const char *p, size_t len, char *out, size_t out_cap)
{
    size_t w = 0;

    for (size_t i = 0; i < len; i++) {
        if (p[i] != '\\') {
            if (w + 1 >= out_cap) {
                return false;
            }
            out[w++] = p[i];
            continue;
        }
        if (++i >= len) {
            return false;
        }
        /* Every escape but \u writes exactly one byte, so one check covers
         * them all; \u does its own, per code point. */
        if (p[i] != 'u' && w + 1 >= out_cap) {
            return false;
        }
        switch (p[i]) {
        case '"':
        case '\\':
        case '/':
            out[w++] = p[i];
            break;
        case 'b':
            out[w++] = '\b';
            break;
        case 'f':
            out[w++] = '\f';
            break;
        case 'n':
            out[w++] = '\n';
            break;
        case 'r':
            out[w++] = '\r';
            break;
        case 't':
            out[w++] = '\t';
            break;
        case 'u': {
            uint32_t cp;

            if (i + 4 >= len || !hex4(p + i + 1, &cp)) {
                return false;
            }
            i += 4;
            if (cp >= 0xd800 && cp <= 0xdbff) {
                uint32_t low;
                /* A high surrogate must be followed by its low half. A
                 * lone one is not a code point, and encoding it anyway
                 * would produce bytes no decoder agrees about. */
                if (i + 6 >= len || p[i + 1] != '\\' || p[i + 2] != 'u' ||
                    !hex4(p + i + 3, &low) || low < 0xdc00 || low > 0xdfff) {
                    return false;
                }
                i += 6;
                cp = 0x10000 + ((cp - 0xd800) << 10) + (low - 0xdc00);
            } else if (cp >= 0xdc00 && cp <= 0xdfff) {
                return false; /* a low surrogate with no high half */
            }
            if (!put_utf8(cp, out, out_cap, &w)) {
                return false;
            }
            break;
        }
        default:
            return false;
        }
    }

    out[w] = '\0';
    return true;
}

static bool token_is(const char *body, const jsmntok_t *t, const char *name)
{
    size_t len = (size_t)(t->end - t->start);

    return t->type == JSMN_STRING && len == strlen(name) &&
           memcmp(body + t->start, name, len) == 0;
}

/* Skips a token and everything under it, returning the index that follows.
 * jsmn's array is a pre-order walk, so a nested object's children sit
 * between it and its next sibling; without this, looking for a top-level
 * key would find one nested inside another object. */
static int skip(const jsmntok_t *toks, int count, int i)
{
    int end = toks[i].end;
    int n = i + 1;

    while (n < count && toks[n].start < end) {
        n++;
    }
    return n;
}

/* Finds a key of the object at index obj, returning the index of its value
 * or -1. */
static int object_get(const char *body, const jsmntok_t *toks, int count,
                      int obj, const char *name)
{
    int i;

    if (toks[obj].type != JSMN_OBJECT) {
        return -1;
    }
    i = obj + 1;
    for (int n = 0; n < toks[obj].size && i < count; n++) {
        int value = i + 1;

        if (value >= count) {
            return -1;
        }
        if (token_is(body, &toks[i], name)) {
            return value;
        }
        i = skip(toks, count, value);
    }
    return -1;
}

static bool get_string(const char *body, size_t body_len, const char *object,
                       const char *field, char *out, size_t out_cap)
{
    jsmntok_t toks[MAX_TOKENS];
    jsmn_parser parser;
    int count, target;

    if (body_len == 0 || body_len > SSOOSSH_MAX_RESPONSE) {
        return false;
    }

    jsmn_init(&parser);
    count = jsmn_parse(&parser, body, body_len, toks, MAX_TOKENS);
    if (count < 1 || toks[0].type != JSMN_OBJECT) {
        return false;
    }

    target = 0;
    if (object != NULL) {
        target = object_get(body, toks, count, 0, object);
        if (target < 0 || toks[target].type != JSMN_OBJECT) {
            return false;
        }
    }

    target = object_get(body, toks, count, target, field);
    if (target < 0 || toks[target].type != JSMN_STRING) {
        /* A null, a number, or an object where a string was expected. All
         * of them are "no value here", which is what a caller does with a
         * field the server did not send. */
        return false;
    }

    return unescape(body + toks[target].start,
                    (size_t)(toks[target].end - toks[target].start), out,
                    out_cap);
}

bool ssoossh_json_data_string(const char *body, size_t body_len,
                              const char *field, char *out, size_t out_cap)
{
    return get_string(body, body_len, "data", field, out, out_cap);
}

bool ssoossh_json_top_string(const char *body, size_t body_len,
                             const char *field, char *out, size_t out_cap)
{
    return get_string(body, body_len, NULL, field, out, out_cap);
}

void ssoossh_json_wr_init(ssoossh_json_wr *w, char *buf, size_t cap)
{
    w->buf = buf;
    w->cap = cap;
    w->len = 0;
    w->bad = false;
    if (cap > 0) {
        buf[0] = '\0';
    }
}

void ssoossh_json_append(ssoossh_json_wr *w, const char *raw)
{
    size_t n = strlen(raw);

    if (w->bad || w->len + n + 1 > w->cap) {
        w->bad = true;
        return;
    }
    memcpy(w->buf + w->len, raw, n);
    w->len += n;
    w->buf[w->len] = '\0';
}

void ssoossh_json_append_string(ssoossh_json_wr *w, const char *s)
{
    size_t at = w->len;

    if (w->bad || at + 1 >= w->cap) {
        w->bad = true;
        return;
    }
    w->buf[at++] = '"';

    for (size_t i = 0; s[i] != '\0'; i++) {
        unsigned char c = (unsigned char)s[i];
        char esc[8];
        size_t n;

        if (c == '"' || c == '\\') {
            esc[0] = '\\';
            esc[1] = (char)c;
            n = 2;
        } else if (c == '\n') {
            memcpy(esc, "\\n", 2);
            n = 2;
        } else if (c == '\r') {
            memcpy(esc, "\\r", 2);
            n = 2;
        } else if (c == '\t') {
            memcpy(esc, "\\t", 2);
            n = 2;
        } else if (c < 0x20) {
            static const char hex[] = "0123456789abcdef";
            esc[0] = '\\';
            esc[1] = 'u';
            esc[2] = '0';
            esc[3] = '0';
            esc[4] = hex[c >> 4];
            esc[5] = hex[c & 0xf];
            n = 6;
        } else {
            esc[0] = (char)c;
            n = 1;
        }

        if (at + n + 2 > w->cap) {
            w->bad = true;
            return;
        }
        memcpy(w->buf + at, esc, n);
        at += n;
    }

    if (at + 2 > w->cap) {
        w->bad = true;
        return;
    }
    w->buf[at++] = '"';
    w->buf[at] = '\0';
    w->len = at;
}

bool ssoossh_json_wr_ok(const ssoossh_json_wr *w)
{
    return !w->bad;
}

/* days_from_civil, the standard proleptic-Gregorian conversion. timegm is
 * not portable enough to rely on -- it is a glibc and BSD extension with no
 * POSIX standing -- and setting TZ around mktime inside sudo would mutate
 * process-global state, which is the same rule that keeps openlog out of
 * this module. */
static int64_t days_from_civil(int64_t y, int m, int d)
{
    int64_t era, yoe, doy, doe;

    y -= (m <= 2) ? 1 : 0;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = y - era * 400;
    doy = (153 * (int64_t)(m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

static bool digits(const char *s, size_t n, int *out)
{
    int v = 0;

    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') {
            return false;
        }
        v = v * 10 + (s[i] - '0');
    }
    *out = v;
    return true;
}

bool ssoossh_parse_rfc3339(const char *s, int64_t *out_unix)
{
    int year, mon, day, hour, min, sec;
    size_t i = 0;
    int64_t t;

    if (strlen(s) < 20) {
        return false;
    }
    if (!digits(s, 4, &year) || s[4] != '-' || !digits(s + 5, 2, &mon) ||
        s[7] != '-' || !digits(s + 8, 2, &day) ||
        (s[10] != 'T' && s[10] != 't' && s[10] != ' ') ||
        !digits(s + 11, 2, &hour) || s[13] != ':' || !digits(s + 14, 2, &min) ||
        s[16] != ':' || !digits(s + 17, 2, &sec)) {
        return false;
    }
    if (mon < 1 || mon > 12 || day < 1 || day > 31 || hour > 23 || min > 59 ||
        sec > 60) {
        return false;
    }

    i = 19;
    if (s[i] == '.') {
        i++;
        if (s[i] < '0' || s[i] > '9') {
            return false;
        }
        while (s[i] >= '0' && s[i] <= '9') {
            i++;
        }
    }

    t = days_from_civil(year, mon, day) * 86400 + hour * 3600 + min * 60 + sec;

    if (s[i] == 'Z' || s[i] == 'z') {
        if (s[i + 1] != '\0') {
            return false;
        }
    } else if (s[i] == '+' || s[i] == '-') {
        int oh, om;

        if (!digits(s + i + 1, 2, &oh) || s[i + 3] != ':' ||
            !digits(s + i + 4, 2, &om) || s[i + 6] != '\0') {
            return false;
        }
        if (oh > 23 || om > 59) {
            return false;
        }
        t += (s[i] == '+' ? -1 : 1) * (oh * 3600 + om * 60);
    } else {
        return false;
    }

    *out_unix = t;
    return true;
}
