#include "sshwire.h"

#include <string.h>

void ssh_rd_init(ssh_rd *r, const uint8_t *buf, size_t len)
{
    r->base = buf;
    r->p = buf;
    r->end = buf + len;
    r->bad = false;
}

/* The one place a length is compared against the remaining bytes. Written
 * as a subtraction from end rather than an addition to p, because p + n can
 * wrap when n is attacker-chosen and the comparison after it would then
 * succeed. */
static bool have(const ssh_rd *r, size_t n)
{
    return !r->bad && (size_t)(r->end - r->p) >= n;
}

uint8_t ssh_rd_u8(ssh_rd *r)
{
    if (!have(r, 1)) {
        r->bad = true;
        return 0;
    }
    return *r->p++;
}

uint32_t ssh_rd_u32(ssh_rd *r)
{
    uint32_t v;

    if (!have(r, 4)) {
        r->bad = true;
        return 0;
    }
    v = (uint32_t)r->p[0] << 24 | (uint32_t)r->p[1] << 16 |
        (uint32_t)r->p[2] << 8 | (uint32_t)r->p[3];
    r->p += 4;
    return v;
}

uint64_t ssh_rd_u64(ssh_rd *r)
{
    uint64_t hi = ssh_rd_u32(r);
    uint64_t lo = ssh_rd_u32(r);

    return hi << 32 | lo;
}

bool ssh_rd_str(ssh_rd *r, const uint8_t **out, size_t *out_len)
{
    uint32_t n = ssh_rd_u32(r);

    if (!have(r, n)) {
        r->bad = true;
        return false;
    }
    if (out != NULL) {
        *out = r->p;
    }
    if (out_len != NULL) {
        *out_len = n;
    }
    r->p += n;
    return true;
}

bool ssh_rd_cstr(ssh_rd *r, char *out, size_t out_cap)
{
    const uint8_t *p = NULL;
    size_t n = 0;

    if (!ssh_rd_str(r, &p, &n) || n == 0 || n >= out_cap) {
        return false;
    }
    memcpy(out, p, n);
    out[n] = '\0';
    return true;
}

bool ssh_rd_skip_str(ssh_rd *r)
{
    return ssh_rd_str(r, NULL, NULL);
}

size_t ssh_rd_offset(const ssh_rd *r)
{
    return (size_t)(r->p - r->base);
}

size_t ssh_rd_remaining(const ssh_rd *r)
{
    return r->bad ? 0 : (size_t)(r->end - r->p);
}

bool ssh_rd_ok(const ssh_rd *r)
{
    return !r->bad;
}

bool ssh_rd_done(const ssh_rd *r)
{
    return !r->bad && r->p == r->end;
}

void ssh_wr_init(ssh_wr *w, uint8_t *buf, size_t cap)
{
    w->buf = buf;
    w->cap = cap;
    w->len = 0;
    w->bad = false;
}

void ssh_wr_bytes(ssh_wr *w, const void *p, size_t n)
{
    if (w->bad || n > w->cap - w->len) {
        w->bad = true;
        return;
    }
    memcpy(w->buf + w->len, p, n);
    w->len += n;
}

void ssh_wr_u32(ssh_wr *w, uint32_t v)
{
    uint8_t b[4];

    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)v;
    ssh_wr_bytes(w, b, sizeof(b));
}

void ssh_wr_str(ssh_wr *w, const void *p, size_t n)
{
    if (n > 0xffffffffu) {
        w->bad = true;
        return;
    }
    ssh_wr_u32(w, (uint32_t)n);
    ssh_wr_bytes(w, p, n);
}

void ssh_wr_cstr(ssh_wr *w, const char *s)
{
    ssh_wr_str(w, s, strlen(s));
}

void ssh_wr_mpint(ssh_wr *w, const uint8_t *p, size_t n)
{
    size_t i = 0;

    /* Minimal encoding: an mpint carries no leading zero bytes of its own.
     * Re-encoding a value that arrived with them and comparing the result
     * is how a marshalled key is made to match byte for byte what OpenSSH
     * would have produced. */
    while (i < n && p[i] == 0) {
        i++;
    }
    if (i == n) {
        /* Zero is the empty string, not a zero byte. */
        ssh_wr_u32(w, 0);
        return;
    }

    /* Two's complement: a top bit set would read as negative, so a zero
     * byte goes in front of it. */
    if (p[i] & 0x80) {
        static const uint8_t zero = 0;
        ssh_wr_u32(w, (uint32_t)(n - i + 1));
        ssh_wr_bytes(w, &zero, 1);
        ssh_wr_bytes(w, p + i, n - i);
        return;
    }
    ssh_wr_str(w, p + i, n - i);
}

bool ssh_wr_ok(const ssh_wr *w)
{
    return !w->bad;
}

size_t ssh_wr_len(const ssh_wr *w)
{
    return w->len;
}
