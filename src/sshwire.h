/* The SSH wire encoding (RFC 4251 §5), read and written through one
 * bounds-checked cursor each.
 *
 * This is the file that decides whether the certificate parser is safe.
 * Everything above it -- sshkey.c, sshcert.c -- reads fields through these
 * accessors and does no pointer arithmetic of its own, so "did we check the
 * length" is a question with exactly one place to look.
 *
 * The reader latches its failure rather than returning one per call. A
 * certificate has fourteen fields; testing each read would bury the shape of
 * the format under error handling, and the first overrun poisons everything
 * after it anyway. Callers chain reads and test ssh_rd_ok() once at the end.
 */
#ifndef PAM_SSOOSSH_SSHWIRE_H
#define PAM_SSOOSSH_SSHWIRE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    const uint8_t *p;    /* cursor */
    const uint8_t *end;  /* one past the last readable byte */
    const uint8_t *base; /* where the blob started, for ssh_rd_offset */
    bool bad;            /* latched on the first read that would overrun */
} ssh_rd;

void ssh_rd_init(ssh_rd *r, const uint8_t *buf, size_t len);

/* Every accessor is a no-op returning zero once bad is set, so a caller may
 * chain reads without checking between them. */
uint8_t ssh_rd_u8(ssh_rd *r);
uint32_t ssh_rd_u32(ssh_rd *r);
uint64_t ssh_rd_u64(ssh_rd *r);

/* Reads a uint32-length-prefixed string, borrowing into the source buffer:
 * never allocates, never NUL-terminates. The slice is valid for as long as
 * the buffer the reader was initialized over.
 *
 * Returns false and latches bad if the length runs past the end -- including
 * a length that overflows when added to the cursor, which is the shape a
 * hostile 0xffffffff takes. */
bool ssh_rd_str(ssh_rd *r, const uint8_t **out, size_t *out_len);

/* Skips a string without looking at it. */
bool ssh_rd_skip_str(ssh_rd *r);

/* Byte offset of the cursor from the start of the blob. sshcert.c calls
 * this immediately before reading the signature field, which gives the
 * exact extent of the CA-signed content without re-serializing anything --
 * the copy-clear-marshal-trim dance the Go implementation does. */
size_t ssh_rd_offset(const ssh_rd *r);

/* Bytes not yet consumed. */
size_t ssh_rd_remaining(const ssh_rd *r);

/* True while no read has overrun. */
bool ssh_rd_ok(const ssh_rd *r);

/* True when the blob was consumed exactly, with nothing left over. Trailing
 * bytes after a certificate are not harmless: they are a second certificate
 * the verifier never saw. */
bool ssh_rd_done(const ssh_rd *r);

/* The writing half. Same latched-failure discipline: overflow sets bad and
 * every later write is dropped, so a caller checks once before using the
 * result. */
typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t len;
    bool bad;
} ssh_wr;

void ssh_wr_init(ssh_wr *w, uint8_t *buf, size_t cap);
void ssh_wr_bytes(ssh_wr *w, const void *p, size_t n);
void ssh_wr_u32(ssh_wr *w, uint32_t v);

/* Writes a uint32-length-prefixed string. */
void ssh_wr_str(ssh_wr *w, const void *p, size_t n);
void ssh_wr_cstr(ssh_wr *w, const char *s);

/* Writes an mpint: a two's-complement big-endian integer, minimally
 * encoded, with a leading zero byte inserted when the top bit of the first
 * significant byte is set. Leading zero bytes in the input are dropped
 * first, which is what makes a re-encoded value compare equal to the one
 * OpenSSH would have written. */
void ssh_wr_mpint(ssh_wr *w, const uint8_t *p, size_t n);

bool ssh_wr_ok(const ssh_wr *w);
size_t ssh_wr_len(const ssh_wr *w);

#endif /* PAM_SSOOSSH_SSHWIRE_H */
