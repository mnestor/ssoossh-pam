/* The reading half of server-sent events (WHATWG HTML §9.2), as a push
 * parser: libcurl delivers arbitrary chunks and this reassembles them into
 * lines and lines into events.
 *
 * Less the parts that only matter to a browser's EventSource. There is no
 * Last-Event-ID, because a reconnect here does not resume -- it re-waits,
 * and ssoosshd's Wait is idempotent per request. There is no server-set
 * retry interval either; the reconnect delay is this client's own.
 */
#ifndef PAM_SSOOSSH_SSE_H
#define PAM_SSOOSSH_SSE_H

#include <stdbool.h>
#include <stddef.h>

/* Caps, and a deliberate departure from the Go client's 1 MiB line limit.
 *
 * Go's figure is a maximum a scanner may grow to; in C a fixed buffer means
 * carrying it. A single line larger than the whole response cap cannot
 * contain anything this module reads -- the biggest thing on this stream is
 * one certificate, about 2 KiB -- and a megabyte of resident buffer inside
 * sudo is a worse trade than the smaller cap. An over-long line ends the
 * stream with an error rather than being silently dropped, so a server that
 * genuinely needed more is told, not ignored. */
#define SSOOSSH_SSE_MAX_LINE (64 * 1024)
#define SSOOSSH_SSE_MAX_DATA (64 * 1024)

/* Called for each dispatched event. name is the "event:" field, "" for an
 * event that carried none. Returning false stops the stream, which is how
 * a terminal event ends the wait.
 *
 * data is NUL-terminated and data_len is its length, because a certificate
 * is text and the caller hands it straight to a parser. */
typedef bool (*ssoossh_sse_cb)(const char *name, const char *data,
                               size_t data_len, void *ctx);

typedef struct {
    char line[SSOOSSH_SSE_MAX_LINE];
    size_t line_len;

    char name[128];
    char data[SSOOSSH_SSE_MAX_DATA];
    size_t data_len;

    /* Whether anything has accumulated into the current event. An event
     * with nothing in it is not dispatched -- that is what a stream of
     * nothing but keep-alives looks like. */
    bool have_event;

    /* Latched: a line that did not fit, or a field that did not. The
     * stream is finished either way, and the caller reports it rather than
     * carrying on with a truncated event. */
    bool overflow;

    /* Set once a callback has asked to stop. */
    bool stopped;
} ssoossh_sse;

void ssoossh_sse_init(ssoossh_sse *s);

/* Feeds one chunk. Returns false when the stream should stop -- either
 * because a callback said so (check ->stopped) or because something
 * overflowed (check ->overflow). */
bool ssoossh_sse_feed(ssoossh_sse *s, const char *p, size_t n,
                      ssoossh_sse_cb cb, void *ctx);

/* Ends the stream. A final line with no trailing newline is not
 * dispatched: an event is dispatched by a blank line, and a connection
 * that dropped mid-event has not delivered one. */
void ssoossh_sse_end(ssoossh_sse *s);

#endif /* PAM_SSOOSSH_SSE_H */
