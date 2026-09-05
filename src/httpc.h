/* libcurl, wrapped in the two shapes this module needs: a JSON POST that
 * creates a certificate request, and a streaming GET that stays open until
 * a human acts on it.
 *
 * libcurl rather than an OpenSSL BIO and hand-rolled HTTP, because the
 * events endpoint is a long-lived stream and the create call needs
 * proxy-from-environment, HTTP/2 and TLS 1.3 -- all of which the Go client
 * got from net/http. Hand-rolling that would be roughly 800 lines of
 * chunked-encoding, redirect and proxy handling inside a root-privileged
 * process, to save nothing: the shared library is on the box either way.
 */
#ifndef PAM_SSOOSSH_HTTPC_H
#define PAM_SSOOSSH_HTTPC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sse.h"

typedef enum {
    SSOOSSH_HTTP_OK = 0,
    /* Never reached the server: DNS, connect, TLS. The PAM stack falls
     * through on this, so an ssoossh outage does not become a sudo outage
     * on every host. */
    SSOOSSH_HTTP_TRANSPORT,
    /* Reached the server and it said no. Definitive. */
    SSOOSSH_HTTP_STATUS,
    SSOOSSH_HTTP_TIMEOUT,
    /* Ctrl-C at the approval prompt. */
    SSOOSSH_HTTP_CANCELLED,
    SSOOSSH_HTTP_TOO_LARGE,
    SSOOSSH_HTTP_INTERNAL,
} ssoossh_http_result;

/* CLOCK_MONOTONIC in milliseconds. Deadlines are absolute values of this,
 * so a clock step during a wait cannot extend or shorten it -- which
 * matters because the wait is bounded in real time while a human decides. */
int64_t ssoossh_monotonic_ms(void);

/* Names the libcurl actually linked into this process, for the version
 * line. Same reason as the crypto half: which libcurl is resident in sudo
 * is a property of the host, not of our release. */
const char *ssoossh_httpc_version(void);

/* POSTs body as JSON and reads the response.
 *
 * A non-2xx is SSOOSSH_HTTP_STATUS with *status set and the body still in
 * resp, because ssoosshd's error bodies carry a message worth logging.
 * Cancellation and the deadline are checked throughout, so a Ctrl-C during
 * the create call behaves like one during the wait. */
ssoossh_http_result ssoossh_httpc_post_json(const char *url, const char *body,
                                            bool insecure, int64_t deadline_ms,
                                            char *resp, size_t resp_cap,
                                            size_t *resp_len, long *status);

/* Opens the events stream and feeds it to cb until a callback stops it, the
 * deadline passes, the user interrupts, or the server refuses definitively.
 *
 * A connection that establishes and then drops is not a failure: ssoosshd's
 * wait is idempotent per request, so a fresh connection picks up wherever
 * the request actually is. This reconnects after a short delay and keeps
 * waiting, bounded only by the deadline. So does a refusal with a status
 * that says to come back -- 429, or anything 5xx.
 *
 * Any other refusal is returned as it is. A transport error is deliberately
 * *not* retried: the request is probably still pending server-side, but
 * this runs inside sudo with nothing on the terminal to explain the wait,
 * and "connection refused" now is worth more to whoever is standing there
 * than the same answer a minute from now. */
ssoossh_http_result ssoossh_httpc_events(const char *url, bool insecure,
                                         int64_t deadline_ms, ssoossh_sse_cb cb,
                                         void *ctx, long *status, char *err,
                                         size_t err_cap);

#endif /* PAM_SSOOSSH_HTTPC_H */
