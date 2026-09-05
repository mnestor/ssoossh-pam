#include "httpc.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <curl/curl.h>

#include "cancel.h"
#include "json.h"
#include "log.h"

/* How long to wait before reconnecting an events stream that established
 * and then dropped. The Go client's figure. */
#define RECONNECT_DELAY_MS 250

/* How long one poll iteration blocks. It bounds how long a Ctrl-C waits to
 * be noticed, so it is short enough to feel immediate and long enough not
 * to spin. */
#define POLL_SLICE_MS 200

/* curl_global_init is not thread-safe and must run once. curl_global_cleanup
 * is never called at all: it tears down global state -- OpenSSL's included --
 * that the host process may itself be using. A PAM module does not get to
 * decide when sudo is finished with libcurl. */
static pthread_once_t global_once = PTHREAD_ONCE_INIT;
static CURLcode global_rc = CURLE_OK;

static void global_init(void)
{
    global_rc = curl_global_init(CURL_GLOBAL_DEFAULT);
}

const char *ssoossh_httpc_version(void)
{
    /* Assembled from curl_version_info rather than taken from
     * curl_version(), and the difference is not cosmetic.
     *
     * curl_version() builds the full feature string, and building it asks
     * every backend for its own version -- which on a libcurl compiled with
     * LDAP support means ldap_get_option, which means ldap_int_initialize,
     * which means sasl_client_init. That initialises an LDAP client and a
     * SASL library inside sudo, on every authentication, to write a log
     * line. valgrind is how that was found: the allocations are one-time
     * global state that nothing ever frees.
     *
     * curl_version_info reads a static struct instead. The two fields kept
     * are the ones an operator actually greps for -- which libcurl, and
     * which TLS library it drives. That second one is a separate layer from
     * the crypto this module calls directly, and it is historically the
     * larger attack surface, so it is worth naming on its own. */
    static char version[128];
    static bool built;

    if (!built) {
        const curl_version_info_data *info = curl_version_info(CURLVERSION_NOW);

        if (info == NULL || info->version == NULL) {
            (void)snprintf(version, sizeof(version), "libcurl/(unknown)");
        } else if (info->ssl_version == NULL) {
            (void)snprintf(version, sizeof(version), "libcurl/%s",
                           info->version);
        } else {
            (void)snprintf(version, sizeof(version), "libcurl/%s %s",
                           info->version, info->ssl_version);
        }
        built = true;
    }
    return version;
}

int64_t ssoossh_monotonic_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Applied to every handle. Each line here is load-bearing:
 *
 *   NOSIGNAL, because libcurl otherwise uses SIGALRM and siglongjmp for its
 *   synchronous resolver, which would corrupt sudo's signal state -- the
 *   exact class of interaction this port exists to remove.
 *
 *   No FOLLOWLOCATION: an authentication flow must not silently follow a
 *   redirect to another origin.
 *
 *   TLS 1.3 as the floor, matching the Go client's MinVersion. */
static void apply_common(CURL *h, bool insecure)
{
    static const char *const user_agent =
        "ssoossh-pam-c/" PAM_SSOOSSH_VERSION " (https://github.com/mnestor/"
        "ssoossh)";

    curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(h, CURLOPT_SSLVERSION, (long)CURL_SSLVERSION_TLSv1_3);
    curl_easy_setopt(h, CURLOPT_USERAGENT, user_agent);
    curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT_MS, 10000L);
    curl_easy_setopt(h, CURLOPT_TCP_NODELAY, 1L);
    /* Proxy from the environment is libcurl's default and is deliberately
     * left on: an ssoosshd reached through a corporate proxy is what the Go
     * client's cloned DefaultTransport gave for free. */

    if (insecure) {
        /* insecure-skip-verify. Logged loudly by the caller, because with
         * it on, everything the server says -- including the URL that goes
         * on the tty -- is unauthenticated. */
        curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 0L);
    }
}

/* Accumulates a bounded response body. */
typedef struct {
    char *buf;
    size_t cap;
    size_t len;
    bool too_large;
} body_sink;

static size_t write_body(char *p, size_t size, size_t nmemb, void *ctx)
{
    body_sink *s = ctx;
    size_t n = size * nmemb;

    if (s->len + n + 1 > s->cap) {
        s->too_large = true;
        return 0; /* aborts the transfer */
    }
    memcpy(s->buf + s->len, p, n);
    s->len += n;
    s->buf[s->len] = '\0';
    return n;
}

/* Shared by both calls: aborts the transfer when the user interrupted or
 * the deadline passed. Returning non-zero from here is how libcurl is told
 * to stop, and it is checked often enough that neither has to wait for a
 * socket event. */
typedef struct {
    int64_t deadline_ms;
    bool cancelled;
    bool timed_out;
} progress_ctx;

static int on_progress(void *ctx, curl_off_t dltotal, curl_off_t dlnow,
                       curl_off_t ultotal, curl_off_t ulnow)
{
    progress_ctx *p = ctx;

    (void)dltotal;
    (void)dlnow;
    (void)ultotal;
    (void)ulnow;

    if (ssoossh_cancel_fired()) {
        p->cancelled = true;
        return 1;
    }
    if (ssoossh_monotonic_ms() >= p->deadline_ms) {
        p->timed_out = true;
        return 1;
    }
    return 0;
}

ssoossh_http_result ssoossh_httpc_post_json(const char *url, const char *body,
                                            bool insecure, int64_t deadline_ms,
                                            char *resp, size_t resp_cap,
                                            size_t *resp_len, long *status)
{
    CURL *h = NULL;
    struct curl_slist *headers = NULL;
    body_sink sink = {resp, resp_cap, 0, false};
    progress_ctx prog = {deadline_ms, false, false};
    ssoossh_http_result result = SSOOSSH_HTTP_INTERNAL;
    CURLcode rc;

    *resp_len = 0;
    *status = 0;
    resp[0] = '\0';

    (void)pthread_once(&global_once, global_init);
    if (global_rc != CURLE_OK) {
        return SSOOSSH_HTTP_INTERNAL;
    }

    h = curl_easy_init();
    if (h == NULL) {
        return SSOOSSH_HTTP_INTERNAL;
    }

    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");
    if (headers == NULL) {
        curl_easy_cleanup(h);
        return SSOOSSH_HTTP_INTERNAL;
    }

    apply_common(h, insecure);
    curl_easy_setopt(h, CURLOPT_URL, url);
    curl_easy_setopt(h, CURLOPT_POST, 1L);
    curl_easy_setopt(h, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(h, CURLOPT_POSTFIELDSIZE, (long)strlen(body));
    curl_easy_setopt(h, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, write_body);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, &sink);
    curl_easy_setopt(h, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(h, CURLOPT_XFERINFOFUNCTION, on_progress);
    curl_easy_setopt(h, CURLOPT_XFERINFODATA, &prog);

    rc = curl_easy_perform(h);
    curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, status);
    *resp_len = sink.len;

    if (rc == CURLE_OK) {
        result = (*status >= 200 && *status < 300) ? SSOOSSH_HTTP_OK
                                                   : SSOOSSH_HTTP_STATUS;
    } else if (prog.cancelled) {
        result = SSOOSSH_HTTP_CANCELLED;
    } else if (prog.timed_out) {
        result = SSOOSSH_HTTP_TIMEOUT;
    } else if (sink.too_large) {
        result = SSOOSSH_HTTP_TOO_LARGE;
    } else {
        ssoossh_debugf("create call failed: %s", curl_easy_strerror(rc));
        result = SSOOSSH_HTTP_TRANSPORT;
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(h);
    return result;
}

/* One events connection's state. The status is not known when the first
 * body bytes arrive, so the write callback asks for it and then decides
 * whether it is holding an event stream or an error body. */
typedef struct {
    CURL *easy;
    ssoossh_sse *sse;
    ssoossh_sse_cb cb;
    void *cb_ctx;

    long status;
    bool status_known;

    /* Set when the status says this is not a stream. */
    bool is_error_body;
    char *err;
    size_t err_cap;
    size_t err_len;

    bool sse_stopped;
} stream_ctx;

static size_t write_stream(char *p, size_t size, size_t nmemb, void *ctx)
{
    stream_ctx *s = ctx;
    size_t n = size * nmemb;

    if (!s->status_known) {
        curl_easy_getinfo(s->easy, CURLINFO_RESPONSE_CODE, &s->status);
        s->status_known = true;
        s->is_error_body = s->status >= 300;
    }

    if (s->is_error_body) {
        size_t room = s->err_cap > 0 ? s->err_cap - 1 - s->err_len : 0;
        size_t take = n < room ? n : room;
        if (take > 0) {
            memcpy(s->err + s->err_len, p, take);
            s->err_len += take;
            s->err[s->err_len] = '\0';
        }
        /* The rest is dropped rather than refused: a server answering with
         * an HTML error page should still produce a status, not a transport
         * error that hides it. */
        return n;
    }

    if (!ssoossh_sse_feed(s->sse, p, n, s->cb, s->cb_ctx)) {
        if (s->sse->stopped) {
            s->sse_stopped = true;
        }
        return 0; /* aborts the transfer, which is what a terminal event
                   * and an overflow both want */
    }
    return n;
}

static bool retryable_status(long status)
{
    /* A rate limit or a server-side fault is transient and the request is
     * still pending behind it, so reconnecting is how the wait survives an
     * ssoosshd restart or a burst of load. A 4xx other than 429 is
     * ssoosshd's final answer about this request. */
    return status == 429 || status >= 500;
}

/* Runs one connection to the events URL. */
static ssoossh_http_result run_stream(const char *url, bool insecure,
                                      int64_t deadline_ms, ssoossh_sse *sse,
                                      ssoossh_sse_cb cb, void *ctx,
                                      long *status, char *err, size_t err_cap,
                                      bool *delivered)
{
    CURLM *multi = NULL;
    CURL *h = NULL;
    struct curl_slist *headers = NULL;
    stream_ctx sc;
    ssoossh_http_result result = SSOOSSH_HTTP_INTERNAL;
    int running = 1;

    memset(&sc, 0, sizeof(sc));
    sc.sse = sse;
    sc.cb = cb;
    sc.cb_ctx = ctx;
    sc.err = err;
    sc.err_cap = err_cap;
    *delivered = false;

    h = curl_easy_init();
    multi = curl_multi_init();
    if (h == NULL || multi == NULL) {
        goto done;
    }
    sc.easy = h;

    headers = curl_slist_append(headers, "Accept: text/event-stream");
    /* An intermediate cache holding an events stream would serve a stale
     * outcome, or none at all, forever. */
    headers = curl_slist_append(headers, "Cache-Control: no-cache");
    if (headers == NULL) {
        goto done;
    }

    apply_common(h, insecure);
    curl_easy_setopt(h, CURLOPT_URL, url);
    curl_easy_setopt(h, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(h, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, write_stream);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, &sc);

    if (curl_multi_add_handle(multi, h) != CURLM_OK) {
        goto done;
    }

    /* The poll loop. curl_multi_wait rather than curl_multi_poll: poll is
     * 7.66+ and the version floor is RHEL 8's 7.61. The documented cost is
     * that wait returns immediately when there is no descriptor to wait on
     * -- briefly the case during name resolution -- so the loop sleeps a
     * slice itself when numfds comes back zero. */
    for (;;) {
        int numfds = 0;
        long curl_timeout = -1;
        int64_t remaining = deadline_ms - ssoossh_monotonic_ms();
        long slice;

        if (ssoossh_cancel_fired()) {
            result = SSOOSSH_HTTP_CANCELLED;
            goto done;
        }
        if (remaining <= 0) {
            result = SSOOSSH_HTTP_TIMEOUT;
            goto done;
        }

        if (curl_multi_perform(multi, &running) != CURLM_OK) {
            result = SSOOSSH_HTTP_TRANSPORT;
            goto done;
        }
        if (running == 0) {
            break;
        }

        curl_multi_timeout(multi, &curl_timeout);
        slice = POLL_SLICE_MS;
        if (curl_timeout >= 0 && curl_timeout < slice) {
            slice = curl_timeout;
        }
        if (remaining < slice) {
            slice = (long)remaining;
        }
        if (slice < 1) {
            slice = 1;
        }

        if (curl_multi_wait(multi, NULL, 0, (int)slice, &numfds) != CURLM_OK) {
            result = SSOOSSH_HTTP_TRANSPORT;
            goto done;
        }
        if (numfds == 0) {
            struct timespec ts = {0, (long)slice * 1000000L};
            /* Interrupted by SIGINT is fine: the loop rechecks the flag. */
            (void)nanosleep(&ts, NULL);
        }
    }

    /* The transfer finished. Which way is the question. */
    {
        int msgs = 0;
        CURLMsg *m = curl_multi_info_read(multi, &msgs);
        CURLcode rc = CURLE_OK;

        if (m != NULL && m->msg == CURLMSG_DONE) {
            rc = m->data.result;
        }
        curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, status);

        if (sc.sse_stopped) {
            /* A callback said it had what it needed. The write callback
             * returned short to stop the transfer, which libcurl reports as
             * a write error -- expected, not a failure. */
            *delivered = true;
            result = SSOOSSH_HTTP_OK;
        } else if (sse->overflow) {
            result = SSOOSSH_HTTP_TOO_LARGE;
        } else if (sc.status_known && sc.status >= 300) {
            *status = sc.status;
            result = SSOOSSH_HTTP_STATUS;
        } else if (rc == CURLE_OK) {
            /* The stream ended cleanly without an outcome: a dropped
             * connection, which the caller reconnects for. */
            result = SSOOSSH_HTTP_TRANSPORT;
        } else {
            ssoossh_debugf("events stream ended: %s", curl_easy_strerror(rc));
            result = SSOOSSH_HTTP_TRANSPORT;
        }
    }

done:
    if (multi != NULL) {
        if (h != NULL) {
            curl_multi_remove_handle(multi, h);
        }
        curl_multi_cleanup(multi);
    }
    curl_slist_free_all(headers);
    curl_easy_cleanup(h);
    return result;
}

/* Sleeps between reconnects, waking early for a Ctrl-C or the deadline. */
static bool wait_to_reconnect(int64_t deadline_ms)
{
    int64_t until = ssoossh_monotonic_ms() + RECONNECT_DELAY_MS;

    while (ssoossh_monotonic_ms() < until) {
        struct timespec ts = {0, 20 * 1000000L};

        if (ssoossh_cancel_fired() || ssoossh_monotonic_ms() >= deadline_ms) {
            return false;
        }
        (void)nanosleep(&ts, NULL);
    }
    return true;
}

ssoossh_http_result ssoossh_httpc_events(const char *url, bool insecure,
                                         int64_t deadline_ms, ssoossh_sse_cb cb,
                                         void *ctx, long *status, char *err,
                                         size_t err_cap)
{
    ssoossh_sse *sse;
    ssoossh_http_result result = SSOOSSH_HTTP_TRANSPORT;

    *status = 0;
    if (err_cap > 0) {
        err[0] = '\0';
    }

    (void)pthread_once(&global_once, global_init);
    if (global_rc != CURLE_OK) {
        return SSOOSSH_HTTP_INTERNAL;
    }

    /* On the heap rather than the stack: the two buffers are 128 KiB
     * together, and this runs inside sudo. Freed on every path out. */
    sse = calloc(1, sizeof(*sse));
    if (sse == NULL) {
        return SSOOSSH_HTTP_INTERNAL;
    }

    for (;;) {
        bool delivered = false;

        ssoossh_sse_init(sse);
        result = run_stream(url, insecure, deadline_ms, sse, cb, ctx, status,
                            err, err_cap, &delivered);

        if (result == SSOOSSH_HTTP_OK && delivered) {
            break;
        }
        if (result == SSOOSSH_HTTP_CANCELLED ||
            result == SSOOSSH_HTTP_TIMEOUT ||
            result == SSOOSSH_HTTP_TOO_LARGE) {
            break;
        }
        if (result == SSOOSSH_HTTP_STATUS) {
            if (!retryable_status(*status)) {
                break;
            }
            ssoossh_debugf("events stream refused with %ld; reconnecting",
                           *status);
        } else if (*status != 0) {
            /* A response code means the connection was established and
             * then dropped -- an idle-timed-out proxy, a network blip, an
             * ssoosshd restart. ssoosshd's wait is idempotent per request,
             * so a fresh connection picks up wherever the request is. */
            ssoossh_debugf("events stream dropped; reconnecting");
        } else {
            /* Never established. Not retried: the request is probably
             * still pending server-side, but this runs inside sudo with
             * nothing on the terminal to explain a silent wait, and an
             * answer now is worth more than the same answer in a minute. */
            break;
        }

        if (!wait_to_reconnect(deadline_ms)) {
            result = ssoossh_cancel_fired() ? SSOOSSH_HTTP_CANCELLED
                                            : SSOOSSH_HTTP_TIMEOUT;
            break;
        }
    }

    free(sse);
    return result;
}
