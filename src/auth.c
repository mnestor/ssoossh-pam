/* One authentication attempt, end to end.
 *
 * The shape is auth.go's: validate the configuration before spending
 * anything, generate a keypair, ask ssoosshd to certify it, show a human
 * how to approve, wait, and run the four checks on what comes back.
 *
 * Two things about the structure are deliberate. Everything large lives in
 * one heap allocation rather than on the stack, because this runs inside
 * sudo and the buffers add up to a quarter of a megabyte. And there is one
 * exit path -- `goto done` -- because the private key has to be wiped on
 * every one of them, including the error paths, and a function with
 * fourteen early returns is a function where one of them eventually
 * forgets.
 */
#include "auth.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <security/pam_modules.h>

#include "cancel.h"
#include "checks.h"
#include "console.h"
#include "conv.h"
#include "crypto.h"
#include "httpc.h"
#include "json.h"
#include "localaddrs.h"
#include "log.h"
#include "sse.h"
#include "sshcert.h"
#include "sshkey.h"
#ifndef __APPLE__
#    include "qr.h"
#endif

/* Everything big, in one allocation with one free. */
typedef struct {
    char response[SSOOSSH_MAX_RESPONSE];
    uint8_t cert_blob[SSOOSSH_MAX_CERT];
    char cert_line[SSOOSSH_MAX_CERT_LINE];

    char body[8192];
    char url[1024];
    char events_url[1024];
    char approval_url[1024];
    char verification_url[1024];
    char verification_complete[1024];
    char user_code[64];
    char expires_at[64];
    char server_error[512];

    /* What reaches the tty, and the sanitized pieces it is built from. */
    char message[8192];
    char clean_url[1024];
    char clean_code[64];
#ifndef __APPLE__
    char qr[SSOOSSH_QR_MAX_OUT];
    char clean_qr[SSOOSSH_QR_MAX_OUT];
#endif

    ssoossh_ca_list cas;
    ssoossh_cert cert;

    uint8_t key_blob[SSOOSSH_MAX_KEY_BLOB];
    size_t key_blob_len;
    char key_line[SSOOSSH_MAX_KEY_LINE];
} attempt;

/* What the wait is looking for. */
typedef struct {
    attempt *a;
    char status[32];
    size_t data_len;
    bool have;
} wait_ctx;

/* Every status that resolves a request. Recognizing fewer than the full set
 * means an unlisted one arrives as an informational event and the wait
 * blocks forever on a terminal one that never comes. */
static bool is_terminal(const char *name)
{
    return strcmp(name, "approved") == 0 || strcmp(name, "denied") == 0 ||
           strcmp(name, "expired") == 0 || strcmp(name, "enrolled") == 0 ||
           strcmp(name, "failed") == 0;
}

static bool on_event(const char *name, const char *data, size_t data_len,
                     void *ctx)
{
    wait_ctx *w = ctx;

    if (!is_terminal(name)) {
        ssoossh_debugf("events: informational event %s", name);
        return true;
    }
    if (data_len >= sizeof(w->a->response)) {
        return true;
    }

    (void)snprintf(w->status, sizeof(w->status), "%s", name);
    memcpy(w->a->response, data, data_len);
    w->a->response[data_len] = '\0';
    w->data_len = data_len;
    w->have = true;
    return false; /* stop the stream: this is the answer */
}

/* Builds the create-request body. The field order is the Go struct's, and
 * an empty optional is omitted rather than sent empty, because that is what
 * encoding/json's omitempty does and the wire is a contract. */
static bool build_body(attempt *a, const char *user, const char *public_key,
                       const ssoossh_request_context *ctx, bool console)
{
    char addrs[SSOOSSH_MAX_LOCAL_ADDRS][SSOOSSH_ADDR_LEN];
    size_t n_addrs = ssoossh_local_addresses(addrs, SSOOSSH_MAX_LOCAL_ADDRS);
    size_t len = 0;
    bool ok = true;

    ok = ok && ssoossh_json_append(a->body, sizeof(a->body), &len,
                                   "{\"public_key\":");
    ok = ok &&
         ssoossh_json_append_string(a->body, sizeof(a->body), &len, public_key);
    ok = ok &&
         ssoossh_json_append(a->body, sizeof(a->body), &len, ",\"username\":");
    ok = ok && ssoossh_json_append_string(a->body, sizeof(a->body), &len, user);

    /* The context fields go with a console request and not with a PAM one.
     * The Go module does not send them on /api/certs/pam, and the sudo flow
     * is byte-for-byte wire parity with it until the differential harness
     * says otherwise. A console certificate authorizes a whole session, so
     * the approver needs to know which machine and which terminal is asking
     * -- and the console endpoint is new here anyway, so there is no
     * previous behaviour to match. */
    if (console) {
        static const struct {
            const char *name;
            size_t offset;
        } fields[] = {
            {",\"hostname\":", offsetof(ssoossh_request_context, hostname)},
            {",\"pam_service\":", offsetof(ssoossh_request_context, service)},
            {",\"tty\":", offsetof(ssoossh_request_context, tty)},
            {",\"remote_host\":", offsetof(ssoossh_request_context, rhost)},
        };

        for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
            const char *value = (const char *)ctx + fields[i].offset;

            if (value[0] == '\0') {
                continue;
            }
            ok = ok && ssoossh_json_append(a->body, sizeof(a->body), &len,
                                           fields[i].name);
            ok = ok && ssoossh_json_append_string(a->body, sizeof(a->body),
                                                  &len, value);
        }
    }

    ok = ok && ssoossh_json_append(a->body, sizeof(a->body), &len,
                                   ",\"requested_options\":{");
    if (n_addrs > 0) {
        ok = ok && ssoossh_json_append(a->body, sizeof(a->body), &len,
                                       "\"source_addresses\":[");
        for (size_t i = 0; i < n_addrs; i++) {
            if (i > 0) {
                ok = ok &&
                     ssoossh_json_append(a->body, sizeof(a->body), &len, ",");
            }
            ok = ok && ssoossh_json_append_string(a->body, sizeof(a->body),
                                                  &len, addrs[i]);
        }
        ok = ok && ssoossh_json_append(a->body, sizeof(a->body), &len, "]");
    }
    ok = ok && ssoossh_json_append(a->body, sizeof(a->body), &len, "}}");

    return ok;
}

/* Turns a failure of the HTTP exchange into the PAM code the stack sees.
 *
 * Everything that goes wrong at the HTTP layer is PAM_AUTHINFO_UNAVAIL, not
 * PAM_AUTH_ERR, and the distinction is worth being precise about because it
 * is easy to get backwards.
 *
 * PAM_AUTH_ERR is for a request that *resolved* and the answer was no: a
 * denial, an expiry, a signing failure, a certificate that failed a check.
 * Those are decisions.
 *
 * PAM_AUTHINFO_UNAVAIL is for "this module could not find out". A refused
 * connection is that. So is a 500, a 404, and a response body that is not
 * the JSON it claimed to be -- all of them mean ssoosshd is broken or
 * absent, not that this person may not sudo. The code matters because it is
 * what lets the stack fall through to pam_unix, which is what keeps an
 * ssoossh outage from becoming a sudo outage on every host at once.
 *
 * This also happens to be exactly what the Go module does: its
 * classifyRequestError maps everything except a timeout and a cancellation
 * onto PamAuthInfoUnavail. The differential harness is how the first
 * version of this function was found to disagree. */
static int http_to_pam(ssoossh_http_result r, long status,
                       const char *server_error, const char *what)
{
    switch (r) {
    case SSOOSSH_HTTP_OK:
        return PAM_SUCCESS;
    case SSOOSSH_HTTP_CANCELLED:
        ssoossh_noticef("authentication was interrupted by the user");
        return PAM_IGNORE;
    case SSOOSSH_HTTP_TIMEOUT:
        /* A timeout is a decision -- nobody approved in time -- rather than
         * a failure to reach anyone, which is why it is the one HTTP-layer
         * outcome that is PAM_AUTH_ERR. The Go module agrees. */
        ssoossh_errf("timed out waiting for approval");
        return PAM_AUTH_ERR;
    case SSOOSSH_HTTP_STATUS:
        ssoossh_errf("ssoosshd returned status %ld for the %s%s%s", status,
                     what, server_error[0] != '\0' ? ": " : "", server_error);
        return PAM_AUTHINFO_UNAVAIL;
    case SSOOSSH_HTTP_TOO_LARGE:
        ssoossh_errf("the %s response was larger than this module will read",
                     what);
        return PAM_AUTHINFO_UNAVAIL;
    case SSOOSSH_HTTP_TRANSPORT:
        ssoossh_errf("could not reach the ssoossh server for the %s", what);
        return PAM_AUTHINFO_UNAVAIL;
    case SSOOSSH_HTTP_INTERNAL:
    default:
        ssoossh_errf("the HTTP client could not be built");
        return PAM_ABORT;
    }
}

/* Joins the server's base URL with a relative path the server returned.
 *
 * ssoosshd returns approval, events and verification URLs relative -- it
 * does not know its own public base URL -- so the client that just POSTed
 * to it prepends the one it used. Refuses rather than truncating: a
 * truncated URL is a request to the wrong place, or a link that goes
 * somewhere else.
 *
 * rel may be dst, which is how a field is joined in place. */
static bool join_url(char *dst, size_t dst_cap, const char *base,
                     const char *rel)
{
    size_t b = strlen(base), r = strlen(rel);

    if (b + r + 1 > dst_cap) {
        return false;
    }
    memmove(dst + b, rel, r + 1);
    memcpy(dst, base, b);
    return true;
}

/* Everything the module puts on a tty is assembled here and nowhere else,
 * so there is one place to look for "can a server put bytes on the
 * terminal". Each value is filtered by what it is, not by where it came
 * from. */
static void show_browser_prompt(pam_handle_t *pamh, attempt *a)
{
    size_t dropped;
    int rc;

    dropped = ssoossh_sanitize(SSOOSSH_TEXT_URL, a->approval_url, a->clean_url,
                               sizeof(a->clean_url));
    if (dropped > 0) {
        ssoossh_warnf("the approval URL contained %zu character(s) that are "
                      "not valid in a URL; they were dropped before display",
                      dropped);
    }

    (void)snprintf(a->message, sizeof(a->message),
                   "Approve this request in your browser:\n%s", a->clean_url);

    rc = ssoossh_conv(pamh, PAM_TEXT_INFO, a->message, NULL);
    if (rc != PAM_SUCCESS) {
        /* Not fatal: the request still resolves without the human having
         * seen the URL through this channel, and it is in the log below at
         * debug for a support case working from syslog. */
        ssoossh_warnf("could not display the approval URL via the PAM "
                      "conversation: code %d",
                      rc);
    }
    ssoossh_debugf("approval URL: %s", a->clean_url);
}

static void show_console_prompt(pam_handle_t *pamh, attempt *a,
                                const char *server)
{
    size_t len = 0;
    int rc;

    (void)ssoossh_sanitize(SSOOSSH_TEXT_CODE, a->user_code, a->clean_code,
                           sizeof(a->clean_code));

    /* The verification URLs are relative, so the base URL is prepended
     * here -- the same way the approval URL is built. */
    {
        char joined[2048];

        if (!join_url(joined, sizeof(joined), server, a->verification_url)) {
            joined[0] = '\0';
        }
        (void)ssoossh_sanitize(SSOOSSH_TEXT_URL, joined, a->clean_url,
                               sizeof(a->clean_url));
    }

    len = (size_t)snprintf(a->message, sizeof(a->message),
                           "Approve this login from a device with a browser.\n"
                           "\n"
                           "  Go to:  %s\n"
                           "  Code:   %s\n",
                           a->clean_url, a->clean_code);

#ifndef __APPLE__
    /* The QR encodes the complete verification URL -- /c/<code> -- so a
     * phone camera skips the code box entirely. It is drawn only when it
     * fits; the code above is what always works. */
    if (a->verification_complete[0] != '\0' && len < sizeof(a->message)) {
        char complete[2048];
        size_t qr_len = 0;

        if (join_url(complete, sizeof(complete), server,
                     a->verification_complete)) {
            qr_len = ssoossh_qr_render(complete, a->qr, sizeof(a->qr));
        }
        if (qr_len > 0) {
            (void)ssoossh_sanitize(SSOOSSH_TEXT_QR, a->qr, a->clean_qr,
                                   sizeof(a->clean_qr));
            (void)snprintf(a->message + len, sizeof(a->message) - len, "\n%s",
                           a->clean_qr);
        }
    }
#else
    (void)server;
#endif

    rc = ssoossh_conv(pamh, PAM_TEXT_INFO, a->message, NULL);
    if (rc != PAM_SUCCESS) {
        ssoossh_warnf("could not display the console code via the PAM "
                      "conversation: code %d",
                      rc);
    }
    ssoossh_debugf("console verification URL: %s, code %s", a->clean_url,
                   a->clean_code);
}

int ssoossh_authenticate(pam_handle_t *pamh, const char *user,
                         const ssoossh_config *cfg)
{
    attempt *a = NULL;
    ssoossh_keypair *kp = NULL;
    ssoossh_cancel cancel;
    ssoossh_request_context ctx;
    wait_ctx wait;
    uint8_t point[256];
    size_t point_len = 0, resp_len = 0;
    int64_t start_ms, deadline_ms;
    long status = 0;
    char skew[32], timeout[32];
    bool console = false;
    bool armed = false;
    int rc = PAM_AUTH_ERR;

    /* Configuration is validated before a key is generated or a socket is
     * opened, so a misconfigured pam.d entry costs neither. The two
     * failures get different codes on purpose: no server is "this module
     * cannot say anything about this user", while no trusted CA is "the
     * data this module needs is not here". */
    if (cfg->server[0] == '\0') {
        ssoossh_errf("not configured correctly in pam.d: server is required");
        return PAM_USER_UNKNOWN;
    }
    if (cfg->trusted_ca_file[0] == '\0') {
        ssoossh_errf(
            "not configured correctly in pam.d: trusted-ca-file is required");
        return PAM_NO_MODULE_DATA;
    }

    a = calloc(1, sizeof(*a));
    if (a == NULL) {
        ssoossh_errf("out of memory");
        return PAM_ABORT;
    }

    ssoossh_debugf(
        "args: server=%s trusted-ca-file=%s principals-map=%s "
        "skew-tolerance=%s timeout=%s insecure-skip-verify=%s mode=%s",
        cfg->server, cfg->trusted_ca_file,
        cfg->principals_map[0] != '\0' ? cfg->principals_map : "(unset)",
        ssoossh_duration_string(cfg->skew_tolerance, skew, sizeof(skew)),
        ssoossh_duration_string(cfg->timeout, timeout, sizeof(timeout)),
        cfg->insecure_skip_verify ? "true" : "false",
        cfg->mode == SSOOSSH_MODE_AUTO      ? "auto"
        : cfg->mode == SSOOSSH_MODE_CONSOLE ? "console"
                                            : "sudo");

    if (cfg->insecure_skip_verify) {
        /* Loud, and at warning rather than debug. With this on, nothing the
         * server says is authenticated -- including the URL that goes on
         * the tty of a root process. */
        ssoossh_warnf("insecure-skip-verify is set: the ssoossh server's TLS "
                      "certificate is not being checked");
    }

    switch (ssoossh_ca_load(cfg->trusted_ca_file, &a->cas)) {
    case SSOOSSH_CA_OK:
        break;
    case SSOOSSH_CA_UNREADABLE:
        ssoossh_errf("trusted CA file %s could not be read",
                     cfg->trusted_ca_file);
        rc = PAM_NO_MODULE_DATA;
        goto done;
    case SSOOSSH_CA_MALFORMED:
        rc = PAM_NO_MODULE_DATA;
        goto done;
    case SSOOSSH_CA_NONE_USABLE:
        ssoossh_errf("trusted CA file %s contains no key this build can "
                     "verify with",
                     cfg->trusted_ca_file);
        rc = PAM_NO_MODULE_DATA;
        goto done;
    }
    ssoossh_debugf("loaded %zu trusted CA key(s) from %s (%zu skipped)",
                   a->cas.count, cfg->trusted_ca_file, a->cas.skipped);

    ssoossh_context_read(pamh, &ctx);

    switch (cfg->mode) {
    case SSOOSSH_MODE_CONSOLE:
        console = true;
        break;
    case SSOOSSH_MODE_SUDO:
        console = false;
        break;
    case SSOOSSH_MODE_AUTO:
    default:
        console = ssoossh_context_is_console(&ctx);
        break;
    }
#ifdef __APPLE__
    if (console) {
        /* Console mode is Linux and FreeBSD only. On a build that ships no
         * artifact, a console login is scope with no user -- and an
         * explicit mode=console is refused at argument-parse time, so
         * reaching here means auto-detection picked it. Fall back rather
         * than fail: the browser flow is what this platform has. */
        ssoossh_debugf("console detected but not compiled in on this "
                       "platform; using the browser flow");
        console = false;
    }
#endif
    ssoossh_infof("%s flow for %s (service=%s tty=%s rhost=%s)",
                  console ? "console" : "browser", user,
                  ctx.service[0] != '\0' ? ctx.service : "-",
                  ctx.tty[0] != '\0' ? ctx.tty : "-",
                  ctx.rhost[0] != '\0' ? ctx.rhost : "-");

    if (!ssoossh_crypto_keygen(&kp) ||
        !ssoossh_crypto_public_point(kp, point, sizeof(point), &point_len) ||
        !ssoossh_sshkey_blob_p384(point, point_len, a->key_blob,
                                  sizeof(a->key_blob), &a->key_blob_len) ||
        !ssoossh_sshkey_authorized_line(a->key_blob, a->key_blob_len,
                                        a->key_line, sizeof(a->key_line))) {
        ssoossh_errf("could not generate the per-attempt keypair");
        rc = PAM_ABORT;
        goto done;
    }
    {
        char fp[SSOOSSH_FINGERPRINT_LEN];
        ssoossh_sshkey_fingerprint(a->key_blob, a->key_blob_len, fp);
        ssoossh_debugf("generated ephemeral P-384 keypair for %s: %s", user,
                       fp);
    }

    if (!build_body(a, user, a->key_line, &ctx, console)) {
        ssoossh_errf("the certificate request body could not be built");
        rc = PAM_ABORT;
        goto done;
    }

    (void)snprintf(a->url, sizeof(a->url), "%s/api/certs/%s", cfg->server,
                   console ? "console" : "pam");

    /* The deadline is armed before the create call, so `timeout` bounds the
     * whole attempt rather than only the waiting half. Monotonic, so a
     * clock step while a human decides cannot extend or shorten it. */
    start_ms = ssoossh_monotonic_ms();
    deadline_ms = start_ms + cfg->timeout / SSOOSSH_MILLISECOND;

    /* Armed here rather than around the wait alone: the create call blocks
     * on the network too, and a Ctrl-C during it should behave the same
     * way. Disarmed on every path out, at `done`. */
    ssoossh_cancel_arm(&cancel);
    armed = true;

    {
        ssoossh_http_result r = ssoossh_httpc_post_json(
            a->url, a->body, cfg->insecure_skip_verify, deadline_ms,
            a->response, sizeof(a->response), &resp_len, &status);

        if (r != SSOOSSH_HTTP_OK) {
            (void)ssoossh_json_top_string(a->response, resp_len, "error",
                                          a->server_error,
                                          sizeof(a->server_error));
            rc = http_to_pam(r, status, a->server_error, "certificate request");
            goto done;
        }
    }

    if (!ssoossh_json_data_string(a->response, resp_len, "events_url",
                                  a->events_url, sizeof(a->events_url)) ||
        a->events_url[0] == '\0') {
        ssoossh_errf("the create response carried no events URL");
        rc = PAM_AUTHINFO_UNAVAIL;
        goto done;
    }
    (void)ssoossh_json_data_string(a->response, resp_len, "approval_url",
                                   a->approval_url, sizeof(a->approval_url));
    (void)ssoossh_json_data_string(a->response, resp_len, "user_code",
                                   a->user_code, sizeof(a->user_code));
    (void)ssoossh_json_data_string(a->response, resp_len, "verification_url",
                                   a->verification_url,
                                   sizeof(a->verification_url));
    (void)ssoossh_json_data_string(
        a->response, resp_len, "verification_url_complete",
        a->verification_complete, sizeof(a->verification_complete));

    /* expires_at is the server's own deadline for this request. Honouring
     * it fixes a real defect in the flow as it stands: the module's
     * `timeout` and the server's client_timeout are two numbers an operator
     * has to keep in agreement by hand, and getting it wrong leaves the
     * module waiting on a request the server already killed, reported as a
     * generic timeout. A server that does not send it degrades to today's
     * behaviour with no version negotiation. */
    if (ssoossh_json_data_string(a->response, resp_len, "expires_at",
                                 a->expires_at, sizeof(a->expires_at))) {
        int64_t expires_unix;

        if (ssoossh_parse_rfc3339(a->expires_at, &expires_unix)) {
            int64_t remaining = (expires_unix - (int64_t)time(NULL)) * 1000;
            int64_t server_deadline = ssoossh_monotonic_ms() + remaining;

            if (server_deadline < deadline_ms) {
                ssoossh_debugf("bounding the wait by the server's expires_at "
                               "(%s), %lld ms earlier than timeout",
                               a->expires_at,
                               (long long)(deadline_ms - server_deadline));
                deadline_ms = server_deadline;
            }
        } else {
            ssoossh_warnf("could not parse expires_at %s; using timeout alone",
                          a->expires_at);
        }
    }

    if (console) {
        if (a->user_code[0] == '\0' || a->verification_url[0] == '\0') {
            ssoossh_errf("the console create response carried no code");
            rc = PAM_AUTHINFO_UNAVAIL;
            goto done;
        }
        show_console_prompt(pamh, a, cfg->server);
    } else {
        if (a->approval_url[0] == '\0') {
            ssoossh_errf("the create response carried no approval URL");
            rc = PAM_AUTHINFO_UNAVAIL;
            goto done;
        }
        /* The URLs ssoosshd returns are relative: it does not know its own
         * public base URL, so the client that just POSTed to it prepends
         * the one it used. */
        if (!join_url(a->approval_url, sizeof(a->approval_url), cfg->server,
                      a->approval_url)) {
            ssoossh_errf("the approval URL is too long to use");
            rc = PAM_AUTHINFO_UNAVAIL;
            goto done;
        }
        show_browser_prompt(pamh, a);
    }

    if (!join_url(a->events_url, sizeof(a->events_url), cfg->server,
                  a->events_url)) {
        ssoossh_errf("the events URL is too long to use");
        rc = PAM_AUTHINFO_UNAVAIL;
        goto done;
    }

    memset(&wait, 0, sizeof(wait));
    wait.a = a;
    {
        ssoossh_http_result r = ssoossh_httpc_events(
            a->events_url, cfg->insecure_skip_verify, deadline_ms, on_event,
            &wait, &status, a->server_error, sizeof(a->server_error));

        if (r != SSOOSSH_HTTP_OK || !wait.have) {
            rc = http_to_pam(r == SSOOSSH_HTTP_OK ? SSOOSSH_HTTP_TRANSPORT : r,
                             status, a->server_error, "events stream");
            goto done;
        }
    }

    /* An envelope carrying an error means the server resolved the request
     * as a failure and said why. */
    if (ssoossh_json_top_string(a->response, wait.data_len, "error",
                                a->server_error, sizeof(a->server_error)) &&
        a->server_error[0] != '\0') {
        /* PAM_AUTHINFO_UNAVAIL rather than PAM_AUTH_ERR, matching the Go
         * module: an envelope error reaches its classifyRequestError the
         * same way a transport failure does. Arguably this one *is* a
         * decision and deserves PAM_AUTH_ERR -- but parity is the bar until
         * both modules change together, and falling through to pam_unix is
         * the safer of the two answers anyway. */
        ssoossh_errf("certificate request %s: %s", wait.status,
                     a->server_error);
        rc = PAM_AUTHINFO_UNAVAIL;
        goto done;
    }

    if (strcmp(wait.status, "approved") != 0) {
        /* Every terminal status is handled by name. An unhandled one would
         * otherwise fall through with no certificate and no error, which is
         * exactly the nil-error-success bug the Go module had to fix. */
        if (strcmp(wait.status, "denied") == 0) {
            ssoossh_errf("the request was denied");
        } else if (strcmp(wait.status, "expired") == 0) {
            ssoossh_errf("the request expired before anyone approved it");
        } else if (strcmp(wait.status, "failed") == 0) {
            /* Deliberately not PAM_AUTHINFO_UNAVAIL: the request reached
             * ssoosshd and was processed. This is a definitive no from a
             * reachable server, not a connectivity problem. */
            ssoossh_errf("ssoosshd could not issue the certificate");
        } else {
            ssoossh_errf("the server reported an unrecognized outcome \"%s\"",
                         wait.status);
        }
        rc = PAM_AUTH_ERR;
        goto done;
    }

    if (!ssoossh_json_data_string(a->response, wait.data_len, "certificate",
                                  a->cert_line, sizeof(a->cert_line)) ||
        a->cert_line[0] == '\0') {
        ssoossh_errf("the request was approved but no certificate was "
                     "delivered");
        rc = PAM_AUTH_ERR;
        goto done;
    }

    if (ssoossh_cert_parse_line(a->cert_line, strlen(a->cert_line),
                                a->cert_blob, sizeof(a->cert_blob),
                                &a->cert) != SSOOSSH_CERT_OK) {
        ssoossh_errf("the issued certificate could not be parsed");
        rc = PAM_AUTH_ERR;
        goto done;
    }

    {
        char key_fp[SSOOSSH_FINGERPRINT_LEN], ca_fp[SSOOSSH_FINGERPRINT_LEN];
        ssoossh_sshkey_fingerprint(a->cert.key_blob, a->cert.key_blob_len,
                                   key_fp);
        ssoossh_sshkey_fingerprint(a->cert.signature_key.p,
                                   a->cert.signature_key.len, ca_fp);
        ssoossh_debugf("issued certificate for %s: serial %llu, %zu "
                       "principal(s), key %s, signature key %s (%s)",
                       user, (unsigned long long)a->cert.serial,
                       a->cert.principal_count, key_fp, ca_fp,
                       a->cert.signature_algo);
    }

    if (!ssoossh_check_ca_signature(&a->cert, &a->cas) ||
        !ssoossh_check_key_binding(&a->cert, a->key_blob, a->key_blob_len) ||
        !ssoossh_check_principal(&a->cert, user, cfg->principals_map) ||
        !ssoossh_check_validity(&a->cert, (int64_t)time(NULL),
                                cfg->skew_tolerance)) {
        rc = PAM_AUTH_ERR;
        goto done;
    }

    rc = PAM_SUCCESS;

done:
    if (armed) {
        ssoossh_cancel_disarm(&cancel);
        /* A Ctrl-C that arrived after the transfer finished but before the
         * handler came down still means the same thing. */
        if (rc != PAM_SUCCESS && ssoossh_cancel_fired()) {
            ssoossh_noticef("authentication was interrupted by the user");
            rc = PAM_IGNORE;
        }
    }

    /* The private key lives in a root process's heap. It is per-attempt and
     * never written anywhere, but it is wiped rather than merely freed --
     * and so is everything derived from it, because the response buffer
     * held a certificate and the body held a public key. */
    ssoossh_crypto_keypair_free(kp);
    if (a != NULL) {
        ssoossh_crypto_wipe(a, sizeof(*a));
        free(a);
    }
    return rc;
}
