/* The wire protocol above the socket: the JSON envelope and the event
 * stream.
 *
 * The SSE cases are ported from sse_test.go, including the ones that only
 * matter because a real proxy does them -- comments as keep-alives, a
 * chunk boundary in the middle of a line, CRLF. The JSON cases are written
 * against the three shapes ssoosshd sends plus the shapes a hostile server
 * would send instead.
 */
#include <stdio.h>
#include <string.h>

#include "json.h"
#include "sse.h"
#include "suites.h"
#include "test.h"

int suite_json(void)
{
    char out[512];

    /* The create response, as ssoosshd sends it. */
    {
        static const char body[] =
            "{\"data\":{\"request_id\":\"6f1c0a5e\",\"events_url\":\"/api/"
            "certs/requests/6f1c0a5e/events\",\"approval_url\":\"/approve/"
            "6f1c0a5e\",\"expires_at\":\"2026-09-04T22:30:00Z\"},\"error\":"
            "\"\"}";

        T_CHECK(ssoossh_json_data_string(body, strlen(body), "request_id", out,
                                         sizeof(out)));
        T_EQ_STR(out, "6f1c0a5e");
        T_CHECK(ssoossh_json_data_string(body, strlen(body), "events_url", out,
                                         sizeof(out)));
        T_EQ_STR(out, "/api/certs/requests/6f1c0a5e/events");
        T_CHECK(ssoossh_json_data_string(body, strlen(body), "approval_url",
                                         out, sizeof(out)));
        T_EQ_STR(out, "/approve/6f1c0a5e");

        /* A field the server did not send is absent, not an error. */
        T_CHECK(!ssoossh_json_data_string(body, strlen(body), "user_code", out,
                                          sizeof(out)));
    }

    /* The console create response carries three more fields. */
    {
        static const char body[] =
            "{\"data\":{\"request_id\":\"x\",\"events_url\":\"/e\","
            "\"approval_url\":\"/a\",\"user_code\":\"K7M4-QP2X\","
            "\"verification_url\":\"/console\","
            "\"verification_url_complete\":\"/c/K7M4QP2X\"}}";

        T_CHECK(ssoossh_json_data_string(body, strlen(body), "user_code", out,
                                         sizeof(out)));
        T_EQ_STR(out, "K7M4-QP2X");
        T_CHECK(ssoossh_json_data_string(
            body, strlen(body), "verification_url_complete", out, sizeof(out)));
        T_EQ_STR(out, "/c/K7M4QP2X");
    }

    /* The error body: {"data": null, "error": "..."}. */
    {
        static const char body[] =
            "{\"data\":null,\"error\":\"rate limit exceeded\",\"error_code\":"
            "\"too_many_requests\"}";

        T_CHECK(ssoossh_json_top_string(body, strlen(body), "error", out,
                                        sizeof(out)));
        T_EQ_STR(out, "rate limit exceeded");
        T_CHECK(ssoossh_json_top_string(body, strlen(body), "error_code", out,
                                        sizeof(out)));
        T_EQ_STR(out, "too_many_requests");
        /* data is null, so nothing under it is readable. */
        T_CHECK(!ssoossh_json_data_string(body, strlen(body), "certificate",
                                          out, sizeof(out)));
    }

    /* Escapes. A server that escapes its slashes -- some encoders do -- must
     * produce the same URL as one that does not. */
    {
        static const char body[] =
            "{\"data\":{\"approval_url\":\"\\/approve\\/6f1c\","
            "\"quoted\":\"a\\\"b\",\"newline\":\"a\\nb\","
            "\"unicode\":\"caf\\u00e9\",\"astral\":\"\\ud83d\\ude00\"}}";

        T_CHECK(ssoossh_json_data_string(body, strlen(body), "approval_url",
                                         out, sizeof(out)));
        T_EQ_STR(out, "/approve/6f1c");
        T_CHECK(ssoossh_json_data_string(body, strlen(body), "quoted", out,
                                         sizeof(out)));
        T_EQ_STR(out, "a\"b");
        T_CHECK(ssoossh_json_data_string(body, strlen(body), "newline", out,
                                         sizeof(out)));
        T_EQ_STR(out, "a\nb");
        T_CHECK(ssoossh_json_data_string(body, strlen(body), "unicode", out,
                                         sizeof(out)));
        T_EQ_STR(out, "caf\xc3\xa9");
        T_CHECK(ssoossh_json_data_string(body, strlen(body), "astral", out,
                                         sizeof(out)));
        T_EQ_STR(out, "\xf0\x9f\x98\x80"); /* U+1F600, from a surrogate pair */
    }

    /* Shapes that must not parse. A lone surrogate is the interesting one:
     * encoding it anyway produces bytes no decoder agrees about. */
    {
        static const char *const bad[] = {
            "",
            "[]", /* not an object */
            "not json",
            "{\"data\":{\"a\":\"\\ud83d\"}}", /* lone high */
            "{\"data\":{\"a\":\"\\udc00\"}}", /* lone low */
            "{\"data\":{\"a\":\"\\q\"}}",     /* unknown escape */
            "{\"data\":{\"a\":\"\\u00g0\"}}", /* bad hex */
            "{\"data\":{\"a\":\"unterminated",
        };

        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            T_CHECKF(!ssoossh_json_data_string(bad[i], strlen(bad[i]), "a", out,
                                               sizeof(out)),
                     "accepted malformed JSON: %s", bad[i]);
        }
    }

    /* A nested object must not be mistaken for the envelope's own field.
     * Without a skip that walks past a value's children, "error" inside
     * data would answer a query for the envelope's "error". */
    {
        static const char body[] =
            "{\"data\":{\"error\":\"inner\"},\"error\":\"outer\"}";

        T_CHECK(ssoossh_json_top_string(body, strlen(body), "error", out,
                                        sizeof(out)));
        T_EQ_STR(out, "outer");
        T_CHECK(ssoossh_json_data_string(body, strlen(body), "error", out,
                                         sizeof(out)));
        T_EQ_STR(out, "inner");
    }

    /* A value too long for the caller's buffer fails rather than
     * truncating: half a certificate is not a certificate. */
    {
        static const char body[] = "{\"data\":{\"a\":\"0123456789\"}}";
        char small[4];
        T_CHECK(!ssoossh_json_data_string(body, strlen(body), "a", small,
                                          sizeof(small)));
    }

    /* The JSON writer, which builds the request body. */
    {
        char buf[256];
        ssoossh_json_wr w;

        ssoossh_json_wr_init(&w, buf, sizeof(buf));
        ssoossh_json_append(&w, "{\"k\":");
        ssoossh_json_append_string(&w, "a\"b\\c\nd\te");
        ssoossh_json_append(&w, "}");
        T_CHECK(ssoossh_json_wr_ok(&w));
        T_EQ_STR(buf, "{\"k\":\"a\\\"b\\\\c\\nd\\te\"}");

        /* A control byte becomes \u00XX rather than reaching the wire. */
        ssoossh_json_wr_init(&w, buf, sizeof(buf));
        ssoossh_json_append_string(&w, "a\x01");
        T_CHECK(ssoossh_json_wr_ok(&w));
        T_EQ_STR(buf, "\"a\\u0001\"");

        /* Overflow is reported, never truncated into valid-looking JSON. */
        {
            char tiny[6];
            ssoossh_json_wr tw;

            ssoossh_json_wr_init(&tw, tiny, sizeof(tiny));
            ssoossh_json_append_string(&tw, "abcdefgh");
            T_CHECK(!ssoossh_json_wr_ok(&tw));

            /* And it latches: a later write that would have fit is still
             * dropped, so one check at the end is enough. */
            ssoossh_json_append(&tw, "x");
            T_CHECK(!ssoossh_json_wr_ok(&tw));
        }
    }

    /* RFC 3339, the shape Go's time.Time marshals to. */
    {
        static const struct {
            const char *in;
            int64_t want;
        } ok[] = {
            {"1970-01-01T00:00:00Z", 0},
            {"2026-09-04T22:30:00Z", 1788561000},
            {"2026-09-04T22:30:00.123456789Z", 1788561000},
            {"2026-09-04T23:30:00+01:00", 1788561000},
            {"2026-09-04T21:30:00-01:00", 1788561000},
        };
        static const char *const bad[] = {
            "",
            "2026-09-04",
            "2026-09-04T22:30:00",  /* no zone */
            "2026-13-04T22:30:00Z", /* month 13 */
            "2026-09-04T25:30:00Z",
            "2026-09-04T22:30:00Q",
            "2026-09-04T22:30:00+0100", /* no colon in the offset */
            "not a time",
        };
        int64_t got = 0;

        for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++) {
            T_CHECKF(ssoossh_parse_rfc3339(ok[i].in, &got), "rejected %s",
                     ok[i].in);
            T_CHECKF(got == ok[i].want, "%s parsed to %lld, want %lld",
                     ok[i].in, (long long)got, (long long)ok[i].want);
        }
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            T_CHECKF(!ssoossh_parse_rfc3339(bad[i], &got), "accepted %s",
                     bad[i]);
        }
    }

    return t_failures;
}

/* Collects the events a feed produced, so a case can assert on the whole
 * sequence rather than one at a time. */
typedef struct {
    char names[8][64];
    char data[8][512];
    size_t count;
    /* Stops the stream at this event index, to exercise the early return a
     * terminal event uses. */
    size_t stop_at;
} collector;

static bool collect(const char *name, const char *data, size_t data_len,
                    void *ctx)
{
    collector *c = ctx;

    if (c->count < 8) {
        (void)snprintf(c->names[c->count], sizeof(c->names[0]), "%s", name);
        if (data_len < sizeof(c->data[0])) {
            memcpy(c->data[c->count], data, data_len + 1);
        }
        c->count++;
    }
    return c->stop_at == 0 || c->count < c->stop_at;
}

/* Feeds a whole stream in one chunk. */
static collector feed(const char *stream, size_t stop_at)
{
    ssoossh_sse s;
    collector c;

    memset(&c, 0, sizeof(c));
    c.stop_at = stop_at;
    ssoossh_sse_init(&s);
    (void)ssoossh_sse_feed(&s, stream, strlen(stream), collect, &c);
    return c;
}

int suite_sse(void)
{
    /* One named event with data. */
    {
        collector c = feed("event: approved\ndata: {\"a\":1}\n\n", 0);
        T_EQ_INT(c.count, 1);
        T_EQ_STR(c.names[0], "approved");
        T_EQ_STR(c.data[0], "{\"a\":1}");
    }

    /* No space after the colon: the space is a separator, not data, and
     * exactly one of them is consumed. */
    {
        collector c = feed("event:approved\ndata:  x\n\n", 0);
        T_EQ_INT(c.count, 1);
        T_EQ_STR(c.names[0], "approved");
        T_EQ_STR(c.data[0], " x");
    }

    /* Multiple data lines are joined with newlines, as the spec requires. */
    {
        collector c = feed("event: approved\ndata: one\ndata: two\n\n", 0);
        T_EQ_INT(c.count, 1);
        T_EQ_STR(c.data[0], "one\ntwo");
    }

    /* Comments are keep-alives and dispatch nothing. A stream of nothing
     * but them is a stream with no events, not an empty event. */
    {
        collector c = feed(": keep-alive\n\n: another\n\n", 0);
        T_EQ_INT(c.count, 0);
    }

    /* An event with no name is still an event -- the spec calls it a
     * "message" -- and ssoosshd's are always named, so it should reach the
     * callback and be treated as informational there. */
    {
        collector c = feed("data: hello\n\n", 0);
        T_EQ_INT(c.count, 1);
        T_EQ_STR(c.names[0], "");
        T_EQ_STR(c.data[0], "hello");
    }

    /* A line with no colon names a field whose value is empty. Neither
     * field this client reads means anything empty. */
    {
        collector c = feed("event: approved\nbogus\ndata: x\n\n", 0);
        T_EQ_INT(c.count, 1);
        T_EQ_STR(c.data[0], "x");
    }

    /* id and retry belong to an EventSource and are ignored here. */
    {
        collector c =
            feed("id: 7\nretry: 100\nevent: approved\ndata: x\n\n", 0);
        T_EQ_INT(c.count, 1);
        T_EQ_STR(c.names[0], "approved");
    }

    /* CRLF, which a proxy may introduce. */
    {
        collector c = feed("event: approved\r\ndata: x\r\n\r\n", 0);
        T_EQ_INT(c.count, 1);
        T_EQ_STR(c.names[0], "approved");
        T_EQ_STR(c.data[0], "x");
    }

    /* Two events in one stream, and a callback that stops after the first
     * -- which is what a terminal event does. */
    {
        collector c =
            feed("event: pending\ndata: 1\n\nevent: approved\ndata: 2\n\n", 1);
        T_EQ_INT(c.count, 1);
        T_EQ_STR(c.names[0], "pending");
    }
    {
        collector c =
            feed("event: pending\ndata: 1\n\nevent: approved\ndata: 2\n\n", 0);
        T_EQ_INT(c.count, 2);
        T_EQ_STR(c.names[1], "approved");
        T_EQ_STR(c.data[1], "2");
    }

    /* An event that never got its blank line is not an event. A connection
     * that dropped mid-event has not delivered one. */
    {
        collector c = feed("event: approved\ndata: x\n", 0);
        T_EQ_INT(c.count, 0);
    }

    /* Chunk boundaries fall wherever the network puts them, including in
     * the middle of a field name, a value, and a CRLF pair. */
    {
        static const char stream[] =
            "event: approved\r\ndata: {\"certificate\":\"abc\"}\r\n\r\n";
        for (size_t split = 1; split < sizeof(stream) - 1; split++) {
            ssoossh_sse s;
            collector c;

            memset(&c, 0, sizeof(c));
            ssoossh_sse_init(&s);
            (void)ssoossh_sse_feed(&s, stream, split, collect, &c);
            (void)ssoossh_sse_feed(&s, stream + split,
                                   sizeof(stream) - 1 - split, collect, &c);
            T_CHECKF(c.count == 1, "split at %zu produced %zu event(s)", split,
                     c.count);
            if (c.count == 1) {
                T_EQ_STR(c.names[0], "approved");
                T_EQ_STR(c.data[0], "{\"certificate\":\"abc\"}");
            }
        }
    }

    /* A line that never ends. The stream is stopped and the overflow is
     * latched, so the caller reports it rather than carrying on with a
     * truncated event. */
    {
        ssoossh_sse s;
        collector c;
        char big[SSOOSSH_SSE_MAX_LINE + 16];

        memset(&c, 0, sizeof(c));
        memset(big, 'x', sizeof(big));
        ssoossh_sse_init(&s);
        T_CHECK(!ssoossh_sse_feed(&s, big, sizeof(big), collect, &c));
        T_CHECK(s.overflow);
        T_EQ_INT(c.count, 0);
    }

    return t_failures;
}
