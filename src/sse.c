#include "sse.h"

#include <string.h>

/* Also how a stream is ended: whatever is half-read is discarded, because
 * an event is dispatched by a blank line and a connection that dropped
 * mid-event never sent one -- so a trailing partial line is not an event
 * that arrived, it is one that did not. */
void ssoossh_sse_init(ssoossh_sse *s)
{
    s->line_len = 0;
    s->name[0] = '\0';
    s->data_len = 0;
    s->data[0] = '\0';
    s->have_event = false;
    s->overflow = false;
    s->stopped = false;
}

/* Dispatches whatever has accumulated, then resets for the next event. */
static bool dispatch(ssoossh_sse *s, ssoossh_sse_cb cb, void *ctx)
{
    bool keep_going = true;

    if (s->have_event) {
        s->data[s->data_len] = '\0';
        keep_going = cb(s->name, s->data, s->data_len, ctx);
        if (!keep_going) {
            s->stopped = true;
        }
    }
    s->name[0] = '\0';
    s->data_len = 0;
    s->have_event = false;
    return keep_going;
}

static bool handle_line(ssoossh_sse *s, ssoossh_sse_cb cb, void *ctx)
{
    const char *line = s->line;
    size_t len = s->line_len;
    const char *colon;
    size_t field_len, value_len;
    const char *value;

    /* A blank line dispatches. */
    if (len == 0) {
        return dispatch(s, cb, ctx);
    }

    /* A line beginning with a colon is a comment, which is how servers and
     * proxies keep an idle stream alive. */
    if (line[0] == ':') {
        return true;
    }

    colon = memchr(line, ':', len);
    if (colon == NULL) {
        /* A whole line with no colon names a field whose value is empty.
         * Neither field this client reads means anything empty. */
        return true;
    }
    field_len = (size_t)(colon - line);
    value = colon + 1;
    value_len = len - field_len - 1;

    /* A single leading space after the colon is separator, not data. */
    if (value_len > 0 && value[0] == ' ') {
        value++;
        value_len--;
    }

    if (field_len == 5 && memcmp(line, "event", 5) == 0) {
        if (value_len >= sizeof(s->name)) {
            s->overflow = true;
            return false;
        }
        memcpy(s->name, value, value_len);
        s->name[value_len] = '\0';
        s->have_event = true;
        return true;
    }

    if (field_len == 4 && memcmp(line, "data", 4) == 0) {
        /* Multiple data lines are joined with newlines, as the spec
         * requires. */
        size_t need = value_len + (s->data_len > 0 ? 1 : 0);

        if (s->data_len + need + 1 > sizeof(s->data)) {
            s->overflow = true;
            return false;
        }
        if (s->data_len > 0) {
            s->data[s->data_len++] = '\n';
        }
        memcpy(s->data + s->data_len, value, value_len);
        s->data_len += value_len;
        s->have_event = true;
        return true;
    }

    /* id and retry are read by an EventSource and mean nothing here. */
    return true;
}

bool ssoossh_sse_feed(ssoossh_sse *s, const char *p, size_t n,
                      ssoossh_sse_cb cb, void *ctx)
{
    if (s->overflow || s->stopped) {
        return false;
    }

    for (size_t i = 0; i < n; i++) {
        char c = p[i];

        if (c == '\n') {
            /* A CRLF stream leaves the CR at the end of the line. */
            if (s->line_len > 0 && s->line[s->line_len - 1] == '\r') {
                s->line_len--;
            }
            if (!handle_line(s, cb, ctx)) {
                s->line_len = 0;
                return false;
            }
            s->line_len = 0;
            continue;
        }

        if (s->line_len + 1 >= sizeof(s->line)) {
            s->overflow = true;
            return false;
        }
        s->line[s->line_len++] = c;
    }
    return true;
}
