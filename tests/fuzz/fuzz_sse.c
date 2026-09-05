/* The event-stream parser, fed one chunk at a time the way libcurl feeds
 * it. The split points matter as much as the bytes: a parser that
 * reassembles lines wrongly across a chunk boundary is one a network can
 * reach and a single-shot test cannot.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sse.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static bool sink(const char *name, const char *data, size_t data_len, void *ctx)
{
    (void)name;
    (void)ctx;
    /* Touch every byte, so a length that disagrees with the buffer shows up
     * as a read past the end rather than as nothing at all. */
    volatile char acc = 0;
    for (size_t i = 0; i < data_len; i++) {
        acc = (char)(acc ^ data[i]);
    }
    (void)acc;
    return true;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ssoossh_sse *s;

    if (size == 0) {
        return 0;
    }

    s = malloc(sizeof(*s));
    if (s == NULL) {
        return 0;
    }

    /* The first byte chooses a chunk size, so the fuzzer explores split
     * points as well as content. */
    {
        size_t chunk = (size_t)data[0] + 1;
        const char *p = (const char *)data + 1;
        size_t n = size - 1;

        ssoossh_sse_init(s);
        for (size_t off = 0; off < n;) {
            size_t take = n - off < chunk ? n - off : chunk;
            if (!ssoossh_sse_feed(s, p + off, take, sink, NULL)) {
                break;
            }
            off += take;
        }
        ssoossh_sse_end(s);
    }

    free(s);
    return 0;
}
