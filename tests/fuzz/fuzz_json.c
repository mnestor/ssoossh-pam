/* The JSON reader, over a response body. Both accessors, because the
 * envelope walk and the data walk take different paths through the token
 * array, and the unescaper runs at the end of both.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "json.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char out[4096];
    static const char *const fields[] = {
        "certificate", "events_url", "approval_url", "user_code",
        "expires_at",  "error",      "error_code",
    };

    if (size > SSOOSSH_MAX_RESPONSE) {
        return 0;
    }

    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        (void)ssoossh_json_data_string((const char *)data, size, fields[i], out,
                                       sizeof(out));
        (void)ssoossh_json_top_string((const char *)data, size, fields[i], out,
                                      sizeof(out));
    }

    /* A timestamp field is parsed from a NUL-terminated string, so it gets
     * its own shape of input. */
    {
        char ts[128];
        int64_t unix_time;
        size_t n = size < sizeof(ts) - 1 ? size : sizeof(ts) - 1;

        memcpy(ts, data, n);
        ts[n] = '\0';
        (void)ssoossh_parse_rfc3339(ts, &unix_time);
    }
    return 0;
}
