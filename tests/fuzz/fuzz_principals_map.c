/* The principals-map parser, over a file an operator edits by hand.
 *
 * Operator-controlled rather than network-controlled, and fuzzed anyway:
 * the file is read as root, and a map that fails to load silently changes
 * the policy in force -- the module falls back to requiring the exact
 * account name. Both outcomes have to be reached deliberately rather than
 * by a parser losing its place.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "principals_map.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char path[] = "/tmp/ssoossh-fuzz-map-XXXXXX";
    ssoossh_principals p;
    char err[256];
    int fd;

    if (size > 256 * 1024) {
        return 0;
    }

    fd = mkstemp(path);
    if (fd < 0) {
        return 0;
    }
    if (write(fd, data, size) != (ssize_t)size) {
        (void)close(fd);
        (void)unlink(path);
        return 0;
    }
    (void)close(fd);

    if (ssoossh_principals_map_load(path, "alice", &p, err, sizeof(err)) ==
        SSOOSSH_MAP_OK) {
        static const char *const certp[] = {"alice", "admin"};

        if (p.count > SSOOSSH_MAX_MAP_PRINCIPALS) {
            __builtin_trap();
        }
        for (size_t i = 0; i < p.count; i++) {
            /* Every stored principal must be NUL-terminated inside its
             * slot, or the comparison below reads past it. */
            if (strnlen(p.principals[i], SSOOSSH_MAX_PRINCIPAL_LEN) >=
                SSOOSSH_MAX_PRINCIPAL_LEN) {
                __builtin_trap();
            }
        }
        (void)ssoossh_principals_allow(&p, certp, 2);
    }

    (void)unlink(path);
    return 0;
}
