#include "fixture.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test.h"

size_t fixture_read(const char *name, char *buf, size_t cap)
{
    const char *dir = getenv("SSOOSSH_FIXTURES");
    char path[512];
    FILE *f;
    size_t n;

    (void)snprintf(path, sizeof(path), "%s/%s",
                   dir != NULL ? dir : "tests/fixtures", name);
    f = fopen(path, "rb");
    if (f == NULL) {
        t_failf(__FILE__, __LINE__, "cannot open fixture %s", path);
        return 0;
    }
    n = fread(buf, 1, cap - 1, f);
    (void)fclose(f);
    buf[n] = '\0';
    return n;
}

size_t fixture_read_line(const char *name, char *buf, size_t cap)
{
    size_t n = fixture_read(name, buf, cap);

    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) {
        buf[--n] = '\0';
    }
    return n;
}
