/* The unit-test runner.
 *
 * Writing to stdout is fine here and nowhere else: this is a test binary,
 * not the module. The CI grep that forbids stdio in the module explicitly
 * exempts tests/ for exactly this.
 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "suites.h"
#include "test.h"

int t_failures;

void t_failf(const char *file, int line, const char *fmt, ...)
{
    va_list ap;
    const char *base = strrchr(file, '/');

    t_failures++;
    fprintf(stderr, "  FAIL %s:%d: ", base != NULL ? base + 1 : file, line);
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

static const struct {
    const char *name;
    int (*fn)(void);
} suites[] = {
    {"duration", suite_duration}, {"args", suite_args},
    {"sanitize", suite_sanitize}, {"sshwire", suite_sshwire},
    {"der", suite_der},           {"crypto", suite_crypto},
    {"sshkey", suite_sshkey},     {"sshcert", suite_sshcert},
};

int main(int argc, char **argv)
{
    const char *only = (argc > 1) ? argv[1] : NULL;
    int total = 0, ran = 0;

    for (size_t i = 0; i < sizeof(suites) / sizeof(suites[0]); i++) {
        if (only != NULL && strcmp(only, suites[i].name) != 0) {
            continue;
        }
        t_failures = 0;
        int failures = suites[i].fn();
        printf("%-16s %s\n", suites[i].name, failures == 0 ? "ok" : "FAILED");
        total += failures;
        ran++;
    }

    if (ran == 0) {
        fprintf(stderr, "no suite matched %s\n", only);
        return 2;
    }
    if (total != 0) {
        fprintf(stderr, "unit: %d failure(s)\n", total);
        return 1;
    }
    printf("unit: ok (%d suites)\n", ran);
    return 0;
}
