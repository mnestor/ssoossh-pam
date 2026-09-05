/* A unit-test harness small enough to read in one sitting.
 *
 * There is no framework here on purpose. The module links libpam,
 * libcrypto, and (from P4) libcurl, and every one of those is something an
 * operator's distribution provides; adding a test framework to the build
 * would be the first dependency in this repository that exists only for
 * developers. A suite is a function returning its failure count, and the
 * table in main.c is the registry.
 *
 * The acceptance criteria are the Go module's own test tables. Where a case
 * below looks arbitrary, it is usually because args_test.go or
 * checks_test.go had exactly that case, and parity is the bar.
 */
#ifndef SSOOSSH_TEST_H
#define SSOOSSH_TEST_H

#include <stdint.h>
#include <string.h>

/* Failures in the suite currently running. Reset by the runner. */
extern int t_failures;

/* Reports one failure. The format is deliberately printf-shaped so a case
 * can say what it compared, not just that it did. */
/* nonnull as well as format: gcc 15 otherwise reasons its way to a
 * "null format string" on the inlined call sites and fails the build under
 * -Werror. Every caller passes a literal, so saying so costs nothing. */
void t_failf(const char *file, int line, const char *fmt, ...)
    __attribute__((format(printf, 3, 4))) __attribute__((nonnull(3)));

#define T_CHECK(cond)                                                          \
    do {                                                                       \
        if (!(cond)) {                                                         \
            t_failf(__FILE__, __LINE__, "%s", #cond);                          \
        }                                                                      \
    } while (0)

#define T_CHECKF(cond, ...)                                                    \
    do {                                                                       \
        if (!(cond)) {                                                         \
            t_failf(__FILE__, __LINE__, __VA_ARGS__);                          \
        }                                                                      \
    } while (0)

#define T_EQ_INT(got, want)                                                    \
    do {                                                                       \
        long long g_ = (long long)(got), w_ = (long long)(want);               \
        if (g_ != w_) {                                                        \
            t_failf(__FILE__, __LINE__, "%s: got %lld, want %lld", #got, g_,   \
                    w_);                                                       \
        }                                                                      \
    } while (0)

#define T_EQ_STR(got, want)                                                    \
    do {                                                                       \
        const char *g_ = (got), *w_ = (want);                                  \
        if (g_ == NULL || w_ == NULL || strcmp(g_, w_) != 0) {                 \
            t_failf(__FILE__, __LINE__, "%s: got \"%s\", want \"%s\"", #got,   \
                    g_ == NULL ? "(null)" : g_, w_ == NULL ? "(null)" : w_);   \
        }                                                                      \
    } while (0)

#define T_EQ_MEM(got, got_len, want, want_len)                                 \
    do {                                                                       \
        size_t gl_ = (got_len), wl_ = (want_len);                              \
        if (gl_ != wl_ || memcmp((got), (want), gl_) != 0) {                   \
            t_failf(__FILE__, __LINE__, "%s: %zu bytes, want %zu and equal",   \
                    #got, gl_, wl_);                                           \
        }                                                                      \
    } while (0)

#endif /* SSOOSSH_TEST_H */
