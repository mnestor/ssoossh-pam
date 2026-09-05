/* Ported from args_test.go, case for case, plus the cases C has to answer
 * that Go did not: the duration grammar (time.ParseDuration has no libc
 * equivalent), URL normalization (which the Go module did inside its API
 * client), and `mode`, which is new and fail-closed.
 */
#include "args.h"
#include "suites.h"
#include "test.h"

/* Parses a NULL-terminated argument list, so a case reads like the pam.d
 * line it stands for. */
static ssoossh_args_status parse(ssoossh_config *cfg, const char *const *args)
{
    int argc = 0;

    while (args[argc] != NULL) {
        argc++;
    }
    return ssoossh_args_parse(argc, (const char **)args, cfg, NULL);
}

/* A compound literal, so a case reads as the pam.d line it stands for.
 * Never called with no arguments -- C11 has no __VA_OPT__ and the empty
 * case has its own name below rather than a compiler extension. */
#define ARGS(...) ((const char *const[]){__VA_ARGS__, NULL})

static const char *const no_args[] = {NULL};

int suite_duration(void)
{
    static const struct {
        const char *in;
        ssoossh_duration want;
    } ok[] = {
        /* time.ParseDuration's own documented examples. */
        {"0", 0},
        {"5s", 5 * SSOOSSH_SECOND},
        {"2s", 2 * SSOOSSH_SECOND},
        {"60s", 60 * SSOOSSH_SECOND},
        {"90s", 90 * SSOOSSH_SECOND},
        {"2m", 120 * SSOOSSH_SECOND},
        {"1h", 3600 * SSOOSSH_SECOND},
        {"300ms", 300 * SSOOSSH_MILLISECOND},
        {"500ms", 500 * SSOOSSH_MILLISECOND},
        {"1.5h", 5400 * SSOOSSH_SECOND},
        {"1h30m", 5400 * SSOOSSH_SECOND},
        {"2h45m", (2 * 3600 + 45 * 60) * SSOOSSH_SECOND},
        {"-1.5h", -5400 * SSOOSSH_SECOND},
        {"+2s", 2 * SSOOSSH_SECOND},
        {"-0", 0},
        {"100ns", 100},
        {"1us", 1000},
        {"1\xc2\xb5s", 1000}, /* µs, U+00B5 -- what Go itself emits */
        {"1\xce\xbcs", 1000}, /* μs, U+03BC -- what some editors produce */
        {"1ms", SSOOSSH_MILLISECOND},
        {"0.5s", 500 * SSOOSSH_MILLISECOND},
        {".5s", 500 * SSOOSSH_MILLISECOND},
        {"1.0s", SSOOSSH_SECOND},
        {"3h30m45s", (3 * 3600 + 30 * 60 + 45) * SSOOSSH_SECOND},
    };
    static const char *const bad[] = {
        "",
        " ",
        "not-a-duration",
        "2",  /* a number with no unit */
        "2x", /* a unit that is not one */
        "s",  /* a unit with no number */
        ".s", /* the same, with a stray point */
        "-.s",
        "1d", /* days: Go has no such unit, and neither do we */
        "1.5",
        "--2s",
        "2s3",                   /* trailing digits with no unit */
        "9223372036854775808ns", /* one past int64 */
        "10000000000000000000h", /* overflows the multiply */
    };

    for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++) {
        ssoossh_duration got = 12345; /* poisoned, to catch a silent no-write */
        T_CHECKF(ssoossh_duration_parse(ok[i].in, &got),
                 "duration_parse(%s) rejected a valid value", ok[i].in);
        T_CHECKF(got == ok[i].want, "duration_parse(%s) = %lld, want %lld",
                 ok[i].in, (long long)got, (long long)ok[i].want);
    }

    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        ssoossh_duration got = 999;
        T_CHECKF(!ssoossh_duration_parse(bad[i], &got),
                 "duration_parse(%s) accepted an invalid value", bad[i]);
        /* A rejected parse must leave the caller's value alone -- that is
         * what makes "unparseable is silently the default" work in
         * ssoossh_args_parse without a second variable. */
        T_CHECKF(got == 999, "duration_parse(%s) wrote through on failure",
                 bad[i]);
    }

    /* Rendering, which log lines quote back at operators. The expected
     * strings are what Go's Duration.String produces for the same values. */
    static const struct {
        ssoossh_duration in;
        const char *want;
    } strings[] = {
        {0, "0s"},
        {2 * SSOOSSH_SECOND, "2s"},
        {5400 * SSOOSSH_SECOND, "1h30m0s"},
        {4200 * SSOOSSH_MILLISECOND, "4.2s"},
        {500 * SSOOSSH_MILLISECOND, "500ms"},
        {1500, "1.5\xc2\xb5s"},
        {100, "100ns"},
        {-2 * SSOOSSH_SECOND, "-2s"},
        {(60 * 60 + 60) * SSOOSSH_SECOND, "1h1m0s"},
    };
    for (size_t i = 0; i < sizeof(strings) / sizeof(strings[0]); i++) {
        char buf[32];
        T_EQ_STR(ssoossh_duration_string(strings[i].in, buf, sizeof(buf)),
                 strings[i].want);
    }

    return t_failures;
}

int suite_args(void)
{
    ssoossh_config cfg;

    /* Defaults, from an empty argument list. */
    T_EQ_INT(parse(&cfg, no_args), SSOOSSH_ARGS_OK);
    T_EQ_STR(cfg.server, "");
    T_EQ_STR(cfg.trusted_ca_file, "");
    T_EQ_STR(cfg.principals_map, "");
    T_EQ_INT(cfg.skew_tolerance, SSOOSSH_DEFAULT_SKEW_TOLERANCE);
    T_EQ_INT(cfg.timeout, SSOOSSH_DEFAULT_TIMEOUT);
    T_CHECK(!cfg.insecure_skip_verify);
    T_CHECK(!cfg.debug);
    T_EQ_INT(cfg.mode, SSOOSSH_MODE_AUTO);

    /* key=value pairs. */
    T_EQ_INT(parse(&cfg, ARGS("server=https://example.com",
                              "trusted-ca-file=/etc/ssoossh/ca.pub")),
             SSOOSSH_ARGS_OK);
    T_EQ_STR(cfg.server, "https://example.com");
    T_EQ_STR(cfg.trusted_ca_file, "/etc/ssoossh/ca.pub");

    /* An empty key is skipped, not an error. */
    T_EQ_INT(parse(&cfg, ARGS("=novalue", "server=https://example.com")),
             SSOOSSH_ARGS_OK);
    T_EQ_STR(cfg.server, "https://example.com");

    /* Split on the first '=' only, so a value may contain one. */
    T_EQ_INT(parse(&cfg, ARGS("server=https://example.com/a=b")),
             SSOOSSH_ARGS_OK);
    T_EQ_STR(cfg.server, "https://example.com/a=b");

    /* libpam has already merged a bracketed value into one element, so the
     * spaces inside it are ours to keep. */
    T_EQ_INT(parse(&cfg, ARGS("trusted-ca-file=a spaced path")),
             SSOOSSH_ARGS_OK);
    T_EQ_STR(cfg.trusted_ca_file, "a spaced path");

    /* A bare flag is boolean true. */
    T_EQ_INT(parse(&cfg, ARGS("insecure-skip-verify")), SSOOSSH_ARGS_OK);
    T_CHECK(cfg.insecure_skip_verify);

    T_EQ_INT(parse(&cfg, ARGS("insecure-skip-verify=false")), SSOOSSH_ARGS_OK);
    T_CHECK(!cfg.insecure_skip_verify);

    /* An unparseable bool leaves the safe default rather than failing. */
    T_EQ_INT(parse(&cfg, ARGS("insecure-skip-verify=maybe")), SSOOSSH_ARGS_OK);
    T_CHECK(!cfg.insecure_skip_verify);

    /* debug is tri-state in the Go module. Here the third state is gone
     * and folded into the second: stdout is accepted so no pam.d line
     * fails to parse, and logs to syslog like any other truthy value. */
    T_EQ_INT(parse(&cfg, ARGS("debug=false")), SSOOSSH_ARGS_OK);
    T_CHECK(!cfg.debug);
    T_EQ_INT(parse(&cfg, ARGS("debug=FALSE")), SSOOSSH_ARGS_OK);
    T_CHECK(!cfg.debug);
    T_EQ_INT(parse(&cfg, ARGS("debug")), SSOOSSH_ARGS_OK);
    T_CHECK(cfg.debug);
    T_EQ_INT(parse(&cfg, ARGS("debug=stdout")), SSOOSSH_ARGS_OK);
    T_CHECK(cfg.debug);
    T_EQ_INT(parse(&cfg, ARGS("debug=STDOUT")), SSOOSSH_ARGS_OK);
    T_CHECK(cfg.debug);
    T_EQ_INT(parse(&cfg, ARGS("debug=verbose")), SSOOSSH_ARGS_OK);
    T_CHECK(cfg.debug);
    T_EQ_INT(parse(&cfg, ARGS("debug=")), SSOOSSH_ARGS_OK);
    T_CHECK(!cfg.debug);

    /* Durations, and the fall back to the default that an existing pam.d
     * line with a typo in it depends on. */
    T_EQ_INT(parse(&cfg, ARGS("skew-tolerance=5s")), SSOOSSH_ARGS_OK);
    T_EQ_INT(cfg.skew_tolerance, 5 * SSOOSSH_SECOND);
    T_EQ_INT(parse(&cfg, ARGS("skew-tolerance=not-a-duration")),
             SSOOSSH_ARGS_OK);
    T_EQ_INT(cfg.skew_tolerance, SSOOSSH_DEFAULT_SKEW_TOLERANCE);
    T_EQ_INT(parse(&cfg, ARGS("timeout=90s")), SSOOSSH_ARGS_OK);
    T_EQ_INT(cfg.timeout, 90 * SSOOSSH_SECOND);
    T_EQ_INT(parse(&cfg, ARGS("timeout=2m")), SSOOSSH_ARGS_OK);
    T_EQ_INT(cfg.timeout, 120 * SSOOSSH_SECOND);
    T_EQ_INT(parse(&cfg, ARGS("timeout=not-a-duration")), SSOOSSH_ARGS_OK);
    T_EQ_INT(cfg.timeout, SSOOSSH_DEFAULT_TIMEOUT);

    T_EQ_INT(parse(&cfg, ARGS("principals-map=/etc/ssoossh/principals.yaml")),
             SSOOSSH_ARGS_OK);
    T_EQ_STR(cfg.principals_map, "/etc/ssoossh/principals.yaml");

    /* Server normalization. The Go module did this inside its API client;
     * doing it at parse time means the value in the log line and the value
     * on the wire are the same string. */
    T_EQ_INT(parse(&cfg, ARGS("server=example.com")), SSOOSSH_ARGS_OK);
    T_EQ_STR(cfg.server, "https://example.com");
    T_EQ_INT(parse(&cfg, ARGS("server=https://example.com/")), SSOOSSH_ARGS_OK);
    T_EQ_STR(cfg.server, "https://example.com");
    T_EQ_INT(parse(&cfg, ARGS("server=https://example.com///")),
             SSOOSSH_ARGS_OK);
    T_EQ_STR(cfg.server, "https://example.com");
    T_EQ_INT(parse(&cfg, ARGS("server=http://example.com")), SSOOSSH_ARGS_OK);
    T_EQ_STR(cfg.server, "http://example.com");
    T_EQ_INT(parse(&cfg, ARGS("server=HTTPS://example.com")), SSOOSSH_ARGS_OK);
    T_EQ_STR(cfg.server, "HTTPS://example.com");
    T_EQ_INT(parse(&cfg, ARGS("server=  example.com  ")), SSOOSSH_ARGS_OK);
    T_EQ_STR(cfg.server, "https://example.com");
    T_EQ_INT(parse(&cfg, ARGS("server=")), SSOOSSH_ARGS_OK);
    T_EQ_STR(cfg.server, "");
    T_EQ_INT(parse(&cfg, ARGS("server=/")), SSOOSSH_ARGS_OK);
    T_EQ_STR(cfg.server, "");

    /* An unknown argument warns and carries on: a pam.d line carrying an
     * argument from a newer module must not take the auth stack down. */
    T_EQ_INT(parse(&cfg, ARGS("no-such-argument=1", "server=example.com")),
             SSOOSSH_ARGS_OK);
    T_EQ_STR(cfg.server, "https://example.com");

    /* mode. auto is the default and decides per login; sudo and console
     * force one flow; anything else is fail-closed rather than a silent
     * fall back to the flow the line did not ask for. */
    T_EQ_INT(parse(&cfg, ARGS("mode=auto")), SSOOSSH_ARGS_OK);
    T_EQ_INT(cfg.mode, SSOOSSH_MODE_AUTO);
    T_EQ_INT(parse(&cfg, ARGS("mode=sudo")), SSOOSSH_ARGS_OK);
    T_EQ_INT(cfg.mode, SSOOSSH_MODE_SUDO);
#ifdef __APPLE__
    /* Console mode is not compiled into the macOS build. */
    T_EQ_INT(parse(&cfg, ARGS("mode=console")),
             SSOOSSH_ARGS_CONSOLE_UNSUPPORTED);
#else
    T_EQ_INT(parse(&cfg, ARGS("mode=console")), SSOOSSH_ARGS_OK);
    T_EQ_INT(cfg.mode, SSOOSSH_MODE_CONSOLE);
#endif
    T_EQ_INT(parse(&cfg, ARGS("mode=whatever")), SSOOSSH_ARGS_BAD_MODE);
    T_EQ_INT(parse(&cfg, ARGS("mode=Console")), SSOOSSH_ARGS_BAD_MODE);
    T_EQ_INT(parse(&cfg, ARGS("mode")), SSOOSSH_ARGS_BAD_MODE);

    /* A value that does not fit is reported rather than truncated: a
     * truncated path is the wrong file and a truncated URL is the wrong
     * server. */
    {
        char big[SSOOSSH_MAX_PATH + 32];
        const char *args[2];

        memset(big, 'a', sizeof(big) - 1);
        big[sizeof(big) - 1] = '\0';
        memcpy(big, "trusted-ca-file=/", 17);
        args[0] = big;
        args[1] = NULL;
        T_EQ_INT(parse(&cfg, args), SSOOSSH_ARGS_VALUE_TOO_LONG);
    }

    /* bad_arg names the element that failed, so the syslog line can quote
     * the operator's own text back at them. */
    {
        const char *bad = NULL;
        const char *args[] = {"mode=nope", NULL};
        T_EQ_INT(ssoossh_args_parse(1, args, &cfg, &bad),
                 SSOOSSH_ARGS_BAD_MODE);
        T_EQ_STR(bad, "mode=nope");
    }

    return t_failures;
}
