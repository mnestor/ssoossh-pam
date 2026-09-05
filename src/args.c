/* Module argument parsing. Port of args.go, plus the duration grammar C has
 * no equivalent for.
 *
 * Nothing here allocates. Values are copied into fixed buffers inside the
 * config, so there is no cleanup path to get wrong on a pam.d line that
 * fails to parse -- and the parse runs before anything else in the module,
 * where a leak would be hardest to see.
 */
#include "args.h"

#include <stdio.h>
#include <string.h>

#include "log.h"

/* Nanoseconds per unit, in the order time.ParseDuration's unitMap lists
 * them. "µs" is spelled two ways because both encodings occur in the wild:
 * U+00B5 MICRO SIGN, which is what Go's own Duration.String emits, and
 * U+03BC GREEK SMALL LETTER MU, which is what some editors produce. */
static const struct {
    const char *name;
    ssoossh_duration unit;
} duration_units[] = {
    {"ns", 1},
    {"us", 1000},
    {"\xc2\xb5s", 1000}, /* µs, U+00B5 */
    {"\xce\xbcs", 1000}, /* μs, U+03BC */
    {"ms", 1000000},
    {"s", 1000000000},
    {"m", 60LL * 1000000000},
    {"h", 3600LL * 1000000000},
};

#define INT64_MAX_V ((int64_t)0x7fffffffffffffffLL)

/* Consumes a run of decimal digits, failing rather than wrapping on
 * overflow -- the same contract as Go's leadingInt. */
static bool leading_int(const char **sp, int64_t *out)
{
    const char *s = *sp;
    int64_t x = 0;

    for (; *s >= '0' && *s <= '9'; s++) {
        if (x > INT64_MAX_V / 10) {
            return false;
        }
        x *= 10;
        int64_t d = *s - '0';
        if (x > INT64_MAX_V - d) {
            return false;
        }
        x += d;
    }
    *sp = s;
    *out = x;
    return true;
}

/* Consumes the digits after a decimal point, accumulating value and scale.
 * Digits past the point where the accumulator would overflow are consumed
 * and discarded rather than rejected: they cannot affect a nanosecond
 * result, and Go drops them the same way. */
static void leading_fraction(const char **sp, int64_t *value, double *scale)
{
    const char *s = *sp;
    int64_t x = 0;
    double sc = 1;
    bool overflow = false;

    for (; *s >= '0' && *s <= '9'; s++) {
        if (overflow) {
            continue;
        }
        if (x > INT64_MAX_V / 10) {
            overflow = true;
            continue;
        }
        int64_t y = x * 10 + (*s - '0');
        if (y < 0) {
            overflow = true;
            continue;
        }
        x = y;
        sc *= 10;
    }
    *sp = s;
    *value = x;
    *scale = sc;
}

bool ssoossh_duration_parse(const char *s, ssoossh_duration *out)
{
    int64_t d = 0;
    bool neg = false;

    if (s == NULL) {
        return false;
    }

    if (*s == '-' || *s == '+') {
        neg = (*s == '-');
        s++;
    }

    /* The one value allowed to omit its unit, and the reason "0" in a pam.d
     * line does not silently become the default. */
    if (strcmp(s, "0") == 0) {
        *out = 0;
        return true;
    }
    if (*s == '\0') {
        return false;
    }

    while (*s != '\0') {
        int64_t v = 0, f = 0;
        double scale = 1;
        bool pre, post = false;
        const char *unit_start;
        size_t unit_len;
        ssoossh_duration unit = 0;

        if (!(*s == '.' || (*s >= '0' && *s <= '9'))) {
            return false;
        }

        const char *before = s;
        if (!leading_int(&s, &v)) {
            return false;
        }
        pre = (s != before);

        if (*s == '.') {
            s++;
            const char *frac_start = s;
            leading_fraction(&s, &f, &scale);
            post = (s != frac_start);
        }
        if (!pre && !post) {
            /* ".s" and "-.s": a unit with no number in front of it. */
            return false;
        }

        unit_start = s;
        while (*s != '\0' && *s != '.' && !(*s >= '0' && *s <= '9')) {
            s++;
        }
        unit_len = (size_t)(s - unit_start);
        if (unit_len == 0) {
            return false; /* missing unit */
        }
        for (size_t i = 0;
             i < sizeof(duration_units) / sizeof(duration_units[0]); i++) {
            if (strlen(duration_units[i].name) == unit_len &&
                memcmp(duration_units[i].name, unit_start, unit_len) == 0) {
                unit = duration_units[i].unit;
                break;
            }
        }
        if (unit == 0) {
            return false; /* unknown unit */
        }

        if (v > INT64_MAX_V / unit) {
            return false;
        }
        v *= unit;
        if (f > 0) {
            /* double, not integer arithmetic: an hour's worth of fraction
             * needs more precision than int64 division leaves. The result
             * is bounded by one unit, so the cast cannot itself overflow;
             * the sign check below catches the sum that can. */
            v += (int64_t)((double)f * ((double)unit / scale));
            if (v < 0) {
                return false;
            }
        }
        d += v;
        if (d < 0) {
            return false;
        }
    }

    *out = neg ? -d : d;
    return true;
}

/* The two halves of Go's Duration.String, which builds its answer
 * right-to-left into a fixed buffer. Ported shape and all: writing the
 * digits backwards is what makes the "omit trailing zeros of the fraction"
 * rule a single pass. */
static size_t fmt_int(char *buf, size_t w, uint64_t v)
{
    if (v == 0) {
        buf[--w] = '0';
        return w;
    }
    while (v > 0) {
        buf[--w] = (char)('0' + (v % 10));
        v /= 10;
    }
    return w;
}

static size_t fmt_frac(char *buf, size_t w, uint64_t *v, int prec)
{
    bool print = false;

    for (int i = 0; i < prec; i++) {
        uint64_t digit = *v % 10;
        print = print || digit != 0;
        if (print) {
            buf[--w] = (char)('0' + digit);
        }
        *v /= 10;
    }
    if (print) {
        buf[--w] = '.';
    }
    return w;
}

char *ssoossh_duration_string(ssoossh_duration d, char *buf, size_t buf_size)
{
    /* 32 is what Go sizes its own buffer at: the longest possible rendering
     * is 2540400h10m10.000000000s. */
    char tmp[32];
    size_t w = sizeof(tmp);
    uint64_t u;
    bool neg = d < 0;

    u = neg ? (uint64_t)(-(d + 1)) + 1 : (uint64_t)d;

    if (u < (uint64_t)SSOOSSH_SECOND) {
        int prec;

        if (u == 0) {
            (void)snprintf(buf, buf_size, "0s");
            return buf;
        }
        tmp[--w] = 's';
        if (u < 1000) {
            prec = 0;
            tmp[--w] = 'n';
        } else if (u < 1000000) {
            prec = 3;
            /* U+00B5 MICRO SIGN, the two bytes Go writes. */
            tmp[--w] = (char)0xb5;
            tmp[--w] = (char)0xc2;
        } else {
            prec = 6;
            tmp[--w] = 'm';
        }
        w = fmt_frac(tmp, w, &u, prec);
        w = fmt_int(tmp, w, u);
    } else {
        tmp[--w] = 's';
        w = fmt_frac(tmp, w, &u, 9);
        w = fmt_int(tmp, w, u % 60);
        u /= 60;
        if (u > 0) {
            tmp[--w] = 'm';
            w = fmt_int(tmp, w, u % 60);
            u /= 60;
            /* Stops at hours, as Go does: days are not all the same
             * length, so there is no honest larger unit. */
            if (u > 0) {
                tmp[--w] = 'h';
                w = fmt_int(tmp, w, u);
            }
        }
    }
    if (neg) {
        tmp[--w] = '-';
    }

    (void)snprintf(buf, buf_size, "%.*s", (int)(sizeof(tmp) - w), tmp + w);
    return buf;
}

/* Copies value into dst, reporting truncation rather than silently storing
 * a prefix. A truncated URL is a request to the wrong server and a
 * truncated path is the wrong file; neither is something to guess at. */
static bool copy_value(char *dst, size_t dst_size, const char *value)
{
    size_t len = strlen(value);

    if (len >= dst_size) {
        return false;
    }
    memcpy(dst, value, len + 1);
    return true;
}

/* strconv.ParseBool's accepted spellings, which is what the Go module used
 * for insecure-skip-verify. Anything else leaves the flag at its safe
 * default rather than failing the login. */
static bool parse_bool(const char *v, bool *out)
{
    static const char *const yes[] = {"1", "t", "T", "true", "TRUE", "True"};
    static const char *const no[] = {"0", "f", "F", "false", "FALSE", "False"};

    for (size_t i = 0; i < sizeof(yes) / sizeof(yes[0]); i++) {
        if (strcmp(v, yes[i]) == 0) {
            *out = true;
            return true;
        }
    }
    for (size_t i = 0; i < sizeof(no) / sizeof(no[0]); i++) {
        if (strcmp(v, no[i]) == 0) {
            *out = false;
            return true;
        }
    }
    return false;
}

static bool ascii_eq_fold(const char *a, const char *b)
{
    for (; *a != '\0' && *b != '\0'; a++, b++) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') {
            ca = (char)(ca - 'A' + 'a');
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (char)(cb - 'A' + 'a');
        }
        if (ca != cb) {
            return false;
        }
    }
    return *a == *b;
}

static bool has_prefix_fold(const char *s, const char *prefix)
{
    size_t n = strlen(prefix);
    char head[16];

    if (strlen(s) < n || n >= sizeof(head)) {
        return false;
    }
    memcpy(head, s, n);
    head[n] = '\0';
    return ascii_eq_fold(head, prefix);
}

/* normalizeServerURL from the Go client: trims surrounding whitespace and
 * trailing slashes, and supplies https:// when the pam.d line gave no
 * scheme -- which the `server` argument has always promised. Without it a
 * bare "sso.example.com" produces a request that cannot be sent and an
 * approval URL no browser can open. */
static bool normalize_server(const char *raw, char *dst, size_t dst_size)
{
    size_t start = 0, end = strlen(raw);

    while (start < end && (raw[start] == ' ' || raw[start] == '\t' ||
                           raw[start] == '\n' || raw[start] == '\r')) {
        start++;
    }
    while (end > start && (raw[end - 1] == ' ' || raw[end - 1] == '\t' ||
                           raw[end - 1] == '\n' || raw[end - 1] == '\r')) {
        end--;
    }
    while (end > start && raw[end - 1] == '/') {
        end--;
    }

    size_t len = end - start;
    if (len == 0) {
        dst[0] = '\0';
        return true;
    }

    char trimmed[SSOOSSH_MAX_URL];
    if (len >= sizeof(trimmed)) {
        return false;
    }
    memcpy(trimmed, raw + start, len);
    trimmed[len] = '\0';

    if (has_prefix_fold(trimmed, "http://") ||
        has_prefix_fold(trimmed, "https://")) {
        return copy_value(dst, dst_size, trimmed);
    }
    /* Assembled with memcpy rather than snprintf: the bound is already
     * checked here, and a format call the compiler cannot prove bounded
     * fails the build under -Werror=format-truncation. */
    static const char scheme[] = "https://";
    const size_t scheme_len = sizeof(scheme) - 1;

    if (len + scheme_len >= dst_size) {
        return false;
    }
    memcpy(dst, scheme, scheme_len);
    memcpy(dst + scheme_len, trimmed, len + 1);
    return true;
}

ssoossh_args_status ssoossh_args_parse(int argc, const char **argv,
                                       ssoossh_config *cfg,
                                       const char **bad_arg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->skew_tolerance = SSOOSSH_DEFAULT_SKEW_TOLERANCE;
    cfg->timeout = SSOOSSH_DEFAULT_TIMEOUT;
    cfg->mode = SSOOSSH_MODE_AUTO;
    if (bad_arg != NULL) {
        *bad_arg = NULL;
    }

    for (int i = 0; i < argc; i++) {
        const char *arg = argv[i];
        const char *eq;
        char key[64];
        const char *value;
        size_t key_len;

        if (arg == NULL) {
            continue;
        }

        /* Split on the *first* '=' so a value may contain one -- a
         * principals-map path, or a server URL with a query string. */
        eq = strchr(arg, '=');
        if (eq == NULL) {
            key_len = strlen(arg);
            value = "true"; /* flag-style argument */
        } else {
            key_len = (size_t)(eq - arg);
            value = eq + 1;
        }

        /* An empty key is skipped rather than reported: "=value" in a
         * pam.d line is a typo with no plausible intent, and the Go module
         * ignores it. A key too long for the buffer cannot match any
         * argument this module has, so it is ignored the same way an
         * unknown key is. */
        if (key_len == 0 || key_len >= sizeof(key)) {
            continue;
        }
        memcpy(key, arg, key_len);
        key[key_len] = '\0';

        if (strcmp(key, "server") == 0) {
            if (!normalize_server(value, cfg->server, sizeof(cfg->server))) {
                goto too_long;
            }
        } else if (strcmp(key, "trusted-ca-file") == 0) {
            if (!copy_value(cfg->trusted_ca_file, sizeof(cfg->trusted_ca_file),
                            value)) {
                goto too_long;
            }
        } else if (strcmp(key, "principals-map") == 0) {
            if (!copy_value(cfg->principals_map, sizeof(cfg->principals_map),
                            value)) {
                goto too_long;
            }
        } else if (strcmp(key, "skew-tolerance") == 0) {
            /* Unparseable is silently the default, matching
             * parseDurationOrDefault. An operator who mistypes a tolerance
             * gets the documented 2s rather than a host nobody can log
             * into. */
            (void)ssoossh_duration_parse(value, &cfg->skew_tolerance);
        } else if (strcmp(key, "timeout") == 0) {
            (void)ssoossh_duration_parse(value, &cfg->timeout);
        } else if (strcmp(key, "insecure-skip-verify") == 0) {
            (void)parse_bool(value, &cfg->insecure_skip_verify);
        } else if (strcmp(key, "ssh-only") == 0) {
            (void)parse_bool(value, &cfg->ssh_only);
        } else if (strcmp(key, "debug") == 0) {
            /* Three-state in the Go module: absent or "false" is off, and
             * anything else -- including the legacy "stdout" -- means log.
             * stdout itself is gone: writing to a stream that belongs to
             * sudo is the one thing this module never does. */
            cfg->debug = !(ascii_eq_fold(value, "false") || value[0] == '\0');
        } else if (strcmp(key, "mode") == 0) {
            if (strcmp(value, "auto") == 0) {
                cfg->mode = SSOOSSH_MODE_AUTO;
            } else if (strcmp(value, "sudo") == 0) {
                cfg->mode = SSOOSSH_MODE_SUDO;
            } else if (strcmp(value, "console") == 0) {
#ifdef __APPLE__
                /* Recognized and refused, which is not the same as
                 * unrecognized. Console mode is not compiled into the macOS
                 * build -- that platform ships no artifact, so a console
                 * login there is scope with no user. Saying so beats
                 * running the browser flow under a name that asked for
                 * something else. */
                if (bad_arg != NULL) {
                    *bad_arg = arg;
                }
                return SSOOSSH_ARGS_CONSOLE_UNSUPPORTED;
#else
                cfg->mode = SSOOSSH_MODE_CONSOLE;
#endif
            } else {
                if (bad_arg != NULL) {
                    *bad_arg = arg;
                }
                return SSOOSSH_ARGS_BAD_MODE;
            }
        } else {
            /* An unknown argument is a warning, not a failure: a pam.d line
             * carrying an argument from a newer module version should not
             * take the host's auth stack down. */
            ssoossh_warnf("unknown module argument %s, ignoring", key);
        }
        continue;

    too_long:
        if (bad_arg != NULL) {
            *bad_arg = arg;
        }
        return SSOOSSH_ARGS_VALUE_TOO_LONG;
    }

    return SSOOSSH_ARGS_OK;
}
