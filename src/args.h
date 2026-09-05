/* Module arguments, as written in a pam.d line.
 *
 * The parse is a straight port of args.go, and the shapes it accepts are
 * part of the contract with existing deployments: an /etc/pam.d file that
 * works against the Go module must keep working here. That is why the
 * splitting rule, the tri-state debug value, and the "unparseable duration
 * silently becomes the default" behaviour are reproduced rather than
 * improved on.
 */
#ifndef PAM_SSOOSSH_ARGS_H
#define PAM_SSOOSSH_ARGS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Durations are nanoseconds, matching what time.ParseDuration produces, so
 * that "1.5h" and "500ms" mean here exactly what they mean in the pam.d
 * line an operator already has. */
typedef int64_t ssoossh_duration;

#define SSOOSSH_MILLISECOND ((ssoossh_duration)1000000)
#define SSOOSSH_SECOND (1000 * SSOOSSH_MILLISECOND)

/* Applied to both ends of the validity window (check 4), so it absorbs skew
 * in either direction. Chosen together with the server's
 * cert_options.pam.valid_duration. */
#define SSOOSSH_DEFAULT_SKEW_TOLERANCE (2 * SSOOSSH_SECOND)

/* How long the module blocks on a human approving in a browser. */
#define SSOOSSH_DEFAULT_TIMEOUT (60 * SSOOSSH_SECOND)

/* Bounds on the values that get copied out of PAM-owned argv. A pam.d line
 * longer than these is a configuration error, and reporting it as one is
 * better than silently authenticating against a truncated URL or reading a
 * truncated path. */
#define SSOOSSH_MAX_URL 512
#define SSOOSSH_MAX_PATH 4096

/* Which flow the module runs.
 *
 * `auto` is the default and the interesting one: it picks the console flow
 * when the login is at a console with no browser reachable from it, and the
 * browser flow otherwise. Which of the two is right is a property of where
 * someone is sitting, not something an operator can predict per host when
 * they write the pam.d line -- the same host answers differently for a
 * serial console and for an SSH session. src/console.c decides.
 *
 * `sudo` and `console` force one flow. Both are still fail-closed: an
 * unrecognized value is an error rather than a silent fall back, so a
 * pam.d line written for a future build does not quietly authenticate
 * through a path it did not ask for. */
typedef enum {
    SSOOSSH_MODE_AUTO = 0,
    SSOOSSH_MODE_SUDO,
    SSOOSSH_MODE_CONSOLE,
} ssoossh_mode;

typedef struct {
    /* Normalized: scheme supplied when the pam.d line omitted it, trailing
     * slashes trimmed. Empty when the argument was absent, which
     * pam_sm_authenticate reports as PAM_USER_UNKNOWN before it generates
     * a key or opens a socket. */
    char server[SSOOSSH_MAX_URL];

    char trusted_ca_file[SSOOSSH_MAX_PATH];
    char principals_map[SSOOSSH_MAX_PATH];

    ssoossh_duration skew_tolerance;
    ssoossh_duration timeout;

    bool insecure_skip_verify;
    bool debug;

    ssoossh_mode mode;
} ssoossh_config;

/* Why a parse failed. Only two shapes of argument can fail: `mode`, which
 * is fail-closed by design, and a value too long for the buffers above.
 * Everything else has a documented degradation (a bad duration becomes the
 * default; a bad bool becomes false) and never reports an error. */
typedef enum {
    SSOOSSH_ARGS_OK = 0,
    SSOOSSH_ARGS_BAD_MODE,
    /* mode=console on a build that does not carry it: macOS, which ships
     * no artifact and where a console login is scope with no user. */
    SSOOSSH_ARGS_CONSOLE_UNSUPPORTED,
    SSOOSSH_ARGS_VALUE_TOO_LONG,
} ssoossh_args_status;

/* Parses argc/argv as libpam hands them over. cfg is fully initialized to
 * its defaults whatever the return value, so a caller that logs and refuses
 * still has a usable debug flag to log with.
 *
 * bad_arg, when non-NULL, receives a pointer to the offending argv element
 * on failure -- borrowed from argv, not copied, and only valid as long as
 * PAM's argv is.
 *
 * libpam has already resolved `key=[a bracketed value]` into one argv
 * element by the time this runs (pam.conf(5)), so there is no re-splitting
 * to do here. */
ssoossh_args_status ssoossh_args_parse(int argc, const char **argv,
                                       ssoossh_config *cfg,
                                       const char **bad_arg);

/* time.ParseDuration's grammar: a signed sequence of decimal numbers, each
 * with an optional fraction and a required unit suffix -- "300ms", "-1.5h",
 * "2h45m". Units are ns, us (or µs), ms, s, m, h. A bare "0" is the one
 * value allowed to omit its unit.
 *
 * Returns false on anything else, including overflow, leaving *out
 * untouched. Callers in the argument path substitute their default rather
 * than failing, which is what the Go module does and what an operator's
 * existing pam.d line depends on. */
bool ssoossh_duration_parse(const char *s, ssoossh_duration *out);

/* Renders a duration the way Go's Duration.String does -- "2s", "1.5h",
 * "4.2s", "0s" -- because the strings it produces end up in operator-facing
 * log lines that the Go module's own messages set the precedent for.
 *
 * buf must be at least 32 bytes. Returns buf. */
char *ssoossh_duration_string(ssoossh_duration d, char *buf, size_t buf_size);

#endif /* PAM_SSOOSSH_ARGS_H */
