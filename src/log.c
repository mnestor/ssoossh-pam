#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>

#include "crypto.h"
#include "httpc.h"

#ifndef PAM_SSOOSSH_VERSION
#    define PAM_SSOOSSH_VERSION "dev"
#endif
#ifndef PAM_SSOOSSH_COMPAT
#    define PAM_SSOOSSH_COMPAT "unknown"
#endif

/* Per-process, not per-transaction. A PAM transaction that turns debug on
 * affects concurrent transactions in the same process, which is the same
 * trade the Go module made and is acceptable for a verbosity flag; nothing
 * security-relevant reads it. */
static bool debug_enabled;

void ssoossh_log_set_debug(bool enabled)
{
    debug_enabled = enabled;
}

/* Every message carries the module name because openlog is not called, so
 * syslog attributes the line to the host process (sudo, sshd) instead. */
static void vlogf(int priority, const char *fmt, va_list ap)
{
    char msg[2048];

    /* Return value deliberately unused: a truncated log line is strictly
     * better than no log line, and there is nowhere to report a logging
     * failure to from inside a PAM module. */
    (void)vsnprintf(msg, sizeof(msg), fmt, ap);
    syslog(LOG_AUTHPRIV | priority, "pam_ssoossh: %s", msg);
}

#define DEFINE_LOGF(name, priority)                                            \
    void name(const char *fmt, ...)                                            \
    {                                                                          \
        va_list ap;                                                            \
        va_start(ap, fmt);                                                     \
        vlogf((priority), fmt, ap);                                            \
        va_end(ap);                                                            \
    }

DEFINE_LOGF(ssoossh_infof, LOG_INFO)
DEFINE_LOGF(ssoossh_noticef, LOG_NOTICE)
DEFINE_LOGF(ssoossh_warnf, LOG_WARNING)
DEFINE_LOGF(ssoossh_errf, LOG_ERR)

#undef DEFINE_LOGF

void ssoossh_debugf(const char *fmt, ...)
{
    va_list ap;

    if (!debug_enabled) {
        return;
    }
    va_start(ap, fmt);
    vlogf(LOG_DEBUG, fmt, ap);
    va_end(ap);
}

void ssoossh_log_version(void)
{
    /* The linked library versions, not ours: this module links crypto and
     * HTTP rather than shipping them, so which OpenSSL and which libcurl
     * are resident in sudo is a property of the host. One line per
     * authentication is what makes that a syslog grep across a fleet
     * instead of guesswork -- including for a host whose distribution has
     * stopped issuing updates. */
    /* The ssoosshd field is the server release this build was qualified
     * against (SSOOSSHD_COMPAT in the Makefile), not the server it is
     * talking to: the module never learns that. The two are versioned
     * independently, so this is what answers "does this module match my
     * server" from syslog alone. */
    /* The FIPS field only where the platform has the switch, so a Mac's
     * line does not claim a mode it cannot be in. */
    const char *fips;

    switch (ssoossh_crypto_fips_state()) {
    case SSOOSSH_FIPS_ON:
        fips = " | fips: on";
        break;
    case SSOOSSH_FIPS_OFF:
        fips = " | fips: off";
        break;
    case SSOOSSH_FIPS_UNSWITCHED:
    default:
        fips = "";
        break;
    }
    ssoossh_infof("%s | ssoosshd: %s | crypto: %s%s | http: %s",
                  PAM_SSOOSSH_VERSION, PAM_SSOOSSH_COMPAT,
                  ssoossh_crypto_version(), fips, ssoossh_httpc_version());
}
