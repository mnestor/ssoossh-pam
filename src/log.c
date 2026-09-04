#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>

#ifdef __APPLE__
#  include <CommonCrypto/CommonCrypto.h>
#else
#  include <openssl/crypto.h>
#  include <openssl/opensslv.h>
#endif

#ifndef PAM_SSOOSSH_VERSION
#  define PAM_SSOOSSH_VERSION "dev"
#endif

/* Per-process, not per-transaction. A PAM transaction that turns debug on
 * affects concurrent transactions in the same process, which is the same
 * trade the Go module made and is acceptable for a verbosity flag; nothing
 * security-relevant reads it. */
static bool debug_enabled;

void ssoossh_log_set_debug(bool enabled) { debug_enabled = enabled; }

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

#define DEFINE_LOGF(name, priority)                  \
    void name(const char *fmt, ...)                  \
    {                                                \
        va_list ap;                                  \
        va_start(ap, fmt);                           \
        vlogf((priority), fmt, ap);                  \
        va_end(ap);                                  \
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

/* Names the crypto actually linked into this process.
 *
 * On macOS there is no version to report: Security.framework and
 * CommonCrypto ship with the OS and carry no independently queryable
 * version, so the backend is named instead. */
static const char *crypto_version(void)
{
#ifdef __APPLE__
    return "Security.framework";
#else
    return OpenSSL_version(OPENSSL_VERSION);
#endif
}

void ssoossh_log_version(void)
{
    ssoossh_infof("%s | crypto: %s", PAM_SSOOSSH_VERSION, crypto_version());
}
