/* Logging for pam_ssoossh.
 *
 * The module is loaded into sudo and sshd, where stdout and stderr belong to
 * the host process. Nothing here writes to either: everything goes to
 * syslog(3) under LOG_AUTHPRIV.
 *
 * openlog(3) and closelog(3) are deliberately not called. openlog mutates
 * process-global state (ident, facility, options) and closelog closes a
 * descriptor the host may be holding; neither is ours to touch from inside
 * sudo. syslog(3) on its own uses the default connection, so every message
 * carries its own "pam_ssoossh:" prefix instead.
 */
#ifndef PAM_SSOOSSH_LOG_H
#define PAM_SSOOSSH_LOG_H

#include <stdbool.h>

/* Enables ssoossh_debugf output. Off unless the module argument says
 * otherwise; args parsing arrives in P1. */
void ssoossh_log_set_debug(bool enabled);

void ssoossh_debugf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void ssoossh_infof(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void ssoossh_noticef(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void ssoossh_warnf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void ssoossh_errf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* Logs the module version and the versions of the crypto and HTTP libraries
 * actually linked into this process, at LOG_INFO, unconditionally.
 *
 * Unconditional because a module that only reports its version once debug is
 * already enabled is a worse support problem than one extra line per sudo.
 *
 * The linked-library half matters because this module links crypto rather
 * than shipping it: which OpenSSL is resident in sudo is a property of the
 * host, not of our release, and this line is what makes that answerable
 * across a fleet by grepping syslog. */
void ssoossh_log_version(void);

#endif /* PAM_SSOOSSH_LOG_H */
