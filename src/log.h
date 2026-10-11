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
#include <stddef.h>
#include <stdint.h>

/* Enables ssoossh_debugf output. Off unless the module argument says
 * otherwise; args parsing arrives in P1. */
void ssoossh_log_set_debug(bool enabled);

void ssoossh_debugf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void ssoossh_infof(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void ssoossh_noticef(const char *fmt, ...)
    __attribute__((format(printf, 1, 2)));
void ssoossh_warnf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void ssoossh_errf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* Room for one certificate field -- a key ID, a principal -- once escaped
 * for a log line, NUL included. Real ones are an email address or two; the
 * cap is here because whoever holds the CA key chooses the field, and a log
 * line is not the place to find out how long it can be. */
#define SSOOSSH_LOG_FIELD_LEN 256

/* The same for a server's own message -- an error string -- which runs
 * longer than a name does. */
#define SSOOSSH_LOG_TEXT_LEN 1024

/* Renders len bytes for a log line. Printable ASCII passes through, a
 * double quote and a backslash are escaped with a backslash, and every
 * other byte -- control characters, newlines, DEL, anything non-ASCII --
 * becomes \xNN. The result is NUL-terminated and never ends mid-escape.
 *
 * For text a certificate carries. A CA signature says who issued it, not
 * that it is safe to hand to syslog: an unescaped newline would let a key
 * ID write a second, forged line into auth.log.
 *
 * Returns false if the input did not fit and was cut short, so the caller
 * can mark the cut rather than present a prefix as the whole value. */
bool ssoossh_log_escape(const uint8_t *p, size_t len, char *out,
                        size_t out_cap);

/* ssoossh_log_escape for a NUL-terminated string printed with no cut
 * marker of its own: one that does not fit ends in "..." inside out.
 * out_cap must be at least 4.
 *
 * For any string this host did not write and is about to log: the account
 * name, which sshd hands PAM as the client sent it, valid account or not;
 * the PAM items the application set; and anything the server or its
 * certificate said, which a JSON \n escape or a raw byte in a certificate
 * can turn into a second line. */
void ssoossh_log_escape_str(const char *s, char *out, size_t out_cap);

/* Logs the module version, the ssoosshd release it was qualified against,
 * and the versions of the crypto and HTTP libraries actually linked into
 * this process, at LOG_INFO, unconditionally.
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
