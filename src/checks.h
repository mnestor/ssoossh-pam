/* The four checks that decide the answer.
 *
 * They run in order, every failure produces the same PAM code, and each one
 * logs a line at debug on success saying what it compared -- so an operator
 * running with `debug` can follow the decision from the log alone. Failures
 * log at error level unconditionally, because an operator debugging a
 * refusal has no way to reproduce it with debug turned on afterwards.
 *
 * Port of checks.go, message shapes included: the differential harness
 * compares the decision line in syslog, and an operator who has read one
 * module's messages should recognize the other's.
 */
#ifndef PAM_SSOOSSH_CHECKS_H
#define PAM_SSOOSSH_CHECKS_H

#include <stdbool.h>
#include <stdint.h>

#include "args.h"
#include "sshcert.h"
#include "sshkey.h"

/* Check 1: the certificate must be signed by one of the trusted CAs.
 *
 * A signature verification, not a string comparison against the CA file's
 * contents. A CA key that this backend cannot use, or an algorithm refused
 * by policy, is reported by name rather than as a bare signature failure. */
bool ssoossh_check_ca_signature(const ssoossh_cert *cert,
                                const ssoossh_ca_list *cas);

/* Check 2: the certificate's public key must be the one generated for this
 * attempt. Without it, checks 1, 3 and 4 passing together would accept any
 * CA-signed certificate carrying the right principal -- including one
 * issued to somebody else's keypair. */
bool ssoossh_check_key_binding(const ssoossh_cert *cert, const uint8_t *our_key,
                               size_t our_key_len);

/* Check 3: the certificate's principals must authorize the local account
 * PAM is authenticating -- not an OIDC identity the module never sees.
 *
 * With no map configured this is an exact match. With one configured, a
 * principal mapped to the account is accepted too. A map that is configured
 * but fails to load logs a warning and falls back to the exact match rather
 * than failing the login: a typo'd path degrades to the stricter default
 * instead of locking every account out of the host. */
bool ssoossh_check_principal(const ssoossh_cert *cert, const char *username,
                             const char *map_path);

/* Check 4: now must fall within [valid_after, valid_before], with the
 * tolerance applied symmetrically to absorb clock skew between the issuing
 * server and this host. The failure message names the observed skew,
 * because an operator debugging an intermittent 3am failure needs
 * "certificate not yet valid, 4.2s of skew, tolerance 2s" and not
 * "authentication failed". */
bool ssoossh_check_validity(const ssoossh_cert *cert, int64_t now,
                            ssoossh_duration tolerance);

#endif /* PAM_SSOOSSH_CHECKS_H */
