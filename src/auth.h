/* One authentication attempt.
 *
 * Everything PAM-shaped stays in pam_ssoossh.c: reading the username,
 * mapping a result onto a return code, arming and disarming the SIGINT
 * handler. What is left here is the attempt itself -- generate a keypair,
 * ask ssoosshd to certify it, show a human the approval URL, wait, and
 * check what comes back -- which is the half worth testing without a live
 * pam_handle_t.
 *
 * Port of auth.go.
 */
#ifndef PAM_SSOOSSH_AUTH_H
#define PAM_SSOOSSH_AUTH_H

#include <security/pam_appl.h>

#include "args.h"

/* Runs one attempt for user under cfg, returning the PAM code the module
 * should return. pamh is used only for the conversation.
 *
 * Every failure is logged here, at the level that failure deserves, so the
 * caller does not have to translate a code back into a reason. */
int ssoossh_authenticate(pam_handle_t *pamh, const char *user,
                         const ssoossh_config *cfg);

#endif /* PAM_SSOOSSH_AUTH_H */
