/* pam_ssoossh -- authenticate a local account by having a human approve a
 * short-lived SSH certificate request in a browser.
 *
 * This is the P0 skeleton: it loads, reports its version, and denies. The
 * flow it will run is in plans/pam-ssoossh-c/plan.mdx.
 *
 * Return codes come from <security/pam_modules.h> rather than being written
 * out numerically. That is not hygiene -- Linux-PAM and OpenPAM number their
 * constants differently (7 is PAM_AUTH_ERR on Linux-PAM and PAM_PERM_DENIED
 * on OpenPAM), so taking them from the header is what makes the FreeBSD and
 * macOS targets possible at all.
 */
#include <stddef.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "log.h"

/* The two entry points libpam resolves by name. Everything else in the
 * module is hidden -- see pam_ssoossh.map and the -fvisibility=hidden in the
 * Makefile -- so that nothing here can collide with a symbol in sudo. */
#define PAM_SSOOSSH_EXPORT __attribute__((visibility("default")))

PAM_SSOOSSH_EXPORT int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                           int argc, const char **argv);
PAM_SSOOSSH_EXPORT int pam_sm_setcred(pam_handle_t *pamh, int flags,
                                      int argc, const char **argv);

int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                        int argc, const char **argv)
{
    (void)pamh;
    (void)flags;

    /* Before anything else, including the argc check: an operator whose
     * pam.d line is malformed still needs to learn which module version is
     * refusing them. */
    ssoossh_log_version();

    /* argv is PAM-owned and non-NULL for any well-formed stack. A NULL here
     * means the stack could not be read, which is a configuration fault
     * rather than an authentication failure -- the same distinction
     * PAM_NO_MODULE_DATA carries for a missing trusted-ca-file. */
    if (argv == NULL && argc > 0) {
        ssoossh_errf("module arguments could not be read");
        return PAM_NO_MODULE_DATA;
    }

    ssoossh_errf("not yet implemented (P0 skeleton): denying");
    return PAM_AUTH_ERR;
}

/* The module establishes no credentials of its own: the certificate it
 * validates is consumed within pam_sm_authenticate and never installed into
 * the session. Nothing to set, nothing to delete, nothing to refresh. */
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}
