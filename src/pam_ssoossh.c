/* pam_ssoossh -- authenticate a local account by having a human approve a
 * short-lived SSH certificate request in a browser.
 *
 * This file is the PAM-facing half and nothing else: read the username,
 * parse the module arguments, hand off to auth.c, and turn the answer into
 * a return code. The flow itself is in auth.c, and the plan it implements
 * is in plans/pam-ssoossh-c/plan.mdx.
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

#include "args.h"
#include "auth.h"
#include "log.h"

/* The two entry points libpam resolves by name. Everything else in the
 * module is hidden -- see pam_ssoossh.map and the -fvisibility=hidden in the
 * Makefile -- so that nothing here can collide with a symbol in sudo. */
#define PAM_SSOOSSH_EXPORT __attribute__((visibility("default")))

PAM_SSOOSSH_EXPORT int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                           int argc, const char **argv);
PAM_SSOOSSH_EXPORT int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                                      const char **argv);

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                        const char **argv)
{
    ssoossh_config cfg;
    const char *bad_arg = NULL;
    const char *user = NULL;
    int rc;

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

    switch (ssoossh_args_parse(argc, argv, &cfg, &bad_arg)) {
    case SSOOSSH_ARGS_OK:
        break;
    case SSOOSSH_ARGS_CONSOLE_UNSUPPORTED:
        /* Recognized, designed, and not built: console mode needs server
         * endpoints that do not exist yet. Refusing is the fail-closed half
         * of the `mode` contract -- running the sudo flow instead would
         * authenticate through a path the pam.d line did not ask for. */
        ssoossh_errf("mode=console is not available in this build");
        return PAM_NO_MODULE_DATA;
    case SSOOSSH_ARGS_BAD_MODE:
        ssoossh_errf("unrecognized mode in module argument %s", bad_arg);
        return PAM_NO_MODULE_DATA;
    case SSOOSSH_ARGS_VALUE_TOO_LONG:
        ssoossh_errf("module argument value is too long to use");
        return PAM_NO_MODULE_DATA;
    }

    ssoossh_log_set_debug(cfg.debug);

    /* pam_get_user may itself run a conversation to ask for the name, so it
     * comes after argument parsing: a stack that is going to be refused for
     * a bad `mode` should not prompt first. */
    rc = pam_get_user(pamh, &user, NULL);
    if (rc != PAM_SUCCESS || user == NULL || user[0] == '\0') {
        ssoossh_errf("username could not be retrieved from the PAM handle");
        return PAM_USER_UNKNOWN;
    }

    rc = ssoossh_authenticate(pamh, user, &cfg);
    if (rc == PAM_SUCCESS) {
        ssoossh_infof("successful authentication: %s", user);
    }
    return rc;
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
