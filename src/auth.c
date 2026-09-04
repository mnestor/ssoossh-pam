#include "auth.h"

#include <stdio.h>
#include <string.h>

#include <security/pam_modules.h>

#include "cancel.h"
#include "conv.h"
#include "log.h"

int ssoossh_authenticate(pam_handle_t *pamh, const char *user,
                         const ssoossh_config *cfg)
{
    ssoossh_cancel cancel;
    char skew[32], timeout[32];
    int rc;

    /* Configuration is validated before a key is generated or a socket is
     * opened, so a misconfigured pam.d entry costs neither. The two
     * failures get different codes on purpose: no server is "this module
     * cannot say anything about this user" (PAM_USER_UNKNOWN), while no
     * trusted CA is "the data this module needs is not here"
     * (PAM_NO_MODULE_DATA). */
    if (cfg->server[0] == '\0') {
        ssoossh_errf("not configured correctly in pam.d: server is required");
        return PAM_USER_UNKNOWN;
    }
    if (cfg->trusted_ca_file[0] == '\0') {
        ssoossh_errf(
            "not configured correctly in pam.d: trusted-ca-file is required");
        return PAM_NO_MODULE_DATA;
    }

    ssoossh_debugf(
        "args: server=%s trusted-ca-file=%s principals-map=%s "
        "skew-tolerance=%s timeout=%s insecure-skip-verify=%s",
        cfg->server, cfg->trusted_ca_file,
        cfg->principals_map[0] != '\0' ? cfg->principals_map : "(unset)",
        ssoossh_duration_string(cfg->skew_tolerance, skew, sizeof(skew)),
        ssoossh_duration_string(cfg->timeout, timeout, sizeof(timeout)),
        cfg->insecure_skip_verify ? "true" : "false");

    /* The handler is armed around the wait and nothing else, and disarmed
     * on every path out of it -- including this one, where there is not yet
     * a wait to interrupt. */
    ssoossh_cancel_arm(&cancel);

    rc = ssoossh_conv(pamh, PAM_TEXT_INFO,
                      "pam_ssoossh: browser approval is not built in this "
                      "version; declining.",
                      NULL);
    if (rc != PAM_SUCCESS) {
        /* Not fatal on its own: the attempt would still resolve without the
         * human having seen anything through this channel. */
        ssoossh_warnf("PAM conversation failed with code %d", rc);
    }

    ssoossh_cancel_disarm(&cancel);

    if (ssoossh_cancel_fired()) {
        /* PAM_IGNORE, not PAM_AUTH_ERR: someone who gives up on waiting
         * wants the next module's password prompt, not a dead sudo. */
        ssoossh_noticef("authentication was interrupted by the user");
        return PAM_IGNORE;
    }

    ssoossh_errf("the approval flow is not implemented yet: denying %s", user);
    return PAM_AUTH_ERR;
}
