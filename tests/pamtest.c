// pamtest drives pam_start/pam_authenticate/pam_acct_mgmt against a named
// PAM service, using the standard misc_conv so any PAM_TEXT_INFO messages
// (the approval URL, and later the console code and QR) print to the
// terminal. It needs a real pam.d stack, so it needs root to install one --
// see tests/README.md. tests/loadtest.c covers what can be checked without.
//
//   make tests/pamtest PAMTEST_LIBS=-lpam_misc
//
// misc_conv is Linux-PAM's. On OpenPAM the equivalent is openpam_ttyconv,
// and PAMTEST_LIBS is empty because it lives in libpam itself.
//
// See tests/README.md for the full recipe: build environment, pam.d stanza,
// and how to install the module for a manual run.
#include <security/pam_appl.h>
#ifdef __linux__
#    include <security/pam_misc.h>
#    define SSOOSSH_CONV misc_conv
#else
#    include <security/openpam.h>
#    define SSOOSSH_CONV openpam_ttyconv
#endif
#include <signal.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    const char *service = (argc > 1) ? argv[1] : "ssoossh-test";
    pam_handle_t *p = NULL;
    struct pam_conv conv = {SSOOSSH_CONV, NULL};
    sigset_t block;

    /* Unbuffered, so the approval URL reaches a pipe reader (tee, or the
     * e2e harness) while pam_authenticate is still blocked waiting on the
     * browser. */
    setbuf(stdout, NULL);

    /* sudo runs its policy check -- the whole auth stack -- with the tty
     * signals blocked in the process mask, and re-raises whatever arrived
     * once the check is over. A module that only installs a SIGINT handler
     * never sees a Ctrl-C there: the signal sits pending until the module
     * has given up on its own. Block it here the same way, so the cancel
     * scenarios exercise what sudo does rather than the easier case where
     * a handler alone is enough. */
    sigemptyset(&block);
    sigaddset(&block, SIGINT);
    (void)sigprocmask(SIG_BLOCK, &block, NULL);

    int r = pam_start(service, "games", &conv, &p);
    if (r != PAM_SUCCESS) {
        fprintf(stderr, "start %d\n", r);
        return 1;
    }
    int auth = pam_authenticate(p, 0);
    printf("auth=%s\n", pam_strerror(p, auth));
    /* Run the account stage regardless, matching a real login flow's output,
     * but fold both results into the exit code: a permissive account stack
     * (e.g. pam_permit) must not turn a failed authentication into exit 0. */
    r = pam_acct_mgmt(p, 0);
    printf("acct=%s\n", pam_strerror(p, r));
    pam_end(p, r);
    return (auth == PAM_SUCCESS && r == PAM_SUCCESS) ? 0 : 1;
}
