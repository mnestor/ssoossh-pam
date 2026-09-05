/* The two signals behind ssh-only. The environment half is fully under
 * the test's control, so it is asserted both ways. The ancestry half is
 * whatever this test process actually has above it -- an sshd when the
 * suite is run over SSH, none in CI -- so what is asserted is that it
 * answers without crashing, that it is stable, and that the combined
 * answer is the OR of the two. */
#include <stdlib.h>

#include "sshdetect.h"
#include "suites.h"
#include "test.h"

int suite_sshdetect(void)
{
    bool ancestry;

    unsetenv("SSH_CONNECTION");
    unsetenv("SSH_CLIENT");
    unsetenv("SSH_TTY");
    T_CHECK(!ssoossh_ssh_session_env());

    /* An empty value is the same as unset: a shell that exported the name
     * with nothing in it did not come from sshd. */
    setenv("SSH_TTY", "", 1);
    T_CHECK(!ssoossh_ssh_session_env());

    setenv("SSH_TTY", "/dev/pts/3", 1);
    T_CHECK(ssoossh_ssh_session_env());
    unsetenv("SSH_TTY");

    setenv("SSH_CLIENT", "10.0.0.5 51234 22", 1);
    T_CHECK(ssoossh_ssh_session_env());
    unsetenv("SSH_CLIENT");

    setenv("SSH_CONNECTION", "10.0.0.5 51234 10.0.0.9 22", 1);
    T_CHECK(ssoossh_ssh_session_env());
    T_CHECK(ssoossh_ssh_session());
    unsetenv("SSH_CONNECTION");

    ancestry = ssoossh_ssh_session_ancestry();
    T_CHECK(ssoossh_ssh_session_ancestry() == ancestry);
    T_CHECK(ssoossh_ssh_session() == ancestry);

    return t_failures;
}
