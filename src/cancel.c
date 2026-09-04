#include "cancel.h"

#include <string.h>

/* The only thing the handler touches. sig_atomic_t is the one type the C
 * standard promises can be written from a handler and read outside it
 * without tearing; volatile keeps the poll loop from caching the read. */
static volatile sig_atomic_t interrupted;

static void on_sigint(int signo)
{
    (void)signo;
    interrupted = 1;
}

void ssoossh_cancel_arm(ssoossh_cancel *c)
{
    struct sigaction sa;

    interrupted = 0;
    c->installed = false;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigint;
    (void)sigemptyset(&sa.sa_mask);
    /* No SA_RESTART on purpose. The point of the handler is to make the
     * blocking wait return early; restarting the interrupted call would
     * defeat it, and the poll loop is written to treat EINTR as "check the
     * flag and the deadline, then carry on". */
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, &c->previous) == 0) {
        c->installed = true;
    }
}

void ssoossh_cancel_disarm(ssoossh_cancel *c)
{
    if (!c->installed) {
        return;
    }
    (void)sigaction(SIGINT, &c->previous, NULL);
    c->installed = false;
}

bool ssoossh_cancel_fired(void)
{
    return interrupted != 0;
}
