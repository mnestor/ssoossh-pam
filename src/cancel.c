#include "cancel.h"

#include <pthread.h>
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
    sigset_t only_sigint;

    interrupted = 0;
    c->installed = false;
    c->was_blocked = false;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigint;
    (void)sigemptyset(&sa.sa_mask);
    /* No SA_RESTART on purpose. The point of the handler is to make the
     * blocking wait return early; restarting the interrupted call would
     * defeat it, and the poll loop is written to treat EINTR as "check the
     * flag and the deadline, then carry on". */
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, &c->previous) != 0) {
        return;
    }
    c->installed = true;

    /* A handler only runs for a signal that is deliverable, and sudo runs
     * its whole policy check -- this module included -- with the tty
     * signals blocked in the process mask, so that a Ctrl-C is held pending
     * and re-raised once the check is over. Held pending is exactly what
     * this module must not let happen: the wait would run to its deadline
     * with the user's interrupt sitting in the kernel, and sudo would then
     * die of it afterwards. So SIGINT is unblocked for as long as the
     * handler is installed, and put back the way it was on disarm. Only
     * that one signal, and only on this thread: the mask is per-thread, and
     * this is the thread the wait runs on. */
    (void)sigemptyset(&only_sigint);
    (void)sigaddset(&only_sigint, SIGINT);
    if (pthread_sigmask(SIG_UNBLOCK, &only_sigint, &c->previous_mask) == 0) {
        c->was_blocked = sigismember(&c->previous_mask, SIGINT) == 1;
    }
}

void ssoossh_cancel_disarm(ssoossh_cancel *c)
{
    if (!c->installed) {
        return;
    }
    /* Reverse order of arm: re-block first, so a Ctrl-C that lands in the
     * gap is held for the host exactly as it would have been without this
     * module, then hand the disposition back. */
    if (c->was_blocked) {
        sigset_t only_sigint;

        (void)sigemptyset(&only_sigint);
        (void)sigaddset(&only_sigint, SIGINT);
        (void)pthread_sigmask(SIG_BLOCK, &only_sigint, NULL);
        c->was_blocked = false;
    }
    (void)sigaction(SIGINT, &c->previous, NULL);
    c->installed = false;
}

bool ssoossh_cancel_fired(void)
{
    return interrupted != 0;
}
