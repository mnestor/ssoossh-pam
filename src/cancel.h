/* Ctrl-C during the wait for a browser approval.
 *
 * The module blocks for as long as a minute with a human standing in front
 * of it. Someone who gives up on that usually wants the password prompt
 * pam_unix would have given them -- not a dead sudo. So the module notices
 * SIGINT, tears the transfer down, and returns PAM_IGNORE, which tells
 * libpam this module contributes nothing and to carry on down the stack.
 *
 * Noticing a signal means installing a handler, inside a process that owns
 * its own signal dispositions. Three rules keep that honest:
 *
 *   * The handler is installed immediately before the wait and the previous
 *     disposition restored immediately after, on every exit path. A second
 *     Ctrl-C after the module returns behaves exactly as it would have if
 *     the module had never been loaded.
 *   * The handler does nothing but set a flag. No logging, no allocation,
 *     no libcurl -- none of which is async-signal-safe.
 *   * SIGTERM gets no handler at all. That signal means someone is killing
 *     the process, and swallowing it inside a PAM module would be a bug.
 *
 * And one more, learned from sudo: a handler is not enough on its own.
 * sudo blocks the tty signals in its process mask for the whole policy
 * check, so a Ctrl-C during the wait is held pending rather than delivered,
 * and the handler never runs. SIGINT is therefore also unblocked, on the
 * waiting thread only, for exactly as long as the handler is installed --
 * and re-blocked on disarm if that is how it was found.
 */
#ifndef PAM_SSOOSSH_CANCEL_H
#define PAM_SSOOSSH_CANCEL_H

#include <signal.h>
#include <stdbool.h>

typedef struct {
    struct sigaction previous;
    sigset_t previous_mask;
    bool installed;
    /* SIGINT was blocked when arm ran, so disarm must block it again. */
    bool was_blocked;
} ssoossh_cancel;

/* Installs the handler and clears the flag. A failure to install is not
 * fatal and is not reported: the wait still works, it just cannot be
 * interrupted early, and refusing to authenticate over that would be the
 * wrong trade.
 *
 * The flag is process-global, as any signal handler's state must be. Two
 * PAM transactions waiting at once in one process would share it, and a
 * Ctrl-C would cancel both -- which is what the tty delivering SIGINT to
 * the whole foreground process group would have meant anyway. */
void ssoossh_cancel_arm(ssoossh_cancel *c);

/* Restores the previous disposition. Safe to call on a struct that arm
 * failed for, and safe to call twice. */
void ssoossh_cancel_disarm(ssoossh_cancel *c);

/* Whether SIGINT arrived since the last arm. */
bool ssoossh_cancel_fired(void);

#endif /* PAM_SSOOSSH_CANCEL_H */
