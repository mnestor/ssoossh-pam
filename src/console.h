/* Request context, and deciding whether there is a browser in front of this
 * machine.
 *
 * The sudo flow prints a URL and assumes someone can open it. On a physical
 * console -- a VT, a serial line, a BMC viewer -- there is nothing to click
 * and nothing to copy from, so that flow prints a link nobody can follow.
 * Console mode exists for exactly that case: the machine shows a short code
 * and a QR, and the approver carries them to a device that does have a
 * browser.
 *
 * Which flow to run is therefore a property of where the login is happening,
 * not something an operator should have to predict per host in a pam.d
 * line. `mode=auto` is the default and decides here.
 *
 * The context fields serve a second purpose. They go to the server so the
 * approver can tell a request they caused from one they did not: which
 * machine, through which PAM service, at which terminal, and -- since a real
 * console has no remote host -- whether PAM_RHOST says this did not come
 * from a console at all. Every one of them is self-reported by an
 * unauthenticated caller and the server displays them as claims, never as
 * facts.
 */
#ifndef PAM_SSOOSSH_CONSOLE_H
#define PAM_SSOOSSH_CONSOLE_H

#include <stdbool.h>

#include <security/pam_appl.h>

typedef struct {
    char service[64];
    char tty[128];
    char rhost[256];
    char hostname[256];
    /* PAM_RUSER: the account that invoked the service, where the service
     * sets it -- sudo does, sshd does not. Distinct from PAM_USER, which
     * is the account being authenticated. */
    char ruser[64];
} ssoossh_request_context;

/* Reads what libpam knows about this transaction. Every field is optional:
 * an application that set none of them still authenticates, it just gives
 * the approver less to go on. */
void ssoossh_context_read(pam_handle_t *pamh, ssoossh_request_context *out);

/* Whether this login is at a console with no browser reachable from it.
 *
 * True when PAM_RHOST is empty -- so nothing came in over the network --
 * *and* PAM_TTY names a physical terminal: a Linux virtual console, a
 * FreeBSD one, a serial line, a hypervisor console, or /dev/console itself.
 *
 * Everything else is false, and each exclusion is deliberate. A pty
 * (pts/N) is a terminal emulator inside a graphical session or an SSH
 * session, and in both cases a browser is a keystroke away. An empty
 * PAM_TTY is a cron job or a script, where neither flow has a human at all
 * and the existing one is the safer answer. A set PAM_RHOST means the
 * person is sitting at their own machine, which has a browser, however
 * console-like the tty on this end looks. */
bool ssoossh_context_is_console(const ssoossh_request_context *ctx);

/* Whether this build has the console flow at all. False on macOS, where a
 * console login is loginwindow -- which never shows a PAM message, so there
 * is no one to show a code and a QR to. The flow and its QR encoder are not
 * compiled in there.
 *
 * Stated here once. It used to be re-decided in the argument parser and
 * again in the authenticate path, the second time by undoing an answer the
 * shared detection had already given. */
bool ssoossh_console_flow_supported(void);

#endif /* PAM_SSOOSSH_CONSOLE_H */
