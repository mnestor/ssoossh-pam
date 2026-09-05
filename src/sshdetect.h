/* Did this session arrive over SSH?
 *
 * The question behind `ssh-only`. A person at a Mac's own keyboard has
 * Touch ID and a password; a person who reached it over SSH has neither
 * usable, and the browser flow is what they need. The same split holds
 * anywhere a local login carries a factor a remote one cannot.
 *
 * Two signals, either of which is enough:
 *
 *   * The environment. sshd sets SSH_CONNECTION, SSH_CLIENT and SSH_TTY in
 *     the session, and they survive into sudo -- sudo scrubs the command's
 *     environment, not its own. tmux and screen carry SSH_CONNECTION into
 *     sessions whose process ancestry no longer leads back to sshd.
 *   * The ancestry. Walking parent pids from this process finds an sshd
 *     (or sshd-session, OpenSSH 9.8+) for a plain SSH login even when the
 *     environment has been scrubbed.
 *
 * Neither is a security boundary and this module does not treat it as one.
 * A local user who exports SSH_TTY gets the browser flow instead of Touch
 * ID -- a worse experience, not a weaker check -- and a remote user cannot
 * hide sshd from the process table. The decision is which factor to ask
 * for, and every branch of it still authenticates.
 */
#ifndef PAM_SSOOSSH_SSHDETECT_H
#define PAM_SSOOSSH_SSHDETECT_H

#include <stdbool.h>

/* Either signal. */
bool ssoossh_ssh_session(void);

/* The two signals on their own, for the tests. */
bool ssoossh_ssh_session_env(void);
bool ssoossh_ssh_session_ancestry(void);

#endif /* PAM_SSOOSSH_SSHDETECT_H */
