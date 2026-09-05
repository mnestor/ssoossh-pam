/* Facts about this host and this process, as the request reports them.
 *
 * Everything here goes to the server as a claim. The caller is an
 * unauthenticated process asking to be trusted, so nothing it says about
 * itself can be verified on its own say-so, and the server renders every
 * field as a claim rather than a fact. What the fields buy is context for
 * the approver: which machine, which OS, which command line is asking, and
 * when by that machine's clock -- enough to tell a request they caused from
 * one they did not.
 *
 * Every field is optional and degrades to empty when the source is absent
 * or unreadable. A host with no /etc/machine-id still authenticates; it just
 * gives the approver one thing less to go on. Nothing here fails, logs, or
 * allocates: it runs once per attempt inside sudo and reads a few files.
 */
#ifndef PAM_SSOOSSH_HOSTINFO_H
#define PAM_SSOOSSH_HOSTINFO_H

#include <stddef.h>

/* The server truncates string claims at 256 bytes, so nothing longer is
 * worth sending. Each buffer holds that plus a NUL. */
#define SSOOSSH_HOSTINFO_CAP 256

typedef struct {
    /* The host process's command line with NULs replaced by spaces:
     * /proc/self/cmdline on Linux, KERN_PROC_ARGS on FreeBSD. Empty on
     * macOS, which offers neither to a library without more machinery than
     * the claim is worth. */
    char process[SSOOSSH_HOSTINFO_CAP + 1];
    /* /etc/machine-id on Linux; kern.hostuuid on FreeBSD; gethostuuid(2)
     * on macOS. */
    char machine_id[SSOOSSH_HOSTINFO_CAP + 1];
    /* "<uname -s> <uname -r>", prefixed on Linux by PRETTY_NAME from
     * /etc/os-release, which is the one platform where that names something
     * uname does not. */
    char os[SSOOSSH_HOSTINFO_CAP + 1];
    /* This host's clock, RFC 3339 in UTC: "2026-09-05T13:04:05Z". */
    char client_time[32];
} ssoossh_host_info;

void ssoossh_host_info_read(ssoossh_host_info *out);

#endif /* PAM_SSOOSSH_HOSTINFO_H */
