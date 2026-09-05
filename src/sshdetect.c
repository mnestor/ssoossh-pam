#include "sshdetect.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#if defined(__APPLE__) || defined(__FreeBSD__)
#    include <sys/sysctl.h>
#endif
#if defined(__FreeBSD__)
#    include <sys/user.h>
#endif

bool ssoossh_ssh_session_env(void)
{
    static const char *const names[] = {"SSH_CONNECTION", "SSH_CLIENT",
                                        "SSH_TTY"};

    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        const char *value = getenv(names[i]);

        if (value != NULL && value[0] != '\0') {
            return true;
        }
    }
    return false;
}

/* The command name and parent of one process, or false when the kernel
 * will not say -- a process that exited mid-walk, or a platform with
 * neither /proc nor KERN_PROC_PID. */
static bool process_info(pid_t pid, char comm[32], pid_t *ppid)
{
#if defined(__linux__)
    /* /proc/<pid>/stat: "<pid> (<comm>) <state> <ppid> ...". comm may hold
     * spaces and parentheses, so it is bounded by the first '(' and the
     * last ')' rather than split on whitespace. */
    char path[64], buf[512];
    const char *open, *close;
    FILE *f;
    size_t n, len;
    long parent;

    (void)snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    f = fopen(path, "r");
    if (f == NULL) {
        return false;
    }
    n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';

    open = strchr(buf, '(');
    close = strrchr(buf, ')');
    if (open == NULL || close == NULL || close < open) {
        return false;
    }
    len = (size_t)(close - open) - 1;
    if (len > 31) {
        len = 31;
    }
    memcpy(comm, open + 1, len);
    comm[len] = '\0';

    if (sscanf(close + 1, " %*c %ld", &parent) != 1) {
        return false;
    }
    *ppid = (pid_t)parent;
    return true;
#elif defined(__APPLE__) || defined(__FreeBSD__)
    struct kinfo_proc kp;
    size_t n = sizeof(kp);
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, (int)pid};

    if (sysctl(mib, 4, &kp, &n, NULL, 0) != 0 || n == 0) {
        return false;
    }
#    if defined(__APPLE__)
    (void)snprintf(comm, 32, "%s", kp.kp_proc.p_comm);
    *ppid = kp.kp_eproc.e_ppid;
#    else
    (void)snprintf(comm, 32, "%s", kp.ki_comm);
    *ppid = kp.ki_ppid;
#    endif
    return true;
#else
    (void)pid;
    (void)comm;
    (void)ppid;
    return false;
#endif
}

bool ssoossh_ssh_session_ancestry(void)
{
    pid_t pid = getpid();

    /* Starting from this process, not its parent: when the host is sshd
     * itself -- the module on sshd's own PAM stack -- the answer is self.
     * The hop cap is well past any real depth and guards against a loop
     * in a process table that is being rewritten under the walk. */
    for (int hops = 0; hops < 64 && pid > 1; hops++) {
        char comm[32];
        pid_t ppid = 0;

        if (!process_info(pid, comm, &ppid)) {
            return false;
        }
        if (strncmp(comm, "sshd", 4) == 0) {
            return true;
        }
        if (ppid == pid) {
            return false;
        }
        pid = ppid;
    }
    return false;
}

bool ssoossh_ssh_session(void)
{
    return ssoossh_ssh_session_env() || ssoossh_ssh_session_ancestry();
}
