#include "console.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <security/pam_modules.h>

#include "log.h"

/* Copies a PAM item, which libpam owns and may leave NULL. */
static void read_item(pam_handle_t *pamh, int item, char *out, size_t out_cap)
{
    const void *value = NULL;

    out[0] = '\0';
    if (pam_get_item(pamh, item, &value) != PAM_SUCCESS || value == NULL) {
        return;
    }
    (void)snprintf(out, out_cap, "%s", (const char *)value);
}

void ssoossh_context_read(pam_handle_t *pamh, ssoossh_request_context *out)
{
    memset(out, 0, sizeof(*out));

    read_item(pamh, PAM_SERVICE, out->service, sizeof(out->service));
    read_item(pamh, PAM_TTY, out->tty, sizeof(out->tty));
    read_item(pamh, PAM_RHOST, out->rhost, sizeof(out->rhost));

    if (gethostname(out->hostname, sizeof(out->hostname)) != 0) {
        out->hostname[0] = '\0';
    }
    out->hostname[sizeof(out->hostname) - 1] = '\0';
}

/* Whether name, after any /dev/ prefix, is followed only by digits -- the
 * shape every numbered console device has. Requiring digits is what keeps
 * "ttyS0" from matching the "tty" prefix test and being called a virtual
 * console, and what keeps a device nobody anticipated from matching by
 * accident. */
static bool numbered(const char *name, const char *prefix)
{
    size_t n = strlen(prefix);

    if (strncmp(name, prefix, n) != 0 || name[n] == '\0') {
        return false;
    }
    for (const char *p = name + n; *p != '\0'; p++) {
        if (*p < '0' || *p > '9') {
            return false;
        }
    }
    return true;
}

bool ssoossh_context_is_console(const ssoossh_request_context *ctx)
{
    const char *tty = ctx->tty;

    /* Anything that arrived over the network is not a console login, no
     * matter what the local tty looks like. The person is at their own
     * machine and it has a browser. */
    if (ctx->rhost[0] != '\0') {
        return false;
    }

    /* No tty at all: cron, a script, an application that sets no PAM_TTY.
     * There is no human here to read a code off a screen, so the existing
     * flow is the safer answer. */
    if (tty[0] == '\0') {
        return false;
    }

    if (strncmp(tty, "/dev/", 5) == 0) {
        tty += 5;
    }

    /* /dev/console itself: the kernel console, wherever it points. */
    if (strcmp(tty, "console") == 0) {
        return true;
    }

    /* A pseudo-terminal is a terminal emulator or an SSH session. Excluded
     * explicitly rather than by falling off the end, because it is the case
     * that would otherwise be easiest to get wrong. */
    if (strncmp(tty, "pts/", 4) == 0 || numbered(tty, "pts")) {
        return false;
    }

    return numbered(tty, "tty") ||    /* Linux virtual console */
           numbered(tty, "ttyv") ||   /* FreeBSD virtual console */
           numbered(tty, "ttyS") ||   /* Linux serial */
           numbered(tty, "ttyu") ||   /* FreeBSD serial */
           numbered(tty, "ttyAMA") || /* arm64 PL011 serial, common on BMCs */
           numbered(tty, "ttyUSB") || /* a USB serial adapter */
           numbered(tty, "hvc") ||    /* hypervisor console: KVM, PowerVM */
           numbered(tty, "hvsi") || numbered(tty, "xvc"); /* Xen */
}
