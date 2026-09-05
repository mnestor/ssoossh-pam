#include "hostinfo.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/utsname.h>
#if defined(__FreeBSD__)
#    include <sys/types.h>
#    include <sys/sysctl.h>
#elif defined(__APPLE__)
#    include <uuid/uuid.h>
#endif

static void trim_end(char *s)
{
    size_t n = strlen(s);

    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' ||
                     s[n - 1] == ' ' || s[n - 1] == '\t')) {
        s[--n] = '\0';
    }
}

/* Appends s to the NUL-terminated out, dropping whatever does not fit.
 * Truncation is the intent -- every field here has a cap the server would
 * apply anyway -- and doing it by hand rather than through snprintf keeps
 * gcc's -Wformat-truncation from calling the intent a bug. */
static void cat_capped(char *out, size_t cap, const char *s)
{
    size_t have = strlen(out);
    size_t room = cap - 1 - have;
    size_t n = strlen(s);

    if (n > room) {
        n = room;
    }
    memcpy(out + have, s, n);
    out[have + n] = '\0';
}

#if defined(__linux__)
/* The first line of a small text file, trimmed; empty when it cannot be
 * read. */
static void read_first_line(const char *path, char *out, size_t cap)
{
    FILE *f = fopen(path, "r");

    out[0] = '\0';
    if (f == NULL) {
        return;
    }
    if (fgets(out, (int)cap, f) == NULL) {
        out[0] = '\0';
    }
    fclose(f);
    trim_end(out);
}
#endif

/* The value of PRETTY_NAME in /etc/os-release, unquoted; empty when the
 * file or the key is absent. os-release values may be bare, double-quoted
 * or single-quoted, and this reads all three without interpreting escapes,
 * which the distributions this ships on do not use in that field. */
static void read_pretty_name(char *out, size_t cap)
{
    static const char key[] = "PRETTY_NAME=";
    FILE *f = fopen("/etc/os-release", "r");
    char line[512];

    out[0] = '\0';
    if (f == NULL) {
        return;
    }
    while (fgets(line, sizeof(line), f) != NULL) {
        char *value;
        size_t n;

        if (strncmp(line, key, sizeof(key) - 1) != 0) {
            continue;
        }
        value = line + sizeof(key) - 1;
        trim_end(value);
        n = strlen(value);
        if (n >= 2 && (value[0] == '"' || value[0] == '\'') &&
            value[n - 1] == value[0]) {
            value[n - 1] = '\0';
            value++;
        }
        cat_capped(out, cap, value);
        break;
    }
    fclose(f);
}

static void read_os(char *out, size_t cap)
{
    struct utsname u;

    read_pretty_name(out, cap);
    if (uname(&u) != 0) {
        u.sysname[0] = '\0';
        u.release[0] = '\0';
    }
    if (out[0] != '\0') {
        cat_capped(out, cap, " ");
    }
    cat_capped(out, cap, u.sysname);
    cat_capped(out, cap, " ");
    cat_capped(out, cap, u.release);
    trim_end(out);
}

static void read_machine_id(char *out, size_t cap)
{
#if defined(__linux__)
    read_first_line("/etc/machine-id", out, cap);
#elif defined(__FreeBSD__)
    size_t n = cap - 1;

    if (sysctlbyname("kern.hostuuid", out, &n, NULL, 0) != 0) {
        out[0] = '\0';
        return;
    }
    out[n < cap ? n : cap - 1] = '\0';
    trim_end(out);
#elif defined(__APPLE__)
    /* No kern.hostuuid sysctl here; the host UUID is a syscall of its
     * own, and it wants a timeout it never actually needs. */
    uuid_t id;
    struct timespec wait = {0, 0};

    if (cap < 37 || gethostuuid(id, &wait) != 0) {
        out[0] = '\0';
        return;
    }
    uuid_unparse_lower(id, out);
#else
    (void)cap;
    out[0] = '\0';
#endif
}

#if defined(__linux__) || defined(__FreeBSD__)
/* A NUL-separated argument vector as one line: each NUL becomes a space,
 * and a trailing one -- every vector ends with one -- is dropped. */
static void join_args(char *buf, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (buf[i] == '\0') {
            buf[i] = ' ';
        }
    }
    buf[n] = '\0';
    trim_end(buf);
}
#endif

static void read_process(char *out, size_t cap)
{
#if defined(__linux__)
    FILE *f = fopen("/proc/self/cmdline", "rb");
    size_t n;

    out[0] = '\0';
    if (f == NULL) {
        return;
    }
    n = fread(out, 1, cap - 1, f);
    fclose(f);
    join_args(out, n);
#elif defined(__FreeBSD__)
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ARGS, (int)getpid()};
    size_t n = cap - 1;

    if (sysctl(mib, 4, out, &n, NULL, 0) != 0 && n == 0) {
        out[0] = '\0';
        return;
    }
    /* ENOMEM with a partial fill is the vector being longer than the cap,
     * which is exactly the truncation the cap is for. */
    join_args(out, n < cap ? n : cap - 1);
#else
    (void)cap;
    out[0] = '\0';
#endif
}

static void read_client_time(char *out, size_t cap)
{
    time_t now = time(NULL);
    struct tm tm;

    if (gmtime_r(&now, &tm) == NULL ||
        strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", &tm) == 0) {
        out[0] = '\0';
    }
}

void ssoossh_host_info_read(ssoossh_host_info *out)
{
    memset(out, 0, sizeof(*out));
    read_process(out->process, sizeof(out->process));
    read_machine_id(out->machine_id, sizeof(out->machine_id));
    read_os(out->os, sizeof(out->os));
    read_client_time(out->client_time, sizeof(out->client_time));
}
