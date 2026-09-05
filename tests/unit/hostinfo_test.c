/* The host facts that go to the server as claims. What can be asserted
 * without knowing the host: every field fits the server's cap, the clock
 * is RFC 3339 UTC and agrees with time(2), the OS line carries the kernel
 * name, and the process line -- where the platform offers one -- names
 * this very binary. Where it does not, the field is empty rather than
 * invented. */
#include <string.h>
#include <sys/utsname.h>
#include <time.h>

#include "hostinfo.h"
#include "json.h"
#include "suites.h"
#include "test.h"

int suite_hostinfo(void)
{
    ssoossh_host_info info;
    struct utsname u;
    int64_t parsed = 0;
    int64_t now;

    memset(&info, 0xff, sizeof(info));
    ssoossh_host_info_read(&info);
    now = (int64_t)time(NULL);

    T_CHECK(strlen(info.process) <= SSOOSSH_HOSTINFO_CAP);
    T_CHECK(strlen(info.machine_id) <= SSOOSSH_HOSTINFO_CAP);
    T_CHECK(strlen(info.os) <= SSOOSSH_HOSTINFO_CAP);

    /* The clock: well-formed, parses, and is this machine's now. */
    T_CHECKF(strlen(info.client_time) == 20, "client_time %s",
             info.client_time);
    T_CHECKF(ssoossh_parse_rfc3339(info.client_time, &parsed),
             "client_time %s does not parse", info.client_time);
    T_CHECKF(parsed >= now - 5 && parsed <= now + 5,
             "client_time %s is %lld, now is %lld", info.client_time,
             (long long)parsed, (long long)now);

    /* The OS line always ends in the uname half. */
    T_CHECK(uname(&u) == 0);
    T_CHECKF(strstr(info.os, u.sysname) != NULL, "os %s lacks %s", info.os,
             u.sysname);
    T_CHECKF(strstr(info.os, u.release) != NULL, "os %s lacks %s", info.os,
             u.release);
    T_CHECK(info.os[0] != ' ' && info.os[strlen(info.os) - 1] != ' ');

#if defined(__linux__) || defined(__FreeBSD__)
    /* The vector is this test binary's, joined by spaces with no trailing
     * one and no NUL left inside. */
    T_CHECKF(strstr(info.process, "unit_tests") != NULL, "process %s",
             info.process);
    T_CHECK(info.process[strlen(info.process) - 1] != ' ');
#else
    T_CHECKF(info.process[0] == '\0', "process should be empty here: %s",
             info.process);
#endif

#if defined(__FreeBSD__) || defined(__APPLE__)
    /* kern.hostuuid is always there; a UUID is 36 characters. */
    T_CHECKF(strlen(info.machine_id) == 36, "machine_id %s", info.machine_id);
#endif

    return t_failures;
}
