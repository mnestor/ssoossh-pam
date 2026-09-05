#include "localaddrs.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>

size_t ssoossh_local_addresses(char out[][SSOOSSH_ADDR_LEN], size_t max)
{
    struct ifaddrs *list = NULL, *ifa;
    size_t count = 0;

    if (getifaddrs(&list) != 0) {
        return 0;
    }

    for (ifa = list; ifa != NULL && count < max; ifa = ifa->ifa_next) {
        char buf[SSOOSSH_ADDR_LEN];
        bool duplicate = false;

        if (ifa->ifa_addr == NULL) {
            continue;
        }
        if ((ifa->ifa_flags & IFF_UP) == 0 ||
            (ifa->ifa_flags & IFF_LOOPBACK) != 0) {
            continue;
        }

        if (ifa->ifa_addr->sa_family == AF_INET) {
            const struct sockaddr_in *in =
                (const struct sockaddr_in *)(const void *)ifa->ifa_addr;
            uint32_t host = ntohl(in->sin_addr.s_addr);

            /* 127.0.0.0/8 and 169.254.0.0/16. Link-local addresses are
             * meaningful only within a single link, so they can neither
             * support a source-address restriction nor identify this
             * machine to anything a certificate is presented to. */
            if ((host >> 24) == 127 || (host >> 16) == 0xa9fe) {
                continue;
            }
            if (inet_ntop(AF_INET, &in->sin_addr, buf, sizeof(buf)) == NULL) {
                continue;
            }
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            const struct sockaddr_in6 *in6 =
                (const struct sockaddr_in6 *)(const void *)ifa->ifa_addr;

            if (IN6_IS_ADDR_LOOPBACK(&in6->sin6_addr) ||
                IN6_IS_ADDR_LINKLOCAL(&in6->sin6_addr)) {
                /* fe80::/10 is dropped for the reason above and for one
                 * more: the textual form carries no zone, so one address
                 * derived from a single MAC arrives identically from every
                 * interface carrying it -- a bridge and its member,
                 * docker0 and its veths. */
                continue;
            }
            if (inet_ntop(AF_INET6, &in6->sin6_addr, buf, sizeof(buf)) ==
                NULL) {
                continue;
            }
        } else {
            continue;
        }

        for (size_t i = 0; i < count; i++) {
            if (strcmp(out[i], buf) == 0) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) {
            continue;
        }

        (void)memcpy(out[count], buf, strlen(buf) + 1);
        count++;
    }

    freeifaddrs(list);
    return count;
}
