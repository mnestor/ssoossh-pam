/* The caller's own non-loopback IP addresses, sent as
 * requested_options.source_addresses so ssoosshd can union them with the
 * address it observes the request coming from. A client behind NAT has a
 * private local address that downstream hosts see when it connects, which
 * is not the address ssoosshd sees when it mints the certificate.
 *
 * Best-effort throughout: this is audit and policy-support metadata, never
 * a precondition for issuance, so any failure enumerating interfaces yields
 * however much was gathered rather than failing the authentication.
 */
#ifndef PAM_SSOOSSH_LOCALADDRS_H
#define PAM_SSOOSSH_LOCALADDRS_H

#include <stddef.h>

/* INET6_ADDRSTRLEN, spelled out so the header does not drag in netinet. */
#define SSOOSSH_ADDR_LEN 46

/* More interfaces than any host running sudo has, and a hard stop for one
 * that disagrees. */
#define SSOOSSH_MAX_LOCAL_ADDRS 32

/* Fills out with up to max addresses and returns how many. The result is a
 * set: the server treats source_addresses as a union when it folds in the
 * observed source IP, and a repeat would be stored, displayed and matched
 * against for no gain. */
size_t ssoossh_local_addresses(char out[][SSOOSSH_ADDR_LEN], size_t max);

#endif /* PAM_SSOOSSH_LOCALADDRS_H */
