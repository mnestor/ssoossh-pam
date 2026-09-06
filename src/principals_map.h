/* The principals map: a local, hand-authored file saying which certificate
 * principals may assume which local account.
 *
 * A fixed subset of YAML, parsed by hand. The Go module did the same and
 * for the same reason -- gopkg.in/yaml.v3 cost 549 KB of module size to
 * read a file with exactly one shape -- and the subset it accepts is the
 * contract this port has to reproduce, error for error. A file that loaded
 * there must load here, and a file that failed there must fail here.
 *
 * A map that fails to load is treated as no map at all. That is safe by
 * construction rather than by convention: the map only ever adds principals
 * to an account, so the policy with no map is already the narrow one, and
 * losing the file can only withdraw the extra principals it granted.
 *
 * Accepted:
 *
 *     # a comment
 *     alice:            # an account, at the start of the line
 *       - alice         # a principal allowed to assume it
 *       - admin         # indentation is free; "- " is what marks an item
 *     bob: [bob, ops]   # a flow sequence on the account's own line
 *     carol:            # an account with no principals; "null" and "~"
 *                       # mean the same thing
 *
 * Values may be wrapped in matching quotes, which are stripped. Escapes are
 * not interpreted: a quoted value containing a backslash, a quote of the
 * same kind, or (inside a flow sequence) a comma is rejected rather than
 * guessed at. Anything else YAML allows -- nested mappings, anchors,
 * multi-line scalars, multiple documents -- is an error here.
 */
#ifndef PAM_SSOOSSH_PRINCIPALS_MAP_H
#define PAM_SSOOSSH_PRINCIPALS_MAP_H

#include <stdbool.h>
#include <stddef.h>

/* Only one account's entry is ever needed -- the local account PAM is
 * authenticating -- so only one is kept. The whole file is still parsed and
 * still validated, because a malformed line anywhere is what decides
 * whether the map loads at all. */
#define SSOOSSH_MAX_MAP_PRINCIPALS 64
#define SSOOSSH_MAX_PRINCIPAL_LEN 128

typedef struct {
    char principals[SSOOSSH_MAX_MAP_PRINCIPALS][SSOOSSH_MAX_PRINCIPAL_LEN];
    size_t count;
    /* Whether the account appeared in the file at all. This says only
     * whether the map has anything to add for it; the account's own name is
     * always accepted, and that test is the caller's, on every path. */
    bool found;
} ssoossh_principals;

typedef enum {
    SSOOSSH_MAP_OK = 0,
    SSOOSSH_MAP_UNREADABLE,
    SSOOSSH_MAP_MALFORMED,
} ssoossh_map_status;

/* Parses path and extracts the entry for account.
 *
 * err receives a message naming the line when the file is malformed: the
 * file is hand-edited, and this message reaches an operator through the
 * module's syslog warning, so "line 7: account "bob" is already defined" is
 * the whole value of the error. */
ssoossh_map_status ssoossh_principals_map_load(const char *path,
                                               const char *account,
                                               ssoossh_principals *out,
                                               char *err, size_t err_cap);

/* Whether any of the certificate's principals is listed for the account. */
bool ssoossh_principals_allow(const ssoossh_principals *p,
                              const char *const *cert_principals,
                              size_t cert_count);

#endif /* PAM_SSOOSSH_PRINCIPALS_MAP_H */
