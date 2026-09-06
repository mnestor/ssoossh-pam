#include "checks.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "log.h"
#include "principals_map.h"

/* Renders the certificate's principals for a log line: alice,ops. Bounded
 * and truncated with an ellipsis rather than growing, because this is a
 * message and not a decision. */
/* An RFC 3339 instant for a debug line. A clock the C library cannot break
 * down renders as "?" rather than costing the caller an error path in the
 * middle of a message. */
static void utc_string(int64_t t, char out[32])
{
    time_t tt = (time_t)t;
    struct tm tm;

    if (gmtime_r(&tt, &tm) == NULL ||
        strftime(out, 32, "%Y-%m-%dT%H:%M:%SZ", &tm) == 0) {
        (void)snprintf(out, 32, "?");
    }
}

static void principals_string(const ssoossh_cert *cert, char *out,
                              size_t out_cap)
{
    size_t w = 0;

    out[0] = '\0';
    for (size_t i = 0; i < cert->principal_count; i++) {
        size_t need = cert->principals[i].len + (w > 0 ? 1 : 0);

        if (w + need + 4 >= out_cap) {
            (void)memcpy(out + w, "...", 4);
            return;
        }
        if (w > 0) {
            out[w++] = ',';
        }
        memcpy(out + w, cert->principals[i].p, cert->principals[i].len);
        w += cert->principals[i].len;
    }
    out[w] = '\0';
}

bool ssoossh_check_ca_signature(const ssoossh_cert *cert,
                                const ssoossh_ca_list *cas)
{
    char cert_fp[SSOOSSH_FINGERPRINT_LEN];
    bool saw_unsupported = false;

    for (size_t i = 0; i < cas->count; i++) {
        ssoossh_verify_result r =
            ssoossh_cert_verify(cert, cas->keys[i].blob, cas->keys[i].len);
        char ca_fp[SSOOSSH_FINGERPRINT_LEN];

        switch (r) {
        case SSOOSSH_VERIFY_OK:
            ssoossh_sshkey_fingerprint(cas->keys[i].blob, cas->keys[i].len,
                                       ca_fp);
            ssoossh_debugf("check 1/4 CA signature: signed by %s, trusted CA "
                           "%zu of %zu",
                           ca_fp, i + 1, cas->count);
            return true;
        case SSOOSSH_VERIFY_UNSUPPORTED:
            saw_unsupported = true;
            break;
        case SSOOSSH_VERIFY_BAD:
        case SSOOSSH_VERIFY_ERROR:
            break;
        }
    }

    ssoossh_sshkey_fingerprint(cert->signature_key.p, cert->signature_key.len,
                               cert_fp);

    if (saw_unsupported) {
        /* Naming the algorithm is the whole point. "not signed by a trusted
         * CA" would send an operator looking at their CA file when the
         * problem is that this build cannot verify that algorithm -- or,
         * for ssh-rsa, will not. */
        /* The crypto version is named rather than a cause guessed at: it
         * is the one string that knows what this host's backend actually
         * has. Reciting every backend's possible reason told an operator
         * about a platform they were not running on. */
        ssoossh_errf("certificate signature algorithm %s cannot be verified "
                     "by this build (signature key %s, crypto %s): ssh-rsa "
                     "means RSA with SHA-1 and is refused by policy; any "
                     "other algorithm here is one this host's crypto does "
                     "not provide",
                     cert->signature_algo, cert_fp, ssoossh_crypto_version());
        return false;
    }

    ssoossh_errf("certificate is not signed by a trusted CA (signature key "
                 "%s, %zu trusted key(s) tried)",
                 cert_fp, cas->count);
    return false;
}

bool ssoossh_check_key_binding(const ssoossh_cert *cert, const uint8_t *our_key,
                               size_t our_key_len)
{
    char cert_fp[SSOOSSH_FINGERPRINT_LEN], our_fp[SSOOSSH_FINGERPRINT_LEN];

    if (cert->key_blob_len == 0) {
        ssoossh_errf("certificate carries no public key");
        return false;
    }
    if (cert->key_blob_len != our_key_len ||
        memcmp(cert->key_blob, our_key, our_key_len) != 0) {
        ssoossh_sshkey_fingerprint(cert->key_blob, cert->key_blob_len, cert_fp);
        ssoossh_sshkey_fingerprint(our_key, our_key_len, our_fp);
        ssoossh_errf("certificate public key %s does not match the key "
                     "generated for this attempt %s",
                     cert_fp, our_fp);
        return false;
    }

    ssoossh_sshkey_fingerprint(cert->key_blob, cert->key_blob_len, cert_fp);
    ssoossh_debugf("check 2/4 key binding: certificate key %s matches the key "
                   "generated for this attempt",
                   cert_fp);
    return true;
}

bool ssoossh_check_principal(const ssoossh_cert *cert, const char *username,
                             const char *map_path)
{
    char listed[512];

    principals_string(cert, listed, sizeof(listed));

    if (map_path != NULL && map_path[0] != '\0') {
        ssoossh_principals allowed;
        char err[256];

        if (ssoossh_principals_map_load(map_path, username, &allowed, err,
                                        sizeof(err)) == SSOOSSH_MAP_OK) {
            /* The certificate's principals as NUL-terminated strings, which
             * is what the map comparison wants. A principal too long for
             * the buffer cannot equal any entry the map could hold, so it
             * is skipped rather than truncated into a false match. */
            const char *names[SSOOSSH_MAX_PRINCIPALS];
            char storage[SSOOSSH_MAX_PRINCIPALS][SSOOSSH_MAX_PRINCIPAL_LEN];
            size_t count = 0;

            for (size_t i = 0; i < cert->principal_count; i++) {
                if (cert->principals[i].len >= SSOOSSH_MAX_PRINCIPAL_LEN) {
                    continue;
                }
                memcpy(storage[count], cert->principals[i].p,
                       cert->principals[i].len);
                storage[count][cert->principals[i].len] = '\0';
                names[count] = storage[count];
                count++;
            }

            if (!ssoossh_principals_allow(&allowed, names, count)) {
                ssoossh_errf("certificate principals [%s] are not authorized "
                             "for account \"%s\" per %s (%zu principal(s) "
                             "allowed there)",
                             listed, username, map_path, allowed.count);
                return false;
            }
            ssoossh_debugf("check 3/4 principal: account \"%s\" authorized via "
                           "principals-map %s (certificate principals [%s])",
                           username, map_path, listed);
            return true;
        }

        /* Warning, not debug: an operator who configured a map needs to
         * learn it is being ignored without first turning debug on. */
        ssoossh_warnf("principals-map %s could not be loaded, falling back to "
                      "exact principal match: %s",
                      map_path, err);
    }

    if (!ssoossh_cert_has_principal(cert, username)) {
        ssoossh_errf("certificate principals [%s] do not include \"%s\"",
                     listed, username);
        return false;
    }
    ssoossh_debugf("check 3/4 principal: certificate principals [%s] include "
                   "account \"%s\" (exact match)",
                   listed, username);
    return true;
}

bool ssoossh_check_validity(const ssoossh_cert *cert, int64_t now,
                            ssoossh_duration tolerance)
{
    /* The certificate's bounds are unsigned seconds set by the server;
     * OpenSSH writes 0xffffffffffffffff for "forever", which would overflow
     * a signed conversion. Clamping keeps the comparison honest without
     * making the parser reject a certificate OpenSSH considers valid. */
    int64_t after = cert->valid_after > (uint64_t)INT64_MAX
                        ? INT64_MAX
                        : (int64_t)cert->valid_after;
    int64_t before = cert->valid_before > (uint64_t)INT64_MAX
                         ? INT64_MAX
                         : (int64_t)cert->valid_before;
    int64_t tolerance_s = tolerance / SSOOSSH_SECOND;
    char tol[32], skew_str[32];

    (void)ssoossh_duration_string(tolerance, tol, sizeof(tol));

    if (now < after - tolerance_s) {
        (void)ssoossh_duration_string((after - now) * SSOOSSH_SECOND, skew_str,
                                      sizeof(skew_str));
        ssoossh_errf("certificate not yet valid, %s of skew, tolerance %s",
                     skew_str, tol);
        return false;
    }
    if (now > before + tolerance_s) {
        (void)ssoossh_duration_string((now - before) * SSOOSSH_SECOND, skew_str,
                                      sizeof(skew_str));
        ssoossh_errf("certificate expired, %s of skew, tolerance %s", skew_str,
                     tol);
        return false;
    }

    {
        char after_s[32], before_s[32];

        utc_string(after, after_s);
        utc_string(before, before_s);
        ssoossh_debugf("check 4/4 validity window: now is within [%s, %s] "
                       "(tolerance %s, %llds remaining)",
                       after_s, before_s, tol, (long long)(before - now));
    }
    return true;
}
