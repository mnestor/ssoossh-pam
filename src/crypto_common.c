#include "crypto_common.h"

#include <string.h>

#include "crypto.h"
#include "der.h"
#include "sshwire.h"

bool ssoossh_crypto_supports_key(const char *key_algo)
{
    if (strcmp(key_algo, "ssh-ed25519") == 0) {
        /* Conditional on this host, and the condition is decided once by
         * the backend. */
        return ssoossh_crypto_ed25519_usable();
    }
    return strcmp(key_algo, "ssh-rsa") == 0 ||
           strcmp(key_algo, "ecdsa-sha2-nistp256") == 0 ||
           strcmp(key_algo, "ecdsa-sha2-nistp384") == 0 ||
           strcmp(key_algo, "ecdsa-sha2-nistp521") == 0;
}

const char *ssoossh_sig_algo_key_type(const char *sig_algo)
{
    if (strcmp(sig_algo, "ssh-ed25519") == 0) {
        return ssoossh_crypto_ed25519_usable() ? "ssh-ed25519" : NULL;
    }
    if (strcmp(sig_algo, "rsa-sha2-256") == 0 ||
        strcmp(sig_algo, "rsa-sha2-512") == 0) {
        return "ssh-rsa";
    }
    /* The ECDSA names are their own key type. */
    if (strcmp(sig_algo, "ecdsa-sha2-nistp256") == 0 ||
        strcmp(sig_algo, "ecdsa-sha2-nistp384") == 0 ||
        strcmp(sig_algo, "ecdsa-sha2-nistp521") == 0) {
        return sig_algo;
    }
    return NULL;
}

bool ssoossh_ecdsa_sig_to_der(const uint8_t *sig, size_t sig_len, uint8_t *out,
                              size_t out_cap, size_t *out_len)
{
    ssh_rd r;
    const uint8_t *rr = NULL, *ss = NULL;
    size_t r_len = 0, s_len = 0;

    ssh_rd_init(&r, sig, sig_len);
    if (!ssh_rd_str(&r, &rr, &r_len) || !ssh_rd_str(&r, &ss, &s_len) ||
        !ssh_rd_done(&r)) {
        return false;
    }
    return ssoossh_der_ecdsa_sig(rr, r_len, ss, s_len, out, out_cap, out_len);
}
