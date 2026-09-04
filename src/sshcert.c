#include "sshcert.h"

#include <string.h>

#include "base64.h"
#include "sshwire.h"

#define CERT_SUFFIX "-cert-v01@openssh.com"

/* An algorithm name too long for the buffer is refused rather than
 * truncated: two algorithms with a common prefix would otherwise compare
 * equal. */
static bool copy_name(const uint8_t *p, size_t len, char *out, size_t out_cap)
{
    if (len == 0 || len >= out_cap) {
        return false;
    }
    memcpy(out, p, len);
    out[len] = '\0';
    return true;
}

/* "ecdsa-sha2-nistp384-cert-v01@openssh.com" -> "ecdsa-sha2-nistp384".
 * The base name is what the rebuilt subject key blob is prefixed with, and
 * what decides how many key fields follow the nonce. */
static bool base_algo(const char *cert_algo, char *out, size_t out_cap)
{
    size_t n = strlen(cert_algo);
    size_t suffix = strlen(CERT_SUFFIX);

    if (n <= suffix || strcmp(cert_algo + n - suffix, CERT_SUFFIX) != 0) {
        return false;
    }
    n -= suffix;
    if (n >= out_cap) {
        return false;
    }
    memcpy(out, cert_algo, n);
    out[n] = '\0';
    return true;
}

/* How many length-prefixed fields carry the subject key, by base
 * algorithm. Two for ECDSA (curve, point) and for RSA (e, n); one for
 * Ed25519. Returns 0 for an algorithm this module does not handle. */
static int key_field_count(const char *base)
{
    if (strcmp(base, "ssh-ed25519") == 0) {
        return 1;
    }
    if (strcmp(base, "ssh-rsa") == 0 ||
        strcmp(base, "ecdsa-sha2-nistp256") == 0 ||
        strcmp(base, "ecdsa-sha2-nistp384") == 0 ||
        strcmp(base, "ecdsa-sha2-nistp521") == 0) {
        return 2;
    }
    return 0;
}

/* The principals field is a string that itself contains a sequence of
 * strings -- a nested blob, which is its own little parser and its own
 * little bounds problem. */
static bool parse_principals(const uint8_t *p, size_t len, ssoossh_cert *out)
{
    ssh_rd r;

    ssh_rd_init(&r, p, len);
    out->principal_count = 0;
    while (!ssh_rd_done(&r)) {
        const uint8_t *name = NULL;
        size_t name_len = 0;

        if (!ssh_rd_str(&r, &name, &name_len)) {
            return false;
        }
        if (out->principal_count >= SSOOSSH_MAX_PRINCIPALS) {
            /* Refused, not truncated. Dropping principals silently changes
             * the answer to check 3. */
            return false;
        }
        out->principals[out->principal_count].p = name;
        out->principals[out->principal_count].len = name_len;
        out->principal_count++;
    }
    return ssh_rd_ok(&r);
}

ssoossh_cert_status ssoossh_cert_parse(const uint8_t *blob, size_t blob_len,
                                       ssoossh_cert *out)
{
    ssh_rd r;
    const uint8_t *p = NULL;
    size_t n = 0;
    char base[64];
    size_t key_start, key_end;
    int fields;
    ssh_wr kw;

    memset(out, 0, sizeof(*out));
    out->blob = blob;

    if (blob_len == 0 || blob_len > SSOOSSH_MAX_CERT) {
        return SSOOSSH_CERT_MALFORMED;
    }

    ssh_rd_init(&r, blob, blob_len);

    if (!ssh_rd_str(&r, &p, &n) ||
        !copy_name(p, n, out->algo, sizeof(out->algo))) {
        return SSOOSSH_CERT_MALFORMED;
    }
    if (!base_algo(out->algo, base, sizeof(base))) {
        /* Not a certificate at all: a plain public key, most likely. */
        return SSOOSSH_CERT_MALFORMED;
    }
    fields = key_field_count(base);
    if (fields == 0) {
        return SSOOSSH_CERT_UNSUPPORTED;
    }

    /* nonce: never read, only skipped. It is the server's freshness
     * material and means nothing here -- this module's freshness comes from
     * the per-attempt keypair. */
    if (!ssh_rd_skip_str(&r)) {
        return SSOOSSH_CERT_MALFORMED;
    }

    /* The subject key fields, captured as a byte range rather than
     * re-encoded. Prepending the base algorithm to exactly these bytes
     * reproduces the public key blob OpenSSH would have written, which is
     * what check 2 compares against. */
    key_start = ssh_rd_offset(&r);
    for (int i = 0; i < fields; i++) {
        if (!ssh_rd_skip_str(&r)) {
            return SSOOSSH_CERT_MALFORMED;
        }
    }
    key_end = ssh_rd_offset(&r);

    ssh_wr_init(&kw, out->key_blob, sizeof(out->key_blob));
    ssh_wr_cstr(&kw, base);
    ssh_wr_bytes(&kw, blob + key_start, key_end - key_start);
    if (!ssh_wr_ok(&kw)) {
        return SSOOSSH_CERT_MALFORMED;
    }
    out->key_blob_len = ssh_wr_len(&kw);

    out->serial = ssh_rd_u64(&r);
    out->type = ssh_rd_u32(&r);

    if (!ssh_rd_str(&r, &out->key_id.p, &out->key_id.len)) {
        return SSOOSSH_CERT_MALFORMED;
    }
    if (!ssh_rd_str(&r, &p, &n) || !parse_principals(p, n, out)) {
        return SSOOSSH_CERT_MALFORMED;
    }

    out->valid_after = ssh_rd_u64(&r);
    out->valid_before = ssh_rd_u64(&r);

    /* Critical options, extensions and reserved are skipped. Extensions
     * describe what an sshd session may do with the certificate; this
     * module is deciding whether a local account may be assumed, and
     * honouring a force-command or a source-address here would be
     * inventing a policy the server never asked for. */
    if (!ssh_rd_skip_str(&r) || !ssh_rd_skip_str(&r) || !ssh_rd_skip_str(&r)) {
        return SSOOSSH_CERT_MALFORMED;
    }

    if (!ssh_rd_str(&r, &out->signature_key.p, &out->signature_key.len)) {
        return SSOOSSH_CERT_MALFORMED;
    }

    /* Everything before the signature field is what the CA signed. One
     * integer, captured here, instead of copying the certificate, clearing
     * its signature, re-marshalling it and trimming the length prefix. */
    out->signed_len = ssh_rd_offset(&r);

    if (!ssh_rd_str(&r, &p, &n)) {
        return SSOOSSH_CERT_MALFORMED;
    }
    /* Trailing bytes are not slack. After a certificate they are a second
     * certificate that nobody verified. */
    if (!ssh_rd_done(&r)) {
        return SSOOSSH_CERT_MALFORMED;
    }

    /* The signature is itself a two-field blob: the algorithm that produced
     * it, then the signature body. */
    {
        ssh_rd sr;
        const uint8_t *algo = NULL;
        size_t algo_len = 0;

        ssh_rd_init(&sr, p, n);
        if (!ssh_rd_str(&sr, &algo, &algo_len) ||
            !copy_name(algo, algo_len, out->signature_algo,
                       sizeof(out->signature_algo))) {
            return SSOOSSH_CERT_MALFORMED;
        }
        if (!ssh_rd_str(&sr, &out->signature.p, &out->signature.len) ||
            !ssh_rd_done(&sr)) {
            return SSOOSSH_CERT_MALFORMED;
        }
    }

    return SSOOSSH_CERT_OK;
}

ssoossh_cert_status ssoossh_cert_parse_line(const char *line, size_t line_len,
                                            uint8_t *scratch,
                                            size_t scratch_cap,
                                            ssoossh_cert *out)
{
    size_t i = 0, b64_start, b64_len, blob_len = 0;

    /* The same shape as an authorized_keys line: a type, a base64 body, and
     * an optional comment. The type is not trusted -- the blob names itself
     * and the two are compared after the decode. */
    while (i < line_len && (line[i] == ' ' || line[i] == '\t')) {
        i++;
    }
    while (i < line_len && line[i] != ' ' && line[i] != '\t') {
        i++;
    }
    while (i < line_len && (line[i] == ' ' || line[i] == '\t')) {
        i++;
    }
    b64_start = i;
    while (i < line_len && line[i] != ' ' && line[i] != '\t' &&
           line[i] != '\n' && line[i] != '\r') {
        i++;
    }
    b64_len = i - b64_start;
    if (b64_len == 0) {
        return SSOOSSH_CERT_MALFORMED;
    }

    if (!ssoossh_b64_decode(line + b64_start, b64_len, scratch, scratch_cap,
                            &blob_len)) {
        return SSOOSSH_CERT_MALFORMED;
    }
    return ssoossh_cert_parse(scratch, blob_len, out);
}

ssoossh_verify_result ssoossh_cert_verify(const ssoossh_cert *cert,
                                          const uint8_t *ca_blob,
                                          size_t ca_blob_len)
{
    return ssoossh_crypto_verify(cert->signature_algo, ca_blob, ca_blob_len,
                                 cert->blob, cert->signed_len,
                                 cert->signature.p, cert->signature.len);
}

bool ssoossh_cert_has_principal(const ssoossh_cert *cert, const char *name)
{
    size_t len = strlen(name);

    for (size_t i = 0; i < cert->principal_count; i++) {
        if (cert->principals[i].len == len &&
            memcmp(cert->principals[i].p, name, len) == 0) {
            return true;
        }
    }
    return false;
}
