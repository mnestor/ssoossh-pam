#include "sshkey.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base64.h"
#include "log.h"
#include "sshwire.h"

/* A trusted-ca-file larger than this is not a CA file. Read with a cap
 * rather than by stat size, so a growing file or a fifo cannot make the
 * module allocate what it was pointed at.
 *
 * 32 KiB rather than something generous because it is a stack buffer inside
 * sudo, and because SSOOSSH_MAX_CAS caps the useful content well below it:
 * 32 RSA-8192 keys in authorized_keys form is about 45 KiB, and every
 * realistic file is two or three ECDSA lines. */
#define MAX_CA_FILE (32 * 1024)

bool ssoossh_sshkey_blob_p384(const uint8_t *point, size_t point_len,
                              uint8_t *out, size_t out_cap, size_t *out_len)
{
    ssh_wr w;

    ssh_wr_init(&w, out, out_cap);
    ssh_wr_cstr(&w, "ecdsa-sha2-nistp384");
    ssh_wr_cstr(&w, "nistp384");
    ssh_wr_str(&w, point, point_len);
    if (!ssh_wr_ok(&w)) {
        return false;
    }
    *out_len = ssh_wr_len(&w);
    return true;
}

/* The key type is read back out of the blob rather than passed in: the
 * line's type field and the blob's own must agree, and reading one from the
 * other is how they cannot disagree. */
static bool blob_algo(const uint8_t *blob, size_t blob_len, char *out,
                      size_t out_cap)
{
    ssh_rd r;

    ssh_rd_init(&r, blob, blob_len);
    return ssh_rd_cstr(&r, out, out_cap);
}

bool ssoossh_sshkey_authorized_line(const uint8_t *blob, size_t blob_len,
                                    char *out, size_t out_cap)
{
    char algo[64];
    size_t algo_len;

    if (!blob_algo(blob, blob_len, algo, sizeof(algo))) {
        return false;
    }
    algo_len = strlen(algo);
    if (algo_len + 2 >= out_cap) {
        return false;
    }
    memcpy(out, algo, algo_len);
    out[algo_len] = ' ';
    if (!ssoossh_b64_encode(blob, blob_len, out + algo_len + 1,
                            out_cap - algo_len - 1)) {
        return false;
    }
    /* The trailing newline ssh.MarshalAuthorizedKey emits. */
    size_t n = strlen(out);
    if (n + 2 > out_cap) {
        return false;
    }
    out[n] = '\n';
    out[n + 1] = '\0';
    return true;
}

void ssoossh_sshkey_fingerprint(const uint8_t *blob, size_t blob_len,
                                char out[SSOOSSH_FINGERPRINT_LEN])
{
    static const char prefix[] = "SHA256:";
    const size_t prefix_len = sizeof(prefix) - 1;
    uint8_t digest[32];
    char b64[64];
    size_t n;

    /* A key that cannot be hashed still has to render, because this goes
     * into the middle of a log message and a caller should not need an
     * error path to write one. */
    memcpy(out, "<none>", sizeof("<none>"));

    if (blob == NULL || blob_len == 0 ||
        !ssoossh_crypto_sha256(blob, blob_len, digest) ||
        !ssoossh_b64_encode(digest, sizeof(digest), b64, sizeof(b64))) {
        return;
    }

    /* ssh-keygen prints the digest unpadded. */
    n = strlen(b64);
    while (n > 0 && b64[n - 1] == '=') {
        n--;
    }
    if (prefix_len + n + 1 > SSOOSSH_FINGERPRINT_LEN) {
        return;
    }
    memcpy(out, prefix, prefix_len);
    memcpy(out + prefix_len, b64, n);
    out[prefix_len + n] = '\0';
}

static bool is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\r';
}

bool ssoossh_sshkey_parse_line(const char *line, size_t line_len, uint8_t *blob,
                               size_t blob_cap, size_t *blob_len, char *algo,
                               size_t algo_cap, bool *is_blank)
{
    size_t i = 0, type_start, type_len, b64_start, b64_len;
    char blob_type[64];

    if (is_blank != NULL) {
        *is_blank = false;
    }

    while (i < line_len && is_space(line[i])) {
        i++;
    }
    if (i == line_len || line[i] == '#') {
        if (is_blank != NULL) {
            *is_blank = true;
        }
        return false;
    }

    type_start = i;
    while (i < line_len && !is_space(line[i])) {
        i++;
    }
    type_len = i - type_start;
    if (type_len == 0 || type_len >= algo_cap) {
        return false;
    }

    while (i < line_len && is_space(line[i])) {
        i++;
    }
    b64_start = i;
    while (i < line_len && !is_space(line[i])) {
        i++;
    }
    b64_len = i - b64_start;
    if (b64_len == 0) {
        return false;
    }
    /* Anything after the base64 is a comment and is ignored, which is what
     * authorized_keys means by the third field.
     *
     * An options field before the key type is not supported and lands here
     * as a malformed line. Options describe what an authorized key may do
     * on login; a trusted-ca-file entry is not that, and reading one as a
     * key type would be reading the operator's file as something other
     * than what they wrote. */

    memcpy(algo, line + type_start, type_len);
    algo[type_len] = '\0';

    if (!ssoossh_b64_decode(line + b64_start, b64_len, blob, blob_cap,
                            blob_len)) {
        return false;
    }
    if (!blob_algo(blob, *blob_len, blob_type, sizeof(blob_type))) {
        return false;
    }
    /* The line names a type and so does the blob inside it. A mismatch is
     * a key pretending to be an algorithm it is not. */
    if (strcmp(algo, blob_type) != 0) {
        return false;
    }
    return true;
}

ssoossh_ca_status ssoossh_ca_load(const char *path, ssoossh_ca_list *out)
{
    char buf[MAX_CA_FILE + 1];
    FILE *f;
    size_t n, line_no = 0, pos = 0;

    memset(out, 0, sizeof(*out));

    f = fopen(path, "re");
    if (f == NULL) {
        return SSOOSSH_CA_UNREADABLE;
    }
    n = fread(buf, 1, sizeof(buf) - 1, f);
    if (ferror(f) != 0) {
        (void)fclose(f);
        return SSOOSSH_CA_UNREADABLE;
    }
    /* A file that filled the buffer is either larger than the cap or
     * exactly it; either way it is not something to guess at. */
    if (n >= MAX_CA_FILE) {
        (void)fclose(f);
        ssoossh_errf("trusted CA file %s is larger than %d bytes", path,
                     MAX_CA_FILE);
        return SSOOSSH_CA_MALFORMED;
    }
    (void)fclose(f);
    buf[n] = '\0';

    while (pos <= n) {
        const char *line = buf + pos;
        size_t len = 0;
        uint8_t blob[SSOOSSH_MAX_KEY_BLOB];
        size_t blob_len = 0;
        char algo[64];
        bool blank = false;

        while (pos + len < n && line[len] != '\n') {
            len++;
        }
        pos += len + 1;
        line_no++;
        if (len == 0) {
            if (pos > n) {
                break;
            }
            continue;
        }

        if (!ssoossh_sshkey_parse_line(line, len, blob, sizeof(blob), &blob_len,
                                       algo, sizeof(algo), &blank)) {
            if (blank) {
                continue;
            }
            ssoossh_errf("trusted CA file %s line %zu is not a valid key", path,
                         line_no);
            return SSOOSSH_CA_MALFORMED;
        }

        if (!ssoossh_crypto_supports_key(algo)) {
            /* Not fatal on its own. A file mid-rotation may list a key
             * this platform cannot use -- an Ed25519 CA appended on a
             * Friday must not take every macOS host offline, and it must
             * certainly not do it with "not signed by a trusted CA" as the
             * only explanation. */
            ssoossh_warnf("trusted CA file %s line %zu uses %s, which this "
                          "build's crypto backend cannot verify; skipping it",
                          path, line_no, algo);
            out->skipped++;
            continue;
        }

        if (out->count >= SSOOSSH_MAX_CAS) {
            ssoossh_warnf("trusted CA file %s holds more than %d keys; "
                          "ignoring the rest from line %zu",
                          path, SSOOSSH_MAX_CAS, line_no);
            break;
        }

        memcpy(out->keys[out->count].blob, blob, blob_len);
        out->keys[out->count].len = blob_len;
        (void)snprintf(out->keys[out->count].algo,
                       sizeof(out->keys[out->count].algo), "%s", algo);
        out->count++;
    }

    if (out->count == 0) {
        return SSOOSSH_CA_NONE_USABLE;
    }
    return SSOOSSH_CA_OK;
}
