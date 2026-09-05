/* The crypto seam and the key handling above it, against keys ssh-keygen
 * actually minted.
 *
 * The interop case matters more than it looks: a public key this module
 * marshals is what ssoosshd signs, so a marshalling bug produces a
 * certificate for a key nobody holds, and check 2 rejects it with a message
 * about key binding rather than about encoding. Handing the same bytes to
 * ssh-keygen is the cheapest way to find that at the source.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "crypto.h"
#include "fixture.h"
#include "sshkey.h"
#include "suites.h"
#include "test.h"

int suite_crypto(void)
{
    ssoossh_keypair *kp = NULL;
    uint8_t point[256];
    size_t point_len = 0;

    /* SHA-256 known answer, so a backend that hashes nothing at all cannot
     * pass by returning true. */
    {
        static const uint8_t want[32] = {
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
            0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
            0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
        uint8_t got[32];
        T_CHECK(ssoossh_crypto_sha256((const uint8_t *)"abc", 3, got));
        T_EQ_MEM(got, sizeof(got), want, sizeof(want));
    }

    /* The per-attempt key is always P-384: an uncompressed point is
     * 1 + 48 + 48 bytes and starts with 0x04. */
    T_CHECK(ssoossh_crypto_keygen(&kp));
    if (kp != NULL) {
        T_CHECK(
            ssoossh_crypto_public_point(kp, point, sizeof(point), &point_len));
        T_EQ_INT(point_len, 97);
        T_EQ_INT(point[0], 0x04);

        /* Two generations differ. A backend that returned a fixed key
         * would pass every other test in this file. */
        {
            ssoossh_keypair *kp2 = NULL;
            uint8_t point2[256];
            size_t point2_len = 0;
            T_CHECK(ssoossh_crypto_keygen(&kp2));
            if (kp2 != NULL) {
                T_CHECK(ssoossh_crypto_public_point(kp2, point2, sizeof(point2),
                                                    &point2_len));
                T_CHECK(point2_len != point_len ||
                        memcmp(point, point2, point_len) != 0);
                ssoossh_crypto_keypair_free(kp2);
            }
        }
        ssoossh_crypto_keypair_free(kp);
    }

    /* Freeing NULL is allowed, because the cleanup path in auth.c runs on
     * failures that happen before the key exists. */
    ssoossh_crypto_keypair_free(NULL);

    /* The capability matrix, asserted rather than documented. A backend
     * that quietly gains or loses an algorithm fails here. */
    T_CHECK(ssoossh_crypto_supports_key("ecdsa-sha2-nistp256"));
    T_CHECK(ssoossh_crypto_supports_key("ecdsa-sha2-nistp384"));
    T_CHECK(ssoossh_crypto_supports_key("ecdsa-sha2-nistp521"));
    T_CHECK(ssoossh_crypto_supports_key("ssh-rsa"));
    T_CHECK(!ssoossh_crypto_supports_key("ssh-dss"));
    T_CHECK(!ssoossh_crypto_supports_key("sk-ssh-ed25519@openssh.com"));
    /* Ed25519 is expected everywhere, with one excuse: a host whose
     * OpenSSL is in FIPS mode and whose FIPS module has no EdDSA (RHEL 8).
     * The backend probes for that and says so; anything else that loses
     * the algorithm -- on macOS, the Security.framework SPI being absent
     * or failing its self-test -- is a failure here, with the version line
     * saying which. */
    {
        const char *fips = ssoossh_crypto_fips_state();
        bool fips_on = fips != NULL && strcmp(fips, "on") == 0;

        if (!ssoossh_crypto_supports_key("ssh-ed25519")) {
            T_CHECKF(fips_on,
                     "no ssh-ed25519 support and FIPS mode is not on "
                     "(crypto: %s, fips: %s)",
                     ssoossh_crypto_version(), fips != NULL ? fips : "n/a");
            if (fips_on) {
                printf("  note: ssh-ed25519 unavailable under FIPS mode "
                       "(crypto: %s)\n",
                       ssoossh_crypto_version());
            }
        }
        T_CHECK(fips == NULL || strcmp(fips, "on") == 0 ||
                strcmp(fips, "off") == 0);
    }

    T_CHECK(ssoossh_crypto_version() != NULL);
    T_CHECK(ssoossh_crypto_version()[0] != '\0');

    return t_failures;
}

/* Hands a marshalled key to ssh-keygen and reads back what it made of it.
 * Returns false when ssh-keygen is not installed, which the caller reports
 * as a visible skip rather than a silent pass. */
static bool ssh_keygen_fingerprint(const char *line, char *out, size_t out_cap)
{
    char path[] = "/tmp/ssoossh-key-XXXXXX";
    char cmd[600];
    FILE *p, *f;
    int fd;
    bool ok = false;

    if (system("command -v ssh-keygen >/dev/null 2>&1") != 0) {
        return false;
    }

    fd = mkstemp(path);
    if (fd < 0) {
        return false;
    }
    f = fdopen(fd, "w");
    if (f == NULL) {
        (void)close(fd);
        (void)unlink(path);
        return false;
    }
    (void)fputs(line, f);
    (void)fclose(f);

    (void)snprintf(cmd, sizeof(cmd), "ssh-keygen -l -f %s 2>/dev/null", path);
    p = popen(cmd, "r");
    if (p != NULL) {
        if (fgets(out, (int)out_cap, p) != NULL) {
            ok = true;
        }
        (void)pclose(p);
    }
    (void)unlink(path);
    return ok;
}

int suite_sshkey(void)
{
    char line[SSOOSSH_MAX_KEY_LINE];
    uint8_t blob[SSOOSSH_MAX_KEY_BLOB];
    size_t blob_len = 0;
    char algo[64];
    bool blank = false;

    /* Every fixture key parses, and its line type and blob type agree. */
    {
        static const struct {
            const char *file;
            const char *algo;
            const char *fingerprint;
        } keys[] = {
            {"ca_ecdsa384.pub", "ecdsa-sha2-nistp384",
             "SHA256:Dvkg6J/g955MeJzanKcST/X11kL7AVOAw1YLiYCaQTA"},
            {"ca_ed25519.pub", "ssh-ed25519",
             "SHA256:GyDkRd7QPZuYu4czIRJoNdep1zJKqxlfuWQ5PUVCcig"},
            {"ca_rsa.pub", "ssh-rsa",
             "SHA256:ftTZW6xDqKO44SJnlvnkqxx5mmBOvvvaOlNjjd2BQDU"},
            {"user.pub", "ecdsa-sha2-nistp384",
             "SHA256:E61G9rlI1u4Gjhah8Y0KY8yLAbGTQ0K9w/+1MAzkRZg"},
        };

        for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
            char fp[SSOOSSH_FINGERPRINT_LEN];
            size_t n = fixture_read_line(keys[i].file, line, sizeof(line));
            if (n == 0) {
                continue;
            }
            T_CHECKF(ssoossh_sshkey_parse_line(line, n, blob, sizeof(blob),
                                               &blob_len, algo, sizeof(algo),
                                               &blank),
                     "%s did not parse", keys[i].file);
            T_EQ_STR(algo, keys[i].algo);
            /* The fingerprints are ssh-keygen -l's own output for these
             * files, so this is a comparison against the reference
             * implementation rather than against ourselves. */
            ssoossh_sshkey_fingerprint(blob, blob_len, fp);
            T_EQ_STR(fp, keys[i].fingerprint);
        }
    }

    /* Comments, blank lines, and a line whose base64 is not base64. */
    T_CHECK(!ssoossh_sshkey_parse_line("# comment", 9, blob, sizeof(blob),
                                       &blob_len, algo, sizeof(algo), &blank));
    T_CHECK(blank);
    T_CHECK(!ssoossh_sshkey_parse_line("   ", 3, blob, sizeof(blob), &blob_len,
                                       algo, sizeof(algo), &blank));
    T_CHECK(blank);
    T_CHECK(!ssoossh_sshkey_parse_line("ssh-ed25519 !!!", 15, blob,
                                       sizeof(blob), &blob_len, algo,
                                       sizeof(algo), &blank));
    T_CHECK(!blank);

    /* A line whose declared type disagrees with the blob inside it: a key
     * claiming to be an algorithm it is not. */
    {
        size_t n = fixture_read_line("ca_ed25519.pub", line, sizeof(line));
        if (n > 0) {
            char forged[SSOOSSH_MAX_KEY_LINE];
            const char *space = strchr(line, ' ');
            T_CHECK(space != NULL);
            if (space != NULL) {
                (void)snprintf(forged, sizeof(forged), "ssh-rsa%s", space);
                T_CHECK(!ssoossh_sshkey_parse_line(forged, strlen(forged), blob,
                                                   sizeof(blob), &blob_len,
                                                   algo, sizeof(algo), &blank));
            }
        }
    }

    /* Loading trusted-ca-file, including every documented degradation. */
    {
        ssoossh_ca_list cas;

        T_EQ_INT(ssoossh_ca_load("tests/fixtures/cas_one.pub", &cas),
                 SSOOSSH_CA_OK);
        T_EQ_INT(cas.count, 1);
        T_EQ_STR(cas.keys[0].algo, "ecdsa-sha2-nistp384");

        T_EQ_INT(ssoossh_ca_load("tests/fixtures/cas_two.pub", &cas),
                 SSOOSSH_CA_OK);
        T_EQ_INT(cas.count, 2);

        T_EQ_INT(ssoossh_ca_load("tests/fixtures/cas_comments.pub", &cas),
                 SSOOSSH_CA_OK);
        T_EQ_INT(cas.count, 1);

        /* An Ed25519 and an ECDSA CA in one file. Both are usable
         * everywhere but under a FIPS configuration without EdDSA, where
         * the Ed25519 line is skipped and the ECDSA one carries the file
         * -- which is the mid-rotation case this skip exists for. */
        T_EQ_INT(ssoossh_ca_load("tests/fixtures/cas_mixed.pub", &cas),
                 SSOOSSH_CA_OK);
        if (ssoossh_crypto_supports_key("ssh-ed25519")) {
            T_EQ_INT(cas.count, 2);
            T_EQ_INT(cas.skipped, 0);
        } else {
            T_EQ_INT(cas.count, 1);
            T_EQ_INT(cas.skipped, 1);
        }

        /* The mid-rotation case: a file listing a key no backend can use
         * still authenticates against the one it can. The unusable line
         * is skipped with a warning naming its type, and the count says
         * the ECDSA one carried the file. */
        T_EQ_INT(ssoossh_ca_load("tests/fixtures/cas_unusable.pub", &cas),
                 SSOOSSH_CA_OK);
        T_EQ_INT(cas.count, 1);
        T_EQ_INT(cas.skipped, 1);

        T_EQ_INT(ssoossh_ca_load("tests/fixtures/cas_empty.pub", &cas),
                 SSOOSSH_CA_NONE_USABLE);
        T_EQ_INT(ssoossh_ca_load("tests/fixtures/cas_malformed.pub", &cas),
                 SSOOSSH_CA_MALFORMED);
        T_EQ_INT(ssoossh_ca_load("tests/fixtures/does-not-exist", &cas),
                 SSOOSSH_CA_UNREADABLE);
    }

    /* Round trip: generate a key the way an attempt does, marshal it, and
     * let ssh-keygen tell us what it is. */
    {
        ssoossh_keypair *kp = NULL;
        uint8_t point[256];
        size_t point_len = 0;
        char out[256];

        T_CHECK(ssoossh_crypto_keygen(&kp));
        if (kp != NULL) {
            T_CHECK(ssoossh_crypto_public_point(kp, point, sizeof(point),
                                                &point_len));
            T_CHECK(ssoossh_sshkey_blob_p384(point, point_len, blob,
                                             sizeof(blob), &blob_len));
            T_CHECK(ssoossh_sshkey_authorized_line(blob, blob_len, line,
                                                   sizeof(line)));

            /* ssh.MarshalAuthorizedKey ends its output with a newline and
             * the Go module sends that verbatim, so the C module does too. */
            T_CHECK(strncmp(line, "ecdsa-sha2-nistp384 ", 20) == 0);
            T_CHECK(line[strlen(line) - 1] == '\n');

            if (ssh_keygen_fingerprint(line, out, sizeof(out))) {
                T_CHECKF(strstr(out, "384") != NULL,
                         "ssh-keygen did not call it a 384-bit key: %s", out);
                T_CHECKF(strstr(out, "ECDSA") != NULL,
                         "ssh-keygen did not call it ECDSA: %s", out);
            } else {
                /* Printed rather than skipped silently. CI installs
                 * openssh-client precisely so this never appears there. */
                (void)fprintf(stderr,
                              "  SKIP ssh-keygen interop: ssh-keygen not "
                              "available\n");
            }
            ssoossh_crypto_keypair_free(kp);
        }
    }

    return t_failures;
}
