/* The principals map, the four checks, console detection, and the QR
 * renderer.
 *
 * The map cases are principalsmap_test.go's tables, both halves. Which
 * files parse is a security-relevant answer rather than a convenience: a
 * map that fails to load is treated as no map at all, and the module falls
 * back to requiring the exact local account name -- a different policy than
 * the file asked for.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "checks.h"
#include "console.h"
#include "fixture.h"
#include "localaddrs.h"
#include "principals_map.h"
#include "sshcert.h"
#include "sshkey.h"
#include "suites.h"
#include "test.h"
#ifndef __APPLE__
#    include "../../third_party/qrcodegen/qrcodegen.h"
#    include "qr.h"
#endif

/* Writes content to a temp file and loads it, so the table can be written
 * as the file text it stands for. */
static ssoossh_map_status load_text(const char *text, const char *account,
                                    ssoossh_principals *out, char *err,
                                    size_t err_cap)
{
    char path[] = "/tmp/ssoossh-map-XXXXXX";
    int fd = mkstemp(path);
    FILE *f;
    ssoossh_map_status rc;

    if (fd < 0) {
        t_failf(__FILE__, __LINE__, "mkstemp failed");
        return SSOOSSH_MAP_UNREADABLE;
    }
    f = fdopen(fd, "w");
    if (f == NULL) {
        (void)close(fd);
        (void)unlink(path);
        return SSOOSSH_MAP_UNREADABLE;
    }
    (void)fwrite(text, 1, strlen(text), f);
    (void)fclose(f);

    rc = ssoossh_principals_map_load(path, account, out, err, err_cap);
    (void)unlink(path);
    return rc;
}

int suite_principals_map(void)
{
    ssoossh_principals p;
    char err[256];

    /* Everything principalsmap_test.go accepts. The expectation is
     * expressed as the entry for "alice", because that is the only entry
     * this module ever needs. */
    {
        static const struct {
            const char *in;
            bool found;
            size_t count;
            const char *first;
        } ok[] = {
            {"alice:\n  - alice\n  - admin\n", true, 2, "alice"},
            {"alice:\n  - admin\nbob:\n  - bob\n", true, 1, "admin"},
            /* List items are accepted at any indentation, including none. */
            {"alice:\n- admin\n    - ops\n", true, 2, "admin"},
            /* An account with nothing under it allows nobody. */
            {"alice:\n", true, 0, NULL},
            {"alice: null\n", true, 0, NULL},
            {"alice: ~\n", true, 0, NULL},
            {"alice: []\n", true, 0, NULL},
            {"alice: [admin, ops]\n", true, 2, "admin"},
            {"# who may become alice\n\nalice:\n\n  - admin\n", true, 1,
             "admin"},
            {"alice:   # the admin account\n  - admin # on call\n", true, 1,
             "admin"},
            /* A hash that is part of a value, not a comment. */
            {"alice:\n  - admin#1\n", true, 1, "admin#1"},
            {"\"alice\":\n  - \"admin\"\n", true, 1, "admin"},
            {"'alice':\n  - 'admin'\n", true, 1, "admin"},
            {"alice:\n  - 'admin # not a comment'\n", true, 1,
             "admin # not a comment"},
            {"alice:\r\n  - admin\r\n", true, 1, "admin"},
            {"", false, 0, NULL},
            {"# nothing here yet\n", false, 0, NULL},
            /* An account that is not ours parses fine and yields nothing. */
            {"bob:\n  - admin\n", false, 0, NULL},
        };

        for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++) {
            T_CHECKF(load_text(ok[i].in, "alice", &p, err, sizeof(err)) ==
                         SSOOSSH_MAP_OK,
                     "case %zu did not load: %s", i, err);
            T_CHECKF(p.found == ok[i].found, "case %zu: found=%d, want %d", i,
                     (int)p.found, (int)ok[i].found);
            T_CHECKF(p.count == ok[i].count,
                     "case %zu: %zu principals, want "
                     "%zu",
                     i, p.count, ok[i].count);
            if (ok[i].first != NULL && p.count > 0) {
                T_EQ_STR(p.principals[0], ok[i].first);
            }
        }
    }

    /* Everything it rejects. Each of these would otherwise be read as
     * something other than what the file says. */
    {
        static const char *const bad[] = {
            "alice: [this is not: valid\n", /* unterminated flow sequence */
            "alice: admin\n",               /* a scalar where a list belongs */
            "alice: \"\"\n",                /* an empty string, likewise */
            "  - admin\n",                  /* a principal under no account */
            "alice: [admin]\n  - ops\n",    /* an item after an inline list */
            "alice:\n  - admin\nalice:\n  - ops\n", /* a duplicate account */
            "alice:\n\t- admin\n",                  /* tab indentation */
            "alice\n",                 /* neither an account nor an item */
            ":\n  - admin\n",          /* an empty account name */
            "alice:\n  -\n",           /* a bare dash */
            "alice:\n  -admin\n",      /* no space after the dash */
            "alice: [admin, , ops]\n", /* an empty entry in a list */
            "alice:\n  - 'admin\n",    /* an unterminated quote */
            "alice: ['admin]\n",       /* the same, inside a list */
            "'a\\b':\n  - admin\n",    /* escapes in an account name */
            "alice:\n  - \"ad\\u006din\"\n", /* escapes in a value */
            "alice:\n  admin:\n    - ops\n", /* a nested mapping */
        };

        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            T_CHECKF(load_text(bad[i], "alice", &p, err, sizeof(err)) ==
                         SSOOSSH_MAP_MALFORMED,
                     "accepted what it should reject: %s", bad[i]);
            /* The message names the line, because it reaches an operator
             * through a syslog warning and nothing else will. */
            T_CHECKF(err[0] != '\0', "rejected %s with no message", bad[i]);
        }
    }

    /* A file that is not there at all. */
    T_EQ_INT(ssoossh_principals_map_load("/nonexistent/principals.yaml",
                                         "alice", &p, err, sizeof(err)),
             SSOOSSH_MAP_UNREADABLE);

    /* Allowed(): an account with no entry is never allowed, even when a
     * certificate principal happens to match its name. */
    {
        static const char *const certp[] = {"admin", "alice"};

        T_CHECK(load_text("alice:\n  - admin\n", "alice", &p, err,
                          sizeof(err)) == SSOOSSH_MAP_OK);
        T_CHECK(ssoossh_principals_allow(&p, certp, 2));
        T_CHECK(!ssoossh_principals_allow(&p, certp + 1, 1));

        T_CHECK(load_text("bob:\n  - admin\n", "alice", &p, err, sizeof(err)) ==
                SSOOSSH_MAP_OK);
        T_CHECK(!ssoossh_principals_allow(&p, certp, 2));

        /* An account present with an empty list allows nobody. */
        T_CHECK(load_text("alice: []\n", "alice", &p, err, sizeof(err)) ==
                SSOOSSH_MAP_OK);
        T_CHECK(!ssoossh_principals_allow(&p, certp, 2));
    }

    return t_failures;
}

/* Loads a fixture certificate for the check cases. */
static bool cert_of(const char *name, uint8_t *scratch, size_t cap,
                    ssoossh_cert *cert)
{
    char line[SSOOSSH_MAX_CERT_LINE];
    size_t n = fixture_read_line(name, line, sizeof(line));

    return n > 0 && ssoossh_cert_parse_line(line, n, scratch, cap, cert) ==
                        SSOOSSH_CERT_OK;
}

int suite_checks(void)
{
    uint8_t scratch[SSOOSSH_MAX_CERT];
    ssoossh_cert cert;
    ssoossh_ca_list cas;

    if (ssoossh_ca_load("tests/fixtures/cas_one.pub", &cas) != SSOOSSH_CA_OK) {
        t_failf(__FILE__, __LINE__, "could not load the CA fixture");
        return t_failures;
    }

    /* Check 1, both ways. */
    if (cert_of("cert_ca_ecdsa384.cert", scratch, sizeof(scratch), &cert)) {
        T_CHECK(ssoossh_check_ca_signature(&cert, &cas));
    }
    if (cert_of("cert_untrusted.cert", scratch, sizeof(scratch), &cert)) {
        T_CHECK(!ssoossh_check_ca_signature(&cert, &cas));
    }

    /* Check 2. The failing case is the one that matters: a certificate
     * correctly signed by a trusted CA, carrying the right principals,
     * inside its window, and issued to somebody else's keypair. */
    {
        uint8_t user_key[SSOOSSH_MAX_KEY_BLOB];
        size_t user_len = 0;
        char line[SSOOSSH_MAX_KEY_LINE], algo[64];
        bool blank = false;
        size_t n = fixture_read_line("user.pub", line, sizeof(line));

        if (n > 0 &&
            ssoossh_sshkey_parse_line(line, n, user_key, sizeof(user_key),
                                      &user_len, algo, sizeof(algo), &blank)) {
            if (cert_of("cert_ca_ecdsa384.cert", scratch, sizeof(scratch),
                        &cert)) {
                T_CHECK(ssoossh_check_key_binding(&cert, user_key, user_len));
            }
            if (cert_of("cert_other_key.cert", scratch, sizeof(scratch),
                        &cert)) {
                /* Signed by the trusted CA, and for a different key. */
                T_CHECK(ssoossh_check_ca_signature(&cert, &cas));
                T_CHECK(!ssoossh_check_key_binding(&cert, user_key, user_len));
            }
        }
    }

    /* Check 3, without a map: an exact match against the local account. */
    if (cert_of("cert_ca_ecdsa384.cert", scratch, sizeof(scratch), &cert)) {
        T_CHECK(ssoossh_check_principal(&cert, "alice", ""));
        T_CHECK(ssoossh_check_principal(&cert, "ops", ""));
        T_CHECK(!ssoossh_check_principal(&cert, "bob", ""));
        T_CHECK(!ssoossh_check_principal(&cert, "ali", ""));
    }

    /* Check 3, with a map. The map only ever adds principals to an
     * account, so every case here is the exact match plus whatever the map
     * grants -- never less. */
    if (cert_of("cert_ca_ecdsa384.cert", scratch, sizeof(scratch), &cert)) {
        char path[] = "/tmp/ssoossh-map-XXXXXX";
        int fd = mkstemp(path);

        if (fd >= 0) {
            FILE *f = fdopen(fd, "w");
            if (f != NULL) {
                /* deploy is authorized by the certificate's "ops"
                 * principal, which is not the account name. locked is
                 * listed with nothing, which grants nothing extra. */
                (void)fputs("deploy:\n  - ops\nnobody:\n  - someone\n"
                            "locked:\n",
                            f);
                (void)fclose(f);

                /* The map grants a principal that is not the account
                 * name. */
                T_CHECK(ssoossh_check_principal(&cert, "deploy", path));
                /* And grants nothing the certificate does not carry. */
                T_CHECK(!ssoossh_check_principal(&cert, "nobody", path));
                /* An account the map never mentions still matches its own
                 * name: the map adds, it does not gate. */
                T_CHECK(ssoossh_check_principal(&cert, "alice", path));
                /* An account listed with an empty list is the same as an
                 * account that is absent -- it adds nothing, and it is not
                 * a way to lock the account out. Here the certificate
                 * carries no "locked" principal, so it is refused on the
                 * exact match, not by the entry. */
                T_CHECK(!ssoossh_check_principal(&cert, "locked", path));
            }
            (void)unlink(path);
        }

        /* A map that cannot be read leaves exactly the policy that applies
         * with no map at all. Since the map can only ever add, losing it
         * can only ever withdraw an extra way in -- these two assertions
         * match the no-map block above, which is the property that makes
         * the failure safe. */
        T_CHECK(ssoossh_check_principal(&cert, "alice",
                                        "/nonexistent/principals.yaml"));
        T_CHECK(!ssoossh_check_principal(&cert, "deploy",
                                         "/nonexistent/principals.yaml"));
    }

    /* Check 4. The fixtures are minted with windows that cannot drift. */
    if (cert_of("cert_ca_ecdsa384.cert", scratch, sizeof(scratch), &cert)) {
        T_CHECK(ssoossh_check_validity(&cert, (int64_t)time(NULL),
                                       2 * SSOOSSH_SECOND));
    }
    if (cert_of("cert_expired.cert", scratch, sizeof(scratch), &cert)) {
        T_CHECK(!ssoossh_check_validity(&cert, (int64_t)time(NULL),
                                        2 * SSOOSSH_SECOND));
        /* The tolerance is symmetric, and large enough tolerance rescues a
         * certificate that is only just outside its window. */
        T_CHECK(ssoossh_check_validity(&cert, (int64_t)cert.valid_before + 1,
                                       2 * SSOOSSH_SECOND));
        T_CHECK(!ssoossh_check_validity(&cert, (int64_t)cert.valid_before + 3,
                                        2 * SSOOSSH_SECOND));
    }
    if (cert_of("cert_future.cert", scratch, sizeof(scratch), &cert)) {
        T_CHECK(!ssoossh_check_validity(&cert, (int64_t)time(NULL),
                                        2 * SSOOSSH_SECOND));
        T_CHECK(ssoossh_check_validity(&cert, (int64_t)cert.valid_after - 1,
                                       2 * SSOOSSH_SECOND));
        T_CHECK(!ssoossh_check_validity(&cert, (int64_t)cert.valid_after - 3,
                                        2 * SSOOSSH_SECOND));
    }

    return t_failures;
}

int suite_localaddrs(void)
{
    char addrs[SSOOSSH_MAX_LOCAL_ADDRS][SSOOSSH_ADDR_LEN];
    size_t n = ssoossh_local_addresses(addrs, SSOOSSH_MAX_LOCAL_ADDRS);

    /* A machine with no non-loopback address is possible, so the count is
     * not asserted. What is asserted is that nothing that came back is
     * something that should have been filtered out, and that the result is
     * a set. */
    for (size_t i = 0; i < n; i++) {
        T_CHECKF(addrs[i][0] != '\0', "address %zu is empty", i);
        T_CHECKF(strncmp(addrs[i], "127.", 4) != 0,
                 "loopback address %s was not filtered", addrs[i]);
        T_CHECKF(strcmp(addrs[i], "::1") != 0,
                 "loopback address %s was not filtered", addrs[i]);
        T_CHECKF(strncmp(addrs[i], "169.254.", 8) != 0,
                 "link-local address %s was not filtered", addrs[i]);
        T_CHECKF(strncmp(addrs[i], "fe80", 4) != 0,
                 "link-local address %s was not filtered", addrs[i]);
        for (size_t j = i + 1; j < n; j++) {
            T_CHECKF(strcmp(addrs[i], addrs[j]) != 0,
                     "address %s appears twice", addrs[i]);
        }
    }

    return t_failures;
}

int suite_console(void)
{
    static const struct {
        const char *tty;
        const char *rhost;
        bool console;
        const char *why;
    } cases[] = {
        /* Physical consoles: no browser here. */
        {"tty1", "", true, "a Linux virtual console"},
        {"/dev/tty1", "", true, "the same, spelled with its full path"},
        {"tty63", "", true, "the last virtual console"},
        {"console", "", true, "the kernel console"},
        {"/dev/console", "", true, "the same, with its path"},
        {"ttyS0", "", true, "a serial console"},
        {"/dev/ttyS1", "", true, "another serial line"},
        {"ttyAMA0", "", true, "an arm64 PL011, which is what a BMC gives"},
        {"ttyUSB0", "", true, "a USB serial adapter"},
        {"hvc0", "", true, "a hypervisor console"},
        {"ttyv0", "", true, "a FreeBSD virtual console"},
        {"ttyu0", "", true, "a FreeBSD serial line"},

        /* A pseudo-terminal is a terminal emulator or an SSH session, and
         * a browser is a keystroke away in both. */
        {"pts/0", "", false, "a local terminal emulator"},
        {"/dev/pts/12", "", false, "the same, with its path"},

        /* Anything that came in over the network is not a console login,
         * however console-like the local tty looks. */
        {"pts/0", "10.0.0.5", false, "an SSH session"},
        {"tty1", "10.0.0.5", false, "a remote login claiming a console tty"},

        /* No tty: cron, a script, an application that sets no PAM_TTY.
         * There is no human here to read a code off a screen. */
        {"", "", false, "no terminal at all"},

        /* Shapes that must not be mistaken for a console. */
        {"ttyprintk", "", false, "a kernel log device, not a terminal"},
        {"tty", "", false, "the controlling-terminal device, unnumbered"},
        {"ttyS", "", false, "a serial prefix with no number"},
        {"/dev/null", "", false, "not a terminal"},
        {"unknown", "", false, "what some applications set"},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        ssoossh_request_context ctx;

        memset(&ctx, 0, sizeof(ctx));
        (void)snprintf(ctx.tty, sizeof(ctx.tty), "%s", cases[i].tty);
        (void)snprintf(ctx.rhost, sizeof(ctx.rhost), "%s", cases[i].rhost);

        T_CHECKF(ssoossh_context_is_console(&ctx) == cases[i].console,
                 "tty=%s rhost=%s: expected %s (%s)", cases[i].tty,
                 cases[i].rhost, cases[i].console ? "console" : "browser",
                 cases[i].why);
    }

    return t_failures;
}

#ifndef __APPLE__
int suite_qr(void)
{
    static const char url[] = "https://sso.example.com/c/K7M4QP2X";
    char out[SSOOSSH_QR_MAX_OUT];
    size_t n = ssoossh_qr_render(url, out, sizeof(out));
    uint8_t qr[qrcodegen_BUFFER_LEN_FOR_VERSION(4)];
    uint8_t tmp[qrcodegen_BUFFER_LEN_FOR_VERSION(4)];
    int size, rows = 0, cols = 0;

    T_CHECK(n > 0);
    if (n == 0) {
        return t_failures;
    }

    /* Nothing but the five characters the whitelist allows. */
    for (size_t i = 0; i < n;) {
        unsigned char c = (unsigned char)out[i];

        if (c == ' ' || c == '\n') {
            i++;
            continue;
        }
        T_CHECKF(c == 0xE2 && (unsigned char)out[i + 1] == 0x96 &&
                     ((unsigned char)out[i + 2] == 0x80 ||
                      (unsigned char)out[i + 2] == 0x84 ||
                      (unsigned char)out[i + 2] == 0x88),
                 "byte %zu (0x%02x) is not one of the allowed characters", i,
                 c);
        i += 3;
    }

    /* The rendering must match the encoder cell for cell. Comparing
     * against qrcodegen rather than against a stored image is the right
     * boundary: this file owns the drawing, the pinned dependency owns the
     * code, and a change in either shows up here. */
    T_CHECK(qrcodegen_encodeText(url, tmp, qr, qrcodegen_Ecc_LOW, 1, 4,
                                 qrcodegen_Mask_AUTO, true));
    size = qrcodegen_getSize(qr);

    {
        size_t i = 0;
        int x = -2, y = -2;

        while (i < n) {
            unsigned char c = (unsigned char)out[i];
            bool top, bottom;

            if (c == '\n') {
                T_CHECKF(x == size + 2, "row %d ended at column %d, want %d", y,
                         x, size + 2);
                if (cols == 0) {
                    cols = x + 2;
                }
                rows++;
                x = -2;
                y += 2;
                i++;
                continue;
            }

            if (c == ' ') {
                top = false;
                bottom = false;
                i++;
            } else {
                unsigned char third = (unsigned char)out[i + 2];
                top = (third == 0x80 || third == 0x88);
                bottom = (third == 0x84 || third == 0x88);
                i += 3;
            }

            /* A light module is drawn bright; outside the code is the
             * quiet zone, which is light too and which a scanner needs to
             * find the edges at all. */
            {
                bool want_top = (x < 0 || y < 0 || x >= size || y >= size)
                                    ? true
                                    : !qrcodegen_getModule(qr, x, y);
                bool want_bottom =
                    (x < 0 || y + 1 < 0 || x >= size || y + 1 >= size)
                        ? true
                        : !qrcodegen_getModule(qr, x, y + 1);

                T_CHECKF(top == want_top && bottom == want_bottom,
                         "module (%d,%d) rendered %d/%d, want %d/%d", x, y,
                         (int)top, (int)bottom, (int)want_top,
                         (int)want_bottom);
            }
            x++;
        }
    }

    /* It has to fit an 80x24 console with the code and the URL beside it. */
    T_CHECKF(cols <= 40, "the QR is %d columns wide", cols);
    T_CHECKF(rows <= 20, "the QR is %d rows tall", rows);

    /* Something too long for a code this narrow is not an error: the
     * caller prints the typed code either way. */
    {
        char big[512];
        memset(big, 'x', sizeof(big) - 1);
        big[sizeof(big) - 1] = '\0';
        T_EQ_INT(ssoossh_qr_render(big, out, sizeof(out)), 0);
        T_EQ_STR(out, "");
    }

    /* A buffer too small produces nothing rather than half an image. */
    {
        char small[16];
        T_EQ_INT(ssoossh_qr_render(url, small, sizeof(small)), 0);
    }

    return t_failures;
}
#endif /* !__APPLE__ */
