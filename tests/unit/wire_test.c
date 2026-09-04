/* sshwire, base64 and der: the three encoders every later phase reads
 * through.
 *
 * These have no Go counterpart to port -- x/crypto/ssh did all of it -- so
 * the cases are written against the encodings themselves, with particular
 * attention to the shapes a hostile input takes: a length that runs past
 * the buffer, a length that overflows when added to the cursor, and an
 * alternate encoding of a value that should have exactly one.
 */
#include <string.h>

#include "base64.h"
#include "der.h"
#include "suites.h"
#include "sshwire.h"
#include "test.h"

static void test_reader(void)
{
    static const uint8_t blob[] = {
        0x00, 0x00, 0x00, 0x03, 'a',  'b',  'c',        /* string */
        0x00, 0x00, 0x00, 0x2a,                         /* u32 42 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, /* u64 256 */
    };
    ssh_rd r;
    const uint8_t *p = NULL;
    size_t n = 0;

    ssh_rd_init(&r, blob, sizeof(blob));
    T_CHECK(ssh_rd_str(&r, &p, &n));
    T_EQ_INT(n, 3);
    T_CHECK(memcmp(p, "abc", 3) == 0);
    T_EQ_INT(ssh_rd_offset(&r), 7);
    T_EQ_INT(ssh_rd_u32(&r), 42);
    T_EQ_INT(ssh_rd_u64(&r), 256);
    T_CHECK(ssh_rd_ok(&r));
    T_CHECK(ssh_rd_done(&r));

    /* A length that runs one byte past the end. */
    {
        static const uint8_t over[] = {0x00, 0x00, 0x00, 0x04, 'a', 'b', 'c'};
        ssh_rd o;
        ssh_rd_init(&o, over, sizeof(over));
        T_CHECK(!ssh_rd_str(&o, &p, &n));
        T_CHECK(!ssh_rd_ok(&o));
        /* Everything after a latched failure is a no-op returning zero, so
         * a caller may chain reads and test once. */
        T_EQ_INT(ssh_rd_u32(&o), 0);
        T_CHECK(!ssh_rd_done(&o));
    }

    /* 0xffffffff: the length that overflows if the bounds check is written
     * as an addition to the cursor rather than a subtraction from the end. */
    {
        static const uint8_t huge[] = {0xff, 0xff, 0xff, 0xff, 'a'};
        ssh_rd o;
        ssh_rd_init(&o, huge, sizeof(huge));
        T_CHECK(!ssh_rd_str(&o, &p, &n));
        T_CHECK(!ssh_rd_ok(&o));
    }

    /* An empty buffer answers every read without reading anything. */
    {
        ssh_rd o;
        ssh_rd_init(&o, blob, 0);
        T_CHECK(ssh_rd_done(&o));
        T_EQ_INT(ssh_rd_u32(&o), 0);
        T_CHECK(!ssh_rd_ok(&o));
    }

    /* Trailing bytes are not "done": after a certificate they would be a
     * second certificate nobody verified. */
    {
        ssh_rd o;
        ssh_rd_init(&o, blob, sizeof(blob));
        T_CHECK(ssh_rd_str(&o, &p, &n));
        T_CHECK(!ssh_rd_done(&o));
        T_EQ_INT(ssh_rd_remaining(&o), sizeof(blob) - 7);
    }
}

static void test_writer(void)
{
    uint8_t buf[64];
    ssh_wr w;

    ssh_wr_init(&w, buf, sizeof(buf));
    ssh_wr_cstr(&w, "abc");
    ssh_wr_u32(&w, 42);
    T_CHECK(ssh_wr_ok(&w));
    T_EQ_INT(ssh_wr_len(&w), 11);
    T_CHECK(memcmp(buf,
                   "\x00\x00\x00\x03"
                   "abc\x00\x00\x00\x2a",
                   11) == 0);

    /* Overflow latches and drops the rest rather than writing a partial
     * value the caller might use. */
    {
        uint8_t small[6];
        ssh_wr o;
        ssh_wr_init(&o, small, sizeof(small));
        ssh_wr_cstr(&o, "abcdef");
        T_CHECK(!ssh_wr_ok(&o));
    }

    /* mpint: minimal, and zero-padded when the top bit is set. Both rules
     * matter, because a re-encoded key has to equal byte for byte what
     * OpenSSH would have written. */
    {
        static const uint8_t high[] = {0x80, 0x01};
        static const uint8_t lead0[] = {0x00, 0x00, 0x7f};
        static const uint8_t zero[] = {0x00, 0x00};

        ssh_wr_init(&w, buf, sizeof(buf));
        ssh_wr_mpint(&w, high, sizeof(high));
        T_EQ_INT(ssh_wr_len(&w), 7);
        T_CHECK(memcmp(buf, "\x00\x00\x00\x03\x00\x80\x01", 7) == 0);

        ssh_wr_init(&w, buf, sizeof(buf));
        ssh_wr_mpint(&w, lead0, sizeof(lead0));
        T_EQ_INT(ssh_wr_len(&w), 5);
        T_CHECK(memcmp(buf, "\x00\x00\x00\x01\x7f", 5) == 0);

        /* Zero is the empty string, not a zero byte. */
        ssh_wr_init(&w, buf, sizeof(buf));
        ssh_wr_mpint(&w, zero, sizeof(zero));
        T_EQ_INT(ssh_wr_len(&w), 4);
        T_CHECK(memcmp(buf, "\x00\x00\x00\x00", 4) == 0);
    }
}

static void test_base64(void)
{
    static const struct {
        const char *in;
        const char *want;
    } ok[] = {
        {"", ""},
        {"TWE=", "Ma"},
        {"TWFu", "Man"},
        {"aGVsbG8gd29ybGQ=", "hello world"},
        {"c3VyZS4=", "sure."},
    };
    static const char *const bad[] = {
        "TWF",      /* not a multiple of four */
        "TWFu=",    /* padding in the wrong place */
        "TW=u",     /* data after padding */
        "TWFu====", /* three pad characters */
        "TW Fu",    /* whitespace: an authorized_keys field is one token */
        "TWF\n",    "TWFu-", "TWF*",
        "TWF=", /* non-zero bits under the padding: a second spelling
                 * of "Ma", and one spelling is all a fingerprint
                 * comparison can survive */
    };
    uint8_t out[64];
    char enc[128];
    size_t n = 0;

    for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++) {
        T_CHECKF(ssoossh_b64_decode(ok[i].in, strlen(ok[i].in), out,
                                    sizeof(out), &n),
                 "b64_decode(%s) failed", ok[i].in);
        T_EQ_MEM(out, n, ok[i].want, strlen(ok[i].want));

        T_CHECK(ssoossh_b64_encode((const uint8_t *)ok[i].want,
                                   strlen(ok[i].want), enc, sizeof(enc)));
        T_EQ_STR(enc, ok[i].in);
    }

    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        T_CHECKF(
            !ssoossh_b64_decode(bad[i], strlen(bad[i]), out, sizeof(out), &n),
            "b64_decode(%s) accepted a malformed value", bad[i]);
    }

    /* A decode that does not fit fails rather than writing what it can. */
    {
        uint8_t tiny[2];
        T_CHECK(!ssoossh_b64_decode("aGVsbG8gd29ybGQ=", 16, tiny, sizeof(tiny),
                                    &n));
    }
}

static void test_der(void)
{
    uint8_t out[512];
    size_t n = 0;

    /* SEQUENCE { INTEGER 1, INTEGER 2 } */
    {
        static const uint8_t r[] = {0x01}, s[] = {0x02};
        static const uint8_t want[] = {0x30, 0x06, 0x02, 0x01,
                                       0x01, 0x02, 0x01, 0x02};
        T_CHECK(ssoossh_der_ecdsa_sig(r, 1, s, 1, out, sizeof(out), &n));
        T_EQ_MEM(out, n, want, sizeof(want));
    }

    /* The sign padding an SSH mpint has and a DER INTEGER needs
     * independently: 0x80 is 128, not -128. */
    {
        static const uint8_t r[] = {0x80}, s[] = {0x01};
        static const uint8_t want[] = {0x30, 0x07, 0x02, 0x02, 0x00,
                                       0x80, 0x02, 0x01, 0x01};
        T_CHECK(ssoossh_der_ecdsa_sig(r, 1, s, 1, out, sizeof(out), &n));
        T_EQ_MEM(out, n, want, sizeof(want));
    }

    /* Leading zeros are dropped, so a mpint that arrived padded and one
     * that did not encode identically. */
    {
        static const uint8_t r[] = {0x00, 0x00, 0x05}, s[] = {0x05};
        uint8_t first[64];
        size_t first_len = 0;
        T_CHECK(ssoossh_der_ecdsa_sig(r, sizeof(r), s, 1, first, sizeof(first),
                                      &first_len));
        T_CHECK(ssoossh_der_ecdsa_sig(s, 1, s, 1, out, sizeof(out), &n));
        T_EQ_MEM(first, first_len, out, n);
    }

    /* A compressed EC point is refused: OpenSSH does not emit one, and two
     * encodings of one key is one more than a key comparison survives. */
    {
        uint8_t compressed[49];
        memset(compressed, 0xaa, sizeof(compressed));
        compressed[0] = 0x02;
        T_CHECK(!ssoossh_der_spki_ec(SSOOSSH_CURVE_P384, compressed,
                                     sizeof(compressed), out, sizeof(out), &n));
    }

    /* Ed25519 keys are exactly 32 bytes. */
    {
        uint8_t key[32];
        memset(key, 0x11, sizeof(key));
        T_CHECK(ssoossh_der_spki_ed25519(key, 32, out, sizeof(out), &n));
        /* SEQUENCE(SEQUENCE(OID), BIT STRING) with no parameters: the
         * fixed 12-byte prefix every Ed25519 SPKI has. */
        T_EQ_INT(n, 44);
        T_CHECK(memcmp(out, "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00",
                       12) == 0);
        T_CHECK(!ssoossh_der_spki_ed25519(key, 31, out, sizeof(out), &n));
    }

    /* A buffer too small fails rather than truncating. */
    {
        uint8_t tiny[4];
        static const uint8_t r[] = {0x01};
        T_CHECK(!ssoossh_der_ecdsa_sig(r, 1, r, 1, tiny, sizeof(tiny), &n));
    }
}

int suite_sshwire(void)
{
    test_reader();
    test_writer();
    return t_failures;
}

int suite_der(void)
{
    test_base64();
    test_der();
    return t_failures;
}
