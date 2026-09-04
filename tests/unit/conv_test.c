/* The conversation whitelist.
 *
 * There is no Go equivalent to port: the Go module passes the server's
 * approval URL straight into PAM_TEXT_INFO, which is the hole this closes.
 * So these cases are written against the threat rather than against a
 * previous implementation -- a server-controlled string must not be able to
 * put a control byte on the tty of a process running as root.
 */
#include <string.h>

#include "conv.h"
#include "suites.h"
#include "test.h"

/* Sanitizes into a generous buffer and returns how much was dropped, so a
 * case can assert on both halves in one line each. */
static size_t clean(ssoossh_text_class cls, const char *in, char *out,
                    size_t out_size)
{
    return ssoossh_sanitize(cls, in, out, out_size);
}

int suite_sanitize(void)
{
    char out[256];

    /* A real approval URL survives byte for byte. If this ever stops being
     * true the filter is useless, because an operator cannot click it. */
    static const char *const urls[] = {
        "https://sso.example.com/approve/6f1c0a5e-1f2b-4c3d-8e9f-0a1b2c3d4e5f",
        "https://sso.example.com:8443/approve/abc?token=x%20y&next=/a+b",
        "http://127.0.0.1:8080/c/K7M4-QP2X",
        "https://[2001:db8::1]/approve/id#frag",
    };
    for (size_t i = 0; i < sizeof(urls) / sizeof(urls[0]); i++) {
        T_EQ_INT(clean(SSOOSSH_TEXT_URL, urls[i], out, sizeof(out)), 0);
        T_EQ_STR(out, urls[i]);
    }

    /* Escape sequences. The first is the classic: set the terminal title,
     * or with a different final byte, stuff the input buffer. */
    T_CHECK(clean(SSOOSSH_TEXT_URL, "https://a.example/\x1b]0;pwned\x07x", out,
                  sizeof(out)) > 0);
    T_EQ_STR(out, "https://a.example/]0;pwnedx");

    T_CHECK(clean(SSOOSSH_TEXT_URL, "https://a.example/\x1b[2J\x1b[H", out,
                  sizeof(out)) > 0);
    T_EQ_STR(out, "https://a.example/[2J[H");

    /* A carriage return lets a server overwrite the line it just wrote --
     * the "displayed one URL, sent you to another" trick. */
    T_CHECK(clean(SSOOSSH_TEXT_URL,
                  "https://good.example\rhttps://evil.example", out,
                  sizeof(out)) > 0);
    T_EQ_STR(out, "https://good.examplehttps://evil.example");

    /* Backspace, bell, NUL-adjacent control bytes, and DEL. */
    T_CHECK(clean(SSOOSSH_TEXT_URL, "https://a.example\b\b\b\a\x7f", out,
                  sizeof(out)) == 5);
    T_EQ_STR(out, "https://a.example");

    /* A newline would let a server forge a second line of module output. */
    T_CHECK(clean(SSOOSSH_TEXT_URL, "https://a.example\nApprove: yes", out,
                  sizeof(out)) > 0);
    T_EQ_STR(out, "https://a.exampleApprove:yes");

    /* Non-ASCII: homograph domains render as something they are not, and a
     * lone continuation byte can start a sequence the terminal completes. */
    T_CHECK(clean(SSOOSSH_TEXT_URL, "https://\xd0\xb0pple.example", out,
                  sizeof(out)) == 2);
    T_EQ_STR(out, "https://pple.example");

    /* Truncation counts as dropped, so one non-zero check catches both
     * kinds of loss. */
    {
        char small[8];
        T_CHECK(clean(SSOOSSH_TEXT_URL, "https://a.example", small,
                      sizeof(small)) > 0);
        T_EQ_STR(small, "https:/");
    }

    /* Crockford Base32 plus the group separator, and nothing else. I, L, O
     * and U are not in the alphabet: a code containing one did not come
     * from this server. */
    T_EQ_INT(clean(SSOOSSH_TEXT_CODE, "K7M4-QP2X", out, sizeof(out)), 0);
    T_EQ_STR(out, "K7M4-QP2X");
    T_EQ_INT(clean(SSOOSSH_TEXT_CODE, "ILOU", out, sizeof(out)), 4);
    T_EQ_STR(out, "");
    T_CHECK(clean(SSOOSSH_TEXT_CODE, "k7m4", out, sizeof(out)) == 2);
    T_EQ_STR(out, "74");
    T_CHECK(clean(SSOOSSH_TEXT_CODE, "K7M4\x1b[m", out, sizeof(out)) == 3);
    T_EQ_STR(out, "K7M4");

    /* QR: exactly three block characters, space and newline, matched whole.
     * A truncated sequence is dropped rather than passed through byte by
     * byte, so a server cannot open a sequence the terminal finishes. */
    T_EQ_INT(clean(SSOOSSH_TEXT_QR, "\xe2\x96\x80\xe2\x96\x84\xe2\x96\x88 \n",
                   out, sizeof(out)),
             0);
    T_EQ_STR(out, "\xe2\x96\x80\xe2\x96\x84\xe2\x96\x88 \n");

    /* U+2591 LIGHT SHADE is in the same block and still not allowed. */
    T_EQ_INT(clean(SSOOSSH_TEXT_QR, "\xe2\x96\x91", out, sizeof(out)), 3);
    T_EQ_STR(out, "");

    /* A bare lead byte, and a lead byte followed by an escape. */
    T_EQ_INT(clean(SSOOSSH_TEXT_QR, "\xe2", out, sizeof(out)), 1);
    T_EQ_STR(out, "");
    T_EQ_INT(clean(SSOOSSH_TEXT_QR, "\xe2\x96\x1b", out, sizeof(out)), 3);
    T_EQ_STR(out, "");

    /* Empty input is not an error in any class. */
    T_EQ_INT(clean(SSOOSSH_TEXT_URL, "", out, sizeof(out)), 0);
    T_EQ_STR(out, "");
    T_EQ_INT(clean(SSOOSSH_TEXT_QR, "", out, sizeof(out)), 0);
    T_EQ_STR(out, "");

    /* A zero-size buffer must not be written to at all. */
    T_EQ_INT(ssoossh_sanitize(SSOOSSH_TEXT_URL, "https://a.example", out, 0),
             17);

    return t_failures;
}
