/* Escaping certificate text for syslog.
 *
 * A key ID and the principals are chosen by whoever holds the CA key, and
 * the success line puts the key ID in auth.log as the answer to "who
 * approved this". These cases are written against the threat: a field that
 * carries a newline must not be able to write a second line, and a long one
 * must not be able to push the rest of the message out of the buffer.
 */
#include <string.h>

#include "log.h"
#include "suites.h"
#include "test.h"

/* Escapes a NUL-terminated string, which is every case here bar the one
 * that is about NUL itself. */
static bool esc(const char *in, char *out, size_t out_cap)
{
    return ssoossh_log_escape((const uint8_t *)in, strlen(in), out, out_cap);
}

int suite_log_escape(void)
{
    char out[SSOOSSH_LOG_FIELD_LEN];

    /* What a key_id_template produces passes through untouched, spaces
     * included, or the line stops being greppable for the name in it. */
    T_CHECK(esc("alice@example.com", out, sizeof(out)));
    T_EQ_STR(out, "alice@example.com");
    T_CHECK(esc("alice@example.com via ssoossh", out, sizeof(out)));
    T_EQ_STR(out, "alice@example.com via ssoossh");
    T_CHECK(esc("", out, sizeof(out)));
    T_EQ_STR(out, "");

    /* The forgery this exists to stop: a newline followed by a line that
     * looks like ours. Escaped, it is one line that says what it is. */
    T_CHECK(esc("alice\npam_ssoossh: successful authentication: root", out,
                sizeof(out)));
    T_EQ_STR(out, "alice\\x0apam_ssoossh: successful authentication: root");
    T_CHECK(esc("a\rb\tc\033[2Jd\x7f", out, sizeof(out)));
    T_EQ_STR(out, "a\\x0db\\x09c\\x1b[2Jd\\x7f");

    /* The value is printed inside double quotes, so a quote in it would
     * end the field early, and a backslash would make \x0a ambiguous. */
    T_CHECK(esc("a\"b\\c", out, sizeof(out)));
    T_EQ_STR(out, "a\\\"b\\\\c");

    /* Non-ASCII is escaped byte by byte rather than trusted to be valid
     * UTF-8: syslog daemons disagree about what to do with it. */
    T_CHECK(esc("Jos\xc3\xa9", out, sizeof(out)));
    T_EQ_STR(out, "Jos\\xc3\\xa9");

    /* A NUL inside the field is shown, not taken as the end of it. */
    {
        static const uint8_t nul[] = {'a', 0, 'b'};
        T_CHECK(ssoossh_log_escape(nul, sizeof(nul), out, sizeof(out)));
        T_EQ_STR(out, "a\\x00b");
    }

    /* Too long: cut, reported as cut, and still NUL-terminated within the
     * buffer. */
    {
        char big[1024];

        memset(big, 'x', sizeof(big) - 1);
        big[sizeof(big) - 1] = '\0';
        T_CHECK(!esc(big, out, sizeof(out)));
        T_EQ_INT(strlen(out), sizeof(out) - 1);
    }

    /* Exactly full is not cut: the NUL is the only byte the cap reserves. */
    {
        char small[4];

        T_CHECK(esc("abc", small, sizeof(small)));
        T_EQ_STR(small, "abc");
        T_CHECK(!esc("abcd", small, sizeof(small)));
        T_EQ_STR(small, "abc");
    }

    /* A cut never lands inside an escape: \x0 would decode as some other
     * byte. Here the escape needs four bytes and only three are left. */
    {
        char small[6];

        T_CHECK(!esc("ab\n", small, sizeof(small)));
        T_EQ_STR(small, "ab");
        T_CHECK(!esc("a\"", small, 3));
        T_EQ_INT(strlen(small), 1);
    }

    /* The string form marks its own cut, inside the buffer, because the
     * account name is printed bare rather than in quotes the marker could
     * follow. */
    {
        char big[1024];

        ssoossh_log_escape_str("games", out, sizeof(out));
        T_EQ_STR(out, "games");
        ssoossh_log_escape_str("games\npam_ssoossh: forged", out, sizeof(out));
        T_EQ_STR(out, "games\\x0apam_ssoossh: forged");

        memset(big, 'x', sizeof(big) - 1);
        big[sizeof(big) - 1] = '\0';
        ssoossh_log_escape_str(big, out, sizeof(out));
        T_EQ_INT(strlen(out), SSOOSSH_LOG_FIELD_LEN - 1);
        T_EQ_STR(out + strlen(out) - 3, "...");

        /* The longest name that fits is shown whole, with no marker. */
        big[SSOOSSH_LOG_FIELD_LEN - 4] = '\0';
        ssoossh_log_escape_str(big, out, sizeof(out));
        T_EQ_INT(strlen(out), SSOOSSH_LOG_FIELD_LEN - 4);
        T_CHECK(out[strlen(out) - 1] == 'x');

        /* The smallest buffer allowed holds the marker and nothing else. */
        {
            char tiny[4];

            ssoossh_log_escape_str("", tiny, sizeof(tiny));
            T_EQ_STR(tiny, "");
            ssoossh_log_escape_str("a", tiny, sizeof(tiny));
            T_EQ_STR(tiny, "...");
        }

        /* Cut on an escape: the marker follows whole escapes only. */
        memset(big, 'x', sizeof(big) - 1);
        big[SSOOSSH_LOG_FIELD_LEN - 6] = '\n';
        big[SSOOSSH_LOG_FIELD_LEN - 5] = '\0';
        ssoossh_log_escape_str(big, out, sizeof(out));
        T_EQ_INT(strlen(out), SSOOSSH_LOG_FIELD_LEN - 6 + 3);
        T_EQ_STR(out + strlen(out) - 4, "x...");
    }

    /* A zero-sized buffer is written to not at all. */
    T_CHECK(!esc("a", out, 0));
    T_CHECK(ssoossh_log_escape(NULL, 0, out, 0));

    return t_failures;
}
