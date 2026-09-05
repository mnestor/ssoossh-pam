#include "conv.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"

/* Crockford Base32 omits I, L, O and U -- the letters that get confused
 * with digits or with each other when a human reads a code off a screen and
 * types it somewhere else. */
static bool code_char(unsigned char c)
{
    if (c >= '0' && c <= '9') {
        return true;
    }
    if (c >= 'A' && c <= 'Z') {
        return c != 'I' && c != 'L' && c != 'O' && c != 'U';
    }
    return c == '-';
}

/* RFC 3986's full character repertoire: unreserved / reserved / '%'.
 *
 * Deliberately not narrower. A URL that loses a character is a URL that
 * does not work, and an operator staring at a subtly wrong link is a worse
 * outcome than the one this filter exists to prevent. What matters is that
 * every byte outside 0x21..0x7E is gone, which is where escape sequences,
 * carriage returns, backspaces and terminal control live. */
static bool url_char(unsigned char c)
{
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9')) {
        return true;
    }
    return strchr("-._~:/?#[]@!$&'()*+,;=%", (char)c) != NULL && c != '\0';
}

/* The QR class is the only one whose alphabet is not single bytes, so it
 * gets its own scan. A three-byte sequence is taken whole or not at all:
 * accepting 0xE2 on its own would let a server start a sequence the
 * terminal completes with whatever follows. */
static size_t sanitize_qr(const char *in, char *out, size_t out_size)
{
    size_t dropped = 0, w = 0;

    for (size_t i = 0; in[i] != '\0';) {
        unsigned char c = (unsigned char)in[i];
        size_t take = 0;

        if (c == ' ' || c == '\n') {
            take = 1;
        } else if (c == 0xE2 && (unsigned char)in[i + 1] == 0x96) {
            unsigned char third = (unsigned char)in[i + 2];
            if (third == 0x80 || third == 0x84 || third == 0x88) {
                take = 3; /* U+2580, U+2584, U+2588 */
            }
        }

        if (take == 0) {
            dropped++;
            i++;
            continue;
        }
        if (w + take + 1 > out_size) {
            /* Out of room. Everything left is dropped, including this. */
            dropped += strlen(in + i);
            break;
        }
        memcpy(out + w, in + i, take);
        w += take;
        i += take;
    }

    out[w] = '\0';
    return dropped;
}

size_t ssoossh_sanitize(ssoossh_text_class cls, const char *in, char *out,
                        size_t out_size)
{
    size_t dropped = 0, w = 0;

    if (out_size == 0) {
        return strlen(in);
    }
    if (cls == SSOOSSH_TEXT_QR) {
        return sanitize_qr(in, out, out_size);
    }

    for (size_t i = 0; in[i] != '\0'; i++) {
        unsigned char c = (unsigned char)in[i];
        bool ok = (cls == SSOOSSH_TEXT_CODE) ? code_char(c) : url_char(c);

        if (!ok) {
            dropped++;
            continue;
        }
        if (w + 1 >= out_size) {
            dropped += strlen(in + i);
            break;
        }
        out[w++] = (char)c;
    }

    out[w] = '\0';
    return dropped;
}

int ssoossh_conv(pam_handle_t *pamh, int style, const char *text,
                 char **response)
{
    const struct pam_conv *conv = NULL;
    struct pam_message msg;
    const struct pam_message *msgs[1];
    struct pam_response *resp = NULL;
    int rc;

    if (response != NULL) {
        *response = NULL;
    }

    /* pam_get_item's out parameter is const void **, and the item it hands
     * back is owned by libpam: it must not be freed, and it stays valid for
     * the life of the transaction. */
    rc = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
    if (rc != PAM_SUCCESS) {
        return rc;
    }
    if (conv == NULL || conv->conv == NULL) {
        /* An application that started a transaction without a conversation
         * function. Nothing to say and nowhere to say it. */
        return PAM_CONV_ERR;
    }

    memset(&msg, 0, sizeof(msg));
    msg.msg_style = style;
    /* XSSO's struct pam_message declares msg as char *, not const char *,
     * even though the conversation function must not modify it; msgs itself
     * is an array of const struct pam_message *, so this stays read-only. */
    msg.msg = (char *)text;
    msgs[0] = &msg;

    rc = conv->conv(1, msgs, &resp, conv->appdata_ptr);

    /* The conversation function allocates the response array and we own
     * freeing it, per pam_conv(3) -- including on a failure return, where
     * an implementation may still have allocated. */
    if (resp != NULL) {
        if (rc == PAM_SUCCESS && response != NULL && resp[0].resp != NULL) {
            *response = resp[0].resp; /* ownership moves to the caller */
        } else if (resp[0].resp != NULL) {
            free(resp[0].resp);
        }
        free(resp);
    }
    return rc;
}
