#include "principals_map.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A principals map larger than this is not a hand-authored file. Read on
 * the heap rather than the stack, because unlike the CA file this one has
 * no natural bound on the number of accounts a host might list. */
#define MAX_MAP_FILE (256 * 1024)

/* Reports a malformed line and leaves. Spelling the status assignment and
 * the jump out at each of the dozen sites invited one that set neither --
 * which would return SSOOSSH_MAP_OK with an empty result, the fail-open
 * answer this parser exists to avoid. */
#define MAP_FAIL(...)                                                          \
    do {                                                                       \
        (void)snprintf(err, err_cap, __VA_ARGS__);                             \
        status = SSOOSSH_MAP_MALFORMED;                                        \
        goto done;                                                             \
    } while (0)

/* One line, sliced out of the file buffer. */
typedef struct {
    const char *p;
    size_t len;
} slice;

static slice slice_of(const char *p, size_t len)
{
    slice s = {p, len};
    return s;
}

static bool slice_eq(slice a, const char *b)
{
    size_t n = strlen(b);
    return a.len == n && memcmp(a.p, b, n) == 0;
}

static bool slice_eq_slice(slice a, slice b)
{
    return a.len == b.len && memcmp(a.p, b.p, a.len) == 0;
}

/* Removes a YAML end-of-line comment: a '#' that starts the line or follows
 * whitespace and is not inside a quoted scalar. A '#' anywhere else is an
 * ordinary character of the value, which is why this scans rather than
 * cutting at the first one. */
static slice strip_comment(slice line)
{
    bool in_single = false, in_double = false;

    for (size_t i = 0; i < line.len; i++) {
        char c = line.p[i];

        if (c == '\'' && !in_double) {
            in_single = !in_single;
        } else if (c == '"' && !in_single) {
            in_double = !in_double;
        } else if (c == '#' && !in_single && !in_double &&
                   (i == 0 || line.p[i - 1] == ' ' || line.p[i - 1] == '\t')) {
            return slice_of(line.p, i);
        }
    }
    return line;
}

static slice trim(slice s)
{
    while (s.len > 0 && (s.p[0] == ' ' || s.p[0] == '\t' || s.p[0] == '\r')) {
        s.p++;
        s.len--;
    }
    while (s.len > 0 && (s.p[s.len - 1] == ' ' || s.p[s.len - 1] == '\t' ||
                         s.p[s.len - 1] == '\r')) {
        s.len--;
    }
    return s;
}

/* Strips a matching pair of surrounding quotes. Escapes are not
 * interpreted: a quoted value carrying a backslash or another quote of the
 * same kind is rejected, because reading it literally would silently
 * authorize a principal spelled differently than the file says. */
static bool unquote(slice in, slice *out)
{
    char quote;

    if (in.len == 0) {
        *out = in;
        return true;
    }
    quote = in.p[0];
    if (quote != '"' && quote != '\'') {
        *out = in;
        return true;
    }
    if (in.len < 2 || in.p[in.len - 1] != quote) {
        return false; /* unterminated */
    }
    for (size_t i = 1; i + 1 < in.len; i++) {
        if (in.p[i] == quote || in.p[i] == '\\') {
            return false;
        }
    }
    *out = slice_of(in.p + 1, in.len - 2);
    return true;
}

/* Splits "account: value" at the colon that ends the key, ignoring one
 * inside a quoted key. */
static bool split_key(slice line, slice *key, slice *value)
{
    bool in_single = false, in_double = false;

    for (size_t i = 0; i < line.len; i++) {
        char c = line.p[i];

        if (c == '\'' && !in_double) {
            in_single = !in_single;
        } else if (c == '"' && !in_single) {
            in_double = !in_double;
        } else if (c == ':' && !in_single && !in_double) {
            *key = trim(slice_of(line.p, i));
            *value = trim(slice_of(line.p + i + 1, line.len - i - 1));
            return true;
        }
    }
    return false;
}

static void store(ssoossh_principals *out, slice principal)
{
    if (!out->found || out->count >= SSOOSSH_MAX_MAP_PRINCIPALS ||
        principal.len >= SSOOSSH_MAX_PRINCIPAL_LEN) {
        return;
    }
    memcpy(out->principals[out->count], principal.p, principal.len);
    out->principals[out->count][principal.len] = '\0';
    out->count++;
}

/* YAML's inline list form, "[]" or "[a, b]". The split on commas is naive,
 * which is exactly why unquote rejects a quoted value containing one rather
 * than letting it through cut in half. */
static bool parse_flow(slice value, ssoossh_principals *out, bool collect,
                       char *err, size_t err_cap, size_t line_no)
{
    slice inner;

    if (value.len == 0 || value.p[value.len - 1] != ']') {
        (void)snprintf(err, err_cap, "line %zu: unterminated list", line_no);
        return false;
    }
    inner = trim(slice_of(value.p + 1, value.len - 2));
    if (inner.len == 0) {
        return true;
    }

    for (size_t start = 0; start <= inner.len;) {
        size_t end = start;
        slice field, principal;

        while (end < inner.len && inner.p[end] != ',') {
            end++;
        }
        field = trim(slice_of(inner.p + start, end - start));
        if (!unquote(field, &principal)) {
            (void)snprintf(err, err_cap,
                           "line %zu: quoted value uses escapes or embedded "
                           "quotes, which are not supported",
                           line_no);
            return false;
        }
        if (principal.len == 0) {
            (void)snprintf(err, err_cap, "line %zu: empty principal in list",
                           line_no);
            return false;
        }
        if (collect) {
            store(out, principal);
        }
        if (end >= inner.len) {
            break;
        }
        start = end + 1;
    }
    return true;
}

/* Scans the lines already seen for the same account name. Rescanning rather
 * than keeping a table: the file is hand-authored and a few dozen lines
 * long, and the alternative is a bounded table that a large file silently
 * outgrows -- turning a duplicate into a missed one. */
static bool account_seen(const char *data, size_t upto, slice name)
{
    size_t pos = 0;

    while (pos < upto) {
        size_t len = 0;
        slice line, content, key, value;

        while (pos + len < upto && data[pos + len] != '\n') {
            len++;
        }
        line = slice_of(data + pos, len);
        pos += len + 1;

        content = trim(strip_comment(line));
        if (content.len == 0 || content.p[0] == '-') {
            continue;
        }
        /* Only a line starting at column 0 is an account. */
        if (line.len > 0 && (line.p[0] == ' ' || line.p[0] == '\t')) {
            continue;
        }
        if (split_key(content, &key, &value)) {
            slice unquoted;
            if (unquote(key, &unquoted) && slice_eq_slice(unquoted, name)) {
                return true;
            }
        }
    }
    return false;
}

ssoossh_map_status ssoossh_principals_map_load(const char *path,
                                               const char *account,
                                               ssoossh_principals *out,
                                               char *err, size_t err_cap)
{
    char *data = NULL;
    FILE *f = NULL;
    size_t n, pos = 0, line_no = 0;
    ssoossh_map_status status = SSOOSSH_MAP_OK;
    /* The account whose list is open -- the one a "- principal" line
     * appends to. An inline value closes its account immediately, so a
     * stray item line after one is an error rather than an append to
     * whatever came before. */
    bool open_is_ours = false;
    bool have_open = false;

    memset(out, 0, sizeof(*out));
    if (err_cap > 0) {
        err[0] = '\0';
    }

    f = fopen(path, "re");
    if (f == NULL) {
        (void)snprintf(err, err_cap, "cannot read %s", path);
        return SSOOSSH_MAP_UNREADABLE;
    }
    data = malloc(MAX_MAP_FILE + 1);
    if (data == NULL) {
        (void)fclose(f);
        return SSOOSSH_MAP_UNREADABLE;
    }
    n = fread(data, 1, MAX_MAP_FILE, f);
    if (ferror(f) != 0) {
        (void)fclose(f);
        free(data);
        (void)snprintf(err, err_cap, "cannot read %s", path);
        return SSOOSSH_MAP_UNREADABLE;
    }
    (void)fclose(f);
    if (n >= MAX_MAP_FILE) {
        free(data);
        (void)snprintf(err, err_cap, "%s is larger than %d bytes", path,
                       MAX_MAP_FILE);
        return SSOOSSH_MAP_MALFORMED;
    }
    data[n] = '\0';

    while (pos <= n) {
        size_t len = 0, indent = 0;
        slice raw, content, key, value, name;

        while (pos + len < n && data[pos + len] != '\n') {
            len++;
        }
        raw = slice_of(data + pos, len);
        line_no++;

        content = strip_comment(raw);
        while (indent < content.len &&
               (content.p[indent] == ' ' || content.p[indent] == '\t')) {
            indent++;
        }
        /* Indenting with a tab is rejected rather than silently accepted:
         * YAML forbids it outright, so a file using tabs was never being
         * read the way its author expected. */
        if (memchr(content.p, '\t', indent) != NULL) {
            MAP_FAIL("line %zu: indented with a tab; YAML requires "
                     "spaces",
                     line_no);
        }
        content = trim(content);

        if (content.len == 0) {
            goto next;
        }

        if (content.p[0] == '-') {
            slice item = slice_of(content.p + 1, content.len - 1);
            slice principal;

            /* "-alice" is a plain scalar in YAML, not a list item.
             * Requiring the space keeps this parser from reading one as
             * the other. */
            if (item.len > 0 && item.p[0] != ' ') {
                MAP_FAIL("line %zu: a list item needs a space after "
                         "its \"-\"",
                         line_no);
            }
            if (!unquote(trim(item), &principal)) {
                MAP_FAIL("line %zu: quoted value uses escapes or "
                         "embedded quotes, which are not supported",
                         line_no);
            }
            if (principal.len == 0) {
                MAP_FAIL("line %zu: empty principal", line_no);
            }
            if (!have_open) {
                MAP_FAIL("line %zu: principal is not under any account",
                         line_no);
            }
            if (open_is_ours) {
                store(out, principal);
            }
            goto next;
        }

        /* An account is a key of the file's one top-level mapping, so it
         * starts at column 0. Anything indented is a nested structure this
         * format does not have, and reading it as another account would
         * silently invent a mapping the file never declared. */
        if (indent > 0) {
            MAP_FAIL("line %zu: an account starts at the beginning of "
                     "the line",
                     line_no);
        }
        if (!split_key(content, &key, &value)) {
            MAP_FAIL("line %zu: expected an \"account:\" line or a "
                     "\"- principal\" list item",
                     line_no);
        }
        if (!unquote(key, &name)) {
            MAP_FAIL("line %zu: quoted account name uses escapes or "
                     "embedded quotes, which are not supported",
                     line_no);
        }
        if (name.len == 0) {
            MAP_FAIL("line %zu: empty account name", line_no);
        }
        if (account_seen(data, pos, name)) {
            MAP_FAIL("line %zu: account is already defined", line_no);
        }

        open_is_ours = slice_eq(name, account);
        if (open_is_ours) {
            out->found = true;
        }

        if (value.len == 0) {
            /* The list is on the lines below, or the account has none. */
            have_open = true;
        } else if (slice_eq(value, "null") || slice_eq(value, "~")) {
            have_open = false;
        } else if (value.p[0] == '[') {
            if (!parse_flow(value, out, open_is_ours, err, err_cap, line_no)) {
                status = SSOOSSH_MAP_MALFORMED;
                goto done;
            }
            have_open = false;
        } else {
            MAP_FAIL("line %zu: account must be followed by a list of "
                     "principals",
                     line_no);
        }

    next:
        pos += len + 1;
        if (len == 0 && pos > n) {
            break;
        }
    }

done:
    free(data);
    if (status != SSOOSSH_MAP_OK) {
        memset(out, 0, sizeof(*out));
    }
    return status;
}

bool ssoossh_principals_allow(const ssoossh_principals *p,
                              const char *const *cert_principals,
                              size_t cert_count)
{
    if (!p->found) {
        return false;
    }
    for (size_t i = 0; i < cert_count; i++) {
        for (size_t j = 0; j < p->count; j++) {
            if (strcmp(cert_principals[i], p->principals[j]) == 0) {
                return true;
            }
        }
    }
    return false;
}
