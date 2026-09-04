/* Reading tests/fixtures, which hold real keys and certificates minted by
 * ssh-keygen.
 *
 * They are checked in rather than generated at test time, so the suite runs
 * on a CI image with no openssh-client. tests/make-fixtures.sh regenerates
 * them when a new shape needs covering. */
#ifndef SSOOSSH_TEST_FIXTURE_H
#define SSOOSSH_TEST_FIXTURE_H

#include <stddef.h>

/* Reads a fixture into buf and returns its length, or 0 (having reported a
 * failure) if it could not be read. The directory is tests/fixtures
 * relative to the working directory, overridable with SSOOSSH_FIXTURES for
 * a runner that starts somewhere else. */
size_t fixture_read(const char *name, char *buf, size_t cap);

/* The same, with the trailing newline trimmed -- which is what a caller
 * parsing one authorized_keys line wants. */
size_t fixture_read_line(const char *name, char *buf, size_t cap);

#endif /* SSOOSSH_TEST_FIXTURE_H */
