/* Every suite the runner knows about. Declared here rather than in main.c
 * so -Wmissing-prototypes stays on for the test build too: a suite whose
 * definition drifts from its declaration should fail the compile, not be
 * silently skipped.
 *
 * The list grows a phase at a time. A suite appears here when the code it
 * covers does, never before -- an empty placeholder that always passes is
 * indistinguishable from a suite nobody wrote. */
#ifndef SSOOSSH_TEST_SUITES_H
#define SSOOSSH_TEST_SUITES_H

int suite_duration(void);
int suite_args(void);
int suite_sanitize(void);
int suite_sshwire(void);
int suite_der(void);
int suite_crypto(void);
int suite_sshkey(void);
int suite_sshcert(void);
int suite_ed25519(void);
int suite_json(void);
int suite_sse(void);
int suite_principals_map(void);
int suite_checks(void);
int suite_localaddrs(void);
int suite_console(void);
int suite_hostinfo(void);
#ifndef __APPLE__
int suite_qr(void);
#endif

#endif /* SSOOSSH_TEST_SUITES_H */
