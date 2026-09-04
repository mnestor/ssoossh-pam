/* libcurl, wrapped in the two shapes this module needs: a JSON POST that
 * creates a certificate request, and a streaming GET that stays open until
 * a human acts on it.
 *
 * libcurl rather than an OpenSSL BIO and hand-rolled HTTP, because the
 * events endpoint is a long-lived stream and the create call needs
 * proxy-from-environment, HTTP/2 and TLS 1.3 -- all of which the Go client
 * got from net/http. Hand-rolling that would be roughly 800 lines of
 * chunked-encoding, redirect and proxy handling inside a root-privileged
 * process, to save nothing: the shared library is on the box either way.
 */
#ifndef PAM_SSOOSSH_HTTPC_H
#define PAM_SSOOSSH_HTTPC_H

/* Names the libcurl actually linked into this process, for the version
 * line. Same reason as the crypto half: which libcurl is resident in sudo
 * is a property of the host, not of our release. */
const char *ssoossh_httpc_version(void);

#endif /* PAM_SSOOSSH_HTTPC_H */
