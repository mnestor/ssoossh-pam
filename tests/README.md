# Testing

Five harnesses, split by what they need and what they can reach.

| | Needs | Reaches |
| --- | --- | --- |
| `make test` | nothing | the symbol set, the loader, and 16 unit suites |
| `make san` | nothing | the same, under ASan and UBSan |
| `make fuzz-run` | clang | every parser that reads bytes the module did not write |
| `sudo make e2e` | root, python3, ssh-keygen | the whole flow, through a real PAM stack |
| `sudo make differential` | the above, plus a built Go module | both modules, side by side |
| `tests/pamtest` | root | one attempt, by hand, against whatever you point it at |
| `make check-apple-spi` | macOS | the Ed25519 SPI, in the SDK and through the running framework |

## `make test` — runs anywhere, no privileges

```console
$ make test
check-symbols: ok
loadtest: ok (./pam_ssoossh.so)
duration         ok
args             ok
...
unit: ok (16 suites)
```

`make check-symbols` reads the symbol table statically and asserts that
exactly `pam_sm_authenticate` and `pam_sm_setcred` are exported.
`tests/loadtest.c` asserts the same thing through the dynamic loader, which
additionally catches a missing `DT_NEEDED`, a failed constructor, and a
symbol that is in the table but unresolvable in practice. It also names
internals that must *not* resolve, so a regression in `-fvisibility=hidden`
or the version script fails the build rather than quietly widening what
`sudo` can see.

`tests/unit/` links the module's own objects rather than recompiling them, so
what the suites exercise is the code that ships — same flags, same warnings.
`./tests/unit_tests <suite>` runs one.

The acceptance criteria are the Go module's own test tables. `args`,
`principals-map` and `checks` are ported case for case from `args_test.go`,
`principalsmap_test.go` and `checks_test.go`; where a case looks arbitrary,
it is usually because the Go table had exactly that case and parity is the
bar.

### Fixtures

`tests/fixtures/` holds real keys and certificates minted by `ssh-keygen`: a
CA per key type in the capability matrix, certificates signed by each, one
signed by an untrusted CA, one for a different subject key, an expired one, a
not-yet-valid one, and an `ssh-rsa` (SHA-1) one that exists only so the
refusal can be proven.

They are checked in rather than generated at test time, because a suite that
quietly skips when `openssh-client` is absent is worse than no suite.
`tests/make-fixtures.sh` regenerates them; commit what it writes. No private
key is committed — the CAs' private halves are deleted by that script.

One test does shell out to `ssh-keygen` at run time: the interop case that
hands it a key this module marshalled and reads back what it made of it. It
prints a visible `SKIP` when `ssh-keygen` is absent, and CI installs
`openssh-client` so it never does there.

## `make san` — the same suites, instrumented

```console
$ make san
```

A clean rebuild with `-fsanitize=address,undefined` and then the whole gate.
`SAN=1` is the switch; `make san` is that plus the rebuild the changed flags
require. The test harnesses are built with the sanitisers too — an
ASan-instrumented shared object `dlopen`ed by an uninstrumented program
aborts before it runs anything.

## `make fuzz-run` — the parsers, over hostile bytes

```console
$ make fuzz-run                          # a short run of each
$ make fuzz-run FUZZ_RUNS=5000000        # a long one
$ build/fuzz/fuzz_sshcert tests/fixtures # one target, interactively
```

Five libFuzzer targets, built with clang and always with the sanitisers: a
fuzzer that finds an overread and does not stop is a fuzzer that finds
nothing. They cover the certificate parser, the event-stream parser, the JSON
reader, the principals-map parser, and the `authorized_keys` line parser with
its base64.

The corpus is `tests/fixtures`, so a run starts from something structurally
valid and mutates outward, which is where the interesting inputs are.

`fuzz_sshcert` does more than "does not crash": on every input the parser
accepts, it asserts that the signed extent and every borrowed slice lie
inside the blob. A parser that returned success with an offset past the end
would hand the verifier a length it would then read, and ASan would not
notice until it did.

## `sudo make e2e` — the whole flow, through real PAM

```console
$ make && make tests/pamtest      # build as yourself
$ sudo make e2e                   # then run as root
  approved           ok
  denied             ok
  ...
e2e: all scenarios passed
```

Building first is not required — `make e2e` builds what it needs — but doing
it as yourself means `sudo` finds everything up to date and leaves no
root-owned object files in the tree.

`tests/stubd.py` is a stub `ssoosshd` that speaks the two endpoints the
module uses and **mints real certificates with `ssh-keygen`** against a CA
generated for the run. Real, because that is the point: a stub returning a
canned string would test the HTTP client and nothing below it.

`tests/e2e.sh` installs the module, writes a dedicated `pam.d` service, and
drives it once per scenario, checking both halves of the answer — the PAM
return code the stack saw, and the decision line the module wrote to syslog.
Under `sufficient` with `pam_permit` behind it the stack says Success for
both an approval and a refusal, which is the documented posture, so the
syslog line is what distinguishes them.

`sudo tests/e2e.sh approved denied` runs a subset. The scenarios:

| | |
| --- | --- |
| `approved` | the happy path, against a certificate signed a moment earlier |
| `denied`, `expired`, `failed` | each terminal status, by name |
| `enrolled` | a terminal status that carries no certificate a login can use |
| `unknown` | an event name nobody listed — informational, so this ends at the timeout, matching the Go client |
| `envelope-error` | a terminal event whose envelope carries an error |
| `no-cert` | approved, with no certificate delivered |
| `drop` | the stream establishes, drops, and the module reconnects and gets the answer |
| `error-500` | a retryable refusal, then the outcome |
| `error-404` | a definitive refusal, not retried |
| `bad-json`, `create-500` | a create response that is not JSON, and one that is an error |
| `escape` | an approval URL carrying terminal escape sequences |
| `wrong-key` | check 2: correctly signed, right principals, wrong keypair |
| `untrusted` | check 1 |
| `expired-cert` | check 4 |
| `wrong-principal`, `principals-map` | check 3, both ways |
| `slow` | the module's own timeout ends the wait |
| `console` | the console flow, code and QR |
| `cancel-requisite`, `cancel-bracketed` | Ctrl-C falls through to the next module |

The two `cancel` scenarios are the ones worth explaining. Ctrl-C makes the
module return `PAM_IGNORE` — "this module contributes nothing" — so libpam
moves on. The Go module returns `PAM_AUTH_ERR` there, which tears the whole
attempt down, and this is the one sanctioned divergence between them.
Proving it needs a control flag that tells the two codes apart: under
`sufficient` both continue, so that stanza cannot distinguish them. Under
`requisite` and under the bracketed form, `PAM_AUTH_ERR` is immediately final
and `PAM_IGNORE` is not, and both are run — because the documentation offers
them, and a dispatcher that treats `PAM_IGNORE` as a failure under one of
them is a documentation bug worth finding before it is published.

## `sudo make differential` — the two modules, side by side

Two implementations of one protocol diverge in the cases nobody tests. This
is the countermeasure: the Go module and this one, loaded alone under
`required` so what comes back is the module's own answer, against the same
stub server, on the same seventeen scenarios, comparing the PAM return code
exactly.

```console
$ cd ~/git/ssoossh
$ CGO_ENABLED=1 go build -tags=pam -buildmode=c-shared \
      -o /tmp/pam_ssoossh_go.so ./pam_ssoossh/
$ cd ~/git/ssoossh-pam-c
$ SSOOSSH_GO_MODULE=/tmp/pam_ssoossh_go.so sudo -E make differential
differential: C module 97192 bytes, Go module 11157376 bytes
  approved           same: Success
  ...
differential: no unexplained divergence
```

It earned its keep on the first run. Four scenarios disagreed — a 404 from
the events endpoint, a 500 from the create call, a create response that was
not JSON, and a terminal event carrying an envelope error — and in every
one the C module said `PAM_AUTH_ERR` where the Go module says
`PAM_AUTHINFO_UNAVAIL`. The Go module was right: `PAM_AUTH_ERR` is for a
request that resolved and the answer was no, while `PAM_AUTHINFO_UNAVAIL`
is for "this module could not find out", and the difference is what lets
the stack fall through to `pam_unix` rather than turning an ssoossh outage
into a sudo outage.

Only the return code is compared. The two modules word their log messages
differently on purpose — this one names the algorithm in a signature
refusal, for instance — so a diff of prose would be noise hiding signal.
The syslog lines are printed side by side when a scenario diverges.

Two divergences are expected and the harness says so rather than failing:
Ctrl-C returns `PAM_IGNORE` here and `PAM_AUTH_ERR` there, and an `ssh-rsa`
(SHA-1) certificate is refused here and accepted there. The second is not
reachable through the stub, which signs with ECDSA, so the unit suite
asserts it instead.

## `tests/pamtest` — one attempt, by hand

```console
$ make tests/pamtest
$ sudo make install
$ ./tests/pamtest ssoossh-test
$ tail -f /var/log/auth.log      # or: journalctl -t sudo -f
```

`tests/pamtest.c` drives `pam_start` / `pam_authenticate` / `pam_acct_mgmt`
against a named service, using the platform's tty conversation function so
`PAM_TEXT_INFO` messages — the approval URL, the console code and QR — print
to the terminal. On Linux that links `-lpam_misc` for `misc_conv`; on FreeBSD
and macOS it uses `openpam_ttyconv`, which is in libpam itself.

`make install` finds the module directory rather than being told it: Debian
puts PAM modules under a multiarch triplet, the RHEL family under `lib64`,
Alpine under `/usr/lib/security`, and FreeBSD under its local prefix. It
prints where the module landed, and `make install SECURITYDIR=<dir>`
overrides the search.

On macOS, do not install into `/usr/lib/pam/` — it is protected by System
Integrity Protection. A `pam.d` entry accepts an absolute path, so point it
straight at the build directory instead:

```
auth  sufficient  /Users/you/ssoossh-pam-c/pam_ssoossh.bundle  server=...
```

### A dedicated test service

A separate service name, so iterating never touches the real `sudo` or
`login` stack:

```
# /etc/pam.d/ssoossh-test
auth    sufficient  pam_ssoossh.so server=https://ssoossh.example.com \
                    trusted-ca-file=/etc/ssoossh/ca.pub \
                    principals-map=/etc/ssoossh/principals.yaml \
                    skew-tolerance=2s timeout=60s debug
auth    required    pam_unix.so
account required    pam_unix.so
```

### Before touching a real service

Only once this is solid against `ssoossh-test` should the same stanza go near
`/etc/pam.d/sudo` or `/etc/pam.d/login`. **Keep a second root shell open while
editing either.** A `login` stack that refuses everyone is not recoverable
over SSH if SSH is also using it.

## Cross-platform matrix

The Linux jobs can be reproduced locally with the same images CI uses:

```console
$ make cross
$ make cross IMAGES=el8
```

`almalinux:8` is the version floor — gcc 8.5, OpenSSL 1.1.1k, curl 7.61.1. It
is the only image that compiles the OpenSSL 1.1.1 and `curl_multi_wait`
paths, so it is the one worth running before claiming a change is portable.

Red Hat's own `ubi8` cannot be used: `pam-devel` is not in the unentitled UBI
repositories, so the module cannot be built there at all.

## Validating the workflows

`make cross` proves the module builds; it says nothing about whether
`.github/workflows/ci.yml` is correct.
[nektos/act](https://github.com/nektos/act) runs the workflow itself against
the host's Docker daemon:

```console
$ make ci-list                  # what act sees
$ make ci-local                 # the whole push event
$ make ci-local JOB=linux       # one job
$ act push -j linux --matrix name:el8   # one matrix entry
```

If a run fails at `Set up job` with `error getting credentials - err: exit
status 255`, that is not the workflow. VS Code's dev containers extension
writes a `credsStore` into `~/.docker/config.json` naming a helper that shells
out to the extension's own server process, and in a session that is not the
extension's — an SSH login, a `docker exec`, this container after the window
is closed — the helper exits 255. `docker` shrugs that off; act does not.
`make ci-local` detects a helper that will not answer and runs act with an
empty docker config instead, so this only bites a bare `act` invocation.

Because every job in `ci.yml` runs inside its own `container:`, what act
executes is close to what GitHub will — the runner image is only a host for
the job container. That makes a local run worth trusting for everything except
runner-specific behaviour (secrets, OIDC, the hosted tool cache).

The release workflow's Linux rows run under act too, one matrix entry at a
time, and every project step passes; only the final `upload-artifact` fails,
with exit 127, because act cannot put a Node runtime into a job container
the way GitHub's runners do ([nektos/act#107](https://github.com/nektos/act/issues/107)).
That is act's limit, not the workflow's:

```console
$ act push -W .github/workflows/release.yml -j linux \
      --matrix target:linux-x86_64-musl --artifact-server-path build/act-artifacts
```

FreeBSD and macOS are in `.github/workflows/cross-platform.yml` behind
`workflow_dispatch`, and act cannot run either: there is no macOS runner to
emulate, and the FreeBSD VM action needs nested virtualisation. They are
deliberately not on the push path until the port is finished on Linux.

Neither platform has ever been compiled. [`docs/porting.md`](../docs/porting.md)
is the same sequence written out for a human with a machine: what to
install, what to run in what order, and what is most likely to break first.
