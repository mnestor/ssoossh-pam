# qrcodegen

[nayuki/QR-Code-generator](https://github.com/nayuki/QR-Code-generator), the
C implementation, pinned at **v1.8.0**, MIT, unmodified.

```
sha256  300eff07ee25baaa7578f20284411638154716379437391e7e689c0e6ce81403  qrcodegen.c
sha256  e82df4bff37d18b5863b9e7486fe6bda1b6cda8c3b9ecebfec473907265cb589  qrcodegen.h
```

`LICENSE` is the MIT text from the top of `qrcodegen.h`; upstream carries no
separate licence file at this tag.

Vendored rather than linked, like jsmn, and for the same rule: every
*link-time* dependency is a library the operating system already ships. It
allocates nothing — the caller supplies both buffers — so there is no heap
state for a QR render to get wrong inside `sudo`.

Console mode draws the *complete verification URL* the server returns
(`/c/<code>`), which is short on purpose: version 3 at error-correction
level L encodes it in 29×29 modules, and drawn two rows per terminal row
with half-block characters and a two-module quiet zone that is 33 columns by
17 rows — inside an 80×24 console with the surrounding text.

The QR is rendered here rather than fetched as ANSI art from the server.
That is the whole reason this dependency exists: the alternative is writing
server-supplied bytes to a terminal owned by a root process, which is the
one thing `src/conv.c` is built to prevent.

Compiled on Linux and FreeBSD only. macOS ships no artifact and console mode
is not compiled into it, so the Makefile leaves this out of that build
entirely.

## Updating

Replace both files, update the hashes above, and run `make test`. The known-
answer test in `tests/unit/qr_test.c` is what will notice a behavioural
change.
