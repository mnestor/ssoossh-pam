# jsmn

[zserge/jsmn](https://github.com/zserge/jsmn), pinned at **v1.1.0**, MIT,
unmodified.

```
sha256  1ed6154dedf009212a08a397e9c4ed50a0ce31d5a8301bb294e137ae3188c13b  jsmn.h
```

Vendored rather than linked, and that distinction is the rule this project
holds to everywhere: every *link-time* dependency is a library the operating
system already ships. jsmn is a few hundred lines compiled into the module,
auditable in an afternoon, and adds nothing to `ldd` output — and nothing to
the exported symbol table either, because `-fvisibility=hidden` and the
version script keep `jsmn_parse` out of `sudo`'s namespace. `tests/loadtest`
asserts that.

It is a tokenizer, not a parser: it allocates nothing, builds no object
graph, and hands back offsets into the caller's own buffer. There is no heap
structure here for a malformed response to corrupt. `src/json.c` walks those
tokens for the three shapes this module reads, and caps the response at
64 KiB before any of it runs.

## Updating

Replace `jsmn.h`, update the version and hash above, and run `make test`.
Nothing in `src/` includes it except `src/json.c`.
