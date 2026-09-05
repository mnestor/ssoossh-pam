# pam_ssoossh -- PAM module authenticating against ssoosshd.
#
# Four targets across three PAM implementations, so the platform branch is
# structural rather than incidental:
#
#   Linux (glibc, musl)  Linux-PAM,  OpenSSL,               ELF version script
#   FreeBSD              OpenPAM,    OpenSSL in base,       ELF version script
#   macOS                OpenPAM,    Security.framework,    ld64 symbol list
#
# macOS ships as a signed installer package (packaging/macos.sh), arm64
# only, that puts the module under /usr/local/lib/pam. Console mode is not
# compiled into it.

UNAME  := $(shell uname -s)
ARCH   := $(shell uname -m)

# Where libpam looks for modules. There is no portable answer -- Debian puts
# it under a multiarch triplet, the RHEL family under lib64, Alpine under
# /usr/lib, FreeBSD under its local prefix, and usr-merge moved several of
# them within living memory -- and installing to the wrong one produces a
# module that loads for nobody, with no error anywhere to say so. So the
# directory is discovered rather than assumed: the first of these that
# actually exists on the machine doing the install. Where two names are the
# same directory through a usr-merge symlink, either answer is right.
#
#   make install SECURITYDIR=/lib/security     to override
#
# Nothing matches on macOS, which is deliberate -- /usr/lib/pam is protected
# by System Integrity Protection, so a pam.d entry there names the module
# by absolute path, and tests/e2e.sh detects the empty answer and uses the
# build directory. The installer package (packaging/macos.sh) is how the
# module reaches a Mac, at /usr/local/lib/pam. See docs/porting.md.
ifeq ($(UNAME),Darwin)
  # Deliberately empty. /usr/lib/pam is protected by System Integrity
  # Protection, so OpenPAM's own directory is off limits; a pam.d entry
  # takes an absolute path instead -- the build directory under
  # tests/e2e.sh, /usr/local/lib/pam once the package is installed.
  #
  # Stated rather than searched for, so that a stray /usr/local/lib/security
  # left by some other package cannot become an install target that nothing
  # ever loads from. `make install SECURITYDIR=/usr/local/lib/pam` is the
  # by-hand equivalent of the package.
  SECURITYDIR ?=
else ifeq ($(UNAME),FreeBSD)
  # FreeBSD is the other exception: OpenPAM has no security/ subdirectory at
  # all. Base modules sit directly in /usr/lib and ports install to
  # /usr/local/lib, which is where a third-party module belongs. Confirm
  # with `ls /usr/lib/pam_unix.so` on the host.
  SECURITYDIR ?= /usr/local/lib
else
  SECURITYDIR ?= $(firstword $(wildcard \
      /lib/$(ARCH)-linux-gnu/security \
      /usr/lib/$(ARCH)-linux-gnu/security \
      /lib64/security \
      /usr/lib64/security \
      /lib/security \
      /usr/lib/security \
      /usr/local/lib/security))
endif

# Version is stamped in at build time rather than tracked in a header, so a
# working tree and a release build report differently on purpose. Logged at
# LOG_INFO on every authentication -- see src/log.c.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# The ssoosshd release this module was last qualified against. The module
# and the server are versioned independently -- a QR fix here needs no
# server release, and vice versa -- so this is the compatibility fact a
# fleet actually needs, and it travels with the version: logged on every
# authentication, printed in the dist manifest, named in the packages.
# Bumping it is the deliberate act of re-running the differential harness
# and the end-to-end scenarios against a newer server.
SSOOSSHD_COMPAT ?= v1.0.0

# An alternate OpenSSL for a host whose distribution has stopped issuing
# updates:  make OPENSSL_PREFIX=/opt/openssl-3.5
# See the plan's "Crypto on an unsupported distribution". Ignored on macOS,
# which does not use OpenSSL at all.
OPENSSL_PREFIX ?=
ifneq ($(OPENSSL_PREFIX),)
  export PKG_CONFIG_PATH := $(OPENSSL_PREFIX)/lib/pkgconfig:$(OPENSSL_PREFIX)/lib64/pkgconfig:$(PKG_CONFIG_PATH)
endif

MODULE  := pam_ssoossh.so
BUILD   := build

# Sanitiser flags have to reach the link line of the shared object and of
# the test binary, which have nothing else in common -- LDFLAGS proper
# carries -shared and the version script, and an executable must inherit
# neither. See the san target.
SANCFLAGS  :=
SANLDFLAGS :=
ifeq ($(SAN),1)
  SANCFLAGS  := -fsanitize=address,undefined -fno-omit-frame-pointer -O1
  SANLDFLAGS := -fsanitize=address,undefined
  CFLAGS     += $(SANCFLAGS)
  LDFLAGS    += $(SANLDFLAGS)
endif

# Exactly one crypto backend is compiled. Both are always present in the
# tree so a change to the seam breaks the build of the platform it was not
# written on -- but only the one this platform can link is fed to the
# compiler.
SRC     := $(filter-out src/crypto_openssl.c src/crypto_darwin.c src/qr.c, \
                        $(wildcard src/*.c))
VENDOR  :=
ifeq ($(UNAME),Darwin)
  SRC    += src/crypto_darwin.c
else
  # Console mode, and so the QR encoder, are Linux and FreeBSD only: a
  # Mac's console login is loginwindow, which never shows a PAM message,
  # so a console flow there is scope with no user.
  SRC    += src/crypto_openssl.c src/qr.c
  VENDOR += third_party/qrcodegen/qrcodegen.c
endif
OBJ     := $(patsubst src/%.c,$(BUILD)/%.o,$(SRC))
ifneq ($(VENDOR),)
  OBJ   += $(BUILD)/qrcodegen.o
endif

CFLAGS  += -std=c11 -O2 -fPIC \
           -fvisibility=hidden \
           -Wall -Wextra -Wconversion -Wshadow -Wpointer-arith \
           -Wstrict-prototypes -Wmissing-prototypes -Werror \
           -fstack-protector-strong \
           -D_FORTIFY_SOURCE=2 \
           -DPAM_SSOOSSH_VERSION='"$(VERSION)"' \
           -DPAM_SSOOSSH_COMPAT='"$(SSOOSSHD_COMPAT)"'
CPPFLAGS += -Isrc

PKGS    := libcrypto libcurl

ifeq ($(UNAME),Darwin)
  # Apple's own crypto: no OpenSSL, no Homebrew, nothing to install.
  MODULE  := pam_ssoossh.bundle
  PKGS    := $(filter-out libcrypto,$(PKGS))
  LDLIBS  += -framework Security -framework CoreFoundation
  # ld64 has neither version scripts nor -z options.
  LDFLAGS += -bundle -Wl,-bind_at_load \
             -Wl,-exported_symbols_list,pam_ssoossh.syms
  MINVER  ?= 15.0
  CFLAGS  += -mmacosx-version-min=$(MINVER)
  LDFLAGS += -mmacosx-version-min=$(MINVER)
  # Apple's strip refuses a bundle outright ("symbols referenced by indirect
  # symbol table entries"); -x drops the local symbols, which is what
  # there is to drop, and leaves the two exports alone.
  STRIP   := strip -x
else
  STRIP   := strip --strip-unneeded
  LDFLAGS += -shared -Wl,--no-undefined \
             -Wl,-z,relro,-z,now -Wl,-z,noexecstack \
             -Wl,--version-script=pam_ssoossh.map
  ifeq ($(UNAME),Linux)
    CFLAGS += -D_GNU_SOURCE -fstack-clash-protection
  endif
endif

# pkg-config where it knows the package, plain -l otherwise. FreeBSD's base
# OpenSSL does not always install a libcrypto.pc, and failing the whole build
# over a missing metadata file would be silly when the library is right there.
ifneq ($(strip $(PKGS)),)
  ifeq ($(shell pkg-config --exists $(PKGS) 2>/dev/null && echo yes),yes)
    CFLAGS += $(shell pkg-config --cflags $(PKGS))
    LDLIBS += $(shell pkg-config --libs $(PKGS))
  else
    LDLIBS += $(patsubst lib%,-l%,$(PKGS))
  endif
endif
LDLIBS += -lpam
ifneq ($(UNAME),Darwin)
  # pthread_once, which guards curl_global_init. On glibc 2.34 and later this
  # is a stub -- libpthread was merged into libc -- but on the RHEL 8 floor's
  # 2.28 it is a real library, and leaving it out is a link error that no
  # modern distribution reproduces. macOS has it in libSystem.
  LDLIBS += -lpthread
endif

ifneq ($(OPENSSL_PREFIX),)
  LDFLAGS += -Wl,-rpath,$(OPENSSL_PREFIX)/lib
endif

.PHONY: all clean check-symbols check-stdio check-size test san install unsanitised \
        help cross lint plan-serve ci-local ci-list fuzz fuzz-run e2e \
        differential

all: $(MODULE)

$(BUILD):
	@mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# Vendored code gets the same standard, the same hardening and the same
# optimisation, but not -Wconversion. jsmn and qrcodegen are pinned by hash
# and unmodified (see third_party/*/README.md); patching a dependency to
# satisfy our warning flags would mean carrying a fork and re-applying it at
# every update. Everything they touch has already been bounded by the caller.
VENDOR_CFLAGS := $(filter-out -Wconversion,$(CFLAGS))

$(BUILD)/qrcodegen.o: third_party/qrcodegen/qrcodegen.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(VENDOR_CFLAGS) -c $< -o $@

$(MODULE): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

# The module must expose exactly the two PAM entry points. Anything else --
# a vendored library's symbols, a helper named parse() -- is a name that can
# collide inside sudo.
check-symbols: $(MODULE)
	@set -e; \
	if [ "$(UNAME)" = "Darwin" ]; then \
	  got=$$(nm -gU $(MODULE) | awk '$$2 ~ /^[TD]$$/ {print $$3}' | sed 's/^_//' | sort); \
	else \
	  got=$$(nm -D --defined-only $(MODULE) | awk '$$2 ~ /^[TDBR]$$/ {print $$3}' | sort); \
	fi; \
	want=$$(printf 'pam_sm_authenticate\npam_sm_setcred\n'); \
	if [ "$$got" != "$$want" ]; then \
	  echo "check-symbols: exported symbols are not the expected two:"; \
	  echo "$$got" | sed 's/^/  /'; \
	  exit 1; \
	fi; \
	echo "check-symbols: ok"

# Needs a real pam.d stack, so it needs root -- see tests/README.md.
# PAMTEST_LIBS is -lpam_misc on Linux-PAM and empty on OpenPAM.
#
# -std=c11 defines __STRICT_ANSI__, which hides the POSIX signal API the
# driver uses to block SIGINT the way sudo does -- sigset_t and
# sigprocmask are undeclared without a feature macro, on glibc and musl
# alike. _POSIX_C_SOURCE rather than the module's _GNU_SOURCE: this file
# is built on FreeBSD and macOS too and wants nothing glibc-specific.
PAMTEST_LIBS ?= $(if $(filter Linux,$(UNAME)),-lpam_misc,)

tests/pamtest: tests/pamtest.c
	$(CC) -std=c11 -O1 -Wall -Wextra -D_POSIX_C_SOURCE=200809L \
	    $(SANCFLAGS) $(SANLDFLAGS) -o $@ $< -lpam $(PAMTEST_LIBS)

# Runs anywhere, including CI: proves the module loads and that exactly the
# right symbols are reachable through the dynamic loader.
#
# Built with the sanitisers when SAN=1, because it dlopens a module that
# was: an ASan-instrumented shared object loaded into an uninstrumented
# program aborts before it runs a single test.
tests/loadtest: tests/loadtest.c
	$(CC) -std=c11 -O1 -Wall -Wextra -Werror $(SANCFLAGS) $(SANLDFLAGS) \
	    -o $@ $< $(if $(filter Darwin,$(UNAME)),,-ldl)

# The unit suite links the module's own objects rather than recompiling
# them, so what the tests exercise is the code that ships -- same flags,
# same warnings, same -fvisibility=hidden. Hidden visibility is no obstacle
# inside a single executable, and building the sources a second way to make
# them testable would mean the tested build and the shipped one could
# differ.
UNIT_SRC := $(wildcard tests/unit/*.c)
UNIT_OBJ := $(patsubst tests/unit/%.c,$(BUILD)/unit/%.o,$(UNIT_SRC))

$(BUILD)/unit:
	@mkdir -p $(BUILD)/unit

$(BUILD)/unit/%.o: tests/unit/%.c | $(BUILD)/unit
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

tests/unit_tests: $(OBJ) $(UNIT_OBJ)
	$(CC) $(SANLDFLAGS) -o $@ $^ $(LDLIBS)

test: check-symbols tests/loadtest tests/unit_tests
	@./tests/loadtest ./$(MODULE)
	@./tests/unit_tests

# Nothing in the module may write to stdout or stderr. It lives inside sudo
# and sshd, where both streams belong to the host process, and the only path
# that ever deliberately broke that rule -- debug=stdout -- is gone, so this
# is an unconditional failure rather than one with an exemption in it.
#
# tests/ is exempt because a test binary printing its results is the point.
check-stdio:
	@if grep -nE '\b(printf|fprintf|puts|putchar|perror|vprintf|vfprintf)\s*\(|\bwrite\s*\(\s*[12]\s*,' \
	     src/*.c src/*.h; then \
	  echo "check-stdio: the module must not write to stdout or stderr"; \
	  exit 1; \
	fi; \
	echo "check-stdio: ok"

# A stripped module over this usually means something got statically linked
# that should not have been. The bundled-crypto variant has its own, much
# larger target and is checked separately, so it cannot mask a regression
# here.
SIZE_LIMIT ?= 524288

check-size: $(MODULE)
	@cp $(MODULE) $(BUILD)/stripped.so && $(STRIP) $(BUILD)/stripped.so; \
	size=$$(wc -c < $(BUILD)/stripped.so); \
	echo "check-size: $$size bytes stripped (limit $(SIZE_LIMIT))"; \
	if [ "$$size" -gt "$(SIZE_LIMIT)" ]; then \
	  echo "check-size: over the limit"; \
	  exit 1; \
	fi

# macOS only: the Ed25519 SPI the Darwin backend resolves at runtime,
# checked in the SDK's export list and through the running framework. Both
# views, because they drift separately -- see tests/apple-spi-check.sh and
# docs/porting.md. Elsewhere it reports that there is nothing to check.
check-apple-spi:
	@if [ "$(UNAME)" = "Darwin" ]; then \
	  $(MAKE) --no-print-directory tests/unit_tests; \
	fi; \
	tests/apple-spi-check.sh

# `make san` leaves an instrumented module behind and removes the test
# binaries. Anything that then dlopens that module from an uninstrumented
# harness fails with "ASan runtime does not come first", which looks like a
# module bug and is not one, and anything that packages it ships a module
# that needs libasan. Targets that must have a plain module depend on this.
unsanitised:
	@if nm $(MODULE) 2>/dev/null | grep -q asan; then \
	  echo "the built module is sanitised; rebuilding it plain"; \
	  $(MAKE) --no-print-directory clean; \
	fi

# The whole flow against tests/stubd.py, through a real PAM stack. Needs
# root to install the module and write /etc/pam.d -- see tests/README.md.
e2e: unsanitised
	@$(MAKE) --no-print-directory $(MODULE) tests/pamtest
	@tests/e2e.sh $(SCENARIOS)

# The same flow, run against the Go module as well, comparing the PAM
# return code scenario by scenario. Needs SSOOSSH_GO_MODULE pointing at a
# built one -- see tests/differential.sh.
differential:
	@$(MAKE) --no-print-directory $(MODULE) tests/pamtest
	@tests/differential.sh

# make SAN=1 turns the sanitisers on for everything built in that
# invocation, the unit suite included -- which is the point of it being a
# switch rather than a target: the parsers are where ASan and UBSan earn
# their keep, and those are only reachable from the tests.
#
# `make san` is that plus the clean rebuild the changed flags require.
san:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory SAN=1 all test

# libFuzzer targets over every parser that touches bytes the module did not
# write. Built with clang -- gcc has no libFuzzer -- and always with the
# sanitisers, because a fuzzer that finds an overread and does not stop is a
# fuzzer that finds nothing.
#
#   make fuzz                 build them all
#   make fuzz-run             a short run of each, which is what CI does
#   make fuzz-run FUZZ_RUNS=1000000 RUNS=... for a long one
#
# The corpus is tests/fixtures: real certificates and real CA files, so a
# run starts from something structurally valid and mutates outward.
FUZZ_SRC  := $(wildcard tests/fuzz/*.c)
FUZZ_BINS := $(patsubst tests/fuzz/%.c,$(BUILD)/fuzz/%,$(FUZZ_SRC))
FUZZ_CC   ?= clang
FUZZ_RUNS ?= 20000

$(BUILD)/fuzz:
	@mkdir -p $(BUILD)/fuzz

# The module's own sources are recompiled here rather than reused: the
# fuzzer needs clang's instrumentation, and $(OBJ) was built by $(CC) with
# neither. Everything else about the flags matches.
$(BUILD)/fuzz/%: tests/fuzz/%.c $(SRC) | $(BUILD)/fuzz
	$(FUZZ_CC) $(CPPFLAGS) -std=c11 -g -O1 \
	    -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer \
	    -D_GNU_SOURCE -DPAM_SSOOSSH_VERSION='"$(VERSION)"' \
	    -DPAM_SSOOSSH_COMPAT='"$(SSOOSSHD_COMPAT)"' \
	    -o $@ $< $(SRC) $(if $(VENDOR),$(VENDOR),) $(LDLIBS)

fuzz: $(FUZZ_BINS)
	@echo "fuzz: built $(words $(FUZZ_BINS)) target(s) in $(BUILD)/fuzz"

# The corpus directory order matters: libFuzzer *writes* new
# coverage-increasing inputs into the first one it is given and only reads
# the rest. So the writable corpus is under build/ and tests/fixtures is a
# read-only seed -- otherwise a run leaves several thousand hash-named files
# in the fixtures directory, which is how that was learned.
FUZZ_CORPUS := $(BUILD)/fuzz/corpus

fuzz-run: $(FUZZ_BINS)
	@set -e; \
	mkdir -p $(FUZZ_CORPUS); \
	for f in $(FUZZ_BINS); do \
	  echo "=== $$(basename $$f) ==="; \
	  mkdir -p $(FUZZ_CORPUS)/$$(basename $$f); \
	  $$f -runs=$(FUZZ_RUNS) -max_total_time=60 -print_final_stats=0 \
	      $(FUZZ_CORPUS)/$$(basename $$f) tests/fixtures 2>&1 | tail -3; \
	done; \
	echo "fuzz-run: ok"

# Build and gate on every Linux image CI uses, through the host's Docker
# daemon. `make cross IMAGES=el8` for one.
cross:
	@tests/cross-build.sh $(IMAGES)

# Every tool here is in the devcontainer. Outside it, a missing one is
# reported and skipped rather than failing the target: a partial lint is more
# use than an error about a tool the caller may not want to install.
lint:
	@rc=0; \
	for t in actionlint shellcheck clang-format cppcheck groff; do \
	  command -v $$t >/dev/null || { echo "lint: $$t not installed, skipping"; continue; }; \
	  case $$t in \
	    actionlint)    actionlint || rc=1 ;; \
	    groff)         groff -man -Tutf8 -z -ww docs/*.[58] || rc=1 ;; \
	    shellcheck)    shellcheck -x tests/*.sh packaging/*.sh || rc=1 ;; \
	    clang-format)  clang-format --dry-run --Werror src/*.c src/*.h tests/*.c || rc=1 ;; \
	    cppcheck)      cppcheck --quiet --error-exitcode=1 \
	                     --enable=warning,portability \
	                     --suppress=missingIncludeSystem -Isrc src tests || rc=1 ;; \
	  esac; \
	done; \
	[ $$rc -eq 0 ] && echo "lint: ok"; exit $$rc

# compile_commands.json for clangd. Regenerate after adding a source file.
compile_commands.json:
	bear -- $(MAKE) --always-make all

# Run the CI workflow locally with nektos/act, before pushing. Every job in
# ci.yml runs in its own container, so what act reproduces is close to what
# GitHub will do -- close enough that a workflow bug shows up here first.
#
#   make ci-local            the whole push event
#   make ci-local JOB=linux  one job
#
# The credential dance below is not incidental. act reads the docker client
# config for registry auth before it starts a job, and VS Code's dev
# containers extension writes a `credsStore` into it naming a helper that
# shells out to that extension's own server process. In any session that is
# not the extension's -- an SSH login, a docker exec, this container after
# the window is closed -- the helper exits 255. The docker CLI treats that as
# "no credentials" and carries on; act treats it as fatal and fails every job
# at "Set up job", before a single step runs.
#
# Every image ci.yml uses is public, so when the configured helper does not
# answer, act is pointed at a config with no helper at all. A credential
# store that does answer is left alone, so this stays correct on a normal
# machine and for a private image.
ACT_DOCKER_CONFIG := $(BUILD)/act-docker

ci-local:
	@helper=$$(sed -n 's/.*"credsStore"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
	    "$${DOCKER_CONFIG:-$$HOME/.docker}/config.json" 2>/dev/null); \
	if [ -n "$$helper" ] && \
	   ! echo '{}' | "docker-credential-$$helper" list >/dev/null 2>&1; then \
	  echo "ci-local: credential helper '$$helper' is not answering;" \
	       "running act with an empty docker config"; \
	  mkdir -p $(ACT_DOCKER_CONFIG); \
	  printf '{}\n' > $(ACT_DOCKER_CONFIG)/config.json; \
	  export DOCKER_CONFIG="$(CURDIR)/$(ACT_DOCKER_CONFIG)"; \
	fi; \
	act push $(if $(JOB),-j $(JOB),) $(ACT_ARGS)

ci-list:
	@act -l

# Serves the visual plan over a localhost bridge on a fixed port, so an SSH
# tunnel from another machine has a stable target.
plan-serve:
	npx -y @agent-native/core@latest plan local serve \
	    --dir plans/pam-ssoossh-c --kind plan --port 8787

# A release artifact: the stripped module, the man pages, the example
# pam.d stanzas, the licence, and a BUILDINFO naming what it was built with and which sonames it needs --
# which is the question an operator has, since the module links the host's
# libraries rather than shipping them. tests/dist-target.sh names the
# platform; the release workflow passes DIST_TARGET explicitly and asserts
# the two agree.
#
#   make dist                                    dist/pam_ssoossh-<version>-<target>.tar.gz
#   make dist DIST_TARGET=linux-x86_64-musl      name it for the workflow's matrix entry
#
# On macOS, stripping invalidates the ad-hoc signature the linker wrote,
# and an arm64 Mac loads no code without one, so it is re-signed ad hoc
# here; packaging/macos.sh replaces that with the Developer ID signature.
DIST        := dist
DIST_TARGET ?= $(shell tests/dist-target.sh)
DIST_NAME   := pam_ssoossh-$(VERSION)-$(DIST_TARGET)

dist: unsanitised
	@$(MAKE) --no-print-directory $(MODULE)
	@set -e; \
	stage=$(BUILD)/$(DIST_NAME); \
	rm -rf "$$stage"; mkdir -p "$$stage" $(DIST); \
	cp $(MODULE) "$$stage/pam_ssoossh.so"; \
	$(STRIP) "$$stage/pam_ssoossh.so" 2>/dev/null || strip "$$stage/pam_ssoossh.so"; \
	if [ "$(UNAME)" = "Darwin" ]; then codesign -s - -f "$$stage/pam_ssoossh.so" 2>/dev/null; fi; \
	cp LICENSE "$$stage/"; \
	mkdir -p "$$stage/man" "$$stage/examples"; \
	cp docs/*.8 docs/*.5 "$$stage/man/"; \
	cp -R docs/examples/. "$$stage/examples/"; \
	{ \
	  echo "package:   $(DIST_NAME)"; \
	  echo "version:   $(VERSION)"; \
	  echo "ssoosshd:  $(SSOOSSHD_COMPAT)"; \
	  echo "target:    $(DIST_TARGET)"; \
	  echo "built:     $$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
	  echo "host:      $$(uname -srm)"; \
	  echo "compiler:  $$($(CC) --version 2>/dev/null | head -1)"; \
	  echo "libcrypto: $$(pkg-config --modversion libcrypto 2>/dev/null || echo 'Security.framework')"; \
	  echo "libcurl:   $$(pkg-config --modversion libcurl 2>/dev/null || echo '?')"; \
	  echo "needs:"; \
	  if command -v readelf >/dev/null; then \
	    readelf -d "$$stage/pam_ssoossh.so" | awk '/NEEDED/ {gsub(/[][]/, "", $$5); print "  " $$5}'; \
	  elif command -v otool >/dev/null; then \
	    otool -L "$$stage/pam_ssoossh.so" | awk 'NR > 1 {print "  " $$1}'; \
	  fi; \
	} > "$$stage/BUILDINFO"; \
	tar -C $(BUILD) -czf $(DIST)/$(DIST_NAME).tar.gz $(DIST_NAME); \
	rm -rf "$$stage"; \
	echo "dist: $(DIST)/$(DIST_NAME).tar.gz"; \
	tar -tzf $(DIST)/$(DIST_NAME).tar.gz | sed 's/^/  /'

# deb, rpm and apk from that tarball, through nfpm and packaging/package.sh,
# which decides the formats and dependencies from the target name. Needs
# nfpm: https://github.com/goreleaser/nfpm/releases, or NFPM=/path/to/it.
# On macOS the same entry point builds the installer package instead,
# with Apple's own tools -- see packaging/macos.sh for the signing
# variables it reads.
NFPM ?= nfpm

packages: dist
	@NFPM=$(NFPM) packaging/package.sh $(DIST)/$(DIST_NAME).tar.gz $(DIST)

MANDIR ?= /usr/local/share/man
DOCDIR ?= /usr/local/share/doc/pam_ssoossh

install: $(MODULE)
	@test -n "$(SECURITYDIR)" || { \
	  echo "install: no PAM module directory found on this system;" \
	       "pass SECURITYDIR=<dir>" >&2; exit 1; }
	install -d $(DESTDIR)$(SECURITYDIR)
	install -m 0644 $(MODULE) $(DESTDIR)$(SECURITYDIR)/$(MODULE)
	install -d $(DESTDIR)$(MANDIR)/man8 $(DESTDIR)$(MANDIR)/man5
	install -m 0644 docs/*.8 $(DESTDIR)$(MANDIR)/man8/
	install -m 0644 docs/*.5 $(DESTDIR)$(MANDIR)/man5/
	install -d $(DESTDIR)$(DOCDIR)/examples/pam.d
	install -m 0644 docs/examples/pam.d/* $(DESTDIR)$(DOCDIR)/examples/pam.d/
	install -m 0644 $(filter-out docs/examples/pam.d,$(wildcard docs/examples/*)) $(DESTDIR)$(DOCDIR)/examples/
	@echo "installed $(DESTDIR)$(SECURITYDIR)/$(MODULE)"
	@echo "installed man pages under $(DESTDIR)$(MANDIR)"
	@echo "installed examples under $(DESTDIR)$(DOCDIR)/examples"

clean:
	rm -rf $(BUILD) pam_ssoossh.so pam_ssoossh.bundle tests/pamtest \
	       tests/loadtest tests/unit_tests

# Machine-readable answers for the test harnesses, which have to know what
# this platform calls the module and where it goes:
#
#   make print-MODULE        pam_ssoossh.so, or .bundle on macOS
#   make print-SECURITYDIR   empty where there is nowhere to install
print-%:
	@echo "$($*)"

help:
	@echo "make            build $(MODULE) for $(UNAME)"
	@echo "make test       symbol gate, load gate, and the unit suite"
	@echo "make san        rebuild with ASan and UBSan"
	@echo "make tests/pamtest"
	@echo "                build the manual PAM harness (needs libpam-misc on Linux)"
	@echo "make e2e        the whole flow against a stub server (needs root)"
	@echo "make fuzz-run   libFuzzer over every parser that reads network bytes"
	@echo "make cross      build and gate on every Linux image CI uses"
	@echo "make lint       actionlint, shellcheck, clang-format, cppcheck, groff"
	@echo "make ci-local   run the CI workflow locally with nektos/act"
	@echo "make differential"
	@echo "                the same scenarios against the Go module too"
	@echo "make check-stdio"
	@echo "                assert the module writes to neither stdout nor stderr"
	@echo "make check-size assert the stripped module is under $(SIZE_LIMIT) bytes"
	@echo "make check-apple-spi"
	@echo "                macOS: assert Apple still exports the Ed25519 SPI, and it works"
	@echo "make dist       package a release artifact under dist/ (see tests/dist-target.sh)"
	@echo "make packages   deb, rpm and apk from that artifact with nfpm; a .pkg on macOS (see packaging/)"
	@echo "make install    install into $(if $(SECURITYDIR),$(SECURITYDIR),<no PAM module dir found>)"
	@echo ""
	@echo "VERSION=$(VERSION)"
	@echo "SSOOSSHD_COMPAT=$(SSOOSSHD_COMPAT)  the ssoosshd release this build was qualified against"
	@echo "OPENSSL_PREFIX= build against a self-maintained OpenSSL"
