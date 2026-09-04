# pam_ssoossh -- PAM module authenticating against ssoosshd.
#
# Four targets across three PAM implementations, so the platform branch is
# structural rather than incidental:
#
#   Linux (glibc, musl)  Linux-PAM,  OpenSSL,               ELF version script
#   FreeBSD              OpenPAM,    OpenSSL in base,       ELF version script
#   macOS                OpenPAM,    Security.framework,    ld64 symbol list
#
# macOS is a developer and CI target only; it never ships an artifact, and
# console mode is not compiled into it.

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
# by System Integrity Protection and a pam.d entry there takes an absolute
# path to the build directory instead. See tests/README.md.
SECURITYDIR ?= $(firstword $(wildcard \
    /lib/$(ARCH)-linux-gnu/security \
    /usr/lib/$(ARCH)-linux-gnu/security \
    /lib64/security \
    /usr/lib64/security \
    /lib/security \
    /usr/lib/security \
    /usr/local/lib/security))

# Version is stamped in at build time rather than tracked in a header, so a
# working tree and a release build report differently on purpose. Logged at
# LOG_INFO on every authentication -- see src/log.c.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

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
SRC     := $(filter-out src/crypto_openssl.c src/crypto_darwin.c, \
                        $(wildcard src/*.c))
ifeq ($(UNAME),Darwin)
  SRC   += src/crypto_darwin.c
else
  SRC   += src/crypto_openssl.c
endif
OBJ     := $(patsubst src/%.c,$(BUILD)/%.o,$(SRC))

CFLAGS  += -std=c11 -O2 -fPIC \
           -fvisibility=hidden \
           -Wall -Wextra -Wconversion -Wshadow -Wpointer-arith \
           -Wstrict-prototypes -Wmissing-prototypes -Werror \
           -fstack-protector-strong \
           -D_FORTIFY_SOURCE=2 \
           -DPAM_SSOOSSH_VERSION='"$(VERSION)"'
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
else
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

ifneq ($(OPENSSL_PREFIX),)
  LDFLAGS += -Wl,-rpath,$(OPENSSL_PREFIX)/lib
endif

.PHONY: all clean check-symbols test san install help cross lint plan-serve \
        ci-local ci-list

all: $(MODULE)

$(BUILD):
	@mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

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
PAMTEST_LIBS ?= $(if $(filter Linux,$(UNAME)),-lpam_misc,)

tests/pamtest: tests/pamtest.c
	$(CC) -std=c11 -O1 -Wall -Wextra $(SANCFLAGS) $(SANLDFLAGS) \
	    -o $@ $< -lpam $(PAMTEST_LIBS)

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

# make SAN=1 turns the sanitisers on for everything built in that
# invocation, the unit suite included -- which is the point of it being a
# switch rather than a target: the parsers are where ASan and UBSan earn
# their keep, and those are only reachable from the tests.
#
# `make san` is that plus the clean rebuild the changed flags require.
san:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory SAN=1 all test

# Build and gate on every Linux image CI uses, through the host's Docker
# daemon. `make cross IMAGES=el8` for one.
cross:
	@tests/cross-build.sh $(IMAGES)

# Every tool here is in the devcontainer. Outside it, a missing one is
# reported and skipped rather than failing the target: a partial lint is more
# use than an error about a tool the caller may not want to install.
lint:
	@rc=0; \
	for t in actionlint shellcheck clang-format cppcheck; do \
	  command -v $$t >/dev/null || { echo "lint: $$t not installed, skipping"; continue; }; \
	  case $$t in \
	    actionlint)    actionlint || rc=1 ;; \
	    shellcheck)    shellcheck tests/*.sh || rc=1 ;; \
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

install: $(MODULE)
	@test -n "$(SECURITYDIR)" || { \
	  echo "install: no PAM module directory found on this system;" \
	       "pass SECURITYDIR=<dir>" >&2; exit 1; }
	install -d $(DESTDIR)$(SECURITYDIR)
	install -m 0644 $(MODULE) $(DESTDIR)$(SECURITYDIR)/pam_ssoossh.so
	@echo "installed $(DESTDIR)$(SECURITYDIR)/pam_ssoossh.so"

clean:
	rm -rf $(BUILD) pam_ssoossh.so pam_ssoossh.bundle tests/pamtest \
	       tests/loadtest tests/unit_tests

help:
	@echo "make            build $(MODULE) for $(UNAME)"
	@echo "make test       build and check the exported symbol set"
	@echo "make san        rebuild with ASan and UBSan"
	@echo "make tests/pamtest"
	@echo "                build the manual PAM harness (needs libpam-misc on Linux)"
	@echo "make install    install into $(if $(SECURITYDIR),$(SECURITYDIR),<no PAM module dir found>)"
	@echo ""
	@echo "VERSION=$(VERSION)"
	@echo "OPENSSL_PREFIX= build against a self-maintained OpenSSL"
