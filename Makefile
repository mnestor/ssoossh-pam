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
PREFIX ?= /usr/local

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

SRC     := $(wildcard src/*.c)
OBJ     := $(patsubst src/%.c,$(BUILD)/%.o,$(SRC))

CFLAGS  += -std=c11 -O2 -fPIC \
           -fvisibility=hidden \
           -Wall -Wextra -Wconversion -Wshadow -Wpointer-arith \
           -Wstrict-prototypes -Wmissing-prototypes -Werror \
           -fstack-protector-strong \
           -D_FORTIFY_SOURCE=2 \
           -DPAM_SSOOSSH_VERSION='"$(VERSION)"'
CPPFLAGS += -Isrc

# libcurl joins this list in P4, when src/httpc.c exists. Adding it before
# there is anything to link would only make the build need a package it does
# not yet use.
PKGS    := libcrypto

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

.PHONY: all clean check-symbols test san install help

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
	$(CC) -std=c11 -O1 -Wall -Wextra -o $@ $< -lpam $(PAMTEST_LIBS)

# Runs anywhere, including CI: proves the module loads and that exactly the
# right symbols are reachable through the dynamic loader.
tests/loadtest: tests/loadtest.c
	$(CC) -std=c11 -O1 -Wall -Wextra -Werror -o $@ $< $(if $(filter Darwin,$(UNAME)),,-ldl)

test: check-symbols tests/loadtest
	@./tests/loadtest ./$(MODULE)

san: CFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer -O1
san: LDFLAGS += -fsanitize=address,undefined
san: clean all

install: $(MODULE)
	install -d $(DESTDIR)$(SECURITYDIR)
	install -m 0644 $(MODULE) $(DESTDIR)$(SECURITYDIR)/pam_ssoossh.so

clean:
	rm -rf $(BUILD) pam_ssoossh.so pam_ssoossh.bundle tests/pamtest

help:
	@echo "make            build $(MODULE) for $(UNAME)"
	@echo "make test       build and check the exported symbol set"
	@echo "make san        rebuild with ASan and UBSan"
	@echo "make tests/pamtest"
	@echo "                build the manual PAM harness (needs libpam-misc on Linux)"
	@echo ""
	@echo "VERSION=$(VERSION)"
	@echo "OPENSSL_PREFIX= build against a self-maintained OpenSSL"
