# syntax=docker/dockerfile:1
#
# Development image for pam_ssoossh.
#
# Debian 12 on purpose, not the newest thing available: it is one of the four
# CI targets (gcc 12, OpenSSL 3.0.20), so a local build exercises a toolchain
# CI actually uses. The other three targets are reached through the host's
# Docker daemon -- see tests/cross-build.sh.
FROM mcr.microsoft.com/devcontainers/base:bookworm

ENV DEBIAN_FRONTEND=noninteractive

# Build and analysis toolchain.
#
#   libpam0g-dev      pam_modules.h, pam_appl.h, and pam_misc.h + libpam_misc,
#                     which tests/pamtest.c needs for misc_conv
#   libpam-modules    pam_unix / pam_permit, for the second module in a test
#                     stack that Ctrl-C fallthrough is verified against
#   libssl-dev        libcrypto, the crypto backend on this platform
#   libcurl4-*-dev    needed from P4; installed now so the dependency is not
#                     discovered at the moment it is wanted
#   clang + llvm      libFuzzer for the P3/P5 fuzz targets, plus clang-tidy
#                     and clang-format
#   openssh-client    ssh-keygen, which P2 round-trips generated keys against
#   rsyslog           the module logs to syslog and nothing else; without a
#                     syslog sink in the container there is nothing to read
#   manpages-dev      pam.conf(5), syslog(3), getifaddrs(3) are all referenced
#                     by the plan and worth having locally
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        clang \
        clang-format \
        clang-tidy \
        clangd \
        lld \
        llvm \
        make \
        pkg-config \
        bear \
        libpam0g-dev \
        libpam-modules \
        libssl-dev \
        libcurl4-openssl-dev \
        openssh-client \
        valgrind \
        gdb \
        strace \
        ltrace \
        cppcheck \
        shellcheck \
        rsyslog \
        binutils \
        file \
        jq \
        ripgrep \
        python3 \
        python3-venv \
        man-db \
        manpages \
        manpages-dev \
    && rm -rf /var/lib/apt/lists/*

# actionlint, for .github/workflows/ci.yml. Not packaged in Debian; taken from
# the release tarball so it needs no Go toolchain at image-build time.
ARG ACTIONLINT_VERSION=1.7.7
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
        amd64) al_arch=amd64 ;; \
        arm64) al_arch=arm64 ;; \
        *) echo "unsupported arch $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/actionlint.tgz \
        "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_${al_arch}.tar.gz"; \
    tar -xzf /tmp/actionlint.tgz -C /usr/local/bin actionlint; \
    rm -f /tmp/actionlint.tgz; \
    actionlint --version

# nektos/act, for running .github/workflows locally before pushing. It drives
# the host's Docker daemon (mounted into this container), so the workflow runs
# in the same images CI uses rather than an approximation of them.
ARG ACT_VERSION=0.2.89
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
        amd64) act_arch=x86_64 ;; \
        arm64) act_arch=arm64 ;; \
        *) echo "unsupported arch $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/act.tgz \
        "https://github.com/nektos/act/releases/download/v${ACT_VERSION}/act_Linux_${act_arch}.tar.gz"; \
    tar -xzf /tmp/act.tgz -C /usr/local/bin act; \
    rm -f /tmp/act.tgz; \
    act --version

# The module logs to syslog under LOG_AUTHPRIV and never to stdout or stderr,
# so a container with no syslog sink makes its output invisible. imuxsock only
# -- imklog needs the kernel log, which an unprivileged container cannot read.
RUN printf '%s\n' \
    'module(load="imuxsock")' \
    '$FileCreateMode 0644' \
    'authpriv.*  /var/log/auth.log' \
    '*.*         /var/log/syslog' \
    > /etc/rsyslog.d/00-devcontainer.conf \
    && sed -i 's/^module(load="imklog")/#module(load="imklog")/' /etc/rsyslog.conf || true

# vscode already has passwordless sudo in this base image, which the PAM stack
# tests need: they install a module into a security directory and write
# /etc/pam.d. Assert it rather than assuming it stays true.
RUN su - vscode -c 'sudo -n true' && echo "passwordless sudo: ok"
