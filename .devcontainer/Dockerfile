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
#   libclang-rt-dev   compiler-rt: the archives -fsanitize=fuzzer and clang's
#                     own -fsanitize=address link against. clang alone does
#                     not pull them in, and without them a fuzz target fails
#                     at link with a missing libclang_rt.*.a rather than
#                     anything that names the real problem. (gcc's sanitiser
#                     build is unaffected -- libasan comes with gcc.)
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
        libclang-rt-dev \
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
# so a container with no syslog sink makes its output invisible.
#
# Two changes to the stock Debian config, and deliberately no more:
#
#   * imklog is commented out -- it needs the kernel log, which an
#     unprivileged container cannot read.
#   * $FileCreateMode is widened to 0644 so `tail /var/log/auth.log` works
#     without sudo. Stock is 0640 root:adm, and the module's whole output
#     channel lands in that file.
#
# No routing rules of our own. Stock rsyslog.conf already sends
# `auth,authpriv.*` to /var/log/auth.log, and a drop-in is additive, not a
# replacement: a second rule naming the same file writes every line twice,
# which turns "grep syslog for the version line" into a count that lies.
# $IncludeConfig runs before the stock rules, so the mode below still applies
# to them.
RUN printf '%s\n' \
    '$FileCreateMode 0644' \
    > /etc/rsyslog.d/00-devcontainer.conf \
    && sed -i 's/^module(load="imklog")/#module(load="imklog")/' /etc/rsyslog.conf || true

# Claude Code, installed the same way it is on the host: the native installer,
# not npm. It goes in as vscode rather than root so it lands in the user's own
# ~/.local and can self-update without sudo.
#
# Installed here rather than mounted from the host on purpose. The host binary
# is built for that host's glibc -- Debian 13 there, Debian 12 here -- and a
# mounted binary would be one glibc bump away from not running at all.
USER vscode
RUN curl -fsSL https://claude.ai/install.sh | bash
USER root

# The installer warns about this: ~/.local/bin is not on PATH in this base
# image. Set it as ENV rather than appending to .bashrc so it applies to
# non-login shells too, which is what tooling actually spawns.
ENV PATH="/home/vscode/.local/bin:${PATH}"

# vscode already has passwordless sudo in this base image, which the PAM stack
# tests need: they install a module into a security directory and write
# /etc/pam.d. Assert both that and the CLI rather than assuming they hold.
RUN su - vscode -c 'sudo -n true' && echo "passwordless sudo: ok" \
    && su - vscode -c '/home/vscode/.local/bin/claude --version' \
    && echo "claude cli: ok"

# Default to vscode, so the image behaves the same whether it is started by
# the devcontainer CLI (which also gets remoteUser/containerUser from
# devcontainer.json) or by a plain `docker run`. Ending a Dockerfile as root
# is how a session silently ends up writing root-owned files into a
# bind-mounted worktree.
#
# Safe with devcontainer features: the CLI generates its own layer that
# re-asserts root before running feature installers.
USER vscode
