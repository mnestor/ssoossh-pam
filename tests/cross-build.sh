#!/usr/bin/env bash
#
# Build and gate the module on every Linux image CI uses, through the host's
# Docker daemon. Run it before claiming a change is portable -- in particular
# before claiming anything about the OpenSSL version floor, since el8 is the
# only image here that compiles the 1.1.1 paths.
#
#   tests/cross-build.sh            all images
#   tests/cross-build.sh el8        one image
#
# These are sibling containers started through the host's Docker socket, so
# the bind source below is resolved by the *host* daemon against the *host*
# filesystem -- not by this container. A container path would silently mount
# the wrong thing, or nothing.
#
# The devcontainer mounts the host's checkout root at /workspace and exports
# where that came from, so the fix is a prefix swap. Outside the container
# both are the same path and the swap is a no-op.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

host_root="${HOST_WORKSPACE_ROOT:-}"
if [ -n "$host_root" ] && [ "${repo_root#/workspace/}" != "$repo_root" ]; then
    host_repo="${host_root}/${repo_root#/workspace/}"
else
    host_repo="$repo_root"
fi

# image:packages-install-command
# openssh-client is here for one test: the interop case that hands a key
# this module marshalled to ssh-keygen and reads back what it made of it.
# It prints a visible SKIP without it, and a test that quietly skips is one
# nobody notices has stopped running.
declare -A IMAGES=(
    [debian12]="debian:12|apt-get update -qq && apt-get install -y -qq --no-install-recommends build-essential pkg-config libssl-dev libcurl4-openssl-dev libpam0g-dev openssh-client"
    [alpine]="alpine:3|apk add --no-cache build-base pkgconf openssl-dev curl-dev linux-pam-dev compiler-rt openssh-keygen"
    [el8]="almalinux:8|dnf install -y -q gcc make pkgconf-pkg-config openssl-devel libcurl-devel pam-devel libasan libubsan openssh-clients"
)

targets=("${@:-}")
if [ -z "${targets[0]:-}" ]; then
    targets=(debian12 alpine el8)
fi

failed=()
for name in "${targets[@]}"; do
    spec="${IMAGES[$name]:-}"
    if [ -z "$spec" ]; then
        echo "unknown image '$name'; known: ${!IMAGES[*]}" >&2
        exit 2
    fi
    image="${spec%%|*}"
    install="${spec#*|}"

    echo "=== $name ($image) ==="
    # An explicit if, not `[ ... ] && echo`: under `set -e` a bare AND-list
    # whose test fails is a trap worth not setting for the next reader.
    if [ "$host_repo" != "$repo_root" ]; then
        echo "source: $host_repo (translated to host path)"
    fi
    # The source is mounted read-only and copied into a scratch directory, so
    # a container build never leaves root-owned object files in the worktree.
    if docker run --rm -v "$host_repo:/src:ro" -w /w "$image" sh -c "
        set -e
        $install >/dev/null 2>&1
        cp -r /src/. /w/ 2>/dev/null || true
        rm -rf /w/build /w/pam_ssoossh.so /w/tests/loadtest /w/tests/pamtest
        printf 'cc:        %s\n' \"\$(cc --version | head -1)\"
        printf 'libcrypto: %s\n' \"\$(pkg-config --modversion libcrypto 2>/dev/null || echo '(no pkg-config data)')\"
        make VERSION=cross-build >/dev/null
        make VERSION=cross-build test
        make VERSION=cross-build check-stdio
        make VERSION=cross-build check-size
        # The sanitiser build too, because it needs runtime libraries the
        # plain build does not -- an omission act caught in CI that a
        # build-and-gate-only run here would have missed.
        make VERSION=cross-build san >/dev/null && echo 'san: ok'
    "; then
        echo "--- $name: PASS"
    else
        echo "--- $name: FAIL" >&2
        failed+=("$name")
    fi
    echo
done

if [ ${#failed[@]} -ne 0 ]; then
    echo "failed: ${failed[*]}" >&2
    exit 1
fi
echo "all images passed"
