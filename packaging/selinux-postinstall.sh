#!/bin/sh
# Loads the pam_ssoossh policy module.
#
# Runs on install and on upgrade. semodule -i is the same call for both:
# it replaces a module of the same name, so there is no separate upgrade
# path and no need to look at $1 here.
set -e

PP=/usr/share/selinux/packages/pam-ssoossh/pam_ssoossh.pp

# A host with SELinux disabled at boot still has the tooling and still
# loads modules fine -- the policy simply does not take effect until it is
# enabled -- so this deliberately does not check getenforce. Refusing to
# install here would leave a host that enables SELinux later with a
# package installed and no module loaded.
if ! command -v semodule >/dev/null 2>&1; then
    echo "pam-ssoossh-selinux: semodule not found; policy not loaded" >&2
    echo "  install policycoreutils, then: semodule -i $PP" >&2
    exit 0
fi

if ! semodule -i "$PP"; then
    echo "pam-ssoossh-selinux: failed to load $PP" >&2
    echo "  the module is installed but not active; pam_ssoossh will still" >&2
    echo "  be denied outbound TCP in confined domains such as login" >&2
    exit 1
fi

exit 0
