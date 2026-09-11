#!/bin/sh
# Unloads the pam_ssoossh policy module on removal, but not on upgrade.
#
# rpm passes the number of remaining instances of the package as $1: 0 on
# a real removal, 1 or more part-way through an upgrade. Removing the
# module during an upgrade would unload the policy the new package is
# about to reinstall, leaving a window where a console login on a confined
# host fails -- and, if the reinstall then failed, leaving it broken.
set -e

case "${1:-0}" in
0) ;;
*) exit 0 ;;
esac

command -v semodule >/dev/null 2>&1 || exit 0

# A module that is not loaded is not an error worth failing a removal
# over: the host may have had SELinux disabled, or an operator may have
# removed it by hand.
semodule -r pam_ssoossh >/dev/null 2>&1 || true

exit 0
