#!/usr/bin/env python3
"""A minimal /dev/log, for a container with no syslog daemon.

The module's only output channel is syslog(3). In the devcontainer rsyslog
owns /dev/log and the messages land in /var/log/auth.log; in a bare CI job
container there is no daemon at all, the socket does not exist, and
everything the module says goes nowhere -- which makes every assertion the
e2e harness wants to check unverifiable.

Rather than install a syslog daemon into three CI images, this binds the
socket itself and appends what arrives to a file. It parses nothing: the
harness greps, and a syslog line is legible enough to grep without being
decoded.

Not a syslog implementation and not trying to be. It exists so that
`make e2e` can run somewhere with no init system.
"""

import argparse
import os
import socket
import sys


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--socket", default="/dev/log")
    p.add_argument("--out", required=True)
    args = p.parse_args()

    # A stale socket from an earlier run would make bind fail with EADDRINUSE
    # even though nothing is listening.
    if os.path.exists(args.socket):
        try:
            os.unlink(args.socket)
        except OSError as e:
            sys.exit(f"logsink: cannot remove {args.socket}: {e}")

    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.bind(args.socket)
    # World-writable, because the module runs as whoever PAM is
    # authenticating for -- which in a test is not necessarily this process.
    os.chmod(args.socket, 0o666)

    sys.stderr.write(f"logsink: {args.socket} -> {args.out}\n")
    sys.stderr.flush()

    with open(args.out, "a", encoding="utf-8", errors="replace") as f:
        while True:
            data = s.recv(65536)
            if not data:
                continue
            f.write(data.decode("utf-8", "replace").rstrip("\x00") + "\n")
            f.flush()


if __name__ == "__main__":
    main()
