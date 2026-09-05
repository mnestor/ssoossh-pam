#!/usr/bin/env python3
"""A stub ssoosshd, for exercising the module without a real server.

It speaks the two endpoints the module uses -- POST /api/certs/{pam,console}
and GET /api/certs/requests/<id>/events -- and mints real certificates with
ssh-keygen against the fixture CA. The certificates are real because that is
the point: a stub that returned a canned string would test the HTTP client
and nothing below it.

Scenarios are chosen per run, so the same harness covers the paths a live
server makes expensive to reach on purpose:

    approved      the happy path, a real certificate for the posted key
    denied        a terminal event with no certificate
    expired       likewise
    failed        the server processed it and could not sign
    unknown       an event name nobody listed, which is informational
    enrolled      a terminal status that carries no PAM certificate
    drop          establishes the stream, sends nothing, drops it, and
                  serves the outcome on the reconnect
    slow          holds the stream open past the module's timeout
    error-500     refuses the events connect with a retryable status, then
                  serves the outcome
    error-404     refuses it definitively
    bad-json      a create response that is not JSON
    escape        an approval URL carrying terminal escape sequences
    wrong-key     a certificate for a key the module did not generate
    untrusted     a certificate signed by a CA the module does not trust

Nothing here runs in production and nothing here is careful about
concurrency beyond what one PAM transaction needs.
"""

import argparse
import http.server
import json
import os
import re
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import uuid

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

# Every certificate the stub mints, keyed by request id.
STATE = {}
STATE_LOCK = threading.Lock()

ARGS = None


def sign(public_key_text, ca="ca_ecdsa384", principals="games,ops",
         validity="-5m:+5m"):
    """Signs public_key_text with a fixture CA and returns the certificate.

    The private halves are not committed -- make-fixtures.sh deletes them --
    so a CA is regenerated here on first use and cached for the run. What
    matters to the module is that the certificate verifies against the
    public half it was handed, and a CA generated here satisfies that as
    long as the test points trusted-ca-file at the matching .pub.
    """
    workdir = ARGS.workdir
    ca_path = os.path.join(workdir, ca)
    if not os.path.exists(ca_path):
        raise RuntimeError(f"no CA private key at {ca_path}")

    with tempfile.TemporaryDirectory() as tmp:
        key_path = os.path.join(tmp, "id.pub")
        with open(key_path, "w", encoding="utf-8") as f:
            f.write(public_key_text)
        subprocess.run(
            ["ssh-keygen", "-q", "-s", ca_path, "-I", "stub", "-n",
             principals, "-V", validity, "-z", "1", key_path],
            check=True,
        )
        with open(os.path.join(tmp, "id-cert.pub"), encoding="utf-8") as f:
            return f.read().strip()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *a):  # noqa: A003 - base class name
        if ARGS.verbose:
            sys.stderr.write("stubd: " + (fmt % a) + "\n")

    # -- create -----------------------------------------------------------

    def do_POST(self):  # noqa: N802 - base class name
        if not re.fullmatch(r"/api/certs/(pam|console)", self.path):
            self.send_error(404)
            return

        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length))
        console = self.path.endswith("/console")

        if ARGS.scenario == "bad-json":
            self.respond_raw(200, b"not json at all")
            return
        if ARGS.scenario == "create-500":
            self.respond(500, {"data": None, "error": "signing backend down"})
            return

        request_id = str(uuid.uuid4())
        with STATE_LOCK:
            STATE[request_id] = {
                "public_key": body["public_key"],
                "console": console,
                "connects": 0,
            }

        approval = "/approve/" + request_id
        if ARGS.scenario == "escape":
            # A hostile server putting terminal control on the tty of a root
            # process. The module must show a URL with none of it left.
            approval = "/approve/\x1b]0;pwned\x07\r" + request_id

        data = {
            "request_id": request_id,
            "events_url": f"/api/certs/requests/{request_id}/events",
            "approval_url": approval,
            "expires_at": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + ARGS.expires_in)
            ),
        }
        if console:
            data["user_code"] = "K7M4-QP2X"
            data["verification_url"] = "/console"
            data["verification_url_complete"] = "/c/K7M4QP2X"

        self.respond(200, {"data": data, "error": ""})

    # -- events -----------------------------------------------------------

    def do_GET(self):  # noqa: N802 - base class name
        m = re.fullmatch(r"/api/certs/requests/([0-9a-f-]+)/events", self.path)
        if not m:
            self.send_error(404)
            return
        request_id = m.group(1)
        with STATE_LOCK:
            entry = STATE.get(request_id)
        if entry is None:
            self.send_error(404)
            return
        entry["connects"] += 1

        if ARGS.scenario == "error-404":
            self.respond(404, {"data": None, "error": "no such request"})
            return
        if ARGS.scenario == "error-500" and entry["connects"] == 1:
            # Retryable: the module should come back and get the outcome.
            self.respond(500, {"data": None, "error": "try again"})
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        # A keep-alive comment first: a real stream carries them, and they
        # must dispatch nothing.
        self.wfile.write(b": keep-alive\n\n")
        self.wfile.flush()

        if ARGS.scenario == "drop" and entry["connects"] == 1:
            # Establish, send nothing terminal, and drop. The module should
            # reconnect and pick up the outcome.
            self.wfile.write(b"event: pending\ndata: {}\n\n")
            self.wfile.flush()
            return

        if ARGS.scenario == "slow":
            time.sleep(ARGS.hold)
            return

        time.sleep(ARGS.delay)
        self.send_event(entry)

    def send_event(self, entry):
        scenario = ARGS.scenario

        if scenario in ("denied", "expired", "failed", "enrolled"):
            self.write_event(scenario, {"data": {}, "error": ""})
            return

        if scenario == "unknown":
            # A status this module does not recognize. Deliberately treated
            # as informational rather than terminal, matching the Go client:
            # a name nobody listed is not an outcome, and inventing one from
            # it would be worse than waiting for the timeout.
            self.write_event("bananas", {"data": {}, "error": ""})
            return

        if scenario == "envelope-error":
            self.write_event("failed",
                             {"data": {}, "error": "the signer refused"})
            return

        if scenario == "no-cert":
            self.write_event("approved", {"data": {}, "error": ""})
            return

        key = entry["public_key"]
        ca = "ca_ecdsa384"
        principals = ARGS.principals
        validity = ARGS.validity

        if scenario == "wrong-key":
            # Correctly signed by a trusted CA, right principals, inside its
            # window, and issued to a keypair the module never generated.
            with open(os.path.join(FIXTURES, "other.pub"), encoding="utf-8") as f:
                key = f.read()
        elif scenario == "untrusted":
            ca = "ca_untrusted"

        cert = sign(key, ca=ca, principals=principals, validity=validity)
        self.write_event("approved", {"data": {"certificate": cert},
                                      "error": ""})

    def write_event(self, name, payload):
        body = json.dumps(payload)
        chunk = f"event: {name}\ndata: {body}\n\n".encode()
        self.wfile.write(chunk)
        self.wfile.flush()

    # -- plumbing ---------------------------------------------------------

    def respond(self, code, payload):
        self.respond_raw(code, json.dumps(payload).encode())

    def respond_raw(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# ThreadingMixIn + HTTPServer rather than ThreadingHTTPServer, which only
# exists from Python 3.7. The RHEL 8 image -- the version floor this project
# designs to -- ships 3.6, and a stub that cannot start there means the e2e
# suite silently does not run on the one image that matters most.
class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    global ARGS

    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--scenario", default="approved")
    p.add_argument("--delay", type=float, default=0.1,
                   help="seconds to hold the stream before the outcome")
    p.add_argument("--hold", type=float, default=3600,
                   help="seconds the slow scenario holds the stream open")
    p.add_argument("--expires-in", type=float, default=300,
                   help="seconds until the create response's expires_at")
    # "games" is the account tests/pamtest.c authenticates, so the
    # default certificate authorizes it. A scenario that wants check 3
    # to fail overrides this.
    p.add_argument("--principals", default="games,ops")
    p.add_argument("--validity", default="-5m:+5m")
    p.add_argument("--workdir", required=True,
                   help="directory holding the CA private keys to sign with")
    p.add_argument("--verbose", action="store_true")
    ARGS = p.parse_args()

    if shutil.which("ssh-keygen") is None:
        sys.exit("stubd: ssh-keygen is required to mint certificates")

    server = Server(("127.0.0.1", ARGS.port), Handler)
    sys.stderr.write(
        f"stubd: listening on 127.0.0.1:{ARGS.port} scenario={ARGS.scenario}\n"
    )
    sys.stderr.flush()
    server.serve_forever()


if __name__ == "__main__":
    main()
