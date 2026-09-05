#!/usr/bin/env python3
"""Asserts on the create body the module sent, as stubd recorded it.

    context_check.py <record.json> <expected pam_service> <ca.pub>

The outcome scenarios prove the module reacts correctly to what comes back;
this proves what went out. Every context field is a self-reported claim,
so the checks are for shape and for agreement with what this harness knows
about the host it is running on -- the service name it wrote into pam.d,
the CA it generated -- not for truth in any deeper sense.
"""
import json
import os
import platform
import re
import subprocess
import sys

record = json.load(open(sys.argv[1], encoding="utf-8"))
service = sys.argv[2]
ca_pub = sys.argv[3]
body = record["body"]
problems = []


def need(key, ok, why):
    if key not in body:
        problems.append(f"{key}: missing ({why})")
    elif not ok(body[key]):
        problems.append(f"{key}: {why}, got {body[key]!r}")


def is_str(v):
    return isinstance(v, str) and v != ""


def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


if record["path"] != "/api/certs/pam":
    problems.append(f"path: expected the sudo endpoint, got {record['path']}")

# Field order is the contract's, and the new ones sit between remote_host
# and requested_options.
keys = list(body)
if keys[:2] != ["public_key", "username"] or keys[-1] != "requested_options":
    problems.append(f"order: {keys}")

need("hostname", is_str, "non-empty string")
need("pam_service", lambda v: v == service, f"the service name {service}")
for key in ("caller_uid", "caller_pid", "caller_ppid"):
    need(key, is_int, "JSON integer")
need("os", is_str, "non-empty string")
need("client", lambda v: is_str(v) and v.startswith("pam_ssoossh-c/"),
     "module name and version")
need("mode", lambda v: v == "auto", "the configured mode")
need("client_time",
     lambda v: is_str(v) and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", v),
     "RFC 3339 UTC")

# The fingerprint must be the CA this run generated, in ssh-keygen's form.
want_fp = subprocess.run(["ssh-keygen", "-lf", ca_pub], capture_output=True,
                         text=True, check=True).stdout.split()[1]
need("trusted_ca_fingerprints",
     lambda v: v == [want_fp], f"exactly [{want_fp}]")

system = platform.system()
if system in ("Linux", "FreeBSD"):
    need("process", lambda v: is_str(v) and "pamtest" in v and "\0" not in v,
         "pamtest's command line")
elif "process" in body:
    problems.append(f"process: must be absent on {system}, got {body['process']!r}")

if system != "Linux" or os.path.exists("/etc/machine-id"):
    need("machine_id", is_str, "non-empty string")

# omitempty: a string that is empty is omitted, never sent as "".
for key in ("tty", "remote_host", "requesting_user", "process", "machine_id"):
    if key in body and body[key] == "":
        problems.append(f"{key}: sent empty, should be omitted")

if problems:
    print("\n".join(problems))
    print("body: " + json.dumps(body, indent=1))
    sys.exit(1)
