#!/usr/bin/env python3
"""Smoke test of the execution credential (fact_policy loaded with cred=1, ports 61000-64998,
no_ctx_allow=1). Run as root from the repository root while the policy runs:
    policy/fact_policy /sys/fs/cgroup 61000 64998 1 policy/fact_policy.bpf.o 0 0 0 1 > /tmp/p.log &
    python3 tests/cred_smoke.py /tmp/p.log
Checks: (1) other prctl options are unaffected; (2) the switch sets the credential of the
calling thread; (3) new threads and child processes inherit it; (4) clearing removes it;
(5) the kernel charges sent and received bytes to the credential; (6) openat markers are not
accepted in this mode. Prints one line per check and exits non-zero on any failure.
"""
import ctypes
import json
import os
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from fact_rt import agentctx  # noqa: E402
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "policy"))
import policyctl  # noqa: E402

LOG = sys.argv[1] if len(sys.argv) > 1 else "/tmp/p.log"
fails = 0


def check(name, ok, detail=""):
    global fails
    print(f"{'OK  ' if ok else 'FAIL'} {name} {detail}")
    fails += 0 if ok else 1


def decisions(port):
    out = []
    for line in open(LOG):
        if line.startswith('{"ev":"decision"'):
            d = json.loads(line)
            if d["dport"] == port:
                out.append(d)
    return out


def try_connect(port):
    s = socket.socket()
    s.settimeout(1)
    r = s.connect_ex(("127.0.0.1", port))
    s.close()
    return r


libc = ctypes.CDLL("libc.so.6", use_errno=True)
PR_SET_NAME, PR_GET_NAME = 15, 16
libc.prctl(PR_SET_NAME, b"credtest", 0, 0, 0)
buf = ctypes.create_string_buffer(16)
libc.prctl(PR_GET_NAME, buf, 0, 0, 0)
check("other prctl options unaffected", buf.value == b"credtest", buf.value)

agentctx.install(iface="prctl")
with agentctx.bind("exA"):
    agentctx.sync_kernel()
    try_connect(61010)
    t = threading.Thread(target=try_connect, args=(61011,))
    t.start(); t.join()
    subprocess.run([sys.executable, "-I", "-c",
                    "import socket;s=socket.socket();s.settimeout(1);s.connect_ex(('127.0.0.1',61012));s.close()"])
time.sleep(0.5)
for port, what in ((61010, "calling thread"), (61011, "new thread"), (61012, "child process")):
    d = decisions(port)
    check(f"credential of the {what}", len(d) == 1 and d[0]["ctx"] == "exA", [x["ctx"] for x in d])

agentctx.invalidate()
agentctx.sync_kernel()          # no binding: clears the credential
try_connect(61013)
time.sleep(0.3)
d = decisions(61013)
check("cleared credential", len(d) == 1 and d[0]["has_ctx"] == 0, [x["has_ctx"] for x in d])

try:
    os.close(os.open("/run/agentctx/begin/exB", os.O_RDONLY))
except FileNotFoundError:
    pass
try_connect(61014)
time.sleep(0.3)
d = decisions(61014)
check("openat marker not accepted", len(d) == 1 and d[0]["has_ctx"] == 0, [x["ctx"] for x in d])

# accounting: an echo server on a policed port; exA is allowed to it
policyctl.allow("exA", [61020])
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 61020)); srv.listen(1)


def echo():
    c, _ = srv.accept()
    data = b""
    while len(data) < 1000:
        data += c.recv(4096)
    c.sendall(data[:700])
    c.close()


threading.Thread(target=echo, daemon=True).start()
with agentctx.bind("exA"):
    agentctx.sync_kernel()
    s = socket.create_connection(("127.0.0.1", 61020))
    agentctx.sync_kernel()
    s.sendall(b"x" * 1000)
    got = b""
    while len(got) < 700:
        chunk = s.recv(4096)
        if not chunk:
            break
        got += chunk
    s.close()
time.sleep(0.3)
u = policyctl.usage().get("exA", {})
check("sent bytes charged in the kernel", u.get("bytes") == 1000, u)
check("received bytes charged in the kernel", u.get("rx_bytes") == 700, u)
sys.exit(1 if fails else 0)
