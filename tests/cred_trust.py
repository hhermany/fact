#!/usr/bin/env python3
"""Who may switch the execution credential (rule R4), with fact_policy loaded with cred=1.
Run as root from the repository root while the policy runs:
    policy/fact_policy /sys/fs/cgroup 61000 64998 1 policy/fact_policy.bpf.o 0 0 0 1 > /tmp/p.log &
    python3 tests/cred_trust.py
Checks: (1) the registered process switches; (2) its threads switch; (3) a child process
inherits the credential but not the right to switch (EPERM); (4) exec revokes the right;
(5) the right is removed when the registered process exits. Exits non-zero on any failure."""
import ctypes
import os
import subprocess
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "policy"))
import policyctl  # noqa: E402

PR_FACT, SET = 0x46414354, 1
EPERM, EALREADY = 1, 114
libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_ulong]
fails = 0


def switch(ident):
    r = libc.prctl(PR_FACT, SET, ident, 0, 0)
    return 0 if r == 0 else ctypes.get_errno()


def check(name, ok, detail=""):
    global fails
    print(("OK  " if ok else "FAIL"), name, detail)
    fails += 0 if ok else 1


CHILD = ("import ctypes;l=ctypes.CDLL('libc.so.6',use_errno=True);"
         "l.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_char_p,ctypes.c_ulong,ctypes.c_ulong];"
         "r=l.prctl(0x46414354,1,b'other',0,0);print(0 if r==0 else ctypes.get_errno())")


def trusted_map_has(pid):
    r = subprocess.run(["bpftool", "map", "lookup", "pinned", "/sys/fs/bpf/fact/trust_map", "key",
                        *[str(x) for x in int(pid).to_bytes(4, "little")]], capture_output=True)
    return r.returncode == 0


if len(sys.argv) > 1 and sys.argv[1] == "--helper-exit":   # a registered process that just exits
    policyctl.trust(os.getpid())
    print("registered", trusted_map_has(os.getpid()), flush=True)
    sys.exit(0)

if len(sys.argv) > 1 and sys.argv[1] == "--helper":   # a registered process that then execs
    policyctl.trust(os.getpid())
    print("helper-switch", switch(b"exH"), flush=True)
    os.execv(sys.executable, [sys.executable, "-I", "-c", CHILD])

policyctl.trust(os.getpid())
check("registered process switches", switch(b"exA") == EALREADY)
res = []
t = threading.Thread(target=lambda: res.append(switch(b"exB")))
t.start(); t.join()
check("its threads switch", res == [EALREADY], res)
out = subprocess.run([sys.executable, "-I", "-c", CHILD], capture_output=True, text=True).stdout.strip()
check("child inherits the credential, not the right", out == str(EPERM), out)
p = subprocess.Popen([sys.executable, "-I", os.path.abspath(__file__), "--helper"], stdout=subprocess.PIPE, text=True)
lines = p.communicate()[0].split()
check("registered helper switches before exec", "helper-switch" in lines and lines[lines.index("helper-switch") + 1] == str(EALREADY), lines)
check("exec revokes the right", lines[-1:] == [str(EPERM)], lines)
q = subprocess.Popen([sys.executable, "-I", os.path.abspath(__file__), "--helper-exit"], stdout=subprocess.PIPE, text=True)
reg = q.communicate()[0].split()
check("right removed when the registered process exits", reg == ["registered", "True"] and not trusted_map_has(q.pid), (reg, q.pid))
sys.exit(1 if fails else 0)
