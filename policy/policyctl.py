#!/usr/bin/env python3
"""Control of the pinned maps of the FACT policy (/sys/fs/bpf/fact).

  policyctl.py allow <exec_id> <port> [<port> ...]     adds permissions
  policyctl.py load  <file.json>                       {"exec": [ports, ...], ...}
  policyctl.py clear                                   removes every permission
  policyctl.py usage                                   prints the per-execution budget usage (JSON)

Uses bpftool (key = id[48] + port u32, value = u8 1).
"""
import json
import subprocess
import sys

PIN = "/sys/fs/bpf/fact/allow_map"
ID_LEN = 48


def key_bytes(exec_id, port):
    b = exec_id.encode()
    if len(b) >= ID_LEN or b"/" in b:
        raise ValueError(f"invalid id: {exec_id!r}")
    raw = b + b"\0" * (ID_LEN - len(b)) + int(port).to_bytes(4, "little")
    return [str(x) for x in raw]


def allow(exec_id, ports):
    for p in ports:
        subprocess.run(["bpftool", "map", "update", "pinned", PIN, "key", *key_bytes(exec_id, p),
                        "value", "1"], check=True)


def load_dict(d):
    """Loads {exec: [ports]} in a single bpftool process (batch mode)."""
    import tempfile
    lines = [f"map update pinned {PIN} key {' '.join(key_bytes(e, p))} value 1"
             for e, ports in d.items() for p in ports]
    if not lines:
        return 0
    with tempfile.NamedTemporaryFile("w", suffix=".bpftool", delete=False) as f:
        f.write("\n".join(lines) + "\n")
    subprocess.run(["bpftool", "batch", "file", f.name], check=True, capture_output=True)
    return len(lines)


def register_root(pid, exec_id):
    """Registers the root of a process tree that belongs to ONE execution
    (used by the policy's lineage check)."""
    k = [str(x) for x in int(pid).to_bytes(4, "little")]
    b = exec_id.encode()
    if len(b) >= ID_LEN:
        raise ValueError(f"invalid id: {exec_id!r}")
    val = [str(x) for x in b + b"\0" * (ID_LEN - len(b))]
    base = PIN.rsplit("/", 1)[0]
    subprocess.run(["bpftool", "map", "update", "pinned", f"{base}/dom_map", "key", *k, "value", *k], check=True)
    subprocess.run(["bpftool", "map", "update", "pinned", f"{base}/owner_map", "key", *k, "value", *val], check=True)


def trust(pid):
    """Accepts markers only from the given process (the agent runtime) and from
    other processes registered the same way; markers from any other process are
    ignored by the policy (trusted-runtime mode, see fact_policy.bpf.c)."""
    base = PIN.rsplit("/", 1)[0]
    for k in (int(pid), 0xFFFFFFFF):   # the runtime first, then the switch
        subprocess.run(["bpftool", "map", "update", "pinned", f"{base}/trust_map",
                        "key", *[str(x) for x in k.to_bytes(4, "little")], "value", "1"], check=True)


def load_budgets(d):
    """Per-execution budgets {exec: {"bytes": B, "conns": C}} (0 = no limit) and zeroed
    usage counters, in one bpftool process (E10budget)."""
    import tempfile
    base = PIN.rsplit("/", 1)[0]
    lines = []
    for e, b in d.items():
        k = " ".join(key_bytes(e, 0)[:ID_LEN])
        bv = " ".join(str(x) for x in int(b.get("bytes", 0)).to_bytes(8, "little") + int(b.get("conns", 0)).to_bytes(8, "little"))
        lines.append(f"map update pinned {base}/budget_map key {k} value {bv}")
        lines.append(f"map update pinned {base}/usage_map key {k} value {' '.join(['0'] * 24)}")
    if not lines:
        return 0
    with tempfile.NamedTemporaryFile("w", suffix=".bpftool", delete=False) as f:
        f.write("\n".join(lines) + "\n")
    subprocess.run(["bpftool", "batch", "file", f.name], check=True, capture_output=True)
    return len(d)


def usage():
    """{exec: {"bytes", "conns", "denied"}} read from the pinned usage map."""
    base = PIN.rsplit("/", 1)[0]
    out = subprocess.run(["bpftool", "-j", "map", "dump", "pinned", f"{base}/usage_map"], check=True,
                         capture_output=True, text=True).stdout
    res = {}
    for e in json.loads(out or "[]"):
        key = bytes(int(x, 16) for x in e["key"]).split(b"\0")[0].decode()
        v = bytes(int(x, 16) for x in e["value"])
        res[key] = {"bytes": int.from_bytes(v[0:8], "little"), "conns": int.from_bytes(v[8:16], "little"),
                    "denied": int.from_bytes(v[16:24], "little")}
    return res


def load(path):
    return load_dict(json.load(open(path)))


def clear():
    out = subprocess.run(["bpftool", "-j", "map", "dump", "pinned", PIN], check=True,
                         capture_output=True, text=True).stdout
    for e in json.loads(out or "[]"):
        key = [str(int(x, 16)) for x in e["key"]]
        subprocess.run(["bpftool", "map", "delete", "pinned", PIN, "key", *key], check=True)


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "allow":
        allow(sys.argv[2], sys.argv[3:])
    elif cmd == "load":
        print(load(sys.argv[2]), "permissions")
    elif cmd == "clear":
        clear()
    elif cmd == "usage":
        print(json.dumps(usage()))
    else:
        sys.exit(__doc__)
