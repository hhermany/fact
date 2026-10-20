#!/usr/bin/env python3
"""Scores byte attribution on reused connections (E5reuse), against an independent
per-request reference.

Reference: the destination (workload/http_farm.py, KeepAliveHttpListener) logs,
for every HTTP request it serves, the client's source port (which identifies the
connection), the request path (the operation id, mapped to its execution by
plan.json op_map), and the byte ranges the request and its response occupied in
each direction of that connection (requests.jsonl). The collector's send/recv
events (collector/fact-bytes.bt) carry the socket, the source port, and the byte
counts; their cumulative offsets per connection place each event's bytes in the
reference ranges. The reference is never given to the resolvers: they receive
only (ts, pid, tid, cgroup, ctx), as in score.py.

Credit rules compared, for the bytes the client sends and receives:
  opener       the identity of the connection, resolved at connect (what FACT
               does for connections: everything on the socket goes to the
               execution that opened it);
  sender       sent bytes: the identity of the thread at each send (fact_rt with
               send binding); received bytes: the identity of the socket's last
               sender (a response belongs to the request sent before it).
Categories per byte, as for connections: C (single origin = reference), I (single
origin != reference), A (several candidates), M (none).

Usage: score_bytes.py RUN_DIR      -> RUN_DIR/score_bytes.json
"""
import json
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from resolvers import ResolverInput, World, check_independence, resolve_fused, strip_reference_fields  # noqa: E402
from score import load_jsonl  # noqa: E402


def classify(out, ref):
    if len(out) == 1:
        return "C" if ref in out else "I"
    return "A" if out else "M"


def split(lo, hi, ranges):
    """Splits [lo, hi) over the reference ranges [(a, b, exec)]: yields (exec, nbytes);
    bytes outside every range are yielded with exec None."""
    covered = 0
    for a, b, e in ranges:
        n = min(hi, b) - max(lo, a)
        if n > 0:
            covered += n
            yield e, n
    if hi - lo - covered > 0:
        yield None, hi - lo - covered


def score(rdir):
    check_independence()
    events, _ = load_jsonl(os.path.join(rdir, "events.jsonl"))
    plan = json.load(open(os.path.join(rdir, "plan.json")))
    reg = json.load(open(os.path.join(rdir, "registry.json")))
    reqs, _ = load_jsonl(os.path.join(rdir, "requests.jsonl"))
    w = World(roots={int(k): set(v) for k, v in reg["roots"].items()},
              cgroups={int(k): set(v) for k, v in reg["cgroups"].items()})
    op_exec = plan["op_map"]
    ports = set(plan["reuse_ports"])

    # reference ranges per connection: client->server and server->client. A connection is
    # (client source port, epoch): the kernel may give a closed connection's source port to a
    # later one, so the k-th connection seen with a port on each side is matched with the k-th
    # on the other. At the destination a connection's first request starts at byte 0; in the
    # collector a new connection on a port is a new (socket, connect) pair.
    ref_tx, ref_rx = defaultdict(list), defaultdict(list)
    conn_execs = defaultdict(set)
    srv_epoch = Counter()
    for r in reqs:
        p = r["peer_port"]
        if r["req"][0] == 0:
            srv_epoch[p] += 1
        key = (p, srv_epoch[p])
        e = op_exec.get(r["path"].strip("/"))
        ref_tx[key].append((r["req"][0], r["req"][1], e))
        ref_rx[key].append((r["resp"][0], r["resp"][1], e))
        conn_execs[key].add(e)
    conn_seq = {}                     # sk -> sequence of its last connect (sockets are reused)
    cli_epoch, cli_last = Counter(), {}

    opener = {}                       # sk -> identity resolved at connect
    off_tx, off_rx = Counter(), Counter()
    res = {d: {m: Counter() for m in ("opener", "sender")} for d in ("sent", "received")}
    unref = Counter()
    for ev in sorted(events, key=lambda x: x.get("ts", 0)):
        kind = ev.get("ev")
        if kind == "fork":
            w.parent[ev["ctid"]] = ev["ptid"]
        elif kind == "connect" and ev.get("dport") in ports:
            opener[ev["sk"]] = resolve_fused(strip_reference_fields(ev), w)
            conn_seq[ev["sk"]] = conn_seq.get(ev["sk"], 0) + 1
        elif kind in ("send", "recv") and ev.get("dport") in ports:
            sk, p, n = ev["sk"], ev["sport"], int(ev["bytes"])
            ident = (sk, conn_seq.get(sk, 0))
            if cli_last.get(p) != ident:
                cli_epoch[p] += 1
                cli_last[p] = ident
            sport = (p, cli_epoch[p])
            if kind == "send":
                lo = off_tx[sport]
                off_tx[sport] += n
                ranges, d = ref_tx[sport], "sent"
                now = resolve_fused(strip_reference_fields(ev), w)
            else:
                lo = off_rx[sport]
                off_rx[sport] += n
                ranges, d = ref_rx[sport], "received"
                x = strip_reference_fields(ev)
                now = resolve_fused(ResolverInput(x.ts, x.pid, x.tid, x.cgroup, ev.get("sk_ctx", "")), w)
            op = opener.get(sk, frozenset())
            for e, k in split(lo, lo + n, ranges):
                if e is None:
                    unref[d] += k
                    continue
                for m, out in (("opener", op), ("sender", now)):
                    res[d][m][classify(out, e)] += k
                    res[d][m]["N"] += k
    out = {"run": rdir, "tool": plan.get("tool"), "send_binding": plan.get("send_binding"),
           "requests": len(reqs), "connections": len(conn_execs),
           "connections_shared": sum(1 for s in conn_execs.values() if len(s) > 1),
           "unreferenced_bytes": dict(unref),
           "bytes": {d: {m: dict(c) for m, c in v.items()} for d, v in res.items()}}
    return out


def main():
    r = score(sys.argv[1])
    json.dump(r, open(os.path.join(sys.argv[1], "score_bytes.json"), "w"), indent=1)
    b = r["bytes"]
    print(json.dumps({"tool": r["tool"], "send_binding": r["send_binding"], "requests": r["requests"],
                      "connections": r["connections"], "shared": r["connections_shared"],
                      **{f"{d}_{m}_I": b[d][m].get("I", 0) for d in b for m in b[d]},
                      **{f"{d}_N": b[d]["opener"].get("N", 0) for d in b}}))


if __name__ == "__main__":
    main()
