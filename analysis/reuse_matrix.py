#!/usr/bin/env python3
"""Connection reuse, request by request (E6reuse, E6reusecred; raw runs).

For every request: the class of the execution that opened the connection it travelled on
(collector connect event of that socket, latest before the request's first send), the class
of the execution that sent it, whether its destination is permitted to the sender, and whether
the destination received it (requests.jsonl, the independent reference). A request the
destination never received has no connection to attribute (opener "-"). Also counts the
kernel's denials by kind (connect at cgroup/connect4, send at the LSM).

Usage: reuse_matrix.py [--campaigns campaigns] [--out analysis/output] -> reuse_matrix.csv
"""
import argparse
import collections
import csv
import glob
import json
import os


def ident(x):
    return (x or "").rsplit("/", 1)[-1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--campaigns", default="campaigns")
    ap.add_argument("--out", default="analysis/output")
    a = ap.parse_args()
    out = collections.Counter()
    for rd in sorted(glob.glob(os.path.join(a.campaigns, "*-E6reuse*-confirmatory-*", "runs", "*"))):
        exp = os.path.basename(os.path.dirname(os.path.dirname(rd))).split("-")[1]
        plan = json.load(open(os.path.join(rd, "plan.json")))
        cls = plan["policy"]["classes"]
        allow = {e: set(v) for e, v in plan["policy"]["allow"].items()}
        ready = next(json.loads(l) for l in open(os.path.join(rd, "policy_events.jsonl")) if l.startswith('{"ev":"ready"'))
        ps = ready.get("per_send", 0)
        conns, first_send = collections.defaultdict(list), {}
        for l in open(os.path.join(rd, "events.jsonl")):
            if not l.startswith("{"):
                continue
            e = json.loads(l)
            if e.get("ev") == "connect" and e.get("dport") in plan["reuse_ports"]:
                conns[e["sk"]].append((e["ts"], ident(e.get("ctx")), e["dport"]))
            elif e.get("ev") == "send" and "sport" in e:
                first_send.setdefault((e["sport"], e["dport"]), (e["sk"], e["ts"]))
        got = {}
        for l in open(os.path.join(rd, "requests.jsonl")):
            if l.startswith("{"):
                r = json.loads(l)
                got[r["path"].strip("/")] = r
        for l in open(os.path.join(rd, "policy_events.jsonl")):
            if l.startswith('{"ev":"decision"'):
                d = json.loads(l)
                if d["verdict"] == "deny":
                    out[(exp, ps, "denial:" + d.get("kind", "connect"), "-", cls.get(d["ctx"], "-"), "forbidden"
                         if d["dport"] not in allow.get(d["ctx"], set()) else "permitted")] += 1
        for l in open(os.path.join(rd, "ops.jsonl")):
            if not l.startswith("{"):
                continue
            o = json.loads(l)
            s, dp = o["exec_id"], o["dport"]
            perm = "permitted" if dp in allow[s] else "forbidden"
            r = got.get(o["op_id"])
            if not r:
                out[(exp, ps, "not_received", "-", cls[s], perm)] += 1
                continue
            sk, ts = first_send.get((r["peer_port"], dp), (None, 0))
            c = [x for x in conns.get(sk, []) if x[0] <= ts and x[2] == dp]
            op = c[-1][1] if c else "?"
            out[(exp, ps, "received", cls.get(op, "?"), cls[s], perm)] += 1
    with open(os.path.join(a.out, "reuse_matrix.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["experiment", "per_send", "outcome", "opener_class", "sender_class", "destination", "count"])
        for k in sorted(out, key=str):
            w.writerow(list(k) + [out[k]])
    print(f"reuse_matrix.csv: {len(out)} rows")


if __name__ == "__main__":
    main()
