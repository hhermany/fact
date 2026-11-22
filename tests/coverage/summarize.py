#!/usr/bin/env python3
"""Summarizes a coverage run (tests/coverage/run.sh): per test, the return value, whether the
destination received its tag, and whether that is what the policy prescribes; the bytes the
kernel charged to each identity against the bytes the destination received from it; the
collector's IPv6 events; and the compilation of every collector script.
Usage: summarize.py RUN_DIR OUT_JSON"""
import collections
import json
import sys

d, out = sys.argv[1], sys.argv[2]
got = collections.defaultdict(list)
for l in open(f"{d}/dest.jsonl"):
    r = json.loads(l)
    got[r["tag"]].append(r["listener"])
tests = json.load(open(f"{d}/client.json"))
for l in open(f"{d}/uring.jsonl"):
    if l.startswith("{"):
        r = json.loads(l)
        tests.append({"test": r["test"], "ret": r["res"], "errno": 0 if r["res"] >= 0 else -r["res"]})
rows, ok = [], True
for t in tests:
    name = t["test"]
    # A's sends are permitted, except io_uring work deferred to the io-wq worker, which carries no
    # credential and falls to the default action (deny); B's and unlabeled sends are forbidden
    expect = "delivered" if name.startswith(("A_", "U_A_send_inline")) else "blocked"
    seen = "delivered" if got.get(name) else "blocked"
    rows.append({"test": name, "ret": t["ret"], "errno": t["errno"], "dest": got.get(name, []),
                 "expected": expect, "observed": seen, "pass": expect == seen})
    ok &= expect == seen
usage = json.load(open(f"{d}/usage.json"))
recv = collections.Counter()
for tag, ls in got.items():
    recv["A" if tag.startswith(("A_", "U_A")) else "other"] += (len(tag) + 1) * len(ls)
ev = [json.loads(l) for l in open(f"{d}/events.jsonl") if l.startswith("{")]
v6 = [{"ev": e["ev"], "proto": e.get("proto", "tcp"), "daddr": e["daddr"], "dport": e["dport"],
       "ctx": e["ctx"].rsplit("/", 1)[-1]} for e in ev if ":" in str(e.get("daddr", ""))]
dry = {}
for l in open(f"{d}/dryrun.txt"):
    p = l.split()
    if len(p) == 2 and p[0].startswith("collector/"):
        dry[p[0]] = int(p[1])
res = {"all_pass": ok, "tests": rows,
       "charged_bytes": {k: v["bytes"] for k, v in usage.items()},
       "received_bytes": dict(recv),
       "accounting_exact": usage.get("A", {}).get("bytes") == recv["A"] and usage.get("B", {}).get("bytes", 0) == 0,
       "collector_ipv6_events": v6, "collector_dry_run_rc": dry}
json.dump(res, open(out, "w"), indent=1)
print(f"coverage: all_pass={ok} accounting_exact={res['accounting_exact']} "
      f"tests={len(rows)} ipv6_events={len(v6)} dry_run={dry}")
