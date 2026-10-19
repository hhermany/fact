#!/usr/bin/env python3
"""Equivalence of factd (live, with the reordering buffer, events in file order)
and the offline score (score.json, fused resolver, sorted events).

For each run: per-execution credits (C + I credited to it), ambiguous (A), and
unattributed (M) must match. Applies the same reference filter as the offline
score (planned port), only to compare the same set of connections.
Usage: python3 tests/test_factd_equiv.py campaigns/<c1> [campaigns/<c2> ...]
"""
import glob
import json
import os
import sys
from collections import Counter

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(HERE, "factd"))
from factd import Daemon, iter_lines  # noqa: E402


def check_run(rdir, reorder_ms):
    plan = json.load(open(os.path.join(rdir, "plan.json")))
    reg = json.load(open(os.path.join(rdir, "registry.json")))
    sc = json.load(open(os.path.join(rdir, "score.json")))["resolvers"]["fused"]
    dmap = {int(k) for k in plan["dport_map"]}
    listen = plan["listen_addr"]
    recs = []
    d = Daemon(reg, reorder_ns=int(reorder_ms * 1e6), emit=recs.append,
               filt=lambda ev: ev["daddr"] == listen and ev["dport"] in dmap)
    for ev in iter_lines(open(os.path.join(rdir, "events.jsonl"))):
        d.push(ev)
    d.drain()
    summ = recs[-1]
    live = {e: c.get("connections", 0) for e, c in summ["exec"].items()}
    offl = {e: v["credited_ok"] + v["credited_wrong"] for e, v in sc["accounting"].items()}
    offl = {e: n for e, n in offl.items() if n}
    unc = summ["uncredited"]
    same = (live == offl and unc.get("ambiguous", 0) == sc["A"] and unc.get("unattributed", 0) == sc["M"])
    return same, live, offl, unc, (sc["A"], sc["M"])


def main():
    reorder = float(os.environ.get("REORDER_MS", "100"))
    tot, bad = 0, []
    for c in sys.argv[1:]:
        man = os.path.join(c, "manifest.json")
        if os.path.exists(man) and json.load(open(man)).get("runs_failed", 0):
            print("skipped (campaign with failed runs):", c)
            continue
        for rdir in sorted(glob.glob(os.path.join(c, "runs", "*"))):
            if not os.path.exists(os.path.join(rdir, "score.json")):
                continue
            ok, live, offl, unc, am = check_run(rdir, reorder)
            tot += 1
            if not ok:
                bad.append((rdir, live, offl, unc, am))
    print(f"factd vs offline: {tot - len(bad)}/{tot} equivalent runs (reordering {reorder} ms)")
    for b in bad[:5]:
        print("DIVERGE", b)
    out = os.environ.get("EQUIV_OUT")
    if out:
        json.dump({"runs": tot, "equivalent": tot - len(bad), "reorder_ms": reorder,
                   "campaigns": [os.path.basename(c.rstrip("/")) for c in sys.argv[1:]]},
                  open(out, "w"), indent=1)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
