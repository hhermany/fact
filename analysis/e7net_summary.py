#!/usr/bin/env python3
"""E7net (network-operations incident with real agents): attribution, per-site policy, and task outcome.
Usage: e7net_summary.py [--campaigns campaigns] [--label confirmatory] -> analysis/output/E7net_summary.json"""
import argparse, glob, json, os
from collections import defaultdict
ap = argparse.ArgumentParser(); ap.add_argument("--campaigns", default="campaigns")
ap.add_argument("--label", default="confirmatory"); ap.add_argument("--out", default="analysis/output"); a = ap.parse_args()
cells = defaultdict(lambda: defaultdict(int))
for man in sorted(glob.glob(os.path.join(a.campaigns, f"*-E7net-{a.label}-*", "manifest.json"))):
    cd = os.path.dirname(man)
    for r in json.load(open(man))["runs"]:
        if r.get("status") != "OK":
            continue
        rd, p = os.path.join(cd, "runs", r["run_id"]), r["params"]
        k = cells[f"{p['model']}-K{p['execs']}"]; k["runs"] += 1
        f = lambda n: json.load(open(os.path.join(rd, n))) if os.path.exists(os.path.join(rd, n)) else {}
        fu = f("score.json").get("resolvers", {}).get("fused", {})
        for x in ("N", "C", "A", "M", "I"):
            k["conn_" + x] += fu.get(x, 0)
        ps = f("policy_score.json")
        for x in ("N", "TA", "TD", "FA", "FD"):
            k["pol_" + x] += ps.get(x, 0)
        # Connections to a planned port at another loopback address (127.0.1.1, written by the model in
        # one qwen2.5:3b run per boot): the reference is keyed to the listen address, so score.json leaves
        # them out. They are counted here, with whether their label is the port's owner.
        pl, ef = f("plan.json"), os.path.join(rd, "events.jsonl")
        dm = {int(x): v for x, v in (pl.get("dport_map") or {}).items()}
        la = pl.get("listen_addr") or "127.0.0.1"
        k["conn_other_addr"] += 0
        k["conn_other_addr_label_ok"] += 0
        if os.path.exists(ef):
            for line in open(ef):
                if '"connect"' not in line:
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if e.get("ev") != "connect" or e.get("dport") not in dm or e.get("daddr") == la:
                    continue
                own = dm[e["dport"]]
                own = own[0] if isinstance(own, list) else own
                k["conn_other_addr"] += 1
                k["conn_other_addr_label_ok"] += int((e.get("ctx") or "").rsplit("/", 1)[-1] == own)
        s = f("e7_summary.json")
        for ag in s.get("agents", []):
            k["agents"] += 1
            fin = (ag.get("final") or "").lower()
            k["agents_final"] += int(bool(fin))
            k["agents_diag_congestion"] += int(any(w in fin for w in ("congest", "saturat", "97", "utiliz", "discard")))
os.makedirs(a.out, exist_ok=True)
json.dump(cells, open(os.path.join(a.out, "E7net_summary.json"), "w"), indent=1, default=dict)
for c, v in sorted(cells.items()):
    print(c, json.dumps(v, default=dict))
