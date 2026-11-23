#!/usr/bin/env python3
"""E7net: connections to a planned port at another loopback address (127.0.1.1). score.json leaves them out
because its reference is keyed to the listen address; this scores them with the same fused resolver and the
same port-owner reference as analysis/score.py.
Usage: e7net_other_addr.py [--campaigns campaigns] [--label confirmatory] -> analysis/output/E7net_other_addr.json"""
import argparse, glob, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from score import load_jsonl
from resolvers import World, strip_reference_fields, resolve_fused, check_independence
ap = argparse.ArgumentParser(); ap.add_argument("--campaigns", default="campaigns")
ap.add_argument("--label", default="confirmatory"); ap.add_argument("--out", default="analysis/output"); a = ap.parse_args()
check_independence()
tot = {"N": 0, "C": 0, "A": 0, "M": 0, "I": 0}
rows = []
for man in sorted(glob.glob(os.path.join(a.campaigns, f"*-E7net-{a.label}-*", "manifest.json"))):
    cd = os.path.dirname(man)
    for r in json.load(open(man))["runs"]:
        if r.get("status") != "OK":
            continue
        rd = os.path.join(cd, "runs", r["run_id"])
        plan = json.load(open(os.path.join(rd, "plan.json")))
        reg = json.load(open(os.path.join(rd, "registry.json")))
        dmap = {int(k): v for k, v in plan["dport_map"].items()}
        listen = plan.get("listen_addr") or "127.0.0.1"
        w = World(roots={int(k): set(v) for k, v in reg["roots"].items()},
                  cgroups={int(k): set(v) for k, v in reg["cgroups"].items()})
        events, _ = load_jsonl(os.path.join(rd, "events.jsonl"))
        for ev in sorted(events, key=lambda e: e.get("ts", 0)):
            if ev.get("ev") == "fork":
                w.parent[ev["ctid"]] = ev["ptid"]
            elif ev.get("ev") == "connect" and ev.get("dport") in dmap and ev.get("daddr") != listen:
                own = dmap[ev["dport"]]
                ref = own[0] if isinstance(own, list) else own
                out = resolve_fused(strip_reference_fields(ev), w)
                cat = ("C" if ref in out else "I") if len(out) == 1 else ("A" if out else "M")
                tot["N"] += 1
                tot[cat] += 1
                rows.append({"campaign": os.path.basename(cd), "run": r["run_id"], "daddr": ev["daddr"],
                             "dport": ev["dport"], "reference": ref, "fused": sorted(out), "outcome": cat})
os.makedirs(a.out, exist_ok=True)
json.dump({"total": tot, "connections": rows}, open(os.path.join(a.out, "E7net_other_addr.json"), "w"), indent=1)
for x in rows:
    print(x["campaign"], x["run"], x["daddr"], x["dport"], x["reference"], x["fused"], x["outcome"])
print("TOTAL", json.dumps(tot))
