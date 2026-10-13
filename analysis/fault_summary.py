#!/usr/bin/env python3
"""Summary of the fault-injection campaigns (E5f, E6f, E6n, E7f).

For each cell: injected mislabel fraction, fused-resolver outcomes (C/A/M/I),
mislabeled connections that the fused resolver flagged (A) or credited wrongly
(I), and, with the policy, false allows (FA) and false denies (FD), split by
whether the connection was mislabeled.

Usage: python3 analysis/fault_summary.py CAMPAIGN_DIR [...] [--csv OUT]
"""
import argparse
import csv
import json
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from resolvers import RESOLVERS, World, strip_reference_fields  # noqa: E402


def load_jsonl(path):
    out = []
    if os.path.exists(path):
        for line in open(path):
            if line.startswith("{"):
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return out


def run_summary(rd):
    plan = json.load(open(os.path.join(rd, "plan.json")))
    reg = json.load(open(os.path.join(rd, "registry.json")))
    ops = load_jsonl(os.path.join(rd, "ops.jsonl"))
    if plan.get("mode") in ("mcp", "agent"):
        mislabeled = {o["dport"] for o in ops if "dport" in o and o.get("label", o["exec_id"]) != o["exec_id"]}
    else:   # workload.py: label recorded as the marker the operation emitted
        mislabeled = {o["dport"] for o in ops if "dport" in o and o.get("label") not in (None, o.get("exec_id"))}
    w = World(roots={int(k): set(v) for k, v in reg["roots"].items()},
              cgroups={int(k): set(v) for k, v in reg["cgroups"].items()})
    dmap = {int(k): v[0] for k, v in plan["dport_map"].items()}
    c = Counter()
    for ev in sorted(load_jsonl(os.path.join(rd, "events.jsonl")), key=lambda e: e.get("ts", 0)):
        if ev.get("ev") == "fork":
            w.parent[ev["ctid"]] = ev["ptid"]
        elif ev.get("ev") == "connect" and ev.get("daddr") == plan["listen_addr"] and ev.get("dport") in dmap:
            ref = dmap[ev["dport"]]
            out = RESOLVERS["fused"](strip_reference_fields(ev), w)
            cat = ("C" if ref in out else "I") if len(out) == 1 else ("A" if out else "M")
            c[cat] += 1
            if ev["dport"] in mislabeled:
                c["mis_" + cat] += 1
            c["N"] += 1
    c["mislabeled"] = len(mislabeled)
    pol = {}
    pevents = load_jsonl(os.path.join(rd, "policy_events.jsonl"))
    if "policy" in plan and pevents:
        allow = {e: set(v) for e, v in plan["policy"]["allow"].items()}
        first = {}
        for ev in pevents:
            if ev.get("ev") == "ready":
                pol["lineage_mode"] = ev.get("lineage", 0)
            if ev.get("ev") == "decision" and ev["dport"] in dmap and ev["dport"] not in first:
                first[ev["dport"]] = ev
                pol["conflict"] = pol.get("conflict", 0) + ev.get("conflict", 0)
                pol["from_lineage"] = pol.get("from_lineage", 0) + ev.get("from_lineage", 0)
        for port, owner in dmap.items():
            exp = "allow" if port in allow[owner] else "deny"
            ev = first.get(port)
            k = "ND" if ev is None else ("T" if ev["verdict"] == exp else "F") + ("A" if ev["verdict"] == "allow" else "D")
            pol[k] = pol.get(k, 0) + 1
            if port in mislabeled:
                pol["mis_" + k] = pol.get("mis_" + k, 0) + 1
    return plan, c, pol


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("campaigns", nargs="+")
    ap.add_argument("--csv")
    a = ap.parse_args()
    cells = defaultdict(lambda: {"runs": 0, "att": Counter(), "pol": Counter()})
    rows = []
    for camp in a.campaigns:
        man = json.load(open(os.path.join(camp, "manifest.json")))
        for run in sorted(os.listdir(os.path.join(camp, "runs"))):
            rd = os.path.join(camp, "runs", run)
            if not os.path.isdir(rd) or not os.path.exists(os.path.join(rd, "events.jsonl")):
                continue
            plan, c, pol = run_summary(rd)
            key = (man["experiment"] + (f"/L{pol['lineage_mode']}" if pol.get("lineage_mode") else ""), plan["cond"], (plan.get("tool") or plan.get("mode")) + ("/" + plan["binding_mode"] if plan.get("binding_mode") else ""), plan["execs"], plan.get("wrong_label"))
            cells[key]["runs"] += 1
            cells[key]["att"].update(c)
            cells[key]["pol"].update({k: v for k, v in pol.items() if k != "lineage_mode"})
            rows.append(dict(campaign=man["campaign_id"], run=run, exp=man["experiment"], cond=plan["cond"],
                             tool=key[2], K=plan["execs"], p=plan.get("wrong_label"), **c,
                             **{"pol_" + k: v for k, v in pol.items()}))
    print(f"{'exp':8} {'cond':5} {'tool/mode':14} {'K':>2} {'p':>5} {'runs':>4} {'N':>5} {'mis':>4} "
          f"{'C':>5} {'A':>4} {'I':>4} {'misA':>4} {'misI':>4} | {'FA':>3} {'FD':>3} {'misFA':>5} {'misFD':>5} {'ND':>3} {'conf':>4} {'lin':>4}")
    for k in sorted(cells, key=lambda x: tuple(map(str, x))):
        v = cells[k]
        t, p = v["att"], v["pol"]
        print(f"{k[0]:8} {k[1]:5} {str(k[2]):14} {k[3]:>2} {k[4]:>5.2f} {v['runs']:>4} {t['N']:>5} {t['mislabeled']:>4} "
              f"{t['C']:>5} {t['A']:>4} {t['I']:>4} {t['mis_A']:>4} {t['mis_I']:>4} | "
              f"{p.get('FA', 0):>3} {p.get('FD', 0):>3} {p.get('mis_FA', 0):>5} {p.get('mis_FD', 0):>5} {p.get('ND', 0):>3} {p.get('conflict', 0):>4} {p.get('from_lineage', 0):>4}")
    if a.csv:
        keys = sorted({k for r in rows for k in r})
        with open(a.csv, "w", newline="") as f:
            wr = csv.DictWriter(f, fieldnames=keys)
            wr.writeheader()
            wr.writerows(rows)


if __name__ == "__main__":
    main()
