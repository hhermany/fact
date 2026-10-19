#!/usr/bin/env python3
"""AgentProvenance executed for real vs FACT, on the same rounds.

Reads every confirmatory (or given label) campaign of the experiment under
campaigns/ and, per cell, pools the connections: AgentProvenance's real
attribution (agentprov/score.json) and FACT's fused resolver on the same rounds
(score.json). Cells: (tool, K) for E5ap, the shared MCP server; (structure,
operation mode, K) for E1ap, the synthetic executions with their own process
trees and cgroups (N0), a shared cgroup (N1), or a shared worker (N3).
Writes analysis/output/<experiment>_agentprov.csv.

Usage: agentprov_table.py [--experiment E5ap|E1ap] [--label confirmatory] [--out analysis/output]
"""
import argparse
import collections
import csv
import glob
import json
import os


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--experiment", default="E5ap", choices=["E5ap", "E1ap"])
    ap.add_argument("--label", default="confirmatory")
    ap.add_argument("--campaigns", default="campaigns")
    ap.add_argument("--out", default="analysis/output")
    a = ap.parse_args()
    cells = collections.defaultdict(lambda: collections.Counter())
    nruns = collections.Counter()
    for man in sorted(glob.glob(os.path.join(a.campaigns, f"*-{a.experiment}-{a.label}-*", "manifest.json"))):
        m = json.load(open(man))
        cdir = os.path.dirname(man)
        for r in m["runs"]:
            if r.get("status") != "OK":
                continue
            rdir = os.path.join(cdir, "runs", r["run_id"])
            p = r["params"]
            key = ((p["tool"],) if a.experiment == "E5ap" else (p["cond"], p["mode"])) + (int(p["execs"]),)
            aps = json.load(open(os.path.join(rdir, "agentprov", "score.json")))["summary"]
            fused = json.load(open(os.path.join(rdir, "score.json")))["resolvers"]["fused"]
            c = cells[key]
            for k in "CIAM":
                c["ap_" + k] += aps[k]
                c["an_" + k] += fused[k]
            c["ap_N"] += aps["N"]
            c["an_N"] += fused["N"]
            c["ap_same_op"] += aps["same_op"]
            nruns[key] += 1
    os.makedirs(a.out, exist_ok=True)
    path = os.path.join(a.out, f"{a.experiment}_agentprov.csv")
    keycols = ["tool", "execs"] if a.experiment == "E5ap" else ["cond", "mode", "execs"]
    order = {"sync": 0, "thread": 1, "subproc": 2, "async": 3, "N0": 0, "N1": 1, "N2": 2, "N3": 3, "inproc": 0}
    cols = keycols + ["runs", "system", "N", "C", "I", "A", "M", "C_N", "I_N", "same_op"]
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for key, c in sorted(cells.items(), key=lambda x: tuple(order.get(v, v) for v in x[0])):
            for sysname, pre in (("AgentProvenance", "ap_"), ("FACT", "an_")):
                n = c[pre + "N"]
                w.writerow(list(key) + [nruns[key], sysname, n, c[pre + "C"], c[pre + "I"], c[pre + "A"], c[pre + "M"],
                            round(c[pre + "C"] / n, 4) if n else "", round(c[pre + "I"] / n, 4) if n else "",
                            c["ap_same_op"] if pre == "ap_" else ""])
    print(open(path).read())


if __name__ == "__main__":
    main()
