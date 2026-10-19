#!/usr/bin/env python3
"""AgentProvenance executed for real vs FACT, on the same E5 rounds.

Reads every confirmatory (or given label) E5ap campaign under campaigns/ and,
per cell (tool, K), pools the connections: AgentProvenance's real attribution
(agentprov/score.json) and FACT's fused resolver on the same rounds
(score.json). Writes analysis/output/E5ap_agentprov.csv.

Usage: agentprov_table.py [--label confirmatory] [--out analysis/output]
"""
import argparse
import collections
import csv
import glob
import json
import os


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", default="confirmatory")
    ap.add_argument("--campaigns", default="campaigns")
    ap.add_argument("--out", default="analysis/output")
    a = ap.parse_args()
    cells = collections.defaultdict(lambda: collections.Counter())
    nruns = collections.Counter()
    for man in sorted(glob.glob(os.path.join(a.campaigns, f"*-E5ap-{a.label}-*", "manifest.json"))):
        m = json.load(open(man))
        cdir = os.path.dirname(man)
        for r in m["runs"]:
            if r.get("status") != "OK":
                continue
            rdir = os.path.join(cdir, "runs", r["run_id"])
            p = r["params"]
            key = (p["tool"], int(p["execs"]))
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
    path = os.path.join(a.out, "E5ap_agentprov.csv")
    cols = ["tool", "execs", "runs", "system", "N", "C", "I", "A", "M", "C_N", "I_N", "same_op"]
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for (tool, k), c in sorted(cells.items(), key=lambda x: (["sync", "thread", "subproc", "async"].index(x[0][0]), x[0][1])):
            for sysname, pre in (("AgentProvenance", "ap_"), ("FACT", "an_")):
                n = c[pre + "N"]
                w.writerow([tool, k, nruns[(tool, k)], sysname, n, c[pre + "C"], c[pre + "I"], c[pre + "A"], c[pre + "M"],
                            round(c[pre + "C"] / n, 4) if n else "", round(c[pre + "I"] / n, 4) if n else "",
                            c["ap_same_op"] if pre == "ap_" else ""])
    print(open(path).read())


if __name__ == "__main__":
    main()
