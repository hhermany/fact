#!/usr/bin/env python3
"""E7r: compares each run replayed without a model with the recorded run it repeats.

For each OK run of the E7r campaigns (given label), reads plan.json (replay_of) and
compares it with the original recording (E7c/E7o):
- the tool calls (tool, arguments, label, in each agent's order);
- the outcome of the fused resolver (N, C, A, M, I);
- the policy decisions (N, TA, TD, FA, FD, ND).
Writes analysis/output/E7r_replay.csv per cell (model, K) and prints the total.

Usage: replay_compare.py [--label confirmatory] [--campaigns campaigns] [--originals campaigns] [--out analysis/output]
"""
import argparse
import collections
import csv
import glob
import json
import os


def calls(rdir):
    by = collections.defaultdict(list)
    for line in open(os.path.join(rdir, "ops.jsonl")):
        o = json.loads(line)
        by[o["exec_id"]].append((o["t_start"], o["tool"], json.dumps(o["args"], sort_keys=True), o.get("label")))
    return {e: [x[1:] for x in sorted(v)] for e, v in by.items()}


def outcome(rdir):
    f = json.load(open(os.path.join(rdir, "score.json")))["resolvers"]["fused"]
    p = json.load(open(os.path.join(rdir, "policy_score.json")))
    return {**{k: f[k] for k in ("N", "C", "A", "M", "I")}, **{"p" + k: p[k] for k in ("N", "TA", "TD", "FA", "FD", "ND")}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", default="confirmatory")
    ap.add_argument("--campaigns", default="campaigns")
    ap.add_argument("--originals", default=None, help="directory of the recorded E7c/E7o campaigns (default: --campaigns)")
    ap.add_argument("--out", default="analysis/output")
    a = ap.parse_args()
    cells = collections.defaultdict(collections.Counter)
    for man in sorted(glob.glob(os.path.join(a.campaigns, f"*-E7r-{a.label}-*", "manifest.json"))):
        m = json.load(open(man))
        cdir = os.path.dirname(man)
        for r in m["runs"]:
            if r.get("status") != "OK":
                continue
            rdir = os.path.join(cdir, "runs", r["run_id"])
            plan = json.load(open(os.path.join(rdir, "plan.json")))
            parts = plan["replay_of"].rstrip("/").split("/")
            orig = os.path.join(a.originals or a.campaigns, parts[-3], parts[-2], parts[-1])   # <campaign>/runs/<run>
            new, old = outcome(rdir), outcome(orig)
            c = cells[(plan["model"], plan["execs"])]
            c["runs"] += 1
            c["same_calls"] += calls(rdir) == calls(orig)
            c["same_outcome"] += new == old
            for k, v in new.items():
                c[k] += v
    os.makedirs(a.out, exist_ok=True)
    cols = ["model", "execs", "runs", "same_calls", "same_outcome", "N", "C", "A", "M", "I",
            "pN", "pTA", "pTD", "pFA", "pFD", "pND"]
    with open(os.path.join(a.out, "E7r_replay.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for (model, k), c in sorted(cells.items()):
            w.writerow([model, k] + [c[x] for x in cols[2:]])
    tot = sum(cells.values(), collections.Counter())
    print(f"E7r: {tot['runs']} runs; same calls {tot['same_calls']}; same outcome {tot['same_outcome']}; "
          f"connections {tot['N']} (I={tot['I']}, A={tot['A']}, M={tot['M']}); decisions {tot['pN']} "
          f"(FA={tot['pFA']}, FD={tot['pFD']}, ND={tot['pND']})")


if __name__ == "__main__":
    main()
