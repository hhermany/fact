#!/usr/bin/env python3
"""Projects the number of repetitions N per cell from a pilot (Hoefler & Belli 2015):
N = ceil((t * s / (e * mean))^2), with t from the pilot (df = n-1) and e the target
relative precision.

Per-run metric (read from analysis/runs.csv):
  E1: I/N of the 'context' resolver in cells with p > 0 (the only one with variability
      in the pilot; the others are deterministic and reported as counts).
  E2: capture (captured/attempted) and I/N of 'fused'.
  E3: connect latency p50 and p99 and throughput, per (instr, markers), from analysis/overhead.csv.
Cells with standard deviation 0 are reported as 'deterministic' (minimum N = pilot_n).
The final choice of N is a human decision and goes into workflow/config.yaml.

Usage: python3 size_n.py analysis/runs.csv --experiment E1 --label pilot \
        --target 0.05 --output analysis/n_projected_E1.json
"""
import argparse
import csv
import json
import math
import statistics as st
from collections import defaultdict

T975 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("runs_csv")
    ap.add_argument("--experiment", required=True)
    ap.add_argument("--label", default="pilot")
    ap.add_argument("--target", type=float, default=0.05)
    ap.add_argument("--output")
    a = ap.parse_args()

    cells = defaultdict(list)
    if a.experiment == "E3":   # overhead: reads analysis/overhead.csv next to runs.csv
        import os
        ovh = os.path.join(os.path.dirname(os.path.abspath(a.runs_csv)), "overhead.csv")
        for r in csv.DictReader(open(ovh)):
            if r["label"] != a.label:
                continue
            key = (r["instr"], r["markers"])
            for m in ("p50_ns", "p99_ns", "throughput_cps"):
                cells[key + (m,)].append(float(r[m]))
    for r in (csv.DictReader(open(a.runs_csv)) if a.experiment != "E3" else []):
        if r["experiment"] != a.experiment or r["label"] != a.label:
            continue
        key_base = (r["cond"], r["wrong_label"], r["mode"], r["execs"], r["jitter"])
        n = int(r["N"]) or 1
        if a.experiment == "E1" and r["resolver"] == "context" and float(r["wrong_label"]) > 0:
            cells[key_base + ("context I/N",)].append(int(r["I"]) / n)
        if a.experiment != "E1" and r["resolver"] == "fused":
            cells[key_base + ("capture",)].append(int(r["captured"]) / max(int(r["attempted"]), 1))
            cells[key_base + ("fused I/N",)].append(int(r["I"]) / n)

    out = []
    for key, xs in sorted(cells.items()):
        k = len(xs)
        m = st.mean(xs)
        s = st.stdev(xs) if k > 1 else 0.0
        if s == 0:
            proj, note = k, "deterministic in the pilot"
        elif m == 0:
            proj, note = None, "mean 0 with variance: relative precision undefined (use absolute)"
        else:
            t = T975.get(k - 1, 1.96)
            proj, note = math.ceil((t * s / (a.target * m)) ** 2), ""
        out.append({"cell": list(key[:-1]), "metric": key[-1], "pilot_n": k, "mean": m, "sd": s,
                    "n_projected": proj, "note": note})
        print(f"{key}: n={k} mean={m:.4f} sd={s:.4f} -> N={proj} {note}")
    if a.output:
        json.dump({"experiment": a.experiment, "target": a.target, "cells": out}, open(a.output, "w"), indent=1)


if __name__ == "__main__":
    main()
