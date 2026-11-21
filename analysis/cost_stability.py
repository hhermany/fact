#!/usr/bin/env python3
"""Stability of the cost results (E9cost, E3send, E3, E3b, E3net, E3cred) from the per-run data.

Runs of different configurations that share a cell and a repetition index were
run in the same boot with the same seed, so they are paired: the effect is
computed per pair (relative for E9cost tool-call latency and host CPU per call,
absolute nanoseconds for E3send, E3, E3b, E3net and E3cred, plus relative for
E3net), never per connection or per send. The paper reports these paired medians. For each
effect: number of pairs, per-boot medians, the median over all pairs, its 95%
percentile-bootstrap interval over pairs (10 000 resamples, fixed seed), and the
range. Usage: cost_stability.py [--campaigns DIR] [--label confirmatory] [--out DIR]
                          [--overhead analysis/overhead.csv]
Output: OUT/cost_stability.csv
"""
import argparse
import csv
import glob
import json
import os
import random
import re
import statistics as st
from collections import defaultdict


def runs(campaigns, exp, label):
    for man in sorted(glob.glob(os.path.join(campaigns, f"*-{exp}-{label}-*", "manifest.json"))):
        cdir = os.path.dirname(man)
        for r in json.load(open(man))["runs"]:
            if r.get("status") == "OK":
                m = re.search(r"rep(\d+)", r["run_id"])
                yield os.path.basename(cdir), int(m.group(1)) if m else 0, r["params"], os.path.join(cdir, "runs", r["run_id"])


def boot_ci(xs, n=10000, seed=1):
    rnd = random.Random(seed)
    meds = sorted(st.median(rnd.choices(xs, k=len(xs))) for _ in range(n))
    return meds[int(0.025 * n)], meds[int(0.975 * n) - 1]


def summarize(name, unit, pairs):
    """pairs: list of (boot, effect)."""
    xs = [e for _, e in pairs]
    if not xs:
        return None
    by_boot = defaultdict(list)
    for b, e in pairs:
        by_boot[b].append(e)
    lo, hi = boot_ci(xs)
    boots = sorted(by_boot)
    return [name, unit, len(xs), len(boots),
            " / ".join(f"{st.median(by_boot[b]):.3g}" for b in boots),
            f"{st.median(xs):.3g}", f"{lo:.3g}", f"{hi:.3g}", f"{min(xs):.3g}", f"{max(xs):.3g}"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--campaigns", default="campaigns")
    ap.add_argument("--label", default="confirmatory")
    ap.add_argument("--out", default="analysis/output")
    ap.add_argument("--overhead", default="analysis/overhead.csv")
    a = ap.parse_args()
    rows = []

    # E9cost: every option on except budgets vs. no FACT, paired by (boot, sessions, repetition)
    cell = defaultdict(dict)
    for camp, rep, p, rd in runs(a.campaigns, "E9cost", a.label):
        s = json.load(open(os.path.join(rd, "e4_summary.json")))
        h = json.load(open(os.path.join(rd, "host_cpu.json")))
        cell[(camp, int(p["execs"]), rep)][p["fact"]] = (s["tool_ms_p50"], s["tool_ms_p99"], h["host_cpu_s"] / h["calls"])
    for k in sorted({k[1] for k in cell}):
        pr = [(c, v) for (c, kk, _), v in cell.items() if kk == k and "off" in v and "all" in v]
        for i, (nm, unit) in enumerate([("E9cost tool call p50", "%"), ("E9cost tool call p99", "%"), ("E9cost host CPU per call", "%")]):
            r = summarize(f"{nm}, K={k}", unit, [(c, 100 * (v["all"][i] / v["off"][i] - 1)) for c, v in pr])
            if r:
                rows.append(r)

    # E3send: per-send p50, paired by (boot, protocol, repetition)
    cell = defaultdict(dict)
    for camp, rep, p, rd in runs(a.campaigns, "E3send", a.label):
        cell[(camp, p["proto"], rep)][p["policy"]] = json.load(open(os.path.join(rd, "overhead.json")))["p50_ns"]
    for proto in sorted({k[1] for k in cell}):
        for pol, ref in (("send_in", "none"), ("budget", "none"), ("budget", "send_in"), ("conn", "none")):
            pr = [(c, v[pol] - v[ref]) for (c, pp, _), v in cell.items() if pp == proto and pol in v and ref in v]
            r = summarize(f"E3send {proto}: {pol} - {ref}", "ns", pr)
            if r:
                rows.append(r)

    # E3, E3b, E3net: connect() p50 per run (per-run table), paired by (boot, repetition), markers off
    if os.path.exists(a.overhead):
        cell = defaultdict(dict)
        for r in csv.DictReader(open(a.overhead)):
            if r["label"] != a.label or r["campaign_runs_failed"] != "0" or r["markers"] != "0":
                continue
            m = re.search(r"rep(\d+)", r["run_id"])
            cell[(r["experiment"], r["boot_id"], int(m.group(1)) if m else 0)][r["instr"]] = float(r["p50_ns"])
        for exp, instr in (("E3", "collector"), ("E3b", "fast"), ("E3net", "collector")):
            pr = [(b, v[instr] - v["none"]) for (e, b, _), v in cell.items() if e == exp and instr in v and "none" in v]
            for r in (summarize(f"{exp} connect p50: {instr} - none", "ns", pr),
                      summarize(f"{exp} connect p50: {instr} - none", "%",
                                [(b, 100 * (v[instr] / v["none"] - 1)) for (e, b, _), v in cell.items()
                                 if e == exp and instr in v and "none" in v])):
                if r:
                    rows.append(r)

    # E3cred: connect() and open() p50 per run, kernel-held credential (prctl) and markers (openat) vs. none,
    # paired by (boot, repetition)
    cell = defaultdict(dict)
    for camp, rep, p, rd in runs(a.campaigns, "E3cred", a.label):
        f = os.path.join(rd, "overhead.json")
        if os.path.exists(f):
            o = json.load(open(f))
            cell[(camp, rep)][o["iface"]] = (o["connect"]["p50_ns"], o["open"]["p50_ns"])
    for iface in ("prctl", "openat"):
        for i, op in enumerate(("connect", "open")):
            r = summarize(f"E3cred {op} p50: {iface} - none", "ns",
                          [(c, v[iface][i] - v["none"][i]) for (c, _), v in cell.items() if iface in v and "none" in v])
            if r:
                rows.append(r)

    os.makedirs(a.out, exist_ok=True)
    path = os.path.join(a.out, "cost_stability.csv")
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["effect", "unit", "pairs", "boots", "median_per_boot", "median", "ci95_lo", "ci95_hi", "min", "max"])
        w.writerows(rows)
    print(open(path).read())


if __name__ == "__main__":
    main()
