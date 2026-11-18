#!/usr/bin/env python3
"""Summarizes the OBI association test (bench/obi_assoc.py) per instrumentation, server,
tool, and K: requests whose outgoing trace ID is the owning execution's (correct), another
execution's (wrong), one no execution sent (new_trace), or absent (none).

Usage: obi_summary.py [--campaigns campaigns] [--out analysis/output]  -> OUT/obi_assoc.csv
"""
import argparse, collections, csv, glob, json, os


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--campaigns", default="campaigns")
    ap.add_argument("--out", default="analysis/output")
    a = ap.parse_args()
    cols = ("requests", "correct", "wrong", "new_trace", "none")
    tot = collections.defaultdict(lambda: collections.Counter())
    for p in glob.glob(os.path.join(a.campaigns, "obi-assoc-*", "*", "*", "obi_score.json")):
        s = json.load(open(p))
        ctrl = os.path.basename(os.path.dirname(p)).startswith("ctrl-")
        k = ("no OBI (control)" if ctrl else "OBI v1.0.0", s["mode"], s.get("tool", "async"), s["execs"])
        tot[k]["runs"] += 1
        for c in cols:
            tot[k][c] += s[c]
    os.makedirs(a.out, exist_ok=True)
    path = os.path.join(a.out, "obi_assoc.csv")
    with open(path, "w", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["instrumentation", "server", "tool", "execs", "runs", *cols])
        for k in sorted(tot, key=lambda k: (k[0] != "OBI v1.0.0", k[1], k[2], k[3])):
            w.writerow([*k, tot[k]["runs"], *(tot[k][c] for c in cols)])
    print(open(path).read(), end="")


if __name__ == "__main__":
    main()
