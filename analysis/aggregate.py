#!/usr/bin/env python3
"""Agrega várias rodadas (score.json) por condição × taxa de rótulo errado × resolver.

A unidade de repetição é a rodada: médias e IC 95% (t de Student) são calculados
sobre as proporções de cada rodada, nunca sobre eventos agrupados.

Resumo rápido no console (a análise oficial é em R a partir de collect_runs.py).
Uso: python3 aggregate.py <dir com rodadas>/ [--csv saida.csv]
"""
import argparse
import csv
import glob
import json
import math
import os
import statistics as st
from collections import defaultdict

T95 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262,
       10: 2.228, 14: 2.145, 19: 2.093, 29: 2.045}


def t95(df):
    if df in T95:
        return T95[df]
    return 1.96 if df > 29 else T95[max(k for k in T95 if k <= df)]


def ci(xs):
    xs = [x for x in xs if x is not None]
    if not xs:
        return None, None, 0
    m = st.mean(xs)
    if len(xs) < 2:
        return m, None, len(xs)
    return m, t95(len(xs) - 1) * st.stdev(xs) / math.sqrt(len(xs)), len(xs)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("runs_dir")
    ap.add_argument("--csv")
    a = ap.parse_args()

    groups = defaultdict(lambda: defaultdict(list))   # (cond, p, resolver) -> metric -> [valores por rodada]
    capture = defaultdict(lambda: [0, 0, 0])          # (cond, p) -> [tentadas, capturadas, rodadas]
    for path in sorted(glob.glob(os.path.join(a.runs_dir, "*", "score.json"))):
        r = json.load(open(path))
        plan = json.load(open(os.path.join(os.path.dirname(path), "plan.json")))
        key = (r["cond"], plan.get("wrong_label", 0.0), plan.get("mode", "?"), plan.get("execs", 2))
        cap = r["capture"]
        capture[key][0] += cap["attempted"]
        capture[key][1] += cap["captured"]
        capture[key][2] += 1
        for name, v in r["resolvers"].items():
            g = groups[key + (name,)]
            n = v["N"]
            for m in ("C", "A", "M", "I"):
                g[m + "/N"].append(v[m] / n if n else None)
            wrong = sum(d["credited_wrong"] for d in v["accounting"].values())
            g["wrong_credit/N"].append(wrong / n if n else None)

    rows = []
    print(f"{'cond':4} {'p':>5} {'mode':7} {'K':>3} {'resolver':8} {'runs':>4}  {'C/N':>15} {'A/N':>15} {'M/N':>15} {'I/N':>15}")
    for key in sorted(groups):
        cond, p, mode, kexec, name = key
        g = groups[key]
        cells, row = [], {"cond": cond, "p": p, "mode": mode, "execs": kexec, "resolver": name}
        for m in ("C/N", "A/N", "M/N", "I/N", "wrong_credit/N"):
            mean, half, nruns = ci(g[m])
            row[m + "_mean"], row[m + "_ci95"], row["runs"] = mean, half, nruns
            if m != "wrong_credit/N":
                cells.append("     -        " if mean is None else
                             f"{mean:.3f}±{half:.3f}" if half is not None else f"{mean:.3f}")
        rows.append(row)
        print(f"{cond:4} {p:>5} {mode:7} {kexec:>3} {name:8} {row['runs']:>4}  " + " ".join(f"{c:>15}" for c in cells))
    print("\ncaptura (capturadas/tentadas) por condição:")
    for key in sorted(capture):
        t, c, n = capture[key]
        print(f"  {key[0]} p={key[1]} mode={key[2]} K={key[3]}: {c}/{t} em {n} rodadas")
    if a.csv:
        with open(a.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)


if __name__ == "__main__":
    main()
