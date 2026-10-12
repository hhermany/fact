#!/usr/bin/env python3
"""Projeta o N de repetições por célula a partir de um piloto (Hoefler & Belli 2015),
mesma lógica do dimensionar_n.py do CMP223: N = ceil((t * s / (e * média))^2),
com t do piloto (df = n-1) e e = precisão relativa alvo.

Métrica por rodada (lida de analysis/runs.csv):
  E1: I/N do resolver 'context' em células com p > 0 (a única com variabilidade
      no piloto; as demais são determinísticas e reportadas como contagens).
  E2: captura (captured/attempted) e I/N do 'fused'.
  E3: p50, p99 de latência de connect e vazão, por (instr, markers), de analysis/overhead.csv.
Células com desvio padrão 0 são reportadas como 'determinística' (N mínimo = pilot_n).
A decisão final de N é humana e vai para workflow/config.yaml.

Uso: python3 dimensionar_n.py analysis/runs.csv --experiment E1 --label pilot \
        --target 0.05 --output analysis/n_projetado_E1.json
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
    if a.experiment == "E3":   # overhead: lê analysis/overhead.csv ao lado de runs.csv
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
            cells[key_base + ("captura",)].append(int(r["captured"]) / max(int(r["attempted"]), 1))
            cells[key_base + ("fused I/N",)].append(int(r["I"]) / n)

    out = []
    for key, xs in sorted(cells.items()):
        k = len(xs)
        m = st.mean(xs)
        s = st.stdev(xs) if k > 1 else 0.0
        if s == 0:
            proj, note = k, "determinística no piloto"
        elif m == 0:
            proj, note = None, "média 0 com variância: precisão relativa indefinida (usar absoluta)"
        else:
            t = T975.get(k - 1, 1.96)
            proj, note = math.ceil((t * s / (a.target * m)) ** 2), ""
        out.append({"cell": list(key[:-1]), "metric": key[-1], "pilot_n": k, "mean": m, "sd": s,
                    "n_projetado": proj, "nota": note})
        print(f"{key}: n={k} média={m:.4f} dp={s:.4f} -> N={proj} {note}")
    if a.output:
        json.dump({"experiment": a.experiment, "target": a.target, "cells": out}, open(a.output, "w"), indent=1)


if __name__ == "__main__":
    main()
