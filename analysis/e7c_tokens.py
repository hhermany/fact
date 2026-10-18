#!/usr/bin/env python3
"""Consumo de tokens e custo do E7c (agentes com modelos da Anthropic via API).

Lê as campanhas E7c (rótulo dado) com manifest e, por célula (modelo, K), soma os
tokens de entrada e saída que a própria API informou em cada chamada
(e7_summary.json, campos input_tokens/output_tokens de cada agente). O custo usa a
tabela de preços da Anthropic (US$ por milhão de tokens), consultada em 18/10/2026
em https://platform.claude.com/docs/en/about-claude/pricing.
Escreve analysis/output/E7c_tokens.csv.

Uso: e7c_tokens.py [--label confirmatory] [--out analysis/output]
"""
import argparse
import collections
import csv
import glob
import json
import os

PRICE = {"claude-opus-5-5": (4.00, 20.00), "claude-haiku-5-5": (0.10, 0.50)}   # (entrada, saída)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", default="confirmatory")
    ap.add_argument("--campaigns", default="campaigns")
    ap.add_argument("--out", default="analysis/output")
    a = ap.parse_args()
    cells = collections.defaultdict(collections.Counter)
    for man in sorted(glob.glob(os.path.join(a.campaigns, f"*-E7c-{a.label}-*", "manifest.json"))):
        m = json.load(open(man))
        cdir = os.path.dirname(man)
        for r in m["runs"]:
            if r.get("status") != "OK":
                continue
            s = json.load(open(os.path.join(cdir, "runs", r["run_id"], "e7_summary.json")))
            key = (s["model"], len(s["agents"]))
            c = cells[key]
            c["runs"] += 1
            for ag in s["agents"]:
                c["agents"] += 1
                c["llm_calls"] += ag.get("steps", 0)
                c["input_tokens"] += ag.get("input_tokens", 0)
                c["output_tokens"] += ag.get("output_tokens", 0)
                c["api_retries"] += ag.get("api_retries", 0)
    os.makedirs(a.out, exist_ok=True)
    cols = ["model", "execs", "runs", "agents", "llm_calls", "input_tokens", "output_tokens", "api_retries",
            "in_per_agent", "out_per_agent", "usd"]
    with open(os.path.join(a.out, "E7c_tokens.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for (model, k), c in sorted(cells.items()):
            pi, po = PRICE[model]
            usd = (c["input_tokens"] * pi + c["output_tokens"] * po) / 1e6
            w.writerow([model, k, c["runs"], c["agents"], c["llm_calls"], c["input_tokens"], c["output_tokens"],
                        c["api_retries"], round(c["input_tokens"] / c["agents"], 1),
                        round(c["output_tokens"] / c["agents"], 1), round(usd, 4)])
            print(model, k, dict(c), f"US$ {usd:.4f}")


if __name__ == "__main__":
    main()
