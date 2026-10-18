#!/usr/bin/env python3
"""Consumo de tokens e custo dos agentes com modelos comerciais via API (E7c: Anthropic; E7o: OpenAI).

Lê as campanhas do experimento (rótulo dado) com manifest e, por célula (modelo, K), soma os
tokens de entrada e saída que a própria API informou em cada chamada
(e7_summary.json, campos input_tokens/output_tokens de cada agente). O custo usa a
tabela de preços de cada empresa (US$ por milhão de tokens), consultada em 18/10/2026
em https://platform.claude.com/docs/en/about-claude/pricing e https://developers.openai.com/api/docs/pricing.
Escreve analysis/output/<exp>_tokens.csv.

Uso: e7c_tokens.py [--exp E7c|E7o] [--label confirmatory] [--out analysis/output]
"""
import argparse
import collections
import csv
import glob
import json
import os

PRICE = {"claude-opus-5-5": (4.00, 20.00), "claude-haiku-5-5": (0.10, 0.50),     # (entrada, saída)
         "gpt-6.1-sol": (2.00, 10.00), "gpt-6-luna": (0.10, 0.50)}
# OpenAI: preços em https://developers.openai.com/api/docs/pricing (18/10/2026); o raciocínio
# conta como saída e já está em output_tokens


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", default="confirmatory")
    ap.add_argument("--exp", default="E7c", help="E7c (Anthropic) ou E7o (OpenAI)")
    ap.add_argument("--campaigns", default="campaigns")
    ap.add_argument("--out", default="analysis/output")
    a = ap.parse_args()
    cells = collections.defaultdict(collections.Counter)
    for man in sorted(glob.glob(os.path.join(a.campaigns, f"*-{a.exp}-{a.label}-*", "manifest.json"))):
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
                c["reasoning_tokens"] += ag.get("reasoning_tokens", 0)
                c["api_retries"] += ag.get("api_retries", 0)
    os.makedirs(a.out, exist_ok=True)
    cols = ["model", "execs", "runs", "agents", "llm_calls", "input_tokens", "output_tokens", "reasoning_tokens", "api_retries",
            "in_per_agent", "out_per_agent", "usd"]
    with open(os.path.join(a.out, f"{a.exp}_tokens.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for (model, k), c in sorted(cells.items()):
            pi, po = PRICE[model]
            usd = (c["input_tokens"] * pi + c["output_tokens"] * po) / 1e6
            w.writerow([model, k, c["runs"], c["agents"], c["llm_calls"], c["input_tokens"], c["output_tokens"],
                        c["reasoning_tokens"], c["api_retries"], round(c["input_tokens"] / c["agents"], 1),
                        round(c["output_tokens"] / c["agents"], 1), round(usd, 4)])
            print(model, k, dict(c), f"US$ {usd:.4f}")


if __name__ == "__main__":
    main()
