#!/usr/bin/env python3
"""Pontua uma rodada: referência independente, C/A/M/I por resolver e
contabilização de conexões por execução.

Uso:
  python3 score.py RUN_DIR [--events RUN_DIR/events.jsonl]

Arquivos esperados em RUN_DIR: events.jsonl (saída do coletor), plan.json,
registry.json, ops.jsonl. Saída: RUN_DIR/score.json e um resumo em stdout.

Definições (para eventos connect com referência válida):
  C  origem atribuída == referência
  A  conjunto de candidatos com > 1 elemento        (A_in: contém a referência)
  M  conjunto vazio
  I  origem atribuída != referência
Eventos connect sem referência (porta fora do plano) são contados e excluídos,
nunca descartados em silêncio. Operações do plano sem connect capturado
contam como perda de captura.
"""
import argparse
import json
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from resolvers import RESOLVERS, World, check_independence, strip_reference_fields  # noqa: E402


def load_jsonl(path):
    out, bad = [], 0
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                bad += 1
    return out, bad


def score(run_dir, events_path=None):
    check_independence()
    events, bad_lines = load_jsonl(events_path or os.path.join(run_dir, "events.jsonl"))
    plan = json.load(open(os.path.join(run_dir, "plan.json")))
    reg = json.load(open(os.path.join(run_dir, "registry.json")))
    ops, _ = load_jsonl(os.path.join(run_dir, "ops.jsonl"))

    w = World(roots={int(k): set(v) for k, v in reg["roots"].items()},
              cgroups={int(k): set(v) for k, v in reg["cgroups"].items()})
    dmap = {int(k): v for k, v in plan["dport_map"].items()}
    listen = plan["listen_addr"]

    counts = {r: Counter() for r in RESOLVERS}
    acct = {r: defaultdict(Counter) for r in RESOLVERS}   # resolver -> exec -> {C,A,M,I}
    ref_acct = Counter()
    excluded = Counter()
    seen_ports = Counter()
    state_by_sk = {}

    # 1ª passada: resultado do handshake por socket (para contabilizar sucesso)
    for ev in events:
        if ev.get("ev") == "tcp_state":
            state_by_sk[ev["sk"]] = ev["new"]

    # 2ª passada em ordem temporal: atualiza árvore e pontua connects
    for ev in sorted(events, key=lambda e: e.get("ts", 0)):
        kind = ev.get("ev")
        if kind == "fork":
            w.parent[ev["ctid"]] = ev["ptid"]
        elif kind == "connect":
            if ev["daddr"] != listen or ev["dport"] not in dmap:
                excluded["no_reference"] += 1
                continue
            ref = dmap[ev["dport"]][0]
            seen_ports[ev["dport"]] += 1
            ref_acct[ref] += 1
            x = strip_reference_fields(ev)
            for name, fn in RESOLVERS.items():
                out = fn(x, w)
                if len(out) == 1:
                    cat = "C" if ref in out else "I"
                elif len(out) > 1:
                    cat = "A"
                    if ref in out:
                        counts[name]["A_in"] += 1
                else:
                    cat = "M"
                counts[name][cat] += 1
                acct[name][ref][cat] += 1
                if cat == "C":
                    acct[name][ref]["credited_ok"] += 1
                elif cat == "I":
                    acct[name][next(iter(out))]["credited_wrong"] += 1   # creditada à execução errada
                else:
                    acct[name][ref]["uncredited"] += 1                   # A ou M: sinalizada, não creditada

    planned = set(dmap)
    attempted = {o["dport"] for o in ops if "dport" in o}
    captured = set(seen_ports)
    dup = sum(1 for p, n in seen_ports.items() if n > 1)

    res = {"run": run_dir, "cond": plan["cond"], "mode": plan["mode"], "binding": plan["binding"],
           "capture": {"planned": len(planned), "attempted": len(attempted),
                       "captured": len(captured & attempted),
                       "lost": sorted(attempted - captured)[:20], "n_lost": len(attempted - captured),
                       "duplicates": dup, "bad_lines": bad_lines,
                       "excluded": dict(excluded)},
           "reference_connects": dict(ref_acct),
           "resolvers": {}}
    for name in RESOLVERS:
        c = counts[name]
        n = c["C"] + c["A"] + c["M"] + c["I"]
        res["resolvers"][name] = {
            "N": n, "C": c["C"], "A": c["A"], "A_in": c["A_in"], "M": c["M"], "I": c["I"],
            "C/N": c["C"] / n if n else None, "A/N": c["A"] / n if n else None,
            "M/N": c["M"] / n if n else None, "I/N": c["I"] / n if n else None,
            "C/(C+I)": c["C"] / (c["C"] + c["I"]) if (c["C"] + c["I"]) else None,
            # contabilização por execução. O erro líquido (credited - reference) pode
            # esconder atribuições erradas que se cancelam; por isso reportamos as
            # parcelas: corretas, creditadas à execução errada e não creditadas.
            "accounting": {e: {"reference": ref_acct[e],
                               "credited_ok": acct[name][e]["credited_ok"],
                               "credited_wrong": acct[name][e]["credited_wrong"],
                               "uncredited": acct[name][e]["uncredited"],
                               "credited": acct[name][e]["credited_ok"] + acct[name][e]["credited_wrong"],
                               "net_error": acct[name][e]["credited_ok"] + acct[name][e]["credited_wrong"] - ref_acct[e]}
                           for e in sorted(ref_acct)},
        }
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir")
    ap.add_argument("--events")
    a = ap.parse_args()
    r = score(a.run_dir, a.events)
    with open(os.path.join(a.run_dir, "score.json"), "w") as f:
        json.dump(r, f, indent=1)
    cap = r["capture"]
    print(f"{r['cond']} mode={r['mode']} binding={r['binding']}  "
          f"captura {cap['captured']}/{cap['attempted']}  perdidos={cap['n_lost']}  excluídos={cap['excluded']}")
    print(f"{'resolver':8} {'N':>5} {'C':>5} {'A':>5} {'M':>5} {'I':>5}  C/(C+I)  contab. por execução [ok/errada/não-cred.; erro líquido]")
    for name, v in r["resolvers"].items():
        prec = f"{v['C/(C+I)']:.3f}" if v["C/(C+I)"] is not None else "  -  "
        err = "  ".join(f"{e}:{d['credited_ok']}/{d['credited_wrong']}/{d['uncredited']};{d['net_error']:+d}"
                        for e, d in v["accounting"].items())
        print(f"{name:8} {v['N']:5} {v['C']:5} {v['A']:5} {v['M']:5} {v['I']:5}  {prec:>7}  {err}")


if __name__ == "__main__":
    main()
