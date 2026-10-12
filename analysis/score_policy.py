#!/usr/bin/env python3
"""Pontua as decisões da política por execução contra a referência independente.

Para cada operação do plano (porta exclusiva -> execução dona), a decisão
esperada é "allow" se a porta está na lista de permissões da execução DONA e
"deny" caso contrário. A decisão observada é a do agentnet_policy para aquela
porta (policy_events.jsonl). Desfechos:
  TA  permitida e devia ser       TD  negada e devia ser
  FA  permitida indevidamente     FD  negada indevidamente
  ND  operação sem decisão registrada
Também classifica o rótulo visto pela política: dono, outra execução, nenhum.
Uso: python3 score_policy.py RUN_DIR
"""
import json
import os
import sys
from collections import Counter


def main(run_dir):
    plan = json.load(open(os.path.join(run_dir, "plan.json")))
    pol = plan["policy"]
    allow = {e: set(v) for e, v in pol["allow"].items()}
    dmap = {int(k): v[0] for k, v in plan["dport_map"].items()}
    first = {}
    for line in open(os.path.join(run_dir, "policy_events.jsonl")):
        if not line.startswith("{"):
            continue
        ev = json.loads(line)
        if ev.get("ev") == "decision" and ev["dport"] in dmap and ev["dport"] not in first:
            first[ev["dport"]] = ev
    out, label = Counter(), Counter()
    by_class = {c: Counter() for c in ("P", "R")}
    for port, owner in dmap.items():
        exp = "allow" if port in allow[owner] else "deny"
        ev = first.get(port)
        if ev is None:
            k = "ND"
        else:
            got = ev["verdict"]
            k = ("T" if got == exp else "F") + ("A" if got == "allow" else "D")
            label["owner" if ev["ctx"] == owner else ("none" if not ev["has_ctx"] else "other")] += 1
        out[k] += 1
        by_class[pol["classes"][owner]][k] += 1
    n = len(dmap)
    res = {"N": n, **{k: out.get(k, 0) for k in ("TA", "TD", "FA", "FD", "ND")},
           "label": dict(label), "by_owner_class": {c: dict(v) for c, v in by_class.items()},
           "expected_allow": sum(1 for p, o in dmap.items() if p in allow[o])}
    json.dump(res, open(os.path.join(run_dir, "policy_score.json"), "w"), indent=1)
    print(f"política: N={n} TA={res['TA']} TD={res['TD']} FA={res['FA']} FD={res['FD']} ND={res['ND']} "
          f"rótulo={dict(label)}")


if __name__ == "__main__":
    main(sys.argv[1])
