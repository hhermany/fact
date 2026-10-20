#!/usr/bin/env python3
"""Scores the egress policy on connections reused across executions (E6reuse).

The sessions share a keep-alive pool to two destinations; permissive executions
may use both, restricted ones only the first (plan.json policy). A restricted
execution's request to the second destination must not reach it, even over a
connection that a permissive execution opened. The reference is the destination's
per-request log (requests.jsonl: the operation id of every request it received).
Per operation:
  TA  allowed and received          FD  allowed but not received
  TD  forbidden and not received    FA  forbidden but received (a bypass)
Also counts the policy's logged denials by kind (connect, sendto, send).

Usage: score_reuse_policy.py RUN_DIR      -> RUN_DIR/policy_score.json
"""
import json
import os
import sys
from collections import Counter


def main(rd):
    plan = json.load(open(os.path.join(rd, "plan.json")))
    allow = {e: set(v) for e, v in plan["policy"]["allow"].items()}
    ops = [json.loads(l) for l in open(os.path.join(rd, "ops.jsonl")) if l.startswith("{")]
    got = {json.loads(l)["path"].strip("/") for l in open(os.path.join(rd, "requests.jsonl")) if l.startswith("{")}
    out, by_class = Counter(), {c: Counter() for c in ("P", "R")}
    for o in ops:
        exp = o["dport"] in allow[o["exec_id"]]
        rec = o["op_id"] in got
        k = ("T" if exp == rec else "F") + ("A" if rec else "D")
        out[k] += 1
        by_class[plan["policy"]["classes"][o["exec_id"]]][k] += 1
    kinds = Counter()
    pe = os.path.join(rd, "policy_events.jsonl")
    if os.path.exists(pe):
        for l in open(pe):
            if l.startswith('{"ev":"decision"'):
                d = json.loads(l)
                if d["verdict"] == "deny":
                    kinds[d.get("kind", "connect")] += 1
    res = {"N": len(ops), **{k: out.get(k, 0) for k in ("TA", "TD", "FA", "FD")}, "ND": 0, "label": {},
           "by_owner_class": {c: dict(v) for c, v in by_class.items()}, "denials_by_kind": dict(kinds),
           "per_send": plan.get("per_send")}
    json.dump(res, open(os.path.join(rd, "policy_score.json"), "w"), indent=1)
    print(f"policy(reuse): N={res['N']} TA={res['TA']} TD={res['TD']} FA={res['FA']} FD={res['FD']} denials={dict(kinds)}")


if __name__ == "__main__":
    main(sys.argv[1])
