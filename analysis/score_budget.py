#!/usr/bin/env python3
"""Scores per-execution budgets enforced in the kernel (E10budget).

Every second execution has a budget (plan.json "budget"): a number of connections
(new connection per call) or of sent bytes (requests over a keep-alive pool shared
by the sessions). The policy counts each execution's usage in the kernel and denies
its operations once the budget is spent. Each session's calls are sequential, so the
expected outcome of every call follows from the calls before it:
  connections: the first max_conns calls are allowed, the rest denied;
  bytes:       a call is allowed while the bytes the destination has received from
               the execution's earlier calls are below max_bytes (so the call that
               crosses the budget still goes through, and the overshoot is below one
               request).
Executions without a budget: every call allowed. The reference is independent of
FACT's own records: the destination's per-request log (requests.jsonl) for byte
budgets, and the outcome of each call seen by the client (ops.jsonl) for connection
budgets. Per call: TA, TD, FA (allowed beyond the budget), FD (denied within it).
Also compares the kernel's byte usage (budget_usage.json) with the destination's
count, per budgeted execution.

With several calls in flight per session (plan "concurrency" C > 1, E10conc), the
order of the calls no longer determines which ones fall within the budget, so each
budgeted execution is judged as a whole: a connection budget must admit exactly
min(max_conns, calls) connections (the kernel counts attempts atomically); a byte
budget must deliver at least min(max_bytes, demand) bytes and overshoot it by less than
C requests (the sends in flight when it is crossed). Unbudgeted executions: every call.

Usage: score_budget.py RUN_DIR      -> RUN_DIR/budget_score.json (and policy_score.json)
"""
import json
import os
import sys
from collections import Counter, defaultdict


def main(rd):
    plan = json.load(open(os.path.join(rd, "plan.json")))
    budget = plan.get("budget", {})
    ops = sorted((json.loads(l) for l in open(os.path.join(rd, "ops.jsonl")) if l.startswith("{")),
                 key=lambda o: (o["exec_id"], o["op_idx"]))
    rq = os.path.join(rd, "requests.jsonl")
    size = {}
    if os.path.exists(rq):
        for l in open(rq):
            if l.startswith("{"):
                r = json.loads(l)
                size[r["path"].strip("/")] = size.get(r["path"].strip("/"), 0) + r["req"][1] - r["req"][0]
    out, per_exec = Counter(), defaultdict(Counter)
    conc = int(plan.get("concurrency") or 1)
    for e in sorted({o["exec_id"] for o in ops}) if conc > 1 else []:
        b = budget.get(e, {})
        mine = [o for o in ops if o["exec_id"] == e]
        if size:
            got = [o for o in mine if o["op_id"] in size]
            d = sum(size[o["op_id"]] for o in got)
            demand = sum(size.get(o["op_id"], 0) for o in mine)
            if b.get("bytes"):
                maxreq = max((size[o["op_id"]] for o in got), default=0)
                ok = d >= min(b["bytes"], demand) and d - b["bytes"] < conc * max(maxreq, 1)
                per_exec[e]["delivered_bytes"] = d
                per_exec[e]["overshoot_bytes"] = max(0, d - b["bytes"])
            else:
                ok = len(got) == len(mine)
        else:
            n_ok = sum(1 for o in mine if o["ok"])
            ok = n_ok == (min(b["conns"], len(mine)) if b.get("conns") else len(mine))
            per_exec[e]["allowed"] = n_ok
        out["exec_ok" if ok else "exec_wrong"] += 1
        per_exec[e]["within_budget_rule"] = int(ok)
    for e in sorted({o["exec_id"] for o in ops}) if conc == 1 else []:
        b = budget.get(e, {})
        cum = n = 0
        for o in (x for x in ops if x["exec_id"] == e):
            if size:   # byte budget (shared pool): what the destination received
                rec = o["op_id"] in size
                exp = not b.get("bytes") or cum < b["bytes"]
                if rec:
                    cum += size[o["op_id"]]
            else:
                rec = bool(o["ok"])
                exp = not b.get("conns") or n < b["conns"]
                n += 1
            k = ("T" if exp == rec else "F") + ("A" if rec else "D")
            out[k] += 1
            per_exec[e][k] += 1
        if b.get("bytes"):
            per_exec[e]["delivered_bytes"] = cum
            per_exec[e]["overshoot_bytes"] = max(0, cum - b["bytes"])
    kernel = {}
    up = os.path.join(rd, "budget_usage.json")
    if os.path.exists(up):
        kernel = json.load(open(up))
    acct = {}
    for e, b in budget.items():
        if b.get("bytes") and e in kernel:
            acct[e] = {"kernel_bytes": kernel[e]["bytes"], "destination_bytes": per_exec[e]["delivered_bytes"]}
    denials = Counter()
    pe = os.path.join(rd, "policy_events.jsonl")
    if os.path.exists(pe):
        for l in open(pe):
            if l.startswith('{"ev":"decision"'):
                d = json.loads(l)
                if d["verdict"] == "deny":
                    denials["budget" if d.get("budget") else "allow_list"] += 1
    res = {"N": len(ops), **{k: out.get(k, 0) for k in ("TA", "TD", "FA", "FD")}, "ND": 0, "label": {},
           "concurrency": conc, "execs_within_rule": out.get("exec_ok", 0), "execs_outside_rule": out.get("exec_wrong", 0),
           "budget_enforced": plan.get("budget_enforced"), "denials": dict(denials),
           "per_exec": {e: dict(v) for e, v in per_exec.items()}, "kernel_vs_destination": acct,
           "accounting_exact": all(v["kernel_bytes"] == v["destination_bytes"] for v in acct.values()),
           "max_overshoot_bytes": max((v.get("overshoot_bytes", 0) for v in per_exec.values()), default=0)}
    json.dump(res, open(os.path.join(rd, "budget_score.json"), "w"), indent=1)
    json.dump(res, open(os.path.join(rd, "policy_score.json"), "w"), indent=1)
    print(f"budget: conc={conc} execs_ok={res['execs_within_rule']} execs_wrong={res['execs_outside_rule']} "
          f"N={res['N']} TA={res['TA']} TD={res['TD']} FA={res['FA']} FD={res['FD']} "
          f"denials={dict(denials)} accounting_exact={res['accounting_exact']} "
          f"max_overshoot={res['max_overshoot_bytes']}")


if __name__ == "__main__":
    main(sys.argv[1])
