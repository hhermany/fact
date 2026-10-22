#!/usr/bin/env python3
"""Scores selective containment in a shared worker (E12contain).

The first execution of the shared MCP server runs away: it loops on uploads through
the keep-alive pool that every session shares, toward a destination that serves one
request at a time at a fixed byte rate. The other executions make normal calls. The
byte budget is placed on nobody (mode none: usage counted in the kernel, nothing
denied), on the whole worker (mode process: every call carries one identity, as a
process-level limit sees it; allowance = the runaway's budget plus the others' demand),
or on the runaway execution only (mode exec).

Reference, independent of FACT's records: the outcome and latency of each call at the
client (ops.jsonl) and the bytes the destination received per request (requests.jsonl,
operation id in the URL path).

Reports, per run: for the normal executions, calls completed, calls failed (a denial
of a normal call is a false denial), and median and p99 call latency; for the runaway
execution, calls completed and bytes delivered to the destination; the budgeted
identity's kernel usage against the destination's count, and the overshoot.

Usage: score_contain.py RUN_DIR  -> RUN_DIR/contain_score.json
"""
import json
import os
import statistics as st
import sys


def pct(v, q):
    v = sorted(v)
    return v[min(len(v) - 1, int(q * (len(v) - 1)))] if v else None


def main(rd):
    plan = json.load(open(os.path.join(rd, "plan.json")))
    c = plan["contain"]
    run = c["runaway"]
    ops = [json.loads(l) for l in open(os.path.join(rd, "ops.jsonl")) if l.startswith("{")]
    size = {}
    for l in open(os.path.join(rd, "requests.jsonl")):
        if l.startswith("{"):
            r = json.loads(l)
            k = r["path"].strip("/")
            size[k] = size.get(k, 0) + r["req"][1] - r["req"][0]
    op_exec = plan["op_map"]
    normal = [o for o in ops if o["exec_id"] != run]
    runaway = [o for o in ops if o["exec_id"] == run]
    lat = [(o["t_end"] - o["t_start"]) / 1e6 for o in normal]
    lat_ok = [(o["t_end"] - o["t_start"]) / 1e6 for o in normal if o["ok"]]
    dest = {}
    for k, b in size.items():
        e = op_exec.get(k)
        dest[e] = dest.get(e, 0) + b
    t0 = min(o["t_start"] for o in ops)
    t_norm_end = max(o["t_end"] for o in normal)
    # runaway bytes delivered while the normal executions were running
    budget = c.get("budget", {})
    kernel = {}
    up = os.path.join(rd, "budget_usage.json")
    if os.path.exists(up):
        kernel = json.load(open(up))
    acct = {}
    for ident, b in budget.items():
        d = sum(dest.values()) if ident == "W" else dest.get(ident, 0)
        acct[ident] = {"budget_bytes": b["bytes"], "destination_bytes": d,
                       "kernel_bytes": kernel.get(ident, {}).get("bytes"),
                       "overshoot_bytes": max(0, d - b["bytes"]) if c["mode"] != "none" else None}
    res = {"mode": c["mode"], "execs": plan["execs"],
           "normal_calls": len(normal), "normal_completed": sum(1 for o in normal if o["ok"]),
           "normal_failed": sum(1 for o in normal if not o["ok"]),
           "normal_p50_ms": st.median(lat) if lat else None, "normal_p99_ms": pct(lat, 0.99),
           "normal_ok_p50_ms": st.median(lat_ok) if lat_ok else None, "normal_ok_p99_ms": pct(lat_ok, 0.99),
           "normal_span_s": (t_norm_end - t0) / 1e9,
           "runaway_calls": len(runaway), "runaway_completed": sum(1 for o in runaway if o["ok"]),
           "runaway_bytes": dest.get(run, 0), "normal_bytes": sum(v for e, v in dest.items() if e != run),
           "budget": acct,
           "accounting_exact": all(v["kernel_bytes"] == v["destination_bytes"] for v in acct.values()) if acct else None}
    json.dump(res, open(os.path.join(rd, "contain_score.json"), "w"), indent=1)
    print(f"contain: mode={res['mode']} K={res['execs']} normal {res['normal_completed']}/{res['normal_calls']} ok "
          f"p50={res['normal_p50_ms']:.1f}ms p99={res['normal_p99_ms']:.1f}ms; runaway {res['runaway_completed']}/"
          f"{res['runaway_calls']} ok, {res['runaway_bytes']} B; accounting_exact={res['accounting_exact']}")


if __name__ == "__main__":
    main(sys.argv[1])
