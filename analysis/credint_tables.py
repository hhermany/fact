#!/usr/bin/env python3
"""Kernel-held credential with budgets: E10conccred, E12containcred, E9costcred.

Same scoring as E10conc (presub_tables.py), E12contain (contain_tables.py), and
E9cost (presub_tables.py, cost_stability.py), on the campaigns that use the
execution credential (prctl(PR_FACT)) instead of openat markers.
Usage: credint_tables.py [--campaigns campaigns] [--label confirmatory] [--out analysis/output]
Output: OUT/credint_summary.json
"""
import argparse, glob, json, os, random, re, statistics as st
from collections import defaultdict


def runs(campaigns, exp, label):
    for man in sorted(glob.glob(os.path.join(campaigns, f"*-{exp}-{label}-*", "manifest.json"))):
        cdir = os.path.dirname(man)
        for r in json.load(open(man))["runs"]:
            if r.get("status") == "OK":
                m = re.search(r"rep(\d+)", r["run_id"])
                yield os.path.basename(cdir), int(m.group(1)) if m else 0, r["params"], os.path.join(cdir, "runs", r["run_id"])


def J(rd, f):
    p = os.path.join(rd, f)
    return json.load(open(p)) if os.path.exists(p) else None


def cred_on(rd):
    for l in open(os.path.join(rd, "policy_events.jsonl")):
        if '"ready"' in l:
            return json.loads(l).get("cred") == 1
    return False


def boot_ci(xs, n=10000, seed=1):
    rnd = random.Random(seed)
    meds = sorted(st.median(rnd.choices(xs, k=len(xs))) for _ in range(n))
    return round(meds[int(0.025 * n)], 2), round(meds[int(0.975 * n) - 1], 2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--campaigns", default="campaigns")
    ap.add_argument("--label", default="confirmatory")
    ap.add_argument("--out", default="analysis/output")
    a = ap.parse_args()
    out = {}

    c = defaultdict(lambda: defaultdict(int))
    for _, _, p, rd in runs(a.campaigns, "E10conccred", a.label):
        r = J(rd, "budget_score.json")
        k = c[f"{p['tool']}-K{p['execs']}"]
        k["runs"] += 1; k["cred_runs"] += int(cred_on(rd))
        k["execs_within_rule"] += r.get("execs_within_rule", 0); k["execs_outside_rule"] += r.get("execs_outside_rule", 0)
        for x in ("N", "TA", "TD", "FA", "FD"):
            k[x] += r[x]
        k["exact_runs"] += int(bool(r["accounting_exact"]))
        k["max_overshoot_bytes"] = max(k["max_overshoot_bytes"], r["max_overshoot_bytes"] or 0)
        s = J(rd, "score.json")
        if s:
            k["misattributed"] += s["resolvers"]["fused"]["I"]
    out["E10conccred"] = c

    c = defaultdict(list)
    for _, _, p, rd in runs(a.campaigns, "E12containcred", a.label):
        r = J(rd, "contain_score.json"); r["cred"] = cred_on(rd)
        c[(r["mode"], r["execs"])].append(r)
    e12 = {}
    for (mode, k), rs in sorted(c.items()):
        over = [v["overshoot_bytes"] for r in rs for v in r["budget"].values() if v["overshoot_bytes"] is not None]
        e12[f"{mode}-K{k}"] = {
            "runs": len(rs), "cred_runs": sum(r["cred"] for r in rs),
            "normal_completed": sum(r["normal_completed"] for r in rs), "normal_calls": sum(r["normal_calls"] for r in rs),
            "normal_p50_ms_min_max": [round(min(r["normal_ok_p50_ms"] for r in rs if r["normal_ok_p50_ms"]), 1),
                                      round(max(r["normal_ok_p50_ms"] for r in rs if r["normal_ok_p50_ms"]), 1)],
            "runaway_bytes_median": st.median(r["runaway_bytes"] for r in rs),
            "runaway_completed_median": st.median(r["runaway_completed"] for r in rs),
            "accounting_exact_runs": sum(all(v["kernel_bytes"] == v["destination_bytes"] for v in r["budget"].values()) for r in rs),
            "max_overshoot_bytes": max(over) if over else None}
    out["E12containcred"] = e12

    cell, chk = defaultdict(dict), defaultdict(lambda: defaultdict(int))
    for camp, rep, p, rd in runs(a.campaigns, "E9costcred", a.label):
        s, h = J(rd, "e4_summary.json"), J(rd, "host_cpu.json")
        cell[(camp, int(p["execs"]), rep)][p["fact"]] = (s["tool_ms_p50"], s["tool_ms_p99"], h["host_cpu_s"] / h["calls"])
        if p["fact"] != "off":
            k = chk[f"K{p['execs']}"]
            k["runs"] += 1; k["calls"] += s["calls"]; k["ok"] += s["ok"]; k["cred_runs"] += int(cred_on(rd))
            sc = J(rd, "score.json")
            k["misattributed"] += sc["resolvers"]["fused"]["I"] if sc else -10**6
            ps = J(rd, "policy_score.json") or J(rd, "budget_score.json") or {}
            k["policy_errors"] += ps.get("FA", 0) + ps.get("FD", 0)
            ip = J(rd, "ipfix_score.json")
            k["ipfix_ok_runs"] += int(bool(ip and ip.get("ipfix_equals_factd") and not ip.get("decode_errors")))
            cs = J(rd, "cost.json")
            if cs:
                k.setdefault("fact_pct_of_host", []).append(round(100 * cs["fact_share_of_host"], 2))
    e9 = {"checks": chk}
    for K in sorted({k[1] for k in cell}):
        pr = [v for (c_, kk, _), v in cell.items() if kk == K and "off" in v and "credbudget" in v]
        for i, nm in enumerate(["tool_p50_pct", "tool_p99_pct", "host_cpu_per_call_pct"]):
            xs = [100 * (v["credbudget"][i] / v["off"][i] - 1) for v in pr]
            if xs:
                e9[f"K{K} {nm}"] = {"pairs": len(xs), "median": round(st.median(xs), 2), "ci95": boot_ci(xs)}
    out["E9costcred"] = e9
    os.makedirs(a.out, exist_ok=True)
    json.dump(out, open(os.path.join(a.out, "credint_summary.json"), "w"), indent=1, default=dict)
    print(json.dumps(out, indent=1, default=dict))


main()
