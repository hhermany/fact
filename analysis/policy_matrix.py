#!/usr/bin/env python3
"""Per-class policy outcomes and the network reach of every decision (raw runs).

For every confirmatory run with a policy score, sums the outcomes per execution class
(P: permissive, R: restricted) and per setting: TA/TD (allowed or denied, as the allow-list
of the execution that owns the operation prescribes), FA/FD (wrongly allowed or denied) and
ND (no decision). Restricted executions issue both permitted and forbidden operations, so
their TA and TD are both counted. Second output: for runs with exclusive ports, whether each
first decision of the kernel reached tcp_connect (the collector's connect event, i.e., a SYN):
a denied connect must not.

Usage: policy_matrix.py [--campaigns campaigns] [--out analysis/output]
  -> policy_matrix.csv, policy_reach.csv
"""
import argparse
import collections
import csv
import glob
import json
import os

FACTORS = ("binding_mode", "per_send", "identity", "wrong_label")


def setting(exp, rd, plan):
    s = []
    for f in FACTORS:
        v = plan.get(f)
        if v not in (None, 0, "auto", "meta"):
            s.append(f"{f}={v}")
    if plan.get("spoof"):
        s.append(f"trust={plan['spoof'].get('trust')}")
    ready = next((json.loads(l) for l in open(os.path.join(rd, "policy_events.jsonl"))
                  if l.startswith('{"ev":"ready"')), {}) if os.path.exists(os.path.join(rd, "policy_events.jsonl")) else {}
    if exp.startswith("E6reuse") and "per_send" in ready:
        s.append(f"per_send={ready['per_send']}")
    return " ".join(s)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--campaigns", default="campaigns")
    ap.add_argument("--out", default="analysis/output")
    a = ap.parse_args()
    agg = collections.defaultdict(collections.Counter)
    reach = collections.Counter()
    for ps in sorted(glob.glob(os.path.join(a.campaigns, "*-confirmatory-*", "runs", "*", "policy_score.json"))):
        rd = os.path.dirname(ps)
        exp = os.path.basename(os.path.dirname(os.path.dirname(rd))).split("-")[1]
        s = json.load(open(ps))
        plan = json.load(open(os.path.join(rd, "plan.json")))
        key = (exp, setting(exp, rd, plan))
        for c, v in (s.get("by_owner_class") or {}).items():
            agg[key + (c,)]["runs"] += 1
            for k in ("TA", "TD", "FA", "FD", "ND"):
                agg[key + (c,)][k] += v.get(k, 0)
        dm = plan.get("dport_map") or {}
        pe, ev = os.path.join(rd, "policy_events.jsonl"), os.path.join(rd, "events.jsonl")
        if dm and os.path.exists(pe) and os.path.exists(ev):
            seen, first = set(), {}
            for l in open(ev):
                if '"ev":"connect"' in l and '"proto"' not in l:
                    try:
                        seen.add(json.loads(l)["dport"])
                    except ValueError:
                        pass
            for l in open(pe):
                if l.startswith('{"ev":"decision"'):
                    d = json.loads(l)
                    first.setdefault(d["dport"], d["verdict"])
            for p in dm:
                if int(p) in first:
                    reach[(exp, first[int(p)], int(p) in seen)] += 1
    with open(os.path.join(a.out, "policy_matrix.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["experiment", "setting", "class", "runs", "TA", "TD", "FA", "FD", "ND"])
        for k in sorted(agg):
            v = agg[k]
            w.writerow(list(k) + [v["runs"], v["TA"], v["TD"], v["FA"], v["FD"], v["ND"]])
    with open(os.path.join(a.out, "policy_reach.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["experiment", "kernel_decision", "reached_tcp_connect", "operations"])
        for k in sorted(reach):
            w.writerow([k[0], k[1], int(k[2]), reach[k]])
    print(f"policy_matrix.csv: {len(agg)} rows; policy_reach.csv: {len(reach)} rows")


if __name__ == "__main__":
    main()
