#!/usr/bin/env python3
"""Summary tables of the pre-submission experiments (E5lib, E5reuse, E6spoof, E7rc).

Pools every OK run of the campaigns with the given label (default confirmatory)
and writes, under analysis/output/:
  E5lib_libs.csv     per (tool, K): connections and the fused resolver's C, I, A, M
  E5reuse_bytes.csv  per (tool, send_binding, K): requests, connections, shared
                     connections, and the bytes (sent and received) credited to a wrong
                     execution under the opener rule and the sender rule
  E6spoof_policy.csv per (trust, K): policy outcomes and the label seen by the policy
  E7rc_cost.csv      per K: CPU cost of FACT over the agents' workload (medians and max)
E1ap is summarized by agentprov_table.py --experiment E1ap.

Usage: presub_tables.py [--label confirmatory] [--campaigns campaigns] [--out analysis/output]
"""
import argparse
import collections
import csv
import glob
import json
import os
import statistics as st


def runs(campaigns, exp, label):
    for man in sorted(glob.glob(os.path.join(campaigns, f"*-{exp}-{label}-*", "manifest.json"))):
        cdir = os.path.dirname(man)
        for r in json.load(open(man))["runs"]:
            if r.get("status") == "OK":
                yield r["params"], os.path.join(cdir, "runs", r["run_id"])


def write(path, cols, rows):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        w.writerows(rows)
    print(f"== {os.path.basename(path)}")
    print(open(path).read())


def pct(a, b):
    return round(100 * a / b, 2) if b else ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", default="confirmatory")
    ap.add_argument("--campaigns", default="campaigns")
    ap.add_argument("--out", default="analysis/output")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    # E5lib
    c = collections.defaultdict(collections.Counter)
    for p, rd in runs(a.campaigns, "E5lib", a.label):
        f = json.load(open(os.path.join(rd, "score.json")))["resolvers"]["fused"]
        k = c[(p["tool"], int(p["execs"]))]
        k["runs"] += 1
        for x in ("N", "C", "I", "A", "M"):
            k[x] += f[x]
    write(os.path.join(a.out, "E5lib_libs.csv"), ["tool", "execs", "runs", "N", "C", "I", "A", "M"],
          [[t, e, v["runs"], v["N"], v["C"], v["I"], v["A"], v["M"]] for (t, e), v in sorted(c.items())])

    # E5reuse
    c = collections.defaultdict(collections.Counter)
    for p, rd in runs(a.campaigns, "E5reuse", a.label):
        r = json.load(open(os.path.join(rd, "score_bytes.json")))
        k = c[(p["tool"], int(p["send_binding"]), int(p["execs"]))]
        k["runs"] += 1
        k["requests"] += r["requests"]
        k["connections"] += r["connections"]
        k["shared"] += r["connections_shared"]
        for d in ("sent", "received"):
            for m in ("opener", "sender"):
                b = r["bytes"].get(d, {}).get(m, {})
                k[f"{d}_{m}_I"] += b.get("I", 0)
                k[f"{d}_{m}_A"] += b.get("A", 0)
                k[f"{d}_{m}_M"] += b.get("M", 0)
            k[f"{d}_N"] += r["bytes"].get(d, {}).get("opener", {}).get("N", 0)
    write(os.path.join(a.out, "E5reuse_bytes.csv"),
          ["tool", "send_binding", "execs", "runs", "requests", "connections", "shared_connections",
           "sent_bytes", "sent_I_pct_opener", "sent_I_pct_sender", "received_bytes",
           "received_I_pct_opener", "received_I_pct_sender", "unattributed_or_ambiguous_bytes_sender"],
          [[t, sb, e, v["runs"], v["requests"], v["connections"], v["shared"],
            v["sent_N"], pct(v["sent_opener_I"], v["sent_N"]), pct(v["sent_sender_I"], v["sent_N"]),
            v["received_N"], pct(v["received_opener_I"], v["received_N"]),
            pct(v["received_sender_I"], v["received_N"]),
            v["sent_sender_A"] + v["sent_sender_M"] + v["received_sender_A"] + v["received_sender_M"]]
           for (t, sb, e), v in sorted(c.items())])

    # E6spoof
    c = collections.defaultdict(collections.Counter)
    for p, rd in runs(a.campaigns, "E6spoof", a.label):
        s = json.load(open(os.path.join(rd, "policy_score.json")))
        k = c[(int(p["trust"]), int(p["execs"]))]
        k["runs"] += 1
        for x in ("N", "TA", "TD", "FA", "FD", "ND"):
            k[x] += s[x]
        for lab, n in s["label"].items():
            k["label_" + lab] += n
    write(os.path.join(a.out, "E6spoof_policy.csv"),
          ["trust", "execs", "runs", "decisions", "TA", "TD", "FA", "FD", "ND", "label_owner", "label_other", "label_none"],
          [[t, e, v["runs"], v["N"], v["TA"], v["TD"], v["FA"], v["FD"], v["ND"], v["label_owner"],
            v["label_other"], v["label_none"]] for (t, e), v in sorted(c.items())])

    # E7rc
    c = collections.defaultdict(list)
    for p, rd in runs(a.campaigns, "E7rc", a.label):
        c[int(p["execs"])].append(json.load(open(os.path.join(rd, "cost.json"))))
    rows = []
    for e, rs in sorted(c.items()):
        share = [r["fact_share_of_host"] for r in rs]
        cores = [r["fact_cores"] for r in rs]
        fd = [r["factd_cpu_s"] / r["wall_s"] for r in rs if r.get("factd_cpu_s") is not None]
        rows.append([e, len(rs), round(st.median(r["wall_s"] for r in rs), 1),
                     round(100 * st.median(share), 3), round(100 * max(share), 3),
                     round(st.median(cores), 5), round(max(cores), 5),
                     round(st.median(r.get("factd_events", 0) for r in rs)),
                     round(100 * st.median(fd), 3) if fd else ""])
    write(os.path.join(a.out, "E7rc_cost.csv"),
          ["execs", "runs", "wall_s_median", "fact_pct_of_host_median", "fact_pct_of_host_max",
           "fact_cores_median", "fact_cores_max", "factd_events_median", "factd_pct_of_one_core_median"], rows)


if __name__ == "__main__":
    main()
