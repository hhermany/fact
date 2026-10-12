#!/usr/bin/env python3
"""Reúne as rodadas do E3 (overhead.json) de todas as campanhas num CSV (uma linha por rodada).
Uso: python3 collect_overhead.py campaigns/ --out analysis/overhead.csv
"""
import argparse
import csv
import glob
import json
import os


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("campaigns_dir")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    rows = []
    for man_path in sorted(glob.glob(os.path.join(a.campaigns_dir, "*", "manifest.json"))):
        man = json.load(open(man_path))
        if man["spec"].get("runner") != "overhead":
            continue
        pos = {r["run_id"]: r["position"] for r in man["runs"]}
        for path in sorted(glob.glob(os.path.join(os.path.dirname(man_path), "runs", "*", "overhead.json"))):
            o = json.load(open(path))
            run_id = os.path.basename(os.path.dirname(path))
            cnt = o.get("bpf_total_run_cnt") or 0
            rows.append({
                "campaign_id": man["campaign_id"], "experiment": man["experiment"], "label": man["label"],
                "boot_id": man["environment"].get("boot_id"), "git_commit": man["git"].get("commit"),
                "campaign_runs_failed": man.get("runs_failed", 0),
                "run_id": run_id, "run_position": pos.get(run_id),
                "instr": o["instr"], "markers": o["markers"], "n": o["n"], "failures": o["failures"],
                "mean_ns": o["mean_ns"], "p50_ns": o["p50_ns"], "p90_ns": o["p90_ns"], "p99_ns": o["p99_ns"],
                "throughput_cps": o["throughput_cps"],
                "bpf_run_cnt": cnt, "bpf_run_time_ns": o.get("bpf_total_run_time_ns"),
                "bpf_ns_per_run": (o["bpf_total_run_time_ns"] / cnt) if cnt else None,
                "collector_process_cpu_s": o.get("collector_process_cpu_s"),
            })
    if not rows:
        raise SystemExit("nenhuma rodada de overhead encontrada")
    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"{len(rows)} rodadas de overhead -> {a.out}")


if __name__ == "__main__":
    main()
