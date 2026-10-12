#!/usr/bin/env python3
"""Reúne as rodadas do E2b (capacity.json) num CSV. Uso:
  python3 collect_capacity.py campaigns/ --out analysis/capacity.csv
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
        if man["spec"].get("runner") != "capacity":
            continue
        for path in sorted(glob.glob(os.path.join(os.path.dirname(man_path), "runs", "*", "capacity.json"))):
            c = json.load(open(path))
            rows.append({"campaign_id": man["campaign_id"], "experiment": man["experiment"], "label": man["label"],
                         "boot_id": man["environment"].get("boot_id"),
                         "campaign_runs_failed": man.get("runs_failed", 0),
                         "run_id": os.path.basename(os.path.dirname(path)), **c})
    if not rows:
        raise SystemExit("nenhuma rodada de capacidade encontrada")
    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"{len(rows)} rodadas -> {a.out}")


if __name__ == "__main__":
    main()
