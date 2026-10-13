#!/usr/bin/env python3
"""Build the data deposit (e.g., for Zenodo) from the campaign archives.

Usage:
  python3 scripts/package_data.py ARCHIVE_DIR OUT_DIR [--labels confirmatory,pilot,validation]

ARCHIVE_DIR holds <campaign_id>.tar.gz files. Only campaigns that have a
manifest in campaigns/ are packaged. OUT_DIR receives the archives, a
SHA256SUMS file, and DATA_README.md with one row per campaign (experiment,
label, runs, boot, start time). Nothing is modified in ARCHIVE_DIR.
"""
import argparse
import hashlib
import json
import os
import shutil
import sys

ap = argparse.ArgumentParser()
ap.add_argument("archive_dir")
ap.add_argument("out_dir")
ap.add_argument("--labels", default="confirmatory,pilot,validation")
a = ap.parse_args()
labels = set(a.labels.split(","))

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
camp_dir = os.path.join(root, "campaigns")
os.makedirs(a.out_dir, exist_ok=True)

rows, sums, missing = [], [], []
for cid in sorted(os.listdir(camp_dir)):
    mpath = os.path.join(camp_dir, cid, "manifest.json")
    if not os.path.exists(mpath):
        continue
    m = json.load(open(mpath))
    if m.get("label") not in labels:
        continue
    src = os.path.join(a.archive_dir, cid + ".tar.gz")
    if not os.path.exists(src):
        missing.append(cid)
        continue
    dst = os.path.join(a.out_dir, os.path.basename(src))
    shutil.copy2(src, dst)
    h = hashlib.sha256()
    with open(dst, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    sums.append(f"{h.hexdigest()}  {os.path.basename(dst)}")
    env = m.get("environment", {})
    rows.append((cid, m.get("experiment"), m.get("label"), m.get("total_runs"), m.get("runs_ok"),
                 env.get("boot_id", "?")[:8], m.get("started_utc"), os.path.getsize(dst)))

with open(os.path.join(a.out_dir, "SHA256SUMS"), "w") as f:
    f.write("\n".join(sums) + "\n")

boots = {}
for r in rows:
    boots.setdefault(r[5], len(boots) + 1)
with open(os.path.join(a.out_dir, "DATA_README.md"), "w") as f:
    f.write("# agentnet campaign data\n\n")
    f.write("One archive per campaign. Each holds, per run: `events.jsonl` (collector output), `plan.json` "
            "(run plan, including the destination-port reference), `registry.json`, `ops.jsonl`, `score.json`, "
            "and environment snapshots; plus the campaign `manifest.json`, `run_order.json`, and "
            "`checksums.sha256`. Only `confirmatory` campaigns produce numbers in the paper; pilots sized them.\n\n")
    f.write("Verify with `sha256sum -c SHA256SUMS`. Regenerate every table with the repository's "
            "`snakemake --cores 1 validar relatorio baselines` after extracting the archives into `campaigns/`.\n\n")
    f.write("| Campaign | Exp. | Label | Runs (ok) | Boot | Started (UTC) | Size (MB) |\n|---|---|---|---|---|---|---|\n")
    for r in rows:
        f.write(f"| `{r[0]}` | {r[1]} | {r[2]} | {r[3]} ({r[4]}) | {boots[r[5]]} | {r[6]} | {r[7]/1e6:.1f} |\n")
    f.write("\nBoot: hosts boots numbered in order of first appearance (from the recorded boot ID).\n")

print(f"{len(rows)} campaigns packaged into {a.out_dir}")
if missing:
    print("missing archives:", ", ".join(missing), file=sys.stderr)
    sys.exit(1)
