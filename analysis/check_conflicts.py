#!/usr/bin/env python3
"""Counts structural conflicts in every recorded run: connections and sends whose
lineage set and cgroup set are both non-empty and disjoint. In such a case the
fused resolver keeps the result ambiguous (analysis/resolvers.py); the count shows
whether any reported run exercised that rule.

Scans campaigns/*/runs/*/ (events.jsonl + registry.json) and, with --archives,
also the runs inside campaigns/*.tar.gz.

Usage: check_conflicts.py [--campaigns campaigns] [--archives]
       -> analysis/output/structural_conflicts.csv
"""
import argparse
import collections
import csv
import glob
import io
import json
import os
import sys
import tarfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from resolvers import World, strip_reference_fields, structural_conflict  # noqa: E402


def scan(events, reg):
    w = World(roots={int(k): set(v) for k, v in reg.get("roots", {}).items()},
              cgroups={int(k): set(v) for k, v in reg.get("cgroups", {}).items()})
    n = conf = 0
    for ev in sorted(events, key=lambda e: e.get("ts", 0)):
        k = ev.get("ev")
        if k == "fork":
            w.parent[ev["ctid"]] = ev["ptid"]
        elif k in ("connect", "send", "recv"):
            n += 1
            conf += structural_conflict(strip_reference_fields(ev), w)
    return n, conf


def parse(lines):
    out = []
    for line in lines:
        if line.startswith("{"):
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--campaigns", default="campaigns")
    ap.add_argument("--archives", action="store_true")
    ap.add_argument("--out", default="analysis/output")
    a = ap.parse_args()
    tot = collections.defaultdict(lambda: [0, 0, 0])   # experiment -> runs, events, conflicts
    for reg_path in glob.glob(os.path.join(a.campaigns, "*", "runs", "*", "registry.json")):
        rd = os.path.dirname(reg_path)
        ev_path = os.path.join(rd, "events.jsonl")
        if not os.path.exists(ev_path):
            continue
        exp = os.path.basename(os.path.dirname(os.path.dirname(rd))).split("-")[1]
        n, c = scan(parse(open(ev_path)), json.load(open(reg_path)))
        t = tot[exp]
        t[0] += 1; t[1] += n; t[2] += c
    if a.archives:
        for tg in glob.glob(os.path.join(a.campaigns, "*.tar.gz")):
            exp = os.path.basename(tg).split("-")[1]
            if os.path.isdir(tg[:-7]):
                continue          # already scanned unpacked
            with tarfile.open(tg) as tf:
                members = {m.name: m for m in tf.getmembers()}
                for name in members:
                    if not name.endswith("/registry.json"):
                        continue
                    evn = name[:-len("registry.json")] + "events.jsonl"
                    if evn not in members:
                        continue
                    reg = json.load(tf.extractfile(members[name]))
                    evs = parse(io.TextIOWrapper(tf.extractfile(members[evn])))
                    n, c = scan(evs, reg)
                    t = tot[exp]
                    t[0] += 1; t[1] += n; t[2] += c
    os.makedirs(a.out, exist_ok=True)
    path = os.path.join(a.out, "structural_conflicts.csv")
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["experiment", "runs", "events", "structural_conflicts"])
        for e, (r, n, c) in sorted(tot.items()):
            w.writerow([e, r, n, c])
        w.writerow(["TOTAL", sum(v[0] for v in tot.values()), sum(v[1] for v in tot.values()),
                    sum(v[2] for v in tot.values())])
    print(open(path).read())


if __name__ == "__main__":
    main()
