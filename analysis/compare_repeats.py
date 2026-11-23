#!/usr/bin/env python3
"""Repeatability of the parity runs: compares, run by run, the campaigns of one family in two
directories (e.g. two IPv4 passes), with the same outputs and classes as compare_families.py. A
difference that also appears between two runs of the same family is not caused by the family.

Usage: compare_repeats.py DIR_A DIR_B [--family 4] [--out OUT.json]
       [--recorded analysis/runs.csv] [--recorded-campaigns campaigns]
"""
import argparse
import collections
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import compare_families as cf  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("a")
    ap.add_argument("b")
    ap.add_argument("--family", type=int, default=4)
    ap.add_argument("--out")
    ap.add_argument("--recorded")
    ap.add_argument("--recorded-campaigns")
    a = ap.parse_args()
    ca, cb = cf.campaigns(a.a), cf.campaigns(a.b)
    varcells = cf.variable_cells(a.recorded) if a.recorded else set()
    report = {}
    for exp in sorted({e for e, f in ca if f == a.family} & {e for e, f in cb if f == a.family}):
        da, db = (os.path.join(c[(exp, a.family)], "runs") for c in (ca, cb))
        ra = {os.path.basename(p) for p in glob.glob(os.path.join(da, "*")) if os.path.isdir(p)}
        rb = {os.path.basename(p) for p in glob.glob(os.path.join(db, "*")) if os.path.isdir(p)}
        recvals = cf.recorded_values(a.recorded_campaigns, exp) if a.recorded_campaigns else {}
        same, diff, cats = 0, [], collections.Counter()
        for run in sorted(ra & rb):
            oa, ob = cf.outputs(os.path.join(da, run)), cf.outputs(os.path.join(db, run))
            bad = sorted((k for k in set(oa) | set(ob) if oa.get(k, "<absent>") != ob.get(k, "<absent>")), key=str)
            if not bad:
                same += 1
                continue
            try:
                plan = json.load(open(os.path.join(da, run, "plan.json")))
            except (OSError, ValueError):
                plan = {}
            variable = cf.cell_variable(exp, plan, varcells)
            c = cf.cell_token(run)
            kind = {k: cf.classify(exp, "/".join(map(str, k)), variable,
                                   recvals.get((c, k)) if recvals else None, False, oa.get(k), ob.get(k))
                    for k in bad}
            kinds = collections.Counter(kind.values())
            cats.update(kinds.keys())
            diff.append({"run": run, "kinds": dict(kinds),
                         "keys": [{"key": "/".join(map(str, k)), "kind": kind[k], "a": oa.get(k, "<absent>"),
                                   "b": ob.get(k, "<absent>")} for k in bad[:40]]})
        report[exp] = {"compared": len(ra & rb), "identical": same, "different": diff}
        print(f"{exp} IPv{a.family}×IPv{a.family}: identical {same}/{len(ra & rb)}"
              + (f"; differ in: {dict(cats)}" if diff else ""))
    if a.out:
        json.dump(report, open(a.out, "w"), indent=1, default=str)


if __name__ == "__main__":
    main()
