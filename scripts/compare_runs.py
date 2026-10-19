#!/usr/bin/env python3
"""Compares the runs of a re-executed campaign with the recorded confirmatory runs.

Use it after re-running experiments (for example a pilot with --n 1 and the paper's
campaign seed) to check that the outcomes reproduce the recorded ones. Both inputs
are CSV files in the format of analysis/collect_runs.py:

  python3 -I analysis/collect_runs.py NEW_CAMPAIGNS_DIR --out /tmp/new_runs.csv
  python3 -I scripts/compare_runs.py /tmp/new_runs.csv analysis/runs.csv

Each new run is matched with the confirmatory runs of the same experiment, the same
parameters, and the same seed (one per boot). For every resolver it compares the
outcome counts (N, C, A, M, I), the capture counts, and the policy decisions:
  identical  the recorded runs agree with each other and the new run equals them;
  variable   the recorded runs differ among themselves (a nondeterministic cell, such
             as manual markers with asynchronous tools); the new run is reported as
             within or outside the recorded range;
  MISMATCH   the recorded runs agree with each other but the new run differs.
Exits with code 1 if there is any mismatch.
"""
import collections
import csv
import sys

KEY = ["experiment", "cond", "wrong_label", "mode", "execs", "jitter", "tool", "binding_mode", "model", "seed",
       "resolver"]
VALUES = ["attempted", "captured", "N", "C", "A", "M", "I",
          "pol_N", "pol_TA", "pol_TD", "pol_FA", "pol_FD", "pol_ND"]


def load(path, label=None):
    rows = list(csv.DictReader(open(path)))
    return [r for r in rows if label is None or r["label"] == label]


def key(r):
    return tuple(r.get(k, "") for k in KEY)


def vals(r):
    return tuple(r.get(v, "") for v in VALUES)


def main():
    new = load(sys.argv[1])
    ref = collections.defaultdict(list)
    for r in load(sys.argv[2], "confirmatory"):
        ref[key(r)].append(vals(r))
    stats = collections.defaultdict(collections.Counter)
    bad = []
    for r in new:
        exp = r["experiment"]
        refs = ref.get(key(r))
        if not refs:
            stats[exp]["no reference"] += 1
            continue
        v = vals(r)
        if len(set(refs)) == 1:
            if v == refs[0]:
                stats[exp]["identical"] += 1
            else:
                stats[exp]["MISMATCH"] += 1
                bad.append((r["run_id"], r["resolver"], dict(zip(VALUES, v)), dict(zip(VALUES, refs[0]))))
        else:
            inside = all(min(float(x[i] or 0) for x in refs) <= float(v[i] or 0) <= max(float(x[i] or 0) for x in refs)
                         for i in range(len(VALUES)))
            stats[exp]["variable, within recorded range" if inside else "variable, outside recorded range"] += 1
    for exp in sorted(stats):
        print(f"{exp}: " + ", ".join(f"{k} {n}" for k, n in sorted(stats[exp].items())))
    for b in bad[:20]:
        print("MISMATCH", b)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
