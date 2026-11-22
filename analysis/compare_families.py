#!/usr/bin/env python3
"""Address-family parity of the experiments (scripts/run_parity.sh).

For every experiment run over IPv4 and over IPv6 with the same seed (campaign.py --family 4|6;
same seed -> same run order, run ids and plans), compares the two runs' outputs: every JSON file
of the run directory except the plan, registry and tokens, flattened to key paths; values whose
key names a time, a latency, a rate, a CPU measure, an id of the host or an address are left out
(they differ between any two runs, or between the families by construction). A run is identical
when every other value matches. With --runs-csv and --recorded it also compares each family with
the recorded confirmatory campaigns, as scripts/compare_runs.py does.

Usage: compare_families.py CAMPAIGNS_DIR [--out OUT.json] [--runs-csv RUNS.csv --recorded analysis/runs.csv]
"""
import argparse
import collections
import csv
import glob
import json
import os
import re
import sys

SKIP_FILES = {"plan.json", "registry.json", "tokens.json", "registry.json.tmp"}
# key-name segments of values that are not outcomes: times, latencies, rates, CPU, host ids, addresses
VOLATILE = {"ms", "ns", "us", "s", "lat", "latency", "latencies", "time", "times", "wall", "cpu", "throughput",
            "cps", "sps", "rate", "ts", "t", "start", "end", "p50", "p90", "p99", "mean", "median", "max", "min",
            "std", "sd", "duration", "seconds", "elapsed", "boot", "pid", "tid", "ppid", "sk", "sport", "stamp",
            "host", "daddr", "saddr", "addr", "address", "listen", "dest", "ip", "uptime", "load", "loadavg",
            "hz", "jiffies", "utime", "stime", "rss", "kb", "version", "path", "sha256", "id", "ids", "position",
            "returncode", "first", "last", "gap", "gaps", "lead", "delay", "interval", "window", "windows",
            "bpf", "run", "cnt", "run_time_ns", "run_cnt", "peer", "listener", "replay", "of"}
NUM_OK_VOLATILE = {"max_bytes", "max_conns"}   # budgets are inputs, compared


def volatile(path):
    for seg in path:
        if not isinstance(seg, str):
            continue
        if seg in NUM_OK_VOLATILE:
            return False
        parts = [p for p in re.split(r"[_\-\.]", seg.lower()) if p]
        if any(p in VOLATILE for p in parts):
            return True
    return False


def flatten(x, path=()):
    if isinstance(x, dict):
        for k, v in x.items():
            yield from flatten(v, path + (str(k),))
    elif isinstance(x, list):
        if all(not isinstance(v, (dict, list)) for v in x):
            yield path, tuple(x)
        else:
            for i, v in enumerate(x):
                yield from flatten(v, path + (i,))
    else:
        yield path, x


def outputs(rdir):
    res = {}
    for p in sorted(glob.glob(os.path.join(rdir, "**", "*.json"), recursive=True)):
        name = os.path.relpath(p, rdir)
        if os.path.basename(p) in SKIP_FILES:
            continue
        try:
            data = json.load(open(p))
        except (ValueError, OSError):
            continue
        for path, v in flatten(data):
            if not volatile(path):
                res[(name,) + path] = v
    return res


def campaigns(cdir):
    """{(experiment, family): campaign dir} (the latest campaign of each)."""
    out = {}
    for man in sorted(glob.glob(os.path.join(cdir, "*", "manifest.json"))):
        m = json.load(open(man))
        out[(m["experiment"], int(m.get("family", 4)))] = os.path.dirname(man)
    return out


def compare_recorded(runs_csv, recorded):
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))
    import compare_runs as cr
    ref = collections.defaultdict(list)
    for r in cr.load(recorded, "confirmatory"):
        ref[cr.key(r)].append(cr.vals(r))
    stats = collections.defaultdict(collections.Counter)
    for r in csv.DictReader(open(runs_csv)):
        fam = 6 if "-ipv6-" in r["campaign_id"] else 4
        refs = ref.get(cr.key(r))
        exp = r["experiment"]
        if not refs:
            stats[(exp, fam)]["no reference"] += 1
            continue
        v = cr.vals(r)
        if len(set(refs)) == 1:
            stats[(exp, fam)]["identical" if v == refs[0] else "MISMATCH"] += 1
        else:
            inside = all(min(float(x[i] or 0) for x in refs) <= float(v[i] or 0) <= max(float(x[i] or 0) for x in refs)
                         for i in range(len(cr.VALUES)))
            stats[(exp, fam)]["variable, within recorded range" if inside else "variable, outside recorded range"] += 1
    return {f"{e} IPv{f}": dict(c) for (e, f), c in sorted(stats.items())}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("campaigns")
    ap.add_argument("--out")
    ap.add_argument("--runs-csv")
    ap.add_argument("--recorded")
    a = ap.parse_args()
    camps = campaigns(a.campaigns)
    report = {"experiments": {}}
    for exp in sorted({e for e, _ in camps}):
        if (exp, 4) not in camps or (exp, 6) not in camps:
            report["experiments"][exp] = {"missing": [f for f in (4, 6) if (exp, f) not in camps]}
            print(f"{exp}: missing family {report['experiments'][exp]['missing']}")
            continue
        d4, d6 = (os.path.join(camps[(exp, f)], "runs") for f in (4, 6))
        r4 = {os.path.basename(p) for p in glob.glob(os.path.join(d4, "*")) if os.path.isdir(p)}
        r6 = {os.path.basename(p) for p in glob.glob(os.path.join(d6, "*")) if os.path.isdir(p)}
        same, diff = 0, []
        for run in sorted(r4 & r6):
            o4, o6 = outputs(os.path.join(d4, run)), outputs(os.path.join(d6, run))
            keys = set(o4) | set(o6)
            bad = sorted(k for k in keys if o4.get(k, "<absent>") != o6.get(k, "<absent>"))
            if bad:
                diff.append({"run": run, "differences": len(bad),
                             "examples": [{"key": "/".join(map(str, k)), "ipv4": o4.get(k, "<absent>"),
                                           "ipv6": o6.get(k, "<absent>")} for k in bad[:12]]})
            else:
                same += 1
        report["experiments"][exp] = {"runs_ipv4": len(r4), "runs_ipv6": len(r6), "compared": len(r4 & r6),
                                      "identical": same, "different": diff}
        print(f"{exp}: runs {len(r4)}/{len(r6)}, identical {same}/{len(r4 & r6)}"
              + (f", different: {', '.join(d['run'] for d in diff)}" if diff else ""))
    if a.runs_csv and a.recorded:
        report["recorded"] = compare_recorded(a.runs_csv, a.recorded)
        for k, v in report["recorded"].items():
            print(f"vs recorded {k}: {v}")
    if a.out:
        json.dump(report, open(a.out, "w"), indent=1, default=str)


if __name__ == "__main__":
    main()
