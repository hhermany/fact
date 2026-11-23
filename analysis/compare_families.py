#!/usr/bin/env python3
"""Address-family parity of the experiments (scripts/run_parity.sh).

For every experiment run over IPv4 and over IPv6 with the same seed (campaign.py --family 4|6;
same seed -> same run order, run ids and plans), compares the two runs' outputs: every JSON file
of the run directory except the plan, registry and tokens, flattened to key paths; values whose
key names a time, a latency, a rate, a CPU measure, an id of the host or an address are left out
(they differ between any two runs, or between the families by construction). A run is identical
when every other value matches. With --runs-csv and --recorded it also compares each family with
the recorded confirmatory campaigns, as scripts/compare_runs.py does.

Every difference is classified, from evidence:
  "unplanned"     connections outside the plan (the MCP transport, other processes of the host),
                  which the collector also sees (capture/excluded);
  "baseline"      AgentProvenance's own outputs;
  "performance"   capacity under saturation (E2b), measurement cost (cost.json, cost_snapshots.json:
                  CPU and the BPF programs loaded on the host), and the IPFIX packaging counts
                  (records, messages: one record per execution per export interval, so they follow
                  the timing of the run, factd/ipfix.py);
  "variable cell" the same value of the same cell already differs among the recorded IPv4
                  confirmatory runs: per key, from the recorded run directories
                  (--recorded-campaigns), or per cell, from analysis/runs.csv (--recorded) for the
                  experiments whose run directories are not kept (e.g. asynchronous tools with
                  manual markers, where attribution follows the scheduling of the event loop); or the
                  key differs between two IPv4 runs of the same cell made with the comparison
                  (--repeats A,B: two campaign directories of IPv4 repetitions);
  "model output"  the agents' final answers, model turns and token counts (E7*), set by the model,
                  whose prompt names the destination by its address (127.0.0.1 or ::1);
  "request size"  byte totals of HTTP runs whose requests are all exactly ADDR_DELTA bytes shorter
                  over IPv6 with responses of the same size (requests.jsonl; the same requests, or the
                  same number of requests whose sizes differ by ADDR_DELTA as multisets; without
                  requests.jsonl, the same operations with the same outcomes in ops.jsonl and a byte
                  difference that is a multiple of ADDR_DELTA, e.g. the httpx GET of E9cost): the Host
                  header carries the destination, "127.0.0.1:PORT" or "[::1]:PORT"; the collector's
                  count still equals the destination's in both families (any error key that differed
                  would be an "outcome");
  "outcome"       anything else.
Parity holds when no run has an outcome difference.

Usage: compare_families.py CAMPAIGNS_DIR [--out OUT.json] [--runs-csv RUNS.csv --recorded analysis/runs.csv]
                           [--recorded-campaigns campaigns] [--repeats DIR_A,DIR_B]
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
SKIP_RE = re.compile(r"(^|/)bpf_prog_[^/]*\.json$|^agentprov/(events|correlations)\.json$")   # program ids and load times; AgentProvenance's raw data
CELL = ["cond", "wrong_label", "mode", "execs", "jitter", "tool", "binding_mode", "model", "seed"]
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
        if os.path.basename(p) in SKIP_FILES or SKIP_RE.search(name):
            continue
        try:
            data = json.load(open(p))
        except (ValueError, OSError):
            continue
        for path, v in flatten(data):
            if not volatile(path):
                res[(name,) + path] = v
    return res


PERF_FILES = ("capacity.json", "cost.json", "cost_snapshots.json")
PACKAGING = re.compile(r"^ipfix_score\.json/(records|messages)$")
CELL_OUTCOME_FILES = ("score.json", "policy_score.json", "e4_summary.json", "re.json")
# what the model wrote and the tokens it was billed for (the prompt names the destination by its address)
MODEL_TEXT = re.compile(r"^e7_summary\.json/(agents/\d+/)?(final|steps|input_tokens|output_tokens)$")
ADDR_DELTA = len("127.0.0.1") - len("[::1]")   # bytes per HTTP request (Host header)
BYTES_SEG = re.compile(r"(^|_)(bytes|tx|rx|octets|sent|received)(_|$)")


def classify(exp, key, variable, recvals=None, reqsize=False, a=None, b=None):
    if "/excluded/" in key or key.endswith("/excluded"):
        return "unplanned"
    if key.startswith("agentprov") or "agentprov" in key:
        return "baseline"
    if exp == "E2b" or key.startswith(PERF_FILES) or PACKAGING.match(key):
        return "performance"
    if MODEL_TEXT.match(key):
        return "model output"
    if recvals is not None and len(recvals) > 1:
        return "variable cell"
    if variable and key.startswith(CELL_OUTCOME_FILES):
        return "variable cell"
    if reqsize and any(BYTES_SEG.search(seg) for seg in key.split("/")) and size_delta(a, b):
        return "request size"
    return "outcome"


def size_delta(a, b):
    """True when a - b (element-wise for tuples) is a non-negative multiple of ADDR_DELTA."""
    xs, ys = (a, b) if isinstance(a, tuple) and isinstance(b, tuple) else ((a,), (b,))
    if len(xs) != len(ys) or not all(isinstance(x, int) and isinstance(y, int) for x, y in zip(xs, ys)):
        return False
    return all(x >= y and (x - y) % ADDR_DELTA == 0 for x, y in zip(xs, ys))


def requests_differ_by_host(r4, r6):
    """Same requests in both runs, each ADDR_DELTA bytes shorter over IPv6, responses of equal size."""
    f4, f6 = os.path.join(r4, "requests.jsonl"), os.path.join(r6, "requests.jsonl")
    if not (os.path.exists(f4) and os.path.exists(f6)):
        return False
    def load(f):
        out = []
        for line in open(f):
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if r.get("path") and r.get("req") and r.get("resp"):
                out.append((r["path"], r["req"][1] - r["req"][0], r["resp"][1] - r["resp"][0]))
        return sorted(out)
    a, b = load(f4), load(f6)
    if not a or len(a) != len(b):
        return False
    if [x[0] for x in a] == [y[0] for y in b]:             # same requests: each one ADDR_DELTA shorter
        return all(x[1] - y[1] == ADDR_DELTA and x[2] == y[2] for x, y in zip(a, b))
    # same number of requests, different operations (e.g. which ones a budget let through): the sizes,
    # as multisets, differ by ADDR_DELTA each and the responses are the same sizes
    return sorted(x[1] - ADDR_DELTA for x in a) == sorted(y[1] for y in b) and \
        sorted(x[2] for x in a) == sorted(y[2] for y in b)


def same_operations(r4, r6):
    """Without requests.jsonl: both runs made the same operations with the same outcomes."""
    f4, f6 = os.path.join(r4, "ops.jsonl"), os.path.join(r6, "ops.jsonl")
    if not (os.path.exists(f4) and os.path.exists(f6)) or os.path.exists(os.path.join(r4, "requests.jsonl")):
        return False
    def load(f):
        out = []
        for line in open(f):
            try:
                r = json.loads(line)
            except ValueError:
                continue
            out.append((r.get("op_id"), r.get("exec_id"), r.get("ok")))
        return sorted(out, key=str)
    a = load(f4)
    return bool(a) and a == load(f6)


def repeat_differences(dirs, family=4):
    """{(experiment, cell, key)} that differ between two runs of the same cell in two campaign
    directories of the same family (repetitions)."""
    da, db = (campaigns(d) for d in dirs)
    out = set()
    for exp in {e for e, f in da if f == family} & {e for e, f in db if f == family}:
        ra, rb = (os.path.join(c[(exp, family)], "runs") for c in (da, db))
        for run in {os.path.basename(p) for p in glob.glob(os.path.join(ra, "*"))} & \
                {os.path.basename(p) for p in glob.glob(os.path.join(rb, "*"))}:
            oa, ob = outputs(os.path.join(ra, run)), outputs(os.path.join(rb, run))
            out.update((exp, cell_token(run), k) for k in set(oa) | set(ob) if oa.get(k) != ob.get(k))
    return out


def cell_token(run):
    return next((t for t in os.path.basename(run).split("-") if re.fullmatch(r"c\d+", t)), None)


def recorded_values(cdir, exp):
    """{(cell, key): set of values} over the recorded confirmatory run directories of exp."""
    vals = collections.defaultdict(set)
    for r in glob.glob(os.path.join(cdir, f"*-{exp}-confirmatory-*", "runs", "*")):
        c = cell_token(r)
        for k, v in outputs(r).items():
            vals[(c, k)].add(v)
    return vals


def variable_cells(recorded):
    """Cells whose recorded confirmatory runs (analysis/runs.csv) differ from run to run: a list of
    (experiment, {factor: value}) with the factors that the recorded rows carry (older campaigns
    leave some empty, e.g. binding_mode in E4)."""
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))
    import compare_runs as cr
    vals = collections.defaultdict(set)
    for r in cr.load(recorded, "confirmatory"):
        vals[tuple(r.get(k, "") for k in ["experiment"] + CELL[:-1] + ["resolver"])].add(cr.vals(r))
    out = set()
    for k, v in vals.items():
        if len(v) > 1:
            out.add((k[0], tuple((f, x) for f, x in zip(CELL[:-1], k[1:-1]) if x != "")))
    return out


def cell_variable(exp, plan, varcells):
    def same(f, x):
        y = plan.get(f)
        if y is None:
            return False
        try:
            return float(x) == float(y)
        except (TypeError, ValueError):
            return str(x) == str(y)
    return any(e == exp and all(same(f, x) for f, x in fs) for e, fs in varcells)


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
    ap.add_argument("--recorded-campaigns", help="directory of the recorded campaigns (run directories)")
    ap.add_argument("--repeats", help="DIR_A,DIR_B: two campaign directories of IPv4 repetitions")
    a = ap.parse_args()
    camps = campaigns(a.campaigns)
    repdiff = repeat_differences(a.repeats.split(",")) if a.repeats else set()
    varcells = variable_cells(a.recorded) if a.recorded else set()
    report = {"experiments": {}}
    for exp in sorted({e for e, _ in camps}):
        if (exp, 4) not in camps or (exp, 6) not in camps:
            report["experiments"][exp] = {"missing": [f for f in (4, 6) if (exp, f) not in camps]}
            print(f"{exp}: missing family {report['experiments'][exp]['missing']}")
            continue
        d4, d6 = (os.path.join(camps[(exp, f)], "runs") for f in (4, 6))
        r4 = {os.path.basename(p) for p in glob.glob(os.path.join(d4, "*")) if os.path.isdir(p)}
        r6 = {os.path.basename(p) for p in glob.glob(os.path.join(d6, "*")) if os.path.isdir(p)}
        same, diff, cats = 0, [], collections.Counter()
        recvals = recorded_values(a.recorded_campaigns, exp) if a.recorded_campaigns else {}
        for run in sorted(r4 & r6):
            o4, o6 = outputs(os.path.join(d4, run)), outputs(os.path.join(d6, run))
            keys = set(o4) | set(o6)
            bad = sorted((k for k in keys if o4.get(k, "<absent>") != o6.get(k, "<absent>")), key=str)
            if bad:
                try:
                    plan = json.load(open(os.path.join(d4, run, "plan.json")))
                    variable = cell_variable(exp, plan, varcells)
                except (OSError, ValueError):
                    plan, variable = {}, False
                reqsize = requests_differ_by_host(os.path.join(d4, run), os.path.join(d6, run)) or \
                    same_operations(os.path.join(d4, run), os.path.join(d6, run))
                c = cell_token(run)
                kind = {k: classify(exp, "/".join(map(str, k)), variable,
                                    recvals.get((c, k)) if recvals else None, reqsize,
                                    o4.get(k), o6.get(k)) for k in bad}
                for k in bad:   # the key also differs between two IPv4 runs of this cell
                    if kind[k] == "outcome" and (exp, c, k) in repdiff:
                        kind[k] = "variable cell"
                kinds = collections.Counter(kind.values())
                cats.update(kinds.keys())
                diff.append({"run": run, "cell": {f: plan.get(f) for f in CELL if plan.get(f) is not None},
                             "differences": len(bad), "kinds": dict(kinds),
                             "outcome_keys": ["/".join(map(str, k)) for k in bad if kind[k] == "outcome"][:20],
                             "examples": [{"key": "/".join(map(str, k)), "kind": kind[k],
                                           "ipv4": o4.get(k, "<absent>"), "ipv6": o6.get(k, "<absent>")}
                                          for k in (sorted(bad, key=lambda k: kind[k] != "outcome"))[:12]]})
            else:
                same += 1
        outcome = [d["run"] for d in diff if d["kinds"].get("outcome")]
        report["experiments"][exp] = {"runs_ipv4": len(r4), "runs_ipv6": len(r6), "compared": len(r4 & r6),
                                      "identical": same, "outcome_differences": outcome, "different": diff}
        print(f"{exp}: runs {len(r4)}/{len(r6)}, identical {same}/{len(r4 & r6)}"
              + (f"; other runs differ only in: {dict(c for c in cats.items() if c[0] != 'outcome')}" if diff else "")
              + (f"; OUTCOME DIFFERENCES: {', '.join(outcome)}" if outcome else ""))
    if a.runs_csv and a.recorded:
        report["recorded"] = compare_recorded(a.runs_csv, a.recorded)
        for k, v in report["recorded"].items():
            print(f"vs recorded {k}: {v}")
    if a.out:
        json.dump(report, open(a.out, "w"), indent=1, default=str)


if __name__ == "__main__":
    main()
