#!/usr/bin/env python3
"""Baselines from related work, applied offline to the same event logs.

The reviewed systems do not publish a complete attribution rule for
concurrent executions, so each mechanism is emulated from its documented
inputs and evaluated in two variants: one that picks a single candidate and
one that reports every compatible candidate (ambiguity).

  tw-nearest / tw-set   AgentSight-style: process lineage first; inside a
                        shared process, temporal proximity to the most recent
                        intent marker (window W, 100 or 500 ms, the range
                        given in the AgentSight paper).
  scope-latest / scope-all
                        AgentProvenance-style: explicit execution-scope
                        bindings per PID (begin..end markers), resolved
                        through the process tree; with several active scopes
                        on the same PID, the latest-started one or all of them.

Inputs are the same as for our resolvers (ts, pid, tid, cgroup, ctx of the
connect event) plus the stream of fork and ctx_begin/ctx_end events seen
before it. Destination fields are never read (checked by AST, as in
resolvers.py).

Usage:
  python3 baselines.py CAMPAIGN_DIR [CAMPAIGN_DIR ...] > baselines.csv
"""
import ast
import csv
import inspect
import json
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from resolvers import (RESOLVERS, World, resolve_lineage,  # noqa: E402
                       strip_reference_fields)

MS = 1_000_000


class Scopes:
    """Intent markers per process, reconstructed from ctx_begin/ctx_end."""

    def __init__(self):
        self.begins = defaultdict(list)    # pid -> [(ts, exec_id)]
        self.active = defaultdict(dict)    # pid -> {exec_id: ts of the open scope}

    @staticmethod
    def _exec(ev):
        return ev["ctx"].rsplit("/", 1)[-1]

    def begin(self, ev):
        e = self._exec(ev)
        self.begins[ev["pid"]].append((ev["ts"], e))
        self.active[ev["pid"]][e] = ev["ts"]

    def end(self, ev):
        self.active[ev["pid"]].pop(self._exec(ev), None)

    def owner(self, x, w):
        """Nearest process (itself or an ancestor) that carries markers."""
        for p in (x.pid, *w.ancestors(x.tid)):
            if p in self.begins:
                return p
        for p in w.ancestors(x.pid):
            if p in self.begins:
                return p
        return None


def _lineage_unique(x, w):
    s = resolve_lineage(x, w)
    return s if len(s) == 1 else None


def tw_nearest(x, w, sc, win):
    s = _lineage_unique(x, w)
    if s:
        return s
    p = sc.owner(x, w)
    if p is None:
        return frozenset()
    cand = [(t, e) for t, e in sc.begins[p] if x.ts - win <= t <= x.ts]
    return frozenset([max(cand)[1]]) if cand else frozenset()


def tw_set(x, w, sc, win):
    s = _lineage_unique(x, w)
    if s:
        return s
    p = sc.owner(x, w)
    if p is None:
        return frozenset()
    return frozenset(e for t, e in sc.begins[p] if x.ts - win <= t <= x.ts)


def scope_latest(x, w, sc, win=None):
    s = _lineage_unique(x, w)
    if s:
        return s
    p = sc.owner(x, w)
    if p is None or not sc.active[p]:
        return frozenset()
    return frozenset([max(sc.active[p].items(), key=lambda kv: kv[1])[0]])


def scope_all(x, w, sc, win=None):
    s = _lineage_unique(x, w)
    if s:
        return s
    p = sc.owner(x, w)
    if p is None:
        return frozenset()
    return frozenset(sc.active[p])


BASELINES = {
    "tw-nearest-100ms": (tw_nearest, 100 * MS),
    "tw-set-100ms": (tw_set, 100 * MS),
    "tw-nearest-500ms": (tw_nearest, 500 * MS),
    "tw-set-500ms": (tw_set, 500 * MS),
    "scope-latest": (scope_latest, None),
    "scope-all": (scope_all, None),
}


def check_independence():
    forbidden = {"daddr", "dport", "dport_map", "op_id", "plan", "reference"}
    for fn in {f for f, _ in BASELINES.values()} | {Scopes.owner, Scopes.begin, _lineage_unique}:
        for node in ast.walk(ast.parse(inspect.getsource(fn).strip())):
            ident = getattr(node, "id", None) or getattr(node, "attr", None)
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                ident = node.value
            if ident in forbidden:
                raise AssertionError(f"{fn.__name__} references {ident}")


def load_jsonl(path):
    out = []
    with open(path) as f:
        for line in f:
            if line.startswith("{"):
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return out


def score_run(run_dir):
    plan = json.load(open(os.path.join(run_dir, "plan.json")))
    reg = json.load(open(os.path.join(run_dir, "registry.json")))
    events = load_jsonl(os.path.join(run_dir, "events.jsonl"))
    w = World(roots={int(k): set(v) for k, v in reg["roots"].items()},
              cgroups={int(k): set(v) for k, v in reg["cgroups"].items()})
    sc = Scopes()
    dmap = {int(k): v for k, v in plan["dport_map"].items()}
    counts = defaultdict(Counter)
    for ev in sorted(events, key=lambda e: e.get("ts", 0)):
        k = ev.get("ev")
        if k == "fork":
            w.parent[ev["ctid"]] = ev["ptid"]
        elif k == "ctx_begin":
            sc.begin(ev)
        elif k == "ctx_end":
            sc.end(ev)
        elif k == "connect":
            if ev["daddr"] != plan["listen_addr"] or ev["dport"] not in dmap:
                continue
            ref = dmap[ev["dport"]][0]
            x = strip_reference_fields(ev)
            outs = {n: fn(x, w) for n, fn in RESOLVERS.items()}
            outs.update({n: f(x, w, sc, win) for n, (f, win) in BASELINES.items()})
            for n, out in outs.items():
                cat = ("C" if ref in out else "I") if len(out) == 1 else ("A" if out else "M")
                counts[n][cat] += 1
    return plan, counts


def main():
    check_independence()
    wr = csv.writer(sys.stdout)
    wr.writerow(["campaign", "run", "cond", "mode", "tool", "binding_mode", "K", "p",
                 "resolver", "N", "C", "A", "M", "I"])
    for camp in sys.argv[1:]:
        for run in sorted(os.listdir(os.path.join(camp, "runs"))):
            rd = os.path.join(camp, "runs", run)
            if not os.path.exists(os.path.join(rd, "events.jsonl")):
                continue
            plan, counts = score_run(rd)
            for n, c in counts.items():
                wr.writerow([os.path.basename(camp.rstrip("/")), run, plan.get("cond"), plan.get("mode"),
                             plan.get("tool", ""), plan.get("binding_mode", ""), plan.get("execs"),
                             plan.get("wrong_label", 0), n, sum(c.values()), c["C"], c["A"], c["M"], c["I"]])


if __name__ == "__main__":
    main()
