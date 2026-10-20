#!/usr/bin/env python3
"""factd: LIVE per-execution attribution and accounting.

Reads the collector's JSON stream (stdin or --replay file), keeps the process
tree and the execution registry, attributes each connect with the fused
resolver (the same function used in the offline evaluation; it receives only
ts, pid, tid, cgroup, and ctx), and exports, at each interval, one flow record
per execution:

  {"type":"exec_flow","t0":..,"t1":..,"exec":"E01","connections":n,
   "established":x,"failed":y,"destinations":d}
  {"type":"uncredited","t0":..,"t1":..,"ambiguous":a,"unattributed":m,
   "ambiguous_sets":{"E01|E02": k, ...}}

Ambiguous or unattributed connections are NEVER credited to an execution: they
are exported separately, with their candidate sets (explicit ambiguity).

Bytes: with a collector that reports sends and receives (collector/fact-bytes.bt),
each send is credited with the fused resolver applied to the sending thread (send
binding), and each receive to the socket's last sender; the records then carry
octets_sent and octets_received, and uncredited bytes are exported with their
candidate sets like connections.

IPFIX (--ipfix HOST:PORT): the same records are also exported as IPFIX messages
over UDP (factd/ipfix.py; per-execution template with an executionId element),
so a standard flow collector receives per-execution accounting.

Events from different CPUs may arrive out of order; a reordering buffer
(--reorder-ms) releases events in ts order once they are older than
(largest ts seen - window).

Usage:
  bpftrace -B line collector/fact-fast.bt | factd.py --registry reg.json
  factd.py --replay events.jsonl --registry reg.json --out flows.jsonl
  tail -F events.jsonl | factd.py --registry reg.json --ipfix 127.0.0.1:4739
"""
import argparse
import heapq
import json
import os
import signal
import sys
import time
from collections import Counter, defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "analysis"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from resolvers import ResolverInput, World, check_independence, resolve_fused, strip_reference_fields  # noqa: E402
import ipfix  # noqa: E402


class Daemon:
    def __init__(self, registry, interval_ns=1_000_000_000, reorder_ns=100_000_000, emit=None, filt=None,
                 exporter=None, epoch_offset_ns=0):
        check_independence()
        self.w = World()
        self.load_registry(registry)
        self.interval = interval_ns
        self.reorder = reorder_ns
        self.emit = emit or (lambda r: print(json.dumps(r), flush=True))
        self.filt = filt                      # used only in tests (same filter as the offline score)
        self.heap, self.seq, self.max_ts = [], 0, 0
        self.win0 = None
        self.sk_exec = {}
        self.reset_window()
        self.total = defaultdict(Counter)     # exec -> totals (for the final summary)
        self.total_unc = Counter()
        self.exporter = exporter              # ipfix.Exporter or None
        self.epoch = epoch_offset_ns          # event ts (monotonic) -> Unix time

    def load_registry(self, reg):
        self.w.roots = {int(k): set(v) for k, v in reg.get("roots", {}).items()}
        self.w.cgroups = {int(k): set(v) for k, v in reg.get("cgroups", {}).items()}

    def reset_window(self):
        self.win = defaultdict(Counter)
        self.dests = defaultdict(set)
        self.unc = Counter()
        self.amb_sets = Counter()
        self.unc_cells = defaultdict(Counter)   # (status, candidate set) -> connections/octets

    def push(self, ev):
        ts = ev.get("ts", 0)
        heapq.heappush(self.heap, (ts, self.seq, ev))
        self.seq += 1
        self.max_ts = max(self.max_ts, ts)
        while self.heap and self.heap[0][0] <= self.max_ts - self.reorder:
            self.process(heapq.heappop(self.heap)[2])

    def drain(self):
        while self.heap:
            self.process(heapq.heappop(self.heap)[2])
        self.flush(final=True)

    def process(self, ev):
        ts, kind = ev.get("ts", 0), ev.get("ev")
        if self.win0 is None and ts:
            self.win0 = ts
        while self.win0 is not None and ts >= self.win0 + self.interval:
            self.flush()
            self.win0 += self.interval
        if kind == "fork":
            self.w.parent[ev["ctid"]] = ev["ptid"]
        elif kind == "connect":
            if self.filt and not self.filt(ev):
                return
            cand = resolve_fused(strip_reference_fields(ev), self.w)
            if len(cand) == 1:
                (e,) = cand
                self.win[e]["connections"] += 1
                self.total[e]["connections"] += 1
                self.dests[e].add((ev.get("daddr"), ev.get("dport")))
                self.sk_exec[ev["sk"]] = e
            elif len(cand) > 1:
                self.unc["ambiguous"] += 1
                self.total_unc["ambiguous"] += 1
                self.amb_sets["|".join(sorted(cand))] += 1
                self.unc_cells[("ambiguous", "|".join(sorted(cand)))]["connections"] += 1
            else:
                self.unc["unattributed"] += 1
                self.total_unc["unattributed"] += 1
                self.unc_cells[("unattributed", "")]["connections"] += 1
        elif kind in ("send", "recv"):
            if self.filt and not self.filt(ev):
                return
            x = strip_reference_fields(ev)
            if kind == "recv":   # a response belongs to the socket's last sender
                x = ResolverInput(x.ts, x.pid, x.tid, x.cgroup, ev.get("sk_ctx", ""))
            cand = resolve_fused(x, self.w)
            k = "octets_sent" if kind == "send" else "octets_received"
            n = int(ev.get("bytes", 0))
            if len(cand) == 1:
                (e,) = cand
                self.win[e][k] += n
                self.total[e][k] += n
            else:
                st = "ambiguous" if cand else "unattributed"
                self.unc_cells[(st, "|".join(sorted(cand)))][k] += n
                self.total_unc[f"{k}_{st}"] += n
        elif kind == "tcp_state":
            e = self.sk_exec.pop(ev["sk"], None)
            if e is not None:
                k = "established" if ev.get("new") == 1 else "failed"
                self.win[e][k] += 1
                self.total[e][k] += 1

    def flush(self, final=False):
        if self.win0 is None:
            return
        t0, t1 = self.win0, self.win0 + self.interval
        for e, c in sorted(self.win.items()):
            rec = {"type": "exec_flow", "t0": t0, "t1": t1, "exec": e,
                   "connections": c["connections"], "established": c["established"],
                   "failed": c["failed"], "destinations": len(self.dests[e])}
            if c["octets_sent"] or c["octets_received"]:
                rec.update(octets_sent=c["octets_sent"], octets_received=c["octets_received"])
            self.emit(rec)
        if self.unc:
            self.emit({"type": "uncredited", "t0": t0, "t1": t1, "ambiguous": self.unc["ambiguous"],
                       "unattributed": self.unc["unattributed"], "ambiguous_sets": dict(self.amb_sets)})
        if self.exporter is not None and (self.win or self.unc_cells):
            ms0, ms1 = (t0 + self.epoch) // 1_000_000, (t1 + self.epoch) // 1_000_000
            ex = [ipfix.encode_exec(ms0, ms1, e, c["connections"], c["established"], c["failed"],
                                    len(self.dests[e]), c["octets_sent"], c["octets_received"])
                  for e, c in sorted(self.win.items())]
            un = [ipfix.encode_unc(ms0, ms1, st, cs, c["connections"], c["octets_sent"], c["octets_received"])
                  for (st, cs), c in sorted(self.unc_cells.items())]
            self.exporter.send(ex, un)
        self.reset_window()
        if final:
            self.emit({"type": "summary", "exec": {e: dict(c) for e, c in sorted(self.total.items())},
                       "uncredited": dict(self.total_unc)})


def iter_lines(f):
    for line in f:
        line = line.strip()
        if line.startswith("{"):
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def follow(path, stop):
    """Yields the lines appended to path (tail -F) until stop() is true and the
    file has no more data."""
    while not os.path.exists(path):
        if stop():
            return
        time.sleep(0.05)
    with open(path) as f:
        buf = ""
        while True:
            chunk = f.readline()
            if chunk:
                buf += chunk
                if buf.endswith("\n"):
                    yield buf
                    buf = ""
                continue
            if stop():
                return
            time.sleep(0.02)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--registry", required=True)
    ap.add_argument("--replay")
    ap.add_argument("--out")
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--reorder-ms", type=float, default=100.0)
    ap.add_argument("--ipfix", help="HOST:PORT of an IPFIX collector (UDP)")
    ap.add_argument("--follow", help="follow a growing collector stream file (live); SIGTERM ends it")
    a = ap.parse_args()
    out = open(a.out, "w") if a.out else sys.stdout
    reg_mtime = os.path.getmtime(a.registry)
    exporter = ipfix.Exporter(*a.ipfix.rsplit(":", 1)) if a.ipfix else None
    d = Daemon(json.load(open(a.registry)), int(a.interval * 1e9), int(a.reorder_ms * 1e6),
               emit=lambda r: (out.write(json.dumps(r) + "\n"), out.flush()),
               exporter=exporter, epoch_offset_ns=time.time_ns() - time.monotonic_ns())
    stopping = []
    signal.signal(signal.SIGTERM, lambda *_: stopping.append(1))
    if a.follow:
        src = follow(a.follow, lambda: bool(stopping))
    else:
        src = open(a.replay) if a.replay else sys.stdin
    try:
        for ev in iter_lines(src):
            if stopping and not a.follow:
                break
            if not a.replay and os.path.getmtime(a.registry) != reg_mtime:   # registry updated
                reg_mtime = os.path.getmtime(a.registry)
                d.load_registry(json.load(open(a.registry)))
            d.push(ev)
    except KeyboardInterrupt:
        pass
    d.drain()


if __name__ == "__main__":
    main()
