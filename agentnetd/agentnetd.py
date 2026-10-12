#!/usr/bin/env python3
"""agentnetd — atribuição e contabilidade por execução AO VIVO.

Lê o fluxo JSON do coletor (stdin ou --replay arquivo), mantém a árvore de
processos e o registro de execuções, atribui cada connect com o resolvedor
fundido (mesma função usada na avaliação offline; recebe só ts, pid, tid,
cgroup e ctx) e exporta, a cada intervalo, registros de fluxo por execução:

  {"type":"exec_flow","t0":..,"t1":..,"exec":"E01","connections":n,
   "established":x,"failed":y,"destinations":d}
  {"type":"uncredited","t0":..,"t1":..,"ambiguous":a,"unattributed":m,
   "ambiguous_sets":{"E01|E02": k, ...}}

Conexões ambíguas ou sem atribuição NUNCA são creditadas a uma execução: são
exportadas à parte, com os conjuntos de candidatos (ambiguidade explícita).

Eventos de CPUs diferentes podem chegar fora de ordem; um buffer de
reordenação (--reorder-ms) libera eventos em ordem de ts quando ficam mais
antigos que (maior ts visto - janela).

Uso:
  bpftrace -B line collector/agentnet-fast.bt | agentnetd.py --registry reg.json
  agentnetd.py --replay events.jsonl --registry reg.json --out flows.jsonl
"""
import argparse
import heapq
import json
import os
import sys
import time
from collections import Counter, defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "analysis"))
from resolvers import World, check_independence, resolve_fused, strip_reference_fields  # noqa: E402


class Daemon:
    def __init__(self, registry, interval_ns=1_000_000_000, reorder_ns=100_000_000, emit=None, filt=None):
        check_independence()
        self.w = World()
        self.load_registry(registry)
        self.interval = interval_ns
        self.reorder = reorder_ns
        self.emit = emit or (lambda r: print(json.dumps(r), flush=True))
        self.filt = filt                      # usado só em testes (mesmo filtro do score offline)
        self.heap, self.seq, self.max_ts = [], 0, 0
        self.win0 = None
        self.sk_exec = {}
        self.reset_window()
        self.total = defaultdict(Counter)     # exec -> totais (para o resumo final)
        self.total_unc = Counter()

    def load_registry(self, reg):
        self.w.roots = {int(k): set(v) for k, v in reg.get("roots", {}).items()}
        self.w.cgroups = {int(k): set(v) for k, v in reg.get("cgroups", {}).items()}

    def reset_window(self):
        self.win = defaultdict(Counter)
        self.dests = defaultdict(set)
        self.unc = Counter()
        self.amb_sets = Counter()

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
            else:
                self.unc["unattributed"] += 1
                self.total_unc["unattributed"] += 1
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
            self.emit({"type": "exec_flow", "t0": t0, "t1": t1, "exec": e,
                       "connections": c["connections"], "established": c["established"],
                       "failed": c["failed"], "destinations": len(self.dests[e])})
        if self.unc:
            self.emit({"type": "uncredited", "t0": t0, "t1": t1, "ambiguous": self.unc["ambiguous"],
                       "unattributed": self.unc["unattributed"], "ambiguous_sets": dict(self.amb_sets)})
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--registry", required=True)
    ap.add_argument("--replay")
    ap.add_argument("--out")
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--reorder-ms", type=float, default=100.0)
    a = ap.parse_args()
    out = open(a.out, "w") if a.out else sys.stdout
    reg_mtime = os.path.getmtime(a.registry)
    d = Daemon(json.load(open(a.registry)), int(a.interval * 1e9), int(a.reorder_ms * 1e6),
               emit=lambda r: (out.write(json.dumps(r) + "\n"), out.flush()))
    src = open(a.replay) if a.replay else sys.stdin
    try:
        for ev in iter_lines(src):
            if not a.replay and os.path.getmtime(a.registry) != reg_mtime:   # registro atualizado
                reg_mtime = os.path.getmtime(a.registry)
                d.load_registry(json.load(open(a.registry)))
            d.push(ev)
    except KeyboardInterrupt:
        pass
    d.drain()


if __name__ == "__main__":
    main()
