#!/usr/bin/env python3
"""Cost of fact_rt's send binding, per send() on a kept-alive loopback connection.

A local server thread reads and discards; the client sends --n messages of --size
bytes on ONE connection, in each mode (order randomized per repetition):
  off        plain socket.send (hooks removed)
  same       send hooks installed, the identity does not change between sends
             (per-thread cache hit: no system call is added)
  rebind     as same, but the identity is (re)bound around every send (cost of the
             contextvar set/reset that an alternating workload also pays)
  alternate  send hooks installed, the identity alternates between two executions
             at every send (worst case: one marker, i.e. one failed openat, per send);
             the marker's own cost is alternate - rebind
Prints one JSON line per (repetition, mode) with ns per send (median of --batches
batches). Run it with and without a collector active (bench/send_bind_round.sh) to
include the collector's cost of tracing the markers and the sends.

Usage: python3 send_bind.py --n 20000 --size 256 --reps 10 --seed 1
"""
import argparse
import json
import os
import random
import socket
import statistics as st
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from fact_rt import agentctx  # noqa: E402

HOOK = None


def server(lsock):
    c, _ = lsock.accept()
    while c.recv(1 << 16):
        pass


def run(mode, n, size, batches):
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    threading.Thread(target=server, args=(lsock,), daemon=True).start()
    s = socket.socket()
    s.connect(lsock.getsockname())
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    msg = b"x" * size
    socket.socket.send = agentctx._orig["send"] if mode == "off" else HOOK
    agentctx.invalidate()
    per = []
    ids = ("execA", "execB")
    for _ in range(batches):
        t0 = time.perf_counter_ns()
        if mode in ("alternate", "rebind"):
            alt = mode == "alternate"
            for i in range(n):
                with agentctx.bind(ids[i & 1] if alt else ids[0]):
                    s.send(msg)
        else:
            with agentctx.bind("execA"):
                for _ in range(n):
                    s.send(msg)
        per.append((time.perf_counter_ns() - t0) / n)
    s.close()
    lsock.close()
    return st.median(per)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=20000)
    ap.add_argument("--size", type=int, default=256)
    ap.add_argument("--reps", type=int, default=10)
    ap.add_argument("--batches", type=int, default=5)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--label", default="")
    a = ap.parse_args()
    global HOOK
    agentctx.install(sends=True)
    HOOK = socket.socket.send
    rng = random.Random(a.seed)
    modes = ["off", "same", "rebind", "alternate"]
    run("off", 2000, a.size, 1)   # warm-up
    for rep in range(a.reps):
        rng.shuffle(modes)
        for m in modes:
            ns = run(m, a.n, a.size, a.batches)
            print(json.dumps({"label": a.label, "rep": rep, "mode": m, "ns_per_send": round(ns, 1),
                              "n": a.n, "size": a.size}), flush=True)


if __name__ == "__main__":
    main()
