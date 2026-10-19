#!/usr/bin/env python3
"""Destination services on a second machine (experiments over the network interface).

Accepts and closes connections on every port of the given ranges, like the
workloads' local Listener, but listening on the network interface's address. Runs
on the destination machine (not instrumented); the measured host connects to it
through the workloads' --dest-host. Does not need root (ports above 1024).

Usage: python3 remote_farm.py --addr 0.0.0.0 --ranges 61000-61999 65000-65499
"""
import argparse
import resource
import selectors
import signal
import socket
import sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--addr", default="0.0.0.0")
    ap.add_argument("--ranges", nargs="+", default=["61000-61999", "65000-65499"])
    a = ap.parse_args()
    ports = []
    for r in a.ranges:
        lo, hi = (int(x) for x in r.split("-"))
        ports += range(lo, hi + 1)
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    want = min(hard, len(ports) + 256)
    if soft < want:
        resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))
    sel = selectors.DefaultSelector()
    for p in ports:
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((a.addr, p))
        s.listen(1024)
        s.setblocking(False)
        sel.register(s, selectors.EVENT_READ)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    print(f"ready {len(ports)} ports on {a.addr}", flush=True)
    while True:
        for key, _ in sel.select():
            while True:
                try:
                    c, _ = key.fileobj.accept()
                    c.close()
                except (BlockingIOError, ConnectionAbortedError):
                    break


if __name__ == "__main__":
    main()
