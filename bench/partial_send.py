#!/usr/bin/env python3
"""Directed test of byte accounting under backpressure (E5partial).

A receiver thread with a small receive buffer reads slowly; the sender, with a
small send buffer and a NONBLOCKING socket, sends --total bytes in --chunk-byte
calls. Under backpressure many send() calls are partial (they queue fewer bytes
than requested) or fail with EAGAIN; the sender retries the remainder. The
sending thread carries the identity E01 (one marker), as in the MCP workloads.

Writes OUT/partial.json:
  requested      sum of the sizes passed to send() (what counting the size
                 requested at tcp_sendmsg would credit)
  accepted       sum of the positive return values of send()
  received       bytes the receiver read (the destination's count)
  calls, partial, eagain   number of send() calls, partial ones, and EAGAIN failures
Usage: partial_send.py --out OUT --port P [--total 8000000] [--chunk 65536]
"""
import argparse
import errno
import json
import os
import socket
import threading
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--total", type=int, default=8_000_000)
    ap.add_argument("--chunk", type=int, default=65536)
    a = ap.parse_args()
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
    ls.bind(("127.0.0.1", a.port))
    ls.listen(1)
    got = [0]

    def rx():
        c, _ = ls.accept()
        while True:
            b = c.recv(4096)
            if not b:
                break
            got[0] += len(b)
            time.sleep(0.0002)        # slow reader: the sender meets backpressure
        c.close()

    t = threading.Thread(target=rx)
    t.start()
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8192)
    s.connect(("127.0.0.1", a.port))
    s.setblocking(False)
    try:   # identity of the sending thread, as the runtime hands it over
        os.close(os.open("/run/agentctx/begin/E01", os.O_RDONLY))
    except FileNotFoundError:
        pass
    data = b"x" * a.chunk
    st = {"requested": 0, "accepted": 0, "calls": 0, "partial": 0, "eagain": 0}
    left = a.total
    while left > 0:
        n = min(left, a.chunk)
        st["calls"] += 1
        st["requested"] += n
        try:
            k = s.send(data[:n])
        except BlockingIOError as e:
            if e.errno != errno.EAGAIN:
                raise
            st["eagain"] += 1
            time.sleep(0.0005)
            continue
        st["accepted"] += k
        if k < n:
            st["partial"] += 1
        left -= k
    s.setblocking(True)
    s.shutdown(socket.SHUT_WR)
    t.join()
    s.close()
    ls.close()
    st["received"] = got[0]
    json.dump(st, open(os.path.join(a.out, "partial.json"), "w"), indent=1)
    print(json.dumps(st))


if __name__ == "__main__":
    main()
