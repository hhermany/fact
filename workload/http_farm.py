#!/usr/bin/env python3
"""Minimal HTTP destinations for tools that use real client libraries (E5lib).

Like the workloads' Listener (and remote_farm.py), it listens on every planned
port, so the destination port remains the independent reference of the origin.
Unlike them, it answers each connection with a short HTTP/1.1 response
("200 OK", body "ok", Connection: close), because HTTP client libraries (httpx,
aiohttp, requests, urllib, curl) treat a connection closed without a response
as an error. Every connection is answered and closed: nothing is reused.

As a module: HttpListener(ports, addr).start() on the measured host.
As a script, on the second machine (not instrumented, no root needed):
  python3 http_farm.py --addr 0.0.0.0 --ranges 61000-61999
"""
import argparse
import resource
import selectors
import signal
import socket
import sys
import threading

RESPONSE = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n"
            b"Connection: close\r\n\r\nok")


def _serve(conn):
    try:
        conn.settimeout(5)
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 65536:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
        if buf:
            conn.sendall(RESPONSE)
    except OSError:
        pass
    finally:
        conn.close()


class HttpListener(threading.Thread):
    """Answers every connection on every planned port with a short HTTP response."""

    def __init__(self, ports, addr="127.0.0.1"):
        super().__init__(daemon=True)
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        want = min(hard, len(ports) + 1024)
        if soft < want:
            resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))
        self.sel = selectors.DefaultSelector()
        for p in ports:
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((addr, p))
            s.listen(256)
            s.setblocking(False)
            self.sel.register(s, selectors.EVENT_READ)
        self.stop = False

    def run(self):
        while not self.stop:
            for key, _ in self.sel.select(timeout=0.2):
                while True:
                    try:
                        c, _ = key.fileobj.accept()
                    except (BlockingIOError, ConnectionAbortedError):
                        break
                    c.setblocking(True)
                    threading.Thread(target=_serve, args=(c,), daemon=True).start()


def _serve_keepalive(conn, port, log, lock):
    """Serves several requests on one connection (HTTP/1.1 keep-alive) and logs,
    for each request, the byte ranges it occupied on the connection in each
    direction. The client's source port identifies the connection; the request
    path carries the operation id (the reference)."""
    peer = conn.getpeername()[1]
    rx = tx = 0
    buf = b""
    try:
        conn.settimeout(30)
        while True:
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                buf += chunk
            head, buf = buf.split(b"\r\n\r\n", 1)
            req_len = len(head) + 4
            length = 0
            for line in head.split(b"\r\n")[1:]:
                k, _, v = line.partition(b":")
                if k.strip().lower() == b"content-length":
                    length = int(v.strip())
            while len(buf) < length:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                buf += chunk
            buf = buf[length:]
            req_len += length
            path = head.split(b"\r\n", 1)[0].split(b" ")[1].decode()
            resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n"
                    b"Connection: keep-alive\r\n\r\nok")
            with lock:   # logged before answering, so the log is complete when the client sees the response
                log.append({"port": port, "peer_port": peer, "path": path,
                            "req": [rx, rx + req_len], "resp": [tx, tx + len(resp)]})
            conn.sendall(resp)
            rx += req_len
            tx += len(resp)
    except (OSError, ValueError, IndexError):
        pass
    finally:
        conn.close()


class KeepAliveHttpListener(HttpListener):
    """Like HttpListener, but keeps connections open across requests (so a client
    pool can reuse them) and records every request's byte ranges (E5reuse)."""

    def __init__(self, ports, addr="127.0.0.1"):
        super().__init__(ports, addr)
        self.log, self.lock = [], threading.Lock()

    def run(self):
        while not self.stop:
            for key, _ in self.sel.select(timeout=0.2):
                while True:
                    try:
                        c, _ = key.fileobj.accept()
                    except (BlockingIOError, ConnectionAbortedError):
                        break
                    c.setblocking(True)
                    port = key.fileobj.getsockname()[1]
                    threading.Thread(target=_serve_keepalive, args=(c, port, self.log, self.lock),
                                     daemon=True).start()

    def dump(self, path):
        import json
        with self.lock, open(path, "w") as f:
            for r in self.log:
                f.write(json.dumps(r) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--addr", default="0.0.0.0")
    ap.add_argument("--ranges", nargs="+", default=["61000-61999"])
    a = ap.parse_args()
    ports = []
    for r in a.ranges:
        lo, hi = (int(x) for x in r.split("-"))
        ports += range(lo, hi + 1)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    lst = HttpListener(ports, a.addr)
    print(f"ready {len(ports)} HTTP ports on {a.addr}", flush=True)
    lst.run()


if __name__ == "__main__":
    main()
