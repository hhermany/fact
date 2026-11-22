#!/usr/bin/env python3
# Destination for the coverage test: logs every tag it receives, per listener (outside the policed cgroup).
import json, socket, sys, threading
out = open(sys.argv[1], "a", buffering=1)
def log(listener, data):
    for t in data.decode(errors="replace").split("\n"):
        if t.strip():
            out.write(json.dumps({"listener": listener, "tag": t.strip()}) + "\n")
def tcp(fam, addr, port, name, v6only=1):
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if fam == socket.AF_INET6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, v6only)
    s.bind((addr, port)); s.listen(64)
    def serve(c):
        buf = b""
        while True:
            d = c.recv(65536)
            if not d:
                break
            buf += d
            if b"\n" in buf:
                head, _, buf = buf.rpartition(b"\n")
                log(name, head)
        if buf:
            log(name, buf)
    while True:
        c, _ = s.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()
def udp(fam, addr, port, name):
    s = socket.socket(fam, socket.SOCK_DGRAM)
    if fam == socket.AF_INET6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind((addr, port))
    while True:
        d, _ = s.recvfrom(65536)
        log(name, d)
for args in [(socket.AF_INET, "127.0.0.1", 62001, "tcp4"), (socket.AF_INET6, "::1", 62001, "tcp6"),
             (socket.AF_INET6, "::", 62003, "tcp6_dualstack", 0)]:
    threading.Thread(target=tcp, args=args, daemon=True).start()
for args in [(socket.AF_INET, "127.0.0.1", 62002, "udp4"), (socket.AF_INET6, "::1", 62002, "udp6")]:
    threading.Thread(target=udp, args=args, daemon=True).start()
print("ready", flush=True)
threading.Event().wait()
