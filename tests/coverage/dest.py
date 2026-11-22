#!/usr/bin/env python3
# Destination of the coverage test (outside the policed cgroup): logs every newline-terminated
# tag it receives (and its size), with the listener and the peer's address, and answers each TCP tag with "r\n"
# (received bytes, charged in credential mode). One dual-stack socket per port serves IPv4,
# IPv6 and IPv4-mapped clients: TCP on base+1, UDP on base+2 and base+3,
# with base 62000, 62010 and 62020 for the families v4, v6 and v4mapped of client.py.
import json, socket, sys, threading
out = open(sys.argv[1], "a", buffering=1)
lock = threading.Lock()
def log(line, listener, peer):
    with lock:   # tags are padded to 48 bytes: n = bytes received, newline included
        out.write(json.dumps({"tag": line.decode(errors="replace").strip(), "n": len(line) + 1,
                              "listener": listener, "peer": peer}) + "\n")
def dual(kind, port):
    s = socket.socket(socket.AF_INET6, kind)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("::", port))
    return s
def tcp(port):
    s = dual(socket.SOCK_STREAM, port); s.listen(64)
    def conn(c, peer):
        buf = b""
        while True:
            b = c.recv(65536)
            if not b:
                break
            buf += b
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                log(line, f"tcp{port}", peer)
                try:
                    c.sendall(b"r\n")
                except OSError:
                    pass
        c.close()
    def acc():
        while True:
            c, a = s.accept()
            threading.Thread(target=conn, args=(c, a[0]), daemon=True).start()
    threading.Thread(target=acc, daemon=True).start()
def udp(port):
    s = dual(socket.SOCK_DGRAM, port)
    def rx():
        while True:
            b, a = s.recvfrom(65536)
            for line in b.split(b"\n"):
                if line:
                    log(line, f"udp{port}", a[0])
    threading.Thread(target=rx, daemon=True).start()
for base in (62000, 62010, 62020):
    tcp(base + 1)
    udp(base + 2)
    udp(base + 3)
print("ready", flush=True)
threading.Event().wait()
