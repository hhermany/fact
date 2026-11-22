#!/usr/bin/env python3
# Coverage test client (runs inside the policed cgroup; see run.sh). Execution A may reach ports
# 62001-62003; execution B may not. A opens the sockets, then B tries every send path, over IPv4,
# IPv6 and IPv4-mapped IPv6 addresses; each payload is a tag the destination logs, so delivery is
# observed at the destination, not inferred from return codes.
import ctypes, errno, json, os, socket, sys, tempfile, time
res = []
def mark(x):
    try:
        os.open("/run/agentctx/" + ("end" if x is None else "begin/" + x), os.O_RDONLY)
    except OSError:
        pass
def tag(name):
    return (name + "\n").encode()
def tryit(name, fn):
    try:
        r = fn()
        res.append({"test": name, "ret": r if isinstance(r, (int, type(None))) else str(r), "errno": 0})
    except OSError as e:
        res.append({"test": name, "ret": None, "errno": errno.errorcode.get(e.errno, e.errno)})
    time.sleep(0.05)
libc = ctypes.CDLL(None, use_errno=True)
class iovec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]
class msghdr(ctypes.Structure):
    _fields_ = [("name", ctypes.c_void_p), ("namelen", ctypes.c_uint), ("iov", ctypes.POINTER(iovec)),
                ("iovlen", ctypes.c_size_t), ("control", ctypes.c_void_p), ("controllen", ctypes.c_size_t),
                ("flags", ctypes.c_int)]
class mmsghdr(ctypes.Structure):
    _fields_ = [("hdr", msghdr), ("len", ctypes.c_uint)]
def sendmmsg(fd, data):
    buf = ctypes.create_string_buffer(data, len(data))
    iov = iovec(ctypes.cast(buf, ctypes.c_void_p), len(data))
    m = (mmsghdr * 1)()
    m[0].hdr.iov = ctypes.pointer(iov); m[0].hdr.iovlen = 1
    r = libc.sendmmsg(fd, m, 1, 0)
    if r < 0:
        e = ctypes.get_errno(); raise OSError(e, os.strerror(e))
    return r
mark("A")
a4 = socket.create_connection(("127.0.0.1", 62001))
u4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u4.connect(("127.0.0.1", 62002))
tryit("A_send_control", lambda: a4.send(tag("A_send_control")))
mark("B")
tryit("B_send", lambda: a4.send(tag("B_send")))
tryit("B_sendall", lambda: a4.sendall(tag("B_sendall")))
tryit("B_sendto_connected", lambda: a4.sendto(tag("B_sendto_connected"), ("127.0.0.1", 62001)))
tryit("B_sendmsg", lambda: a4.sendmsg([tag("B_sendmsg")]))
tryit("B_sendmmsg", lambda: sendmmsg(a4.fileno(), tag("B_sendmmsg")))
tryit("B_write", lambda: os.write(a4.fileno(), tag("B_write")))
tryit("B_writev", lambda: os.writev(a4.fileno(), [tag("B_writev")]))
f = tempfile.TemporaryFile(); f.write(tag("B_sendfile")); f.flush()
tryit("B_sendfile", lambda: os.sendfile(a4.fileno(), f.fileno(), 0, len(tag("B_sendfile"))))
def spl():
    r, w = os.pipe(); os.write(w, tag("B_splice"))
    return os.splice(r, a4.fileno(), len(tag("B_splice")))
tryit("B_splice", spl)
def zc():
    a4.setsockopt(socket.SOL_SOCKET, 60, 1)   # SO_ZEROCOPY
    return a4.send(tag("B_msg_zerocopy"), 0x4000000)   # MSG_ZEROCOPY
tryit("B_msg_zerocopy", zc)
dupfd = os.dup(a4.fileno())
tryit("B_write_dup_fd", lambda: os.write(dupfd, tag("B_write_dup_fd")))
tryit("B_udp_connected_send", lambda: u4.send(tag("B_udp_connected_send")))
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
tryit("B_udp_unconnected_sendto", lambda: u.sendto(tag("B_udp_unconnected_sendto"), ("127.0.0.1", 62002)))
def newc():
    s = socket.create_connection(("127.0.0.1", 62001), timeout=2); s.send(tag("B_connect4_new")); return 0
tryit("B_connect4_new", newc)
def c6():
    s = socket.socket(socket.AF_INET6); s.settimeout(2); s.connect(("::1", 62001)); s.send(tag("B_ipv6_connect")); return 0
tryit("B_ipv6_connect", c6)
def mapped():
    s = socket.socket(socket.AF_INET6); s.settimeout(2); s.connect(("::ffff:127.0.0.1", 62003)); s.send(tag("B_v4mapped_connect")); return 0
tryit("B_v4mapped_connect", mapped)
u6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
tryit("B_ipv6_udp_sendto", lambda: u6.sendto(tag("B_ipv6_udp_sendto"), ("::1", 62002)))
# IPv6: A may use its destinations over IPv6 too (same ports); B may not, on A's socket or its own
mark("A")
a6 = socket.socket(socket.AF_INET6); a6.connect(("::1", 62001))
tryit("A_ipv6_send", lambda: a6.send(tag("A_ipv6_send")))
ua6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
tryit("A_ipv6_udp_sendto", lambda: ua6.sendto(tag("A_ipv6_udp_sendto"), ("::1", 62002)))
def amapped():
    s = socket.socket(socket.AF_INET6); s.settimeout(2); s.connect(("::ffff:127.0.0.1", 62003)); s.send(tag("A_v4mapped_connect")); return 0
tryit("A_v4mapped_connect", amapped)
tryit("A_v4mapped_udp_sendto", lambda: ua6.sendto(tag("A_v4mapped_udp_sendto"), ("::ffff:127.0.0.1", 62002)))
mark("B")
tryit("B_ipv6_send_on_A_socket", lambda: a6.send(tag("B_ipv6_send_on_A_socket")))
tryit("B_v4mapped_udp_sendto", lambda: ua6.sendto(tag("B_v4mapped_udp_sendto"), ("::ffff:127.0.0.1", 62002)))
mark(None)
def noctx():
    s = socket.create_connection(("127.0.0.1", 62001), timeout=2); s.send(tag("noctx_connect4")); return 0
tryit("noctx_connect4", noctx)
mark("A")
tryit("A_send_after", lambda: a4.send(tag("A_send_after")))
time.sleep(0.3)
json.dump(res, open(sys.argv[1], "w"), indent=1)
