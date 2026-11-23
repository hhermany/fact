#!/usr/bin/env python3
# Coverage test client (runs inside the policed cgroup; see run.sh).
# Usage: client.py OUT_JSON FAMILY MODE  (ports: TCP base+1, UDP base+2 and base+3)
#, FAMILY in v4 | v6 | v4mapped, MODE in persend | connect | cred | budget.
# The same battery runs in every family, each on its own ports (TCP base+1, UDP base+2): execution A
# may reach them, B may not. A opens the sockets, then B tries every send path; A sends again; a
# connection without identity follows. In budget mode, Q (3 connections), R (100 bytes over TCP),
# V (R's budget, with a decoy address passed with each TCP send) and S (50 bytes of datagrams)
# test the kernel-held budgets. Identities are handed over with
# markers (openat), or with the credential (prctl) in cred mode. Every payload is a tag padded to
# 48 bytes that the destination logs, so delivery is observed at the destination.
import ctypes, errno, json, os, socket, sys, tempfile, time
out, FAM, MODE = sys.argv[1], sys.argv[2], sys.argv[3]
AF, HOST, BASE = {"v4": (socket.AF_INET, "127.0.0.1", 62000), "v6": (socket.AF_INET6, "::1", 62010),
                  "v4mapped": (socket.AF_INET6, "::ffff:127.0.0.1", 62020)}[FAM]
T, U = BASE + 1, BASE + 2
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_ulong]
res, rx = [], {}
def ident(x):
    if MODE == "cred":   # execution credential: FACT_SET / FACT_CLEAR
        libc.prctl(0x46414354, 1 if x else 2, x.encode() if x else None, 0, 0)
        return
    try:
        os.close(os.open("/run/agentctx/" + ("end" if x is None else "begin/" + x), os.O_RDONLY))
    except OSError:
        pass
def tag(name):
    return (f"{FAM}/{name}".ljust(47) + "\n").encode()
def tryit(name, fn):
    try:
        r = fn()
        res.append({"test": name, "ret": r if isinstance(r, (int, type(None))) else str(r), "errno": 0})
    except OSError as e:
        res.append({"test": name, "ret": None, "errno": errno.errorcode.get(e.errno, e.errno)})
    time.sleep(0.05)
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
def connect_send(name, keep=None):
    s = socket.socket(AF); s.settimeout(2); s.connect((HOST, T)); r = s.send(tag(name))
    if keep is not None:
        keep.append(s)
    return r
def drain(socks):
    n = 0
    for s in socks:
        s.setblocking(False)
        try:
            while True:
                b = s.recv(65536)
                if not b:
                    break
                n += len(b)
        except (BlockingIOError, OSError):
            pass
    return n
# ---- A opens the sockets; B tries every send path on them and on its own
ident("A")
a = socket.socket(AF); a.connect((HOST, T))
u = socket.socket(AF, socket.SOCK_DGRAM); u.connect((HOST, U))
u3 = socket.socket(AF, socket.SOCK_DGRAM); u3.connect((HOST, U + 1))   # connected UDP B reuses (own port)
tryit("A_send_control", lambda: a.send(tag("A_send_control")))
tryit("A_udp_connected_send_control", lambda: u.send(tag("A_udp_connected_send_control")))
tryit("A_udp3_connected_send_control", lambda: u3.send(tag("A_udp3_connected_send_control")))
ident("B")
tryit("B_send", lambda: a.send(tag("B_send")))
tryit("B_sendall", lambda: a.sendall(tag("B_sendall")))
tryit("B_sendto_connected", lambda: a.sendto(tag("B_sendto_connected"), (HOST, T)))
# an address of an unpoliced port with a send on A's TCP connection: TCP ignores it, the policy too
tryit("B_sendto_decoy_port", lambda: a.sendto(tag("B_sendto_decoy_port"), (HOST, 22)))
tryit("B_sendmsg", lambda: a.sendmsg([tag("B_sendmsg")]))
tryit("B_sendmmsg", lambda: sendmmsg(a.fileno(), tag("B_sendmmsg")))
tryit("B_write", lambda: os.write(a.fileno(), tag("B_write")))
tryit("B_writev", lambda: os.writev(a.fileno(), [tag("B_writev")]))
f = tempfile.TemporaryFile(); f.write(tag("B_sendfile")); f.flush()
tryit("B_sendfile", lambda: os.sendfile(a.fileno(), f.fileno(), 0, len(tag("B_sendfile"))))
def spl():
    r, w = os.pipe(); os.write(w, tag("B_splice"))
    return os.splice(r, a.fileno(), len(tag("B_splice")))
tryit("B_splice", spl)
def zc():
    a.setsockopt(socket.SOL_SOCKET, 60, 1)   # SO_ZEROCOPY
    return a.send(tag("B_msg_zerocopy"), 0x4000000)   # MSG_ZEROCOPY
tryit("B_msg_zerocopy", zc)
dupfd = os.dup(a.fileno())
tryit("B_write_dup_fd", lambda: os.write(dupfd, tag("B_write_dup_fd")))
tryit("B_udp_connected_send", lambda: u3.send(tag("B_udp_connected_send")))
tryit("B_udp_sendto_peer_connected", lambda: u3.sendto(tag("B_udp_sendto_peer_connected"), (HOST, U + 1)))
ub = socket.socket(AF, socket.SOCK_DGRAM)
tryit("B_udp_unconnected_sendto", lambda: ub.sendto(tag("B_udp_unconnected_sendto"), (HOST, U)))
tryit("B_connect_new", lambda: connect_send("B_connect_new"))
# ---- A again: still permitted on its sockets, new datagrams and new connections
ident("A")
tryit("A_send_after", lambda: a.send(tag("A_send_after")))
ua = socket.socket(AF, socket.SOCK_DGRAM)
tryit("A_udp_unconnected_sendto", lambda: ua.sendto(tag("A_udp_unconnected_sendto"), (HOST, U)))
akeep = []
tryit("A_connect_new", lambda: connect_send("A_connect_new", akeep))
time.sleep(0.4)
rx["A"] = drain([a] + akeep)          # the destination's answers, read by A
# ---- no identity: default action (deny)
ident(None)
tryit("N_connect_new", lambda: connect_send("N_connect_new"))
# ---- budgets (budget mode): connections, TCP bytes and datagram bytes
if MODE == "budget":
    ident("Q")
    qkeep = []
    for k in range(1, 5):
        tryit(f"Q_conn_{k}", lambda k=k: connect_send(f"Q_conn_{k}", qkeep))
    ident("R")
    r = socket.socket(AF); r.connect((HOST, T))
    for k in range(1, 9):
        tryit(f"R_send_{k}", lambda k=k: r.send(tag(f"R_send_{k}")))
    ident("V")   # the byte budget of R, with an unpoliced port's address passed with every TCP send
    v = socket.socket(AF); v.connect((HOST, T))
    for k in range(1, 5):
        tryit(f"V_sendto_decoy_{k}", lambda k=k: v.sendto(tag(f"V_sendto_decoy_{k}"), (HOST, 22)))
    ident("S")
    s = socket.socket(AF, socket.SOCK_DGRAM)
    for k in range(1, 5):
        tryit(f"S_sendto_{k}", lambda k=k: s.sendto(tag(f"S_sendto_{k}"), (HOST, U)))
ident(None)
time.sleep(0.3)
json.dump({"family": FAM, "mode": MODE, "tests": res, "rx_read": rx}, open(out, "w"), indent=1)
