"""Task-scoped binding of the execution identity in the runtime (user-space side).

Problem (E4): the kernel context is keyed by thread. A marker emitted at the
start of an async tool call is overwritten when another coroutine runs on the
same event-loop thread, and connections leave with the wrong identity, without
any kernel signal detecting it.

Solution: the identity follows the TASK (contextvars, which asyncio copies into
every Task and anyio/asyncio.to_thread copy into worker threads) and is handed
to the kernel immediately before each event that the kernel attributes:
  - connect() on AF_INET/AF_INET6 sockets;
  - process creation (subprocess.Popen and os.fork).
There is no await between the marker and the system call, so no other coroutine
can run in between: the connection (or the child) carries the identity of the
task that created it. Without a current identity, the kernel context is cleared
before connect: the connection has no context (the resolver reports it as
ambiguous/uncredited) instead of inheriting a stale identity.

The delivery mechanism is the same as the collector's: openat on
/run/agentctx/begin/<id> or /run/agentctx/end (nonexistent paths; the cost is
one failed system call). A per-thread cache avoids re-marking when the identity
has not changed: a thread's kernel context only changes through markers emitted
by that thread (or through inheritance at creation, when the new thread's cache
is still empty).

Optional send binding (install(sends=True)): the identity is also handed to the
kernel right before each send on an AF_INET/AF_INET6 socket (send, sendall,
sendto, sendmsg), so that the bytes of a connection reused by several tasks
(e.g., an HTTP client's connection pool shared by sessions) carry the identity
of the task that sends them, not of the task that opened the connection. With
asyncio, a transport's write() sends immediately from the calling task, and a
deferred write runs in the context captured when the writer was registered.
It is off by default; the experiments before E5reuse ran without it.

Optional clearing (install(clear=True)): the thread's kernel context is cleared
right after each hooked system call, so code that bypasses the hooks (e.g., a
native library calling connect(2) directly) finds no identity on the thread
instead of the identity of the last task that connected on it. The resolver then
reports such connections as ambiguous or unattributed and the policy applies its
default action, instead of crediting them to a wrong execution (E5native). The
cost is one more failed system call per hooked call; off by default before E5native.

UDP (install(udp=True)): the identity is also handed over before each send on an
AF_INET/AF_INET6 datagram socket (send, sendto, sendmsg, sendall; connected or
not), where the kernel sees a UDP flow, and asyncio's getaddrinfo runs the
resolver in the caller's context, so the resolver thread carries the caller's
identity (E5udp).

Execution credential (FACT_IFACE=prctl, or install(iface="prctl")): instead of
openat markers, the identity is switched with prctl(PR_FACT, FACT_SET, id) or
prctl(PR_FACT, FACT_CLEAR), which the kernel side (fact_policy with cred=1)
authorizes in the BPF LSM hook task_prctl and stores as a credential of the task.
A refused switch (EPERM: the caller is not a trusted runtime process) is counted
in stats["refused"]. install() fails if the kernel side is not loaded (EINVAL),
so the runtime never runs believing it is bound when it is not.

Usage:
    from fact_rt import agentctx
    agentctx.install()
    with agentctx.bind("exec-42"):
        ...   # connections and subprocesses of this task carry exec-42
"""
import contextvars
import ctypes
import os
import socket
import subprocess
import threading
from contextlib import contextmanager

CTX_BEGIN = "/run/agentctx/begin/"
CTX_END = "/run/agentctx/end"
_UNSET = object()

current = contextvars.ContextVar("fact_exec", default=None)
_tls = threading.local()
_lock = threading.Lock()
stats = {"marks": 0, "cached": 0, "refused": 0}
IFACE = os.environ.get("FACT_IFACE", "openat")   # "openat" (markers) or "prctl" (execution credential)
PR_FACT, FACT_SET, FACT_CLEAR = 0x46414354, 1, 2
_prctl = None
_ids = {}
_installed = False
_clear = False          # install(clear=True): clear the thread's kernel context after each hooked call
enabled = True          # False disables the hooks without uninstalling them (tests)
_orig = {}


def _emit(path):
    try:
        os.close(os.open(path, os.O_RDONLY))
    except FileNotFoundError:
        pass


FACT_ACK = 114   # EALREADY: the kernel side acknowledges an applied switch


def _acked(r):
    return r == -1 and ctypes.get_errno() == FACT_ACK


def _prctl_init():
    global _prctl
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    f = libc.prctl
    f.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_ulong]
    f.restype = ctypes.c_int
    if not _acked(f(PR_FACT, FACT_CLEAR, None, 0, 0)):
        raise RuntimeError("execution credential unavailable: load fact_policy with cred=1 (BPF LSM)")
    _prctl = f


def _switch(want):
    """Hands the identity `want` (None = clear) to the kernel."""
    if IFACE == "prctl":
        if want is None:
            r = _prctl(PR_FACT, FACT_CLEAR, None, 0, 0)
        else:
            b = _ids.get(want)
            if b is None:
                b = _ids[want] = want.encode()
            r = _prctl(PR_FACT, FACT_SET, b, 0, 0)
        if not _acked(r):
            with _lock:
                stats["refused"] += 1
        return
    _emit(CTX_BEGIN + want if want is not None else CTX_END)


def _valid(exec_id):
    return isinstance(exec_id, str) and 0 < len(exec_id) <= 40 and "/" not in exec_id and "\0" not in exec_id


def sync_kernel():
    """Sets the calling thread's kernel context to the identity of the current
    task. Must be called with no await between it and the system call it guards."""
    if not enabled:
        return
    want = current.get()
    if getattr(_tls, "last", _UNSET) == want:
        with _lock:
            stats["cached"] += 1
        return
    # Code the runtime mediates carries the identity of the task that runs it, even in
    # a thread that inherited another credential at clone (a pool worker created during
    # one execution may later run another's task): an empty context clears it. The
    # kernel's inheritance (rule R2) covers what the runtime does not mediate: child
    # processes and native threads.
    _switch(want)
    _tls.last = want
    with _lock:
        stats["marks"] += 1


def clear_kernel():
    """Clears the calling thread's kernel context (install(clear=True))."""
    if not enabled or not _clear:
        return
    if getattr(_tls, "last", _UNSET) is None:
        return
    _switch(None)
    _tls.last = None
    with _lock:
        stats["marks"] += 1


def invalidate():
    """Forgets the per-thread cache (use if other code emits markers)."""
    _tls.last = _UNSET


@contextmanager
def bind(exec_id):
    """Binds exec_id to the current task (sync or async) for the duration of the block."""
    if exec_id is not None and not _valid(exec_id):
        raise ValueError(f"invalid execution identity: {exec_id!r}")
    tok = current.set(exec_id)
    try:
        yield
    finally:
        current.reset(tok)


def install(sends=False, clear=False, udp=False, iface=None):
    """Installs the connect and process-creation hooks (idempotent); with
    sends=True, also the send hooks; with clear=True, the thread's kernel context
    is cleared after each hooked call; with udp=True, the datagram hooks (see the
    module docstring)."""
    global _installed, _clear, IFACE
    if (iface or IFACE) == "prctl" and _prctl is None:
        _prctl_init()   # before switching the interface: fails if the kernel side is missing
    if iface:
        IFACE = iface
    _clear = _clear or clear
    if udp and not _orig.get("dgram"):
        _install_dgram()
    if sends and not _orig.get("send"):
        _install_sends()
    if _installed:
        return
    _orig["connect"] = socket.socket.connect
    _orig["connect_ex"] = socket.socket.connect_ex
    _orig["execute_child"] = subprocess.Popen._execute_child

    def connect(self, address):
        if self.family not in (socket.AF_INET, socket.AF_INET6):
            return _orig["connect"](self, address)
        sync_kernel()
        try:
            return _orig["connect"](self, address)
        finally:
            clear_kernel()

    def connect_ex(self, address):
        if self.family not in (socket.AF_INET, socket.AF_INET6):
            return _orig["connect_ex"](self, address)
        sync_kernel()
        try:
            return _orig["connect_ex"](self, address)
        finally:
            clear_kernel()

    def execute_child(self, *args, **kwargs):
        sync_kernel()
        try:
            return _orig["execute_child"](self, *args, **kwargs)
        finally:
            clear_kernel()

    socket.socket.connect = connect
    socket.socket.connect_ex = connect_ex
    subprocess.Popen._execute_child = execute_child
    os.register_at_fork(before=sync_kernel, after_in_parent=clear_kernel)
    _installed = True


def _install_sends():
    for name in ("send", "sendall", "sendto", "sendmsg"):
        orig = getattr(socket.socket, name)
        _orig[name] = orig

        def hook(self, *args, _orig_fn=orig, **kwargs):
            if self.family not in (socket.AF_INET, socket.AF_INET6):
                return _orig_fn(self, *args, **kwargs)
            sync_kernel()
            try:
                return _orig_fn(self, *args, **kwargs)
            finally:
                clear_kernel()

        hook.__name__ = name
        setattr(socket.socket, name, hook)


def _install_dgram():
    import asyncio.base_events
    _orig["dgram"] = True
    for name in ("send", "sendall", "sendto", "sendmsg"):
        orig = getattr(socket.socket, name)

        def hook(self, *args, _orig_fn=orig, **kwargs):
            if self.type != socket.SOCK_DGRAM or self.family not in (socket.AF_INET, socket.AF_INET6):
                return _orig_fn(self, *args, **kwargs)
            sync_kernel()
            try:
                return _orig_fn(self, *args, **kwargs)
            finally:
                clear_kernel()

        hook.__name__ = name
        setattr(socket.socket, name, hook)

    gai = socket.getaddrinfo
    _orig["getaddrinfo"] = gai

    def getaddrinfo(*args, **kwargs):
        sync_kernel()
        try:
            return gai(*args, **kwargs)
        finally:
            clear_kernel()

    socket.getaddrinfo = getaddrinfo
    loop_gai = asyncio.base_events.BaseEventLoop.getaddrinfo

    async def loop_getaddrinfo(self, host, port, *, family=0, type=0, proto=0, flags=0):
        # run_in_executor does not copy the caller's context; do it, so that the
        # resolver thread hands the caller's identity to the kernel
        ctx = contextvars.copy_context()
        return await self.run_in_executor(None, ctx.run, getaddrinfo, host, port, family, type, proto, flags)

    _orig["loop_getaddrinfo"] = loop_gai
    asyncio.base_events.BaseEventLoop.getaddrinfo = loop_getaddrinfo
