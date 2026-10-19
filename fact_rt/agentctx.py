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

Usage:
    from fact_rt import agentctx
    agentctx.install()
    with agentctx.bind("exec-42"):
        ...   # connections and subprocesses of this task carry exec-42
"""
import contextvars
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
stats = {"marks": 0, "cached": 0}
_installed = False
enabled = True          # False disables the hooks without uninstalling them (tests)
_orig = {}


def _emit(path):
    try:
        os.close(os.open(path, os.O_RDONLY))
    except FileNotFoundError:
        pass


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
    _emit(CTX_BEGIN + want if want is not None else CTX_END)
    _tls.last = want
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


def install():
    """Installs the connect and process-creation hooks (idempotent)."""
    global _installed
    if _installed:
        return
    _orig["connect"] = socket.socket.connect
    _orig["connect_ex"] = socket.socket.connect_ex
    _orig["execute_child"] = subprocess.Popen._execute_child

    def connect(self, address):
        if self.family in (socket.AF_INET, socket.AF_INET6):
            sync_kernel()
        return _orig["connect"](self, address)

    def connect_ex(self, address):
        if self.family in (socket.AF_INET, socket.AF_INET6):
            sync_kernel()
        return _orig["connect_ex"](self, address)

    def execute_child(self, *args, **kwargs):
        sync_kernel()
        return _orig["execute_child"](self, *args, **kwargs)

    socket.socket.connect = connect
    socket.socket.connect_ex = connect_ex
    subprocess.Popen._execute_child = execute_child
    os.register_at_fork(before=sync_kernel)
    _installed = True
