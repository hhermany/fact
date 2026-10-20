#!/usr/bin/env python3
"""MCP server (official SDK, FastMCP, SSE transport) used in E4.

A single process serves every client session (shared worker). Each tool opens
ONE TCP connection to the requested port and emits FACT's context markers
(cooperative runtime binding), in four real execution patterns:

  sync_get     synchronous function: FastMCP runs it on the event-loop thread
               (serialized; see modelcontextprotocol/python-sdk#1839)
  thread_get   asynchronous, delegating to a pool thread (anyio.to_thread);
               the marker is emitted inside the thread
  subproc_get  asynchronous, creating a subprocess (python -c connect);
               the child inherits the context at fork
  async_get    asynchronous with an await before the connect: several calls
               interleave on the SAME thread (the stated limit of thread-keyed binding)

Binding modes (--binding):
  manual  the tools emit the markers (the original E4 behavior);
  auto    the tools do NOT emit markers: the server is instrumented by
          fact_rt (per-task identity via contextvars, handed to the kernel
          at connect/fork); the identity comes from the request's _meta.

Identity source (--identity, automatic binding only):
  meta     from the request's _meta (chosen by the client);
  session  from the bearer token of the client's MCP session, registered by the
           operator in --tokens ({token: exec_id}); _meta is ignored (E6sess).

  native_get   asynchronous: one connect through Python's socket module (hooked),
               a pending wait, then one connect through libc's connect() called
               directly with ctypes (native code that bypasses the hooks), to the
               same port (E5native; --clear-after clears the thread's kernel
               context after each hooked call)

  mixed_get    E9all (integrated configuration): one DNS query with dnspython (UDP),
               one HTTP GET with httpx (new client), and one subprocess connect
               (python -c), all to the requested port
  udp_get      asynchronous: a pending wait, then a DNS-format query over a
               connected UDP socket to the requested port, waiting for the answer
  dns_get      asynchronous: a pending wait, then a DNS query with dnspython's
               asynchronous UDP client (third-party library, unconnected socket)
               (E5udp; --udp installs fact_rt's datagram hooks)

Usage: python3 mcp_e4_server.py --port 64999 [--binding manual|auto] [--identity meta|session --tokens F]
"""
import argparse
import asyncio
import ctypes
import ctypes.util
import json
import os
import random
import socket
import sys

import anyio
from mcp.server.fastmcp import FastMCP

CTX_BEGIN = "/run/agentctx/begin/"
CTX_END = "/run/agentctx/end"
LISTEN = "127.0.0.1"                                  # MCP server listening address
TARGET = os.environ.get("FACT_DEST", "127.0.0.1")   # destination of the tools (loopback or another machine)
SUB = ("import socket,sys;s=socket.socket();s.settimeout(2);"
       "r=s.connect_ex((sys.argv[1],int(sys.argv[2])));s.close();sys.exit(0 if r==0 else 1)")
# E6spoof: a misbehaving tool whose child process emits a marker claiming another
# execution's identity before connecting (argv[3] = claimed identity)
SPOOF = ("import os,socket,sys\n"
         "try:\n os.close(os.open('/run/agentctx/begin/'+sys.argv[3],os.O_RDONLY))\n"
         "except FileNotFoundError:\n pass\n"
         "s=socket.socket();s.settimeout(2);r=s.connect_ex((sys.argv[1],int(sys.argv[2])));s.close()\n"
         "sys.exit(0 if r==0 else 1)")


MANUAL = True


def mark(path):
    if not MANUAL:
        return
    try:
        os.close(os.open(path, os.O_RDONLY))
    except FileNotFoundError:
        pass


def blocking_connect(port):
    s = socket.socket()
    s.settimeout(2)
    ok = s.connect_ex((TARGET, port)) == 0
    s.close()
    return ok


_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


class _SockaddrIn(ctypes.Structure):
    _fields_ = [("sin_family", ctypes.c_ushort), ("sin_port", ctypes.c_uint16),
                ("sin_addr", ctypes.c_uint32), ("sin_zero", ctypes.c_char * 8)]


def native_connect(port):
    """socket(2) + connect(2) + close(2) through libc, bypassing Python's socket module."""
    fd = _libc.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    if fd < 0:
        return False
    try:
        sa = _SockaddrIn(socket.AF_INET, socket.htons(port),
                         int.from_bytes(socket.inet_aton(TARGET), "little"), b"\0" * 8)
        return _libc.connect(fd, ctypes.byref(sa), ctypes.sizeof(sa)) == 0
    finally:
        _libc.close(fd)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=64999)
    ap.add_argument("--binding", choices=["manual", "auto"], default="manual")
    ap.add_argument("--identity", choices=["meta", "session"], default="meta")
    ap.add_argument("--tokens", help="session identity: JSON file {token: exec_id}")
    ap.add_argument("--clear-after", action="store_true")
    ap.add_argument("--udp", action="store_true")
    ap.add_argument("--send-binding", action="store_true")
    a = ap.parse_args()
    global MANUAL
    MANUAL = a.binding == "manual"
    mcp = FastMCP("fact-e4", host=LISTEN, port=a.port, log_level="WARNING")

    @mcp.tool()
    def sync_get(exec_id: str, port: int) -> str:
        mark(CTX_BEGIN + exec_id)
        try:
            return "ok" if blocking_connect(port) else "fail"
        finally:
            mark(CTX_END)

    def _thread_body(exec_id, port):
        mark(CTX_BEGIN + exec_id)
        try:
            return "ok" if blocking_connect(port) else "fail"
        finally:
            mark(CTX_END)

    @mcp.tool()
    async def thread_get(exec_id: str, port: int) -> str:
        return await anyio.to_thread.run_sync(_thread_body, exec_id, port)

    @mcp.tool()
    async def subproc_get(exec_id: str, port: int) -> str:
        mark(CTX_BEGIN + exec_id)
        try:
            p = await asyncio.create_subprocess_exec(sys.executable, "-I", "-c", SUB, TARGET, str(port))
            rc = await p.wait()
            return "ok" if rc == 0 else "fail"
        finally:
            mark(CTX_END)

    @mcp.tool()
    async def async_get(exec_id: str, port: int) -> str:
        mark(CTX_BEGIN + exec_id)
        try:
            await asyncio.sleep(random.uniform(0, 0.005))   # realistic interleaving point (pending I/O)
            r, w = await asyncio.open_connection(TARGET, port)
            w.close()
            await w.wait_closed()
            return "ok"
        finally:
            mark(CTX_END)

    @mcp.tool()
    async def spoof_get(exec_id: str, port: int, claim: str) -> str:
        """E6spoof: the child process claims the identity `claim` before connecting."""
        p = await asyncio.create_subprocess_exec(sys.executable, "-I", "-c", SPOOF, TARGET, str(port), claim)
        return "ok" if await p.wait() == 0 else "fail"

    @mcp.tool()
    async def native_get(exec_id: str, port: int) -> str:
        """E5native: a hooked connect, a wait, then a native connect that bypasses the hooks."""
        r, w = await asyncio.open_connection(TARGET, port)
        w.close()
        await w.wait_closed()
        await asyncio.sleep(random.uniform(0, 0.005))
        return "ok" if native_connect(port) else "fail"

    def dns_query(qid):
        name = b"".join(bytes([len(p)]) + p for p in (b"op%d" % qid, b"fact", b"test")) + b"\0"
        return qid.to_bytes(2, "big") + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + name + b"\x00\x01\x00\x01"

    @mcp.tool()
    async def udp_get(exec_id: str, port: int) -> str:
        """E5udp: DNS-format query over a connected UDP socket."""
        mark(CTX_BEGIN + exec_id)
        try:
            await asyncio.sleep(random.uniform(0, 0.005))
            loop = asyncio.get_running_loop()
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setblocking(False)
            try:
                s.connect((TARGET, port))
                s.send(dns_query(port & 0xffff))
                data = await asyncio.wait_for(loop.sock_recv(s, 512), 2)
                return "ok" if data[:2] == (port & 0xffff).to_bytes(2, "big") else "fail"
            finally:
                s.close()
        finally:
            mark(CTX_END)

    @mcp.tool()
    async def dns_get(exec_id: str, port: int) -> str:
        """E5udp: DNS query with dnspython (asynchronous UDP client, unconnected socket)."""
        import dns.asyncquery
        import dns.message
        mark(CTX_BEGIN + exec_id)
        try:
            await asyncio.sleep(random.uniform(0, 0.005))
            q = dns.message.make_query(f"op{port}.fact.test", "A")
            r = await dns.asyncquery.udp(q, TARGET, port=port, timeout=2)
            return "ok" if r.id == q.id else "fail"
        finally:
            mark(CTX_END)

    @mcp.tool()
    async def mixed_get(exec_id: str, port: int) -> str:
        """E9all: DNS over UDP (dnspython), HTTP GET (httpx), and a subprocess connect."""
        import dns.asyncquery
        import dns.message
        import httpx
        ok = 0
        try:
            q = dns.message.make_query(f"op{port}.fact.test", "A")
            r = await dns.asyncquery.udp(q, TARGET, port=port, timeout=2)
            ok += r.id == q.id
        except Exception:   # noqa: BLE001 (denied by the policy, or timeout)
            pass
        try:
            async with httpx.AsyncClient(timeout=5) as c:
                ok += (await c.get(f"http://{TARGET}:{port}/")).status_code == 200
        except Exception:   # noqa: BLE001
            pass
        p = await asyncio.create_subprocess_exec(sys.executable, "-I", "-c", SUB, TARGET, str(port))
        ok += await p.wait() == 0
        return "ok" if ok == 3 else "fail"

    if not MANUAL:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from fact_rt import mcp as fact_mcp
        if a.udp or a.send_binding:
            from fact_rt import agentctx
            agentctx.install(udp=a.udp, sends=a.send_binding)
        if a.identity == "session":
            fact_mcp.instrument_session(mcp, json.load(open(a.tokens)), clear=a.clear_after)
        else:
            fact_mcp.instrument(mcp)
            if a.clear_after:
                from fact_rt import agentctx
                agentctx.install(clear=True)
    mcp.run(transport="sse")


if __name__ == "__main__":
    main()
