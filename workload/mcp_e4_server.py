#!/usr/bin/env python3
"""MCP server (official SDK, FastMCP, SSE transport) used in E4.

A single process serves every client session (shared worker). Each tool opens
ONE TCP connection to the requested port and emits agentnet's context markers
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
          agentnet_rt (per-task identity via contextvars, handed to the kernel
          at connect/fork); the identity comes from the request's _meta.

Usage: python3 mcp_e4_server.py --port 64999 [--binding manual|auto]
"""
import argparse
import asyncio
import os
import random
import socket
import sys

import anyio
from mcp.server.fastmcp import FastMCP

CTX_BEGIN = "/run/agentctx/begin/"
CTX_END = "/run/agentctx/end"
LISTEN = "127.0.0.1"                                  # MCP server listening address
TARGET = os.environ.get("AGENTNET_DEST", "127.0.0.1")   # destination of the tools (loopback or another machine)
SUB = ("import socket,sys;s=socket.socket();s.settimeout(2);"
       "r=s.connect_ex((sys.argv[1],int(sys.argv[2])));s.close();sys.exit(0 if r==0 else 1)")


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=64999)
    ap.add_argument("--binding", choices=["manual", "auto"], default="manual")
    a = ap.parse_args()
    global MANUAL
    MANUAL = a.binding == "manual"
    mcp = FastMCP("agentnet-e4", host=LISTEN, port=a.port, log_level="WARNING")

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

    if not MANUAL:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from agentnet_rt import mcp as agentnet_mcp
        agentnet_mcp.instrument(mcp)
    mcp.run(transport="sse")


if __name__ == "__main__":
    main()
