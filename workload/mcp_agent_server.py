#!/usr/bin/env python3
"""MCP server with network tools, used by the LLM agents (E7).

A single process serves every session (shared worker), instrumented by
fact_rt (automatic binding: the identity comes from the _meta of each
tools/call; the tools know nothing about FACT). Three tools with different
execution patterns:

  http_get(url)     async: HTTP/1.0 request with asyncio (interleaves on the event loop)
  fetch_url(url)    subprocess: python -c urllib (the child inherits the identity)
  tcp_check(host, port)  pool thread (anyio.to_thread): TCP connection test

Usage: python3 mcp_agent_server.py --port 64999 [--binding auto|none]
"""
import argparse
import asyncio
import os
import socket
import sys
from urllib.parse import urlparse

import anyio
from mcp.server.fastmcp import FastMCP

FETCH = ("import sys,urllib.request\n"
         "try:\n"
         "  r=urllib.request.urlopen(sys.argv[1],timeout=3); print(r.status, r.read(200).decode(errors='replace'))\n"
         "except Exception as e:\n"
         "  print('error', e); sys.exit(1)\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=64999)
    ap.add_argument("--binding", choices=["auto", "none"], default="auto")
    a = ap.parse_args()
    mcp = FastMCP("netops", host="127.0.0.1", port=a.port, log_level="WARNING")

    @mcp.tool()
    async def http_get(url: str) -> str:
        """Fetch a URL over HTTP and return the status line and the beginning of the body."""
        u = urlparse(url)
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(u.hostname, u.port or 80), 3)
            w.write(f"GET {u.path or '/'} HTTP/1.0\r\nHost: {u.hostname}\r\n\r\n".encode())
            await w.drain()
            data = await asyncio.wait_for(r.read(400), 3)
            w.close()
            return data.decode(errors="replace")
        except Exception as e:
            return f"error: {type(e).__name__}: {e}"

    @mcp.tool()
    async def fetch_url(url: str) -> str:
        """Fetch a URL with a separate helper process (for services that need a fresh client)."""
        p = await asyncio.create_subprocess_exec(sys.executable, "-I", "-c", FETCH, url,
                                                 stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        out, _ = await p.communicate()
        return out.decode(errors="replace")[:400]

    def _tcp(host, port):
        s = socket.socket()
        s.settimeout(3)
        try:
            r = s.connect_ex((host, int(port)))
            return "open" if r == 0 else f"closed (errno {r})"
        finally:
            s.close()

    @mcp.tool()
    async def tcp_check(host: str, port: int) -> str:
        """Check whether a TCP port accepts connections."""
        return await anyio.to_thread.run_sync(_tcp, host, port)

    if a.binding == "auto":
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from fact_rt import mcp as fact_mcp
        fact_mcp.instrument(mcp)
    mcp.run(transport="sse")


if __name__ == "__main__":
    main()
