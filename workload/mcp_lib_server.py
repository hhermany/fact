#!/usr/bin/env python3
"""MCP server (official SDK, FastMCP, SSE transport) whose tools use third-party
client code, unmodified (E5lib).

As in E4/E5, a single process serves every client session (shared worker), and
each tool call makes one HTTP request to the requested port. The request is made
by code we did not write and did not change; the tools only build the URL:

  httpx_get     httpx.AsyncClient (async; the client of the official MCP SDK)
  aiohttp_get   aiohttp.ClientSession (async)
  requests_get  requests.get (synchronous; FastMCP runs it on the event-loop thread)
  urllib_get    urllib.request.urlopen (synchronous, standard library)
  fetch         fetch_url() of the official MCP fetch server (mcp-server-fetch,
                version pinned in flake.nix), which uses httpx.AsyncClient
  curl          the curl binary, run as a subprocess (asyncio)

Every client opens a new connection for each call (a new client or session per
call), so connections are not reused across calls; connection reuse is a
separate question. The server runs only with the automatic binding: fact_rt
wraps the tools/call handler and the identity comes from the request's _meta;
the tools emit no markers.

Usage: python3 mcp_lib_server.py --port 64999
"""
import argparse
import asyncio
import os
import sys
import urllib.request

from mcp.server.fastmcp import FastMCP

LISTEN = "127.0.0.1"                                  # MCP server listening address
TARGET = os.environ.get("FACT_DEST", "127.0.0.1")   # destination of the tools (loopback or another machine)
TIMEOUT = 5


def url_of(port):
    return f"http://{TARGET}:{int(port)}/"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=64999)
    ap.add_argument("--binding", choices=["auto"], default="auto")
    a = ap.parse_args()
    mcp = FastMCP("fact-lib", host=LISTEN, port=a.port, log_level="WARNING")

    @mcp.tool()
    async def httpx_get(exec_id: str, port: int) -> str:
        import httpx
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            r = await client.get(url_of(port))
        return "ok" if r.status_code == 200 else "fail"

    @mcp.tool()
    async def aiohttp_get(exec_id: str, port: int) -> str:
        import aiohttp
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=TIMEOUT)) as s:
            async with s.get(url_of(port)) as r:
                await r.read()
                return "ok" if r.status == 200 else "fail"

    @mcp.tool()
    def requests_get(exec_id: str, port: int) -> str:
        import requests
        r = requests.get(url_of(port), timeout=TIMEOUT)
        return "ok" if r.status_code == 200 else "fail"

    @mcp.tool()
    def urllib_get(exec_id: str, port: int) -> str:
        with urllib.request.urlopen(url_of(port), timeout=TIMEOUT) as r:
            r.read()
            return "ok" if r.status == 200 else "fail"

    @mcp.tool()
    async def fetch(exec_id: str, port: int) -> str:
        from mcp_server_fetch.server import DEFAULT_USER_AGENT_AUTONOMOUS, fetch_url
        content, _prefix = await fetch_url(url_of(port), DEFAULT_USER_AGENT_AUTONOMOUS, force_raw=True)
        return "ok" if content == "ok" else "fail"

    @mcp.tool()
    async def curl(exec_id: str, port: int) -> str:
        p = await asyncio.create_subprocess_exec(
            "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", str(TIMEOUT), url_of(port),
            stdout=asyncio.subprocess.PIPE)
        out, _ = await p.communicate()
        return "ok" if out.strip() == b"200" else "fail"

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from fact_rt import mcp as fact_mcp
    fact_mcp.instrument(mcp)
    mcp.run(transport="sse")


if __name__ == "__main__":
    main()
