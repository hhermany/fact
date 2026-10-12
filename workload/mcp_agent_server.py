#!/usr/bin/env python3
"""Servidor MCP de ferramentas de rede usado pelo agente LLM (E7).

Um único processo atende todas as sessões (worker compartilhado), instrumentado
pelo agentnet_rt (vínculo automático: a identidade vem do _meta de cada
tools/call; as ferramentas não sabem nada do agentnet). Três ferramentas com
padrões de execução diferentes:

  http_get(url)     async: requisição HTTP/1.0 com asyncio (intercala no event loop)
  fetch_url(url)    subprocesso: python -c urllib (o filho herda a identidade)
  tcp_check(host, port)  thread do pool (anyio.to_thread): teste de conexão TCP

Uso: python3 mcp_agent_server.py --port 64999 [--binding auto|none]
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
        from agentnet_rt import mcp as agentnet_mcp
        agentnet_mcp.instrument(mcp)
    mcp.run(transport="sse")


if __name__ == "__main__":
    main()
