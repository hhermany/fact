#!/usr/bin/env python3
"""Servidor MCP (SDK oficial, FastMCP, transporte SSE) usado no E4.

Um único processo atende todas as sessões de cliente (worker compartilhado).
Cada ferramenta abre UMA conexão TCP para a porta pedida e emite os marcadores
de contexto do agentnet (vínculo cooperativo do runtime), em quatro padrões de
execução reais:

  sync_get     função síncrona: o FastMCP a executa na thread do event loop
               (serializada; ver modelcontextprotocol/python-sdk#1839)
  thread_get   assíncrona que delega a uma thread do pool (anyio.to_thread);
               o marcador é emitido dentro da thread
  subproc_get  assíncrona que cria um subprocesso (python -c connect);
               o filho herda o contexto no fork
  async_get    assíncrona com await antes do connect: várias chamadas se
               intercalam na MESMA thread (limite declarado do vínculo por thread)

Modos de vínculo (--binding):
  manual  as ferramentas emitem os marcadores (comportamento original do E4);
  auto    as ferramentas NÃO emitem marcadores: o servidor é instrumentado pelo
          agentnet_rt (identidade por tarefa via contextvars, entregue ao kernel
          no connect/fork); a identidade vem do _meta da requisição.

Uso: python3 mcp_e4_server.py --port 64999 [--binding manual|auto]
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
LISTEN = "127.0.0.1"                                  # escuta do servidor MCP
TARGET = os.environ.get("AGENTNET_DEST", "127.0.0.1")   # destino das ferramentas (loopback ou outra máquina)
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
            await asyncio.sleep(random.uniform(0, 0.005))   # ponto de intercalação realista (I/O pendente)
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
