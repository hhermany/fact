#!/usr/bin/env python3
"""Teste do agentnet_rt sem eBPF: simula o mapa de contexto do kernel (tid -> id)
e verifica, para cada connect e cada fork de subprocesso, se a identidade que o
kernel veria é a da execução que pediu a chamada. Referência independente: cada
execução conecta numa porta exclusiva.

Também roda o modo manual (marcadores na ferramenta) para reproduzir a falha do
E4 com ferramentas async. Uso: python3 tests/test_agentctx_sim.py
"""
import asyncio
import os
import random
import socket
import subprocess
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agentnet_rt import agentctx  # noqa: E402

SIM = {}            # tid -> contexto (simulação do mapa @ctx do coletor)
LOG = []            # (dport, ctx no momento do connect)
MANUAL = {"on": False}


def sim_emit(path):
    tid = threading.get_native_id()
    if path.startswith(agentctx.CTX_BEGIN):
        SIM[tid] = path[len(agentctx.CTX_BEGIN):]
    else:
        SIM.pop(tid, None)


agentctx._emit = sim_emit
agentctx.install()
_real_connect = agentctx._orig["connect"]
_real_exec = agentctx._orig["execute_child"]


def rec_connect(self, address):
    if self.family == socket.AF_INET and address[1] >= 20000:
        LOG.append((address[1], SIM.get(threading.get_native_id())))
    return _real_connect(self, address)


def rec_exec(self, args, *rest, **kw):
    # o filho herdaria o contexto da thread que faz o fork; registra pela porta pedida
    port = int(args[-1]) if args and str(args[-1]).isdigit() else None
    if port:
        LOG.append((port, SIM.get(threading.get_native_id())))
    return _real_exec(self, args, *rest, **kw)


agentctx._orig["connect"] = rec_connect
agentctx._orig["execute_child"] = rec_exec


def mark(exec_id):
    if MANUAL["on"]:
        sim_emit(agentctx.CTX_BEGIN + exec_id if exec_id else agentctx.CTX_END)


def build_server():
    import anyio
    from mcp.server.fastmcp import FastMCP
    srv = FastMCP("t")
    SUB = "import sys;sys.exit(0)"

    def blocking(port):
        s = socket.socket()
        s.settimeout(2)
        s.connect(("127.0.0.1", port))
        s.close()
        return "ok"

    @srv.tool()
    def sync_get(exec_id: str, port: int) -> str:
        mark(exec_id)
        try:
            return blocking(port)
        finally:
            mark(None)

    def tb(exec_id, port):
        mark(exec_id)
        try:
            return blocking(port)
        finally:
            mark(None)

    @srv.tool()
    async def thread_get(exec_id: str, port: int) -> str:
        return await anyio.to_thread.run_sync(tb, exec_id, port)

    @srv.tool()
    async def subproc_get(exec_id: str, port: int) -> str:
        mark(exec_id)
        try:
            p = await asyncio.create_subprocess_exec(sys.executable, "-c", SUB, str(port))
            await p.wait()
            return "ok"
        finally:
            mark(None)

    @srv.tool()
    async def async_get(exec_id: str, port: int) -> str:
        mark(exec_id)
        try:
            await asyncio.sleep(random.uniform(0, 0.005))
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.close()
            await w.wait_closed()
            return "ok"
        finally:
            mark(None)
    return srv


async def run(mode, tool, K=4, ops=25):
    from mcp.shared.memory import create_connected_server_and_client_session
    from agentnet_rt.mcp import instrument, call_tool_with_exec
    MANUAL["on"] = mode == "manual"
    agentctx.enabled = mode == "auto"
    srv = build_server()
    if mode == "auto":
        instrument(srv)
    servers = [await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0) for _ in range(K)]
    ports = {s.sockets[0].getsockname()[1]: f"E{i:02d}" for i, s in enumerate(servers)}
    LOG.clear()
    SIM.clear()
    agentctx._tls.__dict__.clear()

    async def one(port, eid):
        async with create_connected_server_and_client_session(srv._mcp_server) as cs:
            for _ in range(ops):
                args = {"exec_id": eid, "port": port}
                if mode == "auto":
                    await call_tool_with_exec(cs, tool, args, eid)
                else:
                    await cs.call_tool(tool, args)
    await asyncio.gather(*(one(p, e) for p, e in ports.items()))
    for s in servers:
        s.close()
    ok = sum(1 for p, c in LOG if c == ports[p])
    none = sum(1 for p, c in LOG if c is None)
    wrong = len(LOG) - ok - none
    return len(LOG), ok, wrong, none


def main():
    random.seed(1)
    bad = 0
    for tool in ["sync_get", "thread_get", "subproc_get", "async_get"]:
        for mode in ["manual", "auto"]:
            n, ok, wrong, none = asyncio.run(run(mode, tool))
            print(f"{tool:12s} {mode:6s} N={n:4d} correto={ok:4d} errado={wrong:4d} sem_ctx={none:4d}")
            if mode == "auto" and ok != n:
                bad += 1
    print("marcas:", agentctx.stats)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
