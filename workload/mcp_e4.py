#!/usr/bin/env python3
"""Driver do E4: servidor MCP real compartilhado por K sessões de cliente.

- Sobe mcp_e4_server.py num cgroup próprio (raiz registrada = processo servidor).
- Abre K sessões MCP concorrentes (uma por execução); cada sessão faz --ops
  chamadas sequenciais da ferramenta --tool, cada uma para uma porta de destino
  exclusiva (referência independente, como no workload sintético).
- Grava plan.json, registry.json, ops.jsonl no formato do score.py, mais
  e4_summary.json com a latência das chamadas vista pelo cliente.

Conexões cliente<->servidor MCP (porta do servidor) ficam fora do plano e são
contadas como "excluídas sem referência" pelo score.py.

Uso (root, dentro do nix develop, com o coletor ativo):
  python3 mcp_e4.py --tool async --execs 2 --ops 25 --seed 1 --out runs/x
"""
import argparse
import asyncio
import json
import os
import random
import socket
import statistics as st
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from workload import Listener, cg_create, cg_move  # noqa: E402
from agentnet_rt.mcp import call_tool_with_exec  # noqa: E402

TOOLS = {"sync": "sync_get", "thread": "thread_get", "subproc": "subproc_get", "async": "async_get"}


def wait_port(port, timeout=20.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        s = socket.socket()
        try:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        finally:
            s.close()
        time.sleep(0.2)
    return False


async def session(url, tool, exec_id, ops, log, binding):
    from mcp import ClientSession
    from mcp.client.sse import sse_client
    lat = []
    async with sse_client(url) as (read, write):
        async with ClientSession(read, write) as s:
            await s.initialize()
            for op in ops:
                t0 = time.time_ns()
                args = {"exec_id": exec_id, "port": op["dport"]}
                label = op.get("label", exec_id)
                if binding == "auto":   # identidade no _meta; a ferramenta não a usa
                    res = await call_tool_with_exec(s, TOOLS[tool], args, label)
                else:
                    res = await s.call_tool(TOOLS[tool], args)
                t1 = time.time_ns()
                text = "".join(getattr(c, "text", "") for c in res.content)
                lat.append((t1 - t0) / 1e6)
                log.write(json.dumps(dict(op, kind=tool, t_start=t0, t_end=t1, ok=(text == "ok"), label=label)) + "\n")
    return lat


async def run_clients(url, tool, ops_by_exec, log, binding):
    tasks = [session(url, tool, e, ops, log, binding) for e, ops in ops_by_exec.items()]
    return await asyncio.gather(*tasks)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cond", default="E4")
    ap.add_argument("--tool", required=True, choices=list(TOOLS))
    ap.add_argument("--execs", type=int, default=2)
    ap.add_argument("--ops", type=int, default=25)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--base-port", type=int, default=61000)
    ap.add_argument("--server-port", type=int, default=64999)
    ap.add_argument("--binding-mode", choices=["manual", "auto"], default="manual")
    ap.add_argument("--dest-host", default="127.0.0.1",
                    help="destino das ferramentas; fora do loopback, os serviços rodam em outra máquina (workload/remote_farm.py)")
    ap.add_argument("--policy", type=int, default=0,
                    help="1: carrega a política por execução (exige o agentnet_policy ativo)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--mode", default="mcp")          # aceitos por compatibilidade com o run_round
    ap.add_argument("--wrong-label", type=float, default=0.0)
    ap.add_argument("--jitter", type=float, default=0.0)
    ap.add_argument("--threads", type=int, default=0)
    a = ap.parse_args()
    random.seed(a.seed)
    os.makedirs(a.out, exist_ok=True)

    execs = ["A", "B"] if a.execs == 2 else [f"E{i:02d}" for i in range(a.execs)]
    ports = list(range(a.base_port, a.base_port + a.ops * len(execs)))
    random.shuffle(ports)
    it = iter(ports)
    ops_by_exec = {e: [{"exec_id": e, "op_id": f"{e}-{i:04d}", "op_idx": i, "dport": next(it)}
                       for i in range(a.ops)] for e in execs}
    # falhas de vínculo (como no E1): exatamente round(p * ops) chamadas por execução
    # levam no _meta a identidade de outra execução; posições sorteadas
    n_wrong = round(a.wrong_label * a.ops)
    if abs(n_wrong - a.wrong_label * a.ops) > 1e-9:
        sys.exit(f"wrong_label*ops = {a.wrong_label * a.ops} não é inteiro")
    if n_wrong and a.binding_mode != "auto":
        sys.exit("--wrong-label se aplica ao vínculo automático (identidade no _meta)")
    if n_wrong:
        frng = random.Random(a.seed + 104729)
        for e in execs:
            for i in frng.sample(range(a.ops), n_wrong):
                ops_by_exec[e][i]["label"] = frng.choice([x for x in execs if x != e])
    from importlib.metadata import version
    plan = {"cond": a.cond, "mode": "mcp", "tool": a.tool, "binding": True, "binding_mode": a.binding_mode, "seed": a.seed,
            "ops_per_exec": a.ops, "execs": len(execs), "exec_ids": execs, "wrong_label": a.wrong_label,
            "wrong_per_exec": n_wrong,
            "listen_addr": a.dest_host, "mcp_version": version("mcp"),
            "dport_map": {str(o["dport"]): [o["exec_id"], o["op_id"]] for e in execs for o in ops_by_exec[e]}}
    if a.policy:
        # classes alternadas: P (permissiva: todos os destinos do plano) e R (restrita:
        # metade sorteada dos próprios destinos). Rótulo errado R->P permite indevidamente;
        # P->R ou entre R nega indevidamente.
        rng = random.Random(a.seed + 7919)
        classes = {e: ("P" if i % 2 == 0 else "R") for i, e in enumerate(execs)}
        allow = {}
        for e in execs:
            own = [o["dport"] for o in ops_by_exec[e]]
            allow[e] = sorted(ports) if classes[e] == "P" else sorted(rng.sample(own, len(own) // 2))
        plan["policy"] = {"classes": classes, "allow": allow}
    json.dump(plan, open(os.path.join(a.out, "plan.json"), "w"), indent=1)
    if a.policy:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "policy"))
        import policyctl
        policyctl.load_dict(plan["policy"]["allow"])

    remote = a.dest_host != "127.0.0.1"
    if remote:   # serviços na outra máquina: confere que a faixa do plano responde antes de medir
        for p in (min(ports), max(ports)):
            s = socket.socket()
            s.settimeout(2)
            try:
                if s.connect_ex((a.dest_host, p)) != 0:
                    sys.exit(f"destino remoto {a.dest_host}:{p} não responde (remote_farm.py ativo?)")
            finally:
                s.close()
        listener = None
    else:
        listener = Listener(ports)
        listener.start()
    cg_path, cg_id = cg_create("E4-server")
    here = os.path.dirname(os.path.abspath(__file__))
    srv = subprocess.Popen([sys.executable, "-I", os.path.join(here, "mcp_e4_server.py"),
                            "--port", str(a.server_port), "--binding", a.binding_mode],
                           env=dict(os.environ, AGENTNET_DEST=a.dest_host),
                           stdout=open(os.path.join(a.out, "server.log"), "w"), stderr=subprocess.STDOUT)
    cg_move(cg_path, srv.pid)
    json.dump({"roots": {str(srv.pid): execs}, "cgroups": {str(cg_id): execs}},
              open(os.path.join(a.out, "registry.json"), "w"), indent=1)
    try:
        if not wait_port(a.server_port):
            sys.exit("servidor MCP não subiu (ver server.log)")
        with open(os.path.join(a.out, "ops.jsonl"), "w") as log:
            lats = asyncio.run(run_clients(f"http://127.0.0.1:{a.server_port}/sse", a.tool, ops_by_exec, log, a.binding_mode))
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=5)
        except subprocess.TimeoutExpired:
            srv.kill()
        if listener:
            listener.stop = True
    allv = [x for l in lats for x in l]
    json.dump({"tool": a.tool, "calls": len(allv), "tool_ms_p50": st.median(allv),
               "tool_ms_mean": st.mean(allv), "tool_ms_p90": sorted(allv)[int(0.9 * (len(allv) - 1))]},
              open(os.path.join(a.out, "e4_summary.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
