#!/usr/bin/env python3
"""E4 driver: a real MCP server shared by K client sessions.

- Starts mcp_e4_server.py in its own cgroup (registered root = server process).
- Opens K concurrent MCP sessions (one per execution); each session makes --ops
  sequential calls of the --tool tool, each to an exclusive destination port
  (independent reference, as in the synthetic workload).
- Writes plan.json, registry.json, and ops.jsonl in score.py's format, plus
  e4_summary.json with the call latency seen by the client.

Client<->MCP server connections (server port) are outside the plan and are
counted as "excluded without reference" by score.py.

Usage (root, inside nix develop, with the collector active):
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
from http_farm import HttpListener  # noqa: E402
from fact_rt.mcp import call_tool_with_exec  # noqa: E402

TOOLS = {"sync": "sync_get", "thread": "thread_get", "subproc": "subproc_get", "async": "async_get"}
# E5lib: tools whose request is made by third-party client code (workload/mcp_lib_server.py)
LIB_TOOLS = {"httpx": "httpx_get", "aiohttp": "aiohttp_get", "requests": "requests_get", "urllib": "urllib_get",
             "fetch": "fetch", "curl": "curl"}
TOOLS.update(LIB_TOOLS)


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
                if binding == "auto":   # identity in _meta; the tool does not use it
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
                    help="destination of the tools; outside loopback, the services run on another machine (workload/remote_farm.py)")
    ap.add_argument("--policy", type=int, default=0,
                    help="1: loads the per-execution policy (requires fact_policy running)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--mode", default="mcp")          # accepted for compatibility with run_round
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
    # binding faults (as in E1): exactly round(p * ops) calls per execution carry
    # another execution's identity in _meta; random positions
    n_wrong = round(a.wrong_label * a.ops)
    if abs(n_wrong - a.wrong_label * a.ops) > 1e-9:
        sys.exit(f"wrong_label*ops = {a.wrong_label * a.ops} is not an integer")
    lib = a.tool in LIB_TOOLS
    if lib and a.binding_mode != "auto":
        sys.exit("the third-party library tools (E5lib) run only with the automatic binding")
    if n_wrong and a.binding_mode != "auto":
        sys.exit("--wrong-label applies to the automatic binding (identity in _meta)")
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
        # alternating classes: P (permissive: every planned destination) and R (restricted:
        # a random half of its own destinations). A wrong label R->P wrongly allows;
        # P->R or between R wrongly denies.
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
    if remote:   # services on the other machine: check that the planned range answers before measuring
        # with the policy active, planned ports (61000-64998) without identity are denied
        # already here; so check a remote_farm port outside the policed range
        for p in ((65000,) if a.policy else (min(ports), max(ports))):
            s = socket.socket()
            s.settimeout(2)
            try:
                if s.connect_ex((a.dest_host, p)) != 0:
                    sys.exit(f"remote destination {a.dest_host}:{p} does not answer (is remote_farm.py running?)")
            finally:
                s.close()
        listener = None
    else:
        listener = HttpListener(ports) if lib else Listener(ports)
        listener.start()
    cg_path, cg_id = cg_create("E4-server")
    here = os.path.dirname(os.path.abspath(__file__))
    srv = subprocess.Popen([sys.executable, "-I", os.path.join(here, "mcp_lib_server.py" if lib else "mcp_e4_server.py"),
                            "--port", str(a.server_port), "--binding", a.binding_mode],
                           env=dict(os.environ, FACT_DEST=a.dest_host),
                           stdout=open(os.path.join(a.out, "server.log"), "w"), stderr=subprocess.STDOUT)
    cg_move(cg_path, srv.pid)
    json.dump({"roots": {str(srv.pid): execs}, "cgroups": {str(cg_id): execs}},
              open(os.path.join(a.out, "registry.json"), "w"), indent=1)
    try:
        if not wait_port(a.server_port):
            sys.exit("MCP server did not start (see server.log)")
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
