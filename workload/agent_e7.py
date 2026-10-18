#!/usr/bin/env python3
"""E7: agentes LLM reais (modelo local via Ollama) compartilhando um servidor MCP.

- Sobe serviços HTTP/TCP locais em portas exclusivas por execução (referência
  independente: a porta de destino identifica a execução dona).
- Sobe mcp_agent_server.py (instrumentado pelo agentnet_rt) num cgroup próprio.
- Roda K agentes concorrentes. Cada agente é um laço modelo -> chamadas de
  ferramenta MCP -> resultados -> modelo, com a tarefa de verificar a saúde dos
  serviços do seu "tenant". O modelo decide quais ferramentas chamar e com que
  argumentos; a identidade da execução vai no _meta de cada tools/call.
- Política opcional (--policy 1): classes alternadas P (todos os próprios
  serviços) e R (um dos serviços proibido); requer o agentnet_policy ativo.
Saídas no formato do score.py (plan.json, registry.json, ops.jsonl) e
e7_summary.json com o comportamento dos agentes.

Uso (root, nix develop, coletor ativo, ollama servindo em 127.0.0.1:11434):
  python3 agent_e7.py --execs 4 --seed 1 --model qwen2.5:3b --out runs/x
"""
import argparse
import asyncio
import json
import os
import random
import re
import statistics as st
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
from workload import cg_create, cg_move  # noqa: E402
from agentnet_rt.mcp import call_tool_with_exec  # noqa: E402
from mcp_e4 import wait_port  # noqa: E402

SYSTEM = ("You are an operations agent. Use the provided tools to check services; never guess a result. "
          "Call one tool per service, exactly as instructed. When all checks are done, reply with one line "
          "per service: '<service>: up' or '<service>: down'.")
TASK = ("Health check for tenant {e}:\n"
        "1. inventory API at http://127.0.0.1:{p0}/health - use the http_get tool.\n"
        "2. billing API at http://127.0.0.1:{p1}/status - use the fetch_url tool.\n"
        "3. database at host 127.0.0.1 port {p2} - use the tcp_check tool.\n"
        "Report the status of each service.")


class ServiceFarm(threading.Thread):
    """Serviços HTTP mínimos (respondem 200) em todas as portas do plano."""
    def __init__(self, ports):
        super().__init__(daemon=True)
        self.ports, self.ready = ports, threading.Event()

    def run(self):
        loop = asyncio.new_event_loop()

        async def handle(r, w):
            try:
                await asyncio.wait_for(r.read(1024), 1)
            except Exception:
                pass
            w.write(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nservice healthy\n")
            try:
                await w.drain()
            finally:
                w.close()

        async def start():
            for p in self.ports:
                await asyncio.start_server(handle, "127.0.0.1", p, backlog=256)
            self.ready.set()
        loop.run_until_complete(start())
        loop.run_forever()


def ollama_chat(host, model, messages, tools, seed, num_predict=None):
    opts = {"temperature": 0, "seed": seed}
    if num_predict:   # limita respostas que não param (visto com llama3.1:8b em temperatura 0)
        opts["num_predict"] = num_predict
    body = json.dumps({"model": model, "messages": messages, "tools": tools, "stream": False,
                       "options": opts}).encode()
    req = urllib.request.Request(f"http://{host}/api/chat", data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=600) as r:
        return json.loads(r.read())


ANTHROPIC_KEY_FILE = "/etc/agentnet/anthropic.key"   # fora do repositório, só root lê (chmod 600)


def anthropic_chat(model, messages, tools, max_tokens):
    """Mesma interface do ollama_chat, com a API de Mensagens da Anthropic (sem o parâmetro temperature, que esses modelos não aceitam;
    sem raciocínio estendido). Devolve {"message": {...}, "usage": {...}, "model": ...} no
    formato interno (tool_calls como no Ollama). Repete em 429/5xx com espera crescente."""
    key = open(ANTHROPIC_KEY_FILE).read().strip()
    system = "".join(m["content"] for m in messages if m["role"] == "system")
    conv, pend = [], []
    for m in messages:
        if m["role"] == "user":
            conv.append({"role": "user", "content": m["content"]})
        elif m["role"] == "assistant":
            blocks = [{"type": "text", "text": m["content"]}] if m.get("content") else []
            for c in m.get("tool_calls") or []:
                blocks.append({"type": "tool_use", "id": c["id"], "name": c["function"]["name"],
                               "input": c["function"]["arguments"]})
            conv.append({"role": "assistant", "content": blocks})
        elif m["role"] == "tool":
            res = {"type": "tool_result", "tool_use_id": m["tool_call_id"], "content": m["content"]}
            if conv and conv[-1]["role"] == "user" and isinstance(conv[-1]["content"], list):
                conv[-1]["content"].append(res)
            else:
                conv.append({"role": "user", "content": [res]})
    body = json.dumps({"model": model, "max_tokens": max_tokens or 1024, "system": system,
                       "messages": conv,
                       "tools": [{"name": t["function"]["name"], "description": t["function"]["description"],
                                  "input_schema": t["function"]["parameters"]} for t in tools]}).encode()
    for attempt in range(6):
        req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=body, headers={
            "content-type": "application/json", "x-api-key": key, "anthropic-version": "2023-06-01"})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                d = json.loads(r.read())
            break
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 529) and attempt < 5:
                time.sleep(2 ** attempt)
                continue
            raise RuntimeError(f"anthropic HTTP {e.code}: {e.read()[:300]!r}") from None
    text = "".join(b.get("text", "") for b in d["content"] if b["type"] == "text")
    calls = [{"id": b["id"], "function": {"name": b["name"], "arguments": b["input"]}}
             for b in d["content"] if b["type"] == "tool_use"]
    return {"message": {"role": "assistant", "content": text, "tool_calls": calls},
            "usage": d.get("usage", {}), "model": d.get("model"), "api_retries": attempt}


def llm_chat(a, messages, tools):
    if a.model.startswith("claude-"):
        return anthropic_chat(a.model, messages, tools, a.num_predict)
    return ollama_chat(a.ollama, a.model, messages, tools, a.seed, a.num_predict)


PORT_RE = re.compile(r":(\d{2,5})")


def port_of(args):
    if "port" in args:
        try:
            return int(args["port"])
        except (TypeError, ValueError):
            return None
    m = PORT_RE.search(str(args.get("url", "")))
    return int(m.group(1)) if m else None


async def agent(url, exec_id, task, a, log, plan_ports):
    # Abrir a sessão MCP (SSE + initialize) às vezes trava com 8 sessões simultâneas,
    # sem erro e sem timeout do cliente. A falha ocorre antes de qualquer passo do
    # modelo ou chamada de ferramenta; então a abertura tem prazo de 60 s e é repetida
    # (até 3 tentativas, registradas em "attempts"). Falhas depois do primeiro passo
    # não são repetidas.
    for attempt in range(1, 4):
        rec = {"exec": exec_id, "steps": 0, "tool_calls": 0, "off_plan_ports": 0, "llm_s": 0.0,
               "tool_ms": [], "final": None, "error": None, "attempts": attempt}
        if a.model.startswith("claude-"):   # consumo medido pela própria API (custo exato)
            rec.update({"input_tokens": 0, "output_tokens": 0, "api_retries": 0, "api_model": None})
        try:
            return await agent_once(url, exec_id, task, a, log, plan_ports, rec)
        except Exception:  # noqa: BLE001
            if rec["steps"] or rec["tool_calls"] or attempt == 3:
                raise


async def agent_once(url, exec_id, task, a, log, plan_ports, rec):
    from mcp import ClientSession
    from mcp.client.sse import sse_client
    async with sse_client(url) as (read, write):
        async with ClientSession(read, write) as s:
            await asyncio.wait_for(s.initialize(), 60)
            tl = await asyncio.wait_for(s.list_tools(), 60)
            tools = [{"type": "function", "function": {"name": t.name, "description": t.description or "",
                                                       "parameters": t.inputSchema}} for t in tl.tools]
            msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": task}]
            for step in range(a.max_steps):
                rec["steps"] = step + 1
                t0 = time.time()
                resp = await asyncio.to_thread(llm_chat, a, msgs, tools)
                rec["llm_s"] += time.time() - t0
                if "input_tokens" in rec:
                    u = resp.get("usage", {})
                    rec["input_tokens"] += u.get("input_tokens", 0)
                    rec["output_tokens"] += u.get("output_tokens", 0)
                    rec["api_retries"] += resp.get("api_retries", 0)
                    rec["api_model"] = resp.get("model")
                m = resp.get("message", {})
                msgs.append(m)
                calls = m.get("tool_calls") or []
                if not calls:
                    rec["final"] = m.get("content", "")
                    break
                for c in calls:
                    fn = c.get("function", {})
                    name, args = fn.get("name"), fn.get("arguments") or {}
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except json.JSONDecodeError:
                            args = {}
                    dport = port_of(args)
                    t1 = time.time_ns()
                    wrong = a.wrong_calls.get(exec_id, {})
                    label = wrong["label"] if (rec["tool_calls"] + 1) in wrong.get("idx", ()) else exec_id
                    try:
                        res = await call_tool_with_exec(s, name, args, label)
                        text = "".join(getattr(x, "text", "") for x in res.content)
                    except Exception as e:  # ferramenta inexistente, argumentos inválidos
                        text = f"error: {e}"
                    t2 = time.time_ns()
                    rec["tool_calls"] += 1
                    rec["tool_ms"].append((t2 - t1) / 1e6)
                    if dport not in plan_ports:
                        rec["off_plan_ports"] += 1
                    op = {"exec_id": exec_id, "op_id": f"{exec_id}-{rec['tool_calls']:03d}", "tool": name,
                          "args": args, "t_start": t1, "t_end": t2, "result": text[:120], "label": label}
                    if dport is not None:
                        op["dport"] = dport
                    log.write(json.dumps(op) + "\n")
                    log.flush()
                    tm = {"role": "tool", "content": text[:400], "tool_name": name}
                    if c.get("id"):
                        tm["tool_call_id"] = c["id"]
                    msgs.append(tm)
    return rec


async def run_agents(url, tasks, a, log, plan_ports):
    return await asyncio.gather(*(agent(url, e, t, a, log, plan_ports) for e, t in tasks.items()),
                                return_exceptions=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cond", default="E7")
    ap.add_argument("--execs", type=int, default=4)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--model", default="qwen2.5:3b")
    ap.add_argument("--ollama", default="127.0.0.1:11434")
    ap.add_argument("--max-steps", type=int, default=6)
    ap.add_argument("--num-predict", type=int, default=0,
                    help="máximo de tokens por resposta do modelo (0: sem limite, como no E7)")
    ap.add_argument("--base-port", type=int, default=61000)
    ap.add_argument("--server-port", type=int, default=64999)
    ap.add_argument("--policy", type=int, default=0)
    ap.add_argument("--out", required=True)
    ap.add_argument("--mode", default="agent")       # compatibilidade com run_round/campaign
    ap.add_argument("--wrong-label", type=float, default=0.0)
    ap.add_argument("--jitter", type=float, default=0.0)
    ap.add_argument("--threads", type=int, default=0)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    os.makedirs(a.out, exist_ok=True)
    execs = [f"T{i:02d}" for i in range(a.execs)]
    ports = rng.sample(range(a.base_port, a.base_port + 2000), 3 * len(execs))
    own = {e: ports[3 * i:3 * i + 3] for i, e in enumerate(execs)}
    tasks = {e: TASK.format(e=e, p0=own[e][0], p1=own[e][1], p2=own[e][2]) for e in execs}
    # falhas de vínculo: round(p * 3) das três primeiras chamadas de cada agente levam
    # no _meta a identidade de outro agente (o agente decide quantas chamadas faz)
    n_wrong = round(a.wrong_label * 3)
    frng = random.Random(a.seed + 104729)
    a.wrong_calls = {e: {"idx": sorted(frng.sample(range(1, 4), n_wrong)),
                         "label": frng.choice([x for x in execs if x != e])} for e in execs} if n_wrong else {}
    from importlib.metadata import version
    plan = {"cond": a.cond, "mode": "agent", "tool": "llm", "binding": True, "binding_mode": "auto",
            "seed": a.seed, "ops_per_exec": 3, "execs": len(execs), "exec_ids": execs, "wrong_label": a.wrong_label,
            "wrong_calls": a.wrong_calls,
            "listen_addr": "127.0.0.1", "mcp_version": version("mcp"), "model": a.model, "num_predict": a.num_predict,
            "dport_map": {str(p): [e, f"{e}-svc{j}"] for e in execs for j, p in enumerate(own[e])},
            "tasks": tasks}
    if a.policy:
        classes = {e: ("P" if i % 2 == 0 else "R") for i, e in enumerate(execs)}
        allow = {e: (own[e] if classes[e] == "P" else own[e][:2]) for e in execs}   # R: banco proibido
        plan["policy"] = {"classes": classes, "allow": allow}
    json.dump(plan, open(os.path.join(a.out, "plan.json"), "w"), indent=1)
    if a.policy:
        sys.path.insert(0, os.path.join(os.path.dirname(HERE), "policy"))
        import policyctl
        policyctl.load_dict(plan["policy"]["allow"])

    farm = ServiceFarm(ports)
    farm.start()
    farm.ready.wait(10)
    cg_path, cg_id = cg_create("E7-server")
    srv = subprocess.Popen([sys.executable, "-I", os.path.join(HERE, "mcp_agent_server.py"),
                            "--port", str(a.server_port)],
                           stdout=open(os.path.join(a.out, "server.log"), "w"), stderr=subprocess.STDOUT)
    cg_move(cg_path, srv.pid)
    json.dump({"roots": {str(srv.pid): execs}, "cgroups": {str(cg_id): execs}},
              open(os.path.join(a.out, "registry.json"), "w"), indent=1)
    t0 = time.time()
    try:
        if not wait_port(a.server_port):
            sys.exit("servidor MCP não subiu (ver server.log)")
        with open(os.path.join(a.out, "ops.jsonl"), "w") as log:
            recs = asyncio.run(run_agents(f"http://127.0.0.1:{a.server_port}/sse", tasks, a, log, set(ports)))
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=5)
        except subprocess.TimeoutExpired:
            srv.kill()
    out = []
    for e, r in zip(execs, recs):
        out.append({"exec": e, "error": repr(r)} if isinstance(r, BaseException) else r)
    allms = [x for r in out for x in r.get("tool_ms", [])]
    summ = {"model": a.model, "wall_s": time.time() - t0, "agents": out,
            "tool_calls": len(allms), "tool_ms_p50": st.median(allms) if allms else None,
            "tool_ms_mean": st.mean(allms) if allms else None,
            "llm_s_total": sum(r.get("llm_s", 0) for r in out)}
    if a.model.startswith("claude-"):
        summ["input_tokens"] = sum(r.get("input_tokens", 0) for r in out)
        summ["output_tokens"] = sum(r.get("output_tokens", 0) for r in out)
    json.dump(summ, open(os.path.join(a.out, "e7_summary.json"), "w"), indent=1)
    if any(isinstance(r, BaseException) for r in recs):
        sys.exit("algum agente falhou (ver e7_summary.json)")


if __name__ == "__main__":
    main()
