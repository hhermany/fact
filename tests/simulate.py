#!/usr/bin/env python3
"""Gera uma rodada sintética no formato do coletor (events.jsonl) para testar
o pipeline de análise SEM eBPF. Não é dado experimental."""
import json
import os
import random
import sys

CTX = "/run/agentctx/begin/"


def gen(cond, out, ops=20, mode="mixed", binding=True, seed=0, conflict=False):
    random.seed(seed)
    os.makedirs(out, exist_ok=True)
    ev, opslog, ts, nt = [], [], [0], [5000]

    def t():
        ts[0] += 1000
        return ts[0]

    def newtid():
        nt[0] += 1
        return nt[0]

    ports = list(range(41000, 41000 + 2 * ops))
    random.shuffle(ports)
    it = iter(ports)
    plan_ops = {e: [{"exec_id": e, "op_id": f"{e}-{i}", "op_idx": i, "dport": next(it)} for i in range(ops)]
                for e in "AB"}
    dmap = {str(o["dport"]): [o["exec_id"], o["op_id"]] for e in "AB" for o in plan_ops[e]}
    reg = {"roots": {}, "cgroups": {}}
    ctx = {}
    sk = [1 << 40]

    def connect(pid, tid, cg, port):
        sk[0] += 64
        ev.append({"ev": "connect", "ts": t(), "pid": pid, "tid": tid, "cgroup": cg, "comm": "python3",
                   "sk": sk[0], "ctx": ctx.get(tid, ""), "daddr": "127.0.0.1", "dport": port})
        ev.append({"ev": "tcp_state", "ts": t(), "sk": sk[0], "old": 2, "new": 1})

    def fork(ptid, ppid, cg):
        c = newtid()
        ctx[c] = ctx.get(ptid, "")
        ev.append({"ev": "fork", "ts": t(), "ptid": ptid, "ctid": c, "ppid": ppid, "cgroup": cg, "ctx": ctx[c]})
        return c

    def op(o, pid, tid, cg):
        sub = mode == "subproc" or (mode == "mixed" and o["op_idx"] % 2)
        if sub:
            c = fork(tid, pid, cg)
            connect(c, c, cg, o["dport"])
            ev.append({"ev": "exit", "ts": t(), "pid": c, "tid": c})
        else:
            connect(pid, tid, cg, o["dport"])
        opslog.append(dict(o, ok=True))

    parent = 100
    if cond in ("N0", "N1"):
        cgs = {"A": 11, "B": 12} if cond == "N0" else {"A": 11, "B": 11}
        roots = {}
        for e in "AB":
            r = fork(parent, parent, 1)
            roots[e] = r
            reg["roots"][str(r)] = [e]
            reg["cgroups"].setdefault(str(cgs[e]), []).append(e)
            if binding:
                ctx[r] = CTX + e
        seq = [("A", o) for o in plan_ops["A"]] + [("B", o) for o in plan_ops["B"]]
        random.shuffle(seq)   # intercalação = concorrência
        for e, o in seq:
            op(o, roots[e], roots[e], cgs[e])
    else:
        w = 200
        reg["roots"][str(w)] = ["A", "B"]
        reg["cgroups"]["21"] = ["A", "B"]
        allops = plan_ops["A"] + plan_ops["B"]
        random.shuffle(allops)
        threads = [w] if cond == "N2" else [fork(w, w, 21) for _ in range(4)]
        for i, o in enumerate(allops):
            tid = threads[i % len(threads)]
            if binding:
                ctx[tid] = CTX + o["exec_id"]
            op(o, w, tid, 21)
            ctx[tid] = ""
    if conflict:   # contexto errado injetado numa execução N1: testa detecção de conflito
        for x in ev:
            if x["ev"] == "connect" and x["ctx"].endswith("A"):
                x["ctx"] = CTX + "B"
                break

    json.dump({"cond": cond, "mode": mode, "binding": binding, "seed": seed, "ops_per_exec": ops,
               "listen_addr": "127.0.0.1", "dport_map": dmap}, open(f"{out}/plan.json", "w"))
    json.dump(reg, open(f"{out}/registry.json", "w"))
    with open(f"{out}/events.jsonl", "w") as f:
        f.write('{"ev":"ready","ts":0}\n')
        for x in ev:
            f.write(json.dumps(x) + "\n")
        f.write('{"ev":"connect","ts":%d,"pid":1,"tid":1,"cgroup":1,"comm":"sshd","sk":1,"ctx":"",'
                '"daddr":"10.0.0.1","dport":443}\n' % (ts[0] + 1))   # tráfego de fundo
    with open(f"{out}/ops.jsonl", "w") as f:
        for x in opslog:
            f.write(json.dumps(x) + "\n")


if __name__ == "__main__":
    base = sys.argv[1]
    for cond in ("N0", "N1", "N2", "N3"):
        for b in (True, False):
            gen(cond, f"{base}/{cond}-{'bind' if b else 'nobind'}", binding=b)
    gen("N1", f"{base}/N1-conflict", conflict=True)
