#!/usr/bin/env python3
"""Runs AgentProvenance (v0.9.0) for real on one E5 round, next to FACT.

The AgentProvenance sensor runs during the round (started by run_round.sh with
AGENTPROV=<binary>). After the workload ends, this script registers one
ToolCallScope binding per MCP tool call, as a harness integration would: tool
call id, execution scope (the session), the identity of the process that served
the call (pid, root pid, cgroup: the shared MCP server in E5ap, or the execution's
own process tree and cgroup when each execution has one, as in AgentProvenance's
per-execution sandboxes, E1ap) and the exact call window [t_start, t_end]
measured by the client or, with AGENTPROV_WINDOW=server (E5aps), the window
measured inside the server (handler entry to exit, server_calls.jsonl), which
excludes the client's queueing. The sensor holds uncorrelated
events for late bindings (--pending-ttl), so the bindings registered here are
matched by AgentProvenance's own correlation engine. Then it stops the sensor
and exports AgentProvenance's events and correlations as JSON.

Usage: agentprov_bind.py <round_dir> <agentprov_binary> <sensor_pid>
Outputs (in <round_dir>/agentprov/): binds.log, events.json, correlations.json
"""
import datetime as dt
import json
import os
import signal
import subprocess
import sys
import time


def rfc3339(ns):
    s, frac = divmod(int(ns), 1_000_000_000)
    return dt.datetime.fromtimestamp(s, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + f".{frac:09d}Z"


def main():
    rdir, ap, spid = sys.argv[1], sys.argv[2], int(sys.argv[3])
    dd = os.path.join(rdir, "agentprov")
    data = os.path.join(dd, "store")
    reg = json.load(open(os.path.join(rdir, "registry.json")))
    # process tree and cgroup that serve each execution: a single shared server
    # (E5ap) or one per execution (E1ap, N0/N1)
    root_of = {e: int(pid) for pid, es in reg["roots"].items() for e in es}
    cg_of = {e: cg for cg, es in reg["cgroups"].items() for e in es}
    run_id = "fact-" + os.path.basename(os.path.normpath(rdir))
    ops = [json.loads(l) for l in open(os.path.join(rdir, "ops.jsonl"))]
    window = os.environ.get("AGENTPROV_WINDOW", "client")
    if window == "server":   # each (execution, port) is one call in E5 (one port per operation)
        srv = {(c["exec_id"], c["port"]): c for c in map(json.loads, open(os.path.join(rdir, "server_calls.jsonl")))}
        for op in ops:
            c = srv[(op["exec_id"], op["dport"])]
            op["t_start"], op["t_end"] = c["t_start"], c["t_end"]
    with open(os.path.join(dd, "binds.log"), "w") as log:
        for op in ops:
            cmd = [ap, "--data-dir", data, "telemetry", "bind", "--run", run_id,
                   "--tool-call", op["op_id"], "--execution-scope", op["exec_id"],
                   "--pid", str(root_of[op["exec_id"]]), "--root-pid", str(root_of[op["exec_id"]]),
                   "--cgroup-id", str(cg_of[op["exec_id"]]),
                   "--started-at", rfc3339(op["t_start"]), "--ended-at", rfc3339(op["t_end"])]
            r = subprocess.run(cmd, capture_output=True, text=True)
            log.write(json.dumps({"op_id": op["op_id"], "rc": r.returncode, "window": window,
                                  "out": r.stdout[-300:], "err": r.stderr[-300:]}) + "\n")
            if r.returncode != 0:
                sys.exit(f"bind failed ({op['op_id']}): {r.stderr.strip()[-300:]}")
    # the sensor retries pending events every flush interval; give it a few rounds
    time.sleep(float(os.environ.get("AGENTPROV_SETTLE_S", "5")))
    os.kill(spid, signal.SIGINT)
    for _ in range(300):
        try:
            os.kill(spid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    def dump(args, name):
        r = subprocess.run([ap, "--data-dir", data] + args, capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit(f"{' '.join(args)} failed: {r.stderr.strip()[-300:]}")
        with open(os.path.join(dd, name), "w") as f:
            f.write(r.stdout)
    dump(["telemetry", "list", "--json", "--limit", "100000"], "events.json")
    dump(["telemetry", "correlations", "--json"], "correlations.json")
    dump(["sensor", "status"], "sensor_status.txt")
    print(json.dumps({"agentprov_binds": len(ops), "run": run_id, "window": window}))


if __name__ == "__main__":
    main()
