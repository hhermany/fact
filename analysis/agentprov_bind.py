#!/usr/bin/env python3
"""Runs AgentProvenance (v0.9.0) for real on one E5 round, next to agentnet.

The AgentProvenance sensor runs during the round (started by run_round.sh with
AGENTPROV=<binary>). After the workload ends, this script registers one
ToolCallScope binding per MCP tool call, as a harness integration would: tool
call id, execution scope (the session), the identity of the process that served
the call (the shared MCP server: pid, root pid, cgroup) and the exact call
window [t_start, t_end] measured by the client. The sensor holds uncorrelated
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
    srv_pid = int(next(iter(reg["roots"])))
    cg_id = next(iter(reg["cgroups"]))
    run_id = "agentnet-" + os.path.basename(os.path.normpath(rdir))
    ops = [json.loads(l) for l in open(os.path.join(rdir, "ops.jsonl"))]
    with open(os.path.join(dd, "binds.log"), "w") as log:
        for op in ops:
            cmd = [ap, "--data-dir", data, "telemetry", "bind", "--run", run_id,
                   "--tool-call", op["op_id"], "--execution-scope", op["exec_id"],
                   "--pid", str(srv_pid), "--root-pid", str(srv_pid), "--cgroup-id", str(cg_id),
                   "--started-at", rfc3339(op["t_start"]), "--ended-at", rfc3339(op["t_end"])]
            r = subprocess.run(cmd, capture_output=True, text=True)
            log.write(json.dumps({"op_id": op["op_id"], "rc": r.returncode,
                                  "out": r.stdout[-300:], "err": r.stderr[-300:]}) + "\n")
            if r.returncode != 0:
                sys.exit(f"bind falhou ({op['op_id']}): {r.stderr.strip()[-300:]}")
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
            sys.exit(f"{' '.join(args)} falhou: {r.stderr.strip()[-300:]}")
        with open(os.path.join(dd, name), "w") as f:
            f.write(r.stdout)
    dump(["telemetry", "list", "--json", "--limit", "100000"], "events.json")
    dump(["telemetry", "correlations", "--json"], "correlations.json")
    dump(["sensor", "status"], "sensor_status.txt")
    print(json.dumps({"agentprov_binds": len(ops), "run": run_id}))


if __name__ == "__main__":
    main()
