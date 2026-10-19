#!/usr/bin/env python3
"""CPU cost of FACT during a run with a realistic workload (COST=1 in run_round.sh).

E3/E3b measure the worst case (a closed loop of connects). Here the cost is
measured while the workload of the experiment runs (e.g., LLM agents replayed
by E7r, or the shared MCP server of E5), between two instants taken right before
the workload starts and right after it ends:

  before OUT BPID [PPOL]   snapshot: bpftool prog show (with kernel.bpf_stats_enabled=1),
                           CPU ticks of the collector (bpftrace) and of the policy loader,
                           CPU ticks of the whole host, wall clock
  after OUT BPID [PPOL]    the same snapshot, then writes OUT/cost.json with the deltas
  factd OUT                replays the run's collector stream through factd (the live
                           daemon) and adds its CPU time to cost.json

cost.json:
  wall_s                        duration of the workload
  collector_cpu_s               user+system CPU of the bpftrace process (event export)
  policy_loader_cpu_s           the same for the policy loader (ring-buffer reader), if loaded
  bpf_run_time_s, bpf_run_cnt   CPU time and runs of every eBPF program that ran in the
                                interval (collector and policy), from bpf_stats
  host_cpu_s                    CPU time used by the whole host in the interval (all cores)
  fact_cpu_s                    collector + policy loader + eBPF programs
  fact_share_of_host            fact_cpu_s / host_cpu_s
  fact_cores                    fact_cpu_s / wall_s (cores used on average)
  factd_cpu_s, factd_events     CPU time of factd to process the run's stream (offline replay)
"""
import json
import os
import resource
import subprocess
import sys
import time

HZ = os.sysconf("SC_CLK_TCK")
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def proc_ticks(pid):
    try:
        f = open(f"/proc/{int(pid)}/stat").read().rsplit(")", 1)[1].split()
        return int(f[11]) + int(f[12])          # utime + stime (fields 14 and 15)
    except (OSError, ValueError, IndexError):
        return None


def host_ticks():
    f = open("/proc/stat").readline().split()[1:]
    v = [int(x) for x in f]
    return sum(v) - v[3] - v[4]                  # everything but idle and iowait


def snapshot(out, bpid, ppol):
    progs = json.loads(subprocess.run(["bpftool", "prog", "show", "--json"], capture_output=True,
                                      text=True).stdout or "[]")
    return {"t_ns": time.monotonic_ns(), "collector": proc_ticks(bpid),
            "policy": proc_ticks(ppol) if ppol else None, "host": host_ticks(),
            "progs": {str(p["id"]): {"name": p.get("name"), "type": p.get("type"),
                                     "run_time_ns": p.get("run_time_ns", 0), "run_cnt": p.get("run_cnt", 0)}
                      for p in progs}}


def main():
    step, out = sys.argv[1], sys.argv[2]
    path = os.path.join(out, "cost_snapshots.json")
    if step in ("before", "after"):
        bpid = sys.argv[3]
        ppol = sys.argv[4] if len(sys.argv) > 4 and sys.argv[4] else None
        snaps = json.load(open(path)) if step == "after" else {}
        snaps[step] = snapshot(out, bpid, ppol)
        json.dump(snaps, open(path, "w"))
        if step == "after":
            b, a = snaps["before"], snaps["after"]
            progs = []
            for pid, p in a["progs"].items():
                if pid in b["progs"]:
                    dn = p["run_time_ns"] - b["progs"][pid]["run_time_ns"]
                    dc = p["run_cnt"] - b["progs"][pid]["run_cnt"]
                    if dc > 0:
                        progs.append({"id": int(pid), "name": p["name"], "type": p["type"],
                                      "delta_run_cnt": dc, "delta_run_time_ns": dn})
            wall = (a["t_ns"] - b["t_ns"]) / 1e9
            col = (a["collector"] - b["collector"]) / HZ if a["collector"] is not None else None
            pol = (a["policy"] - b["policy"]) / HZ if a["policy"] is not None and b["policy"] is not None else 0.0
            bpf = sum(p["delta_run_time_ns"] for p in progs) / 1e9
            host = (a["host"] - b["host"]) / HZ
            fact = (col or 0.0) + pol + bpf
            res = {"wall_s": round(wall, 3), "collector_cpu_s": col, "policy_loader_cpu_s": pol,
                   "bpf_run_time_s": round(bpf, 6), "bpf_run_cnt": sum(p["delta_run_cnt"] for p in progs),
                   "bpf_progs": progs, "host_cpu_s": host, "fact_cpu_s": round(fact, 6),
                   "fact_share_of_host": round(fact / host, 6) if host else None,
                   "fact_cores": round(fact / wall, 6) if wall else None}
            json.dump(res, open(os.path.join(out, "cost.json"), "w"), indent=1)
            print(json.dumps({k: res[k] for k in ("wall_s", "fact_cpu_s", "fact_share_of_host", "fact_cores")}))
    elif step == "factd":
        r0 = resource.getrusage(resource.RUSAGE_CHILDREN)
        flows = os.path.join(out, "factd_cost_flows.jsonl")
        subprocess.run([sys.executable, "-I", os.path.join(HERE, "factd", "factd.py"), "--replay",
                        os.path.join(out, "events.jsonl"), "--registry", os.path.join(out, "registry.json"),
                        "--out", flows], check=True, capture_output=True)
        r1 = resource.getrusage(resource.RUSAGE_CHILDREN)
        res = json.load(open(os.path.join(out, "cost.json")))
        res["factd_cpu_s"] = round((r1.ru_utime - r0.ru_utime) + (r1.ru_stime - r0.ru_stime), 4)
        res["factd_events"] = sum(1 for _ in open(os.path.join(out, "events.jsonl")))
        os.remove(flows)
        json.dump(res, open(os.path.join(out, "cost.json"), "w"), indent=1)
    else:
        sys.exit(f"unknown step {step}")


if __name__ == "__main__":
    main()
