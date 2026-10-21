#!/usr/bin/env python3
"""E11file: the execution credential on another kernel-mediated resource (file writes).

K executions share one Python process. Each performs OPS writes of random size to its
own files; before each write the runtime hands the task's credential to the kernel
(a mediated call, like the connect and send hooks), and fact_policy (cred=1, files=1)
charges the bytes vfs_write accepted for regular files to the writing task's
credential. Modes:
  async: K asyncio tasks interleaved on one thread (an await between writes);
  pool:  a ThreadPoolExecutor with two workers serves every call of every execution,
         so each worker thread runs calls of different executions in turn.
The reference is what each write returned, summed per execution (plan.json); the
kernel's counters are dumped by the round script (file_usage.json).

Usage: file_e11.py --out DIR --mode async|pool --execs K --ops N --seed S
"""
import argparse
import asyncio
import concurrent.futures as cf
import contextvars
import json
import os
import random
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
from fact_rt import agentctx  # noqa: E402


def write_op(d, e, i, size):
    fd = os.open(os.path.join(d, f"{e}-{i}"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        agentctx.sync_kernel()   # no await or other task between the handoff and the write
        return os.write(fd, b"x" * size)
    finally:
        os.close(fd)


def call(d, e, i, size):
    with agentctx.bind(e):       # as the MCP wrapper binds each tools/call
        return write_op(d, e, i, size)


async def run_async(d, plan, rng):
    async def one(e, sizes):
        with agentctx.bind(e):
            out = []
            for i, s in enumerate(sizes):
                out.append(write_op(d, e, i, s))
                await asyncio.sleep(rng.uniform(0, 0.002))
            return e, out
    res = await asyncio.gather(*(one(e, s) for e, s in plan.items()))
    return {e: sum(o) for e, o in res}


def run_pool(d, plan, rng):
    jobs = [(e, i, s) for e, sizes in plan.items() for i, s in enumerate(sizes)]
    rng.shuffle(jobs)
    got = {e: 0 for e in plan}
    with cf.ThreadPoolExecutor(max_workers=2) as ex:
        futs = {ex.submit(contextvars.copy_context().run, call, d, e, i, s): e for e, i, s in jobs}
        for f in cf.as_completed(futs):
            got[futs[f]] += f.result()
    return got


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--mode", choices=["async", "pool"], required=True)
    ap.add_argument("--execs", type=int, required=True)
    ap.add_argument("--ops", type=int, default=25)
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    plan = {f"exec-{k:02d}": [rng.randint(1, 65536) for _ in range(a.ops)] for k in range(a.execs)}
    agentctx.install(iface="prctl")
    d = tempfile.mkdtemp(prefix="fact-e11-")
    try:
        got = asyncio.run(run_async(d, plan, rng)) if a.mode == "async" else run_pool(d, plan, rng)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    agentctx.sync_kernel()           # outside any execution: clears this thread's credential
    json.dump({"mode": a.mode, "execs": a.execs, "ops": a.ops, "seed": a.seed, "pid": os.getpid(),
               "ref_bytes": got, "planned_bytes": {e: sum(s) for e, s in plan.items()},
               "runtime_stats": dict(agentctx.stats)},
              open(os.path.join(a.out, "plan.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
