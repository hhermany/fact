#!/usr/bin/env python3
"""Synthetic network workload for conditions N0-N3.

Each execution (A, B, ...) performs network operations to local destinations.
Each operation uses an EXCLUSIVE DESTINATION PORT, known before the execution
and recorded in plan.json. This port is the independent reference of the origin:
the resolvers may not read daddr/dport.

Conditions:
  N0  distinct trees, distinct cgroups                   (control)
  N1  distinct trees, SAME cgroup, concurrent
  N2  ONE worker serves A and B sequentially             (reuse)
  N3  ONE worker serves A and B on concurrent threads    (thread multiplexing)

Operation modes (--mode):
  inproc   connect() made by the execution's own process/thread
  subproc  connect() made by a child process (fork+exec of python -c)
  mixed    alternates inproc and subproc

Executions: --execs K (K=2 uses A,B; K>2 uses E00..E{K-1}). Rate: --jitter (maximum
pause between operations of an execution; 0 = maximum rate).

Usage (as root, with the collector already active and the "ready" sentinel received):
  sudo python3 workload.py --cond N1 --ops 50 --mode mixed --out runs/r001 --seed 1

Outputs in --out:
  plan.json      map dport -> (exec_id, op_id) and parameters
  registry.json  roots (pid -> exec_ids), cgroups (id -> exec_ids)
  ops.jsonl      operations actually attempted, with timestamps and outcome
"""
import argparse
import resource
import json
import os
import random
import selectors
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from netfam import LOOPBACK, SOCKET_FOR_ARGV1, af  # noqa: E402

CG_ROOT = "/sys/fs/cgroup/fact"
CTX_BEGIN = "/run/agentctx/begin/"
CTX_END = "/run/agentctx/end"
LISTEN_ADDR = LOOPBACK        # 127.0.0.1, or ::1 with FACT_FAMILY=6 (workload/netfam.py)
EXECS = ["A", "B"]          # redefined in main() according to --execs


# ---------------------------------------------------------------- markers
def ctx_mark(path):
    try:
        fd = os.open(path, os.O_RDONLY)
        os.close(fd)
    except FileNotFoundError:
        pass


def ctx_begin(exec_id, enabled):
    if enabled:
        ctx_mark(CTX_BEGIN + exec_id)


def ctx_end(enabled):
    if enabled:
        ctx_mark(CTX_END)


# ---------------------------------------------------------------- cgroups
def cg_create(name):
    path = os.path.join(CG_ROOT, name)
    os.makedirs(path, exist_ok=True)
    return path, os.stat(path).st_ino   # inode == cgroup v2 id as seen by eBPF


def cg_move(path, pid):
    with open(os.path.join(path, "cgroup.procs"), "w") as f:
        f.write(str(pid))


# ---------------------------------------------------------------- listener
class Listener(threading.Thread):
    """Accepts and closes connections on every planned port."""

    def __init__(self, ports):
        super().__init__(daemon=True)
        self.sel = selectors.DefaultSelector()
        self.socks = []
        for p in ports:
            s = socket.socket(af(LISTEN_ADDR))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((LISTEN_ADDR, p))
            s.listen(64)
            s.setblocking(False)
            self.sel.register(s, selectors.EVENT_READ)
            self.socks.append(s)
        self.stop = False

    def run(self):
        while not self.stop:
            for key, _ in self.sel.select(timeout=0.2):
                try:
                    c, _ = key.fileobj.accept()
                    c.close()
                except BlockingIOError:
                    pass


# ---------------------------------------------------------------- operations
SUBPROC_CODE = (
    "import socket,sys;s=" + SOCKET_FOR_ARGV1 + ";s.settimeout(2);"
    "r=s.connect_ex((sys.argv[1],int(sys.argv[2])));s.close();sys.exit(0 if r==0 else 1)"
)


def do_op(op, mode, log, lock):
    t0 = time.time_ns()
    use_sub = mode == "subproc" or (mode == "mixed" and op["op_idx"] % 2 == 1)
    if use_sub:
        r = subprocess.run([sys.executable, "-I", "-c", SUBPROC_CODE, LISTEN_ADDR, str(op["dport"])])
        ok = r.returncode == 0
    else:
        s = socket.socket(af(LISTEN_ADDR))
        s.settimeout(2)
        ok = s.connect_ex((LISTEN_ADDR, op["dport"])) == 0
        s.close()
    rec = dict(op, kind="subproc" if use_sub else "inproc", t_start=t0, t_end=time.time_ns(),
               ok=ok, pid=os.getpid(), tid=threading.get_native_id())
    with lock:
        log.write(json.dumps(rec) + "\n")
        log.flush()


def label_for(op):
    """Label emitted by the runtime: drawn in advance in the plan (see main). An EXACT
    number of operations per execution receives another execution's label (binding
    fault model), so that fault injection adds no variance."""
    return op.get("label", op["exec_id"])


def run_op_with_ctx(op, mode, binding, log, lock):
    """Marks the context per operation (tool call), in any condition."""
    label = label_for(op)
    ctx_begin(label, binding)
    try:
        do_op(dict(op, label=label if binding else None), mode, log, lock)
    finally:
        ctx_end(binding)


def run_execution(exec_id, ops, mode, binding, log, lock, jitter):
    """One execution with its own root (N0/N1)."""
    for op in ops:
        run_op_with_ctx(op, mode, binding, log, lock)
        time.sleep(random.uniform(0, jitter))


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cond", required=True, choices=["N0", "N1", "N2", "N3"])
    ap.add_argument("--ops", type=int, default=50, help="operations per execution")
    ap.add_argument("--mode", default="mixed", choices=["inproc", "subproc", "mixed"])
    ap.add_argument("--no-binding", action="store_true", help="do not emit context markers")
    ap.add_argument("--base-port", type=int, default=61000)
    ap.add_argument("--jitter", type=float, default=0.01)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--execs", type=int, default=2, help="number K of concurrent executions")
    ap.add_argument("--threads", type=int, default=8, help="worker threads in N3")
    ap.add_argument("--wrong-label", type=float, default=0.0,
                    help="fraction of operations per execution labeled with another execution (exact count, random positions)")
    ap.add_argument("--policy", type=int, default=0,
                    help="1: loads the per-execution policy (requires fact_policy running)")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    random.seed(a.seed)
    global EXECS
    EXECS = ["A", "B"] if a.execs == 2 else [f"E{i:02d}" for i in range(a.execs)]
    if a.base_port + a.ops * len(EXECS) > 65535:
        sys.exit("not enough ports: reduce --ops or --execs")
    # the listening ports must not fall in the ephemeral range (otherwise client
    # connections take them and bind fails under load)
    lo, hi = map(int, open("/proc/sys/net/ipv4/ip_local_port_range").read().split())
    if a.base_port <= hi and a.base_port + a.ops * len(EXECS) - 1 >= lo:
        sys.exit(f"ports {a.base_port}+ overlap the ephemeral range {lo}-{hi}: use --base-port above {hi}")
    # one listening port per operation: raise the file-descriptor limit
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    need = a.ops * len(EXECS) + 256
    if soft < need:
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(max(need, soft), hard), hard))
    os.makedirs(a.out, exist_ok=True)
    binding = not a.no_binding

    # Plan: one exclusive port per operation, shuffled so that the order does not encode the execution.
    ports = list(range(a.base_port, a.base_port + a.ops * len(EXECS)))
    random.shuffle(ports)
    ops, it = {e: [] for e in EXECS}, iter(ports)
    for e in EXECS:
        for i in range(a.ops):
            ops[e].append({"exec_id": e, "op_id": f"{e}-{i:04d}", "op_idx": i, "dport": next(it)})
    # label faults: exactly round(p * ops) operations per execution, at random positions
    n_wrong = round(a.wrong_label * a.ops)
    if abs(n_wrong - a.wrong_label * a.ops) > 1e-9:
        sys.exit(f"wrong_label*ops = {a.wrong_label * a.ops} is not an integer: choose levels that give an exact count")
    for e in EXECS:
        for i in random.sample(range(a.ops), n_wrong):
            ops[e][i]["label"] = random.choice([x for x in EXECS if x != e])
    plan = {"cond": a.cond, "mode": a.mode, "binding": binding, "seed": a.seed, "ops_per_exec": a.ops,
            "wrong_label": a.wrong_label, "wrong_per_exec": round(a.wrong_label * a.ops),
            "execs": len(EXECS), "jitter": a.jitter,
            "threads": a.threads, "exec_ids": EXECS,
            "listen_addr": LISTEN_ADDR,
            "dport_map": {str(o["dport"]): [o["exec_id"], o["op_id"]] for e in EXECS for o in ops[e]}}
    if a.policy:
        # same classes as E6: P (every planned destination) and R (a random half of its
        # own); separate generator, so as not to change the plan of the other conditions
        prng = random.Random(a.seed + 7919)
        classes = {e: ("P" if i % 2 == 0 else "R") for i, e in enumerate(EXECS)}
        allow = {}
        for e in EXECS:
            own = [o["dport"] for o in ops[e]]
            allow[e] = sorted(ports) if classes[e] == "P" else sorted(prng.sample(own, len(own) // 2))
        plan["policy"] = {"classes": classes, "allow": allow}
    with open(os.path.join(a.out, "plan.json"), "w") as f:
        json.dump(plan, f, indent=1)
    if a.policy:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "policy"))
        import policyctl
        policyctl.load_dict(plan["policy"]["allow"])

    listener = Listener(ports)   # thread started only after the forks
    lock = threading.Lock()
    log = open(os.path.join(a.out, "ops.jsonl"), "w")
    registry = {"roots": {}, "cgroups": {}}

    if a.cond in ("N0", "N1"):
        cgs = {e: cg_create(f"{a.cond}-{e}" if a.cond == "N0" else f"{a.cond}-shared") for e in EXECS}
        children, gates = {}, {}
        for e in EXECS:
            rfd, wfd = os.pipe()
            pid = os.fork()
            if pid == 0:
                # Child = root of execution e. Waits to be moved into its cgroup
                # and for the simultaneous release of the roots (concurrency).
                os.close(wfd)
                random.seed(a.seed * 1000 + EXECS.index(e) + 1)   # own sequence per root
                os.read(rfd, 1)
                clog = open(os.path.join(a.out, f"ops-{e}.jsonl"), "w")
                run_execution(e, ops[e], a.mode, binding, clog, threading.Lock(), a.jitter)
                clog.close()
                os._exit(0)
            os.close(rfd)
            cg_path, cg_id = cgs[e]
            cg_move(cg_path, pid)
            if a.policy:     # single-owner root: the policy can check lineage
                policyctl.register_root(pid, e)
            children[e], gates[e] = pid, wfd
            registry["roots"][str(pid)] = [e]
            registry["cgroups"].setdefault(str(cg_id), []).append(e)
        listener.start()
        for e in EXECS:          # releases the roots together
            os.write(gates[e], b"g")
            os.close(gates[e])
        for e in EXECS:
            os.waitpid(children[e], 0)
        # merges the roots' logs into ops.jsonl
        for e in EXECS:
            p = os.path.join(a.out, f"ops-{e}.jsonl")
            with open(p) as f:
                log.write(f.read())
            os.remove(p)

    if a.cond in ("N2", "N3"):
        listener.start()
        cg_path, cg_id = cg_create(f"{a.cond}-worker")
        cg_move(cg_path, os.getpid())
        registry["roots"][str(os.getpid())] = EXECS[:]
        registry["cgroups"][str(cg_id)] = EXECS[:]
        all_ops = [o for e in EXECS for o in ops[e]]
        random.shuffle(all_ops)
        if a.cond == "N2":
            for op in all_ops:
                run_op_with_ctx(op, a.mode, binding, log, lock)
        else:
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=a.threads) as pool:
                list(pool.map(lambda op: run_op_with_ctx(op, a.mode, binding, log, lock), all_ops))

    listener.stop = True
    log.close()
    with open(os.path.join(a.out, "registry.json"), "w") as f:
        json.dump(registry, f, indent=1)


if __name__ == "__main__":
    main()
