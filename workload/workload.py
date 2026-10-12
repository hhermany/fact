#!/usr/bin/env python3
"""Workload sintético de rede para as condições N0–N3.

Cada execução (A, B, ...) faz operações de rede para destinos locais. Cada
operação usa uma PORTA DE DESTINO EXCLUSIVA, conhecida antes da execução e
registrada em plan.json. Essa porta é a referência independente da origem:
os resolvers não podem ler daddr/dport.

Condições:
  N0  árvores distintas, cgroups distintos               (controle)
  N1  árvores distintas, MESMO cgroup, concorrentes      (= C1 do manuscrito)
  N2  UM worker atende A e B em sequência                (reutilização)
  N3  UM worker atende A e B em threads concorrentes     (multiplexação por thread)

Modos de operação (--mode):
  inproc   connect() feito pelo próprio processo/thread da execução
  subproc  connect() feito por um processo filho (fork+exec de python -c)
  mixed    alterna inproc e subproc

Execuções: --execs K (K=2 usa A,B; K>2 usa E00..E{K-1}). Taxa: --jitter (pausa
máxima entre operações de uma execução; 0 = taxa máxima).

Uso (como root, com o coletor já ativo e o sentinel "ready" recebido):
  sudo python3 workload.py --cond N1 --ops 50 --mode mixed --out runs/r001 --seed 1

Saídas em --out:
  plan.json      mapa dport -> (exec_id, op_id) e parâmetros
  registry.json  raízes (pid -> exec_ids), cgroups (id -> exec_ids)
  ops.jsonl      operações efetivamente tentadas, com timestamps e resultado
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

CG_ROOT = "/sys/fs/cgroup/agentnet"
CTX_BEGIN = "/run/agentctx/begin/"
CTX_END = "/run/agentctx/end"
LISTEN_ADDR = "127.0.0.1"
EXECS = ["A", "B"]          # redefinido em main() conforme --execs


# ---------------------------------------------------------------- marcadores
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
    return path, os.stat(path).st_ino   # inode == id do cgroup v2 visto pelo eBPF


def cg_move(path, pid):
    with open(os.path.join(path, "cgroup.procs"), "w") as f:
        f.write(str(pid))


# ---------------------------------------------------------------- listener
class Listener(threading.Thread):
    """Aceita e fecha conexões em todas as portas do plano."""

    def __init__(self, ports):
        super().__init__(daemon=True)
        self.sel = selectors.DefaultSelector()
        self.socks = []
        for p in ports:
            s = socket.socket()
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


# ---------------------------------------------------------------- operações
SUBPROC_CODE = (
    "import socket,sys;s=socket.socket();s.settimeout(2);"
    "r=s.connect_ex((sys.argv[1],int(sys.argv[2])));s.close();sys.exit(0 if r==0 else 1)"
)


def do_op(op, mode, log, lock):
    t0 = time.time_ns()
    use_sub = mode == "subproc" or (mode == "mixed" and op["op_idx"] % 2 == 1)
    if use_sub:
        r = subprocess.run([sys.executable, "-I", "-c", SUBPROC_CODE, LISTEN_ADDR, str(op["dport"])])
        ok = r.returncode == 0
    else:
        s = socket.socket()
        s.settimeout(2)
        ok = s.connect_ex((LISTEN_ADDR, op["dport"])) == 0
        s.close()
    rec = dict(op, kind="subproc" if use_sub else "inproc", t_start=t0, t_end=time.time_ns(),
               ok=ok, pid=os.getpid(), tid=threading.get_native_id())
    with lock:
        log.write(json.dumps(rec) + "\n")
        log.flush()


def label_for(op):
    """Rótulo emitido pelo runtime: pré-sorteado no plano (ver main). Um número
    EXATO de operações por execução recebe o rótulo de outra execução (modelo de
    falha do vínculo), para que a injeção de falha não acrescente variância."""
    return op.get("label", op["exec_id"])


def run_op_with_ctx(op, mode, binding, log, lock):
    """Marca contexto por operação (tool call), em qualquer condição."""
    label = label_for(op)
    ctx_begin(label, binding)
    try:
        do_op(dict(op, label=label if binding else None), mode, log, lock)
    finally:
        ctx_end(binding)


def run_execution(exec_id, ops, mode, binding, log, lock, jitter):
    """Uma execução com raiz própria (N0/N1)."""
    for op in ops:
        run_op_with_ctx(op, mode, binding, log, lock)
        time.sleep(random.uniform(0, jitter))


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cond", required=True, choices=["N0", "N1", "N2", "N3"])
    ap.add_argument("--ops", type=int, default=50, help="operações por execução")
    ap.add_argument("--mode", default="mixed", choices=["inproc", "subproc", "mixed"])
    ap.add_argument("--no-binding", action="store_true", help="não emitir marcadores de contexto")
    ap.add_argument("--base-port", type=int, default=61000)
    ap.add_argument("--jitter", type=float, default=0.01)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--execs", type=int, default=2, help="número K de execuções concorrentes")
    ap.add_argument("--threads", type=int, default=8, help="threads do worker em N3")
    ap.add_argument("--wrong-label", type=float, default=0.0,
                    help="fração de operações por execução rotuladas com outra execução (número exato, posições sorteadas)")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    random.seed(a.seed)
    global EXECS
    EXECS = ["A", "B"] if a.execs == 2 else [f"E{i:02d}" for i in range(a.execs)]
    if a.base_port + a.ops * len(EXECS) > 65535:
        sys.exit("portas insuficientes: reduza --ops ou --execs")
    # as portas de escuta não podem cair na faixa efêmera (senão conexões de
    # cliente as ocupam e o bind falha sob carga)
    lo, hi = map(int, open("/proc/sys/net/ipv4/ip_local_port_range").read().split())
    if a.base_port <= hi and a.base_port + a.ops * len(EXECS) - 1 >= lo:
        sys.exit(f"portas {a.base_port}+ sobrepõem a faixa efêmera {lo}-{hi}: use --base-port acima de {hi}")
    # uma porta de escuta por operação: eleva o limite de descritores
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    need = a.ops * len(EXECS) + 256
    if soft < need:
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(max(need, soft), hard), hard))
    os.makedirs(a.out, exist_ok=True)
    binding = not a.no_binding

    # Plano: porta exclusiva por operação, embaralhada para não codificar a execução na ordem.
    ports = list(range(a.base_port, a.base_port + a.ops * len(EXECS)))
    random.shuffle(ports)
    ops, it = {e: [] for e in EXECS}, iter(ports)
    for e in EXECS:
        for i in range(a.ops):
            ops[e].append({"exec_id": e, "op_id": f"{e}-{i:04d}", "op_idx": i, "dport": next(it)})
    # falhas de rótulo: exatamente round(p * ops) operações por execução, posições sorteadas
    n_wrong = round(a.wrong_label * a.ops)
    if abs(n_wrong - a.wrong_label * a.ops) > 1e-9:
        sys.exit(f"wrong_label*ops = {a.wrong_label * a.ops} não é inteiro: escolha níveis que dão contagem exata")
    for e in EXECS:
        for i in random.sample(range(a.ops), n_wrong):
            ops[e][i]["label"] = random.choice([x for x in EXECS if x != e])
    plan = {"cond": a.cond, "mode": a.mode, "binding": binding, "seed": a.seed, "ops_per_exec": a.ops,
            "wrong_label": a.wrong_label, "wrong_per_exec": round(a.wrong_label * a.ops),
            "execs": len(EXECS), "jitter": a.jitter,
            "threads": a.threads, "exec_ids": EXECS,
            "listen_addr": LISTEN_ADDR,
            "dport_map": {str(o["dport"]): [o["exec_id"], o["op_id"]] for e in EXECS for o in ops[e]}}
    with open(os.path.join(a.out, "plan.json"), "w") as f:
        json.dump(plan, f, indent=1)

    listener = Listener(ports)   # thread iniciada só depois dos forks
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
                # Filho = raiz da execução e. Espera ser movido para o cgroup
                # e a liberação simultânea das duas raízes (concorrência).
                os.close(wfd)
                random.seed(a.seed * 1000 + EXECS.index(e) + 1)   # sequência própria por raiz
                os.read(rfd, 1)
                clog = open(os.path.join(a.out, f"ops-{e}.jsonl"), "w")
                run_execution(e, ops[e], a.mode, binding, clog, threading.Lock(), a.jitter)
                clog.close()
                os._exit(0)
            os.close(rfd)
            cg_path, cg_id = cgs[e]
            cg_move(cg_path, pid)
            children[e], gates[e] = pid, wfd
            registry["roots"][str(pid)] = [e]
            registry["cgroups"].setdefault(str(cg_id), []).append(e)
        listener.start()
        for e in EXECS:          # libera as raízes juntas
            os.write(gates[e], b"g")
            os.close(gates[e])
        for e in EXECS:
            os.waitpid(children[e], 0)
        # junta os logs das raízes em ops.jsonl
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
