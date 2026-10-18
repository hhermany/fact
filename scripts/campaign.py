#!/usr/bin/env python3
"""Executa uma campanha completa a partir de uma especificação de experimento.

- Desenho: produto cartesiano dos níveis dos fatores × N repetições (sementes
  base_seed+rep).
- Ordem das rodadas sorteada com a semente da campanha e registrada.
- Ambiente capturado no início e no fim; commit/branch/dirty registrados.
- Saída imutável: campaigns/<campaign_id>/ + manifest.json + checksums.sha256
  + campaigns/<campaign_id>.tar.gz. Nunca sobrescreve campanha existente.
- label=confirmatory exige árvore git limpa e preflight PASS.

Uso (root):
  python3 scripts/campaign.py --spec workflow/experiments/E1.json --n 10 \
      --seed 22301 --label pilot --campaigns-dir campaigns
"""
import argparse
import datetime as dt
import hashlib
import itertools
import json
import os
import random
import socket
import subprocess
import sys
import tarfile
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# fator do spec -> argumento do workload.py
ARG = {"cond": None, "wrong_label": "--wrong-label", "mode": "--mode", "execs": "--execs",
       "jitter": "--jitter", "ops": "--ops", "threads": "--threads", "tool": "--tool",
       "binding_mode": "--binding-mode", "model": "--model", "ollama": "--ollama", "dest_host": "--dest-host"}


def sh(cmd, cwd=None):
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=60).stdout.strip()
    except Exception as e:   # noqa: BLE001
        return f"INDISPONIVEL: {e}"


def git_info():
    top = sh(["git", "rev-parse", "--show-toplevel"], cwd=HERE)
    if top.startswith("INDISPONIVEL") or not top:
        return {"commit": None, "branch": None, "dirty": None, "status": "sem git"}
    # diretórios de dados/saída não contam como "sujeira" de código
    status = sh(["git", "status", "--porcelain", "--", HERE,
                 ":(exclude)campaigns", ":(exclude)preflight", ":(exclude)analysis/output",
                 ":(exclude)analysis/runs.csv", ":(exclude)analysis/overhead.csv", ":(exclude)analysis/capacity.csv",
                 ":(exclude)analysis/n_projetado_*.json"], cwd=HERE)
    return {"toplevel": top, "commit": sh(["git", "rev-parse", "HEAD"], cwd=HERE),
            "branch": sh(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=HERE),
            "dirty": bool(status), "status_porcelain": status.splitlines()[:200]}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--spec", required=True)
    ap.add_argument("--n", type=int, required=True, help="repetições por célula")
    ap.add_argument("--seed", type=int, required=True, help="semente da campanha (ordem e sementes das rodadas)")
    ap.add_argument("--label", required=True, choices=["smoke", "pilot", "validation", "confirmatory"])
    ap.add_argument("--campaigns-dir", default=os.path.join(HERE, "campaigns"))
    ap.add_argument("--preflight", help="diretório de um preflight PASS (obrigatório para confirmatory)")
    a = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("rode como root")
    spec = json.load(open(a.spec))
    git = git_info()
    if a.label == "confirmatory":
        if git["dirty"] is not False:
            sys.exit("campanha confirmatória exige árvore git limpa (commit antes)")
        if not a.preflight or "RESULTADO PASS" not in open(os.path.join(a.preflight, "preflight.txt")).read():
            sys.exit("campanha confirmatória exige --preflight com RESULTADO PASS")

    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    cid = f"{socket.gethostname()}-{spec['experiment']}-{a.label}-{stamp}"
    cdir = os.path.join(a.campaigns_dir, cid)
    os.makedirs(cdir, exist_ok=False)

    # desenho
    names = list(spec["factors"])
    cells = [dict(zip(names, vals)) for vals in itertools.product(*(spec["factors"][n] for n in names))]
    runs = []
    for ci, cell in enumerate(cells):
        for rep in range(a.n):
            params = dict(spec.get("fixed", {}), **cell)
            # números aleatórios comuns: a mesma repetição usa a mesma semente em
            # todas as células (comparações pareadas entre condições; declarado na metodologia)
            runs.append({"cell": ci, "rep": rep, "seed": a.seed + rep, "params": params})
    rng = random.Random(a.seed)
    rng.shuffle(runs)
    for pos, r in enumerate(runs, 1):
        r["position"] = pos
        tag = r["params"].get("cond") or "-".join(f"{k}{v}" for k, v in sorted(r["params"].items())
                                                   if k in spec["factors"])
        r["run_id"] = f"r{pos:04d}-{tag}-c{r['cell']:02d}-rep{r['rep']:02d}"

    with open(os.path.join(cdir, "run_order.json"), "w") as f:
        json.dump({"campaign_seed": a.seed, "order": [(r["position"], r["run_id"]) for r in runs]}, f, indent=1)
    subprocess.run([os.path.join(HERE, "scripts", "capture_env.sh"), os.path.join(cdir, "environment"), "-inicio"])
    for fn in ("flake.nix", "flake.lock"):
        if os.path.exists(os.path.join(HERE, fn)):
            with open(os.path.join(HERE, fn)) as src, open(os.path.join(cdir, fn), "w") as dst:
                dst.write(src.read())
    with open(os.path.join(cdir, "command.txt"), "w") as f:
        f.write(" ".join(sys.argv) + "\n")

    runner = spec.get("runner", "attribution")
    expected = {"overhead": "overhead.json", "capacity": "capacity.json"}.get(runner, "score.json")
    t0 = time.time()
    for r in runs:
        p = r["params"]
        rdir = os.path.join(cdir, "runs", r["run_id"])
        if runner == "overhead":       # E3: microbenchmark de connect
            cmd = [os.path.join(HERE, "scripts", "e3_round.sh"), rdir, "--instr", str(p["instr"]),
                   "--markers", str(p["markers"]), "--n", str(p.get("n", 20000)),
                   "--warmup", str(p.get("warmup", 1000)), "--seed", str(r["seed"])]
            if p.get("dest_host"):
                cmd += ["--host", str(p["dest_host"])]
        elif runner == "capacity":     # E2b: capacidade do coletor
            cmd = [os.path.join(HERE, "scripts", "e2b_round.sh"), rdir, "--par", str(p["par"]),
                   "--n", str(p.get("n", 50000)), "--collector", str(p["collector"]), "--seed", str(r["seed"])]
        else:                          # E1/E2: atribuição
            cmd = [os.path.join(HERE, "run_round.sh"), p["cond"], rdir, "--seed", str(r["seed"])]
            for k, v in p.items():
                if ARG.get(k):
                    cmd += [ARG[k], str(v)]
            if p.get("binding") is False:
                cmd.append("--no-binding")
        env = dict(os.environ)
        if p.get("collector"):
            env["COLLECTOR"] = str(p["collector"])
        if p.get("workload"):
            env["WORKLOAD"] = str(p["workload"])
        if p.get("agentprov"):         # sistema relacionado executado de verdade, ao lado do agentnet
            env["AGENTPROV"] = str(p["agentprov"])
        if p.get("policy"):
            env["POLICY"] = "1"
            env["POLICY_NOCTX_ALLOW"] = str(p.get("policy_noctx_allow", 0))
            env["POLICY_LINEAGE"] = str(p.get("policy_lineage", 0))
        ts = time.time()
        res = subprocess.run(cmd, capture_output=True, text=True, env=env)
        r.update(returncode=res.returncode, seconds=round(time.time() - ts, 3), command=cmd[1:])
        r["status"] = "OK" if res.returncode == 0 and os.path.exists(os.path.join(rdir, expected)) else "FALHA"
        if r["status"] != "OK":
            with open(os.path.join(cdir, "runs", r["run_id"] + ".stderr"), "w") as f:
                f.write(res.stdout[-5000:] + "\n---\n" + res.stderr[-5000:])
        print(f"[{r['position']}/{len(runs)}] {r['run_id']} {r['status']} {r['seconds']}s", flush=True)

    subprocess.run([os.path.join(HERE, "scripts", "capture_env.sh"), os.path.join(cdir, "environment"), "-fim"])
    env = {k: sh(["cat", f"/proc/sys/kernel/{k}"]) for k in ("hostname",)}
    env["boot_id"] = sh(["cat", "/proc/sys/kernel/random/boot_id"])
    env["kernel"] = sh(["uname", "-r"])
    env["bpftrace"] = sh(["bpftrace", "--version"])
    env["python"] = sys.version.split()[0]
    env["virt"] = sh(["systemd-detect-virt"])
    manifest = {
        "campaign_id": cid, "experiment": spec["experiment"], "label": a.label, "description": spec.get("description"),
        "spec": spec, "n_per_cell": a.n, "campaign_seed": a.seed, "cells": len(cells), "total_runs": len(runs),
        "started_utc": stamp, "duration_s": round(time.time() - t0, 1),
        "runs_ok": sum(r["status"] == "OK" for r in runs), "runs_failed": sum(r["status"] != "OK" for r in runs),
        "git": git, "environment": env, "preflight": a.preflight,
        "unavailable_note": "itens INDISPONIVEL em environment/ não puderam ser observados",
        "runs": runs,
    }
    with open(os.path.join(cdir, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=1)

    # checksums de tudo, depois o pacote
    with open(os.path.join(cdir, "checksums.sha256"), "w") as out:
        for root, _, files in os.walk(cdir):
            for fn in sorted(files):
                if fn == "checksums.sha256":
                    continue
                path = os.path.join(root, fn)
                out.write(f"{sha256(path)}  {os.path.relpath(path, cdir)}\n")
    with tarfile.open(cdir + ".tar.gz", "w:gz") as tar:
        tar.add(cdir, arcname=cid)
    print(f"CAMPANHA {cid}: {manifest['runs_ok']}/{len(runs)} OK em {manifest['duration_s']}s")
    print(f"PACOTE {cdir}.tar.gz")
    sys.exit(0 if manifest["runs_failed"] == 0 else 1)


if __name__ == "__main__":
    main()
