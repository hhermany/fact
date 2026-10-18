#!/usr/bin/env python3
"""Reúne todas as rodadas de todas as campanhas num CSV longo (uma linha por
rodada × resolver), entrada única da análise em R.

Lê campaigns/<campaign_id>/manifest.json e runs/<run_id>/{plan,score}.json.
Não altera nada nas campanhas.

Uso: python3 collect_runs.py campaigns/ --out analysis/runs.csv
"""
import argparse
import csv
import glob
import json
import os

FACTORS = ["cond", "wrong_label", "mode", "execs", "jitter", "threads", "ops_per_exec", "binding", "seed",
           "tool", "mcp_version", "binding_mode", "model", "listen_addr"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("campaigns_dir")
    ap.add_argument("--out", required=True)
    ap.add_argument("--exclude-experiments", default="",
                    help="lista separada por vírgulas; os experimentos de falhas (E5f, E6f, E6n, E6L, E6Ls, E7f) "
                         "são analisados por fault_tables.py e ficam fora do runs.csv versionado")
    a = ap.parse_args()
    skip = {e for e in a.exclude_experiments.split(",") if e}

    rows = []
    for man_path in sorted(glob.glob(os.path.join(a.campaigns_dir, "*", "manifest.json"))):
        man = json.load(open(man_path))
        if man["experiment"] in skip:
            continue
        cdir = os.path.dirname(man_path)
        status = {r["run_id"]: r for r in man.get("runs", [])}
        for score_path in sorted(glob.glob(os.path.join(cdir, "runs", "*", "score.json"))):
            rdir = os.path.dirname(score_path)
            run_id = os.path.basename(rdir)
            plan = json.load(open(os.path.join(rdir, "plan.json")))
            sc = json.load(open(score_path))
            cap = sc["capture"]
            base = {
                "campaign_id": man["campaign_id"], "experiment": man["experiment"], "label": man["label"],
                "host": man["environment"].get("hostname"), "boot_id": man["environment"].get("boot_id"),
                "git_commit": man["git"].get("commit"), "git_dirty": man["git"].get("dirty"),
                "campaign_runs_failed": man.get("runs_failed", 0),
                "run_id": run_id, "run_position": status.get(run_id, {}).get("position"),
                "attempted": cap["attempted"], "captured": cap["captured"], "lost": cap["n_lost"],
                "duplicates": cap["duplicates"], "excluded_no_ref": cap["excluded"].get("no_reference", 0),
            }
            base.update({f: plan.get(f) for f in FACTORS})
            e4 = os.path.join(rdir, "e4_summary.json")
            if not os.path.exists(e4):
                e4 = os.path.join(rdir, "e7_summary.json")
            if os.path.exists(e4):
                es = json.load(open(e4))
                base.update(tool_ms_p50=es["tool_ms_p50"], tool_ms_mean=es["tool_ms_mean"])
            else:
                base.update(tool_ms_p50=None, tool_ms_mean=None)
            ps = os.path.join(rdir, "policy_score.json")
            if os.path.exists(ps):
                pj = json.load(open(ps))
                base.update({f"pol_{k}": pj[k] for k in ("N", "TA", "TD", "FA", "FD", "ND", "expected_allow")})
                base.update(pol_label_owner=pj["label"].get("owner", 0), pol_label_other=pj["label"].get("other", 0),
                            pol_label_none=pj["label"].get("none", 0))
            else:
                base.update({f"pol_{k}": None for k in ("N", "TA", "TD", "FA", "FD", "ND", "expected_allow")})
                base.update(pol_label_owner=None, pol_label_other=None, pol_label_none=None)
            cfile = os.path.join(rdir, "collector.txt")
            base["collector"] = open(cfile).read().strip() if os.path.exists(cfile) else "agentnet.bt"
            for name, v in sc["resolvers"].items():
                acc = v["accounting"].values()
                row = dict(base, resolver=name, N=v["N"], C=v["C"], A=v["A"], A_in=v["A_in"], M=v["M"], I=v["I"],
                           credited_ok=sum(d["credited_ok"] for d in acc),
                           credited_wrong=sum(d["credited_wrong"] for d in acc),
                           uncredited=sum(d["uncredited"] for d in acc),
                           abs_net_error=sum(abs(d["net_error"]) for d in acc))
                rows.append(row)
    if not rows:
        raise SystemExit("nenhuma rodada encontrada")
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"{len(rows)} linhas ({len(rows) // 4} rodadas) -> {a.out}")


if __name__ == "__main__":
    main()
