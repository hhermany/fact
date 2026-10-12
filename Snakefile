# Orquestração do agentnet (mesmo modelo do CMP223):
#   preflight -> piloto_<E> -> dimensionar_<E> -> campanha_<E> -> validar -> relatorio
# O alvo padrão (all) só reconstrói a análise a partir das campanhas existentes:
# não coleta dado novo. Coletar é sempre um alvo explícito, ex.:
#   snakemake --cores 1 piloto_E1
# Rodar dentro de `nix develop`, como root (o coletor eBPF exige).
import glob

configfile: "workflow/config.yaml"
EXPS = list(config["experiments"])
SEED = config["campaign_seed"]


rule all:
    input:
        "analysis/output/resumo_celulas.csv"


rule preflight:
    output:
        "preflight/last/preflight.txt"
    shell:
        "rm -rf preflight/last && scripts/preflight.sh preflight/last"


rule piloto:
    input:
        "preflight/last/preflight.txt"
    output:
        touch(".sentinels/piloto_{exp}.done")
    params:
        spec=lambda w: config["experiments"][w.exp]["spec"],
        n=lambda w: config["experiments"][w.exp]["pilot_n"]
    shell:
        "python3 -I scripts/campaign.py --spec {params.spec} --n {params.n} --seed {SEED} "
        "--label pilot --preflight preflight/last"


def n_decidido(w):
    n = config["experiments"][w.exp].get("n")
    if not n:
        raise ValueError(f"N de {w.exp} ainda não decidido em workflow/config.yaml (decisão humana após o piloto)")
    return n


rule campanha:
    input:
        "preflight/last/preflight.txt"
    output:
        touch(".sentinels/campanha_{exp}.done")
    params:
        spec=lambda w: config["experiments"][w.exp]["spec"],
        n=n_decidido
    shell:
        "python3 -I scripts/campaign.py --spec {params.spec} --n {params.n} --seed {SEED} "
        "--label confirmatory --preflight preflight/last"


rule validar:
    input:
        glob.glob("campaigns/*/manifest.json")
    output:
        "analysis/runs.csv"
    shell:
        "python3 -I analysis/collect_runs.py campaigns --out {output}"


rule dimensionar:
    input:
        "analysis/runs.csv"
    output:
        "analysis/n_projetado_{exp}.json"
    params:
        target=config["precision_target"]
    shell:
        "python3 -I scripts/dimensionar_n.py {input} --experiment {wildcards.exp} --label pilot "
        "--target {params.target} --output {output}"


rule relatorio:
    input:
        "analysis/runs.csv"
    output:
        "analysis/output/resumo_celulas.csv",
        "analysis/output/tex/results_meta.tex"
    shell:
        "(python3 -I analysis/collect_overhead.py campaigns --out analysis/overhead.csv || rm -f analysis/overhead.csv) && "
        "(python3 -I analysis/collect_capacity.py campaigns --out analysis/capacity.csv || rm -f analysis/capacity.csv) && "
        "Rscript analysis/analysis.R {input} analysis/output analysis/overhead.csv analysis/output/tex"


# atalhos legíveis
for e in EXPS:
    rule:
        name: f"piloto_{e}"
        input: f".sentinels/piloto_{e}.done"
    rule:
        name: f"campanha_{e}"
        input: f".sentinels/campanha_{e}.done"
