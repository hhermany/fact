# Workflow of the experiments:
#   preflight -> pilot_<E> -> size_<E> -> campaign_<E> -> validate -> report
# The default target (all) only rebuilds the analysis from the existing campaigns:
# it collects no new data. Collecting is always an explicit target, e.g.:
#   snakemake --cores 1 pilot_E1
# Run inside `nix develop`, as root (the eBPF collector requires it).
import glob

configfile: "workflow/config.yaml"
EXPS = list(config["experiments"])
SEED = config["campaign_seed"]


rule all:
    input:
        "analysis/output/cell_summary.csv",
        "analysis/output/fig/fig_e1.pdf"


rule preflight:
    output:
        "preflight/last/preflight.txt"
    shell:
        "rm -rf preflight/last && scripts/preflight.sh preflight/last"


rule pilot:
    input:
        "preflight/last/preflight.txt"
    output:
        touch(".sentinels/pilot_{exp}.done")
    params:
        spec=lambda w: config["experiments"][w.exp]["spec"],
        n=lambda w: config["experiments"][w.exp]["pilot_n"]
    shell:
        "python3 -I scripts/campaign.py --spec {params.spec} --n {params.n} --seed {SEED} "
        "--label pilot --preflight preflight/last"


def n_decided(w):
    n = config["experiments"][w.exp].get("n")
    if not n:
        raise ValueError(f"N of {w.exp} not decided yet in workflow/config.yaml (a human decision after the pilot)")
    return n


rule campaign:
    input:
        "preflight/last/preflight.txt"
    output:
        touch(".sentinels/campaign_{exp}.done")
    params:
        spec=lambda w: config["experiments"][w.exp]["spec"],
        n=n_decided
    shell:
        "python3 -I scripts/campaign.py --spec {params.spec} --n {params.n} --seed {SEED} "
        "--label confirmatory --preflight preflight/last"


rule validate:
    input:
        glob.glob("campaigns/*/manifest.json")
    output:
        "analysis/runs.csv"
    shell:
        "python3 -I analysis/collect_runs.py campaigns --out {output}"


rule size:
    input:
        "analysis/runs.csv"
    output:
        "analysis/n_projected_{exp}.json"
    params:
        target=config["precision_target"]
    shell:
        "python3 -I scripts/size_n.py {input} --experiment {wildcards.exp} --label pilot "
        "--target {params.target} --output {output}"


rule report:
    input:
        "analysis/runs.csv"
    output:
        "analysis/output/cell_summary.csv",
        "analysis/output/tex/results_meta.tex"
    shell:
        "(python3 -I analysis/collect_overhead.py campaigns --out analysis/overhead.csv || rm -f analysis/overhead.csv) && "
        "(python3 -I analysis/collect_capacity.py campaigns --out analysis/capacity.csv || rm -f analysis/capacity.csv) && "
        "Rscript analysis/analysis.R {input} analysis/output analysis/overhead.csv analysis/output/tex && python3 -I scripts/fullwidth_tables.py analysis/output/tex"


rule baselines:
    # emulated mechanisms of related systems (AgentSight-style time window,
    # AgentProvenance-style latest scope) on the confirmatory E1 and E5 logs
    output:
        "analysis/output/baselines.csv",
        "analysis/output/tex/tab_baselines.tex"
    shell:
        "python3 -I analysis/baselines.py campaigns/hermes-E1-confirmatory-* campaigns/hermes-E5-confirmatory-* "
        "> {output[0]} && python3 -I analysis/baselines_table.py {output[0]} analysis/output/tex && python3 -I scripts/fullwidth_tables.py analysis/output/tex"


rule agentprov:
    # AgentProvenance v0.9.0 executed next to FACT in the E5 rounds (E5ap)
    output:
        "analysis/output/E5ap_agentprov.csv"
    shell:
        "python3 -I analysis/agentprov_table.py --label confirmatory --out analysis/output > /dev/null"


rule agentprov_native:
    # AgentProvenance v0.9.0 in the setting it targets: executions with their own process trees and cgroups (E1ap)
    output:
        "analysis/output/E1ap_agentprov.csv"
    shell:
        "python3 -I analysis/agentprov_table.py --experiment E1ap --label confirmatory --out analysis/output > /dev/null"


rule e7c_tokens:
    # tokens reported by the Anthropic API in each E7c call, and the cost
    output:
        "analysis/output/E7c_tokens.csv"
    shell:
        "python3 -I analysis/e7c_tokens.py --label confirmatory --out analysis/output > /dev/null"


rule e7o_tokens:
    # the same for E7o (OpenAI); reasoning tokens are included in the output
    output:
        "analysis/output/E7o_tokens.csv"
    shell:
        "python3 -I analysis/e7c_tokens.py --exp E7o --label confirmatory --out analysis/output > /dev/null"


rule replay_compare:
    # E7r: each run replayed without a model, compared with the original recording (E7c/E7o)
    output:
        "analysis/output/E7r_replay.csv"
    shell:
        "python3 -I analysis/replay_compare.py --label confirmatory --out analysis/output > /dev/null"


rule figures:
    # figures of the paper (ggplot), from the summarized results only
    input:
        "analysis/output/cell_summary.csv",
        "analysis/output/baselines.csv",
        "analysis/output/E5ap_agentprov.csv",
        "analysis/output/E7c_tokens.csv",
        "analysis/output/E7o_tokens.csv",
        "analysis/output/E7r_replay.csv"
    output:
        expand("analysis/output/fig/{f}.pdf", f=["fig_e1", "fig_acct", "fig_e5e6", "fig_baselines"])
    shell:
        "Rscript analysis/figures.R analysis/output analysis/output/fig"


rule faults:
    # fault injection (E5f, E6f, E7f) and lineage-checked policy (E6L, E6Ls)
    output:
        "analysis/output/tex/tab_fault.tex",
        "analysis/output/tex/tab_lineage.tex",
        "analysis/output/tex/fault_meta.tex"
    shell:
        "python3 -I analysis/fault_tables.py campaigns analysis/output/tex && python3 -I scripts/fullwidth_tables.py analysis/output/tex"


# readable shortcuts
for e in EXPS:
    rule:
        name: f"pilot_{e}"
        input: f".sentinels/pilot_{e}.done"
    rule:
        name: f"campaign_{e}"
        input: f".sentinels/campaign_{e}.done"
