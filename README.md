# agentnet

Verifiable per-execution network attribution, accounting and control for AI agents, with eBPF.
Artifact of the paper *Who Opened This Connection? Verifiable Per-Execution Network Accounting
and Control for AI Agents* (submitted to IEEE/IFIP NOMS 2027).

## What is here

| Path | Content |
|---|---|
| `collector/` | bpftrace collectors (`agentnet.bt` full, `agentnet-fast.bt` optimized, `agentnet-count.bt` ablation) |
| `agentnet_rt/` | Runtime binding: execution identity follows the task (Python `contextvars`) and is handed to the kernel right before each `connect`/process creation; FastMCP integration via `_meta` |
| `policy/` | Per-execution egress policy: `cgroup/connect4` eBPF program (libbpf) + loader + `policyctl.py` |
| `agentnetd/` | Live attribution and per-execution accounting daemon |
| `analysis/` | Resolvers (fused, with explicit ambiguity), scoring against the independent reference, R analysis that generates every table of the paper |
| `workload/` | Synthetic workloads (E1–E3), MCP server/driver (E4–E6), LLM agents on a local model (E7) |
| `scripts/`, `workflow/`, `Snakefile`, `flake.nix` | Reproducible pipeline: Nix shell, Snakemake (preflight → pilot → campaign → validation → report) |
| `campaigns/` | One directory per campaign with `manifest.json`, `checksums.sha256` and environment snapshot. **Raw run data are not in git** (hundreds of MB): they are archived separately (see below) and verified by the checksums |
| `tests/` | Simulation test of the runtime binding; equivalence test live daemon × offline scoring |
| `paper/` | LaTeX sources of the paper (tables in `paper/generated/` come from `analysis/analysis.R`) |
| `docs/METODOLOGIA.md` | Experimental methodology (Portuguese), with the literature that justifies each choice |

## Reproducing

Requirements on the host: Linux with BTF, bpftrace ≥ 0.25, bpftool, clang/libbpf, Nix with flakes, root.

```sh
nix --extra-experimental-features 'nix-command flakes' develop
snakemake --cores 1 preflight            # environment checks
snakemake --cores 1 piloto_E5            # a pilot (not used in the paper)
snakemake --cores 1 campanha_E5          # a confirmatory campaign (requires a clean git tree)
snakemake --cores 1 validar relatorio    # regenerate every table from the campaigns
```

## Raw data

Campaign archives (`<campaign_id>.tar.gz`) are kept outside git. Archive location: **to be defined (Zenodo DOI)**.
Each archive can be checked against `campaigns/<campaign_id>/checksums.sha256`.

## History

Developed first in a branch of the authors' earlier repository (`noms/agentnet`, last commit `de5c489`);
this repository starts from that state without the raw data.
