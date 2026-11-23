# FACT

Per-execution network attribution, accounting, and control for AI agents, with eBPF.
Artifact of the paper *Who Opened This Connection? eBPF-based Per-Execution Network Attribution,
Accounting, and Control for AI Agents* (submitted to IEEE/IFIP NOMS 2027).

FACT carries each tool call's execution identity to the kernel, so connections, sends and datagrams are attributed,
accounted and authorized per execution, even when concurrent tool calls share one worker process, thread or
keep-alive connection. It works over IPv4 and IPv6 (including IPv4-mapped addresses): the policy, the byte
accounting and the collectors hook both families, a coverage matrix checks every send path in both, and all 54
experiments of the paper were re-run over IPv6 with no difference in any FACT decision or count (see "IPv6" under
"Paper to data"). Column D9 of Table I records the same property for the related systems, from their source
(checked in November 2026) and, for the two we ran, from their execution:

| System | IPv4 and IPv6 | Evidence |
|---|---|---|
| AgentProvenance | no | run: v0.9.0 records no `network_connect` for an IPv6 destination; source: v0.10.1 (82c8f46) `internal/sensor/exec.c:459`, `if (sa.sin_family != AF_INET) return 0;` |
| AgentGuard | no | source (cef1a1f): `enforcer.bpf.c:620` denies every AF_INET6 connect, "No IPv6 path exists" |
| ActPlane | no | source (1cbb4d0): `docs/rule-language.md:113`, kernel endpoint matching is IPv4 only; IPv6 is reported as unsupported |
| AgentSight | yes | source (fbc6d91): `bpf/process_ext/bpf_net.h:114,157` format IPv6 destinations |
| OBI | yes | run: the association test gave the same counts over IPv6 as over IPv4 |
| AgentCgroup | no | does not attribute network activity |
| ContractWarden | no evidence | no public source found |
| FACT | yes | the coverage matrix and the 54 experiments, over both families |

## What is here

| Path | Content |
|---|---|
| `collector/` | bpftrace collectors (`fact.bt` full, `fact-fast.bt` optimized, `fact-count.bt` ablation, `fact-bytes.bt` with per-send/receive byte events) |
| `fact_rt/` | Runtime binding: execution identity follows the task (Python `contextvars`) and is handed to the kernel right before each `connect`/process creation (optionally also before each `send`, for connections reused by several tasks); FastMCP integration via `_meta` |
| `policy/` | Per-execution egress policy: `cgroup/connect4`/`connect6` and `cgroup/sendmsg4`/`sendmsg6` eBPF programs (IPv4, IPv6, IPv4-mapped), optional per-send authorization (BPF LSM `socket_sendmsg`), byte accounting (fexit on `tcp_sendmsg`, `udp_sendmsg`, `udpv6_sendmsg`, `tcp_recvmsg`, `vfs_write`), kernel-held credential (BPF LSM `task_prctl`), and an fentry on `udpv6_sendmsg` that tells connected IPv4-mapped datagrams apart (libbpf) + loader + `policyctl.py`; optional trusted-runtime mode (markers accepted only from registered runtime processes) |
| `factd/` | Live attribution and per-execution accounting daemon |
| `analysis/` | Resolvers (fused, with explicit ambiguity), scoring against the independent reference, R analysis that generates every table of the paper, and `figures.R`, a literate R script (knitr::spin) that draws every figure with ggplot from the summarized CSVs; `baselines.py` emulates the correlation mechanisms of related systems on the same logs |
| `workload/` | Synthetic workloads (E1–E3), MCP server/driver (E4–E6), LLM agents (E7, E7m); `remote_farm.py` serves the destinations on a second machine (E3net, E5net, E6net) |
| `scripts/`, `workflow/`, `Snakefile`, `flake.nix` | Reproducible pipeline: Nix shell, Snakemake (preflight → pilot → size → campaign → validate → report) |
| `campaigns/` | One directory per campaign with `manifest.json`, `checksums.sha256` and environment snapshot. **Raw run data are not distributed** (hundreds of MB); they can be regenerated and checked against the checksums (see Data) |
| `tests/` | Simulation test of the runtime binding; equivalence test live daemon × offline scoring |
| `docs/METHODOLOGY.md` | Experimental methodology, with the literature that justifies each choice; `docs/FAULT-INJECTION-PILOTS.md` records the fault-injection pilots |

## Reproducing

Requirements on the host: Linux with BTF, bpftrace ≥ 0.25, bpftool, clang/libbpf, Nix with flakes, root. E6reuse and E9b also need the BPF LSM enabled (kernel built with `CONFIG_BPF_LSM=y` and `bpf` in the `lsm=` boot parameter, e.g. `/etc/default/grub.d/99-fact-bpf-lsm.cfg` + `update-grub` + reboot; check with `cat /sys/kernel/security/lsm`).

```sh
nix --extra-experimental-features 'nix-command flakes' develop
snakemake --cores 1 preflight            # environment checks
snakemake --cores 1 pilot_E5             # a pilot (not used in the paper)
snakemake --cores 1 campaign_E5          # a confirmatory campaign (requires a clean git tree)
snakemake --cores 1 validate report      # regenerate every table from the campaigns
snakemake --cores 1 baselines            # comparison with emulated related mechanisms
snakemake --cores 1 figures              # figures of the paper (ggplot), from the summarized results
```

The table below names results by the files generated for them (`fig_e1.pdf`, `tab_e2.tex`, ...); "Paper to
data" below maps the paper's figures, tables, and sections to them.

| Experiment | Campaigns | Generated by |
|---|---|---|
| Figs. E1 and accounting | `hermes-E1-confirmatory-*` (two boots) | `analysis/analysis.R`, `analysis/figures.R` |
| Table E2, E2b | `hermes-E2-confirmatory-*`, `hermes-E2b-confirmatory-*` | `analysis/analysis.R` |
| Tables E3, E3b; E1fast equivalence | `hermes-E3-confirmatory-*`, `hermes-E3b-confirmatory-*`, `hermes-E1fast-confirmatory-*` | `analysis/collect_overhead.py`, `analysis/analysis.R` |
| E4; Fig. E5/E6 | `hermes-E4-confirmatory-*`, `hermes-E5-confirmatory-*`, `hermes-E6-confirmatory-*` | `analysis/analysis.R`, `analysis/score_policy.py`, `analysis/figures.R` |
| Fig. of related mechanisms | `hermes-E1-confirmatory-*`, `hermes-E5-confirmatory-*` | `analysis/baselines.py`, `analysis/figures.R` |
| E7 | `hermes-E7-confirmatory-*` | `analysis/score_policy.py`, `analysis/analysis.R` |
| Binding faults (E5f, E6f, E7f) and lineage-checked policy (E6L, E6Ls) | `hermes-E5f-confirmatory-*`, `hermes-E6f-confirmatory-*`, `hermes-E7f-confirmatory-*`, `hermes-E6L-confirmatory-*`, `hermes-E6Ls-confirmatory-*` | `analysis/fault_tables.py` |
| Network interface between two VMs, vmxnet3 (E5net, E6net, E3net) | `hermes-E5net-confirmatory-*`, `hermes-E6net-confirmatory-*`, `hermes-E3net-confirmatory-*` | `analysis/analysis.R` |
| AgentProvenance executed (E5ap); larger models (E7m) | `hermes-E5ap-confirmatory-*`, `hermes-E7m-confirmatory-*` | `analysis/agentprov_table.py`, `analysis/analysis.R`, `analysis/figures.R` |
| Commercial models (E7c, E7o) and model-free replay (E7r) | `hermes-E7c-confirmatory-*`, `hermes-E7o-confirmatory-*`, `hermes-E7r-confirmatory-*` | `analysis/e7c_tokens.py`, `analysis/replay_compare.py`, `analysis/analysis.R` |
| Live accounting (`factd`) | all confirmatory campaigns (`analysis/output/factd_equiv.json`) | `tests/test_factd_equiv.py` |
| AgentProvenance in its own setting (E1ap) | `hermes-E1ap-confirmatory-*` | `analysis/agentprov_table.py --experiment E1ap` |
| Policy on reused connections, per-send authorization (E6reuse); integrated configuration with the policy on every send (E9b) | `hermes-E6reuse-confirmatory-*`, `hermes-E9b-confirmatory-*` | `analysis/presub_tables.py`, `analysis/score_reuse_policy.py` |
| Integrated configuration, every option available before budgets and the kernel-held credential (E9all) | `hermes-E9all-confirmatory-*` | `analysis/presub_tables.py`, `analysis/score_ipfix.py` |
| Kernel-held credential with budgets: concurrent budgets (E10conccred), selective containment (E12containcred), integrated cost with every option (E9costcred) | `hermes-E10conccred-confirmatory-*`, `hermes-E12containcred-confirmatory-*`, `hermes-E9costcred-confirmatory-*` | `analysis/credint_tables.py` |
| Network-operations incident with LLM agents (E7net) | `hermes-E7net-confirmatory-*` | `analysis/e7net_summary.py`, `analysis/e7net_other_addr.py` |
| OBI v1.0.0 association test (no FACT) | `campaigns/obi-assoc-20261118/` | `bench/obi_assoc.py`, `scripts/run_obi_all.sh`, `scripts/run_obi_tools.sh`, `analysis/obi_summary.py` |
| Session identity (E6sess), failure boundary (E5native), unmodified fetch server (E5fetch), UDP flows (E5udp), IPFIX export (E8ipfix) | `hermes-E6sess-confirmatory-*`, `hermes-E5native-confirmatory-*`, `hermes-E5fetch-confirmatory-*`, `hermes-E5udp-confirmatory-*`, `hermes-E8ipfix-confirmatory-*` | `analysis/presub_tables.py`, `analysis/score_ipfix.py` |
| Second runtime: Node.js MCP server (E5node) | `hermes-E5node-confirmatory-*` | `analysis/presub_tables.py` |
| Third-party clients (E5lib), connection reuse and bytes (E5reuse), spoofed markers (E6spoof), CPU cost under agents (E7rc) | `hermes-E5lib-confirmatory-*`, `hermes-E5reuse-confirmatory-*`, `hermes-E6spoof-confirmatory-*`, `hermes-E7rc-confirmatory-*` | `analysis/presub_tables.py`, `analysis/score_bytes.py` |
| Send-binding cost | `analysis/output/send_bind/` | `bench/send_bind_round.sh` |

## Paper to data (submitted version)

Figure, table, and section numbers refer to the submitted paper. Campaign directories are
`campaigns/hermes-<ID>-confirmatory-*`; summarized results are under `analysis/output/`, and the tables
and figures generated from them under `analysis/output/tex/` and `analysis/output/fig/`.

| Paper | Campaigns | Summarized result |
|---|---|---|
| Fig. 2; scaling to K = 64 (Sec. VI-A) | E1, E2 | `cell_summary.csv`, `E2_scale.csv` |
| Fig. 3 (shared MCP server) | E5, E6 | `E5_framework.csv`, `E6_policy.csv` |
| Fig. 4 (related mechanisms) | E1, E1ap, E5, E5ap, E5aps | `baselines.csv`, `E1ap_agentprov.csv`, `E5ap_agentprov.csv`, `E5aps_agentprov.csv` |
| Sec. VI-B (faulty identities, native code) | E5f, E6f, E7f, E6L, E6Ls, E5native | `analysis/fault_tables.py`, `E5native_boundary.csv` |
| Table III, Sec. VI-C (policy, reuse, bytes, budgets) | E6, E5reuse, E6reuse, E5partial, E5udp, E10budget, E10conc, E10conccred | `E6_policy.csv`, `E5reuse_bytes.csv`, `E6reuse_policy.csv`, `E5partial.csv`, `E5udp_flows.csv`, `E10budget.csv`, `credint_summary.json` |
| Table IV, Sec. VI-D (selective containment) | E12contain, E12containcred | `contain_summary.json`, `credint_summary.json` |
| Sec. VI-E (real agents, overhead) | E7, E7m, E7c, E7o, E7r, E7net, E3, E3net, E3send, E7rc, E9costcred, E9cost | `E7net_summary.json`, `E7net_other_addr.json`, `credint_summary.json`, `E7_*.csv`, `E3_overhead.csv`, `E3net_overhead.csv`, `E3send_cost.csv`, `E7rc_cost.csv`, `E9cost.csv`, `cost_stability.csv` (every overhead figure in the text is a paired median from this file, except those of the integrated workload, E9costcred, which are paired medians in `credint_summary.json`; the 0.2% of host CPU at the agents' pace is `fact_pct_of_host_median` in `E7rc_cost.csv`; the other files summarize each configuration, so differences of their medians can differ slightly) |
| Kernel-held credential (Secs. IV-G, VII) | E3cred, E6cred, E6reusecred, E6spoofcred, E11file | `kcred_summary.json` |
| Live accounting and IPFIX (Sec. IV-E) | E8ipfix, E9all | `E8ipfix_accounting.csv`, `E9all_ipfix.csv`, `factd_equiv.json` |
| OBI measured (Sec. III) | OBI test (`campaigns/obi-assoc-20261118/`) | `obi_assoc.csv` |
| Structural conflicts (Sec. IV-D) | every recorded run, pilots included (campaigns assembled with `scripts/extract_campaigns.sh`) | `structural_conflicts.csv` |
| Policy outcomes per class, reach of denied connects (Secs. V-C, VI-C) | every confirmatory run with a policy | `policy_matrix.csv`, `policy_reach.csv` (`analysis/policy_matrix.py`) |
| Connection reuse by opener and sender (Sec. VI-C) | E6reuse, E6reusecred | `reuse_matrix.csv` (`analysis/reuse_matrix.py`) |
| Send-path coverage over IPv4 and IPv6 (Secs. IV-F, VII) | directed test `tests/coverage/run.sh` | `coverage_test.json` |
| IPv6 reruns (Sec. VII, External) | every experiment, once per cell, over IPv4 and IPv6 (`scripts/run_parity.sh`) | `analysis/output/ipv6/` (see "IPv6" above) |
| Table I, column D9 (IPv4 and IPv6 coverage of related systems) | AgentProvenance and OBI runs; source of the others | table at the top of this README |

### Configuration behind each result

Every number in the paper comes from one configuration. "Markers" is the runtime handoff of Sec. IV-B/C
(`fact_rt`, task-scoped unless stated); "kernel-held" is the credential of Sec. IV-G (`prctl(PR_FACT)`).
Whenever the policy runs, its loader attaches `cgroup/connect4`, `cgroup/sendmsg4` for unconnected datagrams
(since 2026-10-20, commit a5798ff), and their IPv6 counterparts `connect6` and `sendmsg6` (since 2026-11-22);
"connection-level" means without the BPF LSM `socket_sendmsg` hook, which per-send authorization adds.

| Result | Campaigns | Identity handoff | Policy | Budgets | IPFIX | Workload |
|---|---|---|---|---|---|---|
| Fig. 2, K = 64 (Sec. VI-A) | E1, E2 | markers (context per operation) | none | no | no | synthetic workers N0-N3 |
| Fig. 3 | E5, E6 | markers: thread-keyed (manual) vs. task-scoped | connection-level (E6) | no | no | shared MCP server, four tool types |
| Fig. 4 | E1, E1ap, E5, E5ap, E5aps | markers (FACT); AgentProvenance bindings | none | no | no | synthetic N3; shared MCP server |
| Sec. VI-B | E5f, E6f, E7f, E6L, E6Ls, E5native | markers, mislabeled at rate p; clearing on/off (E5native) | connection-level, lineage check (E6L, E6Ls) | no | no | synthetic; shared MCP server; LLM agents (E7f) |
| Sec. VI-C, Table III: egress policy | E6 | markers | connection-level | no | no | shared MCP server |
| Sec. VI-C, Table III: reused connections | E5reuse, E6reuse | markers + send binding | per-send on/off (E6reuse) | no | no | shared keep-alive pools |
| Sec. VI-C, Table III: accepted bytes | E5partial | n/a (one sender) | none | no | no | nonblocking sender under backpressure |
| Sec. VI-C: unconnected datagrams | E5udp, E9b | markers + datagram hooks | per-send, `cgroup/sendmsg4` (E9b) | no | E9b | shared MCP server, DNS over UDP |
| Sec. VI-C, Table III: budgets | E10budget, E10conc | markers + send binding | per-send | connections, bytes | no | shared MCP server, keep-alive pool |
| Table IV (Sec. VI-D) | E12contain | markers + send binding | per-send | bytes (worker or runaway) | no | shared MCP server, keep-alive pool |
| Sec. VI-E: real agents | E7, E7m, E7c, E7o | markers via `_meta` | connection-level, per tenant | no | no | LLM operations agents (health checks) |
| Sec. VI-E: network-operations incident | E7net | markers via `_meta` | connection-level, per site | no | no | LLM operations agents (RESTCONF, telemetry, NETCONF) |
| Sec. VI-E: kernel-held credential | E6cred, E6reusecred, E6spoofcred, E11file, E3cred | kernel-held (`prctl`) vs. markers (E3cred) | connection-level; per-send (E6reusecred) | no | no | shared MCP server; file writes; connect benchmark |
| Sec. VI-E: kernel-held credential with budgets | E10conccred, E12containcred | kernel-held (`prctl`) + send binding | per-send | as E10conc, E12contain | no | as E10conc, E12contain |
| Sec. VI-E: collector and per-send cost | E3, E3net, E3send | markers off/on (E3); none (E3send) | none, connection, per-send, budget (E3send) | E3send only | no | microbenchmarks (loopback, vmxnet3) |
| Sec. VI-E: CPU at agent pace | E7rc | markers | connection-level | no | no | model-free replay of E7c/E7o runs |
| Sec. VI-E: integrated cost | E9costcred | kernel-held (`prctl`), session-derived identity, clearing, send binding, datagram hooks, trusted runtime | per-send | connections (limit not reached) | yes | as E9cost |
| Integrated cost with markers (earlier version) | E9cost | markers, session-derived identity, clearing, send binding, datagram hooks, trusted runtime | per-send | no | yes | shared MCP server: DNS, HTTP, subprocess per call |
| Sec. IV-E: live IPFIX | E8ipfix, E9all | markers (+ as in E9cost for E9all) | none (E8ipfix); connection-level (E9all) | no | yes | shared MCP server |

E10conccred, E12containcred, and E9costcred combine the kernel-held credential with budgets; E9all, E9b, and
E9cost predate both and use markers.

Every operation's expected policy decision follows the allow-list of the execution that owns it (exclusive
port), not its class: restricted executions issue both permitted and forbidden operations, and
`policy_matrix.csv` gives the outcomes per class with their denominators. In `reuse_matrix.csv`, each request of
E6reuse/E6reusecred is classified by the execution that opened its connection and the one that sent it; with
per-send authorization, none of the 864 forbidden requests reached the destination (411 were denied at the LSM
on connections a permissive execution had opened), and every permitted one did, whoever opened the connection.

In `campaign_validation.csv` and in the capture columns of `runs.csv`, `attempted` counts the planned connections
and `captured` those that reached `tcp_connect`. Under an egress policy, a connection denied at `cgroup/connect4`
or `cgroup/connect6` never reaches `tcp_connect`, so in E6, E6net, E7, E7c, E7m, E7o, and E7r `lost` is exactly
the number of denied connections (3680, 3670, 52, 312, 312, 312, and 1248: the TD + FD + ND of their policy
tables), not capture loss. Capture loss is measured where nothing is denied (E1, E2: none).

IPv6. The policy (`cgroup/connect6`, `cgroup/sendmsg6`, the LSM program and the accounting fexits, including
`udpv6_sendmsg`) and the collectors cover IPv6 and IPv4-mapped addresses since 2026-11-22, after the campaigns;
their IPv4 code paths are unchanged. Destinations are identified by port, over either family. The workloads,
benchmarks, factd and the tests take the family from `FACT_FAMILY` (4 by default, or 6; `workload/netfam.py`), so
`scripts/campaign.py --family 6` runs any experiment over IPv6 (campaign ids end in `-ipv6`; the second machine
and a remote model server are given with `--set dest_host=<IPv6 address>` and `--set ollama=[<address>]:11434`).
The paper's campaigns are IPv4.

Coverage matrix. `tests/coverage/run.sh` (root, BPF LSM) checks the send paths in four policy modes (per-send
authorization, connection-level only, kernel-held credential, budgets) toward IPv4, IPv6 and IPv4-mapped
destinations: execution B, which may not reach the destination, tries send, sendall, sendto, sendmsg, sendmmsg,
write, writev, sendfile, splice, MSG_ZEROCOPY, a duplicated descriptor, connected and unconnected UDP, new
connections, io_uring and a TCP send naming another port, on sockets execution A opened and on its own; the destination logs what arrives, and
the kernel's usage map what each identity was charged. On 2026-11-23, after the fixes below, every check passed in every mode and
family, and the outcomes, charges, budget counters, policy decisions and the events of all seven collectors
were the same across families (`analysis/output/coverage_test.json`). The matrix found one difference, now
fixed (commit e14922f): toward an IPv4-mapped destination, `udpv6_sendmsg` hands even a connected send to
`udp_sendmsg` with the destination filled in, so `cgroup/sendmsg4` decided again a send that is never re-decided
on an IPv4 socket; an fentry on `udpv6_sendmsg` records whether the application named a destination, and the
policy leaves the connected case to the per-send check, as on IPv4. A review of the code then found two
bypasses, now fixed and tested by the matrix; no experiment exercises them. In both families (commit 9db09f7),
an address passed with `sendto` or `sendmsg` on a TCP socket, which TCP ignores, was taken by the LSM program and by the byte charge as the
destination: naming an unpoliced port, execution B could send on a connection A had opened, and an execution could
send past its byte budget (`B_sendto_decoy_port`, `V_sendto_decoy_*`); the policy now reads a message's address for
datagrams only. Over IPv4 only (commit 3fb966a), `udp_sendmsg` takes a datagram's address of family AF_UNSPEC as an
AF_INET one (`udpv6_sendmsg` ignores it), and the charge did not, so such datagrams were not charged to the byte
budget (`W_sendto_unspec_*`, run over IPv4 only; the decision itself was right, since `cgroup/sendmsg4` sees the
address); the collectors now also read an IPv6 socket's datagram address by its family (commit e493781). With the
code before each fix, its checks fail (`analysis/output/ipv6/coverage_before_fix1.json`, `coverage_before_fix2.json`);
with all of them, every check passes. Re-run over both families, E3send, E5udp, E6reuse, E6reusecred, E9all,
E10budget, E10conc and E12containcred after the first fix, and E5udp and E9b after the others, attributed every
sent and received byte to its sender, as before; their other differences from the earlier runs are of the kinds
found between two IPv4 runs of the same code (connections opened by the keep-alive pools, the shared budget of
E12; `analysis/output/ipv6/regression_after_fixes.txt`). Sends that io_uring defers to its kernel
worker (`IOSQE_ASYNC`) carry no credential and fall to the default action (deny), even for A. As an IPv4
regression of this policy, E6, E6reuse and E6reusecred were re-run with `--n 1` and the paper's seed (28 runs; see
"Re-running the confirmatory campaigns"): every E6 resolver row of FACT's automatic binding and of the
deterministic cells matched the recorded runs (56 identical); the 8 others are the two cells with manual markers
and asynchronous tools, whose outcomes vary between boots. With per-send authorization, none of the 144
forbidden requests of E6reuse and of E6reusecred reached the destination, and every permitted one did.

Experiments over IPv6. `scripts/run_parity.sh` runs each experiment once per cell (`--n 1`, the paper's seed)
over IPv4 and over IPv6, and `analysis/compare_families.py` compares the two runs of each cell: every output
except times, latencies, rates, CPU, host ids and addresses. On 2026-11-22/23 this covered all 54 experiments
(504 pairs of runs), including the second machine (E3net, E5net, E6net, E7m) and the model APIs (E7c, E7o,
E7net), and 14 of them were run once more over IPv4 and over IPv6 (`analysis/compare_repeats.py` compares two
IPv4 runs; outputs in `analysis/output/ipv6/`). 349 pairs were identical. Every other difference has a cause shown in the data, and none is a
different decision or count by FACT for the same traffic:
- request size: HTTP clients put the destination in the Host header, `127.0.0.1:PORT` or `[::1]:PORT`, so each
  request is 4 bytes shorter over IPv6 (httpx 155 and 151 bytes, requests 158 and 154, aiohttp 139 and 135). In
  every such pair each request differs by exactly 4 bytes and each response has the same size, the collector's
  count equals the destination's in both families, and the IPv4 run reproduces the recorded campaigns (E5reuse,
  E6reuse, E6reusecred, E8ipfix, E10, E12; in E9costcred each execution's 25 httpx GETs take 4550 bytes over
  IPv4 and 4450 over IPv6; the 7 runaway uploads of E12contain, 28 bytes less). Byte budgets follow: with 10
  requests over a 1500-byte budget, E10budget overshoots by 50 bytes over IPv4 and 10 over IPv6;
- variable cells: values that already differ among the recorded IPv4 runs of the same cell, or between the two
  IPv4 runs of this comparison (asynchronous tools with manual markers in E4, E5 and E6, the Node runtime in
  E5node, E5native, partial sends in E5partial, connection reuse in the keep-alive pools: E5reuse c06 opened 8
  and 12 connections in two IPv4 runs, 8 and 10 in two IPv6 runs);
- performance: CPU cost, capacity, the BPF programs loaded on the host, and the number of IPFIX records (one per
  execution per export interval, so it follows the timing of the run);
- model output: the agents' final answers, model turns and token counts (E7, E7f, E7c, E7o, E7net), which
  the model sets from prompts that name the destination by its address (an IPv6 prompt is 33 tokens shorter
  per agent in E7c); the attribution and policy results of E7c match the recorded campaigns in both families;
- a shared byte budget (E12contain, E12containcred, process mode): which normal requests get in before the
  worker's budget runs out varies from run to run (the recorded IPv4 runs of E12containcred c03 completed 12, 14
  or 17 normal requests; two IPv4 runs of E12contain c03 here differ by one request of execution E07), and so does
  the per-execution split of admitted and denied requests. In one IPv6 run, per-send authorization let a
  request's 175-byte header through and denied its body when the budget ran out; FACT charged the 175 bytes the
  destination received (232588 = 232413 bytes of complete requests + 175), while the reference counts complete
  requests only, so that run is not "exact". An IPv4 run of another cell also left bytes outside complete
  requests at the destination (66049), and the IPv6 repetition of the cell was exact.

Also over IPv6: E6n (8 of 8 pairs identical), and the OBI association test (comparison only), whose counts
were the same as over IPv4 and as recorded (`analysis/output/obi_assoc.csv`).

AgentProvenance over IPv6. AgentProvenance v0.9.0 (comparison only) attaches to `sys_enter_connect` but records no
`network_connect` event for an IPv6 destination, in any mode: over IPv6 it attributes no connection (it still
records the process events of subprocesses). Its results in the paper are over IPv4.

In E7net, qwen2.5:3b wrote the host's other loopback address (127.0.1.1) in two calls of one run per boot. The
reference is keyed to the listen address (127.0.0.1), so `score.json` leaves these four connections out (356
scored); `analysis/e7net_summary.py` counts them separately (`conn_other_addr`), and their labels match the
owners of the ports. `analysis/e7net_other_addr.py` scores them with the same fused resolver against the same
port-owner reference (`E7net_other_addr.json`: 4 of 4 correct, none ambiguous, missing or wrong), so the paper
reports all 360 connections as correctly attributed.

## Re-running the confirmatory campaigns

Every confirmatory result in the paper comes from two boots of the same host. To repeat them:

```sh
sudo scripts/run_confirmatory.sh          # boot 1: all experiments with N set in workflow/config.yaml
sudo reboot
sudo scripts/run_confirmatory.sh          # boot 2: same command
nix --extra-experimental-features 'nix-command flakes' develop -c \
  snakemake --cores 1 validate report baselines faults figures   # regenerate every table and figure
```

To check a re-execution against the recorded results, run any experiment with the paper's seed and compare
run by run (cells with manual markers and asynchronous tools are nondeterministic: compare them with the recorded
range, which two boots do not bound):

```sh
python3 scripts/campaign.py --spec workflow/experiments/E5.json --n 1 --seed 51193 --label pilot --campaigns-dir /tmp/rerun
python3 -I analysis/collect_runs.py /tmp/rerun --out /tmp/rerun.csv
python3 -I scripts/compare_runs.py /tmp/rerun.csv analysis/runs.csv
```

`scripts/run_confirmatory.sh E6L E5f` runs only the listed experiments. The script builds the policy with the host
toolchain, runs the preflight, starts Ollama for E7/E7f, and writes a log per boot under `campaigns/logs/`.
N per experiment and the campaign seed are fixed in `workflow/config.yaml`; the comments there record how each N
was chosen.

## External dependencies of some experiments

FACT itself is self-contained: the collector, the attribution, the task-scoped binding and the egress
policy need only the measured host (Linux with eBPF/bpftrace) and this repository. Nothing below is required
to use FACT or to run E1-E7. The items below exist only for the comparison and variant experiments:

| Experiment | Needs | Role |
|---|---|---|
| E5ap, E1ap | AgentProvenance v0.9.0 on the measured host | **comparison only**: a related system run next to FACT on the same rounds, to measure its attribution against the same reference |
| E3net, E5net, E6net | second machine running `workload/remote_farm.py` | destinations outside loopback |
| E7m | second machine with Ollama and GPU | larger local models |
| E7net | Anthropic API key (as E7c) and local Ollama with qwen2.5:3b (as E7) | network-operations incident with commercial and local models |
| OBI test | OBI v1.0.0 binary on the measured host (`~/obi/obi`) | **comparison only**: association of outgoing requests to incoming ones in the shared MCP server |
| E7c | Anthropic API key in `/etc/fact/anthropic.key` (root, mode 600) | commercial models (Claude Opus 5.5, Haiku 5.5); cost and tokens are recorded per run |
| E7r | only the recorded E7c and E7o campaigns, extracted under `campaigns/` (no API key, no model) | model-free replay of every recorded E7c/E7o run: same tool calls, arguments, labels and relative timing |
| E7o | OpenAI API key in `/etc/fact/openai.key` (root, mode 600) | commercial models (gpt-6.1-sol, gpt-6-luna; Responses API, reasoning effort low); cost and tokens, including reasoning, are recorded per run |

Before the first run of any campaign (pilot or confirmatory), `scripts/campaign.py` calls
`scripts/check_deps.py`, which checks every external dependency the experiment uses (a real minimal call per
model, through the same code and tools as the agents; the remote ports; the AgentProvenance version). If any
check fails, the campaign is not created and the reason is printed; the result of the check is stored in the
campaign as `deps_check.txt`.

## Second machine (E3net, E5net, E6net, E7m), AgentProvenance (E5ap) and model APIs (E7c, E7o)

These experiments use a second VM on the same layer-2 segment (`172.28.255.13` in the specs under `workflow/experiments/`; change `dest_host`/`ollama` there for another address):

```sh
# on the second machine
python3 workload/remote_farm.py --addr 0.0.0.0            # destinations: ports 61000-61999 and 65000-65499
OLLAMA_HOST=0.0.0.0:11434 OLLAMA_NUM_PARALLEL=8 ollama serve   # Ollama v0.40.6 with GPU
ollama pull qwen2.5:7b && ollama pull llama3.1:8b          # digests 845dbda0ea48, 46e0c10c039e (Q4_K_M)
# on the measured host: AgentProvenance v0.9.0 release, extracted to /opt/agentprov
sha256sum agentprov_v0.9.0_linux_amd64.tar.gz   # 8963e25bfbad050de9aff2bf8eba8d77bb660c45697efc00436bf55020a124ae
sudo scripts/run_confirmatory.sh E5ap E5net E6net E3net E7m   # once per boot, two boots
# E7c: an Anthropic API key, readable only by root
sudo install -d -m 700 /etc/fact && sudo sh -c 'read -s K; printf %s "$K" > /etc/fact/anthropic.key; chmod 600 /etc/fact/anthropic.key'
sudo scripts/run_confirmatory.sh E7c                           # once per boot, two boots (about US$ 2.3 per boot)
# E7o: an OpenAI API key, stored the same way in /etc/fact/openai.key
sudo scripts/run_confirmatory.sh E7o                           # once per boot, two boots
# E7r: replay of E7c/E7o without any API (extract the recorded campaigns first)
scripts/extract_campaigns.sh campaigns ~/raw-data   # if they are only archived
sudo scripts/run_confirmatory.sh E7r                           # once per boot, two boots; no cost
```

## OBI association test (comparison only, no FACT)

OBI v1.0.0 attaches to the shared server (by its open port; by executable for the subprocess tool) with
context propagation on (`OTEL_EBPF_BPF_CONTEXT_PROPAGATION=all`). Each execution sends its own W3C trace
ID; each tool call makes one outgoing GET to a port owned by that execution, and the destination logs the
trace ID it receives. Reference: the destination port. 25 calls per execution, K = 4 and 8, three
repetitions, plus one control run without OBI per configuration.

```sh
# root, inside nix develop; OBI binary at $OBI_BIN (default ~/obi/obi)
scripts/run_obi_all.sh   /tmp/obi_runs    # direct and MCP-SSE servers, asynchronous tool
scripts/run_obi_tools.sh /tmp/obi_runs2   # MCP-SSE server, thread-pool and subprocess tools
python3 analysis/obi_summary.py           # -> analysis/output/obi_assoc.csv
```

## Regenerating the summarized CSVs

Older campaigns are archived as `.tar.gz`, some in `campaigns/` and the others in the authors' raw-data archive,
which is not part of this repository (see Data; `campaigns/<campaign_id>/checksums.sha256` holds the SHA-256 of every raw file).
To rebuild `analysis/runs.csv` and `analysis/overhead.csv` from all of them:

```sh
scripts/extract_campaigns.sh /tmp/all ~/raw-data
python3 -I analysis/collect_runs.py /tmp/all --out analysis/runs.csv --exclude-experiments E5f,E6f,E6n,E6L,E6Ls,E7f
python3 -I analysis/collect_overhead.py /tmp/all --out analysis/overhead.csv
```

On 2026-11-20, with the raw archives, this reproduced the versioned files (8492 and 224 rows): every count and
measurement is identical; only the factor columns `listen_addr` and `model`, added to `collect_runs.py` after
`runs.csv` was written, are filled in instead of empty. Campaigns recorded after that also appear in the
regenerated file; their results come from their own scripts (table above). On the same day every other summarized
result under `analysis/output/` (CSV, JSON, and TeX) was regenerated from the raw runs and was byte-identical,
except `structural_conflicts.csv`, which then also covered the archived runs (3910 runs instead of 3199); the
figures differed only in their creation date, and 360 runs drawn at random (8 per experiment) rescored with
`analysis/score.py` reproduced their `score.json`. The second boot of E2 (scaling to K = 64), run afterwards on
2026-11-21, added 480 rows to `runs.csv` (120 runs, no capture loss and no misattribution, as in the first boot),
and `structural_conflicts.csv` now counts 4030 runs.

On 2026-11-23 the whole check was repeated at commit `b43d327` from the 59 campaign archives. Every raw file matched
its checksum except the `events.jsonl` of 64 of the 85 failed runs (EADDRINUSE, see `docs/METHODOLOGY.md`) of the
pilot `hermes-E2-pilot-20261012T050414Z`, which no result uses; its 35 completed runs match. The 8972 rows of
`runs.csv` and the 224 of `overhead.csv` were reproduced exactly, and every other summarized result was
byte-identical except `policy_matrix.csv` and `policy_reach.csv`, which had been generated without the archived
E6 and E7 campaigns and now include them (rows added, none changed).

## Data

This repository contains everything needed to rerun the experiments and to check how each number in the paper was produced:
the code, the workflow, one directory per campaign under `campaigns/` (manifest, run order, environment snapshot, and
SHA-256 checksums of every raw file), the summarized results under `analysis/output/`, and the tables and figures generated from them
under `analysis/output/tex/` and `analysis/output/fig/`.

The raw per-run event logs (hundreds of MB) are not distributed. They can be regenerated with
`scripts/run_confirmatory.sh` (see above), and a regenerated campaign can be compared with the original one through its
manifest and checksums. The `git` field of each manifest refers to the private development repository in which the campaign ran
(see History). `scripts/package_data.py` remains available to package raw archives locally.

## License

Code: MIT (see `LICENSE`). Summarized results: CC BY 4.0. Citation metadata: `CITATION.cff`.

## History

Developed first in the authors' private development repository (last commit `de5c489`);
this repository starts from that state without the raw data.

The system was called *agentnet* during development and renamed FACT before submission. Campaigns recorded
before the rename name the collectors `agentnet.bt` and `agentnet-fast.bt` (in each run's `collector.txt` and in
the E2b capacity records); the analysis maps those names to the current `fact.bt` and `fact-fast.bt`, so the
recorded campaigns and new ones are analyzed together.

The figures can also be read as a notebook, with the code next to each plot:

```sh
Rscript -e 'rmarkdown::render("analysis/figures.R", knit_root_dir = getwd(), output_dir = "analysis/output")'
```
