# Scientific methodology: FACT / NOMS 2027

This document ties **each methodological decision to a verified reference** (list in Section 9). It covers the framework (automatic runtime binding, per-execution policy, live daemon, LLM agents) and every experiment reported in the paper.

## 0. Status and rules for using the data

| Stage | Allowed use |
|---|---|
| Smoke tests and pilots | Validate the pipeline and estimate variability. **They are never results** and never enter the paper as evidence. |
| `confirmatory` campaigns | **The only source of the paper's numbers.** They require a clean commit, a preflight PASS, and no failed run. A campaign with any failure is preserved as a record but excluded from the tables. |

Smoke and pilot numbers quoted in internal documents are always labeled as such.

## 1. Scientific question and contribution

**Question:** can each network connection be attributed to the agent execution that opened it, including inside a shared worker with asynchronous tools, with explicit reporting when attribution is not possible, and can that identity be used for management (accounting and policy) at an acceptable cost?

**Contribution (framework):**
1. kernel signals (lineage, cgroup) and a runtime-emitted identity, fused with explicit ambiguity;
2. automatic binding of the identity to the **task** (contextvars), handed to the kernel at `connect`/fork, without changing tool code;
3. live per-execution accounting (factd), with the correct, wrongly credited, and uncredited parts;
4. a per-execution egress policy (cgroup/connect4) with the same identity;
5. validation of everything against an independent reference.

| RQ | Operational hypothesis |
|---|---|
| RQ1 signal sufficiency | By construction, cgroup is ambiguous in N1–N3 and lineage in N2–N3. We measure whether the system **reports** A instead of I, and the capture loss. |
| RQ2 fusion under a wrong context | H2a: in N0/N1, I(fused)=0 for any mislabel fraction p. H2b: in N2/N3, I(fused)=I(context). |
| RQ3 accounting | The net error underestimates the attribution error; the decomposition exposes it. |
| RQ4 cost and scale | Per-connection cost (E3/E3b), with no loss up to the measured limit (E2). |
| RQ5 framework | H5a: with automatic binding, I=0 also for async tools (E5). H5b: policy decisions follow the correct identity (E6). H5c: the system works with real LLM agents (E7). |

## 2. Technique, object, and scope

- **Technique:** measurement of a real system under a controlled workload [Jain 1991, ch. 3: measurement is the indicated technique when the system exists and the question involves the real behavior of the kernel]. Simulation is used only as a unit test (`tests/test_agentctx_sim.py`), never as a result.
- **Object:** IPv4 `tcp_connect` events and `connect` decisions (cgroup/connect4).
- **Attribution unit:** synthetic execution (E1–E3), MCP session (E4–E6), or LLM agent execution (E7).
- **Out of scope:** bytes per flow, IPv6, UDP, runtimes other than Python (the mechanism is general, but the implementation is Python).

## 3. Experimental design

### 3.1 Experiments

| Exp. | RQ | Factors (levels) | Fixed |
|---|---|---|---|
| E1 correctness | 1–3 | S ∈ {N0..N3} × p ∈ {0, 0.05, 0.2} × mode ∈ {inproc, subproc} | K=2, 100 ops/execution |
| E2 scale | 4 | S ∈ {N1, N3} × K ∈ {2..64} × rate ∈ {paced, max} | p=0 |
| E3 overhead | 4 | instrumentation ∈ {none, collector} × markers ∈ {no, yes} | 20,000 connects/run |
| E3b ablation | 4 | collector ∈ {none, probes only, full, optimized} × markers | same |
| E1fast | 4 | = E1, with the optimized collector | equivalence |
| E4 real runtime | 1 | tool ∈ {sync, thread, subproc, async} × K ∈ {2,4} | manual markers |
| **E5 framework** | 5 | binding ∈ {manual, automatic} × tool × K ∈ {2,4,8} | real MCP server |
| **E6 policy** | 5 | binding × tool × K ∈ {2,8} | alternating P/R classes |
| **E7 LLM agent** | 5 | K=4 agents (Ollama, temperature 0) | automatic binding + policy |
| E5net | 5 | = E5 (binding × tool × K ∈ {2,4,8}) | services on the second machine (network interface) |
| E6net | 5 | = E6 (binding × tool × K ∈ {2,8}) | same |
| E3net | 4 | = E3 (instrumentation × markers) | acceptor on the second machine; 20,000 connects/run |
| E5ap | 5 | tool × K ∈ {2,4,8} | automatic binding; AgentProvenance v0.9.0 run in the same run |
| E7m | 5 | model ∈ {qwen2.5:7b, llama3.1:8b} × K ∈ {4,8} | Ollama on a GPU in the second machine; automatic binding + policy; num_predict=512 |
| E7c | 5 | model ∈ {claude-opus-5-5, claude-haiku-5-5} × K ∈ {4,8} | Anthropic API; automatic binding + policy; max_tokens=512; tokens and cost recorded |
| E7o | 5 | model ∈ {gpt-6.1-sol, gpt-6-luna} × K ∈ {4,8} | OpenAI Responses API; reasoning effort low; automatic binding + policy; tokens (including reasoning) and cost recorded |
| E7r | 5 | model (the 4 of E7c/E7o) × K ∈ {4,8} × recording ∈ {boot 1, boot 2} | model-free replay of the recorded runs; automatic binding + policy |
| E1ap | 5 | S ∈ {N0, N1, N3} × mode ∈ {inproc, subproc} | K=4, 100 ops/execution; AgentProvenance v0.9.0 with each execution's own process and cgroup in its bindings |
| E5lib | 5 | client ∈ {httpx, aiohttp, requests, urllib, curl, MCP fetch server's `fetch_url`} × K ∈ {4,8} | automatic binding; tools only call unmodified third-party code; HTTP destinations |
| E5node | 5 | tool ∈ {timer then `net.connect`, spawn `node -e connect`, `node:http` GET} × binding ∈ {manual, automatic} × K ∈ {4,8} | second runtime: one Node.js process (official TypeScript SDK 1.32.1, one JavaScript thread) serves all sessions; automatic binding by `fact_rt_node` (AsyncLocalStorage; marker at the libuv `connect` and at `spawn`) |
| E5reuse | 5 | client ∈ {httpx fresh (control), httpx shared, aiohttp shared, requests shared} × send binding ∈ {off, on} × K ∈ {4,8} | keep-alive pool shared by the sessions; collector `fact-bytes.bt`; per-request byte reference at the destination |
| E6spoof | 5 | trusted-runtime mode ∈ {off, on} × K ∈ {2,4,8} | E6 classes; every call of a restricted execution runs a tool whose child claims a permissive identity |
| E7rc | 4 | model (the 4 of E7c/E7o) × K ∈ {4,8} × recording | E7r replays with CPU accounting (`COST=1`: process CPU, `bpf_stats`, factd replay) |

E1, E5, and E6 are full factorials, which allows estimating effects and interactions without confounding [Montgomery 2017, chs. 5–6; Jain 1991, part IV].

### 3.2 Design principles

- **Paired comparison.** The four resolvers are applied offline to the same log of each run, so differences between resolvers do not come from different executions (blocking at the run level [Montgomery 2017, ch. 4]).
- **Independent reference.** Each operation receives an exclusive destination port, drawn before the run. The resolvers receive only `ts, pid, tid, cgroup, ctx`, and an AST check blocks reference fields. This is a **test oracle independent of the implementation** [Barr et al. 2015]: the verdict uses no information that the evaluated system could have corrupted. For the policy (E6/E7), the expected verdict is derived from the port (owner) and the owner's allow-list.
- **Controlled fault injection.** Mislabels in an exact number (p × ops per execution, random positions) follow the fault-injection methodology for validating fault-tolerance mechanisms [Arlat et al. 1990; Hsueh, Tsai & Iyer 1997]: defined faults (type, location, time), controlled activation, and observation of the effect. With an exact count, injection adds no sampling variance.
- **Randomized run order** (recorded seed). Measurement bias can arise from seemingly irrelevant configuration factors [Mytkowicz et al. 2009]. Drawing the order prevents the condition from being confounded with temporal position, warm-up, or drift.
- **Common random numbers** across conditions (same seed per repetition), stated in the paper; this reduces the variance of comparisons between conditions [Jain 1991].
- **Several boots as blocks.** The system state after boot is a level of variation of its own, and only repeating over several boots captures it [Kalibera & Jones 2013; Georges et al. 2007].

### 3.3 Unit of repetition and N: criterion per experiment

**Unit:** the complete run, with a fresh collector, new cgroups, and new services. Events within a run are dependent, and counting them as replicates would be pseudo-replication [Georges et al. 2007, who use the VM invocation as the unit]. Runs within one boot are replicates within a block [Kalibera & Jones 2013].

| Type of result | Experiments | N criterion |
|---|---|---|
| **Property (zero errors expected)** | E1, E5 (automatic), E6 (automatic), E7 | Exact Clopper-Pearson upper bound on the error rate [Clopper & Pearson 1934]. With 0 errors in n cases, the one-sided 95% bound is 1−0.05^(1/n) ≈ 3/n (the "rule of three" [Hanley & Lippman-Hand 1983]). **Target: ≤ 1% ⇒ n ≥ 299 cases per cell.** Cases are connections or decisions. Since events within a run are not independent, the bound is interpreted per connection and accompanied by the run-by-run check that no run had an error. |
| **Performance (continuous variable)** | E3, E3b | Variance measured in the pilot per level (boot, run), and N per level chosen by the method of Kalibera & Jones 2013. The target is a 95% CI half-width of the median ≤ 5% [Hoefler & Belli 2015, rule 5]. **At least 2 boots.** |
| **Capacity** | E2 | Sweep of K and rate up to the first loss. N per cell from the variability of the loss in the pilot [Hoefler & Belli 2015]. |
| **Equivalence** | E1fast; factd vs. offline | Exact equality cell by cell or run by run. A single divergence refutes it. |

Application: in E5 and E6, the smallest cell (K=2, 25 ops) has 50 cases per run, hence 299/50 ⇒ **6 runs per cell (3 per boot, 2 boots)**. Cells with larger K have more cases and the same N. In E7, N follows the same criterion, applied to the number of decisions per run observed in the pilot.

**Additional experiments**, each with the criterion of its original experiment:

- **E5net, E6net:** same levels and N as E5 and E6 (6 runs per cell; K=2 gives 300 cases ≥ 299). The levels are the same so that the loopback vs. network-interface comparison is cell by cell.
- **E5ap:** the same cells as E5 in automatic mode, 6 runs. For FACT the property criterion applies (≥ 299 connections per cell). For AgentProvenance, whose error rate is not zero, the goal is to estimate the proportion: with ≥ 300 connections per cell, the 95% CI half-width of a proportion is ≤ 1.96·√(0.25/300) ≈ 5.7 percentage points in the worst case (p = 0.5) [Jain 1991, ch. 13]; the paper's conclusions (92–96% error with K ≥ 4) are far from that limit.
- **E3net:** same levels and N as E3 (5 runs per boot, 2 boots), sized from the E3 pilot for a 95% CI half-width of the median ≤ 5%. A posteriori check: the obtained half-widths were 1.9–3.6% of the mean in the four cells, below the target.
- **E7c:** same design and N as E7m (26 runs per cell over two boots; 312 decisions with K=4). The two models are a high-end one (Opus 5.5) and the entry-level one (Haiku 5.5) of Anthropic's current tool-calling line; Fable 5.1, above Opus, was left out for cost; the cost measured in the pilot (≈ US$ 4.80 for the whole campaign) was the criterion for not including a third model.
- **E7o:** same design and N as E7c, with a high-end model (gpt-6.1-sol) and the entry-level one (gpt-6-luna) of OpenAI's current tool-calling line. gpt-6-astra was left out for cost (≈ US$ 11 estimated for the campaign). Reasoning effort `low`: the lowest level accepted by both models (gpt-6.1-sol rejects `none` and `minimal`; tested on 2026-10-18).
- **E7r:** each of the 208 recorded E7c and E7o runs is repeated once in each boot (13 runs per cell and boot × 16 cells), without calling a model. The criterion is equality: the replayed calls and the outcome (attribution and policy decisions) must be identical to the recording. Reason: the commercial models have no dated version in the APIs (checked on 2026-10-18: only `claude-opus-5-5`, `claude-haiku-5-5`, `gpt-6.1-sol`, `gpt-6-luna`), so they may change; the recording allows reproducing the measurement without them.
- **Pre-submission experiments (2026-10-20), each with the criterion of the experiment it extends:**
  - **E1ap:** 6 runs per cell (3 per boot), 400 connections per run, hence 2400 per cell; the 95% CI half-width of AgentProvenance's error rate is ≤ 2 points.
  - **E5lib:** 6 runs per cell, as E5 (K=4 gives 100 connections per run, 600 ≥ 299 per cell).
  - **E5node:** 6 runs per cell, same criterion as E5lib.
  - **E5reuse:** 6 runs per cell; the criterion is applied to bytes, with a per-request reference logged by the destination (byte ranges of each request and response on each connection). Connections are matched by (client source port, epoch), because the kernel can give a closed connection's port to a later one (the first scoring keyed by port only and merged such connections; the campaigns are rescored from the raw events by `analysis/presub_tables.py`).
  - **E6spoof:** 6 runs per cell, as E6 (K=2 gives 50 decisions per run).
  - **E7rc:** one replay of each recorded E7c/E7o run per boot (16 runs per boot); reported as medians and maxima.
  - **Send-binding cost** (`bench/send_bind_round.sh`): 10 repetitions per mode (off, same identity, rebind, alternating identity) and collector (none, `fact.bt`, `fact-bytes.bt`), 5 batches of 20,000 sends of 256 bytes each; median ns per send. A first execution overlapped with a manual test and was discarded.
- **E7m:** the same criterion as E7, applied to the policy decisions: with K=4 there are 12 decisions per run (pilot), hence 26 runs = 312 ≥ 299; with K=8, 624. The attributed connections per cell vary with the model (260–912), because the model decides how many tools to call; the criterion is applied to decisions, as in E7. K=4 repeats E7; K=8 is the largest K of E5 and the parallelism configured in Ollama (`OLLAMA_NUM_PARALLEL=8`). The two models are the tool-calling models of up to 8B parameters that fit in the 12 GB GPU (Q4_K_M quantization).

### 3.4 Metrics

- C/N, A/N, M/N, I/N, C/(C+I), and A_in per resolver; capture (attempted, captured, lost, duplicated, excluded without reference), always reported.
- **Accounting:** correct, wrongly credited, uncredited. The net error is never reported alone.
- **Policy:** TA, TD, FA (wrongly allowed: a security risk), FD (wrongly denied: a loss of availability), ND (no decision).
- **Performance:** median and p99 `connect` latency, throughput, ns per BPF program run (bpf_stats), and CPU of the collector process; tool-call latency (E4–E7).
- **Agent (E7):** tool calls, off-plan ports (hallucination), LLM time, task completion.

### 3.5 Analysis plan (pre-registered)

1. **Validation:** failed runs invalidate the campaign. Capture is always reported.
2. **Properties:** total counts with the Clopper-Pearson bound; I=0 is tested as a property, without a significance test, because the outcome is deterministic given the plan [Jain 1991, ch. 2, "common mistakes"].
3. **Performance:** median per run, then the mean of the medians with a 95% CI over runs, with the boot as a block. Bootstrap per run as a check [Le Boudec 2010, ch. 2]. Effect size reported in µs and in %, never significance alone [Hoefler & Belli 2015].
4. Tables and figures generated by script (R) from the immutable campaigns; no number typed by hand. `results_meta.tex` records the provenance.

## 4. Controls and environment

- **Controlled:** workload, seeds, levels, order, state reset per run, absence of other campaigns (preflight).
- **Recorded per campaign:** kernel, bpftrace, bpftool, Python, R, BTF, CPU, memory, virtualization (VMware), loadavg, NTP, commit, and flake.lock [Bajpai et al. 2019; Collberg & Proebsting 2016].
- **Limitation:** a VM with 8 vCPUs, without frequency control. This is stated; the several boots partly mitigate it.

## 5. Reproducibility

- **Second machine (E3net, E5net, E6net, E7m):** a VM on the same physical host and L2 segment. Destination services: `workload/remote_farm.py --addr 0.0.0.0` (ports 61000–61999 and 65000–65499). Models: Ollama v0.40.6 on a GPU (RTX 3060, 12 GB), `OLLAMA_HOST=0.0.0.0:11434`, `OLLAMA_NUM_PARALLEL=8`; qwen2.5:7b (digest 845dbda0ea48ed74) and llama3.1:8b (46e0c10c039e0191), both Q4_K_M. The destination IP is in the specs (`dest_host`, `ollama`).
- **Independence of FACT:** the collector, attribution, task-scoped binding, and policy depend only on the measured host and on this repository. AgentProvenance is used **only in the comparative experiment E5ap**; the second machine and the commercial APIs, only in the variants (E3net, E5net, E6net, E7m, E7c, E7o).
- **Dependency check:** before the first run of any campaign, `scripts/campaign.py` calls `scripts/check_deps.py`, which tests every external dependency of the experiment (a real, minimal call to each model with the same code and tools as the agents; the second machine's ports; the AgentProvenance version; the recorded campaigns for E7r). If anything fails, the campaign is not created; the result is stored in `deps_check.txt` in the campaign. Reason: the first E7c pilot failed entirely because the API rejected the `temperature` parameter for these models (incident 10).
- **Anthropic API (E7c):** key in `/etc/fact/anthropic.key` (root, mode 600, outside the repository). No `temperature` parameter (rejected by the API for these models), no extended thinking, `max_tokens` 512. The input and output tokens reported by the API are recorded per agent; cost per cell in `analysis/output/E7c_tokens.csv` (prices of 2026-10-18).
- **OpenAI API (E7o):** key in `/etc/fact/openai.key` (root, mode 600). Responses API (tool calling for these models is served only there), `store=false`, encrypted reasoning sent back in the next step, `max_output_tokens` 4096 (includes reasoning), no `temperature`. Cost per cell in `analysis/output/E7o_tokens.csv`.
- **Model-free replay (E7r) and transcripts:** the agents' behavior in each run is recorded in `ops.jsonl` (tool, arguments, label, and timestamps of each call) and, for model runs made from the E7r commit on, the full conversation with the model in `transcript.jsonl`. The `--replay-from` mode of `agent_e7.py` repeats a recorded run without a model: the same seed generates the same port plan, and the recorded plan is checked before the run.
- **AgentProvenance (E5ap, comparison only):** release v0.9.0 (commit fb83e641), `agentprov_v0.9.0_linux_amd64.tar.gz` with SHA-256 8963e25bfbad050de9aff2bf8eba8d77bb660c45697efc00436bf55020a124ae, extracted into `/opt/agentprov` (path in the specs).
- **Versioned CSVs:** several older campaigns exist only as `.tar.gz`. To regenerate `analysis/runs.csv` and `analysis/overhead.csv` from scratch, extract the archives first (`scripts/extract_campaigns.sh`) and run `collect_runs.py`/`collect_overhead.py` on the resulting directory.
- **Rename.** The system was called agentnet during development and renamed FACT before submission. Campaigns recorded before the rename name the collectors `agentnet.bt`/`agentnet-fast.bt`; the analysis maps them to `fact.bt`/`fact-fast.bt`. After the rename, the experiments were re-run with the paper's seed and compared run by run with the recorded campaigns (`scripts/compare_runs.py`).
- **Two layers. The Nix flake pins Python, R, Snakemake, Jupyter, and Ollama. Kernel, bpftrace, clang, and libbpf come from the host and are recorded.
- **Snakemake:** preflight → pilot → size → campaign → validate → report.
- **Each campaign is immutable:** manifest.json, run_order, environment/, SHA-256 checksums, and .tar.gz.
- **Public artifact** (code, data, and scripts), following the recommendations for experimental networking research [Bajpai et al. 2019].

## 6. Threats to validity (categories of Wohlin et al. 2012)

- **Internal:**
  - capture loss under load (measured in E2);
  - reuse of `sk` or of a PID;
  - residual state between runs (mitigated by a fresh collector and new cgroups);
  - interference between the bpftrace collector and the policy program, which coexist in E6/E7.
- **Construct:**
  - "connection" means a `connect` attempt; bytes are attributed only in E5reuse, and only for HTTP/1.1 keep-alive (protocols that multiplex several sessions' requests on one connection, such as HTTP/2, are not evaluated);
  - a synthetic execution is not a real task (mitigated in E4–E7 with a real MCP server and LLM agents);
  - in E7, the model's behavior is part of the workload, not a controlled variable.
- **External:**
  - one host and one kernel; one MCP SDK version per runtime (Python mcp, TypeScript @modelcontextprotocol/sdk 1.32.1);
  - open models of up to 8B parameters and four commercial models from two providers;
  - binding implemented for two runtimes (Python asyncio and Node.js);
  - the trusted-runtime mode (E6spoof) stops a tool's child process from claiming another identity, not code running inside the runtime process;
  - E5node hooks Node's internal libuv binding (`tcp_wrap`), not a public API: the hook may need updating across Node major versions, and connections opened by native addons or worker threads that do not load `fact_rt_node` are outside it;
  - E5lib runs the official MCP fetch server's `fetch_url` inside the shared server, not that server as a whole;
  - IPv4 only; the second machine is reached through a virtual switch.
- **Conclusion:**
  - dependence among events of a run (handled with the run as the unit);
  - common random numbers, stated;
  - Clopper-Pearson bounds computed per connection under dependence, and therefore interpreted together with the run-by-run check.

## 7. Recorded engineering incidents

1. **Ports in the ephemeral range** (EADDRINUSE in the E2 pilot). Fixed with ports above 61000 and a check of `ip_local_port_range`.
2. **`e3_round.sh` without the execute bit.** Fixed in commit 43c69de.
3. **Orphan bpftrace after a failed run.** It inflated the latency of an E4 pilot. Fixed with an EXIT trap in commit 6a27d3d.
4. **The trap propagated the `kill` failure under `set -e`** and invalidated E1fast 165110Z. Fixed in commit 0609da0; the campaign was kept and excluded from the tables.
5. **E6net, pilot:** the reachability check of the remote destination used planned ports, which the policy (without identity) denies; the pilot failed in every run. Fixed in commit 5df053c (the check uses port 65000, outside the policed range).
6. **Reboot during a confirmatory campaign (2026-10-18, ~12:40 UTC):** campaign E5ap 122406Z was left without a manifest and is ignored by the analysis. The confirmatory campaign was redone from the start in the next boot.
7. **E7m, boot 1:** 4 runs with llama3.1:8b failed because a model answer did not end and the call to Ollama hit 600 s. The campaign (131239Z, no manifest) was discarded; fixed with `num_predict=512` (commit 6e0a24f), recorded in each run's plan.
8. **E7m, boot 2:** opening an agent's MCP session hung with no error and no client timeout, before the model's first step. The campaign (152437Z) was discarded; fixed with a 60 s deadline and up to 3 attempts only before the first step (commit 40ca786).
9. **Probe connections in E5net:** before each run, the driver checks whether the remote destination answers, connecting to the first and last planned ports. These 2 connections per run (144 in total) have no identity and appear as unattributed (M) for the fused resolver; they are not errors (I = 0).
10. **E7c, first pilot (203816Z):** the 4 runs failed because the Anthropic API rejects the `temperature` parameter for Opus 5.5 and Haiku 5.5. Fixed in commit 2c98973 (parameter removed); the next pilot (204028Z) passed. So that no campaign starts with a broken dependency, `scripts/check_deps.py` now runs before every campaign (models, second machine, AgentProvenance), and `run_confirmatory.sh` propagates campaign failures (`pipefail`).
11. **E5reuse, first scoring:** connections were keyed by the client source port only; a port reused by a later connection merged two connections and produced false errors (up to 1.5% of the bytes in the control). Fixed in commit 54fc45e (key: source port and epoch); the campaigns were rescored from the raw events, unchanged.

## 8. Methodological references

- J. Arlat et al. Fault injection for dependability validation: a methodology and some applications. *IEEE TSE* 16(2), 1990.
- V. Bajpai et al. The Dagstuhl beginners guide to reproducibility for experimental networking research. *ACM SIGCOMM CCR* 49(1), 2019.
- E. T. Barr, M. Harman, P. McMinn, M. Shahbaz, S. Yoo. The oracle problem in software testing: a survey. *IEEE TSE* 41(5), 2015.
- C. J. Clopper, E. S. Pearson. The use of confidence or fiducial limits illustrated in the case of the binomial. *Biometrika* 26(4), 1934.
- C. Collberg, T. A. Proebsting. Repeatability in computer systems research. *CACM* 59(3), 2016.
- A. Georges, D. Buytaert, L. Eeckhout. Statistically rigorous Java performance evaluation. *OOPSLA* 2007.
- J. A. Hanley, A. Lippman-Hand. If nothing goes wrong, is everything all right? Interpreting zero numerators. *JAMA* 249(13), 1983.
- T. Hoefler, R. Belli. Scientific benchmarking of parallel computing systems: twelve ways to tell the masses when reporting performance results. *SC* 2015.
- M.-C. Hsueh, T. K. Tsai, R. K. Iyer. Fault injection techniques and tools. *IEEE Computer* 30(4), 1997.
- R. Jain. *The Art of Computer Systems Performance Analysis.* Wiley, 1991.
- T. Kalibera, R. Jones. Rigorous benchmarking in reasonable time. *ISMM* 2013.
- J.-Y. Le Boudec. *Performance Evaluation of Computer and Communication Systems.* EPFL Press, 2010.
- D. C. Montgomery. *Design and Analysis of Experiments*, 9th ed. Wiley, 2017.
- T. Mytkowicz, A. Diwan, M. Hauswirth, P. F. Sweeney. Producing wrong data without doing anything obviously wrong! *ASPLOS* 2009.
- C. Wohlin et al. *Experimentation in Software Engineering.* Springer, 2012.
