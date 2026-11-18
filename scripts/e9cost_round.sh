#!/usr/bin/env bash
# One E9cost run: cost of the full recommended configuration under the E9 workload.
#   scripts/e9cost_round.sh <OUT_DIR> --fact off|all|credbudget --execs K [--ops 25] [--seed S]
# Workload in both: the shared MCP server (one process), K sessions, 25 calls each;
# every call sends a DNS query over UDP (dnspython), an HTTP GET (httpx), and a
# subprocess connect (workload/mcp_e4.py --tool mixed). Every call is permitted.
# - off: no FACT at all: no collector, no policy, no markers, no fact_rt
#        (--binding-mode none).
# - all: everything on, as in E9b: collector fact-all.bt, session-derived identity,
#        clearing, send binding, datagram hooks, trusted runtime, policy with
#        per-send authorization (BPF LSM), live factd exporting IPFIX; every execution
#        may reach all its destinations (--allow-all 1), so both configurations make
#        the same calls; attribution, policy, and IPFIX are scored as in E9b, and the
#        CPU of FACT's components is measured (COST=1, scripts/cost_probe.py).
# Both record the client-side latency of every call (e4_summary.json: p50/p90/p99)
# and the CPU time of the whole host during the workload only (host_cpu.json; for 'all',
# the interval of scripts/cost_probe.py, which excludes the scoring after the workload).
set -euo pipefail
OUT="$1"; shift
FACT=all; K=4; OPS=25; SEED=0
while [ $# -gt 0 ]; do
  case "$1" in
    --fact) FACT="$2"; shift 2;;
    --execs) K="$2"; shift 2;;
    --ops) OPS="$2"; shift 2;;
    --seed) SEED="$2"; shift 2;;
    *) echo "unknown argument $1"; exit 2;;
  esac
done
HERE="$(cd "$(dirname "$0")/.." && pwd)"
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
mkdir -p "$OUT"
cpu() { awk '/^cpu / {s=0; for (i=2; i<=NF; i++) if (i!=5 && i!=6) s+=$i; print s}' /proc/stat; }
C0=$(cpu); T0=$(date +%s.%N)
case "$FACT" in
  off)
    "${FACT_PYTHON:-python3}" -I "$HERE/workload/mcp_e4.py" --cond E9cost --out "$OUT" --tool mixed \
        --binding-mode none --execs "$K" --ops "$OPS" --seed "$SEED" > "$OUT/workload.log" 2>&1
    ;;
  all)
    COLLECTOR=fact-all.bt WORKLOAD=workload/mcp_e4.py POLICY=1 POLICY_NOCTX_ALLOW=0 POLICY_PER_SEND=1 \
    IPFIX=1 COST=1 "$HERE/run_round.sh" E9cost "$OUT" --seed "$SEED" --tool mixed --binding-mode auto \
        --execs "$K" --ops "$OPS" --identity session --clear-after 1 --send-binding 1 --trust 1 \
        --allow-all 1 > "$OUT/round.log" 2>&1
    ;;
  credbudget)   # E9costcred: as 'all', with the execution credential (prctl) and per-execution budgets
    COLLECTOR=fact-cred.bt WORKLOAD=workload/mcp_e4.py POLICY=1 POLICY_NOCTX_ALLOW=0 POLICY_PER_SEND=1 \
    POLICY_BUDGET=1 POLICY_BUDGET_PLAN=1 POLICY_CRED=1 FACT_IFACE=prctl \
    IPFIX=1 COST=1 "$HERE/run_round.sh" E9cost "$OUT" --seed "$SEED" --tool mixed --binding-mode auto \
        --execs "$K" --ops "$OPS" --identity session --clear-after 1 --send-binding 1 --trust 1 \
        --allow-all 1 --budget-conns 100000 > "$OUT/round.log" 2>&1
    ;;
  *) echo "unknown --fact $FACT"; exit 2;;
esac
C1=$(cpu); T1=$(date +%s.%N)
python3 -I - "$OUT" "$C0" "$C1" "$T0" "$T1" "$(getconf CLK_TCK)" "$FACT" <<'EOF'
import json, os, sys
out, c0, c1, t0, t1, hz, fact = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4]), float(sys.argv[5]), int(sys.argv[6]), sys.argv[7]
s = json.load(open(os.path.join(out, "e4_summary.json")))
res = {"fact": fact, "host_cpu_s": (c1 - c0) / hz, "wall_s": t1 - t0, "calls": s["calls"], "ok": s["ok"]}
cp = os.path.join(out, "cost.json")
if os.path.exists(cp):   # 'all': only the workload interval (cost_probe), not the scoring after it
    c = json.load(open(cp))
    res["host_cpu_round_s"], res["wall_round_s"] = res["host_cpu_s"], res["wall_s"]
    res["host_cpu_s"], res["wall_s"] = c["host_cpu_s"], c["wall_s"]
json.dump(res, open(os.path.join(out, "host_cpu.json"), "w"), indent=1)
print(json.dumps({**res, **{k: s[k] for k in ("tool_ms_p50", "tool_ms_p90", "tool_ms_p99")}}))
if s["ok"] != s["calls"]:
    sys.exit(f"{s['calls'] - s['ok']} calls failed")
EOF
