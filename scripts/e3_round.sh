#!/usr/bin/env bash
# One E3 run (overhead). Usage:
#   scripts/e3_round.sh <OUT_DIR> --instr none|collector|count|fast --markers 0|1 [--n 20000] [--warmup 1000] [--seed S]
# - instr=none: the microbenchmark only.
# - instr=collector (= fact.bt, full), count (fact-count.bt, probes without
#   exporting events), or fast (fact-fast.bt, optimized): collector active (waits for the
#   ready sentinel) with bpf_stats enabled, to measure the CPU time of the BPF programs (run_time_ns).
# Outputs: overhead.json (summary), latencies.csv, bpf_prog_stats.json, collector.err.
set -euo pipefail
OUT="$1"; shift
INSTR=none; MARKERS=0; N=20000; WARMUP=1000; SEED=0; HOST=""
while [ $# -gt 0 ]; do
  case "$1" in
    --instr) INSTR="$2"; shift 2;;
    --markers) MARKERS="$2"; shift 2;;
    --n) N="$2"; shift 2;;
    --warmup) WARMUP="$2"; shift 2;;
    --seed) SEED="$2"; shift 2;;
    --host) HOST="$2"; shift 2;;
    *) echo "unknown argument $1"; exit 2;;
  esac
done
HERE="$(cd "$(dirname "$0")/.." && pwd)"
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
mkdir -p "$OUT"
BIN="$HERE/bench/connect_bench"
[ -x "$BIN" ] && [ "$BIN" -nt "$HERE/bench/connect_bench.c" ] || gcc -O2 -Wall -o "$BIN" "$HERE/bench/connect_bench.c"
PORT=$(( 65000 + SEED % 500 ))   # outside the default ephemeral range (32768-60999)
cat /proc/loadavg > "$OUT/loadavg-start.txt"
cat /proc/sys/net/ipv4/ip_local_port_range > "$OUT/ip_local_port_range.txt"

BPID=""
case "$INSTR" in
  none) BT="";;
  collector) BT="$HERE/collector/fact.bt";;
  count) BT="$HERE/collector/fact-count.bt";;
  fast) BT="$HERE/collector/fact-fast.bt";;
  *) echo "unknown instr: $INSTR"; exit 2;;
esac
if [ -n "$BT" ]; then
  sysctl -q -w kernel.bpf_stats_enabled=1
  bpftrace -B line "$BT" > "$OUT/events.jsonl" 2> "$OUT/collector.err" &
  BPID=$!
  trap 'kill -INT "$BPID" 2>/dev/null || true; wait "$BPID" 2>/dev/null || true' EXIT   # never leaves an orphan collector
  for i in $(seq 1 300); do
    grep -q '"ev":"ready"' "$OUT/events.jsonl" 2>/dev/null && break
    kill -0 "$BPID" 2>/dev/null || { cat "$OUT/collector.err"; exit 1; }
    sleep 0.1
  done
  grep -q '"ev":"ready"' "$OUT/events.jsonl" || { kill "$BPID"; echo "no ready sentinel"; exit 1; }
  bpftool prog show --json > "$OUT/bpf_prog_before.json"
fi

CPU0=$(awk '{print $14+$15}' /proc/$BPID/stat 2>/dev/null || echo 0)
if [ "${FACT_FAMILY:-4}" = 6 ]; then LOOP="::1"; else LOOP="127.0.0.1"; fi   # connect_bench follows FACT_FAMILY
echo "${HOST:-$LOOP}" > "$OUT/dest_host.txt"
"$BIN" --n "$N" --warmup "$WARMUP" --port "$PORT" --markers "$MARKERS" --out "$OUT/latencies.csv" ${HOST:+--host "$HOST"} > "$OUT/bench.json"

if [ -n "$BPID" ]; then
  bpftool prog show --json > "$OUT/bpf_prog_after.json"
  CPU1=$(awk '{print $14+$15}' /proc/$BPID/stat)
  echo "$(( CPU1 - CPU0 ))" > "$OUT/collector_cpu_ticks.txt"
  kill -INT "$BPID"; wait "$BPID" || true
  sysctl -q -w kernel.bpf_stats_enabled=0
fi
cat /proc/loadavg > "$OUT/loadavg-end.txt"

python3 -I - "$OUT" "$INSTR" "$MARKERS" "$(getconf CLK_TCK)" <<'EOF'
import json, os, sys
out, instr, markers, hz = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
b = json.load(open(os.path.join(out, "bench.json")))
res = {"instr": instr, "markers": markers, **b}
pa, pd = os.path.join(out, "bpf_prog_before.json"), os.path.join(out, "bpf_prog_after.json")
if os.path.exists(pa) and os.path.exists(pd):
    before = {p["id"]: p for p in json.load(open(pa))}
    progs = []
    # the collector was already active at 'before': the cost is the delta between the two instants
    for p in json.load(open(pd)):
        if p["id"] in before:
            d_ns = p.get("run_time_ns", 0) - before[p["id"]].get("run_time_ns", 0)
            d_cnt = p.get("run_cnt", 0) - before[p["id"]].get("run_cnt", 0)
            if d_cnt > 0:
                progs.append({"id": p["id"], "name": p.get("name"), "type": p.get("type"),
                              "delta_run_cnt": d_cnt, "delta_run_time_ns": d_ns})
    res["bpf_progs"] = progs
    res["bpf_total_run_time_ns"] = sum(p["delta_run_time_ns"] for p in progs)
    res["bpf_total_run_cnt"] = sum(p["delta_run_cnt"] for p in progs)
    t = open(os.path.join(out, "collector_cpu_ticks.txt")).read().strip()
    res["collector_process_cpu_s"] = int(t) / hz   # utime+stime of the bpftrace process
json.dump(res, open(os.path.join(out, "overhead.json"), "w"), indent=1)
print(json.dumps({k: res[k] for k in ("instr", "markers", "p50_ns", "p99_ns", "throughput_cps") if k in res}))
EOF
