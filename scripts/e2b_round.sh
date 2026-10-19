#!/usr/bin/env bash
# E2b (collector capacity): P concurrent instances of the closed-loop connect
# microbenchmark, with the collector active. Measures the aggregate rate and the
# fraction of captured connects (events with each instance's port / connects made),
# plus the lost events that bpftrace reports. Usage:
#   scripts/e2b_round.sh <OUT> --par P [--n 50000] [--collector agentnet.bt|agentnet-fast.bt] [--seed S]
set -euo pipefail
OUT="$1"; shift
PAR=1; N=50000; COL=agentnet.bt; SEED=0
while [ $# -gt 0 ]; do
  case "$1" in
    --par) PAR="$2"; shift 2;;
    --n) N="$2"; shift 2;;
    --collector) COL="$2"; shift 2;;
    --seed) SEED="$2"; shift 2;;
    *) echo "unknown argument $1"; exit 2;;
  esac
done
HERE="$(cd "$(dirname "$0")/.." && pwd)"
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
mkdir -p "$OUT"
BIN="$HERE/bench/connect_bench"
[ -x "$BIN" ] || gcc -O2 -Wall -o "$BIN" "$HERE/bench/connect_bench.c"
cat /proc/loadavg > "$OUT/loadavg-start.txt"
bpftrace -B line "$HERE/collector/$COL" > "$OUT/events.jsonl" 2> "$OUT/collector.err" &
BPID=$!
trap 'kill -INT "$BPID" 2>/dev/null || true; wait "$BPID" 2>/dev/null || true' EXIT
for i in $(seq 1 300); do
  grep -q '"ev":"ready"' "$OUT/events.jsonl" 2>/dev/null && break
  kill -0 "$BPID" 2>/dev/null || { cat "$OUT/collector.err"; exit 1; }
  sleep 0.1
done
grep -q '"ev":"ready"' "$OUT/events.jsonl" || { echo "no ready sentinel"; exit 1; }
BASE=$(( 65000 + (SEED % 50) * 10 ))
T0=$(date +%s.%N)
PIDS=()
for i in $(seq 0 $((PAR - 1))); do
  "$BIN" --n "$N" --warmup 0 --port $((BASE + i)) --markers 0 > "$OUT/bench-$i.json" &
  PIDS+=($!)
done
for p in "${PIDS[@]}"; do wait "$p"; done
T1=$(date +%s.%N)
sleep 1
kill -INT "$BPID"; wait "$BPID" || true
cat /proc/loadavg > "$OUT/loadavg-end.txt"
python3 -I - "$OUT" "$PAR" "$N" "$BASE" "$T0" "$T1" "$COL" <<'PY'
import json, os, re, sys
out, par, n, base, t0, t1, col = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), float(sys.argv[5]), float(sys.argv[6]), sys.argv[7]
ports = set(range(base, base + par))
cap = 0
for line in open(os.path.join(out, "events.jsonl")):
    if '"ev":"connect"' in line:
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("dport") in ports:
            cap += 1
err = open(os.path.join(out, "collector.err")).read()
lost = sum(int(x) for x in re.findall(r"Lost (\d+) events", err))
done = sum(json.load(open(os.path.join(out, f"bench-{i}.json")))["n"] for i in range(par))
fails = sum(json.load(open(os.path.join(out, f"bench-{i}.json")))["failures"] for i in range(par))
res = {"collector": col, "par": par, "connects": done, "failures": fails, "captured": cap,
       "capture": cap / done if done else None, "lost_reported": lost, "wall_s": t1 - t0,
       "agg_rate_cps": done / (t1 - t0)}
json.dump(res, open(os.path.join(out, "capacity.json"), "w"), indent=1)
print(json.dumps(res))
PY
gzip -f "$OUT/events.jsonl"   # raw data kept, compressed (hundreds of MB per run at high P)
