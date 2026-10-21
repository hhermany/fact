#!/usr/bin/env bash
# One E11file run: the execution credential charging file writes (fact_policy cred=1,
# files=1), K executions in one process; the kernel's per-credential counters are
# compared with what the writes returned.
#   scripts/e11file_round.sh <OUT_DIR> --mode async|pool --execs K [--ops N] [--seed S]
set -euo pipefail
OUT="$1"; shift
MODE=async; EXECS=4; OPS=25; SEED=0
while [ $# -gt 0 ]; do
  case "$1" in
    --mode) MODE="$2"; shift 2;;
    --execs) EXECS="$2"; shift 2;;
    --ops) OPS="$2"; shift 2;;
    --seed) SEED="$2"; shift 2;;
    *) echo "unknown argument $1"; exit 2;;
  esac
done
HERE="$(cd "$(dirname "$0")/.." && pwd)"
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
mkdir -p "$OUT"
[ -x "$HERE/policy/fact_policy" ] && [ -f "$HERE/policy/fact_policy.bpf.o" ] || make -s -C "$HERE/policy"
"$HERE/policy/fact_policy" /sys/fs/cgroup 61000 64998 1 "$HERE/policy/fact_policy.bpf.o" 0 0 0 1 1 \
    > "$OUT/policy_events.jsonl" 2> "$OUT/policy.err" &
PPOL=$!
trap 'kill -INT $PPOL 2>/dev/null || true; wait $PPOL 2>/dev/null || true' EXIT
for i in $(seq 1 300); do
  grep -q '"ev":"ready"' "$OUT/policy_events.jsonl" 2>/dev/null && break
  kill -0 "$PPOL" 2>/dev/null || { cat "$OUT/policy.err"; exit 1; }
  sleep 0.1
done
grep -q '"ev":"ready"' "$OUT/policy_events.jsonl" || { echo "policy not ready"; exit 1; }
"${FACT_PYTHON:-python3}" -I "$HERE/workload/file_e11.py" --out "$OUT" --mode "$MODE" --execs "$EXECS" \
    --ops "$OPS" --seed "$SEED"
"${FACT_PYTHON:-python3}" -I "$HERE/policy/policyctl.py" fusage > "$OUT/file_usage.json"
kill -INT $PPOL; wait $PPOL || true
trap - EXIT
"${FACT_PYTHON:-python3}" -I "$HERE/analysis/score_file.py" "$OUT" | tee "$OUT/summary_file.txt"
