#!/usr/bin/env bash
# Cost of the send binding (bench/send_bind.py) with no collector, with the default
# collector (fact.bt), and with the byte collector (fact-bytes.bt), in random order.
# Usage (root, inside nix develop): bench/send_bind_round.sh OUT_DIR [SEED]
# Writes OUT_DIR/send_bind.jsonl and OUT_DIR/send_bind_summary.csv (median ns per send).
set -euo pipefail
OUT="$1"; SEED="${2:-51193}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$OUT"
: > "$OUT/send_bind.jsonl"
uname -r > "$OUT/kernel.txt"; ( cd "$HERE" && git rev-parse HEAD ) > "$OUT/commit.txt"
ORDER=$(python3 -c "import random; r=random.Random($SEED); l=['none','fact.bt','fact-bytes.bt']; r.shuffle(l); print(' '.join(l))")
echo "order: $ORDER" | tee "$OUT/order.txt"
for c in $ORDER; do
  BPID=""
  if [ "$c" != none ]; then
    bpftrace -B line "$HERE/collector/$c" > "$OUT/events-$c.jsonl" 2> "$OUT/collector-$c.err" &
    BPID=$!
    for i in $(seq 1 300); do grep -q '"ev":"ready"' "$OUT/events-$c.jsonl" 2>/dev/null && break; sleep 0.1; done
    grep -q '"ev":"ready"' "$OUT/events-$c.jsonl" || { echo "collector $c not ready"; kill "$BPID"; exit 1; }
  fi
  "${FACT_PYTHON:-python3}" -I "$HERE/bench/send_bind.py" --label "$c" --seed "$SEED" >> "$OUT/send_bind.jsonl"
  if [ -n "$BPID" ]; then kill -INT "$BPID"; wait "$BPID" || true; rm -f "$OUT/events-$c.jsonl"; fi
done
python3 -I - "$OUT" <<'PY'
import collections, json, statistics as st, sys, os
out = sys.argv[1]
d = collections.defaultdict(list)
for l in open(os.path.join(out, "send_bind.jsonl")):
    r = json.loads(l); d[(r["label"], r["mode"])].append(r["ns_per_send"])
with open(os.path.join(out, "send_bind_summary.csv"), "w") as f:
    f.write("collector,mode,reps,ns_per_send_median,ns_min,ns_max\n")
    for (c, m), v in sorted(d.items()):
        f.write(f"{c},{m},{len(v)},{st.median(v):.1f},{min(v):.1f},{max(v):.1f}\n")
print(open(os.path.join(out, "send_bind_summary.csv")).read())
PY
