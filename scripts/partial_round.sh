#!/usr/bin/env bash
# One E5partial run: byte accounting under backpressure (bench/partial_send.py) with
# the byte collector (fact-bytes.bt). Compares, for the measured connection, the bytes
# the collector credits (return value of tcp_sendmsg), the sizes requested at
# tcp_sendmsg (what counting the argument would credit), and the bytes the
# destination received. Usage: scripts/partial_round.sh <OUT_DIR> [--seed S]
# Output: OUT/partial_score.json
set -euo pipefail
OUT="$1"; shift
SEED=0
while [ $# -gt 0 ]; do
  case "$1" in
    --seed) SEED="$2"; shift 2;;
    *) echo "unknown argument $1"; exit 2;;
  esac
done
HERE="$(cd "$(dirname "$0")/.." && pwd)"
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
mkdir -p "$OUT"
PORT=$(( 62000 + SEED % 1000 ))
bpftrace -B line "$HERE/collector/fact-bytes.bt" > "$OUT/events.jsonl" 2> "$OUT/collector.err" &
BPID=$!
trap 'kill -INT "$BPID" 2>/dev/null || true; wait "$BPID" 2>/dev/null || true' EXIT
for i in $(seq 1 300); do
  grep -q '"ev":"ready"' "$OUT/events.jsonl" 2>/dev/null && break
  kill -0 "$BPID" 2>/dev/null || { cat "$OUT/collector.err"; exit 1; }
  sleep 0.1
done
grep -q '"ev":"ready"' "$OUT/events.jsonl" || { echo "collector not ready"; exit 1; }
"${FACT_PYTHON:-python3}" -I "$HERE/bench/partial_send.py" --out "$OUT" --port "$PORT" > "$OUT/bench.log"
sleep 1
kill -INT "$BPID"; wait "$BPID" || true
trap - EXIT
python3 -I - "$OUT" "$PORT" <<'EOF'
import json, os, sys
out, port = sys.argv[1], int(sys.argv[2])
p = json.load(open(os.path.join(out, "partial.json")))
acc = req = n = 0
ctx = set()
for l in open(os.path.join(out, "events.jsonl")):
    if not l.startswith("{"):
        continue
    e = json.loads(l)
    if e.get("ev") == "send" and e.get("dport") == port:
        acc += e["bytes"]; req += e.get("req", 0); n += 1; ctx.add(e.get("ctx"))
res = {"bench": p, "collector_sends": n, "collector_bytes": acc, "collector_requested": req,
       "contexts": sorted(ctx),
       "exact": acc == p["accepted"] == p["received"],
       "requested_overcount_pct": round(100 * (req - p["received"]) / p["received"], 2)}
json.dump(res, open(os.path.join(out, "partial_score.json"), "w"), indent=1)
print(json.dumps({k: v for k, v in res.items() if k != "bench"}))
if not res["exact"]:
    sys.exit("collector bytes differ from the destination's count")
EOF
