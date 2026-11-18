#!/usr/bin/env bash
# One OBI association run: OBI (v1.0.0) attached by open port to the shared server, context
# propagation on; or no OBI (control). OBI binary: $OBI_BIN (default ~/obi/obi). Usage (root, inside nix develop): obi_round.sh OUT MODE K CALLS SEED obi|none
set -u
OUT=$1; MODE=$2; K=$3; CALLS=$4; SEED=$5; OBI=$6; TOOL=${7:-async}; SEL=${8:-port}; PORT=63900
mkdir -p "$OUT"
if [ "$OBI" = obi ]; then
  if [ "$SEL" = exe ]; then SELV="OTEL_EBPF_AUTO_TARGET_EXE=*python3*"; else SELV="OTEL_EBPF_OPEN_PORT=$PORT"; fi
  env $SELV OTEL_EBPF_BPF_CONTEXT_PROPAGATION=all OTEL_EBPF_TRACE_PRINTER=text \
    "${OBI_BIN:-$HOME/obi/obi}" > "$OUT/obi.log" 2>&1 &
  OPID=$!; sleep 5
fi
OBI_WARMUP=${OBI_WARMUP:-10} python3 "$(dirname "$0")/../bench/obi_assoc.py" --mode "$MODE" --execs "$K" --calls "$CALLS" \
  --seed "$SEED" --tool "$TOOL" --port $PORT --out "$OUT" > "$OUT/run.log" 2>&1
if [ "$OBI" = obi ]; then kill -INT $OPID; wait $OPID 2>/dev/null; fi
tail -1 "$OUT/run.log"
