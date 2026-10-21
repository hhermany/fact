#!/usr/bin/env bash
# One E3cred run: cost of the context interface, openat markers vs. the execution credential.
#   scripts/e3cred_round.sh <OUT_DIR> --iface none|openat|prctl [--n 20000] [--warmup 1000] [--seed S]
# - none:   no collector, no policy; connect without switches.
# - openat: collector fact-all.bt and fact_policy (cred=0): both attach a probe to every
#           openat on the host; the benchmark marks begin/end with openat around each connect.
# - prctl:  collector fact-cred.bt and fact_policy (cred=1): the switch is prctl(PR_FACT),
#           authorized by the BPF LSM; no openat probe.
# Each run measures (1) connect() latency with two switches per connection (connect_bench),
# and (2) open()+close() latency of an unrelated file (open_bench), i.e., what the interface
# costs processes that never use it. bpf_stats gives the eBPF time per program.
# Outputs: overhead.json, connect.json, open.json, bpf_prog_*.json.
set -euo pipefail
OUT="$1"; shift
IFACE=none; N=20000; WARMUP=1000; SEED=0
while [ $# -gt 0 ]; do
  case "$1" in
    --iface) IFACE="$2"; shift 2;;
    --n) N="$2"; shift 2;;
    --warmup) WARMUP="$2"; shift 2;;
    --seed) SEED="$2"; shift 2;;
    *) echo "unknown argument $1"; exit 2;;
  esac
done
HERE="$(cd "$(dirname "$0")/.." && pwd)"
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
mkdir -p "$OUT"
CB="$HERE/bench/connect_bench"; OB="$HERE/bench/open_bench"
[ -x "$CB" ] && [ "$CB" -nt "$HERE/bench/connect_bench.c" ] || gcc -O2 -Wall -o "$CB" "$HERE/bench/connect_bench.c"
[ -x "$OB" ] && [ "$OB" -nt "$HERE/bench/open_bench.c" ] || gcc -O2 -Wall -o "$OB" "$HERE/bench/open_bench.c"
[ -x "$HERE/policy/fact_policy" ] && [ -f "$HERE/policy/fact_policy.bpf.o" ] || make -s -C "$HERE/policy"
PORT=$(( 65000 + SEED % 500 ))
case "$IFACE" in
  none) BT=""; CRED=""; MK=0;;
  openat) BT="$HERE/collector/fact-all.bt"; CRED=0; MK=1;;
  prctl) BT="$HERE/collector/fact-cred.bt"; CRED=1; MK=2;;
  *) echo "unknown iface: $IFACE"; exit 2;;
esac
BPID=""; PPOL=""
trap 'kill -INT $BPID $PPOL 2>/dev/null || true; wait $BPID $PPOL 2>/dev/null || true' EXIT
if [ -n "$BT" ]; then
  sysctl -q -w kernel.bpf_stats_enabled=1
  bpftrace -B line "$BT" > "$OUT/events.jsonl" 2> "$OUT/collector.err" &
  BPID=$!
  for i in $(seq 1 300); do
    grep -q '"ev":"ready"' "$OUT/events.jsonl" 2>/dev/null && break
    kill -0 "$BPID" 2>/dev/null || { cat "$OUT/collector.err"; exit 1; }
    sleep 0.1
  done
  "$HERE/policy/fact_policy" /sys/fs/cgroup 61000 64998 1 "$HERE/policy/fact_policy.bpf.o" 0 0 0 "$CRED" \
      > "$OUT/policy_events.jsonl" 2> "$OUT/policy.err" &
  PPOL=$!
  for i in $(seq 1 300); do
    grep -q '"ev":"ready"' "$OUT/policy_events.jsonl" 2>/dev/null && break
    kill -0 "$PPOL" 2>/dev/null || { cat "$OUT/policy.err"; exit 1; }
    sleep 0.1
  done
  grep -q '"ev":"ready"' "$OUT/policy_events.jsonl" || { echo "policy not ready"; exit 1; }
  bpftool prog show --json > "$OUT/bpf_prog_before.json"
fi
"$CB" --n "$N" --warmup "$WARMUP" --port "$PORT" --markers "$MK" --out "$OUT/latencies.csv" > "$OUT/connect.json"
"$OB" --n $(( N * 10 )) --warmup "$WARMUP" --path /etc/hostname > "$OUT/open.json"
if [ -n "$BT" ]; then
  bpftool prog show --json > "$OUT/bpf_prog_after.json"
  kill -INT $BPID $PPOL; wait $BPID $PPOL || true
  sysctl -q -w kernel.bpf_stats_enabled=0
fi
trap - EXIT
python3 -I - "$OUT" "$IFACE" <<'PY'
import json, os, sys
out, iface = sys.argv[1], sys.argv[2]
res = {"iface": iface, "connect": json.load(open(os.path.join(out, "connect.json"))),
       "open": json.load(open(os.path.join(out, "open.json")))}
pa, pd = os.path.join(out, "bpf_prog_before.json"), os.path.join(out, "bpf_prog_after.json")
if os.path.exists(pa):
    before = {p["id"]: p for p in json.load(open(pa))}
    res["bpf_progs"] = [{"name": p.get("name"), "run_cnt": p.get("run_cnt", 0) - before[p["id"]].get("run_cnt", 0),
                         "ns_per_run": round((p.get("run_time_ns", 0) - before[p["id"]].get("run_time_ns", 0)) /
                                             max(1, p.get("run_cnt", 0) - before[p["id"]].get("run_cnt", 0)), 1)}
                        for p in json.load(open(pd)) if p["id"] in before and p.get("run_cnt", 0) > before[p["id"]].get("run_cnt", 0)]
json.dump(res, open(os.path.join(out, "overhead.json"), "w"), indent=1)
print(json.dumps({"iface": iface, "connect_p50": res["connect"]["p50_ns"], "open_p50": res["open"]["p50_ns"]}))
PY
