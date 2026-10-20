#!/usr/bin/env bash
# One E3send run: cost of the egress policy per send (bench/send_bench.c). Usage:
#   scripts/e3send_round.sh <OUT_DIR> --policy none|conn|send_out|send_in --proto tcp|udp|udpu
#                           [--n 200000] [--warmup 10000] [--seed S]
# - none:     no policy loaded.
# - conn:     policy loaded without per-send authorization (cgroup/connect4 + cgroup/sendmsg4);
#             the benchmark port is inside the policed range and its identity is allowed.
# - send_in:  per-send authorization on (BPF LSM socket_sendmsg); port inside the range, allowed.
# - send_out: per-send authorization on; port OUTSIDE the policed range: the cost every
#             other send on the host pays (the program runs for every send and returns early).
# The policed range is 61000-64998 and no_ctx_allow=1, so no traffic outside the benchmark
# (\eg SSH) can be denied. bpf_stats is enabled to record the run time of the policy programs.
# Outputs: overhead.json (summary), bpf_prog_*.json, policy.err.
set -euo pipefail
OUT="$1"; shift
POL=none; PROTO=tcp; N=200000; WARMUP=10000; SEED=0
while [ $# -gt 0 ]; do
  case "$1" in
    --policy) POL="$2"; shift 2;;
    --proto) PROTO="$2"; shift 2;;
    --n) N="$2"; shift 2;;
    --warmup) WARMUP="$2"; shift 2;;
    --seed) SEED="$2"; shift 2;;
    *) echo "unknown argument $1"; exit 2;;
  esac
done
HERE="$(cd "$(dirname "$0")/.." && pwd)"
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
mkdir -p "$OUT"
BIN="$HERE/bench/send_bench"
[ -x "$BIN" ] && [ "$BIN" -nt "$HERE/bench/send_bench.c" ] || gcc -O2 -Wall -pthread -o "$BIN" "$HERE/bench/send_bench.c"
LO=61000; HI=64998
case "$POL" in
  none|conn|send_in) PORT=$(( 63000 + SEED % 1000 ));;
  send_out) PORT=$(( 65000 + SEED % 500 ));;
  *) echo "unknown policy: $POL"; exit 2;;
esac
PER_SEND=0; [ "${POL#send_}" != "$POL" ] && PER_SEND=1
cat /proc/loadavg > "$OUT/loadavg-start.txt"
cat /sys/kernel/security/lsm > "$OUT/lsm.txt"

PPID_POL=""
if [ "$POL" != none ]; then
  [ -x "$HERE/policy/fact_policy" ] && [ -f "$HERE/policy/fact_policy.bpf.o" ] || make -s -C "$HERE/policy"
  sysctl -q -w kernel.bpf_stats_enabled=1
  "$HERE/policy/fact_policy" /sys/fs/cgroup "$LO" "$HI" 1 "$HERE/policy/fact_policy.bpf.o" 0 "$PER_SEND" \
      > "$OUT/policy_events.jsonl" 2> "$OUT/policy.err" &
  PPID_POL=$!
  trap 'kill -INT "$PPID_POL" 2>/dev/null || true; wait "$PPID_POL" 2>/dev/null || true; sysctl -q -w kernel.bpf_stats_enabled=0' EXIT
  for i in $(seq 1 100); do
    grep -q '"ev":"ready"' "$OUT/policy_events.jsonl" 2>/dev/null && break
    kill -0 "$PPID_POL" 2>/dev/null || { cat "$OUT/policy.err"; exit 1; }
    sleep 0.1
  done
  grep -q '"ev":"ready"' "$OUT/policy_events.jsonl" || { echo "policy not ready"; exit 1; }
  python3 -I "$HERE/policy/policyctl.py" allow BENCH "$PORT"
  bpftool prog show --json > "$OUT/bpf_prog_before.json"
fi

"$BIN" --proto "$PROTO" --n "$N" --warmup "$WARMUP" --port "$PORT" > "$OUT/bench.json"

if [ -n "$PPID_POL" ]; then
  bpftool prog show --json > "$OUT/bpf_prog_after.json"
fi
cat /proc/loadavg > "$OUT/loadavg-end.txt"

python3 -I - "$OUT" "$POL" "$PROTO" <<'EOF'
import json, os, sys
out, pol, proto = sys.argv[1], sys.argv[2], sys.argv[3]
b = json.load(open(os.path.join(out, "bench.json")))
res = {"policy": pol, "proto": proto, **b}
pa, pd = os.path.join(out, "bpf_prog_before.json"), os.path.join(out, "bpf_prog_after.json")
if os.path.exists(pa) and os.path.exists(pd):
    before = {p["id"]: p for p in json.load(open(pa))}
    progs = []
    for p in json.load(open(pd)):
        if p["id"] in before and p.get("name", "").startswith("on_"):
            d_ns = p.get("run_time_ns", 0) - before[p["id"]].get("run_time_ns", 0)
            d_cnt = p.get("run_cnt", 0) - before[p["id"]].get("run_cnt", 0)
            if d_cnt > 0:
                progs.append({"id": p["id"], "name": p.get("name"), "type": p.get("type"),
                              "delta_run_cnt": d_cnt, "delta_run_time_ns": d_ns,
                              "ns_per_run": round(d_ns / d_cnt, 1)})
    res["bpf_progs"] = progs
denials = 0
pe = os.path.join(out, "policy_events.jsonl")
if os.path.exists(pe):
    for l in open(pe):
        if l.startswith("{") and '"verdict":"deny"' in l:
            denials += 1
res["policy_denials"] = denials
json.dump(res, open(os.path.join(out, "overhead.json"), "w"), indent=1)
print(json.dumps({k: res[k] for k in ("policy", "proto", "p50_ns", "p99_ns", "throughput_sps", "policy_denials")}))
if b.get("failures") or denials:
    sys.exit(1)
EOF
