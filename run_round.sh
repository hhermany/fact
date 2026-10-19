#!/usr/bin/env bash
# Runs ONE run: collector -> wait for the "ready" sentinel -> workload -> stop collector -> score.
# Usage: sudo ./run_round.sh <COND N0|N1|N2|N3> <OUT_DIR> [extra workload.py args]
# E.g.:  sudo ./run_round.sh N1 runs/N1-r001 --ops 100 --mode mixed --seed 1
#
# Waits for bpftrace's real ready sentinel instead of a fixed "sleep".
set -euo pipefail
COND="$1"; OUT="$2"; shift 2
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT"
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }

uname -r > "$OUT/kernel.txt"; bpftrace --version > "$OUT/bpftrace.txt" 2>&1 || true
( cd "$HERE" && git rev-parse HEAD 2>/dev/null || echo "no-git" ) > "$OUT/commit.txt"

COLLECTOR="${COLLECTOR:-agentnet.bt}"     # collector variant (agentnet.bt or agentnet-fast.bt)
echo "$COLLECTOR" > "$OUT/collector.txt"
"${AGENTNET_PYTHON:-python3}" --version > "$OUT/python.txt" 2>&1
bpftrace -B line "$HERE/collector/$COLLECTOR" > "$OUT/events.jsonl" 2> "$OUT/collector.err" &
BPID=$!
# stops the collector on ANY exit (including a workload failure under set -e):
# without this, a failed run leaves bpftrace running indefinitely.
PPOL=""
trap 'kill -INT "$BPID" $PPOL 2>/dev/null || true; wait "$BPID" $PPOL 2>/dev/null || true' EXIT
for i in $(seq 1 300); do            # up to 30 s
  grep -q '"ev":"ready"' "$OUT/events.jsonl" 2>/dev/null && break
  kill -0 "$BPID" 2>/dev/null || { echo "collector died:"; cat "$OUT/collector.err"; exit 1; }
  sleep 0.1
done
grep -q '"ev":"ready"' "$OUT/events.jsonl" || { echo "ready sentinel did not appear"; kill "$BPID"; exit 1; }

# Per-execution policy (E6): loads agentnet_policy on the root cgroup, policing
# only the planned ports (61000-64998); POLICY_NOCTX_ALLOW = action without identity.
EXTRA=()
if [ "${POLICY:-0}" = 1 ]; then
  [ -x "$HERE/policy/agentnet_policy" ] && [ -f "$HERE/policy/agentnet_policy.bpf.o" ] || make -s -C "$HERE/policy"
  "$HERE/policy/agentnet_policy" /sys/fs/cgroup 61000 64998 "${POLICY_NOCTX_ALLOW:-0}" \
      "$HERE/policy/agentnet_policy.bpf.o" "${POLICY_LINEAGE:-0}" > "$OUT/policy_events.jsonl" 2> "$OUT/policy.err" &
  PPOL=$!
  for i in $(seq 1 100); do
    grep -q '"ev":"ready"' "$OUT/policy_events.jsonl" 2>/dev/null && break
    kill -0 "$PPOL" 2>/dev/null || { echo "policy died:"; cat "$OUT/policy.err"; exit 1; }
    sleep 0.1
  done
  grep -q '"ev":"ready"' "$OUT/policy_events.jsonl" || { echo "policy not ready"; exit 1; }
  EXTRA=(--policy 1)
fi

# Related system actually run (optional): AGENTPROV=<AgentProvenance binary>.
# Its sensor runs next to the collector, in its own cgroup (the sensor discards
# events of its own cgroup as noise), and holds the events until the per-tool-call
# bindings, registered after the workload.
APID=""
if [ -n "${AGENTPROV:-}" ]; then
  mkdir -p "$OUT/agentprov" /sys/fs/cgroup/agentprov_sensor
  "$AGENTPROV" --data-dir "$OUT/agentprov/store" init > "$OUT/agentprov/init.log" 2>&1
  "$AGENTPROV" --version > "$OUT/agentprov/version.txt" 2>&1 || true
  bash -c 'echo $$ > /sys/fs/cgroup/agentprov_sensor/cgroup.procs; exec "$@"' _ \
    "$AGENTPROV" --data-dir "$OUT/agentprov/store" sensor stream --pending-ttl 30m \
    --flush-interval 250ms --auto-tls=false > "$OUT/agentprov/sensor.log" 2>&1 &
  APID=$!
  trap 'kill -INT "$BPID" $PPOL $APID 2>/dev/null || true; wait "$BPID" $PPOL $APID 2>/dev/null || true' EXIT
  for i in $(seq 1 300); do
    grep -q 'ready probes-attached' "$OUT/agentprov/sensor.log" 2>/dev/null && break
    kill -0 "$APID" 2>/dev/null || { echo "AgentProvenance sensor died:"; cat "$OUT/agentprov/sensor.log"; exit 1; }
    sleep 0.1
  done
  grep -q 'ready probes-attached' "$OUT/agentprov/sensor.log" || { echo "AgentProvenance sensor not ready"; exit 1; }
fi

WORKLOAD="${WORKLOAD:-workload/workload.py}"   # E4: workload/mcp_e4.py
"${AGENTNET_PYTHON:-python3}" -I "$HERE/$WORKLOAD" --cond "$COND" --out "$OUT" "$@" "${EXTRA[@]}"
sleep 1                               # drains the last events from the buffer
kill -INT "$BPID"; wait "$BPID" || true
if [ -n "$APID" ]; then
  "${AGENTNET_PYTHON:-python3}" -I "$HERE/analysis/agentprov_bind.py" "$OUT" "$AGENTPROV" "$APID"
  wait "$APID" 2>/dev/null || true
  "${AGENTNET_PYTHON:-python3}" -I "$HERE/analysis/score_agentprov.py" "$OUT" | tee "$OUT/agentprov_summary.txt"
fi
if [ -n "$PPOL" ]; then
  kill -INT "$PPOL"; wait "$PPOL" || true
  "${AGENTNET_PYTHON:-python3}" -I "$HERE/analysis/score_policy.py" "$OUT" | tee "$OUT/policy_summary.txt"
fi

"${AGENTNET_PYTHON:-python3}" -I "$HERE/analysis/score.py" "$OUT" | tee "$OUT/summary.txt"
