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

COLLECTOR="${COLLECTOR:-fact.bt}"     # collector variant (fact.bt or fact-fast.bt)
echo "$COLLECTOR" > "$OUT/collector.txt"
"${FACT_PYTHON:-python3}" --version > "$OUT/python.txt" 2>&1
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

# Per-execution policy (E6): loads fact_policy on the root cgroup, policing
# only the planned ports (61000-64998); POLICY_NOCTX_ALLOW = action without identity.
EXTRA=()
if [ "${POLICY:-0}" = 1 ]; then
  [ -x "$HERE/policy/fact_policy" ] && [ -f "$HERE/policy/fact_policy.bpf.o" ] || make -s -C "$HERE/policy"
  "$HERE/policy/fact_policy" /sys/fs/cgroup 61000 64998 "${POLICY_NOCTX_ALLOW:-0}" \
      "$HERE/policy/fact_policy.bpf.o" "${POLICY_LINEAGE:-0}" > "$OUT/policy_events.jsonl" 2> "$OUT/policy.err" &
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

# Live accounting exported over IPFIX (optional): IPFIX=1. factd follows the
# collector's stream while the workload runs and exports IPFIX over UDP to
# 127.0.0.1:4739, where tshark captures it (analysis/score_ipfix.py decodes the
# capture with Wireshark's IPFIX dissector and compares it with the reference).
FPID=""; TPID=""
if [ "${IPFIX:-0}" = 1 ]; then
  [ -f "$OUT/registry.json" ] || echo '{"roots":{},"cgroups":{}}' > "$OUT/registry.json"
  # dumpcap may not write into the repository's directories: capture to /tmp, move afterwards
  TPCAP="$(mktemp /tmp/fact-ipfix-XXXXXX.pcap)"; chmod 666 "$TPCAP"
  tshark -q -i lo -f "udp port 4739" -w "$TPCAP" > "$OUT/tshark.log" 2>&1 &
  TPID=$!
  for i in $(seq 1 100); do
    grep -q "Capturing on" "$OUT/tshark.log" 2>/dev/null && break
    sleep 0.1
  done
  sleep 0.5
  grep -q "Capturing on" "$OUT/tshark.log" && kill -0 "$TPID" 2>/dev/null || { echo "tshark did not start"; cat "$OUT/tshark.log"; exit 1; }
  "${FACT_PYTHON:-python3}" -I "$HERE/factd/factd.py" --follow "$OUT/events.jsonl" --registry "$OUT/registry.json" \
      --ipfix 127.0.0.1:4739 --out "$OUT/factd_live.jsonl" 2> "$OUT/factd.err" &
  FPID=$!
  trap 'kill -INT "$BPID" $PPOL $APID 2>/dev/null || true; kill $FPID $TPID 2>/dev/null || true; wait "$BPID" $PPOL $APID $FPID $TPID 2>/dev/null || true' EXIT
fi

# CPU cost under the experiment's own workload (optional): COST=1 (scripts/cost_probe.py)
if [ "${COST:-0}" = 1 ]; then
  sysctl -q -w kernel.bpf_stats_enabled=1
  "${FACT_PYTHON:-python3}" -I "$HERE/scripts/cost_probe.py" before "$OUT" "$BPID" "$PPOL"
fi
WORKLOAD="${WORKLOAD:-workload/workload.py}"   # E4: workload/mcp_e4.py
"${FACT_PYTHON:-python3}" -I "$HERE/$WORKLOAD" --cond "$COND" --out "$OUT" "$@" "${EXTRA[@]}"
if [ "${COST:-0}" = 1 ]; then
  "${FACT_PYTHON:-python3}" -I "$HERE/scripts/cost_probe.py" after "$OUT" "$BPID" "$PPOL"
  sysctl -q -w kernel.bpf_stats_enabled=0
fi
sleep 1                               # drains the last events from the buffer
kill -INT "$BPID"; wait "$BPID" || true
if [ -n "$FPID" ]; then                # factd drains its buffer, exports the last interval, exits
  kill -TERM "$FPID"; wait "$FPID" || true
  sleep 1; kill -INT "$TPID"; wait "$TPID" || true
  mv "$TPCAP" "$OUT/ipfix.pcap"
fi
if [ -n "$APID" ]; then
  "${FACT_PYTHON:-python3}" -I "$HERE/analysis/agentprov_bind.py" "$OUT" "$AGENTPROV" "$APID"
  wait "$APID" 2>/dev/null || true
  "${FACT_PYTHON:-python3}" -I "$HERE/analysis/score_agentprov.py" "$OUT" | tee "$OUT/agentprov_summary.txt"
fi
if [ -n "$PPOL" ]; then
  kill -INT "$PPOL"; wait "$PPOL" || true
  "${FACT_PYTHON:-python3}" -I "$HERE/analysis/score_policy.py" "$OUT" | tee "$OUT/policy_summary.txt"
fi

"${FACT_PYTHON:-python3}" -I "$HERE/analysis/score.py" "$OUT" | tee "$OUT/summary.txt"
if [ -f "$OUT/requests.jsonl" ]; then   # E5reuse: per-request reference on reused connections
  "${FACT_PYTHON:-python3}" -I "$HERE/analysis/score_bytes.py" "$OUT" | tee "$OUT/summary_bytes.txt"
fi
if [ "${COST:-0}" = 1 ]; then
  "${FACT_PYTHON:-python3}" -I "$HERE/scripts/cost_probe.py" factd "$OUT"
fi
if [ "${IPFIX:-0}" = 1 ]; then
  "${FACT_PYTHON:-python3}" -I "$HERE/analysis/score_ipfix.py" "$OUT" | tee "$OUT/summary_ipfix.txt"
fi
