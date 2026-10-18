#!/usr/bin/env bash
# Executa UMA rodada: coletor -> espera sentinel "ready" -> workload -> para coletor -> pontua.
# Uso: sudo ./run_round.sh <COND N0|N1|N2|N3> <OUT_DIR> [args extras do workload.py]
# Ex.: sudo ./run_round.sh N1 runs/N1-r001 --ops 100 --mode mixed --seed 1
#
# Espera o sentinel real do bpftrace em vez de "sleep" fixo (lição da rep1 de 25/09).
set -euo pipefail
COND="$1"; OUT="$2"; shift 2
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT"
[ "$(id -u)" -eq 0 ] || { echo "rode como root (sudo)"; exit 1; }

uname -r > "$OUT/kernel.txt"; bpftrace --version > "$OUT/bpftrace.txt" 2>&1 || true
( cd "$HERE" && git rev-parse HEAD 2>/dev/null || echo "sem-git" ) > "$OUT/commit.txt"

COLLECTOR="${COLLECTOR:-agentnet.bt}"     # variante do coletor (agentnet.bt ou agentnet-fast.bt)
echo "$COLLECTOR" > "$OUT/collector.txt"
"${AGENTNET_PYTHON:-python3}" --version > "$OUT/python.txt" 2>&1
bpftrace -B line "$HERE/collector/$COLLECTOR" > "$OUT/events.jsonl" 2> "$OUT/collector.err" &
BPID=$!
# encerra o coletor em QUALQUER saída (inclusive falha do workload com set -e):
# sem isso, uma rodada que falha deixa o bpftrace rodando indefinidamente.
PPOL=""
trap 'kill -INT "$BPID" $PPOL 2>/dev/null || true; wait "$BPID" $PPOL 2>/dev/null || true' EXIT
for i in $(seq 1 300); do            # até 30 s
  grep -q '"ev":"ready"' "$OUT/events.jsonl" 2>/dev/null && break
  kill -0 "$BPID" 2>/dev/null || { echo "coletor morreu:"; cat "$OUT/collector.err"; exit 1; }
  sleep 0.1
done
grep -q '"ev":"ready"' "$OUT/events.jsonl" || { echo "sentinel ready não apareceu"; kill "$BPID"; exit 1; }

# Política por execução (E6): carrega o agentnet_policy no cgroup raiz, policiando
# só as portas do plano (61000-64998); POLICY_NOCTX_ALLOW = ação sem identidade.
EXTRA=()
if [ "${POLICY:-0}" = 1 ]; then
  [ -x "$HERE/policy/agentnet_policy" ] && [ -f "$HERE/policy/agentnet_policy.bpf.o" ] || make -s -C "$HERE/policy"
  "$HERE/policy/agentnet_policy" /sys/fs/cgroup 61000 64998 "${POLICY_NOCTX_ALLOW:-0}" \
      "$HERE/policy/agentnet_policy.bpf.o" "${POLICY_LINEAGE:-0}" > "$OUT/policy_events.jsonl" 2> "$OUT/policy.err" &
  PPOL=$!
  for i in $(seq 1 100); do
    grep -q '"ev":"ready"' "$OUT/policy_events.jsonl" 2>/dev/null && break
    kill -0 "$PPOL" 2>/dev/null || { echo "política morreu:"; cat "$OUT/policy.err"; exit 1; }
    sleep 0.1
  done
  grep -q '"ev":"ready"' "$OUT/policy_events.jsonl" || { echo "política sem ready"; exit 1; }
  EXTRA=(--policy 1)
fi

# Sistema relacionado executado de verdade (opcional): AGENTPROV=<binário do
# AgentProvenance>. O sensor dele roda ao lado do coletor, num cgroup próprio
# (o sensor descarta eventos do próprio cgroup como ruído), e retém os eventos
# até os vínculos por chamada de ferramenta, registrados depois do workload.
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
    kill -0 "$APID" 2>/dev/null || { echo "sensor AgentProvenance morreu:"; cat "$OUT/agentprov/sensor.log"; exit 1; }
    sleep 0.1
  done
  grep -q 'ready probes-attached' "$OUT/agentprov/sensor.log" || { echo "sensor AgentProvenance sem ready"; exit 1; }
fi

WORKLOAD="${WORKLOAD:-workload/workload.py}"   # E4: workload/mcp_e4.py
"${AGENTNET_PYTHON:-python3}" -I "$HERE/$WORKLOAD" --cond "$COND" --out "$OUT" "$@" "${EXTRA[@]}"
sleep 1                               # drena eventos finais do buffer
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
