#!/usr/bin/env bash
# Preflight: verifica, antes de qualquer campanha, que o host consegue rodar o
# coletor e registra o ambiente. Sai com código != 0 se algo essencial falhar.
# Uso: sudo scripts/preflight.sh <dir_saida>
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$HERE/preflight/$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT"
fail=0
check() { if eval "$2" >/dev/null 2>&1; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi; }
{
  echo "preflight $(date -u +%FT%TZ) host=$(hostname)"
  check "root"                '[ "$(id -u)" -eq 0 ]'
  check "bpftrace"            'command -v bpftrace'
  check "btf"                 '[ -r /sys/kernel/btf/vmlinux ]'
  check "cgroup2"             'findmnt -t cgroup2 /sys/fs/cgroup'
  check "python3"             'command -v python3'
  check "tracepoint sock"     '[ -d /sys/kernel/tracing/events/sock/inet_sock_set_state ] || [ -d /sys/kernel/debug/tracing/events/sock/inet_sock_set_state ]'
  check "kprobe tcp_connect"  'grep -qw tcp_connect /proc/kallsyms'
  # Anexa o coletor de verdade por ~2 s e confere o número de probes.
  timeout -s INT 3 bpftrace -B line "$HERE/collector/agentnet.bt" > "$OUT/attach.stdout" 2> "$OUT/attach.stderr"
  if grep -q '"ev":"ready"' "$OUT/attach.stdout" && grep -q 'Attached 8 probes' "$OUT/attach.stderr"; then
    echo "PASS coletor anexado (8 probes, sentinel ready)"
  else
    echo "FAIL coletor: ver attach.stderr"; fail=1
  fi
  python3 -I -c "import sys; sys.path.insert(0, '$HERE/analysis'); import resolvers; resolvers.check_independence()" \
    && echo "PASS independência dos resolvers (AST)" || { echo "FAIL independência (AST)"; fail=1; }
  echo "RESULTADO $([ $fail -eq 0 ] && echo PASS || echo FAIL)"
} | tee "$OUT/preflight.txt"
"$HERE/scripts/capture_env.sh" "$OUT/environment"
# 'fail' foi alterado dentro do pipe (subshell); o veredito vem do arquivo.
grep -q '^RESULTADO PASS' "$OUT/preflight.txt"
