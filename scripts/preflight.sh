#!/usr/bin/env bash
# Preflight: before any campaign, checks that the host can run the collector and
# records the environment. Exits with a non-zero code if anything essential fails.
# Usage: sudo scripts/preflight.sh <out_dir>
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
  # Attaches the real collector for ~2 s and checks the number of probes.
  timeout -s INT 3 bpftrace -B line "$HERE/collector/fact.bt" > "$OUT/attach.stdout" 2> "$OUT/attach.stderr"
  if grep -q '"ev":"ready"' "$OUT/attach.stdout" && grep -q 'Attached 8 probes' "$OUT/attach.stderr"; then
    echo "PASS collector attached (8 probes, ready sentinel)"
  else
    echo "FAIL collector: see attach.stderr"; fail=1
  fi
  python3 -I -c "import sys; sys.path.insert(0, '$HERE/analysis'); import resolvers; resolvers.check_independence()" \
    && echo "PASS resolver independence (AST)" || { echo "FAIL resolver independence (AST)"; fail=1; }
  echo "RESULT $([ $fail -eq 0 ] && echo PASS || echo FAIL)"
} | tee "$OUT/preflight.txt"
"$HERE/scripts/capture_env.sh" "$OUT/environment"
# 'fail' was changed inside the pipe (subshell); the verdict comes from the file.
grep -q '^RESULT PASS' "$OUT/preflight.txt"
