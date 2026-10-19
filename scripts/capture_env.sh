#!/usr/bin/env bash
# Records the observed environment in <dir>/ (one file per item). Never fails:
# anything unavailable is recorded as "UNAVAILABLE".
# Usage: capture_env.sh <dir> [suffix]
set -u
D="$1"; SUF="${2:-}"
mkdir -p "$D"
cap() { local f="$1"; shift; { "$@" 2>&1 || echo "UNAVAILABLE: $*"; } > "$D/$f$SUF.txt"; }
cap uname        uname -a
cap os_release   cat /etc/os-release
cap hostname     hostname
cap boot_id      cat /proc/sys/kernel/random/boot_id
cap uptime       cat /proc/uptime
cap loadavg      cat /proc/loadavg
cap lscpu        lscpu
cap meminfo      head -5 /proc/meminfo
cap virt         systemd-detect-virt
cap cpufreq      cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
cap btf          ls -la /sys/kernel/btf/vmlinux
cap cgroup_mount findmnt -t cgroup2
cap bpftrace     bpftrace --version
cap bpftool      bpftool version
cap python       python3 --version
cap nix          nix --version
cap pid_max      cat /proc/sys/kernel/pid_max
cap clocksource  cat /sys/devices/system/clocksource/clocksource0/current_clocksource
cap ntp          timedatectl show
cap procs_top    ps -eo pid,comm,%cpu,%mem --sort=-%cpu
exit 0
