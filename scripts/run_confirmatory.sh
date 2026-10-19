#!/usr/bin/env bash
# Runs the confirmatory campaigns of ONE boot.
#
# The paper's confirmatory results use two boots: run this script, reboot the
# host, and run it again. Each run creates new, immutable campaign directories
# under campaigns/ (nothing is overwritten).
#
# Usage (as root, from the repository root, outside the Nix shell):
#   scripts/run_confirmatory.sh                 # every experiment with N set in workflow/config.yaml
#   scripts/run_confirmatory.sh E6L E5f         # only these experiments
#
# Requirements: Linux with BTF, bpftrace >= 0.25, bpftool, clang and libbpf
# headers on the host (the policy loader is built with the host toolchain),
# Nix with flakes. Experiments E7 and E7f also need Ollama with the model
# qwen2.5:3b (pulled automatically if missing).
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }

SEED=$(awk '/^campaign_seed:/ {print $2}' workflow/config.yaml)
LOG_DIR=${LOG_DIR:-campaigns/logs}
mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/boot-$(cat /proc/sys/kernel/random/boot_id | cut -c1-8)-$(date -u +%Y%m%dT%H%M%SZ).log"
exec > >(tee -a "$LOG") 2>&1
echo "boot_id $(cat /proc/sys/kernel/random/boot_id)  seed $SEED  log $LOG"

# 1. policy loader and BPF object (host toolchain; see policy/Makefile)
make -s -C policy

# 2. everything else runs inside the pinned Nix environment
EXPS="$*"
nix --extra-experimental-features 'nix-command flakes' develop -c env EXPS="$EXPS" SEED="$SEED" bash -c '
set -u -o pipefail
if [ -z "$EXPS" ]; then
  EXPS=$(python3 -c "import yaml; c=yaml.safe_load(open(\"workflow/config.yaml\"))[\"experiments\"]; print(\" \".join(e for e, v in c.items() if v.get(\"n\")))")
fi
echo "experiments: $EXPS"

rm -rf preflight/last && scripts/preflight.sh preflight/last > /dev/null 2>&1 || true
grep -q "RESULT PASS" preflight/last/preflight.txt || { echo "PREFLIGHT FAILED"; tail -20 preflight/last/preflight.txt; exit 1; }
echo "preflight PASS"

case " $EXPS " in *" E7"*)
  if ! curl -s --max-time 3 127.0.0.1:11434/api/tags > /dev/null; then
    nohup ollama serve > /tmp/ollama.log 2>&1 &
    for i in $(seq 1 60); do curl -s --max-time 2 127.0.0.1:11434/api/tags > /dev/null && break; sleep 1; done
  fi
  ollama list | grep -q "qwen2.5:3b" || ollama pull qwen2.5:3b
  ;;
esac

status=0
for e in $EXPS; do
  n=$(python3 -c "import yaml; print(yaml.safe_load(open(\"workflow/config.yaml\"))[\"experiments\"][\"$e\"][\"n\"])")
  spec=$(python3 -c "import yaml; print(yaml.safe_load(open(\"workflow/config.yaml\"))[\"experiments\"][\"$e\"][\"spec\"])")
  echo "== $e n=$n $(date -u +%H:%M:%S)"
  python3 scripts/campaign.py --spec "$spec" --n "$n" --seed "$SEED" --label confirmatory --preflight preflight/last \
    | grep -v "^\[" || status=1
done
exit $status
'
echo "done. After the second boot: snakemake --cores 1 validate report baselines faults"
