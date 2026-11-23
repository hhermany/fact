#!/usr/bin/env bash
# Address-family parity of the experiments: runs each experiment once per cell (--n 1, the paper's
# campaign seed) over IPv4 and over IPv6 (scripts/campaign.py --family 4|6), at the current commit,
# then compares the two families run by run (analysis/compare_families.py) and each family with the
# recorded confirmatory campaigns (scripts/compare_runs.py, for the experiments in analysis/runs.csv).
#
# Usage (as root, from the repository root, outside the Nix shell):
#   scripts/run_parity.sh OUT_DIR                 # every local experiment (list below)
#   scripts/run_parity.sh OUT_DIR E6 E6reuse      # only these
# The default list leaves out the experiments that need the second machine (E3net, E5net, E6net,
# E7m: run them with --set dest_host=<IPv6 address> after starting remote_farm.py --addr ::) and
# the paid model APIs (E7c, E7o, E7net); E7r/E7rc replay the recorded API sessions without them.
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
OUT=$(realpath -m "$1"); shift
mkdir -p "$OUT"
SEED=$(awk '/^campaign_seed:/ {print $2}' workflow/config.yaml)
DEFAULT="E1 E1fast E1ap E2 E2b E3 E3b E3cred E3send E4 E5 E5f E5ap E5aps E5fetch E5lib E5native E5node E5partial
E5reuse E5udp E6 E6L E6Ls E6f E6n E6cred E6reuse E6reusecred E6sess E6spoof E6spoofcred E7 E7f E7r E7rc E8ipfix E9all
E9b E9cost E9costcred E10budget E10conc E10conccred E11file E12contain E12containcred"
EXPS="${*:-$DEFAULT}"
exec > >(tee -a "$OUT/parity.log") 2>&1
echo "parity: seed $SEED, commit $(git rev-parse --short HEAD), experiments: $(echo $EXPS)"
make -s -C policy
nix --extra-experimental-features 'nix-command flakes' develop -c env EXPS="$EXPS" SEED="$SEED" OUT="$OUT" bash -c '
set -u -o pipefail
case " $EXPS " in *" E7"*)
  # Ollama on both families ([::]:11434 is dual-stack), so E7 runs over IPv4 or IPv6 (FACT_FAMILY)
  if ! curl -sg --max-time 3 "http://[::1]:11434/api/tags" > /dev/null; then
    pkill -x ollama 2>/dev/null && sleep 2   # -x: the command line of this script also contains "ollama serve"
    OLLAMA_HOST="[::]:11434" nohup ollama serve > /tmp/ollama.log 2>&1 &
    for i in $(seq 1 60); do curl -sg --max-time 2 "http://[::1]:11434/api/tags" > /dev/null && break; sleep 1; done
  fi
  ;;
esac
for e in $EXPS; do
  spec=$(python3 -c "import yaml; print(yaml.safe_load(open(\"workflow/config.yaml\"))[\"experiments\"][\"$e\"][\"spec\"])")
  for fam in 4 6; do
    echo "== $e IPv$fam $(date -u +%H:%M:%S)"
    python3 scripts/campaign.py --spec "$spec" --n 1 --seed "$SEED" --label pilot --family $fam \
      --campaigns-dir "$OUT/campaigns" | grep -v "^\[" || echo "CAMPAIGN FAILED $e IPv$fam"
  done
done
python3 -I analysis/collect_runs.py "$OUT/campaigns" --out "$OUT/runs.csv" || true
python3 -I analysis/compare_families.py "$OUT/campaigns" --out "$OUT/compare_families.json" \
  --runs-csv "$OUT/runs.csv" --recorded analysis/runs.csv --recorded-campaigns campaigns | tee "$OUT/compare_families.txt"
'
