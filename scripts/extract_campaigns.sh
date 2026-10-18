#!/usr/bin/env bash
# Monta, num diretório de trabalho, todas as campanhas: as que estão em campaigns/
# e as arquivadas em .tar.gz (em campaigns/ e nos diretórios dados).
# Uso: scripts/extract_campaigns.sh DESTINO [DIR_COM_TAR_GZ ...]
# Ex.: scripts/extract_campaigns.sh /tmp/todas ~/noms-brutos
#      python3 -I analysis/collect_runs.py /tmp/todas --out analysis/runs.csv \
#          --exclude-experiments E5f,E6f,E6n,E6L,E6Ls,E7f
#      python3 -I analysis/collect_overhead.py /tmp/todas --out analysis/overhead.csv
# Os .tar.gz de dados brutos têm SHA256SUMS; confira com `sha256sum -c SHA256SUMS`.
set -euo pipefail
OUT=${1:?uso: extract_campaigns.sh DESTINO [DIR_COM_TAR_GZ ...]}; shift
mkdir -p "$OUT"
for src in campaigns "$@"; do
  for t in "$src"/*.tar.gz; do
    [ -e "$t" ] || continue
    tar xzf "$t" -C "$OUT"
  done
done
for d in campaigns/*/; do
  n=$(basename "$d")
  [ -e "$OUT/$n" ] || cp -r "$d" "$OUT/"
done
echo "$(ls "$OUT" | wc -l) campanhas em $OUT"
