#!/usr/bin/env bash
# Assembles every campaign in one working directory: those in campaigns/ and those
# archived as .tar.gz (in campaigns/ and in the given directories).
# Usage: scripts/extract_campaigns.sh DEST [DIR_WITH_TAR_GZ ...]
# E.g.:  scripts/extract_campaigns.sh /tmp/all ~/raw-data
#        python3 -I analysis/collect_runs.py /tmp/all --out analysis/runs.csv \
#            --exclude-experiments E5f,E6f,E6n,E6L,E6Ls,E7f
#        python3 -I analysis/collect_overhead.py /tmp/all --out analysis/overhead.csv
# The raw-data .tar.gz archives come with SHA256SUMS; check with `sha256sum -c SHA256SUMS`.
set -euo pipefail
OUT=${1:?usage: extract_campaigns.sh DEST [DIR_WITH_TAR_GZ ...]}; shift
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
echo "$(ls "$OUT" | wc -l) campaigns in $OUT"
