#!/usr/bin/env bash
# OBI association campaign: modes x K x 3 repetitions, OBI on; plus controls without OBI. Root, in nix develop.
D=$(dirname "$0"); R=${1:-/tmp/obi_runs}; rm -rf $R; mkdir -p $R
for rep in 1 2 3; do for m in direct mcp-sse; do for k in 4 8; do
  echo "OBI $m K=$k rep=$rep $($D/obi_round.sh $R/obi-$m-k$k-r$rep $m $k 25 $rep obi)"
done; done; done
for m in direct mcp-sse; do echo "CTRL $m K=4 $($D/obi_round.sh $R/ctrl-$m $m 4 25 1 none)"; done
chmod -R a+rX $R
