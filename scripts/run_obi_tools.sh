#!/usr/bin/env bash
D=$(dirname "$0"); R=${1:-/tmp/obi_runs2}; rm -rf $R; mkdir -p $R
for rep in 1 2 3; do for k in 4 8; do
  echo "OBI mcp-sse thread K=$k rep=$rep $($D/obi_round.sh $R/thread-k$k-r$rep mcp-sse $k 25 $rep obi thread port)"
  echo "OBI mcp-sse subproc K=$k rep=$rep $($D/obi_round.sh $R/subproc-k$k-r$rep mcp-sse $k 25 $rep obi subproc exe)"
done; done
for t in thread subproc; do echo "CTRL mcp-sse $t K=4 $($D/obi_round.sh $R/ctrl-$t mcp-sse 4 25 1 none $t)"; done
chmod -R a+rX $R
