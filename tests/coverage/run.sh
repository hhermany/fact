#!/usr/bin/env bash
# Directed coverage test of the egress hooks (per-send authorization, IPv4 and IPv6).
# Execution A may reach ports 62001-62003; execution B may not. A opens TCP and UDP sockets,
# then B tries every send path we know of: send/sendall/sendto/sendmsg/sendmmsg, write/writev,
# sendfile, splice, MSG_ZEROCOPY, a duplicated fd, UDP connected and unconnected, new connects,
# IPv6 and IPv4-mapped addresses, and io_uring (inline and forced to the io-wq worker). The
# destination (outside the policed cgroup) logs every tag it receives; the kernel's usage map
# shows what each identity was charged; the collector (fact-all.bt) runs alongside, and every
# collector script is compiled (bpftrace --dry-run).
# Usage, as root from the repository root (needs the BPF LSM and liburing for io_uring):
#   sudo env "PATH=$PATH" bash tests/coverage/run.sh [OUT_DIR]
set -u
R=$(pwd); T=$R/tests/coverage; O=${1:-/tmp/fact-coverage}; CG=/sys/fs/cgroup/fact_coverage
mkdir -p $O $CG
make -s -C policy
if [ ! -x $O/uring ]; then
  D=$(nix --extra-experimental-features 'nix-command flakes' build --no-link --print-out-paths nixpkgs#liburing.dev | tail -1)
  L=$(nix --extra-experimental-features 'nix-command flakes' build --no-link --print-out-paths nixpkgs#liburing.out | tail -1)
  gcc -O1 -I$D/include $T/uring.c -L$L/lib -luring -Wl,-rpath,$L/lib -o $O/uring
fi
: > $O/dryrun.txt
for f in collector/*.bt; do bpftrace --dry-run $f > /dev/null 2>> $O/dryrun.txt; echo "$f $?" >> $O/dryrun.txt; done
: > $O/dest.jsonl
python3 -I $T/dest.py $O/dest.jsonl > $O/dest.out 2>&1 & DP=$!
policy/fact_policy $CG 62000 62010 0 policy/fact_policy.bpf.o 0 1 2 0 > $O/decisions.jsonl 2> $O/policy.err & PP=$!
bpftrace collector/fact-all.bt > $O/events.jsonl 2> $O/collector.err & BP=$!
for i in $(seq 1 100); do grep -q ready $O/decisions.jsonl 2>/dev/null && grep -q ready $O/dest.out 2>/dev/null \
  && grep -q '"ready"' $O/events.jsonl 2>/dev/null && break; sleep 0.2; done
python3 -c "import sys; sys.path.insert(0,'policy'); import policyctl; policyctl.load_dict({'A':[62001,62002,62003]}); policyctl.load_budgets({'A':{'bytes':10**9},'B':{'bytes':10**9}})"
sh -c "echo \$\$ > $CG/cgroup.procs; exec python3 -I $T/client.py $O/client.json"
sh -c "echo \$\$ > $CG/cgroup.procs; exec $O/uring" > $O/uring.jsonl 2> $O/uring.err
sleep 0.5
python3 -c "import sys,json; sys.path.insert(0,'policy'); import policyctl; print(json.dumps(policyctl.usage()))" > $O/usage.json
kill -INT $BP; kill $PP $DP; wait $PP $BP 2>/dev/null; rmdir $CG 2>/dev/null
python3 -I $T/summarize.py $O analysis/output/coverage_test.json
[ -n "${SUDO_UID:-}" ] && chown -R $SUDO_UID:$SUDO_GID $O analysis/output/coverage_test.json
