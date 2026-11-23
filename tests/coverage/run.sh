#!/usr/bin/env bash
# Directed coverage test of the egress hooks, as a parity matrix over address families.
# For each policy mode and each family (IPv4, IPv6, IPv4-mapped IPv6, each on its own ports), a
# fresh policy and all seven collectors run while client.py and uring.c execute the same battery:
# execution A opens TCP and UDP sockets, then B tries every send path we know of (send/sendall/
# sendto/sendmsg/sendmmsg, write/writev, sendfile, splice, MSG_ZEROCOPY, a duplicated fd, UDP
# connected and unconnected, new connects, a TCP send with a decoy address, and io_uring inline and
# forced to the io-wq worker), A
# sends again, and a connection without identity follows. Modes:
#   persend  markers, per-send authorization (LSM), usage counted
#   connect  markers, connection-level authorization only, usage counted
#   cred     execution credential (prctl), per-send authorization, sent and received bytes counted
#   budget   markers, per-send authorization, budgets enforced (connections, TCP bytes, datagram bytes;
#            over IPv4 also datagrams addressed with family AF_UNSPEC, which udp_sendmsg accepts)
# The destination (outside the policed cgroup) logs every tag it receives; the kernel's usage map
# shows what each identity was charged; summarize.py checks each mode's expected outcomes and that
# every family gives the same outcomes, charges, and collector events. Every collector script is
# also compiled (bpftrace --dry-run).
# Usage, as root from the repository root (needs the BPF LSM, IPv6 on lo, and liburing):
#   sudo env "PATH=$PATH" bash tests/coverage/run.sh [OUT_DIR]
set -u
R=$(pwd); T=$R/tests/coverage; O=${1:-/tmp/fact-coverage}; CG=/sys/fs/cgroup/fact_coverage
COLLECTORS="fact fact-fast fact-count fact-bytes fact-cred fact-udp fact-all"
mkdir -p $O $CG
make -s -C policy
if [ ! -x $O/uring ] || [ $T/uring.c -nt $O/uring ]; then
  D=$(nix --extra-experimental-features 'nix-command flakes' build --no-link --print-out-paths nixpkgs#liburing.dev | tail -1)
  L=$(nix --extra-experimental-features 'nix-command flakes' build --no-link --print-out-paths nixpkgs#liburing.out | tail -1)
  gcc -O1 -I$D/include $T/uring.c -L$L/lib -luring -Wl,-rpath,$L/lib -o $O/uring
fi
: > $O/dryrun.txt
for f in collector/*.bt; do bpftrace --dry-run $f > /dev/null 2>> $O/dryrun.txt; echo "$f $?" >> $O/dryrun.txt; done
POLICED="[62001,62002,62003,62004,62011,62012,62013,62014,62021,62022,62023,62024]"
for MODE in persend connect cred budget; do
  case $MODE in
    persend) ARGS="0 1 2 0";;   # lineage per_send budget cred
    connect) ARGS="0 0 2 0";;
    cred)    ARGS="0 1 2 1";;
    budget)  ARGS="0 1 1 0";;
  esac
  IFACE=markers; [ $MODE = cred ] && IFACE=cred
  for FAM in v4 v6 v4mapped; do
    D=$O/$MODE/$FAM; mkdir -p $D; rm -f $D/*.jsonl $D/*.json
    case $FAM in v4) H=127.0.0.1; P=62001;; v6) H=::1; P=62011;; v4mapped) H=::ffff:127.0.0.1; P=62021;; esac
    : > $D/dest.jsonl
    python3 -I $T/dest.py $D/dest.jsonl > $D/dest.out 2>&1 & DP=$!
    policy/fact_policy $CG 62000 62030 0 policy/fact_policy.bpf.o $ARGS > $D/decisions.jsonl 2> $D/policy.err & PP=$!
    BPS=""
    for c in $COLLECTORS; do bpftrace collector/$c.bt > $D/events-$c.jsonl 2> $D/collector-$c.err & BPS="$BPS $!"; done
    for i in $(seq 1 300); do
      n=0; for c in $COLLECTORS; do grep -q '"ready"' $D/events-$c.jsonl 2>/dev/null && n=$((n+1)); done
      grep -q ready $D/decisions.jsonl 2>/dev/null && grep -q ready $D/dest.out 2>/dev/null && [ $n = 7 ] && break
      sleep 0.2
    done
    python3 -c "import sys; sys.path.insert(0,'policy'); import policyctl; p=$POLICED; \
policyctl.load_dict({'A':p,'Q':p,'R':p,'S':p,'V':p,'W':p}); \
policyctl.load_budgets({'A':{'bytes':10**9},'B':{'bytes':10**9},'Q':{'conns':3},'R':{'bytes':100},'S':{'bytes':50},'V':{'bytes':100},'W':{'bytes':50}})"
    sh -c "echo \$\$ > $CG/cgroup.procs; exec python3 -I $T/client.py $D/client.json $FAM $MODE"
    sh -c "echo \$\$ > $CG/cgroup.procs; exec $O/uring $FAM $H $P $IFACE" > $D/uring.jsonl 2> $D/uring.err
    sleep 0.5
    python3 -c "import sys,json; sys.path.insert(0,'policy'); import policyctl; print(json.dumps(policyctl.usage()))" > $D/usage.json
    kill -INT $BPS; kill $PP $DP; wait $PP $BPS 2>/dev/null
    echo "phase $MODE $FAM done"
  done
done
rmdir $CG 2>/dev/null
python3 -I $T/summarize.py $O analysis/output/coverage_test.json
[ -n "${SUDO_UID:-}" ] && chown -R $SUDO_UID:$SUDO_GID $O analysis/output/coverage_test.json
