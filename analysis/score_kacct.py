#!/usr/bin/env python3
"""Scores the per-credential accounting kept in the kernel (execution credential,
fact_policy with cred=1) against the destination's per-request reference.

The kernel charges, per credential, the bytes each send accepted (return value of
tcp_sendmsg/udp_sendmsg, charged to the sending task's credential) and the bytes
each receive returned (tcp_recvmsg, charged to the socket's last sender), for the
policed destinations; run_round.sh dumps these counters (cred_usage.json) before
the policy exits. The reference is the destination's log (requests.jsonl): for each
request, its path (the operation, mapped to its execution by plan.json op_map) and
the byte ranges of the request and of its response on the connection. Per
execution: kernel sent bytes vs. the sum of its requests, kernel received bytes vs.
the sum of its responses. No user-space event stream is involved.

Usage: score_kacct.py RUN_DIR      -> RUN_DIR/kacct_score.json
"""
import json
import os
import sys
from collections import Counter


def main(rd):
    plan = json.load(open(os.path.join(rd, "plan.json")))
    usage = json.load(open(os.path.join(rd, "cred_usage.json")))
    op_exec = plan["op_map"]
    ref_tx, ref_rx = Counter(), Counter()
    for line in open(os.path.join(rd, "requests.jsonl")):
        if not line.startswith("{"):
            continue
        r = json.loads(line)
        e = op_exec.get(r["path"].strip("/"))
        if e is None:
            continue
        ref_tx[e] += r["req"][1] - r["req"][0]
        ref_rx[e] += r["resp"][1] - r["resp"][0]
    execs = sorted(set(ref_tx) | set(ref_rx))
    per = {e: {"kernel_tx": usage.get(e, {}).get("bytes", 0), "ref_tx": ref_tx[e],
               "kernel_rx": usage.get(e, {}).get("rx_bytes", 0), "ref_rx": ref_rx[e]} for e in execs}
    other = {k: v for k, v in usage.items() if k not in per}
    tx_err = sum(abs(v["kernel_tx"] - v["ref_tx"]) for v in per.values())
    rx_err = sum(abs(v["kernel_rx"] - v["ref_rx"]) for v in per.values())
    res = {"execs": len(execs), "ref_tx": sum(ref_tx.values()), "ref_rx": sum(ref_rx.values()),
           "abs_err_tx": tx_err, "abs_err_rx": rx_err,
           "exact": tx_err == 0 and rx_err == 0 and not any(v.get("bytes") or v.get("rx_bytes") for v in other.values()),
           "other_credentials": other, "per_exec": per}
    json.dump(res, open(os.path.join(rd, "kacct_score.json"), "w"), indent=1)
    print(f"kacct: execs={len(execs)} tx={res['ref_tx']} rx={res['ref_rx']} "
          f"abs_err_tx={tx_err} abs_err_rx={rx_err} exact={res['exact']} other={len(other)}")


if __name__ == "__main__":
    main(sys.argv[1])
