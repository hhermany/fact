#!/usr/bin/env python3
"""Summarizes the coverage matrix (tests/coverage/run.sh). For every policy mode and address family:
each test's outcome as observed at the destination against the outcome the mode prescribes; the
bytes the kernel charged to each identity against the bytes the destination received from it (and,
with the credential, received bytes against what the client read); and, across families, whether
outcomes, charges, budget counters, policy decisions, and the events of each of the seven
collectors are the same once addresses and ports are normalized. Also the compilation of every
collector script. Usage: summarize.py RUN_DIR OUT_JSON"""
import collections
import json
import os
import re
import sys

d, out = sys.argv[1], sys.argv[2]
FAMS = {"v4": 62000, "v6": 62010, "v4mapped": 62020}
HOSTS = {"v4": {"127.0.0.1"}, "v6": {"::1"}, "v4mapped": {"::ffff:127.0.0.1", "127.0.0.1"}}
COLLECTORS = ["fact", "fact-fast", "fact-count", "fact-bytes", "fact-cred", "fact-udp", "fact-all"]
B_ON_A_SOCKET = {"B_send", "B_sendall", "B_sendto_connected", "B_sendmsg", "B_sendmmsg", "B_write", "B_writev",
                 "B_sendfile", "B_splice", "B_msg_zerocopy", "B_write_dup_fd", "B_udp_connected_send",
                 "U_B_send_inline", "U_B_send_async", "U_B_send_zc", "U_B_write", "U_B_write_async", "U_B_sendmsg"}



# Differences between families expected by design, reported separately and left out of the parity
# checks: none. (For an IPv4-mapped destination, udpv6_sendmsg hands even a connected send to
# udp_sendmsg with the destination in the message, so cgroup/sendmsg4 runs for it; the policy
# recognizes that case (fentry on udpv6_sendmsg) and, as on IPv4, does not decide it again.
# B_udp_connected_send and B_udp_sendto_peer_connected, on their own port base+3, test both cases.)
KNOWN = {}
PORT3_TAGS = {"A_udp3_connected_send_control", "B_udp_connected_send", "B_udp_sendto_peer_connected"}


def expected(mode, name, fam):
    """What the mode prescribes for a test of client.py / uring.c."""
    if (mode, fam, name) in KNOWN:
        return KNOWN[(mode, fam, name)]
    if name.startswith("N_"):
        return "blocked"                                   # no identity: default action (deny)
    if mode == "connect":                                  # connection-level authorization only
        if name.startswith(("A_", "U_A_")) or name in B_ON_A_SOCKET:
            return "delivered"                             # sends on sockets A opened are not re-checked
        return "blocked"                                   # B's new connections and datagrams are
    if name == "U_A_send_async_control":
        return "blocked"                                   # io-wq worker: no identity, default action
    if name.startswith(("A_", "U_A_")):
        return "delivered"
    if name.startswith("Q_conn_"):
        return "delivered" if int(name.rsplit("_", 1)[1]) <= 3 else "blocked"   # 3 connections
    if name.startswith("R_send_"):
        # 48-byte sends, allowed while fewer than 100 bytes were accepted: 0, 48, 96 -> 3 sends
        return "delivered" if int(name.rsplit("_", 1)[1]) <= 3 else "blocked"
    if name.startswith("S_sendto_"):
        # 48-byte datagrams under a 50-byte budget: 0, 48 -> 2 datagrams
        return "delivered" if int(name.rsplit("_", 1)[1]) <= 2 else "blocked"
    return "blocked"                                       # B, per send


def who(name):
    return name[2:].split("_", 1)[0] if name.startswith("U_") else name.split("_", 1)[0]


def norm_port(p, base):
    p = int(p)
    return p - base if base < p <= base + 9 else None


def collector_signature(path, base, skip=()):
    """Network events of the family's ports, without addresses, ports, times or ids."""
    sig, sks = collections.Counter(), set()
    evs = []
    for l in open(path, errors="replace"):
        if l.startswith("{"):
            try:
                evs.append(json.loads(l))
            except ValueError:
                pass
    for e in evs:
        if e.get("ev") in ("connect", "send", "recv") and "dport" in e:
            p = norm_port(e["dport"], base)
            if p is None or p in skip:
                continue
            if e["ev"] == "connect" and e.get("proto", "tcp") == "tcp":
                sks.add(e.get("sk"))
            sig[(e["ev"], e.get("proto", "tcp"), p, str(e.get("ctx", "")).rsplit("/", 1)[-1],
                 str(e.get("sk_ctx", "")).rsplit("/", 1)[-1], e.get("bytes"), e.get("req"))] += 1
    for e in evs:
        if e.get("ev") == "tcp_state" and e.get("sk") in sks:
            sig[("tcp_state", e.get("old"), e.get("new"))] += 1
    return sig


def count_signature(path):
    """fact-count.bt keeps only counters, printed at exit: @n[connect]: N."""
    c = {}
    for l in open(path, errors="replace"):
        m = re.match(r"@n\[(\w+)\]: (\d+)", l.strip())
        if m:
            c[m.group(1)] = int(m.group(2))
    return {k: c.get(k, 0) for k in ("connect", "tcp_state")}


res = {"modes": {}}
all_ok = True
for mode in ("persend", "connect", "cred", "budget"):
    per = {}
    for fam, base in FAMS.items():
        r = os.path.join(d, mode, fam)
        got = collections.defaultdict(list)
        for l in open(f"{r}/dest.jsonl"):
            x = json.loads(l)
            if x["tag"].startswith(fam + "/"):
                got[x["tag"][len(fam) + 1:]].append(x["n"])
        cl = json.load(open(f"{r}/client.json"))
        tests = list(cl["tests"])
        for l in open(f"{r}/uring.jsonl"):
            if l.startswith("{"):
                u = json.loads(l)
                tests.append({"test": u["test"], "ret": u["res"], "errno": 0 if u["res"] >= 0 else -u["res"]})
        rows = []
        for t in tests:
            seen = "delivered" if got.get(t["test"]) else "blocked"
            exp = expected(mode, t["test"], fam)
            rows.append({"test": t["test"], "errno": t["errno"], "expected": exp, "observed": seen,
                         "pass": exp == seen})
        usage = json.load(open(f"{r}/usage.json"))
        recv = collections.Counter()
        for name, ns in got.items():
            if "_async" not in name:   # io-wq work carries no identity: charged to nobody
                recv[who(name)] += sum(ns)
        charged = {k: v["bytes"] for k, v in usage.items() if v["bytes"]}
        skip = (3,) if any(k[0] == mode for k in KNOWN) else ()   # port of a KNOWN difference
        p3 = collections.Counter()                          # bytes of that port, left out of parity
        if skip:
            for name, ns in got.items():
                if name in PORT3_TAGS:
                    p3[who(name)] += sum(ns)
        usage_cmp = {k: dict(v, bytes=v["bytes"] - p3.get(k, 0)) for k, v in usage.items()}
        acct_ok = all(charged.get(k, 0) == recv.get(k, 0) for k in set(charged) | set(recv) if k != "N")
        rx_ok = True
        if mode == "cred":
            rx_ok = usage.get("A", {}).get("rx_bytes") == cl["rx_read"]["A"] and cl["rx_read"]["A"] > 0
        dec = collections.Counter()
        daddrs = set()
        for l in open(f"{r}/decisions.jsonl"):
            if l.startswith('{"ev":"decision"'):
                x = json.loads(l)
                p = norm_port(x["dport"], base)
                if p is None or p in skip:
                    continue
                dec[(x["kind"], x["verdict"], x["ctx"], p, x["budget"])] += 1
                daddrs.add(x["daddr"])
        daddr_ok = daddrs <= HOSTS[fam]
        sigs = {c: collector_signature(f"{r}/events-{c}.jsonl", base, skip) for c in COLLECTORS if c != "fact-count"}
        cnt = count_signature(f"{r}/events-fact-count.jsonl")
        per[fam] = {"tests": rows, "pass": all(x["pass"] for x in rows), "charged": charged,
                    "received": dict(recv), "accounting_exact": acct_ok, "rx_exact": rx_ok,
                    "usage": usage, "_usage_cmp": usage_cmp, "decision_daddrs": sorted(daddrs), "decision_daddr_ok": daddr_ok,
                    "_dec": dec, "_sigs": sigs, "fact_count": cnt}
    # parity across families
    ref = per["v4"]
    outcome = {f: {x["test"]: x["observed"] for x in per[f]["tests"]
                   if (mode, "v4mapped", x["test"]) not in KNOWN} for f in FAMS}
    parity = {
        "outcomes": all(outcome[f] == outcome["v4"] for f in FAMS),
        "usage_counters": all(per[f]["_usage_cmp"] == ref["_usage_cmp"] for f in FAMS),
        "decisions": all(per[f]["_dec"] == ref["_dec"] for f in FAMS),
        "collectors": {c: all(per[f]["_sigs"][c] == ref["_sigs"][c] for f in FAMS) for c in COLLECTORS if c != "fact-count"},
        "fact_count": all(per[f]["fact_count"] == ref["fact_count"] for f in FAMS),
    }
    nonempty = {c: sum(ref["_sigs"][c].values()) for c in ref["_sigs"]}
    mode_ok = (all(per[f]["pass"] and per[f]["accounting_exact"] and per[f]["rx_exact"] and per[f]["decision_daddr_ok"]
                   for f in FAMS)
               and parity["outcomes"] and parity["usage_counters"] and parity["decisions"]
               and all(parity["collectors"].values()) and parity["fact_count"]
               and all(n > 0 for c, n in nonempty.items() if c != "fact-cred" or mode == "cred"))
    all_ok &= mode_ok
    for f in FAMS:
        per[f]["collector_events"] = {c: sum(per[f]["_sigs"][c].values()) for c in per[f]["_sigs"]}
        per[f]["decisions"] = sum(per[f]["_dec"].values())
        del per[f]["_dec"], per[f]["_sigs"], per[f]["_usage_cmp"]
    known = {f"{m}/{f}/{n}": {"expected": e, "observed": next((x["observed"] for x in per[f]["tests"] if x["test"] == n), None)}
             for (m, f, n), e in KNOWN.items() if m == mode}
    res["modes"][mode] = {"pass": mode_ok, "parity": parity, "known_family_difference": known, "families": per}
dry = {}
for l in open(f"{d}/dryrun.txt"):
    p = l.split()
    if len(p) == 2 and p[0].startswith("collector/"):
        dry[p[0]] = int(p[1])
res["collector_dry_run_rc"] = dry
res["all_pass"] = all_ok and all(v == 0 for v in dry.values())
json.dump(res, open(out, "w"), indent=1)
for m, v in res["modes"].items():
    fams = v["families"]
    print(f"coverage {m}: pass={v['pass']} parity={json.dumps(v['parity'])} "
          + " ".join(f"{f}:tests={len(x['tests'])},ok={x['pass']},acct={x['accounting_exact']},rx={x['rx_exact']},"
                     f"daddr={x['decision_daddrs']}" for f, x in fams.items()))
print(f"coverage: all_pass={res['all_pass']} dry_run={dry}")
