#!/usr/bin/env python3
"""Scores the live IPFIX export of factd (E8ipfix) against the independent reference.

Inputs of a run: ipfix.pcap (the UDP messages factd exported while the workload
ran, captured by tshark), factd_live.jsonl (factd's own records), plan.json,
events.jsonl (only for the reference: destination port of each planned
connection) and, with connection reuse, requests.jsonl (bytes per request).

The capture is decoded with Wireshark's IPFIX dissector (tshark -T pdml): the
messages must decode with no malformed-packet or expert error, and the fields of
each data record are read in template order (factd/ipfix.py). Per execution, the
IPFIX totals are compared with
  - factd's own records (the export must carry exactly what factd computed);
  - the reference: connections whose planned destination port belongs to the
    execution (dport_map) and, with reuse, the request and response bytes of the
    execution's requests (op_map + requests.jsonl byte ranges).
Accounting error = sum over executions of |IPFIX - reference| / sum of the reference.

Usage: score_ipfix.py RUN_DIR      -> RUN_DIR/ipfix_score.json
"""
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from score import load_jsonl  # noqa: E402


def decode_pcap(path):
    """Returns (records, n_messages, n_errors) from Wireshark's dissector."""
    xml = subprocess.run(["tshark", "-r", path, "-d", "udp.port==4739,cflow", "-T", "pdml"],
                         capture_output=True, text=True, check=True).stdout
    root = ET.fromstring(xml)
    recs, nmsg, nerr = [], 0, 0
    for pk in root.findall("packet"):
        nmsg += 1
        for f in pk.iter("field"):
            if f.get("name") in ("_ws.malformed", "_ws.expert") or f.get("name", "").startswith("_ws.expert"):
                nerr += 1
        for proto in pk.findall("proto"):
            if proto.get("name") != "cflow":
                continue
            fields = [(f.get("name"), f.get("value"), f.get("show")) for f in proto.iter("field")]
            set_id, cur, rows = None, [], []
            for n, v, show in fields:
                if n == "cflow.flowset_id":
                    if cur:
                        rows.append((set_id, cur))
                    set_id, cur = int(show), []
                elif n in ("cflow.abstimestart",):
                    if cur:
                        rows.append((set_id, cur))
                    cur = [(n, v)]
                elif n in ("cflow.abstimeend", "cflow.enterprise_private_entry", "cflow.flows",
                           "cflow.octets"):
                    cur.append((n, v))
            if cur:
                rows.append((set_id, cur))
            for sid, row in rows:
                vals = [v for n, v in row if n != "cflow.abstimestart" and n != "cflow.abstimeend"]
                if sid == 257 and len(vals) == 4:     # empty candidate set (unattributed)
                    vals.insert(1, "")
                if sid == 256 and len(vals) == 7:
                    recs.append({"type": "exec", "exec": bytes.fromhex(vals[0]).decode(),
                                 "connections": int(vals[1], 16), "established": int(vals[2], 16),
                                 "failed": int(vals[3], 16), "destinations": int(vals[4], 16),
                                 "octets_sent": int(vals[5], 16), "octets_received": int(vals[6], 16)})
                elif sid == 257 and len(vals) == 5:
                    recs.append({"type": "uncredited", "status": int(vals[0], 16),
                                 "candidates": bytes.fromhex(vals[1]).decode() if vals[1] else "",
                                 "connections": int(vals[2], 16), "octets_sent": int(vals[3], 16),
                                 "octets_received": int(vals[4], 16)})
                elif sid in (256, 257):
                    nerr += 1
    return recs, nmsg, nerr


def reference(rdir, plan):
    events, _ = load_jsonl(os.path.join(rdir, "events.jsonl"))
    ref = defaultdict(Counter)
    dmap = plan.get("dport_map") or {}
    for ev in events:
        if ev.get("ev") == "connect" and str(ev.get("dport")) in dmap:
            ref[dmap[str(ev["dport"])][0]]["connections"] += 1
    rq = os.path.join(rdir, "requests.jsonl")
    if os.path.exists(rq):
        reqs, _ = load_jsonl(rq)
        for r in reqs:
            e = plan["op_map"].get(r["path"].strip("/"))
            if e is not None:
                ref[e]["octets_sent"] += r["req"][1] - r["req"][0]
                ref[e]["octets_received"] += r["resp"][1] - r["resp"][0]
    return ref


def score(rdir):
    plan = json.load(open(os.path.join(rdir, "plan.json")))
    recs, nmsg, nerr = decode_pcap(os.path.join(rdir, "ipfix.pcap"))
    ip = defaultdict(Counter)
    unc = Counter()
    for r in recs:
        if r["type"] == "exec":
            for k in ("connections", "established", "failed", "octets_sent", "octets_received"):
                ip[r["exec"]][k] += r[k]
        else:
            for k in ("connections", "octets_sent", "octets_received"):
                unc[k] += r[k]
    live = [json.loads(x) for x in open(os.path.join(rdir, "factd_live.jsonl")) if x.startswith("{")]
    summ = next((x for x in live if x.get("type") == "summary"), {"exec": {}})
    ref = reference(rdir, plan)
    keys = ["connections"] + (["octets_sent", "octets_received"] if plan.get("op_map") else [])
    out = {"run": rdir, "tool": plan.get("tool"), "execs": plan.get("execs"), "messages": nmsg,
           "decode_errors": nerr, "records": len(recs)}
    for k in keys:
        tot_ref = sum(ref[e][k] for e in ref)
        err = sum(abs(ip[e][k] - ref[e][k]) for e in set(ref) | set(ip))
        out[k] = {"reference": tot_ref, "ipfix_credited": sum(ip[e][k] for e in ip),
                  "abs_error": err, "error_pct": round(100 * err / tot_ref, 4) if tot_ref else None,
                  "uncredited": unc[k]}
    out["ipfix_equals_factd"] = all(ip[e][k] == summ["exec"].get(e, {}).get(k, 0)
                                    for e in set(ip) | set(summ["exec"])
                                    for k in ("connections", "established", "failed",
                                              "octets_sent", "octets_received"))
    out["per_exec"] = {e: {k: [ip[e][k], ref[e][k]] for k in keys} for e in sorted(set(ref) | set(ip))}
    return out


def main():
    r = score(sys.argv[1])
    json.dump(r, open(os.path.join(sys.argv[1], "ipfix_score.json"), "w"), indent=1)
    print(json.dumps({k: v for k, v in r.items() if k not in ("per_exec", "run")}))


if __name__ == "__main__":
    main()
