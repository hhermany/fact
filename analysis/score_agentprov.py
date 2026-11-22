#!/usr/bin/env python3
"""Scores AgentProvenance's real attribution on one round against the reference.

Reference: plan.json (destination port -> execution, op). AgentProvenance output:
agentprov/events.json (its telemetry events, each with the tool call its own
correlation engine assigned, or none). For every planned connection we look up
AgentProvenance's connect event to that port on the destination host and take
the execution of the tool call it was attributed to.

C: attributed to the right execution; I: to another execution; A: reported as
ambiguous by AgentProvenance; M: no event, or event left uncorrelated.
Writes agentprov/score.json and prints a one-line summary.
"""
import collections
import json
import os
import sys

PORT_KEYS = ("dport", "dst_port", "remote_port", "daddr_port", "port", "peer_port", "destination_port")


def find_port(obj):
    """Destination port in the event payload (searches nested dicts)."""
    if isinstance(obj, dict):
        for k in PORT_KEYS:
            v = obj.get(k)
            if isinstance(v, (int, str)) and str(v).isdigit():
                return int(v)
        for k in ("payload", "raw", "remote", "dst", "destination", "peer", "addr", "network"):
            if k in obj:
                p = find_port(obj[k])
                if p is not None:
                    return p
        for k in ("remote_addr", "dst_addr", "destination", "addr", "address", "sockaddr"):
            v = obj.get(k)
            if isinstance(v, str) and ":" in v and v.rsplit(":", 1)[1].isdigit():
                return int(v.rsplit(":", 1)[1])
    return None


def main():
    rdir = sys.argv[1]
    plan = json.load(open(os.path.join(rdir, "plan.json")))
    ref = {int(p): v for p, v in plan["dport_map"].items()}
    # AgentProvenance writes "events": null when it observed nothing (e.g., in-process IPv6
    # connections, which it does not capture): no events, every operation scored as such
    ev = json.load(open(os.path.join(rdir, "agentprov", "events.json")))["events"] or []
    ops = {json.loads(l)["op_id"]: json.loads(l)["exec_id"] for l in open(os.path.join(rdir, "ops.jsonl"))}
    by_port = collections.defaultdict(list)
    types = collections.Counter(e["event_type"] for e in ev)
    for e in ev:
        try:
            payload = json.loads(e.get("payload") or "{}")
        except ValueError:
            payload = {}
        p = find_port(payload)
        if p in ref:
            by_port[p].append(e)
    res = collections.Counter()
    detail = []
    for port, (exec_true, op_true) in sorted(ref.items()):
        cands = by_port.get(port, [])
        # one connect per planned port; if the sensor emitted several events for it
        # (e.g. connect + state change), any attributed one counts
        tcs = {e["tool_call_id"] for e in cands if e.get("tool_call_id")}
        classes = {e.get("correlation_class") for e in cands}
        if not cands:
            k, got = "M", None
        elif len(tcs) > 1:
            k, got = "A", sorted(tcs)
        elif tcs:
            got = tcs.pop()
            k = "C" if ops.get(got) == exec_true else "I"
        elif "ambiguous" in classes:
            k, got = "A", None
        else:
            k, got = "M", None
        res[k] += 1
        detail.append({"dport": port, "exec": exec_true, "op": op_true, "class": k, "tool_call": got,
                       "methods": sorted({e.get("correlation_method") for e in cands})})
    n = len(ref)
    out = {"N": n, **{x: res[x] for x in "CIAM"}, "C_N": res["C"] / n if n else None,
           "event_types": dict(types), "events_total": len(ev), "events_matched_ports": len(by_port),
           "same_op": sum(d["tool_call"] == d["op"] for d in detail)}
    json.dump({"summary": out, "detail": detail}, open(os.path.join(rdir, "agentprov", "score.json"), "w"), indent=1)
    print(json.dumps(out))


if __name__ == "__main__":
    main()
