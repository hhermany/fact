#!/usr/bin/env python3
"""Round trip of factd's IPFIX encoder (factd/ipfix.py): records encoded into one
message decode to the same values; the message length and set lengths are valid."""
import os
import socket
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "factd"))
import ipfix  # noqa: E402


def round_trip(host):
    rx = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind((host, 0))
    ex = ipfix.Exporter(f"[{host}]" if ":" in host else host, rx.getsockname()[1])
    ex.send([ipfix.encode_exec(1, 2, "E01", 5, 4, 1, 3, 1000, 2000),
             ipfix.encode_exec(1, 2, "x" * 300, 1, 1, 0, 1, 0, 0)],
            [ipfix.encode_unc(1, 2, "ambiguous", "E01|E02", 2, 10, 20),
             ipfix.encode_unc(1, 2, "unattributed", "", 1, 0, 0)])
    recs = ipfix.decode(rx.recv(65535))
    assert [r["exec"] for r in recs if r["type"] == "exec"] == ["E01", "x" * 300], recs
    e = recs[0]
    assert (e["connections"], e["established"], e["failed"], e["destinations"],
            e["octets_sent"], e["octets_received"]) == (5, 4, 1, 3, 1000, 2000), e
    u = [r for r in recs if r["type"] == "uncredited"]
    assert (u[0]["status"], u[0]["candidates"], u[0]["octets_received"]) == (2, "E01|E02", 20), u
    assert (u[1]["status"], u[1]["candidates"]) == (3, ""), u
    assert ex.seq == 4


def main():
    """Over IPv4 and IPv6 (export to 127.0.0.1 and to [::1])."""
    for host in ("127.0.0.1", "::1"):
        try:
            round_trip(host)
        except OSError as e:
            if host == "::1" and e.errno == 97:   # EAFNOSUPPORT: the host has no IPv6
                print("ipfix round trip (::1): SKIPPED, no IPv6 on this host")
                continue
            raise
        print(f"ipfix round trip ({host}): OK")


if __name__ == "__main__":
    main()
