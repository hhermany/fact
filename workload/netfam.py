"""Address family of the experiments.

FACT_FAMILY=6 runs a workload over IPv6 (loopback ::1); any other value, or none,
runs it over IPv4 (loopback 127.0.0.1), as in the recorded campaigns. The family
of a socket follows the literal address it is used with, so a destination given
explicitly (--dest-host) decides it as well.
"""
import os
import socket

FAMILY = 6 if os.environ.get("FACT_FAMILY") == "6" else 4
LOOPBACK = "::1" if FAMILY == 6 else "127.0.0.1"
ANY = "::" if FAMILY == 6 else "0.0.0.0"


def af(host):
    """Socket family for a literal address."""
    return socket.AF_INET6 if ":" in str(host) else socket.AF_INET


def url_host(host):
    """Host part of a URL or of a HOST:PORT string (IPv6 literals in brackets)."""
    return f"[{host}]" if ":" in str(host) else str(host)


def split_hostport(s):
    """'127.0.0.1:4739' or '[::1]:4739' -> (host, port)."""
    host, port = s.rsplit(":", 1)
    return host.strip("[]"), int(port)


# Code run with python -c in a child process: the family follows the address in argv[1].
SOCKET_FOR_ARGV1 = "socket.socket(socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET)"
