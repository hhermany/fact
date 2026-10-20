"""Minimal IPFIX (RFC 7011) exporter for factd's per-execution records.

Two templates, resent in every message (IPFIX over UDP, RFC 7011 Sec. 8.4):

  256  credited traffic of one execution in one interval
       flowStartMilliseconds (152), flowEndMilliseconds (153),
       executionId (PEN 32473, 1; string, variable length),
       observedFlowTotalCount (163): connections opened,
       established (PEN 32473, 2), failed (PEN 32473, 3),
       distinctDestinations (PEN 32473, 4),
       octetDeltaCount (1): bytes sent,
       reverseOctetDeltaCount (PEN 29305, 1; RFC 5103): bytes received
  257  traffic NOT credited to any execution in one interval, per candidate set
       flowStartMilliseconds, flowEndMilliseconds,
       attributionStatus (PEN 32473, 5; 2 = ambiguous, 3 = unattributed),
       candidateSet (PEN 32473, 6; string "E01|E02", empty when unattributed),
       observedFlowTotalCount, octetDeltaCount, reverseOctetDeltaCount

PEN 32473 is the IANA enterprise number reserved for documentation (RFC 5612),
used here for FACT's own information elements; PEN 29305 is the reverse
information element space of RFC 5103.
"""
import socket
import struct
import time

PEN_FACT = 32473
PEN_REVERSE = 29305
VARLEN = 0xFFFF
T_EXEC, T_UNC = 256, 257
STATUS = {"ambiguous": 2, "unattributed": 3}

# (ie id, length, pen or None)
FIELDS_EXEC = [(152, 8, None), (153, 8, None), (1, VARLEN, PEN_FACT), (163, 8, None),
               (2, 8, PEN_FACT), (3, 8, PEN_FACT), (4, 8, PEN_FACT), (1, 8, None), (1, 8, PEN_REVERSE)]
FIELDS_UNC = [(152, 8, None), (153, 8, None), (5, 1, PEN_FACT), (6, VARLEN, PEN_FACT), (163, 8, None),
              (1, 8, None), (1, 8, PEN_REVERSE)]


def _template(tid, fields):
    out = struct.pack("!HH", tid, len(fields))
    for ie, ln, pen in fields:
        if pen is None:
            out += struct.pack("!HH", ie, ln)
        else:
            out += struct.pack("!HHI", ie | 0x8000, ln, pen)
    return out


def _set(set_id, body):
    pad = (-len(body)) % 4
    return struct.pack("!HH", set_id, 4 + len(body) + pad) + body + b"\0" * pad


def _varlen(s):
    b = s.encode()
    if len(b) < 255:
        return struct.pack("!B", len(b)) + b
    return struct.pack("!BH", 255, len(b)) + b


TEMPLATES = _set(2, _template(T_EXEC, FIELDS_EXEC) + _template(T_UNC, FIELDS_UNC))


def encode_exec(t0_ms, t1_ms, exec_id, conns, est, failed, dests, sent, recv):
    return (struct.pack("!QQ", t0_ms, t1_ms) + _varlen(exec_id)
            + struct.pack("!QQQQQQ", conns, est, failed, dests, sent, recv))


def encode_unc(t0_ms, t1_ms, status, cand, conns, sent, recv):
    return (struct.pack("!QQB", t0_ms, t1_ms, STATUS[status]) + _varlen(cand)
            + struct.pack("!QQQ", conns, sent, recv))


class Exporter:
    def __init__(self, host, port, domain=1):
        self.addr = (host, int(port))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.domain = domain
        self.seq = 0            # data records sent before this message (RFC 7011 Sec. 3.1)
        self.messages = 0

    def send(self, exec_records, unc_records):
        """exec_records / unc_records: lists of encoded data records."""
        body = TEMPLATES
        if exec_records:
            body += _set(T_EXEC, b"".join(exec_records))
        if unc_records:
            body += _set(T_UNC, b"".join(unc_records))
        hdr = struct.pack("!HHIII", 10, 16 + len(body), int(time.time()), self.seq, self.domain)
        self.sock.sendto(hdr + body, self.addr)
        self.seq += len(exec_records) + len(unc_records)
        self.messages += 1


def decode(msg):
    """Decodes one message produced by Exporter (used by the tests; the evaluation
    decodes with Wireshark's IPFIX dissector, analysis/score_ipfix.py)."""
    ver, ln, _t, _seq, _dom = struct.unpack("!HHIII", msg[:16])
    assert ver == 10 and ln == len(msg)
    off, out = 16, []
    while off < ln:
        sid, slen = struct.unpack("!HH", msg[off:off + 4])
        body, off = msg[off + 4:off + slen], off + slen
        if sid not in (T_EXEC, T_UNC):
            continue
        p = 0
        while p + 17 <= len(body):
            t0, t1 = struct.unpack("!QQ", body[p:p + 16])
            p += 16
            if sid == T_UNC:
                st = body[p]
                p += 1
            n = body[p]
            p += 1
            if n == 255:
                n = struct.unpack("!H", body[p:p + 2])[0]
                p += 2
            s = body[p:p + n].decode()
            p += n
            if sid == T_EXEC:
                vals = struct.unpack("!QQQQQQ", body[p:p + 48])
                p += 48
                out.append({"type": "exec", "t0": t0, "t1": t1, "exec": s, "connections": vals[0],
                            "established": vals[1], "failed": vals[2], "destinations": vals[3],
                            "octets_sent": vals[4], "octets_received": vals[5]})
            else:
                vals = struct.unpack("!QQQ", body[p:p + 24])
                p += 24
                out.append({"type": "uncredited", "t0": t0, "t1": t1, "status": st, "candidates": s,
                            "connections": vals[0], "octets_sent": vals[1], "octets_received": vals[2]})
    return out
