#!/usr/bin/env python3
"""Summarizes the confirmatory campaigns of the kernel-held execution credential
(E3cred, E6cred, E6reusecred, E6spoofcred, E11file) from the per-run score files.

Writes analysis/output/kcred_summary.json and, for the paper, a LaTeX file of macros
(\\KcConnAdd, \\KcConnAddMk, \\KcOpenAdd, \\KcOpenAddMk, \\KcRows and the counts).

Usage: kcred_tables.py CAMPAIGNS_DIR OUT_TEX
"""
import glob
import json
import os
import statistics
import sys
from collections import Counter

EXPS = ("E3cred", "E6cred", "E6reusecred", "E6spoofcred", "E11file")


def campaigns(cdir, exp):
    out = []
    for m in sorted(glob.glob(os.path.join(cdir, f"*-{exp}-confirmatory-*", "manifest.json"))):
        man = json.load(open(m))
        if man["experiment"] == exp and man["runs_failed"] == 0:
            out.append((os.path.dirname(m), man))
    return out


def runs(cdir, exp):
    for cd, man in campaigns(cdir, exp):
        for r in man["runs"]:
            yield os.path.join(cd, "runs", r["run_id"]), r["params"], man["environment"]["boot_id"]


def load(path):
    return json.load(open(path)) if os.path.exists(path) else None


def fmt(n):
    return f"{n:,}".replace(",", "\\,")


def main(cdir, out_tex):
    s = {}
    # E6cred: attribution (fused resolver) and egress decisions
    c, p, nr, boots = Counter(), Counter(), 0, set()
    for rd, prm, boot in runs(cdir, "E6cred"):
        nr += 1; boots.add(boot)
        f = load(os.path.join(rd, "score.json"))["resolvers"]["fused"]
        c.update({k: f[k] for k in ("N", "C", "A", "M", "I")})
        p.update({k: v for k, v in load(os.path.join(rd, "policy_score.json")).items() if k in ("N", "TA", "TD", "FA", "FD", "ND")})
    s["E6cred"] = {"runs": nr, "boots": len(boots), "attr": dict(c), "policy": dict(p)}
    # E6reusecred: per-send policy on reused connections and in-kernel accounting
    p, nr, exact, tx, rx, boots = Counter(), 0, 0, 0, 0, set()
    for rd, prm, boot in runs(cdir, "E6reusecred"):
        nr += 1; boots.add(boot)
        p.update({k: v for k, v in load(os.path.join(rd, "policy_score.json")).items() if k in ("N", "TA", "TD", "FA", "FD")})
        k = load(os.path.join(rd, "kacct_score.json"))
        exact += bool(k["exact"]); tx += k["ref_tx"]; rx += k["ref_rx"]
    s["E6reusecred"] = {"runs": nr, "boots": len(boots), "policy": dict(p), "kacct_exact_runs": exact,
                        "bytes_tx": tx, "bytes_rx": rx}
    # E6spoofcred: a tool's child switches to a permissive credential, trust off/on
    by = {0: Counter(), 1: Counter()}
    nr, boots = 0, set()
    for rd, prm, boot in runs(cdir, "E6spoofcred"):
        nr += 1; boots.add(boot)
        t = int(prm["trust"])
        by[t].update({k: v for k, v in load(os.path.join(rd, "policy_score.json")).items() if k in ("N", "FA", "FD", "ND")})
        by[t]["refused"] += sum(1 for l in open(os.path.join(rd, "events.jsonl")) if '"ev":"switch_refused"' in l)
        by[t]["runs"] += 1
    s["E6spoofcred"] = {"runs": nr, "boots": len(boots), "trust": {str(k): dict(v) for k, v in by.items()}}
    # E11file: bytes written per credential vs. what the writes returned
    nr, exact, total, err, boots = 0, 0, 0, 0, set()
    for rd, prm, boot in runs(cdir, "E11file"):
        nr += 1; boots.add(boot)
        f = load(os.path.join(rd, "file_score.json"))
        exact += f["abs_err"] == 0 and f["other_credentials_bytes"] == 0; total += f["bytes_ref"]; err += f["abs_err"]
    s["E11file"] = {"runs": nr, "boots": len(boots), "exact_runs": exact, "bytes": total, "abs_err": err}
    # E3cred: medians over runs of the per-run median latencies
    lat = {}
    nr, boots = 0, set()
    for rd, prm, boot in runs(cdir, "E3cred"):
        nr += 1; boots.add(boot)
        o = load(os.path.join(rd, "overhead.json"))
        lat.setdefault(o["iface"], {"connect": [], "open": []})
        lat[o["iface"]]["connect"].append(o["connect"]["p50_ns"]); lat[o["iface"]]["open"].append(o["open"]["p50_ns"])
    med = {i: {k: statistics.median(v) for k, v in d.items()} for i, d in lat.items()}
    s["E3cred"] = {"runs": nr, "boots": len(boots), "median_ns": med}
    os.makedirs("analysis/output", exist_ok=True)
    json.dump(s, open("analysis/output/kcred_summary.json", "w"), indent=1)

    m = s["E3cred"]["median_ns"]
    add = lambda i, k: (m[i][k] - m["none"][k]) / 1000.0
    a, pol = s["E6cred"]["attr"], s["E6cred"]["policy"]
    rp, sp = s["E6reusecred"], s["E6spoofcred"]["trust"]
    forb = rp["policy"]["TD"] + rp["policy"]["FA"]
    off, on = sp["0"], sp["1"]
    fl = s["E11file"]
    rows = [
        f"Attribution (E6cred) & wrong / connections & {a['I']} / {fmt(a['N'])} \\\\",
        f"Egress decisions (E6cred) & wrong / decisions & {pol['FA'] + pol['FD'] + pol['ND']} / {fmt(pol['N'])} \\\\",
        f"Forbidden reuse (E6reusecred) & passed / forbidden requests & {rp['policy']['FA']} / {fmt(forb)} \\\\",
        f"Permitted requests (E6reusecred) & denied / permitted & {rp['policy']['FD']} / {fmt(rp['policy']['TA'] + rp['policy']['FD'])} \\\\",
        f"Kernel bytes vs.\\ destination & exact runs (sent+recv.) & {rp['kacct_exact_runs']}/{rp['runs']} ({(rp['bytes_tx'] + rp['bytes_rx']) / 1e6:.1f}\\,MB) \\\\",
        f"Child switch (E6spoofcred) & bypass, no trust / trust & {100 * off['FA'] / off['N']:.0f}\\% / {on['FA']} ({fmt(on['refused'])} refused) \\\\",
        f"File writes (E11file) & exact runs & {fl['exact_runs']}/{fl['runs']} ({fl['bytes'] / 1e6:.1f}\\,MB) \\\\",
    ]
    with open(out_tex, "w") as f:
        f.write("% generated by analysis/kcred_tables.py from the confirmatory campaigns; do not edit\n")
        f.write(f"\\renewcommand{{\\KcConnAdd}}{{{add('prctl', 'connect'):.1f}}}\n")
        f.write(f"\\renewcommand{{\\KcConnAddMk}}{{{add('openat', 'connect'):.1f}}}\n")
        f.write(f"\\renewcommand{{\\KcOpenAdd}}{{{add('prctl', 'open'):.2f}}}\n")
        f.write(f"\\renewcommand{{\\KcOpenAddMk}}{{{add('openat', 'open'):.2f}}}\n")
        f.write("\\renewcommand{\\KcRows}{" + "\n".join(rows) + "}\n")
        for e in EXPS:
            f.write(f"\\def\\KcRuns{e.replace('E', '').replace('3', 'Three').replace('6', 'Six').replace('11', 'Eleven')}{{{s[e]['runs']}}}\n")
    print(json.dumps(s, indent=1)[:3000])


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
