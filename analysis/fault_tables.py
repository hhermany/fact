#!/usr/bin/env python3
"""Paper tables for fault injection and the lineage-checked policy (generated; do not edit the .tex).

Usage: python3 analysis/fault_tables.py CAMPAIGNS_DIR OUT_DIR [label]
Uses every confirmatory campaign of E5f, E6f, E7f, E6L, and E6Ls in CAMPAIGNS_DIR.
Writes OUT_DIR/tab_fault.tex, OUT_DIR/tab_lineage.tex, and OUT_DIR/fault_meta.tex.
"""
import glob
import json
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fault_summary import run_summary  # noqa: E402

root, out = sys.argv[1], sys.argv[2]
LABEL = sys.argv[3] if len(sys.argv) > 3 else "confirmatory"   # "pilot" só para testar o script


def campaigns(exp):
    res = []
    for d in sorted(glob.glob(os.path.join(root, f"*-{exp}-{LABEL}-*"))):
        if os.path.isdir(d) and os.path.exists(os.path.join(d, "manifest.json")):
            m = json.load(open(os.path.join(d, "manifest.json")))
            if m["experiment"] == exp and m["label"] == LABEL and m["runs_failed"] == 0:
                res.append((d, m))
    return res


def runs(exp):
    for d, m in campaigns(exp):
        for r in m["runs"]:
            rd = os.path.join(d, "runs", r["run_id"])
            plan, att, pol = run_summary(rd)
            yield r["params"], plan, att, pol, m


meta, used = {}, []
# ---- E5f (attribution) and E6f (policy), pooled over tools
att5 = defaultdict(Counter)
pol6 = defaultdict(Counter)
n5 = n6 = 0
for params, plan, att, pol, m in runs("E5f"):
    att5[(plan["execs"], plan["wrong_label"])].update(att)
    n5 += 1
for params, plan, att, pol, m in runs("E6f"):
    pol6[(plan["execs"], plan["wrong_label"])].update(pol)
    pol6[(plan["execs"], plan["wrong_label"])]["mislabeled"] += att["mislabeled"]
    n6 += 1
e7 = Counter()
e7pol = Counter()
n7 = 0
for params, plan, att, pol, m in runs("E7f"):
    e7.update(att)
    e7pol.update(pol)
    n7 += 1

lines = ["% gerado por analysis/fault_tables.py — não editar à mão",
         r"\begin{tabular}{@{}lrrrrrrr@{}}", r"\toprule",
         r" & & \multicolumn{3}{c}{attribution (E5f)} & \multicolumn{3}{c}{policy (E6f, E7f)} \\",
         r"\cmidrule(lr){3-5}\cmidrule(l){6-8}",
         r"$K$ & $p$ & mislab. & wrong & other err. & FA & FD & other err. \\", r"\midrule"]
spill = 0
for key in sorted(set(att5) | set(pol6)):
    a, p = att5[key], pol6[key]
    other_a = a["I"] - a["mis_I"] + a["A"] + a["M"]
    other_p = (p.get("FA", 0) - p.get("mis_FA", 0)) + (p.get("FD", 0) - p.get("mis_FD", 0)) + p.get("ND", 0)
    spill += other_a + other_p
    lines.append(f"{key[0]} & {key[1]:.2f} & {a['mislabeled']} & {a['mis_I']} & {other_a} & "
                 f"{p.get('mis_FA', 0)} & {p.get('mis_FD', 0)} & {other_p} \\\\")
if n7:
    other7 = (e7pol.get("FA", 0) - e7pol.get("mis_FA", 0)) + (e7pol.get("FD", 0) - e7pol.get("mis_FD", 0))
    spill_e7 = other7 + (e7["I"] - e7["mis_I"])
    lines += [r"\midrule",
              f"\\multicolumn{{2}}{{l}}{{E7f (LLM)}} & {e7['mislabeled']} & {e7['mis_I']} & {e7['I'] - e7['mis_I']} & "
              f"{e7pol.get('mis_FA', 0)} & {e7pol.get('mis_FD', 0)} & {other7} \\\\"]
    meta.update(FaultEsevenMis=e7["mislabeled"], FaultEsevenFA=e7pol.get("mis_FA", 0),
                FaultEsevenAllowed=e7pol.get("mis_FA", 0) + e7pol.get("mis_TA", 0),
                FaultEsevenFD=e7pol.get("mis_FD", 0), FaultEsevenRuns=n7, FaultEsevenOther=spill_e7)
lines += [r"\bottomrule", r"\end{tabular}"]
open(os.path.join(out, "tab_fault.tex"), "w").write("\n".join(lines) + "\n")
tot_mis5 = sum(a["mislabeled"] for a in att5.values())
tot_wrong5 = sum(a["mis_I"] for a in att5.values())
tot_conn5 = sum(a["N"] for a in att5.values())
tot_mis6 = sum(p["mislabeled"] for p in pol6.values())
tot_err6 = sum(p.get("mis_FA", 0) + p.get("mis_FD", 0) for p in pol6.values())
meta.update(FaultEfiveRuns=n5, FaultEsixRuns=n6, FaultConn=tot_conn5, FaultMis=tot_mis5, FaultMisWrong=tot_wrong5,
            FaultSpill=spill, FaultPolMis=tot_mis6, FaultPolErr=tot_err6,
            FaultPolErrPct=f"{100 * tot_err6 / tot_mis6:.0f}" if tot_mis6 else "0")

# ---- E6L: lineage modes, pooled over structure and operation mode
lin = defaultdict(Counter)
nl = 0
for params, plan, att, pol, m in runs("E6L"):
    k = (int(params.get("policy_lineage", 0)), plan["wrong_label"])
    lin[k].update(pol)
    lin[k]["mislabeled"] += att["mislabeled"]
    lin[k]["decisions"] += sum(pol.get(x, 0) for x in ("TA", "TD", "FA", "FD"))
    nl += 1
names = {0: "label only", 1: "deny on conflict", 2: "tree owner"}
lines = ["% gerado por analysis/fault_tables.py — não editar à mão",
         r"\begin{tabular}{@{}lrrrrrr@{}}", r"\toprule",
         r"Lineage check & $p$ & decisions & mislab. & conflicts & FA & FD \\", r"\midrule"]
exact = True
for k in sorted(lin):
    v = lin[k]
    if k[0] and v.get("conflict", 0) != v["mislabeled"]:
        exact = False
    lines.append(f"{names[k[0]]} & {k[1]:.2f} & {v['decisions']} & {v['mislabeled']} & "
                 f"{v.get('conflict', 0) if k[0] else '--'} & {v.get('FA', 0)} & {v.get('FD', 0)} \\\\")
lines += [r"\bottomrule", r"\end{tabular}"]
open(os.path.join(out, "tab_lineage.tex"), "w").write("\n".join(lines) + "\n")
m2_err = sum(v.get("FA", 0) + v.get("FD", 0) for k, v in lin.items() if k[0] == 2)
m2_dec = sum(v["decisions"] for k, v in lin.items() if k[0] == 2)
m1_fa = sum(v.get("FA", 0) for k, v in lin.items() if k[0] == 1)
m0_err = sum(v.get("FA", 0) + v.get("FD", 0) for k, v in lin.items() if k[0] == 0)
m0_mis = sum(v["mislabeled"] for k, v in lin.items() if k[0] == 0)
meta.update(LinRuns=nl, LinConflictsExact="yes" if exact else "no", LinModeTwoErr=m2_err, LinModeTwoDec=m2_dec,
            LinModeOneFA=m1_fa, LinModeZeroErr=m0_err, LinModeZeroMis=m0_mis,
            LinModeZeroPct=f"{100 * m0_err / m0_mis:.0f}" if m0_mis else "0")

# ---- E6Ls: shared worker control (no false vetoes)
ls = Counter()
nls = 0
for params, plan, att, pol, m in runs("E6Ls"):
    ls.update(pol)
    nls += 1
meta.update(LsRuns=nls, LsDecisions=sum(ls.get(x, 0) for x in ("TA", "TD", "FA", "FD")),
            LsErrors=ls.get("FA", 0) + ls.get("FD", 0) + ls.get("ND", 0), LsConflicts=ls.get("conflict", 0))

camps = sorted({m["campaign_id"] for e in ("E5f", "E6f", "E7f", "E6L", "E6Ls") for _, m in campaigns(e)})
meta["FaultCampaigns"] = ", ".join(camps)
with open(os.path.join(out, "fault_meta.tex"), "w") as f:
    f.write("% gerado por analysis/fault_tables.py\n")
    for k, v in meta.items():
        f.write(f"\\def\\{k}{{{v}}}\n")
print(open(os.path.join(out, "tab_fault.tex")).read())
print(open(os.path.join(out, "tab_lineage.tex")).read())
print(open(os.path.join(out, "fault_meta.tex")).read())
