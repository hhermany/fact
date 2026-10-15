#!/usr/bin/env python3
"""Make every generated table span the column width (tabular -> tabular* with \\columnwidth).

Usage: python3 scripts/fullwidth_tables.py DIR [DIR ...]
Idempotent: files already using tabular* are left unchanged.
"""
import glob
import os
import sys

for d in sys.argv[1:]:
    for f in sorted(glob.glob(os.path.join(d, "tab_*.tex"))):
        t = open(f).read()
        if "tabular*" in t or "\\begin{tabular}{@{}" not in t:
            continue
        t = t.replace("\\begin{tabular}{@{}", "\\begin{tabular*}{\\columnwidth}{@{\\extracolsep{\\fill}}", 1)
        t = t.replace("\\end{tabular}", "\\end{tabular*}")
        open(f, "w").write(t)
        print("full width:", f)
