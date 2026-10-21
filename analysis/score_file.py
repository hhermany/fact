#!/usr/bin/env python3
"""Scores E11file: bytes the kernel charged per credential for regular-file writes
(file_usage.json, dumped from fact_policy's file_usage map) against what each
execution's writes returned (plan.json ref_bytes). Credentials outside the plan are
reported separately. Usage: score_file.py RUN_DIR -> RUN_DIR/file_score.json"""
import json
import os
import sys


def main(rd):
    plan = json.load(open(os.path.join(rd, "plan.json")))
    usage = json.load(open(os.path.join(rd, "file_usage.json")))
    ref = plan["ref_bytes"]
    per = {e: {"ref": ref[e], "kernel": usage.get(e, 0), "err": usage.get(e, 0) - ref[e]} for e in sorted(ref)}
    other = {k: v for k, v in usage.items() if k not in ref}
    res = {"mode": plan["mode"], "execs": plan["execs"], "ops": plan["ops"],
           "bytes_ref": sum(ref.values()), "bytes_kernel": sum(v["kernel"] for v in per.values()),
           "abs_err": sum(abs(v["err"]) for v in per.values()),
           "execs_exact": sum(v["err"] == 0 for v in per.values()),
           "other_credentials_bytes": sum(other.values()), "per_exec": per, "other": other}
    json.dump(res, open(os.path.join(rd, "file_score.json"), "w"), indent=1)
    print(f"E11file {res['mode']} K={res['execs']}: ref {res['bytes_ref']} B, kernel {res['bytes_kernel']} B, "
          f"|err| {res['abs_err']} B, exact {res['execs_exact']}/{res['execs']}, other {res['other_credentials_bytes']} B")


if __name__ == "__main__":
    main(sys.argv[1])
