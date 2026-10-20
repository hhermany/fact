#!/usr/bin/env python3
"""Directed test of the fused resolver's rules, including a structural conflict
(lineage and cgroup both informative and disjoint): the context must not settle it."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "analysis"))
from resolvers import ResolverInput, World, resolve_fused  # noqa: E402

B = "/run/agentctx/begin/"


def x(tid, cg, ctx=""):
    return ResolverInput(0, tid, tid, cg, ctx)


def main():
    w = World(parent={11: 10, 21: 20}, roots={10: {"e1"}, 20: {"e2"}}, cgroups={100: {"e1"}, 200: {"e2"}, 300: {"e1", "e2"}})
    cases = [
        (x(11, 100, B + "e1"), {"e1"}),            # consistent structure and context
        (x(11, 100, B + "e2"), {"e1", "e2"}),      # context contradicts the structure -> ambiguous
        (x(11, 200, B + "e1"), {"e1", "e2"}),      # structural conflict, context in the union -> ambiguous
        (x(11, 200, ""), {"e1", "e2"}),            # structural conflict, no context -> ambiguous
        (x(11, 300, B + "e1"), {"e1"}),            # cgroup shared, lineage informative
        (x(99, 300, B + "e2"), {"e2"}),            # shared cgroup, no lineage: context refines
        (x(99, 0, B + "e2"), {"e2"}),              # no structure: context
        (x(99, 0, ""), set()),                     # nothing: missing
    ]
    for inp, want in cases:
        got = set(resolve_fused(inp, w))
        assert got == want, (inp, got, want)
    print(f"fusion rules: {len(cases)} cases OK")


if __name__ == "__main__":
    main()
