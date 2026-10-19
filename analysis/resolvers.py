"""Attribution resolvers for TCP connection events.

INDEPENDENCE RULE: no resolver may read daddr, dport, or any reference field.
They receive only `ResolverInput` (below), built by `strip_reference_fields`.
`check_independence()` verifies this on the AST.

Output of every resolver: a frozenset of exec_ids.
  len == 1  -> attributed origin
  len  > 1  -> ambiguity (candidate set)
  len == 0  -> no attribution
"""
import ast
import inspect
from dataclasses import dataclass, field

ALLOWED_FIELDS = ("ts", "pid", "tid", "cgroup", "ctx")
CTX_PREFIX = "/run/agentctx/begin/"


@dataclass(frozen=True)
class ResolverInput:
    ts: int
    pid: int
    tid: int
    cgroup: int
    ctx: str


def strip_reference_fields(ev):
    return ResolverInput(**{k: ev[k] for k in ALLOWED_FIELDS})


@dataclass
class World:
    """State rebuilt from fork/exit events and from the launcher registry."""
    parent: dict = field(default_factory=dict)        # tid -> parent tid
    roots: dict = field(default_factory=dict)         # root pid -> set(exec_ids)
    cgroups: dict = field(default_factory=dict)       # cgroup id -> set(exec_ids)

    def ancestors(self, tid, limit=4096):
        seen = 0
        while tid is not None and seen < limit:
            yield tid
            tid = self.parent.get(tid)
            seen += 1


# ---------------------------------------------------------------- single-signal resolvers
def resolve_cgroup(x: ResolverInput, w: World):
    return frozenset(w.cgroups.get(x.cgroup, ()))


def resolve_lineage(x: ResolverInput, w: World):
    for t in w.ancestors(x.tid):
        if t in w.roots:
            return frozenset(w.roots[t])
    # tid may be a thread whose fork was not seen: try the pid (tgid)
    for t in w.ancestors(x.pid):
        if t in w.roots:
            return frozenset(w.roots[t])
    return frozenset()


def resolve_context(x: ResolverInput, w: World):
    if x.ctx.startswith(CTX_PREFIX):
        return frozenset([x.ctx[len(CTX_PREFIX):]])
    return frozenset()


# ---------------------------------------------------------------- fusion
def resolve_fused(x: ResolverInput, w: World):
    """Fusion with explicit ambiguity.

    1. Structural signals: K = intersection of the NON-empty lineage and cgroup
       sets. If both are non-empty and disjoint -> conflict -> union (ambiguous).
    2. Context c (if any):
         - K empty (no structural information)      -> {c}
         - c in K                                   -> {c}   (context refines K)
         - c not in K                               -> K | {c} (conflict: ambiguous)
    3. No context: K (may be a single origin, ambiguous, or empty).
    It never chooses among candidates that no information separates.
    """
    sets = [s for s in (resolve_lineage(x, w), resolve_cgroup(x, w)) if s]
    if not sets:
        k = frozenset()
    elif len(sets) == 1:
        k = sets[0]
    else:
        inter = sets[0] & sets[1]
        k = inter if inter else sets[0] | sets[1]
    c = resolve_context(x, w)
    if not c:
        return k
    if not k or c <= k:
        return c
    return k | c


RESOLVERS = {
    "cgroup": resolve_cgroup,
    "lineage": resolve_lineage,
    "context": resolve_context,
    "fused": resolve_fused,
}


def check_independence():
    """Fails if any resolver references reference fields."""
    forbidden = {"daddr", "dport", "dport_map", "op_id", "plan", "reference"}
    for name, fn in RESOLVERS.items():
        tree = ast.parse(inspect.getsource(fn))
        for node in ast.walk(tree):
            ident = None
            if isinstance(node, ast.Name):
                ident = node.id
            elif isinstance(node, ast.Attribute):
                ident = node.attr
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                ident = node.value
            if ident in forbidden:
                raise AssertionError(f"resolver {name} references forbidden field: {ident}")
    return True
