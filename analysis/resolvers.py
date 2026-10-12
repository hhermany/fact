"""Resolvers de atribuição para eventos de conexão TCP.

REGRA DE INDEPENDÊNCIA: nenhum resolver pode ler daddr, dport ou qualquer
campo da referência. Eles recebem apenas `ResolverInput` (abaixo), montado
por `strip_reference_fields`. `check_independence()` verifica isso por AST,
no mesmo espírito da verificação usada no C1.

Saída de todo resolver: frozenset de exec_ids.
  len == 1  -> origem atribuída
  len  > 1  -> ambiguidade (conjunto de candidatos)
  len == 0  -> ausência de atribuição
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
    """Estado reconstruído a partir de fork/exit e do registro do launcher."""
    parent: dict = field(default_factory=dict)        # tid -> tid pai
    roots: dict = field(default_factory=dict)         # pid raiz -> set(exec_ids)
    cgroups: dict = field(default_factory=dict)       # cgroup id -> set(exec_ids)

    def ancestors(self, tid, limit=4096):
        seen = 0
        while tid is not None and seen < limit:
            yield tid
            tid = self.parent.get(tid)
            seen += 1


# ---------------------------------------------------------------- resolvers isolados
def resolve_cgroup(x: ResolverInput, w: World):
    return frozenset(w.cgroups.get(x.cgroup, ()))


def resolve_lineage(x: ResolverInput, w: World):
    for t in w.ancestors(x.tid):
        if t in w.roots:
            return frozenset(w.roots[t])
    # tid pode ser uma thread cujo fork não foi visto: tenta pelo pid (tgid)
    for t in w.ancestors(x.pid):
        if t in w.roots:
            return frozenset(w.roots[t])
    return frozenset()


def resolve_context(x: ResolverInput, w: World):
    if x.ctx.startswith(CTX_PREFIX):
        return frozenset([x.ctx[len(CTX_PREFIX):]])
    return frozenset()


# ---------------------------------------------------------------- fusão
def resolve_fused(x: ResolverInput, w: World):
    """Fusão com ambiguidade explícita.

    1. Sinais estruturais: K = interseção dos conjuntos NÃO vazios de lineage e
       cgroup. Se ambos não vazios e disjuntos -> conflito -> união (ambíguo).
    2. Contexto c (se houver):
         - K vazio (sem informação estrutural)      -> {c}
         - c ∈ K                                    -> {c}   (contexto refina K)
         - c ∉ K                                    -> K ∪ {c} (conflito: ambíguo)
    3. Sem contexto: K (pode ser unitário, ambíguo ou vazio).
    Nunca escolhe entre candidatos sem informação que os separe.
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
    """Falha se algum resolver referenciar campos da referência."""
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
                raise AssertionError(f"resolver {name} referencia campo proibido: {ident}")
    return True
