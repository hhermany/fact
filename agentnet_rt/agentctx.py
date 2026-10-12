"""Ligação da identidade de execução no runtime (lado usuário do agentnet).

Problema (E4): o contexto do kernel é indexado por thread. Um marcador emitido
no início de uma chamada de ferramenta async é sobrescrito quando outra
coroutine roda na mesma thread do event loop, e as conexões saem com a
identidade errada, sem que nenhum sinal do kernel o detecte.

Solução: a identidade segue a TAREFA (contextvars, que o asyncio copia para cada
Task e o anyio/asyncio.to_thread copiam para threads de trabalho) e é entregue ao
kernel imediatamente antes de cada evento que o kernel atribui:
  - connect() de socket AF_INET/AF_INET6;
  - criação de processo (subprocess.Popen e os.fork).
Entre o marcador e a chamada de sistema não há await, então nenhuma outra
coroutine pode rodar no meio: a conexão (ou o filho) sai com a identidade da
tarefa que a originou. Sem identidade corrente, o contexto do kernel é limpo
antes do connect: a conexão fica sem contexto (o resolvedor a reporta como
ambígua/sem crédito) em vez de herdar uma identidade antiga.

O mecanismo de entrega é o mesmo do coletor: openat em /run/agentctx/begin/<id>
ou /run/agentctx/end (caminhos inexistentes; custo de uma syscall que falha).
Um cache por thread evita remarcar quando a identidade não mudou: o contexto do
kernel de uma thread só muda pelos marcadores emitidos por ela mesma (ou pela
herança na criação, quando o cache da thread nova ainda está vazio).

Uso:
    from agentnet_rt import agentctx
    agentctx.install()
    with agentctx.bind("exec-42"):
        ...   # conexões e subprocessos desta tarefa levam exec-42
"""
import contextvars
import os
import socket
import subprocess
import threading
from contextlib import contextmanager

CTX_BEGIN = "/run/agentctx/begin/"
CTX_END = "/run/agentctx/end"
_UNSET = object()

current = contextvars.ContextVar("agentnet_exec", default=None)
_tls = threading.local()
_lock = threading.Lock()
stats = {"marks": 0, "cached": 0}
_installed = False
enabled = True          # False desliga os ganchos sem desinstalá-los (testes)
_orig = {}


def _emit(path):
    try:
        os.close(os.open(path, os.O_RDONLY))
    except FileNotFoundError:
        pass


def _valid(exec_id):
    return isinstance(exec_id, str) and 0 < len(exec_id) <= 40 and "/" not in exec_id and "\0" not in exec_id


def sync_kernel():
    """Iguala o contexto do kernel da thread chamadora à identidade da tarefa
    corrente. Deve ser chamada sem await entre ela e a syscall que protege."""
    if not enabled:
        return
    want = current.get()
    if getattr(_tls, "last", _UNSET) == want:
        with _lock:
            stats["cached"] += 1
        return
    _emit(CTX_BEGIN + want if want is not None else CTX_END)
    _tls.last = want
    with _lock:
        stats["marks"] += 1


def invalidate():
    """Esquece o cache da thread (usar se outro código emitir marcadores)."""
    _tls.last = _UNSET


@contextmanager
def bind(exec_id):
    """Associa exec_id à tarefa corrente (sync ou async) durante o bloco."""
    if exec_id is not None and not _valid(exec_id):
        raise ValueError(f"identidade de execução inválida: {exec_id!r}")
    tok = current.set(exec_id)
    try:
        yield
    finally:
        current.reset(tok)


def install():
    """Instala os ganchos de connect e criação de processo (idempotente)."""
    global _installed
    if _installed:
        return
    _orig["connect"] = socket.socket.connect
    _orig["connect_ex"] = socket.socket.connect_ex
    _orig["execute_child"] = subprocess.Popen._execute_child

    def connect(self, address):
        if self.family in (socket.AF_INET, socket.AF_INET6):
            sync_kernel()
        return _orig["connect"](self, address)

    def connect_ex(self, address):
        if self.family in (socket.AF_INET, socket.AF_INET6):
            sync_kernel()
        return _orig["connect_ex"](self, address)

    def execute_child(self, *args, **kwargs):
        sync_kernel()
        return _orig["execute_child"](self, *args, **kwargs)

    socket.socket.connect = connect
    socket.socket.connect_ex = connect_ex
    subprocess.Popen._execute_child = execute_child
    os.register_at_fork(before=sync_kernel)
    _installed = True
