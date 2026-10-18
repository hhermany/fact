#!/usr/bin/env python3
"""Checagem das dependências externas de uma campanha, antes da primeira rodada.

Chamada por scripts/campaign.py para toda campanha (piloto ou confirmatória). A
campanha só começa se todas as dependências que a especificação usa responderem:

- modelos servidos por API (Anthropic, prefixo "claude-"; OpenAI, prefixo "gpt-"): uma chamada real e
  mínima, com o mesmo código, as mesmas ferramentas e os mesmos parâmetros dos
  agentes (workload/agent_e7.py); falha se a API recusar algo (parâmetro não
  aceito, modelo inexistente, chave inválida, falta de saldo);
- modelos servidos pelo Ollama (local ou na segunda máquina): o modelo precisa
  estar instalado no servidor indicado e responder a uma chamada com ferramentas
  (o que também o carrega na memória antes da primeira rodada);
- serviços na segunda máquina (dest_host: E3net, E5net, E6net): as duas faixas de
  portas do workload/remote_farm.py precisam aceitar conexões;
- AgentProvenance (E5ap): o binário precisa existir e informar a versão esperada.

Imprime uma linha por verificação e sai com código 1 se alguma falhar.
Uso: check_deps.py workflow/experiments/<exp>.json
"""
import json
import os
import socket
import subprocess
import sys
import types
import urllib.request

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(HERE, "workload"))

DEFAULT_OLLAMA = "127.0.0.1:11434"
DEFAULT_E7_MODEL = "qwen2.5:3b"          # padrão de workload/agent_e7.py (E7, E7f)
REMOTE_FARM_PORTS = (61000, 65000)       # uma porta de cada faixa do remote_farm.py
AGENTPROV_VERSION = "0.9.0"
TOOLS = [{"type": "function", "function": {
    "name": "tcp_check", "description": "Check whether a TCP port accepts connections.",
    "parameters": {"properties": {"host": {"title": "Host", "type": "string"},
                                  "port": {"title": "Port", "type": "integer"}},
                   "required": ["host", "port"], "title": "tcp_checkArguments", "type": "object"}}}]


def values(spec, key, default=None):
    """Todos os valores que um parâmetro assume na campanha (fator ou fixo)."""
    if key in spec.get("factors", {}):
        return list(spec["factors"][key])
    if key in spec.get("fixed", {}):
        return [spec["fixed"][key]]
    return [default] if default is not None else []


def check_models(spec):
    fixed = spec.get("fixed", {})
    if not str(fixed.get("workload", "")).endswith("agent_e7.py"):
        return []
    import agent_e7   # noqa: E402
    msgs = [{"role": "system", "content": agent_e7.SYSTEM},
            {"role": "user", "content": "Check the database at host 127.0.0.1 port 1 with the tcp_check tool."}]
    out = []
    for model in values(spec, "model", DEFAULT_E7_MODEL):
        for host in values(spec, "ollama", DEFAULT_OLLAMA):
            a = types.SimpleNamespace(model=model, ollama=host, seed=0, num_predict=fixed.get("num_predict", 0))
            where = ("API da Anthropic" if model.startswith("claude-") else "API da OpenAI") if agent_e7.is_api_model(model) else f"Ollama {host}"
            try:
                if not agent_e7.is_api_model(model):
                    tags = json.loads(urllib.request.urlopen(f"http://{host}/api/tags", timeout=10).read())
                    names = {m["name"]: m.get("digest", "")[:16] for m in tags.get("models", [])}
                    if model not in names:
                        raise RuntimeError(f"modelo não instalado (instalados: {sorted(names)})")
                r = agent_e7.llm_chat(a, msgs, TOOLS)
                calls = r["message"].get("tool_calls") or []
                extra = f", digest {names[model]}" if not agent_e7.is_api_model(model) else \
                    f", uso {r.get('usage', {}).get('input_tokens')}+{r.get('usage', {}).get('output_tokens')} tokens"
                out.append((True, f"modelo {model} ({where}): OK, {len(calls)} chamada(s) de ferramenta{extra}"))
            except Exception as e:  # noqa: BLE001
                out.append((False, f"modelo {model} ({where}): FALHOU: {e}"))
            if agent_e7.is_api_model(model):
                break   # a API não depende do servidor Ollama
    return out


def check_dest_hosts(spec):
    out = []
    for host in values(spec, "dest_host"):
        if host in ("127.0.0.1", "localhost"):
            continue
        for port in REMOTE_FARM_PORTS:
            try:
                with socket.create_connection((host, port), timeout=3):
                    pass
                out.append((True, f"segunda máquina {host}:{port}: OK"))
            except OSError as e:
                out.append((False, f"segunda máquina {host}:{port}: FALHOU ({e}); remote_farm.py está ativo?"))
    return out


def check_agentprov(spec):
    out = []
    for path in values(spec, "agentprov"):
        try:
            v = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10).stdout.strip()
            ok = AGENTPROV_VERSION in v
            out.append((ok, f"AgentProvenance {path}: {'OK' if ok else 'FALHOU'} ({v or 'sem saída'})"))
        except Exception as e:  # noqa: BLE001
            out.append((False, f"AgentProvenance {path}: FALHOU ({e})"))
    return out


def main():
    spec = json.load(open(sys.argv[1]))
    res = check_models(spec) + check_dest_hosts(spec) + check_agentprov(spec)
    if not res:
        print(f"dependências externas ({spec['experiment']}): nenhuma")
    for ok, msg in res:
        print(("  " if ok else "! ") + msg)
    return 0 if all(ok for ok, _ in res) else 1


if __name__ == "__main__":
    sys.exit(main())
