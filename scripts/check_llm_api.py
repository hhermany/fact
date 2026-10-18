#!/usr/bin/env python3
"""Checagem prévia da API do modelo antes de uma campanha de agentes (E7c).

Para cada modelo da especificação servido por API (prefixo "claude-"), faz uma
chamada real e mínima com o mesmo código, as mesmas ferramentas e os mesmos
parâmetros que os agentes usam (workload/agent_e7.py). Se a API recusar algo
(parâmetro não aceito, modelo inexistente, chave inválida, falta de saldo), sai
com código 1 e mostra o erro, e a campanha não começa.

Uso: check_llm_api.py workflow/experiments/E7c.json
"""
import json
import os
import sys
import types

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(HERE, "workload"))


def main():
    spec = json.load(open(sys.argv[1]))
    models = [m for m in spec.get("factors", {}).get("model", [spec.get("fixed", {}).get("model", "")])
              if str(m).startswith("claude-")]
    if not models:
        print("checagem da API: nenhum modelo servido por API")
        return 0
    import agent_e7   # noqa: E402
    tools = [{"type": "function", "function": {"name": "tcp_check", "description": "Check whether a TCP port accepts connections.",
                                               "parameters": {"properties": {"host": {"title": "Host", "type": "string"},
                                                                             "port": {"title": "Port", "type": "integer"}},
                                                              "required": ["host", "port"], "title": "tcp_checkArguments",
                                                              "type": "object"}}}]
    msgs = [{"role": "system", "content": agent_e7.SYSTEM},
            {"role": "user", "content": "Check the database at host 127.0.0.1 port 1 with the tcp_check tool."}]
    ok = True
    for m in models:
        a = types.SimpleNamespace(model=m, num_predict=spec.get("fixed", {}).get("num_predict", 512),
                                  ollama=None, seed=0)
        try:
            r = agent_e7.llm_chat(a, msgs, tools)
            calls = r["message"].get("tool_calls") or []
            print(f"checagem da API: {m} OK (modelo {r.get('model')}, uso {r.get('usage', {}).get('input_tokens')}+"
                  f"{r.get('usage', {}).get('output_tokens')} tokens, {len(calls)} chamada(s) de ferramenta)")
        except Exception as e:  # noqa: BLE001
            ok = False
            print(f"checagem da API: {m} FALHOU: {e}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
