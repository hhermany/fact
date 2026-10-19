#!/usr/bin/env python3
"""Checks a campaign's external dependencies before its first run.

Called by scripts/campaign.py for every campaign (pilot or confirmatory). The
campaign starts only if every dependency that the specification uses responds:

- models served by an API (Anthropic, prefix "claude-"; OpenAI, prefix "gpt-"): one real,
  minimal call, with the same code, tools, and parameters as the agents
  (workload/agent_e7.py); fails if the API rejects anything (unsupported
  parameter, unknown model, invalid key, no credit);
- models served by Ollama (local or on the second machine): the model must be
  installed on the given server and answer a call with tools (which also loads
  it into memory before the first run);
- services on the second machine (dest_host: E3net, E5net, E6net): both port
  ranges of workload/remote_farm.py must accept connections;
- AgentProvenance (E5ap): the binary must exist and report the expected version;
- model-free replay (E7r): the recorded campaigns must be extracted and complete.

Prints one line per check and exits with code 1 if any fails.
Usage: check_deps.py workflow/experiments/<exp>.json
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
DEFAULT_E7_MODEL = "qwen2.5:3b"          # default of workload/agent_e7.py (E7, E7f)
REMOTE_FARM_PORTS = (61000, 65000)       # one port from each range of remote_farm.py
AGENTPROV_VERSION = "0.9.0"
TOOLS = [{"type": "function", "function": {
    "name": "tcp_check", "description": "Check whether a TCP port accepts connections.",
    "parameters": {"properties": {"host": {"title": "Host", "type": "string"},
                                  "port": {"title": "Port", "type": "integer"}},
                   "required": ["host", "port"], "title": "tcp_checkArguments", "type": "object"}}}]


def values(spec, key, default=None):
    """Every value a parameter takes in the campaign (factor or fixed)."""
    if key in spec.get("factors", {}):
        return list(spec["factors"][key])
    if key in spec.get("fixed", {}):
        return [spec["fixed"][key]]
    return [default] if default is not None else []


def check_replay(spec):
    """Model-free replay (E7r): the recorded campaigns must be extracted and complete."""
    src = spec.get("fixed", {}).get("replay_from", "")
    out = []
    for c in (x for x in src.split(",") if x):
        path = c if os.path.isabs(c) else os.path.join(HERE, c)
        man = os.path.join(path, "manifest.json")
        if os.path.isfile(man):
            m = json.load(open(man))
            ok = m.get("runs_failed", 1) == 0
            out.append((ok, f"recording {c}: {'OK' if ok else 'FAILED'} ({m.get('runs_ok')} runs, {m.get('experiment')})"))
        else:
            out.append((False, f"recording {c}: FAILED (no manifest; extract it with scripts/extract_campaigns.sh)"))
    return out


def check_models(spec):
    fixed = spec.get("fixed", {})
    if not str(fixed.get("workload", "")).endswith("agent_e7.py") or fixed.get("replay_from"):
        return []
    import agent_e7   # noqa: E402
    msgs = [{"role": "system", "content": agent_e7.SYSTEM},
            {"role": "user", "content": "Check the database at host 127.0.0.1 port 1 with the tcp_check tool."}]
    out = []
    for model in values(spec, "model", DEFAULT_E7_MODEL):
        for host in values(spec, "ollama", DEFAULT_OLLAMA):
            a = types.SimpleNamespace(model=model, ollama=host, seed=0, num_predict=fixed.get("num_predict", 0))
            where = ("Anthropic API" if model.startswith("claude-") else "OpenAI API") if agent_e7.is_api_model(model) else f"Ollama {host}"
            try:
                if not agent_e7.is_api_model(model):
                    tags = json.loads(urllib.request.urlopen(f"http://{host}/api/tags", timeout=10).read())
                    names = {m["name"]: m.get("digest", "")[:16] for m in tags.get("models", [])}
                    if model not in names:
                        raise RuntimeError(f"model not installed (installed: {sorted(names)})")
                r = agent_e7.llm_chat(a, msgs, TOOLS)
                calls = r["message"].get("tool_calls") or []
                extra = f", digest {names[model]}" if not agent_e7.is_api_model(model) else \
                    f", usage {r.get('usage', {}).get('input_tokens')}+{r.get('usage', {}).get('output_tokens')} tokens"
                out.append((True, f"model {model} ({where}): OK, {len(calls)} tool call(s){extra}"))
            except Exception as e:  # noqa: BLE001
                out.append((False, f"model {model} ({where}): FAILED: {e}"))
            if agent_e7.is_api_model(model):
                break   # the API does not depend on the Ollama server
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
                out.append((True, f"second machine {host}:{port}: OK"))
            except OSError as e:
                out.append((False, f"second machine {host}:{port}: FAILED ({e}); is remote_farm.py running?"))
    return out


def check_agentprov(spec):
    out = []
    for path in values(spec, "agentprov"):
        try:
            v = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10).stdout.strip()
            ok = AGENTPROV_VERSION in v
            out.append((ok, f"AgentProvenance {path}: {'OK' if ok else 'FAILED'} ({v or 'no output'})"))
        except Exception as e:  # noqa: BLE001
            out.append((False, f"AgentProvenance {path}: FAILED ({e})"))
    return out


def main():
    spec = json.load(open(sys.argv[1]))
    res = check_models(spec) + check_replay(spec) + check_dest_hosts(spec) + check_agentprov(spec)
    if not res:
        print(f"external dependencies ({spec['experiment']}): none")
    for ok, msg in res:
        print(("  " if ok else "! ") + msg)
    return 0 if all(ok for ok, _ in res) else 1


if __name__ == "__main__":
    sys.exit(main())
