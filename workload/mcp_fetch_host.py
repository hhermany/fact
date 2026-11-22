#!/usr/bin/env python3
"""Runs the official MCP fetch server (mcp-server-fetch, pinned in flake.nix)
UNMODIFIED as one process serving many sessions (E5fetch).

The fetch server is written for stdio (one process per client). Here its own
serve() coroutine runs once per SSE session inside one process, with only its
transport replaced (fact_rt.mcp.serve_stdio_server): tool definitions, argument
handling, the robots.txt check, and the HTTP client are the server's code. The
execution identity is derived from the session's bearer token (registered by
the operator); the server code neither sees nor forwards it.

Usage: python3 mcp_fetch_host.py --port 64999 --tokens tokens.json
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=64999)
    ap.add_argument("--tokens", required=True)
    ap.add_argument("--binding", default="auto")       # accepted for symmetry with the other servers
    a = ap.parse_args()
    import mcp_server_fetch.server as fetch_server
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from netfam import LOOPBACK
    from fact_rt import mcp as fact_mcp
    fact_mcp.serve_stdio_server(fetch_server,
                                lambda: fetch_server.serve(custom_user_agent="FACT-E5fetch"),
                                json.load(open(a.tokens)), host=LOOPBACK, port=a.port)


if __name__ == "__main__":
    main()
