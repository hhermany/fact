#!/usr/bin/env python3
"""OBI association test: does OpenTelemetry eBPF Instrumentation tie each outgoing
request of a shared server to the incoming request (execution) that caused it?

No FACT here. A server process (instrumented by OBI through its open port) serves K
executions concurrently; every execution sends its own W3C traceparent (one trace ID per
execution) on each incoming request, and each request makes the server issue one outgoing
HTTP GET to a destination port owned by that execution. With context propagation on, OBI
writes a traceparent into the outgoing request; the destination (this process, not
instrumented) logs it. Reference: the destination port identifies the execution.

  correct      outgoing trace ID == the owning execution's trace ID
  wrong        outgoing trace ID == another execution's trace ID
  new_trace    a trace ID no execution sent (OBI started a new trace)
  none         no traceparent at all

Modes (server side):
  direct    Starlette handler awaits the outgoing GET inside the request (OBI's pattern)
  mcp-sse   MCP server (FastMCP, SSE transport), async tool doing the GET
  mcp-http  MCP server (FastMCP, streamable HTTP transport), same tool

Usage: python3 obi_assoc.py --mode mcp-sse --execs 4 --calls 25 --out DIR
       (OBI attaches to --port; run OBI separately, see obi_round.sh)
"""
import argparse, asyncio, hashlib, json, os, random, subprocess, sys, time

TOOL = r'''
import asyncio, random, sys, httpx
MODE, PORT, KIND = sys.argv[1], int(sys.argv[2]), (sys.argv[3] if len(sys.argv) > 3 else "async")
async def out(p):
    await asyncio.sleep(random.uniform(0, 0.02))
    url = f"http://127.0.0.1:{p}/item"
    if KIND == "thread":     # worker thread (asyncio.to_thread), blocking client
        code = (await asyncio.to_thread(httpx.get, url)).status_code
    elif KIND == "subproc":  # child process doing the request
        pr = await asyncio.create_subprocess_exec(sys.executable, "-c",
            "import sys,urllib.request; print(urllib.request.urlopen(sys.argv[1]).status)", url, stdout=asyncio.subprocess.PIPE)
        code = (await pr.communicate())[0].decode().strip()
    else:                    # asynchronous coroutine on the event loop
        async with httpx.AsyncClient() as c:
            code = (await c.get(url)).status_code
    await asyncio.sleep(random.uniform(0, 0.02))
    return str(code)
if MODE == "direct":
    import uvicorn
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route
    async def fetch(req):
        return PlainTextResponse(await out(int(req.query_params["port"])))
    uvicorn.run(Starlette(routes=[Route("/fetch", fetch)]), host="127.0.0.1", port=PORT, log_level="warning")
else:
    from mcp.server.fastmcp import FastMCP
    m = FastMCP("obi", host="127.0.0.1", port=PORT, log_level="WARNING")
    @m.tool()
    async def fetch(port: int) -> str:
        """GET an item from a service port."""
        return await out(port)
    m.run(transport="sse" if MODE == "mcp-sse" else "streamable-http")
'''


def tid(e):
    return hashlib.md5(f"fact-obi-{e}".encode()).hexdigest()


def tp(e, i):
    return f"00-{tid(e)}-{hashlib.md5(f'{e}-{i}'.encode()).hexdigest()[:16]}-01"


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["direct", "mcp-sse", "mcp-http"], required=True)
    ap.add_argument("--execs", type=int, default=4)
    ap.add_argument("--calls", type=int, default=25)
    ap.add_argument("--port", type=int, default=63900)
    ap.add_argument("--base", type=int, default=63000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--tool", choices=["async", "thread", "subproc"], default="async")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    random.seed(a.seed)
    os.makedirs(a.out, exist_ok=True)
    execs = [f"e{i}" for i in range(a.execs)]
    port_of = {e: a.base + i for i, e in enumerate(execs)}
    log = []

    async def handle(r, w):
        req = await r.readuntil(b"\r\n\r\n")
        hdr = {l.split(b":", 1)[0].strip().lower().decode(): l.split(b":", 1)[1].strip().decode()
               for l in req.split(b"\r\n")[1:] if b":" in l}
        log.append({"port": w.get_extra_info("sockname")[1], "traceparent": hdr.get("traceparent"), "t": time.time()})
        w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        await w.drain(); w.close()

    servers = [await asyncio.start_server(handle, "127.0.0.1", p) for p in port_of.values()]
    srv = subprocess.Popen([sys.executable, "-c", TOOL, a.mode, str(a.port), a.tool])
    for _ in range(100):
        try:
            _, w = await asyncio.open_connection("127.0.0.1", a.port); w.close(); break
        except OSError:
            await asyncio.sleep(0.1)
    with open(os.path.join(a.out, "ready"), "w") as f:
        f.write(str(srv.pid))
    await asyncio.sleep(float(os.environ.get("OBI_WARMUP", "3")))   # lets OBI attach before the load
    import httpx
    t0 = time.time()

    async def run_direct(e):
        async with httpx.AsyncClient() as c:
            for i in range(a.calls):
                await c.get(f"http://127.0.0.1:{a.port}/fetch", params={"port": port_of[e]},
                            headers={"traceparent": tp(e, i)})

    async def run_mcp(e):
        from mcp import ClientSession
        if a.mode == "mcp-sse":
            from mcp.client.sse import sse_client as cl
            url = f"http://127.0.0.1:{a.port}/sse"
        else:
            from mcp.client.streamable_http import streamablehttp_client as cl
            url = f"http://127.0.0.1:{a.port}/mcp"
        async def once():   # SSE session opening can hang with simultaneous sessions (as in E7): deadline + retry
            async with cl(url, headers={"traceparent": tp(e, 0)}) as streams:
                async with ClientSession(streams[0], streams[1]) as s:
                    await asyncio.wait_for(s.initialize(), 20)
                    done.set()
                    for i in range(a.calls):
                        await asyncio.wait_for(s.call_tool("fetch", {"port": port_of[e]}), 20)
        await asyncio.sleep(0.5 * execs.index(e))
        for attempt in range(3):
            done = asyncio.Event()
            try:
                return await asyncio.wait_for(once(), 30 + 2 * a.calls)
            except Exception:
                if done.is_set() or attempt == 2:
                    raise

    await asyncio.gather(*[(run_direct if a.mode == "direct" else run_mcp)(e) for e in execs])
    wall = time.time() - t0
    await asyncio.sleep(0.5)
    srv.terminate()
    try:   # uvicorn waits for open SSE streams on SIGTERM: bounded wait, then kill
        srv.wait(timeout=5)
    except subprocess.TimeoutExpired:
        srv.kill(); srv.wait()
    for s in servers:
        s.close()
    owner = {p: e for e, p in port_of.items()}
    known = {tid(e): e for e in execs}
    c = {"correct": 0, "wrong": 0, "new_trace": 0, "none": 0}
    for r in log:
        t = r["traceparent"]
        if not t:
            c["none"] += 1
        else:
            got = known.get(t.split("-")[1])
            c["correct" if got == owner[r["port"]] else "wrong" if got else "new_trace"] += 1
    res = {"mode": a.mode, "tool": a.tool, "execs": a.execs, "calls": a.calls, "requests": len(log), **c, "wall_s": round(wall, 2)}
    json.dump(log, open(os.path.join(a.out, "dest_log.json"), "w"))
    json.dump(res, open(os.path.join(a.out, "obi_score.json"), "w"), indent=1)
    print(json.dumps(res))


asyncio.run(main())
