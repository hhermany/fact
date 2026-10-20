"""Integration with the official MCP SDK: each tool call runs bound to the
identity of the execution that requested it, without changing tool code.

Two sources of the identity:
  meta     params._meta["fact/exec"] of the tools/call request (a field the MCP
           reserves for metadata), sent by the client with call_tool_with_exec();
           if absent, a per-MCP-session identity. The client chooses it.
  session  the server derives it from the MCP session: each SSE connection must
           present a bearer token that the operator registered for one execution
           (tokens file: {token: exec_id}); the whole session runs bound to that
           execution and any _meta claim is ignored. A client cannot name another
           execution, only use the token it was given (E6sess).
serve_sse() runs any MCP server over SSE with the session identity, including a
third-party server whose code is unmodified (E5fetch).
"""
import contextlib
import contextvars
import hmac

from . import agentctx

META_KEY = "fact/exec"


def _exec_of_request(server, key, per_session):
    try:
        rc = server.request_context
    except LookupError:
        return None
    meta = rc.meta
    if meta is not None:
        v = (meta.model_extra or {}).get(key)
        if v is not None:
            return str(v)
    if per_session:
        return f"s{id(rc.session) & 0xffffffff:08x}"
    return None


def instrument(fastmcp, key=META_KEY, per_session=True, sends=False):
    """Wraps the tools/call handler of a FastMCP instance (sends: see agentctx.install)."""
    agentctx.install(sends=sends)
    orig = fastmcp.call_tool
    low = fastmcp._mcp_server

    async def call_tool(name, arguments):
        with agentctx.bind(_exec_of_request(low, key, per_session)):
            return await orig(name, arguments)

    low.call_tool()(call_tool)
    return fastmcp


async def call_tool_with_exec(session, name, arguments, exec_id, key=META_KEY):
    """Client side: tools/call with the execution identity in _meta."""
    from mcp import types
    params = types.CallToolRequestParams.model_validate(
        {"name": name, "arguments": arguments, "_meta": {key: exec_id}})
    return await session.send_request(
        types.ClientRequest(types.CallToolRequest(method="tools/call", params=params)),
        types.CallToolResult)


# --- session-derived identity ------------------------------------------------

session_streams = contextvars.ContextVar("fact_session_streams", default=None)


def _exec_of_token(request, tokens):
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    tok = auth[7:].strip()
    for t, e in tokens.items():          # constant-time comparison per entry
        if hmac.compare_digest(t, tok):
            return e
    return None


def sse_app(run_session, tokens, sse_path="/sse", message_path="/messages/"):
    """Starlette app serving MCP over SSE with the session-derived identity:
    run_session(read_stream, write_stream) runs one MCP session; it is called
    with the execution of the session's token bound to the current task, so every
    task the session creates (request handlers, tool calls, worker threads,
    subprocesses) inherits it. Sessions without a registered token are refused."""
    from mcp.server.sse import SseServerTransport
    from starlette.applications import Starlette
    from starlette.responses import Response
    from starlette.routing import Mount, Route
    sse = SseServerTransport(message_path)

    async def handle_sse(request):
        exec_id = _exec_of_token(request, tokens)
        if exec_id is None:
            return Response("unauthorized", status_code=401)
        with agentctx.bind(exec_id):
            async with sse.connect_sse(request.scope, request.receive, request._send) as streams:
                await run_session(streams[0], streams[1])
        return Response()

    return Starlette(routes=[Route(sse_path, endpoint=handle_sse),
                             Mount(message_path, app=sse.handle_post_message)])


def instrument_session(fastmcp, tokens, sends=False, clear=False):
    """FastMCP with the session-derived identity: replaces its SSE app (the tools
    and the tools/call handler are untouched; _meta is not read)."""
    agentctx.install(sends=sends, clear=clear)
    low = fastmcp._mcp_server

    async def run_session(r, w):
        await low.run(r, w, low.create_initialization_options())

    fastmcp.sse_app = lambda: sse_app(run_session, tokens, fastmcp.settings.sse_path,
                                      fastmcp.settings.message_path)
    return fastmcp


@contextlib.asynccontextmanager
async def _session_stdio():
    """Stand-in for mcp.server.stdio.stdio_server(): yields the current session's
    SSE streams (serve_stdio_server)."""
    streams = session_streams.get()
    if streams is None:
        raise RuntimeError("no MCP session bound to this task")
    yield streams


def serve_stdio_server(module, serve, tokens, host="127.0.0.1", port=64999, sends=False, clear=False):
    """Runs a third-party MCP server written for stdio, unmodified, as ONE process
    serving many sessions over SSE: for each session, the server's own serve()
    coroutine runs with module.stdio_server replaced by the session's SSE streams
    (the only change is the transport), bound to the session's execution."""
    import uvicorn
    agentctx.install(sends=sends, clear=clear)
    module.stdio_server = _session_stdio

    async def run_session(r, w):
        tok = session_streams.set((r, w))
        try:
            await serve()
        finally:
            session_streams.reset(tok)

    uvicorn.run(sse_app(run_session, tokens), host=host, port=port, log_level="warning")
