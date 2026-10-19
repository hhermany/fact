"""Integration with the official MCP SDK (FastMCP): each tool call runs bound to
the identity of the execution that requested it, without changing tool code.

The identity comes from params._meta["agentnet/exec"] of the tools/call request
(a field the MCP reserves for metadata); if absent, from a per-MCP-session
identity (one session = one agent execution). The client sends the _meta with
call_tool_with_exec().
"""
from . import agentctx

META_KEY = "agentnet/exec"


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


def instrument(fastmcp, key=META_KEY, per_session=True):
    """Wraps the tools/call handler of a FastMCP instance."""
    agentctx.install()
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
