"""Integração com o SDK oficial do MCP (FastMCP): cada chamada de ferramenta roda
ligada à identidade da execução que a pediu, sem mudar o código das ferramentas.

A identidade vem de params._meta["agentnet/exec"] da requisição tools/call
(campo reservado pelo MCP para metadados); na ausência dele, de uma identidade
por sessão MCP (uma sessão = uma execução do agente). O cliente envia o _meta
com call_tool_with_exec().
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
    """Envolve o tratador tools/call de uma instância FastMCP."""
    agentctx.install()
    orig = fastmcp.call_tool
    low = fastmcp._mcp_server

    async def call_tool(name, arguments):
        with agentctx.bind(_exec_of_request(low, key, per_session)):
            return await orig(name, arguments)

    low.call_tool()(call_tool)
    return fastmcp


async def call_tool_with_exec(session, name, arguments, exec_id, key=META_KEY):
    """Lado cliente: tools/call com a identidade da execução em _meta."""
    from mcp import types
    params = types.CallToolRequestParams.model_validate(
        {"name": name, "arguments": arguments, "_meta": {key: exec_id}})
    return await session.send_request(
        types.ClientRequest(types.CallToolRequest(method="tools/call", params=params)),
        types.CallToolResult)
