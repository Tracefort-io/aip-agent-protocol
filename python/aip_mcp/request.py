"""Read the requested MCP method and tool out of a JSON-RPC request body.

The proxy needs the tool name to run step V6, because V6 evaluates the token's
policy against the tool actually being invoked. Forwarding without it is how
the proxy came to verify signatures and nothing else.

MCP is JSON-RPC 2.0 over HTTP. A tool invocation looks like:

    {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
     "params": {"name": "search", "arguments": {...}}}

Only ``tools/call`` names a tool. ``initialize``, ``tools/list``,
``resources/read`` and the rest do not, and must still have their chain
verified even though no tool-specific policy applies.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

#: Scope prefix used for tool capabilities in AIP policies, e.g. ``tool:search``.
TOOL_SCOPE_PREFIX = "tool:"


@dataclass(frozen=True)
class McpRequest:
    """What the proxy could determine about an MCP request."""

    method: str | None
    tool: str | None
    batch: bool = False

    @property
    def required_scope(self) -> str | None:
        """The scope this request needs, or None if it invokes no tool."""
        if self.tool is None:
            return None
        return f"{TOOL_SCOPE_PREFIX}{self.tool}"


def parse_mcp_request(body: bytes) -> McpRequest:
    """Extract the method and tool name from a JSON-RPC body.

    Never raises. A body that is not JSON, not an object, or not JSON-RPC
    yields ``McpRequest(None, None)``, which the caller must treat as "no tool
    established" rather than "no tool required".

    A JSON-RPC batch containing more than one distinct tool cannot be
    authorized by a single V6 evaluation, so it is reported via ``batch`` and
    rejected by the caller rather than authorized on the first entry.
    """
    if not body:
        return McpRequest(None, None)

    try:
        payload = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return McpRequest(None, None)

    if isinstance(payload, list):
        calls = [p for p in payload if isinstance(p, dict)]
        tools = {_tool_of(p) for p in calls} - {None}
        methods = {p.get("method") for p in calls if isinstance(p.get("method"), str)}
        if len(tools) > 1:
            return McpRequest(None, None, batch=True)
        tool = next(iter(tools), None)
        method = next(iter(methods), None) if len(methods) == 1 else None
        return McpRequest(method, tool, batch=True)

    if not isinstance(payload, dict):
        return McpRequest(None, None)

    method = payload.get("method")
    return McpRequest(method if isinstance(method, str) else None, _tool_of(payload))


def _tool_of(payload: dict) -> str | None:
    if payload.get("method") != "tools/call":
        return None
    params = payload.get("params")
    if not isinstance(params, dict):
        return None
    name = params.get("name")
    return name if isinstance(name, str) and name else None
